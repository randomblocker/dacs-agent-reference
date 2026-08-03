/**
 * Full in-process DACS Standard lifecycle for the fixed-price roster agents.
 *
 * The current SDK session core still emits reduced artifacts, so Standard is
 * authoritative here. Canonicalisation, decimals and settlement semantics are
 * delegated to the SDK through `standard-profile`; full artifact fidelity is
 * temporary until dacs-sdk#5/#53/#55 cover these shapes and session state.
 */
import { randomBytes } from "node:crypto";
import { resolveFromDid, verify } from "../../src/identity.js";
import type { BuyerAdapter } from "./buyer.js";
import type { SellerAdapter } from "./seller-adapter.js";
import {
  addAgreementSignature,
  addAutoAcceptInstanceSignature,
  addBundleSignature,
  attestationRef,
  createCommitment,
  createEmptyVetRecord,
  createIdentityBundle,
  deliverableRef,
  emptyRequirement,
  listingRef,
  sameCanonicalBundle,
  signSettlementEvidence,
  standardAnchorName,
  standardPaymentAnchorName,
  standardHash,
  verifyAgreement,
  verifyBundle,
  verifyCommitment,
  verifyEvidence,
  verifyIdentityBundle,
  verifyListing,
  verifyVetRecord,
  type AgreementDocument,
  type AutoAcceptCommitment,
  type AttestationBundle,
  type AttestationRef,
  type ChainTxRef,
  type CommitmentRecord,
  type IdentityBundle,
  type Listing,
  type PaymentRailRef,
  type PriceTerm,
  type SessionRecord,
  type SessionState,
  type SettlementEvidence,
} from "./standard-profile.js";
import { runFixedPriceNegotiation, type FixedPriceSellerSigner } from "../negotiation-l2ps/fixed-price.js";
import type { AnchorReceipt } from "../../src/ports.js";

const cryptoDeps = { resolvePublicKey: async (claim: string) => resolveFromDid(claim), verify };

export interface StandardSettlementReceipt {
  txRefs: ChainTxRef[];
  finality: NonNullable<SettlementEvidence["settlementFinality"]>;
  paymentFee?: PriceTerm;
}

export interface StandardRunInput {
  jobId: string;
  listingRef: string;
  listing: Listing;
  buyer: BuyerAdapter;
  seller: SellerAdapter;
  params: Record<string, unknown>;
  /** Execute the selected rail. It is called only after the commitment anchor. */
  settle(input: { jobId: string; agreement: AgreementDocument; commitment: CommitmentRecord }): Promise<StandardSettlementReceipt>;
  now?: () => number;
  onSessionRecord?: (record: SessionRecord) => void | Promise<void>;
  /** Production negotiation seam. Omit only for the local live-co-sign path. */
  fixedPrice?: {
    sellerSign?: FixedPriceSellerSigner;
    listingReceipt?: AnchorReceipt;
    autoAcceptCommitment?: AutoAcceptCommitment;
    autoAcceptCommitmentRef?: string;
    autoAcceptCommitmentReceipt?: AnchorReceipt;
  };
}

export interface StandardRunResult {
  agreement: AgreementDocument;
  agreementRef: AttestationRef;
  commitment: CommitmentRecord;
  commitmentRef: AttestationRef;
  paymentEvidence: SettlementEvidence;
  paymentEvidenceRef: AttestationRef;
  deliveryEvidence: SettlementEvidence;
  deliveryEvidenceRef: AttestationRef;
  buyerBundle: AttestationBundle;
  buyerBundleRef: string;
  sellerBundle: AttestationBundle;
  sellerBundleRef: string;
  delivery: Awaited<ReturnType<SellerAdapter["deliver"]>>;
  session: SessionRecord;
}

function phaseOf(listing: Listing, prefix: "pay-" | "deliver-"): { kind: Listing["pipeline"][number]["kind"]; index: number } {
  const index = listing.pipeline.findIndex((phase) => phase.kind.startsWith(prefix));
  if (index < 0) throw new Error(`listing has no ${prefix} phase`);
  return { kind: listing.pipeline[index]!.kind, index };
}

function listingPrice(listing: Listing): PriceTerm {
  if (listing.pricing.kind !== "fixed") throw new Error("standard fixed runner requires fixed PricingSpec");
  return listing.pricing.price;
}

async function transition(input: StandardRunInput, session: SessionRecord, state: SessionState, terminal = false): Promise<void> {
  const updatedAt = (input.now ?? Date.now)();
  session.state = state;
  session.lastUpdatedAt = updatedAt;
  if (terminal) session.endedAt = updatedAt;
  await input.onSessionRecord?.(structuredClone(session));
}

function pipelineIndex(listing: Listing, kind: Listing["pipeline"][number]["kind"]): number {
  const index = listing.pipeline.findIndex((step) => step.kind === kind);
  if (index < 0) throw new Error(`listing pipeline is missing ${kind}`);
  return index;
}

function recordPhase(
  session: SessionRecord,
  listing: Listing,
  index: number,
  invokedAt: number,
  result: SessionRecord["phaseResults"][number]["result"],
  contextDelta: Record<string, unknown> = result.contextDelta ?? {},
): void {
  const step = listing.pipeline[index];
  if (!step) throw new Error(`listing pipeline index ${index} is missing`);
  session.phaseResults.push({
    index,
    step: structuredClone(step),
    invokedAt,
    result: { ...result, ...(Object.keys(contextDelta).length > 0 ? { contextDelta } : {}) },
    contextDelta,
  });
}

function vetRefs(session: SessionRecord): AttestationRef[] {
  return session.parties.flatMap((party) => party.vetRecordRef ? [party.vetRecordRef] : []);
}

function evidenceRefs(session: SessionRecord): AttestationRef[] {
  return session.phaseResults.flatMap((entry) =>
    (entry.step.kind.startsWith("pay-") || entry.step.kind.startsWith("deliver-")) && entry.result.attestationRef
      ? [entry.result.attestationRef]
      : [],
  );
}

export async function runStandardFixedSession(input: StandardRunInput): Promise<StandardRunResult> {
  const now = input.now ?? Date.now;
  const startedAt = now();
  const buyer = input.buyer.standardParty;
  const seller = input.seller.standardParty;
  if (input.listing.seller.identity.presentedBy !== seller.primaryClaim) throw new Error("runtime seller does not own the selected listing");
  const expectedListingRef = await input.buyer.substrate.anchorAddressFor(
    seller.primaryClaim,
    standardAnchorName("listing", [seller.primaryClaim, input.listing.listingId, String(input.listing.listingVersion)]),
  );
  const anchoredListing = await input.buyer.substrate.read(input.listingRef);
  const listingVerdict = await verifyListing(input.listing, { ...cryptoDeps });
  if (input.listingRef !== expectedListingRef || !anchoredListing || standardHash(anchoredListing) !== standardHash(input.listing) || !listingVerdict.ok) {
    throw new Error(`selected listing failed deterministic anchor/cryptographic verification: ${listingVerdict.reason ?? "anchor mismatch"}`);
  }
  if (input.listing.buyerRequirement.required.length > 0 || (input.listing.buyerRequirement.oneOf?.length ?? 0) > 0) {
    // SDK maturity boundary: a real RecipeRegistry evaluator must replace this
    // empty-requirement path before credential-restricted listings are enabled.
    throw new Error("credential-bearing BundleRequirement is not yet supported by the roster Standard adapter");
  }
  const session: SessionRecord = {
    recordVersion: "1",
    jobId: input.jobId,
    state: "draft",
    listingRef: listingRef(input.listing),
    parties: [],
    pipeline: structuredClone(input.listing.pipeline),
    phaseResults: [],
    startedAt,
    lastUpdatedAt: startedAt,
    recipeRegistryVersion: 1,
    railRegistryVersion: 1,
  };

  let buyerBundle: IdentityBundle | undefined;
  let sellerBundle: IdentityBundle | undefined;
  let agreement: AgreementDocument | undefined;
  let agreementRef: AttestationRef | undefined;
  let currentPhase: Listing["pipeline"][number]["kind"] = "vet-credentials";
  let currentPhaseIndex = pipelineIndex(input.listing, currentPhase);
  let currentStage: "vet" | "negotiate" | "commit" | "settle" = "vet";
  const phaseSummary: AttestationBundle["phaseSummary"] = [];
  try {
    const buyerNonce = randomBytes(16).toString("hex");
    const sellerNonce = randomBytes(16).toString("hex");
    buyerBundle = await createIdentityBundle(buyer, { sessionNonce: buyerNonce, presentedAt: now() });
    sellerBundle = await createIdentityBundle(seller, { sessionNonce: sellerNonce, presentedAt: now() });
    const buyerIdentity = await verifyIdentityBundle(buyerBundle, { expectedNonce: buyerNonce, ...cryptoDeps });
    const sellerIdentity = await verifyIdentityBundle(sellerBundle, { expectedNonce: sellerNonce, ...cryptoDeps });
    if (!buyerIdentity.ok || !sellerIdentity.ok) throw new Error(`Identify failed: ${buyerIdentity.reason ?? sellerIdentity.reason}`);
    const buyerBundleHash = standardHash(buyerBundle, ["presentation"]);
    const sellerBundleHash = standardHash(sellerBundle, ["presentation"]);
    session.parties = [
      { role: "buyer", bundleHash: buyerBundleHash, primaryClaim: buyer.primaryClaim },
      { role: "seller", bundleHash: sellerBundleHash, primaryClaim: seller.primaryClaim },
    ];
    await input.onSessionRecord?.(structuredClone(session));

    await transition(input, session, "vet-pending");
    const vetInvokedAt = now();
    const buyerVet = await createEmptyVetRecord(seller, { jobId: input.jobId, bundle: buyerBundle, requirement: input.listing.buyerRequirement, generatedAt: now() });
    const sellerRequirement = emptyRequirement();
    const sellerVet = await createEmptyVetRecord(buyer, { jobId: input.jobId, bundle: sellerBundle, requirement: sellerRequirement, generatedAt: now() });
    const buyerVetLocator = await input.seller.substrate.anchor(standardAnchorName("composite", [input.jobId, buyer.primaryClaim]), buyerVet);
    const sellerVetLocator = await input.buyer.substrate.anchor(standardAnchorName("composite", [input.jobId, seller.primaryClaim]), sellerVet);
    const buyerVetRef = attestationRef(buyerVetLocator, buyerVet, seller.primaryClaim);
    const sellerVetRef = attestationRef(sellerVetLocator, sellerVet, buyer.primaryClaim);
    if (!(await verifyVetRecord(buyerVet, { jobId: input.jobId, bundle: buyerBundle, requirement: input.listing.buyerRequirement, verifier: seller.primaryClaim, ...cryptoDeps }))
      || !(await verifyVetRecord(sellerVet, { jobId: input.jobId, bundle: sellerBundle, requirement: sellerRequirement, verifier: buyer.primaryClaim, ...cryptoDeps }))) throw new Error("Vet verification failed");
    session.parties = [
      { ...session.parties[0]!, vetRecordRef: buyerVetRef },
      { ...session.parties[1]!, vetRecordRef: sellerVetRef },
    ];
    recordPhase(session, input.listing, currentPhaseIndex, vetInvokedAt, { ok: true, attestationRef: buyerVetRef }, { buyerVetRef, sellerVetRef });
    phaseSummary.push({ index: currentPhaseIndex, kind: "vet-credentials", outcome: "ok" });
    await transition(input, session, "vet-completed");

    currentStage = "negotiate";
    currentPhase = "negotiate-fixed-price";
    currentPhaseIndex = pipelineIndex(input.listing, currentPhase);
    await transition(input, session, "negotiate-pending");
    const negotiateInvokedAt = now();
    const commitInvokedAt = now();
    const fixed = await runFixedPriceNegotiation({
      jobId: input.jobId,
      listing: input.listing,
      listingAnchorRef: input.listingRef,
      listingReceipt: input.fixedPrice?.listingReceipt,
      buyer: { bundle: buyerBundle, vetRecord: buyerVet, vetRecordRef: buyerVetRef },
      seller: { bundle: sellerBundle, vetRecord: sellerVet, vetRecordRef: sellerVetRef },
      buyerParty: buyer,
      buyerSubstrate: input.buyer.substrate,
      sellerSign: input.fixedPrice?.sellerSign ?? (async ({ agreement: proposed, autoAcceptCommitment }) =>
        autoAcceptCommitment
          ? addAutoAcceptInstanceSignature(proposed, autoAcceptCommitment, seller)
          : addAgreementSignature(proposed, seller)),
      autoAcceptCommitment: input.fixedPrice?.autoAcceptCommitment,
      autoAcceptCommitmentRef: input.fixedPrice?.autoAcceptCommitmentRef,
      autoAcceptCommitmentReceipt: input.fixedPrice?.autoAcceptCommitmentReceipt,
      generatedAt: now(),
      requestScope: input.params,
      onAgreementSigned: async (signedAgreement, agreementHash) => {
        agreement = signedAgreement;
        recordPhase(session, input.listing, currentPhaseIndex, negotiateInvokedAt, { ok: true }, { agreementHash });
        phaseSummary.push({ index: currentPhaseIndex, kind: "negotiate-fixed-price", outcome: "ok" });
        await transition(input, session, "negotiate-completed");
        currentStage = "commit";
        currentPhase = "commit-agreement";
        currentPhaseIndex = pipelineIndex(input.listing, currentPhase);
        await transition(input, session, "commit-pending");
      },
    });
    agreement = fixed.agreement;
    agreementRef = fixed.agreementRef;
    const commitment = fixed.commitment;
    const commitmentRef = fixed.commitmentRef;
    recordPhase(session, input.listing, currentPhaseIndex, commitInvokedAt, { ok: true, attestationRef: commitmentRef }, {
      agreementRef,
      commitmentRef,
      agreementAnchorTxRef: fixed.agreementReceipt.txRef,
      committedAt: fixed.commitmentReceipt.anchoredAt,
      anchorTxRef: fixed.commitmentReceipt.txRef,
      ...(fixed.commitmentReceipt.blockNumber === undefined ? {} : { blockNumber: fixed.commitmentReceipt.blockNumber }),
    });
    phaseSummary.push({ index: currentPhaseIndex, kind: "commit-agreement", outcome: "ok", attestationRef: commitmentRef });
    await transition(input, session, "commit-completed");

    currentStage = "settle";
    const paymentPhase = phaseOf(input.listing, "pay-");
    currentPhase = paymentPhase.kind;
    currentPhaseIndex = paymentPhase.index;
    await transition(input, session, "settle-pending");
    const paymentInvokedAt = now();
    const receipt = await input.settle({ jobId: input.jobId, agreement, commitment });
    const paymentEvidence = await signSettlementEvidence({
      evidenceVersion: "1",
      jobId: input.jobId,
      phase: paymentPhase.kind as Extract<typeof paymentPhase.kind, `pay-${string}`>,
      outcome: "success",
      paymentTxRefs: receipt.txRefs,
      paymentAmount: agreement.terms.price,
      paymentFee: receipt.paymentFee,
      settlementFinality: receipt.finality,
      observedAt: now(),
    }, buyer);
    const rail = agreement.terms.rail as PaymentRailRef;
    const railType = rail.railId === "demos-native:DEM" ? "demos-native" : rail.railId.split(":")[0]!;
    const paymentVerdict = await verifyEvidence(paymentEvidence, { orchestrator: buyer.primaryClaim, agreement, railType, railId: rail.railId, ...cryptoDeps });
    if (!paymentVerdict.ok) throw new Error(`Payment evidence failed: ${paymentVerdict.reasons.join("; ")}`);
    const paymentLocator = await input.buyer.substrate.anchor(
      standardPaymentAnchorName(input.jobId, rail.railId, paymentPhase.index),
      paymentEvidence,
    );
    const paymentEvidenceRef = attestationRef(paymentLocator, paymentEvidence, buyer.primaryClaim);
    recordPhase(session, input.listing, currentPhaseIndex, paymentInvokedAt, { ok: true, txRefs: receipt.txRefs, attestationRef: paymentEvidenceRef });
    phaseSummary.push({ index: paymentPhase.index, kind: paymentPhase.kind, outcome: "ok", txRefs: receipt.txRefs, attestationRef: paymentEvidenceRef });

    const deliveryPhase = phaseOf(input.listing, "deliver-");
    currentPhase = deliveryPhase.kind;
    currentPhaseIndex = deliveryPhase.index;
    const deliveryInvokedAt = now();
    const delivery = await input.seller.deliver(input.jobId, input.params);
    if (delivery.attestation.requestHash !== agreement.terms.additionalTerms?.requestHash) {
      throw new Error("Delivery request binding does not match the signed agreement");
    }
    const contentHash = typeof delivery.attestation.meta?.reportHash === "string" ? delivery.attestation.meta.reportHash : delivery.attestation.resultHash;
    const deliveryEvidence = await signSettlementEvidence({
      evidenceVersion: "1",
      jobId: input.jobId,
      phase: deliveryPhase.kind as Extract<typeof deliveryPhase.kind, `deliver-${string}`>,
      outcome: "success",
      deliverableContentHash: contentHash,
      deliverableAnchor: { kind: "storage-program", locator: delivery.attestationRef },
      attestationRef: attestationRef(delivery.attestationRef, delivery.attestation, seller.primaryClaim),
      observedAt: now(),
    }, seller);
    const deliveryVerdict = await verifyEvidence(deliveryEvidence, { orchestrator: seller.primaryClaim, agreement, railType, railId: rail.railId, ...cryptoDeps });
    if (!deliveryVerdict.ok) throw new Error(`Delivery evidence failed: ${deliveryVerdict.reasons.join("; ")}`);
    const deliveryLocator = await input.seller.substrate.anchor(standardAnchorName("evidence", [input.jobId, deliveryPhase.kind]), deliveryEvidence);
    const deliveryEvidenceRef = attestationRef(deliveryLocator, deliveryEvidence, seller.primaryClaim);
    recordPhase(session, input.listing, currentPhaseIndex, deliveryInvokedAt, { ok: true, attestationRef: deliveryEvidenceRef });
    phaseSummary.push({ index: deliveryPhase.index, kind: deliveryPhase.kind, outcome: "ok", attestationRef: deliveryEvidenceRef });

    const body: AttestationBundle = {
      bundleVersion: "1",
      jobId: input.jobId,
      outcome: "completed",
      anchoredByRole: "buyer",
      listingRef: listingRef(input.listing),
      agreementRef,
      parties: [
        { role: "buyer", bundleHash: buyerBundleHash, primaryClaim: buyer.primaryClaim },
        { role: "seller", bundleHash: sellerBundleHash, primaryClaim: seller.primaryClaim },
      ],
      phaseSummary,
      vetRecords: vetRefs(session),
      settlementEvidence: evidenceRefs(session),
      recipeRegistryVersion: 1,
      railRegistryVersion: 1,
      finalisedAt: now(),
      signatures: [],
    };
    let signed = await addBundleSignature(body, buyer);
    signed = await addBundleSignature(signed, seller);
    const buyerBundleCopy = { ...signed, anchoredByRole: "buyer" as const };
    const sellerBundleCopy = { ...signed, anchoredByRole: "seller" as const };
    const [buyerVerdict, sellerVerdict] = await Promise.all([
      verifyBundle(buyerBundleCopy, { expectedRole: "buyer", ...cryptoDeps }),
      verifyBundle(sellerBundleCopy, { expectedRole: "seller", ...cryptoDeps }),
    ]);
    if (!buyerVerdict.ok || !sellerVerdict.ok || !sameCanonicalBundle(buyerBundleCopy, sellerBundleCopy)) throw new Error(`Bundle verification failed: ${buyerVerdict.reason ?? sellerVerdict.reason}`);
    const buyerBundleRef = await input.buyer.substrate.anchor(standardAnchorName("bundle", [input.jobId, "buyer"]), buyerBundleCopy);
    const sellerBundleRef = await input.seller.substrate.anchor(standardAnchorName("bundle", [input.jobId, "seller"]), sellerBundleCopy);
    await transition(input, session, "settle-completed");
    await transition(input, session, "finalised", true);
    return { agreement, agreementRef, commitment, commitmentRef, paymentEvidence, paymentEvidenceRef, deliveryEvidence, deliveryEvidenceRef, buyerBundle: buyerBundleCopy, buyerBundleRef, sellerBundle: sellerBundleCopy, sellerBundleRef, delivery, session };
  } catch (error) {
    const failureState: SessionState = currentStage === "vet" ? "vet-failed"
      : currentStage === "negotiate" ? "negotiate-failed"
      : currentStage === "commit" ? "commit-failed"
      : "settle-failed";
    const reason = (error as Error).message;
    if (!session.phaseResults.some((entry) => entry.index === currentPhaseIndex)) {
      recordPhase(session, input.listing, currentPhaseIndex, now(), { ok: false, reason, errorClass: "permanent" });
    }
    const failure: AttestationBundle = {
      bundleVersion: "1",
      jobId: input.jobId,
      outcome: "failed-perm",
      anchoredByRole: "buyer",
      listingRef: listingRef(input.listing),
      agreementRef,
      parties: [
        ...(buyerBundle ? [{ role: "buyer" as const, bundleHash: standardHash(buyerBundle, ["presentation"]), primaryClaim: buyer.primaryClaim }] : []),
        ...(sellerBundle ? [{ role: "seller" as const, bundleHash: standardHash(sellerBundle, ["presentation"]), primaryClaim: seller.primaryClaim }] : []),
      ],
      phaseSummary: [...phaseSummary, {
        index: Math.max(0, input.listing.pipeline.findIndex((phase) => phase.kind === currentPhase)),
        kind: currentPhase,
        outcome: "fail",
        errorClass: "permanent",
      }],
      vetRecords: vetRefs(session),
      settlementEvidence: evidenceRefs(session),
      recipeRegistryVersion: 1,
      railRegistryVersion: 1,
      finalisedAt: now(),
      signatures: [],
    };
    const signedFailure = await addBundleSignature(failure, buyer);
    await input.buyer.substrate.anchor(standardAnchorName("bundle", [input.jobId, "buyer"]), signedFailure);
    await transition(input, session, failureState, true);
    throw error;
  }
}
