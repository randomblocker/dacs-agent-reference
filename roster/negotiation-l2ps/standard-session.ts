/** Standard-conformant Identify/Vet helpers for the public RFQ channel. */
import { randomBytes } from "node:crypto";
import type { AnchorAcceptance, AnchorReceipt, SubstratePort } from "../../src/ports.js";
import { resolveFromDid, verify } from "../../src/identity.js";
import {
  addBundleSignature,
  attestationRef,
  createEmptyVetRecord,
  createIdentityBundle,
  listingRef,
  standardAnchorName,
  standardHash,
  verifyIdentityBundle,
  verifyVetRecord,
  type AttestationRef,
  type BundleRequirement,
  type CompositeVerificationRecord,
  type DacsParty,
  type IdentityBundle,
  type Listing,
  type AttestationBundle,
  type PhaseType,
} from "../dacs/standard-profile.js";
import type { SecurityResearcherHistory } from "../dacs/security-researcher-vet.js";

export interface StandardSessionContext {
  party: DacsParty;
  sub: SubstratePort;
  listing: Listing;
  listingAnchorRef: string;
  /** DACS-signed session identity metadata (for example a proved Base account). */
  identityMetadata?: Record<string, unknown>;
  /** Optional live evidence sources used by Auditor-specific DACS-2 Vet. */
  securityResearcherVet?: {
    githubLoginFor(did: string): Promise<string | null>;
    historyFor(did: string): Promise<SecurityResearcherHistory>;
  };
}

export interface StandardSellerSessionContext {
  party: DacsParty;
  sub: SubstratePort;
  /** DACS-signed session identity metadata (for example a proved Base account). */
  identityMetadata?: Record<string, unknown>;
  getListing(listingAnchorRef?: string): Promise<{
    listing: Listing;
    listingAnchorRef: string;
    autoAcceptCommitment?: import("../dacs/standard-profile.js").AutoAcceptCommitment;
    autoAcceptCommitmentRef?: string;
  }>;
}

export interface VettedParty {
  bundle: IdentityBundle;
  vetRecord: CompositeVerificationRecord;
  vetRecordRef: AttestationRef;
  anchorReceipt?: AnchorReceipt | AnchorAcceptance;
}

export type VetRecordFactory = (input: {
  verifier: DacsParty;
  jobId: string;
  bundle: IdentityBundle;
  requirement: BundleRequirement;
}) => Promise<CompositeVerificationRecord>;

export type VetRecordVerifier = (input: {
  record: CompositeVerificationRecord;
  jobId: string;
  bundle: IdentityBundle;
  requirement: BundleRequirement;
  verifier: string;
}) => Promise<boolean>;

export const cryptoDeps = {
  resolvePublicKey: async (claim: string) => resolveFromDid(claim),
  verify,
};

export function sessionNonce(): string {
  return randomBytes(16).toString("hex");
}

export async function presentIdentity(
  party: DacsParty,
  nonce: string,
  metadata?: Record<string, unknown>,
): Promise<IdentityBundle> {
  return createIdentityBundle(party, { sessionNonce: nonce, ...(metadata ? { metadata } : {}) });
}

export async function verifyPresentation(bundle: IdentityBundle, nonce: string, expectedParty: string): Promise<void> {
  if (bundle.presentedBy !== expectedParty) throw new Error("identity presentation does not match the expected party");
  const verdict = await verifyIdentityBundle(bundle, { expectedNonce: nonce, ...cryptoDeps });
  if (!verdict.ok) throw new Error(`identity presentation failed: ${verdict.reason}`);
}

export async function vetAndAnchor(
  ctx: Pick<StandardSessionContext, "party" | "sub">,
  jobId: string,
  bundle: IdentityBundle,
  requirement: BundleRequirement,
  createRecord?: VetRecordFactory,
): Promise<VettedParty> {
  const vetRecord = createRecord
    ? await createRecord({ verifier: ctx.party, jobId, bundle, requirement })
    : await createEmptyVetRecord(ctx.party, { jobId, bundle, requirement });
  const name = standardAnchorName("composite", [jobId, bundle.presentedBy]);
  const receipt = ctx.sub.anchorAccepted
    ? await ctx.sub.anchorAccepted(name, vetRecord)
    : ctx.sub.anchorWithReceipt
      ? await ctx.sub.anchorWithReceipt(name, vetRecord)
      : undefined;
  const locator = receipt?.address ?? await ctx.sub.anchor(name, vetRecord);
  return {
    bundle,
    vetRecord,
    vetRecordRef: attestationRef(locator, vetRecord, ctx.party.primaryClaim),
    ...(receipt ? { anchorReceipt: receipt } : {}),
  };
}

/** Verify an exact anchor from its confirmed transaction, with a legacy read fallback. */
export async function verifyConfirmedAnchor(
  sub: SubstratePort,
  locator: string,
  value: Record<string, unknown>,
  receipt?: AnchorReceipt,
  owner?: string,
): Promise<void> {
  if (receipt && sub.resolveAnchorReceipt) {
    const resolved = await sub.resolveAnchorReceipt(receipt.txRef, owner, {
      expectedConfirmationBlock: receipt.expectedConfirmationBlock,
      transactionContent: receipt.transactionContent,
      transactionContentValueOmitted: receipt.transactionContentValueOmitted,
      anchorValue: value,
    });
    const expectedHash = standardHash(value, []);
    if (resolved.address !== locator
      || resolved.txRef.replace(/^0x/, "") !== receipt.txRef.replace(/^0x/, "")
      || resolved.contentHash !== expectedHash) {
      throw new Error("confirmed anchor receipt does not bind the declared content");
    }
    return;
  }
  const anchored = await sub.read(locator);
  if (!anchored || standardHash(anchored, []) !== standardHash(value, [])) {
    throw new Error("artifact is not read-visible at its declared anchor");
  }
}

export async function verifyAnchoredVet(
  ctx: Pick<StandardSessionContext, "sub">,
  input: {
    jobId: string;
    bundle: IdentityBundle;
    requirement: BundleRequirement;
    verifier: string;
    record: CompositeVerificationRecord;
    ref: AttestationRef;
    receipt?: AnchorReceipt | AnchorAcceptance;
    verifyRecord?: VetRecordVerifier;
  },
): Promise<void> {
  if (input.ref.anchor.kind !== "storage-program" || input.ref.signer !== input.verifier) throw new Error("vet record reference is not verifier-bound storage");
  const recordHash = standardHash(input.record, []);
  if (input.receipt && "status" in input.receipt && input.receipt.status === "accepted") {
    if (input.ref.anchor.locator !== input.receipt.address
      || input.ref.contentHash !== standardHash(input.record)
      || input.receipt.contentHash !== recordHash) {
      throw new Error("accepted Vet anchor does not bind the declared content");
    }
    // Both public name resolution and getTransactionStatus can lag the node
    // that accepted the writer's broadcast. The signed protocol frame binds
    // the exact record hash and returned address here; it deliberately does
    // not turn either eventually-consistent projection into a negotiation
    // gate. `confirmVettedParty` independently resolves consensus before the
    // gateway is allowed to move value.
  } else {
    const expected = await ctx.sub.anchorAddressFor(
      input.verifier,
      standardAnchorName("composite", [input.jobId, input.bundle.presentedBy]),
    );
    if (input.ref.anchor.locator !== expected || input.ref.contentHash !== standardHash(input.record)) {
      throw new Error("vet record reference does not match its deterministic anchor/content");
    }
    await verifyConfirmedAnchor(ctx.sub, expected, input.record as unknown as Record<string, unknown>, input.receipt, input.verifier);
  }
  const valid = input.verifyRecord
    ? await input.verifyRecord({
      record: input.record,
      jobId: input.jobId,
      bundle: input.bundle,
      requirement: input.requirement,
      verifier: input.verifier,
    })
    : await verifyVetRecord(input.record, { ...input, ...cryptoDeps });
  if (!valid) throw new Error("vet record signature, evidence or decision is invalid");
}

/** Consensus gate used before any value-moving phase. */
export async function confirmVettedParty(sub: SubstratePort, party: VettedParty): Promise<void> {
  const evidence = party.anchorReceipt;
  if (!evidence) {
    await verifyConfirmedAnchor(sub, party.vetRecordRef.anchor.locator, party.vetRecord as unknown as Record<string, unknown>);
    return;
  }
  if ("status" in evidence && evidence.status === "accepted") {
    if (!sub.confirmAcceptedAnchor) throw new Error("substrate cannot finalise an accepted Vet anchor");
    const receipt = await sub.confirmAcceptedAnchor(evidence, party.vetRecordRef.signer);
    if (receipt.address !== evidence.address || receipt.contentHash !== evidence.contentHash) {
      throw new Error("final Vet anchor differs from its accepted artifact");
    }
    return;
  }
  await verifyConfirmedAnchor(sub, party.vetRecordRef.anchor.locator, party.vetRecord as unknown as Record<string, unknown>, evidence, party.vetRecordRef.signer);
}

/** Anchor a signed buyer-owned terminal record for any fail-closed path. */
export async function anchorAbortBundle(
  ctx: StandardSessionContext,
  jobId: string,
  reason: string,
  failedPhase: PhaseType = "negotiate-rfq",
): Promise<string> {
  const self = await createIdentityBundle(ctx.party, { sessionNonce: sessionNonce() });
  const index = Math.max(0, ctx.listing.pipeline.findIndex((phase) => phase.kind === failedPhase));
  const body: AttestationBundle = {
    bundleVersion: "1",
    jobId,
    outcome: "aborted-by-self",
    anchoredByRole: "buyer",
    listingRef: listingRef(ctx.listing),
    parties: [{ role: "buyer", bundleHash: standardHash(self, ["presentation"]), primaryClaim: ctx.party.primaryClaim }],
    phaseSummary: [{ index, kind: failedPhase, outcome: "fail", errorClass: "permanent" }],
    vetRecords: [],
    settlementEvidence: [],
    recipeRegistryVersion: 1,
    railRegistryVersion: 1,
    finalisedAt: Date.now(),
    signatures: [],
  };
  // `reason` is intentionally not placed in the public bundle: error strings
  // may contain private channel text. The durable SessionRecord keeps it.
  void reason;
  const signed = await addBundleSignature(body, ctx.party);
  return ctx.sub.anchor(standardAnchorName("bundle", [jobId, "buyer"]), signed);
}
