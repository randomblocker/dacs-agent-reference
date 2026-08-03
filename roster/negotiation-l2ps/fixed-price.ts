import type { AnchorReceipt, SubstratePort } from "../../src/ports.js";
import {
  addAgreementSignature,
  attestationRef,
  createCommitment,
  deliverableRef,
  listingRef,
  requestScopeHash,
  standardAnchorName,
  standardHash,
  verifyAgreement,
  verifyAutoAcceptCommitment,
  verifyCommitment,
  verifyListing,
  type AgreementDocument,
  type AttestationRef,
  type AutoAcceptCommitment,
  type DacsParty,
  type Listing,
} from "../dacs/standard-profile.js";
import { cryptoDeps, verifyConfirmedAnchor, type VettedParty } from "./standard-session.js";
import { isX402Rail, x402AgreementAdditionalTerms } from "../dacs/x402-production.js";

export interface FixedPriceSellerRequest {
  agreement: AgreementDocument;
  requestHash: string;
  autoAcceptCommitment?: AutoAcceptCommitment;
}

/** A live seller/autosigner returns the agreement with exactly one seller signature added. */
export type FixedPriceSellerSigner = (request: FixedPriceSellerRequest) => Promise<AgreementDocument>;

export interface FixedPriceNegotiationInput {
  jobId: string;
  listing: Listing;
  listingAnchorRef: string;
  listingReceipt?: AnchorReceipt;
  buyer: VettedParty;
  seller: VettedParty;
  buyerParty: DacsParty;
  buyerSubstrate: SubstratePort;
  sellerSign: FixedPriceSellerSigner;
  autoAcceptCommitment?: AutoAcceptCommitment;
  autoAcceptCommitmentRef?: string;
  autoAcceptCommitmentReceipt?: AnchorReceipt;
  generatedAt?: number;
  /** Exact work input; only its deterministic hash is disclosed on-chain. */
  requestScope: Record<string, unknown>;
  /** Buyer EVM payer bound into an x402 agreement; forbidden on native DEM listings. */
  x402Payer?: string;
  /** Lifecycle observer invoked only after both signatures verify, before SR-2 writes. */
  onAgreementSigned?: (agreement: AgreementDocument, agreementHash: string) => void | Promise<void>;
}

export interface FixedPriceNegotiationResult {
  agreement: AgreementDocument;
  agreementHash: string;
  agreementRef: AttestationRef;
  agreementReceipt: AnchorReceipt;
  commitment: Awaited<ReturnType<typeof createCommitment>>;
  commitmentRef: AttestationRef;
  commitmentReceipt: AnchorReceipt;
  autoAcceptCommitmentRef?: string;
}

function listedPrice(listing: Listing): AgreementDocument["terms"]["price"] {
  if (listing.pricing.kind === "fixed") return listing.pricing.price;
  if (listing.pricing.kind === "negotiable") return listing.pricing.bandCenter;
  throw new Error("fixed-price negotiation cannot accept auction pricing");
}

function buildAgreement(input: FixedPriceNegotiationInput): AgreementDocument {
  const negotiation = input.listing.pipeline.filter((step) => step.kind.startsWith("negotiate-"));
  if (negotiation.length !== 1 || negotiation[0]?.kind !== "negotiate-fixed-price") {
    throw new Error("listing does not select negotiate-fixed-price");
  }
  const generatedAt = input.generatedAt ?? Date.now();
  const deadlineSec = input.listing.terms.deadlineSecAfterCommit ?? 300;
  if (!Number.isSafeInteger(deadlineSec) || deadlineSec <= 0) throw new Error("listing deadlineSecAfterCommit must be positive");
  const rail = input.listing.pipeline.some((step) => step.kind.startsWith("pay-"))
    ? input.listing.acceptedRails?.[0]
    : undefined;
  if (input.listing.pipeline.some((step) => step.kind.startsWith("pay-")) && !rail) {
    throw new Error("paid fixed-price listing has no accepted rail");
  }
  if (isX402Rail(rail) && !input.x402Payer) throw new Error("x402 fixed-price agreement requires the buyer EVM payer");
  if (!isX402Rail(rail) && input.x402Payer) throw new Error("native fixed-price agreement must not bind an x402 payer");
  const paymentPhaseIndex = input.listing.pipeline.findIndex((phase) => phase.kind === "pay-x402");
  return {
    agreementVersion: "1",
    jobId: input.jobId,
    listingRef: listingRef(input.listing),
    parties: [
      {
        role: "buyer",
        bundleHash: standardHash(input.buyer.bundle, ["presentation"]),
        primaryClaim: input.buyer.bundle.presentedBy,
        vetRecordRef: input.buyer.vetRecordRef,
      },
      {
        role: "seller",
        bundleHash: standardHash(input.seller.bundle, ["presentation"]),
        primaryClaim: input.seller.bundle.presentedBy,
        vetRecordRef: input.seller.vetRecordRef,
      },
    ],
    terms: {
      deliverable: deliverableRef(input.listing.offering.deliverable),
      price: listedPrice(input.listing),
      ...(rail ? { rail } : {}),
      deadline: generatedAt + deadlineSec * 1_000,
      additionalTerms: {
        requestHash: requestScopeHash(input.requestScope),
        ...(rail && input.x402Payer ? x402AgreementAdditionalTerms(rail, input.x402Payer, input.jobId, paymentPhaseIndex) : {}),
      },
    },
    derivedFromPattern: "fixed-price",
    generatedAt,
    signatures: [],
  };
}

function requireReceipt(receipt: AnchorReceipt | undefined, operation: string): AnchorReceipt {
  if (!receipt) throw new Error(`${operation} requires a confirmed SR-2 receipt`);
  return receipt;
}

async function anchorAgreementAndCommitment(
  sub: SubstratePort,
  agreement: AgreementDocument,
  commitment: Awaited<ReturnType<typeof createCommitment>>,
): Promise<[AnchorReceipt, AnchorReceipt]> {
  const entries = [
    { name: standardAnchorName("agreement", [agreement.jobId]), value: agreement },
    { name: standardAnchorName("commitment", [agreement.jobId]), value: commitment },
  ];
  if (sub.anchorBatchWithReceipts) {
    const receipts = await sub.anchorBatchWithReceipts(entries);
    if (receipts.length !== 2) throw new Error("fixed-price anchor batch returned an incomplete receipt set");
    return [requireReceipt(receipts[0], "agreement anchor"), requireReceipt(receipts[1], "commitment anchor")];
  }
  if (!sub.anchorWithReceipt) throw new Error("fixed-price production flow requires receipt-capable SR-2 anchoring");
  return [
    await sub.anchorWithReceipt(entries[0]!.name, entries[0]!.value),
    await sub.anchorWithReceipt(entries[1]!.name, entries[1]!.value),
  ];
}

/**
 * DACS-3 fixed-price orchestration shared by the live-co-sign and auto-accept
 * paths. The exact buyer-signed scope is sent to the seller; any seller-side
 * mutation fails before anchoring. Agreement + commitment writes use the
 * substrate's ordered batch API; Demos confirms each same-wallet nonce before
 * broadcasting its successor.
 */
export async function runFixedPriceNegotiation(
  input: FixedPriceNegotiationInput,
): Promise<FixedPriceNegotiationResult> {
  const listingVerdict = await verifyListing(input.listing, {
    now: input.generatedAt,
    ...cryptoDeps,
    readRevocation: async (listing) => {
      const name = standardAnchorName("revocation", [
        listing.seller.identity.presentedBy,
        listing.listingId,
        String(listing.listingVersion),
      ]);
      if (input.buyerSubstrate.readAnchorFor) {
        return input.buyerSubstrate.readAnchorFor(listing.seller.identity.presentedBy, name);
      }
      return input.buyerSubstrate.read(await input.buyerSubstrate.anchorAddressFor(
        listing.seller.identity.presentedBy,
        name,
      ));
    },
  });
  if (!listingVerdict.ok) throw new Error(`fixed-price listing rejected: ${listingVerdict.reason}`);
  const expectedListingRef = await input.buyerSubstrate.anchorAddressFor(
    input.listing.seller.identity.presentedBy,
    standardAnchorName("listing", [
      input.listing.seller.identity.presentedBy,
      input.listing.listingId,
      String(input.listing.listingVersion),
    ]),
  );
  if (input.listingAnchorRef !== expectedListingRef) throw new Error("listing is not in the seller's deterministic slot");
  await verifyConfirmedAnchor(
    input.buyerSubstrate,
    input.listingAnchorRef,
    input.listing as unknown as Record<string, unknown>,
    input.listingReceipt,
    input.listing.seller.identity.presentedBy,
  );
  if (input.buyer.bundle.presentedBy !== input.buyerParty.primaryClaim) throw new Error("buyer signer does not match the vetted buyer");
  if (input.seller.bundle.presentedBy !== input.listing.seller.identity.presentedBy) throw new Error("vetted seller does not own the listing");
  const auto = input.listing.terms.acceptanceModel === "auto-accept";
  if (auto !== Boolean(input.autoAcceptCommitment)) throw new Error(auto ? "auto-accept commitment is required" : "unexpected auto-accept commitment");

  if (auto) {
    if (!input.autoAcceptCommitmentRef) throw new Error("auto-accept commitment anchor is required");
    const expected = await input.buyerSubstrate.anchorAddressFor(
      input.listing.seller.identity.presentedBy,
      standardAnchorName("auto-accept", [
        input.listing.seller.identity.presentedBy,
        input.listing.listingId,
        String(input.listing.listingVersion),
      ]),
    );
    if (expected !== input.autoAcceptCommitmentRef) throw new Error("auto-accept commitment is not in the seller's deterministic slot");
    const template = await verifyAutoAcceptCommitment(input.autoAcceptCommitment!, input.listing, cryptoDeps);
    if (!template.ok) throw new Error(`auto-accept commitment rejected: ${template.reason}`);
    await verifyConfirmedAnchor(
      input.buyerSubstrate,
      expected,
      input.autoAcceptCommitment! as unknown as Record<string, unknown>,
      input.autoAcceptCommitmentReceipt,
      input.listing.seller.identity.presentedBy,
    );
  }

  let agreement = await addAgreementSignature(buildAgreement(input), input.buyerParty);
  const unsignedScopeHash = standardHash(agreement);
  const sellerSigned = await input.sellerSign({
    agreement: structuredClone(agreement),
    requestHash: requestScopeHash(input.requestScope),
    ...(input.autoAcceptCommitment ? { autoAcceptCommitment: structuredClone(input.autoAcceptCommitment) } : {}),
  });
  if (standardHash(sellerSigned) !== unsignedScopeHash) throw new Error("seller changed the buyer-signed agreement scope");
  agreement = sellerSigned;

  const provisional = await verifyAgreement(agreement, input.listing, {
    ...cryptoDeps,
    ...(input.autoAcceptCommitment ? { autoAcceptCommitment: input.autoAcceptCommitment } : {}),
  });
  if (!provisional.ok) throw new Error(`fixed-price agreement rejected: ${provisional.reason}`);
  await input.onAgreementSigned?.(structuredClone(agreement), provisional.hash!);

  const commitment = await createCommitment(input.buyerParty, agreement);
  const [agreementReceipt, commitmentReceipt] = await anchorAgreementAndCommitment(input.buyerSubstrate, agreement, commitment);
  await verifyConfirmedAnchor(input.buyerSubstrate, agreementReceipt.address, agreement as unknown as Record<string, unknown>, agreementReceipt, input.buyerParty.primaryClaim);
  await verifyConfirmedAnchor(input.buyerSubstrate, commitmentReceipt.address, commitment as unknown as Record<string, unknown>, commitmentReceipt, input.buyerParty.primaryClaim);

  const authoritative = await verifyAgreement(agreement, input.listing, {
    ...cryptoDeps,
    committedAt: commitmentReceipt.anchoredAt,
    ...(input.autoAcceptCommitment ? { autoAcceptCommitment: input.autoAcceptCommitment } : {}),
  });
  if (!authoritative.ok) throw new Error(`anchored fixed-price agreement rejected: ${authoritative.reason}`);
  if (!(await verifyCommitment(commitment, agreement, input.listing, { ...cryptoDeps, anchoredAt: commitmentReceipt.anchoredAt }))) {
    throw new Error("anchored fixed-price commitment failed verification");
  }

  return {
    agreement,
    agreementHash: authoritative.hash!,
    agreementRef: attestationRef(agreementReceipt.address, agreement, input.buyerParty.primaryClaim),
    agreementReceipt,
    commitment,
    commitmentRef: attestationRef(commitmentReceipt.address, commitment, input.buyerParty.primaryClaim),
    commitmentReceipt,
    ...(input.autoAcceptCommitmentRef ? { autoAcceptCommitmentRef: input.autoAcceptCommitmentRef } : {}),
  };
}
