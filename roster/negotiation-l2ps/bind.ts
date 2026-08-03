/**
 * Binding — turn a completed L2PS negotiation into the canonical, verifiable
 * artifacts the DACS settle/commit phases consume.
 *
 * The negotiation produced agreed `AuditTerms` and a signed envelope transcript.
 * This layer binds them together the way DACS-3 §8.5/§8.6 do:
 *
 *   - `lastMessageHash` — the hash of the final signed envelope (the `accept`),
 *     which is `AgreementDocument.derivedFromChannel.lastMessageHash`: the public,
 *     verifiable link from the agreement to the private transcript.
 *   - `ChannelAgreement` — a minimal AgreementDocument-shaped record binding the
 *     agreed terms, both parties' signer ids, and the channel derivation. Its
 *     `agreementHash` is what commit-agreement anchors (SR-2).
 *   - `sessionOpenParams` — the `{ repo, tier, deadline, price, jobId }` the
 *     steward's `dacs/wire/audit-negotiator.ts#makeAuditNegotiatorWork` conveys
 *     at session-open, so the negotiated outcome flows straight into settlement.
 *
 * Both parties derive the SAME `ChannelAgreement` from their own transcript view
 * (identical signed envelopes ⇒ identical hashes), so the agreementHash is a
 * mutual commitment neither side can unilaterally restate — proven by the live
 * run, where seller and buyer print matching agreementHashes.
 *
 * Anchor-safety: the agreement embeds only ENUMS, NUMBERS, IDS, and HEX HASHES —
 * never raw LLM rationale — so its canonical form is pure ASCII and won't trip
 * the storage-program non-ASCII anchoring hash-mismatch.
 */
import { createHash } from "node:crypto";
import type { AuditTerms } from "../audit-negotiator/terms.js";
import { stableStringify, type ChannelEnvelope, type Signer, type WireSig } from "./wire.js";
import { assertPositiveAmount } from "@kynesyslabs/dacs";
import {
  addAgreementSignature,
  deliverableRef,
  listingRef,
  standardHash,
  verifyAgreement,
  type AgreementDocument,
  type DacsParty,
  type Listing,
} from "../dacs/standard-profile.js";
import type { VettedParty } from "./standard-session.js";
import { isX402Rail, x402AgreementAdditionalTerms } from "../dacs/x402-production.js";
import { resolveFromDid, verify } from "../../src/identity.js";

function sha256Hex(s: string): string {
  return createHash("sha256").update(s, "utf8").digest("hex");
}

/** Hash of one full signed envelope (the wire message, signature included). */
export function envelopeHash(env: ChannelEnvelope): string {
  return sha256Hex(stableStringify(env));
}

/** Hash of the ordered signed transcript. */
export function transcriptHash(envelopes: readonly ChannelEnvelope[]): string {
  return sha256Hex(stableStringify(envelopes));
}

/** `derivedFromChannel.lastMessageHash` — the hash of the final envelope. */
export function lastMessageHash(envelopes: readonly ChannelEnvelope[]): string {
  if (envelopes.length === 0) throw new Error("bind: empty transcript has no last message");
  return envelopeHash(envelopes[envelopes.length - 1]!);
}

/** A minimal AgreementDocument (§8.5): agreed terms bound to the channel. */
export interface ChannelAgreement {
  agreementVersion: "1";
  jobId: string;
  channelId: string;
  /** Both parties' stable signer ids (ed25519 pubkey hex). */
  parties: { seller: string; buyer: string };
  /** The negotiated terms (tier × deadline × price). */
  terms: AuditTerms;
  derivedFromChannel: { channelId: string; lastMessageHash: string; transcriptHash: string };
  generatedAt: string;
}

export interface BuildAgreementInput {
  jobId: string;
  channelId: string;
  agreed: AuditTerms;
  sellerId: string;
  buyerId: string;
  envelopes: readonly ChannelEnvelope[];
  generatedAt: string;
}

/** Assemble the ChannelAgreement from a concluded negotiation. Deterministic. */
export function buildChannelAgreement(input: BuildAgreementInput): ChannelAgreement {
  return {
    agreementVersion: "1",
    jobId: input.jobId,
    channelId: input.channelId,
    parties: { seller: input.sellerId, buyer: input.buyerId },
    terms: { tier: input.agreed.tier, deadline: input.agreed.deadline, price: input.agreed.price },
    derivedFromChannel: {
      channelId: input.channelId,
      lastMessageHash: lastMessageHash(input.envelopes),
      transcriptHash: transcriptHash(input.envelopes),
    },
    generatedAt: input.generatedAt,
  };
}

/** The hash commit-agreement anchors (SR-2). Pure ASCII canonical form. */
export function agreementHash(a: ChannelAgreement): string {
  return sha256Hex(stableStringify(a));
}

/** A party's signature over the agreement hash (dual-signed per §8.5). */
export interface AgreementSignature {
  signerId: string;
  role: "seller" | "buyer";
  sig: WireSig;
}

/** Sign the agreement hash bytes with this side's signer. */
export async function signAgreement(signer: Signer, role: "seller" | "buyer", a: ChannelAgreement): Promise<AgreementSignature> {
  const bytes = new TextEncoder().encode(agreementHash(a));
  const sig = await signer.sign(bytes);
  return { signerId: signer.id, role, sig };
}

/** Verify a party's agreement signature. */
export async function verifyAgreementSignature(signer: Signer, a: ChannelAgreement, s: AgreementSignature): Promise<boolean> {
  const bytes = new TextEncoder().encode(agreementHash(a));
  return signer.verify(bytes, s.sig, s.signerId);
}

/**
 * The session-open parameters the DACS audit-negotiator wire expects — the
 * negotiated outcome, ready to convey into settlement + delivery.
 */
export interface SessionOpenParams {
  jobId: string;
  repo: string;
  tier: "quick" | "deep";
  deadline: "standard" | "rush";
  price: number;
}

export function sessionOpenParams(a: ChannelAgreement, repo: string): SessionOpenParams {
  return { jobId: a.jobId, repo, tier: a.terms.tier, deadline: a.terms.deadline, price: a.terms.price };
}

// ---------------------------------------------------------------------------
// Full DACS §8.5 binding used by the public Butler→Auditor path.
// ---------------------------------------------------------------------------

export interface BuildStandardAgreementInput {
  jobId: string;
  channelId: string;
  agreed: AuditTerms;
  listing: Listing;
  buyer: VettedParty;
  seller: VettedParty;
  envelopes: readonly ChannelEnvelope[];
  requestHash: string;
  x402Payer?: string;
  generatedAt?: number;
}

export function buildStandardAgreement(input: BuildStandardAgreementInput): AgreementDocument {
  const generatedAt = input.generatedAt ?? Date.now();
  const windowMs = (input.listing.terms.deadlineSecAfterCommit ?? 300) * 1_000;
  const amount = assertPositiveAmount(String(input.agreed.price));
  const rail = input.listing.acceptedRails?.[0];
  if (!rail) throw new Error("Standard agreement cannot bind a paid listing without an accepted rail");
  if (isX402Rail(rail) && !input.x402Payer) throw new Error("x402 RFQ agreement requires the buyer EVM payer");
  if (!isX402Rail(rail) && input.x402Payer) throw new Error("native RFQ agreement must not bind an x402 payer");
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
      price: {
        amount,
        currency: input.listing.pricing.kind === "negotiable"
          ? input.listing.pricing.bandCenter.currency
          : input.listing.pricing.kind === "fixed"
            ? input.listing.pricing.price.currency
            : input.listing.pricing.reservePrice?.currency ?? "DEM",
        unit: input.listing.pricing.kind === "negotiable"
          ? input.listing.pricing.bandCenter.unit
          : input.listing.pricing.kind === "fixed"
            ? input.listing.pricing.price.unit
            : input.listing.pricing.reservePrice?.unit,
      },
      rail,
      deadline: generatedAt + windowMs,
      additionalTerms: {
        auditTier: input.agreed.tier,
        auditDeadline: input.agreed.deadline,
        requestHash: input.requestHash,
        ...(input.x402Payer ? x402AgreementAdditionalTerms(rail, input.x402Payer, input.jobId, paymentPhaseIndex) : {}),
      },
    },
    derivedFromPattern: "rfq",
    derivedFromChannel: { subnet: input.channelId, lastMessageHash: lastMessageHash(input.envelopes) },
    generatedAt,
    signatures: [],
  };
}

export function isStandardAgreement(value: unknown): value is AgreementDocument {
  return Boolean(value && typeof value === "object" && (value as { agreementVersion?: unknown }).agreementVersion === "1" && Array.isArray((value as { parties?: unknown }).parties));
}

export function standardAgreementHash(agreement: AgreementDocument): string {
  return standardHash(agreement);
}

export function auditTermsFromStandardAgreement(agreement: AgreementDocument): AuditTerms {
  const extra = agreement.terms.additionalTerms;
  const tier = extra?.auditTier;
  const deadline = extra?.auditDeadline;
  const price = Number(agreement.terms.price.amount);
  if ((tier !== "quick" && tier !== "deep") || (deadline !== "standard" && deadline !== "rush") || !Number.isFinite(price) || price <= 0) {
    throw new Error("Standard agreement has invalid audit-specific terms");
  }
  return { tier, deadline, price };
}

export async function signStandardAgreement(agreement: AgreementDocument, party: DacsParty): Promise<AgreementDocument> {
  return addAgreementSignature(agreement, party);
}

export async function verifyStandardAgreement(
  agreement: AgreementDocument,
  listing: Listing,
  requiredRoles: Array<"buyer" | "seller"> = ["buyer", "seller"],
): Promise<{ ok: boolean; reason?: string; hash?: string }> {
  return verifyAgreement(agreement, listing, {
    resolvePublicKey: async (claim) => resolveFromDid(claim),
    verify,
    requiredRoles,
  });
}
