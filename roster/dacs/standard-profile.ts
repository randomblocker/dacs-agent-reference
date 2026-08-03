/**
 * DACS Standard profile used by the public agent lifecycle while the SDK's
 * reduced MVP artifact types are being brought up to the normative shapes.
 *
 * The Standard is authoritative. This module deliberately reuses the SDK for
 * canonical JSON, hashes, decimal arithmetic, domain-separated payloads, and
 * SettlementEvidence semantics. Types/builders that the SDK cannot yet express
 * live here temporarily and are covered by Standard-derived tests.
 */
import {
  assertPositiveAmount,
  canonicalize,
  contentHash,
  sha256Hex,
  signedBytes,
  verifySettlementEvidence,
} from "@kynesyslabs/dacs";
import type { Signer } from "@kynesyslabs/dacs";

export type ClaimReference = string;
export type PhaseType =
  | "vet-credentials"
  | "negotiate-fixed-price"
  | "negotiate-rfq"
  | "negotiate-sealed-envelope"
  | "commit-agreement"
  | "pay-evm-erc20"
  | "pay-solana-spl"
  | "pay-cross-chain-htlc"
  | "pay-cross-chain-liquidity-tank"
  | "pay-ap2"
  | "pay-x402"
  | "pay-dem"
  | "deliver-storage-program"
  | "deliver-entitlement"
  | "deliver-attested-payload"
  | "rate";

export interface ComponentSignature {
  algorithm: "ed25519" | "ecdsa-secp256k1" | "sr1-aggregate";
  signer: ClaimReference;
  value: string;
}

export interface IdentityBundle {
  bundleVersion: "1";
  presentedBy: ClaimReference;
  presentedAt: number;
  sessionNonce?: string;
  claims: Array<{
    ref: ClaimReference;
    verifiedBy?: VerifyResultRef;
    issuedAt?: number;
    expiresAt?: number;
    metadata?: Record<string, unknown>;
  }>;
  presentation:
    | { kind: "siwd"; message: string; signature: string; address: string }
    | { kind: "per-claim"; signatures: Array<{ ref: ClaimReference; signature: string }> }
    | { kind: "session-key"; key: string; signature: string; rootBinding?: string }
    | { kind: "sr1-root"; rootClaim: ClaimReference; aggregateSignature: string };
}

export interface ClaimRequirement {
  scheme: string;
  verificationRequired: boolean;
  maxAge?: number;
  recipeVersion?: number;
  parameters?: Record<string, unknown>;
}

export interface BundleRequirement {
  requirementVersion: "1";
  required: ClaimRequirement[];
  oneOf?: ClaimRequirement[][];
  preferredPresentation?: "siwd" | "sr1-root" | "per-claim" | "session-key" | "any";
  primaryClaimSelector?: string;
}

export interface PriceTerm {
  amount: string;
  currency: string;
  unit?: string;
}

export type PricingSpec =
  | { kind: "fixed"; price: PriceTerm }
  | { kind: "negotiable"; bandCenter: PriceTerm; minPct: number; maxPct: number }
  | {
      kind: "auction";
      reservePrice?: PriceTerm;
      selectionRule: "lowest-price" | "highest-price" | "first-acceptable" | `rule-ref:${string}`;
    };

export type DeliverableSpec =
  | {
      kind: "storage-program";
      schemaUrl?: string;
      expectedSizeBytes?: number;
      accessModel?: "public" | "buyer-only" | "encrypt-to-buyer";
    }
  | { kind: "entitlement"; durationSec: number; renewable: boolean }
  | {
      kind: "attested-payload";
      payloadFormat: string;
      verificationMethod?: string | Record<string, unknown>;
      expectedSizeBytes?: number;
    }
  | { kind: "external"; description: string; verificationMethod?: string | Record<string, unknown> };

export interface DeliverableRef {
  deliverableType: DeliverableSpec["kind"];
  hash: string;
  schemaUrl?: string;
}

export interface PaymentRailRef {
  railId: string;
  railVersion?: number;
  parameters?: Record<string, unknown>;
}

export interface Listing {
  dacsVersion: "1";
  listingVersion: number;
  listingId: string;
  requiredCapabilities?: Array<"SR-1" | "SR-2" | "SR-3" | "SR-4" | "SR-5">;
  seller: {
    identity: IdentityBundle;
    displayName: string;
    publicEndpoint?: string;
  };
  offering: {
    title: string;
    description: string;
    category: string;
    tags: string[];
    deliverable: DeliverableSpec;
    extendedDescriptionUrl?: string;
    extendedDescriptionHash?: string;
  };
  buyerRequirement: BundleRequirement;
  pipeline: Array<{ kind: PhaseType; parameters?: Record<string, unknown> }>;
  pricing: PricingSpec;
  acceptedRails?: PaymentRailRef[];
  terms: {
    termsOfServiceUrl?: string;
    termsOfServiceHash?: string;
    jurisdictions?: string[];
    conflictOfLawsRule?: "buyer-jurisdiction" | "seller-jurisdiction" | `rule-ref:${string}`;
    deadlineSecAfterCommit?: number;
    acceptanceModel?: "auto-accept";
    cancellationPolicy?: "none" | "pre-commit" | "with-fee";
    retentionYears?: number;
    transcriptDisclosurePolicy?: "none" | "encrypted-anchored-recommended" | "encrypted-anchored-required";
  };
  validity: { notBefore: number; notAfter?: number };
  signature: ComponentSignature;
}

export interface ListingRevocation {
  listingId: string;
  listingVersion: number;
  listingContentHash: string;
  revokedAt: number;
  reason?: string;
  signature: ComponentSignature;
}

export interface AttestationRef {
  anchor: { kind: "storage-program" | "ipfs" | "https"; locator: string };
  contentHash: string;
  signer?: ClaimReference;
}

export interface VerifyResultRef {
  anchor: { kind: "storage-program" | "ipfs" | "https"; locator: string };
  contentHash: string;
  recipeVersion: number;
}

export interface CompositeVerificationRecord {
  recordVersion: "1";
  jobId: string;
  evaluatedParty: ClaimReference;
  bundleHash: string;
  requirementHash: string;
  freshness: VerifyResultRef[];
  supplementary: Array<{
    source: string;
    signalType: string;
    value: number | string;
    observedAt: number;
    attestation?: AttestationRef;
  }>;
  dealSpecific: VerifyResultRef[];
  overallDecision: "pass" | "fail" | "indeterminate" | "error";
  warnings?: Array<{
    claimRef: ClaimReference;
    code: "AUTHORITY_UNAVAILABLE" | "AUTHORITY_RATE_LIMITED" | "DNS_RESOLUTION_FAILED" | "TLS_HANDSHAKE_FAILED" | "RESPONSE_MALFORMED" | "RETRY_EXHAUSTED";
    retryable: boolean;
    suggestedRetryAfterMs?: number;
  }>;
  generatedAt: number;
  signature: ComponentSignature;
}

export interface ListingRef {
  listingId: string;
  version: number;
  contentHash: string;
}

/**
 * Seller-side template commitment for DACS-3 section 8.4.1 auto-accept.
 * This is a separately signed and anchored artifact. It never contains a
 * per-session agreement signature: those are produced live after the exact
 * agreement hash is known.
 */
export interface AutoAcceptCommitment {
  listingRef: ListingRef;
  listingContentHash: string;
  acceptanceModel: "auto-accept";
  validUntil: number;
  sellerSignature: ComponentSignature;
}

export interface AgreementParty {
  role: "buyer" | "seller" | "bidder-non-winning";
  bundleHash: string;
  primaryClaim: ClaimReference;
  vetRecordRef: AttestationRef;
  encryptionKey?: string;
}

export interface FeeItem {
  kind: "network" | "platform" | "processing" | "spread" | "subscription" | "other";
  collector: ClaimReference | "substrate";
  label?: string;
  fixed?: PriceTerm;
  rateBps?: number;
  toleranceBps?: number;
  recurrence?: {
    period: "daily" | "weekly" | "monthly" | "quarterly" | "annual" | { everySeconds: number };
    count?: number;
    until?: number;
  };
}

export interface FeeSchedule {
  priceBasis: "inclusive" | "exclusive";
  items: FeeItem[];
  oneOffTotal: PriceTerm;
  recurringTotal?: PriceTerm;
  minimumTermSeconds?: number;
  earlyTerminationFee?: FeeItem;
  disclosureNote?: string;
}

export interface AgreementDocument {
  agreementVersion: "1";
  jobId: string;
  listingRef: ListingRef;
  parties: AgreementParty[];
  terms: {
    deliverable: DeliverableRef;
    price: PriceTerm;
    rail?: PaymentRailRef;
    deadline: number;
    priceAnchor?: {
      asset: string;
      quoteCurrency: string;
      price: string;
      attestationRef: AttestationRef;
      observedAt: number;
      sourceUrl: string;
    };
    feeSchedule?: FeeSchedule;
    additionalTerms?: Record<string, unknown>;
  };
  derivedFromPattern: "fixed-price" | "rfq" | "sealed-envelope";
  derivedFromChannel?: { subnet: string; lastMessageHash: string };
  generatedAt: number;
  signatures: Array<{ party: ClaimReference; algorithm: ComponentSignature["algorithm"]; value: string }>;
}

export interface CommitmentRecord {
  dacsVersion: "1";
  jobId: string;
  agreementHash: string;
  listingRef: ListingRef;
  parties: ClaimReference[];
  pattern: "fixed-price" | "rfq" | "sealed-envelope";
  committedAt: number;
  signature: ComponentSignature;
}

export type ChainTxRef =
  | { kind: "evm"; chainId: number; txHash: string }
  | { kind: "solana"; cluster: "mainnet" | "devnet" | "testnet"; signature: string }
  | { kind: "demos"; txHash: string; blockNumber: number }
  | { kind: "storage-program"; address: string; writeTxHash: string }
  | { kind: "ap2"; mandateId: string; providerRef: string; protocolVersion: string }
  | { kind: "x402"; httpResource: string; paymentReceiptHash: string; settlementTxHash?: string; chainId?: number; logIndex?: number; protocolVersion: string }
  | { kind: "htlc-lock"; chainId: number; contractAddress: string; lockTxHash: string }
  | { kind: "htlc-reveal"; chainId: number; contractAddress: string; revealTxHash: string }
  | { kind: "htlc-claim"; chainId: number; contractAddress: string; claimTxHash: string }
  | { kind: "htlc-refund"; chainId: number; contractAddress: string; refundTxHash: string }
  | { kind: "liquidity-tank"; bridgeId: string; sourceChainId: number; destChainId: number; lockTxHash: string; releaseTxHash?: string; recoveryDeadline?: number };

export interface SettlementEvidence {
  evidenceVersion: "1";
  jobId: string;
  phase: Extract<PhaseType, `pay-${string}` | `deliver-${string}`>;
  outcome: "success" | "failure";
  reason?: string;
  paymentTxRefs?: ChainTxRef[];
  paymentAmount?: PriceTerm;
  paymentFee?: PriceTerm;
  deliverableContentHash?: string;
  deliverableAnchor?: { kind: string; locator: string };
  attestationRef?: AttestationRef;
  settlementFinality?: {
    model: "block-depth" | "commitment-level" | "provider-receipt" | "htlc-reveal" | "liquidity-tank" | "bft-final";
    finalityBlocks?: number;
    finalityCommitmentLevel?: "processed" | "confirmed" | "finalized";
    finalityObservedAt: number;
  };
  amendmentRefs?: AttestationRef[];
  supersedesEvidenceRef?: AttestationRef;
  observedAt: number;
  signature: ComponentSignature;
}

export interface BundlePhaseEntry {
  index: number;
  kind: PhaseType;
  outcome: "ok" | "fail";
  errorClass?: "permanent" | "transient" | "counterparty" | "substrate" | "settlement-atomicity";
  txRefs?: ChainTxRef[];
  attestationRef?: AttestationRef;
}

export interface AttestationBundle {
  bundleVersion: "1";
  jobId: string;
  outcome: "completed" | "failed-perm" | "failed-counterparty" | "failed-substrate" | "aborted-by-self" | "aborted-by-other";
  anchoredByRole: "buyer" | "seller" | "orchestrator";
  listingRef: ListingRef;
  agreementRef?: AttestationRef;
  cancellation?: { claimedPolicy: "pre-commit" };
  parties: Array<{
    role: "buyer" | "seller" | "orchestrator";
    bundleHash: string;
    primaryClaim: ClaimReference;
  }>;
  phaseSummary: BundlePhaseEntry[];
  vetRecords: AttestationRef[];
  settlementEvidence: AttestationRef[];
  amendments?: AttestationRef[];
  ratingRefs?: AttestationRef[];
  recipeRegistryVersion: number;
  railRegistryVersion: number;
  finalisedAt: number;
  signatures: Array<{ party: ClaimReference; algorithm: ComponentSignature["algorithm"]; value: string }>;
}

export type SessionState =
  | "draft"
  | "vet-pending" | "vet-completed" | "vet-failed"
  | "negotiate-pending" | "negotiate-completed" | "negotiate-failed"
  | "commit-pending" | "commit-completed" | "commit-failed"
  | "settle-pending" | "settle-asymmetric" | "settle-completed" | "settle-failed"
  | "rate-pending" | "rate-completed"
  | "finalised"
  | "aborted-by-self" | "aborted-by-other"
  | "substrate-failure-paused" | "failed-substrate";

export interface PhaseHandlerResult {
  ok: boolean;
  reason?: string;
  txRefs?: ChainTxRef[];
  explorerUrls?: string[];
  contextDelta?: Record<string, unknown>;
  attestationRef?: AttestationRef;
  errorClass?: BundlePhaseEntry["errorClass"];
}

export interface SessionRecord {
  recordVersion: "1";
  jobId: string;
  state: SessionState;
  listingRef: ListingRef;
  parties: Array<{ role: "buyer" | "seller" | "orchestrator"; bundleHash: string; primaryClaim: ClaimReference; vetRecordRef?: AttestationRef }>;
  pipeline: Array<{ kind: PhaseType; parameters?: Record<string, unknown> }>;
  phaseResults: Array<{
    index: number;
    step: { kind: PhaseType; parameters?: Record<string, unknown> };
    invokedAt: number;
    result: PhaseHandlerResult;
    contextDelta: Record<string, unknown>;
  }>;
  startedAt: number;
  lastUpdatedAt: number;
  endedAt?: number;
  recipeRegistryVersion: number;
  railRegistryVersion: number;
  amendments?: AttestationRef[];
}

export interface DacsParty {
  primaryClaim: ClaimReference;
  sign: Signer;
}

export type ResolvePublicKey = (claim: ClaimReference) => Promise<Uint8Array | null> | Uint8Array | null;
export type VerifySignature = (
  bytes: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
) => Promise<boolean> | boolean;

const SEP = {
  identity: "dacs-bundle-presentation:v1:",
  listing: "dacs-listing:v1:",
  revocation: "dacs-revocation:v1:",
  composite: "dacs-composite:v1:",
  agreement: "dacs-agreement:v1:",
  commitment: "dacs-commitment:v1:",
  evidence: "dacs-evidence:v1:",
  bundle: "dacs-bundle:v1:",
  autoAcceptCommitment: "dacs-auto-accept-commitment:v1:",
  autoAcceptInstance: "dacs-auto-accept-instance:v1:",
} as const;

const PHASES = new Set<PhaseType>([
  "vet-credentials", "negotiate-fixed-price", "negotiate-rfq", "negotiate-sealed-envelope",
  "commit-agreement", "pay-evm-erc20", "pay-solana-spl", "pay-cross-chain-htlc",
  "pay-cross-chain-liquidity-tank", "pay-ap2", "pay-x402", "pay-dem",
  "deliver-storage-program", "deliver-entitlement", "deliver-attested-payload", "rate",
]);

const CAPABILITIES = new Set(["SR-1", "SR-2", "SR-3", "SR-4", "SR-5"]);
const PRESENTATIONS = new Set(["siwd", "sr1-root", "per-claim", "session-key", "any"]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value: unknown, max = Number.MAX_SAFE_INTEGER): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= max;
}

function isOptionalNonNegativeSafeInteger(value: unknown): boolean {
  return value === undefined || (Number.isSafeInteger(value) && Number(value) >= 0);
}

function validPriceTerm(value: unknown): value is PriceTerm {
  if (!isRecord(value) || !isNonEmptyString(value.amount) || !isNonEmptyString(value.currency)) return false;
  if (value.unit !== undefined && !isNonEmptyString(value.unit)) return false;
  try {
    assertCanonicalPositive(value.amount);
    return true;
  } catch {
    return false;
  }
}

function validRequirement(value: unknown): value is BundleRequirement {
  if (!isRecord(value) || value.requirementVersion !== "1" || !Array.isArray(value.required)) return false;
  const validClaim = (claim: unknown): boolean => isRecord(claim)
    && isNonEmptyString(claim.scheme)
    && typeof claim.verificationRequired === "boolean"
    && isOptionalNonNegativeSafeInteger(claim.maxAge)
    && (claim.recipeVersion === undefined || (Number.isSafeInteger(claim.recipeVersion) && Number(claim.recipeVersion) >= 1))
    && (claim.parameters === undefined || isRecord(claim.parameters));
  if (!value.required.every(validClaim)) return false;
  if (value.oneOf !== undefined && (!Array.isArray(value.oneOf) || !value.oneOf.every((group) => Array.isArray(group) && group.length > 0 && group.every(validClaim)))) return false;
  if (value.preferredPresentation !== undefined && !PRESENTATIONS.has(String(value.preferredPresentation))) return false;
  return value.primaryClaimSelector === undefined || isNonEmptyString(value.primaryClaimSelector);
}

function validDeliverable(value: unknown): value is DeliverableSpec {
  if (!isRecord(value) || !isNonEmptyString(value.kind)) return false;
  if (value.kind === "storage-program") {
    return (value.schemaUrl === undefined || isNonEmptyString(value.schemaUrl))
      && isOptionalNonNegativeSafeInteger(value.expectedSizeBytes)
      && (value.accessModel === undefined || ["public", "buyer-only", "encrypt-to-buyer"].includes(String(value.accessModel)));
  }
  if (value.kind === "entitlement") return Number.isSafeInteger(value.durationSec) && Number(value.durationSec) > 0 && typeof value.renewable === "boolean";
  if (value.kind === "attested-payload") {
    return isNonEmptyString(value.payloadFormat)
      && (value.verificationMethod === undefined || isNonEmptyString(value.verificationMethod) || isRecord(value.verificationMethod))
      && isOptionalNonNegativeSafeInteger(value.expectedSizeBytes);
  }
  return value.kind === "external" && isNonEmptyString(value.description)
    && (value.verificationMethod === undefined || isNonEmptyString(value.verificationMethod) || isRecord(value.verificationMethod));
}

function listingSchemaReason(listing: unknown): string | undefined {
  if (!isRecord(listing)) return "listing is not an object";
  if (!Number.isInteger(listing.listingVersion) || Number(listing.listingVersion) < 1) return "invalid listingVersion";
  if (typeof listing.listingId !== "string" || !/^[A-Za-z0-9._~-]{1,128}$/.test(listing.listingId)) return "invalid listingId";
  if (listing.requiredCapabilities !== undefined && (!Array.isArray(listing.requiredCapabilities)
    || listing.requiredCapabilities.some((capability) => !CAPABILITIES.has(String(capability)))
    || new Set(listing.requiredCapabilities).size !== listing.requiredCapabilities.length)) return "invalid requiredCapabilities";
  if (!isRecord(listing.seller) || !isRecord(listing.seller.identity)
    || !isNonEmptyString(listing.seller.displayName, 200)
    || (listing.seller.publicEndpoint !== undefined && (!isNonEmptyString(listing.seller.publicEndpoint) || !/^https:\/\//i.test(listing.seller.publicEndpoint)))) return "invalid seller";
  if (!isRecord(listing.offering)
    || !isNonEmptyString(listing.offering.title, 200)
    || typeof listing.offering.description !== "string" || listing.offering.description.length > 2_000
    || !isNonEmptyString(listing.offering.category) || !/^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+$/.test(listing.offering.category)
    || !Array.isArray(listing.offering.tags) || listing.offering.tags.length > 16
    || listing.offering.tags.some((tag) => !isNonEmptyString(tag, 32))
    || !validDeliverable(listing.offering.deliverable)) return "invalid offering";
  const hasExtendedUrl = listing.offering.extendedDescriptionUrl !== undefined;
  const hasExtendedHash = listing.offering.extendedDescriptionHash !== undefined;
  if (hasExtendedUrl !== hasExtendedHash
    || (hasExtendedUrl && (!isNonEmptyString(listing.offering.extendedDescriptionUrl)
      || !/^https:\/\//i.test(listing.offering.extendedDescriptionUrl)
      || typeof listing.offering.extendedDescriptionHash !== "string"
      || !/^[0-9a-f]{64}$/i.test(listing.offering.extendedDescriptionHash)))) return "invalid extended description binding";
  if (!validRequirement(listing.buyerRequirement)) return "invalid buyerRequirement";
  if (!Array.isArray(listing.pipeline) || listing.pipeline.length === 0
    || listing.pipeline.some((step) => !isRecord(step) || !PHASES.has(step.kind as PhaseType) || (step.parameters !== undefined && !isRecord(step.parameters)))) return "pipeline contains an invalid phase";
  if (!isRecord(listing.pricing) || !isNonEmptyString(listing.pricing.kind)) return "invalid pricing";
  if (listing.pricing.kind === "fixed" && !validPriceTerm(listing.pricing.price)) return "invalid fixed pricing";
  if (listing.pricing.kind === "negotiable" && (!validPriceTerm(listing.pricing.bandCenter)
    || !Number.isSafeInteger(listing.pricing.minPct) || Number(listing.pricing.minPct) < 0 || Number(listing.pricing.minPct) >= 100
    || !Number.isSafeInteger(listing.pricing.maxPct) || Number(listing.pricing.maxPct) < 0)) return "invalid negotiable pricing";
  if (listing.pricing.kind === "auction" && (listing.pricing.reservePrice !== undefined && !validPriceTerm(listing.pricing.reservePrice)
    || typeof listing.pricing.selectionRule !== "string"
    || !/^(lowest-price|highest-price|first-acceptable|rule-ref:[0-9a-f]{64}:.+)$/i.test(listing.pricing.selectionRule))) return "invalid auction pricing";
  if (!["fixed", "negotiable", "auction"].includes(listing.pricing.kind)) return "invalid pricing kind";
  if (listing.acceptedRails !== undefined && (!Array.isArray(listing.acceptedRails) || listing.acceptedRails.some((rail) => !isRecord(rail)
    || !isNonEmptyString(rail.railId, 64)
    || (rail.railVersion !== undefined && (!Number.isSafeInteger(rail.railVersion) || Number(rail.railVersion) < 1))
    || (rail.parameters !== undefined && !isRecord(rail.parameters))))) return "invalid acceptedRails";
  if (!isRecord(listing.terms)) return "invalid terms";
  if (listing.terms.acceptanceModel !== undefined && listing.terms.acceptanceModel !== "auto-accept") return "invalid acceptanceModel";
  if (!isRecord(listing.validity) || !Number.isSafeInteger(listing.validity.notBefore) || Number(listing.validity.notBefore) < 0
    || (listing.validity.notAfter !== undefined && (!Number.isSafeInteger(listing.validity.notAfter) || Number(listing.validity.notAfter) <= Number(listing.validity.notBefore)))) return "invalid listing validity";
  if (!isRecord(listing.signature) || !["ed25519", "ecdsa-secp256k1", "sr1-aggregate"].includes(String(listing.signature.algorithm))
    || !isNonEmptyString(listing.signature.signer) || !isNonEmptyString(listing.signature.value)) return "invalid listing signature";
  return undefined;
}

function assertSafeInteger(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${name} must be a non-negative safe integer`);
}

function assertCanonicalPositive(amount: string): void {
  if (assertPositiveAmount(amount) !== amount) throw new Error("amount is not in minimal CD-1 form");
}

function decimalParts(amount: string): { units: bigint; scale: number } {
  assertCanonicalPositive(amount);
  const [whole, fraction = ""] = amount.split(".");
  return { units: BigInt(`${whole}${fraction}`), scale: fraction.length };
}

/** §8.5.2: percentage bounds round half-up at bandCenter's own precision. */
function roundedBand(listing: Extract<PricingSpec, { kind: "negotiable" }>): { low: bigint; high: bigint; scale: number } {
  const center = decimalParts(listing.bandCenter.amount);
  const halfUp = (numerator: bigint): bigint => {
    const quotient = numerator / 100n;
    return numerator % 100n >= 50n ? quotient + 1n : quotient;
  };
  return {
    low: halfUp(center.units * BigInt(100 - listing.minPct)),
    high: halfUp(center.units * BigInt(100 + listing.maxPct)),
    scale: center.scale,
  };
}

function compareDecimalToScaled(amount: string, scaled: bigint, scale: number): number {
  const candidate = decimalParts(amount);
  const left = candidate.units * (10n ** BigInt(scale));
  const right = scaled * (10n ** BigInt(candidate.scale));
  return left < right ? -1 : left > right ? 1 : 0;
}

function without<T extends object>(value: T, fields: readonly string[]): Record<string, unknown> {
  return Object.fromEntries(Object.entries(value).filter(([key, item]) => !fields.includes(key) && item !== undefined));
}

export function standardHash(value: object, omit: readonly string[] = ["signature", "signatures"]): string {
  return sha256Hex(canonicalize(without(value, omit)));
}

/** Content binding for the concrete work request carried outside public DACS artifacts. */
export function requestScopeHash(scope: Record<string, unknown>): string {
  const encode = (value: unknown): unknown => {
    if (value === null) return { t: "null" };
    if (typeof value === "string") return { t: "string", v: value };
    if (typeof value === "boolean") return { t: "boolean", v: value };
    if (typeof value === "number") {
      if (!Number.isFinite(value)) throw new Error("work request contains a non-finite number");
      return { t: "number", v: String(value) };
    }
    if (Array.isArray(value)) return { t: "array", v: value.map(encode) };
    if (value && typeof value === "object") {
      return {
        t: "object",
        v: Object.entries(value as Record<string, unknown>)
          .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
          .map(([key, item]) => [key, encode(item)]),
      };
    }
    throw new Error("work request contains an unsupported value");
  };
  return standardHash({ request: encode(scope) }, []);
}

function encodeSignature(value: Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}

function decodeSignature(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "base64url"));
}

async function signHash(party: DacsParty, separator: string, hash: string): Promise<ComponentSignature> {
  return {
    algorithm: "ed25519",
    signer: party.primaryClaim,
    value: encodeSignature(await party.sign(signedBytes(separator, hash))),
  };
}

async function verifyHash(
  signature: ComponentSignature | { party: string; algorithm: "ed25519"; value: string },
  separator: string,
  hash: string,
  resolve: ResolvePublicKey,
  verify: VerifySignature,
): Promise<boolean> {
  const claim = "signer" in signature ? signature.signer : signature.party;
  const key = await resolve(claim);
  if (!key || key.length !== 32 || signature.algorithm !== "ed25519") return false;
  try {
    return await verify(signedBytes(separator, hash), decodeSignature(signature.value), key);
  } catch {
    return false;
  }
}

export function emptyRequirement(): BundleRequirement {
  return { requirementVersion: "1", required: [], preferredPresentation: "per-claim" };
}

export async function createIdentityBundle(
  party: DacsParty,
  input: { presentedAt?: number; sessionNonce?: string; metadata?: Record<string, unknown> } = {},
): Promise<IdentityBundle> {
  if (input.sessionNonce !== undefined && !/^[0-9a-f]{32,}$/i.test(input.sessionNonce)) {
    throw new Error("sessionNonce must carry at least 128 bits as hex");
  }
  const unsigned = {
    bundleVersion: "1" as const,
    presentedBy: party.primaryClaim,
    presentedAt: input.presentedAt ?? Date.now(),
    sessionNonce: input.sessionNonce,
    claims: [{ ref: party.primaryClaim, metadata: input.metadata }],
  };
  assertSafeInteger(unsigned.presentedAt, "presentedAt");
  const hash = standardHash(unsigned, []);
  const signature = encodeSignature(await party.sign(signedBytes(SEP.identity, hash)));
  return {
    ...unsigned,
    presentation: { kind: "per-claim", signatures: [{ ref: party.primaryClaim, signature }] },
  };
}

export async function verifyIdentityBundle(
  bundle: IdentityBundle,
  input: { expectedNonce?: string; resolvePublicKey: ResolvePublicKey; verify: VerifySignature },
): Promise<{ ok: boolean; reason?: string; bundleHash?: string }> {
  if (!isRecord(bundle)) return { ok: false, reason: "IdentityBundle is not an object" };
  if (bundle.bundleVersion !== "1") return { ok: false, reason: "unsupported IdentityBundle version" };
  if (!isNonEmptyString(bundle.presentedBy) || !Number.isSafeInteger(bundle.presentedAt) || bundle.presentedAt < 0) return { ok: false, reason: "invalid identity presenter or presentedAt" };
  if (!Array.isArray(bundle.claims) || bundle.claims.length === 0
    || bundle.claims.some((claim) => !isRecord(claim) || !isNonEmptyString(claim.ref))
    || new Set(bundle.claims.map((claim) => claim.ref)).size !== bundle.claims.length) return { ok: false, reason: "claims must be non-empty, shaped and unique" };
  if (!bundle.claims.some((claim) => claim.ref === bundle.presentedBy)) return { ok: false, reason: "presentedBy is not in claims" };
  if (input.expectedNonce !== undefined && bundle.sessionNonce !== input.expectedNonce) return { ok: false, reason: "session nonce mismatch" };
  if (input.expectedNonce !== undefined && !bundle.sessionNonce) return { ok: false, reason: "session nonce missing" };
  if (!isRecord(bundle.presentation) || bundle.presentation.kind !== "per-claim" || !Array.isArray(bundle.presentation.signatures)
    || bundle.presentation.signatures.some((signature) => !isRecord(signature) || !isNonEmptyString(signature.ref) || !isNonEmptyString(signature.signature))) {
    return { ok: false, reason: "unsupported or invalid presentation" };
  }
  const scope = without(bundle, ["presentation"]);
  const hash = standardHash(scope, []);
  for (const claim of bundle.claims) {
    const signature = bundle.presentation.signatures.find((entry) => entry.ref === claim.ref);
    if (!signature) return { ok: false, reason: `claim ${claim.ref} has no presentation signature` };
    const key = await input.resolvePublicKey(claim.ref);
    if (!key || key.length !== 32) return { ok: false, reason: `claim ${claim.ref} key is unresolvable` };
    let valid = false;
    try {
      valid = await input.verify(signedBytes(SEP.identity, hash), decodeSignature(signature.signature), key);
    } catch {
      valid = false;
    }
    if (!valid) return { ok: false, reason: `claim ${claim.ref} presentation signature is invalid` };
  }
  return { ok: true, bundleHash: hash };
}

export function deliverableRef(spec: DeliverableSpec): DeliverableRef {
  return {
    deliverableType: spec.kind,
    hash: sha256Hex(canonicalize(spec)),
    schemaUrl: spec.kind === "storage-program" ? spec.schemaUrl : undefined,
  };
}

export function listingRef(listing: Listing): ListingRef {
  return { listingId: listing.listingId, version: listing.listingVersion, contentHash: standardHash(listing) };
}

export async function signListing(body: Omit<Listing, "signature">, party: DacsParty): Promise<Listing> {
  if (body.seller.identity.presentedBy !== party.primaryClaim) throw new Error("listing signer is not the seller identity");
  return { ...body, signature: await signHash(party, SEP.listing, standardHash(body, [])) };
}

export async function createListingRevocation(
  listing: Listing,
  party: DacsParty,
  input: { revokedAt?: number; reason?: string } = {},
): Promise<ListingRevocation> {
  if (listing.signature.signer !== party.primaryClaim) throw new Error("revocation signer must match the listing signer");
  return createScopedListingRevocation({
    listingId: listing.listingId,
    listingVersion: listing.listingVersion,
    listingContentHash: standardHash(listing),
  }, party, input);
}

/**
 * Build the same owner-signed revocation marker for any already-verified
 * listing profile, including the pinned legacy SDK shape.
 */
export async function createScopedListingRevocation(
  listing: Pick<ListingRevocation, "listingId" | "listingVersion" | "listingContentHash">,
  party: DacsParty,
  input: { revokedAt?: number; reason?: string } = {},
): Promise<ListingRevocation> {
  if (!/^[A-Za-z0-9._~-]{1,128}$/.test(listing.listingId)) throw new Error("revocation listingId is invalid");
  if (!Number.isSafeInteger(listing.listingVersion) || listing.listingVersion < 1) {
    throw new Error("revocation listingVersion must be a positive integer");
  }
  if (!/^[0-9a-f]{64}$/i.test(listing.listingContentHash)) {
    throw new Error("revocation listingContentHash must be sha256 hex");
  }
  if (input.reason !== undefined && (input.reason.length === 0 || input.reason.length > 256)) {
    throw new Error("revocation reason must contain 1-256 characters");
  }
  const body = {
    listingId: listing.listingId,
    listingVersion: listing.listingVersion,
    listingContentHash: listing.listingContentHash.toLowerCase(),
    revokedAt: input.revokedAt ?? Date.now(),
    ...(input.reason === undefined ? {} : { reason: input.reason }),
  };
  assertSafeInteger(body.revokedAt, "revokedAt");
  return { ...body, signature: await signHash(party, SEP.revocation, standardHash(body, [])) };
}

export async function verifyScopedListingRevocation(
  marker: unknown,
  expected: Pick<ListingRevocation, "listingId" | "listingVersion" | "listingContentHash">
    & { signer: ClaimReference },
  input: { resolvePublicKey: ResolvePublicKey; verify: VerifySignature },
): Promise<boolean> {
  if (!isRecord(marker) || marker.listingId !== expected.listingId || marker.listingVersion !== expected.listingVersion
    || marker.listingContentHash !== expected.listingContentHash || !Number.isSafeInteger(marker.revokedAt) || Number(marker.revokedAt) < 0
    || (marker.reason !== undefined && typeof marker.reason !== "string") || !isRecord(marker.signature)) return false;
  const signature = marker.signature as unknown as ComponentSignature;
  return signature.signer === expected.signer
    && await verifyHash(signature, SEP.revocation, standardHash(marker), input.resolvePublicKey, input.verify);
}

async function verifyListingRevocation(
  marker: unknown,
  listing: Listing,
  input: { resolvePublicKey: ResolvePublicKey; verify: VerifySignature },
): Promise<boolean> {
  return verifyScopedListingRevocation(marker, {
    listingId: listing.listingId,
    listingVersion: listing.listingVersion,
    listingContentHash: standardHash(listing),
    signer: listing.signature.signer,
  }, input);
}

export async function verifyListing(
  listing: Listing,
  input: {
    now?: number;
    resolvePublicKey: ResolvePublicKey;
    verify: VerifySignature;
    /** Resolve the owner-scoped revocation slot. A present marker is validated before it is honoured. */
    readRevocation?: (listing: Listing) => Promise<Record<string, unknown> | null>;
  },
): Promise<{ ok: boolean; reason?: string; ref?: ListingRef }> {
  const now = input.now ?? Date.now();
  // DACS-1 §6.3.4 reader validation order. Keep these gates ordered: schema,
  // major, window, canonical signature, revocation, identity, pipeline, rails,
  // and finally signer control through the seller bundle.
  const schemaReason = listingSchemaReason(listing);
  if (schemaReason) return { ok: false, reason: schemaReason };
  if (listing.dacsVersion !== "1") return { ok: false, reason: "unsupported DACS major" };
  if (now < listing.validity.notBefore || (listing.validity.notAfter !== undefined && now > listing.validity.notAfter)) return { ok: false, reason: "listing is outside its validity window" };
  try {
    if (Buffer.byteLength(canonicalize(listing), "utf8") > 16_384) return { ok: false, reason: "listing exceeds the 16KB canonical size cap" };
  } catch {
    return { ok: false, reason: "listing is not canonically encodable" };
  }
  if (!(await verifyHash(listing.signature, SEP.listing, standardHash(listing), input.resolvePublicKey, input.verify))) return { ok: false, reason: "listing signature invalid" };
  if (input.readRevocation) {
    const marker = await input.readRevocation(listing);
    if (marker && await verifyListingRevocation(marker, listing, input)) return { ok: false, reason: "listing version is revoked" };
    if (marker) return { ok: false, reason: "listing revocation slot contains an invalid marker" };
  }
  const identity = await verifyIdentityBundle(listing.seller.identity, {
    resolvePublicKey: input.resolvePublicKey,
    verify: input.verify,
  });
  if (!identity.ok) return { ok: false, reason: `seller identity invalid: ${identity.reason}` };
  // The current advertised roster profile intentionally supports one payment
  // and one delivery invocation. PIPE-5 repetition remains fail-closed until
  // the orchestrator can execute and independently evidence every invocation.
  if (new Set(listing.pipeline.map((step) => step.kind)).size !== listing.pipeline.length) return { ok: false, reason: "pipeline contains duplicate phases" };
  const negotiation = listing.pipeline.filter((step) => step.kind.startsWith("negotiate-"));
  const commitIndex = listing.pipeline.findIndex((step) => step.kind === "commit-agreement");
  const negotiationIndex = listing.pipeline.findIndex((step) => step.kind.startsWith("negotiate-"));
  if (negotiation.length !== 1 || commitIndex !== negotiationIndex + 1) return { ok: false, reason: "pipeline must contain one negotiate phase immediately followed by commit" };
  if (listing.terms.acceptanceModel === "auto-accept" && negotiation[0]?.kind !== "negotiate-fixed-price") {
    return { ok: false, reason: "auto-accept is valid only for negotiate-fixed-price" };
  }
  if (!listing.pipeline.some((step) => step.kind.startsWith("deliver-"))) return { ok: false, reason: "pipeline has no delivery phase" };
  const payment = listing.pipeline.filter((step) => step.kind.startsWith("pay-"));
  const delivery = listing.pipeline.filter((step) => step.kind.startsWith("deliver-"));
  if (payment.length > 1 || delivery.length !== 1) return { ok: false, reason: "pipeline must contain at most one payment and exactly one delivery phase" };
  if (listing.pipeline.some((step) => step.kind.startsWith("pay-")) && (!listing.acceptedRails || listing.acceptedRails.length === 0)) return { ok: false, reason: "payment pipeline has no accepted rail" };
  if (listing.acceptedRails && (listing.acceptedRails.some((rail) => !rail.railId) || new Set(listing.acceptedRails.map((rail) => rail.railId)).size !== listing.acceptedRails.length)) return { ok: false, reason: "accepted rails are invalid or duplicated" };
  const paymentRail = payment[0]?.parameters?.rail;
  if (payment[0] && (typeof paymentRail !== "string" || !listing.acceptedRails?.some((rail) => rail.railId === paymentRail))) {
    return { ok: false, reason: "payment phase must bind one accepted rail by railId" };
  }
  if (payment[0]?.kind === "pay-dem" && !listing.acceptedRails?.some((rail) => rail.railId === "demos-native:DEM")) return { ok: false, reason: "pay-dem pipeline has no demos-native:DEM rail" };
  if (payment[0]?.kind === "pay-x402" && !listing.acceptedRails?.some((rail) => rail.railId.startsWith("x402"))) return { ok: false, reason: "pay-x402 pipeline has no x402 rail" };
  const amount = listing.pricing.kind === "fixed" ? listing.pricing.price.amount : listing.pricing.kind === "negotiable" ? listing.pricing.bandCenter.amount : listing.pricing.reservePrice?.amount;
  try {
    if (amount !== undefined) assertCanonicalPositive(amount);
    if (listing.pricing.kind === "negotiable" && roundedBand(listing.pricing).low <= 0n) throw new Error("rounded lower bound is not positive");
  } catch {
    return { ok: false, reason: "pricing amount is not canonical positive CD-1" };
  }
  if (listing.pricing.kind === "negotiable" && (!Number.isSafeInteger(listing.pricing.minPct) || listing.pricing.minPct < 0 || listing.pricing.minPct >= 100 || !Number.isSafeInteger(listing.pricing.maxPct) || listing.pricing.maxPct < 0)) return { ok: false, reason: "invalid negotiable price band" };
  if (!listing.seller.identity.claims.some((claim) => claim.ref === listing.signature.signer)) return { ok: false, reason: "listing signer is absent from seller identity" };
  return { ok: true, ref: listingRef(listing) };
}

export function attestationRef(locator: string, value: object, signer?: string): AttestationRef {
  return { anchor: { kind: "storage-program", locator }, contentHash: standardHash(value), signer };
}

export async function createEmptyVetRecord(
  party: DacsParty,
  input: { jobId: string; bundle: IdentityBundle; requirement: BundleRequirement; generatedAt?: number },
): Promise<CompositeVerificationRecord> {
  if (input.requirement.required.length > 0 || (input.requirement.oneOf?.length ?? 0) > 0) {
    throw new Error("empty Vet is valid only for an empty BundleRequirement");
  }
  return createVetRecord(party, {
    ...input,
    freshness: [],
    supplementary: [],
    dealSpecific: [],
    overallDecision: "pass",
  });
}

/**
 * Build and sign a DACS-2 CompositeVerificationRecord from evidence evaluated
 * by the verifier. Policy-specific code is responsible for producing the
 * evidence and decision; this shared helper binds it to the exact identity
 * presentation, BundleRequirement and job.
 */
export async function createVetRecord(
  party: DacsParty,
  input: {
    jobId: string;
    bundle: IdentityBundle;
    requirement: BundleRequirement;
    freshness?: CompositeVerificationRecord["freshness"];
    supplementary?: CompositeVerificationRecord["supplementary"];
    dealSpecific?: CompositeVerificationRecord["dealSpecific"];
    overallDecision: CompositeVerificationRecord["overallDecision"];
    warnings?: CompositeVerificationRecord["warnings"];
    generatedAt?: number;
  },
): Promise<CompositeVerificationRecord> {
  const generatedAt = input.generatedAt ?? Date.now();
  if (!Number.isSafeInteger(generatedAt) || generatedAt < 0) throw new Error("Vet generatedAt is invalid");
  if (!["pass", "fail", "indeterminate", "error"].includes(input.overallDecision)) {
    throw new Error("Vet overallDecision is invalid");
  }
  const supplementary = input.supplementary ?? [];
  if (supplementary.some((signal) =>
    !signal.source
    || !signal.signalType
    || !Number.isSafeInteger(signal.observedAt)
    || signal.observedAt < 0
    || (typeof signal.value !== "number" && typeof signal.value !== "string")
  )) {
    throw new Error("Vet supplementary signal is invalid");
  }
  const body = {
    recordVersion: "1" as const,
    jobId: input.jobId,
    evaluatedParty: input.bundle.presentedBy,
    bundleHash: standardHash(input.bundle, ["presentation"]),
    requirementHash: sha256Hex(canonicalize(input.requirement)),
    freshness: input.freshness ?? [],
    supplementary,
    dealSpecific: input.dealSpecific ?? [],
    overallDecision: input.overallDecision,
    ...(input.warnings ? { warnings: input.warnings } : {}),
    generatedAt,
  };
  return { ...body, signature: await signHash(party, SEP.composite, standardHash(body, [])) };
}

export async function verifyVetRecord(
  record: CompositeVerificationRecord,
  input: { jobId: string; bundle: IdentityBundle; requirement: BundleRequirement; verifier: string; resolvePublicKey: ResolvePublicKey; verify: VerifySignature },
): Promise<boolean> {
  return record.recordVersion === "1" &&
    record.jobId === input.jobId &&
    record.evaluatedParty === input.bundle.presentedBy &&
    record.bundleHash === standardHash(input.bundle, ["presentation"]) &&
    record.requirementHash === sha256Hex(canonicalize(input.requirement)) &&
    record.overallDecision === "pass" &&
    record.signature.signer === input.verifier &&
    await verifyHash(record.signature, SEP.composite, standardHash(record), input.resolvePublicKey, input.verify);
}

export async function addAgreementSignature(agreement: AgreementDocument, party: DacsParty): Promise<AgreementDocument> {
  if (!agreement.parties.some((entry) => entry.primaryClaim === party.primaryClaim)) throw new Error("agreement signer is not a party");
  const hash = standardHash(agreement);
  const signature = await signHash(party, SEP.agreement, hash);
  return { ...agreement, signatures: [...agreement.signatures.filter((entry) => entry.party !== party.primaryClaim), { party: party.primaryClaim, algorithm: "ed25519", value: signature.value }] };
}

/** Hash of the unsigned auto-accept template scope. */
export function autoAcceptCommitmentHash(commitment: AutoAcceptCommitment): string {
  return standardHash(commitment, ["sellerSignature"]);
}

/** Build the separately anchored seller template commitment (§8.4.1). */
export async function createAutoAcceptCommitment(
  listing: Listing,
  seller: DacsParty,
  validUntil: number,
  now = Date.now(),
): Promise<AutoAcceptCommitment> {
  if (listing.terms.acceptanceModel !== "auto-accept") throw new Error("listing does not declare auto-accept");
  if (listing.pipeline.filter((step) => step.kind.startsWith("negotiate-")).length !== 1
    || !listing.pipeline.some((step) => step.kind === "negotiate-fixed-price")) {
    throw new Error("auto-accept requires exactly one negotiate-fixed-price phase");
  }
  if (listing.seller.identity.presentedBy !== seller.primaryClaim || listing.signature.signer !== seller.primaryClaim) {
    throw new Error("auto-accept signer is not the listing seller");
  }
  if (!Number.isSafeInteger(validUntil) || validUntil <= now) throw new Error("auto-accept validUntil must be in the future");
  if (listing.validity.notAfter !== undefined && validUntil > listing.validity.notAfter) {
    throw new Error("auto-accept validity exceeds the listing validity window");
  }
  const body = {
    listingRef: listingRef(listing),
    listingContentHash: standardHash(listing),
    acceptanceModel: "auto-accept" as const,
    validUntil,
  };
  return { ...body, sellerSignature: await signHash(seller, SEP.autoAcceptCommitment, standardHash(body, [])) };
}

/** Verify the template both provisionally and, when supplied, at commit time. */
export async function verifyAutoAcceptCommitment(
  commitment: AutoAcceptCommitment,
  listing: Listing,
  input: {
    now?: number;
    committedAt?: number;
    resolvePublicKey: ResolvePublicKey;
    verify: VerifySignature;
  },
): Promise<{ ok: boolean; reason?: string; hash?: string }> {
  const now = input.now ?? Date.now();
  if (listing.terms.acceptanceModel !== "auto-accept") return { ok: false, reason: "listing does not declare auto-accept" };
  if (commitment.acceptanceModel !== "auto-accept") return { ok: false, reason: "invalid auto-accept model" };
  if (!Number.isSafeInteger(commitment.validUntil) || commitment.validUntil < 0) return { ok: false, reason: "invalid auto-accept validity" };
  if (input.committedAt === undefined) {
    if (now > commitment.validUntil) return { ok: false, reason: "auto-accept commitment is expired" };
  } else if (!Number.isSafeInteger(input.committedAt) || input.committedAt < 0 || input.committedAt > commitment.validUntil) {
    return { ok: false, reason: "agreement committed after auto-accept expiry" };
  }
  if (canonicalize(commitment.listingRef) !== canonicalize(listingRef(listing))
    || commitment.listingContentHash !== standardHash(listing)) {
    return { ok: false, reason: "auto-accept commitment does not bind this listing" };
  }
  if (commitment.sellerSignature.signer !== listing.seller.identity.presentedBy
    || commitment.sellerSignature.signer !== listing.signature.signer) {
    return { ok: false, reason: "auto-accept commitment signer is not the listing seller" };
  }
  const hash = autoAcceptCommitmentHash(commitment);
  if (!(await verifyHash(commitment.sellerSignature, SEP.autoAcceptCommitment, hash, input.resolvePublicKey, input.verify))) {
    return { ok: false, reason: "auto-accept commitment signature invalid" };
  }
  return { ok: true, hash };
}

/** Add the live seller signature bound to this exact agreement + template. */
export async function addAutoAcceptInstanceSignature(
  agreement: AgreementDocument,
  commitment: AutoAcceptCommitment,
  seller: DacsParty,
): Promise<AgreementDocument> {
  const sellerParty = agreement.parties.find((party) => party.role === "seller");
  if (sellerParty?.primaryClaim !== seller.primaryClaim || commitment.sellerSignature.signer !== seller.primaryClaim) {
    throw new Error("auto-accept signer is not the agreement seller");
  }
  const payload = new TextEncoder().encode(`${SEP.autoAcceptInstance}${standardHash(agreement)}${autoAcceptCommitmentHash(commitment)}`);
  const value = encodeSignature(await seller.sign(payload));
  return {
    ...agreement,
    signatures: [
      ...agreement.signatures.filter((entry) => entry.party !== seller.primaryClaim),
      { party: seller.primaryClaim, algorithm: "ed25519", value },
    ],
  };
}

async function verifyAutoAcceptInstanceSignature(
  signature: AgreementDocument["signatures"][number],
  agreementHash: string,
  commitment: AutoAcceptCommitment,
  input: { resolvePublicKey: ResolvePublicKey; verify: VerifySignature },
): Promise<boolean> {
  const key = await input.resolvePublicKey(signature.party);
  if (!key || key.length !== 32 || signature.algorithm !== "ed25519") return false;
  const payload = new TextEncoder().encode(`${SEP.autoAcceptInstance}${agreementHash}${autoAcceptCommitmentHash(commitment)}`);
  try {
    return await input.verify(payload, decodeSignature(signature.value), key);
  } catch {
    return false;
  }
}

export async function verifyAgreement(
  agreement: AgreementDocument,
  listing: Listing,
  input: {
    resolvePublicKey: ResolvePublicKey;
    verify: VerifySignature;
    requiredRoles?: Array<AgreementParty["role"]>;
    autoAcceptCommitment?: AutoAcceptCommitment;
    committedAt?: number;
    now?: number;
  },
): Promise<{ ok: boolean; reason?: string; hash?: string }> {
  if (agreement.agreementVersion !== "1") return { ok: false, reason: "unsupported agreement version" };
  if (!Number.isSafeInteger(agreement.generatedAt) || !Number.isSafeInteger(agreement.terms.deadline) || agreement.terms.deadline < agreement.generatedAt) return { ok: false, reason: "invalid agreement timing" };
  const buyerParties = agreement.parties.filter((party) => party.role === "buyer");
  const sellerParties = agreement.parties.filter((party) => party.role === "seller");
  if (buyerParties.length !== 1 || sellerParties.length !== 1) return { ok: false, reason: "agreement requires exactly one buyer and seller" };
  if (new Set(agreement.parties.map((party) => party.primaryClaim)).size !== agreement.parties.length) return { ok: false, reason: "agreement party claims are not unique" };
  if (agreement.parties.some((party) => !party.bundleHash || !party.vetRecordRef?.contentHash)) return { ok: false, reason: "agreement party identity/vet binding is incomplete" };
  const ref = listingRef(listing);
  if (canonicalize(agreement.listingRef) !== canonicalize(ref)) return { ok: false, reason: "agreement listing reference mismatch" };
  const pattern = listing.pipeline.find((step) => step.kind.startsWith("negotiate-"))?.kind.replace("negotiate-", "");
  if (agreement.derivedFromPattern !== pattern) return { ok: false, reason: "agreement negotiation pattern mismatch" };
  const expectedDeliverable = deliverableRef(listing.offering.deliverable);
  if (canonicalize(agreement.terms.deliverable) !== canonicalize(expectedDeliverable)) return { ok: false, reason: "agreement deliverable mismatch" };
  const listingCurrency = listing.pricing.kind === "fixed" ? listing.pricing.price.currency : listing.pricing.kind === "negotiable" ? listing.pricing.bandCenter.currency : listing.pricing.reservePrice?.currency;
  if (listingCurrency !== agreement.terms.price.currency) return { ok: false, reason: "agreement currency mismatch" };
  if (listing.pricing.kind === "fixed" && canonicalize(listing.pricing.price) !== canonicalize(agreement.terms.price)) return { ok: false, reason: "fixed price mismatch" };
  try {
    assertCanonicalPositive(agreement.terms.price.amount);
    if (listing.pricing.kind === "negotiable") {
      if (listing.pricing.bandCenter.unit !== agreement.terms.price.unit) return { ok: false, reason: "negotiated price unit mismatch" };
      if (agreement.derivedFromPattern === "fixed-price") {
        if (canonicalize(agreement.terms.price) !== canonicalize(listing.pricing.bandCenter)) return { ok: false, reason: "fixed-price negotiation must equal the negotiable listing center" };
      } else {
        const band = roundedBand(listing.pricing);
        if (compareDecimalToScaled(agreement.terms.price.amount, band.low, band.scale) < 0
          || compareDecimalToScaled(agreement.terms.price.amount, band.high, band.scale) > 0) {
          return { ok: false, reason: "negotiated price is outside the rounded listing band" };
        }
      }
    }
  } catch {
    return { ok: false, reason: "agreement price is not canonical positive CD-1" };
  }
  const hasPay = listing.pipeline.some((step) => step.kind.startsWith("pay-"));
  if (hasPay !== (agreement.terms.rail !== undefined)) return { ok: false, reason: "agreement rail presence mismatch" };
  if (agreement.terms.rail && !listing.acceptedRails?.some((rail) => canonicalize(rail) === canonicalize(agreement.terms.rail))) return { ok: false, reason: "agreement rail was not accepted by listing" };
  const requiredRoles = input.requiredRoles ?? ["buyer", "seller"];
  const required = agreement.parties.filter((party) => requiredRoles.includes(party.role));
  const hash = standardHash(agreement);
  for (const party of required) {
    const signature = agreement.signatures.find((entry) => entry.party === party.primaryClaim);
    if (!signature) return { ok: false, reason: `missing or invalid ${party.role} agreement signature` };
    if (party.role === "seller" && listing.terms.acceptanceModel === "auto-accept") {
      const commitment = input.autoAcceptCommitment;
      if (!commitment) return { ok: false, reason: "auto-accept commitment is required" };
      const template = await verifyAutoAcceptCommitment(commitment, listing, {
        now: input.now,
        committedAt: input.committedAt,
        resolvePublicKey: input.resolvePublicKey,
        verify: input.verify,
      });
      if (!template.ok || !(await verifyAutoAcceptInstanceSignature(signature, hash, commitment, input))) {
        return { ok: false, reason: `missing or invalid ${party.role} auto-accept instance signature` };
      }
    } else if (!(await verifyHash(signature, SEP.agreement, hash, input.resolvePublicKey, input.verify))) {
      return { ok: false, reason: `missing or invalid ${party.role} agreement signature` };
    }
  }
  return { ok: true, hash };
}

export async function createCommitment(
  orchestrator: DacsParty,
  agreement: AgreementDocument,
  committedAt = Date.now(),
): Promise<CommitmentRecord> {
  const body = {
    dacsVersion: "1" as const,
    jobId: agreement.jobId,
    agreementHash: standardHash(agreement),
    listingRef: agreement.listingRef,
    parties: agreement.parties.filter((party) => party.role !== "bidder-non-winning").map((party) => party.primaryClaim),
    pattern: agreement.derivedFromPattern,
    committedAt,
  };
  return { ...body, signature: await signHash(orchestrator, SEP.commitment, standardHash(body, [])) };
}

export async function verifyCommitment(
  commitment: CommitmentRecord,
  agreement: AgreementDocument,
  listing: Listing,
  input: { resolvePublicKey: ResolvePublicKey; verify: VerifySignature; anchoredAt?: number },
): Promise<boolean> {
  const deadlineWindow = listing.terms.deadlineSecAfterCommit;
  const authoritativeCommittedAt = input.anchoredAt ?? commitment.committedAt;
  const expectedParties = agreement.parties.filter((party) => party.role !== "bidder-non-winning").map((party) => party.primaryClaim).sort();
  return commitment.dacsVersion === "1" &&
    commitment.jobId === agreement.jobId &&
    commitment.agreementHash === standardHash(agreement) &&
    canonicalize(commitment.listingRef) === canonicalize(agreement.listingRef) &&
    commitment.pattern === agreement.derivedFromPattern &&
    Number.isSafeInteger(commitment.committedAt) && commitment.committedAt >= agreement.generatedAt &&
    Number.isSafeInteger(authoritativeCommittedAt) && authoritativeCommittedAt >= agreement.generatedAt &&
    commitment.parties.slice().sort().join("\u0000") === expectedParties.join("\u0000") &&
    agreement.parties.some((party) => party.primaryClaim === commitment.signature.signer && party.role === "buyer") &&
    (listing.validity.notAfter === undefined || authoritativeCommittedAt <= listing.validity.notAfter) &&
    (deadlineWindow === undefined || agreement.terms.deadline <= authoritativeCommittedAt + deadlineWindow * 1000) &&
    await verifyHash(commitment.signature, SEP.commitment, standardHash(commitment), input.resolvePublicKey, input.verify);
}

export async function signSettlementEvidence(body: Omit<SettlementEvidence, "signature">, orchestrator: DacsParty): Promise<SettlementEvidence> {
  return { ...body, signature: await signHash(orchestrator, SEP.evidence, standardHash(body, [])) };
}

export async function verifyEvidence(
  evidence: SettlementEvidence,
  input: { orchestrator: string; agreement: AgreementDocument; railType: string; railId: string; resolvePublicKey: ResolvePublicKey; verify: VerifySignature },
): Promise<{ ok: boolean; reasons: string[] }> {
  // SDK maturity gap: current verifySettlementEvidence accepts the normative
  // `bft-final` model but its PAYMENT_PHASES table still omits `pay-dem`
  // (dacs-sdk #22/#23). Keep the app profile Standard-correct and delete this
  // branch once the SDK verifier handles §9.5.9 directly.
  if (evidence.phase === "pay-dem") {
    const reasons: string[] = [];
    if (evidence.evidenceVersion !== "1") reasons.push("evidenceVersion must be 1");
    if (evidence.jobId !== input.agreement.jobId) reasons.push("evidence jobId does not match agreement");
    if (evidence.outcome !== "success") reasons.push("pay-dem success evidence is required for completion");
    if (evidence.paymentAmount?.amount !== input.agreement.terms.price.amount || evidence.paymentAmount?.currency !== input.agreement.terms.price.currency) reasons.push("payment amount does not equal agreement price");
    if (evidence.settlementFinality?.model !== "bft-final" || !Number.isSafeInteger(evidence.settlementFinality.finalityObservedAt)) reasons.push("pay-dem requires observed bft-final finality");
    if (!Array.isArray(evidence.paymentTxRefs) || evidence.paymentTxRefs.length === 0 || evidence.paymentTxRefs.some((ref) => ref.kind !== "demos" || !/^[0-9a-f]{64}$/i.test(ref.txHash) || !Number.isSafeInteger(ref.blockNumber) || ref.blockNumber < 0)) reasons.push("pay-dem requires Demos tx refs with included blockNumber");
    if (evidence.signature.signer !== input.orchestrator || !(await verifyHash(evidence.signature, SEP.evidence, standardHash(evidence), input.resolvePublicKey, input.verify))) reasons.push("pay-dem evidence signature is invalid");
    return { ok: reasons.length === 0, reasons };
  }
  const verdict = await verifySettlementEvidence(evidence, {
    orchestrator: input.orchestrator,
    agreement: { amount: input.agreement.terms.price.amount, currency: input.agreement.terms.price.currency },
    rail: { railId: input.railId, railType: input.railType },
  }, {
    resolvePublicKey: async (signer) => await input.resolvePublicKey(signer),
    verify: input.verify,
  });
  return { ok: verdict.decision === "pass", reasons: verdict.reasons };
}

export function bundleHash(bundle: AttestationBundle): string {
  return standardHash(bundle, ["signatures", "anchoredByRole"]);
}

export async function addBundleSignature(bundle: AttestationBundle, party: DacsParty): Promise<AttestationBundle> {
  if (!bundle.parties.some((entry) => entry.primaryClaim === party.primaryClaim)) throw new Error("bundle signer is not a party");
  const signature = await signHash(party, SEP.bundle, bundleHash(bundle));
  return { ...bundle, signatures: [...bundle.signatures.filter((entry) => entry.party !== party.primaryClaim), { party: party.primaryClaim, algorithm: "ed25519", value: signature.value }] };
}

export async function verifyBundle(
  bundle: AttestationBundle,
  input: { expectedRole?: AttestationBundle["anchoredByRole"]; requiredRoles?: Array<"buyer" | "seller" | "orchestrator">; resolvePublicKey: ResolvePublicKey; verify: VerifySignature },
): Promise<{ ok: boolean; reason?: string }> {
  if (bundle.bundleVersion !== "1") return { ok: false, reason: "unsupported bundle version" };
  if (!bundle.jobId || !Number.isSafeInteger(bundle.finalisedAt) || bundle.finalisedAt < 0) return { ok: false, reason: "invalid bundle job/finalisation" };
  if (input.expectedRole && bundle.anchoredByRole !== input.expectedRole) return { ok: false, reason: "anchoredByRole/address mismatch" };
  if (!Array.isArray(bundle.parties) || new Set(bundle.parties.map((party) => party.primaryClaim)).size !== bundle.parties.length) return { ok: false, reason: "bundle parties are absent or duplicated" };
  if (!bundle.parties.some((party) => party.role === bundle.anchoredByRole)) return { ok: false, reason: "anchoredByRole is not represented by a party" };
  if (!Array.isArray(bundle.phaseSummary) || bundle.phaseSummary.some((phase) => !Number.isSafeInteger(phase.index) || phase.index < 0 || !PHASES.has(phase.kind))) return { ok: false, reason: "bundle phase summary is invalid" };
  const indices = bundle.phaseSummary.map((phase) => phase.index);
  if (new Set(indices).size !== indices.length || indices.some((index, i) => i > 0 && index <= indices[i - 1]!)) return { ok: false, reason: "bundle phase indices are duplicated or out of order" };
  const refs = [...bundle.vetRecords, ...bundle.settlementEvidence, ...(bundle.amendments ?? []), ...(bundle.ratingRefs ?? [])];
  if (refs.some((ref) => !ref.anchor?.locator || !/^[0-9a-f]{64}$/i.test(ref.contentHash))) return { ok: false, reason: "bundle contains an invalid artifact reference" };
  if (new Set(bundle.signatures.map((signature) => signature.party)).size !== bundle.signatures.length) return { ok: false, reason: "bundle contains duplicate party signatures" };
  if (bundle.outcome === "completed") {
    const kinds = new Set(bundle.phaseSummary.filter((phase) => phase.outcome === "ok").map((phase) => phase.kind));
    if (!bundle.agreementRef || bundle.phaseSummary.some((phase) => phase.outcome !== "ok") || ![...kinds].some((kind) => kind.startsWith("negotiate-")) || !kinds.has("commit-agreement") || ![...kinds].some((kind) => kind.startsWith("deliver-"))) return { ok: false, reason: "completed bundle is missing successful agreement/commit/negotiation/delivery" };
    if (bundle.phaseSummary.some((phase) => phase.kind.startsWith("pay-")) && bundle.settlementEvidence.length < 2) return { ok: false, reason: "completed paid bundle lacks payment and delivery evidence" };
    if (bundle.parties.filter((party) => party.role === "buyer").length !== 1 || bundle.parties.filter((party) => party.role === "seller").length !== 1) return { ok: false, reason: "completed bundle requires exactly one buyer and seller" };
  } else if (!bundle.phaseSummary.some((phase) => phase.outcome === "fail")) {
    return { ok: false, reason: "non-completed bundle has no failed phase" };
  }
  const selectedRoles = input.requiredRoles;
  const requiredRoles = bundle.outcome === "aborted-by-self" || bundle.outcome === "aborted-by-other"
    ? []
    : bundle.parties.filter((party) => (party.role === "buyer" || party.role === "seller" || party.role === "orchestrator") && (!selectedRoles || selectedRoles.includes(party.role)));
  const hash = bundleHash(bundle);
  for (const party of requiredRoles) {
    const signature = bundle.signatures.find((entry) => entry.party === party.primaryClaim);
    if (!signature || !(await verifyHash(signature, SEP.bundle, hash, input.resolvePublicKey, input.verify))) return { ok: false, reason: `missing or invalid ${party.role} bundle signature` };
  }
  if (requiredRoles.length === 0 && bundle.signatures.length < 1) return { ok: false, reason: "abort bundle has no signature" };
  return { ok: true };
}

export function sameCanonicalBundle(left: AttestationBundle, right: AttestationBundle): boolean {
  return bundleHash(left) === bundleHash(right);
}

export function standardAnchorName(kind: "listing" | "revocation" | "auto-accept" | "composite" | "agreement" | "commitment" | "evidence" | "bundle", parts: string[]): string {
  const logical = kind === "listing"
    ? `dacs1:${encodeURIComponent(parts[0] ?? "")}:${parts[1] ?? ""}:v${parts[2] ?? ""}`
    : kind === "revocation"
      ? `dacs1-revoked:${encodeURIComponent(parts[0] ?? "")}:${parts[1] ?? ""}:v${parts[2] ?? ""}`
    : kind === "auto-accept"
      ? `dacs3:auto-accept:${encodeURIComponent(parts[0] ?? "")}:${parts[1] ?? ""}:v${parts[2] ?? ""}`
    : kind === "composite"
      ? `dacs2:composite:${parts[0] ?? ""}:${encodeURIComponent(parts[1] ?? "")}`
      : kind === "agreement"
        ? `dacs3:agreement:${parts[0] ?? ""}`
        : kind === "commitment"
          ? `dacs3:commit:${parts[0] ?? ""}`
          : kind === "evidence"
            ? `dacs4:evidence:${parts[0] ?? ""}:${parts[1] ?? ""}`
            : `dacs5:bundle:${parts[0] ?? ""}:${parts[1] ?? ""}`;
  // Demos StorageProgram names are colon-free. This reversible encoding is the
  // logical→native input binding; callers publish the returned native ref.
  return Buffer.from(logical, "utf8").toString("base64url");
}

/** DACS-4 PC-2/SB-1 address for one concrete payment-phase invocation. */
export function standardPaymentAnchorName(jobId: string, railId: string, phaseIndex: number): string {
  if (!jobId || !railId) throw new Error("payment evidence address requires jobId and railId");
  if (!Number.isSafeInteger(phaseIndex) || phaseIndex < 0) {
    throw new Error("payment evidence address requires a non-negative phaseIndex");
  }
  const logical = `dacs4:payment:${jobId}:${encodeURIComponent(railId)}:${phaseIndex}`;
  return Buffer.from(logical, "utf8").toString("base64url");
}

export function rawContentHash(value: unknown): string {
  return contentHash({ value });
}
