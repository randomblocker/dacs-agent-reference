/**
 * Procurement Butler — types and ports.
 *
 * The butler is a buyer-side agent CORE: pure deterministic logic written
 * against two injected ports (a marketplace to search, a counterparty to
 * negotiate with). No DACS lifecycle wiring, no credentials, no LLM — the
 * mock adapters in `marketplace-stub.ts` make the demo run offline.
 *
 * Money is plain USD numbers, rounded to cents at every step.
 */

// ---------------------------------------------------------------------------
// Listings & fees
// ---------------------------------------------------------------------------

export type PaymentRail = "pay-dem" | "pay-x402" | "pay-evm-erc8183";

export type FeeSchedule =
  /** One flat price for the whole job. */
  | { kind: "fixed"; price: number }
  /** Metered pricing with a minimum total bill (the billing floor). */
  | { kind: "per-unit"; unitPrice: number; unit: string; minTotal: number };

/** Mechanical acceptance checks a listing may declare for its deliverables. */
export type AcceptanceCheck =
  | { kind: "sha256"; expected: string }
  | { kind: "content-includes"; needle: string }
  | { kind: "min-length"; minChars: number };

export interface AcceptancePolicy {
  /** All checks must pass for a mechanical accept. */
  checks: AcceptanceCheck[];
}

export interface QualityStats {
  /** 0..5 average rating. */
  rating: number;
  completedJobs: number;
  /** 0..1 fraction of jobs disputed. */
  disputeRate: number;
}

export interface Listing {
  id: string;
  provider: string;
  description: string;
  /** Capability tags, matched case-insensitively against the goal. */
  capabilities: string[];
  fees: FeeSchedule;
  rails: PaymentRail[];
  /**
   * Whether the provider entertains counter-offers. The provider's walk-away
   * floor is PRIVATE (held by the seller, discovered only by negotiating).
   */
  negotiable: boolean;
  quality: QualityStats;
  /** Absent/empty = no mechanical checks -> acceptance needs an evaluator. */
  acceptance?: AcceptancePolicy;
}

// ---------------------------------------------------------------------------
// Ports (injected; stub adapters in marketplace-stub.ts)
// ---------------------------------------------------------------------------

export interface MarketplacePort {
  /** Return candidate listings for a capability query (server may over-return). */
  search(query: { capabilities: string[] }): Promise<Listing[]>;
}

/**
 * Multi-dimensional negotiated terms (RFQ). Structural on purpose: the pure
 * Butler core stays decoupled from any specific desk's term shape. The
 * audit-negotiator's `AuditTerms` (tier: "quick"|"deep", …) is assignable to
 * this, so its RFQ engine can drive the Butler without a code dependency here.
 */
export interface NegotiatedTerms {
  tier: string;
  deadline: string;
  price: number;
}

export type NegotiationResponse =
  /** `terms` is the optional multi-dim agreement when reached via RFQ (additive). */
  | { type: "accept"; price: number; terms?: NegotiatedTerms }
  | { type: "counter"; price: number }
  | { type: "reject" };

/**
 * A buyer's RFQ brief — the dimensions the scalar `respond` seam cannot express
 * (acceptable tiers, preferred tier/deadline, budget). Carried on the goal and
 * handed to a counterparty that implements `negotiateRfq`.
 */
export interface RfqRequest {
  budget: number;
  acceptableTiers: string[];
  preferredTier: string;
  preferredDeadline: string;
}

/** The outcome of a multi-dimensional RFQ negotiation. */
export interface RfqOutcome {
  result: "agreed" | "walked";
  /** Present iff agreed — the terms both sides' guards accepted. */
  terms?: NegotiatedTerms;
  reason: string;
  /** Total turns the RFQ engine ran. */
  rounds: number;
}

/** Seller-side counterparty the butler negotiates against. */
export interface NegotiationPort {
  respond(listingId: string, offer: number, round: number): Promise<NegotiationResponse>;
  /**
   * Optional multi-dimensional RFQ negotiation. When a counterparty implements
   * it AND the goal carries an `rfq` brief, the Butler runs a full
   * tier×deadline×price negotiation instead of collapsing to the scalar
   * `respond` path. Absent ⇒ the Butler uses the scalar path unchanged.
   */
  negotiateRfq?(listingId: string, request: RfqRequest): Promise<RfqOutcome>;
}

// ---------------------------------------------------------------------------
// Goal, config, decision
// ---------------------------------------------------------------------------

export interface ProcurementGoal {
  description: string;
  /** Every tag here must appear in a listing's capabilities to qualify. */
  requiredCapabilities: string[];
  /** Estimated units of work, for per-unit fee schedules (default 1). */
  estimatedUnits?: number;
  /**
   * Optional multi-dimensional RFQ brief. When present and a negotiable
   * listing's counterparty supports `negotiateRfq`, that listing is negotiated
   * via the RFQ engine (tier×deadline×price) rather than the scalar path.
   */
  rfq?: RfqRequest;
}

export interface ButlerConfig {
  /** Rails in descending preference; listings supporting none are excluded. */
  railPreference: PaymentRail[];
  /** Score weights (need not sum to 1; they are used as-is). */
  weights: { price: number; rail: number; quality: number };
  negotiation: {
    /** Opening offer = ask * (1 - openDiscount), capped at reservation. */
    openDiscount: number;
    /** Per-round fraction of the remaining gap conceded toward reservation. */
    concessionRate: number;
    /** Max buyer offers before walking (final offer = reservation price). */
    maxRounds: number;
  };
}

export interface CandidateScores {
  price: number;
  rail: number;
  quality: number;
  total: number;
}

/** One row of the audit trail — every listing the butler looked at. */
export interface CandidateAudit {
  listingId: string;
  provider: string;
  /** The advertised total for the job: fixed price, or metered unitPrice x units. */
  askPrice: number;
  /**
   * Per-unit deals only: the unit count `askPrice` was metered over, and the
   * metered basis, so the audit trail is transparent about how a usage-based
   * total was reached (`askPrice = max(minTotal, unitPrice * units)`). Absent
   * for flat/fixed listings.
   */
  units?: number;
  feeBasis?: { unit: string; unitPrice: number; minTotal: number };
  /** Populated when the candidate was dropped before selection. */
  excluded?: string;
  /** Populated for candidates that survived filtering. */
  scores?: CandidateScores;
  chosenRail?: PaymentRail;
}

export interface NegotiationRound {
  round: number;
  actor: "buyer" | "seller";
  action: "offer" | "counter" | "accept" | "walk";
  price?: number;
}

export interface NegotiationTranscript {
  listingId: string;
  ask: number;
  reservation: number;
  rounds: NegotiationRound[];
  result: "agreed" | "walked";
  agreedPrice?: number;
  /**
   * Present when this negotiation ran the multi-dimensional RFQ path. The scalar
   * `rounds` are empty in that case (RFQ moves are tier×deadline×price, not
   * scalar offers); the full RFQ outcome (agreed terms, turn count) lives here.
   */
  rfq?: RfqOutcome;
}

/** The concluded terms, later passed back into acceptDeliverable. */
export interface ProcurementAgreement {
  listingId: string;
  provider: string;
  goal: string;
  price: number;
  rail: PaymentRail;
  negotiated: boolean;
  acceptance?: AcceptancePolicy;
  /**
   * Multi-dimensional agreed terms when the deal was reached via RFQ. `price`
   * above equals `agreedTerms.price` (the settlement amount); the extra tier +
   * deadline dimensions are carried here for the seller to fulfil against.
   */
  agreedTerms?: NegotiatedTerms;
}

export interface ProcurementDecision {
  goal: ProcurementGoal;
  budget: number;
  outcome: "awarded" | "no-award";
  winner?: ProcurementAgreement;
  /** Every listing considered, with exclusion reasons or scores. */
  candidates: CandidateAudit[];
  /** Every negotiation attempted, in the order attempted. */
  negotiations: NegotiationTranscript[];
}

// ---------------------------------------------------------------------------
// Deliverable acceptance
// ---------------------------------------------------------------------------

export interface Deliverable {
  content: string;
  meta?: Record<string, unknown>;
}

export type AcceptanceResult =
  | { verdict: "accept"; checksRun: string[] }
  | { verdict: "reject"; reason: string; checksRun: string[] }
  | { verdict: "needs-evaluator"; reason: string };
