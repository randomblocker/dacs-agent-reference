/**
 * Negotiated Security-Audit Desk — terms, honest cost model, and the
 * deterministic negotiation GUARD.
 *
 * This is the piece that makes negotiation *honest* rather than theatrical.
 * The audit desk sells work whose cost genuinely varies per job, and the
 * seller only learns the cost by pre-scanning the target (KLOC, whether any
 * Solidity is present ⇒ how many real tools apply). That scan is the seller's
 * PRIVATE information; the buyer sees only the public rate formula. So there is
 * a real gap to close and a real reason for the two sides to exchange offers.
 *
 * Deals are MULTI-DIMENSIONAL — price × tier × deadline — so a policy can trade
 * one dimension for another ("can't do rush at that price, but standard yes, or
 * rush for +N DEM"). The scalar-haggle `NegotiationPort` in procurement-butler
 * can't express that; this module's `AuditTerms` can.
 *
 * The cost model reuses the sec-audit deep tier's real pricing
 * (`deepAuditPriceFor`, deep-audit.ts §Pricing) so the floor a seller defends
 * is the same number the delivered artifact would bill. Money is DEM
 * display-unit numbers rounded to cents, exactly like the Butler's `roundCents`
 * and the wire's `roundFee`.
 */
import { deepAuditPriceFor } from "../sec-audit/deep-audit.js";

// ---------------------------------------------------------------------------
// Deal dimensions
// ---------------------------------------------------------------------------

/**
 * The depth tier. Both ride the SAME sec-audit engine; they differ in what the
 * engine is allowed to do:
 *   - quick — deterministic rule-table scan only (scanner.ts). No sandbox, no
 *             LLM deep-pass. Cheap, fast, KLOC-priced.
 *   - deep  — sandboxed Semgrep (+ Slither if Solidity) + an LLM deep review,
 *             priced by real work done (`deepAuditPriceFor`).
 */
export type AuditTier = "quick" | "deep";

/** Turnaround. `rush` preempts other queued work ⇒ it costs the seller more. */
export type Deadline = "standard" | "rush";

/** A concrete, fully-specified deal. `price` is DEM display units (cents-rounded). */
export interface AuditTerms {
  tier: AuditTier;
  deadline: Deadline;
  price: number;
}

/** The message that crosses the negotiation channel each turn. */
export type NegotiationMove =
  | { kind: "offer"; terms: AuditTerms; rationale: string }
  | { kind: "counter"; terms: AuditTerms; rationale: string }
  | { kind: "accept"; terms: AuditTerms; rationale: string }
  | { kind: "reject"; rationale: string };

// ---------------------------------------------------------------------------
// The seller's private pre-scan
// ---------------------------------------------------------------------------

/**
 * What a pre-scan of the target reveals — the seller's PRIVATE information.
 * Derived by cloning + walking the tree (live) or by an injected `ScanPort`
 * (offline/tests). Tool applicability mirrors deep-audit.ts §pickTools:
 * Semgrep for any repo; Slither if any `.sol` file is present.
 */
export interface ScanFacts {
  repo: string;
  /** Thousands of lines of code across scanned files. */
  kloc: number;
  fileCount: number;
  hasSolidity: boolean;
  /** Real tools the deep tier would run: Semgrep always, Slither iff Solidity. */
  numTools: number;
}

/** Derive `numTools` from language facts, exactly as the deep engine picks tools. */
export function toolsForScan(hasSolidity: boolean): number {
  return 1 /* Semgrep, always */ + (hasSolidity ? 1 : 0); /* Slither iff .sol */
}

// ---------------------------------------------------------------------------
// Honest cost model
// ---------------------------------------------------------------------------

/**
 * The desk's cost/margin parameters. `minMarginPct` sets the walk-away floor
 * over true cost; `listMarginPct` sets the opening list anchor. `rushMultiplier`
 * inflates cost for preemptive turnaround. All private to the seller.
 */
export interface DeskEconomics {
  /** Quick-tier cost = quickBase + quickPerKloc·ceil(KLOC). */
  quickBase: number;
  quickPerKloc: number;
  /** Rush turnaround multiplies the true cost (preempts other work). */
  rushMultiplier: number;
  /** Walk-away floor = cost·(1 + minMarginPct). */
  minMarginPct: number;
  /** Opening list ask = cost·(1 + listMarginPct). */
  listMarginPct: number;
}

export const DEFAULT_ECONOMICS: DeskEconomics = {
  quickBase: 1,
  quickPerKloc: 0.25,
  rushMultiplier: 1.5,
  minMarginPct: 0.15,
  listMarginPct: 0.6,
};

export function roundCents(n: number): number {
  return Math.round(n * 100) / 100;
}

/**
 * The seller's TRUE cost to deliver `(tier, deadline)` for a scanned target.
 * Deep tier reuses the delivered artifact's own bill (`deepAuditPriceFor`) so
 * the floor maps to a number the buyer can later re-derive from the artifact.
 */
export function costFor(
  scan: ScanFacts,
  tier: AuditTier,
  deadline: Deadline,
  econ: DeskEconomics = DEFAULT_ECONOMICS,
): number {
  const base =
    tier === "deep"
      ? deepAuditPriceFor(scan.numTools, scan.kloc)
      : roundCents(econ.quickBase + econ.quickPerKloc * Math.ceil(scan.kloc));
  const withRush = deadline === "rush" ? base * econ.rushMultiplier : base;
  return roundCents(withRush);
}

/** Walk-away floor for a deal — the seller MUST NOT settle below this. */
export function floorFor(
  scan: ScanFacts,
  tier: AuditTier,
  deadline: Deadline,
  econ: DeskEconomics = DEFAULT_ECONOMICS,
): number {
  return roundCents(costFor(scan, tier, deadline, econ) * (1 + econ.minMarginPct));
}

/** Opening list ask for a deal — the seller's public anchor. */
export function askFor(
  scan: ScanFacts,
  tier: AuditTier,
  deadline: Deadline,
  econ: DeskEconomics = DEFAULT_ECONOMICS,
): number {
  return roundCents(costFor(scan, tier, deadline, econ) * (1 + econ.listMarginPct));
}

// ---------------------------------------------------------------------------
// The deterministic GUARD
// ---------------------------------------------------------------------------

/**
 * The offered tiers/deadlines the desk actually supports, plus the numeric
 * bounds a move must respect. Both policies validate every inbound and outbound
 * move against a guard so an LLM (or a buggy remote) can never push a side past
 * an invariant it must not cross.
 */
export interface SellerGuard {
  offeredTiers: AuditTier[];
  offeredDeadlines: Deadline[];
  /** Per-(tier,deadline) walk-away floor. The seller never settles below. */
  floor: (tier: AuditTier, deadline: Deadline) => number;
}

export interface BuyerGuard {
  offeredTiers: AuditTier[];
  offeredDeadlines: Deadline[];
  /** The buyer never settles above this. */
  budget: number;
  /** Tiers the buyer is willing to accept (a quick pass may not satisfy the goal). */
  acceptableTiers: AuditTier[];
}

export interface GuardVerdict {
  ok: boolean;
  reason?: string;
}

/** Structural validity shared by both sides: real terms, positive rounded price. */
export function validTermsShape(terms: AuditTerms, tiers: AuditTier[], deadlines: Deadline[]): GuardVerdict {
  if (!terms || typeof terms !== "object") return { ok: false, reason: "terms missing" };
  if (!tiers.includes(terms.tier)) return { ok: false, reason: `tier '${terms.tier}' not offered` };
  if (!deadlines.includes(terms.deadline)) return { ok: false, reason: `deadline '${terms.deadline}' not offered` };
  if (typeof terms.price !== "number" || !Number.isFinite(terms.price) || terms.price <= 0) {
    return { ok: false, reason: `price '${terms.price}' is not a positive number` };
  }
  if (roundCents(terms.price) !== terms.price) return { ok: false, reason: `price '${terms.price}' not cents-rounded` };
  return { ok: true };
}

/**
 * Seller guard: a deal the SELLER emits or accepts must be a supported
 * tier/deadline at or ABOVE the floor for that combination. This is the
 * invariant an LLM seller policy can never be argued out of.
 */
export function sellerMaySettle(terms: AuditTerms, guard: SellerGuard): GuardVerdict {
  const shape = validTermsShape(terms, guard.offeredTiers, guard.offeredDeadlines);
  if (!shape.ok) return shape;
  const floor = guard.floor(terms.tier, terms.deadline);
  if (terms.price < floor) {
    return { ok: false, reason: `price ${terms.price} below floor ${floor} for ${terms.tier}/${terms.deadline}` };
  }
  return { ok: true };
}

/**
 * Buyer guard: a deal the BUYER emits or accepts must be an acceptable tier at
 * or BELOW budget. The invariant an LLM buyer policy can never be argued past.
 */
export function buyerMaySettle(terms: AuditTerms, guard: BuyerGuard): GuardVerdict {
  const shape = validTermsShape(terms, guard.offeredTiers, guard.offeredDeadlines);
  if (!shape.ok) return shape;
  if (!guard.acceptableTiers.includes(terms.tier)) {
    return { ok: false, reason: `tier '${terms.tier}' does not satisfy the goal` };
  }
  if (terms.price > guard.budget) {
    return { ok: false, reason: `price ${terms.price} over budget ${guard.budget}` };
  }
  return { ok: true };
}
