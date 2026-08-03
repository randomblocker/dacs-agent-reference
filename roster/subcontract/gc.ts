/**
 * Sub-contracting General Contractor (GC) — nested negotiation + revenue split.
 *
 * The novel move that fixed-price agent markets (x402, Olas) literally cannot
 * express: a buyer wants a COMPOUND deliverable (e.g. a full security review =
 * general code audit + a Solidity deep-dive + a dependency advisory) that no
 * single agent does best. A General Contractor agent:
 *
 *   1. SOURCES each component by sub-negotiating with a specialist seller — the
 *      GC is the BUYER in each of those RFQs.
 *   2. Only after sourcing does it know its true cost floor (Σ agreed sub-prices).
 *      That floor is the OUTCOME of the inner negotiations — private information
 *      that compounds — so the GC's buyer-facing floor is honestly grounded.
 *   3. SELLS the assembled bundle to the buyer — the GC is the SELLER in that RFQ.
 *   4. Its margin = bundle price − Σ sub-prices, split transparently in the plan.
 *
 * Everything runs on the audit desk's existing engine, UNCHANGED: each specialist
 * is a `deterministicSeller` (a real audit desk with its own private scan), each
 * sub-negotiation is a `deterministicBuyer` (the GC) against it, and the bundle
 * sale is one more RFQ with a GC-specific seller policy whose floor is the
 * sourced cost. This module adds only orchestration on top.
 */
import {
  askFor,
  buyerMaySettle,
  roundCents,
  sellerMaySettle,
  type AuditTerms,
  type AuditTier,
  type Deadline,
  type DeskEconomics,
  type ScanFacts,
  type SellerGuard,
} from "../audit-negotiator/terms.js";
import {
  deterministicBuyer,
  deterministicSeller,
  sellerGuardFor,
  type Policy,
  type PublicState,
  type SellerBrief,
} from "../audit-negotiator/policies.js";
import { runNegotiation, type NegotiationResult } from "../audit-negotiator/negotiate.js";

const OFFERED_TIERS: AuditTier[] = ["quick", "deep"];

// ---------------------------------------------------------------------------
// Job & plan shapes
// ---------------------------------------------------------------------------

/** One component of a compound job, sourced from a specialist audit desk. */
export interface Specialist {
  id: string;
  label: string;
  /** The specialist's PRIVATE scan of its slice of the target. */
  scan: ScanFacts;
  /** The specialist's economics (specialties price differently). */
  econ: DeskEconomics;
  /** The tier this component needs — the GC will accept nothing weaker. */
  requiredTier: AuditTier;
}

export interface SubcontractJob {
  buyerBudget: number;
  /** The bundle deadline — flows to every sub-negotiation (rush lifts sub floors). */
  deadline: Deadline;
  specialists: Specialist[];
  /** GC margin over sourced cost — its bundle floor = cost × (1 + this). Default 0.2. */
  coordMarginPct?: number;
  /** Fraction of the buyer budget the GC is willing to spend sourcing. Default 0.75. */
  sourcingFraction?: number;
  maxTurns?: number;
}

export interface SubResult {
  specialist: string;
  label: string;
  /** The GC's sourcing budget allocated to this component. */
  allocation: number;
  outcome: "agreed" | "walked";
  price?: number;
  terms?: AuditTerms;
  negotiation: NegotiationResult;
}

export interface SubcontractPlan {
  outcome: "awarded" | "no-source" | "no-deal";
  reason: string;
  /** Every component sourcing attempt (the inner negotiations). */
  subs: SubResult[];
  /** Σ agreed sub-prices — the GC's true cost (present iff all sourced). */
  bundleCost?: number;
  /** The GC's walk-away floor for the bundle = bundleCost × (1 + coordMargin). */
  bundleFloor?: number;
  /** The negotiated bundle price the buyer pays (present iff awarded). */
  bundlePrice?: number;
  /** bundlePrice − bundleCost (present iff awarded). */
  gcMargin?: number;
  /** The outer (buyer ⇄ GC) negotiation (present once sourcing succeeded). */
  bundleNegotiation?: NegotiationResult;
}

// ---------------------------------------------------------------------------
// The GC's bundle-seller policy (fixed floor = sourced cost + margin)
// ---------------------------------------------------------------------------

/**
 * A seller policy for the assembled bundle. Unlike the audit desk's seller, its
 * floor is not scan-derived — it is the cost the GC already committed to its
 * sub-contractors, plus its coordination margin. It anchors at a list markup,
 * concedes toward the floor, and holds firm there on the final turn. No tier
 * downgrade: the bundle is all-or-nothing (every component was already sourced).
 */
export function gcBundleSeller(
  bundleFloor: number,
  deadline: Deadline,
  opts: { listMarginPct?: number; concessionStep?: number } = {},
): Policy {
  const listMargin = opts.listMarginPct ?? 0.4;
  const step = opts.concessionStep ?? 0.34;
  const ask = roundCents(bundleFloor * (1 + listMargin));

  return async (state: PublicState) => {
    // Find the buyer's latest position.
    let buyerTerms: AuditTerms | undefined;
    for (let i = state.transcript.length - 1; i >= 0; i--) {
      const t = state.transcript[i]!;
      if (t.side === "buyer" && (t.move.kind === "offer" || t.move.kind === "counter")) {
        buyerTerms = t.move.terms;
        break;
      }
      if (t.side === "buyer" && t.move.kind === "reject") {
        return { kind: "reject", rationale: "Buyer walked." };
      }
    }

    // Opening quote.
    if (!buyerTerms) {
      return {
        kind: "offer",
        terms: { tier: "deep", deadline, price: ask },
        rationale: `Bundle quote: I've lined up every specialist for a full review by the ${deadline} deadline.`,
      };
    }

    // Buyer's price clears our sourced floor ⇒ close.
    if (buyerTerms.price >= bundleFloor) {
      return { kind: "accept", terms: { tier: "deep", deadline, price: roundCents(buyerTerms.price) }, rationale: "Clears my sourced cost — done." };
    }

    const isFinal = state.round >= state.maxRounds;
    const conceded = isFinal ? bundleFloor : Math.max(bundleFloor, roundCents(ask - (ask - bundleFloor) * step * state.round));
    return {
      kind: "counter",
      terms: { tier: "deep", deadline, price: conceded },
      rationale: isFinal
        ? `Final: ${conceded} is my floor — it's what the specialists already cost me.`
        : `Conceding to ${conceded}; I still have three specialists to pay.`,
    };
  };
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

/**
 * Run the full sub-contract: source every component, assemble the cost floor,
 * then negotiate the bundle with the buyer. Deterministic and offline; the
 * inner and outer negotiations all use the audit desk's engine.
 */
export async function runSubcontract(job: SubcontractJob): Promise<SubcontractPlan> {
  const coordMargin = job.coordMarginPct ?? 0.2;
  const sourcingFraction = job.sourcingFraction ?? 0.75;
  const maxTurns = job.maxTurns ?? 6;
  const offeredDeadlines: Deadline[] = [job.deadline];

  // Weight the sourcing budget across components by each specialist's ask.
  const asks = job.specialists.map((s) => askFor(s.scan, s.requiredTier, job.deadline, s.econ));
  const askTotal = asks.reduce((a, b) => a + b, 0) || 1;
  const sourcingTotal = job.buyerBudget * sourcingFraction;

  const subs: SubResult[] = [];
  for (const [i, spec] of job.specialists.entries()) {
    const allocation = roundCents((sourcingTotal * asks[i]!) / askTotal);

    const sellerGuard = sellerGuardFor(spec.scan, OFFERED_TIERS, offeredDeadlines, spec.econ);
    const buyerGuard = {
      offeredTiers: OFFERED_TIERS,
      offeredDeadlines,
      budget: allocation,
      acceptableTiers: [spec.requiredTier],
    };
    const sellerBrief: SellerBrief = { scan: spec.scan, guard: sellerGuard, econ: spec.econ };
    const specialist = deterministicSeller(sellerBrief);
    const gcAsBuyer = deterministicBuyer({ guard: buyerGuard, preferredTier: spec.requiredTier, preferredDeadline: job.deadline });

    const negotiation = await runNegotiation(specialist, gcAsBuyer, { maxTurns, sellerGuard, buyerGuard });
    subs.push({
      specialist: spec.id,
      label: spec.label,
      allocation,
      outcome: negotiation.outcome,
      price: negotiation.agreed?.price,
      terms: negotiation.agreed,
      negotiation,
    });
  }

  // If any component could not be sourced, the bundle can't be assembled.
  const unsourced = subs.filter((s) => s.outcome !== "agreed");
  if (unsourced.length > 0) {
    return {
      outcome: "no-source",
      reason: `could not source ${unsourced.length}/${subs.length} component(s): ${unsourced.map((s) => s.label).join(", ")}`,
      subs,
    };
  }

  const bundleCost = roundCents(subs.reduce((a, s) => a + (s.price ?? 0), 0));
  const bundleFloor = roundCents(bundleCost * (1 + coordMargin));

  // Sell the assembled bundle to the buyer.
  const sellerGuard: SellerGuard = {
    offeredTiers: ["deep"],
    offeredDeadlines,
    floor: () => bundleFloor,
  };
  const buyerGuard = {
    offeredTiers: ["deep"] as AuditTier[],
    offeredDeadlines,
    budget: job.buyerBudget,
    acceptableTiers: ["deep"] as AuditTier[],
  };
  const seller = gcBundleSeller(bundleFloor, job.deadline);
  const buyer = deterministicBuyer({ guard: buyerGuard, preferredTier: "deep", preferredDeadline: job.deadline });

  const bundleNegotiation = await runNegotiation(seller, buyer, { maxTurns, sellerGuard, buyerGuard });

  if (bundleNegotiation.outcome !== "agreed" || !bundleNegotiation.agreed) {
    return {
      outcome: "no-deal",
      reason: `sourced at ${bundleCost} (floor ${bundleFloor}) but buyer walked: ${bundleNegotiation.reason}`,
      subs,
      bundleCost,
      bundleFloor,
      bundleNegotiation,
    };
  }

  const bundlePrice = bundleNegotiation.agreed.price;
  return {
    outcome: "awarded",
    reason: `bundle awarded at ${bundlePrice} DEM; sourced at ${bundleCost}; GC margin ${roundCents(bundlePrice - bundleCost)}`,
    subs,
    bundleCost,
    bundleFloor,
    bundlePrice,
    gcMargin: roundCents(bundlePrice - bundleCost),
    bundleNegotiation,
  };
}

/** Guard sanity re-exports so callers can re-check a plan's terms if they want. */
export { sellerMaySettle, buyerMaySettle };
