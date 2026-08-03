/**
 * Deterministic negotiation policies for the audit desk (seller + buyer).
 *
 * These are the offline, testable CORE — no LLM, no I/O. They do principled
 * price haggling on a target (tier, deadline) with one structural concession the
 * dimensions make possible: when the buyer's budget cannot reach the DEEP floor,
 * the seller may propose downgrading the tier (deep → quick) rather than just
 * walking. That single cross-dimension move is what a scalar haggler can't do.
 *
 * The LLM policies (`llm-policy.ts`) get the FULL multi-dimensional freedom —
 * arbitrary tier/deadline trades and free-text rationale. Both kinds of policy
 * emit `NegotiationMove`s that are validated against the same guard before they
 * ever reach the counterparty (see `negotiate.ts`), so a policy — deterministic
 * or LLM — can never breach an invariant.
 *
 * A `Policy` is a pure function of the PUBLIC state (the transcript so far). Its
 * PRIVATE brief (the seller's scan/floors, the buyer's budget) is captured in
 * the closure when the policy is built, never exposed on the wire.
 */
import {
  askFor,
  buyerMaySettle,
  floorFor,
  roundCents,
  sellerMaySettle,
  type AuditTerms,
  type AuditTier,
  type BuyerGuard,
  type Deadline,
  type DeskEconomics,
  type NegotiationMove,
  type ScanFacts,
  type SellerGuard,
} from "./terms.js";

// ---------------------------------------------------------------------------
// Policy contract
// ---------------------------------------------------------------------------

/** One recorded turn: which side moved, and what they said. */
export interface Turn {
  side: "seller" | "buyer";
  move: NegotiationMove;
}

/** The public state a policy sees — the shared transcript and round accounting. */
export interface PublicState {
  transcript: Turn[];
  /** This side's own turn count so far (1-based on the turn it is producing). */
  round: number;
  /** Hard cap on this side's turns (RFQ maxTurns is enforced by the harness). */
  maxRounds: number;
}

/** A negotiation policy: produce the next move from the public state. */
export type Policy = (state: PublicState) => Promise<NegotiationMove>;

/** The last move the counterparty made (or undefined on the opening turn). */
export function lastCounterpartyMove(state: PublicState, me: "seller" | "buyer"): NegotiationMove | undefined {
  for (let i = state.transcript.length - 1; i >= 0; i--) {
    if (state.transcript[i]!.side !== me) return state.transcript[i]!.move;
  }
  return undefined;
}

/** The prices a side has offered/countered, in order — its concession trajectory. */
export function priceTrajectory(state: PublicState, side: "seller" | "buyer"): number[] {
  const prices: number[] = [];
  for (const t of state.transcript) {
    if (t.side === side && (t.move.kind === "offer" || t.move.kind === "counter")) prices.push(t.move.terms.price);
  }
  return prices;
}

/**
 * Extrapolate one more concession step from a monotone trajectory: the last
 * price plus its last upward increment. Lets the seller estimate whether a buyer
 * can plausibly reach a floor it cannot see the budget behind.
 */
export function projectedReach(trajectory: number[]): number | undefined {
  if (trajectory.length === 0) return undefined;
  const last = trajectory[trajectory.length - 1]!;
  if (trajectory.length === 1) return last;
  const prev = trajectory[trajectory.length - 2]!;
  return roundCents(last + Math.max(0, last - prev));
}

// ---------------------------------------------------------------------------
// Seller
// ---------------------------------------------------------------------------

export interface SellerBrief {
  scan: ScanFacts;
  guard: SellerGuard;
  econ: DeskEconomics;
  /** Fraction of the ask→floor gap conceded per round (default 0.34). */
  concessionStep?: number;
  /** The tier the desk anchors its opening quote on (default "deep"). */
  anchorTier?: AuditTier;
  /** The deadline the desk anchors its opening quote on (default "standard"). */
  anchorDeadline?: Deadline;
}

/**
 * Deterministic seller. Opens by anchoring a quote at its list ask on the
 * anchor tier; then, against each buyer position, either accepts (buyer's price
 * clears the floor for the buyer's requested terms), counters with a conceded
 * price on those terms, or — when even the fully-conceded floor is out of the
 * buyer's reach and the buyer wanted the deep tier — proposes the cheaper quick
 * tier. Walks only when nothing it can offer clears its floor.
 */
export function deterministicSeller(brief: SellerBrief): Policy {
  const step = brief.concessionStep ?? 0.34;
  const anchorTier = brief.anchorTier ?? "deep";
  const anchorDeadline = brief.anchorDeadline ?? "standard";

  return async (state) => {
    const last = lastCounterpartyMove(state, "seller");

    // Opening quote — anchor high on the list ask.
    if (!last) {
      const price = askFor(brief.scan, anchorTier, anchorDeadline, brief.econ);
      return {
        kind: "offer",
        terms: { tier: anchorTier, deadline: anchorDeadline, price },
        rationale:
          `Scanned ${brief.scan.repo}: ${brief.scan.kloc} KLOC, ${brief.scan.fileCount} files` +
          `${brief.scan.hasSolidity ? " incl. Solidity" : ""} ⇒ ${brief.scan.numTools} tool(s) for a deep audit. ` +
          `Opening quote for the ${anchorTier}/${anchorDeadline} tier.`,
      };
    }

    if (last.kind === "reject") return { kind: "reject", rationale: "Counterparty walked." };
    if (last.kind === "accept") {
      // Buyer accepted our terms; mirror an accept iff it still clears our floor.
      const v = sellerMaySettle(last.terms, brief.guard);
      return v.ok
        ? { kind: "accept", terms: last.terms, rationale: "Agreed." }
        : { kind: "reject", rationale: `Cannot honour accepted terms: ${v.reason}` };
    }

    // Buyer made an offer/counter at some terms.
    const want = last.terms;
    const floor = brief.guard.floor(want.tier, want.deadline);

    // If the buyer's price already clears our floor for their requested terms, take it.
    if (want.price >= floor) {
      return { kind: "accept", terms: { ...want, price: roundCents(want.price) }, rationale: "Your terms clear our floor — done." };
    }

    // Concede toward the floor on the buyer's requested terms.
    const ask = askFor(brief.scan, want.tier, want.deadline, brief.econ);
    const isFinal = state.round >= state.maxRounds;
    const conceded = isFinal ? floor : Math.max(floor, roundCents(ask - (ask - floor) * step * state.round));

    if (!isFinal) {
      return {
        kind: "counter",
        terms: { tier: want.tier, deadline: want.deadline, price: conceded },
        rationale: `Conceding to ${conceded} for ${want.tier}/${want.deadline}.`,
      };
    }

    // Final round. The buyer's price is below our floor. We get one last move and
    // the buyer's reply is terminal, so choose between holding the deep floor and
    // downgrading to quick using the ONLY signal we have: can the buyer plausibly
    // reach the deep floor? Extrapolate one more of their concession steps. A fast
    // climber can likely cover the floor (their hidden budget has room); a stalled
    // buyer cannot, so a quick-tier offer is the only deal left on the table.
    const canReachDeep = (projectedReach(priceTrajectory(state, "buyer")) ?? want.price) >= floor;
    const canDowngrade = want.tier === "deep" && brief.guard.offeredTiers.includes("quick");
    if (!canReachDeep && canDowngrade) {
      const quickFloor = brief.guard.floor("quick", want.deadline);
      if (want.price >= quickFloor) {
        return {
          kind: "counter",
          terms: { tier: "quick", deadline: want.deadline, price: quickFloor },
          rationale: `Deep won't reach your budget (floor ${floor}); the quick static tier fits at ${quickFloor}.`,
        };
      }
    }

    // Hold the deep floor as take-it-or-leave — the buyer may have room we can't see.
    return {
      kind: "counter",
      terms: { tier: want.tier, deadline: want.deadline, price: conceded },
      rationale: `Final: ${conceded} is our floor for ${want.tier}/${want.deadline}.`,
    };
  };
}

// ---------------------------------------------------------------------------
// Buyer
// ---------------------------------------------------------------------------

export interface BuyerBrief {
  guard: BuyerGuard;
  /** The tier the buyer prefers (must be in guard.acceptableTiers). */
  preferredTier: AuditTier;
  preferredDeadline: Deadline;
  /** Opening ask discount off the seller's quote (default 0.35). */
  openDiscount?: number;
  /** Per-round fraction of the gap conceded up toward budget (default 0.5). */
  concessionRate?: number;
}

/**
 * Deterministic buyer. Responds to the seller's quote by anchoring low (a
 * discount off the seller's ask, capped at budget) on its preferred acceptable
 * terms; concedes upward toward budget each round; accepts a seller counter once
 * it is at or below the buyer's current willingness AND within budget/acceptable
 * tier. Entertains a seller tier-downgrade if that tier is acceptable and priced
 * within budget. Walks when the seller stays above budget at the last round.
 */
export function deterministicBuyer(brief: BuyerBrief): Policy {
  const openDiscount = brief.openDiscount ?? 0.35;
  const concessionRate = brief.concessionRate ?? 0.5;
  const budget = brief.guard.budget;

  return async (state) => {
    const last = lastCounterpartyMove(state, "buyer");
    if (!last || last.kind === "reject") {
      return { kind: "reject", rationale: "No workable quote." };
    }

    const sellerTerms = last.terms;

    // Track our willingness across rounds from the transcript (our own last offer).
    const myLast = [...state.transcript].reverse().find((t) => t.side === "buyer");
    const myLastPrice =
      myLast && (myLast.move.kind === "offer" || myLast.move.kind === "counter") ? myLast.move.terms.price : undefined;

    // Opening response: anchor low on our preferred acceptable terms.
    if (myLastPrice === undefined) {
      const target = roundCents(Math.min(budget, sellerTerms.price * (1 - openDiscount)));
      const terms: AuditTerms = { tier: brief.preferredTier, deadline: brief.preferredDeadline, price: target };
      const v = buyerMaySettle(terms, brief.guard);
      if (!v.ok) return { kind: "reject", rationale: `Opening terms invalid: ${v.reason}` };
      return { kind: "offer", terms, rationale: `We can start at ${target} for ${terms.tier}/${terms.deadline}.` };
    }

    const isFinal = state.round >= state.maxRounds;
    // Where we'd move next: concede up toward budget.
    const willingness = isFinal ? budget : roundCents(myLastPrice + (budget - myLastPrice) * concessionRate);

    // Accept the seller's counter if it is acceptable, within budget, and at/below
    // where we were heading.
    const canSettle = buyerMaySettle(sellerTerms, brief.guard);
    if (canSettle.ok && sellerTerms.price <= willingness) {
      return { kind: "accept", terms: { ...sellerTerms, price: roundCents(sellerTerms.price) }, rationale: "Accepted." };
    }

    // Seller proposed a different (cheaper) tier that is acceptable and in budget.
    if (canSettle.ok && sellerTerms.tier !== brief.preferredTier && sellerTerms.price <= budget) {
      return { kind: "accept", terms: { ...sellerTerms, price: roundCents(sellerTerms.price) }, rationale: `Taking the ${sellerTerms.tier} tier at ${sellerTerms.price}.` };
    }

    if (isFinal) {
      // Last chance: if the seller's terms clear our guard, take them; else walk
      // with the ACTUAL reason (over budget, or a tier that doesn't meet the goal).
      if (canSettle.ok) {
        return { kind: "accept", terms: { ...sellerTerms, price: roundCents(sellerTerms.price) }, rationale: "Final: within budget, accepted." };
      }
      return { kind: "reject", rationale: canSettle.reason ?? `Seller's ${sellerTerms.price} not acceptable.` };
    }

    // Otherwise concede upward on our own preferred terms.
    const terms: AuditTerms = { tier: brief.preferredTier, deadline: brief.preferredDeadline, price: willingness };
    return { kind: "counter", terms, rationale: `Up to ${willingness} for ${terms.tier}/${terms.deadline}.` };
  };
}

// ---------------------------------------------------------------------------
// Guard builders
// ---------------------------------------------------------------------------

/** Build the seller's guard (floors per tier/deadline) from a scan + economics. */
export function sellerGuardFor(
  scan: ScanFacts,
  offeredTiers: AuditTier[],
  offeredDeadlines: Deadline[],
  econ: DeskEconomics,
): SellerGuard {
  return {
    offeredTiers,
    offeredDeadlines,
    floor: (tier, deadline) => floorFor(scan, tier, deadline, econ),
  };
}
