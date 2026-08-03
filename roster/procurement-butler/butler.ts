/**
 * Procurement Butler — buyer-side agent core.
 *
 * Given a goal + budget it: searches the marketplace port, filters by
 * capability, scores survivors (price / rail preference / track record),
 * negotiates with negotiable providers via a bounded deterministic policy,
 * and emits a ProcurementDecision carrying the FULL audit trail — every
 * candidate, every score, every negotiation round. Afterwards,
 * `acceptDeliverable` applies the listing's declared mechanical checks.
 *
 * Everything is pure policy over injected ports: no LLM, no chain, no I/O.
 *
 * Negotiation policy (buyer side):
 *   reservation R = min(budget, ask)          — never pay above either
 *   opening      = ask * (1 - openDiscount)   — capped at R
 *   each round the willingness moves toward R by concessionRate of the
 *   remaining gap; the FINAL round offers R outright. A seller counter is
 *   accepted when it is at or below the buyer's next position. If the seller
 *   never comes down to R, the butler walks.
 */
import { createHash } from "node:crypto";
import type {
  AcceptanceResult,
  ButlerConfig,
  CandidateAudit,
  CandidateScores,
  Deliverable,
  FeeSchedule,
  Listing,
  MarketplacePort,
  NegotiatedTerms,
  NegotiationPort,
  NegotiationTranscript,
  PaymentRail,
  ProcurementAgreement,
  ProcurementDecision,
  ProcurementGoal,
  RfqOutcome,
  RfqRequest,
} from "./types.js";

export const DEFAULT_CONFIG: ButlerConfig = {
  railPreference: ["pay-dem", "pay-x402", "pay-evm-erc8183"],
  weights: { price: 0.35, rail: 0.25, quality: 0.4 },
  negotiation: { openDiscount: 0.25, concessionRate: 0.5, maxRounds: 4 },
};

export function roundCents(n: number): number {
  return Math.round(n * 100) / 100;
}

/** The provider's advertised total for the job (fixed price, or metered × units). */
export function askPriceOf(fees: FeeSchedule, units: number): number {
  if (fees.kind === "fixed") return roundCents(fees.price);
  return roundCents(Math.max(fees.unitPrice * units, fees.minTotal));
}

function clamp01(n: number): number {
  return Math.min(1, Math.max(0, n));
}

export class ProcurementButler {
  constructor(
    private readonly market: MarketplacePort,
    private readonly counterparty: NegotiationPort,
    private readonly config: ButlerConfig = DEFAULT_CONFIG,
  ) {}

  // -------------------------------------------------------------------------
  // Procurement
  // -------------------------------------------------------------------------

  async procure(goal: ProcurementGoal, budget: number): Promise<ProcurementDecision> {
    const units = goal.estimatedUnits ?? 1;
    const listings = await this.market.search({ capabilities: goal.requiredCapabilities });

    const candidates: CandidateAudit[] = [];
    const viable: Array<{ listing: Listing; ask: number; rail: PaymentRail; scores: CandidateScores }> = [];

    for (const listing of listings) {
      const ask = askPriceOf(listing.fees, units);
      const audit: CandidateAudit = { listingId: listing.id, provider: listing.provider, askPrice: ask };
      // Usage-based deals: surface the unit count + metered basis for transparency.
      if (listing.fees.kind === "per-unit") {
        audit.units = units;
        audit.feeBasis = {
          unit: listing.fees.unit,
          unitPrice: listing.fees.unitPrice,
          minTotal: listing.fees.minTotal,
        };
      }
      candidates.push(audit);

      // (1) Capability match — every required tag must be present.
      const have = new Set(listing.capabilities.map((c) => c.toLowerCase()));
      const missing = goal.requiredCapabilities.filter((c) => !have.has(c.toLowerCase()));
      if (missing.length > 0) {
        audit.excluded = `capability mismatch: missing [${missing.join(", ")}]`;
        continue;
      }

      // (2) Payable rail — must support at least one configured rail.
      const rail = this.bestRail(listing.rails);
      if (rail === null) {
        audit.excluded = `no supported payment rail (offers: ${listing.rails.join(", ") || "none"})`;
        continue;
      }
      audit.chosenRail = rail;

      // (3) Budget — a non-negotiable ask over budget can never conclude.
      // Negotiable over-budget listings stay in: the floor is private, so the
      // only way to learn whether they'll meet the budget is to negotiate.
      if (!listing.negotiable && ask > budget) {
        audit.excluded = `over budget: fixed ask $${ask.toFixed(2)} > $${budget.toFixed(2)} (non-negotiable)`;
        continue;
      }

      const scores = this.score(listing, ask, rail, budget);
      audit.scores = scores;
      viable.push({ listing, ask, rail, scores });
    }

    // Highest total first; deterministic id tiebreak.
    viable.sort((a, b) => b.scores.total - a.scores.total || a.listing.id.localeCompare(b.listing.id));

    // Attempt candidates in score order until one concludes within budget.
    const negotiations: NegotiationTranscript[] = [];
    let winner: ProcurementAgreement | undefined;

    for (const cand of viable) {
      if (cand.listing.negotiable) {
        // Multi-dimensional RFQ path: a goal that carries an `rfq` brief AND a
        // counterparty that implements `negotiateRfq` negotiate tier×deadline×
        // price instead of collapsing to a scalar offer. Otherwise: scalar path,
        // byte-for-byte unchanged.
        if (goal.rfq && this.counterparty.negotiateRfq) {
          const rfq = await this.counterparty.negotiateRfq(cand.listing.id, goal.rfq);
          negotiations.push(this.rfqTranscript(cand.listing.id, cand.ask, goal.rfq, rfq));
          if (rfq.result !== "agreed" || rfq.terms === undefined) continue;
          winner = this.agreementFor(cand.listing, goal, roundCents(rfq.terms.price), cand.rail, true, rfq.terms);
        } else {
          const transcript = await this.negotiate(cand.listing.id, cand.ask, budget);
          negotiations.push(transcript);
          if (transcript.result !== "agreed" || transcript.agreedPrice === undefined) continue;
          winner = this.agreementFor(cand.listing, goal, transcript.agreedPrice, cand.rail, true);
        }
      } else {
        // Non-negotiable survivors are already within budget (step 3).
        winner = this.agreementFor(cand.listing, goal, cand.ask, cand.rail, false);
      }
      break;
    }

    return {
      goal,
      budget,
      outcome: winner ? "awarded" : "no-award",
      winner,
      candidates,
      negotiations,
    };
  }

  // -------------------------------------------------------------------------
  // Negotiation (bounded, deterministic)
  // -------------------------------------------------------------------------

  private async negotiate(listingId: string, ask: number, budget: number): Promise<NegotiationTranscript> {
    const { openDiscount, concessionRate, maxRounds } = this.config.negotiation;
    const reservation = roundCents(Math.min(budget, ask));
    const rounds: NegotiationTranscript["rounds"] = [];

    let willingness = roundCents(Math.min(reservation, ask * (1 - openDiscount)));

    for (let r = 1; r <= maxRounds; r++) {
      const offer = r === maxRounds ? reservation : willingness;
      rounds.push({ round: r, actor: "buyer", action: "offer", price: offer });

      const resp = await this.counterparty.respond(listingId, offer, r);
      if (resp.type === "accept") {
        rounds.push({ round: r, actor: "seller", action: "accept", price: resp.price });
        return { listingId, ask, reservation, rounds, result: "agreed", agreedPrice: roundCents(resp.price) };
      }
      if (resp.type === "reject") {
        rounds.push({ round: r, actor: "seller", action: "walk" });
        break;
      }

      const counter = roundCents(resp.price);
      rounds.push({ round: r, actor: "seller", action: "counter", price: counter });

      // Concede toward the reservation price; take the counter if it is
      // already at or below where we were headed next.
      willingness = roundCents(willingness + (reservation - willingness) * concessionRate);
      if (counter <= willingness) {
        rounds.push({ round: r, actor: "buyer", action: "accept", price: counter });
        return { listingId, ask, reservation, rounds, result: "agreed", agreedPrice: counter };
      }
    }

    rounds.push({ round: rounds.length ? rounds[rounds.length - 1]!.round : maxRounds, actor: "buyer", action: "walk" });
    return { listingId, ask, reservation, rounds, result: "walked" };
  }

  /** Record a multi-dimensional RFQ negotiation as a transcript for the audit trail. */
  private rfqTranscript(listingId: string, ask: number, req: RfqRequest, rfq: RfqOutcome): NegotiationTranscript {
    return {
      listingId,
      ask,
      reservation: roundCents(req.budget),
      rounds: [], // RFQ moves are multi-dimensional, not scalar rounds — see `rfq`.
      result: rfq.result,
      agreedPrice: rfq.terms ? roundCents(rfq.terms.price) : undefined,
      rfq,
    };
  }

  // -------------------------------------------------------------------------
  // Scoring
  // -------------------------------------------------------------------------

  private bestRail(offered: PaymentRail[]): PaymentRail | null {
    for (const rail of this.config.railPreference) {
      if (offered.includes(rail)) return rail;
    }
    return null;
  }

  private score(listing: Listing, ask: number, rail: PaymentRail, budget: number): CandidateScores {
    const w = this.config.weights;

    // Cheaper relative to budget is better; over-budget (negotiable) asks floor at 0.
    const price = clamp01(1 - ask / budget);

    // Most-preferred rail = 1, least = 1/n.
    const n = this.config.railPreference.length;
    const rank = this.config.railPreference.indexOf(rail);
    const railScore = (n - rank) / n;

    // Track record: rating dominates, volume adds confidence, disputes discount.
    const q = listing.quality;
    const quality = clamp01(
      ((q.rating / 5) * 0.7 + (Math.min(q.completedJobs, 50) / 50) * 0.3) * (1 - q.disputeRate),
    );

    const total = w.price * price + w.rail * railScore + w.quality * quality;
    const r3 = (x: number) => Math.round(x * 1000) / 1000;
    return { price: r3(price), rail: r3(railScore), quality: r3(quality), total: r3(total) };
  }

  private agreementFor(
    listing: Listing,
    goal: ProcurementGoal,
    price: number,
    rail: PaymentRail,
    negotiated: boolean,
    agreedTerms?: NegotiatedTerms,
  ): ProcurementAgreement {
    return {
      listingId: listing.id,
      provider: listing.provider,
      goal: goal.description,
      price,
      rail,
      negotiated,
      acceptance: listing.acceptance,
      ...(agreedTerms ? { agreedTerms } : {}),
    };
  }

  // -------------------------------------------------------------------------
  // Deliverable acceptance
  // -------------------------------------------------------------------------

  /**
   * Apply the mechanical checks the listing declared. Three outcomes:
   *   accept          — every declared check passed
   *   reject          — a declared check failed (with the reason)
   *   needs-evaluator — the listing declared no mechanical checks, so this
   *                     deliverable needs subjective evaluation
   */
  acceptDeliverable(deliverable: Deliverable, agreement: ProcurementAgreement): AcceptanceResult {
    const checks = agreement.acceptance?.checks ?? [];
    if (checks.length === 0) {
      return {
        verdict: "needs-evaluator",
        reason: `listing ${agreement.listingId} declares no mechanical acceptance checks`,
      };
    }

    const checksRun: string[] = [];
    for (const check of checks) {
      checksRun.push(check.kind);
      switch (check.kind) {
        case "sha256": {
          const actual = createHash("sha256").update(deliverable.content, "utf8").digest("hex");
          if (actual !== check.expected) {
            return {
              verdict: "reject",
              reason: `sha256 mismatch: expected ${check.expected.slice(0, 12)}…, got ${actual.slice(0, 12)}…`,
              checksRun,
            };
          }
          break;
        }
        case "content-includes":
          if (!deliverable.content.includes(check.needle)) {
            return {
              verdict: "reject",
              reason: `content missing required marker "${check.needle}"`,
              checksRun,
            };
          }
          break;
        case "min-length":
          if (deliverable.content.length < check.minChars) {
            return {
              verdict: "reject",
              reason: `content too short: ${deliverable.content.length} < ${check.minChars} chars`,
              checksRun,
            };
          }
          break;
      }
    }
    return { verdict: "accept", checksRun };
  }
}
