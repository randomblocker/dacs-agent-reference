/**
 * Butler bridge — the multi-dimensional RFQ engine behind the Butler's
 * `NegotiationPort.negotiateRfq` seam.
 *
 * The Procurement Butler's scalar `respond(listingId, offer, round)` can only
 * move price; it cannot express the audit desk's tier × deadline dimensions, so
 * collapsing to it loses the whole point of the negotiation (the cross-dimension
 * move — "deep won't reach your budget, take the quick tier"). This class
 * implements the ADDITIVE `negotiateRfq` seam (`procurement-butler/types.ts`):
 * given the buyer's RFQ brief (budget + acceptable tiers + preference) and the
 * desk's PRIVATE pre-scan, it runs the real `runNegotiation` engine — the same
 * guard-bound, deterministic-or-LLM core the desk's own demo uses — and returns
 * the agreed `AuditTerms` as structural `NegotiatedTerms`. The agreed price then
 * flows into the Butler's `ProcurementAgreement` as the settlement amount, and
 * the tier/deadline ride along in `agreedTerms`.
 *
 * Note on topology: the core engine runs BOTH policies in-process (it is
 * substrate-independent by design — the `Turn[]` transcript is exactly what an
 * L2PS `ChannelSession` would carry over two processes). So this bridge supplies
 * the seller brief (private scan → floors) AND builds the buyer brief from the
 * Butler's RFQ request, then runs the two-sided negotiation locally. Splitting
 * the two policies across a signed L2PS transport — and binding the agreed terms
 * into a full `AgreementDocument` — are the documented follow-ups (see README);
 * this delivers the reachable-agreement bridge, not the wire transport.
 */
import { runNegotiation, type NegotiationConfig } from "./negotiate.js";
import {
  deterministicBuyer,
  deterministicSeller,
  sellerGuardFor,
  type BuyerBrief,
  type Policy,
  type SellerBrief,
} from "./policies.js";
import { llmBuyer, llmSeller, type LlmPolicyOpts } from "./llm-policy.js";
import {
  DEFAULT_ECONOMICS,
  type AuditTier,
  type BuyerGuard,
  type Deadline,
  type DeskEconomics,
  type ScanFacts,
} from "./terms.js";
import type {
  NegotiationPort,
  NegotiationResponse,
  RfqOutcome,
  RfqRequest,
} from "../procurement-butler/types.js";

const OFFERED_TIERS: AuditTier[] = ["quick", "deep"];
const OFFERED_DEADLINES: Deadline[] = ["standard", "rush"];
const KNOWN_TIERS = new Set<string>(OFFERED_TIERS);
const KNOWN_DEADLINES = new Set<string>(OFFERED_DEADLINES);

export interface AuditDeskConfig {
  /** The seller's PRIVATE pre-scan of the target — drives its per-tier floors. */
  scan: ScanFacts;
  econ?: DeskEconomics;
  /** Tiers the desk offers (default quick + deep). */
  offeredTiers?: AuditTier[];
  /** Deadlines the desk offers (default standard + rush). */
  offeredDeadlines?: Deadline[];
  /** RFQ-1 turn cap (default 6, DACS-3 RFQ default). */
  maxTurns?: number;
  /**
   * When set, run LLM policies (each with its deterministic fallback + the
   * input-injection scanner on counterparty text) instead of pure deterministic.
   */
  llm?: { seller?: LlmPolicyOpts; buyer?: LlmPolicyOpts };
}

/**
 * A DACS negotiation counterparty for the audit-negotiation desk. Implements the
 * Butler's `NegotiationPort`: the scalar `respond` is not this desk's channel
 * (it is RFQ-native), so it rejects — a scalar-only Butler simply walks and
 * chooses another provider. The real path is `negotiateRfq`.
 */
export class AuditDeskCounterparty implements NegotiationPort {
  constructor(private readonly cfg: AuditDeskConfig) {}

  /** Scalar path not supported — the desk negotiates multi-dimensionally. */
  async respond(): Promise<NegotiationResponse> {
    return { type: "reject" };
  }

  /** Run the real multi-dimensional RFQ engine and return the agreed terms. */
  async negotiateRfq(_listingId: string, req: RfqRequest): Promise<RfqOutcome> {
    const tiers = this.cfg.offeredTiers ?? OFFERED_TIERS;
    const deadlines = this.cfg.offeredDeadlines ?? OFFERED_DEADLINES;
    const econ = this.cfg.econ ?? DEFAULT_ECONOMICS;
    const maxTurns = this.cfg.maxTurns ?? 6;

    // Map the buyer's structural request into the desk's typed dimensions,
    // dropping anything the desk doesn't offer.
    const acceptableTiers = req.acceptableTiers.filter((t): t is AuditTier => KNOWN_TIERS.has(t) && tiers.includes(t as AuditTier));
    if (acceptableTiers.length === 0) {
      return { result: "walked", reason: `no acceptable tier in [${req.acceptableTiers.join(", ")}] is offered`, rounds: 0 };
    }
    const preferredTier: AuditTier =
      KNOWN_TIERS.has(req.preferredTier) && acceptableTiers.includes(req.preferredTier as AuditTier)
        ? (req.preferredTier as AuditTier)
        : acceptableTiers[0]!;
    const preferredDeadline: Deadline = KNOWN_DEADLINES.has(req.preferredDeadline) ? (req.preferredDeadline as Deadline) : "standard";

    const sellerGuard = sellerGuardFor(this.cfg.scan, tiers, deadlines, econ);
    const buyerGuard: BuyerGuard = { offeredTiers: tiers, offeredDeadlines: deadlines, budget: req.budget, acceptableTiers };
    const sellerBrief: SellerBrief = { scan: this.cfg.scan, guard: sellerGuard, econ };
    const buyerBrief: BuyerBrief = { guard: buyerGuard, preferredTier, preferredDeadline };

    const seller: Policy = this.cfg.llm ? llmSeller(sellerBrief, this.cfg.llm.seller) : deterministicSeller(sellerBrief);
    const buyer: Policy = this.cfg.llm ? llmBuyer(buyerBrief, this.cfg.llm.buyer) : deterministicBuyer(buyerBrief);

    const cfg: NegotiationConfig = { maxTurns, sellerGuard, buyerGuard };
    const r = await runNegotiation(seller, buyer, cfg);

    return {
      result: r.outcome,
      terms: r.agreed ? { tier: r.agreed.tier, deadline: r.agreed.deadline, price: r.agreed.price } : undefined,
      reason: r.reason,
      rounds: r.turns,
    };
  }
}
