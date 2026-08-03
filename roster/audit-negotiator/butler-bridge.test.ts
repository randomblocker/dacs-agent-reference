/**
 * Butler ↔ audit-negotiator RFQ bridge tests:
 *   npx tsx --test roster/audit-negotiator/butler-bridge.test.ts
 *
 * Covers:
 *   - the wire round-trip: an rfq-negotiable listing → Butler discovers →
 *     multi-dimensional RFQ via the desk → agreed terms → settlement amount;
 *   - the agreed price/tier honour both the desk floor and the buyer budget;
 *   - a tight budget on an rfq desk still downgrades tier (the cross-dimension
 *     move a scalar port can't make) rather than walking;
 *   - the additive path is inert on the scalar side: a goal WITHOUT `rfq`, or a
 *     counterparty WITHOUT `negotiateRfq`, behaves exactly as before.
 */
import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { ProcurementButler, DEFAULT_CONFIG } from "../procurement-butler/butler.js";
import { MarketplaceStub } from "../procurement-butler/marketplace-stub.js";
import type { Listing, MarketplacePort, NegotiationPort, ProcurementGoal } from "../procurement-butler/types.js";
import { AuditDeskCounterparty } from "./butler-bridge.js";
import { fakeScan } from "./scan.js";
import { floorFor, DEFAULT_ECONOMICS, type ScanFacts } from "./terms.js";

/** A minimal marketplace returning exactly the given listings (search over-returns). */
function marketOf(listings: Listing[]): MarketplacePort {
  return { async search() { return listings; } };
}

function rfqListing(over: Partial<Listing> = {}): Listing {
  return {
    id: "lst-audit-rfq",
    provider: "Audit-Negotiation Desk",
    description: "RFQ security audit",
    capabilities: ["security-audit", "audit-negotiator"],
    // Indicative ask for scoring only — the real price is negotiated.
    fees: { kind: "fixed", price: 20 },
    rails: ["pay-dem"],
    negotiable: true,
    quality: { rating: 4.8, completedJobs: 60, disputeRate: 0.0 },
    acceptance: { checks: [{ kind: "min-length", minChars: 10 }] },
    ...over,
  };
}

const GOAL_BASE: ProcurementGoal = { description: "audit our repo", requiredCapabilities: ["security-audit"] };

describe("RFQ round-trip through the Butler", () => {
  test("discovers rfq listing → runs multi-dim RFQ → agreed terms become the settlement amount", async () => {
    const scan = await fakeScan("acme/payments-api");
    const desk = new AuditDeskCounterparty({ scan });
    const budget = 40;
    const butler = new ProcurementButler(marketOf([rfqListing()]), desk, DEFAULT_CONFIG);

    const goal: ProcurementGoal = {
      ...GOAL_BASE,
      rfq: { budget, acceptableTiers: ["deep"], preferredTier: "deep", preferredDeadline: "standard" },
    };
    const decision = await butler.procure(goal, budget);

    assert.equal(decision.outcome, "awarded");
    assert.equal(decision.winner?.negotiated, true);
    // The agreed multi-dim terms rode along, and the settlement price == terms.price.
    assert.ok(decision.winner?.agreedTerms, "winner carries multi-dim agreedTerms");
    assert.equal(decision.winner!.agreedTerms!.tier, "deep");
    assert.equal(decision.winner!.price, decision.winner!.agreedTerms!.price, "settlement amount = agreed terms price");
    // Honours BOTH the desk floor and the buyer budget.
    const floor = floorFor(scan, "deep", decision.winner!.agreedTerms!.deadline as "standard" | "rush", DEFAULT_ECONOMICS);
    assert.ok(decision.winner!.price >= floor, `price ${decision.winner!.price} >= floor ${floor}`);
    assert.ok(decision.winner!.price <= budget, `price ${decision.winner!.price} <= budget ${budget}`);
    // The audit trail carries the RFQ outcome.
    const nego = decision.negotiations.find((n) => n.listingId === "lst-audit-rfq");
    assert.ok(nego?.rfq, "negotiation transcript carries the rfq outcome");
    assert.equal(nego!.rfq!.result, "agreed");
    assert.ok(nego!.rfq!.rounds >= 1);
  });

  test("tight budget downgrades tier via RFQ (the cross-dimension move) rather than walking", async () => {
    // A big Solidity repo: deep floor is high; budget below deep but the buyer
    // accepts quick → the desk downgrades the tier instead of walking.
    const scan: ScanFacts = { repo: "defi/huge", kloc: 30, fileCount: 80, hasSolidity: true, numTools: 2 };
    const deepFloor = floorFor(scan, "deep", "standard", DEFAULT_ECONOMICS);
    const quickFloor = floorFor(scan, "quick", "standard", DEFAULT_ECONOMICS);
    const budget = Math.round(((deepFloor + quickFloor) / 2) * 100) / 100;
    assert.ok(budget < deepFloor && budget >= quickFloor, "budget between quick and deep floors");

    const desk = new AuditDeskCounterparty({ scan });
    const butler = new ProcurementButler(marketOf([rfqListing()]), desk, DEFAULT_CONFIG);
    const goal: ProcurementGoal = {
      ...GOAL_BASE,
      rfq: { budget, acceptableTiers: ["quick", "deep"], preferredTier: "deep", preferredDeadline: "standard" },
    };
    const decision = await butler.procure(goal, budget);
    assert.equal(decision.outcome, "awarded");
    assert.equal(decision.winner!.agreedTerms!.tier, "quick", "downgraded to quick");
    assert.ok(decision.winner!.price <= budget);
  });

  test("unreachable budget on an rfq desk walks (no award)", async () => {
    const scan: ScanFacts = { repo: "defi/huge", kloc: 40, fileCount: 100, hasSolidity: true, numTools: 2 };
    const desk = new AuditDeskCounterparty({ scan });
    const butler = new ProcurementButler(marketOf([rfqListing()]), desk, DEFAULT_CONFIG);
    const goal: ProcurementGoal = {
      ...GOAL_BASE,
      rfq: { budget: 1, acceptableTiers: ["deep"], preferredTier: "deep", preferredDeadline: "standard" },
    };
    const decision = await butler.procure(goal, 1);
    assert.equal(decision.outcome, "no-award");
    const nego = decision.negotiations.find((n) => n.listingId === "lst-audit-rfq");
    assert.equal(nego?.rfq?.result, "walked");
  });
});

describe("additive path is inert on the scalar side", () => {
  test("a goal WITHOUT rfq against an rfq desk uses the scalar path (desk rejects → walk)", async () => {
    const scan = await fakeScan("acme/payments-api");
    const desk = new AuditDeskCounterparty({ scan });
    const butler = new ProcurementButler(marketOf([rfqListing()]), desk, DEFAULT_CONFIG);
    // No goal.rfq ⇒ Butler runs the scalar negotiate() path; the desk's scalar
    // respond() rejects ⇒ the negotiation walks ⇒ no award.
    const decision = await butler.procure(GOAL_BASE, 40);
    assert.equal(decision.outcome, "no-award");
    const nego = decision.negotiations.find((n) => n.listingId === "lst-audit-rfq");
    assert.equal(nego?.result, "walked");
    assert.equal(nego?.rfq, undefined, "scalar path produced no rfq detail");
  });

  test("a scalar counterparty (no negotiateRfq) is unaffected even when goal.rfq is set", async () => {
    // MarketplaceStub implements only the scalar respond(); with a real floor it
    // haggles scalar-ly. goal.rfq is present but ignored (no negotiateRfq).
    const listing = rfqListing({ id: "lst-scalar", negotiable: true, fees: { kind: "fixed", price: 9 } });
    const stub = new MarketplaceStub([listing], { floors: { "lst-scalar": 3 }, concessionStep: 0.3 });
    const butler = new ProcurementButler(stub, stub, DEFAULT_CONFIG);
    const goal: ProcurementGoal = {
      ...GOAL_BASE,
      rfq: { budget: 5, acceptableTiers: ["deep"], preferredTier: "deep", preferredDeadline: "standard" },
    };
    const decision = await butler.procure(goal, 5);
    assert.equal(decision.outcome, "awarded", "scalar haggle still closes");
    assert.equal(decision.winner?.negotiated, true);
    assert.equal(decision.winner?.agreedTerms, undefined, "scalar path carries no multi-dim terms");
    const nego = decision.negotiations.find((n) => n.listingId === "lst-scalar");
    assert.ok(nego?.rounds.length && nego.rounds.length > 0, "scalar rounds recorded (not the rfq path)");
    assert.equal(nego?.rfq, undefined);
  });
});
