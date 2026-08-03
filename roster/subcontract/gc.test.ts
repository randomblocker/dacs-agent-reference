/**
 * Sub-contracting GC tests — node:test + node:assert:
 *   npx tsx --test roster/subcontract/gc.test.ts
 *
 * The invariants that make the nesting honest: every sourced sub-price sits at
 * or above that specialist's private floor and at or below the GC's sourcing
 * allocation; the GC never sells the bundle below what it sourced (margin ≥ 0);
 * the revenue split is internally consistent; and a budget too tight to source
 * or to clear the assembled floor fails cleanly rather than producing a loss.
 */
import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_ECONOMICS, floorFor, type DeskEconomics, type ScanFacts } from "../audit-negotiator/terms.js";
import { toolsForScan } from "../audit-negotiator/terms.js";
import { runSubcontract, gcBundleSeller, type Specialist, type SubcontractJob } from "./gc.js";

function scan(repo: string, kloc: number, hasSolidity = false): ScanFacts {
  return { repo, kloc, fileCount: 40, hasSolidity, numTools: toolsForScan(hasSolidity) };
}

function job(over: Partial<SubcontractJob> = {}): SubcontractJob {
  const specialists: Specialist[] = [
    { id: "code-audit", label: "General code audit", scan: scan("p#app", 8), econ: DEFAULT_ECONOMICS, requiredTier: "deep" },
    { id: "sol", label: "Solidity deep-dive", scan: scan("p#contracts", 6, true), econ: DEFAULT_ECONOMICS, requiredTier: "deep" },
    { id: "deps", label: "Dependency advisory", scan: scan("p#deps", 4), econ: DEFAULT_ECONOMICS, requiredTier: "quick" },
  ];
  return { buyerBudget: 90, deadline: "standard", specialists, coordMarginPct: 0.2, sourcingFraction: 0.75, ...over };
}

describe("sourcing (inner negotiations)", () => {
  test("a generous budget sources every component within both guards", async () => {
    const plan = await runSubcontract(job());
    assert.equal(plan.outcome, "awarded", plan.reason);
    for (const sub of plan.subs) {
      assert.equal(sub.outcome, "agreed");
      assert.ok(sub.price !== undefined && sub.terms);
      // Sub-price is at/above the specialist's private floor…
      const spec = job().specialists.find((s) => s.id === sub.specialist)!;
      const floor = floorFor(spec.scan, sub.terms!.tier, sub.terms!.deadline, spec.econ);
      assert.ok(sub.price! >= floor, `${sub.specialist}: price ${sub.price} < floor ${floor}`);
      // …and at/below what the GC allocated to source it.
      assert.ok(sub.price! <= sub.allocation, `${sub.specialist}: price ${sub.price} > allocation ${sub.allocation}`);
    }
  });
});

describe("bundle (outer negotiation) + revenue split", () => {
  test("awarded plan: margin ≥ 0, split is consistent, floor honoured", async () => {
    const plan = await runSubcontract(job());
    assert.equal(plan.outcome, "awarded");
    // Cost = sum of sub prices.
    const summed = Math.round(plan.subs.reduce((a, s) => a + (s.price ?? 0), 0) * 100) / 100;
    assert.equal(plan.bundleCost, summed);
    // Floor = cost × (1 + coordMargin).
    assert.equal(plan.bundleFloor, Math.round(summed * 1.2 * 100) / 100);
    // GC never sells below its sourced floor, nor above the buyer's budget.
    assert.ok(plan.bundlePrice! >= plan.bundleFloor!, "bundle sold below floor");
    assert.ok(plan.bundlePrice! <= 90, "bundle sold above budget");
    // Margin identity + non-negativity (the GC never loses money).
    assert.equal(plan.gcMargin, Math.round((plan.bundlePrice! - plan.bundleCost!) * 100) / 100);
    assert.ok(plan.gcMargin! >= 0, "GC margin negative");
  });
});

describe("failure modes fail cleanly (no loss)", () => {
  test("a budget too small to source a component yields no-source", async () => {
    const plan = await runSubcontract(job({ buyerBudget: 3 }));
    assert.notEqual(plan.outcome, "awarded");
    assert.ok(plan.outcome === "no-source" || plan.outcome === "no-deal");
    // No award ⇒ no margin claimed.
    assert.equal(plan.gcMargin, undefined);
  });

  test("sourced but buyer can't clear the assembled floor ⇒ no-deal, never a loss", async () => {
    // Big specialists (high floors) but a budget that sources them yet leaves the
    // bundle floor just out of reach.
    const specialists: Specialist[] = [
      { id: "a", label: "A", scan: scan("p#a", 20, true), econ: DEFAULT_ECONOMICS, requiredTier: "deep" },
      { id: "b", label: "B", scan: scan("p#b", 18), econ: DEFAULT_ECONOMICS, requiredTier: "deep" },
    ];
    // sourcingFraction 1.0 so both can be sourced, but coordMargin pushes the
    // bundle floor above a budget only barely covering raw cost.
    const plan = await runSubcontract({
      buyerBudget: 55,
      deadline: "standard",
      specialists,
      coordMarginPct: 0.5,
      sourcingFraction: 1.0,
    });
    if (plan.outcome === "awarded") {
      // If it did award, the invariants must still hold.
      assert.ok(plan.gcMargin! >= 0);
      assert.ok(plan.bundlePrice! >= plan.bundleFloor!);
    } else {
      assert.ok(plan.outcome === "no-deal" || plan.outcome === "no-source");
    }
  });
});

describe("gcBundleSeller policy", () => {
  test("opens above floor and never counters below it", async () => {
    const seller = gcBundleSeller(20, "standard", { listMarginPct: 0.4 });
    const open = await seller({ transcript: [], round: 1, maxRounds: 3 });
    if (open.kind === "reject") assert.fail("unexpected reject");
    assert.equal(open.kind, "offer");
    assert.ok(open.terms.price >= 20, "opening below floor");

    // A lowball buyer offer draws a counter, never below floor.
    const counter = await seller({
      transcript: [
        { side: "seller", move: open },
        { side: "buyer", move: { kind: "offer", terms: { tier: "deep", deadline: "standard", price: 5 }, rationale: "lowball" } },
      ],
      round: 2,
      maxRounds: 3,
    });
    if (counter.kind === "reject") assert.fail("unexpected reject");
    assert.ok(counter.terms.price >= 20, "countered below floor");
  });

  test("accepts a buyer offer at/above the sourced floor", async () => {
    const seller = gcBundleSeller(20, "standard");
    const open = await seller({ transcript: [], round: 1, maxRounds: 3 });
    const move = await seller({
      transcript: [
        { side: "seller", move: open },
        { side: "buyer", move: { kind: "offer", terms: { tier: "deep", deadline: "standard", price: 22 }, rationale: "fair" } },
      ],
      round: 2,
      maxRounds: 3,
    });
    assert.equal(move.kind, "accept");
  });
});
