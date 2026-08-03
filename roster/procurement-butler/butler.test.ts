/**
 * Procurement Butler tests — node:test + node:assert, run via:
 *   npx tsx --test roster/procurement-butler/butler.test.ts
 */
import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { ProcurementButler, DEFAULT_CONFIG, askPriceOf } from "./butler.js";
import { MarketplaceStub, STOCK_CATALOG, STOCK_SELLER_BOOK } from "./marketplace-stub.js";
import type { Listing, ProcurementAgreement, ProcurementGoal } from "./types.js";

const GOAL: ProcurementGoal = {
  description: "summarize this repository's architecture",
  requiredCapabilities: ["code-analysis", "summarization"],
  estimatedUnits: 4,
};

function listing(overrides: Partial<Listing> & { id: string }): Listing {
  return {
    provider: overrides.id,
    description: "test listing",
    capabilities: ["code-analysis", "summarization"],
    fees: { kind: "fixed", price: 4 },
    rails: ["pay-dem"],
    negotiable: false,
    quality: { rating: 4.0, completedJobs: 50, disputeRate: 0.0 },
    ...overrides,
  };
}

function butlerOver(listings: Listing[], floors: Record<string, number> = {}) {
  const market = new MarketplaceStub(listings, { floors, concessionStep: 0.3 });
  return new ProcurementButler(market, market, DEFAULT_CONFIG);
}

describe("capability filtering", () => {
  test("listings missing a required capability are excluded with a reason", async () => {
    const b = butlerOver([
      listing({ id: "match" }),
      listing({ id: "partial", capabilities: ["summarization", "image-generation"] }),
    ]);
    const d = await b.procure(GOAL, 5);

    const partial = d.candidates.find((c) => c.listingId === "partial");
    assert.ok(partial?.excluded, "partial-match listing should be excluded");
    assert.match(partial!.excluded!, /capability mismatch/);
    assert.match(partial!.excluded!, /code-analysis/);
    assert.equal(d.winner?.listingId, "match");
  });

  test("stock catalog: the image shop never survives filtering", async () => {
    const b = new ProcurementButler(new MarketplaceStub(), new MarketplaceStub());
    const d = await b.procure(GOAL, 5);
    const pixel = d.candidates.find((c) => c.listingId === "lst-pixel-forge");
    assert.match(pixel!.excluded!, /capability mismatch/);
  });
});

describe("budget exclusion", () => {
  test("a non-negotiable ask over budget is excluded before selection", async () => {
    const b = butlerOver([
      listing({ id: "pricey", fees: { kind: "fixed", price: 12 } }),
      listing({ id: "fits", fees: { kind: "fixed", price: 4 } }),
    ]);
    const d = await b.procure(GOAL, 5);

    const pricey = d.candidates.find((c) => c.listingId === "pricey");
    assert.match(pricey!.excluded!, /over budget/);
    assert.equal(d.winner?.listingId, "fits");
    // No negotiation was wasted on it.
    assert.ok(!d.negotiations.some((n) => n.listingId === "pricey"));
  });

  test("per-unit ask respects the billing floor (minTotal)", () => {
    assert.equal(askPriceOf({ kind: "per-unit", unitPrice: 0.9, unit: "module", minTotal: 2.7 }, 1), 2.7);
    assert.equal(askPriceOf({ kind: "per-unit", unitPrice: 0.9, unit: "module", minTotal: 2.7 }, 4), 3.6);
  });
});

describe("rail preference tiebreak", () => {
  test("identical listings differing only in rail: preferred rail wins", async () => {
    const b = butlerOver([
      listing({ id: "on-erc8183", rails: ["pay-evm-erc8183"] }),
      listing({ id: "on-dem", rails: ["pay-dem"] }),
    ]);
    const d = await b.procure(GOAL, 5);

    assert.equal(d.winner?.listingId, "on-dem");
    assert.equal(d.winner?.rail, "pay-dem");
    const loser = d.candidates.find((c) => c.listingId === "on-erc8183")!;
    const winner = d.candidates.find((c) => c.listingId === "on-dem")!;
    assert.ok(winner.scores!.total > loser.scores!.total, "rail score should decide the tie");
  });

  test("a listing supporting no configured rail is excluded", async () => {
    const only = listing({ id: "weird-rail", rails: [] });
    const b = butlerOver([only]);
    const d = await b.procure(GOAL, 5);
    assert.equal(d.outcome, "no-award");
    assert.match(d.candidates[0]!.excluded!, /no supported payment rail/);
  });
});

describe("negotiation", () => {
  test("converges to an agreed price below ask and at/above the seller floor", async () => {
    const b = butlerOver([listing({ id: "haggler", negotiable: true, fees: { kind: "fixed", price: 4.8 } })], {
      haggler: 3.2,
    });
    const d = await b.procure(GOAL, 5);

    assert.equal(d.outcome, "awarded");
    const n = d.negotiations.find((t) => t.listingId === "haggler")!;
    assert.equal(n.result, "agreed");
    assert.ok(n.agreedPrice! < n.ask, `agreed ${n.agreedPrice} should be below ask ${n.ask}`);
    assert.ok(n.agreedPrice! >= 3.2, `agreed ${n.agreedPrice} should respect the seller floor`);
    assert.ok(n.agreedPrice! <= 5, "agreed price must be within budget");
    assert.equal(d.winner?.price, n.agreedPrice);
    assert.equal(d.winner?.negotiated, true);
    // Transcript records both sides.
    assert.ok(n.rounds.some((r) => r.actor === "buyer" && r.action === "offer"));
    assert.ok(n.rounds.some((r) => r.actor === "seller"));
  });

  test("walks away when the seller's private floor exceeds the budget", async () => {
    const b = butlerOver([listing({ id: "too-proud", negotiable: true, fees: { kind: "fixed", price: 9 } })], {
      "too-proud": 7.5,
    });
    const d = await b.procure(GOAL, 5);

    assert.equal(d.outcome, "no-award");
    const n = d.negotiations.find((t) => t.listingId === "too-proud")!;
    assert.equal(n.result, "walked");
    assert.equal(n.agreedPrice, undefined);
    assert.equal(n.rounds.at(-1)?.action, "walk");
    // Bounded: buyer never offered more than its reservation (= budget here).
    for (const r of n.rounds) {
      if (r.actor === "buyer" && r.price !== undefined) assert.ok(r.price <= 5);
    }
  });

  test("after walking from the top candidate, the runner-up can still win (stock catalog)", async () => {
    const market = new MarketplaceStub(STOCK_CATALOG, STOCK_SELLER_BOOK);
    const b = new ProcurementButler(market, market);
    const d = await b.procure(GOAL, 5);

    assert.equal(d.outcome, "awarded");
    assert.equal(d.winner?.listingId, "lst-cartographer");
    assert.ok(d.winner!.price <= 5);
    const walked = d.negotiations.find((t) => t.listingId === "lst-premium-insights");
    assert.equal(walked?.result, "walked");
  });
});

describe("acceptDeliverable", () => {
  const agreement: ProcurementAgreement = {
    listingId: "lst-x",
    provider: "X",
    goal: GOAL.description,
    price: 4,
    rail: "pay-dem",
    negotiated: false,
    acceptance: {
      checks: [
        { kind: "content-includes", needle: "## Architecture" },
        { kind: "min-length", minChars: 40 },
      ],
    },
  };
  const b = butlerOver([]);

  test("accept: all declared mechanical checks pass", () => {
    const r = b.acceptDeliverable(
      { content: "## Architecture\n\nPorts and adapters, mock-first, tested end to end." },
      agreement,
    );
    assert.equal(r.verdict, "accept");
    assert.deepEqual((r as { checksRun: string[] }).checksRun, ["content-includes", "min-length"]);
  });

  test("reject: a failing check reports its reason", () => {
    const r = b.acceptDeliverable({ content: "lgtm." }, agreement);
    assert.equal(r.verdict, "reject");
    assert.match((r as { reason: string }).reason, /## Architecture/);
  });

  test("reject: sha256 mismatch", () => {
    const pinned: ProcurementAgreement = {
      ...agreement,
      acceptance: { checks: [{ kind: "sha256", expected: createHash("sha256").update("exact bytes").digest("hex") }] },
    };
    assert.equal(b.acceptDeliverable({ content: "exact bytes" }, pinned).verdict, "accept");
    const r = b.acceptDeliverable({ content: "different bytes" }, pinned);
    assert.equal(r.verdict, "reject");
    assert.match((r as { reason: string }).reason, /sha256 mismatch/);
  });

  test("needs-evaluator: listing declares no mechanical checks", () => {
    const r = b.acceptDeliverable({ content: "anything" }, { ...agreement, acceptance: undefined });
    assert.equal(r.verdict, "needs-evaluator");
    assert.match((r as { reason: string }).reason, /no mechanical acceptance checks/);
  });
});
