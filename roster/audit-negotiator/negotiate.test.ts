/**
 * Negotiated Security-Audit Desk tests — node:test + node:assert:
 *   npx tsx --test roster/audit-negotiator/negotiate.test.ts
 *
 * Covers the invariants that matter: the guard can never be breached, agreements
 * land within both sides' bounds, the cross-dimension tier-downgrade fires when
 * budget can't reach the deep floor, the LLM path parses and — crucially — falls
 * back deterministically on garbage/out-of-guard output, and the harness always
 * terminates within maxTurns.
 */
import { describe, test } from "node:test";
import assert from "node:assert/strict";
import {
  askFor,
  buyerMaySettle,
  costFor,
  DEFAULT_ECONOMICS,
  floorFor,
  sellerMaySettle,
  toolsForScan,
  type AuditTier,
  type BuyerGuard,
  type Deadline,
  type ScanFacts,
} from "./terms.js";
import {
  deterministicBuyer,
  deterministicSeller,
  sellerGuardFor,
  type BuyerBrief,
  type Policy,
  type SellerBrief,
} from "./policies.js";
import { runNegotiation, type NegotiationConfig } from "./negotiate.js";
import { buildSellerPrompt, llmBuyer, llmSeller, parseMove, type LlmFn } from "./llm-policy.js";
import { fakeScan } from "./scan.js";

const TIERS: AuditTier[] = ["quick", "deep"];
const DEADLINES: Deadline[] = ["standard", "rush"];

function scanOf(over: Partial<ScanFacts> = {}): ScanFacts {
  const hasSolidity = over.hasSolidity ?? false;
  return { repo: "t/repo", kloc: 10, fileCount: 40, hasSolidity, numTools: toolsForScan(hasSolidity), ...over };
}

function setup(scan: ScanFacts, buyer: { budget: number; acceptableTiers: AuditTier[]; tier?: AuditTier; deadline?: Deadline }) {
  const sellerGuard = sellerGuardFor(scan, TIERS, DEADLINES, DEFAULT_ECONOMICS);
  const buyerGuard: BuyerGuard = {
    offeredTiers: TIERS,
    offeredDeadlines: DEADLINES,
    budget: buyer.budget,
    acceptableTiers: buyer.acceptableTiers,
  };
  const sellerBrief: SellerBrief = { scan, guard: sellerGuard, econ: DEFAULT_ECONOMICS };
  const buyerBrief: BuyerBrief = {
    guard: buyerGuard,
    preferredTier: buyer.tier ?? "deep",
    preferredDeadline: buyer.deadline ?? "standard",
  };
  const cfg: NegotiationConfig = { maxTurns: 6, sellerGuard, buyerGuard };
  return { sellerGuard, buyerGuard, sellerBrief, buyerBrief, cfg };
}

// ---------------------------------------------------------------------------

describe("cost model", () => {
  test("deep costs more than quick; rush costs more than standard; floor > cost; ask > floor", () => {
    const scan = scanOf({ kloc: 12, hasSolidity: true });
    assert.ok(costFor(scan, "deep", "standard") > costFor(scan, "quick", "standard"));
    assert.ok(costFor(scan, "deep", "rush") > costFor(scan, "deep", "standard"));
    assert.ok(floorFor(scan, "deep", "standard") > costFor(scan, "deep", "standard"));
    assert.ok(askFor(scan, "deep", "standard") > floorFor(scan, "deep", "standard"));
  });

  test("solidity adds a tool, raising deep cost", () => {
    const noSol = scanOf({ hasSolidity: false, numTools: toolsForScan(false) });
    const sol = scanOf({ hasSolidity: true, numTools: toolsForScan(true) });
    assert.equal(noSol.numTools, 1);
    assert.equal(sol.numTools, 2);
    assert.ok(costFor(sol, "deep", "standard") > costFor(noSol, "deep", "standard"));
  });
});

describe("deterministic negotiation", () => {
  test("a generous budget closes on the deep tier within both guards", async () => {
    const scan = scanOf({ kloc: 8, hasSolidity: false });
    const { sellerBrief, buyerBrief, cfg, sellerGuard, buyerGuard } = setup(scan, { budget: 30, acceptableTiers: ["deep"] });
    const r = await runNegotiation(deterministicSeller(sellerBrief), deterministicBuyer(buyerBrief), cfg);
    assert.equal(r.outcome, "agreed");
    assert.ok(r.agreed);
    assert.equal(r.agreed!.tier, "deep");
    // Agreement respects BOTH guards.
    assert.ok(sellerMaySettle(r.agreed!, sellerGuard).ok, "seller floor honoured");
    assert.ok(buyerMaySettle(r.agreed!, buyerGuard).ok, "buyer budget honoured");
  });

  test("a tight budget that accepts quick is downgraded rather than walked", async () => {
    const scan = scanOf({ kloc: 30, hasSolidity: true }); // deep floor is high
    const deepFloor = floorFor(scan, "deep", "standard");
    const quickFloor = floorFor(scan, "quick", "standard");
    // Budget below the deep floor but above the quick floor.
    const budget = Math.round(((deepFloor + quickFloor) / 2) * 100) / 100;
    assert.ok(budget < deepFloor && budget >= quickFloor);
    const { sellerBrief, buyerBrief, cfg } = setup(scan, { budget, acceptableTiers: ["quick", "deep"] });
    const r = await runNegotiation(deterministicSeller(sellerBrief), deterministicBuyer(buyerBrief), cfg);
    assert.equal(r.outcome, "agreed");
    assert.equal(r.agreed!.tier, "quick", "should downgrade to quick");
    assert.ok(r.agreed!.price <= budget);
  });

  test("a budget below every floor walks", async () => {
    const scan = scanOf({ kloc: 40, hasSolidity: true });
    const { sellerBrief, buyerBrief, cfg } = setup(scan, { budget: 1, acceptableTiers: ["deep"] });
    const r = await runNegotiation(deterministicSeller(sellerBrief), deterministicBuyer(buyerBrief), cfg);
    assert.equal(r.outcome, "walked");
    assert.equal(r.agreed, undefined);
  });

  test("harness always terminates within maxTurns", async () => {
    const scan = scanOf();
    const { sellerBrief, buyerBrief, cfg } = setup(scan, { budget: 12, acceptableTiers: ["deep"] });
    const r = await runNegotiation(deterministicSeller(sellerBrief), deterministicBuyer(buyerBrief), cfg);
    assert.ok(r.turns <= cfg.maxTurns);
  });
});

describe("guard is unbreachable", () => {
  test("a rogue seller policy that offers below floor is caught and walks", async () => {
    const scan = scanOf({ kloc: 10 });
    const { buyerBrief, cfg, sellerGuard } = setup(scan, { budget: 50, acceptableTiers: ["deep"] });
    // Rogue seller: always offers deep/standard at 0.01 (below any floor).
    const rogue: Policy = async () => ({
      kind: "offer",
      terms: { tier: "deep", deadline: "standard", price: 0.01 },
      rationale: "rogue",
    });
    const r = await runNegotiation(rogue, deterministicBuyer(buyerBrief), cfg);
    assert.equal(r.outcome, "walked");
    assert.match(r.reason, /out-of-guard/);
    // The floor was never actually crossed.
    assert.ok(0.01 < sellerGuard.floor("deep", "standard"));
  });

  test("a rogue buyer policy that accepts above budget is caught and walks", async () => {
    const scan = scanOf({ kloc: 10 });
    const { sellerBrief, cfg } = setup(scan, { budget: 3, acceptableTiers: ["deep"] });
    // Rogue buyer: offers deep/standard at 999 (over budget).
    const rogue: Policy = async () => ({
      kind: "offer",
      terms: { tier: "deep", deadline: "standard", price: 999 },
      rationale: "rogue",
    });
    const r = await runNegotiation(deterministicSeller(sellerBrief), rogue, cfg);
    assert.equal(r.outcome, "walked");
    assert.match(r.reason, /out-of-guard/);
  });
});

describe("LLM policy path", () => {
  test("parseMove tolerates fenced JSON and prose", () => {
    const raw = 'sure!\n```json\n{"kind":"counter","tier":"deep","deadline":"standard","price":9.5,"rationale":"meet me"}\n```';
    const m = parseMove(raw);
    assert.ok(m && m.kind === "counter");
    assert.equal(m.terms.price, 9.5);
  });

  test("parseMove returns undefined on garbage", () => {
    assert.equal(parseMove("no json here"), undefined);
    assert.equal(parseMove('{"kind":"bogus"}'), undefined);
  });

  test("accept fills tier/deadline from on-table terms", () => {
    const m = parseMove('{"kind":"accept","price":7,"rationale":"ok"}', { tier: "deep", deadline: "rush", price: 7 });
    assert.ok(m && m.kind === "accept");
    assert.equal(m.terms.tier, "deep");
    assert.equal(m.terms.deadline, "rush");
  });

  test("llm seller falls back deterministically when the CLI returns garbage", async () => {
    const scan = scanOf({ kloc: 8 });
    const { sellerBrief, buyerBrief, cfg, sellerGuard, buyerGuard } = setup(scan, { budget: 30, acceptableTiers: ["deep"] });
    const garbage: LlmFn = async () => "the model said no json";
    let fellBack = false;
    const seller = llmSeller(sellerBrief, { llm: garbage, onTurn: (i) => (fellBack ||= !i.usedLlm) });
    const r = await runNegotiation(seller, deterministicBuyer(buyerBrief), cfg);
    assert.ok(fellBack, "should have fallen back at least once");
    // Fallback still produced a valid, guard-respecting outcome.
    if (r.outcome === "agreed") {
      assert.ok(sellerMaySettle(r.agreed!, sellerGuard).ok);
      assert.ok(buyerMaySettle(r.agreed!, buyerGuard).ok);
    }
  });

  test("llm seller uses a well-formed, in-guard move when the CLI returns one", async () => {
    const scan = scanOf({ kloc: 8 });
    const floor = floorFor(scan, "deep", "standard");
    const price = Math.round((floor + 5) * 100) / 100;
    const { sellerBrief } = setup(scan, { budget: 30, acceptableTiers: ["deep"] });
    const good: LlmFn = async () => `{"kind":"offer","tier":"deep","deadline":"standard","price":${price},"rationale":"quote"}`;
    let usedLlm = false;
    const seller = llmSeller(sellerBrief, { llm: good, onTurn: (i) => (usedLlm ||= i.usedLlm) });
    const move = await seller({ transcript: [], round: 1, maxRounds: 3 });
    assert.ok(usedLlm);
    if (move.kind === "reject") assert.fail("expected an offer, got reject");
    assert.equal(move.kind, "offer");
    assert.equal(move.terms.price, price);
  });

  test("llm seller REJECTS a CLI move that breaches the floor and falls back", async () => {
    const scan = scanOf({ kloc: 8 });
    const { sellerBrief } = setup(scan, { budget: 30, acceptableTiers: ["deep"] });
    const belowFloor: LlmFn = async () => '{"kind":"offer","tier":"deep","deadline":"standard","price":0.01,"rationale":"too low"}';
    let usedLlm = true;
    const seller = llmSeller(sellerBrief, { llm: belowFloor, onTurn: (i) => (usedLlm &&= i.usedLlm) });
    const move = await seller({ transcript: [], round: 1, maxRounds: 3 });
    assert.equal(usedLlm, false, "out-of-guard LLM move must be rejected → fallback");
    if (move.kind === "reject") assert.fail("expected a fallback offer/counter, got reject");
    assert.ok(sellerMaySettle(move.terms, sellerBrief.guard).ok, "fallback move respects the floor");
  });

  test("buildSellerPrompt embeds the private floors and hides nothing structural", () => {
    const scan = scanOf({ kloc: 8 });
    const { sellerBrief } = setup(scan, { budget: 30, acceptableTiers: ["deep"] });
    const prompt = buildSellerPrompt(sellerBrief, { transcript: [], round: 1, maxRounds: 3 });
    assert.match(prompt, /floor/);
    assert.match(prompt, /deep\/standard/);
  });
});

describe("scan drives variance", () => {
  test("different repos scan differently and can produce different outcomes", async () => {
    const a = await fakeScan("org/small-ts-lib");
    const b = await fakeScan("org/huge-solidity-monorepo");
    assert.notDeepEqual(
      { kloc: a.kloc, sol: a.hasSolidity },
      { kloc: b.kloc, sol: b.hasSolidity },
      "fake scan should vary by repo",
    );
  });
});
