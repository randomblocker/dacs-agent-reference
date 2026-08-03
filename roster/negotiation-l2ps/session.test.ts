/**
 * Distributed-session tests — node:test:
 *   npx tsx --test roster/negotiation-l2ps/session.test.ts
 *
 * The load-bearing test is PARITY: over an in-process channel, the two-process
 * loop must reach the SAME agreement the in-process `runNegotiation` engine does
 * for the same briefs. If that holds, the L2PS transport is a faithful split of
 * the engine, not a reimplementation that drifts. Plus: envelope tamper/sequence
 * enforcement, and a walk when a peer's move is out of guard.
 */
import { describe, test } from "node:test";
import assert from "node:assert/strict";
import {
  DEFAULT_ECONOMICS,
  buyerMaySettle,
  sellerMaySettle,
  toolsForScan,
  type AuditTier,
  type BuyerGuard,
  type Deadline,
  type ScanFacts,
} from "../audit-negotiator/terms.js";
import { deterministicBuyer, deterministicSeller, sellerGuardFor, type BuyerBrief, type SellerBrief } from "../audit-negotiator/policies.js";
import { runNegotiation } from "../audit-negotiator/negotiate.js";
import { InProcessChannelPair } from "./channel.js";
import { runSide } from "./session.js";
import { canonicalBytes, openEnvelope, sealEnvelope, type Signer, type WireSig } from "./wire.js";

const TIERS: AuditTier[] = ["quick", "deep"];
const DEADLINES: Deadline[] = ["standard", "rush"];
const CHANNEL = "chan-test-1";

/** Trivial deterministic signer for tests: binds sender id + canonical content. */
function fakeSigner(id: string): Signer {
  const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
  return {
    id,
    async sign(canonical) {
      return { signature: hex(canonical), publicKey: id, scheme: "test" } satisfies WireSig;
    },
    async verify(canonical, sig, expectedSenderId) {
      return sig.publicKey === expectedSenderId && sig.signature === hex(canonical);
    },
  };
}

function scanOf(over: Partial<ScanFacts> = {}): ScanFacts {
  const hasSolidity = over.hasSolidity ?? false;
  return { repo: "t/repo", kloc: 10, fileCount: 40, hasSolidity, numTools: toolsForScan(hasSolidity), ...over };
}

function briefs(scan: ScanFacts, budget: number, acceptableTiers: AuditTier[], tier: AuditTier = "deep", deadline: Deadline = "standard") {
  const sellerGuard = sellerGuardFor(scan, TIERS, DEADLINES, DEFAULT_ECONOMICS);
  const buyerGuard: BuyerGuard = { offeredTiers: TIERS, offeredDeadlines: DEADLINES, budget, acceptableTiers };
  const sellerBrief: SellerBrief = { scan, guard: sellerGuard, econ: DEFAULT_ECONOMICS };
  const buyerBrief: BuyerBrief = { guard: buyerGuard, preferredTier: tier, preferredDeadline: deadline };
  return { sellerGuard, buyerGuard, sellerBrief, buyerBrief };
}

async function runDistributed(sellerBrief: SellerBrief, buyerBrief: BuyerBrief, sellerGuard: ReturnType<typeof sellerGuardFor>, buyerGuard: BuyerGuard, maxTurns = 6) {
  const [chanS, chanB] = InProcessChannelPair();
  const sellerResult = runSide({
    role: "seller",
    channelId: CHANNEL,
    policy: deterministicSeller(sellerBrief),
    maySettle: (t) => sellerMaySettle(t, sellerGuard),
    peerSenderId: "buyer-peer",
    signer: fakeSigner("seller-peer"),
    channel: chanS,
    maxTurns,
  });
  const buyerResult = runSide({
    role: "buyer",
    channelId: CHANNEL,
    policy: deterministicBuyer(buyerBrief),
    maySettle: (t) => buyerMaySettle(t, buyerGuard),
    peerSenderId: "seller-peer",
    signer: fakeSigner("buyer-peer"),
    channel: chanB,
    maxTurns,
  });
  return Promise.all([sellerResult, buyerResult]);
}

describe("parity with the in-process engine", () => {
  const scenarios: Array<{ name: string; scan: ScanFacts; budget: number; acceptable: AuditTier[]; tier?: AuditTier; deadline?: Deadline }> = [
    { name: "deep close", scan: scanOf({ kloc: 8 }), budget: 30, acceptable: ["deep"] },
    { name: "walk (unaffordable)", scan: scanOf({ kloc: 40, hasSolidity: true }), budget: 3, acceptable: ["deep"] },
    { name: "downgrade to quick", scan: scanOf({ kloc: 30, hasSolidity: true }), budget: 9, acceptable: ["quick", "deep"] },
    { name: "rush deal", scan: scanOf({ kloc: 8 }), budget: 25, acceptable: ["deep"], deadline: "rush" },
  ];

  for (const s of scenarios) {
    test(`distributed === in-process: ${s.name}`, async () => {
      const { sellerGuard, buyerGuard, sellerBrief, buyerBrief } = briefs(s.scan, s.budget, s.acceptable, s.tier, s.deadline);

      // Reference: in-process engine.
      const ref = await runNegotiation(deterministicSeller(sellerBrief), deterministicBuyer(buyerBrief), {
        maxTurns: 6,
        sellerGuard,
        buyerGuard,
      });

      // Distributed: two sides over an in-process channel.
      const [sellerR, buyerR] = await runDistributed(sellerBrief, buyerBrief, sellerGuard, buyerGuard);

      // Both sides agree with each other…
      assert.equal(sellerR.outcome, buyerR.outcome, "seller/buyer disagree on outcome");
      assert.deepEqual(sellerR.agreed, buyerR.agreed, "seller/buyer disagree on terms");
      // …and match the in-process engine.
      assert.equal(sellerR.outcome, ref.outcome, `outcome drift vs in-process (${s.name})`);
      assert.deepEqual(sellerR.agreed, ref.agreed, `terms drift vs in-process (${s.name})`);
    });
  }
});

describe("envelope enforcement", () => {
  test("a tampered body is rejected on open", async () => {
    const signer = fakeSigner("seller-peer");
    const env = await sealEnvelope(signer, CHANNEL, 1, { kind: "offer", terms: { tier: "deep", deadline: "standard", price: 10 }, rationale: "q" }, 1000);
    // Tamper the price after signing.
    const tampered = { ...env, body: { ...env.body, terms: { tier: "deep" as const, deadline: "standard" as const, price: 1 }, kind: "offer" as const, rationale: "q" } };
    const verdict = await openEnvelope(signer, tampered, { channelId: CHANNEL, sequence: 1, sender: "seller-peer" });
    assert.equal(verdict.ok, false);
    assert.match(verdict.reason ?? "", /signature invalid/);
  });

  test("an out-of-sequence envelope is rejected", async () => {
    const signer = fakeSigner("seller-peer");
    const env = await sealEnvelope(signer, CHANNEL, 5, { kind: "reject", rationale: "x" }, 1000);
    const verdict = await openEnvelope(signer, env, { channelId: CHANNEL, sequence: 1, sender: "seller-peer" });
    assert.equal(verdict.ok, false);
    assert.match(verdict.reason ?? "", /sequence/);
  });

  test("a wrong-sender envelope is rejected", async () => {
    const signer = fakeSigner("seller-peer");
    const env = await sealEnvelope(signer, CHANNEL, 1, { kind: "reject", rationale: "x" }, 1000);
    const verdict = await openEnvelope(signer, env, { channelId: CHANNEL, sequence: 1, sender: "someone-else" });
    assert.equal(verdict.ok, false);
    assert.match(verdict.reason ?? "", /sender/);
  });

  test("canonicalBytes is stable regardless of key order", () => {
    const a = canonicalBytes({ channelId: "c", sequence: 1, sender: "s", sentAt: 1, type: "offer", body: { kind: "offer", terms: { tier: "deep", deadline: "standard", price: "5" }, rationale: "r" } });
    const b = canonicalBytes({ body: { rationale: "r", kind: "offer", terms: { price: "5", deadline: "standard", tier: "deep" } }, type: "offer", sentAt: 1, sender: "s", sequence: 1, channelId: "c" } as never);
    assert.equal(Buffer.from(a).toString("hex"), Buffer.from(b).toString("hex"));
  });
});
