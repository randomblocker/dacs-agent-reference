/**
 * Treasury Ops tests — node:test + node:assert, fully offline. Run via:
 *   npx tsx --test roster/treasury-ops/treasury-ops.test.ts
 *
 * Journals go to per-test mkdtemp dirs, never the repo.
 */
import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { approve } from "./approval.js";
import { execute } from "./executor.js";
import { MockChain, MockChainCrash, portsFor } from "./mock-chain.js";
import { computeIntentId, computePlanHash, plan } from "./planner.js";
import { buildProof, TreasurySigner, verifyProof } from "./proof.js";
import type { BalanceSnapshot, ExecutionPlan, ExecutionResult, TreasuryPolicy } from "./types.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const POLICY: TreasuryPolicy = {
  policyId: "test-policy",
  accounts: [
    { id: "a1", chain: "c1", address: "T1", label: "chain-1 ops", minBalance: 100, targetPct: 60 },
    { id: "a2", chain: "c2", address: "T2", label: "chain-2 ops", minBalance: 50, targetPct: 40 },
  ],
  allowlist: [
    { address: "P1", chain: "c1", label: "payee one" },
    { address: "P2", chain: "c2", label: "payee two" },
  ],
  payroll: [
    { recipient: "P1", chain: "c1", amount: 100, label: "payee one", period: "2026-07" },
    { recipient: "P2", chain: "c2", amount: 80, label: "payee two", period: "2026-07" },
  ],
  perTxCap: 1000,
  perRunCap: 5000,
  feeBufferPerTx: 2,
};
const BALANCES: BalanceSnapshot = { a1: 2000, a2: 500 };
const CHAIN_INIT = { c1: { T1: 2000 }, c2: { T2: 500 } };

const APPROVER = new TreasurySigner("approver");
const EXECUTOR = new TreasurySigner("executor");

/** Recompute intentIds + planHash so a hand-edited plan is self-consistent. */
function rebuild(edited: ExecutionPlan): ExecutionPlan {
  const intents = edited.intents.map((intent, index) => ({
    ...intent,
    intentId: computeIntentId(edited.runId, index, intent.kind, intent.to.address, intent.to.chain, intent.amount),
  }));
  const body = { runId: edited.runId, policyId: edited.policyId, balances: edited.balances, intents, shortfalls: edited.shortfalls };
  return { ...body, planHash: computePlanHash(body) };
}

function approvedTokenFor(p: ExecutionPlan, policy: TreasuryPolicy = POLICY) {
  const res = approve(p, policy, APPROVER);
  assert.ok(res.approved, `expected approval, got ${JSON.stringify(res)}`);
  return res.token;
}

async function scratchDir(): Promise<string> {
  return mkdtemp(join(tmpdir(), "treasury-ops-test-"));
}

// ---------------------------------------------------------------------------
// Planner
// ---------------------------------------------------------------------------

describe("planner", () => {
  test("payroll first, then rebalance toward targets; deterministic", () => {
    const p1 = plan(POLICY, BALANCES, { runId: "r1" });
    const p2 = plan(POLICY, BALANCES, { runId: "r1" });
    assert.deepEqual(p1, p2, "same inputs must produce the identical plan (pure)");

    assert.equal(p1.intents.filter((i) => i.kind === "payroll").length, 2);
    const kinds = p1.intents.map((i) => i.kind);
    const firstRebalance = kinds.indexOf("rebalance");
    assert.ok(firstRebalance === -1 || !kinds.slice(firstRebalance).includes("payroll"), "payroll must precede rebalance");

    // Post-payroll: a1=1898, a2=418, total=2316 -> targets 1389.6/926.4 -> move 508 a1->a2.
    const rebalances = p1.intents.filter((i) => i.kind === "rebalance");
    assert.equal(rebalances.length, 1);
    assert.equal(rebalances[0]!.amount, 508);
    assert.equal(rebalances[0]!.from.accountId, "a1");
    assert.equal(rebalances[0]!.to.address, "T2");
  });

  test("intentIds are deterministic and position-qualified (duplicate payments don't collide)", () => {
    const dupPolicy: TreasuryPolicy = {
      ...POLICY,
      payroll: [POLICY.payroll[0]!, POLICY.payroll[0]!], // same person, same amount, twice
    };
    const p = plan(dupPolicy, BALANCES, { runId: "r-dup" });
    const payroll = p.intents.filter((i) => i.kind === "payroll");
    assert.equal(payroll.length, 2);
    assert.notEqual(payroll[0]!.intentId, payroll[1]!.intentId);
    // And the id is a pure function of run|index|kind|recipient|chain|amount.
    assert.equal(payroll[0]!.intentId, computeIntentId("r-dup", 0, "payroll", "P1", "c1", 100));
  });

  test("unfundable payroll becomes a shortfall; plan includes only what fits", () => {
    const p = plan(POLICY, { a1: 2000, a2: 90 }, { runId: "r-short" });
    // a2 headroom = 90 - 50 - 2 = 38 < 80 -> payee two can't be funded.
    assert.equal(p.intents.filter((i) => i.kind === "payroll").length, 1);
    assert.equal(p.shortfalls.length, 1);
    assert.equal(p.shortfalls[0]!.entry.recipient, "P2");
    assert.match(p.shortfalls[0]!.reason, /breaching its floor/);
  });

  test("payroll over the per-tx cap is a shortfall, not an intent", () => {
    const pol = { ...POLICY, payroll: [{ recipient: "P1", chain: "c1", amount: 1500, label: "x", period: "p" }] };
    const p = plan(pol, BALANCES, { runId: "r-cap" });
    assert.equal(p.intents.filter((i) => i.kind === "payroll").length, 0);
    assert.match(p.shortfalls[0]!.reason, /per-tx cap/);
  });

  test("payroll past the run cap is a shortfall", () => {
    const pol: TreasuryPolicy = {
      ...POLICY,
      perRunCap: 150,
      payroll: [
        { recipient: "P1", chain: "c1", amount: 100, label: "x", period: "p" },
        { recipient: "P2", chain: "c2", amount: 80, label: "y", period: "p" },
      ],
    };
    const p = plan(pol, BALANCES, { runId: "r-runcap" });
    assert.equal(p.intents.filter((i) => i.kind === "payroll").length, 1);
    assert.match(p.shortfalls[0]!.reason, /per-run cap/);
  });

  test("non-positive payroll amount is a shortfall", () => {
    const pol = { ...POLICY, payroll: [{ recipient: "P1", chain: "c1", amount: 0, label: "x", period: "p" }] };
    const p = plan(pol, BALANCES, { runId: "r-zero" });
    assert.equal(p.intents.filter((i) => i.kind === "payroll").length, 0);
    assert.match(p.shortfalls[0]!.reason, /non-positive/);
  });

  test("rebalance never breaches the donor's floor", () => {
    const pol: TreasuryPolicy = {
      ...POLICY,
      payroll: [],
      accounts: [
        { id: "a1", chain: "c1", address: "T1", label: "pinned", minBalance: 950, targetPct: 20 },
        { id: "a2", chain: "c2", address: "T2", label: "poor", minBalance: 0, targetPct: 80 },
      ],
    };
    // a1 surplus is 780 but headroom above floor is only 1000-950-2 = 48.
    const p = plan(pol, { a1: 1000, a2: 100 }, { runId: "r-floor" });
    assert.equal(p.intents.length, 1);
    assert.equal(p.intents[0]!.amount, 48);
  });

  test("rebalance splits moves at the per-tx cap", () => {
    const pol: TreasuryPolicy = {
      ...POLICY,
      payroll: [],
      perTxCap: 100,
      accounts: [
        { id: "a1", chain: "c1", address: "T1", label: "rich", minBalance: 0, targetPct: 50 },
        { id: "a2", chain: "c2", address: "T2", label: "poor", minBalance: 0, targetPct: 50 },
      ],
    };
    const p = plan(pol, { a1: 500, a2: 0 }, { runId: "r-split" });
    // total 500, targets 250/250, surplus 250 -> moves of 100, 100, then the rest.
    const amounts = p.intents.map((i) => i.amount);
    assert.ok(amounts.length >= 3, `expected >=3 capped moves, got ${JSON.stringify(amounts)}`);
    assert.ok(amounts.every((a) => a <= 100));
    assert.ok(amounts.reduce((s, a) => s + a, 0) >= 240, "should still get close to target");
  });

  test("policy with allocations not summing to 100 is rejected", () => {
    const bad = { ...POLICY, accounts: POLICY.accounts.map((a) => ({ ...a, targetPct: 10 })) };
    assert.throws(() => plan(bad, BALANCES, { runId: "r-bad" }), /sum to 20/);
  });
});

// ---------------------------------------------------------------------------
// Approval gate
// ---------------------------------------------------------------------------

describe("approval gate", () => {
  const base = () => plan(POLICY, BALANCES, { runId: "r-gate" });

  test("clean plan is approved with a signed token over the planHash", () => {
    const p = base();
    const res = approve(p, POLICY, APPROVER);
    assert.ok(res.approved);
    assert.equal(res.token.planHash, p.planHash);
    assert.equal(res.token.approverPublicKey, APPROVER.publicKeyB64);
  });

  test("payroll to a non-allowlisted recipient is rejected", () => {
    const p = rebuild({ ...base(), intents: base().intents.map((i, idx) => (idx === 0 ? { ...i, to: { ...i.to, address: "EVIL" } } : i)) });
    const res = approve(p, POLICY, APPROVER);
    assert.ok(!res.approved);
    assert.deepEqual([...new Set(res.violations.map((v) => v.code))], ["recipient-not-allowlisted"]);
  });

  test("rebalance to a non-treasury account is rejected (even an allowlisted payee)", () => {
    const p0 = base();
    const p = rebuild({
      ...p0,
      intents: p0.intents.map((i) => (i.kind === "rebalance" ? { ...i, to: { ...i.to, address: "P2" } } : i)),
    });
    // "P2" is on the payroll allowlist, but rebalance moves must stay in-treasury.
    const res = approve(p, POLICY, APPROVER);
    assert.ok(!res.approved);
    assert.ok(res.violations.some((v) => v.code === "recipient-not-allowlisted" && /not a treasury account/.test(v.detail)));
  });

  test("per-tx cap breach is rejected", () => {
    const p = rebuild({ ...base(), intents: base().intents.map((i, idx) => (idx === 0 ? { ...i, amount: 1001 } : i)) });
    const res = approve(p, POLICY, APPROVER);
    assert.ok(!res.approved);
    assert.deepEqual([...new Set(res.violations.map((v) => v.code))], ["per-tx-cap-exceeded"]);
  });

  test("per-run cap is re-checked against the gate's own policy", () => {
    const p = base(); // totals 688 — fine under POLICY, not under a tighter one
    const res = approve(p, { ...POLICY, perRunCap: 100 }, APPROVER);
    assert.ok(!res.approved);
    assert.deepEqual([...new Set(res.violations.map((v) => v.code))], ["per-run-cap-exceeded"]);
  });

  test("floor breach is caught by the gate's own simulation", () => {
    const tight: TreasuryPolicy = { ...POLICY, accounts: POLICY.accounts.map((a) => (a.id === "a1" ? { ...a, minBalance: 1900 } : a)) };
    const res = approve(base(), tight, APPROVER);
    assert.ok(!res.approved);
    assert.ok(res.violations.some((v) => v.code === "floor-breach"));
  });

  test("unknown source account is rejected", () => {
    const p = rebuild({ ...base(), intents: base().intents.map((i, idx) => (idx === 0 ? { ...i, from: { ...i.from, accountId: "ghost" } } : i)) });
    const res = approve(p, POLICY, APPROVER);
    assert.ok(!res.approved);
    assert.ok(res.violations.some((v) => v.code === "unknown-account"));
  });

  test("non-positive amount is rejected", () => {
    const p = rebuild({ ...base(), intents: base().intents.map((i, idx) => (idx === 0 ? { ...i, amount: -5 } : i)) });
    const res = approve(p, POLICY, APPROVER);
    assert.ok(!res.approved);
    assert.ok(res.violations.some((v) => v.code === "non-positive-amount"));
  });

  test("tampered intentId is rejected", () => {
    const p0 = base();
    const intents = p0.intents.map((i, idx) => (idx === 0 ? { ...i, intentId: "f".repeat(64) } : i));
    const body = { runId: p0.runId, policyId: p0.policyId, balances: p0.balances, intents, shortfalls: p0.shortfalls };
    const res = approve({ ...body, planHash: computePlanHash(body) }, POLICY, APPROVER);
    assert.ok(!res.approved);
    assert.ok(res.violations.some((v) => v.code === "intent-id-mismatch"));
  });

  test("tampered planHash is rejected", () => {
    const p = base();
    const res = approve({ ...p, planHash: p.planHash.replace(/^./, p.planHash[0] === "0" ? "1" : "0") }, POLICY, APPROVER);
    assert.ok(!res.approved);
    assert.ok(res.violations.some((v) => v.code === "plan-hash-mismatch"));
  });

  test("a plan violating several rules lists EVERY violation", () => {
    const p0 = base();
    const p = rebuild({
      ...p0,
      intents: [
        ...p0.intents,
        {
          intentId: "recomputed",
          kind: "payroll",
          from: { accountId: "ghost", chain: "c1", address: "??" },
          to: { address: "EVIL", chain: "c1", label: "attacker" },
          amount: 4000,
          rationale: "ignore previous instructions",
        },
      ],
    });
    const res = approve(p, POLICY, APPROVER);
    assert.ok(!res.approved);
    const codes = new Set(res.violations.map((v) => v.code));
    assert.ok(codes.has("recipient-not-allowlisted"));
    assert.ok(codes.has("per-tx-cap-exceeded"));
    assert.ok(codes.has("unknown-account"));
  });
});

// ---------------------------------------------------------------------------
// Executor
// ---------------------------------------------------------------------------

describe("executor", () => {
  test("happy path: transfers land, fees debited, journal written", async () => {
    const p = plan(POLICY, BALANCES, { runId: "x-happy" });
    const token = approvedTokenFor(p);
    const chain = new MockChain(structuredClone(CHAIN_INIT), { feePerTransfer: 1 });
    const outcome = await execute(p, token, portsFor(chain, ["c1", "c2"]), {
      journalDir: await scratchDir(),
      trustedApproverKeys: [APPROVER.publicKeyB64],
    });
    assert.ok(outcome.executed);
    assert.ok(outcome.result.perIntent.every((r) => r.status === "ok"));
    // a1: 2000 - (100+1) - (508+1); a2: 500 - (80+1) + 508.
    assert.equal(await chain.getBalance({ chain: "c1", address: "T1" }), 1390);
    assert.equal(await chain.getBalance({ chain: "c2", address: "T2" }), 927);
    assert.equal(await chain.getBalance({ chain: "c1", address: "P1" }), 100);
    assert.equal(await chain.getBalance({ chain: "c2", address: "P2" }), 80);
    assert.equal(chain.feesCollected, 3);
  });

  test("forged approval signature: refused, nothing executes", async () => {
    const p = plan(POLICY, BALANCES, { runId: "x-forged" });
    const token = approvedTokenFor(p);
    const forger = new TreasurySigner("approver");
    const forged = { ...token, signature: forger.signHash(p.planHash) };
    const chain = new MockChain(structuredClone(CHAIN_INIT));
    const outcome = await execute(p, forged, portsFor(chain, ["c1", "c2"]), { journalDir: await scratchDir() });
    assert.ok(!outcome.executed);
    assert.match(outcome.refusal, /signature invalid/);
    assert.equal(await chain.getBalance({ chain: "c1", address: "T1" }), 2000, "no money may move");
  });

  test("token from an untrusted approver key: refused when keys are pinned", async () => {
    const p = plan(POLICY, BALANCES, { runId: "x-untrusted" });
    // A self-appointed "approver" signs its own token — internally valid...
    const rogue = new TreasurySigner("approver");
    const rogueRes = approve(p, POLICY, rogue);
    assert.ok(rogueRes.approved);
    const chain = new MockChain(structuredClone(CHAIN_INIT));
    // ...but the executor is pinned to the real gate's key.
    const outcome = await execute(p, rogueRes.token, portsFor(chain, ["c1", "c2"]), {
      journalDir: await scratchDir(),
      trustedApproverKeys: [APPROVER.publicKeyB64],
    });
    assert.ok(!outcome.executed);
    assert.match(outcome.refusal, /not signed by a trusted approver/);
  });

  test("plan tampered after approval (self-consistent rebuild): refused", async () => {
    const p = plan(POLICY, BALANCES, { runId: "x-tamper" });
    const token = approvedTokenFor(p);
    const tampered = rebuild({ ...p, intents: p.intents.map((i, idx) => (idx === 0 ? { ...i, amount: 999 } : i)) });
    const chain = new MockChain(structuredClone(CHAIN_INIT));
    const outcome = await execute(tampered, token, portsFor(chain, ["c1", "c2"]), { journalDir: await scratchDir() });
    assert.ok(!outcome.executed);
    assert.match(outcome.refusal, /different plan/);
  });

  test("plan body edited without rebuilding its hash: refused", async () => {
    const p = plan(POLICY, BALANCES, { runId: "x-tamper2" });
    const token = approvedTokenFor(p);
    const sloppy = { ...p, intents: p.intents.map((i, idx) => (idx === 0 ? { ...i, amount: 999 } : i)) };
    const outcome = await execute(sloppy, token, portsFor(new MockChain(structuredClone(CHAIN_INIT)), ["c1", "c2"]), {
      journalDir: await scratchDir(),
    });
    assert.ok(!outcome.executed);
    assert.match(outcome.refusal, /tampered plan/);
  });

  test("allowlist bypass is unrepresentable: gate rejects, executor refuses without the gate", async () => {
    // The attacker crafts a fully self-consistent plan paying themselves…
    const p0 = plan(POLICY, BALANCES, { runId: "x-bypass" });
    const evil = rebuild({ ...p0, intents: p0.intents.map((i, idx) => (idx === 0 ? { ...i, to: { ...i.to, address: "EVIL" } } : i)) });
    // …the only token issuer is the gate, and the gate says no…
    const gateSaysNo = approve(evil, POLICY, APPROVER);
    assert.ok(!gateSaysNo.approved);
    // …and a token minted by anyone else is refused by the pinned executor.
    const attacker = new TreasurySigner("approver");
    const selfMinted = {
      planHash: evil.planHash,
      policyId: POLICY.policyId,
      approvedAt: new Date().toISOString(),
      approverPublicKey: attacker.publicKeyB64,
      signature: attacker.signHash(evil.planHash),
    };
    const chain = new MockChain(structuredClone(CHAIN_INIT));
    const outcome = await execute(evil, selfMinted, portsFor(chain, ["c1", "c2"]), {
      journalDir: await scratchDir(),
      trustedApproverKeys: [APPROVER.publicKeyB64],
    });
    assert.ok(!outcome.executed);
    assert.equal(await chain.getBalance({ chain: "c1", address: "EVIL" }), 0);
  });

  test("per-intent failure is recorded and the run continues", async () => {
    const p = plan(POLICY, BALANCES, { runId: "x-fail" });
    const token = approvedTokenFor(p);
    const chain = new MockChain(structuredClone(CHAIN_INIT), {
      feePerTransfer: 1,
      failures: { [p.intents[1]!.intentId]: { times: 99, mode: "fail" } },
    });
    const outcome = await execute(p, token, portsFor(chain, ["c1", "c2"]), { journalDir: await scratchDir() });
    assert.ok(outcome.executed);
    const statuses = outcome.result.perIntent.map((r) => r.status);
    assert.deepEqual(statuses, ["ok", "failed", "ok"]);
    assert.match(outcome.result.perIntent[1]!.error!, /injected failure/);
  });

  test("crash mid-run, then idempotent resume: completed intents skipped, no double spend", async () => {
    const p = plan(POLICY, BALANCES, { runId: "x-crash" });
    const token = approvedTokenFor(p);
    const journalDir = await scratchDir();
    const chain = new MockChain(structuredClone(CHAIN_INIT), {
      feePerTransfer: 1,
      failures: { [p.intents[2]!.intentId]: { times: 1, mode: "crash" } },
    });
    const ports = portsFor(chain, ["c1", "c2"]);

    await assert.rejects(execute(p, token, ports, { journalDir }), MockChainCrash);
    // Two intents landed before the crash.
    assert.equal(await chain.getBalance({ chain: "c1", address: "P1" }), 100);

    const resumed = await execute(p, token, ports, { journalDir });
    assert.ok(resumed.executed);
    assert.deepEqual(resumed.result.resumedIntentIds, [p.intents[0]!.intentId, p.intents[1]!.intentId]);
    assert.ok(resumed.result.perIntent.every((r) => r.status === "ok"));
    assert.equal(resumed.result.perIntent.length, p.intents.length);
    // Final balances match a single clean run exactly — nothing paid twice.
    assert.equal(await chain.getBalance({ chain: "c1", address: "T1" }), 1390);
    assert.equal(await chain.getBalance({ chain: "c2", address: "T2" }), 927);
    assert.equal(await chain.getBalance({ chain: "c1", address: "P1" }), 100);
    assert.equal(await chain.getBalance({ chain: "c2", address: "P2" }), 80);
  });
});

// ---------------------------------------------------------------------------
// Proof of execution
// ---------------------------------------------------------------------------

describe("proof of execution", () => {
  async function executedProof() {
    const p = plan(POLICY, BALANCES, { runId: "pr-1" });
    const token = approvedTokenFor(p);
    const chain = new MockChain(structuredClone(CHAIN_INIT), { feePerTransfer: 1 });
    const outcome = await execute(p, token, portsFor(chain, ["c1", "c2"]), { journalDir: await scratchDir() });
    assert.ok(outcome.executed);
    return { p, token, result: outcome.result, proof: buildProof(outcome.result, token, EXECUTOR) };
  }
  const KEYS = { approverPublicKey: APPROVER.publicKeyB64, executorPublicKey: EXECUTOR.publicKeyB64 };

  test("genuine proof verifies against pinned keys", async () => {
    const { p, proof } = await executedProof();
    assert.deepEqual(verifyProof(proof, p, KEYS), { valid: true, problems: [] });
  });

  test("swapped txRef invalidates the proof", async () => {
    const { p, proof } = await executedProof();
    const doctored = structuredClone(proof);
    doctored.perIntent[0]!.txRef = "mocktx:c1:feedfacefeedfacefeedface";
    const verdict = verifyProof(doctored, p, KEYS);
    assert.ok(!verdict.valid);
    assert.ok(verdict.problems.some((x) => /proofHash does not match/.test(x)));
  });

  test("an executed-but-unplanned intent is detectable, even if the executor signed it", async () => {
    const { p, token, result } = await executedProof();
    const padded: ExecutionResult = {
      ...result,
      perIntent: [
        ...result.perIntent,
        { intentId: "b".repeat(64), status: "ok", txRef: "mocktx:c1:unplanned", preBalances: { from: 1, to: 0 }, at: new Date().toISOString() },
      ],
    };
    const proof = buildProof(padded, token, EXECUTOR); // legitimately signed!
    const verdict = verifyProof(proof, p, KEYS);
    assert.ok(!verdict.valid);
    assert.ok(verdict.problems.some((x) => /NOT in the approved plan/.test(x)));
  });

  test("forged executor signature is rejected", async () => {
    const { p, proof } = await executedProof();
    const impostor = new TreasurySigner("executor");
    const forged = { ...proof, signature: impostor.signHash(proof.proofHash) };
    const verdict = verifyProof(forged, p, KEYS);
    assert.ok(!verdict.valid);
    assert.ok(verdict.problems.some((x) => /executor signature invalid/.test(x)));
  });

  test("proof re-signed end-to-end by an impostor fails against the pinned executor key", async () => {
    const { p, token, result } = await executedProof();
    const impostor = new TreasurySigner("executor");
    const reissued = buildProof(result, token, impostor); // internally consistent…
    const verdict = verifyProof(reissued, p, KEYS); // …but not the key we trust
    assert.ok(!verdict.valid);
  });

  test("approval token inside the proof is checked against the pinned approver key", async () => {
    const { p, proof } = await executedProof();
    const stranger = new TreasurySigner("approver");
    const verdict = verifyProof(proof, p, { ...KEYS, approverPublicKey: stranger.publicKeyB64 });
    assert.ok(!verdict.valid);
    assert.ok(verdict.problems.some((x) => /approval token signature invalid/.test(x)));
  });

  test("proof for a different plan does not verify", async () => {
    const { proof } = await executedProof();
    const other = plan(POLICY, BALANCES, { runId: "pr-other" });
    const verdict = verifyProof(proof, other, KEYS);
    assert.ok(!verdict.valid);
    assert.ok(verdict.problems.some((x) => /different plan|does not match the plan/.test(x)));
  });
});
