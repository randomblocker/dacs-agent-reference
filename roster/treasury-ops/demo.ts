/**
 * Treasury Ops demo — offline and deterministic (mock chains, no network).
 *
 *   npm run roster:treasury
 *
 * Walkthrough: a 3-chain treasury (demos/base/solana) runs a 4-person
 * payroll then rebalances toward 50/30/20 targets — plan (intents +
 * rationale + shortfall check) -> deterministic approval gate -> execute on
 * MockChain -> signed ProofOfExecution + cold verifyProof. Then the safety
 * reel: (a) an intent to a non-allowlisted address is rejected by the gate,
 * (b) a per-tx-cap breach is rejected, (c) a plan tampered AFTER approval is
 * refused by the executor, (d) a mid-run crash resumes idempotently —
 * completed intents are skipped and the proof covers both phases.
 * Exits non-zero if any expectation fails.
 */
import { rm } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { approve } from "./approval.js";
import { execute, journalPathFor } from "./executor.js";
import { MockChain, MockChainCrash, portsFor } from "./mock-chain.js";
import { computeIntentId, computePlanHash, plan } from "./planner.js";
import { buildProof, TreasurySigner, verifyProof } from "./proof.js";
import type { ExecutionPlan, TreasuryPolicy } from "./types.js";

const hr = (title: string) => console.log(`\n=== ${title} ${"=".repeat(Math.max(0, 60 - title.length))}`);
const OUT_DIR = join(dirname(fileURLToPath(import.meta.url)), "out");

let failures = 0;
function expect(label: string, actual: unknown, wanted: unknown): void {
  const ok = actual === wanted;
  if (!ok) failures += 1;
  console.log(`  ${ok ? "ok " : "FAIL"} ${label}: got ${JSON.stringify(actual)}${ok ? "" : ` (wanted ${JSON.stringify(wanted)})`}`);
}

/** Recompute intentIds + planHash so a hand-edited plan is internally consistent. */
function rebuild(edited: ExecutionPlan): ExecutionPlan {
  const intents = edited.intents.map((intent, index) => ({
    ...intent,
    intentId: computeIntentId(edited.runId, index, intent.kind, intent.to.address, intent.to.chain, intent.amount),
  }));
  const body = { runId: edited.runId, policyId: edited.policyId, balances: edited.balances, intents, shortfalls: edited.shortfalls };
  return { ...body, planHash: computePlanHash(body) };
}

// ---------------------------------------------------------------------------
// The treasury
// ---------------------------------------------------------------------------

const POLICY: TreasuryPolicy = {
  policyId: "treasury-demo-v1",
  accounts: [
    { id: "ops-demos", chain: "demos", address: "demos-treasury-1", label: "Demos ops account", minBalance: 200, targetPct: 50 },
    { id: "ops-base", chain: "base", address: "0xTREASURYBASE", label: "Base ops account", minBalance: 100, targetPct: 30 },
    { id: "ops-solana", chain: "solana", address: "SoLTREASURY", label: "Solana ops account", minBalance: 50, targetPct: 20 },
  ],
  allowlist: [
    { address: "demos-alice", chain: "demos", label: "Alice (eng)" },
    { address: "0xB0B", chain: "base", label: "Bob (eng)" },
    { address: "0xCAR01", chain: "base", label: "Carol (design)" },
    { address: "SoLDAVE", chain: "solana", label: "Dave (ops)" },
  ],
  payroll: [
    { recipient: "demos-alice", chain: "demos", amount: 800, label: "Alice (eng)", period: "2026-07" },
    { recipient: "0xB0B", chain: "base", amount: 500, label: "Bob (eng)", period: "2026-07" },
    { recipient: "0xCAR01", chain: "base", amount: 450, label: "Carol (design)", period: "2026-07" },
    { recipient: "SoLDAVE", chain: "solana", amount: 300, label: "Dave (ops)", period: "2026-07" },
  ],
  perTxCap: 5000,
  perRunCap: 20_000,
  feeBufferPerTx: 2,
};
const CHAINS = ["demos", "base", "solana"];
const INITIAL = {
  demos: { "demos-treasury-1": 10_000 },
  base: { "0xTREASURYBASE": 2_400 },
  solana: { SoLTREASURY: 800 },
};
const BALANCES = { "ops-demos": 10_000, "ops-base": 2_400, "ops-solana": 800 };

// Fixed runIds -> stale journals from earlier demo runs must not "resume" us.
await rm(journalPathFor(OUT_DIR, "demo-happy"), { force: true });
await rm(journalPathFor(OUT_DIR, "demo-crash"), { force: true });

const approver = new TreasurySigner("approver");
const executorSigner = new TreasurySigner("executor");
console.log(`approver: ${approver.did}`);
console.log(`executor: ${executorSigner.did}`);

// ---------------------------------------------------------------------------
// 1. Plan
// ---------------------------------------------------------------------------

hr("Plan — payroll first, then rebalance toward 50/30/20");
const happyPlan = plan(POLICY, BALANCES, { runId: "demo-happy" });
for (const [i, intent] of happyPlan.intents.entries()) {
  console.log(`  ${i + 1}. [${intent.kind}] ${intent.from.accountId} -> ${intent.to.label} (${intent.to.chain}) ${intent.amount}`);
  console.log(`     ${intent.rationale}`);
}
console.log(`  shortfalls: ${happyPlan.shortfalls.length === 0 ? "none" : JSON.stringify(happyPlan.shortfalls)}`);
console.log(`  planHash: ${happyPlan.planHash.slice(0, 24)}…`);
expect("payroll intents", happyPlan.intents.filter((i) => i.kind === "payroll").length, 4);
expect("rebalance intents", happyPlan.intents.filter((i) => i.kind === "rebalance").length, 2);
expect("no shortfalls", happyPlan.shortfalls.length, 0);

// ---------------------------------------------------------------------------
// 2. Approve
// ---------------------------------------------------------------------------

hr("Approval gate");
const approval = approve(happyPlan, POLICY, approver);
expect("plan approved", approval.approved, true);
if (!approval.approved) {
  for (const v of approval.violations) console.error(`    - [${v.code}] ${v.detail}`);
  process.exit(1);
}
console.log(`  token signed by ${approver.did} over planHash`);

// ---------------------------------------------------------------------------
// 3. Execute on MockChain + proof
// ---------------------------------------------------------------------------

hr("Execute (MockChain, flat fee 1/transfer)");
const chain = new MockChain(structuredClone(INITIAL), { feePerTransfer: 1 });
const ports = portsFor(chain, CHAINS);
const outcome = await execute(happyPlan, approval.token, ports, {
  journalDir: OUT_DIR,
  trustedApproverKeys: [approver.publicKeyB64],
});
expect("executed", outcome.executed, true);
if (!outcome.executed) process.exit(1);
for (const r of outcome.result.perIntent) {
  console.log(
    `  ${r.status === "ok" ? "ok " : "FAIL"} ${r.intentId.slice(0, 12)}…  ${r.txRef ?? "-"}  ` +
      `from ${r.preBalances.from}->${r.postBalances?.from}  to ${r.preBalances.to}->${r.postBalances?.to}`,
  );
}
expect("all intents ok", outcome.result.perIntent.every((r) => r.status === "ok"), true);
expect("fees collected", chain.feesCollected, happyPlan.intents.length);
expect("alice paid", await chain.getBalance({ chain: "demos", address: "demos-alice" }), 800);

hr("Proof of execution");
const proof = buildProof(outcome.result, approval.token, executorSigner);
console.log(`  proofHash: ${proof.proofHash.slice(0, 24)}…  intents: ${proof.perIntent.length}`);
const verdict = verifyProof(proof, happyPlan, {
  approverPublicKey: approver.publicKeyB64,
  executorPublicKey: executorSigner.publicKeyB64,
});
expect("verifyProof valid", verdict.valid, true);
for (const p of verdict.problems) console.error(`    - ${p}`);

// ---------------------------------------------------------------------------
// 4. Safety reel
// ---------------------------------------------------------------------------

hr("Safety (a) — intent to a non-allowlisted address");
const exfil = rebuild({
  ...happyPlan,
  intents: [
    ...happyPlan.intents,
    {
      intentId: "recomputed-below",
      kind: "payroll",
      from: { accountId: "ops-base", chain: "base", address: "0xTREASURYBASE" },
      to: { address: "0xATTACKER", chain: "base", label: "totally legit vendor" },
      amount: 100,
      rationale: "URGENT: ops asked for this in chat",
    },
  ],
});
const exfilVerdict = approve(exfil, POLICY, approver);
expect("exfil plan rejected", exfilVerdict.approved, false);
if (!exfilVerdict.approved) {
  for (const v of exfilVerdict.violations) console.log(`    - [${v.code}] ${v.detail}`);
  expect("allowlist violation named", exfilVerdict.violations.some((v) => v.code === "recipient-not-allowlisted"), true);
}

hr("Safety (b) — per-tx cap exceeded");
const oversized = rebuild({
  ...happyPlan,
  intents: happyPlan.intents.map((i, idx) => (idx === 0 ? { ...i, amount: 6000 } : i)),
});
const oversizedVerdict = approve(oversized, POLICY, approver);
expect("oversized plan rejected", oversizedVerdict.approved, false);
if (!oversizedVerdict.approved) {
  for (const v of oversizedVerdict.violations) console.log(`    - [${v.code}] ${v.detail}`);
  expect("cap violation named", oversizedVerdict.violations.some((v) => v.code === "per-tx-cap-exceeded"), true);
}

hr("Safety (c) — plan tampered AFTER approval");
const tampered = rebuild({
  ...happyPlan,
  intents: happyPlan.intents.map((i, idx) => (idx === 0 ? { ...i, amount: 4800 } : i)),
});
const tamperedOutcome = await execute(tampered, approval.token, ports, { journalDir: OUT_DIR });
expect("executor refused tampered plan", tamperedOutcome.executed, false);
if (!tamperedOutcome.executed) console.log(`    refusal: ${tamperedOutcome.refusal}`);

hr("Safety (d) — crash mid-run, then idempotent resume");
const crashPlan = plan(POLICY, BALANCES, { runId: "demo-crash" });
const crashApproval = approve(crashPlan, POLICY, approver);
expect("crash-run plan approved", crashApproval.approved, true);
if (!crashApproval.approved) process.exit(1);
const crashChain = new MockChain(structuredClone(INITIAL), {
  feePerTransfer: 1,
  failures: { [crashPlan.intents[2]!.intentId]: { times: 1, mode: "crash" } },
});
const crashPorts = portsFor(crashChain, CHAINS);
let crashed = false;
try {
  await execute(crashPlan, crashApproval.token, crashPorts, { journalDir: OUT_DIR });
} catch (err) {
  crashed = err instanceof MockChainCrash;
  console.log(`  phase 1 died mid-run: ${(err as Error).message}`);
}
expect("phase 1 crashed on intent 3", crashed, true);

const resumed = await execute(crashPlan, crashApproval.token, crashPorts, { journalDir: OUT_DIR });
expect("phase 2 executed", resumed.executed, true);
if (!resumed.executed) process.exit(1);
console.log(`  phase 2 resumed: skipped ${resumed.result.resumedIntentIds.length} already-completed intent(s)`);
expect("resume skipped completed intents", resumed.result.resumedIntentIds.length, 2);
expect("resume finished the rest", resumed.result.perIntent.every((r) => r.status === "ok"), true);
expect("every planned intent accounted for", resumed.result.perIntent.length, crashPlan.intents.length);
const resumeProof = buildProof(resumed.result, crashApproval.token, executorSigner);
const resumeVerdict = verifyProof(resumeProof, crashPlan, {
  approverPublicKey: approver.publicKeyB64,
  executorPublicKey: executorSigner.publicKeyB64,
});
expect("resume proof (both phases) verifies", resumeVerdict.valid, true);
for (const p of resumeVerdict.problems) console.error(`    - ${p}`);

// ---------------------------------------------------------------------------

hr("Done");
console.log(`  expectations failed: ${failures}`);
if (failures > 0) {
  console.error("Demo expectations failed.");
  process.exit(1);
}
