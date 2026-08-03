/**
 * Approval gate — `approve(plan, policy, signer)` is deterministic and does
 * no I/O. It NEVER trusts the planner: every intent is re-validated against
 * the policy from scratch (allowlist, caps, floor simulation, intent-id and
 * plan-hash recomputation). Any violation → typed rejection listing EVERY
 * violation found; only a fully clean plan gets a signed ApprovalToken
 * (ed25519 over the planHash), which is the sole thing the executor accepts.
 *
 * Recipient rules — the reason off-allowlist transfers are unrepresentable
 * downstream of this gate:
 *   - payroll intents must pay an exact allowlist entry (address + chain);
 *   - rebalance intents must pay one of the policy's OWN accounts
 *     (address + chain) — treasury-internal moves only.
 */
import { computeIntentId, computePlanHash } from "./planner.js";
import type { TreasurySigner } from "./proof.js";
import type { ApprovalResult, ExecutionPlan, TreasuryPolicy, Violation } from "./types.js";

export function approve(plan: ExecutionPlan, policy: TreasuryPolicy, signer: TreasurySigner): ApprovalResult {
  const violations: Violation[] = [];
  const fee = policy.feeBufferPerTx;

  if (plan.policyId !== policy.policyId) {
    violations.push({ code: "plan-policy-mismatch", detail: `plan is for policy ${plan.policyId}, gate holds ${policy.policyId}` });
  }

  const { planHash, ...body } = plan;
  if (planHash !== computePlanHash(body)) {
    violations.push({ code: "plan-hash-mismatch", detail: "planHash does not match the canonical plan body" });
  }

  const accountsById = new Map(policy.accounts.map((a) => [a.id, a]));
  const working: Record<string, number> = {};
  for (const a of policy.accounts) {
    const snapshot = plan.balances[a.id];
    if (typeof snapshot !== "number") {
      violations.push({ code: "missing-balance", detail: `plan carries no balance snapshot for account ${a.id}` });
      continue;
    }
    working[a.id] = snapshot;
  }

  let runTotal = 0;
  for (const [index, intent] of plan.intents.entries()) {
    const label = `intent ${index + 1} (${intent.kind}, ${intent.amount} to ${intent.to.label})`;

    const expectedId = computeIntentId(plan.runId, index, intent.kind, intent.to.address, intent.to.chain, intent.amount);
    if (intent.intentId !== expectedId) {
      violations.push({ code: "intent-id-mismatch", detail: `${label}: intentId does not match its contents`, intentId: intent.intentId });
    }

    if (!Number.isFinite(intent.amount) || intent.amount <= 0) {
      violations.push({ code: "non-positive-amount", detail: `${label}: amount must be a positive number`, intentId: intent.intentId });
      continue;
    }
    if (intent.amount > policy.perTxCap) {
      violations.push({
        code: "per-tx-cap-exceeded",
        detail: `${label}: amount ${intent.amount} exceeds per-tx cap ${policy.perTxCap}`,
        intentId: intent.intentId,
      });
    }
    runTotal += intent.amount;

    // Recipient — the load-bearing check.
    if (intent.kind === "payroll") {
      const allowed = policy.allowlist.some((e) => e.address === intent.to.address && e.chain === intent.to.chain);
      if (!allowed) {
        violations.push({
          code: "recipient-not-allowlisted",
          detail: `${label}: recipient ${intent.to.address} on ${intent.to.chain} is not on the allowlist`,
          intentId: intent.intentId,
        });
      }
    } else {
      const own = policy.accounts.some((a) => a.address === intent.to.address && a.chain === intent.to.chain);
      if (!own) {
        violations.push({
          code: "recipient-not-allowlisted",
          detail: `${label}: rebalance destination ${intent.to.address} on ${intent.to.chain} is not a treasury account`,
          intentId: intent.intentId,
        });
      }
    }

    // Source account + floor simulation from the plan's snapshot.
    const source = accountsById.get(intent.from.accountId);
    if (!source || source.chain !== intent.from.chain || source.address !== intent.from.address) {
      violations.push({
        code: "unknown-account",
        detail: `${label}: source ${intent.from.accountId} (${intent.from.address} on ${intent.from.chain}) is not a policy account`,
        intentId: intent.intentId,
      });
      continue;
    }
    if (typeof working[source.id] === "number") {
      working[source.id]! -= intent.amount + fee;
      if (working[source.id]! < source.minBalance) {
        violations.push({
          code: "floor-breach",
          detail: `${label}: would take ${source.id} to ${working[source.id]}, below its floor ${source.minBalance} (fee buffer ${fee} included)`,
          intentId: intent.intentId,
        });
      }
      // Rebalance credits land back in a treasury account.
      const dest = policy.accounts.find((a) => a.address === intent.to.address && a.chain === intent.to.chain);
      if (dest && typeof working[dest.id] === "number") working[dest.id]! += intent.amount;
    }
  }

  if (runTotal > policy.perRunCap) {
    violations.push({ code: "per-run-cap-exceeded", detail: `plan totals ${runTotal}, exceeding the per-run cap ${policy.perRunCap}` });
  }

  if (violations.length > 0) return { approved: false, violations };

  return {
    approved: true,
    token: {
      planHash: plan.planHash,
      policyId: policy.policyId,
      approvedAt: new Date().toISOString(),
      approverPublicKey: signer.publicKeyB64,
      signature: signer.signHash(plan.planHash),
    },
  };
}
