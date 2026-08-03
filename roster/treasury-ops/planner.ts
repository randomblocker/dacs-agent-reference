/**
 * Planner — `plan(policy, balances, opts)` is PURE: same inputs, same plan,
 * same planHash. No clocks, no randomness, no I/O.
 *
 * Payroll first (in roster order), then rebalancing moves toward the
 * policy's target allocation percentages — never breaching an account's
 * floor, the per-tx cap, or the per-run cap. A payroll entry that cannot be
 * funded within those limits becomes a typed shortfall instead of an intent.
 *
 * The planner is the PROPOSER in the SafeAgent split: nothing it emits is
 * trusted — the approval gate re-derives every check from the policy.
 */
import { sha256Hex } from "../oracle-desk/attested-fetch.js";
import { canonicalJson } from "../evalbot/ruling.js";
import type {
  BalanceSnapshot,
  ExecutionPlan,
  PayrollShortfall,
  TransferIntent,
  TreasuryAccount,
  TreasuryPolicy,
} from "./types.js";

export interface PlanOptions {
  /** Caller-chosen run id; part of every intentId, so runs never collide. */
  runId: string;
  /** Rebalance moves smaller than this are skipped as dust (default 1). */
  minMove?: number;
}

/** Deterministic intent id: position-qualified so duplicates can't collide. */
export function computeIntentId(
  runId: string,
  index: number,
  kind: TransferIntent["kind"],
  recipient: string,
  chain: string,
  amount: number,
): string {
  return sha256Hex(`${runId}|${index}|${kind}|${recipient}|${chain}|${amount}`);
}

/** sha256 over the canonical (key-sorted) JSON of the plan body. */
export function computePlanHash(plan: Omit<ExecutionPlan, "planHash">): string {
  return sha256Hex(canonicalJson(plan));
}

export function validatePolicy(policy: TreasuryPolicy): void {
  if (policy.accounts.length === 0) throw new Error("policy has no accounts");
  const ids = new Set<string>();
  for (const a of policy.accounts) {
    if (ids.has(a.id)) throw new Error(`duplicate account id ${a.id}`);
    ids.add(a.id);
    if (a.minBalance < 0) throw new Error(`account ${a.id}: negative minBalance`);
  }
  const pctSum = policy.accounts.reduce((s, a) => s + a.targetPct, 0);
  if (Math.abs(pctSum - 100) > 1e-6) throw new Error(`target allocations sum to ${pctSum}, expected 100`);
  if (policy.perTxCap <= 0 || policy.perRunCap <= 0) throw new Error("caps must be positive");
  if (policy.feeBufferPerTx < 0) throw new Error("feeBufferPerTx must be >= 0");
}

/** Spendable amount above the floor, reserving the fee buffer for one tx. */
function headroom(account: TreasuryAccount, balance: number, feeBuffer: number): number {
  return balance - account.minBalance - feeBuffer;
}

export function plan(policy: TreasuryPolicy, balances: BalanceSnapshot, opts: PlanOptions): ExecutionPlan {
  validatePolicy(policy);
  for (const a of policy.accounts) {
    if (typeof balances[a.id] !== "number") throw new Error(`no balance snapshot for account ${a.id}`);
  }

  const minMove = opts.minMove ?? 1;
  const fee = policy.feeBufferPerTx;
  const working: Record<string, number> = {};
  for (const a of policy.accounts) working[a.id] = balances[a.id]!;

  const intents: TransferIntent[] = [];
  const shortfalls: PayrollShortfall[] = [];
  let runTotal = 0;

  const push = (
    kind: TransferIntent["kind"],
    from: TreasuryAccount,
    to: { address: string; chain: string; label: string },
    amount: number,
    rationale: string,
  ): void => {
    intents.push({
      intentId: computeIntentId(opts.runId, intents.length, kind, to.address, to.chain, amount),
      kind,
      from: { accountId: from.id, chain: from.chain, address: from.address },
      to,
      amount,
      rationale,
    });
  };

  // -------------------------------------------------------------------------
  // 1. Payroll — roster order; each payment funded from an account on the
  //    recipient's chain with enough headroom, or flagged as a shortfall.
  // -------------------------------------------------------------------------
  for (const entry of policy.payroll) {
    if (entry.amount <= 0) {
      shortfalls.push({ entry, reason: "non-positive amount" });
      continue;
    }
    if (entry.amount > policy.perTxCap) {
      shortfalls.push({ entry, reason: `amount ${entry.amount} exceeds per-tx cap ${policy.perTxCap}` });
      continue;
    }
    if (runTotal + entry.amount > policy.perRunCap) {
      shortfalls.push({ entry, reason: `would exceed per-run cap ${policy.perRunCap} (already planned ${runTotal})` });
      continue;
    }
    const funding = policy.accounts.find(
      (a) => a.chain === entry.chain && headroom(a, working[a.id]!, fee) >= entry.amount,
    );
    if (!funding) {
      shortfalls.push({
        entry,
        reason: `no account on chain ${entry.chain} can fund ${entry.amount} without breaching its floor`,
      });
      continue;
    }
    push(
      "payroll",
      funding,
      { address: entry.recipient, chain: entry.chain, label: entry.label },
      entry.amount,
      `payroll ${entry.period}: ${entry.label} (${entry.amount} on ${entry.chain} from ${funding.id})`,
    );
    working[funding.id]! -= entry.amount + fee;
    runTotal += entry.amount;
  }

  // -------------------------------------------------------------------------
  // 2. Rebalance — move surplus toward deficit until targets are met (or
  //    floors/caps stop us). Greedy largest-surplus -> largest-deficit.
  // -------------------------------------------------------------------------
  const total = policy.accounts.reduce((s, a) => s + working[a.id]!, 0);
  const target: Record<string, number> = {};
  for (const a of policy.accounts) target[a.id] = (a.targetPct / 100) * total;

  for (let guard = 0; guard < 100; guard++) {
    const byDelta = [...policy.accounts].sort(
      (x, y) => working[y.id]! - target[y.id]! - (working[x.id]! - target[x.id]!),
    );
    const receiver = byDelta[byDelta.length - 1]!;
    const deficit = target[receiver.id]! - working[receiver.id]!;
    // First surplus account that can actually give something (floors bind).
    const donor = byDelta.find(
      (a) =>
        a.id !== receiver.id &&
        working[a.id]! - target[a.id]! >= minMove &&
        headroom(a, working[a.id]!, fee) >= minMove,
    );
    if (!donor) break;
    const surplus = working[donor.id]! - target[donor.id]!;

    const move = Math.floor(
      Math.min(surplus, deficit, headroom(donor, working[donor.id]!, fee), policy.perTxCap, policy.perRunCap - runTotal),
    );
    if (move < minMove) break;

    push(
      "rebalance",
      donor,
      { address: receiver.address, chain: receiver.chain, label: receiver.label },
      move,
      `rebalance: ${donor.id} is ${Math.floor(surplus)} over its ${donor.targetPct}% target, ` +
        `${receiver.id} is ${Math.floor(deficit)} under its ${receiver.targetPct}% target — move ${move}`,
    );
    working[donor.id]! -= move + fee;
    working[receiver.id]! += move;
    runTotal += move;
  }

  const body: Omit<ExecutionPlan, "planHash"> = {
    runId: opts.runId,
    policyId: policy.policyId,
    balances: { ...balances },
    intents,
    shortfalls,
  };
  return { ...body, planHash: computePlanHash(body) };
}
