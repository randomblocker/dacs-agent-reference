/**
 * Treasury Ops Agent — types and ports.
 *
 * Money-adjacent, so the whole module is the SafeAgent split:
 *
 *   planner (pure) --ExecutionPlan--> approval gate (deterministic, no I/O,
 *   re-validates EVERYTHING from scratch) --ApprovalToken--> thin executor
 *   (verifies token + planHash FIRST, then walks intents through ChainPorts).
 *
 * The executor only accepts approved plans; the approval gate never trusts
 * the planner; transfers to anyone outside the policy's allowlist (payroll)
 * or the policy's own accounts (rebalance) are rejected by the gate, so an
 * unapproved recipient is unreachable through the executor by construction.
 *
 * Amounts are plain integer base units (think "DEM cents"); the mock chain
 * charges a small flat fee per transfer so balance math stays honest, and
 * the policy's `feeBufferPerTx` is what planner + gate reserve per transfer
 * when checking floors (the real fee must fit inside it).
 */

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/** Chain is just an id on the port — e.g. "demos" | "base" | "solana". */
export type ChainId = string;

export interface AccountRef {
  chain: ChainId;
  address: string;
}

export interface TreasuryAccount {
  /** Stable id used in balance snapshots and intents (e.g. "ops-demos"). */
  id: string;
  chain: ChainId;
  address: string;
  label: string;
  /** Hard floor: no plan may take this account below it (fees included). */
  minBalance: number;
  /** Target share of total treasury balance, in percent. Must sum to 100. */
  targetPct: number;
}

/** The ONLY recipients payroll transfers may ever reach. */
export interface AllowlistEntry {
  address: string;
  chain: ChainId;
  label: string;
}

export interface PayrollEntry {
  recipient: string;
  chain: ChainId;
  amount: number;
  label: string;
  /** Billing period this payment covers, e.g. "2026-07". */
  period: string;
}

export interface TreasuryPolicy {
  policyId: string;
  accounts: TreasuryAccount[];
  allowlist: AllowlistEntry[];
  payroll: PayrollEntry[];
  /** Max amount of any single transfer. */
  perTxCap: number;
  /** Max sum of all transfer amounts in one run (fees excluded). */
  perRunCap: number;
  /** Reserved per transfer for chain fees when checking floors. */
  feeBufferPerTx: number;
}

// ---------------------------------------------------------------------------
// Plan
// ---------------------------------------------------------------------------

export type IntentKind = "payroll" | "rebalance";

export interface TransferIntent {
  /** Deterministic: sha256 over runId|index|kind|recipient|chain|amount. */
  intentId: string;
  kind: IntentKind;
  from: { accountId: string; chain: ChainId; address: string };
  to: { address: string; chain: ChainId; label: string };
  amount: number;
  rationale: string;
}

export interface PayrollShortfall {
  entry: PayrollEntry;
  reason: string;
}

/** accountId -> balance, the snapshot the plan was computed from. */
export type BalanceSnapshot = Record<string, number>;

export interface ExecutionPlan {
  runId: string;
  policyId: string;
  /** Snapshot planning was based on (gate re-simulates floors against it). */
  balances: BalanceSnapshot;
  /** Ordered: payroll first, then rebalance moves. */
  intents: TransferIntent[];
  /** Payroll entries that could NOT be funded within floors/caps. */
  shortfalls: PayrollShortfall[];
  /** sha256 over the canonical JSON of the plan minus this field. */
  planHash: string;
}

// ---------------------------------------------------------------------------
// Approval
// ---------------------------------------------------------------------------

export interface ApprovalToken {
  planHash: string;
  policyId: string;
  approvedAt: string;
  /** ed25519 SPKI DER, base64 — the gate's signing identity. */
  approverPublicKey: string;
  /** ed25519 over the planHash bytes (hex-decoded), base64. */
  signature: string;
}

export type ViolationCode =
  | "plan-policy-mismatch"
  | "plan-hash-mismatch"
  | "intent-id-mismatch"
  | "recipient-not-allowlisted"
  | "per-tx-cap-exceeded"
  | "per-run-cap-exceeded"
  | "floor-breach"
  | "unknown-account"
  | "non-positive-amount"
  | "missing-balance";

export interface Violation {
  code: ViolationCode;
  detail: string;
  intentId?: string;
}

export type ApprovalResult =
  | { approved: true; token: ApprovalToken }
  | { approved: false; violations: Violation[] };

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

/** Chain adapter port. Real mode = Demos XM SDK adapters; mock in tests. */
export interface ChainPort {
  getBalance(account: AccountRef): Promise<number>;
  transfer(intent: TransferIntent): Promise<{ txRef: string }>;
}

/**
 * A thrown transfer error carrying `abortsRun: true` kills the whole run
 * (simulated crash); any other error is recorded as a per-intent failure
 * and the executor continues with the remaining intents.
 */
export interface AbortsRun {
  abortsRun: true;
}

export type IntentStatus = "ok" | "failed";

export interface IntentRecord {
  intentId: string;
  status: IntentStatus;
  txRef?: string;
  preBalances: { from: number; to: number };
  postBalances?: { from: number; to: number };
  error?: string;
  at: string;
}

export interface ExecutionResult {
  runId: string;
  planHash: string;
  startedAt: string;
  finishedAt: string;
  /** One record per attempted intent, prior-run journal records included. */
  perIntent: IntentRecord[];
  /** Intents skipped this run because the journal already shows them ok. */
  resumedIntentIds: string[];
}

export type ExecuteOutcome =
  | { executed: true; result: ExecutionResult }
  | { executed: false; refusal: string };

// ---------------------------------------------------------------------------
// Proof of execution
// ---------------------------------------------------------------------------

export interface ProofOfExecution {
  planHash: string;
  runId: string;
  approvalToken: ApprovalToken;
  perIntent: IntentRecord[];
  startedAt: string;
  finishedAt: string;
  /** ed25519 SPKI DER, base64 — the executor's signing identity. */
  executorPublicKey: string;
  /** sha256 over canonical JSON of the proof minus proofHash + signature. */
  proofHash: string;
  /** ed25519 over the proofHash bytes, base64. */
  signature: string;
}

export interface ProofVerifyResult {
  valid: boolean;
  problems: string[];
}
