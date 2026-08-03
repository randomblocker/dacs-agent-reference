/**
 * Executor — the THIN end of the SafeAgent split. It holds the chain ports
 * (the callable money) but makes no decisions: before touching a single
 * intent it verifies (1) the approval token's ed25519 signature — against a
 * trusted approver key when the caller pins one — and (2) that the token's
 * planHash matches a RECOMPUTED hash of the plan it was handed. A tampered
 * or unapproved plan is refused outright; nothing executes.
 *
 * Idempotent resume: every attempted intent is journaled (JSONL, one full
 * IntentRecord per line, gitignored under out/). Re-running the same plan
 * skips intents the journal already shows `ok` — a crash mid-run (an error
 * carrying `abortsRun: true`) leaves the journal behind, and the next
 * execute() call picks up where it died. A plain per-intent failure is
 * recorded and the run CONTINUES with the remaining intents (no in-run
 * retry; failed intents are retried only by a later resume run).
 */
import { appendFile, mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { computePlanHash } from "./planner.js";
import { verifyHashSignature } from "./proof.js";
import type {
  ApprovalToken,
  ChainId,
  ChainPort,
  ExecuteOutcome,
  ExecutionPlan,
  IntentRecord,
  TransferIntent,
} from "./types.js";

export interface ExecutorOptions {
  /** Directory for run journals (default roster/treasury-ops/out). */
  journalDir: string;
  /** When set, the token's approver key MUST be one of these. */
  trustedApproverKeys?: string[];
}

export function journalPathFor(journalDir: string, runId: string): string {
  return join(journalDir, `run-${runId}.journal.jsonl`);
}

async function readJournal(path: string): Promise<IntentRecord[]> {
  let raw: string;
  try {
    raw = await readFile(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw err;
  }
  return raw
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .map((line, i) => {
      try {
        return JSON.parse(line) as IntentRecord;
      } catch {
        throw new Error(`journal line ${i + 1} is not valid JSON`);
      }
    });
}

function isCrash(err: unknown): boolean {
  return typeof err === "object" && err !== null && (err as { abortsRun?: unknown }).abortsRun === true;
}

export async function execute(
  plan: ExecutionPlan,
  token: ApprovalToken,
  ports: Record<ChainId, ChainPort>,
  opts: ExecutorOptions,
): Promise<ExecuteOutcome> {
  // -------------------------------------------------------------------------
  // Gatekeeping FIRST — refuse before any chain access.
  // -------------------------------------------------------------------------
  const { planHash: embedded, ...body } = plan;
  const actualHash = computePlanHash(body);
  if (embedded !== actualHash) {
    return { executed: false, refusal: "plan's embedded planHash does not match its body (tampered plan)" };
  }
  if (token.planHash !== actualHash) {
    return { executed: false, refusal: "approval token covers a different plan (planHash mismatch)" };
  }
  if (opts.trustedApproverKeys && !opts.trustedApproverKeys.includes(token.approverPublicKey)) {
    return { executed: false, refusal: "approval token was not signed by a trusted approver key" };
  }
  if (!verifyHashSignature(token.planHash, token.signature, token.approverPublicKey)) {
    return { executed: false, refusal: "approval token signature invalid (unapproved plan)" };
  }

  // -------------------------------------------------------------------------
  // Journal — load prior progress for idempotent resume.
  // -------------------------------------------------------------------------
  await mkdir(opts.journalDir, { recursive: true });
  const journalPath = journalPathFor(opts.journalDir, plan.runId);
  const prior = await readJournal(journalPath);
  const doneRecords = new Map<string, IntentRecord>();
  for (const record of prior) {
    if (record.status === "ok") doneRecords.set(record.intentId, record);
  }

  const startedAt = new Date().toISOString();
  const perIntent: IntentRecord[] = [];
  const resumedIntentIds: string[] = [];

  const portFor = (chain: ChainId): ChainPort => {
    const port = ports[chain];
    if (!port) throw new Error(`no ChainPort registered for chain ${chain}`);
    return port;
  };

  for (const intent of plan.intents) {
    const already = doneRecords.get(intent.intentId);
    if (already) {
      perIntent.push(already);
      resumedIntentIds.push(intent.intentId);
      continue;
    }
    const record = await runIntent(intent, portFor, journalPath);
    perIntent.push(record);
  }

  return {
    executed: true,
    result: {
      runId: plan.runId,
      planHash: plan.planHash,
      startedAt,
      finishedAt: new Date().toISOString(),
      perIntent,
      resumedIntentIds,
    },
  };
}

async function runIntent(
  intent: TransferIntent,
  portFor: (chain: ChainId) => ChainPort,
  journalPath: string,
): Promise<IntentRecord> {
  const sourcePort = portFor(intent.from.chain);
  const destPort = portFor(intent.to.chain);
  const fromRef = { chain: intent.from.chain, address: intent.from.address };
  const toRef = { chain: intent.to.chain, address: intent.to.address };

  const preBalances = {
    from: await sourcePort.getBalance(fromRef),
    to: await destPort.getBalance(toRef),
  };

  let record: IntentRecord;
  try {
    const { txRef } = await sourcePort.transfer(intent);
    record = {
      intentId: intent.intentId,
      status: "ok",
      txRef,
      preBalances,
      postBalances: {
        from: await sourcePort.getBalance(fromRef),
        to: await destPort.getBalance(toRef),
      },
      at: new Date().toISOString(),
    };
  } catch (err) {
    // A crash aborts the whole run: nothing journaled for this intent, so a
    // resume run retries it. A plain failure is journaled and we move on.
    if (isCrash(err)) throw err;
    record = {
      intentId: intent.intentId,
      status: "failed",
      preBalances,
      error: err instanceof Error ? err.message : String(err),
      at: new Date().toISOString(),
    };
  }

  await appendFile(journalPath, `${JSON.stringify(record)}\n`, "utf8");
  return record;
}
