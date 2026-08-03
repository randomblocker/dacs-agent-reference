/**
 * Ruling ledger — append-only, hash-chained JSONL.
 *
 * Each line is a LedgerEntry { seq, prevHash, entryHash, ruling } where
 * entryHash = sha256(canonicalJson({ seq, prevHash, ruling })) and prevHash
 * is the previous entry's entryHash (GENESIS_HASH for the first). Editing
 * ANY mid-file ruling either breaks its own entryHash, or — if the tamperer
 * recomputes it — breaks the next entry's prevHash link; and the ruling's
 * own signature breaks either way. `verifyLedger` walks all three layers.
 *
 * This file is EvalBot's portable track record: the entries embed the
 * evaluator's public key, so a third party holding only the ledger can
 * verify every ruling was issued by the same signer(s) and never reordered.
 */
import { mkdir, readFile, appendFile } from "node:fs/promises";
import { dirname } from "node:path";
import { sha256Hex } from "../oracle-desk/attested-fetch.js";
import { canonicalJson, verifyRuling } from "./ruling.js";
import type { EvaluationRuling, LedgerEntry, LedgerVerifyResult, ReputationSummary, Verdict } from "./types.js";

export const GENESIS_HASH = sha256Hex("dacs-agents/evalbot ledger genesis v1");

function computeEntryHash(seq: number, prevHash: string, ruling: EvaluationRuling): string {
  return sha256Hex(canonicalJson({ seq, prevHash, ruling }));
}

// ---------------------------------------------------------------------------
// Read / append
// ---------------------------------------------------------------------------

export async function readLedger(path: string): Promise<LedgerEntry[]> {
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
        return JSON.parse(line) as LedgerEntry;
      } catch {
        throw new Error(`ledger line ${i + 1} is not valid JSON`);
      }
    });
}

/** Append a ruling as the next chained entry; returns the entry written. */
export async function appendRuling(path: string, ruling: EvaluationRuling): Promise<LedgerEntry> {
  await mkdir(dirname(path), { recursive: true });
  const existing = await readLedger(path);
  const last = existing[existing.length - 1];
  const seq = (last?.seq ?? 0) + 1;
  const prevHash = last?.entryHash ?? GENESIS_HASH;
  const entry: LedgerEntry = { seq, prevHash, entryHash: computeEntryHash(seq, prevHash, ruling), ruling };
  await appendFile(path, `${JSON.stringify(entry)}\n`, "utf8");
  return entry;
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/**
 * Walk the full chain: sequence numbering, prevHash linkage, entryHash
 * recomputation, and every ruling's own hash + ed25519 signature (against
 * the key embedded in that ruling). Collects ALL problems rather than
 * stopping at the first.
 */
export async function verifyLedger(path: string): Promise<LedgerVerifyResult> {
  const problems: string[] = [];
  let entries: LedgerEntry[];
  try {
    entries = await readLedger(path);
  } catch (err) {
    return { valid: false, entries: 0, problems: [(err as Error).message] };
  }

  let expectedPrev = GENESIS_HASH;
  for (const [i, entry] of entries.entries()) {
    const label = `entry ${i + 1} (seq ${entry.seq})`;
    if (entry.seq !== i + 1) problems.push(`${label}: expected seq ${i + 1}`);
    if (entry.prevHash !== expectedPrev) problems.push(`${label}: prevHash breaks the chain`);
    if (entry.entryHash !== computeEntryHash(entry.seq, entry.prevHash, entry.ruling)) {
      problems.push(`${label}: entryHash does not match its contents`);
    }
    const rulingVerdict = verifyRuling(entry.ruling);
    if (!rulingVerdict.valid) problems.push(`${label}: ruling invalid — ${rulingVerdict.reason}`);
    expectedPrev = entry.entryHash;
  }

  return { valid: problems.length === 0, entries: entries.length, problems };
}

// ---------------------------------------------------------------------------
// Reputation
// ---------------------------------------------------------------------------

export async function summarizeReputation(path: string): Promise<ReputationSummary> {
  const entries = await readLedger(path);
  const byVerdict: Record<Verdict, number> = { accept: 0, reject: 0, indeterminate: 0 };
  for (const entry of entries) byVerdict[entry.ruling.verdict] += 1;

  const decided = byVerdict.accept + byVerdict.reject;
  const issuedAts = entries.map((e) => e.ruling.issuedAt).sort();
  return {
    totalRulings: entries.length,
    byVerdict,
    acceptanceRate: decided > 0 ? byVerdict.accept / decided : null,
    firstIssuedAt: issuedAts[0] ?? null,
    lastIssuedAt: issuedAts[issuedAts.length - 1] ?? null,
  };
}
