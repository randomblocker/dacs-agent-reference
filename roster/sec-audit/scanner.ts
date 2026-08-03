/**
 * Scanner — directory walk, per-file rule dispatch, and suppression
 * handling. Pure with respect to ports: the auditor injects nothing here
 * beyond the filesystem read (node:fs), and every helper below the walk is
 * a pure function over strings so the tests can drive them offline.
 *
 * Walk policy: node_modules/, .git/, and out/ are never entered; symlinks
 * are not followed; results are sorted for deterministic record ids.
 *
 * Suppression: `audit-ok <ruleId>` in a comment on the hit line or the line
 * directly above suppresses that rule's hit at that line. Suppressed hits
 * are returned separately and COUNTED in the report — never silent.
 */
import { readdir, readFile, lstat } from "node:fs/promises";
import { join } from "node:path";
import { isCommentLine, runRepoFileRules, runRepoLineRules } from "./rules-repo.js";
import { runSolidityRules } from "./rules-solidity.js";
import type { AuditMode, RawHit, SuppressionEntry } from "./types.js";

// ---------------------------------------------------------------------------
// Walk
// ---------------------------------------------------------------------------

export const SKIPPED_DIRS: ReadonlySet<string> = new Set(["node_modules", ".git", "out"]);

/** Max bytes a file may have and still be content-scanned (it is always attested). */
export const MAX_SCAN_BYTES = 1_000_000;

/**
 * Recursively list files under `dir` as sorted relative paths (posix
 * separators), skipping SKIPPED_DIRS and symlinks.
 */
export async function walkFiles(dir: string): Promise<string[]> {
  const out: string[] = [];
  async function recurse(rel: string): Promise<void> {
    const abs = rel === "" ? dir : join(dir, rel);
    const entries = await readdir(abs, { withFileTypes: true });
    for (const entry of entries) {
      const childRel = rel === "" ? entry.name : `${rel}/${entry.name}`;
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (SKIPPED_DIRS.has(entry.name)) continue;
        await recurse(childRel);
      } else if (entry.isFile()) {
        out.push(childRel);
      }
    }
  }
  const st = await lstat(dir);
  if (!st.isDirectory()) throw new Error(`scanner: ${dir} is not a directory`);
  await recurse("");
  return out.sort();
}

export async function readFileBytes(dir: string, relPath: string): Promise<Buffer> {
  return readFile(join(dir, relPath));
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

const CODE_EXTENSIONS = new Set([
  ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts",
  ".py", ".rb", ".go", ".rs", ".java", ".php", ".sh", ".bash", ".zsh",
  ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf",
]);

function baseName(relPath: string): string {
  const i = relPath.lastIndexOf("/");
  return i === -1 ? relPath : relPath.slice(i + 1);
}

function extension(relPath: string): string {
  const base = baseName(relPath);
  const dot = base.lastIndexOf(".");
  return dot <= 0 ? "" : base.slice(dot).toLowerCase();
}

export function isSolidityFile(relPath: string): boolean {
  return extension(relPath) === ".sol";
}

/** Files whose CONTENT the repo line rules scan (filename rules see every file). */
export function isRepoCodeFile(relPath: string): boolean {
  const base = baseName(relPath);
  if (base.startsWith(".env")) return true; // secrets hide in env files
  return CODE_EXTENSIONS.has(extension(relPath));
}

/** Cheap binary sniff: a NUL byte in the first 8 KiB. */
export function looksBinary(content: Buffer): boolean {
  const window = content.subarray(0, 8192);
  return window.includes(0);
}

// ---------------------------------------------------------------------------
// Suppressions
// ---------------------------------------------------------------------------

const SUPPRESS_RE = /audit-ok\s+([a-z][a-z0-9-]*)/gi;

/**
 * line (1-based) → rule ids suppressed AT that line. A marker on a
 * comment-only line covers the NEXT line (the classic marker-above style);
 * a trailing marker on a code line covers THAT line only — so an inline
 * marker never leaks onto the following statement.
 */
export function collectSuppressionMarkers(text: string): Map<number, Set<string>> {
  const markers = new Map<number, Set<string>>();
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const effectiveLine = isCommentLine(lines[i]) ? i + 2 : i + 1;
    for (const m of lines[i].matchAll(SUPPRESS_RE)) {
      const set = markers.get(effectiveLine) ?? new Set<string>();
      set.add(m[1].toLowerCase());
      markers.set(effectiveLine, set);
    }
  }
  return markers;
}

export interface SuppressionSplit {
  kept: RawHit[];
  suppressed: SuppressionEntry[];
}

/**
 * Apply suppression markers to a file's hits: a hit is suppressed when an
 * `audit-ok <its ruleId>` marker is effective at the hit's line (inline on
 * the hit line, or on the comment line directly above).
 */
export function applySuppressions(hits: RawHit[], markers: Map<number, Set<string>>): SuppressionSplit {
  const kept: RawHit[] = [];
  const suppressed: SuppressionEntry[] = [];
  for (const hit of hits) {
    if (markers.get(hit.line)?.has(hit.ruleId) ?? false) {
      suppressed.push({ ruleId: hit.ruleId, file: hit.file, line: hit.line, excerpt: hit.excerpt });
    } else {
      kept.push(hit);
    }
  }
  return { kept, suppressed };
}

// ---------------------------------------------------------------------------
// Per-file dispatch
// ---------------------------------------------------------------------------

export interface FileScanResult {
  hits: RawHit[];
  suppressions: SuppressionEntry[];
  /** False when the file was attested but not content-scanned (binary/oversized/mode). */
  scanned: boolean;
}

/**
 * Run the rules a file qualifies for under `mode`. Pure: takes the content,
 * returns hits + honored suppressions.
 */
export function scanFileContent(relPath: string, content: Buffer, mode: AuditMode): FileScanResult {
  const none: FileScanResult = { hits: [], suppressions: [], scanned: false };

  const solidity = isSolidityFile(relPath);
  const wantSolidity = (mode === "auto" || mode === "solidity") && solidity;
  const wantRepo = (mode === "auto" || mode === "repo") && !solidity;
  if (!wantSolidity && !wantRepo) return none;

  // Filename rules need no content and apply regardless of size/binariness.
  const fileHits = wantRepo ? runRepoFileRules(relPath) : [];

  if (content.length > MAX_SCAN_BYTES || looksBinary(content)) {
    return { hits: fileHits, suppressions: [], scanned: false };
  }

  const text = content.toString("utf8");
  const markers = collectSuppressionMarkers(text);

  let lineHits: RawHit[] = [];
  if (wantSolidity) {
    lineHits = runSolidityRules(relPath, text);
  } else if (isRepoCodeFile(relPath)) {
    lineHits = runRepoLineRules(relPath, text);
  }

  const { kept, suppressed } = applySuppressions([...fileHits, ...lineHits], markers);
  return { hits: kept, suppressions: suppressed, scanned: true };
}
