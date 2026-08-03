/**
 * Pre-scan — how the seller learns the PRIVATE cost facts of a target.
 *
 * The pre-scan is the whole reason this negotiation is honest: the seller walks
 * the tree, counts KLOC, and detects Solidity (⇒ whether Slither applies), and
 * that scan is information the buyer does not have. The seller's floor is a
 * function of it (`terms.ts#floorFor`), so the seller can quote from real cost
 * while the buyer can only probe by negotiating.
 *
 * Two ports ship here: a deterministic FAKE (offline demos/tests — its facts are
 * derived from the repo string, so different repos drive genuinely different
 * negotiations) and a REAL local-directory scanner (walks a path on disk). A
 * git-clone scanner is a thin wrapper over `localDirScan` to add when wiring the
 * live desk — it clones, then scans the checkout.
 */
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { toolsForScan, type ScanFacts } from "./terms.js";

/** A pre-scan source: turn a target descriptor into private cost facts. */
export type ScanPort = (target: string) => Promise<ScanFacts>;

// ---------------------------------------------------------------------------
// Deterministic fake (offline)
// ---------------------------------------------------------------------------

/**
 * Deterministic fake scan: facts derived from the repo string so a given repo
 * always scans the same, but different repos differ. Ranges are chosen to
 * exercise both cheap (small TS repo) and expensive (large, Solidity) deals.
 */
export const fakeScan: ScanPort = async (target) => {
  const h = createHash("sha256").update(target).digest();
  const kloc = 2 + (h[0]! % 40); // 2..41 KLOC
  const fileCount = 5 + (h[1]! % 120); // 5..124 files
  const hasSolidity = h[2]! % 3 === 0; // ~1/3 of repos carry Solidity
  return { repo: target, kloc, fileCount, hasSolidity, numTools: toolsForScan(hasSolidity) };
};

// ---------------------------------------------------------------------------
// Real local-directory scan
// ---------------------------------------------------------------------------

const CODE_EXT = new Set([
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".sol", ".py", ".go", ".rs", ".java", ".rb", ".c", ".h", ".cpp", ".sh",
]);
const SKIP_DIR = new Set(["node_modules", ".git", "dist", "build", "out", "coverage", ".next", "vendor"]);
const MAX_FILES = 20_000;

/** Walk a directory, counting code lines and detecting Solidity. */
export function localDirScan(dir: string): ScanFacts {
  let lines = 0;
  let fileCount = 0;
  let hasSolidity = false;

  const walk = (d: string) => {
    if (fileCount >= MAX_FILES) return;
    let entries: string[];
    try {
      entries = readdirSync(d);
    } catch {
      return;
    }
    for (const name of entries) {
      const p = join(d, name);
      let st;
      try {
        st = statSync(p);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        if (!SKIP_DIR.has(name) && !name.startsWith(".")) walk(p);
        continue;
      }
      const dot = name.lastIndexOf(".");
      const ext = dot === -1 ? "" : name.slice(dot).toLowerCase();
      if (!CODE_EXT.has(ext)) continue;
      if (ext === ".sol") hasSolidity = true;
      fileCount++;
      try {
        lines += readFileSync(p, "utf8").split("\n").length;
      } catch {
        /* unreadable file — skip its lines */
      }
    }
  };

  walk(dir);
  const kloc = Math.max(1, Math.round(lines / 100) / 10); // 0.1-KLOC resolution, min 1
  return { repo: dir, kloc, fileCount, hasSolidity, numTools: toolsForScan(hasSolidity) };
}

/** A `ScanPort` over a local directory path. */
export const localDirScanPort: ScanPort = async (target) => localDirScan(target);
