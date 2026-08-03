/**
 * Output normalization — the determinism layer for the executor's
 * reproducibility commitment (D1 in `claudedocs/executor-staked-consensus.md`).
 *
 * WHY THIS EXISTS
 * ---------------
 * The raw per-check commitment is `sha256(stdout+stderr)` (`sandbox.ts`). Two
 * HONEST re-runners of the SAME pinned inputs will NEVER produce byte-identical
 * raw console text: it carries wall-clock timestamps, elapsed durations
 * ("done in 3.4s", per-test "(5 ms)"), npm progress/timing/update-notifier
 * chatter, and ANSI control codes — all pure noise that varies run-to-run. So a
 * quorum over the raw hash can never agree, and no M-of-N attestation is ever
 * possible.
 *
 * `normalizeOutput` projects raw output to a canonical form that STRIPS ONLY
 * provably-non-deterministic noise, then the quorum compares
 * `sha256(normalizeOutput(output))`. The raw hash + `outputTail` stay for human
 * forensics; the NORMALIZED hash is what re-runners compare.
 *
 * THE ONE-WAY SAFETY RULE
 * -----------------------
 * A normalizer has two failure modes and they are NOT symmetric:
 *   - false-DIVERGE (leave noise in) → honest runners disagree → over-disputes.
 *     Annoying, but fail-safe: nobody is wrongly certified.
 *   - false-AGREE (strip real signal) → a genuine divergence in results is
 *     masked → a wrong verdict gets quorum-certified. This is the DANGEROUS
 *     direction and must never happen.
 * Therefore this file is deliberately CONSERVATIVE. It only collapses tokens
 * that carry NO verdict meaning (timestamps, durations, progress, mount paths,
 * ANSI). It NEVER rewrites semantic tokens — in particular it does NOT touch
 * version numbers, so a toolchain-drift divergence (D4) still shows up as a
 * different normalized hash instead of being papered over.
 *
 * CONSENSUS PARAMETER
 * -------------------
 * `NORMALIZATION_VERSION` is itself a consensus parameter: two re-runners on
 * different normalizer versions would false-diverge on identical inputs. It is
 * bound into the quorum attestation (see `QuorumAttestation`), and any change to
 * the rules below MUST bump it and be coordinated across re-runners.
 */
import { createHash } from "node:crypto";

/**
 * Version of the normalization ruleset below. BUMP on ANY change to
 * `normalizeOutput`'s behavior — it is a consensus parameter, bound into the
 * quorum attestation so re-runners can detect a normalizer-version mismatch
 * instead of silently false-diverging.
 */
export const NORMALIZATION_VERSION = "1" as const;

/** Placeholder tokens (short, unlikely to collide with real output). */
const WORKSPACE_PLACEHOLDER = "<WS>";
const NPMCACHE_PLACEHOLDER = "<NPMCACHE>";
const TS_PLACEHOLDER = "<TS>";
const TIME_PLACEHOLDER = "<TIME>";
const EPOCHMS_PLACEHOLDER = "<EPOCHMS>";
const DUR_PLACEHOLDER = "<DUR>";

// ANSI/VT control sequences: CSI (colors, cursor) + OSC (title) + lone ESC.
const ANSI_CSI = /\x1B\[[0-?]*[ -/]*[@-~]/g;
const ANSI_OSC = /\x1B\][^\x07\x1B]*(?:\x07|\x1B\\)/g;

/** Strip ANSI escape sequences (colour, cursor moves, window-title OSC). */
export function stripAnsi(s: string): string {
  return s.replace(ANSI_OSC, "").replace(ANSI_CSI, "");
}

/**
 * Emulate a terminal's carriage-return overwrite: within a physical line,
 * `a\rb\rc` renders as `c` (each `\r` returns the cursor to column 0 and the
 * following text overwrites). This is how npm/download progress spinners redraw
 * in place — the intermediate frames are noise; only the final frame survives.
 */
function collapseCarriageReturns(line: string): string {
  if (!line.includes("\r")) return line;
  const frames = line.split("\r");
  // Later frames overwrite earlier ones from column 0. A short later frame does
  // not fully erase a longer earlier one, but for a hashing projection the last
  // non-empty frame is the stable, sufficient canonicalization.
  for (let i = frames.length - 1; i >= 0; i--) {
    if (frames[i].length > 0) return frames[i];
  }
  return "";
}

/** A whole line that is pure package-manager noise (dropped entirely). */
function isNoiseLine(line: string): boolean {
  const t = line.trim();
  if (t.length === 0) return false; // blank-line trimming handled separately
  // Update-notifier advertisement (npm/yarn "a new version is available"): the
  // advertised version is time-varying, pure noise, unrelated to the run.
  if (t.startsWith("npm notice")) return true;
  // Internal npm timing / http-fetch chatter (only present at high loglevels)
  // carries per-run millisecond timings and cache hit/miss ordering.
  if (/^npm (?:timing|http|sill|verb)\b/.test(t)) return true;
  // Update-notifier box: lines made up solely of box-drawing / padding chars.
  if (/^[\s─-╿│┃╌╍╎╏]+$/.test(t)) return true;
  return false;
}

/** Ordered token replacements applied to each surviving line. */
function normalizeTokens(line: string): string {
  let s = line;
  // Leading progress-spinner glyph (braille block U+2800–U+28FF, as used by
  // ora/npm/cli-spinners): WHICH frame glyph is shown is timing-dependent noise.
  // Braille pattern chars are effectively never real test signal.
  s = s.replace(/^[⠀-⣿]+[ \t]?/, "");
  // ISO-8601 date-times (2026-07-09T12:34:56.789Z, with or without tz/ms).
  s = s.replace(
    /\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?/g,
    TS_PLACEHOLDER,
  );
  // 13-digit millisecond epoch (Date.now()). 13 consecutive digits are almost
  // never verdict signal; timestamps carry no result meaning.
  s = s.replace(/\b\d{13}\b/g, EPOCHMS_PLACEHOLDER);
  // Bare clock times HH:MM:SS(.mmm) — e.g. log prefixes "[12:34:56]".
  s = s.replace(/\b\d{2}:\d{2}:\d{2}(?:\.\d+)?\b/g, TIME_PLACEHOLDER);
  // Elapsed-time tokens (timing is never a verdict signal):
  //   "done in 3.4s", "built in 1.23 s", "in 456ms"
  s = s.replace(/\bin \d+(?:\.\d+)?\s?(?:ms|s)\b/gi, `in ${DUR_PLACEHOLDER}`);
  //   minute+second "1m 2s" / "1m2.3s"
  s = s.replace(/\b\d+m\s?\d+(?:\.\d+)?s\b/g, DUR_PLACEHOLDER);
  //   parenthetical per-test timings jest/vitest "(5 ms)" / "(1.2s)"
  s = s.replace(/\(\s*\d+(?:\.\d+)?\s?m?s\s*\)/g, `(${DUR_PLACEHOLDER})`);
  //   standalone millisecond token "456ms"
  s = s.replace(/\b\d+(?:\.\d+)?\s?ms\b/g, DUR_PLACEHOLDER);
  //   standalone seconds token "1.234 s" / "3s" (jest "Time: 1.234 s", vitest
  //   "Duration 1.2s"). Elapsed time only — never a verdict signal.
  s = s.replace(/\b\d+(?:\.\d+)?\s?s\b/g, DUR_PLACEHOLDER);
  // Absolute mount paths. The workspace is always mounted at /workspace, but
  // its host prefix (and any /tmp cache path) differs per operator.
  s = s.replace(/\/tmp\/\.npm[^\s'"]*/g, NPMCACHE_PLACEHOLDER);
  s = s.replace(/\/workspace\b/g, WORKSPACE_PLACEHOLDER);
  // Trailing whitespace (line-ending / padding variance).
  s = s.replace(/[ \t]+$/g, "");
  return s;
}

/**
 * Project raw combined stdout+stderr to a canonical, byte-stable form for
 * hashing. Pure + deterministic. See the file header for the safety rule: this
 * only removes provably-non-deterministic NOISE and never rewrites result
 * signal (test names, failure messages, exit info, VERSION numbers).
 *
 * Pipeline: strip ANSI → collapse `\r` overwrite per line → drop package-manager
 * noise lines → per-line token normalization (timestamps, durations, mount
 * paths) → trim trailing blank lines. Internal blank lines are preserved (they
 * can be structural); leading/trailing blank lines are trimmed.
 */
export function normalizeOutput(raw: string): string {
  const ansiFree = stripAnsi(raw);
  const physicalLines = ansiFree.replace(/\r\n/g, "\n").split("\n");
  const out: string[] = [];
  for (const physical of physicalLines) {
    const line = collapseCarriageReturns(physical);
    if (isNoiseLine(line)) continue;
    out.push(normalizeTokens(line));
  }
  // Trim leading/trailing whitespace-only lines (EOF newline variance).
  while (out.length > 0 && out[0].trim() === "") out.shift();
  while (out.length > 0 && out[out.length - 1].trim() === "") out.pop();
  return out.join("\n");
}

/** sha256 of the normalized projection — the quorum's per-check commitment. */
export function normalizedOutputHash(raw: string): string {
  return createHash("sha256").update(normalizeOutput(raw), "utf8").digest("hex");
}
