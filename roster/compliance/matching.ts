/**
 * Matching engine — pure functions, no I/O.
 *
 * Name matching pipeline: normalize (lowercase, NFD diacritic strip,
 * punctuation → space, whitespace collapse), token-sort for order
 * insensitivity, then score with the best of: exact-normalized equality,
 * Jaro-Winkler over the token-sorted strings, and Dice token overlap.
 * Thresholds are exported constants; wallet screening is exact
 * case-insensitive address equality.
 */
import type { MatchMethod, MatchSeverity } from "./types.js";

// ---------------------------------------------------------------------------
// Thresholds
// ---------------------------------------------------------------------------

/** Fuzzy score at or above this (or an exact-normalized hit) → "match". */
export const MATCH_THRESHOLD = 0.93;

/** Fuzzy score in [POTENTIAL, MATCH) → "potential-match". Below → no match. */
export const POTENTIAL_THRESHOLD = 0.85;

// ---------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------

/** "José-María" → "Jose-Maria" (NFD decompose, strip combining marks). */
export function stripDiacritics(s: string): string {
  return s.normalize("NFD").replace(/[\u0300-\u036f]/g, "");
}

/**
 * Canonical lowercase form: diacritics stripped, every non-alphanumeric run
 * collapsed to a single space, trimmed. "LAZARUS  GROUP," → "lazarus group".
 */
export function normalizeName(s: string): string {
  return stripDiacritics(transliterate(s.toLowerCase()))
    .replace(/[^a-z0-9]+/g, " ")
    .trim();
}

/**
 * Latin-script letters carrying a STROKE or that are LIGATURES — NFD does NOT
 * decompose these into base + combining mark, so the generic diacritic strip
 * leaves them and the `[^a-z0-9]` pass would DELETE them, silently corrupting
 * the name ("Lukasz" spelt with a stroked l would drop to "ukasz", a screening
 * miss). Transliterate to the conventional ASCII carrier first. Applied to the
 * already-lowercased string.
 */
const TRANSLITERATIONS: ReadonlyArray<readonly [RegExp, string]> = [
  [/ß/g, "ss"], // ß
  [/æ/g, "ae"], // æ
  [/œ/g, "oe"], // œ
  [/ø/g, "o"], // ø
  [/ł/g, "l"], // ł
  [/đ/g, "d"], // đ
  [/ð/g, "d"], // ð
  [/þ/g, "th"], // þ
  [/ħ/g, "h"], // ħ
  [/ı/g, "i"], // ı (dotless i)
  [/ĸ/g, "k"], // ĸ
  [/ŋ/g, "n"], // ŋ
  [/ſ/g, "s"], // ſ (long s)
];

/** Lowercased input -> transliterate stroked/ligature letters NFD cannot decompose. */
export function transliterate(lower: string): string {
  let out = lower;
  for (const [re, rep] of TRANSLITERATIONS) out = out.replace(re, rep);
  return out;
}

/**
 * Corporate-form designators dropped when comparing ENTITY names, so
 * "Oceanic Freight Solutions LLC" and "Oceanic Freight Solutions" (or "... Ltd")
 * are not diluted by a legal-form token that carries no identity. Conservative
 * and explicit: the suffix-stripped "core" variant is only ever an ADDITIONAL
 * scoring signal (best-of full vs core), never a replacement, so it cannot
 * invent a match from two unrelated names that share only a legal suffix.
 */
export const CORPORATE_SUFFIXES: ReadonlySet<string> = new Set([
  "ltd", "limited", "llc", "inc", "incorporated", "corp", "corporation", "co", "company",
  "gmbh", "ag", "sa", "sas", "srl", "spa", "bv", "nv", "plc", "pte", "pty", "llp", "lp",
  "ojsc", "jsc", "pjsc", "ooo", "oao", "zao", "ab", "oy", "as", "aps", "kg", "kk", "sarl",
]);

/** Tokens with trailing corporate-form designators removed (never emptied). */
export function coreTokens(tokens: readonly string[]): string[] {
  const core = tokens.filter((t) => !CORPORATE_SUFFIXES.has(t));
  return core.length > 0 ? core : [...tokens];
}

export function nameTokens(s: string): string[] {
  const n = normalizeName(s);
  return n.length === 0 ? [] : n.split(" ");
}

/** Order-insensitive key: normalized tokens sorted and re-joined. */
export function tokenSortKey(s: string): string {
  return nameTokens(s).sort().join(" ");
}

// ---------------------------------------------------------------------------
// Jaro-Winkler
// ---------------------------------------------------------------------------

/** Standard Jaro-Winkler similarity in [0, 1] (prefix scale 0.1, max 4). */
export function jaroWinkler(s1: string, s2: string): number {
  if (s1 === s2) return s1.length === 0 ? 0 : 1;
  const len1 = s1.length;
  const len2 = s2.length;
  if (len1 === 0 || len2 === 0) return 0;

  const window = Math.max(0, Math.floor(Math.max(len1, len2) / 2) - 1);
  const matched1 = new Array<boolean>(len1).fill(false);
  const matched2 = new Array<boolean>(len2).fill(false);

  let matches = 0;
  for (let i = 0; i < len1; i++) {
    const lo = Math.max(0, i - window);
    const hi = Math.min(len2 - 1, i + window);
    for (let j = lo; j <= hi; j++) {
      if (!matched2[j] && s1[i] === s2[j]) {
        matched1[i] = true;
        matched2[j] = true;
        matches += 1;
        break;
      }
    }
  }
  if (matches === 0) return 0;

  let transpositions = 0;
  let k = 0;
  for (let i = 0; i < len1; i++) {
    if (!matched1[i]) continue;
    while (!matched2[k]) k += 1;
    if (s1[i] !== s2[k]) transpositions += 1;
    k += 1;
  }
  const t = transpositions / 2;
  const jaro = (matches / len1 + matches / len2 + (matches - t) / matches) / 3;

  let prefix = 0;
  const maxPrefix = Math.min(4, len1, len2);
  for (let i = 0; i < maxPrefix; i++) {
    if (s1[i] === s2[i]) prefix += 1;
    else break;
  }
  return jaro + prefix * 0.1 * (1 - jaro);
}

// ---------------------------------------------------------------------------
// Token overlap (Dice coefficient over token sets)
// ---------------------------------------------------------------------------

export function diceTokenOverlap(tokensA: ReadonlySet<string>, tokensB: ReadonlySet<string>): number {
  if (tokensA.size === 0 || tokensB.size === 0) return 0;
  let shared = 0;
  for (const t of tokensA) if (tokensB.has(t)) shared += 1;
  return (2 * shared) / (tokensA.size + tokensB.size);
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

/** A name pre-normalized once so list-wide scans don't re-normalize. */
export interface PreparedName {
  raw: string;
  key: string;
  tokens: Set<string>;
  /** Token-sort key with corporate suffixes dropped (identity core). */
  coreKey: string;
  coreTokens: Set<string>;
}

export function prepareName(raw: string): PreparedName {
  const tokens = nameTokens(raw);
  const core = coreTokens(tokens);
  return {
    raw,
    key: [...tokens].sort().join(" "),
    tokens: new Set(tokens),
    coreKey: [...core].sort().join(" "),
    coreTokens: new Set(core),
  };
}

export interface NameScore {
  score: number;
  method: Extract<MatchMethod, "exact" | "jaro-winkler" | "token-overlap">;
}

/** Best of exact / Jaro-Winkler / token-overlap over one (key, tokenset) pair. */
function scoreVariant(aKey: string, aTokens: ReadonlySet<string>, bKey: string, bTokens: ReadonlySet<string>): NameScore {
  if (aKey.length === 0 || bKey.length === 0) return { score: 0, method: "token-overlap" };
  if (aKey === bKey) return { score: 1, method: "exact" };
  const jw = jaroWinkler(aKey, bKey);
  const dice = diceTokenOverlap(aTokens, bTokens);
  return jw >= dice ? { score: jw, method: "jaro-winkler" } : { score: dice, method: "token-overlap" };
}

/**
 * Best score across exact / Jaro-Winkler / token-overlap for one pair, scored
 * on BOTH the full name and the corporate-suffix-stripped core, taking the
 * higher. The core variant only ever raises a score (so "Acme Trading Ltd" ~
 * "Acme Trading" reads as exact rather than a diluted 0.8 token-overlap); it
 * never fabricates a match, because dropping a shared suffix can only shrink
 * the token sets both names are measured on.
 */
export function scorePrepared(a: PreparedName, b: PreparedName): NameScore {
  const full = scoreVariant(a.key, a.tokens, b.key, b.tokens);
  if (full.score >= 1) return full;
  const core = scoreVariant(a.coreKey, a.coreTokens, b.coreKey, b.coreTokens);
  return core.score > full.score ? core : full;
}

/** Convenience for tests / one-off pairs. */
export function scoreNames(a: string, b: string): NameScore {
  return scorePrepared(prepareName(a), prepareName(b));
}

export interface BestNameMatch extends NameScore {
  subjectName: string;
  entryName: string;
}

/**
 * Best pair across BOTH alias sets over ALREADY-PREPARED entry names — the
 * hot path. Identical scoring to `bestNameMatch`, but the caller supplies the
 * entry's PreparedNames so a list-wide scan normalizes each entry name ONCE
 * (at parse time) instead of re-normalizing it on every request. `entry.raw`
 * carries the original string, so the reported `entryName` is unchanged.
 */
export function bestNameMatchPrepared(
  subject: readonly PreparedName[],
  entryPrepared: readonly PreparedName[],
): BestNameMatch | null {
  let best: BestNameMatch | null = null;
  for (const entry of entryPrepared) {
    for (const s of subject) {
      const scored = scorePrepared(s, entry);
      if (scored.score < POTENTIAL_THRESHOLD) continue;
      if (!best || scored.score > best.score) {
        best = { ...scored, subjectName: s.raw, entryName: entry.raw };
      }
    }
  }
  return best;
}

/**
 * Best pair across BOTH alias sets (every subject name × every entry name),
 * or null when nothing reaches POTENTIAL_THRESHOLD. Thin wrapper that prepares
 * the entry names on the fly — behavior-identical to `bestNameMatchPrepared`.
 */
export function bestNameMatch(subject: readonly PreparedName[], entryNames: readonly string[]): BestNameMatch | null {
  return bestNameMatchPrepared(subject, entryNames.map(prepareName));
}

/** Threshold classification for fuzzy scores. */
export function classifyScore(score: number): Extract<MatchSeverity, "match" | "potential-match"> | null {
  if (score >= MATCH_THRESHOLD) return "match";
  if (score >= POTENTIAL_THRESHOLD) return "potential-match";
  return null;
}

/**
 * Severity a (method, score) pair MUST carry — the single derivation used
 * both when building matches and when re-verifying a report, so an edited
 * score or severity is caught as an inconsistency. Returns null for a fuzzy
 * score below POTENTIAL_THRESHOLD (such a match should not exist at all).
 */
export function severityForMatch(method: MatchMethod, score: number): MatchSeverity | null {
  switch (method) {
    case "wallet-exact":
    case "exact":
      return "match";
    case "edgar-registration":
      return "info";
    case "jaro-winkler":
    case "token-overlap":
      return classifyScore(score);
    case "pep-match":
      // A PEP hit is a different risk category from a sanctions hit: an EXACT
      // normalized name match is a definite positive ("match" — this IS a known
      // PEP), but a fuzzy PEP hit is capped at "potential-match" because PEP
      // datasets are large and common-name collisions must route to human EDD,
      // never an automatic block.
      if (score >= 1) return "match";
      return score >= POTENTIAL_THRESHOLD ? "potential-match" : null;
  }
}

// ---------------------------------------------------------------------------
// Wallets
// ---------------------------------------------------------------------------

/** Exact case-insensitive address equality (conservative for screening). */
export function walletsEqual(a: string, b: string): boolean {
  const ta = a.trim();
  const tb = b.trim();
  return ta.length > 0 && ta.toLowerCase() === tb.toLowerCase();
}
