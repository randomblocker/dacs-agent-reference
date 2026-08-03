/**
 * Per-snapshot prepared-name memo — a behavior-neutral accelerator.
 *
 * Every entry name+alias is run through `prepareName()` ONCE per snapshot and
 * cached by the entries-array identity, so a memoized (re-used) snapshot pays
 * the normalization cost once instead of on every request. The scorer sees
 * identical inputs either way — this changes NOTHING about what counts as a
 * match, only how often names are normalized.
 *
 * (An earlier version also held a token/n-gram "candidate index" to shrink the
 * ~2M-entry PEP scan. It was removed: no such index can be a safe superset of
 * Jaro-Winkler fuzzy matching — transposition typos score highly yet share no
 * n-gram — so it could drop a real hit (a false clear). PEP is now full-scanned;
 * see `screenNamesAgainstPep` in screener.ts.)
 */
import type { ListEntry } from "./types.js";
import { prepareName, type PreparedName } from "./matching.js";

const preparedCache = new WeakMap<readonly ListEntry[], PreparedName[][]>();

/** `[name, ...aliases]` prepared once per entry, memoized by the entries array. */
export function preparedNamesFor(entries: readonly ListEntry[]): PreparedName[][] {
  const hit = preparedCache.get(entries);
  if (hit) return hit;
  const prepared = entries.map((e) => [e.name, ...e.aliases].map(prepareName));
  preparedCache.set(entries, prepared);
  return prepared;
}
