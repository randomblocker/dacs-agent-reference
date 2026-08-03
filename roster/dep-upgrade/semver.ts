/**
 * Minimal semver — parse/compare plus the range subset this agent needs.
 * Zero dependencies by design (repo rule).
 *
 * Supported range grammar (enough for package.json declarations and npm's
 * advisory `vulnerable_versions` strings):
 *
 *   range      := group ( "||" group )*          — OR
 *   group      := comparator ( <space> comparator )*  — AND
 *   comparator := "*" | "x" | ""                 — match-all
 *              | "^" version                     — caret
 *              | "~" version                     — tilde
 *              | (">=" | ">" | "<=" | "<" | "=") version
 *              | version                         — exact (full) / x-range (partial)
 *
 * Partial versions (`1`, `1.2`, `1.2.x`) are padded with zeros for operator
 * comparators and expanded to x-ranges (`1.2` → >=1.2.0 <1.3.0) when bare.
 *
 * Deliberate simplification vs node-semver: prerelease versions compare
 * numerically against range bounds (no "only match prereleases of the same
 * [major,minor,patch]" gating). The planner never *selects* prereleases
 * (see `isStable`), so this only affects advisory matching of prerelease
 * installs — acceptable for this agent.
 */

export interface SemVer {
  major: number;
  minor: number;
  patch: number;
  prerelease: Array<string | number>;
  raw: string;
}

const FULL_RE = /^v?=?\s*(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

export function parseSemver(input: string): SemVer | null {
  const m = FULL_RE.exec(input.trim());
  if (!m) return null;
  const prerelease = m[4]
    ? m[4].split(".").map((id) => (/^\d+$/.test(id) ? Number(id) : id))
    : [];
  return {
    major: Number(m[1]),
    minor: Number(m[2]),
    patch: Number(m[3]),
    prerelease,
    raw: input.trim(),
  };
}

function comparePrerelease(a: SemVer["prerelease"], b: SemVer["prerelease"]): number {
  if (a.length === 0 && b.length === 0) return 0;
  if (a.length === 0) return 1; // release > prerelease
  if (b.length === 0) return -1;
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (i >= a.length) return -1; // shorter (prefix) is smaller
    if (i >= b.length) return 1;
    const x = a[i];
    const y = b[i];
    if (x === y) continue;
    const xNum = typeof x === "number";
    const yNum = typeof y === "number";
    if (xNum && yNum) return (x as number) < (y as number) ? -1 : 1;
    if (xNum) return -1; // numeric identifiers sort before alphanumeric
    if (yNum) return 1;
    return (x as string) < (y as string) ? -1 : 1;
  }
  return 0;
}

export function compareSemver(a: SemVer, b: SemVer): -1 | 0 | 1 {
  for (const key of ["major", "minor", "patch"] as const) {
    if (a[key] !== b[key]) return a[key] < b[key] ? -1 : 1;
  }
  const pre = comparePrerelease(a.prerelease, b.prerelease);
  return pre < 0 ? -1 : pre > 0 ? 1 : 0;
}

/** Compare two version strings; throws on unparseable input. */
export function compareVersions(a: string, b: string): -1 | 0 | 1 {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  if (!pa || !pb) throw new Error(`semver: cannot compare "${a}" vs "${b}"`);
  return compareSemver(pa, pb);
}

export function isStable(version: string): boolean {
  const v = parseSemver(version);
  return v !== null && v.prerelease.length === 0;
}

// ---------------------------------------------------------------------------
// Ranges
// ---------------------------------------------------------------------------

type Op = ">=" | ">" | "<=" | "<" | "=";

interface Comparator {
  op: Op;
  version: SemVer;
}

/** A group is a set of ANDed comparators; empty group matches everything. */
type Group = Comparator[];

interface Partial3 {
  major: number;
  minor: number | undefined;
  patch: number | undefined;
  prerelease: Array<string | number>;
}

const PARTIAL_RE = /^v?(\d+)(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

function parsePartial(input: string): Partial3 | null {
  const m = PARTIAL_RE.exec(input.trim());
  if (!m) return null;
  const num = (s: string | undefined): number | undefined =>
    s === undefined || /[xX*]/.test(s) ? undefined : Number(s);
  return {
    major: Number(m[1]),
    minor: num(m[2]),
    patch: num(m[3]),
    prerelease: m[4] ? m[4].split(".").map((id) => (/^\d+$/.test(id) ? Number(id) : id)) : [],
  };
}

function mk(major: number, minor: number, patch: number, prerelease: Array<string | number> = []): SemVer {
  return { major, minor, patch, prerelease, raw: `${major}.${minor}.${patch}` };
}

function padded(p: Partial3): SemVer {
  return mk(p.major, p.minor ?? 0, p.patch ?? 0, p.prerelease);
}

function caretComparators(p: Partial3): Comparator[] {
  const lower = padded(p);
  let upper: SemVer;
  if (p.minor === undefined) {
    upper = mk(p.major + 1, 0, 0); // ^1 → <2.0.0
  } else if (p.major > 0) {
    upper = mk(p.major + 1, 0, 0); // ^1.2(.3) → <2.0.0
  } else if (p.minor > 0 || p.patch === undefined) {
    upper = mk(0, p.minor + 1, 0); // ^0.2.3 / ^0.0 → <0.(minor+1).0
  } else {
    upper = mk(0, p.minor, p.patch + 1); // ^0.0.3 → <0.0.4
  }
  return [
    { op: ">=", version: lower },
    { op: "<", version: upper },
  ];
}

function tildeComparators(p: Partial3): Comparator[] {
  const lower = padded(p);
  const upper = p.minor === undefined ? mk(p.major + 1, 0, 0) : mk(p.major, p.minor + 1, 0);
  return [
    { op: ">=", version: lower },
    { op: "<", version: upper },
  ];
}

/** Bare partial like `1` or `1.2` → x-range (`>=1.2.0 <1.3.0`). */
function xRangeComparators(p: Partial3): Comparator[] {
  const lower = padded(p);
  const upper = p.minor === undefined ? mk(p.major + 1, 0, 0) : mk(p.major, p.minor + 1, 0);
  return [
    { op: ">=", version: lower },
    { op: "<", version: upper },
  ];
}

function parseComparatorToken(token: string): Comparator[] {
  if (token === "*" || token.toLowerCase() === "x") return [];
  const opMatch = /^(>=|<=|>|<|=|\^|~)?(.*)$/.exec(token)!;
  const op = opMatch[1] ?? "";
  const rest = opMatch[2]!;
  const p = parsePartial(rest);
  if (!p) throw new Error(`semver: unparseable comparator "${token}"`);

  if (op === "^") return caretComparators(p);
  if (op === "~") return tildeComparators(p);
  if (op === "") {
    // Bare version: full → exact; partial → x-range.
    if (p.minor !== undefined && p.patch !== undefined) {
      return [{ op: "=", version: padded(p) }];
    }
    return xRangeComparators(p);
  }
  return [{ op: op as Op, version: padded(p) }];
}

function parseGroup(group: string): Group {
  const tokens = group.trim().split(/\s+/).filter((t) => t.length > 0);
  const comparators: Comparator[] = [];
  for (const token of tokens) comparators.push(...parseComparatorToken(token));
  return comparators;
}

/** Parse a range string into OR-ed groups of AND-ed comparators. */
export function parseRange(range: string): Group[] {
  const trimmed = range.trim();
  if (trimmed === "" || trimmed === "*" || trimmed.toLowerCase() === "x") return [[]];
  return trimmed.split("||").map(parseGroup);
}

function testComparator(v: SemVer, c: Comparator): boolean {
  const cmp = compareSemver(v, c.version);
  switch (c.op) {
    case ">=": return cmp >= 0;
    case ">": return cmp > 0;
    case "<=": return cmp <= 0;
    case "<": return cmp < 0;
    case "=": return cmp === 0;
  }
}

/**
 * True when `version` matches `range`. Unparseable versions never satisfy;
 * unparseable ranges throw (a bad advisory range is a data bug we must see).
 */
export function satisfies(version: string, range: string): boolean {
  const v = parseSemver(version);
  if (!v) return false;
  const groups = parseRange(range);
  return groups.some((group) => group.every((c) => testComparator(v, c)));
}

function sortedParsed(versions: string[]): Array<{ raw: string; parsed: SemVer }> {
  return versions
    .map((raw) => ({ raw, parsed: parseSemver(raw) }))
    .filter((x): x is { raw: string; parsed: SemVer } => x.parsed !== null)
    .sort((a, b) => compareSemver(a.parsed, b.parsed));
}

/** Lowest version in `versions` satisfying `range`, or null. */
export function minSatisfying(versions: string[], range: string): string | null {
  for (const v of sortedParsed(versions)) if (satisfies(v.raw, range)) return v.raw;
  return null;
}

/** Highest version in `versions` satisfying `range`, or null. */
export function maxSatisfying(versions: string[], range: string): string | null {
  const sorted = sortedParsed(versions);
  for (let i = sorted.length - 1; i >= 0; i--) {
    if (satisfies(sorted[i]!.raw, range)) return sorted[i]!.raw;
  }
  return null;
}

/** Major component of a version string; throws on garbage. */
export function majorOf(version: string): number {
  const v = parseSemver(version);
  if (!v) throw new Error(`semver: unparseable version "${version}"`);
  return v.major;
}
