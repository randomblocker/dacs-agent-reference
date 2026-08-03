/**
 * Rubric engine — deterministic evaluation of `mechanical` criteria.
 *
 * Every check returns { pass, reason }; the orchestrator maps pass -> 100
 * and fail -> 0. Checks never throw on bad input (unparseable JSON, invalid
 * regex, unregistered predicate names…) — they fail with a reason instead,
 * so a malformed deliverable scores 0 rather than crashing the evaluation.
 *
 * The dot-path resolver is dependency-free: "a.b.0.c" walks objects and
 * array indices; ".length" additionally works on arrays AND strings, which
 * lets rubrics express "findings.length >= 1" or "summary.text.length >= 120"
 * without a query language.
 */
import { sha256Hex } from "../oracle-desk/attested-fetch.js";
import type { MechanicalCheck, NumericOp, PredicateRegistry } from "./types.js";

// ---------------------------------------------------------------------------
// Dot-path resolver
// ---------------------------------------------------------------------------

export interface PathResolution {
  found: boolean;
  value: unknown;
}

const NOT_FOUND: PathResolution = { found: false, value: undefined };

/** Resolve a dot-path against a parsed JSON value. No deps, no eval. */
export function resolveJsonPath(root: unknown, path: string): PathResolution {
  const segments = path.split(".");
  if (segments.some((s) => s.length === 0)) return NOT_FOUND;

  let current: unknown = root;
  for (const seg of segments) {
    if (current === null || current === undefined) return NOT_FOUND;

    if (typeof current === "string") {
      if (seg !== "length") return NOT_FOUND;
      current = current.length;
      continue;
    }
    if (Array.isArray(current)) {
      if (seg === "length") {
        current = current.length;
        continue;
      }
      if (!/^\d+$/.test(seg)) return NOT_FOUND;
      const idx = Number(seg);
      if (idx >= current.length) return NOT_FOUND;
      current = current[idx];
      continue;
    }
    if (typeof current === "object") {
      const record = current as Record<string, unknown>;
      if (!Object.prototype.hasOwnProperty.call(record, seg)) return NOT_FOUND;
      current = record[seg];
      continue;
    }
    // number / boolean — nothing further to walk into.
    return NOT_FOUND;
  }
  return { found: true, value: current };
}

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

export interface CheckOutcome {
  pass: boolean;
  reason: string;
}

function parseJson(content: string): { ok: true; value: unknown } | { ok: false } {
  try {
    return { ok: true, value: JSON.parse(content) };
  } catch {
    return { ok: false };
  }
}

function compareNumeric(value: number, op: NumericOp, target: number): boolean {
  switch (op) {
    case ">=":
      return value >= target;
    case ">":
      return value > target;
    case "<=":
      return value <= target;
    case "<":
      return value < target;
    case "==":
      return value === target;
  }
}

/** Run one mechanical check against the deliverable content. Never throws. */
export function runMechanicalCheck(
  test: MechanicalCheck,
  content: string,
  predicates: PredicateRegistry = {},
): CheckOutcome {
  switch (test.check) {
    case "content-includes": {
      const pass = content.includes(test.needle);
      return { pass, reason: pass ? `content includes "${test.needle}"` : `content missing "${test.needle}"` };
    }

    case "regex-match": {
      let re: RegExp;
      try {
        re = new RegExp(test.pattern, test.flags);
      } catch (err) {
        return { pass: false, reason: `invalid regex /${test.pattern}/: ${(err as Error).message}` };
      }
      const pass = re.test(content);
      return { pass, reason: pass ? `matches /${test.pattern}/` : `no match for /${test.pattern}/` };
    }

    case "min-length": {
      const pass = content.length >= test.minChars;
      return { pass, reason: `length ${content.length} ${pass ? ">=" : "<"} min ${test.minChars}` };
    }

    case "max-length": {
      const pass = content.length <= test.maxChars;
      return { pass, reason: `length ${content.length} ${pass ? "<=" : ">"} max ${test.maxChars}` };
    }

    case "sha256-equals": {
      const actual = sha256Hex(content);
      const pass = actual === test.expected.toLowerCase();
      return { pass, reason: pass ? "sha256 matches" : `sha256 ${actual.slice(0, 12)}… != expected ${test.expected.slice(0, 12)}…` };
    }

    case "json-parses": {
      const parsed = parseJson(content);
      return { pass: parsed.ok, reason: parsed.ok ? "valid JSON" : "content is not valid JSON" };
    }

    case "json-path-exists": {
      const parsed = parseJson(content);
      if (!parsed.ok) return { pass: false, reason: "content is not valid JSON" };
      const res = resolveJsonPath(parsed.value, test.path);
      return { pass: res.found, reason: res.found ? `path "${test.path}" exists` : `path "${test.path}" missing` };
    }

    case "numeric-threshold": {
      const parsed = parseJson(content);
      if (!parsed.ok) return { pass: false, reason: "content is not valid JSON" };
      const res = resolveJsonPath(parsed.value, test.path);
      if (!res.found) return { pass: false, reason: `path "${test.path}" missing` };
      if (typeof res.value !== "number" || !Number.isFinite(res.value)) {
        return { pass: false, reason: `path "${test.path}" is not a finite number (got ${typeof res.value})` };
      }
      const pass = compareNumeric(res.value, test.op, test.value);
      return { pass, reason: `${test.path} = ${res.value} ${pass ? "satisfies" : "fails"} ${test.op} ${test.value}` };
    }

    case "custom-predicate": {
      const predicate = predicates[test.name];
      if (!predicate) return { pass: false, reason: `no predicate registered under "${test.name}"` };
      try {
        const result = predicate(content);
        return { pass: result.pass, reason: result.detail ?? `predicate "${test.name}" ${result.pass ? "passed" : "failed"}` };
      } catch (err) {
        return { pass: false, reason: `predicate "${test.name}" threw: ${(err as Error).message}` };
      }
    }
  }
}
