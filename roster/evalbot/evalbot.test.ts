/**
 * EvalBot tests — fully offline (no LLM, no network). node:test, run:
 *   npx tsx --test roster/evalbot/evalbot.test.ts
 */
import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { sha256Hex } from "../oracle-desk/attested-fetch.js";
import { aggregateScores, decideVerdict, EvalBot, validateRubric } from "./evalbot.js";
import { appendRuling, GENESIS_HASH, readLedger, summarizeReputation, verifyLedger } from "./ledger.js";
import { parseJudgeOutput, type JudgeFn } from "./llm-judge.js";
import { resolveJsonPath, runMechanicalCheck } from "./rubric-engine.js";
import { canonicalJson, computeRulingHash, RulingSigner, signRuling, verifyRuling } from "./ruling.js";
import type { CriterionResult, EvaluationRuling, LedgerEntry, MechanicalCheck, Rubric, UnsignedRuling } from "./types.js";

const NOW = new Date("2026-07-07T12:00:00.000Z");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const check = (test_: MechanicalCheck, content: string, predicates = {}) => runMechanicalCheck(test_, content, predicates);

/** Judge that returns fixed scores for the given ids (or undefined). */
const fixedJudge =
  (scores: Record<string, number> | undefined): JudgeFn =>
  async (criteria) => {
    if (scores === undefined) return undefined;
    const map = new Map<string, { score: number; reason: string }>();
    for (const c of criteria) {
      if (c.id in scores) map.set(c.id, { score: scores[c.id]!, reason: `fixed ${scores[c.id]}` });
    }
    return map;
  };

const mech = (id: string, weight: number, test_: MechanicalCheck) =>
  ({ id, kind: "mechanical", weight, description: id, test: test_ }) as const;
const subj = (id: string, weight: number) => ({ id, kind: "subjective", weight, description: id }) as const;

const PASS: MechanicalCheck = { check: "min-length", minChars: 0 };
const FAIL: MechanicalCheck = { check: "content-includes", needle: "__never_present__" };

async function evaluate(rubric: Rubric, content: string, opts: ConstructorParameters<typeof EvalBot>[0] = {}): Promise<EvaluationRuling> {
  const bot = new EvalBot({ now: () => NOW, useLlm: false, ...opts });
  return bot.evaluate({ jobId: "job-1", rubric, deliverable: { content } });
}

// ---------------------------------------------------------------------------
// Dot-path resolver
// ---------------------------------------------------------------------------

describe("resolveJsonPath", () => {
  const doc = { a: { b: [{ c: 7 }, { c: 8 }] }, s: "hello", n: null, z: 0 };

  test("walks objects, array indices, and finds falsy/null values", () => {
    assert.deepEqual(resolveJsonPath(doc, "a.b.1.c"), { found: true, value: 8 });
    assert.deepEqual(resolveJsonPath(doc, "n"), { found: true, value: null });
    assert.deepEqual(resolveJsonPath(doc, "z"), { found: true, value: 0 });
  });

  test(".length works on arrays and strings", () => {
    assert.deepEqual(resolveJsonPath(doc, "a.b.length"), { found: true, value: 2 });
    assert.deepEqual(resolveJsonPath(doc, "s.length"), { found: true, value: 5 });
  });

  test("missing keys, out-of-range indices, walks into scalars -> not found", () => {
    assert.equal(resolveJsonPath(doc, "a.x").found, false);
    assert.equal(resolveJsonPath(doc, "a.b.2.c").found, false);
    assert.equal(resolveJsonPath(doc, "a.b.notanindex").found, false);
    assert.equal(resolveJsonPath(doc, "z.anything").found, false);
    assert.equal(resolveJsonPath(doc, "n.anything").found, false);
    assert.equal(resolveJsonPath(doc, "a..b").found, false);
  });
});

// ---------------------------------------------------------------------------
// Mechanical predicates — happy + sad for every kind
// ---------------------------------------------------------------------------

describe("mechanical checks", () => {
  const json = JSON.stringify({ findings: [{ id: "F1" }], score: 42, note: "fine" });

  test("content-includes", () => {
    assert.equal(check({ check: "content-includes", needle: "F1" }, json).pass, true);
    assert.equal(check({ check: "content-includes", needle: "F9" }, json).pass, false);
  });

  test("regex-match, including invalid patterns failing gracefully", () => {
    assert.equal(check({ check: "regex-match", pattern: "^\\{" }, json).pass, true);
    assert.equal(check({ check: "regex-match", pattern: "F1", flags: "i" }, "f1 here").pass, true);
    assert.equal(check({ check: "regex-match", pattern: "^nope" }, json).pass, false);
    const invalid = check({ check: "regex-match", pattern: "(" }, json);
    assert.equal(invalid.pass, false);
    assert.match(invalid.reason, /invalid regex/);
  });

  test("min-length / max-length, boundaries inclusive", () => {
    assert.equal(check({ check: "min-length", minChars: 5 }, "12345").pass, true);
    assert.equal(check({ check: "min-length", minChars: 6 }, "12345").pass, false);
    assert.equal(check({ check: "max-length", maxChars: 5 }, "12345").pass, true);
    assert.equal(check({ check: "max-length", maxChars: 4 }, "12345").pass, false);
  });

  test("sha256-equals, case-insensitive expected", () => {
    const digest = sha256Hex("payload");
    assert.equal(check({ check: "sha256-equals", expected: digest }, "payload").pass, true);
    assert.equal(check({ check: "sha256-equals", expected: digest.toUpperCase() }, "payload").pass, true);
    assert.equal(check({ check: "sha256-equals", expected: digest }, "payload!").pass, false);
  });

  test("json-parses", () => {
    assert.equal(check({ check: "json-parses" }, json).pass, true);
    assert.equal(check({ check: "json-parses" }, "{nope").pass, false);
  });

  test("json-path-exists: present (even null), missing, non-JSON content", () => {
    assert.equal(check({ check: "json-path-exists", path: "findings.0.id" }, json).pass, true);
    assert.equal(check({ check: "json-path-exists", path: "x" }, JSON.stringify({ x: null })).pass, true);
    assert.equal(check({ check: "json-path-exists", path: "findings.5" }, json).pass, false);
    assert.equal(check({ check: "json-path-exists", path: "a" }, "not json").pass, false);
  });

  test("numeric-threshold: all operators, boundary, non-numeric, missing path", () => {
    for (const [op, value, pass] of [
      [">=", 42, true],
      [">=", 43, false],
      [">", 41, true],
      [">", 42, false],
      ["<=", 42, true],
      ["<=", 41, false],
      ["<", 43, true],
      ["<", 42, false],
      ["==", 42, true],
      ["==", 41, false],
    ] as const) {
      assert.equal(check({ check: "numeric-threshold", path: "score", op, value }, json).pass, pass, `${op} ${value}`);
    }
    assert.equal(check({ check: "numeric-threshold", path: "findings.length", op: ">=", value: 1 }, json).pass, true);
    assert.equal(check({ check: "numeric-threshold", path: "note", op: ">=", value: 1 }, json).pass, false); // string, not number
    assert.equal(check({ check: "numeric-threshold", path: "nope", op: ">=", value: 1 }, json).pass, false);
    assert.equal(check({ check: "numeric-threshold", path: "score", op: ">=", value: 1 }, "not json").pass, false);
  });

  test("custom-predicate: pass, fail, unregistered name, throwing predicate", () => {
    const predicates = {
      yes: () => ({ pass: true, detail: "fine" }),
      no: () => ({ pass: false, detail: "nope" }),
      boom: () => {
        throw new Error("kapow");
      },
    };
    assert.equal(check({ check: "custom-predicate", name: "yes" }, json, predicates).pass, true);
    assert.deepEqual(check({ check: "custom-predicate", name: "no" }, json, predicates), { pass: false, reason: "nope" });
    const missing = check({ check: "custom-predicate", name: "ghost" }, json, predicates);
    assert.equal(missing.pass, false);
    assert.match(missing.reason, /no predicate registered/);
    const threw = check({ check: "custom-predicate", name: "boom" }, json, predicates);
    assert.equal(threw.pass, false);
    assert.match(threw.reason, /kapow/);
  });
});

// ---------------------------------------------------------------------------
// Aggregation math + verdict logic
// ---------------------------------------------------------------------------

const result = (weight: number, score: number | null): CriterionResult => ({
  criterionId: `c${weight}-${score}`,
  kind: "mechanical",
  weight,
  scored: score !== null,
  score,
  reason: "",
});

describe("weighted aggregation", () => {
  test("weighted mean over scored criteria", () => {
    const agg = aggregateScores([result(1, 100), result(3, 0), result(1, 100), result(1, 100)]);
    assert.deepEqual(agg, { aggregate: 50, totalWeight: 6, scoredWeight: 6 });
  });

  test("unscored criteria are excluded from the mean but counted in totalWeight", () => {
    const agg = aggregateScores([result(2, 90), result(8, null)]);
    assert.deepEqual(agg, { aggregate: 90, totalWeight: 10, scoredWeight: 2 });
  });

  test("nothing scored -> aggregate null", () => {
    assert.equal(aggregateScores([result(5, null)]).aggregate, null);
  });

  test("rounds to 2dp", () => {
    const agg = aggregateScores([result(1, 100), result(2, 0)]);
    assert.equal(agg.aggregate, 33.33);
  });
});

describe("verdict logic", () => {
  const rubric = (acceptThreshold: number, indeterminateBand?: number): Rubric => ({
    acceptThreshold,
    indeterminateBand,
    criteria: [mech("x", 1, PASS)],
  });
  const agg = (aggregate: number | null, totalWeight: number, scoredWeight: number) => ({ aggregate, totalWeight, scoredWeight });

  test("band 0 (default): aggregate == threshold accepts, just below rejects", () => {
    assert.equal(decideVerdict(agg(70, 1, 1), rubric(70)), "accept");
    assert.equal(decideVerdict(agg(69.99, 1, 1), rubric(70)), "reject");
    assert.equal(decideVerdict(agg(100, 1, 1), rubric(70)), "accept");
  });

  test("indeterminate band is inclusive on both edges, decisive just outside", () => {
    const r = rubric(70, 5);
    assert.equal(decideVerdict(agg(75, 1, 1), r), "indeterminate"); // threshold + band
    assert.equal(decideVerdict(agg(65, 1, 1), r), "indeterminate"); // threshold - band
    assert.equal(decideVerdict(agg(70, 1, 1), r), "indeterminate");
    assert.equal(decideVerdict(agg(75.01, 1, 1), r), "accept");
    assert.equal(decideVerdict(agg(64.99, 1, 1), r), "reject");
  });

  test(">50% unscored weight -> indeterminate; exactly 50% still decides", () => {
    assert.equal(decideVerdict(agg(100, 10, 4.9), rubric(70)), "indeterminate");
    assert.equal(decideVerdict(agg(100, 10, 5), rubric(70)), "accept");
    assert.equal(decideVerdict(agg(0, 10, 5), rubric(70)), "reject");
  });

  test("nothing scored -> indeterminate regardless of threshold", () => {
    assert.equal(decideVerdict(agg(null, 10, 0), rubric(0)), "indeterminate");
  });
});

describe("rubric validation", () => {
  test("rejects empty criteria, dup ids, non-positive weights, bad threshold/band", () => {
    assert.throws(() => validateRubric({ acceptThreshold: 50, criteria: [] }), /no criteria/);
    assert.throws(() => validateRubric({ acceptThreshold: 50, criteria: [mech("a", 1, PASS), mech("a", 1, PASS)] }), /duplicate/);
    assert.throws(() => validateRubric({ acceptThreshold: 50, criteria: [mech("a", 0, PASS)] }), /non-positive weight/);
    assert.throws(() => validateRubric({ acceptThreshold: 101, criteria: [mech("a", 1, PASS)] }), /outside 0-100/);
    assert.throws(() => validateRubric({ acceptThreshold: 50, indeterminateBand: -1, criteria: [mech("a", 1, PASS)] }), /must be >= 0/);
    validateRubric({ acceptThreshold: 50, criteria: [mech("a", 1, PASS)] }); // sane rubric passes
  });
});

// ---------------------------------------------------------------------------
// End-to-end evaluation: LLM fallback + mode
// ---------------------------------------------------------------------------

describe("evaluation pipeline", () => {
  const mixed: Rubric = {
    acceptThreshold: 60,
    criteria: [mech("m1", 3, PASS), subj("s1", 7)],
  };

  test("LLM disabled: subjective unscored, excluded from aggregate, mode rubric-only", async () => {
    const ruling = await evaluate(mixed, "content", { useLlm: false });
    const s1 = ruling.perCriterion.find((r) => r.criterionId === "s1")!;
    assert.equal(s1.scored, false);
    assert.equal(s1.score, null);
    assert.match(s1.reason, /disabled/);
    assert.equal(ruling.aggregate, 100); // m1 only
    assert.equal(ruling.mode, "rubric-only");
    assert.equal(ruling.verdict, "indeterminate"); // 7 of 10 weight unscored
  });

  test("LLM enabled but judge fails entirely: same fallback, reason says unavailable", async () => {
    const ruling = await evaluate(mixed, "content", { useLlm: true, judge: fixedJudge(undefined) });
    const s1 = ruling.perCriterion.find((r) => r.criterionId === "s1")!;
    assert.equal(s1.scored, false);
    assert.match(s1.reason, /unavailable/);
    assert.equal(ruling.mode, "rubric-only");
    assert.equal(ruling.verdict, "indeterminate");
  });

  test("judge scores flow into the weighted aggregate and mode full", async () => {
    const ruling = await evaluate(mixed, "content", { useLlm: true, judge: fixedJudge({ s1: 80 }) });
    assert.equal(ruling.mode, "full");
    assert.equal(ruling.aggregate, 86); // (100*3 + 80*7) / 10
    assert.equal(ruling.verdict, "accept");
  });

  test("partially-scored subjective set still flags rubric-only", async () => {
    const rubric: Rubric = { acceptThreshold: 10, criteria: [mech("m1", 6, PASS), subj("s1", 2), subj("s2", 2)] };
    const ruling = await evaluate(rubric, "content", { useLlm: true, judge: fixedJudge({ s1: 50 }) });
    assert.equal(ruling.mode, "rubric-only");
    assert.equal(ruling.perCriterion.find((r) => r.criterionId === "s2")!.scored, false);
    assert.equal(ruling.aggregate, 87.5); // (100*6 + 50*2) / 8
    assert.equal(ruling.verdict, "accept"); // only 2 of 10 unscored
  });

  test("all-mechanical rubric is mode full and judge is never called", async () => {
    let called = 0;
    const spy: JudgeFn = async () => {
      called += 1;
      return new Map();
    };
    const ruling = await evaluate({ acceptThreshold: 50, criteria: [mech("m1", 1, PASS), mech("m2", 1, FAIL)] }, "x", {
      useLlm: true,
      judge: spy,
    });
    assert.equal(called, 0);
    assert.equal(ruling.mode, "full");
    assert.equal(ruling.aggregate, 50);
    assert.equal(ruling.verdict, "accept");
  });
});

// ---------------------------------------------------------------------------
// Judge output parsing (defensive)
// ---------------------------------------------------------------------------

describe("parseJudgeOutput", () => {
  const ids = ["a", "b"];

  test("plain JSON array parses; scores clamp and round; unknown ids dropped", () => {
    const map = parseJudgeOutput(
      '[{"id":"a","score":150,"reason":"r"},{"id":"b","score":33.4,"reason":"r"},{"id":"zz","score":10,"reason":"r"}]',
      ids,
    )!;
    assert.equal(map.get("a")!.score, 100);
    assert.equal(map.get("b")!.score, 33);
    assert.equal(map.has("zz"), false);
  });

  test("tolerates fences and surrounding prose", () => {
    const raw = 'Here you go:\n```json\n[{"id":"a","score":70,"reason":"solid"}]\n```\nDone.';
    assert.equal(parseJudgeOutput(raw, ids)!.get("a")!.score, 70);
  });

  test("garbage, non-arrays, non-numeric scores -> undefined", () => {
    assert.equal(parseJudgeOutput("total nonsense", ids), undefined);
    assert.equal(parseJudgeOutput('{"id":"a","score":50}', ids), undefined);
    assert.equal(parseJudgeOutput('[{"id":"a","score":"high"}]', ids), undefined);
    assert.equal(parseJudgeOutput("[]", ids), undefined);
  });
});

// ---------------------------------------------------------------------------
// Ruling hash + signature
// ---------------------------------------------------------------------------

describe("ruling signing and verification", () => {
  const RUBRIC: Rubric = { acceptThreshold: 50, criteria: [mech("m1", 1, PASS)] };

  test("a fresh ruling verifies; hash covers the canonical body", async () => {
    const ruling = await evaluate(RUBRIC, "hello");
    assert.deepEqual(verifyRuling(ruling), { valid: true });
    const { rulingHash, signature, ...unsigned } = ruling;
    assert.equal(rulingHash, computeRulingHash(unsigned));
    assert.equal(typeof signature, "string");
  });

  test("canonical JSON is key-order independent", () => {
    assert.equal(canonicalJson({ b: 1, a: [{ y: 2, x: 3 }] }), canonicalJson({ a: [{ x: 3, y: 2 }], b: 1 }));
  });

  test("tampering any field fails verification", async () => {
    const ruling = await evaluate(RUBRIC, "hello");
    const clone = (): EvaluationRuling => JSON.parse(JSON.stringify(ruling));

    const verdictFlip = clone();
    verdictFlip.verdict = "reject";
    assert.equal(verifyRuling(verdictFlip).valid, false);

    const scoreEdit = clone();
    scoreEdit.perCriterion[0]!.score = 0;
    assert.equal(verifyRuling(scoreEdit).valid, false);

    const sigForge = clone();
    sigForge.signature = Buffer.alloc(64).toString("base64");
    const verdict = verifyRuling(sigForge);
    assert.equal(verdict.valid, false);
    assert.match(verdict.reason!, /signature/);

    // A re-hashed tamper (attacker recomputes rulingHash) still fails the signature.
    const rehashed = clone();
    rehashed.verdict = "reject";
    const { rulingHash: _h, signature: _s, ...unsigned } = rehashed;
    rehashed.rulingHash = computeRulingHash(unsigned);
    const rehashVerdict = verifyRuling(rehashed);
    assert.equal(rehashVerdict.valid, false);
    assert.match(rehashVerdict.reason!, /signature/);
  });

  test("verification against a third-party-supplied key catches signer substitution", async () => {
    const ruling = await evaluate(RUBRIC, "hello");
    const stranger = new RulingSigner();
    assert.equal(verifyRuling(ruling, stranger.publicKeyB64).valid, false);
    assert.equal(verifyRuling(ruling, ruling.evaluatorPublicKey).valid, true);
  });
});

// ---------------------------------------------------------------------------
// Internal consistency — a VALIDLY SIGNED ruling whose verdict/aggregate/mode
// don't follow from its own scores must still be rejected (no fail-open on a
// signature that only proves authenticity, not soundness).
// ---------------------------------------------------------------------------

describe("ruling internal consistency", () => {
  const signer = new RulingSigner();
  const scored = (id: string, weight: number, score: number | null, kind: "mechanical" | "subjective" = "mechanical"): CriterionResult => ({
    criterionId: id,
    kind,
    weight,
    scored: score !== null,
    score,
    reason: "",
  });

  /** Freshly SIGN an arbitrary (possibly-inconsistent) ruling body. Hash + sig are valid. */
  const sign = (over: Partial<UnsignedRuling>): EvaluationRuling =>
    signRuling(
      {
        jobId: "job-x",
        evaluatorDid: signer.did,
        evaluatorPublicKey: signer.publicKeyB64,
        verdict: "accept",
        aggregate: 100,
        perCriterion: [scored("m1", 1, 100)],
        mode: "full",
        issuedAt: NOW.toISOString(),
        ...over,
      },
      signer,
    );

  test("a self-consistent signed ruling verifies", () => {
    assert.deepEqual(verifyRuling(sign({})), { valid: true });
  });

  test("aggregate that doesn't match the weighted mean is rejected", () => {
    const r = sign({ aggregate: 50 }); // scores mean 100
    const v = verifyRuling(r);
    assert.equal(v.valid, false);
    assert.match(v.reason!, /aggregate .* does not match/);
  });

  test("score out of 0-100 is rejected", () => {
    const r = sign({ perCriterion: [scored("m1", 1, 150)], aggregate: 150 });
    const v = verifyRuling(r);
    assert.equal(v.valid, false);
    assert.match(v.reason!, /not in 0-100/);
  });

  test("unscored criterion carrying a non-null score is rejected", () => {
    const bad: CriterionResult = { criterionId: "s1", kind: "subjective", weight: 1, scored: false, score: 42, reason: "" };
    const r = sign({ perCriterion: [scored("m1", 1, 100), bad], aggregate: 100, mode: "rubric-only" });
    const v = verifyRuling(r);
    assert.equal(v.valid, false);
    assert.match(v.reason!, /unscored but carries score/);
  });

  test("mode inconsistent with an unscored subjective criterion is rejected", () => {
    // subjective unscored, but mode claims "full"
    const r = sign({
      perCriterion: [scored("m1", 1, 100), scored("s1", 1, null, "subjective")],
      aggregate: 100,
      mode: "full",
      verdict: "accept",
    });
    const v = verifyRuling(r);
    assert.equal(v.valid, false);
    assert.match(v.reason!, /mode "full" does not match/);
  });

  test("accept/reject verdict when a majority of weight is unscored is rejected (rubric-free)", () => {
    const r = sign({
      perCriterion: [scored("m1", 1, 100), scored("s1", 3, null, "subjective")],
      aggregate: 100,
      mode: "rubric-only",
      verdict: "accept", // 3 of 4 weight unscored ⇒ must be indeterminate
    });
    const v = verifyRuling(r);
    assert.equal(v.valid, false);
    assert.match(v.reason!, /must be indeterminate/);
  });

  test("verdict that contradicts the aggregate under the rubric is caught only WITH the rubric", () => {
    // aggregate 100, rubric threshold 60 ⇒ true verdict is accept; ruling lies "reject".
    const r = sign({ verdict: "reject" });
    const rubric: Rubric = { acceptThreshold: 60, criteria: [mech("m1", 1, PASS)] };
    // Rubric-free checks can't see the accept/reject boundary, so this passes...
    assert.equal(verifyRuling(r).valid, true);
    // ...but re-deriving against the posted rubric catches it.
    const v = verifyRuling(r, undefined, rubric);
    assert.equal(v.valid, false);
    assert.match(v.reason!, /does not follow from aggregate/);
  });

  test("a genuine ruling re-derives cleanly against its own rubric", async () => {
    const rubric: Rubric = { acceptThreshold: 50, criteria: [mech("m1", 1, PASS)] };
    const ruling = await evaluate(rubric, "hello");
    assert.deepEqual(verifyRuling(ruling, undefined, rubric), { valid: true });
  });
});

// ---------------------------------------------------------------------------
// Ledger
// ---------------------------------------------------------------------------

describe("ruling ledger", () => {
  const RUBRIC_PASS: Rubric = { acceptThreshold: 50, criteria: [mech("m1", 1, PASS)] };
  const RUBRIC_FAIL: Rubric = { acceptThreshold: 50, criteria: [mech("m1", 1, FAIL)] };
  const RUBRIC_UNSCORED: Rubric = { acceptThreshold: 50, criteria: [subj("s1", 1)] };

  async function withLedger(fn: (path: string, rulings: EvaluationRuling[]) => Promise<void>): Promise<void> {
    const dir = await mkdtemp(join(tmpdir(), "evalbot-ledger-test-"));
    try {
      const path = join(dir, "ledger.jsonl");
      const bot = new EvalBot({ now: () => NOW, useLlm: false });
      const rulings = [];
      for (const [i, rubric] of [RUBRIC_PASS, RUBRIC_FAIL, RUBRIC_UNSCORED, RUBRIC_PASS].entries()) {
        rulings.push(await bot.evaluate({ jobId: `job-${i + 1}`, rubric, deliverable: { content: "x" } }));
      }
      for (const r of rulings) await appendRuling(path, r);
      await fn(path, rulings);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }

  test("appends chain from genesis and verifies end to end", async () => {
    await withLedger(async (path) => {
      const entries = await readLedger(path);
      assert.deepEqual(entries.map((e) => e.seq), [1, 2, 3, 4]);
      assert.equal(entries[0]!.prevHash, GENESIS_HASH);
      assert.equal(entries[1]!.prevHash, entries[0]!.entryHash);
      const verdict = await verifyLedger(path);
      assert.deepEqual(verdict, { valid: true, entries: 4, problems: [] });
    });
  });

  test("verifyLedger of a missing file is a valid empty chain", async () => {
    const verdict = await verifyLedger(join(tmpdir(), "evalbot-nonexistent", "ledger.jsonl"));
    assert.deepEqual(verdict, { valid: true, entries: 0, problems: [] });
  });

  test("broken chain (edited prevHash) is detected", async () => {
    await withLedger(async (path) => {
      const entries = await readLedger(path);
      entries[2]!.prevHash = "ff".repeat(32);
      await writeFile(path, entries.map((e) => JSON.stringify(e)).join("\n") + "\n", "utf8");
      const verdict = await verifyLedger(path);
      assert.equal(verdict.valid, false);
      assert.ok(verdict.problems.some((p) => /entry 3 .*prevHash breaks the chain/.test(p)));
      assert.ok(verdict.problems.some((p) => /entry 3 .*entryHash does not match/.test(p)));
    });
  });

  test("mid-file ruling tamper is detected even when the tamperer recomputes hashes", async () => {
    await withLedger(async (path) => {
      const entries = await readLedger(path);
      // Naive tamper: edit the ruling, keep hashes -> entryHash mismatch.
      const naive = structuredClone(entries) as LedgerEntry[];
      naive[1]!.ruling.verdict = "accept";
      await writeFile(path, naive.map((e) => JSON.stringify(e)).join("\n") + "\n", "utf8");
      let verdict = await verifyLedger(path);
      assert.equal(verdict.valid, false);
      assert.ok(verdict.problems.some((p) => /entry 2 .*entryHash does not match/.test(p)));

      // Sophisticated tamper: recompute entryHash too -> the NEXT entry's
      // prevHash breaks, and the ruling's own hash+signature still fail.
      const sneaky = structuredClone(entries) as LedgerEntry[];
      sneaky[1]!.ruling.verdict = "accept";
      sneaky[1]!.entryHash = sha256Hex(canonicalJson({ seq: sneaky[1]!.seq, prevHash: sneaky[1]!.prevHash, ruling: sneaky[1]!.ruling }));
      await writeFile(path, sneaky.map((e) => JSON.stringify(e)).join("\n") + "\n", "utf8");
      verdict = await verifyLedger(path);
      assert.equal(verdict.valid, false);
      assert.ok(verdict.problems.some((p) => /entry 3 .*prevHash breaks the chain/.test(p)));
      assert.ok(verdict.problems.some((p) => /entry 2 .*ruling invalid/.test(p)));
    });
  });

  test("corrupt JSON line fails verification instead of throwing", async () => {
    await withLedger(async (path) => {
      const raw = await readFile(path, "utf8");
      await writeFile(path, raw + "{not json\n", "utf8");
      const verdict = await verifyLedger(path);
      assert.equal(verdict.valid, false);
      assert.ok(verdict.problems.some((p) => /not valid JSON/.test(p)));
    });
  });

  test("reputation summary: counts, acceptance rate over decided rulings, issue times", async () => {
    await withLedger(async (path) => {
      const rep = await summarizeReputation(path);
      assert.equal(rep.totalRulings, 4);
      assert.deepEqual(rep.byVerdict, { accept: 2, reject: 1, indeterminate: 1 });
      assert.equal(rep.acceptanceRate, 2 / 3); // indeterminate excluded
      assert.equal(rep.firstIssuedAt, NOW.toISOString());
      assert.equal(rep.lastIssuedAt, NOW.toISOString());
    });
  });

  test("empty ledger reputation is all zeros with null rate/times", async () => {
    const rep = await summarizeReputation(join(tmpdir(), "evalbot-nonexistent", "ledger.jsonl"));
    assert.deepEqual(rep, {
      totalRulings: 0,
      byVerdict: { accept: 0, reject: 0, indeterminate: 0 },
      acceptanceRate: null,
      firstIssuedAt: null,
      lastIssuedAt: null,
    });
  });
});
