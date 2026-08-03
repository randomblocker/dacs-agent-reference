/**
 * EvalBot demo — evaluates a REAL sibling-agent artifact: a due-diligence
 * report produced by the dd-researcher core (run in-memory over the oracle
 * desk's FakeAttestedFetch with canned upstream bodies — no network, fully
 * deterministic by default).
 *
 *   npm run roster:eval                # deterministic (no LLM, no network)
 *   EVAL_USE_LLM=1 npm run roster:eval # scores the subjective rubric via `claude -p`
 *
 * Walkthrough: (1) genuine report -> accept; (2) tampered report (citations
 * dropped) -> reject; (3) subjective-heavy rubric without the LLM ->
 * indeterminate, mode rubric-only; (4) all three rulings appended to the
 * hash-chained ledger, then verifyLedger + summarizeReputation; (5) one
 * ruling re-verified with an independent verifyRuling call. Exits non-zero
 * if any expectation fails.
 */
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { FakeAttestedFetch } from "../oracle-desk/attested-fetch.js";
import { DDResearcher } from "../dd-researcher/researcher.js";
import { EvalBot, verifyRuling } from "./evalbot.js";
import { appendRuling, summarizeReputation, verifyLedger } from "./ledger.js";
import type { CustomPredicate, EvaluationRuling, Rubric, Verdict } from "./types.js";

const hr = (title: string) => console.log(`\n=== ${title} ${"=".repeat(Math.max(0, 60 - title.length))}`);
const LEDGER_PATH = join(dirname(fileURLToPath(import.meta.url)), "out", "ledger.jsonl");

let failures = 0;
function expect(label: string, actual: unknown, wanted: unknown): void {
  const ok = actual === wanted;
  if (!ok) failures += 1;
  console.log(`  ${ok ? "ok " : "FAIL"} ${label}: got ${JSON.stringify(actual)}${ok ? "" : ` (wanted ${JSON.stringify(wanted)})`}`);
}

// ---------------------------------------------------------------------------
// 1. Produce a real dd-researcher report (offline, canned upstreams)
// ---------------------------------------------------------------------------

hr("Producing the evaluation target (dd-researcher, offline)");

const REG = JSON.stringify({
  name: "express",
  "dist-tags": { latest: "4.19.2" },
  versions: {
    "4.19.2": { version: "4.19.2", license: "MIT", repository: { type: "git", url: "git+https://github.com/expressjs/express.git" } },
  },
  time: { created: "2010-12-29T19:38:25Z", modified: "2026-05-01T00:00:00Z", "4.19.2": "2026-05-01T00:00:00.000Z" },
  maintainers: [{ name: "a" }, { name: "b" }, { name: "c" }],
  license: "MIT",
});
const DL = JSON.stringify({ downloads: 5_000_000, start: "2026-06-01", end: "2026-06-30", package: "express" });
const GH = JSON.stringify({
  full_name: "expressjs/express",
  stargazers_count: 65_000,
  open_issues_count: 100,
  forks_count: 12_000,
  pushed_at: "2026-06-20T00:00:00Z",
  archived: false,
  license: { spdx_id: "MIT" },
});

const researcher = new DDResearcher(
  new FakeAttestedFetch([
    ["registry.npmjs.org", { status: 200, body: REG }],
    ["api.npmjs.org/downloads", { status: 200, body: DL }],
    ["api.github.com/repos", { status: 200, body: GH }],
  ]),
  { useLlm: false },
);
const report = await researcher.research({ kind: "npm-package", name: "express" });
const reportJson = JSON.stringify(report, null, 2);
console.log(`  report: ${report.findings.length} finding(s), ${report.evidence.length} evidence item(s), ${reportJson.length} chars`);

// ---------------------------------------------------------------------------
// 2. The rubric + custom predicate
// ---------------------------------------------------------------------------

/** Custom mechanical check: EVERY finding must cite at least one evidence id. */
const everyFindingCites: CustomPredicate = (content) => {
  let doc: unknown;
  try {
    doc = JSON.parse(content);
  } catch {
    return { pass: false, detail: "deliverable is not JSON" };
  }
  const findings = (doc as { findings?: unknown }).findings;
  if (!Array.isArray(findings) || findings.length === 0) return { pass: false, detail: "no findings array" };
  for (const f of findings as Array<{ id?: unknown; citations?: unknown }>) {
    if (!Array.isArray(f.citations) || f.citations.length === 0) {
      return { pass: false, detail: `finding ${String(f.id ?? "?")} cites no evidence` };
    }
  }
  return { pass: true, detail: `${findings.length} finding(s), every one cites evidence` };
};

const ddRubric: Rubric = {
  acceptThreshold: 80,
  indeterminateBand: 5,
  criteria: [
    { id: "has-findings", kind: "mechanical", weight: 1, description: "report contains at least one finding", test: { check: "numeric-threshold", path: "findings.length", op: ">=", value: 1 } },
    { id: "all-findings-cited", kind: "mechanical", weight: 3, description: "every finding cites attested evidence", test: { check: "custom-predicate", name: "every-finding-cites" } },
    { id: "summary-substantial", kind: "mechanical", weight: 1, description: "executive summary is at least 120 chars", test: { check: "numeric-threshold", path: "summary.text.length", op: ">=", value: 120 } },
    { id: "evidence-appendix", kind: "mechanical", weight: 1, description: "attested evidence appendix is present", test: { check: "json-path-exists", path: "evidence.0.attestation.digest" } },
  ],
};

const evalbot = new EvalBot({ predicates: { "every-finding-cites": everyFindingCites } });
console.log(`  evaluator: ${evalbot.evaluatorDid}`);

function show(ruling: EvaluationRuling): void {
  console.log(`  verdict=${ruling.verdict}  aggregate=${ruling.aggregate}  mode=${ruling.mode}`);
  for (const r of ruling.perCriterion) {
    console.log(`    ${r.scored ? String(r.score).padStart(3) : "  —"}  w=${r.weight}  ${r.criterionId}: ${r.reason}`);
  }
}

// ---------------------------------------------------------------------------
// 3. Genuine report -> accept
// ---------------------------------------------------------------------------

hr("Ruling 1 — genuine report");
const genuine = await evalbot.evaluate({ jobId: "dd-express-genuine", rubric: ddRubric, deliverable: { content: reportJson } });
show(genuine);
expect("genuine report verdict", genuine.verdict, "accept" satisfies Verdict);

// ---------------------------------------------------------------------------
// 4. Tampered report (citations dropped) -> reject
// ---------------------------------------------------------------------------

hr("Ruling 2 — tampered report (citations dropped from a finding)");
const tampered = JSON.parse(reportJson) as { findings: Array<{ citations?: unknown }> };
delete tampered.findings[0]!.citations;
const tamperedRuling = await evalbot.evaluate({
  jobId: "dd-express-tampered",
  rubric: ddRubric,
  deliverable: { content: JSON.stringify(tampered, null, 2) },
});
show(tamperedRuling);
expect("tampered report verdict", tamperedRuling.verdict, "reject" satisfies Verdict);

// ---------------------------------------------------------------------------
// 5. Subjective-heavy rubric, no LLM -> indeterminate / rubric-only
// ---------------------------------------------------------------------------

hr("Ruling 3 — subjective-heavy rubric");
const proseRubric: Rubric = {
  acceptThreshold: 60,
  criteria: [
    { id: "well-formed", kind: "mechanical", weight: 3, description: "report is valid JSON", test: { check: "json-parses" } },
    { id: "prose-quality", kind: "subjective", weight: 7, description: "executive summary is clear, specific, and decision-ready", guidance: "penalize vagueness and unsupported claims" },
  ],
};
const proseRuling = await evalbot.evaluate({
  jobId: "dd-express-prose",
  rubric: proseRubric,
  deliverable: { content: reportJson },
  context: "Due-diligence report on npm package express, produced by a sibling agent.",
});
show(proseRuling);
if (process.env.EVAL_USE_LLM === "1") {
  console.log("  (EVAL_USE_LLM=1 — subjective scoring attempted; verdict/mode depend on the judge)");
} else {
  expect("subjective-heavy verdict without LLM", proseRuling.verdict, "indeterminate" satisfies Verdict);
  expect("mode without LLM", proseRuling.mode, "rubric-only");
}

// ---------------------------------------------------------------------------
// 6. Ledger: append, verify chain, summarize reputation
// ---------------------------------------------------------------------------

hr("Ledger — EvalBot's portable track record");
for (const ruling of [genuine, tamperedRuling, proseRuling]) {
  const entry = await appendRuling(LEDGER_PATH, ruling);
  console.log(`  appended seq ${entry.seq}  ${ruling.jobId}  verdict=${ruling.verdict}  entryHash=${entry.entryHash.slice(0, 16)}…`);
}
const ledgerVerdict = await verifyLedger(LEDGER_PATH);
expect("verifyLedger valid", ledgerVerdict.valid, true);
for (const p of ledgerVerdict.problems) console.error(`    - ${p}`);
console.log(`  chain verified: ${ledgerVerdict.entries} entr${ledgerVerdict.entries === 1 ? "y" : "ies"} (ledger persists across runs)`);

const rep = await summarizeReputation(LEDGER_PATH);
console.log(
  `  reputation: total=${rep.totalRulings}  accept=${rep.byVerdict.accept}  reject=${rep.byVerdict.reject}  ` +
    `indeterminate=${rep.byVerdict.indeterminate}  acceptanceRate=${rep.acceptanceRate === null ? "n/a" : rep.acceptanceRate.toFixed(2)}`,
);
console.log(`  first=${rep.firstIssuedAt}  last=${rep.lastIssuedAt}`);

// ---------------------------------------------------------------------------
// 7. Independent third-party signature check
// ---------------------------------------------------------------------------

hr("Third-party verification of ruling 1");
const independent = verifyRuling(genuine, genuine.evaluatorPublicKey);
expect("verifyRuling(genuine) valid", independent.valid, true);
if (!independent.valid) console.error(`    reason: ${independent.reason}`);

hr("Done");
console.log(`  expectations failed: ${failures}`);
if (failures > 0) {
  console.error("Demo expectations failed.");
  process.exit(1);
}
