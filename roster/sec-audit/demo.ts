/**
 * Security-Audit Agent demo:
 *
 *   npm run roster:secaudit
 *
 *  1. Audits the bundled intentionally-vulnerable fixture and ASSERTS that
 *     every expected rule fired and the inline `audit-ok` suppression was
 *     honored + counted. Dependency advisories come from the REAL npm bulk
 *     advisory endpoint when reachable (fallback: dep-upgrade's canned
 *     registry — the banner states which mode ran).
 *  2. Audits a REAL clean-ish target — this repo's src/ directory — and
 *     prints whatever it finds (no assertions on counts).
 *  3. Emits report.json + report.md, re-verifies the report from disk
 *     INCLUDING the re-hash drift check against the fixture, then tampers
 *     one finding in memory and shows verifyReport catching it.
 *
 * Optional: SEC_USE_LLM=1 (with the `claude` CLI on PATH) adds a segregated
 * llm-suggested candidate section. Default OFF; deterministic findings
 * never depend on it. Exit 0 only if all expectations hold.
 */
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { RealRegistry, lodashFallbackRegistry } from "../dep-upgrade/registry.js";
import type { RegistryPort } from "../dep-upgrade/types.js";
import { runAudit } from "./auditor.js";
import { maybeClaudeCliPass } from "./llm-pass.js";
import { verifyReport, writeReport } from "./report.js";
import type { SecAuditReport } from "./types.js";
import { SEVERITY_ORDER } from "./types.js";

const hr = (title: string) => console.log(`\n=== ${title} ${"=".repeat(Math.max(0, 60 - title.length))}`);
const here = dirname(fileURLToPath(import.meta.url));
const fixtureDir = join(here, "fixture");
const srcDir = join(here, "..", "..", "src");

let failures = 0;
function expect(what: string, ok: boolean): void {
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${what}`);
  if (!ok) failures += 1;
}

function printFindings(report: SecAuditReport, max = 50): void {
  for (const severity of SEVERITY_ORDER) {
    for (const f of report.findings.filter((x) => x.severity === severity).slice(0, max)) {
      console.log(`  [${f.severity.padEnd(8)}] ${f.ruleId.padEnd(28)} ${f.file}:${f.line}  ${f.excerpt.slice(0, 72)}`);
    }
  }
  for (const f of report.llmFindings) {
    console.log(`  [llm:${f.severity}] ${f.ruleId} ${f.file}:${f.line}  ${f.rationale.slice(0, 80)}`);
  }
}

// ---------------------------------------------------------------------------
// Registry mode: probe the REAL bulk advisory endpoint first.
// ---------------------------------------------------------------------------
let registry: RegistryPort;
let registryLabel: "live" | "canned";
try {
  const real = new RealRegistry(10_000);
  const probe = await real.getAdvisories({ lodash: ["4.17.20"] });
  if ((probe.get("lodash") ?? []).length === 0) {
    throw new Error("advisory endpoint answered but returned no lodash advisories — treating as unusable");
  }
  registry = real;
  registryLabel = "live";
} catch (err) {
  console.warn(`WARNING: live advisory endpoint unreachable/unusable (${(err as Error).message})`);
  console.warn("Falling back to dep-upgrade's canned registry so the demo still completes.");
  registry = lodashFallbackRegistry();
  registryLabel = "canned";
}

const llm = maybeClaudeCliPass(process.env);

hr("Security-Audit Agent");
console.log(`  advisory data   ${registryLabel === "live" ? "REAL (live npm bulk advisory endpoint)" : "FALLBACK (canned fake registry)"}`);
console.log(`  LLM pass        ${llm ? "ON (SEC_USE_LLM=1, claude CLI found) — segregated candidates only" : "OFF (default; set SEC_USE_LLM=1 with the claude CLI on PATH)"}`);

// ---------------------------------------------------------------------------
// 1. Fixture audit — every expected rule must fire, suppression honored.
// ---------------------------------------------------------------------------
hr("1. Fixture audit (intentionally vulnerable)");
const fixtureReport = await runAudit({ targetDir: fixtureDir, mode: "auto" }, { registry, registryLabel, llm });
printFindings(fixtureReport);

const EXPECTED_RULES = [
  // repo checks (app.js)
  "secret-aws-key",
  "code-eval",
  "code-exec-interpolation",
  "crypto-math-random-token",
  "code-http-url",
  "tls-verification-disabled",
  // solidity heuristics (Vault.sol)
  "sol-floating-pragma",
  "sol-tx-origin",
  "sol-missing-access-control",
  "sol-reentrancy",
  "sol-unchecked-call",
  "sol-selfdestruct",
  // dependency advisories (package.json → lodash 4.17.20)
  "dep-vulnerable",
];

console.log("");
for (const ruleId of EXPECTED_RULES) {
  const stat = fixtureReport.ruleStats.find((r) => r.id === ruleId);
  expect(`rule ${ruleId} fired`, (stat?.count ?? 0) >= 1);
}
expect(
  "suppression honored + counted (code-http-url via inline audit-ok)",
  fixtureReport.suppressions.length === 1 && fixtureReport.suppressions[0].ruleId === "code-http-url",
);
const suppressedLine = fixtureReport.suppressions[0]?.line;
expect(
  "suppressed line produced no finding",
  suppressedLine !== undefined &&
    !fixtureReport.findings.some((f) => f.file === "app.js" && f.line === suppressedLine && f.ruleId === "code-http-url"),
);
expect(
  "every finding cites an attested file record",
  [...fixtureReport.findings, ...fixtureReport.llmFindings].every(
    (f) => f.citations.length > 0 && f.citations.every((c) => fixtureReport.files.some((r) => r.id === c)),
  ),
);
expect(`deps audit ran in ${registryLabel} mode`, fixtureReport.deps.mode === registryLabel);
expect("scanned-file manifest covers the fixture", fixtureReport.files.length === 4);

// ---------------------------------------------------------------------------
// 2. Real clean-ish target: this repo's src/ — print, don't assert counts.
// ---------------------------------------------------------------------------
hr("2. Real target audit — this repo's src/");
const srcReport = await runAudit({ targetDir: srcDir, mode: "repo" }, { registry, registryLabel });
console.log(`  files scanned: ${srcReport.files.length}; deterministic findings: ${srcReport.findings.length}; suppressions: ${srcReport.suppressions.length}`);
console.log(`  deps audit: ${srcReport.deps.mode} — ${srcReport.deps.note}`);
if (srcReport.findings.length > 0) printFindings(srcReport, 20);
else console.log("  (no findings)");

// ---------------------------------------------------------------------------
// 3. Emit + verify (with re-hash drift check), then tamper.
// ---------------------------------------------------------------------------
hr("3. Emit + verify + tamper");
const stamp = new Date().toISOString().replace(/[:.]/g, "-");
const outDir = join(here, "out", `fixture-${stamp}`);
const emitted = await writeReport(fixtureReport, outDir);
console.log(`  wrote ${emitted.jsonPath}`);
console.log(`  wrote ${emitted.mdPath}`);

const fromDisk = JSON.parse(await readFile(emitted.jsonPath, "utf8")) as unknown;
const verdict = await verifyReport(fromDisk, fixtureDir);
console.log(
  `  verify: valid=${verdict.valid} attestations=${verdict.attestationsChecked} findings=${verdict.findingsChecked} rehashed=${verdict.filesRehashed} drift=${verdict.driftedFiles.length}`,
);
for (const p of verdict.problems) console.log(`    problem: ${p}`);
expect("report verifies from disk (attestations + citations + seal)", verdict.valid);
expect("re-hash drift check ran over every manifest file", verdict.filesRehashed === fixtureReport.files.length);
expect("no drift: report matches the exact fixture content on disk", verdict.driftedFiles.length === 0);

// Tamper one finding in memory: soften a severity — the seal must catch it.
const tampered = JSON.parse(JSON.stringify(fromDisk)) as { findings: Array<{ severity: string; rationale: string }> };
tampered.findings[0].severity = "info";
tampered.findings[0].rationale = "nothing to see here";
const tamperedVerdict = await verifyReport(tampered);
expect("tampered finding caught by verifyReport", !tamperedVerdict.valid);
console.log(`  tamper problems: ${tamperedVerdict.problems.join(" | ")}`);

// ---------------------------------------------------------------------------
hr("Result");
if (failures === 0) {
  console.log("  all expectations hold — exit 0");
} else {
  console.error(`  ${failures} expectation(s) FAILED — exit 1`);
  process.exitCode = 1;
}
