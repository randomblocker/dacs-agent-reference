/**
 * DD Researcher demo — runs a REAL due diligence on npm package "express"
 * and crypto token "bitcoin" (CoinGecko), writes report.json + report.md
 * under roster/dd-researcher/out/, then re-verifies both reports from the
 * emitted JSON like a third party would.
 *
 *   npm run roster:dd            # deterministic summary (reproducible)
 *   DD_USE_LLM=1 npm run roster:dd   # `claude -p` summary when available
 *
 * A flaky/rate-limited upstream (GitHub unauthenticated 403s are routine)
 * prints a warning and degrades the report; a verifyReport failure is a
 * hard failure (exit 1) — that's OUR bug, not the internet's.
 */
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { RealAttestedFetch } from "../oracle-desk/attested-fetch.js";
import { DDResearcher } from "./researcher.js";
import { verifyReport, writeReport } from "./report.js";
import type { Subject } from "./types.js";
import { SEVERITY_ORDER, subjectLabel, subjectSlug } from "./types.js";

const hr = (title: string) => console.log(`\n=== ${title} ${"=".repeat(Math.max(0, 60 - title.length))}`);

const OUT_BASE = join(dirname(fileURLToPath(import.meta.url)), "out");
const STAMP = new Date().toISOString().replace(/[:.]/g, "-");

const subjects: Subject[] = [
  { kind: "npm-package", name: "express" },
  { kind: "crypto-token", id: "bitcoin" },
];

const researcher = new DDResearcher(new RealAttestedFetch(), {
  useLlm: process.env.DD_USE_LLM === "1",
});

let verifyFailures = 0;
let upstreamWarnings = 0;

for (const subject of subjects) {
  hr(subjectLabel(subject));
  const report = await researcher.research(subject);

  console.log("  evidence:");
  for (const e of report.evidence) {
    console.log(`    ${e.id.padEnd(3)} ${e.source.padEnd(15)} HTTP ${e.status} ${e.ok ? "ok" : "UNAVAILABLE"}  ${e.url}`);
    if (!e.ok) upstreamWarnings += 1;
  }
  for (const gap of report.gaps) {
    console.warn(`    --  ${gap.source.padEnd(15)} UNREACHABLE (${gap.reason})  ${gap.url}`);
    console.warn("        WARNING: source unreachable — report degraded, continuing.");
    upstreamWarnings += 1;
  }

  const counts = SEVERITY_ORDER.map((s) => `${report.findings.filter((f) => f.severity === s).length} ${s}`).join(", ");
  console.log(`  findings: ${report.findings.length} (${counts})`);
  for (const f of report.findings.filter((f) => f.severity !== "info")) {
    console.log(`    [${f.severity}] ${f.title}  ${f.citations.map((c) => `[${c}]`).join("")}`);
  }
  console.log(`  summary (${report.summary.method}): ${report.summary.text.slice(0, 160)}…`);

  const outDir = join(OUT_BASE, `${subjectSlug(subject)}-${STAMP}`);
  const emitted = await writeReport(report, outDir);
  console.log(`  wrote ${emitted.jsonPath}`);
  console.log(`  wrote ${emitted.mdPath}`);

  // Third-party check: re-verify from the emitted JSON, not the in-memory object.
  const verdict = verifyReport(JSON.parse(await readFile(emitted.jsonPath, "utf8")));
  if (verdict.valid) {
    console.log(
      `  verifyReport: OK — ${verdict.evidenceChecked} attestation(s) re-verified, ${verdict.findingsChecked} finding(s) with resolvable citations`,
    );
  } else {
    verifyFailures += 1;
    console.error("  verifyReport: FAILED");
    for (const p of verdict.problems) console.error(`    - ${p}`);
  }
}

hr("Done");
console.log(`  subjects=${subjects.length}  upstreamWarnings=${upstreamWarnings}  verifyFailures=${verifyFailures}`);

if (verifyFailures > 0) {
  console.error("Report verification failed — that is a local bug, failing the demo.");
  process.exit(1);
}
