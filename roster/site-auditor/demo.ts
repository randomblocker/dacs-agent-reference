/**
 * Site-Reliability Auditor demo — REAL audits of https://example.com and
 * https://www.cloudflare.com (3 timing samples each: live fetch timing, live
 * node:tls certificate inspection, live security-header + hygiene reads),
 * then a before/after re-audit of example.com with a provable delta.
 *
 *   npm run roster:sitecheck
 *
 * Degradation policy: any single measurement failing (blocked probe, TLS
 * hiccup) prints a warning and degrades the affected category — never a
 * hard failure. Each site gets a ~20s overall guard. Since both runs are
 * real back-to-back probes, the before/after deltas will be small/noisy;
 * the point is the provable delta machinery, not a synthetic improvement.
 * Exit is non-zero ONLY when verifyAudit/verifyDelta fails (our bug, not
 * the internet's) or when ALL checks for BOTH sites failed.
 */
import { MockDahrAttestor } from "../oracle-desk/attested-fetch.js";
import { withTimeout } from "../shared/attest-primitives.js";
import { SiteAuditor } from "./auditor.js";
import { compareAudits, evaluatePayOnImprovement, renderDeltaMarkdown, verifyDelta, verifyPayOnImprovement } from "./compare.js";
import { RealProber } from "./prober.js";
import { auditOutDir, verifyAudit, writeAuditReport } from "./report.js";
import type { ImprovementTarget, SiteAuditReport } from "./types.js";
import { join } from "node:path";
import { writeFile } from "node:fs/promises";

const hr = (title: string) => console.log(`\n=== ${title} ${"=".repeat(Math.max(0, 60 - title.length))}`);
const roundTrip = (r: SiteAuditReport): unknown => JSON.parse(JSON.stringify(r));

const TARGETS = ["https://example.com/", "https://www.cloudflare.com/"];
const SITE_GUARD_MS = 20_000;

const auditor = new SiteAuditor(new RealProber(), new MockDahrAttestor());

let verifyFailures = 0;

function allChecksFailed(report: SiteAuditReport | null): boolean {
  return report === null || report.categories.every((c) => c.degraded);
}

function printReport(report: SiteAuditReport): void {
  console.log(`  category scores (overall ${report.overallScore}/100):`);
  for (const c of report.categories) {
    if (c.degraded) {
      console.warn(`    ${c.category.padEnd(12)} — DEGRADED: ${c.degradedReason ?? "measurement missing"}`);
    } else {
      console.log(`    ${c.category.padEnd(12)} ${String(c.score).padStart(5)}/100`);
    }
  }
  const perf = report.categories.find((c) => c.category === "performance");
  if (perf?.metrics) {
    const m = perf.metrics;
    console.log("  timing (ms):        p50      p95      min      max");
    console.log(`    total       ${fmt(m.p50TotalMs)} ${fmt(m.p95TotalMs)} ${fmt(m.minTotalMs)} ${fmt(m.maxTotalMs)}`);
    console.log(`    ttfb        ${fmt(m.p50TtfbMs)} ${fmt(m.p95TtfbMs)} ${fmt(m.minTtfbMs)} ${fmt(m.maxTtfbMs)}`);
  }
  for (const c of report.categories) {
    for (const check of c.checks) {
      console.log(`    ${check.id.padEnd(38)} ${String(check.score).padStart(5)}  ${check.citations.map((id) => `[${id}]`).join("")} ${short(check.detail)}`);
    }
  }
  for (const g of report.provenance.gaps) {
    console.warn(`    WARNING: ${g.kind} measurement failed — ${g.reason}`);
  }
}

const fmt = (n: number | undefined) => String(n ?? "—").padStart(8);
const short = (s: string, max = 80) => (s.length > max ? `${s.slice(0, max)}…` : s);

async function auditOnce(url: string, label: string): Promise<SiteAuditReport | null> {
  hr(label);
  try {
    const report = await withTimeout(auditor.audit({ url, samples: 3 }), SITE_GUARD_MS, `audit(${url})`);
    printReport(report);

    const emitted = await writeAuditReport(report);
    console.log(`  emitted: ${emitted.jsonPath}`);
    console.log(`           ${emitted.mdPath}`);

    // Third-party stance: verify the JSON round-trip, not the in-memory object.
    const verdict = verifyAudit(roundTrip(report));
    if (verdict.valid) {
      console.log(`  verifyAudit: VALID — ${verdict.attestationsChecked} attestation(s) re-verified, ${verdict.checksChecked} check citation(s) resolved, all scores re-derived from evidence`);
    } else {
      verifyFailures += 1;
      console.error(`  verifyAudit: INVALID`);
      for (const p of verdict.problems) console.error(`    - ${p}`);
    }
    return report;
  } catch (err) {
    console.warn(`  WARNING: audit failed entirely (${(err as Error).message}) — continuing.`);
    return null;
  }
}

// ---------------------------------------------------------------------------
// 1. Real audits
// ---------------------------------------------------------------------------

const reports: Array<SiteAuditReport | null> = [];
for (const target of TARGETS) {
  reports.push(await auditOnce(target, `Audit ${target}`));
}

// ---------------------------------------------------------------------------
// 2. Before/after: re-audit example.com and compare (real runs, so the
//    deltas are small/noisy — the provable-delta machinery is the point)
// ---------------------------------------------------------------------------

const baseline = reports[0];
if (baseline !== null) {
  const current = await auditOnce(TARGETS[0], `Re-audit ${TARGETS[0]} (the "after" run)`);
  if (current !== null) {
    hr("Before/after delta");
    const delta = compareAudits(baseline, current);
    console.log(`  overall: ${delta.overall.verdict} (${delta.overall.scoreDelta >= 0 ? "+" : ""}${delta.overall.scoreDelta} points, ${delta.baseline.overallScore} → ${delta.current.overallScore})`);
    for (const c of delta.categories) {
      const metrics = c.metricDeltas
        .filter((m) => m.metric.startsWith("p"))
        .map((m) => `${m.metric} ${m.delta >= 0 ? "+" : ""}${m.delta}`)
        .join(", ");
      console.log(`    ${c.category.padEnd(12)} ${c.verdict.padEnd(10)} Δ${c.scoreDelta >= 0 ? "+" : ""}${c.scoreDelta}${metrics ? `  (${metrics})` : ""}`);
    }

    const deltaPath = join(auditOutDir(current), "delta.md");
    await writeFile(deltaPath, renderDeltaMarkdown(delta), "utf8");
    console.log(`  emitted: ${deltaPath}`);

    const dv = verifyDelta(JSON.parse(JSON.stringify(delta)), roundTrip(baseline), roundTrip(current));
    if (dv.valid) {
      console.log("  verifyDelta: VALID — both reports re-verified end to end, delta reproduced exactly");
    } else {
      verifyFailures += 1;
      console.error("  verifyDelta: INVALID");
      for (const p of dv.problems) console.error(`    - ${p}`);
    }

    // ---- Pay-on-improvement: the contract a buyer settles against ----------
    // The two runs are real back-to-back probes, so the delta is small/noisy —
    // pick a deliberately modest target so the SETTLEMENT machinery is what the
    // demo exercises (not a staged win). The buyer would pay iff `met` AND the
    // outcome re-verifies from the two reports' own attestations.
    hr("Pay-on-improvement settlement");
    const target: ImprovementTarget = { kind: "overall-score-gain", minGain: 1 };
    const outcome = evaluatePayOnImprovement(delta, target);
    console.log(`  target: overall score +${target.minGain}`);
    console.log(`  outcome: ${outcome.met ? "MET — buyer pays" : "NOT MET — buyer does not pay"} (${outcome.detail})`);
    const pv = verifyPayOnImprovement(JSON.parse(JSON.stringify(outcome)), target, roundTrip(baseline), roundTrip(current));
    if (pv.valid) {
      console.log(`  verifyPayOnImprovement: VALID — outcome (met=${pv.met}) re-derived from the two attested reports; a doctored delta could not fake it`);
    } else {
      verifyFailures += 1;
      console.error("  verifyPayOnImprovement: INVALID");
      for (const p of pv.problems) console.error(`    - ${p}`);
    }
  } else {
    console.warn("  WARNING: re-audit failed — skipping the before/after comparison.");
  }
} else {
  console.warn("\nWARNING: baseline audit of example.com failed — skipping the before/after comparison.");
}

// ---------------------------------------------------------------------------
// Exit policy
// ---------------------------------------------------------------------------

hr("Summary");
const bothDead = allChecksFailed(reports[0]) && allChecksFailed(reports[1]);
if (verifyFailures > 0) {
  console.error(`${verifyFailures} verification failure(s) — that is OUR bug, not the internet's. Exiting non-zero.`);
  process.exit(1);
}
if (bothDead) {
  console.error("ALL checks failed for BOTH sites — nothing was measurable. Exiting non-zero.");
  process.exit(1);
}
console.log("Done: audits attested + verified; before/after delta reproduced from evidence. Exit 0.");
