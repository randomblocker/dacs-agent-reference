/**
 * Before/after comparison — the pay-on-improvement surface.
 *
 * `compareAudits(baseline, current)` is a pure, deterministic function of
 * the two reports: per-category score deltas + verdicts, per-metric deltas
 * (p50/p95 etc.), and an overall verdict. Because BOTH sides carry their own
 * attested measurements, the delta is provable: `verifyDelta` re-verifies
 * both reports end to end (attestations + re-derived scores) and then
 * recomputes the comparison, requiring exact equality with the presented
 * delta — a doctored verdict or delta number cannot survive it.
 */
import { canonicalJson } from "../shared/attest-primitives.js";
import { CATEGORY_ORDER, r1 } from "./checks.js";
import { verifyAudit } from "./report.js";
import type {
  AuditDelta,
  CategoryDelta,
  ImprovementTarget,
  MetricDelta,
  PayOnImprovementResult,
  SiteAuditReport,
  Verdict,
  VerifyDeltaResult,
  VerifyPayOnImprovementResult,
} from "./types.js";

function verdictOf(scoreDelta: number): Verdict {
  if (scoreDelta > 0) return "improved";
  if (scoreDelta < 0) return "regressed";
  return "unchanged";
}

export function compareAudits(baseline: SiteAuditReport, current: SiteAuditReport): AuditDelta {
  if (baseline.url !== current.url) {
    throw new Error(`cannot compare audits of different targets: ${baseline.url} vs ${current.url}`);
  }

  const categories: CategoryDelta[] = CATEGORY_ORDER.map((name) => {
    const base = baseline.categories.find((c) => c.category === name);
    const cur = current.categories.find((c) => c.category === name);
    if (!base || !cur) throw new Error(`category ${name} missing from one of the reports`);

    const metricDeltas: MetricDelta[] = [];
    if (base.metrics && cur.metrics) {
      for (const metric of Object.keys(base.metrics).sort()) {
        const b = base.metrics[metric];
        const c = cur.metrics[metric];
        if (typeof b === "number" && typeof c === "number") {
          metricDeltas.push({ metric, baseline: b, current: c, delta: r1(c - b) });
        }
      }
    }

    const scoreDelta = r1(cur.score - base.score);
    return {
      category: name,
      baselineScore: base.score,
      currentScore: cur.score,
      scoreDelta,
      verdict: verdictOf(scoreDelta),
      degraded: { baseline: base.degraded, current: cur.degraded },
      metricDeltas,
    };
  });

  const overallDelta = r1(current.overallScore - baseline.overallScore);
  return {
    version: 1,
    url: baseline.url,
    baseline: { auditedAt: baseline.auditedAt, overallScore: baseline.overallScore },
    current: { auditedAt: current.auditedAt, overallScore: current.overallScore },
    categories,
    overall: { scoreDelta: overallDelta, verdict: verdictOf(overallDelta) },
  };
}

// ---------------------------------------------------------------------------
// Markdown rendering
// ---------------------------------------------------------------------------

const VERDICT_MARK: Record<Verdict, string> = { improved: "▲ improved", regressed: "▼ regressed", unchanged: "= unchanged" };

export function renderDeltaMarkdown(delta: AuditDelta): string {
  const lines: string[] = [];
  lines.push(`# Before/after delta — ${delta.url}`);
  lines.push("");
  lines.push(`- Baseline: ${delta.baseline.auditedAt} (overall ${delta.baseline.overallScore}/100)`);
  lines.push(`- Current: ${delta.current.auditedAt} (overall ${delta.current.overallScore}/100)`);
  lines.push(`- Overall: **${VERDICT_MARK[delta.overall.verdict]}** (${fmtDelta(delta.overall.scoreDelta)} points)`);
  lines.push("");
  lines.push("## Category verdicts");
  lines.push("");
  lines.push("| Category | Before | After | Δ score | Verdict |");
  lines.push("|---|---|---|---|---|");
  for (const c of delta.categories) {
    const flag = c.degraded.baseline || c.degraded.current ? " (degraded side)" : "";
    lines.push(`| ${c.category} | ${c.baselineScore} | ${c.currentScore} | ${fmtDelta(c.scoreDelta)} | ${VERDICT_MARK[c.verdict]}${flag} |`);
  }

  const perf = delta.categories.find((c) => c.metricDeltas.length > 0);
  if (perf) {
    lines.push("");
    lines.push(`## ${perf.category} metric deltas (lower is better for *Ms metrics)`);
    lines.push("");
    lines.push("| Metric | Before | After | Δ |");
    lines.push("|---|---|---|---|");
    for (const m of perf.metricDeltas) {
      lines.push(`| ${m.metric} | ${m.baseline} | ${m.current} | ${fmtDelta(m.delta)} |`);
    }
  }

  lines.push("");
  lines.push("Both sides of this delta carry their own MOCK-DAHR-attested measurements;");
  lines.push("`verifyDelta(delta, baseline, current)` re-verifies both reports and recomputes this comparison.");
  lines.push("");
  return lines.join("\n");
}

function fmtDelta(d: number): string {
  return d > 0 ? `+${d}` : `${d}`;
}

// ---------------------------------------------------------------------------
// Third-party verification
// ---------------------------------------------------------------------------

/**
 * Verify a delta against the two reports it claims to summarize: both
 * reports must fully verify (attestations, citations, re-derived scores),
 * and recomputing `compareAudits` on them must reproduce the delta exactly.
 */
export function verifyDelta(deltaJson: unknown, baselineJson: unknown, currentJson: unknown): VerifyDeltaResult {
  const problems: string[] = [];

  const baseVerdict = verifyAudit(baselineJson);
  if (!baseVerdict.valid) problems.push(...baseVerdict.problems.map((p) => `baseline report: ${p}`));
  const curVerdict = verifyAudit(currentJson);
  if (!curVerdict.valid) problems.push(...curVerdict.problems.map((p) => `current report: ${p}`));

  if (typeof deltaJson !== "object" || deltaJson === null || Array.isArray(deltaJson)) {
    problems.push("delta is not a JSON object");
    return { valid: false, problems };
  }

  if (problems.length === 0) {
    // Reports verified — safe to treat them as SiteAuditReport-shaped.
    const baseline = baselineJson as SiteAuditReport;
    const current = currentJson as SiteAuditReport;
    try {
      const recomputed = compareAudits(baseline, current);
      if (canonicalJson(deltaJson) !== canonicalJson(recomputed)) {
        problems.push("delta does not match a recomputation from the two verified reports (doctored delta?)");
      }
    } catch (err) {
      problems.push(`recomputing the delta failed: ${(err as Error).message}`);
    }
  }

  return { valid: problems.length === 0, problems };
}

// ---------------------------------------------------------------------------
// Pay-on-improvement — settle a pay-on-outcome contract against the attested delta
// ---------------------------------------------------------------------------

/**
 * Evaluate a pay-on-improvement target against a computed delta. Pure and
 * deterministic — `verifyPayOnImprovement` re-runs it on a delta recomputed
 * from the two verified reports and requires exact equality, so a doctored
 * delta cannot fake meeting the target.
 *
 * Anti-gaming: a degraded category is EXCLUDED from the renormalized overall,
 * so a seller could otherwise inflate the "after" overall by dropping a
 * low-scoring category. `overall-score-gain` therefore is NOT met if any
 * category that was measured (non-degraded) in the baseline is degraded in the
 * current run — you cannot claim overall improvement on a shrunk measurement
 * set. Category/metric targets require both sides measured for that dimension.
 */
export function evaluatePayOnImprovement(delta: AuditDelta, target: ImprovementTarget): PayOnImprovementResult {
  const base = (met: boolean, observed: number, required: number, detail: string): PayOnImprovementResult => ({
    version: 1,
    url: delta.url,
    target,
    met,
    observed: r1(observed),
    required,
    detail,
  });

  if (target.kind === "overall-score-gain") {
    const dropped = delta.categories.filter((c) => !c.degraded.baseline && c.degraded.current).map((c) => c.category);
    const observed = delta.overall.scoreDelta;
    if (dropped.length > 0) {
      return base(
        false,
        observed,
        target.minGain,
        `overall gain not creditable: category ${dropped.join(", ")} was measured in the baseline but degraded (excluded) in the current run — cannot claim overall improvement on a shrunk measurement set`,
      );
    }
    const met = observed >= target.minGain;
    return base(
      met,
      observed,
      target.minGain,
      met
        ? `overall rose ${fmtDelta(observed)} points (${delta.baseline.overallScore} -> ${delta.current.overallScore}), target +${target.minGain}`
        : `overall moved ${fmtDelta(observed)} points, short of the required +${target.minGain}`,
    );
  }

  if (target.kind === "category-score-gain") {
    const c = delta.categories.find((x) => x.category === target.category);
    if (!c) return base(false, 0, target.minGain, `category ${target.category} not present in the delta`);
    if (c.degraded.baseline || c.degraded.current) {
      const side = c.degraded.baseline && c.degraded.current ? "both runs" : c.degraded.current ? "the current run" : "the baseline";
      return base(false, c.scoreDelta, target.minGain, `category ${target.category} is degraded in ${side} — not comparable`);
    }
    const met = c.scoreDelta >= target.minGain;
    return base(
      met,
      c.scoreDelta,
      target.minGain,
      met
        ? `${target.category} rose ${fmtDelta(c.scoreDelta)} points (${c.baselineScore} -> ${c.currentScore}), target +${target.minGain}`
        : `${target.category} moved ${fmtDelta(c.scoreDelta)} points, short of the required +${target.minGain}`,
    );
  }

  // metric-drop-pct: a *Ms metric fell by at least minDropPct percent of baseline.
  const c = delta.categories.find((x) => x.category === target.category);
  const md = c?.metricDeltas.find((m) => m.metric === target.metric);
  if (!c || !md) {
    return base(false, 0, target.minDropPct, `metric ${target.category}.${target.metric} not present on both sides of the delta`);
  }
  if (md.baseline <= 0) {
    return base(false, 0, target.minDropPct, `baseline ${target.metric} is ${md.baseline} — cannot express a percentage drop`);
  }
  const dropPct = ((md.baseline - md.current) / md.baseline) * 100;
  const met = dropPct >= target.minDropPct;
  return base(
    met,
    dropPct,
    target.minDropPct,
    met
      ? `${target.metric} dropped ${r1(dropPct)}% (${md.baseline} -> ${md.current}ms), target -${target.minDropPct}%`
      : `${target.metric} changed ${r1(dropPct)}% (${md.baseline} -> ${md.current}ms), short of the required -${target.minDropPct}% drop`,
  );
}

/**
 * Verify a pay-on-improvement result against the target and the two attested
 * reports it settles. Both reports must fully verify (attestations + re-derived
 * scores), the delta is recomputed from them, and the outcome is re-derived
 * from that delta and required to match the presented result exactly. A
 * tampered report fails verification; a doctored delta or a fudged `met`
 * cannot survive the recomputation.
 */
export function verifyPayOnImprovement(
  claimedResult: unknown,
  target: ImprovementTarget,
  baselineJson: unknown,
  currentJson: unknown,
): VerifyPayOnImprovementResult {
  const problems: string[] = [];

  const baseVerdict = verifyAudit(baselineJson);
  if (!baseVerdict.valid) problems.push(...baseVerdict.problems.map((p) => `baseline report: ${p}`));
  const curVerdict = verifyAudit(currentJson);
  if (!curVerdict.valid) problems.push(...curVerdict.problems.map((p) => `current report: ${p}`));

  if (typeof claimedResult !== "object" || claimedResult === null || Array.isArray(claimedResult)) {
    problems.push("pay-on-improvement result is not a JSON object");
    return { valid: false, met: false, problems };
  }

  if (problems.length > 0) return { valid: false, met: false, problems };

  // Reports verified — safe to treat them as SiteAuditReport-shaped.
  const baseline = baselineJson as SiteAuditReport;
  const current = currentJson as SiteAuditReport;
  try {
    const recomputed = evaluatePayOnImprovement(compareAudits(baseline, current), target);
    if (canonicalJson(claimedResult) !== canonicalJson(recomputed)) {
      problems.push("pay-on-improvement result does not match a recomputation from the two verified reports (doctored result or mismatched target?)");
      return { valid: false, met: false, problems };
    }
    return { valid: true, met: recomputed.met, problems };
  } catch (err) {
    problems.push(`recomputing the pay-on-improvement outcome failed: ${(err as Error).message}`);
    return { valid: false, met: false, problems };
  }
}
