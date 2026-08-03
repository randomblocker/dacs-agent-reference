/**
 * Scoring rules (exported thresholds) + the pure derivation that turns a
 * pile of attested measurements into category scores.
 *
 * `deriveAssessment` is deliberately shared: the auditor calls it to BUILD
 * the report and `verifyAudit` calls it again on the report's own attested
 * evidence to RE-DERIVE every category — so an edited metric or score is a
 * mismatch against the attestations, not just a plausible-looking number.
 * Everything here is pure (no I/O, no clock); determinism is what makes the
 * re-derivation an equality check.
 */
import type {
  CategoryName,
  CategoryResult,
  CheckResult,
  MeasurementEvidence,
  MeasurementGap,
  ProbeResult,
  TlsInfo,
} from "./types.js";
import { makeCheck } from "./types.js";

/** Round to one decimal — applied to every derived number so JSON round-trips exactly. */
export function r1(x: number): number {
  return Math.round(x * 10) / 10;
}

// ---------------------------------------------------------------------------
// Percentiles (linear interpolation, same convention as numpy's default)
// ---------------------------------------------------------------------------

export function percentile(values: readonly number[], p: number): number {
  if (values.length === 0) throw new Error("percentile of an empty sample set");
  if (p < 0 || p > 100) throw new Error(`percentile ${p} is not in [0, 100]`);
  const sorted = [...values].sort((a, b) => a - b);
  const rank = ((sorted.length - 1) * p) / 100;
  const lo = Math.floor(rank);
  const hi = Math.ceil(rank);
  if (lo === hi) return sorted[lo];
  return sorted[lo] + (rank - lo) * (sorted[hi] - sorted[lo]);
}

// ---------------------------------------------------------------------------
// Thresholds (all exported so buyers can see exactly what a score means)
// ---------------------------------------------------------------------------

/** p95 total response time → score: first row whose maxMs the p95 does not exceed. */
export const PERF_P95_THRESHOLDS: ReadonlyArray<readonly [maxMs: number, score: number]> = [
  [200, 100],
  [500, 85],
  [1000, 70],
  [2000, 50],
  [4000, 25],
];
/** Score when p95 exceeds every threshold. */
export const PERF_FLOOR_SCORE = 10;

export function scorePerformance(p95TotalMs: number): number {
  for (const [maxMs, score] of PERF_P95_THRESHOLDS) {
    if (p95TotalMs <= maxMs) return score;
  }
  return PERF_FLOOR_SCORE;
}

/** Certificate days remaining → score: first row whose minDays the cert still clears. */
export const TLS_DAYS_THRESHOLDS: ReadonlyArray<readonly [minDays: number, score: number]> = [
  [60, 100],
  [30, 80],
  [14, 60],
  [7, 40],
  [1, 20],
];

export function scoreTls(daysRemaining: number): number {
  for (const [minDays, score] of TLS_DAYS_THRESHOLDS) {
    if (daysRemaining >= minDays) return score;
  }
  return 0; // expiring today or already expired
}

/** Security headers checked on the final response; weights sum to 100. */
export const SECURITY_HEADERS: ReadonlyArray<{ header: string; label: string; weight: number }> = [
  { header: "strict-transport-security", label: "HSTS", weight: 30 },
  { header: "content-security-policy", label: "Content-Security-Policy", weight: 30 },
  { header: "x-content-type-options", label: "X-Content-Type-Options", weight: 15 },
  { header: "x-frame-options", label: "X-Frame-Options", weight: 15 },
  { header: "referrer-policy", label: "Referrer-Policy", weight: 10 },
];

/** Weighted present-count over SECURITY_HEADERS, from lowercased header names. */
export function scoreHeaders(presentHeaderNames: readonly string[]): number {
  const present = new Set(presentHeaderNames);
  return SECURITY_HEADERS.reduce((sum, h) => sum + (present.has(h.header) ? h.weight : 0), 0);
}

/** Transport-hygiene sub-check weights (renormalized over applicable parts). */
export const HYGIENE_WEIGHTS = { compression: 40, cacheControl: 20, httpsRedirect: 40 } as const;

export interface HygieneParts {
  compression: boolean;
  cacheControl: boolean;
  /** "n/a" for plain-http targets (nothing to redirect to). */
  httpsRedirect: boolean | "n/a";
}

export function scoreHygiene(parts: HygieneParts): number {
  let earned = 0;
  let applicable = HYGIENE_WEIGHTS.compression + HYGIENE_WEIGHTS.cacheControl;
  if (parts.compression) earned += HYGIENE_WEIGHTS.compression;
  if (parts.cacheControl) earned += HYGIENE_WEIGHTS.cacheControl;
  if (parts.httpsRedirect !== "n/a") {
    applicable += HYGIENE_WEIGHTS.httpsRedirect;
    if (parts.httpsRedirect) earned += HYGIENE_WEIGHTS.httpsRedirect;
  }
  return r1((earned / applicable) * 100);
}

/** Encodings that count as "compression negotiated" (we send accept-encoding: gzip, br). */
export const COMPRESSED_ENCODINGS: ReadonlyArray<string> = ["gzip", "br", "zstd", "deflate"];

export function compressionNegotiated(headers: Record<string, string>): boolean {
  const enc = (headers["content-encoding"] ?? "").toLowerCase();
  return COMPRESSED_ENCODINGS.some((e) => enc.includes(e));
}

/** Did probing the http:// variant land (via redirects) on an https URL? */
export function httpsRedirectAchieved(probe: Pick<ProbeResult, "finalUrl" | "redirectCount">): boolean {
  return probe.redirectCount >= 1 && probe.finalUrl.startsWith("https://");
}

/** Category weights for the overall score (renormalized over non-degraded categories). */
export const CATEGORY_WEIGHTS: Record<CategoryName, number> = {
  performance: 40,
  tls: 20,
  headers: 25,
  hygiene: 15,
};

export const CATEGORY_ORDER: ReadonlyArray<CategoryName> = ["performance", "tls", "headers", "hygiene"];

// ---------------------------------------------------------------------------
// Derivation — measurements in, categories out (shared by build and verify)
// ---------------------------------------------------------------------------

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

interface ParsedTiming {
  id: string;
  probe: ProbeResult;
}

/** Defensive parse of a measurement body; unusable bodies are simply skipped. */
function parseTiming(e: MeasurementEvidence): ParsedTiming | null {
  try {
    const raw: unknown = JSON.parse(e.body);
    if (!isObject(raw)) return null;
    if (typeof raw.status !== "number" || typeof raw.ttfbMs !== "number" || typeof raw.totalMs !== "number") return null;
    if (!isObject(raw.headers)) return null;
    return { id: e.id, probe: raw as unknown as ProbeResult };
  } catch {
    return null;
  }
}

function parseTls(e: MeasurementEvidence): TlsInfo | null {
  try {
    const raw: unknown = JSON.parse(e.body);
    if (!isObject(raw) || typeof raw.daysRemaining !== "number" || typeof raw.validTo !== "string") return null;
    return raw as unknown as TlsInfo;
  } catch {
    return null;
  }
}

function gapReason(gaps: readonly MeasurementGap[], kind: MeasurementGap["kind"]): string | undefined {
  return gaps.find((g) => g.kind === kind)?.reason;
}

export interface Assessment {
  categories: CategoryResult[];
  overallScore: number;
}

/**
 * Turn attested measurements (+ gaps for the reasons of missing ones) into
 * the four category results and the weighted overall score. Pure and
 * deterministic in its inputs — `verifyAudit` calls this again on a report's
 * own evidence and requires exact equality with the report's categories.
 */
export function deriveAssessment(evidence: readonly MeasurementEvidence[], gaps: readonly MeasurementGap[], url: string): Assessment {
  const isHttps = url.startsWith("https://");
  const timing = evidence.filter((e) => e.kind === "timing-sample").map(parseTiming).filter((t): t is ParsedTiming => t !== null);
  const tlsEvidence = evidence.find((e) => e.kind === "tls");
  const tlsInfo = tlsEvidence ? parseTls(tlsEvidence) : null;
  const httpEvidence = evidence.find((e) => e.kind === "http-redirect");
  const httpParsed = httpEvidence ? parseTiming(httpEvidence) : null;
  const timingGapCount = gaps.filter((g) => g.kind === "timing-sample").length;

  // --- performance ---------------------------------------------------------
  let performance: CategoryResult;
  if (timing.length === 0) {
    performance = {
      category: "performance",
      score: 0,
      degraded: true,
      degradedReason: `no usable timing samples (${gapReason(gaps, "timing-sample") ?? "none attempted"})`,
      checks: [],
    };
  } else {
    const totals = timing.map((t) => t.probe.totalMs);
    const ttfbs = timing.map((t) => t.probe.ttfbMs);
    const metrics: Record<string, number> = {
      p50TotalMs: r1(percentile(totals, 50)),
      p95TotalMs: r1(percentile(totals, 95)),
      minTotalMs: r1(Math.min(...totals)),
      maxTotalMs: r1(Math.max(...totals)),
      p50TtfbMs: r1(percentile(ttfbs, 50)),
      p95TtfbMs: r1(percentile(ttfbs, 95)),
      minTtfbMs: r1(Math.min(...ttfbs)),
      maxTtfbMs: r1(Math.max(...ttfbs)),
    };
    const score = scorePerformance(metrics.p95TotalMs);
    const failedNote = timingGapCount > 0 ? `; ${timingGapCount} sample(s) failed and were excluded` : "";
    performance = {
      category: "performance",
      score,
      degraded: false,
      checks: [
        makeCheck(
          "perf.p95-total",
          "p95 total response time",
          score,
          `p95 ${metrics.p95TotalMs}ms across ${timing.length} sample(s) (p50 ${metrics.p50TotalMs}ms, min ${metrics.minTotalMs}ms, max ${metrics.maxTotalMs}ms)${failedNote}`,
          timing.map((t) => t.id),
        ),
      ],
      metrics,
    };
  }

  // --- tls ------------------------------------------------------------------
  let tls: CategoryResult;
  if (!isHttps) {
    tls = { category: "tls", score: 0, degraded: true, degradedReason: "plain-http target — TLS not applicable", checks: [] };
  } else if (!tlsEvidence || !tlsInfo) {
    tls = {
      category: "tls",
      score: 0,
      degraded: true,
      degradedReason: `TLS inspection unavailable (${gapReason(gaps, "tls") ?? "measurement missing"})`,
      checks: [],
    };
  } else {
    const score = scoreTls(tlsInfo.daysRemaining);
    tls = {
      category: "tls",
      score,
      degraded: false,
      checks: [
        makeCheck(
          "tls.certificate",
          "certificate validity window",
          score,
          `expires ${tlsInfo.validTo} (${tlsInfo.daysRemaining} day(s) remaining), issuer "${tlsInfo.issuer}", ${tlsInfo.protocol}`,
          [tlsEvidence.id],
        ),
      ],
    };
  }

  // --- headers (on the final response of the first successful sample) -------
  const headerSource = timing.find((t) => t.probe.status >= 200 && t.probe.status < 400) ?? null;
  let headers: CategoryResult;
  if (headerSource === null) {
    headers = {
      category: "headers",
      score: 0,
      degraded: true,
      degradedReason: "no successful response to inspect headers on",
      checks: [],
    };
  } else {
    const h = headerSource.probe.headers;
    const checks: CheckResult[] = SECURITY_HEADERS.map((spec) => {
      const value = h[spec.header];
      const present = value !== undefined;
      return makeCheck(
        `headers.${spec.header}`,
        spec.label,
        present ? 100 : 0,
        present ? `present: ${value.length > 120 ? `${value.slice(0, 120)}…` : value}` : "absent on the final response",
        [headerSource.id],
      );
    });
    headers = {
      category: "headers",
      score: scoreHeaders(SECURITY_HEADERS.filter((spec) => h[spec.header] !== undefined).map((spec) => spec.header)),
      degraded: false,
      checks,
    };
  }

  // --- hygiene ---------------------------------------------------------------
  const hygieneChecks: CheckResult[] = [];
  const missing: string[] = [];
  let compression = false;
  let cacheControl = false;
  let httpsRedirect: boolean | "n/a" = isHttps ? false : "n/a";
  if (headerSource !== null) {
    const h = headerSource.probe.headers;
    compression = compressionNegotiated(h);
    cacheControl = h["cache-control"] !== undefined;
    hygieneChecks.push(
      makeCheck(
        "hygiene.compression",
        "compression negotiated",
        compression ? 100 : 0,
        compression ? `content-encoding: ${h["content-encoding"]}` : "no compressed content-encoding despite accept-encoding: gzip, br",
        [headerSource.id],
      ),
      makeCheck(
        "hygiene.cache-control",
        "cache-control present",
        cacheControl ? 100 : 0,
        cacheControl ? `cache-control: ${h["cache-control"]}` : "no cache-control header on the final response",
        [headerSource.id],
      ),
    );
  } else {
    missing.push("compression/cache-control unmeasured (no successful response)");
  }
  if (isHttps) {
    if (httpEvidence && httpParsed) {
      httpsRedirect = httpsRedirectAchieved(httpParsed.probe);
      hygieneChecks.push(
        makeCheck(
          "hygiene.https-redirect",
          "http→https redirect",
          httpsRedirect ? 100 : 0,
          httpsRedirect
            ? `http:// variant redirected to ${httpParsed.probe.finalUrl} in ${httpParsed.probe.redirectCount} hop(s)`
            : `http:// variant answered ${httpParsed.probe.status} at ${httpParsed.probe.finalUrl} without reaching https`,
          [httpEvidence.id],
        ),
      );
    } else {
      missing.push(`http→https redirect unmeasured (${gapReason(gaps, "http-redirect") ?? "measurement missing"})`);
    }
  }
  let hygiene: CategoryResult;
  if (hygieneChecks.length === 0) {
    hygiene = { category: "hygiene", score: 0, degraded: true, degradedReason: missing.join("; ") || "no hygiene measurements", checks: [] };
  } else {
    const applicableRedirect = isHttps && httpEvidence && httpParsed ? httpsRedirect : "n/a";
    const score =
      headerSource !== null
        ? scoreHygiene({ compression, cacheControl, httpsRedirect: applicableRedirect })
        : // only the redirect part was measurable
          (applicableRedirect === true ? 100 : 0);
    hygiene = {
      category: "hygiene",
      score,
      degraded: missing.length > 0,
      ...(missing.length > 0 ? { degradedReason: missing.join("; ") } : {}),
      checks: hygieneChecks,
    };
  }

  // --- overall ----------------------------------------------------------------
  const categories = [performance, tls, headers, hygiene];
  const live = categories.filter((c) => !c.degraded);
  const weightSum = live.reduce((sum, c) => sum + CATEGORY_WEIGHTS[c.category], 0);
  const overallScore = weightSum === 0 ? 0 : r1(live.reduce((sum, c) => sum + c.score * CATEGORY_WEIGHTS[c.category], 0) / weightSum);

  return { categories, overallScore };
}
