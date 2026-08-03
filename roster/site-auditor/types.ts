/**
 * Site-Reliability Auditor — types and ports.
 *
 * The auditor is a service-side agent CORE: given a live site URL it runs
 * performance / TLS / security-header / transport-hygiene checks with node
 * builtins only, scores each category 0-100, and delivers a SiteAuditReport
 * where EVERY number traces back to an attested measurement.
 *
 * All measurement I/O sits behind a ProberPort (real fetch/node:tls adapter
 * + canned fake for offline tests). Probe results are not HTTP bodies, so —
 * exactly like lead-enrich did for DNS answers — each measurement is wrapped
 * in the shared MOCK-DAHR attestation record shape: the "body" is the
 * canonical JSON of the measurement, signed under a `probe:` pseudo-URL, so
 * oracle-desk's `verifyAttestedRecord` verifies it identically to an HTTP
 * fetch. Checks carry citation-by-construction (non-empty citation tuple,
 * throwing constructor), `verifyAudit` re-derives every category score from
 * the attested measurement bodies, and `compareAudits` turns two verified
 * reports into a provable before/after delta — the pay-on-improvement
 * surface. No DACS lifecycle wiring.
 */
import type { MockDahrAttestation } from "../oracle-desk/types.js";

export type { MockDahrAttestation } from "../oracle-desk/types.js";

// ---------------------------------------------------------------------------
// Audit input
// ---------------------------------------------------------------------------

export interface AuditInput {
  /** Target URL, http(s) only, e.g. "https://example.com/". */
  url: string;
  /** Timing samples to take (1..10). Default 3. */
  samples?: number;
  /** Per-probe timeout. Default 8000. */
  timeoutMs?: number;
}

// ---------------------------------------------------------------------------
// Prober port — every network measurement goes through here
// ---------------------------------------------------------------------------

/** One timed HTTP probe with manual redirect following (cap 5). */
export interface ProbeResult {
  /** URL as requested. */
  url: string;
  /** URL of the final (non-redirect) response. */
  finalUrl: string;
  /** Status of the final response. */
  status: number;
  /** Time to first byte of the final response body, ms. */
  ttfbMs: number;
  /** Total time until the body was fully read, ms. */
  totalMs: number;
  /** Bytes of the (decoded) final response body. */
  bodyBytes: number;
  redirectCount: number;
  /** Every URL visited, starting with the requested one. */
  redirectChain: string[];
  /** Final response headers, lowercase keys. */
  headers: Record<string, string>;
  fetchedAt: string;
}

/** TLS certificate + negotiated-protocol inspection of host:443. */
export interface TlsInfo {
  host: string;
  /** Certificate notAfter, ISO-8601. */
  validTo: string;
  /** Whole days until expiry at inspection time (negative = expired). */
  daysRemaining: number;
  issuer: string;
  /** Negotiated protocol, e.g. "TLSv1.3". */
  protocol: string;
  checkedAt: string;
}

export interface ProberPort {
  /** Timed fetch with manual redirect following. Throws on network failure/timeout. */
  probe(url: string, timeoutMs: number): Promise<ProbeResult>;
  /** Inspect the TLS certificate presented on host:443. Throws on failure. */
  tlsInspect(host: string, timeoutMs: number): Promise<TlsInfo>;
}

// ---------------------------------------------------------------------------
// Attested measurements — the evidence layer
// ---------------------------------------------------------------------------

export type MeasurementKind = "timing-sample" | "tls" | "http-redirect";

/**
 * One attested measurement. `body` is the canonical JSON of the raw
 * measurement (ProbeResult or TlsInfo), `url` a `probe:` pseudo-URL, and the
 * attestation signature covers url|fetchedAt|bodyHash — the same record
 * shape lead-enrich used for DNS, verifiable by oracle-desk's
 * `verifyAttestedRecord`.
 */
export interface MeasurementEvidence {
  /** "A1", "A2", … — what check citations point at. */
  id: string;
  kind: MeasurementKind;
  /** Pseudo-URL, e.g. "probe:timing:https://example.com/#2". */
  url: string;
  fetchedAt: string;
  /** Canonical JSON of the measurement. */
  body: string;
  /** sha256 hex of `body`. */
  bodyHash: string;
  attestation: MockDahrAttestation;
}

/** A measurement that could not be taken at all (nothing to attest). */
export interface MeasurementGap {
  kind: MeasurementKind;
  /** The pseudo-URL the measurement WOULD have carried. */
  target: string;
  reason: string;
}

// ---------------------------------------------------------------------------
// Checks — citation by construction
// ---------------------------------------------------------------------------

/** Non-empty citation list — the type-level half of the no-uncited-score ban. */
export type Citations = [string, ...string[]];

export interface CheckResult {
  /** "perf.p95-total", "headers.content-security-policy", … */
  id: string;
  name: string;
  /** 0-100. */
  score: number;
  detail: string;
  citations: Citations;
}

/**
 * The only sanctioned constructor for a check result. Throws on an empty
 * citation list or an out-of-range score — a scored check that cites no
 * attested measurement is unrepresentable by construction.
 */
export function makeCheck(id: string, name: string, score: number, detail: string, citations: readonly string[]): CheckResult {
  if (citations.length === 0) {
    throw new Error(`check ${id}: scored check without a citation is forbidden — every score must cite an attested measurement`);
  }
  if (!Number.isFinite(score) || score < 0 || score > 100) {
    throw new Error(`check ${id}: score ${score} is not in [0, 100]`);
  }
  return { id, name, score, detail, citations: [...citations] as Citations };
}

// ---------------------------------------------------------------------------
// Categories and report
// ---------------------------------------------------------------------------

export type CategoryName = "performance" | "tls" | "headers" | "hygiene";

export interface CategoryResult {
  category: CategoryName;
  /** 0-100. Meaningless (and excluded from the overall) when `degraded`. */
  score: number;
  /** True when the underlying measurement is missing — category excluded from the overall score. */
  degraded: boolean;
  degradedReason?: string;
  checks: CheckResult[];
  /** Aggregates (performance only): p50/p95/min/max of totalMs and ttfbMs. */
  metrics?: Record<string, number>;
}

export interface SiteAuditReport {
  version: 1;
  url: string;
  auditedAt: string;
  /** Timing samples REQUESTED (successful ones are counted in the evidence). */
  samples: number;
  categories: CategoryResult[];
  /** Weighted over non-degraded categories; 0 when everything degraded. */
  overallScore: number;
  provenance: {
    evidence: MeasurementEvidence[];
    gaps: MeasurementGap[];
  };
}

/** Result of the third-party re-verification of a report. */
export interface VerifyAuditResult {
  valid: boolean;
  problems: string[];
  /** How many attestation signatures were re-verified. */
  attestationsChecked: number;
  /** How many checks had their citations resolved. */
  checksChecked: number;
}

// ---------------------------------------------------------------------------
// Before/after deltas — the pay-on-improvement surface
// ---------------------------------------------------------------------------

export type Verdict = "improved" | "regressed" | "unchanged";

export interface MetricDelta {
  metric: string;
  baseline: number;
  current: number;
  /** current - baseline (for *Ms metrics lower is better; for scores higher is better). */
  delta: number;
}

export interface CategoryDelta {
  category: CategoryName;
  baselineScore: number;
  currentScore: number;
  /** current - baseline. */
  scoreDelta: number;
  /** From the score delta sign: higher score = improved. */
  verdict: Verdict;
  degraded: { baseline: boolean; current: boolean };
  /** Deltas over metrics present on BOTH sides (performance p50/p95 etc.). */
  metricDeltas: MetricDelta[];
}

export interface AuditDelta {
  version: 1;
  url: string;
  baseline: { auditedAt: string; overallScore: number };
  current: { auditedAt: string; overallScore: number };
  categories: CategoryDelta[];
  overall: { scoreDelta: number; verdict: Verdict };
}

export interface VerifyDeltaResult {
  valid: boolean;
  problems: string[];
}

// ---------------------------------------------------------------------------
// Pay-on-improvement — the settleable outcome a pay-on-outcome contract pays against
// ---------------------------------------------------------------------------

/**
 * An agreed improvement target — the contract term the buyer and seller settle
 * on. It is a PUBLIC input (it lives in the agreement, not in the attested
 * reports), so `verifyPayOnImprovement` takes it alongside the two attested
 * audits and re-derives whether it was met. Three shapes cover the common
 * pay-on-outcome asks:
 *
 *   - `overall-score-gain`: the weighted overall rose by at least `minGain`.
 *   - `category-score-gain`: one category's score rose by at least `minGain`.
 *   - `metric-drop-pct`: a performance metric (p95TotalMs, …) fell by at least
 *     `minDropPct` percent of its baseline (lower is better for *Ms metrics).
 */
export type ImprovementTarget =
  | { kind: "overall-score-gain"; minGain: number }
  | { kind: "category-score-gain"; category: CategoryName; minGain: number }
  | { kind: "metric-drop-pct"; category: CategoryName; metric: string; minDropPct: number };

/**
 * The settleable artifact: from two attested audits and an agreed target, does
 * the provable delta clear the target? Deterministic and re-derivable — the
 * buyer pays iff `met` is true and `verifyPayOnImprovement` reproduces it from
 * the two reports' own attestations.
 */
export interface PayOnImprovementResult {
  version: 1;
  url: string;
  target: ImprovementTarget;
  /** True iff the attested delta clears the target AND no anti-gaming guard tripped. */
  met: boolean;
  /** The observed quantity the target is compared against (points gained, or % dropped). */
  observed: number;
  /** The threshold the target required (minGain or minDropPct), echoed for the settlement record. */
  required: number;
  /** Human-readable reason — why met, or exactly why not (guard tripped, degraded side, metric absent). */
  detail: string;
}

export interface VerifyPayOnImprovementResult {
  valid: boolean;
  /** The re-derived outcome (meaningful only when `valid`). */
  met: boolean;
  problems: string[];
}
