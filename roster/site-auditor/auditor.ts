/**
 * SiteAuditor — the orchestrator. Takes { url, samples?, timeoutMs? }, runs
 * every measurement through the injected ProberPort, wraps each one in a
 * MOCK-DAHR attestation record, and derives the category scores with the
 * same pure `deriveAssessment` that `verifyAudit` later re-runs.
 *
 * Degradation policy: a failed measurement becomes a MeasurementGap (with
 * the reason) and the dependent category degrades — the audit itself only
 * throws when the input is invalid, never because the network misbehaved.
 */
import { MockDahrAttestor } from "../oracle-desk/attested-fetch.js";
import { deriveAssessment } from "./checks.js";
import { attestMeasurement, httpRedirectPseudoUrl, timingPseudoUrl, tlsPseudoUrl } from "./prober.js";
import type { AuditInput, MeasurementEvidence, MeasurementGap, MeasurementKind, ProberPort, SiteAuditReport } from "./types.js";

export const DEFAULT_SAMPLES = 3;
export const MAX_SAMPLES = 10;
export const DEFAULT_TIMEOUT_MS = 8_000;
/** Breathing room between sequential samples so we measure the site, not our own connection reuse burst. */
export const DEFAULT_SAMPLE_GAP_MS = 150;

/** Validate + normalize the target: http(s) only, fragment stripped. */
export function normalizeTargetUrl(input: string): string {
  let u: URL;
  try {
    u = new URL(input.trim());
  } catch {
    throw new Error(`"${input}" is not a valid URL`);
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") {
    throw new Error(`unsupported protocol "${u.protocol}" — only http(s) targets can be audited`);
  }
  u.hash = "";
  return u.toString();
}

export interface SiteAuditorOptions {
  /** Gap between sequential timing samples. Tests pass 0. */
  sampleGapMs?: number;
}

export class SiteAuditor {
  private readonly sampleGapMs: number;

  constructor(
    private readonly prober: ProberPort,
    private readonly attestor: MockDahrAttestor = new MockDahrAttestor(),
    options: SiteAuditorOptions = {},
  ) {
    this.sampleGapMs = options.sampleGapMs ?? DEFAULT_SAMPLE_GAP_MS;
  }

  async audit(input: AuditInput): Promise<SiteAuditReport> {
    const url = normalizeTargetUrl(input.url);
    const samples = input.samples ?? DEFAULT_SAMPLES;
    if (!Number.isInteger(samples) || samples < 1 || samples > MAX_SAMPLES) {
      throw new Error(`samples must be an integer in [1, ${MAX_SAMPLES}], got ${samples}`);
    }
    const timeoutMs = input.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new Error(`timeoutMs must be positive, got ${timeoutMs}`);

    const evidence: MeasurementEvidence[] = [];
    const gaps: MeasurementGap[] = [];
    let nextId = 1;
    const attest = (kind: MeasurementKind, pseudoUrl: string, measurement: unknown): void => {
      evidence.push(attestMeasurement(this.attestor, `A${nextId++}`, kind, pseudoUrl, measurement));
    };

    // 1. Timing samples — sequential with a small gap, each individually attested.
    for (let i = 1; i <= samples; i++) {
      if (i > 1 && this.sampleGapMs > 0) await sleep(this.sampleGapMs);
      const pseudoUrl = timingPseudoUrl(url, i);
      try {
        attest("timing-sample", pseudoUrl, await this.prober.probe(url, timeoutMs));
      } catch (err) {
        gaps.push({ kind: "timing-sample", target: pseudoUrl, reason: (err as Error).message });
      }
    }

    // 2. TLS + http→https redirect — https targets only.
    const target = new URL(url);
    if (target.protocol === "https:") {
      const tlsUrl = tlsPseudoUrl(target.hostname);
      try {
        attest("tls", tlsUrl, await this.prober.tlsInspect(target.hostname, timeoutMs));
      } catch (err) {
        gaps.push({ kind: "tls", target: tlsUrl, reason: (err as Error).message });
      }

      const httpVariant = `http://${target.host}/`;
      const httpUrl = httpRedirectPseudoUrl(httpVariant);
      try {
        attest("http-redirect", httpUrl, await this.prober.probe(httpVariant, timeoutMs));
      } catch (err) {
        gaps.push({ kind: "http-redirect", target: httpUrl, reason: (err as Error).message });
      }
    }

    // 3. Pure derivation — the same function verifyAudit re-runs later.
    const { categories, overallScore } = deriveAssessment(evidence, gaps, url);

    return {
      version: 1,
      url,
      auditedAt: new Date().toISOString(),
      samples,
      categories,
      overallScore,
      provenance: { evidence, gaps },
    };
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
