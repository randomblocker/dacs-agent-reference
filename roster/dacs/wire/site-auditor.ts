/**
 * Wire the site-auditor core into the shared DACS seller layer on the pay-dem
 * session rail (Pattern 2).
 *
 * The auditor sells an attested `SiteAuditReport` (performance / TLS /
 * security-header / transport-hygiene) where every number traces to an
 * attested measurement (registry.ts §8 — LIVE probes; the core throws only on
 * bad input, never on network misbehaviour). Scope is `parameterized` (the URL
 * is conveyed at session-open) ⇒ pay-dem session rail.
 *
 * The report is float-bearing (timings, sub-scores), so it rides `meta` as a
 * JSON string (see report-meta.ts). `observeDelivered` re-runs the core's own
 * `verifyAudit`, re-deriving every category score from the attested
 * measurement bodies offline.
 */
import { SiteAuditor } from "../../site-auditor/auditor.js";
import { verifyAudit } from "../../site-auditor/report.js";
import { MockDahrAttestor } from "../../oracle-desk/attested-fetch.js";
import type { ProberPort, SiteAuditReport } from "../../site-auditor/types.js";
import type { WorkCallback } from "../seller-adapter.js";
import type { DeliveryVerifyOptions } from "../verifier.js";
import { readReportMeta, reportMeta } from "./report-meta.js";
import { formatFeeSchedule, type FeeSchedule } from "./pricing.js";

/** The DACS serviceId under which the site desk sells audit reports. */
export const SITE_SERVICE_ID = "site-audit";
/** The delivery phase advertised (and required by the session terms). */
export const SITE_DELIVERY_PHASE = "deliver-site-audit";
/** The URL is conveyed at session-open ⇒ pay-dem session rail. */
export const SITE_SCOPE = "parameterized" as const;
/** Default probe samples when the buyer names no `samples` (matches the core). */
export const SITE_DEFAULT_SAMPLES = 3;

/**
 * Usage-based pricing: billed per probe sample requested (a 10-sample audit
 * costs proportionally more than a 1-sample one), with a 1 DEM billing floor.
 * Numbers are DISPLAY units (DEM).
 */
export const SITE_FEES: FeeSchedule = { kind: "per-unit", unitPrice: 0.5, unit: "sample", minTotal: 1 };

/** Units for a site-audit job = the number of probe samples requested. */
export function siteAuditorUnitsFor(params: { samples?: number } | undefined): number {
  return params?.samples ?? SITE_DEFAULT_SAMPLES;
}

/** The listing surface the site desk advertises on the pay-dem rail. */
export function siteAuditorListingSpec(price: { amount: string; asset: string }) {
  const fees = SITE_FEES;
  return {
    serviceId: SITE_SERVICE_ID,
    name: "Site-Reliability Auditor - pay-on-improvement, attested before/after",
    description:
      `Attested, re-verifiable before/after measurements of a live site's ` +
      `performance, TLS, and security headers - every score traces to a signed ` +
      `measurement that re-derives offline. The point is not the audit (Lighthouse ` +
      `is free): it is that the attested delta settles a PAY-ON-IMPROVEMENT ` +
      `contract - you pay only if a target (e.g. overall +N, or p95 down X%) is ` +
      `provably met, third-party-checkable from the two audits' own attestations. ` +
      `Fee: ${formatFeeSchedule(fees, price.asset)}.`,
    supportedNegotiation: ["negotiate-fixed-price"],
    supportedPaymentRails: ["pay-dem"],
    supportedDelivery: [SITE_DELIVERY_PHASE],
    /** Structured usage-based fee (read by the in-process Butler; NOT anchored). */
    fees,
  };
}

/**
 * Build the site-auditor work callback over an injected ProberPort (real
 * fetch/TLS probes, or a FakeProber for tests/offline). The buyer conveys
 * `{ url, samples? }`; the audit report is the deliverable.
 */
export function makeSiteAuditorWork(
  prober: ProberPort,
  attestor: MockDahrAttestor = new MockDahrAttestor(),
): WorkCallback {
  const auditor = new SiteAuditor(prober, attestor, { sampleGapMs: 0 });
  return async (_jobId, params) => {
    const url = String(params.url ?? "");
    if (!url) throw new Error("site-audit: params.url is required");
    const samples = params.samples !== undefined ? Number(params.samples) : undefined;

    const report = await auditor.audit({ url, ...(samples !== undefined ? { samples } : {}) });
    const meta = reportMeta(report);

    return {
      // overallScore is a float ⇒ round for the JCS-safe resultHash digest.
      result: {
        url: report.url,
        overallScore: Math.round(report.overallScore),
        categories: report.categories.length,
        evidence: report.provenance.evidence.length,
      },
      deliverableRef: `site-audit:report:${meta.reportHash}`,
      meta,
    };
  };
}

/**
 * `observeDelivered`: re-run the core's `verifyAudit` over the delivered report
 * offline (attestation signatures re-verified, category scores re-derived).
 */
export function siteAuditorObserveDelivered(): DeliveryVerifyOptions["observeDelivered"] {
  return async (att) => {
    const read = readReportMeta<SiteAuditReport>(att);
    if (!read.ok) return { ok: false, reason: read.reason };
    const verdict = verifyAudit(read.artifact);
    return verdict.valid
      ? { ok: true }
      : { ok: false, reason: `audit verification failed: ${verdict.problems.join("; ")}` };
  };
}
