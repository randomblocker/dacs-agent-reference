/**
 * Wire the compliance core into the shared DACS seller layer on the pay-dem
 * session rail (Pattern 2).
 *
 * The compliance desk sells an attested `ScreeningReport` against OFAC SDN +
 * UN consolidated + SEC EDGAR, where every match cites the attested list
 * downloads it was found on and every screened source records the list
 * versions it was screened against — provable absence (registry.ts §10, LIVE +
 * cache; read-only). Scope is `parameterized` (the subject is conveyed at
 * session-open) ⇒ pay-dem session rail.
 *
 * `observeDelivered` re-runs the core's own `verifyScreening` over the
 * delivered report offline — re-verifying every list-download attestation and
 * every match's citations from the anchor alone.
 */
import { loadAll, screenSubject } from "../../compliance/screener.js";
import { verifyScreening } from "../../compliance/report.js";
import type { ListSourcePort, ScreeningReport, ScreeningSubject, SubjectKind } from "../../compliance/types.js";
import { SOURCE_IDS } from "../../compliance/types.js";
import type { WorkCallback } from "../seller-adapter.js";
import type { DeliveryVerifyOptions } from "../verifier.js";
import { readReportMeta, reportMeta } from "./report-meta.js";
import { formatFee, fixedFeeFromPrice } from "./pricing.js";

/** The DACS serviceId under which the compliance desk sells screenings. */
export const COMPLIANCE_SERVICE_ID = "compliance-screening";
/** The delivery phase advertised (and required by the session terms). */
export const COMPLIANCE_DELIVERY_PHASE = "deliver-screening-report";
/** The subject is conveyed at session-open ⇒ pay-dem session rail. */
export const COMPLIANCE_SCOPE = "parameterized" as const;

/** The listing surface the compliance desk advertises on the pay-dem rail. */
export function complianceListingSpec(price: { amount: string; asset: string }) {
  return {
    serviceId: COMPLIANCE_SERVICE_ID,
    name: "Compliance Desk - regulator-grade sanctions, PEP & registry screening",
    description:
      `Screens a name, entity, or wallet against OFAC SDN, UN, EU, and UK OFSI ` +
      `sanctions lists, an OpenSanctions PEP dataset (aggregator), and the SEC ` +
      `EDGAR registry - producing a re-verifiable audit record: each list is an ` +
      `attested snapshot (source, publication date, content hash, fetch time), ` +
      `every hit cites the exact list version, and every clear cites the snapshot ` +
      `it was screened against (provable absence). Unreachable sources degrade to ` +
      `a logged gap, never a false clear; the verdict and completeness re-derive ` +
      `offline with no fail-open. Fee: ${formatFee(price.amount, price.asset)} per screening.`,
    supportedNegotiation: ["negotiate-fixed-price"],
    supportedPaymentRails: ["pay-dem"],
    supportedDelivery: [COMPLIANCE_DELIVERY_PHASE],
    /** Uniform-effort desk: flat fee. Structured for a uniform Butler mapping (NOT anchored). */
    fees: fixedFeeFromPrice(price),
  };
}

/** Map paid params to a screening subject. */
function subjectFromParams(params: Record<string, unknown>): ScreeningSubject {
  const kind = String(params.kind ?? "") as SubjectKind;
  if (kind !== "person" && kind !== "entity" && kind !== "wallet") {
    throw new Error(`compliance: unknown subject kind "${String(params.kind)}" (want person | entity | wallet)`);
  }
  const walletAddress = typeof params.walletAddress === "string" ? params.walletAddress : undefined;
  const name = typeof params.name === "string" ? params.name : undefined;
  if (kind === "wallet") {
    if (!walletAddress) throw new Error("compliance: kind=wallet requires walletAddress");
  } else if (!name) {
    throw new Error(`compliance: kind=${kind} requires name`);
  }
  const aliases = Array.isArray(params.aliases) ? params.aliases.map((a) => String(a)) : undefined;
  const country = typeof params.country === "string" ? params.country : undefined;
  return {
    kind,
    name: name ?? walletAddress ?? "",
    ...(aliases ? { aliases } : {}),
    ...(country ? { country } : {}),
    ...(walletAddress ? { walletAddress } : {}),
  };
}

/**
 * Build the compliance work callback over injected list sources (real sources
 * over a cache-aware fetch, or `fixtureSources()` for tests/offline). The buyer
 * conveys `{ kind, name?, aliases?, walletAddress?, country? }`.
 */
export function makeComplianceWork(sources: readonly ListSourcePort[]): WorkCallback {
  return async (_jobId, params) => {
    const subject = subjectFromParams(params);
    const inputs = await loadAll(sources);
    const report = screenSubject(subject, inputs);
    const meta = reportMeta(report);

    return {
      result: {
        subject: report.subject.name,
        verdict: report.verdict,
        screeningComplete: report.screeningComplete,
        sources: report.perSource.length,
        gaps: report.perSource.filter((p) => p.status === "gap").length,
        matches: report.perSource.reduce((n, p) => n + (p.status === "screened" ? p.matches.length : 0), 0),
      },
      deliverableRef: `compliance:screening:${meta.reportHash}`,
      meta,
    };
  };
}

/**
 * `observeDelivered`: re-run the core's `verifyScreening` over the delivered
 * report offline (list-download attestations re-verified, citations resolved).
 */
export function complianceObserveDelivered(): DeliveryVerifyOptions["observeDelivered"] {
  return async (att) => {
    const read = readReportMeta<ScreeningReport>(att);
    if (!read.ok) return { ok: false, reason: read.reason };
    // Enforce the full advertised panel: a report that quietly dropped a list
    // to hide a hit fails here, because the buyer knows what was commissioned.
    const verdict = verifyScreening(read.artifact, SOURCE_IDS);
    return verdict.valid
      ? { ok: true }
      : { ok: false, reason: `screening verification failed: ${verdict.problems.join("; ")}` };
  };
}
