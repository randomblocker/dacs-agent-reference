/**
 * Wire the dd-researcher core into the shared DACS seller layer on the pay-dem
 * rail, Pattern 2 (session / push).
 *
 * The due-diligence researcher sells attested DD reports on npm packages and
 * crypto tokens. Here its `research(subject)` becomes the SellerAdapter **work
 * callback**: the paid job takes the buyer's conveyed params ({kind, subject}),
 * gathers attested evidence, derives cited findings, and hands back the report
 * as the deliverable. The DACS-X DeliveryAttestation commits to the report
 * (its content-hash is the delivery's `resultHash`) and carries the full report
 * in signed `meta` so a verifier can re-run the researcher's own `verifyReport`
 * OFFLINE — no re-fetch — from the anchor alone.
 *
 * In Pattern 2 the params are conveyed at session-open (the buyer hands them to
 * the rail, which pushes them into `deliver`) — this is the whole point vs the
 * chain-triggered Pattern 1, where the seller must read them off the anchored
 * agreement because there is no synchronous channel.
 */
import { DDResearcher, type ResearcherOptions } from "../../dd-researcher/researcher.js";
import { verifyReport } from "../../dd-researcher/report.js";
import type { AttestedFetchPort, DDReport, Subject } from "../../dd-researcher/types.js";
import type { WorkCallback } from "../seller-adapter.js";
import type { DeliveryVerifyOptions } from "../verifier.js";
import { formatFee, fixedFeeFromPrice } from "./pricing.js";
import { readReportMeta, reportMeta } from "./report-meta.js";

/** The DACS serviceId under which the dd-researcher sells DD reports. */
export const DD_SERVICE_ID = "dd-research";

/** The delivery phase advertised (and required by the session terms). */
export const DD_DELIVERY_PHASE = "deliver-dd-report";

/** The listing surface the dd-researcher advertises on the pay-dem rail. */
export function ddListingSpec(price: { amount: string; asset: string }) {
  return {
    serviceId: DD_SERVICE_ID,
    name: "Due-Diligence Researcher - source-attested reports",
    description:
      `Audit-grade due diligence on an npm package or crypto token: EVERY finding cites ` +
      `re-verifiable attested evidence (signed source fetches), so a third party re-checks the ` +
      `whole report offline from the anchor alone - not an ungrounded LLM summary that could ` +
      `fabricate a source. Sources: npm registry + downloads, GitHub repo health + security ` +
      `advisories, CoinGecko market/developer signals. A finding with no attested citation is ` +
      `unrepresentable by construction. Fee: ${formatFee(price.amount, price.asset)} per report.`,
    supportedNegotiation: ["negotiate-fixed-price"],
    supportedPaymentRails: ["pay-dem"],
    supportedDelivery: [DD_DELIVERY_PHASE],
    /** Uniform-effort desk: flat fee. Structured for a uniform Butler mapping (NOT anchored). */
    fees: fixedFeeFromPrice(price),
  };
}

/**
 * Map the paid params to a dd-researcher `Subject`. The buyer conveys
 * `{ kind: "npm-package" | "crypto-token", subject: "<name-or-id>" }`.
 */
export function subjectFromParams(params: Record<string, unknown>): Subject {
  const kind = String(params.kind ?? "");
  const subject = String(params.subject ?? params.name ?? params.id ?? "");
  if (!subject) throw new Error(`dd-research: missing subject in params ${JSON.stringify(params)}`);
  if (kind === "npm-package") return { kind: "npm-package", name: subject };
  if (kind === "crypto-token") return { kind: "crypto-token", id: subject };
  throw new Error(`dd-research: unknown subject kind "${kind}" (want npm-package | crypto-token)`);
}

/**
 * Build the dd-research work callback over an injected AttestedFetchPort (real
 * network for the demo, a Fake with canned bodies for tests). The report is the
 * deliverable; its content-hash lands in the delivery attestation, and the full
 * report rides in signed `meta` for the offline `observeDelivered` re-check.
 */
export function makeDdWork(fetchPort: AttestedFetchPort, opts: ResearcherOptions = {}): WorkCallback {
  const researcher = new DDResearcher(fetchPort, opts);
  return async (_jobId, params) => {
    const subject = subjectFromParams(params);
    const report = await researcher.research(subject);
    // Carry the full report as a JCS-safe JSON STRING (reportMeta): the signed
    // DeliveryAttestation scope rejects non-integer JSON numbers, and DD reports
    // are full of floats (CoinGecko prices, ATH %, volume/mcap ratios). A raw
    // object here threw at signing time for every crypto-token report — see
    // wire/report-meta.ts. The reportHash binds the string.
    const meta = reportMeta(report);
    return {
      // The value sold: a compact digest of the report (the full report is the
      // deliverable, carried in meta below and content-committed via resultHash).
      result: {
        subject: report.subject,
        findings: report.findings.length,
        evidence: report.evidence.length,
        gaps: report.gaps.length,
        summary: report.summary.text,
      },
      deliverableRef: `dd:report:${meta.reportHash}`,
      meta,
    };
  };
}

/**
 * The dd-researcher's `observeDelivered` hook: parse the report back out of the
 * signed delivery `meta` (with an UNCONDITIONAL reportJson↔reportHash binding
 * check — no fail-open when the hash is absent), then re-run `verifyReport`,
 * re-verifying every evidence attestation signature and resolving every citation
 * OFFLINE. A stranger confirms the delivered report is sound from the anchor
 * alone, and a report whose findings cite a missing or forged attestation is
 * rejected here.
 */
export function ddObserveDelivered(): DeliveryVerifyOptions["observeDelivered"] {
  return async (att) => {
    const read = readReportMeta<DDReport>(att);
    if (!read.ok) return { ok: false, reason: read.reason };
    const verdict = verifyReport(read.artifact);
    return verdict.valid
      ? { ok: true }
      : { ok: false, reason: `report verification failed: ${verdict.problems.join("; ")}` };
  };
}
