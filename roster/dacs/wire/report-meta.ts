/**
 * Shared helper for the parameterized seller wires (Build D).
 *
 * Every judgment/report seller delivers a rich core artifact (a DD report, a
 * site audit, a screening report, an enriched record, an upgrade plan, an
 * approval, a ruling …). Two constraints shape how it rides the DACS-X
 * DeliveryAttestation:
 *
 *   1. The DACS canonical form (RFC-8785 / JCS via `contentHash`) that
 *      `buildSignedArtifact` signs over REJECTS non-integer JSON numbers
 *      anywhere in the signed scope — and the attestation's `meta` is inside
 *      that scope (Build C note). Site-audit timings, screening match scores,
 *      and audit sub-scores are all floats, so a raw object in `meta` would
 *      throw at signing time.
 *
 *   2. The offline `observeDelivered` re-check wants the FULL artifact so it
 *      can run the core's own third-party verifier (verifyReport /
 *      verifyScreening / verifyAudit / verifyRecord / verifyRuling …).
 *
 * Carrying the artifact as a canonical JSON STRING satisfies both: a string is
 * JCS-safe regardless of the floats it contains, and `observeDelivered` parses
 * it straight back for verification. The `resultHash` (which hashes only the
 * compact `result` digest) is kept integer/string-only by each wire.
 */
import { sha256Hex } from "@kynesyslabs/dacs";
import type { DeliveryAttestation } from "../seller-adapter.js";

/** The signed-meta shape every report seller uses. */
export interface ReportMeta {
  [key: string]: unknown;
  /** The full core artifact, serialized (JCS-safe even with floats inside). */
  reportJson: string;
  /** sha256 over `reportJson` — binds the string to a stable digest. */
  reportHash: string;
}

/** Build the signed `meta` carrying a full artifact as a JSON string. */
export function reportMeta(artifact: unknown): ReportMeta {
  const reportJson = JSON.stringify(artifact);
  return { reportJson, reportHash: sha256Hex(reportJson) };
}

/**
 * Parse the artifact back out of a delivery attestation's meta, checking the
 * hash binding. Returns the parsed artifact, or a reason it could not.
 */
export function readReportMeta<T = unknown>(
  att: DeliveryAttestation,
): { ok: true; artifact: T } | { ok: false; reason: string } {
  const meta = att.meta as Partial<ReportMeta> | undefined;
  if (!meta || typeof meta.reportJson !== "string") {
    return { ok: false, reason: "delivery meta carries no report JSON" };
  }
  if (typeof meta.reportHash !== "string" || sha256Hex(meta.reportJson) !== meta.reportHash) {
    return { ok: false, reason: "report JSON does not match its reportHash" };
  }
  try {
    return { ok: true, artifact: JSON.parse(meta.reportJson) as T };
  } catch (e) {
    return { ok: false, reason: `report JSON did not parse: ${(e as Error).message}` };
  }
}

/** The delivery projection the Butler/evaluator run their checks against. */
export function reportDeliverable(att: DeliveryAttestation): { content: string; meta?: Record<string, unknown> } {
  const meta = att.meta as Partial<ReportMeta> | undefined;
  return { content: typeof meta?.reportJson === "string" ? meta.reportJson : JSON.stringify(att.meta ?? {}), meta: att.meta };
}
