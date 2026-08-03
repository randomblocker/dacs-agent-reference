/**
 * Wire the oracle-desk core into the shared DACS seller layer on the x402 rail.
 *
 * The oracle desk sells **attested Web2 data per call** — and, as of the
 * attest-any-API generalization, ANY https JSON endpoint, not just the three
 * canned price presets. Its data lookup becomes the SellerAdapter **work
 * callback**: the paid job resolves the request (a preset like `crypto-price`,
 * or a raw `{ url, extract }`), does the attested upstream fetch, extracts the
 * sold value with a safe deterministic selector, and hands back the value + the
 * oracle's OWN attestation as delivery `meta`. The DACS-X DeliveryAttestation
 * then wraps the value + attestation, signed by the seller.
 *
 * JCS-FLOAT FIX (was the load-bearing bug): the sold value can now be a FLOAT
 * (a live BTC price), a string, or an object. The DACS canonical form (RFC-8785
 * / JCS via `contentHash`, which `buildSignedArtifact` signs over) REJECTS
 * non-integer JSON numbers anywhere in the signed scope — so the previous wire,
 * which put the raw `value` in signed `meta` and in the `result` digest, threw
 * at sign time for every float. Delivery + anchoring were only possible for the
 * integer chain-height product. The fix routes the full attested value through
 * the JCS-safe string meta helper (`reportMeta`): the deliverable (incl. the
 * float, the attestation, and the raw body) rides as a canonical JSON STRING,
 * and the compact `result` digest is kept integer/string-only. Any value type
 * now delivers + anchors + verifies.
 *
 * The verifier's `observeDelivered` hook re-verifies OFFLINE, with NO fail-open:
 * (a) the reportJson<->reportHash binding, (b) the oracle attestation signature
 * over the fetched bytes, and (c) that the delivered value REALLY is what the
 * selector extracts from the attested body — a tampered value or attestation is
 * rejected.
 */
import {
  attestValue,
  extractBySelector,
  resolveRequest,
  MULTI_SOURCE_NOTE,
  OracleError,
} from "../../oracle-desk/attest-any.js";
import { verifyAttestation } from "../../oracle-desk/attested-fetch.js";
import type { AttestedFetchPort, AttestedFetchResult } from "../../oracle-desk/types.js";
import type { WorkCallback } from "../seller-adapter.js";
import type { DeliveryVerifyOptions } from "../verifier.js";
import { formatFee, fixedFeeFromPrice } from "./pricing.js";
import { readReportMeta, reportMeta } from "./report-meta.js";

export { MULTI_SOURCE_NOTE };

/** The DACS serviceId under which the oracle desk sells attested data. */
export const ORACLE_SERVICE_ID = "oracle-data";

/**
 * The public demo API groups product-specific fields under `params`, while the
 * Oracle work port uses the catalog's flat `{ product, ...fields }` shape.
 * Normalize at the service boundary so the exact same deterministic request
 * works for new agreements and for already-paid agreements created by the
 * original nested demo encoding.
 */
export function normalizeOracleWorkParams(params: Record<string, unknown>): Record<string, unknown> {
  if (params.params === undefined) return structuredClone(params);
  const keys = Object.keys(params);
  if (keys.some((key) => key !== "product" && key !== "params")) {
    throw new Error("nested Oracle request contains fields outside product and params");
  }
  if (!params.params || typeof params.params !== "object" || Array.isArray(params.params)) {
    throw new Error("nested Oracle params must be an object");
  }
  return {
    ...(structuredClone(params.params) as Record<string, unknown>),
    product: params.product,
  };
}

/**
 * The full artifact carried (as a JCS-safe JSON string) in the signed delivery
 * `meta`. Holds the sold value (any type), the source+selector, and the full
 * oracle attestation (incl. the raw body) so `observeDelivered` can re-verify
 * the signature AND re-derive the value from the attested bytes offline.
 */
export interface OracleDeliverable {
  kind: "oracle-attested-value";
  /** The upstream fetched (already SSRF-guarded at work time). */
  url: string;
  /** The safe selector applied to the parsed JSON body. */
  extract: string;
  /** Preset id when this was a canned shortcut; absent for a raw attest-any call. */
  preset?: string;
  /** The sold value — float | string | object | array. */
  value: unknown;
  /** The oracle's own attestation over the fetch (url|fetchedAt|bodyHash + sig + body). */
  attestation: AttestedFetchResult;
}

/** Render any JSON value as a JCS-safe display string for the compact result digest. */
function displayValue(value: unknown): string {
  return typeof value === "string" ? value : JSON.stringify(value);
}

/** The listing surface the oracle desk advertises (attest-any-API, per call). */
export function oracleListingSpec(price: { amount: string; asset: string }) {
  return {
    serviceId: ORACLE_SERVICE_ID,
    // ASCII-only: a non-ASCII char here (e.g. an em-dash) makes the anchored
    // Listing un-settleable on the live Demos node — demosdk and the node hash
    // the storage-program tx over the payload differently for non-ASCII UTF-8,
    // so `confirm` rejects it with "[SIGNATURE ERROR] Transaction hash mismatch"
    // (root-caused in the L1 live run; ASCII content anchors cleanly).
    name: "DAHR Oracle Desk - attest any Web2 API, per call",
    description:
      `Provable "this value came from this URL at this time" for ANY https JSON API - ` +
      `the long tail of Web2 endpoints that Chainlink/Pyth price feeds do not cover. ` +
      `Supply { url, extract } and the desk does an attested fetch over the real bytes, ` +
      `pulls the named field with a safe deterministic selector (no code eval), and ` +
      `returns the value with a DAHR-style attestation a third party re-checks offline ` +
      `from the anchor alone. crypto-price / fx-rate / chain-height ship as convenience ` +
      `presets. Fee: ${formatFee(price.amount, price.asset)} per call.`,
    supportedNegotiation: ["negotiate-fixed-price"],
    supportedPaymentRails: ["pay-x402"],
    supportedDelivery: ["deliver-crypto-price", "deliver-fx-rate", "deliver-chain-height", "deliver-attested-value"],
    /** Uniform-effort desk: flat fee. Structured for a uniform Butler mapping (NOT anchored). */
    fees: fixedFeeFromPrice(price),
  };
}

/**
 * Build the oracle work callback over an injected AttestedFetchPort (real
 * network, or a Fake with canned bodies for tests). The paid `params` are
 * either a preset (`{ product, … }`) or a raw attest-any call (`{ url, extract }`).
 * The delivered value can be any JSON type; it is carried JCS-safely (reportMeta).
 */
export function makeOracleWork(fetchPort: AttestedFetchPort): WorkCallback {
  return async (_jobId, params) => {
    const req = resolveRequest(params); // validates + SSRF-guards; typed throw on any problem
    const attested = await attestValue(fetchPort, req); // upstream/extract failure => typed throw (never a guess)

    const deliverable: OracleDeliverable = {
      kind: "oracle-attested-value",
      url: attested.url,
      extract: attested.extract,
      preset: attested.preset,
      value: attested.value,
      attestation: attested.attestation,
    };
    // JCS-safe: the deliverable (with its float value + attestation + raw body)
    // rides as a canonical JSON STRING; reportHash binds it. The compact result
    // and the extra meta fields are integer/string-only.
    const meta = {
      ...reportMeta(deliverable),
      oracleDigest: attested.attestation.attestation.digest,
      value: displayValue(attested.value),
    };
    return {
      // The value sold, as a JCS-safe compact digest (the full deliverable is in meta).
      result: {
        source: attested.url,
        extract: attested.extract,
        value: displayValue(attested.value),
        oracleDigest: attested.attestation.attestation.digest,
        reportHash: meta.reportHash,
      },
      deliverableRef: `dahr:${attested.attestation.attestation.digest}`,
      meta,
    };
  };
}

/**
 * The oracle desk's `observeDelivered` hook — re-verify OFFLINE, NO fail-open:
 *   1. parse the deliverable back out of signed meta (reportJson<->reportHash
 *      binding is UNCONDITIONAL — absent/mismatched hash => reject),
 *   2. verify the oracle attestation (bodyHash matches body + ed25519 signature),
 *   3. re-derive the value from the attested body via the SAME selector and
 *      require it equals the delivered value.
 * A stranger confirms, from the anchor alone, that the delivered value truly
 * came from that URL. A tampered value or attestation is rejected here.
 */
export function oracleObserveDelivered(): DeliveryVerifyOptions["observeDelivered"] {
  return async (att) => {
    const read = readReportMeta<OracleDeliverable>(att);
    if (!read.ok) return { ok: false, reason: read.reason };
    const d = read.artifact;
    if (d?.kind !== "oracle-attested-value" || !d.attestation) {
      return { ok: false, reason: "delivery meta is not an oracle-attested-value deliverable" };
    }

    // (2) The attestation must be sound over its own body.
    const av = verifyAttestation(d.attestation);
    if (!av.valid) return { ok: false, reason: `oracle attestation invalid: ${av.reason}` };

    // The attestation must be over the URL the deliverable claims.
    if (d.attestation.url !== d.url) {
      return { ok: false, reason: `attestation url ${d.attestation.url} != deliverable url ${d.url}` };
    }

    // (3) The delivered value must be exactly what the selector pulls from the
    // attested bytes — this is what makes tampering with `value` detectable.
    let root: unknown;
    try {
      root = JSON.parse(d.attestation.body);
    } catch {
      return { ok: false, reason: "attested body is not JSON" };
    }
    const re = extractBySelector(root, d.extract);
    if (!re.ok) return { ok: false, reason: `selector no longer resolves in attested body: ${re.error.message}` };
    if (JSON.stringify(re.value) !== JSON.stringify(d.value)) {
      return { ok: false, reason: "delivered value does not match the attested body" };
    }
    return { ok: true };
  };
}

export { OracleError };
