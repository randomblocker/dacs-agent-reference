/**
 * LiveDahr — the real-DAHR AttestedFetchPort adapter.
 *
 * Drop-in replacement for RealAttestedFetch's MockDahrAttestor path: instead of
 * the client fetching a URL itself and signing an ephemeral-key digest, LiveDahr
 * routes the fetch through the Demos node's DAHR web2 proxy
 * (`demos.web2.createDahr().startProxy`). The NODE performs the HTTPS fetch and
 * returns `responseHash` (= sha256 of the raw body); the SDK then anchors the
 * result on-chain in a `web2Request` tx signed by the client's own wallet.
 *
 * ── What this actually proves (measured against the live testnet) ────────────
 * A LIVE-DAHR-web2Request attestation is a SELF-OBSERVED COMMITMENT, not a
 * consensus/TLSNotary proof. Verified against demosnode.discus.sh
 * (scripts/probe-dahr.ts): the returned result carries NO node signature, and
 * the on-chain anchor tx's inner `web2Request.signature` is empty — only the
 * client's wallet signs the outer tx. Validators do not re-fetch the URL.
 *
 * So a third party can independently verify:
 *   1. the body hashes to `responseHash` (body integrity vs the committed hash);
 *   2. the on-chain anchor exists, is signed by the committing identity, and
 *      carries a public block timestamp (verifyLiveAnchorOnChain).
 * It CANNOT verify the upstream actually returned that body without trusting the
 * DAHR node operator.
 *
 * The genuine upgrade over the mock self-signer: the fetch is performed by a
 * SEPARATE party (the DAHR node), and the commitment is anchored under a
 * PERSISTENT on-chain identity with a public timestamp + real fee — versus the
 * mock's throwaway ed25519 key and no anchor. A modest, real trust improvement,
 * not trustlessness.
 */
import { assertSafeUrl, OracleError } from "./attest-any.js";
import { sha256Hex } from "./attested-fetch.js";
import type { AttestedFetchPort, AttestedFetchResult, MockDahrAttestation } from "./types.js";

export const LIVE_DAHR_NOTE =
  "LIVE DAHR web2Request - self-observed commitment: the DAHR node fetched + " +
  "hashed the body and the client anchored it on-chain, but the node does NOT " +
  "sign the result and validators do not re-fetch. A verifier can check the " +
  "body-vs-responseHash and the on-chain anchor, but must trust the DAHR node " +
  "operator for the fetch itself. NOT a consensus/TLSNotary proof.";

/** The subset of a DAHR `startProxy` (IWeb2Result) result LiveDahr consumes. */
export interface DahrProxyResult {
  status: number;
  /** Raw response body. Sometimes a stringified JSON blob, sometimes parsed. */
  data: unknown;
  /** Node's sha256 hex of the raw body. */
  responseHash: string;
  /** Node's sha256 hex of the response headers. */
  responseHeadersHash?: string;
  /** On-chain `web2Request` anchor tx hash (client-signed). */
  txHash?: string;
}

/**
 * The seam LiveDahr is written against, so the adapter is exercisable offline
 * with a fake. The real implementation (RealDahrProxy) wraps a connected
 * `@kynesyslabs/demosdk` Demos instance.
 */
export interface DahrProxyPort {
  /** Fetch `url` via the DAHR web2 proxy; returns the node result + anchor txHash. */
  proxy(url: string, method?: "GET" | "POST"): Promise<DahrProxyResult>;
  /** Committing client wallet address (the persistent identity that signs the anchor). */
  walletAddress(): string;
}

/** Normalise a DAHR `data` field to the exact raw-body string the node hashed. */
function toBodyString(data: unknown): string {
  // The node hashes the raw body bytes. On the wire that arrives as a string
  // (the documented "data is sometimes stringified JSON" gotcha). If the SDK
  // ever hands back a parsed object we cannot faithfully reconstruct the exact
  // bytes, so JSON.stringify is a best effort — the responseHash check below
  // will reject it if it doesn't round-trip.
  if (typeof data === "string") return data;
  if (data == null) return "";
  return JSON.stringify(data);
}

export class LiveDahr implements AttestedFetchPort {
  constructor(
    private readonly port: DahrProxyPort,
    /** Response-size cap (bytes). A larger body is rejected, not truncated. */
    private readonly maxBytes = 512_000,
  ) {}

  async attestFetch(url: string): Promise<AttestedFetchResult> {
    // https-only + no internal/private/metadata targets. The DAHR node also
    // enforces this server-side; we keep the client-side guard for parity with
    // RealAttestedFetch and to fail fast without spending a node round-trip.
    assertSafeUrl(url);

    const res = await this.port.proxy(url, "GET");
    const body = toBodyString(res.data);
    if (Buffer.byteLength(body, "utf8") > this.maxBytes) {
      throw new OracleError("upstream_failure", `upstream body exceeds cap ${this.maxBytes}B`);
    }

    const bodyHash = sha256Hex(body);
    // The node claims responseHash; recompute and require agreement. A mismatch
    // means the body we received is not the one the node hashed (transport
    // corruption, an object we couldn't re-serialise byte-exactly, or a
    // misbehaving node) — refuse rather than emit an attestation that won't
    // verify offline.
    if (res.responseHash && res.responseHash !== bodyHash) {
      throw new OracleError(
        "upstream_failure",
        `DAHR responseHash ${res.responseHash.slice(0, 16)}… != sha256(body) ${bodyHash.slice(0, 16)}…`,
      );
    }

    const anchorTxRef = res.txHash ?? "";
    const attestation: MockDahrAttestation = {
      scheme: "LIVE-DAHR-web2Request",
      note: LIVE_DAHR_NOTE,
      digest: res.responseHash || bodyHash, // node's responseHash (= sha256 of body)
      signature: anchorTxRef, // on-chain anchor tx hash — a commitment ref, not a node sig
      publicKey: this.port.walletAddress(), // committing client identity
      anchorTxRef,
      responseHeadersHash: res.responseHeadersHash,
    };

    return {
      url,
      fetchedAt: new Date().toISOString(),
      status: res.status,
      bodyHash,
      body,
      attestation,
    };
  }
}

// ---------------------------------------------------------------------------
// Real DAHR proxy — wraps a connected demosdk Demos instance
// ---------------------------------------------------------------------------

/** The connected-demos surface RealDahrProxy needs (structural — avoids a hard
 *  demosdk import so the pure roster stays dep-light; pass `adapter.raw`). */
export interface DemosLike {
  web2: { createDahr(): Promise<{ startProxy(params: unknown): Promise<DahrProxyResult> }> };
  getAddress(): string;
}

/**
 * Wraps a connected Demos instance (e.g. `new DemosAdapter({rpc,secret}).raw`
 * after `.connect()`) as a DahrProxyPort. Each `proxy` call opens a fresh DAHR
 * session (matching the SDK's per-call session semantics) and runs one
 * `startProxy` — which fetches, hashes, and broadcasts the on-chain anchor.
 */
export class RealDahrProxy implements DahrProxyPort {
  constructor(private readonly demos: DemosLike) {}

  async proxy(url: string, method: "GET" | "POST" = "GET"): Promise<DahrProxyResult> {
    const dahr = await this.demos.web2.createDahr();
    const result = await dahr.startProxy({ url, method, options: { headers: {} } });
    return {
      status: Number(result?.status ?? 0),
      data: result?.data,
      responseHash: String(result?.responseHash ?? ""),
      responseHeadersHash: result?.responseHeadersHash ? String(result.responseHeadersHash) : undefined,
      txHash: result?.txHash,
    };
  }

  walletAddress(): string {
    return this.demos.getAddress();
  }
}

// ---------------------------------------------------------------------------
// On-chain anchor verification (the part offline verify can't do)
// ---------------------------------------------------------------------------

/** Minimal tx-read surface for verifyLiveAnchorOnChain (structural; testable). */
export interface TxReader {
  getTxByHash(hash: string): Promise<unknown>;
}

export interface AnchorVerification {
  /** True iff the on-chain anchor exists and commits this attestation's digest. */
  valid: boolean;
  reason?: string;
  /** What the anchor *does* prove (for honest surfacing in reports). */
  proves?: string;
  /** What it deliberately does NOT prove. */
  doesNotProve?: string;
  blockNumber?: number;
  /** The committing on-chain identity (tx `from`). */
  committedBy?: string;
}

function get(obj: unknown, path: string[]): unknown {
  let cur: unknown = obj;
  for (const k of path) {
    if (cur == null || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[k];
  }
  return cur;
}

/**
 * Fetch the on-chain `web2Request` anchor and check it genuinely commits this
 * attestation. Proves: a persistent identity committed `(url, responseHash)` at
 * a public block/timestamp and paid a fee — a tamper-evident, non-repudiable
 * record. Does NOT prove the upstream returned the body (no node/consensus
 * signature on-chain; see the module header). Requires a live DAHR attestation.
 */
export async function verifyLiveAnchorOnChain(
  record: { url: string; attestation: MockDahrAttestation },
  reader: TxReader,
): Promise<AnchorVerification> {
  const att = record.attestation;
  if (att.scheme !== "LIVE-DAHR-web2Request") {
    return { valid: false, reason: `not a live DAHR attestation (scheme ${att.scheme})` };
  }
  const txRef = att.anchorTxRef || att.signature;
  if (!txRef) return { valid: false, reason: "no anchor tx ref on the attestation" };

  let tx: unknown;
  try {
    tx = await reader.getTxByHash(txRef);
  } catch (e) {
    return { valid: false, reason: `getTxByHash failed: ${(e as Error).message}` };
  }
  if (!tx || typeof tx !== "object") return { valid: false, reason: "anchor tx not found on-chain" };

  const type = get(tx, ["content", "type"]);
  if (type !== "web2Request") {
    return { valid: false, reason: `anchor tx type is ${String(type)}, expected web2Request` };
  }
  const result = get(tx, ["content", "data", "1", "message", "web2Request", "result"]) as
    | { responseHash?: string; targetUrl?: string }
    | undefined;
  const onChainHash = result?.responseHash;
  if (onChainHash !== att.digest) {
    return {
      valid: false,
      reason: `on-chain responseHash ${String(onChainHash).slice(0, 16)}… != attestation digest ${att.digest.slice(0, 16)}…`,
    };
  }
  if (result?.targetUrl && result.targetUrl !== record.url) {
    return { valid: false, reason: `on-chain targetUrl != attested url` };
  }
  const outerSig = get(tx, ["signature", "data"]);
  if (!outerSig || typeof outerSig !== "string") {
    return { valid: false, reason: "anchor tx carries no client signature" };
  }
  const from = get(tx, ["content", "from"]) as string | undefined;
  const status = get(tx, ["status"]) as string | undefined;
  if (status && status !== "confirmed") {
    return { valid: false, reason: `anchor tx status is ${status}, not confirmed` };
  }
  const blockNumber = get(tx, ["blockNumber"]) as number | undefined;

  return {
    valid: true,
    committedBy: from,
    blockNumber,
    proves:
      "a persistent on-chain identity committed (url, responseHash) in a " +
      "confirmed, fee-paid web2Request tx at a public block timestamp; the " +
      "record is tamper-evident and non-repudiable.",
    doesNotProve:
      "that the upstream URL actually returned this body — the DAHR node does " +
      "not sign the result and validators do not re-fetch, so a verifier still " +
      "trusts the DAHR node operator for the fetch itself.",
  };
}
