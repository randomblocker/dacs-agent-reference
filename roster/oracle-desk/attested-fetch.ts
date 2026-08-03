/**
 * AttestedFetch adapters — real (global fetch) and fake (canned bodies).
 *
 * Both produce the same MOCK-DAHR attestation: sha256 digest over
 * `${url}|${fetchedAt}|${bodyHash}`, signed with an ephemeral ed25519 key
 * (node:crypto). This is EXPLICITLY NOT a real DAHR proof — it exists so the
 * wire shape, hashing discipline, and offline verification path are already
 * exercised end to end; the real DAHR swap is confined to this file.
 */
import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  sign as edSign,
  verify as edVerify,
  type KeyObject,
} from "node:crypto";
import { lookup } from "node:dns/promises";
import { assertSafeUrl, isPrivateIPv4, isPrivateIPv6, OracleError } from "./attest-any.js";
import type { AttestedFetchPort, AttestedFetchResult, MockDahrAttestation } from "./types.js";

// ASCII-only: this note is embedded in the anchored DACS-X delivery attestation
// (via the oracle attestation meta). A non-ASCII char (e.g. an em-dash) makes
// that storage-program tx un-settleable on the live Demos node — demosdk and
// the node hash the payload differently for non-ASCII UTF-8, so `confirm`
// rejects it with "[SIGNATURE ERROR] Transaction hash mismatch" (root-caused in
// the L1 live run).
export const MOCK_ATTESTATION_NOTE =
  "MOCK attestation - ephemeral ed25519 signer, NOT a real DAHR network proof. " +
  "Swap the AttestedFetchPort adapter for real DAHR.";

export const DIRECT_HTTPS_ATTESTATION_NOTE =
  "DIRECT HTTPS observation - the seller fetched these bytes with bounded DNS/SSRF/size/time controls, " +
  "signed their digest, and commits the complete record inside its on-chain DACS delivery. A verifier can " +
  "recompute the body hash and verify both signatures, but this is not TLSNotary and validators do not re-fetch.";

export function sha256Hex(data: string): string {
  return createHash("sha256").update(data, "utf8").digest("hex");
}

function attestationDigest(url: string, fetchedAt: string, bodyHash: string): string {
  return sha256Hex(`${url}|${fetchedAt}|${bodyHash}`);
}

// ---------------------------------------------------------------------------
// Mock attestor (shared by both adapters)
// ---------------------------------------------------------------------------

export class MockDahrAttestor {
  private readonly privateKey: KeyObject;
  readonly publicKeyB64: string;

  constructor(
    private readonly scheme: "MOCK-DAHR-ed25519" | "DIRECT-HTTPS-ed25519" = "MOCK-DAHR-ed25519",
    private readonly note = MOCK_ATTESTATION_NOTE,
  ) {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    this.privateKey = privateKey;
    this.publicKeyB64 = publicKey.export({ type: "spki", format: "der" }).toString("base64");
  }

  attest(url: string, fetchedAt: string, bodyHash: string): MockDahrAttestation {
    const digest = attestationDigest(url, fetchedAt, bodyHash);
    const signature = edSign(null, Buffer.from(digest, "hex"), this.privateKey).toString("base64");
    return { scheme: this.scheme, note: this.note, digest, signature, publicKey: this.publicKeyB64 };
  }
}

/** Production direct-fetch attestor; the outer DACS delivery supplies the stable seller identity. */
export class DirectHttpsAttestor extends MockDahrAttestor {
  constructor() {
    super("DIRECT-HTTPS-ed25519", DIRECT_HTTPS_ATTESTATION_NOTE);
  }
}

/**
 * The body-free part of an attested fetch: enough to re-verify the signature
 * without carrying the raw response around (a holder of the body can still
 * check it against `bodyHash` separately). Shared with the DD researcher,
 * whose reports keep only hashes for oversized bodies.
 */
export interface AttestedRecord {
  url: string;
  fetchedAt: string;
  bodyHash: string;
  attestation: MockDahrAttestation;
}

/**
 * Verify the attestation over a body-free record: recompute the digest from
 * url|fetchedAt|bodyHash, check it matches the attestation's digest, and
 * verify the ed25519 signature against the embedded public key.
 */
export function verifyAttestedRecord(record: AttestedRecord): { valid: boolean; reason?: string } {
  const att = record.attestation;
  if (att.scheme === "LIVE-DAHR-web2Request") {
    // Real DAHR: the node's `responseHash` (= sha256 of the raw body) IS the
    // digest, so offline it must equal the record's bodyHash. That's the whole
    // of what an offline holder can check — the on-chain anchor (`anchorTxRef`)
    // adds a persistent-identity commitment + public timestamp, but proving it
    // requires a chain read (verifyLiveAnchorOnChain), and it still does NOT
    // prove the upstream returned the body (no node/consensus signature).
    if (att.digest !== record.bodyHash) {
      return { valid: false, reason: "live digest (responseHash) does not equal bodyHash" };
    }
    return { valid: true };
  }
  if (att.scheme !== "MOCK-DAHR-ed25519" && att.scheme !== "DIRECT-HTTPS-ed25519") {
    return { valid: false, reason: `unknown scheme ${att.scheme}` };
  }
  const expected = attestationDigest(record.url, record.fetchedAt, record.bodyHash);
  if (att.digest !== expected) return { valid: false, reason: "digest does not cover url|fetchedAt|bodyHash" };
  try {
    const publicKey = createPublicKey({ key: Buffer.from(att.publicKey, "base64"), format: "der", type: "spki" });
    const ok = edVerify(null, Buffer.from(att.digest, "hex"), publicKey, Buffer.from(att.signature, "base64"));
    return ok ? { valid: true } : { valid: false, reason: "ed25519 signature invalid" };
  } catch (err) {
    return { valid: false, reason: `signature verification errored: ${(err as Error).message}` };
  }
}

/**
 * Offline verification of a full fetch result: the body must match its hash,
 * then the record verification above must pass. Anyone holding an
 * AttestedFetchResult can run this.
 */
export function verifyAttestation(result: AttestedFetchResult): { valid: boolean; reason?: string } {
  const att = result.attestation;
  if (att.scheme !== "MOCK-DAHR-ed25519" && att.scheme !== "DIRECT-HTTPS-ed25519" && att.scheme !== "LIVE-DAHR-web2Request") {
    return { valid: false, reason: `unknown scheme ${att.scheme}` };
  }
  if (sha256Hex(result.body) !== result.bodyHash) return { valid: false, reason: "bodyHash does not match body" };
  return verifyAttestedRecord(result);
}

function buildResult(attestor: MockDahrAttestor, url: string, status: number, body: string): AttestedFetchResult {
  const fetchedAt = new Date().toISOString();
  const bodyHash = sha256Hex(body);
  return { url, fetchedAt, status, bodyHash, body, attestation: attestor.attest(url, fetchedAt, bodyHash) };
}

// ---------------------------------------------------------------------------
// Real adapter — actual network fetch
// ---------------------------------------------------------------------------

export class RealAttestedFetch implements AttestedFetchPort {
  constructor(
    private readonly attestor: MockDahrAttestor = new MockDahrAttestor(),
    private readonly timeoutMs = 10_000,
    /** Response-size cap (bytes). A larger body is rejected, not truncated. */
    private readonly maxBytes = 512_000,
  ) {}

  async attestFetch(url: string): Promise<AttestedFetchResult> {
    // SSRF: https-only + no internal/private/metadata targets. Real fetches
    // resolve DNS, so also re-check the RESOLVED addresses (closes the
    // rebinding gap the literal-host check alone leaves open).
    const parsed = assertSafeUrl(url);
    await this.assertResolvesPublic(parsed.hostname);

    const response = await fetch(url, {
      signal: AbortSignal.timeout(this.timeoutMs),
      redirect: "error", // a redirect could bounce us to an internal target post-guard
      headers: { accept: "application/json, text/plain;q=0.9, */*;q=0.8", "user-agent": "dacs-agents-oracle-desk/0.1" },
    });
    const declared = Number(response.headers.get("content-length") ?? "0");
    if (Number.isFinite(declared) && declared > this.maxBytes) {
      throw new OracleError("upstream_failure", `upstream body ${declared}B exceeds cap ${this.maxBytes}B`);
    }
    const body = await response.text();
    if (Buffer.byteLength(body, "utf8") > this.maxBytes) {
      throw new OracleError("upstream_failure", `upstream body exceeds cap ${this.maxBytes}B`);
    }
    return buildResult(this.attestor, url, response.status, body);
  }

  /** Resolve the host and reject if any answer is a private/reserved address. */
  private async assertResolvesPublic(hostname: string): Promise<void> {
    const host = hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
    // Literal IPs are already covered by assertSafeUrl; only names need resolving.
    if (/^[\d.]+$/.test(host) || host.includes(":")) return;
    let addrs: Array<{ address: string; family: number }>;
    try {
      addrs = await lookup(host, { all: true });
    } catch (e) {
      throw new OracleError("upstream_failure", `DNS lookup for ${host} failed: ${(e as Error).message}`);
    }
    for (const { address, family } of addrs) {
      const v4 = family === 4 ? (address.split(".").map(Number) as [number, number, number, number]) : null;
      if (v4 && isPrivateIPv4(v4)) throw new OracleError("unsafe_url", `${host} resolves to private ${address}`);
      if (family === 6 && isPrivateIPv6(address)) throw new OracleError("unsafe_url", `${host} resolves to private ${address}`);
    }
  }
}

// ---------------------------------------------------------------------------
// Fake adapter — canned bodies for offline tests
// ---------------------------------------------------------------------------

export type FakeUpstream =
  /** Served as a normal (attested) response with this status/body. */
  | { status: number; body: string }
  /** Network-level failure: attestFetch rejects with this message. */
  | { fail: string };

/**
 * Routes are (substring, response) pairs matched against the URL in order;
 * an unmatched URL rejects, like a network failure. Successful responses are
 * attested exactly like the real adapter, so signature checks run for real.
 */
export class FakeAttestedFetch implements AttestedFetchPort {
  readonly requested: string[] = [];

  constructor(
    private readonly routes: Array<[substring: string, response: FakeUpstream]>,
    private readonly attestor: MockDahrAttestor = new MockDahrAttestor(),
  ) {}

  async attestFetch(url: string): Promise<AttestedFetchResult> {
    this.requested.push(url);
    const hit = this.routes.find(([needle]) => url.includes(needle));
    if (!hit) throw new Error(`FakeAttestedFetch: no route for ${url}`);
    const [, response] = hit;
    if ("fail" in response) throw new Error(response.fail);
    return buildResult(this.attestor, url, response.status, response.body);
  }
}
