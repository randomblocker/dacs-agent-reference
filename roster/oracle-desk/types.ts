/**
 * DAHR Oracle Desk — types and ports.
 *
 * The oracle desk is a seller-side agent CORE: a small HTTP service that
 * sells attested Web2 data per call. Pure routing/validation logic written
 * against two injected ports: an AttestedFetchPort (real fetch + MOCK DAHR
 * attestation, or canned bodies for tests) and a ChargePolicyPort (payment
 * seam — currently a stub that always allows and records the would-be
 * charge; DACS/x402 wiring lands later as a port swap).
 *
 * No DACS lifecycle wiring, no credentials, no framework — node builtins only.
 */

// ---------------------------------------------------------------------------
// Attestation (MOCK DAHR)
// ---------------------------------------------------------------------------

/**
 * A DAHR-style attestation over an attested fetch. Two schemes share this wire
 * shape so the whole report/provenance layer stays scheme-agnostic (it reads
 * `scheme`, `note`, `digest`); the `scheme` discriminant says what the fields
 * actually PROVE.
 *
 * - `MOCK-DAHR-ed25519` (offline / tests): `digest` = sha256 over
 *   `${url}|${fetchedAt}|${bodyHash}`, signed with an ephemeral ed25519 key.
 *   Proves nothing about who fetched — the client both fetched and signed with a
 *   throwaway key. A pure self-attestation.
 *
 * - `LIVE-DAHR-web2Request` (real DAHR on the live Demos node): a SEPARATE party
 *   (the DAHR proxy node) performs the HTTPS fetch and returns `responseHash`
 *   (= sha256 of the raw body); the client anchors it on-chain in a
 *   `web2Request` tx signed by its OWN persistent wallet (`anchorTxRef`).
 *   IMPORTANT — this is a *self-observed commitment*, NOT a consensus/TLSNotary
 *   proof: the DAHR node does NOT sign the result (the on-chain
 *   `web2Request.signature` is empty) and validators do not re-fetch. A verifier
 *   can independently check (a) the body hashes to `digest`/`responseHash`, and
 *   (b) the on-chain anchor exists under the committing identity at a public
 *   timestamp — but CANNOT prove the upstream actually returned that body
 *   without trusting the DAHR node operator. (Proven by live probe against
 *   demosnode.discus.sh — see scripts/probe-dahr.ts.)
 *
 * Swapping mock→live is an AttestedFetchPort adapter change (LiveDahr), nothing
 * above the port moves.
 */
export interface MockDahrAttestation {
  scheme: "MOCK-DAHR-ed25519" | "DIRECT-HTTPS-ed25519" | "LIVE-DAHR-web2Request";
  /** Loud label stating exactly what this attestation does/doesn't prove. */
  note: string;
  /**
   * Mock: sha256 hex over `${url}|${fetchedAt}|${bodyHash}`.
   * Live: the DAHR node's `responseHash` (= sha256 hex of the raw body).
   */
  digest: string;
  /**
   * Mock: ed25519 signature over the raw digest bytes, base64.
   * Live: the on-chain anchor tx hash (the client-signed `web2Request` tx that
   * commits the fetch) — a commitment *reference*, NOT a verifiable node
   * signature over the digest. Empty if the anchor tx did not broadcast.
   */
  signature: string;
  /**
   * Mock: ephemeral signer public key, SPKI DER base64 — enough to verify offline.
   * Live: the committing client's Demos wallet address (the persistent identity
   * that signed the on-chain anchor).
   */
  publicKey: string;
  /**
   * Live only: the on-chain `web2Request` anchor tx hash (same value as
   * `signature` for the live scheme, surfaced under an unambiguous name for the
   * on-chain verifier). Absent for mock.
   */
  anchorTxRef?: string;
  /** Live only: the DAHR node's sha256 hex over the response headers. */
  responseHeadersHash?: string;
}

/** Everything an attested upstream fetch yields. */
export interface AttestedFetchResult {
  url: string;
  /** ISO-8601 timestamp of the fetch. */
  fetchedAt: string;
  /** Upstream HTTP status. */
  status: number;
  /** sha256 hex of the raw response body. */
  bodyHash: string;
  /** Raw response body text. */
  body: string;
  attestation: MockDahrAttestation;
}

export interface AttestedFetchPort {
  /** Fetch `url`, hash the body, and attach an attestation over the fetch. */
  attestFetch(url: string): Promise<AttestedFetchResult>;
}

// ---------------------------------------------------------------------------
// Payment seam (stub until DACS/x402 wiring)
// ---------------------------------------------------------------------------

export interface ChargeRequest {
  productId: string;
  params: Record<string, string>;
  /** Listed price in USD. */
  price: number;
}

export interface ChargeReceipt {
  chargeId: string;
  productId: string;
  /** What WOULD have been charged. */
  price: number;
  /** Always false today — nothing actually settles. */
  settled: false;
  note: string;
}

export interface ChargePolicyPort {
  /**
   * Decide whether to serve the call and record the would-be charge.
   * The stub always allows; a real policy may throw/deny once payments land.
   */
  authorize(req: ChargeRequest): Promise<ChargeReceipt>;
}

// ---------------------------------------------------------------------------
// Data products
// ---------------------------------------------------------------------------

export interface ProductParamSpec {
  name: string;
  required: boolean;
  /** Anchored regex the raw param value must match. */
  pattern: RegExp;
  /** Human-readable description surfaced in /catalog and 400 errors. */
  description: string;
  example: string;
}

export interface DataProduct {
  id: string;
  description: string;
  /** Price per call, USD. */
  price: number;
  params: ProductParamSpec[];
  /** Human-readable upstream label for the catalog (host, not full URL). */
  upstream: string;
  /** Build the upstream URL from validated params. */
  buildUrl(params: Record<string, string>): string;
  /**
   * Pull the sold value out of the raw upstream body. Throws on shape
   * mismatch (mapped to 502 by the server — the upstream misbehaved).
   */
  extract(body: string, params: Record<string, string>): unknown;
}

// ---------------------------------------------------------------------------
// HTTP wire shapes
// ---------------------------------------------------------------------------

/** GET /catalog */
export interface CatalogResponse {
  service: string;
  paymentStub: true;
  products: Array<{
    id: string;
    description: string;
    price: number;
    upstream: string;
    params: Array<{ name: string; required: boolean; description: string; example: string }>;
  }>;
}

/** GET /data/<productId> — success */
export interface DataResponse {
  product: string;
  params: Record<string, string>;
  value: unknown;
  attestation: AttestedFetchResult;
  priceCharged: number;
  chargeId: string;
}

/** GET /attest?url=&extract= — attest-any-API success */
export interface AttestResponse {
  url: string;
  extract: string;
  value: unknown;
  attestation: AttestedFetchResult;
  priceCharged: number;
  chargeId: string;
}

/** Any error status */
export interface ErrorResponse {
  error: {
    code:
      | "unknown_product"
      | "bad_params"
      | "upstream_failure"
      | "not_found"
      | "internal"
      | "unsafe_url"
      | "bad_selector"
      | "extract_failure";
    message: string;
    details?: unknown;
  };
}
