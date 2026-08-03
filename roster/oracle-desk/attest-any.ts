/**
 * attest-any-API — the generalization of the oracle desk from three hardcoded
 * price products to "attest ANY Web2 JSON API".
 *
 * The buyer supplies `{ url, method?, extract }`. `extract` is a SAFE,
 * deterministic selector — a small dot/JSON-path over the parsed JSON body,
 * NEVER code eval. The agent does the attested fetch (real DAHR-mock over the
 * actual response bytes), pulls the named field out, and returns
 * `{ url, extract, value, attestation }` — a provable "this value came from this
 * URL at this time". This is the differentiator vs Chainlink/Pyth: the long tail
 * of Web2 endpoints a decentralized price oracle will never cover.
 *
 * Two safety surfaces live here, both load-bearing because the URL is now
 * attacker-controlled:
 *   1. SSRF guard (`assertSafeUrl`) — https-only, and refuses internal/private/
 *      link-local/metadata targets so a buyer can't make the oracle fetch
 *      `http://169.254.169.254/…` or `http://localhost/admin`.
 *   2. Selector validation (`parseSelector`) — a restricted charset, a segment
 *      cap, and prototype-pollution key rejection; extraction is pure structural
 *      navigation, no `eval`/`Function`/vm.
 *
 * Extraction failure and SSRF/selector rejection are TYPED errors that propagate
 * as a thrown work callback — never a guessed or fabricated value.
 */
import { CATALOG, findProduct, validateParams } from "./catalog.js";
import type { AttestedFetchPort, AttestedFetchResult } from "./types.js";

// ---------------------------------------------------------------------------
// Typed errors
// ---------------------------------------------------------------------------

export type OracleErrorCode =
  | "unsafe_url" // SSRF guard tripped / not https
  | "bad_selector" // selector fails validation
  | "bad_request" // missing/unknown product or params
  | "upstream_failure" // network error / non-2xx / non-JSON
  | "extract_failure" // selector did not resolve in the body
  | "consensus_failure"; // multi-source values disagreed

export class OracleError extends Error {
  constructor(
    readonly code: OracleErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "OracleError";
  }
}

// ---------------------------------------------------------------------------
// SSRF guard — refuse internal / private / metadata targets
// ---------------------------------------------------------------------------

/** Hostnames that must never be fetched, regardless of DNS. */
const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "metadata", // generic
  "metadata.google.internal", // GCP metadata
  "instance-data", // AWS metadata alias
  "instance-data.ec2.internal",
]);

function stripV6Brackets(host: string): string {
  return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}

/** Parse a dotted-quad; null if not an IPv4 literal. */
function parseIPv4(host: string): [number, number, number, number] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!m) return null;
  const octets = m.slice(1, 5).map((s) => Number(s)) as [number, number, number, number];
  if (octets.some((o) => o < 0 || o > 255)) return null;
  return octets;
}

/** True for any IPv4 in a private / loopback / link-local / reserved range. */
export function isPrivateIPv4(octets: [number, number, number, number]): boolean {
  const [a, b] = octets;
  if (a === 0) return true; // 0.0.0.0/8 "this host"
  if (a === 10) return true; // 10.0.0.0/8 private
  if (a === 127) return true; // 127.0.0.0/8 loopback
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local (incl. cloud metadata 169.254.169.254)
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12 private
  if (a === 192 && b === 168) return true; // 192.168.0.0/16 private
  if (a === 192 && b === 0 && octets[2] === 0) return true; // 192.0.0.0/24 IETF
  if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15 benchmarking
  if (a >= 224) return true; // 224/4 multicast + 240/4 reserved + 255.255.255.255
  return false;
}

/** True for an IPv6 literal that is loopback / unspecified / ULA / link-local, or a mapped-private IPv4. */
export function isPrivateIPv6(host: string): boolean {
  const h = host.toLowerCase();
  if (h === "::1" || h === "::") return true; // loopback / unspecified
  // IPv4-mapped/embedded (::ffff:10.0.0.1 etc.) — pull the trailing v4 and check it.
  const mapped = /(?:^|:)((?:\d{1,3}\.){3}\d{1,3})$/.exec(h);
  if (mapped) {
    const v4 = parseIPv4(mapped[1]!);
    if (v4 && isPrivateIPv4(v4)) return true;
  }
  const head = h.split(":")[0] ?? "";
  if (head.startsWith("fc") || head.startsWith("fd")) return true; // fc00::/7 unique-local
  if (head.startsWith("fe8") || head.startsWith("fe9") || head.startsWith("fea") || head.startsWith("feb"))
    return true; // fe80::/10 link-local
  return false;
}

/**
 * Assert a buyer-supplied URL is safe to fetch: https only, a real host, and
 * NOT an internal/private/link-local/metadata target. Throws an
 * `OracleError("unsafe_url", …)` otherwise. This is a best-effort literal-host
 * check; DNS-rebinding (a public name resolving to a private IP) is closed
 * separately by the real fetch adapter's resolve-time guard.
 */
export function assertSafeUrl(rawUrl: string): URL {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new OracleError("unsafe_url", `not a valid URL: ${JSON.stringify(rawUrl)}`);
  }
  if (url.protocol !== "https:") {
    throw new OracleError("unsafe_url", `only https is allowed (got ${url.protocol})`);
  }
  if (url.username || url.password) {
    throw new OracleError("unsafe_url", "credentials in the URL are not allowed");
  }
  const host = stripV6Brackets(url.hostname).toLowerCase();
  if (!host) throw new OracleError("unsafe_url", "empty host");
  if (BLOCKED_HOSTNAMES.has(host) || host.endsWith(".localhost")) {
    throw new OracleError("unsafe_url", `blocked internal host "${host}"`);
  }
  const v4 = parseIPv4(host);
  if (v4 && isPrivateIPv4(v4)) {
    throw new OracleError("unsafe_url", `blocked private/reserved IPv4 ${host}`);
  }
  if (host.includes(":") && isPrivateIPv6(host)) {
    throw new OracleError("unsafe_url", `blocked private/reserved IPv6 ${host}`);
  }
  return url;
}

// ---------------------------------------------------------------------------
// Selector — safe, deterministic dot/JSON path (no eval)
// ---------------------------------------------------------------------------

const DANGEROUS_KEYS = new Set(["__proto__", "prototype", "constructor"]);
const SELECTOR_SEGMENT = /^[A-Za-z0-9_-]+$/;
const MAX_SELECTOR_SEGMENTS = 32;

/**
 * Parse a selector into path segments. `"$"` or `""` means the JSON root.
 * Otherwise dot-separated segments over the parsed body; a numeric segment
 * indexes an array (or a numeric object key). Rejects prototype-polluting keys
 * and anything outside a conservative charset. Throws `OracleError("bad_selector")`.
 */
export function parseSelector(selector: string): string[] {
  const s = selector.trim();
  if (s === "" || s === "$") return [];
  const segments = s.split(".");
  if (segments.length > MAX_SELECTOR_SEGMENTS) {
    throw new OracleError("bad_selector", `selector has too many segments (max ${MAX_SELECTOR_SEGMENTS})`);
  }
  for (const seg of segments) {
    if (!SELECTOR_SEGMENT.test(seg)) {
      throw new OracleError(
        "bad_selector",
        `selector segment ${JSON.stringify(seg)} is invalid (allowed: letters, digits, "_", "-", "." separators)`,
      );
    }
    if (DANGEROUS_KEYS.has(seg)) {
      throw new OracleError("bad_selector", `selector segment ${JSON.stringify(seg)} is not allowed`);
    }
  }
  return segments;
}

/**
 * Navigate `root` by the parsed selector path. Pure structural access — indexes
 * arrays with numeric segments, reads own object properties otherwise. Returns
 * a typed error (never a guess) when the path does not resolve.
 */
export function extractBySelector(
  root: unknown,
  selector: string,
): { ok: true; value: unknown } | { ok: false; error: OracleError } {
  let path: string[];
  try {
    path = parseSelector(selector);
  } catch (e) {
    return { ok: false, error: e as OracleError };
  }
  let cur: unknown = root;
  const walked: string[] = [];
  for (const seg of path) {
    if (cur === null || cur === undefined) {
      return { ok: false, error: new OracleError("extract_failure", `path "${walked.join(".")}" is ${String(cur)}; cannot read "${seg}"`) };
    }
    if (Array.isArray(cur)) {
      if (!/^\d+$/.test(seg)) {
        return { ok: false, error: new OracleError("extract_failure", `"${walked.join(".")}" is an array; segment "${seg}" is not an index`) };
      }
      const idx = Number(seg);
      if (idx >= cur.length) {
        return { ok: false, error: new OracleError("extract_failure", `index ${idx} out of range at "${walked.join(".")}" (len ${cur.length})`) };
      }
      cur = cur[idx];
    } else if (typeof cur === "object") {
      const obj = cur as Record<string, unknown>;
      if (!Object.prototype.hasOwnProperty.call(obj, seg)) {
        return { ok: false, error: new OracleError("extract_failure", `no field "${seg}" at "${walked.join(".") || "$"}"`) };
      }
      cur = obj[seg];
    } else {
      return { ok: false, error: new OracleError("extract_failure", `"${walked.join(".")}" is a ${typeof cur}, not indexable by "${seg}"`) };
    }
    walked.push(seg);
  }
  return { ok: true, value: cur };
}

function parseJsonBody(body: string, url: string): unknown {
  try {
    return JSON.parse(body);
  } catch {
    throw new OracleError("upstream_failure", `upstream ${url} did not return JSON`);
  }
}

// ---------------------------------------------------------------------------
// Presets — the three canned products as convenience shortcuts over the
// generic path (reusing the catalog's URL builders + param validation).
// ---------------------------------------------------------------------------

/** Maps a preset id → the JSON selector to apply after fetching its URL. */
const PRESET_SELECTOR: Record<string, (params: Record<string, string>) => string> = {
  "crypto-price": (p) => `${p.id}.usd`,
  "fx-rate": (p) => `rates.${p.symbol}`,
  "chain-height": () => "$", // body is a bare JSON number
};

export function isPreset(id: string): boolean {
  return id in PRESET_SELECTOR;
}

export const PRESET_IDS = Object.keys(PRESET_SELECTOR);

/** A resolved fetch request: a safe URL + the selector to apply. */
export interface ResolvedRequest {
  url: string;
  method: "GET";
  selector: string;
  /** Set when this came from a named preset (else a raw generic call). */
  preset?: string;
}

/**
 * Resolve conveyed params into a `ResolvedRequest`, validating + SSRF-guarding.
 * Two shapes are accepted:
 *   - preset:  `{ product: "crypto-price", id: "bitcoin" }`
 *   - generic: `{ url: "https://…", extract: "a.b.c", method?: "GET" }`
 * Throws a typed `OracleError` on any problem.
 */
export function resolveRequest(params: Record<string, unknown>): ResolvedRequest {
  const productId = params.product ?? params.productId;
  if (productId !== undefined && productId !== "") {
    const id = String(productId);
    const product = findProduct(CATALOG, id);
    const selectorOf = PRESET_SELECTOR[id];
    if (!product || !selectorOf) {
      throw new OracleError("bad_request", `unknown preset "${id}" (have: ${PRESET_IDS.join(", ")})`);
    }
    const raw: Record<string, string> = {};
    for (const [k, v] of Object.entries(params)) {
      if (k === "product" || k === "productId") continue;
      raw[k] = String(v);
    }
    const validated = validateParams(product, raw);
    if (!validated.ok) throw new OracleError("bad_request", `bad params — ${validated.problems.join("; ")}`);
    const url = product.buildUrl(validated.params);
    assertSafeUrl(url);
    return { url, method: "GET", selector: selectorOf(validated.params), preset: id };
  }

  // Generic attest-any path.
  const rawUrl = params.url;
  if (rawUrl === undefined || rawUrl === "") {
    throw new OracleError("bad_request", 'supply either { product, … } (preset) or { url, extract } (attest-any)');
  }
  const method = String(params.method ?? "GET").toUpperCase();
  if (method !== "GET") {
    throw new OracleError("bad_request", `only GET is attestable in v1 (got ${method})`);
  }
  const selector = params.extract ?? params.selector ?? "$";
  parseSelector(String(selector)); // validate up front (typed error)
  const url = assertSafeUrl(String(rawUrl));
  return { url: url.toString(), method: "GET", selector: String(selector) };
}

// ---------------------------------------------------------------------------
// The attested fetch + extract
// ---------------------------------------------------------------------------

/** What one attest-any (or preset) call yields. */
export interface AttestedValue {
  url: string;
  extract: string;
  /** The sold value — any JSON (float price, string, object). */
  value: unknown;
  attestation: AttestedFetchResult;
  preset?: string;
}

/**
 * Do the attested fetch for a resolved request and extract the value. Upstream
 * failure or a selector that does not resolve is a TYPED throw — never a
 * fabricated value.
 */
export async function attestValue(fetchPort: AttestedFetchPort, req: ResolvedRequest): Promise<AttestedValue> {
  let attested: AttestedFetchResult;
  try {
    attested = await fetchPort.attestFetch(req.url);
  } catch (e) {
    throw new OracleError("upstream_failure", `attested fetch failed: ${(e as Error).message}`);
  }
  if (attested.status >= 400) {
    throw new OracleError("upstream_failure", `upstream responded ${attested.status}`);
  }
  const root = parseJsonBody(attested.body, req.url);
  const extracted = extractBySelector(root, req.selector);
  if (!extracted.ok) throw extracted.error;
  return { url: req.url, extract: req.selector, value: extracted.value, attestation: attested, preset: req.preset };
}

/** Convenience: resolve params → attested value in one call. */
export async function attestAny(
  fetchPort: AttestedFetchPort,
  params: Record<string, unknown>,
): Promise<AttestedValue> {
  return attestValue(fetchPort, resolveRequest(params));
}

// ---------------------------------------------------------------------------
// Multi-source consensus (optional robustness mode) — see MULTI_SOURCE_NOTE
// ---------------------------------------------------------------------------

/** Doc note surfaced in the demo + docs: honest positioning of single vs multi source. */
export const MULTI_SOURCE_NOTE =
  "A single-source attestation proves provenance (this value came from THIS url), " +
  "not correctness — the source is still a single point of trust. attestConsensus() " +
  "is the robustness follow-up: attest the same field from >=2 independent sources " +
  "and require they agree before returning a value.";

export interface ConsensusResult {
  value: unknown;
  /** One attested fetch per source (all agree on the extracted value). */
  attestations: AttestedValue[];
}

/**
 * Attest the same selector from >=2 independent URLs and require the extracted
 * values to agree (structural JSON equality). Any source failing, or a
 * disagreement, is a typed throw. v1 attests one source provably; this is the
 * opt-in consensus mode for when a single source is too much trust.
 */
export async function attestConsensus(
  fetchPort: AttestedFetchPort,
  urls: string[],
  selector: string,
): Promise<ConsensusResult> {
  if (urls.length < 2) {
    throw new OracleError("consensus_failure", "consensus needs at least 2 sources");
  }
  parseSelector(selector);
  const attestations: AttestedValue[] = [];
  for (const u of urls) {
    assertSafeUrl(u);
    attestations.push(await attestValue(fetchPort, { url: u, method: "GET", selector }));
  }
  const first = JSON.stringify(attestations[0]!.value);
  for (let i = 1; i < attestations.length; i++) {
    if (JSON.stringify(attestations[i]!.value) !== first) {
      throw new OracleError(
        "consensus_failure",
        `sources disagree: ${attestations[0]!.url} => ${first} vs ${attestations[i]!.url} => ${JSON.stringify(attestations[i]!.value)}`,
      );
    }
  }
  return { value: attestations[0]!.value, attestations };
}
