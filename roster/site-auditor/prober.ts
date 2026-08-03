/**
 * Prober adapters — real (global fetch + node:tls) and fake (canned
 * measurements for offline tests). Also the measurement-attestation wrapper:
 * probe results are not HTTP bodies, so — like lead-enrich's DNS answers —
 * each measurement is signed over its canonical JSON under a `probe:`
 * pseudo-URL, in the exact MOCK-DAHR record shape `verifyAttestedRecord`
 * checks.
 */
import { lookup } from "node:dns/promises";
import { request as httpRequest, type IncomingHttpHeaders } from "node:http";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { MockDahrAttestor, sha256Hex } from "../oracle-desk/attested-fetch.js";
import { isPrivateIPv4, isPrivateIPv6 } from "../oracle-desk/attest-any.js";
import { canonicalJson } from "../shared/attest-primitives.js";
import { r1 } from "./checks.js";
import type { MeasurementEvidence, MeasurementKind, ProbeResult, ProberPort, TlsInfo } from "./types.js";

export const MAX_REDIRECTS = 5;
export const MAX_BODY_BYTES = 2 * 1024 * 1024;
const USER_AGENT = "dacs-agents-site-auditor/0.1";
const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "metadata",
  "metadata.google.internal",
  "instance-data",
  "instance-data.ec2.internal",
]);

/** Reject URLs that could address local services before any socket is opened. */
export function assertSafeProbeUrl(raw: string): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`unsafe probe URL: ${JSON.stringify(raw)}`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error(`unsafe probe protocol ${url.protocol}`);
  if (url.username || url.password) throw new Error("credentials in probe URLs are not allowed");
  const host = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (!host || BLOCKED_HOSTNAMES.has(host) || host.endsWith(".localhost")) throw new Error(`blocked probe host ${host || "<empty>"}`);
  const family = isIP(host);
  if (family === 4 && isPrivateIPv4(host.split(".").map(Number) as [number, number, number, number])) {
    throw new Error(`blocked private/reserved probe address ${host}`);
  }
  if (family === 6 && isPrivateIPv6(host)) throw new Error(`blocked private/reserved probe address ${host}`);
  return url;
}

/** Resolve once, reject every unsafe answer, then pin the request to one checked address. */
async function resolvePublicAddress(hostname: string): Promise<{ address: string; family: number }> {
  const host = hostname.replace(/^\[|\]$/g, "");
  const literalFamily = isIP(host);
  if (literalFamily !== 0) return { address: host, family: literalFamily };
  const answers = await lookup(host, { all: true });
  if (answers.length === 0) throw new Error(`DNS lookup for ${host} returned no addresses`);
  for (const answer of answers) {
    if (answer.family === 4 && isPrivateIPv4(answer.address.split(".").map(Number) as [number, number, number, number])) {
      throw new Error(`${host} resolves to blocked private/reserved address ${answer.address}`);
    }
    if (answer.family === 6 && isPrivateIPv6(answer.address)) {
      throw new Error(`${host} resolves to blocked private/reserved address ${answer.address}`);
    }
  }
  return answers[0]!;
}

// ---------------------------------------------------------------------------
// Pseudo-URLs + attestation wrapper
// ---------------------------------------------------------------------------

export function timingPseudoUrl(url: string, sampleIndex: number): string {
  return `probe:timing:${url}#${sampleIndex}`;
}

export function tlsPseudoUrl(host: string): string {
  return `probe:tls:${host}`;
}

export function httpRedirectPseudoUrl(httpUrl: string): string {
  return `probe:http-redirect:${httpUrl}`;
}

/**
 * Wrap a raw measurement in the shared attestation record shape: the "body"
 * is the canonical JSON of the measurement, signed under the probe:
 * pseudo-URL by the same MOCK-DAHR attestor machinery the oracle desk and
 * lead-enrich use — so `verifyAttestedRecord` verifies probe evidence
 * exactly like HTTP evidence.
 */
export function attestMeasurement(
  attestor: MockDahrAttestor,
  id: string,
  kind: MeasurementKind,
  pseudoUrl: string,
  measurement: unknown,
): MeasurementEvidence {
  const fetchedAt = new Date().toISOString();
  const body = canonicalJson(measurement);
  const bodyHash = sha256Hex(body);
  return { id, kind, url: pseudoUrl, fetchedAt, body, bodyHash, attestation: attestor.attest(pseudoUrl, fetchedAt, bodyHash) };
}

// ---------------------------------------------------------------------------
// Real adapter — timed fetch with manual redirects + node:tls inspection
// ---------------------------------------------------------------------------

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

export class RealProber implements ProberPort {
  async probe(url: string, timeoutMs: number): Promise<ProbeResult> {
    const fetchedAt = new Date().toISOString();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new Error(`probe of ${url} timed out after ${timeoutMs}ms`)), timeoutMs);
    const started = performance.now();
    try {
      // Manual redirect following (cap MAX_REDIRECTS) so the chain is observable.
      const redirectChain = [url];
      let current = url;
      let redirectCount = 0;
      let response = await fetchOnce(current, controller.signal, true);
      while (REDIRECT_STATUSES.has(response.status) && response.location !== undefined && redirectCount < MAX_REDIRECTS) {
        current = new URL(response.location, current).toString();
        redirectChain.push(current);
        redirectCount += 1;
        // Each hop is parsed, DNS-checked, and pinned independently. A public
        // URL cannot redirect the auditor into localhost, RFC1918, or metadata.
        response = await fetchOnce(current, controller.signal, true);
      }

      if (REDIRECT_STATUSES.has(response.status) && response.location !== undefined) {
        throw new Error(`probe redirect limit (${MAX_REDIRECTS}) exceeded`);
      }

      const totalMs = performance.now() - started;
      const ttfbMs = response.firstBodyByteAtMs === undefined ? totalMs : response.firstBodyByteAtMs - started;

      return {
        url,
        finalUrl: current,
        status: response.status,
        ttfbMs: r1(ttfbMs),
        totalMs: r1(totalMs),
        bodyBytes: response.bodyBytes,
        redirectCount,
        redirectChain,
        headers: response.headers,
        fetchedAt,
      };
    } finally {
      clearTimeout(timer);
    }
  }

  tlsInspect(host: string, timeoutMs: number): Promise<TlsInfo> {
    return this.tlsInspectSafe(host, timeoutMs);
  }

  private async tlsInspectSafe(host: string, timeoutMs: number): Promise<TlsInfo> {
    const checked = assertSafeProbeUrl(`https://${host}/`);
    const resolved = await resolvePublicAddress(checked.hostname);
    return new Promise<TlsInfo>((resolve, reject) => {
      const socket = tlsConnect({ host: resolved.address, port: 443, servername: checked.hostname, timeout: timeoutMs });
      let settled = false;
      const fail = (err: Error) => {
        if (settled) return;
        settled = true;
        socket.destroy();
        reject(err);
      };
      socket.on("timeout", () => fail(new Error(`TLS connect to ${host}:443 timed out after ${timeoutMs}ms`)));
      socket.on("error", fail);
      socket.once("secureConnect", () => {
        try {
          const cert = socket.getPeerCertificate();
          const protocol = socket.getProtocol() ?? "unknown";
          if (!cert || typeof cert.valid_to !== "string" || cert.valid_to.length === 0) {
            throw new Error(`no peer certificate presented by ${host}`);
          }
          const validToMs = Date.parse(cert.valid_to);
          if (Number.isNaN(validToMs)) throw new Error(`unparseable certificate valid_to "${cert.valid_to}"`);
          const issuerRaw = cert.issuer?.O ?? cert.issuer?.CN; // @types/node allows string | string[]
          const issuer = Array.isArray(issuerRaw) ? issuerRaw.join(", ") : (issuerRaw ?? "unknown");
          settled = true;
          socket.end();
          resolve({
            host: checked.hostname,
            validTo: new Date(validToMs).toISOString(),
            daysRemaining: Math.floor((validToMs - Date.now()) / 86_400_000),
            issuer,
            protocol,
            checkedAt: new Date().toISOString(),
          });
        } catch (err) {
          fail(err as Error);
        }
      });
    });
  }
}

interface SafeHttpResponse {
  status: number;
  headers: Record<string, string>;
  location?: string;
  bodyBytes: number;
  firstBodyByteAtMs?: number;
}

function normalizedHeaders(headers: IncomingHttpHeaders): Record<string, string> {
  return Object.fromEntries(Object.entries(headers).flatMap(([key, value]) => value === undefined ? [] : [[key, Array.isArray(value) ? value.join(", ") : value]]));
}

async function fetchOnce(url: string, signal: AbortSignal, discardRedirectBody: boolean): Promise<SafeHttpResponse> {
  const parsed = assertSafeProbeUrl(url);
  const resolved = await resolvePublicAddress(parsed.hostname);
  return new Promise<SafeHttpResponse>((resolve, reject) => {
    const request = (parsed.protocol === "https:" ? httpsRequest : httpRequest)(parsed, {
      method: "GET",
      signal,
      headers: {
        "user-agent": USER_AGENT,
        accept: "text/html,application/xhtml+xml,*/*;q=0.8",
        "accept-encoding": "gzip, br",
      },
      // Pin the TCP connection to the address that was just checked. This
      // closes the DNS-rebinding gap between validation and connection.
      lookup: (_hostname, _options, callback) => callback(null, resolved.address, resolved.family),
    }, (response) => {
      const headers = normalizedHeaders(response.headers);
      const location = headers.location;
      if (discardRedirectBody && REDIRECT_STATUSES.has(response.statusCode ?? 0) && location !== undefined) {
        response.destroy();
        resolve({ status: response.statusCode ?? 0, headers, location, bodyBytes: 0 });
        return;
      }
      let bodyBytes = 0;
      let firstBodyByteAtMs: number | undefined;
      response.on("data", (chunk: Buffer) => {
        firstBodyByteAtMs ??= performance.now();
        bodyBytes += chunk.byteLength;
        if (bodyBytes > MAX_BODY_BYTES) request.destroy(new Error(`probe response exceeds ${MAX_BODY_BYTES} bytes`));
      });
      response.on("end", () => resolve({ status: response.statusCode ?? 0, headers, location, bodyBytes, firstBodyByteAtMs }));
      response.on("error", reject);
    });
    request.on("error", reject);
    request.end();
  });
}

// ---------------------------------------------------------------------------
// Fake adapter — canned measurements for offline tests
// ---------------------------------------------------------------------------

export type FakeProbe = ProbeResult | { fail: string };
export type FakeTls = TlsInfo | { fail: string };

/**
 * Probes are keyed by the EXACT requested URL and consumed sequentially
 * (the last entry repeats), so a test can hand each timing sample a
 * different latency. Unconfigured URLs/hosts throw, like a network failure.
 */
export class FakeProber implements ProberPort {
  readonly probed: string[] = [];
  private readonly cursors = new Map<string, number>();

  constructor(
    private readonly probes: Record<string, FakeProbe[]>,
    private readonly tls: Record<string, FakeTls> = {},
  ) {}

  async probe(url: string, _timeoutMs: number): Promise<ProbeResult> {
    this.probed.push(url);
    const list = this.probes[url];
    if (!list || list.length === 0) throw new Error(`FakeProber: no probes configured for ${url}`);
    const i = Math.min(this.cursors.get(url) ?? 0, list.length - 1);
    this.cursors.set(url, i + 1);
    const entry = list[i];
    if ("fail" in entry) throw new Error(entry.fail);
    return { ...entry, headers: { ...entry.headers }, redirectChain: [...entry.redirectChain] };
  }

  async tlsInspect(host: string, _timeoutMs: number): Promise<TlsInfo> {
    const cfg = this.tls[host];
    if (!cfg) throw new Error(`FakeProber: no TLS configured for ${host}`);
    if ("fail" in cfg) throw new Error(cfg.fail);
    return { ...cfg };
  }
}
