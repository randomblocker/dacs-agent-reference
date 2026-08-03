/**
 * Shared attestation / DNS primitives.
 *
 * Neutral building blocks that several agents depend on: site-auditor
 * (canonicalJson, withTimeout), the gateway (DnsPort, RealDns), and the DACS
 * ecosystem / live harnesses (FakeDns, RealDns). They were originally defined
 * inside the lead-enrich agent's sources.ts / types.ts; when that agent was
 * dropped these were lifted out here verbatim — this is a relocation, not a
 * rewrite, so the code is identical to what those files held.
 */
import { resolveMx as nodeResolveMx, resolveTxt as nodeResolveTxt } from "node:dns/promises";

// ---------------------------------------------------------------------------
// Timeout guard (shared by the real DNS adapter and the demos)
// ---------------------------------------------------------------------------

export async function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  // Register a no-op handler so a late rejection of the losing promise
  // cannot become an unhandled rejection.
  void promise.catch(() => {});
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

// ---------------------------------------------------------------------------
// Canonical JSON
// ---------------------------------------------------------------------------

/** Deterministic JSON: object keys sorted recursively. */
export function canonicalJson(v: unknown): string {
  const sortValue = (x: unknown): unknown => {
    if (Array.isArray(x)) return x.map(sortValue);
    if (typeof x === "object" && x !== null) {
      const rec = x as Record<string, unknown>;
      return Object.fromEntries(
        Object.keys(rec)
          .sort()
          .map((k) => [k, sortValue(rec[k])]),
      );
    }
    return x;
  };
  return JSON.stringify(sortValue(v));
}

// ---------------------------------------------------------------------------
// DNS port
// ---------------------------------------------------------------------------

export interface MxRecord {
  exchange: string;
  priority: number;
}

/**
 * DNS resolution port. Real adapter wraps node:dns/promises; fake serves
 * canned answers (and canned resolver errors) for offline tests. Adapters
 * throw Node-style errors with a `code` (ENODATA/ENOTFOUND mean "no such
 * records" and are treated as an empty — but still attested — answer).
 */
export interface DnsPort {
  resolveMx(domain: string): Promise<MxRecord[]>;
  /** node:dns shape: one string[] of chunks per TXT record. */
  resolveTxt(domain: string): Promise<string[][]>;
}

// ---------------------------------------------------------------------------
// DNS adapters
// ---------------------------------------------------------------------------

/** Resolver codes that mean "no such records" — an answer, not a failure. */
export const DNS_EMPTY_CODES: ReadonlyArray<string> = ["ENODATA", "ENOTFOUND"];

export class RealDns implements DnsPort {
  constructor(private readonly timeoutMs = 6_000) {}

  resolveMx(domain: string): Promise<MxRecord[]> {
    return withTimeout(nodeResolveMx(domain), this.timeoutMs, `DNS MX ${domain}`);
  }

  resolveTxt(domain: string): Promise<string[][]> {
    return withTimeout(nodeResolveTxt(domain), this.timeoutMs, `DNS TXT ${domain}`);
  }
}

export function dnsError(code: string, message: string): NodeJS.ErrnoException {
  return Object.assign(new Error(message), { code });
}

export interface FakeDnsConfig {
  mx?: MxRecord[] | { errorCode: string };
  txt?: string[][] | { errorCode: string };
}

/** Canned resolver for offline tests; unconfigured lookups throw ENOTFOUND. */
export class FakeDns implements DnsPort {
  constructor(private readonly byDomain: Record<string, FakeDnsConfig>) {}

  async resolveMx(domain: string): Promise<MxRecord[]> {
    const cfg = this.byDomain[domain]?.mx;
    if (cfg === undefined) throw dnsError("ENOTFOUND", `queryMx ENOTFOUND ${domain}`);
    if (!Array.isArray(cfg)) throw dnsError(cfg.errorCode, `queryMx ${cfg.errorCode} ${domain}`);
    return cfg;
  }

  async resolveTxt(domain: string): Promise<string[][]> {
    const cfg = this.byDomain[domain]?.txt;
    if (cfg === undefined) throw dnsError("ENOTFOUND", `queryTxt ENOTFOUND ${domain}`);
    if (!Array.isArray(cfg)) throw dnsError(cfg.errorCode, `queryTxt ${cfg.errorCode} ${domain}`);
    return cfg;
  }
}
