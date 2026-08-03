/**
 * TTL cache for raw list bodies. Sanctions lists are megabytes and change
 * daily at most, so downloads land in `roster/compliance/out/cache/`
 * (gitignored) keyed by sha256(url), with a 24h TTL. The cache stores the
 * ORIGINAL fetch time alongside the body, so the attestation made over the
 * cached bytes keeps an honest fetchedAt and the report can say
 * "cached, originally fetched at T".
 *
 * A stale, corrupt, or shape-invalid entry reads as a miss (null) — never
 * an error; the caller just re-downloads.
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { sha256Hex } from "../oracle-desk/attested-fetch.js";

/** Default freshness window: 24 hours. */
export const CACHE_TTL_MS = 24 * 60 * 60 * 1000;

export interface CachedBody {
  url: string;
  /** ISO-8601 time the body was originally fetched. */
  fetchedAt: string;
  body: string;
}

export function cacheEntryPath(dir: string, url: string): string {
  return join(dir, `${sha256Hex(url)}.json`);
}

/**
 * Read a cached body. Returns null when missing, stale (older than `ttlMs`
 * relative to `nowMs`), corrupt (unparseable JSON), shape-invalid, from-the-
 * future, or stored for a different url (hash collision paranoia).
 */
export async function readCachedBody(
  dir: string,
  url: string,
  ttlMs: number = CACHE_TTL_MS,
  nowMs: number = Date.now(),
): Promise<CachedBody | null> {
  let raw: string;
  try {
    raw = await readFile(cacheEntryPath(dir, url), "utf8");
  } catch {
    return null; // missing
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null; // corrupt
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
  const entry = parsed as Record<string, unknown>;
  if (entry.version !== 1) return null;
  if (entry.url !== url) return null;
  if (typeof entry.fetchedAt !== "string" || typeof entry.body !== "string") return null;

  const fetchedMs = Date.parse(entry.fetchedAt);
  if (Number.isNaN(fetchedMs)) return null;
  const age = nowMs - fetchedMs;
  if (age < 0 || age > ttlMs) return null; // stale (or clock nonsense)

  return { url, fetchedAt: entry.fetchedAt, body: entry.body };
}

/** Write (or overwrite) a cache entry; creates `dir` recursively. */
export async function writeCachedBody(dir: string, url: string, fetchedAt: string, body: string): Promise<void> {
  await mkdir(dir, { recursive: true });
  const entry = { version: 1, url, fetchedAt, body };
  await writeFile(cacheEntryPath(dir, url), JSON.stringify(entry), "utf8");
}
