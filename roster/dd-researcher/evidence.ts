/**
 * Evidence gathering — every upstream observation flows through the injected
 * AttestedFetchPort and lands as an EvidenceItem (attested), or, when the
 * fetch itself throws, as a SourceGap. Extraction is defensive: a 2xx body
 * in an unexpected shape downgrades the item to `ok: false` instead of
 * crashing the run.
 *
 * Sources are keyless public APIs:
 *   npm-package  → registry.npmjs.org doc, api.npmjs.org download counts,
 *                  api.github.com Global Advisory DB (security advisories that
 *                  name the package), api.github.com repo metadata (when the
 *                  registry doc links a GitHub repo; both GitHub calls are
 *                  unauthenticated, so 403 rate limits are expected and handled
 *                  as attested unavailability)
 *   crypto-token → api.coingecko.com coin document
 */
import { sha256Hex } from "../oracle-desk/attested-fetch.js";
import type {
  AttestedFetchPort,
  AttestedFetchResult,
  EvidenceItem,
  EvidenceSource,
  SourceGap,
  Subject,
} from "./types.js";

/** Bodies larger than this are dropped from the report (hash retained). */
export const MAX_STORED_BODY_CHARS = 64_000;

export interface GatheredEvidence {
  evidence: EvidenceItem[];
  gaps: SourceGap[];
}

// ---------------------------------------------------------------------------
// Collector
// ---------------------------------------------------------------------------

class Collector {
  readonly evidence: EvidenceItem[] = [];
  readonly gaps: SourceGap[] = [];

  constructor(private readonly port: AttestedFetchPort) {}

  /**
   * Fetch + attest one source. Returns the EvidenceItem, or undefined when
   * the fetch threw (recorded as a SourceGap).
   */
  async collect(
    source: EvidenceSource,
    url: string,
    extract: (body: string) => Record<string, unknown>,
  ): Promise<EvidenceItem | undefined> {
    let result: AttestedFetchResult;
    try {
      result = await this.port.attestFetch(url);
    } catch (err) {
      this.gaps.push({ source, url, reason: (err as Error).message });
      return undefined;
    }

    let ok = result.status >= 200 && result.status < 300;
    let extracted: Record<string, unknown>;
    if (ok) {
      try {
        extracted = extract(result.body);
      } catch (err) {
        ok = false;
        extracted = { unavailable: true, reason: `unexpected body shape: ${(err as Error).message}` };
      }
    } else {
      extracted = { unavailable: true, httpStatus: result.status };
    }

    if (sha256Hex(result.body) !== result.bodyHash) {
      // The port misbehaved — surface loudly rather than emit bad evidence.
      throw new Error(`AttestedFetchPort returned a bodyHash that does not match the body for ${url}`);
    }

    const item: EvidenceItem = {
      id: `E${this.evidence.length + 1}`,
      source,
      url,
      fetchedAt: result.fetchedAt,
      status: result.status,
      ok,
      bodyHash: result.bodyHash,
      ...(result.body.length <= MAX_STORED_BODY_CHARS ? { body: result.body } : {}),
      extracted,
      attestation: result.attestation,
    };
    this.evidence.push(item);
    return item;
  }
}

// ---------------------------------------------------------------------------
// Shape helpers (defensive JSON narrowing, node builtins only)
// ---------------------------------------------------------------------------

function parseJsonObject(body: string): Record<string, unknown> {
  const parsed: unknown = JSON.parse(body);
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("expected a JSON object");
  }
  return parsed as Record<string, unknown>;
}

function asObject(v: unknown): Record<string, unknown> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

function asString(v: unknown): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}

function asNumber(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

/** npm `license` / `repository` fields come as strings or objects. */
function normalizeLicense(v: unknown): string | null {
  return asString(v) ?? asString(asObject(v)?.type) ?? null;
}

function normalizeRepoUrl(v: unknown): string | null {
  return asString(v) ?? asString(asObject(v)?.url) ?? null;
}

/** "git+https://github.com/expressjs/express.git" → "expressjs/express". */
export function parseGithubRepo(url: string | null): string | null {
  if (!url) return null;
  const m = /github\.com[/:]([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?(?:[/#?].*)?$/.exec(url);
  return m ? `${m[1]}/${m[2]}` : null;
}

// ---------------------------------------------------------------------------
// Extractors
// ---------------------------------------------------------------------------

export function extractNpmRegistry(body: string): Record<string, unknown> {
  const doc = parseJsonObject(body);
  const distTags = asObject(doc["dist-tags"]);
  const latestVersion = asString(distTags?.latest);
  const versions = asObject(doc.versions);
  const latest = latestVersion ? asObject(versions?.[latestVersion]) : null;
  const time = asObject(doc.time);
  const maintainers = Array.isArray(doc.maintainers) ? doc.maintainers : null;
  const repositoryUrl = normalizeRepoUrl(latest?.repository ?? doc.repository);
  const deprecatedMessage = asString(latest?.deprecated);

  return {
    name: asString(doc.name),
    latestVersion,
    deprecated: latest ? latest.deprecated !== undefined && latest.deprecated !== false : false,
    deprecatedMessage,
    license: normalizeLicense(latest?.license ?? doc.license),
    // First-publish timestamp of the whole package — a brand-new package is a
    // supply-chain risk regardless of how fresh its latest release is.
    createdAt: asString(time?.created),
    lastPublishAt: (latestVersion ? asString(time?.[latestVersion]) : null) ?? asString(time?.modified),
    maintainersCount: maintainers ? maintainers.length : null,
    versionCount: versions ? Object.keys(versions).length : null,
    repositoryUrl,
    githubRepo: parseGithubRepo(repositoryUrl),
  };
}

/**
 * GitHub Global Advisory DB — the array returned by
 * `GET /advisories?ecosystem=npm&affects=<name>`. Each entry names a GHSA id,
 * a severity, a summary, and the affected version ranges. We keep a bounded,
 * highest-severity-first sample plus the worst severity for the finding rule.
 */
const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, moderate: 2, low: 1 };

function normalizeAdvisorySeverity(v: unknown): string {
  const s = (asString(v) ?? "unknown").toLowerCase();
  return s === "moderate" ? "medium" : s;
}

export function extractGithubAdvisories(body: string): Record<string, unknown> {
  const parsed: unknown = JSON.parse(body);
  if (!Array.isArray(parsed)) throw new Error("expected a JSON array of advisories");

  const advisories = parsed.map((raw) => {
    const a = asObject(raw) ?? {};
    const vulns = Array.isArray(a.vulnerabilities) ? a.vulnerabilities : [];
    const firstRange = asString(asObject(vulns[0])?.vulnerable_version_range);
    return {
      ghsaId: asString(a.ghsa_id) ?? asString(a.cve_id) ?? "unknown-advisory",
      severity: normalizeAdvisorySeverity(a.severity),
      summary: (asString(a.summary) ?? "(no summary)").slice(0, 200),
      vulnerableRange: firstRange,
    };
  });
  advisories.sort((x, y) => (SEVERITY_RANK[y.severity] ?? 0) - (SEVERITY_RANK[x.severity] ?? 0));

  const worstSeverity =
    advisories.reduce((worst, a) => Math.max(worst, SEVERITY_RANK[a.severity] ?? 0), 0);
  const worstLabel = Object.entries(SEVERITY_RANK).find(([, r]) => r === worstSeverity)?.[0] ?? null;

  return {
    advisoryCount: advisories.length,
    worstSeverity: advisories.length > 0 ? worstLabel : null,
    // Bound the stored sample so a package with a long advisory history does
    // not bloat the report; the count above is the exhaustive figure.
    advisories: advisories.slice(0, 5),
  };
}

export function extractNpmDownloads(body: string): Record<string, unknown> {
  const doc = parseJsonObject(body);
  return {
    downloadsLastMonth: asNumber(doc.downloads),
    start: asString(doc.start),
    end: asString(doc.end),
  };
}

export function extractGithubRepo(body: string): Record<string, unknown> {
  const doc = parseJsonObject(body);
  return {
    fullName: asString(doc.full_name),
    stars: asNumber(doc.stargazers_count),
    openIssues: asNumber(doc.open_issues_count),
    forks: asNumber(doc.forks_count),
    pushedAt: asString(doc.pushed_at),
    archived: doc.archived === true,
    license: asString(asObject(doc.license)?.spdx_id),
  };
}

export function extractCoingeckoCoin(body: string): Record<string, unknown> {
  const doc = parseJsonObject(body);
  const market = asObject(doc.market_data);
  const community = asObject(doc.community_data);
  const dev = asObject(doc.developer_data);
  return {
    id: asString(doc.id),
    symbol: asString(doc.symbol),
    name: asString(doc.name),
    marketCapRank: asNumber(doc.market_cap_rank),
    priceUsd: asNumber(asObject(market?.current_price)?.usd),
    marketCapUsd: asNumber(asObject(market?.market_cap)?.usd),
    volume24hUsd: asNumber(asObject(market?.total_volume)?.usd),
    // Fully-diluted valuation vs circulating market cap: a large gap means most
    // of the supply is not yet circulating — future-dilution / unlock overhang.
    fullyDilutedValuationUsd: asNumber(asObject(market?.fully_diluted_valuation)?.usd),
    athUsd: asNumber(asObject(market?.ath)?.usd),
    athChangePct: asNumber(asObject(market?.ath_change_percentage)?.usd),
    twitterFollowers: asNumber(community?.twitter_followers),
    telegramUsers: asNumber(community?.telegram_channel_user_count),
    devStars: asNumber(dev?.stars),
    devCommits4w: asNumber(dev?.commit_count_4_weeks),
    // Distinct people who opened merged PRs — bus-factor of the token's code.
    devPullRequestContributors: asNumber(dev?.pull_request_contributors),
  };
}

// ---------------------------------------------------------------------------
// Gatherers
// ---------------------------------------------------------------------------

export function npmRegistryUrl(name: string): string {
  return `https://registry.npmjs.org/${encodeURIComponent(name)}`;
}

export function npmDownloadsUrl(name: string): string {
  return `https://api.npmjs.org/downloads/point/last-month/${encodeURIComponent(name)}`;
}

export function githubRepoUrl(ownerRepo: string): string {
  return `https://api.github.com/repos/${ownerRepo}`;
}

export function githubAdvisoriesUrl(name: string): string {
  return `https://api.github.com/advisories?ecosystem=npm&affects=${encodeURIComponent(name)}&per_page=100`;
}

export function coingeckoCoinUrl(id: string): string {
  return (
    `https://api.coingecko.com/api/v3/coins/${encodeURIComponent(id)}` +
    `?localization=false&tickers=false&market_data=true&community_data=true&developer_data=true`
  );
}

export async function gatherEvidence(port: AttestedFetchPort, subject: Subject): Promise<GatheredEvidence> {
  const collector = new Collector(port);

  if (subject.kind === "npm-package") {
    const registry = await collector.collect("npm-registry", npmRegistryUrl(subject.name), extractNpmRegistry);
    await collector.collect("npm-downloads", npmDownloadsUrl(subject.name), extractNpmDownloads);
    // Security advisories are keyed by package name (not the repo link), so this
    // runs even when the registry doc has no resolvable GitHub repository.
    await collector.collect("github-advisories", githubAdvisoriesUrl(subject.name), extractGithubAdvisories);

    const githubRepo = registry?.ok ? (registry.extracted.githubRepo as string | null) : null;
    if (githubRepo) {
      await collector.collect("github-repo", githubRepoUrl(githubRepo), extractGithubRepo);
    }
  } else {
    await collector.collect("coingecko-coin", coingeckoCoinUrl(subject.id), extractCoingeckoCoin);
  }

  return { evidence: collector.evidence, gaps: collector.gaps };
}
