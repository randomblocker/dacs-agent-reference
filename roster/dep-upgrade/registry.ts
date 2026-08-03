/**
 * RegistryPort adapters — REAL npm registry + bulk advisory endpoint, and a
 * canned fake for tests / offline fallback.
 *
 * Real endpoints (no credentials needed):
 *   GET  https://registry.npmjs.org/<pkg>            — packument (abbreviated)
 *   POST https://registry.npmjs.org/-/npm/v1/security/advisories/bulk
 *        body: { "<pkg>": ["<version>", ...] }       — advisories per package
 */
import type { Advisory, Packument, RegistryPort } from "./types.js";

const REGISTRY = "https://registry.npmjs.org";

type Severity = Advisory["severity"];

function normalizeSeverity(raw: unknown): Severity {
  const s = String(raw ?? "").toLowerCase();
  return s === "low" || s === "moderate" || s === "high" || s === "critical" ? s : "unknown";
}

interface BulkAdvisoryEntry {
  id?: unknown;
  ghsa_id?: unknown;
  url?: unknown;
  title?: unknown;
  severity?: unknown;
  vulnerable_versions?: unknown;
}

/** Map one raw bulk-endpoint entry to our Advisory shape (defensively). */
export function mapAdvisory(raw: BulkAdvisoryEntry): Advisory {
  return {
    id: String(raw.ghsa_id ?? raw.id ?? "unknown-advisory"),
    severity: normalizeSeverity(raw.severity),
    title: String(raw.title ?? "(untitled advisory)"),
    url: String(raw.url ?? ""),
    vulnerableVersions: String(raw.vulnerable_versions ?? "*"),
  };
}

export class RealRegistry implements RegistryPort {
  constructor(private readonly timeoutMs = 15_000) {}

  async getPackument(name: string): Promise<Packument> {
    const res = await fetch(`${REGISTRY}/${encodeURIComponent(name)}`, {
      headers: {
        // Abbreviated packument — versions + dist-tags without readmes.
        accept: "application/vnd.npm.install-v1+json",
      },
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!res.ok) throw new Error(`registry: GET /${name} → ${res.status}`);
    const body = (await res.json()) as {
      name?: string;
      "dist-tags"?: Record<string, string>;
      versions?: Record<string, unknown>;
    };
    const latest = body["dist-tags"]?.latest;
    if (!latest) throw new Error(`registry: /${name} has no dist-tags.latest`);
    return { name: body.name ?? name, latest, versions: Object.keys(body.versions ?? {}) };
  }

  async getAdvisories(query: Record<string, string[]>): Promise<Map<string, Advisory[]>> {
    const res = await fetch(`${REGISTRY}/-/npm/v1/security/advisories/bulk`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(query),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!res.ok) throw new Error(`registry: advisory bulk endpoint → ${res.status}`);
    const body = (await res.json()) as Record<string, BulkAdvisoryEntry[]>;
    const out = new Map<string, Advisory[]>();
    for (const [pkg, entries] of Object.entries(body)) {
      out.set(pkg, (entries ?? []).map(mapAdvisory));
    }
    return out;
  }
}

// ---------------------------------------------------------------------------
// Fake adapter — canned data for tests and offline demo fallback
// ---------------------------------------------------------------------------

export class FakeRegistry implements RegistryPort {
  constructor(
    private readonly packuments: Record<string, Packument>,
    private readonly advisories: Record<string, Advisory[]> = {},
  ) {}

  async getPackument(name: string): Promise<Packument> {
    const p = this.packuments[name];
    if (!p) throw new Error(`fake registry: no packument for ${name}`);
    return p;
  }

  async getAdvisories(query: Record<string, string[]>): Promise<Map<string, Advisory[]>> {
    const out = new Map<string, Advisory[]>();
    for (const pkg of Object.keys(query)) {
      const list = this.advisories[pkg];
      if (list && list.length > 0) out.set(pkg, list);
    }
    return out;
  }
}

/**
 * Canned lodash data for the demo's offline fallback — mirrors the real
 * published advisory history around 4.17.20 (GHSA-35jh-r3h4-6jhm, command
 * injection, fixed in 4.17.21).
 */
export function lodashFallbackRegistry(): FakeRegistry {
  return new FakeRegistry(
    {
      lodash: {
        name: "lodash",
        latest: "4.17.21",
        versions: ["4.17.15", "4.17.19", "4.17.20", "4.17.21"],
      },
    },
    {
      lodash: [
        {
          id: "GHSA-35jh-r3h4-6jhm",
          severity: "high",
          title: "Command Injection in lodash",
          url: "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
          vulnerableVersions: "<4.17.21",
        },
        {
          id: "GHSA-29mw-wpgm-hmr9",
          severity: "moderate",
          title: "Regular Expression Denial of Service (ReDoS) in lodash",
          url: "https://github.com/advisories/GHSA-29mw-wpgm-hmr9",
          vulnerableVersions: "<4.17.21",
        },
      ],
    },
  );
}
