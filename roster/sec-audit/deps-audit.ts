/**
 * Dependency risk — the target's package.json run through dep-upgrade's
 * RegistryPort (REAL npm bulk-advisory endpoint, or its canned fake for
 * tests/offline). One hit per vulnerable dependency, listing every advisory
 * id + severity; the hit is pinned to the dependency's line in package.json
 * so the finding cites the attested package.json record.
 *
 * Degradation contract:
 *  - no package.json in the target  → mode "skipped", no hits, no error;
 *  - advisory endpoint unreachable  → mode "unreachable", no hits, no error;
 *  - deps whose declared range can't be reduced to a concrete version
 *    (no lockfile + complex range) are skipped per-dep and noted.
 */
import { parseInventory } from "../dep-upgrade/inventory.js";
import { parseSemver, satisfies } from "../dep-upgrade/semver.js";
import type { Advisory, RegistryPort } from "../dep-upgrade/types.js";
import type { DepsAuditMode, RawHit, RuleMeta, Severity } from "./types.js";

export const DEP_RULE: RuleMeta = {
  id: "dep-vulnerable",
  severity: "high", // table default; each hit carries the max advisory severity
  description: "Dependency has published security advisories affecting the used version",
};

const NPM_TO_SEVERITY: Record<Advisory["severity"], Severity> = {
  critical: "critical",
  high: "high",
  moderate: "medium",
  low: "low",
  unknown: "low",
};

function maxSeverity(advisories: Advisory[]): Severity {
  const order: Severity[] = ["critical", "high", "medium", "low", "info"];
  let best: Severity = "low";
  for (const a of advisories) {
    const s = NPM_TO_SEVERITY[a.severity];
    if (order.indexOf(s) < order.indexOf(best)) best = s;
  }
  return best;
}

/** `^4.17.20` / `~1.2.3` / `=1.0.0` / `v2.0.0` → the bare version, if concrete. */
export function bareVersionFromRange(range: string): string | null {
  const stripped = range.trim().replace(/^[\^~=v\s]+/, "");
  return parseSemver(stripped) ? stripped : null;
}

/** Find the 1-based line where `"<name>"` is declared in package.json text. */
export function findDepLine(pkgJsonText: string, name: string): { line: number; excerpt: string } {
  const needle = `"${name}"`;
  const lines = pkgJsonText.split("\n");
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes(needle) && lines[i].includes(":")) {
      return { line: i + 1, excerpt: lines[i].trim() };
    }
  }
  return { line: 1, excerpt: needle };
}

export interface DepsAuditResult {
  mode: DepsAuditMode;
  note: string;
  hits: RawHit[];
}

/**
 * Audit the dependencies declared in `pkgJsonText` (pass null when the
 * target has no package.json). `registryLabel` states which adapter the
 * caller wired ("live" real endpoint vs "canned" fake) so the report can
 * say which mode produced the advisory data.
 */
export async function auditDependencies(
  pkgJsonText: string | null,
  lockText: string | undefined,
  registry: RegistryPort | null,
  registryLabel: "live" | "canned",
): Promise<DepsAuditResult> {
  if (pkgJsonText === null) {
    return { mode: "skipped", note: "no package.json in target — dependency audit skipped", hits: [] };
  }
  if (registry === null) {
    return { mode: "skipped", note: "no registry port wired — dependency audit skipped", hits: [] };
  }

  let inventory;
  try {
    inventory = parseInventory("(target)", pkgJsonText, lockText);
  } catch (err) {
    return { mode: "skipped", note: `package.json unparseable (${(err as Error).message})`, hits: [] };
  }

  const versionsByDep = new Map<string, string>();
  const unresolvable: string[] = [];
  for (const dep of inventory.deps) {
    const version = dep.installedVersion ?? bareVersionFromRange(dep.range);
    if (version) versionsByDep.set(dep.name, version);
    else unresolvable.push(`${dep.name}@${dep.range}`);
  }
  if (versionsByDep.size === 0) {
    return {
      mode: "skipped",
      note:
        inventory.deps.length === 0
          ? "package.json declares no dependencies"
          : `no dependency resolved to a concrete version (${unresolvable.join(", ")})`,
      hits: [],
    };
  }

  const query: Record<string, string[]> = {};
  for (const [name, version] of versionsByDep) query[name] = [version];

  let advisoryMap: Map<string, Advisory[]>;
  try {
    advisoryMap = await registry.getAdvisories(query);
  } catch (err) {
    return {
      mode: "unreachable",
      note: `advisory endpoint unreachable (${(err as Error).message}) — dependency audit degraded to none`,
      hits: [],
    };
  }

  const hits: RawHit[] = [];
  for (const [name, version] of versionsByDep) {
    const raw = advisoryMap.get(name) ?? [];
    // The bulk endpoint already filters by the versions sent, but re-check
    // defensively so canned adapters with broad lists behave identically.
    const applicable = raw.filter((a) => satisfies(version, a.vulnerableVersions));
    if (applicable.length === 0) continue;
    const listing = applicable.map((a) => `${a.id} (${a.severity}): ${a.title}`).join("; ");
    const { line, excerpt } = findDepLine(pkgJsonText, name);
    hits.push({
      ruleId: DEP_RULE.id,
      severity: maxSeverity(applicable),
      file: "package.json",
      line,
      excerpt,
      rationale: `${name}@${version} is affected by ${applicable.length} published advisor${applicable.length === 1 ? "y" : "ies"} — ${listing}. Upgrade to a version clearing all of them.`,
    });
  }

  const noteParts = [`${versionsByDep.size} dependenc${versionsByDep.size === 1 ? "y" : "ies"} checked via ${registryLabel} advisory data`];
  if (unresolvable.length > 0) noteParts.push(`unresolvable ranges skipped: ${unresolvable.join(", ")}`);
  return { mode: registryLabel, note: noteParts.join("; "), hits };
}
