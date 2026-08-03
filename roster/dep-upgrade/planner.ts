/**
 * Planner — pure function from (inventory, packuments, advisories, config)
 * to a typed UpgradePlan. No I/O; all intel arrives as arguments.
 *
 * Policy:
 *  - Vulnerable dep → nearest published stable version ABOVE current that
 *    clears ALL advisories for that package (not just the active ones — we
 *    never upgrade into a different known hole). Prefer staying inside the
 *    current major; escalate major only if unavoidable, flagged `breaking`.
 *  - Merely outdated → latest stable version satisfying the declared range.
 *  - Next-major bumps are opt-in via `config.proposeNextMajor`.
 */
import {
  compareVersions,
  isStable,
  majorOf,
  maxSatisfying,
  minSatisfying,
  parseSemver,
  satisfies,
} from "./semver.js";
import type {
  Advisory,
  DepEntry,
  DepInventory,
  DepUpgradeConfig,
  Packument,
  UpgradeItem,
  UpgradePlan,
} from "./types.js";

function stableSorted(versions: string[]): string[] {
  return versions.filter(isStable).sort(compareVersions);
}

/** Preserve the ^/~ style of the declared range when bumping it. */
export function preserveRangeStyle(currentRange: string, target: string): string {
  const trimmed = currentRange.trim();
  if (trimmed.startsWith("^")) return `^${target}`;
  if (trimmed.startsWith("~")) return `~${target}`;
  return target; // exact pins, comparators, stars → pin the verified version
}

/**
 * Resolve the concrete "current" version of a dep: the lockfile version when
 * it still satisfies the declared range, else the lowest stable version the
 * range admits (lockfile-less repos, or a stale lock).
 */
export function resolveCurrentVersion(dep: DepEntry, packument: Packument): string | null {
  if (dep.installedVersion && parseSemver(dep.installedVersion)) {
    if (satisfies(dep.installedVersion, dep.range)) return dep.installedVersion;
  }
  return minSatisfying(stableSorted(packument.versions), dep.range);
}

function fmtAdvisories(advisories: Advisory[]): string {
  return advisories.map((a) => `${a.id} (${a.severity})`).join(", ");
}

export function buildPlan(
  inventory: DepInventory,
  packuments: Map<string, Packument>,
  advisories: Map<string, Advisory[]>,
  config: DepUpgradeConfig = {},
): UpgradePlan {
  const items: UpgradeItem[] = [];
  const unactionable: UpgradePlan["unactionable"] = [];

  for (const dep of inventory.deps) {
    const packument = packuments.get(dep.name);
    if (!packument) {
      unactionable.push({ name: dep.name, reason: "no packument available from registry port" });
      continue;
    }
    const stable = stableSorted(packument.versions);
    const current = resolveCurrentVersion(dep, packument);
    if (!current) {
      unactionable.push({
        name: dep.name,
        reason: `no published stable version satisfies declared range "${dep.range}"`,
      });
      continue;
    }

    const pkgAdvisories = advisories.get(dep.name) ?? [];
    const active = pkgAdvisories.filter((a) => satisfies(current, a.vulnerableVersions));
    const clearsAll = (v: string): boolean =>
      pkgAdvisories.every((a) => !satisfies(v, a.vulnerableVersions));

    if (active.length > 0) {
      // Security path: nearest stable version above current clearing everything.
      const candidates = stable.filter((v) => compareVersions(v, current) > 0 && clearsAll(v));
      if (candidates.length === 0) {
        unactionable.push({
          name: dep.name,
          reason: `vulnerable at ${current} (${fmtAdvisories(active)}) but no published version clears all advisories`,
        });
        continue;
      }
      const currentMajor = majorOf(current);
      const sameMajor = candidates.filter((v) => majorOf(v) === currentMajor);
      const target = sameMajor[0] ?? candidates[0]!;
      const breaking = sameMajor.length === 0;
      items.push({
        name: dep.name,
        section: dep.section,
        kind: "security",
        currentVersion: current,
        currentRange: dep.range,
        targetVersion: target,
        newRange: preserveRangeStyle(dep.range, target),
        breaking,
        advisories: active,
        rationale:
          `${current} is affected by ${fmtAdvisories(active)}; ` +
          `${target} is the nearest published version clearing all known advisories` +
          (breaking ? ` — no fix exists within major ${currentMajor}, escalating majors` : ""),
      });
      continue;
    }

    // Maintenance path: latest stable inside the declared range.
    const latestInRange = maxSatisfying(stable, dep.range);
    if (latestInRange && compareVersions(latestInRange, current) > 0 && clearsAll(latestInRange)) {
      items.push({
        name: dep.name,
        section: dep.section,
        kind: "outdated",
        currentVersion: current,
        currentRange: dep.range,
        targetVersion: latestInRange,
        newRange: preserveRangeStyle(dep.range, latestInRange),
        breaking: false,
        advisories: [],
        rationale: `${latestInRange} is the latest stable version satisfying declared range "${dep.range}"`,
      });
    }

    // Opt-in next-major proposal.
    if (config.proposeNextMajor) {
      const latestStable = stable[stable.length - 1];
      if (
        latestStable &&
        majorOf(latestStable) > majorOf(current) &&
        clearsAll(latestStable)
      ) {
        items.push({
          name: dep.name,
          section: dep.section,
          kind: "next-major",
          currentVersion: current,
          currentRange: dep.range,
          targetVersion: latestStable,
          newRange: preserveRangeStyle(dep.range, latestStable),
          breaking: true,
          advisories: [],
          rationale: `opt-in next-major proposal: latest published stable is ${latestStable}`,
        });
      }
    }
  }

  // Security first (they gate everything else), then maintenance, then majors.
  const order: Record<UpgradeItem["kind"], number> = { security: 0, outdated: 1, "next-major": 2 };
  items.sort((a, b) => order[a.kind] - order[b.kind] || a.name.localeCompare(b.name));

  return { items, unactionable };
}
