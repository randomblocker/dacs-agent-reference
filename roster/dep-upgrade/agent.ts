/**
 * Dependency-Upgrade Agent — orchestrator.
 *
 * Pipeline: inventory → registry intel (packuments + bulk advisories) →
 * upgrade plan → apply+verify per item → PR delivery through the GitHubPort
 * (branch `dep-upgrade/<date>`, one commit with the new package.json, PR body
 * citing advisories and the verify evidence). No PR when nothing survives
 * verification.
 */
import { readInventory } from "./inventory.js";
import { buildPlan, resolveCurrentVersion } from "./planner.js";
import { applyAndVerify } from "./apply-verify.js";
import type {
  Advisory,
  CommandRunner,
  DepUpgradeConfig,
  DepUpgradeReport,
  GitHubPort,
  ItemResult,
  Packument,
  RegistryPort,
  RepoRef,
  UpgradePlan,
} from "./types.js";

export interface RunOptions {
  /** Target repo working copy (directory containing package.json). */
  dir: string;
  /** Repo the PR is delivered against (via the GitHubPort). */
  repo: RepoRef;
  config?: DepUpgradeConfig;
  registry: RegistryPort;
  runner: CommandRunner;
  github: GitHubPort;
  /** Branch-date override for deterministic tests (YYYY-MM-DD). */
  today?: string;
}

export function branchName(today?: string): string {
  const date = today ?? new Date().toISOString().slice(0, 10);
  return `dep-upgrade/${date}`;
}

// ---------------------------------------------------------------------------
// PR body
// ---------------------------------------------------------------------------

function advisoryLines(advisories: Advisory[]): string[] {
  return advisories.map((a) => `  - ${a.id} (**${a.severity}**): ${a.title}${a.url ? ` — ${a.url}` : ""}`);
}

function evidenceLines(result: ItemResult): string[] {
  const lines = result.verify.map(
    (v) => `  - \`${v.command}\` → exit ${v.exitCode}${v.exitCode === 0 ? " (green)" : " (RED)"}`,
  );
  if (!result.applied) {
    lines.push(`  - reverted after \`${result.failedAt}\` failed; output tail:`);
    lines.push("    ```");
    lines.push(...(result.outputTail ?? "(no output)").split("\n").map((l) => `    ${l}`));
    lines.push("    ```");
  }
  return lines;
}

export function renderPrBody(plan: UpgradePlan, results: ItemResult[]): string {
  const lines: string[] = [];
  const applied = results.filter((r) => r.applied);
  const failed = results.filter((r) => !r.applied);

  lines.push("## Dependency upgrades");
  lines.push("");
  lines.push(
    `${applied.length} upgrade(s) verified green and included; ` +
      `${failed.length} attempted but reverted after a red verify.`,
  );

  const section = (title: string, group: ItemResult[]) => {
    if (group.length === 0) return;
    lines.push("", `### ${title}`, "");
    for (const r of group) {
      const it = r.item;
      lines.push(
        `- **${it.name}** \`${it.currentRange}\` (${it.currentVersion}) → \`${it.newRange}\` (${it.targetVersion})` +
          ` — ${it.kind}${it.breaking ? ", **BREAKING (major escalation)**" : ""}`,
      );
      lines.push(`  - rationale: ${it.rationale}`);
      if (it.advisories.length > 0) {
        lines.push("  - advisories cleared:");
        lines.push(...advisoryLines(it.advisories).map((l) => `  ${l}`));
      }
      lines.push("  - verify evidence:");
      lines.push(...evidenceLines(r).map((l) => `  ${l}`));
    }
  };

  section("Included (verified green)", applied);
  section("Reverted (verification failed — needs a human)", failed);

  if (plan.unactionable.length > 0) {
    lines.push("", "### Unactionable", "");
    for (const u of plan.unactionable) lines.push(`- **${u.name}**: ${u.reason}`);
  }

  lines.push("", "---", "_Opened by the Dependency-Upgrade Agent (mock GitHub delivery)._");
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

export async function runDepUpgrade(opts: RunOptions): Promise<DepUpgradeReport> {
  const { dir, repo, registry, runner, github } = opts;
  const config = opts.config ?? {};

  // 1. Inventory
  const inventory = await readInventory(dir);

  // 2. Registry intel: packuments first (needed to resolve concrete current
  //    versions for lockfile-less repos), then one bulk advisory query.
  const packuments = new Map<string, Packument>();
  for (const dep of inventory.deps) {
    if (!packuments.has(dep.name)) packuments.set(dep.name, await registry.getPackument(dep.name));
  }
  const advisoryQuery: Record<string, string[]> = {};
  for (const dep of inventory.deps) {
    const packument = packuments.get(dep.name)!;
    const current = resolveCurrentVersion(dep, packument);
    if (current) advisoryQuery[dep.name] = [...(advisoryQuery[dep.name] ?? []), current];
  }
  const advisories =
    Object.keys(advisoryQuery).length > 0
      ? await registry.getAdvisories(advisoryQuery)
      : new Map<string, Advisory[]>();

  // 3. Plan
  const plan = buildPlan(inventory, packuments, advisories, config);

  // 4. Apply + verify
  const { results, finalPackageJson, changed } =
    plan.items.length > 0
      ? await applyAndVerify(dir, plan.items, runner)
      : { results: [], finalPackageJson: "", changed: false };

  // 5. PR delivery — only when something survived verification.
  const prBody = renderPrBody(plan, results);
  let pr: DepUpgradeReport["pr"] = null;
  if (changed) {
    const branch = branchName(opts.today);
    const { default_branch } = await github.getRepo(repo);
    await github.createBranch(repo, branch, default_branch);
    const applied = results.filter((r) => r.applied);
    await github.commitFiles(
      repo,
      branch,
      `deps: upgrade ${applied.map((r) => `${r.item.name}@${r.item.targetVersion}`).join(", ")}`,
      [{ path: "package.json", content: finalPackageJson }],
    );
    const opened = await github.openPR(repo, {
      head: branch,
      base: default_branch,
      title: `deps: ${applied.length} verified upgrade(s) — ${applied.map((r) => r.item.name).join(", ")}`,
      body: prBody,
    });
    pr = { ...opened, branch };
  }

  return { inventory, plan, results, prBody, pr };
}
