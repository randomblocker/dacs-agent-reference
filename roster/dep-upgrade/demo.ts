/**
 * Dependency-Upgrade Agent demo — real end-to-end against the bundled
 * fixture package (lodash pinned to 4.17.20, a version with real published
 * advisories):
 *
 *   npm run roster:depup
 *
 * REAL parts: npm bulk advisory endpoint + registry packuments (RegistryPort)
 * and actual `npm install` + `npm test` runs in the fixture dir
 * (CommandRunner). MOCK part: PR delivery (in-memory GitHub host).
 *
 * If the advisory endpoint is unreachable the demo warns and falls back to
 * the canned FakeRegistry so it still completes (exit 0 either way); the
 * banner states clearly which mode ran. The fixture is restored to its
 * committed state at the end (original package.json rewritten, generated
 * lockfile removed) so the demo is re-runnable.
 */
import { readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { runDepUpgrade } from "./agent.js";
import { RealCommandRunner } from "./apply-verify.js";
import { MockGitHubHost } from "./github-port.js";
import { RealRegistry, lodashFallbackRegistry } from "./registry.js";
import type { RegistryPort } from "./types.js";

const hr = (title: string) => console.log(`\n=== ${title} ${"=".repeat(Math.max(0, 60 - title.length))}`);

const fixtureDir = join(dirname(fileURLToPath(import.meta.url)), "fixture");
const pkgPath = join(fixtureDir, "package.json");
const originalPkgJson = await readFile(pkgPath, "utf8");

// ---------------------------------------------------------------------------
// Pick registry mode: probe the REAL bulk advisory endpoint first.
// ---------------------------------------------------------------------------
let registry: RegistryPort;
let mode: "REAL (live npm registry + advisory endpoint)" | "FALLBACK (canned fake registry)";
try {
  const real = new RealRegistry(10_000);
  const probe = await real.getAdvisories({ lodash: ["4.17.20"] });
  if ((probe.get("lodash") ?? []).length === 0) {
    throw new Error("advisory endpoint answered but returned no lodash advisories — treating as unusable");
  }
  registry = real;
  mode = "REAL (live npm registry + advisory endpoint)";
} catch (err) {
  console.warn(`WARNING: live advisory endpoint unreachable/unusable (${(err as Error).message})`);
  console.warn("Falling back to the canned FakeRegistry so the demo still completes.");
  registry = lodashFallbackRegistry();
  mode = "FALLBACK (canned fake registry)";
}

const github = new MockGitHubHost();
const repo = { owner: "fixture-org", repo: "dep-upgrade-fixture" };
github.addRepo(repo, "main");

let exitCode = 0;
try {
  hr("Dependency-Upgrade Agent");
  console.log(`  target   ${fixtureDir}`);
  console.log(`  registry ${mode}`);
  console.log("  verify   REAL — `npm install` + `npm test` run in the fixture dir");
  console.log("  delivery MOCK GitHub (in-memory; real mode needs an authed gh/token)");

  const report = await runDepUpgrade({
    dir: fixtureDir,
    repo,
    config: { proposeNextMajor: false },
    registry,
    runner: new RealCommandRunner(),
    github,
  });

  hr("Inventory");
  console.log(`  package ${report.inventory.packageName}  lockfile=${report.inventory.hadLockfile}`);
  for (const d of report.inventory.deps) {
    console.log(`  ${d.name.padEnd(12)} ${d.range.padEnd(10)} (${d.section})${d.installedVersion ? `  installed=${d.installedVersion}` : ""}`);
  }

  hr("Upgrade plan");
  for (const it of report.plan.items) {
    console.log(`  ${it.name}: ${it.currentVersion} -> ${it.targetVersion}  [${it.kind}${it.breaking ? ", BREAKING" : ""}]`);
    console.log(`    ${it.rationale}`);
    for (const a of it.advisories) console.log(`    clears ${a.id} (${a.severity}): ${a.title}`);
  }
  for (const u of report.plan.unactionable) console.log(`  unactionable ${u.name}: ${u.reason}`);
  if (report.plan.items.length === 0) console.log("  (nothing to do)");

  hr("Verify results");
  for (const r of report.results) {
    console.log(`  ${r.item.name}@${r.item.targetVersion}: ${r.applied ? "GREEN — kept" : `RED — reverted at \`${r.failedAt}\``}`);
    for (const v of r.verify) console.log(`    ${v.command} -> exit ${v.exitCode}`);
  }

  if (report.pr) {
    hr(`PR opened on mock GitHub (branch ${report.pr.branch})`);
    console.log(github.renderPr(repo, report.pr.number));
    hr("Mock GitHub call log (api.github.com-shaped)");
    for (const call of github.callLog) console.log(`  ${call}`);
  } else {
    hr("No PR opened");
    console.log("  Nothing survived verification — see results above.");
    console.log(report.prBody);
  }

  hr("Done");
  console.log(
    `  mode=${mode.split(" ")[0]}  planned=${report.plan.items.length}` +
      `  green=${report.results.filter((r) => r.applied).length}` +
      `  reverted=${report.results.filter((r) => !r.applied).length}` +
      `  pr=${report.pr ? `#${report.pr.number}` : "none"}`,
  );
} catch (err) {
  console.error(`demo failed: ${(err as Error).stack ?? err}`);
  exitCode = 1;
} finally {
  // Restore the fixture to its committed state so the demo is re-runnable:
  // original package.json back, generated lockfile removed (node_modules is
  // gitignored and re-synced by the next run's `npm install`).
  await writeFile(pkgPath, originalPkgJson, "utf8");
  await rm(join(fixtureDir, "package-lock.json"), { force: true });
  console.log("\nfixture restored to committed state (package.json rewritten, lockfile removed)");
}

process.exit(exitCode);
