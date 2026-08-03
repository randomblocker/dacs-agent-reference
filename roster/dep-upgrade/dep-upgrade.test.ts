/**
 * Dependency-Upgrade Agent tests — node:test + node:assert, fully offline
 * (fake registry, fake command runner, mock GitHub, temp-dir fixtures).
 *
 *   npx tsx --test roster/dep-upgrade/dep-upgrade.test.ts
 */
import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  compareVersions,
  maxSatisfying,
  minSatisfying,
  parseSemver,
  satisfies,
} from "./semver.js";
import { parseInventory, readInventory } from "./inventory.js";
import { buildPlan, preserveRangeStyle, resolveCurrentVersion } from "./planner.js";
import { FakeCommandRunner, applyAndVerify, applyItemToPackageJson } from "./apply-verify.js";
import { MockGitHubHost } from "./github-port.js";
import { FakeRegistry } from "./registry.js";
import { branchName, renderPrBody, runDepUpgrade } from "./agent.js";
import type { Advisory, DepInventory, Packument, UpgradeItem } from "./types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function advisory(overrides: Partial<Advisory> & { vulnerableVersions: string }): Advisory {
  return {
    id: "GHSA-test-0001",
    severity: "high",
    title: "test advisory",
    url: "https://github.com/advisories/GHSA-test-0001",
    ...overrides,
  };
}

function packument(name: string, versions: string[], latest?: string): Packument {
  return { name, latest: latest ?? versions[versions.length - 1]!, versions };
}

function inventoryOf(
  deps: Array<{ name: string; range: string; installedVersion?: string }>,
): DepInventory {
  return {
    dir: "/fake",
    packageName: "test-pkg",
    hadLockfile: false,
    deps: deps.map((d) => ({ section: "dependencies" as const, ...d })),
  };
}

function item(overrides: Partial<UpgradeItem> & { name: string }): UpgradeItem {
  return {
    section: "dependencies",
    kind: "security",
    currentVersion: "1.0.0",
    currentRange: "1.0.0",
    targetVersion: "1.0.1",
    newRange: "1.0.1",
    breaking: false,
    advisories: [],
    rationale: "test",
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// semver
// ---------------------------------------------------------------------------

describe("semver: parse + compare", () => {
  test("parses plain, v-prefixed, prerelease, and build-metadata versions", () => {
    assert.equal(parseSemver("1.2.3")?.minor, 2);
    assert.equal(parseSemver("v4.17.21")?.patch, 21);
    assert.deepEqual(parseSemver("1.0.0-alpha.1")?.prerelease, ["alpha", 1]);
    assert.equal(parseSemver("1.2.3+build.5")?.prerelease.length, 0);
    assert.equal(parseSemver("not-a-version"), null);
    assert.equal(parseSemver("1.2"), null); // full versions only
  });

  test("orders versions including prerelease rules", () => {
    assert.equal(compareVersions("1.2.3", "1.2.4"), -1);
    assert.equal(compareVersions("2.0.0", "1.99.99"), 1);
    assert.equal(compareVersions("1.0.0", "1.0.0"), 0);
    // prerelease < release; identifiers compare per semver spec
    assert.equal(compareVersions("1.0.0-alpha", "1.0.0"), -1);
    assert.equal(compareVersions("1.0.0-alpha", "1.0.0-alpha.1"), -1);
    assert.equal(compareVersions("1.0.0-alpha.9", "1.0.0-alpha.10"), -1); // numeric, not lexical
    assert.equal(compareVersions("1.0.0-alpha.1", "1.0.0-beta"), -1);
    assert.equal(compareVersions("1.0.0-1", "1.0.0-alpha"), -1); // numeric < alphanumeric
  });
});

describe("semver: range satisfaction", () => {
  test("caret ranges, including the 0.x special cases", () => {
    assert.ok(satisfies("1.5.0", "^1.2.3"));
    assert.ok(!satisfies("2.0.0", "^1.2.3"));
    assert.ok(!satisfies("1.2.2", "^1.2.3"));
    assert.ok(satisfies("0.2.9", "^0.2.3")); // ^0.2.3 → <0.3.0
    assert.ok(!satisfies("0.3.0", "^0.2.3"));
    assert.ok(satisfies("0.0.3", "^0.0.3")); // ^0.0.3 → <0.0.4
    assert.ok(!satisfies("0.0.4", "^0.0.3"));
  });

  test("tilde ranges", () => {
    assert.ok(satisfies("1.2.9", "~1.2.3"));
    assert.ok(!satisfies("1.3.0", "~1.2.3"));
    assert.ok(satisfies("1.9.0", "~1")); // ~1 → <2.0.0
  });

  test("comparator AND groups, OR alternatives, stars, exact, x-ranges", () => {
    assert.ok(satisfies("1.5.0", ">=1.2.3 <2.0.0"));
    assert.ok(!satisfies("2.1.0", ">=1.2.3 <2.0.0"));
    assert.ok(satisfies("0.5.0", "<1.0.0 || >=2.0.0"));
    assert.ok(satisfies("2.5.0", "<1.0.0 || >=2.0.0"));
    assert.ok(!satisfies("1.5.0", "<1.0.0 || >=2.0.0"));
    assert.ok(satisfies("99.0.0", "*"));
    assert.ok(satisfies("4.17.20", "4.17.20"));
    assert.ok(!satisfies("4.17.21", "4.17.20"));
    assert.ok(satisfies("1.2.9", "1.2")); // partial → x-range
    assert.ok(!satisfies("1.3.0", "1.2"));
    assert.ok(satisfies("4.17.20", "<4.17.21")); // real advisory shape
    assert.ok(!satisfies("4.17.21", "<4.17.21"));
  });

  test("min/maxSatisfying pick from unsorted lists and skip garbage", () => {
    const versions = ["1.2.0", "not-semver", "1.0.0", "2.0.0", "1.5.0"];
    assert.equal(minSatisfying(versions, ">=1.1.0"), "1.2.0");
    assert.equal(maxSatisfying(versions, "^1.0.0"), "1.5.0");
    assert.equal(minSatisfying(versions, ">=3.0.0"), null);
  });
});

// ---------------------------------------------------------------------------
// inventory
// ---------------------------------------------------------------------------

describe("inventory", () => {
  test("parses a lockfile-less repo: ranges captured, no installed versions", () => {
    const inv = parseInventory(
      "/x",
      JSON.stringify({
        name: "app",
        dependencies: { lodash: "4.17.20", axios: "^1.6.0" },
        devDependencies: { typescript: "~5.7.0" },
      }),
    );
    assert.equal(inv.hadLockfile, false);
    assert.equal(inv.deps.length, 3);
    const lodash = inv.deps.find((d) => d.name === "lodash")!;
    assert.equal(lodash.range, "4.17.20");
    assert.equal(lodash.installedVersion, undefined);
    assert.equal(inv.deps.find((d) => d.name === "typescript")!.section, "devDependencies");
  });

  test("picks installed versions from a v3 lockfile", () => {
    const inv = parseInventory(
      "/x",
      JSON.stringify({ name: "app", dependencies: { lodash: "^4.17.0" } }),
      JSON.stringify({
        lockfileVersion: 3,
        packages: { "": {}, "node_modules/lodash": { version: "4.17.20" } },
      }),
    );
    assert.equal(inv.hadLockfile, true);
    assert.equal(inv.deps[0]!.installedVersion, "4.17.20");
  });

  test("readInventory tolerates a missing lockfile on disk", async () => {
    const dir = await mkdtemp(join(tmpdir(), "depup-inv-"));
    await writeFile(
      join(dir, "package.json"),
      JSON.stringify({ name: "lockless", dependencies: { lodash: "4.17.20" } }),
    );
    const inv = await readInventory(dir);
    assert.equal(inv.packageName, "lockless");
    assert.equal(inv.hadLockfile, false);
    assert.equal(inv.deps[0]!.installedVersion, undefined);
  });
});

// ---------------------------------------------------------------------------
// planner
// ---------------------------------------------------------------------------

const LODASH_VERSIONS = ["4.17.19", "4.17.20", "4.17.21", "4.17.22", "5.0.0"];

describe("planner: security upgrades", () => {
  test("chooses the minimal version that clears all advisories, within the major", () => {
    const plan = buildPlan(
      inventoryOf([{ name: "lodash", range: "4.17.20" }]),
      new Map([["lodash", packument("lodash", LODASH_VERSIONS)]]),
      new Map([["lodash", [advisory({ id: "GHSA-lodash-cmd", vulnerableVersions: "<4.17.21" })]]]),
    );
    assert.equal(plan.items.length, 1);
    const it = plan.items[0]!;
    assert.equal(it.kind, "security");
    assert.equal(it.targetVersion, "4.17.21"); // NOT 4.17.22 or 5.0.0
    assert.equal(it.breaking, false);
    assert.equal(it.advisories[0]!.id, "GHSA-lodash-cmd");
  });

  test("skips a candidate that clears one advisory but is hit by another", () => {
    const plan = buildPlan(
      inventoryOf([{ name: "pkg", range: "1.0.0" }]),
      new Map([["pkg", packument("pkg", ["1.0.0", "1.1.0", "1.2.0"])]]),
      new Map([
        [
          "pkg",
          [
            advisory({ id: "GHSA-a", vulnerableVersions: "<1.1.0" }),
            advisory({ id: "GHSA-b", severity: "critical", vulnerableVersions: "=1.1.0" }),
          ],
        ],
      ]),
    );
    assert.equal(plan.items[0]!.targetVersion, "1.2.0"); // 1.1.0 clears A but trips B
  });

  test("escalates major only when no in-major fix exists, flagged breaking", () => {
    const plan = buildPlan(
      inventoryOf([{ name: "oldlib", range: "^1.2.0", installedVersion: "1.2.0" }]),
      new Map([["oldlib", packument("oldlib", ["1.0.0", "1.2.0", "1.9.0", "2.0.0", "2.1.0"])]]),
      new Map([["oldlib", [advisory({ id: "GHSA-old", severity: "critical", vulnerableVersions: "<2.0.0" })]]]),
    );
    const it = plan.items[0]!;
    assert.equal(it.targetVersion, "2.0.0"); // nearest clearing, majors escalated
    assert.equal(it.breaking, true);
    assert.match(it.rationale, /escalating majors/);
  });

  test("never targets a prerelease and reports unfixable deps as unactionable", () => {
    const plan = buildPlan(
      inventoryOf([{ name: "doomed", range: "1.0.0" }]),
      new Map([["doomed", packument("doomed", ["1.0.0", "2.0.0-beta.1"], "1.0.0")]]),
      new Map([["doomed", [advisory({ id: "GHSA-doom", vulnerableVersions: "<3.0.0" })]]]),
    );
    assert.equal(plan.items.length, 0);
    assert.equal(plan.unactionable.length, 1);
    assert.match(plan.unactionable[0]!.reason, /GHSA-doom/);
  });

  test("rationale cites advisory ids and severities", () => {
    const plan = buildPlan(
      inventoryOf([{ name: "lodash", range: "4.17.20" }]),
      new Map([["lodash", packument("lodash", LODASH_VERSIONS)]]),
      new Map([["lodash", [advisory({ id: "GHSA-35jh-r3h4-6jhm", severity: "high", vulnerableVersions: "<4.17.21" })]]]),
    );
    assert.match(plan.items[0]!.rationale, /GHSA-35jh-r3h4-6jhm \(high\)/);
  });
});

describe("planner: maintenance upgrades", () => {
  test("proposes latest-in-range for merely-outdated deps; next-major only via config", () => {
    const packuments = new Map([["axios", packument("axios", ["1.6.0", "1.6.5", "1.7.0", "2.0.0"])]]);
    const inv = inventoryOf([{ name: "axios", range: "^1.6.0", installedVersion: "1.6.0" }]);

    const defaultPlan = buildPlan(inv, packuments, new Map());
    assert.equal(defaultPlan.items.length, 1);
    assert.equal(defaultPlan.items[0]!.kind, "outdated");
    assert.equal(defaultPlan.items[0]!.targetVersion, "1.7.0");
    assert.equal(defaultPlan.items[0]!.newRange, "^1.7.0"); // range style preserved

    const majorPlan = buildPlan(inv, packuments, new Map(), { proposeNextMajor: true });
    const nextMajor = majorPlan.items.find((i) => i.kind === "next-major")!;
    assert.equal(nextMajor.targetVersion, "2.0.0");
    assert.equal(nextMajor.breaking, true);
  });

  test("resolveCurrentVersion: lockfile-less resolves via range; stale lock falls back", () => {
    const p = packument("lodash", LODASH_VERSIONS);
    assert.equal(resolveCurrentVersion({ name: "lodash", range: "^4.17.19", section: "dependencies" }, p), "4.17.19");
    assert.equal(
      resolveCurrentVersion(
        { name: "lodash", range: "4.17.20", section: "dependencies", installedVersion: "4.17.21" },
        p,
      ),
      "4.17.20", // lock disagrees with declared range → trust the declaration
    );
  });

  test("preserveRangeStyle keeps ^/~ and pins otherwise", () => {
    assert.equal(preserveRangeStyle("^1.2.3", "1.9.0"), "^1.9.0");
    assert.equal(preserveRangeStyle("~1.2.3", "1.2.9"), "~1.2.9");
    assert.equal(preserveRangeStyle("1.2.3", "1.9.0"), "1.9.0");
  });
});

// ---------------------------------------------------------------------------
// apply + verify
// ---------------------------------------------------------------------------

async function tempTarget(deps: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "depup-apply-"));
  await writeFile(join(dir, "package.json"), `${JSON.stringify({ name: "t", dependencies: deps }, null, 2)}\n`);
  return dir;
}

describe("apply + verify", () => {
  test("green verify keeps the item and updates package.json", async () => {
    const dir = await tempTarget({ lodash: "4.17.20" });
    const runner = new FakeCommandRunner(); // everything exits 0
    const { results, changed } = await applyAndVerify(
      dir,
      [item({ name: "lodash", currentRange: "4.17.20", newRange: "4.17.21", targetVersion: "4.17.21" })],
      runner,
    );
    assert.equal(changed, true);
    assert.equal(results[0]!.applied, true);
    assert.deepEqual(results[0]!.verify.map((v) => v.command), ["npm install", "npm test"]);
    const pkg = JSON.parse(await readFile(join(dir, "package.json"), "utf8"));
    assert.equal(pkg.dependencies.lodash, "4.17.21");
    assert.equal(runner.calls[0]!.cwd, dir); // verify ran in the target dir
  });

  test("red verify reverts that item only and captures the output tail", async () => {
    const dir = await tempTarget({ lodash: "4.17.20", axios: "^1.6.0" });
    const runner = new FakeCommandRunner({
      // First `npm test` (lodash item) fails; second (axios item) passes.
      "npm test": [{ exitCode: 1, output: "line1\nassertion exploded: lodash broke the build" }],
    });
    const { results, changed } = await applyAndVerify(
      dir,
      [
        item({ name: "lodash", currentRange: "4.17.20", newRange: "4.17.21", targetVersion: "4.17.21" }),
        item({ name: "axios", kind: "outdated", currentRange: "^1.6.0", newRange: "^1.7.0", targetVersion: "1.7.0" }),
      ],
      runner,
    );
    const [lodashRes, axiosRes] = [results[0]!, results[1]!];
    assert.equal(lodashRes.applied, false);
    assert.equal(lodashRes.failedAt, "npm test");
    assert.match(lodashRes.outputTail!, /lodash broke the build/);
    assert.equal(axiosRes.applied, true);
    assert.equal(changed, true);
    const pkg = JSON.parse(await readFile(join(dir, "package.json"), "utf8"));
    assert.equal(pkg.dependencies.lodash, "4.17.20"); // reverted
    assert.equal(pkg.dependencies.axios, "^1.7.0"); // kept
  });

  test("a failing npm install short-circuits before npm test", async () => {
    const dir = await tempTarget({ lodash: "4.17.20" });
    const runner = new FakeCommandRunner({ "npm install": [{ exitCode: 1, output: "EAI_AGAIN registry.npmjs.org" }] });
    const { results } = await applyAndVerify(
      dir,
      [item({ name: "lodash", currentRange: "4.17.20", newRange: "4.17.21", targetVersion: "4.17.21" })],
      runner,
    );
    assert.equal(results[0]!.failedAt, "npm install");
    assert.equal(results[0]!.verify.length, 1); // npm test never ran
  });

  test("applyItemToPackageJson throws when the dep is missing from the section", () => {
    assert.throws(
      () => applyItemToPackageJson(JSON.stringify({ dependencies: {} }), item({ name: "ghost" })),
      /ghost not found/,
    );
  });
});

// ---------------------------------------------------------------------------
// PR body + delivery (agent end-to-end, offline)
// ---------------------------------------------------------------------------

describe("PR body + mock GitHub delivery", () => {
  test("end-to-end offline run: PR cites advisories and verify evidence", async () => {
    const dir = await tempTarget({ lodash: "4.17.20" });
    const registry = new FakeRegistry(
      { lodash: packument("lodash", LODASH_VERSIONS, "4.17.22") },
      { lodash: [advisory({ id: "GHSA-35jh-r3h4-6jhm", severity: "high", vulnerableVersions: "<4.17.21" })] },
    );
    const github = new MockGitHubHost();
    const repo = { owner: "acme", repo: "target" };
    github.addRepo(repo, "main");

    const report = await runDepUpgrade({
      dir,
      repo,
      registry,
      runner: new FakeCommandRunner(),
      github,
      today: "2026-07-07",
    });

    assert.ok(report.pr, "a PR should have been opened");
    assert.equal(report.pr!.branch, "dep-upgrade/2026-07-07");

    const body = github.getPr(repo, report.pr!.number)!.body;
    // advisory citation
    assert.match(body, /GHSA-35jh-r3h4-6jhm/);
    assert.match(body, /\*\*high\*\*/);
    // verify evidence: commands + exit codes
    assert.match(body, /`npm install` → exit 0/);
    assert.match(body, /`npm test` → exit 0/);
    // the upgrade itself
    assert.match(body, /\*\*lodash\*\* `4\.17\.20` \(4\.17\.20\) → `4\.17\.21` \(4\.17\.21\)/);

    // committed content matches what verification ran against
    const commit = github.listCommits(repo)[0]!;
    assert.equal(commit.branch, "dep-upgrade/2026-07-07");
    const committedPkg = JSON.parse(commit.files[0]!.content);
    assert.equal(committedPkg.dependencies.lodash, "4.17.21");

    // api.github.com-shaped read surface serves the PR back
    const fetched = github.apiFetch(`https://api.github.com/repos/acme/target/pulls/${report.pr!.number}`);
    assert.equal(fetched.status, 200);
  });

  test("no PR is opened when every item goes red; body still reports the failures", async () => {
    const dir = await tempTarget({ lodash: "4.17.20" });
    const registry = new FakeRegistry(
      { lodash: packument("lodash", LODASH_VERSIONS, "4.17.22") },
      { lodash: [advisory({ vulnerableVersions: "<4.17.21" })] },
    );
    const github = new MockGitHubHost();
    github.addRepo({ owner: "acme", repo: "target" });

    const report = await runDepUpgrade({
      dir,
      repo: { owner: "acme", repo: "target" },
      registry,
      runner: new FakeCommandRunner({ "npm test": [{ exitCode: 1, output: "boom" }] }),
      github,
    });

    assert.equal(report.pr, null);
    assert.equal(github.callLog.length, 0); // no GitHub writes at all
    assert.match(report.prBody, /Reverted \(verification failed/);
    assert.match(report.prBody, /exit 1 \(RED\)/);
    assert.match(report.prBody, /boom/);
  });

  test("renderPrBody flags breaking upgrades loudly", () => {
    const body = renderPrBody(
      { items: [], unactionable: [] },
      [
        {
          item: item({ name: "oldlib", breaking: true, targetVersion: "2.0.0", newRange: "^2.0.0" }),
          applied: true,
          verify: [{ command: "npm install", exitCode: 0, output: "" }],
        },
      ],
    );
    assert.match(body, /\*\*BREAKING \(major escalation\)\*\*/);
  });

  test("branchName is dep-upgrade/<date>", () => {
    assert.equal(branchName("2026-01-31"), "dep-upgrade/2026-01-31");
    assert.match(branchName(), /^dep-upgrade\/\d{4}-\d{2}-\d{2}$/);
  });
});
