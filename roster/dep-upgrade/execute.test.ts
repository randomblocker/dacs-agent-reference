/**
 * Dependency-Upgrade EXECUTOR TIER tests — fully offline: FakeSandbox + FakeRepo
 * + canned FakeRegistry, a real temp workspace on disk, no Docker, no network,
 * no LLM (there is no LLM in this tier by construction).
 *
 *   npx tsx --test roster/dep-upgrade/execute.test.ts
 *
 * Covers: plan→apply→verify orchestration; `upgraded-green` vs
 * `upgrade-breaks-suite` vs `upgraded-untested` vs `no-advisories` vs
 * `indeterminate`; fail-safe (no sandbox → indeterminate, the host/sandbox is
 * NEVER run); the advisory re-scan clearing proof; patch/artifact sign+verify
 * and every tampered/missing binding rejected (a forged `upgraded-green` over a
 * failing check / uncleared advisories / phantom patch is rejected); the plan
 * tier staying unchanged; and pricing.
 */
import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FakeSandbox, type ScriptedCheck } from "../../src/agents/sandbox.js";
import { FakeRepo, type FetchedPr } from "../../src/agents/repo-fetch.js";
import { FakeRegistry, lodashFallbackRegistry } from "./registry.js";
import { MockDahrAttestor, canonicalJson } from "../sec-audit/attest-files.js";
import { sha256Hex } from "../oracle-desk/attested-fetch.js";
import type { DeliveryAttestation } from "../dacs/seller-adapter.js";
import {
  makeDepUpgradeWork,
  depUpgradeObserveDelivered,
  makeDepUpgradeExecuteWork,
  depUpgradeExecuteObserveDelivered,
} from "../dacs/wire/dep-upgrade.js";
import {
  EXECUTE_PRICING,
  combineExecVerdict,
  compareReRuns,
  executeCheckArgvPreview,
  executePriceFor,
  patchHashOf,
  pinnedInputsDigest,
  reScanCleared,
  runExecuteUpgrade,
  verifyExecReport,
  type ExecCheck,
  type ExecReport,
  type ReRunArtifact,
} from "./execute.js";
import { NORMALIZATION_VERSION } from "../../src/agents/sandbox.js";
import type { QuorumAttestation } from "../sec-audit/types.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const VULN_PKG = JSON.stringify({
  name: "vuln-app",
  version: "1.0.0",
  scripts: { test: "node test.js" },
  dependencies: { lodash: "4.17.20" },
});

const VULN_PKG_NO_TEST = JSON.stringify({
  name: "vuln-app-notest",
  version: "1.0.0",
  dependencies: { lodash: "4.17.20" },
});

const CLEAN_PKG = JSON.stringify({
  name: "clean-app",
  version: "1.0.0",
  scripts: { test: "node test.js" },
  dependencies: { lodash: "4.17.21" },
});

interface Workspace {
  dir: string;
  cleanup: () => Promise<void>;
}

async function makeWorkspace(pkgJson: string): Promise<Workspace> {
  const dir = await mkdtemp(join(tmpdir(), "dep-exec-test-"));
  await writeFile(join(dir, "package.json"), pkgJson, "utf8");
  return { dir, cleanup: () => rm(dir, { recursive: true, force: true }) };
}

function fetchedFor(dir: string, packageJson: string): FetchedPr {
  return { workspaceDir: dir, headSha: "execsha0000000", diff: "", projectType: "node", packageJson };
}

/** Run the executor against a real temp workspace with an injected FakeSandbox. */
async function runOn(
  pkgJson: string,
  opts: { script?: Record<string, ScriptedCheck>; available?: boolean; registry?: ReturnType<typeof lodashFallbackRegistry> } = {},
): Promise<{ artifact: ExecReport; sandbox: FakeSandbox; ws: Workspace }> {
  const ws = await makeWorkspace(pkgJson);
  const sandbox = new FakeSandbox(opts.script ?? {}, opts.available ?? true);
  const repo = new FakeRepo(fetchedFor(ws.dir, pkgJson));
  const registry = opts.registry ?? lodashFallbackRegistry();
  const artifact = await runExecuteUpgrade({ repo, sandbox, registry }, { repo: "acme/app", ref: "main" });
  return { artifact, sandbox, ws };
}

/** Re-seal a mutated core with a FRESH attestor — a validly self-signed but
 *  potentially inconsistent artifact (the adversary the granular checks catch). */
function reseal(core: Omit<ExecReport, "seal">): ExecReport {
  const attestor = new MockDahrAttestor();
  const bodyHash = sha256Hex(canonicalJson(core));
  const url = `report:dep-upgrade-execute:${core.generatedAt}`;
  return { ...core, seal: { url, bodyHash, attestation: attestor.attest(url, core.generatedAt, bodyHash) } };
}

// ---------------------------------------------------------------------------
// 1. Verdict backbone (pure)
// ---------------------------------------------------------------------------

describe("combineExecVerdict backbone", () => {
  const mk = (name: string, passed: boolean): ExecCheck => ({ name, cmd: ["x"], exitCode: passed ? 0 : 1, passed, outputHash: "h", normalizedOutputHash: "h", outputTail: "" });

  test("no sandbox → indeterminate", () => {
    assert.equal(combineExecVerdict(false, 0, [], false), "indeterminate");
  });
  test("no upgrades → no-advisories", () => {
    assert.equal(combineExecVerdict(true, 0, [], true), "no-advisories");
  });
  test("upgrade + all green + cleared + test → upgraded-green", () => {
    assert.equal(combineExecVerdict(true, 1, [mk("install", true), mk("test", true)], true), "upgraded-green");
  });
  test("upgrade + green but no test script → upgraded-untested", () => {
    assert.equal(combineExecVerdict(true, 1, [mk("install", true)], true), "upgraded-untested");
  });
  test("a red check → upgrade-breaks-suite", () => {
    assert.equal(combineExecVerdict(true, 1, [mk("install", true), mk("test", false)], true), "upgrade-breaks-suite");
  });
  test("green checks but advisories not cleared → upgrade-breaks-suite", () => {
    assert.equal(combineExecVerdict(true, 1, [mk("install", true), mk("test", true)], false), "upgrade-breaks-suite");
  });
});

// ---------------------------------------------------------------------------
// 2. Advisory re-scan clearing proof
// ---------------------------------------------------------------------------

describe("reScanCleared", () => {
  test("chosen version clears all before-advisories → empty", async () => {
    const still = await reScanCleared(
      lodashFallbackRegistry(),
      [{ dep: "lodash", version: "4.17.21" }],
      new Set(["GHSA-35jh-r3h4-6jhm", "GHSA-29mw-wpgm-hmr9"]),
    );
    assert.deepEqual(still, []);
  });

  test("a still-vulnerable chosen version reports the ids (filter is semver, not the endpoint)", async () => {
    // 4.17.20 still satisfies "<4.17.21" — the FakeRegistry does NOT filter by
    // version, so this proves reScanCleared applies its own semver filter.
    const still = await reScanCleared(
      lodashFallbackRegistry(),
      [{ dep: "lodash", version: "4.17.20" }],
      new Set(["GHSA-35jh-r3h4-6jhm", "GHSA-29mw-wpgm-hmr9"]),
    );
    assert.deepEqual(still.sort(), ["GHSA-29mw-wpgm-hmr9", "GHSA-35jh-r3h4-6jhm"]);
  });
});

// ---------------------------------------------------------------------------
// 3. Orchestration: verdict selection
// ---------------------------------------------------------------------------

describe("runExecuteUpgrade — verdict selection", () => {
  test("upgraded-green: apply lodash→4.17.21, checks pass, advisories cleared, verifies", async () => {
    const { artifact, sandbox, ws } = await runOn(VULN_PKG);
    try {
      assert.equal(artifact.verdict, "upgraded-green");
      assert.equal(artifact.sandboxAvailable, true);
      assert.equal(artifact.after.length, 1);
      assert.equal(artifact.after[0]!.dep, "lodash");
      assert.equal(artifact.after[0]!.version, "4.17.21");
      assert.equal(artifact.before[0]!.version, "4.17.20");
      assert.ok(artifact.before[0]!.advisories.length >= 1);
      assert.equal(artifact.advisoriesCleared, true);
      assert.deepEqual(artifact.stillVulnerable, []);
      // install + test ran in the SANDBOX (never the host).
      assert.deepEqual(sandbox.calls.map((c) => c.name).sort(), ["install", "test"]);
      // the patch actually carries the upgrade
      assert.match(artifact.patch.afterPackageJson, /4\.17\.21/);
      assert.equal(patchHashOf(artifact.patch), artifact.patchHash);
      const v = verifyExecReport(artifact);
      assert.ok(v.valid, `should verify: ${v.problems.join("; ")}`);
      assert.ok(v.checksChecked >= 2);
    } finally {
      await ws.cleanup();
    }
  });

  test("upgrade-breaks-suite: a red test → honest 'not drop-in' verdict, still verifies", async () => {
    const { artifact, ws } = await runOn(VULN_PKG, { script: { test: { exitCode: 1, output: "1 failing" } } });
    try {
      assert.equal(artifact.verdict, "upgrade-breaks-suite");
      assert.equal(artifact.after.length, 1); // the bump WAS applied
      assert.ok(artifact.checks.some((c) => c.name === "test" && !c.passed));
      assert.ok(verifyExecReport(artifact).valid);
    } finally {
      await ws.cleanup();
    }
  });

  test("upgraded-untested: no test script → cleared + green checks but suite unproven", async () => {
    const { artifact, sandbox, ws } = await runOn(VULN_PKG_NO_TEST);
    try {
      assert.equal(artifact.verdict, "upgraded-untested");
      assert.equal(artifact.advisoriesCleared, true);
      assert.deepEqual(sandbox.calls.map((c) => c.name), ["install"]); // no test check
      assert.ok(verifyExecReport(artifact).valid);
    } finally {
      await ws.cleanup();
    }
  });

  test("no-advisories: already on a clean version → nothing to do, no checks run", async () => {
    const { artifact, sandbox, ws } = await runOn(CLEAN_PKG);
    try {
      assert.equal(artifact.verdict, "no-advisories");
      assert.equal(artifact.after.length, 0);
      assert.equal(artifact.checks.length, 0);
      assert.equal(sandbox.calls.length, 0, "no checks when nothing to upgrade");
      assert.ok(verifyExecReport(artifact).valid);
    } finally {
      await ws.cleanup();
    }
  });
});

// ---------------------------------------------------------------------------
// 4. Fail-safe — no sandbox → indeterminate, host/sandbox NEVER invoked
// ---------------------------------------------------------------------------

describe("fail-safe (no sandbox)", () => {
  test("indeterminate, nothing applied, sandbox never run", async () => {
    const { artifact, sandbox, ws } = await runOn(VULN_PKG, { available: false });
    try {
      assert.equal(artifact.verdict, "indeterminate");
      assert.equal(artifact.sandboxAvailable, false);
      assert.equal(artifact.after.length, 0);
      assert.equal(artifact.checks.length, 0);
      assert.equal(sandbox.calls.length, 0, "sandbox/host runner NEVER invoked with no sandbox");
      // package.json on disk must be UNCHANGED (no apply happened).
      const onDisk = await (await import("node:fs/promises")).readFile(join(ws.dir, "package.json"), "utf8");
      assert.equal(onDisk, VULN_PKG);
      assert.ok(verifyExecReport(artifact).valid);
    } finally {
      await ws.cleanup();
    }
  });
});

// ---------------------------------------------------------------------------
// 5. verifyExecReport rejects tampering (NO fail-open)
// ---------------------------------------------------------------------------

describe("verifyExecReport rejects tampering (no fail-open)", () => {
  async function greenArtifact(): Promise<ExecReport> {
    const { artifact, ws } = await runOn(VULN_PKG);
    await ws.cleanup();
    return artifact;
  }

  test("baseline green artifact verifies", async () => {
    assert.ok(verifyExecReport(await greenArtifact()).valid);
  });

  test("upgraded-green with a check flipped to failing → rejected", async () => {
    const a = await greenArtifact();
    const { seal: _s, ...core } = a;
    const checks = core.checks.map((c) => (c.name === "test" ? { ...c, exitCode: 1, passed: false } : c));
    const bad = reseal({ ...core, checks });
    const v = verifyExecReport(bad);
    assert.equal(v.valid, false);
    assert.ok(v.problems.some((p) => /every check passed|should be green|test check/i.test(p)));
  });

  test("upgraded-green with advisoriesCleared forced false → rejected", async () => {
    const a = await greenArtifact();
    const { seal: _s, ...core } = a;
    const bad = reseal({ ...core, advisoriesCleared: false });
    const v = verifyExecReport(bad);
    assert.equal(v.valid, false);
    assert.ok(v.problems.some((p) => /not cleared/i.test(p)));
  });

  test("upgraded-green with stillVulnerable non-empty → rejected", async () => {
    const a = await greenArtifact();
    const { seal: _s, ...core } = a;
    const bad = reseal({ ...core, stillVulnerable: ["GHSA-35jh-r3h4-6jhm"] });
    assert.equal(verifyExecReport(bad).valid, false);
  });

  test("phantom after-version not present in the patch → rejected", async () => {
    const a = await greenArtifact();
    const { seal: _s, ...core } = a;
    const after = core.after.map((d) => ({ ...d, version: "9.9.9" }));
    // patchHash must still match the (unchanged) patch, so re-derive it.
    const bad = reseal({ ...core, after, patchHash: patchHashOf(core.patch) });
    const v = verifyExecReport(bad);
    assert.equal(v.valid, false);
    assert.ok(v.problems.some((p) => /phantom upgrade/i.test(p)));
  });

  test("patch tampered but patchHash stale → rejected", async () => {
    const a = await greenArtifact();
    const { seal: _s, ...core } = a;
    const patch = { ...core.patch, afterPackageJson: core.patch.afterPackageJson.replace("4.17.21", "4.17.21-evil") };
    const bad = reseal({ ...core, patch }); // patchHash NOT recomputed → mismatch
    const v = verifyExecReport(bad);
    assert.equal(v.valid, false);
    assert.ok(v.problems.some((p) => /patchHash/i.test(p)));
  });

  test("seal tamper: mutate a field without re-sealing → rejected", async () => {
    const a = await greenArtifact();
    const tampered = { ...a, verdict: "no-advisories" as const }; // seal now stale
    const v = verifyExecReport(tampered);
    assert.equal(v.valid, false);
    assert.ok(v.problems.some((p) => /seal|hash/i.test(p)));
  });

  test("forged 'no-advisories' over a real upgrade (re-sealed) → rejected by backbone", async () => {
    const a = await greenArtifact();
    const { seal: _s, ...core } = a;
    const bad = reseal({ ...core, verdict: "no-advisories" });
    const v = verifyExecReport(bad);
    assert.equal(v.valid, false);
    assert.ok(v.problems.some((p) => /no-advisories.*upgrades are present/i.test(p)));
  });

  test("a check with passed=true but non-zero exitCode → rejected", async () => {
    const a = await greenArtifact();
    const { seal: _s, ...core } = a;
    const checks = core.checks.map((c) => (c.name === "test" ? { ...c, exitCode: 1 } : c)); // passed stays true
    const bad = reseal({ ...core, checks });
    const v = verifyExecReport(bad);
    assert.equal(v.valid, false);
    assert.ok(v.problems.some((p) => /contradicts exitCode/i.test(p)));
  });
});

// ---------------------------------------------------------------------------
// 6. Plan tier UNCHANGED (the cheap tier still round-trips)
// ---------------------------------------------------------------------------

describe("plan tier unchanged", () => {
  test("makeDepUpgradeWork still produces a structurally-valid plan that observeDelivered accepts", async () => {
    const work = makeDepUpgradeWork(lodashFallbackRegistry());
    const res = await work("job-plan", { packageJson: JSON.parse(VULN_PKG) });
    const r = res.result as { planned: number; security: number };
    assert.ok(r.planned >= 1 && r.security >= 1, "plan still finds the lodash security bump");
    const att: DeliveryAttestation = {
      kind: "dacs-x-delivery-attestation",
      serviceId: "dep-upgrade-plan",
      jobId: "job-plan",
      resultHash: sha256Hex(JSON.stringify(res.result)),
      deliverableRef: res.deliverableRef,
      meta: res.meta,
      deliveredAt: new Date().toISOString(),
    };
    const observed = await depUpgradeObserveDelivered()!(att);
    assert.ok(observed.ok, `plan observeDelivered should pass: ${observed.ok ? "" : observed.reason}`);
  });
});

// ---------------------------------------------------------------------------
// 7. Executor wire round-trip (work → observeDelivered)
// ---------------------------------------------------------------------------

describe("executor wire", () => {
  test("makeDepUpgradeExecuteWork delivers an artifact observeDelivered re-verifies", async () => {
    const ws = await makeWorkspace(VULN_PKG);
    try {
      const work = makeDepUpgradeExecuteWork({
        repo: new FakeRepo(fetchedFor(ws.dir, VULN_PKG)),
        sandbox: new FakeSandbox({}, true),
        registry: lodashFallbackRegistry(),
      });
      const res = await work("job-exec", { repo: "acme/app", ref: "main" });
      const r = res.result as { verdict: string; upgraded: number; advisoriesCleared: boolean };
      assert.equal(r.verdict, "upgraded-green");
      assert.equal(r.upgraded, 1);
      assert.equal(r.advisoriesCleared, true);
      const att: DeliveryAttestation = {
        kind: "dacs-x-delivery-attestation",
        serviceId: "dep-upgrade-execute",
        jobId: "job-exec",
        resultHash: sha256Hex(JSON.stringify(res.result)),
        deliverableRef: res.deliverableRef,
        meta: res.meta,
        deliveredAt: new Date().toISOString(),
      };
      const observed = await depUpgradeExecuteObserveDelivered()!(att);
      assert.ok(observed.ok, `exec observeDelivered should pass: ${observed.ok ? "" : observed.reason}`);
    } finally {
      await ws.cleanup();
    }
  });

  test("missing repo param throws", async () => {
    const work = makeDepUpgradeExecuteWork({ repo: new FakeRepo(fetchedFor("x", VULN_PKG)), sandbox: new FakeSandbox({}, true), registry: lodashFallbackRegistry() });
    await assert.rejects(() => work("j", {}), /params\.repo/);
  });
});

// ---------------------------------------------------------------------------
// 8. Pricing — priced by work done, reproducible from the artifact
// ---------------------------------------------------------------------------

describe("executor pricing", () => {
  test("base + per-upgraded-dep + per-check; deterministic", () => {
    // base 4 + 2·1 upgraded + 1·2 checks = 8
    assert.equal(executePriceFor(1, 2), 8);
    // base 4 + 2·3 + 1·4 = 14
    assert.equal(executePriceFor(3, 4), 14);
    // a no-op (0 upgrades, 0 checks) is just the base
    assert.equal(executePriceFor(0, 0), EXECUTE_PRICING.base);
  });

  test("the bill is reproducible from the sealed artifact (after.length, checks.length)", async () => {
    const { artifact, ws } = await runOn(VULN_PKG);
    try {
      const fromArtifact = executePriceFor(artifact.after.length, artifact.checks.length);
      assert.equal(fromArtifact, executePriceFor(1, 2)); // 1 upgrade, install+test
    } finally {
      await ws.cleanup();
    }
  });
});

// ---------------------------------------------------------------------------
// 9. docker argv isolation (what the VPS runs)
// ---------------------------------------------------------------------------

describe("docker argv isolation", () => {
  test("every check spec is isolated; only install takes the network", () => {
    const preview = executeCheckArgvPreview();
    assert.ok(preview.every((p) => p.isolated), "all checks isolated (read-only, cap-drop, no-new-privileges)");
    assert.equal(preview.find((p) => p.name === "install")!.network, "limited");
    assert.ok(preview.filter((p) => p.name !== "install").every((p) => p.network === "none"));
  });
});

// ---------------------------------------------------------------------------
// 10. Quorum substrate (ADDITIVE seam) — compareReRuns adjudication + verify
// ---------------------------------------------------------------------------

describe("compareReRuns adjudication", () => {
  const rr = (verdict: ExecReport["verdict"], hashes: Record<string, string>): ReRunArtifact => ({
    verdict,
    checks: Object.entries(hashes).map(([name, normalizedOutputHash]) => ({ name, normalizedOutputHash })),
  });

  test("identical normalized hashes + verdict → unanimous agree", () => {
    const a = rr("upgraded-green", { install: "aa", test: "bb" });
    const b = rr("upgraded-green", { install: "aa", test: "bb" });
    const c = rr("upgraded-green", { install: "aa", test: "bb" });
    const cmp = compareReRuns([a, b, c]);
    assert.equal(cmp.agree, true);
    assert.equal(cmp.verdictAgree, true);
    assert.deepEqual(cmp.divergentIndices, []);
    assert.ok(cmp.checks.every((ch) => ch.agree));
  });

  test("one divergent test hash → flagged as the minority, not agreed", () => {
    const a = rr("upgraded-green", { install: "aa", test: "bb" });
    const b = rr("upgraded-green", { install: "aa", test: "bb" });
    const c = rr("upgrade-breaks-suite", { install: "aa", test: "XX" }); // the liar / faulty re-runner
    const cmp = compareReRuns([a, b, c]);
    assert.equal(cmp.agree, false);
    assert.deepEqual(cmp.divergentIndices, [2]);
    const testCheck = cmp.checks.find((ch) => ch.name === "test")!;
    assert.equal(testCheck.agree, false);
    assert.deepEqual(testCheck.hashes, ["bb", "bb", "XX"]);
  });

  test("a missing gating check counts as divergence (not a silent agree)", () => {
    const a = rr("upgraded-green", { install: "aa", test: "bb" });
    const b = rr("upgraded-untested", { install: "aa" }); // no test check
    const cmp = compareReRuns([a, b]);
    assert.equal(cmp.agree, false);
    assert.equal(cmp.checks.find((ch) => ch.name === "test")!.agree, false);
  });

  test("an indeterminate re-run never agrees with a green one", () => {
    const a = rr("upgraded-green", { install: "aa", test: "bb" });
    const b = rr("indeterminate", {});
    const cmp = compareReRuns([a, b]);
    assert.equal(cmp.agree, false);
    assert.equal(cmp.verdictAgree, false);
  });
});

describe("quorum seam verification (additive, no fail-open)", () => {
  async function greenCore() {
    const { artifact, ws } = await runOn(VULN_PKG);
    await ws.cleanup();
    const { seal: _s, ...core } = artifact;
    return { artifact, core };
  }

  function goodQuorum(): QuorumAttestation {
    return {
      scheme: "DACS-quorum-mofn",
      note: "SHAPE ONLY — no live multi-signer network yet.",
      normalizationVersion: NORMALIZATION_VERSION,
      pinnedInputsDigest: "a".repeat(64),
      threshold: 2,
      total: 3,
      signatures: [
        { signer: "did:one", signature: "sig1" },
        { signer: "did:two", signature: "sig2" },
      ],
    };
  }

  test("a well-formed quorum-attested artifact verifies", async () => {
    const { core } = await greenCore();
    const sealed = reseal({ ...core, provenance: "quorum-attested" });
    const artifact = { ...sealed, seal: { ...sealed.seal, quorum: goodQuorum() } };
    const v = verifyExecReport(artifact);
    assert.ok(v.valid, v.problems.join("; "));
  });

  test("provenance quorum-attested but no quorum set → rejected", async () => {
    const { core } = await greenCore();
    const bad = reseal({ ...core, provenance: "quorum-attested" }); // seal has no quorum
    const v = verifyExecReport(bad);
    assert.equal(v.valid, false);
    assert.ok(v.problems.some((p) => /quorum is missing/i.test(p)));
  });

  test("fewer distinct signers than threshold → rejected (no fail-open)", async () => {
    const { core } = await greenCore();
    const sealed = reseal({ ...core, provenance: "quorum-attested" });
    const q = { ...goodQuorum(), signatures: [{ signer: "did:one", signature: "sig1" }] }; // 1 < threshold 2
    const v = verifyExecReport({ ...sealed, seal: { ...sealed.seal, quorum: q } });
    assert.equal(v.valid, false);
    assert.ok(v.problems.some((p) => /< threshold/i.test(p)));
  });

  test("duplicate signers are not distinct → rejected", async () => {
    const { core } = await greenCore();
    const sealed = reseal({ ...core, provenance: "quorum-attested" });
    const q = {
      ...goodQuorum(),
      signatures: [
        { signer: "did:one", signature: "sig1" },
        { signer: "did:one", signature: "sig1b" },
      ],
    };
    const v = verifyExecReport({ ...sealed, seal: { ...sealed.seal, quorum: q } });
    assert.equal(v.valid, false);
    assert.ok(v.problems.some((p) => /not distinct/i.test(p)));
  });

  test("normalizationVersion mismatch → rejected (consensus-parameter guard)", async () => {
    const { core } = await greenCore();
    const sealed = reseal({ ...core, provenance: "quorum-attested" });
    const q = { ...goodQuorum(), normalizationVersion: "999" };
    const v = verifyExecReport({ ...sealed, seal: { ...sealed.seal, quorum: q } });
    assert.equal(v.valid, false);
    assert.ok(v.problems.some((p) => /normalizationVersion/i.test(p)));
  });

  test("quorum present but provenance self-attested → rejected", async () => {
    const { core } = await greenCore();
    const sealed = reseal({ ...core }); // provenance stays self-attested
    const v = verifyExecReport({ ...sealed, seal: { ...sealed.seal, quorum: goodQuorum() } });
    assert.equal(v.valid, false);
    assert.ok(v.problems.some((p) => /not 'quorum-attested'/i.test(p)));
  });

  test("pinnedInputsDigest is stable + covers the pinned inputs", () => {
    const base = {
      repo: "acme/app",
      headSha: "execsha0000000",
      patchHash: "b".repeat(64),
      image: "node@sha256:" + "c".repeat(64),
      sourceDateEpoch: 1_700_000_000,
      checkCmds: [["npm", "ci"], ["npm", "test"]],
      normalizationVersion: NORMALIZATION_VERSION,
    };
    const d1 = pinnedInputsDigest(base);
    const d2 = pinnedInputsDigest({ ...base });
    assert.equal(d1, d2, "same inputs → same digest");
    assert.notEqual(d1, pinnedInputsDigest({ ...base, headSha: "different" }));
  });
});
