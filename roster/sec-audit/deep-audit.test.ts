/**
 * Security-Audit DEEP TIER tests — fully offline: FakeSandbox + FakeRepo, canned
 * Semgrep/Slither JSON, no Docker, no network, no LLM.
 *
 *   npx tsx --test roster/sec-audit/deep-audit.test.ts
 *
 * Covers: tool-JSON parsing (incl. malformed → degrade, not crash), fail-safe
 * (no sandbox → indeterminate, host runner never invoked), verdict backbone
 * (tool-reported critical → not "clean"), attested-artifact sign/verify + every
 * tampered/missing binding rejected, docker-arg isolation, pricing, and the
 * quick-scan tier staying independent of the deep tier.
 */
import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FakeSandbox, buildDockerArgs } from "../../src/agents/sandbox.js";
import { FakeRepo, type FetchedPr } from "../../src/agents/repo-fetch.js";
import { lodashFallbackRegistry } from "../dep-upgrade/registry.js";
import { MockDahrAttestor, canonicalJson } from "./attest-files.js";
import { sha256Hex } from "../oracle-desk/attested-fetch.js";
import { auditPostedFiles } from "../dacs/wire/sec-audit.js";
import {
  DEEP_AUDIT_PRICING,
  SEMGREP_TOOL,
  SLITHER_TOOL,
  TOOL_OUTPUT_DIR,
  combineDeepVerdict,
  deepAuditPriceFor,
  deepFindingContentHash,
  deepToolCheckSpec,
  mechanicalFloor,
  parseSemgrepJson,
  parseSlitherJson,
  planTools,
  runDeepAudit,
  runDeepTools,
  toolFindingsHash,
  verifyDeepAudit,
  type DeepAuditArtifact,
  type DeepFinding,
} from "./deep-audit.js";

// ---------------------------------------------------------------------------
// Canned tool output
// ---------------------------------------------------------------------------

const SEMGREP_JSON = JSON.stringify({
  results: [
    {
      check_id: "javascript.lang.security.audit.code-string-concat",
      path: "/workspace/app.js",
      start: { line: 12 },
      extra: { severity: "ERROR", message: "Detected possible command injection via string concatenation" },
    },
    {
      check_id: "generic.secrets.security.detected-generic-secret",
      path: "/workspace/app.js",
      start: { line: 3 },
      extra: { severity: "WARNING", message: "Hardcoded secret literal" },
    },
  ],
  errors: [],
});

const SLITHER_JSON = JSON.stringify({
  success: true,
  error: null,
  results: {
    detectors: [
      {
        check: "reentrancy-eth",
        impact: "High",
        confidence: "Medium",
        description: "Reentrancy in Vault.withdraw()",
        elements: [
          { type: "function", name: "withdraw", source_mapping: { filename_relative: "Vault.sol", lines: [20, 21, 22] } },
        ],
      },
      {
        check: "solc-version",
        impact: "Informational",
        confidence: "High",
        description: "Different pragma directives are used",
        elements: [{ type: "pragma", source_mapping: { filename_relative: "Vault.sol", lines: [1] } }],
      },
    ],
  },
});

// ---------------------------------------------------------------------------
// Workspace fixtures (real temp dirs seeded like a tool would leave them)
// ---------------------------------------------------------------------------

interface Workspace {
  dir: string;
  cleanup: () => Promise<void>;
}

async function makeWorkspace(opts: {
  semgrep?: string;
  slither?: string;
  withSolidity?: boolean;
  packageJson?: string;
} = {}): Promise<Workspace> {
  const dir = await mkdtemp(join(tmpdir(), "deep-audit-test-"));
  await writeFile(join(dir, "app.js"), "const key='AKIA';\nconsole.log(1);\nexec('rm '+userInput);\n", "utf8");
  if (opts.withSolidity !== false) {
    await writeFile(join(dir, "Vault.sol"), "pragma solidity ^0.8.0;\ncontract Vault {}\n", "utf8");
  }
  if (opts.packageJson) await writeFile(join(dir, "package.json"), opts.packageJson, "utf8");
  await mkdir(join(dir, TOOL_OUTPUT_DIR), { recursive: true });
  if (opts.semgrep !== undefined) await writeFile(join(dir, TOOL_OUTPUT_DIR, "semgrep.json"), opts.semgrep, "utf8");
  if (opts.slither !== undefined) await writeFile(join(dir, TOOL_OUTPUT_DIR, "slither.json"), opts.slither, "utf8");
  return { dir, cleanup: () => rm(dir, { recursive: true, force: true }) };
}

function fetchedFor(dir: string, extra: Partial<FetchedPr> = {}): FetchedPr {
  return { workspaceDir: dir, headSha: "abc123def456", diff: "", projectType: "node", ...extra };
}

/** Re-seal a mutated core with a FRESH attestor — a validly self-signed but
 *  potentially inconsistent artifact (the adversary the granular checks catch). */
function reseal(core: Omit<DeepAuditArtifact, "seal">): DeepAuditArtifact {
  const attestor = new MockDahrAttestor();
  const bodyHash = sha256Hex(canonicalJson(core));
  const url = `report:sec-audit-deep:${core.generatedAt}`;
  return { ...core, seal: { url, bodyHash, attestation: attestor.attest(url, core.generatedAt, bodyHash) } };
}

// ---------------------------------------------------------------------------
// 1. Tool-output parsing
// ---------------------------------------------------------------------------

describe("tool-output parsing", () => {
  test("Semgrep JSON → normalized findings with severity mapping", () => {
    const { findings, parseError } = parseSemgrepJson(SEMGREP_JSON);
    assert.equal(parseError, undefined);
    assert.equal(findings.length, 2);
    const high = findings.find((f) => f.severity === "high");
    assert.ok(high, "ERROR maps to high");
    assert.equal(high?.file, "app.js"); // /workspace/ prefix stripped
    assert.equal(high?.line, 12);
    assert.equal(findings.find((f) => f.severity === "medium")?.file, "app.js"); // WARNING → medium
    assert.ok(findings.every((f) => f.tool === "semgrep" && f.origin === "tool"));
  });

  test("Slither JSON → normalized findings, impact mapping + source mapping", () => {
    const { findings, parseError } = parseSlitherJson(SLITHER_JSON);
    assert.equal(parseError, undefined);
    assert.equal(findings.length, 2);
    const re = findings.find((f) => f.ruleId === "reentrancy-eth");
    assert.equal(re?.severity, "high");
    assert.equal(re?.file, "Vault.sol");
    assert.equal(re?.line, 20);
    assert.equal(findings.find((f) => f.ruleId === "solc-version")?.severity, "info");
  });

  test("malformed JSON degrades to 0 findings + a parseError (never throws)", () => {
    const sem = parseSemgrepJson("{not valid json");
    assert.equal(sem.findings.length, 0);
    assert.match(sem.parseError ?? "", /did not parse/);
    const slith = parseSlitherJson('{"results":{"detectors":"nope"}}');
    assert.equal(slith.findings.length, 0);
    assert.match(slith.parseError ?? "", /detectors/);
    // Unexpected-but-valid JSON: no results[] → degrade, no throw.
    assert.equal(parseSemgrepJson('{"foo":1}').findings.length, 0);
  });

  test("contentHash covers every field; a severity edit changes it", () => {
    const [f] = parseSemgrepJson(SEMGREP_JSON).findings;
    const softened = deepFindingContentHash({ ...f, severity: "info" });
    assert.notEqual(softened, f.contentHash);
  });
});

// ---------------------------------------------------------------------------
// 2. Tool planning + sandboxed execution (FakeSandbox)
// ---------------------------------------------------------------------------

describe("tool planning + sandboxed run", () => {
  test("planTools adds Slither only when a .sol file is present", async () => {
    const withSol = await makeWorkspace({ withSolidity: true });
    const noSol = await makeWorkspace({ withSolidity: false });
    try {
      assert.deepEqual((await planTools(withSol.dir)).map((t) => t.name), ["semgrep", "slither"]);
      assert.deepEqual((await planTools(noSol.dir)).map((t) => t.name), ["semgrep"]);
    } finally {
      await withSol.cleanup();
      await noSol.cleanup();
    }
  });

  test("runDeepTools drives the sandbox, reads back JSON, binds outputHash + findingsHash", async () => {
    const ws = await makeWorkspace({ semgrep: SEMGREP_JSON, slither: SLITHER_JSON, withSolidity: true });
    const sandbox = new FakeSandbox({}, true);
    try {
      const { ran, tools, findings } = await runDeepTools(sandbox, fetchedFor(ws.dir));
      assert.equal(ran, true);
      assert.equal(tools.length, 2);
      assert.equal(findings.length, 4); // 2 semgrep + 2 slither
      // Every tool ran in the SANDBOX (host runner never used).
      assert.equal(sandbox.calls.length, 2);
      const sem = tools.find((t) => t.name === "semgrep")!;
      assert.equal(sem.findingCount, 2);
      assert.ok(sem.outputHash.length === 64, "outputHash is a sha256 hex");
      assert.equal(sem.findingsHash, toolFindingsHash(findings.filter((f) => f.tool === "semgrep")));
    } finally {
      await ws.cleanup();
    }
  });

  test("a missing/malformed report degrades (note set), does not crash", async () => {
    const ws = await makeWorkspace({ semgrep: "{broken", withSolidity: false });
    const sandbox = new FakeSandbox({}, true);
    try {
      const { tools, findings } = await runDeepTools(sandbox, fetchedFor(ws.dir));
      assert.equal(findings.length, 0);
      assert.match(tools[0].note ?? "", /did not parse/);
    } finally {
      await ws.cleanup();
    }
  });
});

// ---------------------------------------------------------------------------
// 3. Verdict backbone
// ---------------------------------------------------------------------------

describe("verdict backbone", () => {
  const mkTool = (sev: DeepFinding["severity"]): DeepFinding[] =>
    parseSemgrepJson(
      JSON.stringify({
        results: [{ check_id: "r", path: "a.js", start: { line: 1 }, extra: { severity: sev === "high" ? "ERROR" : "WARNING", message: "m" } }],
      }),
    ).findings;

  test("no sandbox → indeterminate", () => {
    assert.equal(combineDeepVerdict(false, mkTool("high")), "indeterminate");
  });
  test("a high/critical tool finding → critical-issues (never clean)", () => {
    assert.equal(combineDeepVerdict(true, mkTool("high")), "critical-issues");
  });
  test("only medium/low → issues-found", () => {
    assert.equal(combineDeepVerdict(true, mkTool("medium")), "issues-found");
  });
  test("no findings → clean", () => {
    assert.equal(combineDeepVerdict(true, []), "clean");
  });
  test("LLM-origin findings never raise the mechanical floor", () => {
    const llm: DeepFinding = {
      tool: "llm-review",
      origin: "llm",
      ruleId: "llm-x",
      severity: "critical",
      file: "a.js",
      line: 1,
      message: "m",
      contentHash: "x",
    };
    assert.equal(mechanicalFloor([llm]), 0);
  });
});

// ---------------------------------------------------------------------------
// 4. End-to-end runDeepAudit + fail-safe
// ---------------------------------------------------------------------------

describe("runDeepAudit", () => {
  test("fail-safe: no sandbox → indeterminate and the sandbox is NEVER run", async () => {
    const sandbox = new FakeSandbox({}, false);
    const repo = new FakeRepo(fetchedFor("(placeholder — never mounted)"));
    const artifact = await runDeepAudit({ repo, sandbox }, { repo: "acme/thing", ref: "main" });
    assert.equal(artifact.verdict, "indeterminate");
    assert.equal(artifact.sandboxAvailable, false);
    assert.equal(artifact.tools.length, 0);
    assert.equal(artifact.findings.length, 0);
    assert.equal(sandbox.calls.length, 0, "host/sandbox runner never invoked when no sandbox");
    assert.equal(verifyDeepAudit(artifact).valid, true);
  });

  test("full run: tools + advisory + LLM → sealed artifact that verifies", async () => {
    const ws = await makeWorkspace({
      semgrep: SEMGREP_JSON,
      slither: SLITHER_JSON,
      withSolidity: true,
      packageJson: JSON.stringify({ name: "t", dependencies: { lodash: "4.17.20" } }),
    });
    const sandbox = new FakeSandbox({}, true);
    const repo = new FakeRepo(fetchedFor(ws.dir, { packageJson: JSON.stringify({ name: "t", dependencies: { lodash: "4.17.20" } }) }));
    try {
      const artifact = await runDeepAudit(
        { repo, sandbox, registry: lodashFallbackRegistry(), review: async () => ({ summary: "prioritized", findings: [] }) },
        { repo: "acme/thing", pullNumber: 7 },
      );
      assert.equal(artifact.sandboxAvailable, true);
      assert.equal(artifact.verdict, "critical-issues"); // reentrancy(high) + semgrep ERROR + lodash(high)
      assert.deepEqual(artifact.tools.map((t) => t.name).sort(), ["dep-advisory", "llm-review", "semgrep", "slither"]);
      assert.ok(artifact.findings.some((f) => f.tool === "dep-advisory"));
      assert.equal(artifact.ref, "pr:7");
      const v = verifyDeepAudit(artifact);
      assert.ok(v.valid, `should verify: ${v.problems.join("; ")}`);
      assert.ok(v.toolsChecked >= 3 && v.findingsChecked >= 5);
    } finally {
      await ws.cleanup();
    }
  });
});

// ---------------------------------------------------------------------------
// 5. Attested artifact — every tampered/missing binding rejected
// ---------------------------------------------------------------------------

describe("verifyDeepAudit rejects tampering (no fail-open)", () => {
  async function goodArtifact(): Promise<DeepAuditArtifact> {
    const ws = await makeWorkspace({ semgrep: SEMGREP_JSON, slither: SLITHER_JSON, withSolidity: true });
    const sandbox = new FakeSandbox({}, true);
    const repo = new FakeRepo(fetchedFor(ws.dir));
    const artifact = await runDeepAudit({ repo, sandbox, review: async () => ({ summary: "s", findings: [] }) }, { repo: "acme/thing", ref: "main" });
    await ws.cleanup();
    return artifact;
  }
  const core = (a: DeepAuditArtifact): Omit<DeepAuditArtifact, "seal"> => {
    const { seal: _s, ...c } = a;
    return c;
  };

  test("baseline verifies", async () => {
    assert.equal(verifyDeepAudit(await goodArtifact()).valid, true);
  });

  test("tampering a field without re-sealing breaks the seal hash", async () => {
    const a = JSON.parse(JSON.stringify(await goodArtifact())) as DeepAuditArtifact;
    a.target = "evil/repo";
    const v = verifyDeepAudit(a);
    assert.equal(v.valid, false);
    assert.ok(v.problems.some((p) => /seal/.test(p)));
  });

  test("softening a finding severity (contentHash stale) is caught", async () => {
    const a = JSON.parse(JSON.stringify(await goodArtifact())) as DeepAuditArtifact;
    const idx = a.findings.findIndex((f) => f.severity === "high");
    a.findings[idx].severity = "info";
    const v = verifyDeepAudit(reseal(core(a))); // re-seal so we test the granular binding, not the seal
    assert.equal(v.valid, false);
    assert.ok(v.problems.some((p) => /contentHash/.test(p)));
  });

  test("re-hashing a softened finding still breaks the tool's findingsHash", async () => {
    const a = JSON.parse(JSON.stringify(await goodArtifact())) as DeepAuditArtifact;
    const idx = a.findings.findIndex((f) => f.severity === "high");
    a.findings[idx].severity = "info";
    a.findings[idx].contentHash = deepFindingContentHash(a.findings[idx]); // adversary recomputes
    const v = verifyDeepAudit(reseal(core(a)));
    assert.equal(v.valid, false);
    assert.ok(v.problems.some((p) => /findingsHash/.test(p)));
  });

  test("removing a finding breaks its tool's findingsHash + findingCount", async () => {
    const a = JSON.parse(JSON.stringify(await goodArtifact())) as DeepAuditArtifact;
    a.findings = a.findings.filter((f) => f.severity !== "high");
    const v = verifyDeepAudit(reseal(core(a)));
    assert.equal(v.valid, false);
    assert.ok(v.problems.some((p) => /findingsHash|findingCount/.test(p)));
  });

  test("an orphan finding (tool never ran) is rejected", async () => {
    const a = JSON.parse(JSON.stringify(await goodArtifact())) as DeepAuditArtifact;
    const orphan: DeepFinding = {
      tool: "ghost-tool",
      origin: "tool",
      ruleId: "x",
      severity: "low",
      file: "a.js",
      line: 1,
      message: "m",
      contentHash: "",
    };
    orphan.contentHash = deepFindingContentHash(orphan);
    a.findings.push(orphan);
    const v = verifyDeepAudit(reseal(core(a)));
    assert.equal(v.valid, false);
    assert.ok(v.problems.some((p) => /does not resolve to any attested tool/.test(p)));
  });

  test("dropping a ran tool's outputHash is rejected", async () => {
    const a = JSON.parse(JSON.stringify(await goodArtifact())) as DeepAuditArtifact;
    const sem = a.tools.find((t) => t.name === "semgrep")!;
    sem.outputHash = "";
    const v = verifyDeepAudit(reseal(core(a)));
    assert.equal(v.valid, false);
    assert.ok(v.problems.some((p) => /outputHash/.test(p)));
  });

  test("verdict 'clean' over a tool-reported critical is rejected (backbone)", async () => {
    const a = JSON.parse(JSON.stringify(await goodArtifact())) as DeepAuditArtifact;
    a.verdict = "clean"; // the LLM can't sign a clean bill over Slither's high finding
    const v = verifyDeepAudit(reseal(core(a)));
    assert.equal(v.valid, false);
    assert.ok(v.problems.some((p) => /cleaner than the mechanical floor/.test(p)));
  });

  test("indeterminate verdict with findings present is rejected", async () => {
    const a = JSON.parse(JSON.stringify(await goodArtifact())) as DeepAuditArtifact;
    a.verdict = "indeterminate";
    const v = verifyDeepAudit(reseal(core(a)));
    assert.equal(v.valid, false);
    assert.ok(v.problems.some((p) => /indeterminate/.test(p)));
  });
});

// ---------------------------------------------------------------------------
// 6. Docker-arg isolation (dry-constructed; no daemon needed)
// ---------------------------------------------------------------------------

describe("docker-arg isolation", () => {
  test("Semgrep spec: network limited (fetches rules), full isolation, image before argv", () => {
    const args = buildDockerArgs(deepToolCheckSpec(SEMGREP_TOOL, "/tmp/ws"));
    assert.ok(args.includes("--cap-drop") && args.includes("ALL"));
    assert.ok(args.includes("--read-only"));
    assert.ok(args.includes("no-new-privileges"));
    const netIdx = args.indexOf("--network");
    assert.equal(args[netIdx + 1], "bridge"); // limited → bridge
    const imgIdx = args.indexOf(SEMGREP_TOOL.image);
    assert.ok(imgIdx !== -1 && args.indexOf("semgrep", imgIdx) > imgIdx, "untrusted argv follows the image");
  });

  test("Slither spec: network none (compiles offline)", () => {
    const args = buildDockerArgs(deepToolCheckSpec(SLITHER_TOOL, "/tmp/ws"));
    const netIdx = args.indexOf("--network");
    assert.equal(args[netIdx + 1], "none");
  });
});

// ---------------------------------------------------------------------------
// 7. Pricing (deterministic) + quick-tier independence
// ---------------------------------------------------------------------------

describe("pricing + quick-tier", () => {
  test("deep pricing = base + perTool·tools + perKloc·ceil(KLOC)", () => {
    const { base, perTool, perKloc } = DEEP_AUDIT_PRICING;
    assert.equal(deepAuditPriceFor(3, 4.2), base + perTool * 3 + perKloc * 5);
    assert.equal(deepAuditPriceFor(0, 0), base);
  });

  test("quick-scan tier (auditPostedFiles) is unchanged and independent", async () => {
    const report = await auditPostedFiles([{ path: "app.js", content: "eval(userInput);\n" }]);
    assert.ok(report.findings.length >= 1, "quick regex tier still fires");
    assert.equal(report.mode, "auto");
    assert.ok(report.seal.bodyHash.length === 64);
  });
});
