/**
 * Security-Audit DEEP TIER demo:
 *
 *   npm run roster:secaudit-deep
 *
 * Shows the reputation-staked auditor end to end WITHOUT a Docker daemon (it is
 * down in this environment):
 *
 *  0. Attempts a REAL `git` clone of a small public repo via RepoFetchPort
 *     (LiveRepo.fetchRef) to prove the fetch seam works against GitHub; prints
 *     the resolved head SHA (or the reason it couldn't, offline).
 *  1. Runs the DEEP pipeline over a real on-disk tree (a temp copy of the
 *     bundled intentionally-vulnerable fixture) through a SEEDING fake sandbox
 *     that stands in for the real containers: it writes canned Semgrep + Slither
 *     JSON (the shape the real tools emit) into the mounted workspace, exactly
 *     as `returntocorp/semgrep` / `trailofbits/slither` would on the VPS. The
 *     parse → normalize → attest → verify pipeline is REAL.
 *  2. Runs the REAL quick-scan regex tier over the same tree (real work).
 *  3. Runs the REAL dependency-advisory scan (live npm endpoint → canned fallback).
 *  4. Prints the attested findings artifact and re-verifies it offline, then
 *     tampers the verdict to show the no-fail-open backbone catch.
 *  5. Dry-constructs + validates the `docker run` argv for the Semgrep/Slither
 *     images (the security-critical isolation flags), which is exactly what runs
 *     on the VPS when the daemon is up.
 *
 * NOTE: real Semgrep/Slither container execution happens on the VPS when the
 * Docker daemon is reachable; here every tool result is canned + clearly labeled.
 */
import { cp, rm, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { mkdtemp } from "node:fs/promises";
import { buildDockerArgs, hashOutput, normalizedOutputHash, sandboxOutputTail, type CheckResult, type CheckSpec, type SandboxPort } from "../../src/agents/sandbox.js";
import { FakeRepo, LiveRepo, type FetchedPr } from "../../src/agents/repo-fetch.js";
import { RealRegistry, lodashFallbackRegistry } from "../dep-upgrade/registry.js";
import type { RegistryPort } from "../dep-upgrade/types.js";
import { runAudit } from "./auditor.js";
import {
  SEMGREP_TOOL,
  SLITHER_TOOL,
  TOOL_OUTPUT_DIR,
  deepToolCheckSpec,
  runDeepAudit,
  verifyDeepAudit,
  type DeepAuditArtifact,
} from "./deep-audit.js";
import { MockDahrAttestor, canonicalJson } from "./attest-files.js";
import { sha256Hex } from "../oracle-desk/attested-fetch.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixtureDir = join(here, "fixture");
const hr = (t: string) => console.log(`\n=== ${t} ${"=".repeat(Math.max(0, 60 - t.length))}`);

// Canned tool output (the shape the real containers emit), referencing the
// fixture's files so gatherExcerpts + the verdict backbone are exercised.
const SEMGREP_JSON = JSON.stringify({
  results: [
    { check_id: "javascript.lang.security.audit.code-eval", path: "/workspace/app.js", start: { line: 8 }, extra: { severity: "ERROR", message: "Use of eval() on untrusted input" } },
    { check_id: "generic.secrets.security.detected-aws-key", path: "/workspace/app.js", start: { line: 2 }, extra: { severity: "WARNING", message: "Possible hardcoded AWS key" } },
  ],
  errors: [],
});
const SLITHER_JSON = JSON.stringify({
  success: true,
  error: null,
  results: {
    detectors: [
      { check: "reentrancy-eth", impact: "High", confidence: "Medium", description: "Reentrancy in Vault.withdraw()", elements: [{ type: "function", name: "withdraw", source_mapping: { filename_relative: "Vault.sol", lines: [24, 25, 26] } }] },
      { check: "solc-version", impact: "Informational", confidence: "High", description: "Floating pragma is used", elements: [{ type: "pragma", source_mapping: { filename_relative: "Vault.sol", lines: [1] } }] },
    ],
  },
});

/**
 * A fake sandbox that STANDS IN for the real containers: it reports available,
 * and on each `run()` writes the canned tool JSON into the mounted workspace
 * (as the real tool would) so `runDeepTools` reads + hashes + parses a real file.
 * It records every call so we can show which tools "ran".
 */
class SeedingSandbox implements SandboxPort {
  readonly calls: CheckSpec[] = [];
  async available(): Promise<boolean> {
    return true;
  }
  async run(spec: CheckSpec): Promise<CheckResult> {
    this.calls.push(spec);
    const which = spec.name.endsWith("semgrep") ? SEMGREP_JSON : spec.name.endsWith("slither") ? SLITHER_JSON : "{}";
    const out = join(spec.workspaceDir, TOOL_OUTPUT_DIR, spec.name.endsWith("semgrep") ? "semgrep.json" : "slither.json");
    await import("node:fs/promises").then((fs) => fs.writeFile(out, which, "utf8"));
    const tail = `(seeded ${spec.name})`;
    return { name: spec.name, cmd: spec.cmd, exitCode: 1, passed: false, durationMs: 3, outputTail: sandboxOutputTail(tail), outputHash: hashOutput(tail), normalizedOutputHash: normalizedOutputHash(tail) };
  }
}

// ---------------------------------------------------------------------------
// 0. Prove the RepoFetchPort clone seam against a real GitHub repo.
// ---------------------------------------------------------------------------
hr("0. RepoFetchPort — real clone (fetchRef)");
{
  const live = new LiveRepo();
  let cloned: FetchedPr | undefined;
  try {
    cloned = await live.fetchRef("octocat/Hello-World");
    console.log(`  cloned octocat/Hello-World @ ${cloned.headSha.slice(0, 12)} → ${cloned.workspaceDir}`);
    console.log(`  projectType=${cloned.projectType} (whole-repo audit, no PR diff)`);
  } catch (err) {
    console.log(`  (offline / no gh+git) real clone skipped: ${(err as Error).message.split("\n")[0]}`);
  } finally {
    if (cloned) await live.cleanup(cloned.workspaceDir);
  }
}

// ---------------------------------------------------------------------------
// Registry mode for the deep + quick dependency scans.
// ---------------------------------------------------------------------------
let registry: RegistryPort;
let registryLabel: "live" | "canned";
try {
  const real = new RealRegistry(10_000);
  const probe = await real.getAdvisories({ lodash: ["4.17.20"] });
  if ((probe.get("lodash") ?? []).length === 0) throw new Error("no advisories returned");
  registry = real;
  registryLabel = "live";
} catch (err) {
  console.warn(`\nWARNING: live advisory endpoint unusable (${(err as Error).message}); using canned lodash registry.`);
  registry = lodashFallbackRegistry();
  registryLabel = "canned";
}

// ---------------------------------------------------------------------------
// 1. DEEP pipeline over a temp copy of the fixture (Docker DOWN → seeded tools).
// ---------------------------------------------------------------------------
hr("1. Deep audit (real tree, SEEDED tools — Docker daemon is down)");
const tempWs = await mkdtemp(join(tmpdir(), "secaudit-deep-demo-"));
await cp(fixtureDir, tempWs, { recursive: true });

let artifact: DeepAuditArtifact;
try {
  const sandbox = new SeedingSandbox();
  const repo = new FakeRepo({ workspaceDir: tempWs, headSha: "demo0headsha0000", diff: "", projectType: "node", packageJson: await readFile(join(tempWs, "package.json"), "utf8").catch(() => undefined) });
  artifact = await runDeepAudit({ repo, sandbox, registry }, { repo: "demo/fixture", ref: "main" });
  console.log(`  sandbox tools run: ${sandbox.calls.map((c) => c.name).join(", ")}  (real containers on VPS when daemon up)`);
  console.log(`  advisory data: ${registryLabel}`);
} finally {
  // (workspace cleaned by runDeepAudit's finally via FakeRepo — which only
  //  records; remove the temp copy ourselves.)
  await rm(tempWs, { recursive: true, force: true });
}

console.log(`\n  verdict: ${artifact.verdict.toUpperCase()}`);
console.log(`  ── attested tools (per-tool reproducibility commitments) ──`);
for (const t of artifact.tools) {
  console.log(`    ${t.name.padEnd(13)} image=${t.image.padEnd(34)} findings=${String(t.findingCount).padStart(2)}  outputHash sha256:${t.outputHash.slice(0, 16)}…`);
}
console.log(`  ── findings ──`);
for (const f of artifact.findings) {
  console.log(`    [${f.severity.padEnd(8)}] ${f.tool.padEnd(12)} ${f.ruleId.slice(0, 40).padEnd(40)} ${f.file}:${f.line}`);
}
console.log(`  summary: ${artifact.summary}`);
console.log(`  seal: sha256:${artifact.seal.bodyHash.slice(0, 20)}…  provenance=${artifact.provenance}`);

// ---------------------------------------------------------------------------
// 2. REAL quick-scan tier over the same fixture (real regex work).
// ---------------------------------------------------------------------------
hr("2. Quick-scan tier (REAL regex rules — the cheap tier, unchanged)");
const quick = await runAudit({ targetDir: fixtureDir, mode: "auto" }, { registry, registryLabel });
console.log(`  ${quick.findings.length} deterministic finding(s) over ${quick.files.length} files; deps: ${quick.deps.mode}`);
for (const f of quick.findings.slice(0, 6)) console.log(`    [${f.severity.padEnd(8)}] ${f.ruleId.padEnd(28)} ${f.file}:${f.line}`);

// ---------------------------------------------------------------------------
// 3. Verify the attested artifact, then tamper it.
// ---------------------------------------------------------------------------
hr("3. Verify attested findings + no-fail-open backbone");
const v = verifyDeepAudit(artifact);
console.log(`  verifyDeepAudit: valid=${v.valid} toolsChecked=${v.toolsChecked} findingsChecked=${v.findingsChecked}`);

// Tamper: force "clean" over the tool-reported criticals, re-seal with a fresh
// key (a validly self-signed but dishonest artifact) → the backbone must reject.
const { seal: _drop, ...core } = artifact;
const tamperedCore = { ...core, verdict: "clean" as const };
const attestor = new MockDahrAttestor();
const bodyHash = sha256Hex(canonicalJson(tamperedCore));
const url = `report:sec-audit-deep:${tamperedCore.generatedAt}`;
const tampered: DeepAuditArtifact = { ...tamperedCore, seal: { url, bodyHash, attestation: attestor.attest(url, tamperedCore.generatedAt, bodyHash) } };
const tv = verifyDeepAudit(tampered);
console.log(`  tampered ("clean" over criticals, re-signed): valid=${tv.valid}`);
console.log(`    caught: ${tv.problems.join(" | ")}`);

// ---------------------------------------------------------------------------
// 4. Dry-construct the docker run argv the VPS would execute.
// ---------------------------------------------------------------------------
hr("4. docker run argv (validated; executed on the VPS when daemon is up)");
for (const tool of [SEMGREP_TOOL, SLITHER_TOOL]) {
  const args = buildDockerArgs(deepToolCheckSpec(tool, "/srv/jobs/<workspace>"));
  const isolated = args.includes("--read-only") && args.includes("--cap-drop") && args.includes("no-new-privileges");
  const net = args[args.indexOf("--network") + 1];
  console.log(`  ${tool.name}: network=${net}  isolated=${isolated}`);
  console.log(`    docker ${args.join(" ")}`);
}

// ---------------------------------------------------------------------------
hr("Result");
const ok = v.valid && !tv.valid && artifact.verdict === "critical-issues";
if (ok) {
  console.log("  attested findings verify; tampered verdict rejected; quick + deep tiers ran — exit 0");
} else {
  console.error("  demo expectations FAILED — exit 1");
  process.exitCode = 1;
}
