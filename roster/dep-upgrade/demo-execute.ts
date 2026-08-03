/**
 * Dependency-Upgrade EXECUTOR TIER demo:
 *
 *   npm run roster:depup-exec
 *
 * Shows the attested executor end to end WITHOUT a Docker daemon (it is down in
 * this environment):
 *
 *  0. Attempts a REAL `git` clone of a small public repo via RepoFetchPort
 *     (LiveRepo.fetchRef) to prove the fetch seam works against GitHub; prints
 *     the resolved head SHA (or the reason it couldn't, offline).
 *  1. Runs the EXECUTOR pipeline over a real on-disk tree (a temp copy of the
 *     bundled vulnerable fixture: lodash pinned to 4.17.20) through a fake
 *     sandbox that stands in for the real `node:20-alpine` container: it returns
 *     GREEN install/test results (as a passing suite would on the VPS). The
 *     plan → apply → check → advisory-re-scan → attest → verify pipeline is REAL.
 *  2. Prints the before/after, the applied patch, the attested checks, and the
 *     sealed artifact; re-verifies it offline; then tampers the verdict to show
 *     the no-fail-open backbone catch (forge `upgraded-green` over a red suite).
 *  3. Dry-constructs + validates the `docker run` argv for each check (the
 *     security-critical isolation flags), which is exactly what runs on the VPS.
 *
 * NOTE: real container execution (`npm install`/`npm test` in node:20-alpine)
 * happens on the VPS when the Docker daemon is reachable; here every check
 * result is canned + clearly labeled. Real advisory reads hit the live npm
 * endpoint (canned fallback offline).
 */
import { cp, rm, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { mkdtemp } from "node:fs/promises";
import { FakeSandbox } from "../../src/agents/sandbox.js";
import { FakeRepo, LiveRepo, type FetchedPr } from "../../src/agents/repo-fetch.js";
import { RealRegistry, lodashFallbackRegistry } from "./registry.js";
import type { RegistryPort } from "./types.js";
import {
  executeCheckArgvPreview,
  executePriceFor,
  formatExecutePricing,
  runExecuteUpgrade,
  verifyExecReport,
  type ExecReport,
} from "./execute.js";
import { MockDahrAttestor, canonicalJson } from "../sec-audit/attest-files.js";
import { sha256Hex } from "../oracle-desk/attested-fetch.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixtureDir = join(here, "fixture");
const hr = (t: string) => console.log(`\n=== ${t} ${"=".repeat(Math.max(0, 60 - t.length))}`);

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
    console.log(`  projectType=${cloned.projectType}`);
  } catch (err) {
    console.log(`  (offline / no gh+git) real clone skipped: ${(err as Error).message.split("\n")[0]}`);
  } finally {
    if (cloned) await live.cleanup(cloned.workspaceDir);
  }
}

// ---------------------------------------------------------------------------
// Registry mode for the advisory intel + clearing re-scan.
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
// 1. EXECUTOR pipeline over a temp copy of the fixture (Docker DOWN → fake checks).
// ---------------------------------------------------------------------------
hr("1. Execute upgrade (real tree, GREEN fake checks — Docker daemon is down)");
const tempWs = await mkdtemp(join(tmpdir(), "dep-exec-demo-"));
await cp(fixtureDir, tempWs, { recursive: true });
const pkgText = await readFile(join(tempWs, "package.json"), "utf8");

let artifact: ExecReport;
try {
  // A fake sandbox that reports available and returns GREEN for every check —
  // exactly what a passing `npm install` + `npm test` yields in node:20-alpine.
  const sandbox = new FakeSandbox({}, true);
  const repo = new FakeRepo({ workspaceDir: tempWs, headSha: "demo0execsha0000", diff: "", projectType: "node", packageJson: pkgText });
  artifact = await runExecuteUpgrade({ repo, sandbox, registry }, { repo: "demo/fixture", ref: "main" });
  console.log(`  sandbox checks run: ${sandbox.calls.map((c) => c.name).join(", ")}  (real node:20-alpine containers on VPS when daemon up)`);
  console.log(`  advisory data: ${registryLabel}`);
} finally {
  await rm(tempWs, { recursive: true, force: true });
}

console.log(`\n  verdict: ${artifact.verdict.toUpperCase()}`);
console.log(`  ── BEFORE (vulnerable) ──`);
for (const b of artifact.before) console.log(`    ${b.dep}@${b.version}  advisories: ${b.advisories.join(", ") || "(none)"}`);
console.log(`  ── AFTER (chosen) ──`);
for (const a of artifact.after) console.log(`    ${a.dep}@${a.version}  range=${a.range}${a.breaking ? "  [BREAKING]" : ""}`);
console.log(`  advisoriesCleared: ${artifact.advisoriesCleared}  stillVulnerable: ${artifact.stillVulnerable.join(", ") || "(none)"}`);
console.log(`  ── attested checks (per-check reproducibility commitments) ──`);
for (const c of artifact.checks) {
  console.log(`    ${c.name.padEnd(10)} exit=${c.exitCode} ${c.passed ? "PASS" : "FAIL"}  outputHash sha256:${c.outputHash.slice(0, 16)}…`);
}
console.log(`  ── applied patch ──`);
console.log(`    patchHash sha256:${artifact.patchHash.slice(0, 20)}…  lockfileChanged=${artifact.patch.lockfileChanged}`);
console.log(`    package.json diff:`);
for (const line of unifiedDiffPreview(artifact.patch.beforePackageJson, artifact.patch.afterPackageJson)) {
  console.log(`      ${line}`);
}
console.log(`  summary: ${artifact.summary}`);
console.log(`  seal: sha256:${artifact.seal.bodyHash.slice(0, 20)}…  provenance=${artifact.provenance}`);
console.log(`  price: ${executePriceFor(artifact.after.length, artifact.checks.length)} DEM  (${formatExecutePricing()})`);

// ---------------------------------------------------------------------------
// 2. Verify the attested artifact, then tamper it (no-fail-open backbone).
// ---------------------------------------------------------------------------
hr("2. Verify attested artifact + no-fail-open backbone");
const v = verifyExecReport(artifact);
console.log(`  verifyExecReport: valid=${v.valid} checksChecked=${v.checksChecked}`);

// Tamper: forge "upgraded-green" over a FAILING suite, re-seal with a fresh key
// (a validly self-signed but dishonest artifact) → the backbone must reject.
const { seal: _drop, ...core } = artifact;
const forgedChecks = core.checks.map((c) => (c.name === "test" ? { ...c, exitCode: 1, passed: false } : c));
const attestor = new MockDahrAttestor();
const forgedCore = { ...core, checks: forgedChecks };
const bodyHash = sha256Hex(canonicalJson(forgedCore));
const url = `report:dep-upgrade-execute:${forgedCore.generatedAt}`;
const forged: ExecReport = { ...forgedCore, seal: { url, bodyHash, attestation: attestor.attest(url, forgedCore.generatedAt, bodyHash) } };
const fv = verifyExecReport(forged);
console.log(`  forged ("upgraded-green" over a RED test, re-signed): valid=${fv.valid}`);
console.log(`    caught: ${fv.problems.join(" | ")}`);

// ---------------------------------------------------------------------------
// 3. Dry-construct the docker run argv the VPS would execute.
// ---------------------------------------------------------------------------
hr("3. docker run argv (validated; executed on the VPS when daemon is up)");
for (const p of executeCheckArgvPreview("/srv/jobs/<workspace>")) {
  console.log(`  ${p.name.padEnd(10)} network=${p.network.padEnd(8)} isolated=${p.isolated}`);
  console.log(`    docker ${p.args.join(" ")}`);
}

// ---------------------------------------------------------------------------
hr("Result");
const ok = v.valid && !fv.valid && artifact.verdict === "upgraded-green";
if (ok) {
  console.log("  upgrade applied + proven green; attested artifact verifies; forged verdict rejected — exit 0");
} else {
  console.error("  demo expectations FAILED — exit 1");
  process.exitCode = 1;
}

/** A minimal +/- preview of the two manifests' changed lines (demo only). */
function unifiedDiffPreview(before: string, after: string): string[] {
  const b = before.split("\n");
  const a = after.split("\n");
  const out: string[] = [];
  const max = Math.max(b.length, a.length);
  for (let i = 0; i < max; i++) {
    if (b[i] !== a[i]) {
      if (b[i] !== undefined) out.push(`- ${b[i]}`);
      if (a[i] !== undefined) out.push(`+ ${a[i]}`);
    }
  }
  return out.length ? out : ["(no textual change)"];
}
