/**
 * Attested code-evaluator demo — the "sell provable verification, not opinion"
 * pivot, end to end and OFFLINE-safe:
 *
 *   1. Fetch a REAL small public PR via `gh` (diff + head SHA + manifest).
 *   2. Run the evaluator over the FAKE sandbox (scripted green checks) — the
 *      Docker daemon is NOT running in this environment, so untrusted code is
 *      NOT executed here. On the VPS (daemon up) the SAME code path runs the
 *      checks in a real ephemeral container.
 *   3. Sign + anchor the DACS-X evaluation-verdict attestation (the settleable
 *      product) and independently verify it from anchored state alone.
 *   4. Show the DockerSandbox `docker run` command construction (dry), and — if
 *      a daemon happens to be up — actually run `hello-world` to confirm.
 *
 *   npm run src:evaldemo                 # default PR: sindresorhus/slugify#73
 *   EVAL_PR=owner/repo#N npm run src:evaldemo
 */
import { execFile } from "node:child_process";

import { CciDirectory, makeIdentity } from "./identity.js";
import { MemorySubstrate } from "./substrate/memory.js";
import { RealRegistry, FakeRegistry } from "../roster/dep-upgrade/registry.js";
import { EvaluatorAgent } from "./agents/evaluator.js";
import { SellerAgent, evaluatorPriceFor, formatEvaluatorPricing } from "./agents/seller.js";
import { VerifierAgent } from "./agents/verifier.js";
import { LiveRepo, type FetchedPr } from "./agents/repo-fetch.js";
import {
  DockerSandbox,
  FakeSandbox,
  buildDockerArgs,
  DEFAULT_LIMITS,
  type CheckSpec,
} from "./agents/sandbox.js";

const line = (s = "") => console.log(s);
const step = (n: string, msg: string) => console.log(`  ${n.padEnd(11)} ${msg}`);

const DEFAULT_PR = "sindresorhus/slugify#73";

function parseTarget(): { repo: string; pullNumber: number } {
  const raw = process.env.EVAL_PR ?? DEFAULT_PR;
  const m = raw.match(/^(.+)#(\d+)$/);
  if (!m) throw new Error(`EVAL_PR must be owner/repo#N (got ${raw})`);
  return { repo: m[1]!, pullNumber: Number(m[2]) };
}

/** Canned fallback so the demo still runs if `gh` is unavailable. */
function cannedPr(repo: string, pr: number): FetchedPr {
  return {
    workspaceDir: `(canned: ${repo}#${pr})`,
    headSha: "0000000000000000000000000000000000000000",
    diff: "+ export const demo = true;\n- export const demo = false;",
    projectType: "node",
    packageJson: JSON.stringify({ name: repo.split("/")[1], scripts: { test: "node --test" } }),
  };
}

async function dockerAvailable(): Promise<boolean> {
  return new Promise((resolve) => {
    const c = execFile("docker", ["version", "--format", "{{.Server.Version}}"], { timeout: 8000 }, (err, out) =>
      resolve(!err && String(out).trim().length > 0),
    );
    c.on("error", () => resolve(false));
  });
}

async function main() {
  line("┌────────────────────────────────────────────────────────────────────┐");
  line("│  ReviewBot — attested code-EVALUATOR (sandbox-run checks + verdict)  │");
  line("└────────────────────────────────────────────────────────────────────┘");

  const target = parseTarget();
  step("pricing", `advertised: ${formatEvaluatorPricing()}`);

  // ── 1. Fetch a REAL PR via gh (diff + head + manifest; skip the heavy clone) ─
  line("\n━━ 1. Fetch the PR (real, via gh) ━━");
  const repoFetch = new LiveRepo({ skipClone: true });
  let fetched: FetchedPr;
  try {
    fetched = await repoFetch.fetchPr(target.repo, target.pullNumber);
    step("gh", `fetched ${target.repo}#${target.pullNumber} @ ${fetched.headSha.slice(0, 12)} (${fetched.projectType})`);
    step("diff", `${fetched.diff.split("\n").length} diff lines; package.json ${fetched.packageJson ? "present" : "absent"}`);
  } catch (e) {
    step("gh", `unavailable (${(e as Error).message.split("\n")[0]}) — using a canned PR fixture`);
    fetched = cannedPr(target.repo, target.pullNumber);
  }

  // ── 2. Evaluate over the FAKE sandbox (Docker daemon down here) ─────────────
  line("\n━━ 2. Evaluate (FAKE sandbox — no untrusted code runs in this env) ━━");
  // Scripted GREEN checks — on the VPS the DockerSandbox runs these for real.
  const sandbox = new FakeSandbox({
    install: { exitCode: 0, output: "added 42 packages" },
    build: { exitCode: 0, output: "build ok" },
    test: { exitCode: 0, output: "# pass 12  # fail 0" },
    typecheck: { exitCode: 0, output: "" },
  });
  // Dep-advisory uses the REAL npm advisory endpoint (safe: advisory reads, no
  // code execution); it degrades to "unavailable" if offline.
  const registry = (() => {
    try {
      return new RealRegistry();
    } catch {
      return new FakeRegistry({}, {});
    }
  })();
  // Provide the fetched PR to the evaluator via a one-shot repo port.
  const oneShotRepo = { fetchPr: async () => fetched, fetchRef: async () => fetched, cleanup: async () => {} };
  const evaluator = new EvaluatorAgent({ repo: oneShotRepo, sandbox, registry });
  const verdict = await evaluator.evaluate("demo-job", { repo: target.repo, pullNumber: target.pullNumber, title: `${target.repo}#${target.pullNumber}` });

  step("checks", verdict.checks.map((c) => `${c.name}=${c.passed ? "PASS" : "FAIL"}`).join("  "));
  step("verdict", `${verdict.verdict.toUpperCase()} — ${verdict.summary}`);
  step("price", `${evaluatorPriceFor(verdict.checks.length)} DEM (base + per-check over ${verdict.checks.length} checks)`);
  line("  ── attested verdict backbone (per-check commitments) ──");
  for (const c of verdict.checks) {
    line(`    ${c.name.padEnd(13)} exit=${String(c.exitCode).padStart(3)}  passed=${String(c.passed).padEnd(5)}  sha256:${c.outputHash.slice(0, 16)}…`);
  }

  // ── 3. Attest + independently verify the verdict artifact ───────────────────
  line("\n━━ 3. Attest the verdict (DACS-X) + independent verification ━━");
  const substrate = new MemorySubstrate();
  const cci = new CciDirectory();
  const sellerId = makeIdentity("ReviewBot", 0x11);
  const sellerLogin = "reviewbot-demo";
  cci.bind(sellerId.did, sellerLogin); // CCI proof (mock) — self-attested-from-identity
  const seller = new SellerAgent(sellerId, substrate, /* gh unused here */ null as never, sellerLogin);
  const verifier = new VerifierAgent(substrate, cci);

  const { attestationRef } = await seller.deliverEvaluation("demo-job", { repo: target.repo, pullNumber: target.pullNumber }, verdict);
  step("anchor", `evaluation attestation anchored → ${attestationRef}`);
  const ev = await verifier.verifyEvaluation("demo-job", sellerId.did);
  step("verify", `ok=${ev.ok}  verdict=${ev.attestation?.verdict}  headSha=${ev.attestation?.headSha.slice(0, 12)}  provenance=${ev.attestation?.provenance}`);
  step("settleable", "a third party re-verifies the signature and, given the same headSha, re-runs the checks to reproduce the outputHashes");

  // Show that tampering is caught: flip a bound check → signature breaks.
  const stored = substrate.store.get(attestationRef)! as { checks: Array<{ passed: boolean }> };
  const tampered = { ...stored, checks: stored.checks.map((c, i) => (i === 0 ? { ...c, passed: !c.passed } : c)) };
  substrate.store.set(attestationRef, tampered as never);
  const evT = await verifier.verifyEvaluation("demo-job", sellerId.did);
  step("tamper", `flip one bound check → verify ok=${evT.ok} (${evT.reason})`);

  // ── 4. DockerSandbox command construction (dry) + optional live hello-world ──
  line("\n━━ 4. DockerSandbox isolation (real execution runs on the VPS) ━━");
  const installSpec: CheckSpec = {
    name: "install",
    image: "node:20-alpine",
    workspaceDir: "/var/lib/dacs/job-demo",
    cmd: ["npm", "ci"],
    timeoutMs: 300_000,
    network: "limited",
    limits: DEFAULT_LIMITS,
  };
  step("dry-run", "docker " + buildDockerArgs(installSpec).join(" "));
  const daemonUp = await dockerAvailable();
  if (daemonUp) {
    step("daemon", "UP — running `docker run --rm hello-world` to confirm the adapter path");
    const ds = new DockerSandbox();
    const r = await ds.run({ ...installSpec, image: "hello-world", cmd: [], network: "none", workspaceDir: process.cwd() });
    step("docker", `hello-world exit=${r.exitCode} passed=${r.passed} (${r.durationMs}ms)`);
  } else {
    step("daemon", "DOWN/unreachable in this env — checks did NOT execute here (fail-safe honored)");
    // Prove the fail-safe: the real DockerSandbox refuses to run without a daemon.
    const ds = new DockerSandbox();
    try {
      await ds.run(installSpec);
      step("fail-safe", "UNEXPECTED — DockerSandbox.run did not refuse");
    } catch (e) {
      step("fail-safe", `DockerSandbox.run refused: "${(e as Error).message}"`);
    }
  }

  line("\n✅ Attested code-evaluator demo complete. The verdict artifact (bound checks +");
  line("   headSha + verdict, signed from the CCI identity) is the settleable product —");
  line("   a bounty/marketplace/DAO gates on it, not on an opinion.\n");
}

main().catch((e) => {
  console.error("\n❌ evaluator demo failed:", e?.message ?? e);
  process.exit(1);
});
