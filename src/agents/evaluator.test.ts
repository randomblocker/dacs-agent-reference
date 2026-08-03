/**
 * Evaluator tests — fully offline (no Docker, no network, no LLM).
 *   npx tsx --test src/agents/evaluator.test.ts
 *
 * Covers: check orchestration (FakeSandbox + FakeRepo), the verdict backbone
 * (failing test → not approve; hard install/build fail → reject; no sandbox →
 * indeterminate; all-green + clean LLM → approve), the FAIL-SAFE contract (the
 * sandbox is never invoked when unavailable — no host execution path), the
 * attested-verdict artifact sign/verify with every tampered/missing binding
 * rejected, and pricing.
 */
import { describe, test } from "node:test";
import assert from "node:assert/strict";

import { buildSignedArtifact } from "@kynesyslabs/dacs";

import { CciDirectory, makeIdentity } from "../identity.js";
import { MemorySubstrate } from "../substrate/memory.js";
import { MockGitHub } from "../github.js";
import { FakeRegistry } from "../../roster/dep-upgrade/registry.js";
import type { Advisory } from "../../roster/dep-upgrade/types.js";
import {
  SellerAgent,
  EVALUATION_ATTESTATION_SEPARATOR,
  evaluatorPriceFor,
  formatEvaluatorPricing,
  type EvaluationAttestation,
} from "./seller.js";
import { VerifierAgent } from "./verifier.js";
import {
  EvaluatorAgent,
  combineVerdict,
  verdictConsistentWithChecks,
  type EvalReviewFn,
  type EvaluationVerdict,
} from "./evaluator.js";
import { planChecks } from "./checks.js";
import { FakeSandbox } from "./sandbox.js";
import { FakeRepo, type FetchedPr } from "./repo-fetch.js";
import type { StructuredReview } from "./review-llm.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const REPO = "acme/payments";
const PR = 17;
const HEAD = "5fc6af29120eb9fecd32ade74fff932918186523";

const NODE_MANIFEST = JSON.stringify({
  name: "payments",
  scripts: { test: "node --test", build: "tsc -p ." },
  devDependencies: { typescript: "^5.7.0" },
});

function nodePr(over: Partial<FetchedPr> = {}): FetchedPr {
  return {
    workspaceDir: "/fake/ws",
    headSha: HEAD,
    diff: "+ const a = 1;\n- const b = 2;",
    projectType: "node",
    packageJson: NODE_MANIFEST,
    ...over,
  };
}

/** A canned LLM review (structured), injected so no `claude` CLI is needed. */
const reviewer = (review: StructuredReview): EvalReviewFn => async () => review;
const APPROVE: StructuredReview = { verdict: "approve", summary: "LGTM", findings: [] };
const CLEANEST = reviewer(APPROVE);

function makeEvaluator(opts: {
  fetched?: FetchedPr;
  sandbox?: FakeSandbox;
  advisories?: Record<string, Advisory[]>;
  review?: EvalReviewFn;
}) {
  const repo = new FakeRepo(opts.fetched ?? nodePr());
  const sandbox = opts.sandbox ?? new FakeSandbox();
  const registry = new FakeRegistry({}, opts.advisories ?? {});
  const evaluator = new EvaluatorAgent({ repo, sandbox, registry, review: opts.review ?? CLEANEST });
  return { repo, sandbox, registry, evaluator };
}

// ---------------------------------------------------------------------------
// planChecks
// ---------------------------------------------------------------------------

describe("planChecks", () => {
  test("node PR with build+test+typescript → all four checks", () => {
    assert.deepEqual(planChecks(nodePr()), { install: true, build: true, test: true, typecheck: true });
  });
  test("node PR without build script or TS → install+test only", () => {
    const p = nodePr({ packageJson: JSON.stringify({ name: "x", scripts: { test: "jest" } }) });
    assert.deepEqual(planChecks(p), { install: true, build: false, test: true, typecheck: false });
  });
  test("non-node PR → no execution checks", () => {
    const p = nodePr({ projectType: "unknown", packageJson: undefined });
    assert.deepEqual(planChecks(p), { install: false, build: false, test: false, typecheck: false });
  });
});

// ---------------------------------------------------------------------------
// Check orchestration
// ---------------------------------------------------------------------------

describe("check orchestration", () => {
  test("runs install (limited net) then build/test/typecheck (no net) + advisory", async () => {
    const { evaluator, sandbox } = makeEvaluator({});
    const v = await evaluator.evaluate("job-1", { repo: REPO, pullNumber: PR });
    const names = v.checks.map((c) => c.name);
    assert.deepEqual(names, ["install", "build", "test", "typecheck", "dep-advisory"]);
    // install is the ONLY step allowed the network.
    const install = sandbox.calls.find((c) => c.name === "install")!;
    assert.equal(install.network, "limited");
    for (const c of sandbox.calls.filter((c) => c.name !== "install")) assert.equal(c.network, "none");
  });

  test("failed install short-circuits build/test/typecheck", async () => {
    const sandbox = new FakeSandbox({ install: { exitCode: 1 } });
    const { evaluator } = makeEvaluator({ sandbox });
    const v = await evaluator.evaluate("job-1", { repo: REPO, pullNumber: PR });
    // install tried twice (npm ci then npm install), then stops; advisory still runs.
    assert.deepEqual(v.checks.map((c) => c.name), ["install", "dep-advisory"]);
  });

  test("cleans up the fetched workspace", async () => {
    const { evaluator, repo } = makeEvaluator({});
    await evaluator.evaluate("job-1", { repo: REPO, pullNumber: PR });
    assert.deepEqual(repo.cleaned, ["/fake/ws"]);
  });

  test("every CheckResult carries a sha256 outputHash (reproducibility commitment)", async () => {
    const { evaluator } = makeEvaluator({});
    const v = await evaluator.evaluate("job-1", { repo: REPO, pullNumber: PR });
    for (const c of v.checks) assert.match(c.outputHash, /^[0-9a-f]{64}$/);
  });
});

// ---------------------------------------------------------------------------
// Verdict backbone (the crux: mechanical results over LLM judgment)
// ---------------------------------------------------------------------------

describe("verdict backbone", () => {
  test("all-green + clean LLM → approve", async () => {
    const { evaluator } = makeEvaluator({});
    const v = await evaluator.evaluate("job-1", { repo: REPO, pullNumber: PR });
    assert.equal(v.verdict, "approve");
  });

  test("failing test → NOT approve (request-changes), even if the LLM says approve", async () => {
    const sandbox = new FakeSandbox({ test: { exitCode: 1, output: "1 test failed" } });
    const { evaluator } = makeEvaluator({ sandbox, review: CLEANEST }); // LLM still approves
    const v = await evaluator.evaluate("job-1", { repo: REPO, pullNumber: PR });
    assert.notEqual(v.verdict, "approve");
    assert.equal(v.verdict, "request-changes");
    // The failed check is surfaced as a blocker finding sourced from the check.
    assert.ok(v.findings.some((f) => f.source === "check" && f.severity === "blocker" && f.location === "test"));
  });

  test("failing build/install → reject (won't even build; no LLM override)", async () => {
    const sandbox = new FakeSandbox({ install: { exitCode: 1 } });
    const { evaluator } = makeEvaluator({ sandbox, review: CLEANEST });
    const v = await evaluator.evaluate("job-1", { repo: REPO, pullNumber: PR });
    assert.equal(v.verdict, "reject");
  });

  test("no sandbox → indeterminate, and the sandbox is NEVER invoked (fail-safe, no host exec)", async () => {
    const sandbox = new FakeSandbox({}, false); // unavailable
    const { evaluator } = makeEvaluator({ sandbox, review: CLEANEST });
    const v = await evaluator.evaluate("job-1", { repo: REPO, pullNumber: PR });
    assert.equal(v.verdict, "indeterminate");
    assert.match(v.summary, /no sandbox available/);
    assert.equal(sandbox.calls.length, 0); // the untrusted checks NEVER ran
  });

  test("LLM request-changes on a green backbone → request-changes (LLM detail on top)", async () => {
    const { evaluator } = makeEvaluator({
      review: reviewer({ verdict: "request-changes", summary: "naming", findings: [{ severity: "warning", issue: "rename x" }] }),
    });
    const v = await evaluator.evaluate("job-1", { repo: REPO, pullNumber: PR });
    assert.equal(v.verdict, "request-changes");
  });

  test("combineVerdict unit: green backbone + comment → approve", () => {
    const green = [{ name: "install", passed: true }, { name: "test", passed: true }].map(mkCheck);
    assert.equal(combineVerdict(true, green, { verdict: "comment", summary: "", findings: [] }), "approve");
  });

  test("high-severity advisory is a finding but does NOT block a green backbone verdict", async () => {
    const advisories = {
      typescript: [
        { id: "GHSA-xxxx", severity: "high", title: "toy advisory", url: "https://x", vulnerableVersions: "<9" } as Advisory,
      ],
    };
    const { evaluator } = makeEvaluator({ advisories, review: CLEANEST });
    const v = await evaluator.evaluate("job-1", { repo: REPO, pullNumber: PR });
    // advisory is not a gating check → verdict still approve, but the hit is a finding.
    assert.equal(v.verdict, "approve");
    assert.ok(v.findings.some((f) => f.source === "advisory" && f.severity === "blocker"));
  });
});

function mkCheck(x: { name: string; passed: boolean }) {
  return {
    name: x.name,
    cmd: [x.name],
    exitCode: x.passed ? 0 : 1,
    passed: x.passed,
    durationMs: 1,
    outputTail: "",
    outputHash: "0".repeat(64),
    normalizedOutputHash: "0".repeat(64),
  };
}

// ---------------------------------------------------------------------------
// verdictConsistentWithChecks (the verifier's LLM-independent invariant)
// ---------------------------------------------------------------------------

describe("verdictConsistentWithChecks", () => {
  test("approve requires every gating check to pass", () => {
    assert.equal(verdictConsistentWithChecks("approve", [{ name: "test", passed: true }]), true);
    assert.equal(verdictConsistentWithChecks("approve", [{ name: "test", passed: false }]), false);
    // non-gating (advisory) failure does not invalidate approve
    assert.equal(verdictConsistentWithChecks("approve", [{ name: "dep-advisory", passed: false }]), true);
  });
  test("reject / request-changes / indeterminate are always structurally consistent", () => {
    for (const v of ["reject", "request-changes", "indeterminate"] as const) {
      assert.equal(verdictConsistentWithChecks(v, [{ name: "test", passed: false }]), true);
    }
  });
});

// ---------------------------------------------------------------------------
// Pricing (base + per-check)
// ---------------------------------------------------------------------------

describe("evaluator pricing", () => {
  test("base + perCheck × checks, deterministic", () => {
    assert.equal(evaluatorPriceFor(0), 2); // base only
    assert.equal(evaluatorPriceFor(5), 7); // 2 + 1*5
    assert.equal(evaluatorPriceFor(-3), 2); // clamped
  });
  test("format string reflects the basis", () => {
    assert.match(formatEvaluatorPricing(undefined, "DEM"), /2 DEM base \+ 1 DEM per check/);
  });
});

// ---------------------------------------------------------------------------
// Attested evaluation verdict — sign / verify / tamper
// ---------------------------------------------------------------------------

function makeWorld(opts: { bindSellerTo?: string | null } = {}) {
  const sellerLogin = "reviewbot-x";
  const substrate = new MemorySubstrate();
  const github = new MockGitHub();
  const cci = new CciDirectory();
  substrate.mount("https://api.github.com", (url) => github.apiFetch(url));
  github.addUser({ login: sellerLogin, created_at: "2023-01-01T00:00:00Z", public_repos: 10 });
  github.addUser({ login: "eve", created_at: "2024-01-01T00:00:00Z", public_repos: 1 });
  github.addPull(REPO, { number: PR, title: "Add settlement retry loop", diff: "+a\n-b" });

  const sellerId = makeIdentity("ReviewBot", 0x11);
  const bound = opts.bindSellerTo === undefined ? sellerLogin : opts.bindSellerTo;
  if (bound !== null) cci.bind(sellerId.did, bound);

  const seller = new SellerAgent(sellerId, substrate, github, sellerLogin);
  const verifier = new VerifierAgent(substrate, cci);
  return { substrate, github, cci, sellerId, sellerLogin, seller, verifier };
}

/** Produce a real green EvaluationVerdict via the evaluator (offline). */
async function greenVerdict(): Promise<EvaluationVerdict> {
  const { evaluator } = makeEvaluator({});
  return evaluator.evaluate("mkverdict", { repo: REPO, pullNumber: PR, title: "Add settlement retry loop" });
}

describe("deliverEvaluation + verifyEvaluation", () => {
  test("artifact-only delivery (no PR review) → verifies; binds checks+headSha+verdict", async () => {
    const { seller, verifier, sellerId } = makeWorld();
    const v = await greenVerdict();
    const { attestationRef, reviewId } = await seller.deliverEvaluation("job-1", { repo: REPO, pullNumber: PR }, v);
    assert.ok(attestationRef);
    assert.equal(reviewId, 0);
    const ev = await verifier.verifyEvaluation("job-1", sellerId.did);
    assert.equal(ev.ok, true);
    assert.equal(ev.attestation?.headSha, HEAD);
    assert.equal(ev.attestation?.verdict, "approve");
    assert.ok((ev.attestation?.checks.length ?? 0) >= 4);
    for (const c of ev.attestation!.checks) assert.match(c.outputHash, /^[0-9a-f]{64}$/);
  });

  test("with a companion PR review → verifies review presence + CCI binding", async () => {
    const { seller, verifier, github, sellerId } = makeWorld();
    const v = await greenVerdict();
    const { reviewId } = await seller.deliverEvaluation("job-2", { repo: REPO, pullNumber: PR, title: "T" }, v, { postReview: true });
    assert.ok(reviewId > 0);
    assert.equal(github.listReviews(REPO, PR).length, 1);
    const ev = await verifier.verifyEvaluation("job-2", sellerId.did);
    assert.equal(ev.ok, true);
  });

  test("idempotent per jobId — retry reuses the attestation, no double-post", async () => {
    const { seller, github } = makeWorld();
    const v = await greenVerdict();
    const first = await seller.deliverEvaluation("job-3", { repo: REPO, pullNumber: PR }, v, { postReview: true });
    const second = await seller.deliverEvaluation("job-3", { repo: REPO, pullNumber: PR }, v, { postReview: true });
    assert.equal(second.reused, true);
    assert.equal(second.attestationRef, first.attestationRef);
    assert.equal(github.listReviews(REPO, PR).length, 1); // still ONE
  });

  test("no attestation anchored → ok:false", async () => {
    const { verifier, sellerId } = makeWorld();
    const ev = await verifier.verifyEvaluation("nope", sellerId.did);
    assert.equal(ev.ok, false);
    assert.match(ev.reason!, /no evaluation attestation/);
  });

  test("tampered check result → signature invalid", async () => {
    const { seller, verifier, substrate, sellerId } = makeWorld();
    const v = await greenVerdict();
    await seller.deliverEvaluation("job-1", { repo: REPO, pullNumber: PR }, v);
    const addr = await substrate.anchorAddress("dacsx:evaluation:job-1");
    const stored = substrate.store.get(addr)! as unknown as EvaluationAttestation & Record<string, unknown>;
    const flipped = { ...stored, checks: stored.checks.map((c, i) => (i === 0 ? { ...c, passed: !c.passed } : c)) };
    substrate.store.set(addr, flipped as unknown as Record<string, unknown>);
    const ev = await verifier.verifyEvaluation("job-1", sellerId.did);
    assert.equal(ev.ok, false);
    assert.match(ev.reason!, /signature invalid/);
  });

  test("jobId not matching the requested job → rejected", async () => {
    const { seller, verifier, substrate, sellerId } = makeWorld();
    const v = await greenVerdict();
    await seller.deliverEvaluation("job-A", { repo: REPO, pullNumber: PR }, v);
    const addrA = await substrate.anchorAddress("dacsx:evaluation:job-A");
    const addrB = await substrate.anchorAddress("dacsx:evaluation:job-B");
    substrate.store.set(addrB, substrate.store.get(addrA)!);
    const ev = await verifier.verifyEvaluation("job-B", sellerId.did);
    assert.equal(ev.ok, false);
    assert.match(ev.reason!, /jobId .* does not match/);
  });

  test("verdict 'approve' over a FAILED gating check → rejected (backbone consistency)", async () => {
    // Hand-craft a validly-signed but LYING attestation: a failed test, verdict approve.
    const { verifier, substrate, sellerId } = makeWorld();
    const att: EvaluationAttestation = {
      kind: "dacs-x-evaluation-verdict",
      jobId: "job-lie",
      repo: REPO,
      pullNumber: PR,
      headSha: HEAD,
      verdict: "approve",
      checks: [
        { name: "install", exitCode: 0, passed: true, outputHash: "0".repeat(64) },
        { name: "test", exitCode: 1, passed: false, outputHash: "1".repeat(64) },
      ],
      provenance: "self-attested-from-identity",
      reviewId: 0,
      ghAuthor: "",
      deliveredAt: new Date().toISOString(),
    };
    const signed = await buildSignedArtifact(att, EVALUATION_ATTESTATION_SEPARATOR as never, sellerId.sign);
    await substrate.anchor("dacsx:evaluation:job-lie", signed);
    const ev = await verifier.verifyEvaluation("job-lie", sellerId.did);
    assert.equal(ev.ok, false);
    assert.match(ev.reason!, /contradicts a failed gating check/);
  });

  test("missing headSha → rejected", async () => {
    const { verifier, substrate, sellerId } = makeWorld();
    const att: EvaluationAttestation = {
      kind: "dacs-x-evaluation-verdict",
      jobId: "job-nohead",
      repo: REPO,
      pullNumber: PR,
      headSha: "",
      verdict: "request-changes",
      checks: [{ name: "test", exitCode: 1, passed: false, outputHash: "1".repeat(64) }],
      provenance: "self-attested-from-identity",
      reviewId: 0,
      ghAuthor: "",
      deliveredAt: new Date().toISOString(),
    };
    const signed = await buildSignedArtifact(att, EVALUATION_ATTESTATION_SEPARATOR as never, sellerId.sign);
    await substrate.anchor("dacsx:evaluation:job-nohead", signed);
    const ev = await verifier.verifyEvaluation("job-nohead", sellerId.did);
    assert.equal(ev.ok, false);
    assert.match(ev.reason!, /binds no headSha/);
  });

  test("companion review author not CCI-bound to the seller → rejected", async () => {
    const { seller, verifier, sellerId } = makeWorld({ bindSellerTo: "eve" });
    const v = await greenVerdict();
    await seller.deliverEvaluation("job-1", { repo: REPO, pullNumber: PR }, v, { postReview: true });
    const ev = await verifier.verifyEvaluation("job-1", sellerId.did);
    assert.equal(ev.ok, false);
    assert.match(ev.reason!, /not CCI-bound/);
  });

  test("seller key unresolvable → rejected", async () => {
    const { seller, verifier } = makeWorld();
    const v = await greenVerdict();
    await seller.deliverEvaluation("job-1", { repo: REPO, pullNumber: PR }, v);
    const ev = await verifier.verifyEvaluation("job-1", "did:demos:agent:not-a-key");
    assert.equal(ev.ok, false);
    assert.match(ev.reason!, /key unresolvable|no evaluation attestation/);
  });

  test("companion review missing on GitHub → rejected", async () => {
    // Validly-signed attestation claiming a review id that was never posted.
    const { verifier, substrate, sellerId, sellerLogin } = makeWorld();
    const att: EvaluationAttestation = {
      kind: "dacs-x-evaluation-verdict",
      jobId: "job-ghost",
      repo: REPO,
      pullNumber: PR,
      headSha: HEAD,
      verdict: "approve",
      checks: [{ name: "install", exitCode: 0, passed: true, outputHash: "0".repeat(64) }],
      provenance: "self-attested-from-identity",
      reviewId: 424242,
      ghAuthor: sellerLogin,
      deliveredAt: new Date().toISOString(),
    };
    const signed = await buildSignedArtifact(att, EVALUATION_ATTESTATION_SEPARATOR as never, sellerId.sign);
    await substrate.anchor("dacsx:evaluation:job-ghost", signed);
    const ev = await verifier.verifyEvaluation("job-ghost", sellerId.did);
    assert.equal(ev.ok, false);
    assert.match(ev.reason!, /not found on GitHub/);
  });
});
