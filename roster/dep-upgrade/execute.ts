/**
 * Dependency-Upgrade — EXECUTOR TIER (the value lever).
 *
 * The plan tier (planner.ts + the wire's `makeDepUpgradeWork`) produces an
 * advisory-driven UpgradePlan over a POSTED package.json: cheap, safe on the
 * host, and commodity — Dependabot/Renovate do exactly this, free, integrated,
 * and they also run CI. A plan settles nothing a buyer couldn't get for free.
 *
 * The EXECUTOR tier is what a bounty/DAO/untrusting maintainer actually pays
 * for: it clones the repo, computes the advisory-clearing upgrade, APPLIES it,
 * and then PROVES — in an isolated sandbox — that the test suite is still green
 * on the upgraded tree, delivering a reputation-staked attested artifact. The
 * settleable claim is "I got you off the vulnerable version and the suite
 * provably still passes; here is the patch."
 *
 * Pipeline (mirrors the ReviewBot v2 / sec-audit-deep attested-executor pattern):
 *
 *   fetch repo (RepoFetchPort.fetchRef) → advisory-clearing plan (planner.ts,
 *   reused) → APPLY to package.json (apply-verify.ts, reused) → run
 *   install/build/test/typecheck in the SANDBOX (checks.ts runExecutionChecks,
 *   reused) → re-scan advisories on the CHOSEN versions (proof of clearing) →
 *   seal an attested artifact binding before/after/patch/checks/cleared/verdict.
 *
 * FAIL-SAFE, identical to ReviewBot/sec-audit-deep: `npm install`/`npm test` run
 * a repo's own, attacker-controlled toolchain — UNTRUSTED — so execution ALWAYS
 * goes through the SandboxPort. If no sandbox is available the verdict is
 * `indeterminate` and NOTHING is ever installed/tested on the host. Untrusted
 * argv is passed after the image, never shell-interpolated; the network is
 * enabled only for the install step (checks.ts).
 *
 * The MECHANICAL check results are authoritative. There is NO LLM anywhere in
 * this tier — by construction, nothing can override a red suite. `upgraded-green`
 * is derivable only from real passing checks + a fresh advisory re-scan;
 * `verifyExecReport` re-derives the verdict backbone with NO fail-open.
 */
import { readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { applyItemToPackageJson } from "./apply-verify.js";
import { parseInventory } from "./inventory.js";
import { buildPlan, resolveCurrentVersion } from "./planner.js";
import { satisfies } from "./semver.js";
import type { Advisory, DepSection, Packument, RegistryPort, UpgradeItem } from "./types.js";
import {
  DEFAULT_IMAGE,
  GATING_CHECKS,
  runExecutionChecks,
  type RunChecksOptions,
} from "../../src/agents/checks.js";
import type { FetchedPr, RepoFetchPort } from "../../src/agents/repo-fetch.js";
import { buildDockerArgs, NORMALIZATION_VERSION, type CheckResult, type SandboxPort } from "../../src/agents/sandbox.js";
import { MockDahrAttestor, canonicalJson, sha256HexBytes } from "../sec-audit/attest-files.js";
import { sha256Hex, verifyAttestedRecord } from "../oracle-desk/attested-fetch.js";
import { roundFee } from "../dacs/wire/pricing.js";
import type { MockDahrAttestation, ReportSeal } from "../sec-audit/types.js";

// ---------------------------------------------------------------------------
// Bound artifact shapes
// ---------------------------------------------------------------------------

/** A vulnerable dependency BEFORE the upgrade — version + the advisories it carries. */
export interface BeforeDep {
  dep: string;
  section: DepSection;
  /** The concrete version the repo was on (vulnerable). */
  version: string;
  /** GHSA/advisory ids affecting `version` that this upgrade clears. */
  advisories: string[];
}

/** A dependency AFTER the upgrade — the chosen clearing version. */
export interface AfterDep {
  dep: string;
  section: DepSection;
  /** The chosen version (declared range without the ^/~ prefix). */
  version: string;
  /** The new declared range written into package.json (preserves ^/~ style). */
  range: string;
  /** True when the fix forced a major escalation (buyer should read the patch). */
  breaking: boolean;
}

/**
 * The applied patch the buyer can take. The package.json before/after are the
 * load-bearing artifact (the buyer applies them); the lockfile hashes record
 * whether a real install regenerated the lock (it does on the VPS; the offline
 * FakeSandbox leaves it untouched).
 */
export interface UpgradePatch {
  beforePackageJson: string;
  afterPackageJson: string;
  /** sha256 of package-lock.json before install, when a lockfile was present. */
  lockfileBeforeHash?: string;
  /** sha256 of package-lock.json after install, when present (regenerated on real installs). */
  lockfileAfterHash?: string;
  /** True when the lockfile hash changed across the run (a real install ran). */
  lockfileChanged: boolean;
}

/** One post-upgrade check, content-addressed by its full output. */
export interface ExecCheck {
  /** "install" | "build" | "test" | "typecheck". */
  name: string;
  /** argv the sandbox ran (no shell). */
  cmd: string[];
  exitCode: number;
  passed: boolean;
  /**
   * sha256 of the FULL RAW combined stdout+stderr. Human forensics only — does
   * NOT match across independent re-runners (carries timestamps/durations/ANSI).
   */
  outputHash: string;
  /**
   * sha256 of the NORMALIZED output (see src/agents/normalize.ts) — the
   * reproducibility commitment a quorum compares. Two honest re-runners on the
   * same pinned inputs produce the SAME value, under `NORMALIZATION_VERSION`.
   */
  normalizedOutputHash: string;
  /** Bounded tail of the output (context; NOT the binding). */
  outputTail: string;
}

export type ExecVerdict =
  | "upgraded-green" // applied, advisories cleared, suite (incl. tests) provably green
  | "upgraded-untested" // applied, cleared, all RAN checks green, but no test script to prove the suite
  | "upgrade-breaks-suite" // applied, but a check went red (or advisories not actually cleared)
  | "no-advisories" // nothing on a known-vulnerable version — no advisory-clearing upgrade to do
  | "indeterminate"; // no sandbox — refused to install/test untrusted code on the host

/**
 * Verdict backbone — mechanical only, NO LLM. Derivable from the bound fields:
 *   - `indeterminate` iff the sandbox was down (nothing ran).
 *   - `no-advisories` iff there was nothing to upgrade.
 *   - otherwise the upgrade was applied and checks ran:
 *       `upgrade-breaks-suite` if any check failed OR advisories were not cleared;
 *       else `upgraded-green` if a test check ran and passed;
 *       else `upgraded-untested` (checks green but no test suite to prove).
 */
export function combineExecVerdict(
  sandboxAvailable: boolean,
  upgradedCount: number,
  checks: readonly ExecCheck[],
  advisoriesCleared: boolean,
): ExecVerdict {
  if (!sandboxAvailable) return "indeterminate";
  if (upgradedCount === 0) return "no-advisories";
  const allPassed = checks.length > 0 && checks.every((c) => c.passed);
  if (!allPassed || !advisoriesCleared) return "upgrade-breaks-suite";
  const testProven = checks.some((c) => c.name === "test" && c.passed);
  return testProven ? "upgraded-green" : "upgraded-untested";
}

// ---------------------------------------------------------------------------
// Quorum substrate (ADDITIVE — the adjudication compare, not live infra)
// ---------------------------------------------------------------------------

/**
 * The pinned inputs every re-runner reproduces, in canonical form. Digested
 * into the quorum attestation so each signature commits to WHAT was run
 * (headSha, the deliverable patch, the toolchain, the frozen clock, the exact
 * check argv) — not just the output. `normalizationVersion` is carried
 * alongside because it too is a consensus parameter.
 */
export interface PinnedInputs {
  repo: string;
  headSha: string;
  /** sha256 over the canonical patch (execute's `patchHash`). */
  patchHash: string;
  /** Container image — SHOULD be digest-pinned (`node@sha256:…`) for a quorum. */
  image: string;
  /** Frozen clock the sandbox pinned (D3). */
  sourceDateEpoch: number;
  /** Per-check argv, in run order — the exact commands re-runners must repeat. */
  checkCmds: string[][];
  normalizationVersion: string;
}

/** sha256 over the canonical pinned inputs — the digest a quorum signs against. */
export function pinnedInputsDigest(inputs: PinnedInputs): string {
  return sha256Hex(canonicalJson(inputs));
}

/** One gating check's agreement across the re-runs being compared. */
export interface CheckAgreement {
  name: string;
  /** True iff every artifact ran this check and produced the SAME normalized hash. */
  agree: boolean;
  /** Per-artifact normalizedOutputHash (or "<absent>" when the artifact lacks the check). */
  hashes: string[];
}

/** Minimal per-artifact shape `compareReRuns` needs (ExecReport satisfies it). */
export interface ReRunArtifact {
  verdict: ExecVerdict;
  checks: ReadonlyArray<{ name: string; normalizedOutputHash: string }>;
}

export interface ReRunComparison {
  /** Unanimous agreement: identical verdict AND identical normalized hash on every gating check. */
  agree: boolean;
  verdictAgree: boolean;
  verdicts: ExecVerdict[];
  /** Per-gating-check agreement (union of check names across artifacts, first-seen order). */
  checks: CheckAgreement[];
  /**
   * Artifact indices that diverge from the plurality fingerprint (verdict +
   * per-check normalized hashes). Empty iff unanimous. These are the parties a
   * DACS divergence dispute would target — "someone signed a false claim on a
   * deterministic input" — per the adjudication rule (re-run once more; minority slashed).
   */
  divergentIndices: number[];
}

/**
 * Compare N independent re-runs of the SAME pinned inputs and decide agree/
 * diverge per gating check — the offline adjudication substrate a quorum sits
 * on. Pure: no I/O, no signing. Because dep-upgrade's `verdict` is a mechanical
 * function of the content-addressed check outcomes, identical normalized hashes
 * ⇒ identical verdict by construction; divergence is therefore attributable to
 * a specific re-runner. (An `indeterminate` artifact simply fails to agree with
 * a green one — non-determinism never certifies an arbitrary verdict.)
 */
export function compareReRuns(artifacts: readonly ReRunArtifact[]): ReRunComparison {
  const verdicts = artifacts.map((a) => a.verdict);
  const verdictAgree = verdicts.every((v) => v === verdicts[0]);

  // Union of gating-check names across all artifacts, first-seen order.
  const names: string[] = [];
  for (const a of artifacts) {
    for (const c of a.checks) {
      if (GATING_CHECKS.has(c.name) && !names.includes(c.name)) names.push(c.name);
    }
  }

  const hashOfCheck = (a: ReRunArtifact, name: string): string =>
    a.checks.find((c) => c.name === name)?.normalizedOutputHash ?? "<absent>";

  const checks: CheckAgreement[] = names.map((name) => {
    const hashes = artifacts.map((a) => hashOfCheck(a, name));
    const agree = hashes.length > 0 && hashes.every((h) => h !== "<absent>" && h === hashes[0]);
    return { name, agree, hashes };
  });

  // Per-artifact fingerprint = verdict + every gating check's normalized hash.
  const fingerprint = (i: number): string =>
    canonicalJson({ v: verdicts[i], h: names.map((n) => hashOfCheck(artifacts[i], n)) });
  const fingerprints = artifacts.map((_, i) => fingerprint(i));

  // Plurality fingerprint; artifacts not matching it are the divergent minority.
  const counts = new Map<string, number>();
  for (const fp of fingerprints) counts.set(fp, (counts.get(fp) ?? 0) + 1);
  let plurality = fingerprints[0] ?? "";
  let best = -1;
  for (const [fp, n] of counts) if (n > best) ((best = n), (plurality = fp));
  const divergentIndices = fingerprints.flatMap((fp, i) => (fp === plurality ? [] : [i]));

  const agree =
    artifacts.length > 0 && verdictAgree && checks.every((c) => c.agree) && divergentIndices.length === 0;

  return { agree, verdictAgree, verdicts, checks, divergentIndices };
}

// ---------------------------------------------------------------------------
// The attested artifact + seal
// ---------------------------------------------------------------------------

export interface ExecReport {
  version: 1;
  kind: "dep-upgrade-execute";
  /** The upgraded repo (e.g. "owner/name"). */
  repo: string;
  /** The ref descriptor executed against (e.g. "ref:main"). */
  ref: string;
  /** The exact tree SHA the upgrade + checks ran against. */
  headSha: string;
  generatedAt: string;
  /**
   * Provenance TIER over the SAME bound fields (headSha, patchHash, per-check
   * hashes, verdict) — additive, so old verifiers still validate the core:
   *   - "self-attested-from-identity" (default): the executor signs its own
   *     claim that it applied this patch and ran these checks at this headSha.
   *   - "quorum-attested": an M-of-N set of staked re-runners independently
   *     reproduced the pinned inputs and co-signed the agreed digest
   *     (`seal.quorum`); it replaces trusting a single self-seal. The re-runner
   *     network is not live yet — the shape is reserved here.
   * A later "tee-attested" slots into the same seam with no field change.
   */
  provenance: "self-attested-from-identity" | "quorum-attested";
  /** False ⇒ the checks could not be isolated; verdict is `indeterminate`. */
  sandboxAvailable: boolean;
  before: BeforeDep[];
  after: AfterDep[];
  patch: UpgradePatch;
  /** sha256 over the canonical `patch` — binds the deliverable patch. */
  patchHash: string;
  checks: ExecCheck[];
  /** True iff a fresh advisory re-scan of the chosen versions clears all `before` advisories. */
  advisoriesCleared: boolean;
  /** `before` advisory ids that STILL affect the chosen versions (empty ⇒ cleared). */
  stillVulnerable: string[];
  verdict: ExecVerdict;
  summary: string;
  seal: ReportSeal;
}

/** sha256 over the canonical patch object — the deliverable-patch commitment. */
export function patchHashOf(patch: UpgradePatch): string {
  return sha256Hex(canonicalJson(patch));
}

/** Seal = MOCK-DAHR signature over the canonical JSON of the artifact core. */
function sealReport(core: Omit<ExecReport, "seal">, attestor: MockDahrAttestor): ReportSeal {
  const bodyHash = sha256Hex(canonicalJson(core));
  const url = `report:dep-upgrade-execute:${core.generatedAt}`;
  const attestation: MockDahrAttestation = attestor.attest(url, core.generatedAt, bodyHash);
  return { url, bodyHash, attestation };
}

// ---------------------------------------------------------------------------
// Advisory intel + the fresh clearing re-scan (the "cleared" proof)
// ---------------------------------------------------------------------------

/** Gather packuments + a bulk advisory query for a repo's declared deps. */
async function gatherIntel(
  registry: RegistryPort,
  inventory: ReturnType<typeof parseInventory>,
): Promise<{ packuments: Map<string, Packument>; advisories: Map<string, Advisory[]> }> {
  const packuments = new Map<string, Packument>();
  for (const dep of inventory.deps) {
    if (!packuments.has(dep.name)) packuments.set(dep.name, await registry.getPackument(dep.name));
  }
  const query: Record<string, string[]> = {};
  for (const dep of inventory.deps) {
    const current = resolveCurrentVersion(dep, packuments.get(dep.name)!);
    if (current) query[dep.name] = [...(query[dep.name] ?? []), current];
  }
  const advisories =
    Object.keys(query).length > 0 ? await registry.getAdvisories(query) : new Map<string, Advisory[]>();
  return { packuments, advisories };
}

/**
 * Independent proof that the chosen versions clear the advisories: query the
 * registry AGAIN for the target versions and keep only advisories that actually
 * `satisfies(target, vulnerableVersions)`. This filter is load-bearing — the
 * npm bulk endpoint pre-filters by version, but a FakeRegistry may not, so we
 * never trust the endpoint's filtering; we re-check semver ourselves. Returns
 * the `before` advisory ids that still bite the chosen versions (empty ⇒ cleared).
 */
export async function reScanCleared(
  registry: RegistryPort,
  chosen: ReadonlyArray<{ dep: string; version: string }>,
  beforeIds: ReadonlySet<string>,
): Promise<string[]> {
  if (chosen.length === 0) return [];
  const query: Record<string, string[]> = {};
  for (const c of chosen) (query[c.dep] ??= []).push(c.version);
  const advisories = await registry.getAdvisories(query);
  const versionOf = new Map(chosen.map((c) => [c.dep, c.version]));
  const still: string[] = [];
  for (const [dep, list] of advisories) {
    const target = versionOf.get(dep);
    if (!target) continue;
    for (const a of list) {
      // Only advisories that TRULY affect the chosen version count as "still vulnerable".
      if (satisfies(target, a.vulnerableVersions)) still.push(a.id);
    }
  }
  // Report the intersection with the advisories we set out to clear (deduped, sorted).
  return [...new Set(still.filter((id) => beforeIds.has(id)))].sort();
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

export interface ExecuteDeps {
  repo: RepoFetchPort;
  sandbox: SandboxPort;
  registry: RegistryPort;
  checkOptions?: RunChecksOptions;
  attestor?: MockDahrAttestor;
  now?: () => Date;
}

export interface ExecuteTarget {
  repo: string;
  /** The ref to upgrade (default: the cloned HEAD). */
  ref?: string;
}

/** Map a sandbox `CheckResult` to the bound `ExecCheck` (gating checks only). */
function toExecCheck(r: CheckResult): ExecCheck {
  return {
    name: r.name,
    cmd: r.cmd,
    exitCode: r.exitCode,
    passed: r.passed,
    outputHash: r.outputHash,
    normalizedOutputHash: r.normalizedOutputHash,
    outputTail: r.outputTail,
  };
}

async function hashLockfile(dir: string): Promise<string | undefined> {
  const p = join(dir, "package-lock.json");
  if (!existsSync(p)) return undefined;
  try {
    return sha256HexBytes(Buffer.from(await readFile(p, "utf8"), "utf8"));
  } catch {
    return undefined;
  }
}

/**
 * Run an upgrade end to end and return the signed, sealed executor artifact.
 * FAIL-SAFE: with no sandbox, returns an `indeterminate` artifact having applied
 * NOTHING and run NO install/test on the host. Always cleans up the workspace.
 */
export async function runExecuteUpgrade(deps: ExecuteDeps, target: ExecuteTarget): Promise<ExecReport> {
  const attestor = deps.attestor ?? new MockDahrAttestor();
  const now = deps.now ?? (() => new Date());

  const fetched = await deps.repo.fetchRef(target.repo, target.ref);
  const refLabel = `ref:${target.ref ?? "HEAD"}`;

  try {
    const available = await deps.sandbox.available();

    // Original manifest (the "before" side of the patch). A repo with no
    // package.json is not actionable here — an honest `no-advisories`.
    const beforePackageJson = fetched.packageJson ?? "";
    const emptyPatch: UpgradePatch = {
      beforePackageJson,
      afterPackageJson: beforePackageJson,
      lockfileChanged: false,
    };

    // FAIL-SAFE: no sandbox → indeterminate, having touched nothing.
    if (!available) {
      return sealed(
        {
          repo: target.repo,
          ref: refLabel,
          headSha: fetched.headSha,
          before: [],
          after: [],
          patch: emptyPatch,
          checks: [],
          advisoriesCleared: false,
          stillVulnerable: [],
          sandboxAvailable: false,
          summary: "indeterminate — no sandbox available; refusing to install/test untrusted code on the host.",
        },
        attestor,
        now,
      );
    }

    if (fetched.projectType !== "node" || !fetched.packageJson) {
      return sealed(
        {
          repo: target.repo,
          ref: refLabel,
          headSha: fetched.headSha,
          before: [],
          after: [],
          patch: emptyPatch,
          checks: [],
          advisoriesCleared: true,
          stillVulnerable: [],
          sandboxAvailable: true,
          summary: "no-advisories — no package.json / not a node project; no advisory-clearing upgrade to perform.",
        },
        attestor,
        now,
      );
    }

    // 1. Inventory + advisory-clearing plan (planner reused; SECURITY items only —
    //    the value is "off the vulnerable version", not maintenance churn).
    const inventory = parseInventory(fetched.workspaceDir, fetched.packageJson, fetched.packageLock);
    const { packuments, advisories } = await gatherIntel(deps.registry, inventory);
    const plan = buildPlan(inventory, packuments, advisories, { proposeNextMajor: false });
    const securityItems = plan.items.filter((i) => i.kind === "security");

    const before: BeforeDep[] = securityItems.map((it) => ({
      dep: it.name,
      section: it.section,
      version: it.currentVersion,
      advisories: it.advisories.map((a) => a.id),
    }));

    // Nothing on a known-vulnerable version → honest `no-advisories`, no checks.
    if (securityItems.length === 0) {
      return sealed(
        {
          repo: target.repo,
          ref: refLabel,
          headSha: fetched.headSha,
          before,
          after: [],
          patch: emptyPatch,
          checks: [],
          advisoriesCleared: true,
          stillVulnerable: [],
          sandboxAvailable: true,
          summary: `no-advisories — ${inventory.deps.length} dep(s) scanned; none on a version with a clearable published advisory.`,
        },
        attestor,
        now,
      );
    }

    // 2. APPLY the upgrade to the workspace's package.json (cumulative).
    const lockfileBeforeHash = await hashLockfile(fetched.workspaceDir);
    let afterText = beforePackageJson;
    for (const item of securityItems) afterText = applyItemToPackageJson(afterText, item);
    await writeFile(join(fetched.workspaceDir, "package.json"), afterText, "utf8");

    const after: AfterDep[] = securityItems.map((it) => ({
      dep: it.name,
      section: it.section,
      version: it.targetVersion,
      range: it.newRange,
      breaking: it.breaking,
    }));

    // 3. Prove the suite green on the UPGRADED tree — sandbox only, never host.
    //    Re-read the manifest so planChecks sees the upgraded scripts/deps.
    const upgradedFetched: FetchedPr = { ...fetched, packageJson: afterText };
    const raw = await runExecutionChecks(deps.sandbox, upgradedFetched, deps.checkOptions);
    const checks = raw.filter((r) => GATING_CHECKS.has(r.name)).map(toExecCheck);

    const lockfileAfterHash = await hashLockfile(fetched.workspaceDir);
    const patch: UpgradePatch = {
      beforePackageJson,
      afterPackageJson: afterText,
      lockfileBeforeHash,
      lockfileAfterHash,
      lockfileChanged: Boolean(lockfileAfterHash) && lockfileAfterHash !== lockfileBeforeHash,
    };

    // 4. Independent advisory re-scan on the CHOSEN versions (the clearing proof).
    const beforeIds = new Set(before.flatMap((b) => b.advisories));
    const stillVulnerable = await reScanCleared(
      deps.registry,
      after.map((a) => ({ dep: a.dep, version: a.version })),
      beforeIds,
    );
    const advisoriesCleared = stillVulnerable.length === 0;

    const verdict = combineExecVerdict(true, after.length, checks, advisoriesCleared);
    const summary = summarize(verdict, before, after, checks, stillVulnerable);

    return sealed(
      {
        repo: target.repo,
        ref: refLabel,
        headSha: fetched.headSha,
        before,
        after,
        patch,
        checks,
        advisoriesCleared,
        stillVulnerable,
        sandboxAvailable: true,
        summary,
      },
      attestor,
      now,
    );
  } finally {
    await deps.repo.cleanup(fetched.workspaceDir).catch(() => {});
  }
}

/** Assemble the core (deriving verdict + patchHash) and seal it. */
function sealed(
  parts: Omit<ExecReport, "version" | "kind" | "generatedAt" | "provenance" | "verdict" | "patchHash" | "seal"> & {
    summary: string;
  },
  attestor: MockDahrAttestor,
  now: () => Date,
): ExecReport {
  const verdict = combineExecVerdict(parts.sandboxAvailable, parts.after.length, parts.checks, parts.advisoriesCleared);
  const core: Omit<ExecReport, "seal"> = {
    version: 1,
    kind: "dep-upgrade-execute",
    repo: parts.repo,
    ref: parts.ref,
    headSha: parts.headSha,
    generatedAt: now().toISOString(),
    provenance: "self-attested-from-identity",
    sandboxAvailable: parts.sandboxAvailable,
    before: parts.before,
    after: parts.after,
    patch: parts.patch,
    patchHash: patchHashOf(parts.patch),
    checks: parts.checks,
    advisoriesCleared: parts.advisoriesCleared,
    stillVulnerable: parts.stillVulnerable,
    verdict,
    summary: parts.summary,
  };
  return { ...core, seal: sealReport(core, attestor) };
}

function summarize(
  verdict: ExecVerdict,
  before: readonly BeforeDep[],
  after: readonly AfterDep[],
  checks: readonly ExecCheck[],
  stillVulnerable: readonly string[],
): string {
  const bumps = after.map((a) => `${a.dep}→${a.version}${a.breaking ? " (BREAKING)" : ""}`).join(", ");
  const checkStr = checks.map((c) => `${c.name}${c.passed ? "✓" : "✗"}`).join(" ");
  const advCount = new Set(before.flatMap((b) => b.advisories)).size;
  switch (verdict) {
    case "upgraded-green":
      return `upgraded-green — ${after.length} dep(s) upgraded (${bumps}); ${advCount} advisory/ies cleared; suite green [${checkStr}].`;
    case "upgraded-untested":
      return `upgraded-untested — ${after.length} dep(s) upgraded (${bumps}); ${advCount} advisory/ies cleared; install/build/typecheck green but NO test script to prove the suite [${checkStr}].`;
    case "upgrade-breaks-suite":
      return stillVulnerable.length > 0
        ? `upgrade-breaks-suite — applied ${bumps} but the chosen version(s) still carry advisories ${stillVulnerable.join(", ")} [${checkStr}].`
        : `upgrade-breaks-suite — applied ${bumps} but a check went RED [${checkStr}]. The safe upgrade is NOT drop-in.`;
    case "no-advisories":
      return `no-advisories — nothing on a clearable vulnerable version; no upgrade performed.`;
    case "indeterminate":
      return `indeterminate — no sandbox; refused to install/test untrusted code on the host.`;
  }
}

// ---------------------------------------------------------------------------
// Pricing (executor tier) — priced by WORK DONE: base + per-upgraded-dep + per-check
// ---------------------------------------------------------------------------

/**
 * Executor-tier pricing. Unlike the plan tier's per-DECLARED-dependency fee (a
 * cheap read), the executor does real compute: clone + apply + sandboxed
 * install/build/test/typecheck. So it is billed by effort actually expended — a
 * flat base + a fee per dependency actually UPGRADED + a fee per check RUN.
 * Deterministic given (#upgraded, #checks) and reproducible from the artifact
 * (`after.length`, `checks.length`). DISPLAY units (DEM).
 */
export interface ExecutePricing {
  base: number;
  perUpgradedDep: number;
  perCheck: number;
}

export const EXECUTE_PRICING: ExecutePricing = { base: 4, perUpgradedDep: 2, perCheck: 1 };

/** Total bill (display units) = base + perUpgradedDep·#upgraded + perCheck·#checks. */
export function executePriceFor(numUpgraded: number, numChecks: number, p: ExecutePricing = EXECUTE_PRICING): number {
  return roundFee(p.base + p.perUpgradedDep * Math.max(0, numUpgraded) + p.perCheck * Math.max(0, numChecks));
}

export function formatExecutePricing(p: ExecutePricing = EXECUTE_PRICING, asset = "DEM"): string {
  return `${p.base} ${asset} base + ${p.perUpgradedDep} ${asset} per upgraded dep + ${p.perCheck} ${asset} per check`;
}

// ---------------------------------------------------------------------------
// docker argv dry-construction (for the demo — the isolation the VPS runs)
// ---------------------------------------------------------------------------

/** The representative post-upgrade check specs, for dry-constructing the VPS docker argv. */
export function executeCheckArgvPreview(workspaceDir = "/srv/jobs/<workspace>"): Array<{ name: string; network: string; args: string[]; isolated: boolean }> {
  const specs = [
    { name: "install", cmd: ["npm", "install"], network: "limited" as const },
    { name: "build", cmd: ["npm", "run", "build"], network: "none" as const },
    { name: "test", cmd: ["npm", "test"], network: "none" as const },
    { name: "typecheck", cmd: ["npx", "tsc", "--noEmit"], network: "none" as const },
  ];
  return specs.map((s) => {
    const args = buildDockerArgs({
      name: s.name,
      image: DEFAULT_IMAGE,
      workspaceDir,
      cmd: s.cmd,
      timeoutMs: 300_000,
      network: s.network,
      limits: { cpus: "1", memory: "1g", pids: 256 },
    });
    const isolated = args.includes("--read-only") && args.includes("--cap-drop") && args.includes("no-new-privileges");
    return { name: s.name, network: s.network, args, isolated };
  });
}

// ---------------------------------------------------------------------------
// Verification — third-party, offline, NO fail-open
// ---------------------------------------------------------------------------

export interface VerifyExecResult {
  valid: boolean;
  problems: string[];
  checksChecked: number;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

const VALID_EXEC_VERDICTS: ReadonlySet<string> = new Set([
  "upgraded-green",
  "upgraded-untested",
  "upgrade-breaks-suite",
  "no-advisories",
  "indeterminate",
]);

const HEX64 = /^[0-9a-f]{64}$/;

const VALID_PROVENANCES: ReadonlySet<string> = new Set([
  "self-attested-from-identity",
  "quorum-attested",
]);

/**
 * Re-verify an executor artifact as a third party, from the artifact ALONE, with
 * NO network. NO fail-open — every path that cannot confirm a binding is a problem:
 *   - seal: canonical core re-hashed + ed25519 signature verified (tamper-evident);
 *   - patch: patchHash recomputed over the bound patch; and every `after` dep's
 *     chosen version MUST actually appear in `patch.afterPackageJson` (the patch
 *     truly carries the claimed upgrade — no phantom "after" versions);
 *   - each check binds a 64-hex outputHash;
 *   - BACKBONE (the crux), re-derived mechanically:
 *       * `upgraded-green`  ⟹ sandboxAvailable, ≥1 upgrade, advisoriesCleared,
 *                             stillVulnerable empty, AND a passing `install` + a
 *                             passing `test` present AND every check passed;
 *       * `upgraded-untested` ⟹ same but NO test check present (all ran checks green);
 *       * `upgrade-breaks-suite` ⟹ ≥1 upgrade AND (a check failed OR NOT cleared);
 *       * `no-advisories`   ⟹ zero upgrades, no checks;
 *       * `indeterminate`   ⟹ NOT sandboxAvailable, zero upgrades, no checks.
 *     An artifact that claims `upgraded-green` over a failing check or uncleared
 *     advisories is REJECTED — the value claim cannot be forged.
 */
export function verifyExecReport(artifact: unknown): VerifyExecResult {
  const problems: string[] = [];
  let checksChecked = 0;
  const done = (): VerifyExecResult => ({ valid: problems.length === 0, problems, checksChecked });

  if (!isObject(artifact)) {
    problems.push("artifact is not a JSON object");
    return done();
  }
  const a = artifact;

  if (a.version !== 1) problems.push(`unknown version ${String(a.version)}`);
  if (a.kind !== "dep-upgrade-execute") problems.push(`unexpected kind ${String(a.kind)}`);
  if (typeof a.repo !== "string" || a.repo.length === 0) problems.push("repo is missing");
  if (typeof a.headSha !== "string" || a.headSha.length === 0) problems.push("headSha is missing");
  if (!VALID_PROVENANCES.has(String(a.provenance))) problems.push(`unexpected provenance ${String(a.provenance)}`);
  if (!VALID_EXEC_VERDICTS.has(String(a.verdict))) problems.push(`unknown verdict ${String(a.verdict)}`);
  if (typeof a.advisoriesCleared !== "boolean") problems.push("advisoriesCleared is not a boolean");
  if (typeof a.sandboxAvailable !== "boolean") problems.push("sandboxAvailable is not a boolean");

  // --- after[] ------------------------------------------------------------
  const after = Array.isArray(a.after) ? (a.after as unknown[]) : null;
  if (!after) problems.push("after is not an array");
  const afterDeps: AfterDep[] = [];
  if (after) {
    for (const [i, raw] of after.entries()) {
      if (!isObject(raw)) {
        problems.push(`after[${i}] is not an object`);
        continue;
      }
      const d = raw as unknown as AfterDep;
      if (typeof d.dep !== "string" || d.dep.length === 0) problems.push(`after[${i}]: missing dep`);
      if (typeof d.version !== "string" || d.version.length === 0) problems.push(`after[${i}]: missing version`);
      afterDeps.push(d);
    }
  }

  // --- before[] (light structural) ---------------------------------------
  const before = Array.isArray(a.before) ? (a.before as unknown[]) : null;
  if (!before) problems.push("before is not an array");

  // --- checks[] -----------------------------------------------------------
  const checks = Array.isArray(a.checks) ? (a.checks as unknown[]) : null;
  if (!checks) problems.push("checks is not an array");
  const execChecks: ExecCheck[] = [];
  if (checks) {
    for (const [i, raw] of checks.entries()) {
      if (!isObject(raw)) {
        problems.push(`checks[${i}] is not an object`);
        continue;
      }
      const c = raw as unknown as ExecCheck;
      const label = typeof c.name === "string" ? c.name : `checks[${i}]`;
      if (typeof c.name !== "string" || c.name.length === 0) problems.push(`checks[${i}]: missing name`);
      if (typeof c.passed !== "boolean") problems.push(`${label}: passed is not a boolean`);
      if (typeof c.outputHash !== "string" || !HEX64.test(c.outputHash)) problems.push(`${label}: outputHash is not a sha256 hex`);
      if (typeof c.normalizedOutputHash !== "string" || !HEX64.test(c.normalizedOutputHash)) problems.push(`${label}: normalizedOutputHash is not a sha256 hex`);
      // `passed` must agree with exitCode — a check can't claim green on a non-zero exit.
      if (typeof c.exitCode === "number" && c.passed !== (c.exitCode === 0)) {
        problems.push(`${label}: passed=${c.passed} contradicts exitCode=${c.exitCode}`);
      }
      execChecks.push(c);
      checksChecked += 1;
    }
  }

  // --- patch: hash binding + the after-version presence proof ------------
  const patch = a.patch;
  if (!isObject(patch) || typeof patch.beforePackageJson !== "string" || typeof patch.afterPackageJson !== "string") {
    problems.push("patch is missing or malformed");
  } else {
    if (patchHashOf(patch as unknown as UpgradePatch) !== a.patchHash) {
      problems.push("patchHash does not cover the bound patch — the patch was modified");
    }
    // Every claimed `after` version must actually be in the after-manifest.
    const afterManifest = String(patch.afterPackageJson);
    let parsed: Record<string, Record<string, string> | undefined> | null = null;
    try {
      parsed = JSON.parse(afterManifest) as Record<string, Record<string, string> | undefined>;
    } catch {
      problems.push("patch.afterPackageJson is not valid JSON");
    }
    if (parsed) {
      for (const d of afterDeps) {
        const decl = parsed.dependencies?.[d.dep] ?? parsed.devDependencies?.[d.dep];
        if (decl === undefined || !decl.includes(d.version)) {
          problems.push(`after dep "${d.dep}@${d.version}" is not present in patch.afterPackageJson (phantom upgrade)`);
        }
      }
    }
  }

  // --- BACKBONE: the verdict cannot be forged ----------------------------
  const verdict = String(a.verdict) as ExecVerdict;
  const upgradedCount = afterDeps.length;
  const allPassed = execChecks.length > 0 && execChecks.every((c) => c.passed);
  const installGreen = execChecks.some((c) => c.name === "install" && c.passed);
  const testGreen = execChecks.some((c) => c.name === "test" && c.passed);
  const cleared = a.advisoriesCleared === true && Array.isArray(a.stillVulnerable) && a.stillVulnerable.length === 0;

  switch (verdict) {
    case "indeterminate":
      if (a.sandboxAvailable !== false) problems.push("verdict 'indeterminate' but sandboxAvailable is not false");
      if (upgradedCount > 0) problems.push("verdict 'indeterminate' but upgrades are present");
      if (execChecks.length > 0) problems.push("verdict 'indeterminate' but checks are present");
      break;
    case "no-advisories":
      if (upgradedCount > 0) problems.push("verdict 'no-advisories' but upgrades are present");
      if (execChecks.length > 0) problems.push("verdict 'no-advisories' but checks are present");
      break;
    case "upgraded-green":
      if (upgradedCount === 0) problems.push("verdict 'upgraded-green' but no upgrade applied");
      if (!cleared) problems.push("verdict 'upgraded-green' but advisories are not cleared");
      if (!allPassed) problems.push("verdict 'upgraded-green' but not every check passed");
      if (!installGreen) problems.push("verdict 'upgraded-green' but no passing install check");
      if (!testGreen) problems.push("verdict 'upgraded-green' but no passing test check (suite not proven)");
      break;
    case "upgraded-untested":
      if (upgradedCount === 0) problems.push("verdict 'upgraded-untested' but no upgrade applied");
      if (!cleared) problems.push("verdict 'upgraded-untested' but advisories are not cleared");
      if (!allPassed) problems.push("verdict 'upgraded-untested' but not every check passed");
      if (!installGreen) problems.push("verdict 'upgraded-untested' but no passing install check");
      if (testGreen) problems.push("verdict 'upgraded-untested' but a passing test check exists (should be upgraded-green)");
      break;
    case "upgrade-breaks-suite":
      if (upgradedCount === 0) problems.push("verdict 'upgrade-breaks-suite' but no upgrade applied");
      if (allPassed && cleared) problems.push("verdict 'upgrade-breaks-suite' but every check passed AND advisories cleared (should be green)");
      break;
  }

  // --- Seal: canonical core re-hashed + signature verified ---------------
  const seal = a.seal;
  if (!isObject(seal) || typeof seal.url !== "string" || typeof seal.bodyHash !== "string" || !isObject(seal.attestation)) {
    problems.push("seal is missing or malformed");
  } else {
    const { seal: _dropped, ...core } = a;
    const expectedHash = sha256HexBytes(Buffer.from(canonicalJson(core), "utf8"));
    if (expectedHash !== seal.bodyHash) {
      problems.push("seal: artifact content does not hash to the sealed core hash — modified after sealing");
    }
    const sig = verifyAttestedRecord({
      url: String(seal.url),
      fetchedAt: String(a.generatedAt),
      bodyHash: String(seal.bodyHash),
      attestation: seal.attestation as unknown as MockDahrAttestation,
    });
    if (!sig.valid) problems.push(`seal: attestation invalid — ${sig.reason}`);

    // Quorum seam (additive): provenance and seal.quorum must agree, and a
    // present quorum must be structurally sound — NO fail-open on a claimed
    // higher tier. (The single self-seal above is still verified regardless.)
    const quorum = (seal as Record<string, unknown>).quorum;
    if (a.provenance === "quorum-attested") {
      if (!isObject(quorum)) problems.push("provenance 'quorum-attested' but seal.quorum is missing");
      else problems.push(...validateQuorum(quorum, String(seal.bodyHash)));
    } else if (quorum !== undefined) {
      problems.push("seal.quorum present but provenance is not 'quorum-attested'");
    }
  }

  return done();
}

/**
 * Structurally verify an M-of-N quorum attestation (NO fail-open). This checks
 * the SHAPE + the offline-checkable invariants — threshold met by distinct
 * signers over the right digest under a known normalizer version. It does NOT
 * (yet) verify each ed25519 signature or on-chain stake: the live multi-signer
 * network is future infra, and the mock attestor signs a scalar digest, not a
 * per-signer quorum set. Returns problems (empty ⇒ shape OK).
 */
function validateQuorum(q: Record<string, unknown>, bodyHash: string): string[] {
  const out: string[] = [];
  if (q.scheme !== "DACS-quorum-mofn") out.push(`quorum: unexpected scheme ${String(q.scheme)}`);
  if (typeof q.normalizationVersion !== "string" || q.normalizationVersion.length === 0) {
    out.push("quorum: normalizationVersion is missing");
  } else if (q.normalizationVersion !== NORMALIZATION_VERSION) {
    // A verifier on a different normalizer cannot confirm the re-runners agreed
    // — mismatched normalizers false-diverge (the consensus-parameter rule).
    out.push(`quorum: normalizationVersion ${q.normalizationVersion} != verifier's ${NORMALIZATION_VERSION}`);
  }
  if (typeof q.pinnedInputsDigest !== "string" || !HEX64.test(q.pinnedInputsDigest)) {
    out.push("quorum: pinnedInputsDigest is not a sha256 hex");
  }
  const threshold = typeof q.threshold === "number" ? q.threshold : NaN;
  const total = typeof q.total === "number" ? q.total : NaN;
  if (!Number.isInteger(threshold) || threshold < 1) out.push("quorum: threshold must be >= 1");
  if (!Number.isInteger(total) || total < threshold) out.push("quorum: total must be >= threshold");
  const sigs = Array.isArray(q.signatures) ? (q.signatures as unknown[]) : null;
  if (!sigs) {
    out.push("quorum: signatures is not an array");
  } else {
    const signers = new Set<string>();
    for (const [i, raw] of sigs.entries()) {
      if (!isObject(raw) || typeof raw.signer !== "string" || typeof raw.signature !== "string") {
        out.push(`quorum: signatures[${i}] is malformed`);
        continue;
      }
      signers.add(raw.signer);
    }
    if (signers.size !== sigs.length) out.push("quorum: signers are not distinct");
    if (Number.isInteger(threshold) && signers.size < threshold) {
      out.push(`quorum: ${signers.size} distinct signer(s) < threshold ${threshold}`);
    }
  }
  // `bodyHash` is bound by reference here so future signature verification (over
  // `bodyHash|pinnedInputsDigest|normalizationVersion`) has the value on hand.
  void bodyHash;
  return out;
}
