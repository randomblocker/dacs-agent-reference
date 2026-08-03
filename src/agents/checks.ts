/**
 * Check runners — turn a fetched PR into a set of `CheckResult`s.
 *
 * Two kinds of check:
 *   1. EXECUTION checks (install/build/test/typecheck) run the PR's own
 *      toolchain, which is UNTRUSTED code — so they go through the SandboxPort
 *      and NEVER touch the host. `install` is the one step that may need the
 *      network (`network:"limited"`); everything after runs `network:"none"`.
 *   2. The DEPENDENCY-ADVISORY scan reads npm's advisory endpoint for the PR's
 *      declared deps. It executes NO project code (pure advisory reads), so it
 *      is safe to run outside the sandbox — reusing the dep-upgrade agent's
 *      RegistryPort (roster/dep-upgrade/registry.ts).
 *
 * Check PLANNING is derived from the parsed package.json: build runs only if a
 * `build` script exists, test only if a `test` script exists, typecheck only
 * when TypeScript is a declared dependency. Non-node PRs produce no execution
 * checks (graceful degrade) — the evaluator then leans on the LLM layer.
 */
import { parseInventory } from "../../roster/dep-upgrade/inventory.js";
import type { RegistryPort } from "../../roster/dep-upgrade/types.js";
import type { FetchedPr } from "./repo-fetch.js";
import {
  DEFAULT_LIMITS,
  type CheckResult,
  type CheckSpec,
  type SandboxLimits,
  type SandboxPort,
  hashOutput,
  normalizedOutputHash,
  sandboxOutputTail,
} from "./sandbox.js";

export const DEFAULT_IMAGE = "node:20-alpine";
const DEFAULT_TIMEOUT_MS = 300_000;

/** The execution checks that form the mechanical backbone (advisory excluded). */
export const GATING_CHECKS: ReadonlySet<string> = new Set(["install", "build", "test", "typecheck"]);

interface PkgManifest {
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

function parseManifest(text: string | undefined): PkgManifest | null {
  if (!text) return null;
  try {
    return JSON.parse(text) as PkgManifest;
  } catch {
    return null;
  }
}

function isTypeScript(m: PkgManifest): boolean {
  return Boolean(m.devDependencies?.typescript || m.dependencies?.typescript);
}

export interface CheckPlan {
  install: boolean;
  build: boolean;
  test: boolean;
  typecheck: boolean;
}

/** Decide which execution checks apply to this PR from its manifest. */
export function planChecks(fetched: FetchedPr): CheckPlan {
  const m = parseManifest(fetched.packageJson);
  if (fetched.projectType !== "node" || !m) {
    return { install: false, build: false, test: false, typecheck: false };
  }
  return {
    install: true,
    build: Boolean(m.scripts?.build),
    test: Boolean(m.scripts?.test),
    typecheck: isTypeScript(m),
  };
}

export interface RunChecksOptions {
  image?: string;
  timeoutMs?: number;
  limits?: SandboxLimits;
  /**
   * Install strategy (D2 — deterministic install).
   *   - "auto" (default): `npm ci` (lockfile-exact) with a fallback to
   *     `npm install`. The fallback is load-bearing for the ORIGINAL executor:
   *     applying a dep upgrade intentionally desyncs package.json from the
   *     committed lock, so `npm ci` fails and `npm install` must regenerate the
   *     lock (this is the step that produces `lockfileAfterHash`).
   *   - "ci-only": strictly `npm ci`, NO fallback. This is the deterministic,
   *     lockfile-exact install a QUORUM RE-RUNNER uses: it writes the claimant's
   *     committed lockfile (a pinned input) and installs exactly it, so a
   *     resolution difference cannot creep in. A non-deterministic `npm install`
   *     is never reached.
   */
  installStrategy?: "auto" | "ci-only";
}

function spec(
  name: string,
  cmd: string[],
  network: "none" | "limited",
  fetched: FetchedPr,
  opts: RunChecksOptions,
): CheckSpec {
  return {
    name,
    image: opts.image ?? DEFAULT_IMAGE,
    workspaceDir: fetched.workspaceDir,
    cmd,
    timeoutMs: opts.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    network,
    limits: opts.limits ?? DEFAULT_LIMITS,
  };
}

/**
 * Run the sandboxed execution checks for a PR. The install step gets
 * `network:"limited"` (deps must be fetched); all later steps run with the
 * network DISABLED. If install fails, later steps are skipped — they would all
 * fail on missing deps, and the failed install already breaks the backbone.
 *
 * The caller MUST have confirmed `sandbox.available()` first — this function
 * assumes isolation is available and simply drives it.
 */
export async function runExecutionChecks(
  sandbox: SandboxPort,
  fetched: FetchedPr,
  opts: RunChecksOptions = {},
): Promise<CheckResult[]> {
  const plan = planChecks(fetched);
  const results: CheckResult[] = [];
  if (!plan.install) return results; // non-node → no execution checks

  // install: `npm ci` (lockfile-exact). In "auto" a failed ci falls back to
  // `npm install`; in "ci-only" (re-runner determinism, D2) there is NO
  // fallback so a non-deterministic resolution can never enter the commitment.
  let install = await sandbox.run(spec("install", ["npm", "ci"], "limited", fetched, opts));
  if (!install.passed && opts.installStrategy !== "ci-only") {
    const alt = await sandbox.run(spec("install", ["npm", "install"], "limited", fetched, opts));
    if (alt.passed) install = alt; // prefer the passing variant
  }
  results.push(install);
  if (!install.passed) return results; // deps missing → skip the rest

  if (plan.build) results.push(await sandbox.run(spec("build", ["npm", "run", "build"], "none", fetched, opts)));
  if (plan.test) results.push(await sandbox.run(spec("test", ["npm", "test"], "none", fetched, opts)));
  if (plan.typecheck)
    results.push(
      await sandbox.run(spec("typecheck", ["npx", "tsc", "--noEmit"], "none", fetched, opts)),
    );
  return results;
}

// ---------------------------------------------------------------------------
// Dependency-advisory scan (safe outside the sandbox — advisory reads only)
// ---------------------------------------------------------------------------

export interface AdvisoryHit {
  package: string;
  version: string;
  id: string;
  severity: "low" | "moderate" | "high" | "critical" | "unknown";
  title: string;
  url: string;
}

export interface AdvisoryScan {
  /** Synthesized as a CheckResult so it rides in the verdict + attestation. */
  result: CheckResult;
  hits: AdvisoryHit[];
}

/**
 * Query npm's bulk advisory endpoint for the PR's declared deps and fold the
 * answer into a `CheckResult` (name "dep-advisory"). This runs NO project code,
 * so it is safe on the host. High/critical hits mark the check failed (a signal
 * the evaluator surfaces as findings); it is ADVISORY, not part of the
 * build/test backbone (see GATING_CHECKS).
 */
export async function runAdvisoryScan(fetched: FetchedPr, registry: RegistryPort): Promise<AdvisoryScan | null> {
  if (fetched.projectType !== "node" || !fetched.packageJson) return null;
  const inventory = parseInventory(fetched.workspaceDir, fetched.packageJson, fetched.packageLock);
  // Build the bulk query: package → [versions to check]. Prefer the lockfile's
  // installed version; fall back to the declared range stripped of ^/~.
  const query: Record<string, string[]> = {};
  for (const dep of inventory.deps) {
    const version = dep.installedVersion ?? dep.range.replace(/^[\^~>=<\s]+/, "");
    if (version) (query[dep.name] ??= []).push(version);
  }

  const started = Date.now();
  const hits: AdvisoryHit[] = [];
  let output: string;
  try {
    const advisories = Object.keys(query).length > 0 ? await registry.getAdvisories(query) : new Map();
    for (const [pkg, list] of advisories) {
      const version = query[pkg]?.[0] ?? "*";
      for (const a of list) {
        hits.push({ package: pkg, version, id: a.id, severity: a.severity, title: a.title, url: a.url });
      }
    }
    output = hits.length === 0 ? "no known advisories for declared deps" : hits
      .map((h) => `${h.severity.toUpperCase()} ${h.package}@${h.version} ${h.id} — ${h.title}`)
      .join("\n");
  } catch (err) {
    // Advisory endpoint unreachable → a non-fatal, non-passing informational
    // check (NOT a backbone failure). The evaluator does not gate on it.
    output = `advisory scan unavailable: ${(err as Error).message}`;
    const result: CheckResult = {
      name: "dep-advisory",
      cmd: ["advisory:bulk"],
      exitCode: 0,
      passed: true, // unavailable ≠ vulnerable
      durationMs: Date.now() - started,
      outputTail: sandboxOutputTail(output),
      outputHash: hashOutput(output),
      normalizedOutputHash: normalizedOutputHash(output),
    };
    return { result, hits: [] };
  }

  const severe = hits.some((h) => h.severity === "high" || h.severity === "critical");
  const result: CheckResult = {
    name: "dep-advisory",
    cmd: ["advisory:bulk"],
    exitCode: severe ? 1 : 0,
    passed: !severe,
    durationMs: Date.now() - started,
    outputTail: sandboxOutputTail(output),
    outputHash: hashOutput(output),
    normalizedOutputHash: normalizedOutputHash(output),
  };
  return { result, hits };
}
