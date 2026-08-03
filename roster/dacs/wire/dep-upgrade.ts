/**
 * Wire the dep-upgrade core into the shared DACS seller layer on the pay-dem
 * session rail (Pattern 2), advisory-PLAN-only safe slice.
 *
 * The dependency-upgrade agent's full loop applies bumps, runs `npm install` +
 * `npm test`, and opens PRs. That whole surface is UNsafe to sell blind, so the
 * DACS listing sells only the read-only slice the gateway exposes: an
 * advisory-driven `UpgradePlan` over a POSTED package.json — real npm registry
 * reads, zero apply / npm / GitHub side effects (registry.ts §4).
 *
 * Scope is `parameterized`: the buyer conveys the target package.json at
 * session-open, so this settles on the pay-dem session rail. The plan is
 * deterministic and carries the exact package manifest, packuments and
 * advisories used to derive it. `observeDelivered` re-runs `buildPlan` over
 * those frozen inputs, so a buyer can reject a fabricated plan without
 * trusting the seller process.
 */
import { parseInventory } from "../../dep-upgrade/inventory.js";
import { isDeepStrictEqual } from "node:util";
import { buildPlan, resolveCurrentVersion } from "../../dep-upgrade/planner.js";
import {
  formatExecutePricing,
  runExecuteUpgrade,
  verifyExecReport,
  type ExecReport,
  type ExecuteDeps,
  type ExecuteTarget,
} from "../../dep-upgrade/execute.js";
import type { Advisory, Packument, RegistryPort, UpgradePlan } from "../../dep-upgrade/types.js";
import type { WorkCallback } from "../seller-adapter.js";
import type { DeliveryVerifyOptions } from "../verifier.js";
import { readReportMeta, reportMeta } from "./report-meta.js";
import { formatFeeSchedule, type FeeSchedule } from "./pricing.js";

/** The DACS serviceId under which the dep-upgrade desk sells upgrade plans. */
export const DEPUP_SERVICE_ID = "dep-upgrade-plan";
/** The delivery phase advertised (and required by the session terms). */
export const DEPUP_DELIVERY_PHASE = "deliver-upgrade-plan";
/** Params are conveyed at session-open ⇒ pay-dem session rail. */
export const DEPUP_SCOPE = "parameterized" as const;

/**
 * Usage-based pricing: billed per dependency in the posted package.json (a
 * 20-dependency manifest costs proportionally more than a 1-dependency one),
 * with a 1 DEM billing floor. Numbers are DISPLAY units (DEM).
 */
export const DEPUP_FEES: FeeSchedule = { kind: "per-unit", unitPrice: 0.1, unit: "dependency", minTotal: 1 };

/**
 * Units for a dep-upgrade job = the number of dependencies (deps + devDeps) in
 * the posted package.json. Accepts a parsed object or a JSON string.
 */
export function depUpgradeUnitsFor(pkgJson: unknown): number {
  const pkg = typeof pkgJson === "string" ? safeParse(pkgJson) : pkgJson;
  if (!pkg || typeof pkg !== "object") return 0;
  const p = pkg as { dependencies?: Record<string, unknown>; devDependencies?: Record<string, unknown> };
  return Object.keys({ ...(p.dependencies ?? {}), ...(p.devDependencies ?? {}) }).length;
}

function safeParse(s: string): unknown {
  try {
    return JSON.parse(s);
  } catch {
    return undefined;
  }
}

/** The listing surface the dep-upgrade desk advertises on the pay-dem rail. */
export function depUpgradeListingSpec(price: { amount: string; asset: string }) {
  const fees = DEPUP_FEES;
  return {
    serviceId: DEPUP_SERVICE_ID,
    name: "Dependency-Upgrade Desk - advisory-driven upgrade plans",
    description:
      `An upgrade plan for a posted package.json, built from live npm registry ` +
      `and advisory data. Plan only - never installs, verifies, or opens PRs. ` +
      `Fee: ${formatFeeSchedule(fees, price.asset)}.`,
    supportedNegotiation: ["negotiate-fixed-price"],
    supportedPaymentRails: ["pay-dem"],
    supportedDelivery: [DEPUP_DELIVERY_PHASE],
    /** Structured usage-based fee (read by the in-process Butler; NOT anchored). */
    fees,
  };
}

/** The safe-slice deliverable: what the buyer paid for. */
export interface UpgradePlanDeliverable {
  packageName: string;
  plan: UpgradePlan;
  inputs: {
    packageJson: unknown;
    includeNextMajor: boolean;
    packuments: Packument[];
    advisories: Array<{ packageName: string; entries: Advisory[] }>;
  };
}

/**
 * Build the dep-upgrade work callback over an injected RegistryPort (real npm
 * registry, or a canned FakeRegistry for tests/offline). The buyer conveys
 * `{ packageJson, includeNextMajor? }`; the plan is the deliverable.
 */
export function makeDepUpgradeWork(registry: RegistryPort): WorkCallback {
  return async (_jobId, params) => {
    const packageJson = params.packageJson ?? params.package ?? params.manifest;
    if (packageJson === undefined) throw new Error("dep-upgrade: params.packageJson is required");
    const includeNextMajor = params.includeNextMajor === true;

    let inventory;
    try {
      inventory = parseInventory("(posted)", JSON.stringify(packageJson));
    } catch (err) {
      throw new Error(`dep-upgrade: package.json could not be parsed: ${(err as Error).message}`);
    }

    // Registry intel — packuments then one bulk advisory query. No fs, no writes.
    const packuments = new Map<string, Packument>();
    for (const dep of inventory.deps) {
      if (!packuments.has(dep.name)) packuments.set(dep.name, await registry.getPackument(dep.name));
    }
    const advisoryQuery: Record<string, string[]> = {};
    for (const dep of inventory.deps) {
      const current = resolveCurrentVersion(dep, packuments.get(dep.name)!);
      if (current) advisoryQuery[dep.name] = [...(advisoryQuery[dep.name] ?? []), current];
    }
    const advisories =
      Object.keys(advisoryQuery).length > 0
        ? await registry.getAdvisories(advisoryQuery)
        : new Map<string, Advisory[]>();

    const plan = buildPlan(inventory, packuments, advisories, { proposeNextMajor: includeNextMajor });
    const deliverable: UpgradePlanDeliverable = {
      packageName: inventory.packageName,
      plan,
      inputs: {
        packageJson,
        includeNextMajor,
        packuments: [...packuments.values()],
        advisories: [...advisories].map(([packageName, entries]) => ({ packageName, entries })),
      },
    };
    const meta = reportMeta(deliverable);

    return {
      // Compact, integer/string-only digest (JCS-safe for resultHash).
      result: {
        packageName: inventory.packageName,
        planned: plan.items.length,
        unactionable: plan.unactionable.length,
        security: plan.items.filter((i) => i.kind === "security").length,
      },
      deliverableRef: `dep-upgrade:plan:${meta.reportHash}`,
      meta,
    };
  };
}

/**
 * `observeDelivered`: check the artifact hash and structure, then independently
 * re-derive the plan from the carried registry inputs. The exact deterministic
 * output must match; structural shape alone is not sufficient.
 */
export function depUpgradeObserveDelivered(): DeliveryVerifyOptions["observeDelivered"] {
  return async (att) => {
    const read = readReportMeta<UpgradePlanDeliverable>(att);
    if (!read.ok) return { ok: false, reason: read.reason };
    const { plan, packageName, inputs } = read.artifact;
    if (typeof packageName !== "string" || !plan || !Array.isArray(plan.items) || !Array.isArray(plan.unactionable)) {
      return { ok: false, reason: "deliverable is not a structurally-valid UpgradePlan" };
    }
    if (!inputs || !Array.isArray(inputs.packuments) || !Array.isArray(inputs.advisories)) {
      return { ok: false, reason: "deliverable omits the registry inputs needed for independent verification" };
    }
    for (const [i, it] of plan.items.entries()) {
      if (!it || typeof it.name !== "string" || typeof it.targetVersion !== "string") {
        return { ok: false, reason: `plan.items[${i}] missing name/targetVersion` };
      }
    }
    try {
      const inventory = parseInventory("(delivered)", JSON.stringify(inputs.packageJson));
      const packuments = new Map(inputs.packuments.map((entry) => [entry.name, entry]));
      const advisories = new Map(inputs.advisories.map((entry) => [entry.packageName, entry.entries]));
      const rebuilt = buildPlan(inventory, packuments, advisories, {
        proposeNextMajor: inputs.includeNextMajor === true,
      });
      if (!isDeepStrictEqual(rebuilt, plan)) {
        return { ok: false, reason: "plan does not match the deterministic buildPlan output for its carried inputs" };
      }
    } catch (error) {
      return { ok: false, reason: `registry inputs could not be independently verified: ${(error as Error).message}` };
    }
    return { ok: true };
  };
}

// ===========================================================================
// EXECUTOR TIER — attested executor: apply the advisory-clearing upgrade + PROVE
// the suite green in a sandbox. Sold as a SEPARATE service (real work: clone +
// apply + install/test) that rides the SAME seller/verifier wiring; the buyer
// conveys a repo (+ optional ref) at session open, so scope is `parameterized`
// ⇒ pay-dem session rail. This is the value lever over a free Dependabot PR: a
// reputation-staked, third-party-re-verifiable proof that the upgrade lands
// GREEN, with the patch attached — the settleable "off the vuln, suite still
// passes" a bounty/DAO/untrusting maintainer pays for.
// ===========================================================================

/** The DACS serviceId under which the executor sells proven upgrades. */
export const DEPUP_EXEC_SERVICE_ID = "dep-upgrade-execute";
export const DEPUP_EXEC_DELIVERY_PHASE = "deliver-upgrade-execute";
export const DEPUP_EXEC_SCOPE = "parameterized" as const;

/** The listing surface the executor advertises on the pay-dem rail. */
export function depUpgradeExecuteListingSpec() {
  return {
    serviceId: DEPUP_EXEC_SERVICE_ID,
    name: "Dependency-Upgrade Desk (execute) - proven-green upgrade + patch",
    description:
      `Clones your repo, applies the advisory-CLEARING upgrade, and PROVES the ` +
      `suite is still green in an isolated sandbox (install/build/test/typecheck), ` +
      `then delivers a reputation-staked, re-verifiable artifact: the vulnerable ` +
      `versions BEFORE, the chosen versions AFTER, the applied patch (yours to take), ` +
      `each check's bound outputHash, and an independent advisory re-scan confirming ` +
      `the fix. The verdict cannot claim 'upgraded-green' unless the checks provably ` +
      `passed and the advisories are cleared. Fee: ${formatExecutePricing()}.`,
    supportedNegotiation: ["negotiate-fixed-price"],
    supportedPaymentRails: ["pay-dem"],
    supportedDelivery: [DEPUP_EXEC_DELIVERY_PHASE],
  };
}

/** The compact `result` digest carried in the 200 body + hashed into resultHash. */
export interface DepUpgradeExecResult {
  repo: string;
  ref: string;
  headSha: string;
  verdict: ExecReport["verdict"];
  upgraded: number;
  checks: number;
  advisoriesCleared: boolean;
}

/**
 * Build the executor work callback. The buyer conveys `{ repo, ref? }`; the
 * sealed `ExecReport` is the deliverable (carried as the signed delivery-
 * attestation meta via `reportMeta`). The heavy ports (repo fetch, sandbox,
 * registry) are injected here so tests/offline runs wire fakes.
 */
export function makeDepUpgradeExecuteWork(deps: ExecuteDeps): WorkCallback {
  return async (_jobId, params) => {
    const repo = typeof params.repo === "string" ? params.repo : "";
    if (!repo) throw new Error("dep-upgrade-execute: params.repo (owner/name) is required");
    const target: ExecuteTarget = { repo, ref: typeof params.ref === "string" ? params.ref : undefined };

    const artifact = await runExecuteUpgrade(deps, target);
    const result: DepUpgradeExecResult = {
      repo: artifact.repo,
      ref: artifact.ref,
      headSha: artifact.headSha,
      verdict: artifact.verdict,
      upgraded: artifact.after.length,
      checks: artifact.checks.length,
      advisoriesCleared: artifact.advisoriesCleared,
    };

    return {
      result,
      deliverableRef: `dep-upgrade-execute:${artifact.headSha}:${artifact.seal.bodyHash.slice(0, 12)}`,
      meta: reportMeta(artifact),
    };
  };
}

/**
 * `observeDelivered`: re-run `verifyExecReport` over the delivered artifact
 * offline — seal re-hashed, patchHash re-derived, every claimed `after` version
 * proven present in the patch, each check's outputHash bound, and the verdict
 * backbone re-enforced with NO fail-open (an artifact claiming `upgraded-green`
 * over a failing check or uncleared advisories is rejected).
 */
export function depUpgradeExecuteObserveDelivered(): DeliveryVerifyOptions["observeDelivered"] {
  return async (att) => {
    const read = readReportMeta<ExecReport>(att);
    if (!read.ok) return { ok: false, reason: read.reason };
    const verdict = verifyExecReport(read.artifact);
    return verdict.valid
      ? { ok: true }
      : { ok: false, reason: `dep-upgrade-execute verification failed: ${verdict.problems.join("; ")}` };
  };
}
