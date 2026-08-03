/**
 * The dep-upgrade plan is now INDEPENDENTLY verifiable: the deliverable carries
 * the registry snapshots it was derived from, and `observeDelivered` re-runs
 * `buildPlan` over them and requires an exact match. These tests prove the
 * verifier accepts a genuine plan and REJECTS a fabricated one — the property
 * the plan lacked before (it could only be checked for shape).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { lodashFallbackRegistry } from "../dep-upgrade/registry.js";
import {
  makeDepUpgradeWork,
  depUpgradeObserveDelivered,
  type UpgradePlanDeliverable,
} from "./wire/dep-upgrade.js";
import { reportMeta } from "./wire/report-meta.js";
import type { DeliveryAttestation } from "./seller-adapter.js";

const PKG = { name: "app", dependencies: { lodash: "^4.17.20" } };

async function deliverMeta(): Promise<ReturnType<typeof reportMeta>> {
  const work = makeDepUpgradeWork(lodashFallbackRegistry());
  const out = (await work("job-verify", { packageJson: PKG })) as { meta: ReturnType<typeof reportMeta> };
  return out.meta;
}

const attOf = (meta: ReturnType<typeof reportMeta>): DeliveryAttestation =>
  ({ meta } as unknown as DeliveryAttestation);

test("dep-upgrade: a genuine plan verifies by re-derivation", async () => {
  const res = await depUpgradeObserveDelivered()(attOf(await deliverMeta()));
  assert.equal(res.ok, true, res.ok ? "" : res.reason);
});

test("dep-upgrade: a fabricated plan is rejected (re-derivation mismatch)", async () => {
  const deliverable = JSON.parse((await deliverMeta()).reportJson) as UpgradePlanDeliverable;
  // Forge a target version buildPlan would never produce from the same inputs.
  if (deliverable.plan.items.length > 0) {
    deliverable.plan.items[0]!.targetVersion = "9.9.9";
  } else {
    (deliverable.plan.items as unknown[]).push({
      name: "ghost", section: "dependencies", kind: "security",
      currentVersion: "1.0.0", currentRange: "^1.0.0", targetVersion: "9.9.9",
      newRange: "^9.9.9", breaking: true, advisories: [], rationale: "forged",
    });
  }
  const res = await depUpgradeObserveDelivered()(attOf(reportMeta(deliverable)));
  assert.equal(res.ok, false);
  assert.match(res.reason!, /deterministic buildPlan output/);
});

test("dep-upgrade: stripping the carried registry inputs is rejected", async () => {
  const deliverable = JSON.parse((await deliverMeta()).reportJson) as Partial<UpgradePlanDeliverable>;
  delete deliverable.inputs;
  const res = await depUpgradeObserveDelivered()(attOf(reportMeta(deliverable)));
  assert.equal(res.ok, false);
  assert.match(res.reason!, /omits the registry inputs/);
});
