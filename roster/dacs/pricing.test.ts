/**
 * Usage-based (per-unit) pricing tests — the "huge review vs tiny review"
 * problem. For each variable-effort seller a BIG job must cost more than a
 * SMALL one, the billing floor (minTotal) protects tiny jobs, and
 * formatFeeSchedule renders the rate a live buyer reads. Plus computeFee unit
 * tests and the Butler's per-unit audit-trail transparency.
 *
 *   npx tsx --test roster/dacs/pricing.test.ts
 */
import { describe, test } from "node:test";
import assert from "node:assert/strict";
import {
  baseToDisplay,
  computeFee,
  displayToBase,
  fixedFeeFromPrice,
  formatFeeSchedule,
  type FeeSchedule,
} from "./wire/pricing.js";
import { SEC_AUDIT_FEES, secAuditUnitsFor } from "./wire/sec-audit.js";
import { DEPUP_FEES, depUpgradeUnitsFor } from "./wire/dep-upgrade.js";
import { SITE_FEES, siteAuditorUnitsFor } from "./wire/site-auditor.js";
import { REVIEWBOT_FEES, reviewBotUnitsFor } from "../../src/agents/seller.js";
import { ProcurementButler, DEFAULT_CONFIG } from "../procurement-butler/butler.js";
import { MarketplaceStub } from "../procurement-butler/marketplace-stub.js";
import type { Listing, ProcurementGoal } from "../procurement-butler/types.js";

// ===========================================================================
// 1. computeFee — the pricing kernel
// ===========================================================================

describe("computeFee", () => {
  const perUnit: FeeSchedule = { kind: "per-unit", unitPrice: 0.5, unit: "file", minTotal: 1 };

  test("fixed: passthrough regardless of units", () => {
    assert.equal(computeFee({ kind: "fixed", price: 2.5 }, 1), 2.5);
    assert.equal(computeFee({ kind: "fixed", price: 2.5 }, 999), 2.5);
  });

  test("per-unit: scales linearly with units", () => {
    assert.equal(computeFee(perUnit, 4), 2); // 0.5 * 4
    assert.equal(computeFee(perUnit, 10), 5); // 0.5 * 10
    assert.equal(computeFee(perUnit, 20), 10);
  });

  test("per-unit: floor (minTotal) protects tiny jobs", () => {
    assert.equal(computeFee(perUnit, 1), 1, "1 unit x 0.5 = 0.5 -> floored to 1");
    assert.equal(computeFee(perUnit, 2), 1, "2 units x 0.5 = 1.0 == floor");
    assert.equal(computeFee(perUnit, 3), 1.5, "above the floor it scales");
  });

  test("per-unit: rounds to cents deterministically", () => {
    assert.equal(computeFee({ kind: "per-unit", unitPrice: 0.1, unit: "dep", minTotal: 1 }, 33), 3.3);
  });
});

// ===========================================================================
// 2. formatFeeSchedule — the rate a live buyer reads (schema has no fee field)
// ===========================================================================

describe("formatFeeSchedule", () => {
  test("per-unit renders unit + floor", () => {
    assert.equal(
      formatFeeSchedule({ kind: "per-unit", unitPrice: 0.5, unit: "file", minTotal: 1 }, "DEM"),
      "0.5 DEM per file (min 1 DEM)",
    );
    assert.equal(
      formatFeeSchedule({ kind: "per-unit", unitPrice: 0.1, unit: "dependency", minTotal: 1 }, "DEM"),
      "0.1 DEM per dependency (min 1 DEM)",
    );
  });

  test("fixed renders a flat price (matches formatFee over the base price)", () => {
    assert.equal(formatFeeSchedule({ kind: "fixed", price: 1 }, "DEM"), "1 DEM");
    assert.equal(formatFeeSchedule({ kind: "fixed", price: 0.05 }, "USDC"), "0.05 USDC");
  });

  test("all four converted rate strings are ASCII (safe for live anchoring)", () => {
    for (const s of [
      formatFeeSchedule(SEC_AUDIT_FEES, "DEM"),
      formatFeeSchedule(DEPUP_FEES, "DEM"),
      formatFeeSchedule(SITE_FEES, "DEM"),
      formatFeeSchedule(REVIEWBOT_FEES, "DEM"),
    ]) {
      assert.ok(/^[\x20-\x7e]+$/.test(s), `non-ASCII in "${s}"`);
    }
  });
});

// ===========================================================================
// 3. base<->display conversions (on-wire vs human numbers)
// ===========================================================================

describe("base/display conversions", () => {
  test("baseToDisplay scales down by asset decimals", () => {
    assert.equal(baseToDisplay("1000000000", "DEM"), 1);
    assert.equal(baseToDisplay("50000", "USDC"), 0.05);
  });
  test("displayToBase is the inverse", () => {
    assert.equal(displayToBase(1, "DEM"), "1000000000");
    assert.equal(displayToBase(3, "DEM"), "3000000000");
    assert.equal(displayToBase(1.5, "DEM"), "1500000000");
  });
  test("fixedFeeFromPrice derives a display-unit fixed schedule, invariant to units", () => {
    const fees = fixedFeeFromPrice({ amount: "1000000000", asset: "DEM" });
    assert.deepEqual(fees, { kind: "fixed", price: 1 });
    assert.equal(computeFee(fees, 1), 1);
    assert.equal(computeFee(fees, 50), 1, "fixed is invariant to job size");
  });
});

// ===========================================================================
// 4. Each converted seller: BIG job > SMALL job, floor protects tiny jobs
// ===========================================================================

/** A minimal 20-dependency package.json (deps + devDeps counted together). */
function pkgWith(nDeps: number, nDev = 0): Record<string, unknown> {
  const dependencies: Record<string, string> = {};
  const devDependencies: Record<string, string> = {};
  for (let i = 0; i < nDeps; i++) dependencies[`pkg-${i}`] = "^1.0.0";
  for (let i = 0; i < nDev; i++) devDependencies[`dev-${i}`] = "^1.0.0";
  return { name: "t", version: "1.0.0", dependencies, devDependencies };
}

function diffOf(lines: number): string {
  return Array.from({ length: lines }, (_, i) => `+ line ${i}`).join("\n");
}

describe("sec-audit — priced per file scanned", () => {
  test("6-file audit costs more than a 1-file audit; tiny job hits the floor", () => {
    const small = computeFee(SEC_AUDIT_FEES, secAuditUnitsFor([{ path: "a" }]));
    const large = computeFee(SEC_AUDIT_FEES, secAuditUnitsFor(Array.from({ length: 6 }, (_, i) => ({ path: `f${i}` }))));
    assert.equal(small, 1, "1 file -> 0.5 floored to the 1 DEM minimum");
    assert.equal(large, 3, "6 files x 0.5 = 3 DEM");
    assert.ok(large > small);
  });
});

describe("dep-upgrade — priced per dependency", () => {
  test("counts deps + devDeps, accepts a JSON string, and scales", () => {
    assert.equal(depUpgradeUnitsFor(pkgWith(3, 2)), 5);
    assert.equal(depUpgradeUnitsFor(JSON.stringify(pkgWith(4))), 4);
    const small = computeFee(DEPUP_FEES, depUpgradeUnitsFor(pkgWith(1)));
    const large = computeFee(DEPUP_FEES, depUpgradeUnitsFor(pkgWith(20)));
    assert.equal(small, 1, "1 dep -> 0.1 floored to the 1 DEM minimum");
    assert.equal(large, 2, "20 deps x 0.1 = 2 DEM");
    assert.ok(large > small);
  });
});

describe("site-auditor — priced per probe sample", () => {
  test("more samples cost more; default 3; tiny job hits the floor", () => {
    assert.equal(siteAuditorUnitsFor(undefined), 3, "default samples");
    assert.equal(siteAuditorUnitsFor({ samples: 10 }), 10);
    const small = computeFee(SITE_FEES, siteAuditorUnitsFor({ samples: 1 }));
    const large = computeFee(SITE_FEES, siteAuditorUnitsFor({ samples: 10 }));
    assert.equal(small, 1, "1 sample -> 0.5 floored to the 1 DEM minimum");
    assert.equal(large, 5, "10 samples x 0.5 = 5 DEM");
    assert.ok(large > small);
  });
});

describe("ReviewBot — priced per 100 diff lines", () => {
  test("ceil(diffLines/100) units; big review costs more; tiny job hits the floor", () => {
    assert.equal(reviewBotUnitsFor(diffOf(50)), 1);
    assert.equal(reviewBotUnitsFor(diffOf(350)), 4);
    const small = computeFee(REVIEWBOT_FEES, reviewBotUnitsFor(diffOf(50)));
    const large = computeFee(REVIEWBOT_FEES, reviewBotUnitsFor(diffOf(350)));
    assert.equal(small, 1, "50 lines -> 1 unit -> floored to 1 DEM");
    assert.equal(large, 2, "350 lines -> 4 units x 0.5 = 2 DEM");
    assert.ok(large > small);
  });
});

// ===========================================================================
// 5. Butler audit-trail transparency for a per-unit deal
// ===========================================================================

describe("Butler prices per-unit listings by estimatedUnits, transparently", () => {
  const perUnitListing: Listing = {
    id: "lst-secaudit",
    provider: "Security-Audit Desk",
    description: "per-file audit",
    capabilities: ["sec-audit"],
    fees: SEC_AUDIT_FEES,
    rails: ["pay-dem"],
    negotiable: false,
    quality: { rating: 4.7, completedJobs: 48, disputeRate: 0.01 },
    acceptance: { checks: [{ kind: "min-length", minChars: 10 }] },
  };

  function butler(): ProcurementButler {
    const market = new MarketplaceStub([perUnitListing], { floors: {} });
    return new ProcurementButler(market, market, DEFAULT_CONFIG);
  }

  test("askPrice scales with estimatedUnits; audit records unit count + basis", async () => {
    const goal: ProcurementGoal = { description: "audit 6 files", requiredCapabilities: ["sec-audit"], estimatedUnits: 6 };
    const d = await butler().procure(goal, 20);
    const cand = d.candidates.find((c) => c.listingId === "lst-secaudit")!;
    assert.equal(cand.askPrice, 3, "6 files x 0.5 = 3 DEM total");
    assert.equal(cand.units, 6, "audit trail shows the unit count");
    assert.deepEqual(cand.feeBasis, { unit: "file", unitPrice: 0.5, minTotal: 1 });
    assert.equal(d.winner?.price, 3);
  });

  test("a tiny job is billed the floor, not units x price", async () => {
    const goal: ProcurementGoal = { description: "audit 1 file", requiredCapabilities: ["sec-audit"], estimatedUnits: 1 };
    const d = await butler().procure(goal, 20);
    assert.equal(d.candidates.find((c) => c.listingId === "lst-secaudit")!.askPrice, 1, "floor enforced");
  });

  test("a fixed listing carries no per-unit audit annotations", async () => {
    const fixed: Listing = { ...perUnitListing, id: "lst-fixed", fees: { kind: "fixed", price: 4 } };
    const market = new MarketplaceStub([fixed], { floors: {} });
    const d = await new ProcurementButler(market, market).procure(
      { description: "x", requiredCapabilities: ["sec-audit"], estimatedUnits: 6 },
      20,
    );
    const cand = d.candidates.find((c) => c.listingId === "lst-fixed")!;
    assert.equal(cand.askPrice, 4, "fixed price ignores units");
    assert.equal(cand.units, undefined);
    assert.equal(cand.feeBasis, undefined);
  });
});
