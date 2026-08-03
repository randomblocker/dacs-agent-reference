import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { PROCUREMENT_PROFILES, procurementProfile } from "./procurement-profiles.js";

describe("production procurement profiles", () => {
  test("publishes explicit experiences for both fixed variants, RFQ, and sealed envelope", () => {
    assert.equal(PROCUREMENT_PROFILES.length, 6);
    assert.deepEqual(
      PROCUREMENT_PROFILES.map((profile) => profile.mode),
      ["fixed-price-auto-accept", "fixed-price-live-cosign", "rfq", "rfq", "fixed-price-live-cosign", "sealed-envelope"],
    );
    assert.equal(new Set(PROCUREMENT_PROFILES.map((profile) => profile.id)).size, 6);
    assert.equal(new Set(PROCUREMENT_PROFILES.map((profile) => profile.serviceId)).size, 6);
  });

  test("advertises only profiles with installed production executors as live", () => {
    const live = PROCUREMENT_PROFILES.filter((profile) => profile.implementationStatus === "live");
    assert.deepEqual(live.map((profile) => profile.id), ["oracle-auto-accept", "dd-live-fixed", "security-audit-rfq"]);
    for (const profile of PROCUREMENT_PROFILES.filter((item) => item.implementationStatus === "provisioning")) {
      assert.ok(profile.unavailableReason);
    }
  });

  test("keeps the sealed-envelope timing above its normative two-minute floor", () => {
    const sealed = procurementProfile("dd-sealed-tender");
    assert.ok(sealed);
    assert.equal(sealed.negotiationPhase, "negotiate-sealed-envelope");
    assert.ok(sealed.timing.protocolFloorSec >= 120);
    assert.ok(sealed.timing.healthyMinSec >= sealed.timing.protocolFloorSec);
    assert.ok(sealed.timing.hardTimeoutSec > sealed.timing.healthyMaxSec);
  });

  test("gives every profile bounded user input and runtime", () => {
    for (const profile of PROCUREMENT_PROFILES) {
      assert.ok(profile.fields.length > 0);
      assert.ok(profile.fields.some((field) => field.required));
      assert.ok(profile.timing.healthyMinSec > 0);
      assert.ok(profile.timing.healthyMaxSec >= profile.timing.healthyMinSec);
      assert.ok(profile.timing.hardTimeoutSec > profile.timing.healthyMaxSec);
      assert.ok(profile.paymentRails.length > 0);
      assert.deepEqual(profile.executionControl, {
        model: "server-orchestrated",
        interactiveConfirmation: false,
      });
      assert.deepEqual(profile.buyerControl, {
        model: "gateway-custodied-demo",
        acceptsExternalDacsIdentity: false,
        acceptsExternalPaymentSigner: false,
      });
      assert.equal("confirmationGates" in profile, false);
      assert.deepEqual(profile.railInputs.map((input) => input.rail), profile.paymentRails);
      for (const input of profile.railInputs) {
        assert.ok(input.fields.length > 0);
        assert.ok(input.fields.some((field) => field.required));
        assert.equal(input.sampleInput.paymentRail, input.rail);
      }
    }
  });

  test("publishes a USDC-specific RFQ budget instead of relabelling a DEM field", () => {
    const security = procurementProfile("security-audit-rfq");
    assert.ok(security);
    const dem = security.railInputs.find((input) => input.rail === "pay-dem");
    const x402 = security.railInputs.find((input) => input.rail === "pay-x402");
    assert.ok(dem?.fields.some((field) => field.name === "budgetDem"));
    assert.ok(!dem?.fields.some((field) => field.name === "budgetUsdc"));
    assert.ok(x402?.fields.some((field) => field.name === "budgetUsdc"));
    assert.ok(!x402?.fields.some((field) => field.name === "budgetDem"));
  });

  test("keeps the Sponsored Post seller visible but non-executable until its public account controls exist", () => {
    const sponsored = procurementProfile("sponsored-post-live");
    assert.ok(sponsored);
    assert.equal(sponsored.serviceId, "sponsored-post");
    assert.equal(sponsored.mode, "fixed-price-live-cosign");
    assert.equal(sponsored.implementationStatus, "provisioning");
    assert.match(sponsored.unavailableReason ?? "", /dedicated X account/);
    assert.deepEqual(sponsored.paymentRails, ["pay-dem", "pay-x402"]);
  });

  test("keeps Publisher RFQ honest about its domain and generic-transport provisioning gates", () => {
    const publisher = procurementProfile("publisher-ad-rfq");
    assert.ok(publisher);
    assert.equal(publisher.mode, "rfq");
    assert.equal(publisher.implementationStatus, "provisioning");
    assert.match(publisher.unavailableReason ?? "", /Demos GCR domain identity/);
    assert.match(publisher.unavailableReason ?? "", /generic placement\/duration RFQ transport/);
  });
});
