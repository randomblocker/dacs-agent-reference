/**
 * Wire test — the audit-negotiation desk as a DACS seller (offline, stub path):
 *   npx tsx --test roster/dacs/wire-audit-negotiator.test.ts
 *
 * Exercises the listing surface + the agreed-terms delivery + the offline
 * observeDelivered re-check. The deep sandboxed path (DeepAuditDeps) is the same
 * proven wiring as wire/sec-audit.ts and is type-checked but not run here (no
 * sandbox); this covers the negotiated-terms delivery the RFQ desk always emits.
 */
import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { makeIdentity } from "../../src/identity.js";
import { MemorySubstrate } from "../../src/substrate/memory.js";
import { SellerAdapter } from "./seller-adapter.js";
import {
  AUDIT_NEGOTIATOR_SERVICE_ID,
  auditNegotiatorListingSpec,
  auditNegotiatorObserveDelivered,
  makeAuditNegotiatorWork,
  type AgreedTermsRecord,
} from "./wire/audit-negotiator.js";

const deskId = makeIdentity("AuditDesk", 0x0d);

describe("audit-negotiator listing surface", () => {
  test("advertises rfq negotiation + tier/deadline dimensions + a human fee", () => {
    const spec = auditNegotiatorListingSpec();
    assert.equal(spec.serviceId, AUDIT_NEGOTIATOR_SERVICE_ID);
    assert.deepEqual(spec.supportedNegotiation, ["negotiate-rfq"]);
    assert.deepEqual(spec.supportedPaymentRails, ["pay-dem"]);
    assert.match(spec.description, /tier/);
    assert.match(spec.description, /deadline/);
    assert.match(spec.description, /RFQ|negotiat/i);
  });
});

describe("agreed-terms delivery + offline observeDelivered", () => {
  test("delivers a signed agreed-terms record that re-verifies", async () => {
    const sub = new MemorySubstrate();
    const seller = new SellerAdapter(deskId, sub, AUDIT_NEGOTIATOR_SERVICE_ID, makeAuditNegotiatorWork());
    const { attestation, result } = await seller.deliver("job-rfq-1", {
      repo: "acme/payments-api",
      tier: "deep",
      deadline: "standard",
      price: 12.5,
    });

    assert.equal((result as { delivery: string }).delivery, "agreed-terms");
    const verdict = await auditNegotiatorObserveDelivered()(attestation);
    assert.equal(verdict.ok, true, verdict.ok ? "" : verdict.reason);
  });

  test("quick tier agreed-terms record verifies too", async () => {
    const sub = new MemorySubstrate();
    const seller = new SellerAdapter(deskId, sub, AUDIT_NEGOTIATOR_SERVICE_ID, makeAuditNegotiatorWork());
    const { attestation } = await seller.deliver("job-rfq-2", { repo: "tiny/cli", tier: "quick", deadline: "rush", price: 4 });
    const verdict = await auditNegotiatorObserveDelivered()(attestation);
    assert.equal(verdict.ok, true, verdict.ok ? "" : verdict.reason);
  });

  test("a tampered agreed-terms record is rejected (hash binding)", async () => {
    const sub = new MemorySubstrate();
    const seller = new SellerAdapter(deskId, sub, AUDIT_NEGOTIATOR_SERVICE_ID, makeAuditNegotiatorWork());
    const { attestation } = await seller.deliver("job-rfq-3", { repo: "acme/x", tier: "deep", deadline: "standard", price: 10 });
    // Tamper the carried report JSON without fixing its hash.
    const meta = attestation.meta as { reportJson: string; reportHash: string };
    const parsed = JSON.parse(meta.reportJson) as AgreedTermsRecord;
    parsed.price = 0.01;
    const tampered = { ...attestation, meta: { ...meta, reportJson: JSON.stringify(parsed) } };
    const verdict = await auditNegotiatorObserveDelivered()(tampered);
    assert.equal(verdict.ok, false, "hash mismatch must be caught");
  });

  test("missing repo throws (loud degrade, not a silent bad delivery)", async () => {
    const sub = new MemorySubstrate();
    const seller = new SellerAdapter(deskId, sub, AUDIT_NEGOTIATOR_SERVICE_ID, makeAuditNegotiatorWork());
    await assert.rejects(() => seller.deliver("job-rfq-4", { tier: "deep" }), /repo/);
  });
});
