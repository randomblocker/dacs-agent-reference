/**
 * Build D — generalized sellers + EvalBot gate + rail-eligibility tests.
 * Fully offline (fakes only).
 *   npx tsx --test roster/dacs/ecosystem.test.ts
 */
import { describe, test } from "node:test";
import assert from "node:assert/strict";

import { makeIdentity } from "../../src/identity.js";
import { MemorySubstrate } from "../../src/substrate/memory.js";
import { MockDahrAttestor } from "../oracle-desk/attested-fetch.js";
import { lodashFallbackRegistry } from "../dep-upgrade/registry.js";
import { FakeProber, type ProbeResult, type TlsInfo } from "../site-auditor/prober.js";
import { fixtureSources } from "../compliance/sources.js";
import { EvalBot } from "../evalbot/evalbot.js";

import { SellerAdapter, type WorkCallback } from "./seller-adapter.js";
import { VerifierAdapter, type DeliveryVerifyOptions } from "./verifier.js";
import { eligibleRails, executionModeFor, type PurchaseOutcome } from "./wire/butler.js";
import { resolveWithEvaluator, rubricForOutcome } from "./wire/evaluator.js";

import { DEPUP_SCOPE, DEPUP_SERVICE_ID, depUpgradeListingSpec, depUpgradeObserveDelivered, makeDepUpgradeWork } from "./wire/dep-upgrade.js";
import { TREASURY_SCOPE, TREASURY_SERVICE_ID, treasuryListingSpec, treasuryObserveDelivered, makeTreasuryWork } from "./wire/treasury-ops.js";
import { EVALBOT_SCOPE, EVALBOT_SERVICE_ID, evalBotListingSpec, evalBotObserveDelivered, makeEvalBotWork } from "./wire/evalbot.js";
import { SITE_SCOPE, SITE_SERVICE_ID, siteAuditorListingSpec, siteAuditorObserveDelivered, makeSiteAuditorWork } from "./wire/site-auditor.js";
import { SEC_AUDIT_SCOPE, SEC_AUDIT_SERVICE_ID, secAuditListingSpec, secAuditObserveDelivered, makeSecAuditWork } from "./wire/sec-audit.js";
import { COMPLIANCE_SCOPE, COMPLIANCE_SERVICE_ID, complianceListingSpec, complianceObserveDelivered, makeComplianceWork } from "./wire/compliance.js";
import { reportDeliverable } from "./wire/report-meta.js";

const sellerId = makeIdentity("Seller", 0x2a);
const price = { amount: "1000000000", asset: "DEM" };

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function siteProber() {
  const TARGET = "https://acme.test/";
  const HTTP = "http://acme.test/";
  const HOST = "acme.test";
  const HEADERS = { "strict-transport-security": "max-age=63072000", "content-security-policy": "default-src 'self'", "x-content-type-options": "nosniff", "content-type": "text/html" };
  const s = (over: Partial<ProbeResult> = {}): ProbeResult => ({ url: TARGET, finalUrl: TARGET, status: 200, ttfbMs: 80, totalMs: 150, bodyBytes: 12345, redirectCount: 0, redirectChain: [TARGET], headers: { ...HEADERS }, fetchedAt: "2026-07-08T00:00:00.000Z", ...over });
  const tls: TlsInfo = { host: HOST, validTo: "2026-11-04T00:00:00.000Z", daysRemaining: 120, issuer: "CA", protocol: "TLSv1.3", checkedAt: "2026-07-08T00:00:00.000Z" };
  return { prober: new FakeProber({ [TARGET]: [s(), s(), s()], [HTTP]: [s({ url: HTTP, finalUrl: TARGET, redirectCount: 1, redirectChain: [HTTP, TARGET] })] }, { [HOST]: tls }), url: TARGET };
}

const TREASURY_POLICY = {
  policyId: "t-v1",
  accounts: [
    { id: "a", chain: "demos", address: "demos-a", label: "A", minBalance: 100, targetPct: 60 },
    { id: "b", chain: "base", address: "0xB", label: "B", minBalance: 50, targetPct: 40 },
  ],
  allowlist: [{ address: "demos-alice", chain: "demos", label: "Alice" }],
  payroll: [{ recipient: "demos-alice", chain: "demos", amount: 200, label: "Alice", period: "2026-07" }],
  perTxCap: 5000,
  perRunCap: 20000,
  feeBufferPerTx: 5,
};
const TREASURY_BALANCES = { a: 2000, b: 500 };

const EVAL_JOB = {
  rubric: { criteria: [{ id: "p", description: "json", kind: "mechanical" as const, weight: 1, test: { check: "json-parses" as const } }], acceptThreshold: 50 },
  deliverable: { content: JSON.stringify({ ok: true, title: "x" }) },
};

/** Deliver via a real SellerAdapter, then verify with the wire's observeDelivered. */
async function roundTrip(serviceId: string, work: WorkCallback, observeDelivered: DeliveryVerifyOptions["observeDelivered"], params: Record<string, unknown>) {
  const sub = new MemorySubstrate();
  const seller = new SellerAdapter(sellerId, sub, serviceId, work);
  const jobId = `${serviceId}-t`;
  const delivered = await seller.deliver(jobId, params);
  const verifier = new VerifierAdapter(sub);
  const dv = await verifier.verifyDelivery(jobId, { serviceId, sellerDid: sellerId.did, observeDelivered });
  return { dv, delivered, sub, jobId };
}

// ---------------------------------------------------------------------------
// Per-seller: work callback delivers + observeDelivered re-verifies offline
// ---------------------------------------------------------------------------

describe("Build D sellers — deliver + observeDelivered round-trip", () => {
  test("dep-upgrade: plan delivered, structurally re-verified", async () => {
    const { dv } = await roundTrip(DEPUP_SERVICE_ID, makeDepUpgradeWork(lodashFallbackRegistry()), depUpgradeObserveDelivered(), {
      packageJson: { name: "app", version: "1.0.0", dependencies: { lodash: "^4.17.20" } },
    });
    assert.equal(dv.ok, true, dv.reason);
  });

  test("treasury-ops: plan+approval delivered, planHash + token re-verified", async () => {
    const { dv } = await roundTrip(TREASURY_SERVICE_ID, makeTreasuryWork(), treasuryObserveDelivered(), {
      policy: TREASURY_POLICY, balances: TREASURY_BALANCES,
    });
    assert.equal(dv.ok, true, dv.reason);
  });

  test("evalbot: signed ruling delivered, verifyRuling re-verifies", async () => {
    const { dv } = await roundTrip(EVALBOT_SERVICE_ID, makeEvalBotWork(new EvalBot({ useLlm: false })), evalBotObserveDelivered(), EVAL_JOB);
    assert.equal(dv.ok, true, dv.reason);
  });

  test("site-auditor: audit delivered, verifyAudit re-verifies", async () => {
    const site = siteProber();
    const { dv } = await roundTrip(SITE_SERVICE_ID, makeSiteAuditorWork(site.prober), siteAuditorObserveDelivered(), { url: site.url, samples: 3 });
    assert.equal(dv.ok, true, dv.reason);
  });

  test("sec-audit: sealed report delivered, verifyReport re-verifies", async () => {
    const files = [{ path: "src/a.ts", content: "export const x = 1;\n" }];
    const { dv } = await roundTrip(SEC_AUDIT_SERVICE_ID, makeSecAuditWork(new MockDahrAttestor()), secAuditObserveDelivered(), { files });
    assert.equal(dv.ok, true, dv.reason);
  });

  test("compliance: screening delivered, verifyScreening re-verifies", async () => {
    const { dv } = await roundTrip(COMPLIANCE_SERVICE_ID, makeComplianceWork(fixtureSources()), complianceObserveDelivered(), { kind: "entity", name: "Acme Holdings" });
    assert.equal(dv.ok, true, dv.reason);
  });

  test("tampering the delivered meta fails observeDelivered", async () => {
    // A compliance report whose JSON no longer matches its reportHash is rejected.
    const observe = complianceObserveDelivered()!;
    const bad = await observe({
      kind: "dacs-x-delivery-attestation", serviceId: COMPLIANCE_SERVICE_ID, jobId: "j", resultHash: "x",
      deliveredAt: new Date().toISOString(), meta: { reportJson: "{\"verdict\":\"clear\"}", reportHash: "deadbeef" },
    });
    assert.equal(bad.ok, false);
  });
});

// ---------------------------------------------------------------------------
// EvalBot gate: needs-evaluator → accepted/rejected on the ruling
// ---------------------------------------------------------------------------

function stubOutcome(content: string): PurchaseOutcome {
  return {
    decision: { goal: { description: "d", requiredCapabilities: [] }, budget: 1, outcome: "no-award", candidates: [], negotiations: [] },
    jobId: "job-1", rail: "pay-dem", mode: "pay-dem-session", settlementRef: "settle", deliveryRef: "delivery",
    verified: true, deliverable: { content }, acceptance: { verdict: "needs-evaluator", reason: "no mechanical checks" },
    accepted: false, needsEvaluator: true, trail: ["x"],
  };
}

describe("EvalBot evaluator gate", () => {
  test("well-formed judgment deliverable flips needs-evaluator → accepted with a signed ruling", async () => {
    const outcome = stubOutcome(JSON.stringify({ subject: "s", findings: [{ id: "F1" }], evidence: [] }));
    const res = await resolveWithEvaluator(outcome, { serviceId: "dd-research" });
    assert.equal(res.rulingValid, true);
    assert.equal(res.ruling.verdict, "accept");
    assert.equal(res.finalVerdict, "accepted");
    assert.equal(res.accepted, true);
    assert.equal(res.needsEvaluator, false);
  });

  test("malformed deliverable is rejected by the gate", async () => {
    const outcome = stubOutcome("not json at all — truncated<<");
    const res = await resolveWithEvaluator(outcome, { serviceId: "site-audit" });
    assert.equal(res.ruling.verdict, "reject");
    assert.equal(res.finalVerdict, "rejected");
    assert.equal(res.accepted, false);
  });

  test("rubricForOutcome adds a service-specific structural criterion", () => {
    const r = rubricForOutcome({ serviceId: "compliance-screening" });
    assert.ok(r.criteria.some((c) => c.id === "well-formed"));
    const generic = rubricForOutcome({});
    assert.ok(!generic.criteria.some((c) => c.id === "well-formed"));
  });
});

// ---------------------------------------------------------------------------
// Rail-eligibility per scope (Build C policy, exercised for the new sellers)
// ---------------------------------------------------------------------------

describe("rail-eligibility per new seller scope", () => {
  test("all new sellers are parameterized ⇒ pay-dem session only", () => {
    const specs = [
      { scope: DEPUP_SCOPE, spec: depUpgradeListingSpec(price) },
      { scope: TREASURY_SCOPE, spec: treasuryListingSpec(price) },
      { scope: EVALBOT_SCOPE, spec: evalBotListingSpec(price) },
      { scope: SITE_SCOPE, spec: siteAuditorListingSpec(price) },
      { scope: SEC_AUDIT_SCOPE, spec: secAuditListingSpec(price) },
      { scope: COMPLIANCE_SCOPE, spec: complianceListingSpec(price) },
    ];
    for (const { scope, spec } of specs) {
      assert.equal(scope, "parameterized", `${spec.serviceId} should be parameterized`);
      assert.deepEqual(spec.supportedPaymentRails, ["pay-dem"]);
      assert.equal(executionModeFor("pay-dem", scope), "pay-dem-session");
    }
  });

  test("a parameterized seller can use a session-bound x402 resource", () => {
    assert.deepEqual(eligibleRails(["pay-dem", "pay-x402"], "parameterized"), ["pay-dem", "pay-x402"]);
    assert.deepEqual(eligibleRails(["pay-x402"], "parameterized"), ["pay-x402"]);
    assert.deepEqual(eligibleRails(["pay-x402"], "fixed"), ["pay-x402"]);
    assert.deepEqual(eligibleRails(["pay-dem", "pay-evm-erc8183"], "fixed"), ["pay-dem"]);
  });
});
