/**
 * Build A — shared seller layer + x402 rail tests. Fully offline: the Mock
 * facilitator only (no chain, no real facilitator, no network beyond localhost).
 *   npx tsx --test roster/dacs/dacs.test.ts
 */
import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import {
  ARTIFACT_SEPARATORS,
  sha256Hex,
  verifySignedArtifact,
} from "@kynesyslabs/dacs";
import type { SettleRequest } from "../../sdk/dist/agent/runSessionCore.js";
import { makeIdentity, resolveFromDid, verify, CciDirectory } from "../../src/identity.js";
import { MemorySubstrate } from "../../src/substrate/memory.js";
import { FakeAttestedFetch } from "../oracle-desk/attested-fetch.js";
import {
  SellerAdapter,
  deliverySeparator,
  type WorkCallback,
} from "./seller-adapter.js";
import { makeX402MockSettle } from "./buyer.js";
import { VerifierAdapter } from "./verifier.js";
import {
  MockFacilitator,
  startPaywall,
  type PaywallPhase,
  type RunningPaywall,
} from "./paywall.js";
import {
  makeOracleWork,
  oracleObserveDelivered,
  ORACLE_SERVICE_ID,
  type OracleDeliverable,
} from "./wire/oracle-desk.js";
import {
  DD_SERVICE_ID,
  ddObserveDelivered,
  makeDdWork,
} from "./wire/dd-researcher.js";
import type { DeliveryAttestation } from "./seller-adapter.js";

const sellerId = makeIdentity("Seller", 0x0a);
const buyerId = makeIdentity("Buyer", 0x0b);

/** Trivial work callback — no network. */
const trivialWork: WorkCallback = async (_jobId, params) => ({
  result: { echo: params, v: 42 },
  deliverableRef: "ref:trivial",
  meta: { note: "trivial" },
});

describe("SellerAdapter.publishListing", () => {
  test("listing is signed + anchored + readable", async () => {
    const sub = new MemorySubstrate();
    const seller = new SellerAdapter(sellerId, sub, "svc-a", trivialWork);
    const ref = await seller.publishListing({
      serviceId: "svc-a",
      name: "Service A",
      description: "does a thing",
      supportedPaymentRails: ["pay-x402"],
    });

    const raw = await sub.read(ref);
    assert.ok(raw, "listing anchored + readable");
    assert.equal((raw as { serviceId?: string }).serviceId, "svc-a");
    assert.deepEqual((raw as { supportedPaymentRails?: string[] }).supportedPaymentRails, ["pay-x402"]);

    const key = resolveFromDid(sellerId.did)!;
    const ok = await verifySignedArtifact(raw!, ARTIFACT_SEPARATORS.Listing, key, verify);
    assert.equal(ok, true, "listing signature verifies");
  });
});

describe("SellerAdapter.deliver", () => {
  test("anchors a signed DeliveryAttestation that verifySignedArtifact accepts; tampered rejects", async () => {
    const sub = new MemorySubstrate();
    const seller = new SellerAdapter(sellerId, sub, "svc-a", trivialWork);
    const jobId = "job-deliver";

    const d = await seller.deliver(jobId, { x: "1" });
    const addr = await sub.anchorAddress(`dacsx:delivery:${jobId}`);
    const raw = await sub.read(addr);
    assert.ok(raw, "delivery attestation anchored");
    assert.equal(d.attestationRef, addr);

    const key = resolveFromDid(sellerId.did)!;
    const sep = deliverySeparator("svc-a");
    assert.equal(await verifySignedArtifact(raw!, sep, key, verify), true, "clean attestation verifies");

    // Tamper: flip a signed field in storage — verification must fail.
    sub.store.set(addr, { ...raw!, resultHash: "0".repeat(64) });
    assert.equal(
      await verifySignedArtifact((await sub.read(addr))!, sep, key, verify),
      false,
      "tampered attestation rejected",
    );
  });
});

describe("DACS-X separator is per-serviceId", () => {
  test("distinct services get distinct signing domains", () => {
    const a = deliverySeparator("svc-a");
    const b = deliverySeparator("svc-b");
    assert.notEqual(a, b);
    assert.equal(a, deliverySeparator("svc-a"), "deterministic per serviceId");
    assert.match(String(a), /svc-a/);
  });
});

describe("paywall — 402 + verify→work→settle order + cancel-on-failure", () => {
  test("emits 402 without payment (FeeSchedule advertised)", async () => {
    const pw = await startPaywall({
      route: "/data",
      accepts: { network: "eip155:84532", payTo: sellerId.evm, price: { amount: "50000", asset: "USDC" } },
      facilitator: new MockFacilitator(),
      deliver: async () => ({ result: "unreached" }),
    });
    try {
      const res = await fetch(`${pw.url}?jobId=no-pay`);
      assert.equal(res.status, 402);
      const body = (await res.json()) as { accepts: Array<{ price: { amount: string; asset: string } }> };
      assert.equal(body.accepts[0]?.price.amount, "50000");
      assert.equal(body.accepts[0]?.price.asset, "USDC");
    } finally {
      await pw.close();
    }
  });

  test("verified payment runs work BEFORE settle, then 200", async () => {
    const facilitator = new MockFacilitator();
    const phases: PaywallPhase[] = [];
    const workRan: string[] = [];
    const pw = await startPaywall({
      route: "/data",
      accepts: { network: "eip155:84532", payTo: sellerId.evm, price: { amount: "50000", asset: "USDC" } },
      facilitator,
      deliver: async (jobId) => {
        workRan.push(jobId);
        // At the moment work runs, settle must NOT have happened yet.
        assert.equal(facilitator.settled.length, 0, "settle must not run before work");
        return { result: "ok", attestationRef: "ref" };
      },
      onPhase: (p) => phases.push(p),
    });
    try {
      const res = await fetch(`${pw.url}?jobId=job-ok`, { headers: { "x-payment": "mock:job-ok" } });
      assert.equal(res.status, 200);
      assert.equal(res.headers.get("x-payment-response"), "mock-x402-job-ok");
      const body = (await res.json()) as { result: string; settlement: { txHash: string } };
      assert.equal(body.result, "ok");
      assert.equal(body.settlement.txHash, "mock-x402-job-ok");

      assert.deepEqual(workRan, ["job-ok"]);
      assert.deepEqual(facilitator.verified, ["job-ok"]);
      assert.deepEqual(facilitator.settled, ["job-ok"]);
      assert.ok(phases.indexOf("work") < phases.indexOf("settle"), "work before settle");
      assert.deepEqual(phases, ["verify", "work", "settle", "respond"]);
    } finally {
      await pw.close();
    }
  });

  test("work failure cancels the payment and skips settle", async () => {
    const facilitator = new MockFacilitator();
    const pw = await startPaywall({
      route: "/data",
      accepts: { network: "eip155:84532", payTo: sellerId.evm, price: { amount: "50000", asset: "USDC" } },
      facilitator,
      deliver: async () => {
        throw new Error("boom");
      },
    });
    try {
      const res = await fetch(`${pw.url}?jobId=job-fail`, { headers: { "x-payment": "mock:job-fail" } });
      assert.equal(res.status, 502);
      assert.deepEqual(facilitator.verified, ["job-fail"], "payment was verified");
      assert.deepEqual(facilitator.settled, [], "settle skipped — no funds moved");
      assert.deepEqual(facilitator.cancelled, ["job-fail"], "verified payment cancelled");
    } finally {
      await pw.close();
    }
  });
});

describe("buyer x402 settle seam", () => {
  const req: SettleRequest = {
    rail: "pay-x402",
    amount: "50000",
    asset: "USDC",
    payee: sellerId.did,
    jobId: "job-settle",
  };

  test("ok only when delivered (attestation anchored)", async () => {
    const sub = new MemorySubstrate();
    const seller = new SellerAdapter(sellerId, sub, "svc-a", trivialWork);
    const pw = await startPaywall({
      route: "/data",
      accepts: { network: "eip155:84532", payTo: sellerId.evm, price: { amount: "50000", asset: "USDC" } },
      facilitator: new MockFacilitator(),
      deliver: async (jobId, params) => {
        const d = await seller.deliver(jobId, params);
        return { result: d.result, attestationRef: d.attestationRef };
      },
    });
    try {
      const settle = makeX402MockSettle({
        paywallUrl: pw.url,
        sub,
        payerEvm: buyerId.evm,
        payeeEvm: sellerId.evm,
      });
      const r = await settle(req);
      assert.equal(r.ok, true, "delivered → ok");
      assert.equal(r.txHash, "mock-x402-job-settle");
      assert.equal(r.payer, buyerId.evm);
      assert.equal(r.payee, sellerId.evm);
    } finally {
      await pw.close();
    }
  });

  test("not ok when work fails (nothing delivered)", async () => {
    const sub = new MemorySubstrate();
    const pw = await startPaywall({
      route: "/data",
      accepts: { network: "eip155:84532", payTo: sellerId.evm, price: { amount: "50000", asset: "USDC" } },
      facilitator: new MockFacilitator(),
      deliver: async () => {
        throw new Error("boom");
      },
    });
    try {
      const settle = makeX402MockSettle({ paywallUrl: pw.url, sub, payerEvm: buyerId.evm, payeeEvm: sellerId.evm });
      const r = await settle(req);
      assert.equal(r.ok, false, "no delivery → not ok");
    } finally {
      await pw.close();
    }
  });
});

describe("verifier — delivery + observeDelivered hook", () => {
  let sub: MemorySubstrate;
  let seller: SellerAdapter;
  const jobId = "job-oracle";

  before(async () => {
    sub = new MemorySubstrate();
    // Oracle work over a FakeAttestedFetch — fully offline, canned bodies.
    // A FLOAT price (67890.12): pre-fix this threw "non-integer JSON number not
    // allowed" inside deliver() (the JCS-float trap), so only the integer
    // chain-height product could be delivered. It now signs + anchors + verifies.
    const fetchPort = new FakeAttestedFetch([
      ["api.coingecko.com", { status: 200, body: JSON.stringify({ bitcoin: { usd: 67890.12 } }) }],
    ]);
    seller = new SellerAdapter(sellerId, sub, ORACLE_SERVICE_ID, makeOracleWork(fetchPort));
    await seller.deliver(jobId, { product: "crypto-price", id: "bitcoin" });
  });

  test("observeDelivered happy path (embedded oracle attestation re-verifies offline)", async () => {
    const verifier = new VerifierAdapter(sub);
    const dv = await verifier.verifyDelivery(jobId, {
      serviceId: ORACLE_SERVICE_ID,
      sellerDid: sellerId.did,
      observeDelivered: oracleObserveDelivered(),
    });
    assert.equal(dv.ok, true, dv.reason ?? "");
    assert.equal(dv.attestation?.serviceId, ORACLE_SERVICE_ID);
  });

  test("observeDelivered sad path fails the verification", async () => {
    const verifier = new VerifierAdapter(sub);
    const dv = await verifier.verifyDelivery(jobId, {
      serviceId: ORACLE_SERVICE_ID,
      sellerDid: sellerId.did,
      observeDelivered: async () => ({ ok: false, reason: "state not observed" }),
    });
    assert.equal(dv.ok, false);
    assert.match(dv.reason ?? "", /state not observed/);
  });

  test("signature-only verification passes without a hook; wrong serviceId rejected", async () => {
    const verifier = new VerifierAdapter(sub);
    const ok = await verifier.verifyDelivery(jobId, { serviceId: ORACLE_SERVICE_ID, sellerDid: sellerId.did });
    assert.equal(ok.ok, true);
    const wrong = await verifier.verifyDelivery(jobId, { serviceId: "other-svc", sellerDid: sellerId.did });
    assert.equal(wrong.ok, false, "separator/serviceId mismatch rejected");
  });

  test("CCI binding requirement is enforced when requested", async () => {
    const cci = new CciDirectory();
    cci.bind(sellerId.did, "oracle-desk");
    const verifier = new VerifierAdapter(sub, cci);
    const good = await verifier.verifyDelivery(jobId, {
      serviceId: ORACLE_SERVICE_ID,
      sellerDid: sellerId.did,
      requireCciBinding: "oracle-desk",
    });
    assert.equal(good.ok, true, good.reason ?? "");
    const bad = await verifier.verifyDelivery(jobId, {
      serviceId: ORACLE_SERVICE_ID,
      sellerDid: sellerId.did,
      requireCciBinding: "someone-else",
    });
    assert.equal(bad.ok, false);
  });
});

describe("oracle wire — attest-any + JCS-float delivery + no fail-open", () => {
  // crypto-price is a FLOAT product; the JCS canonical (signed) scope rejects
  // non-integer numbers, so the raw value used to throw at sign time. The value
  // now rides JCS-safely (reportMeta), and observeDelivered re-derives it from
  // the attested body — a tampered value or attestation is rejected.
  const FLOAT_PRICE = 67890.12;
  const cryptoFetch = new FakeAttestedFetch([
    ["api.coingecko.com", { status: 200, body: JSON.stringify({ bitcoin: { usd: FLOAT_PRICE } }) }],
  ]);
  // A generic long-tail JSON endpoint (attest-any): { data: { score: 4.2 } }.
  const genericFetch = new FakeAttestedFetch([
    ["example.test", { status: 200, body: JSON.stringify({ data: { score: 4.2, label: "ok" } }) }],
  ]);

  test("a FLOAT preset (crypto-price) signs, anchors, and re-verifies offline", async () => {
    const sub = new MemorySubstrate();
    const seller = new SellerAdapter(sellerId, sub, ORACLE_SERVICE_ID, makeOracleWork(cryptoFetch));
    // Pre-fix this threw "non-integer JSON number not allowed" inside deliver().
    const d = await seller.deliver("job-oracle-float", { product: "crypto-price", id: "bitcoin" });
    // The full value survives in signed meta (not just the display string).
    const meta = d.attestation.meta as { reportJson: string };
    const deliverable = JSON.parse(meta.reportJson) as OracleDeliverable;
    assert.equal(deliverable.value, FLOAT_PRICE);

    const verifier = new VerifierAdapter(sub);
    const dv = await verifier.verifyDelivery("job-oracle-float", {
      serviceId: ORACLE_SERVICE_ID,
      sellerDid: sellerId.did,
      observeDelivered: oracleObserveDelivered(),
    });
    assert.equal(dv.ok, true, dv.reason ?? "");
  });

  test("generic attest-any: { url, extract } over a long-tail JSON API delivers + verifies", async () => {
    const sub = new MemorySubstrate();
    const seller = new SellerAdapter(sellerId, sub, ORACLE_SERVICE_ID, makeOracleWork(genericFetch));
    const jobId = "job-oracle-generic";
    const d = await seller.deliver(jobId, { url: "https://example.test/thing", extract: "data.score" });
    const deliverable = JSON.parse((d.attestation.meta as { reportJson: string }).reportJson) as OracleDeliverable;
    assert.equal(deliverable.value, 4.2);
    assert.equal(deliverable.extract, "data.score");
    assert.equal(deliverable.preset, undefined);

    const verifier = new VerifierAdapter(sub);
    const dv = await verifier.verifyDelivery(jobId, {
      serviceId: ORACLE_SERVICE_ID,
      sellerDid: sellerId.did,
      observeDelivered: oracleObserveDelivered(),
    });
    assert.equal(dv.ok, true, dv.reason ?? "");
  });

  test("observeDelivered rejects a tampered value, tampered attestation, and never fails open", async () => {
    const work = makeOracleWork(cryptoFetch);
    const wr = await work("j", { product: "crypto-price", id: "bitcoin" });
    const meta = wr.meta as { reportJson: string; reportHash: string };
    const obs = oracleObserveDelivered()!;
    const att = (m: Record<string, unknown>): DeliveryAttestation => ({
      kind: "dacs-x-delivery-attestation",
      serviceId: ORACLE_SERVICE_ID,
      jobId: "j",
      resultHash: "0".repeat(64),
      meta: m,
      deliveredAt: new Date().toISOString(),
    });

    // Sound delivery → ok.
    assert.equal((await obs(att({ ...meta }))).ok, true);

    // Fail-open guard: reportJson present but NO reportHash → rejected.
    const noHash = await obs(att({ reportJson: meta.reportJson }));
    assert.equal(noHash.ok, false);
    assert.match(noHash.reason ?? "", /reportHash/);

    // Tampered value (lie about the price) with a re-computed matching hash:
    // binding passes, but the value no longer matches the attested body.
    const lied = JSON.parse(meta.reportJson) as OracleDeliverable;
    lied.value = 999999.99;
    const liedJson = JSON.stringify(lied);
    const liedOut = await obs(att({ reportJson: liedJson, reportHash: sha256Hex(liedJson) }));
    assert.equal(liedOut.ok, false);
    assert.match(liedOut.reason ?? "", /does not match the attested body/);

    // Tampered attestation body (forge the upstream bytes): bodyHash no longer
    // matches → attestation verification fails.
    const forged = JSON.parse(meta.reportJson) as OracleDeliverable;
    forged.attestation = { ...forged.attestation, body: JSON.stringify({ bitcoin: { usd: 1 } }) };
    const forgedJson = JSON.stringify(forged);
    const forgedOut = await obs(att({ reportJson: forgedJson, reportHash: sha256Hex(forgedJson) }));
    assert.equal(forgedOut.ok, false);
    assert.match(forgedOut.reason ?? "", /attestation invalid|bodyHash/);
  });
});

describe("dd-researcher wire — float-safe delivery + no fail-open on the report binding", () => {
  // A crypto-token report is full of non-integer JSON numbers (prices, ATH %,
  // volume/mcap ratios). The DACS canonical (JCS) signed scope REJECTS those,
  // so carrying the report as a raw object in signed meta threw at sign time —
  // token deliveries could not be anchored. The wire now carries it as a
  // JCS-safe JSON string (reportMeta). This exercises that end to end.
  const CG_TOKEN_FLOATS = JSON.stringify({
    id: "bitcoin",
    symbol: "btc",
    name: "Bitcoin",
    market_cap_rank: 1,
    market_data: {
      current_price: { usd: 67890.55 },
      market_cap: { usd: 1.3e12 },
      total_volume: { usd: 3.15e10 },
      fully_diluted_valuation: { usd: 1.36e12 },
      ath: { usd: 126000.42 },
      ath_change_percentage: { usd: -20.63 },
    },
    community_data: { twitter_followers: 6_500_000, telegram_channel_user_count: null },
    developer_data: { stars: 80_000, commit_count_4_weeks: 300, pull_request_contributors: 900 },
  });

  const fetchPort = new FakeAttestedFetch([["api.coingecko.com", { status: 200, body: CG_TOKEN_FLOATS }]]);
  const jobId = "job-dd-token";

  test("a crypto-token report (floats) signs, anchors, and re-verifies offline", async () => {
    const sub = new MemorySubstrate();
    const seller = new SellerAdapter(sellerId, sub, DD_SERVICE_ID, makeDdWork(fetchPort, { useLlm: false }));
    // Pre-fix this threw "non-integer JSON number not allowed" inside deliver().
    await seller.deliver(jobId, { kind: "crypto-token", subject: "bitcoin" });

    const verifier = new VerifierAdapter(sub);
    const dv = await verifier.verifyDelivery(jobId, {
      serviceId: DD_SERVICE_ID,
      sellerDid: sellerId.did,
      observeDelivered: ddObserveDelivered(),
    });
    assert.equal(dv.ok, true, dv.reason ?? "");
  });

  test("observeDelivered rejects a forged citation and never fails open on a missing/stale hash", async () => {
    const work = makeDdWork(fetchPort, { useLlm: false });
    const wr = await work(jobId, { kind: "crypto-token", subject: "bitcoin" });
    const meta = wr.meta as { reportJson: string; reportHash: string };
    const obs = ddObserveDelivered()!;
    const att = (m: Record<string, unknown>): DeliveryAttestation => ({
      kind: "dacs-x-delivery-attestation",
      serviceId: DD_SERVICE_ID,
      jobId,
      resultHash: "0".repeat(64),
      meta: m,
      deliveredAt: new Date().toISOString(),
    });

    // Sound report → ok.
    assert.equal((await obs(att({ ...meta }))).ok, true);

    // Fail-open guard: reportJson present but NO reportHash → rejected, not accepted.
    const noHash = await obs(att({ reportJson: meta.reportJson }));
    assert.equal(noHash.ok, false);
    assert.match(noHash.reason ?? "", /reportHash/);

    // Forged citation with a re-computed matching hash → binding passes, but
    // verifyReport rejects the dangling citation (no fail-open on the substance).
    const forged = JSON.parse(meta.reportJson) as { findings: Array<{ citations: string[] }> };
    forged.findings[0]!.citations = ["E404"];
    const forgedJson = JSON.stringify(forged);
    const forgedOk = await obs(att({ reportJson: forgedJson, reportHash: sha256Hex(forgedJson) }));
    assert.equal(forgedOk.ok, false);
    assert.match(forgedOk.reason ?? "", /citation|verification failed/);

    // Tampered body kept under the ORIGINAL hash → binding mismatch → rejected.
    const staleHash = await obs(att({ reportJson: forgedJson, reportHash: meta.reportHash }));
    assert.equal(staleHash.ok, false);
    assert.match(staleHash.reason ?? "", /reportHash/);
  });
});
