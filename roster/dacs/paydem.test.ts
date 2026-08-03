/**
 * Build B — pay-dem rail + both patterns. Fully offline: MockDemLedger only
 * (no chain, no keys, no network — oracle/dd work runs over FakeAttestedFetch
 * with canned bodies).
 *   npx tsx --test roster/dacs/paydem.test.ts
 */
import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { resolveFromDid, verify } from "../../src/identity.js";
import { verifySignedArtifact } from "@kynesyslabs/dacs";
import type { SessionTerms } from "@kynesyslabs/dacs";
import type { SettleRequest } from "../../sdk/dist/agent/runSessionCore.js";
import { makeIdentity } from "../../src/identity.js";
import { MemorySubstrate } from "../../src/substrate/memory.js";
import { FakeAttestedFetch } from "../oracle-desk/attested-fetch.js";
import {
  SellerAdapter,
  deliverySeparator,
  type WorkCallback,
} from "./seller-adapter.js";
import { BuyerAdapter } from "./buyer.js";
import { VerifierAdapter } from "./verifier.js";
import {
  MockDemLedger,
  demMemoFor,
  demosAddrFromDid,
  didFromDemosAddr,
  payDemRail,
} from "./rails.js";
import { MockLedgerWatch, SellerWatcher } from "./watcher.js";
import {
  DD_DELIVERY_PHASE,
  DD_SERVICE_ID,
  ddListingSpec,
  ddObserveDelivered,
  makeDdWork,
} from "./wire/dd-researcher.js";
import { ORACLE_SERVICE_ID, makeOracleWork, oracleObserveDelivered } from "./wire/oracle-desk.js";

const sellerId = makeIdentity("Seller", 0x0a);
const buyerId = makeIdentity("Buyer", 0x0b);
const oracleId = makeIdentity("Oracle", 0x0c);

const PRICE = { amount: "1000000000", asset: "DEM" };
const PRICE_UNITS = BigInt(PRICE.amount);

const trivialWork: WorkCallback = async (_jobId, params) => ({
  result: { echo: params, v: 42 },
  deliverableRef: "ref:trivial",
  meta: { note: "trivial" },
});

/** Canned CoinGecko coin doc — the dd-researcher's crypto-token source. */
const coingeckoCoin = new FakeAttestedFetch([
  [
    "api.coingecko.com",
    {
      status: 200,
      body: JSON.stringify({
        id: "bitcoin",
        symbol: "btc",
        name: "Bitcoin",
        market_cap_rank: 1,
        market_data: {
          current_price: { usd: 68000 },
          market_cap: { usd: 1_300_000_000_000 },
          total_volume: { usd: 20_000_000_000 },
          ath: { usd: 73000 },
          ath_change_percentage: { usd: -7 },
        },
        community_data: {},
        developer_data: { stars: 70000, commit_count_4_weeks: 120 },
      }),
    },
  ],
]);

/** Canned CoinGecko simple-price — the oracle desk's crypto-price product. */
function oracleFetch(): FakeAttestedFetch {
  return new FakeAttestedFetch([["api.coingecko.com", { status: 200, body: JSON.stringify({ bitcoin: { usd: 68000 } }) }]]);
}

// ---------------------------------------------------------------------------
// Address / memo helpers
// ---------------------------------------------------------------------------

describe("pay-dem addressing + memo binding", () => {
  test("DID ↔ Demos address round-trips; memo binds the jobId", () => {
    const addr = demosAddrFromDid(buyerId.did)!;
    assert.match(addr, /^0x[0-9a-f]{64}$/);
    assert.equal(didFromDemosAddr(addr), buyerId.did);
    assert.equal(demMemoFor("job-1"), "DACS:job-1");
  });
});

// ---------------------------------------------------------------------------
// payDemRail (Pattern 2 push seam)
// ---------------------------------------------------------------------------

describe("payDemRail — records a memo-bound transfer + couples to delivery", () => {
  test("settle transfers DEM with DACS memo, returns mock-dem-<jobId>, ok on delivery", async () => {
    const sub = new MemorySubstrate();
    const ledger = new MockDemLedger();
    const seller = new SellerAdapter(sellerId, sub, "svc-a", trivialWork);
    const jobId = "rail-job";
    const seam = payDemRail(seller, { ledger, sub, payer: demosAddrFromDid(buyerId.did)!, deliverParams: { x: "1" } });

    const req: SettleRequest = { rail: "pay-dem", amount: PRICE.amount, asset: "DEM", payee: sellerId.did, jobId };
    const r = await seam(req);

    assert.equal(r.ok, true, "delivered → ok");
    assert.equal(r.txHash, `mock-dem-${jobId}`);
    assert.equal(r.chainId, "demos");
    assert.equal(r.payer, demosAddrFromDid(buyerId.did));
    assert.equal(r.payee, demosAddrFromDid(sellerId.did));

    assert.equal(ledger.transfers.length, 1);
    const t = ledger.transfers[0]!;
    assert.equal(t.memo, demMemoFor(jobId), "memo binds the jobId");
    assert.equal(t.amount, PRICE_UNITS);
    assert.equal(t.to, demosAddrFromDid(sellerId.did));

    // The seller's delivery attestation must be anchored (the coupling).
    const anchored = await sub.read(await sub.anchorAddress(`dacsx:delivery:${jobId}`));
    assert.ok(anchored, "delivery attestation anchored");
  });
});

// ---------------------------------------------------------------------------
// Pattern 2 — full session on the pay-dem rail (dd-researcher)
// ---------------------------------------------------------------------------

describe("Pattern 2 — dd-researcher session settles + delivers + verifies", () => {
  test("session completes; bundle + delivery verify from anchors; report re-verified offline", async () => {
    const sub = new MemorySubstrate();
    const ledger = new MockDemLedger();
    const seller = new SellerAdapter(sellerId, sub, DD_SERVICE_ID, makeDdWork(coingeckoCoin));
    const listingRef = await seller.publishListing(ddListingSpec(PRICE));

    const buyer = new BuyerAdapter(buyerId, sub);
    const terms: SessionTerms = {
      price: { amount: PRICE.amount, asset: "DEM", decimals: 9, rail: "pay-dem" },
      deliveryPhase: DD_DELIVERY_PHASE,
      deliveryFormat: "application/json",
    };
    const jobId = "dd-session";
    const params = { kind: "crypto-token", subject: "bitcoin" };
    const result = await buyer.buy(listingRef, terms, {
      jobId,
      settleFn: payDemRail(seller, { ledger, sub, payer: buyer.demosAddr, deliverParams: params }),
    });

    assert.equal(result.outcome, "completed");
    // The DEM transfer is memo-bound to the job.
    assert.equal(ledger.transfers.length, 1);
    assert.equal(ledger.transfers[0]!.memo, demMemoFor(jobId));

    const verifier = new VerifierAdapter(sub);
    const bundleV = await verifier.verify(result.bundleRef);
    assert.equal(bundleV.ok, true, "bundle verifies");

    const dv = await verifier.verifyDelivery(jobId, {
      serviceId: DD_SERVICE_ID,
      sellerDid: sellerId.did,
      observeDelivered: ddObserveDelivered(),
    });
    assert.equal(dv.ok, true, dv.reason ?? "");
    assert.equal(dv.attestation?.serviceId, DD_SERVICE_ID);
  });
});

// ---------------------------------------------------------------------------
// Pattern 1 — memo-watcher (oracle desk)
// ---------------------------------------------------------------------------

interface WatchWorld {
  sub: MemorySubstrate;
  ledger: MockDemLedger;
  buyer: BuyerAdapter;
  seller: SellerAdapter;
  sellerAddr: string;
  watcher: SellerWatcher;
}

function makeWatchWorld(): WatchWorld {
  const sub = new MemorySubstrate();
  const ledger = new MockDemLedger();
  const buyer = new BuyerAdapter(buyerId, sub);
  const seller = new SellerAdapter(oracleId, sub, ORACLE_SERVICE_ID, makeOracleWork(oracleFetch()));
  const sellerAddr = demosAddrFromDid(oracleId.did)!;
  const watcher = new SellerWatcher(seller, sub, new MockLedgerWatch(ledger), { sellerAddr, listingPrice: PRICE_UNITS });
  watcher.run();
  return { sub, ledger, buyer, seller, sellerAddr, watcher };
}

const oracleTerms: SessionTerms = {
  price: { amount: PRICE.amount, asset: "DEM", decimals: 9, rail: "pay-dem" },
  deliveryPhase: "deliver-crypto-price",
  deliveryFormat: "application/json",
};

async function openAgreement(w: WatchWorld, jobId: string, params: Record<string, unknown>): Promise<void> {
  await w.buyer.openDemAgreement({ jobId, sellerDid: oracleId.did, listingRef: "listing:oracle", terms: oracleTerms, params });
}

describe("Pattern 1 — watcher turns a memo-tagged transfer into a delivery", () => {
  test("fires on a matching memo: reads params off the agreement, delivers, anchors", async () => {
    const w = makeWatchWorld();
    const jobId = "oracle-1";
    await openAgreement(w, jobId, { product: "crypto-price", id: "bitcoin" });
    await w.buyer.payDemBare(w.ledger, { jobId, sellerDid: oracleId.did, amount: PRICE_UNITS });

    const delivered = w.watcher.decisions.filter((d) => d.action === "delivered");
    assert.equal(delivered.length, 1, "exactly one delivery");
    assert.equal(delivered[0]!.action === "delivered" && delivered[0].jobId, jobId);

    const verifier = new VerifierAdapter(w.sub);
    const dv = await verifier.verifyDelivery(jobId, {
      serviceId: ORACLE_SERVICE_ID,
      sellerDid: oracleId.did,
      observeDelivered: oracleObserveDelivered(),
    });
    assert.equal(dv.ok, true, dv.reason ?? "");
  });

  test("ignores a non-DACS memo (parked, not delivered)", async () => {
    const w = makeWatchWorld();
    await w.ledger.transfer({ from: demosAddrFromDid(buyerId.did)!, to: w.sellerAddr, amount: PRICE_UNITS, memo: "gm ser" });
    assert.equal(w.watcher.decisions.length, 1);
    const d = w.watcher.decisions[0]!;
    assert.equal(d.action, "parked");
    assert.match(d.action === "parked" ? d.reason : "", /not DACS-tagged/);
    assert.equal(w.watcher.decisions.some((x) => x.action === "delivered"), false);
  });

  test("idempotent on replay: a duplicate memo transfer is skipped", async () => {
    const w = makeWatchWorld();
    const jobId = "oracle-replay";
    await openAgreement(w, jobId, { product: "crypto-price", id: "bitcoin" });
    await w.buyer.payDemBare(w.ledger, { jobId, sellerDid: oracleId.did, amount: PRICE_UNITS });
    // Replay the exact same memo-bound transfer.
    await w.ledger.transfer({ from: demosAddrFromDid(buyerId.did)!, to: w.sellerAddr, amount: PRICE_UNITS, memo: demMemoFor(jobId) });

    assert.equal(w.watcher.decisions.filter((d) => d.action === "delivered").length, 1, "delivered once");
    assert.equal(w.watcher.decisions.filter((d) => d.action === "skipped-replay").length, 1, "replay skipped");
  });

  test("parks underpayment (with reason), delivers nothing", async () => {
    const w = makeWatchWorld();
    const jobId = "oracle-underpay";
    await openAgreement(w, jobId, { product: "crypto-price", id: "bitcoin" });
    await w.ledger.transfer({ from: demosAddrFromDid(buyerId.did)!, to: w.sellerAddr, amount: PRICE_UNITS - 1n, memo: demMemoFor(jobId) });

    const parked = w.watcher.decisions.find((d) => d.action === "parked");
    assert.ok(parked, "a park decision exists");
    assert.match(parked!.action === "parked" ? parked!.reason : "", /underpayment/);
    assert.equal(w.watcher.decisions.some((d) => d.action === "delivered"), false);
  });

  test("parks a memo with no resolvable agreement (with reason)", async () => {
    const w = makeWatchWorld();
    const jobId = "oracle-noagreement";
    // No openAgreement — the memo points at a job that was never anchored.
    await w.ledger.transfer({ from: demosAddrFromDid(buyerId.did)!, to: w.sellerAddr, amount: PRICE_UNITS, memo: demMemoFor(jobId) });

    const parked = w.watcher.decisions.find((d) => d.action === "parked");
    assert.ok(parked);
    assert.match(parked!.action === "parked" ? parked!.reason : "", /no resolvable agreement/);
    assert.equal(w.watcher.decisions.some((d) => d.action === "delivered"), false);
  });

  test("exact-price payment is accepted (amount === listing price)", async () => {
    const w = makeWatchWorld();
    const jobId = "oracle-exact";
    await openAgreement(w, jobId, { product: "crypto-price", id: "bitcoin" });
    await w.buyer.payDemBare(w.ledger, { jobId, sellerDid: oracleId.did, amount: PRICE_UNITS });
    assert.equal(w.watcher.decisions.some((d) => d.action === "delivered" && d.jobId === jobId), true);
  });

  test("delivery attestation verifies; a tampered anchor is rejected", async () => {
    const w = makeWatchWorld();
    const jobId = "oracle-tamper";
    await openAgreement(w, jobId, { product: "crypto-price", id: "bitcoin" });
    await w.buyer.payDemBare(w.ledger, { jobId, sellerDid: oracleId.did, amount: PRICE_UNITS });

    const addr = await w.sub.anchorAddress(`dacsx:delivery:${jobId}`);
    const raw = await w.sub.read(addr);
    assert.ok(raw);
    const key = resolveFromDid(oracleId.did)!;
    const sep = deliverySeparator(ORACLE_SERVICE_ID);
    assert.equal(await verifySignedArtifact(raw!, sep, key, verify), true, "clean attestation verifies");

    w.sub.store.set(addr, { ...raw!, resultHash: "0".repeat(64) });
    const verifier = new VerifierAdapter(w.sub);
    const dv = await verifier.verifyDelivery(jobId, { serviceId: ORACLE_SERVICE_ID, sellerDid: oracleId.did });
    assert.equal(dv.ok, false, "tampered attestation rejected");
  });
});
