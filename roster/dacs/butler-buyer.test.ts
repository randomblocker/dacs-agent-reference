/**
 * Build C — Procurement Butler as a real DACS buyer. Fully offline: the mock
 * facilitator / MockDemLedger only; oracle + dd work runs over FakeAttestedFetch
 * with canned bodies. No network beyond localhost (x402 paywall).
 *   npx tsx --test roster/dacs/butler-buyer.test.ts
 */
import { after, describe, test } from "node:test";
import assert from "node:assert/strict";
import type { Listing as DacsListing } from "@kynesyslabs/dacs";
import { makeIdentity } from "../../src/identity.js";
import { MemorySubstrate } from "../../src/substrate/memory.js";
import { FakeAttestedFetch } from "../oracle-desk/attested-fetch.js";
import type { ProcurementGoal } from "../procurement-butler/types.js";
import { SellerAdapter } from "./seller-adapter.js";
import { BuyerAdapter } from "./buyer.js";
import { VerifierAdapter } from "./verifier.js";
import { MockDemLedger, demosAddrFromDid } from "./rails.js";
import { MockLedgerWatch, SellerWatcher } from "./watcher.js";
import { MockFacilitator, startPaywall, type RunningPaywall } from "./paywall.js";
import {
  ORACLE_SERVICE_ID,
  makeOracleWork,
  oracleListingSpec,
  oracleObserveDelivered,
} from "./wire/oracle-desk.js";
import {
  DD_DELIVERY_PHASE,
  DD_SERVICE_ID,
  ddListingSpec,
  ddObserveDelivered,
  makeDdWork,
} from "./wire/dd-researcher.js";
import {
  DacsButlerBuyer,
  eligibleRails,
  executionModeFor,
  toButlerListing,
  type DacsOffer,
  type SellerRuntime,
} from "./wire/butler.js";

const buyerId = makeIdentity("Buyer", 0x0b);
const oracleId = makeIdentity("Oracle", 0x0a);
const ddId = makeIdentity("DD", 0x0c);

const USDC = { amount: "50000", asset: "USDC", decimals: 6 };
const DEM = { amount: "1000000000", asset: "DEM", decimals: 9 };
const DEM_UNITS = BigInt(DEM.amount);

/** Canned CoinGecko simple-price — the oracle desk crypto-price product. */
function oracleFetch(): FakeAttestedFetch {
  return new FakeAttestedFetch([
    ["api.coingecko.com", { status: 200, body: JSON.stringify({ bitcoin: { usd: 68000 } }) }],
  ]);
}

/** Canned CoinGecko coin doc — the dd-researcher crypto-token source. */
function ddFetch(): FakeAttestedFetch {
  return new FakeAttestedFetch([
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
}

const ORACLE_ACCEPTANCE = {
  checks: [
    { kind: "content-includes" as const, needle: "oracleDigest" },
    { kind: "min-length" as const, minChars: 20 },
  ],
};

// ===========================================================================
// 1. DACS Listing → Butler Listing mapping
// ===========================================================================

describe("DACS-Listing → Butler-Listing mapping", () => {
  const listing: DacsListing = {
    agentId: oracleId.did,
    serviceId: ORACLE_SERVICE_ID,
    name: "Oracle Desk",
    description: "attested data",
    claimRequirements: [],
    supportedNegotiation: ["negotiate-fixed-price"],
    supportedPaymentRails: ["pay-x402", "pay-dem"],
    supportedDelivery: ["deliver-crypto-price"],
  };

  test("maps id/provider/capabilities/fees/rails/negotiable/quality/acceptance", () => {
    const offer: DacsOffer = {
      ref: "stor:listing-1",
      listing,
      scope: "fixed",
      fee: { kind: "fixed", price: 0.05 },
      acceptance: ORACLE_ACCEPTANCE,
      quality: { rating: 4.8, completedJobs: 100, disputeRate: 0.0 },
    };
    const bl = toButlerListing(offer);
    assert.equal(bl.id, "stor:listing-1", "id ← anchored ref (unique per listing)");
    assert.equal(bl.provider, "Oracle Desk");
    assert.deepEqual(bl.capabilities, ["oracle-data", "deliver-crypto-price", "pay-x402", "pay-dem"]);
    assert.deepEqual(bl.fees, { kind: "fixed", price: 0.05 });
    assert.deepEqual(bl.rails, ["pay-x402", "pay-dem"], "fixed scope keeps both advertised rails");
    assert.equal(bl.negotiable, true, "negotiate-fixed-price ⇒ negotiable");
    assert.equal(bl.quality.rating, 4.8);
    assert.deepEqual(bl.acceptance, ORACLE_ACCEPTANCE);
  });

  test("absent acceptance stays undefined (routes to needs-evaluator)", () => {
    const bl = toButlerListing({ ref: "r", listing, scope: "fixed", fee: { kind: "fixed", price: 1 } });
    assert.equal(bl.acceptance, undefined);
    assert.deepEqual(bl.quality, { rating: 4, completedJobs: 25, disputeRate: 0.02 }, "neutral default");
  });

  test("negotiable override wins over the advertised negotiation", () => {
    const bl = toButlerListing({ ref: "r", listing, scope: "fixed", fee: { kind: "fixed", price: 1 }, negotiable: false });
    assert.equal(bl.negotiable, false);
  });
});

// ===========================================================================
// 2. Rail-selection policy (eligibility + execution mode) at each branch
// ===========================================================================

describe("rail-selection policy", () => {
  test("fixed scope: x402 AND pay-dem both eligible", () => {
    assert.deepEqual(eligibleRails(["pay-x402", "pay-dem"], "fixed"), ["pay-x402", "pay-dem"]);
  });

  test("parameterized scope supports the session-bound x402 resource", () => {
    assert.deepEqual(eligibleRails(["pay-x402", "pay-dem"], "parameterized"), ["pay-x402", "pay-dem"]);
    assert.deepEqual(eligibleRails(["pay-x402"], "parameterized"), ["pay-x402"]);
  });

  test("pay-evm-erc8183 is never eligible (unwired in this build)", () => {
    assert.deepEqual(eligibleRails(["pay-evm-erc8183", "pay-dem"], "fixed"), ["pay-dem"]);
    assert.deepEqual(eligibleRails(["pay-evm-erc8183"], "fixed"), []);
  });

  test("unknown rails ignored; order + dedupe preserved", () => {
    assert.deepEqual(eligibleRails(["mystery", "pay-dem", "pay-dem", "pay-x402"], "fixed"), ["pay-dem", "pay-x402"]);
  });

  test("executionModeFor: rail + scope → concrete mode", () => {
    assert.equal(executionModeFor("pay-x402", "fixed"), "x402");
    assert.equal(executionModeFor("pay-x402", "parameterized"), "x402");
    assert.equal(executionModeFor("pay-dem", "fixed"), "pay-dem-watcher");
    assert.equal(executionModeFor("pay-dem", "parameterized"), "pay-dem-session");
    assert.throws(() => executionModeFor("pay-evm-erc8183", "fixed"), /not executable/);
  });
});

// ===========================================================================
// 3. Full x402 purchase — outcome verified + accepted
// ===========================================================================

describe("full x402 purchase (oracle desk, fixed scope)", () => {
  const paywalls: RunningPaywall[] = [];
  after(async () => {
    for (const pw of paywalls) await pw.close();
  });

  test("discovers → decides pay-x402 → executes → verified + accepted", async () => {
    const sub = new MemorySubstrate();
    const seller = new SellerAdapter(oracleId, sub, ORACLE_SERVICE_ID, makeOracleWork(oracleFetch()));
    const listingRef = await seller.publishListing({
      ...oracleListingSpec({ amount: USDC.amount, asset: USDC.asset }),
      supportedPaymentRails: ["pay-x402"],
    });

    const buyer = new BuyerAdapter(buyerId, sub);
    const verifier = new VerifierAdapter(sub);
    const bridge = new DacsButlerBuyer(buyer, verifier, sub);

    const offers = await bridge.discoverOffers([
      {
        ref: listingRef,
        scope: "fixed",
        fee: { kind: "fixed", price: 0.05 },
        acceptance: ORACLE_ACCEPTANCE,
        quality: { rating: 4.9, completedJobs: 200, disputeRate: 0.0 },
      },
    ]);
    assert.equal(offers.length, 1, "one anchored listing resolved");
    assert.deepEqual(offers[0]!.butlerListing.rails, ["pay-x402"]);

    const goal: ProcurementGoal = { description: "bitcoin price", requiredCapabilities: ["oracle-data"] };
    const decision = await bridge.procure(goal, 1, offers);
    assert.equal(decision.outcome, "awarded");
    assert.equal(decision.winner?.rail, "pay-x402");

    const pw = await startPaywall({
      route: "/data",
      accepts: { network: "eip155:84532", payTo: oracleId.evm, price: { amount: USDC.amount, asset: USDC.asset } },
      facilitator: new MockFacilitator(),
      deliver: async (jobId, params) => {
        const d = await seller.deliver(jobId, params);
        return { result: d.result, attestationRef: d.attestationRef };
      },
    });
    paywalls.push(pw);

    const runtime: SellerRuntime = {
      sellerDid: oracleId.did,
      sellerEvm: oracleId.evm,
      seller,
      observeDelivered: oracleObserveDelivered(),
      deliveryPhase: "deliver-crypto-price",
      jobParams: { product: "crypto-price", id: "bitcoin" },
      onchainPrice: USDC,
      paywallUrl: pw.url,
    };
    const outcome = await bridge.execute(decision, offers, runtime, { jobId: "x402-job" });

    assert.equal(outcome.mode, "x402");
    assert.equal(outcome.rail, "pay-x402");
    assert.equal(outcome.verified, true, "verifier delivery ok");
    assert.equal(outcome.acceptance.verdict, "accept");
    assert.equal(outcome.accepted, true, "verified AND mechanically accepted");
    assert.ok(outcome.settlementRef.length > 0);
    assert.ok((await sub.read(outcome.deliveryRef)) !== null, "delivery anchored");
  });
});

// ===========================================================================
// 4. Full pay-dem session purchase (dd-researcher) → needs-evaluator
// ===========================================================================

describe("full pay-dem session purchase (dd-researcher, parameterized)", () => {
  test("explicit pay-dem selection remains available alongside session-bound x402", async () => {
    const sub = new MemorySubstrate();
    const ledger = new MockDemLedger();
    const seller = new SellerAdapter(ddId, sub, DD_SERVICE_ID, makeDdWork(ddFetch()));
    const listingRef = await seller.publishListing({
      ...ddListingSpec({ amount: DEM.amount, asset: DEM.asset }),
      supportedPaymentRails: ["pay-dem", "pay-x402"], // advertises both; policy keeps pay-dem
    });

    const buyer = new BuyerAdapter(buyerId, sub);
    const verifier = new VerifierAdapter(sub);
    const bridge = new DacsButlerBuyer(buyer, verifier, sub);

    const offers = await bridge.discoverOffers([
      { ref: listingRef, scope: "parameterized", fee: { kind: "fixed", price: 1 } }, // no acceptance
    ]);
    assert.deepEqual(offers[0]!.butlerListing.rails, ["pay-dem", "pay-x402"]);

    const goal: ProcurementGoal = { description: "DD on bitcoin", requiredCapabilities: ["dd-research"] };
    const decision = await bridge.procure(goal, 5, offers);
    assert.equal(decision.winner?.rail, "pay-dem");

    const runtime: SellerRuntime = {
      sellerDid: ddId.did,
      sellerEvm: ddId.evm,
      seller,
      observeDelivered: ddObserveDelivered(),
      deliveryPhase: DD_DELIVERY_PHASE,
      jobParams: { kind: "crypto-token", subject: "bitcoin" },
      onchainPrice: DEM,
      ledger,
    };
    const outcome = await bridge.execute(decision, offers, runtime, { jobId: "dd-job" });

    assert.equal(outcome.mode, "pay-dem-session");
    assert.equal(outcome.verified, true, outcome.acceptance.verdict);
    assert.equal(outcome.acceptance.verdict, "needs-evaluator");
    assert.equal(outcome.needsEvaluator, true);
    assert.equal(outcome.accepted, false, "needs-evaluator is not auto-accept");
    // The DEM transfer was memo-bound to the job.
    assert.equal(ledger.transfers.length, 1);
    assert.equal(ledger.transfers[0]!.memo, "DACS:dd-job");
  });
});

// ===========================================================================
// 5. Pattern-1 watcher purchase verified + accepted
// ===========================================================================

type ResolvedOffers = Awaited<ReturnType<DacsButlerBuyer["discoverOffers"]>>;

interface WatchWorld {
  sub: MemorySubstrate;
  ledger: MockDemLedger;
  bridge: DacsButlerBuyer;
  seller: SellerAdapter;
  offers: ResolvedOffers;
}

async function makeWatchWorld(acceptance = ORACLE_ACCEPTANCE): Promise<WatchWorld> {
  const sub = new MemorySubstrate();
  const ledger = new MockDemLedger();
  const seller = new SellerAdapter(oracleId, sub, ORACLE_SERVICE_ID, makeOracleWork(oracleFetch()));
  const listingRef = await seller.publishListing({
    ...oracleListingSpec({ amount: DEM.amount, asset: DEM.asset }),
    supportedPaymentRails: ["pay-dem"],
  });
  const sellerAddr = demosAddrFromDid(oracleId.did)!;
  const watcher = new SellerWatcher(seller, sub, new MockLedgerWatch(ledger), {
    sellerAddr,
    listingPrice: DEM_UNITS,
  });
  watcher.run();

  const buyer = new BuyerAdapter(buyerId, sub);
  const verifier = new VerifierAdapter(sub);
  const bridge = new DacsButlerBuyer(buyer, verifier, sub);
  const offers = await bridge.discoverOffers([
    { ref: listingRef, scope: "fixed", fee: { kind: "fixed", price: 0.05 }, acceptance, quality: { rating: 4.7, completedJobs: 80, disputeRate: 0.0 } },
  ]);
  return { sub, ledger, bridge, seller, offers };
}

function watcherRuntime(observeDelivered = oracleObserveDelivered()): SellerRuntime {
  return {
    sellerDid: oracleId.did,
    sellerEvm: oracleId.evm,
    seller: undefined as never, // watcher already running; no push seller needed
    observeDelivered,
    deliveryPhase: "deliver-crypto-price",
    jobParams: { product: "crypto-price", id: "bitcoin" },
    onchainPrice: DEM,
    ledger: undefined as never, // set per call
  };
}

describe("Pattern-1 watcher purchase (oracle desk on pay-dem)", () => {
  test("decides pay-dem → memo-watcher execution → verified + accepted", async () => {
    const w = await makeWatchWorld();
    assert.deepEqual(w.offers[0]!.butlerListing.rails, ["pay-dem"]);

    const goal: ProcurementGoal = { description: "bitcoin price", requiredCapabilities: ["oracle-data"] };
    const decision = await w.bridge.procure(goal, 1, w.offers);
    assert.equal(decision.winner?.rail, "pay-dem");

    const runtime = watcherRuntime();
    runtime.ledger = w.ledger;
    const outcome = await w.bridge.execute(decision, w.offers, runtime, { jobId: "watch-job" });

    assert.equal(outcome.mode, "pay-dem-watcher");
    assert.equal(outcome.settlementRef, "mock-dem-watch-job", "settlementRef is the DEM txHash");
    assert.equal(outcome.verified, true);
    assert.equal(outcome.accepted, true);
    // The delivery was watcher-triggered (buyer never called the seller adapter).
    assert.equal(w.ledger.transfers[0]!.memo, "DACS:watch-job");
  });
});

// ===========================================================================
// 6. acceptDeliverable AND verifier BOTH gate acceptance
// ===========================================================================

describe("acceptance gating — both mechanical checks AND verifier must pass", () => {
  test("verifier passes but mechanical check fails ⇒ not accepted (rejected)", async () => {
    // Acceptance that can never pass on the oracle meta.
    const w = await makeWatchWorld({ checks: [{ kind: "content-includes", needle: "__NEVER_PRESENT__" }] });
    const goal: ProcurementGoal = { description: "px", requiredCapabilities: ["oracle-data"] };
    const decision = await w.bridge.procure(goal, 1, w.offers);
    const runtime = watcherRuntime();
    runtime.ledger = w.ledger;
    const outcome = await w.bridge.execute(decision, w.offers, runtime, { jobId: "gate-mech" });

    assert.equal(outcome.verified, true, "verifier still passes");
    assert.equal(outcome.acceptance.verdict, "reject");
    assert.equal(outcome.accepted, false, "one gate failing ⇒ not accepted");
  });

  test("mechanical check passes but verifier fails ⇒ not accepted", async () => {
    const w = await makeWatchWorld(); // passing mechanical checks
    const goal: ProcurementGoal = { description: "px", requiredCapabilities: ["oracle-data"] };
    const decision = await w.bridge.procure(goal, 1, w.offers);
    // observeDelivered that refuses ⇒ verifier fails.
    const runtime = watcherRuntime(async () => ({ ok: false, reason: "state not observed" }));
    runtime.ledger = w.ledger;
    const outcome = await w.bridge.execute(decision, w.offers, runtime, { jobId: "gate-verify" });

    assert.equal(outcome.acceptance.verdict, "accept", "mechanical checks pass");
    assert.equal(outcome.verified, false, "verifier gate fails");
    assert.equal(outcome.accepted, false, "one gate failing ⇒ not accepted");
  });
});

// ===========================================================================
// 7. Budget + negotiation honored end-to-end
// ===========================================================================

describe("budget + negotiation honored end-to-end", () => {
  test("over-budget non-negotiable ask ⇒ no-award (nothing executes)", async () => {
    const sub = new MemorySubstrate();
    const seller = new SellerAdapter(oracleId, sub, ORACLE_SERVICE_ID, makeOracleWork(oracleFetch()));
    const listingRef = await seller.publishListing({
      ...oracleListingSpec({ amount: DEM.amount, asset: DEM.asset }),
      supportedPaymentRails: ["pay-dem"],
    });
    const buyer = new BuyerAdapter(buyerId, sub);
    const bridge = new DacsButlerBuyer(buyer, new VerifierAdapter(sub), sub);
    const offers = await bridge.discoverOffers([
      { ref: listingRef, scope: "fixed", fee: { kind: "fixed", price: 12 }, negotiable: false, acceptance: ORACLE_ACCEPTANCE },
    ]);
    const decision = await bridge.procure({ description: "px", requiredCapabilities: ["oracle-data"] }, 5, offers);
    assert.equal(decision.outcome, "no-award");
    assert.equal(decision.candidates[0]?.excluded?.includes("over budget"), true);
  });

  test("negotiable ask above budget haggles down within budget, then purchase completes", async () => {
    const w = await makeWatchWorldNegotiable();
    const decision = await w.bridge.procure({ description: "px", requiredCapabilities: ["oracle-data"] }, 5, w.offers);
    assert.equal(decision.outcome, "awarded");
    assert.equal(decision.winner?.negotiated, true, "won via negotiation");
    assert.ok(decision.winner!.price <= 5, `negotiated price ${decision.winner!.price} within budget`);
    assert.ok(decision.negotiations.some((n) => n.result === "agreed"), "an agreed transcript exists");

    const runtime = watcherRuntime();
    runtime.ledger = w.ledger;
    const outcome = await w.bridge.execute(decision, w.offers, runtime, { jobId: "nego-job" });
    assert.equal(outcome.verified, true);
    assert.equal(outcome.accepted, true, "negotiated purchase still settles + delivers + verifies");
  });
});

/** A watcher world whose only listing asks $9 (over the $5 budget) but negotiates to a $3 floor. */
async function makeWatchWorldNegotiable(): Promise<WatchWorld> {
  const sub = new MemorySubstrate();
  const ledger = new MockDemLedger();
  const seller = new SellerAdapter(oracleId, sub, ORACLE_SERVICE_ID, makeOracleWork(oracleFetch()));
  const listingRef = await seller.publishListing({
    ...oracleListingSpec({ amount: DEM.amount, asset: DEM.asset }),
    supportedPaymentRails: ["pay-dem"],
  });
  const sellerAddr = demosAddrFromDid(oracleId.did)!;
  const watcher = new SellerWatcher(seller, sub, new MockLedgerWatch(ledger), { sellerAddr, listingPrice: DEM_UNITS });
  watcher.run();

  const buyer = new BuyerAdapter(buyerId, sub);
  const bridge = new DacsButlerBuyer(buyer, new VerifierAdapter(sub), sub);
  const offers = await bridge.discoverOffers([
    {
      ref: listingRef,
      scope: "fixed",
      fee: { kind: "fixed", price: 9 },
      negotiable: true,
      floor: 3,
      acceptance: ORACLE_ACCEPTANCE,
      quality: { rating: 4.7, completedJobs: 80, disputeRate: 0.0 },
    },
  ]);
  return { sub, ledger, bridge, seller, offers };
}
