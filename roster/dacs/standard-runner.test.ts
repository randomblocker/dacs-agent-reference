import assert from "node:assert/strict";
import test from "node:test";
import { makeIdentity } from "../../src/identity.js";
import { MemorySubstrate } from "../../src/substrate/memory.js";
import { BuyerAdapter } from "./buyer.js";
import { SellerAdapter, standardListingSpecFromLegacy } from "./seller-adapter.js";
import { runStandardFixedSession } from "./standard-runner.js";
import { standardAnchorName } from "./standard-profile.js";

async function setup() {
  const sub = new MemorySubstrate();
  const buyer = new BuyerAdapter(makeIdentity("buyer", 0x61), sub);
  const sellerId = makeIdentity("seller", 0x62);
  const seller = new SellerAdapter(sellerId, sub, "test-service", async () => ({ result: { ok: true } }));
  const spec = standardListingSpecFromLegacy({
    serviceId: "test-service",
    name: "Test service",
    description: "A content-bound test deliverable.",
    supportedNegotiation: ["negotiate-fixed-price"],
    supportedPaymentRails: ["pay-dem"],
    supportedDelivery: ["deliver-test"],
  }, { amount: "1000000000", asset: "DEM" });
  const published = await seller.publishStandardListing(spec);
  return { sub, buyer, seller, published };
}

test("fixed-price Standard runner orders Commit before Settle and produces reconciled two-sided bundles", async () => {
  const { sub, buyer, seller, published } = await setup();
  const states: string[] = [];
  const result = await runStandardFixedSession({
    jobId: "standard-fixed-1",
    listingRef: published.ref,
    listing: published.listing,
    buyer,
    seller,
    params: {},
    async settle({ jobId }) {
      const commitment = await sub.read(await sub.anchorAddress(standardAnchorName("commitment", [jobId])));
      assert.ok(commitment, "commitment must be read-visible before settlement starts");
      return {
        txRefs: [{ kind: "demos", txHash: "a".repeat(64), blockNumber: 12 }],
        finality: { model: "bft-final", finalityObservedAt: Date.now() },
      };
    },
    onSessionRecord(record) { states.push(record.state); },
  });
  assert.equal(result.session.state, "finalised");
  assert.equal(result.session.phaseResults.length, published.listing.pipeline.length);
  assert.equal(result.buyerBundle.signatures.length, 2);
  assert.equal(result.sellerBundle.signatures.length, 2);
  assert.deepEqual(states, [
    "draft",
    "vet-pending", "vet-completed",
    "negotiate-pending", "negotiate-completed",
    "commit-pending", "commit-completed",
    "settle-pending", "settle-completed",
    "finalised",
  ]);
  assert.ok(await sub.read(result.buyerBundleRef));
  assert.ok(await sub.read(result.sellerBundleRef));
});

test("fixed-price Standard runner anchors a signed terminal failure bundle", async () => {
  const { sub, buyer, seller, published } = await setup();
  await assert.rejects(() => runStandardFixedSession({
    jobId: "standard-fixed-failure",
    listingRef: published.ref,
    listing: published.listing,
    buyer,
    seller,
    params: {},
    async settle() { throw new Error("rail unavailable"); },
  }), /rail unavailable/);
  const failureRef = await sub.anchorAddress(standardAnchorName("bundle", ["standard-fixed-failure", "buyer"]));
  const failure = await sub.read(failureRef);
  assert.equal(failure?.outcome, "failed-perm");
  assert.equal(Array.isArray(failure?.signatures), true);
});

test("auto-accept Standard runner uses the separately anchored template and live instance signature", async () => {
  const sub = new MemorySubstrate();
  const buyer = new BuyerAdapter(makeIdentity("auto-buyer", 0x71), sub);
  const sellerId = makeIdentity("auto-seller", 0x72);
  const seller = new SellerAdapter(sellerId, sub, "oracle-data", async () => ({ result: { value: "123.45" } }));
  const base = standardListingSpecFromLegacy({
    serviceId: "oracle-data",
    name: "Oracle auto desk",
    description: "A bounded attested datum.",
    supportedNegotiation: ["negotiate-fixed-price"],
    supportedPaymentRails: ["pay-dem"],
    supportedDelivery: ["deliver-attested-payload"],
  }, { amount: "1000000000", asset: "DEM" });
  const published = await seller.publishStandardListing({
    ...base,
    terms: { ...base.terms, acceptanceModel: "auto-accept" },
    autoAccept: { validUntil: Date.now() + 60_000 },
  });
  assert.ok(published.autoAcceptCommitment);
  assert.ok(published.autoAcceptCommitmentRef);

  const result = await runStandardFixedSession({
    jobId: "standard-auto-1",
    listingRef: published.ref,
    listing: published.listing,
    buyer,
    seller,
    params: { product: "crypto-price" },
    fixedPrice: {
      autoAcceptCommitment: published.autoAcceptCommitment,
      autoAcceptCommitmentRef: published.autoAcceptCommitmentRef,
    },
    async settle() {
      return {
        txRefs: [{ kind: "demos", txHash: "b".repeat(64), blockNumber: 13 }],
        finality: { model: "bft-final", finalityObservedAt: Date.now() },
      };
    },
  });
  assert.equal(result.session.state, "finalised");
  assert.equal(result.agreement.signatures.length, 2);
  assert.equal(result.delivery.result && (result.delivery.result as { value: string }).value, "123.45");
});
