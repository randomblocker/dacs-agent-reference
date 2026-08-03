import assert from "node:assert/strict";
import test from "node:test";
import { makeIdentity } from "../../src/identity.js";
import { MemorySubstrate } from "../../src/substrate/memory.js";
import { BuyerAdapter } from "./buyer.js";
import { SellerAdapter, standardListingSpecFromLegacy } from "./seller-adapter.js";
import { runStandardFixedSession } from "./standard-runner.js";
import { auditNegotiatorStandardListingSpec } from "./wire/audit-negotiator.js";
import { complianceListingSpec } from "./wire/compliance.js";
import { ddListingSpec } from "./wire/dd-researcher.js";
import { depUpgradeListingSpec } from "./wire/dep-upgrade.js";
import { evalBotListingSpec } from "./wire/evalbot.js";
import { oracleListingSpec } from "./wire/oracle-desk.js";
import { secAuditListingSpec } from "./wire/sec-audit.js";
import { siteAuditorListingSpec } from "./wire/site-auditor.js";
import { treasuryListingSpec } from "./wire/treasury-ops.js";

const DEM = { amount: "1000000000", asset: "DEM" };
const USDC = { amount: "1000000", asset: "USDC" };

test("every current roster seller publishes a cryptographically valid full DACS-1 listing", async () => {
  const sub = new MemorySubstrate();
  const buyerId = makeIdentity("indexer", 0x70);
  const buyer = new BuyerAdapter(buyerId, sub);
  const legacy = [
    { spec: oracleListingSpec(USDC), price: USDC },
    { spec: ddListingSpec(DEM), price: DEM },
    { spec: depUpgradeListingSpec(DEM), price: DEM },
    { spec: evalBotListingSpec(DEM), price: DEM },
    { spec: treasuryListingSpec(DEM), price: DEM },
    { spec: siteAuditorListingSpec(DEM), price: DEM },
    { spec: secAuditListingSpec(DEM), price: DEM },
    { spec: complianceListingSpec(DEM), price: DEM },
  ];
  const refs: string[] = [];
  const fixedRuntimes: Array<{ seller: SellerAdapter; listing: Awaited<ReturnType<SellerAdapter["publishStandardListing"]>> }> = [];
  for (const [index, entry] of legacy.entries()) {
    const id = makeIdentity(entry.spec.serviceId, 0x20 + index);
    const seller = new SellerAdapter(id, sub, entry.spec.serviceId, async () => ({ result: null }));
    const standard = standardListingSpecFromLegacy(entry.spec, entry.price);
    const published = await seller.publishStandardListing(standard);
    refs.push(published.ref);
    fixedRuntimes.push({ seller, listing: published });
  }
  const auditorId = makeIdentity("auditor", 0x38);
  refs.push((await new SellerAdapter(auditorId, sub, "audit-negotiator", async () => ({ result: null }))
    .publishStandardListing(auditNegotiatorStandardListingSpec({
      researcherGithub: "dacs-security-researcher",
      operatorClaim: auditorId.did,
    }))).ref);

  const discovered = await buyer.discoverStandard(refs);
  assert.equal(discovered.length, refs.length);
  for (const { listing } of discovered) {
    assert.equal(listing.dacsVersion, "1");
    assert.ok(listing.listingVersion >= 1);
    assert.equal(listing.pipeline[0]?.kind, "vet-credentials");
    const negotiation = listing.pipeline.findIndex((phase) => phase.kind.startsWith("negotiate-"));
    assert.equal(listing.pipeline[negotiation + 1]?.kind, "commit-agreement");
    assert.equal(listing.pipeline.some((phase) => phase.kind === "deliver-attested-payload"), true);
    assert.equal(listing.acceptedRails?.length, 1);
    const payment = listing.pipeline.find((phase) => phase.kind.startsWith("pay-"));
    assert.equal(typeof payment?.parameters?.rail, "string");
    assert.equal(listing.acceptedRails?.some((rail) => rail.railId === payment?.parameters?.rail), true);
  }

  for (const [index, runtime] of fixedRuntimes.entries()) {
    const isX402 = runtime.listing.listing.pipeline.some((phase) => phase.kind === "pay-x402");
    const result = await runStandardFixedSession({
      jobId: `all-agent-standard-${index}`,
      listingRef: runtime.listing.ref,
      listing: runtime.listing.listing,
      buyer,
      seller: runtime.seller,
      params: {},
      async settle() {
        return isX402 ? {
          txRefs: [{ kind: "x402" as const, httpResource: "https://example.test/paid", paymentReceiptHash: "a".repeat(64), protocolVersion: "1" }],
          finality: { model: "provider-receipt" as const, finalityObservedAt: Date.now() },
        } : {
          txRefs: [{ kind: "demos" as const, txHash: (index + 1).toString(16).repeat(64).slice(0, 64), blockNumber: 100 + index }],
          finality: { model: "bft-final" as const, finalityObservedAt: Date.now() },
        };
      },
    });
    assert.equal(result.session.state, "finalised");
  }
});
