import assert from "node:assert/strict";
import test from "node:test";
import { makeIdentity } from "../../src/identity.js";
import { MemorySubstrate } from "../../src/substrate/memory.js";
import { BuyerAdapter } from "../dacs/buyer.js";
import { SellerAdapter } from "../dacs/seller-adapter.js";
import {
  DD_TENDER_SERVICE_ID,
  ddLiveFixedListing,
  ddLiveFixedX402Listing,
  ddSealedTenderListing,
  oracleAutoAcceptListing,
  oracleAutoAcceptX402Listing,
  sponsoredPostLiveListing,
  sponsoredPostLiveX402Listing,
  publisherRfqListing,
  publisherRfqX402Listing,
} from "./procurement-listings.js";
import { auditNegotiatorX402StandardListingSpec } from "../dacs/wire/audit-negotiator.js";
import { X402_RAIL_ID, x402PublicEndpoint } from "../dacs/x402-production.js";

const xAccount = {
  claim: "cci-web2:twitter:DACSdemo",
  platform: "twitter" as const,
  handle: "DACSdemo",
  userId: "123456789",
  proofPostId: "987654321",
  proofPostUrl: "https://x.com/DACSdemo/status/987654321",
  proofTextHash: "a".repeat(64),
};

const domainIdentity = {
  hostname: "dacs.directory",
  claim: "web2:domain:dacs.directory",
  proofUrl: "https://dacs.directory/.well-known/demos-cci.txt",
  gcrOwner: `did:demos:agent:${"b".repeat(64)}`,
};

test("production procurement listings are signed, discoverable and pattern-exact", async () => {
  const sub = new MemorySubstrate();
  const buyer = new BuyerAdapter(makeIdentity("listing-index", 0x51), sub);
  const now = Date.now();
  const specs = [
    oracleAutoAcceptListing({ listingVersion: 2, notBefore: now, validUntil: now + 86_400_000 }),
    ddLiveFixedListing(),
    publisherRfqListing({ domainIdentity }),
    sponsoredPostLiveListing({ accountBinding: xAccount }),
    ddSealedTenderListing(),
  ];
  const refs: string[] = [];
  for (const [index, spec] of specs.entries()) {
    const seller = new SellerAdapter(makeIdentity(`profile-${index}`, 0x52 + index), sub, spec.serviceId, async () => ({ result: null }));
    const published = await seller.publishStandardListing(spec);
    refs.push(published.ref);
    if (spec.terms.acceptanceModel === "auto-accept") {
      assert.ok(published.autoAcceptCommitmentRef);
      assert.ok(published.autoAcceptCommitment);
    }
  }
  const listings = (await buyer.discoverStandard(refs)).map((entry) => entry.listing);
  assert.equal(listings.length, 5);
  assert.equal(listings[0]?.pipeline.some((step) => step.kind === "negotiate-fixed-price"), true);
  assert.equal(listings[0]?.terms.acceptanceModel, "auto-accept");
  assert.equal(listings[1]?.terms.acceptanceModel, undefined);
  assert.equal(listings[2]?.listingId, "publisher-ad-rfq");
  assert.equal(listings[2]?.pipeline.some((step) => step.kind === "negotiate-rfq"), true);
  assert.equal(listings[3]?.listingId, "sponsored-post");
  assert.equal(listings[3]?.seller.identity.claims[0]?.metadata?.linkedAccounts !== undefined, true);
  assert.equal(listings[4]?.listingId, DD_TENDER_SERVICE_ID);
  assert.equal(listings[4]?.pipeline.some((step) => step.kind === "negotiate-sealed-envelope"), true);
  assert.equal(listings[4]?.pricing.kind, "auction");
});

test("Oracle, DD, Security and Sponsored Post publish separate canonical x402 listing shapes", () => {
  const now = Date.now();
  const common = {
    payTo: "0x1111111111111111111111111111111111111111",
    resourceBase: "https://seller.example/x402",
    identityMetadata: { paymentAccounts: [{ kind: "test-binding" }] },
    researcherGithub: "dacs-security-researcher",
    operatorClaim: `did:demos:agent:${"d".repeat(64)}`,
  };
  const specs = [
    oracleAutoAcceptX402Listing({ ...common, listingVersion: 2, validUntil: now + 86_400_000, notBefore: now }),
    ddLiveFixedX402Listing(common),
    auditNegotiatorX402StandardListingSpec(common),
    sponsoredPostLiveX402Listing({ ...common, accountBinding: xAccount }),
    publisherRfqX402Listing({ ...common, domainIdentity }),
  ];
  for (const spec of specs) {
    assert.equal(spec.pipeline.filter((phase) => phase.kind === "pay-x402").length, 1);
    assert.equal(spec.pipeline.some((phase) => phase.kind === "pay-dem"), false);
    assert.equal(spec.acceptedRails.length, 1);
    assert.equal(spec.acceptedRails[0]?.railId, X402_RAIL_ID);
    assert.equal(
      spec.pipeline.find((phase) => phase.kind === "pay-x402")?.parameters?.rail,
      X402_RAIL_ID,
    );
    assert.ok(spec.acceptedRails[0]?.railVersion);
    assert.ok(spec.sellerIdentityMetadata?.paymentAccounts);
    const price = spec.pricing.kind === "fixed" ? spec.pricing.price
      : spec.pricing.kind === "negotiable" ? spec.pricing.bandCenter
      : undefined;
    assert.equal(price?.currency, "USDC");
    assert.equal(spec.publicEndpoint, "https://seller.example/demo/procurement/options");
  }
});

test("x402 listing contact defaults to the live gateway origin and rejects an unrelated override", () => {
  assert.equal(
    x402PublicEndpoint("https://seller.example/demo/x402"),
    "https://seller.example/demo/procurement/options",
  );
  assert.throws(
    () => x402PublicEndpoint("https://seller.example/demo/x402", "https://retired.example/try"),
    /live x402 gateway origin/,
  );
});

test("Publisher listing binds the current Demos GCR domain proof and discloses the standards alias issue", () => {
  const listing = publisherRfqListing({ domainIdentity });
  const metadata = listing.sellerIdentityMetadata?.domainIdentity as Record<string, unknown>;
  assert.equal(metadata.claim, "web2:domain:dacs.directory");
  assert.equal(metadata.canonicalClaimPending, "domain:dacs.directory");
  assert.equal(metadata.standardsIssue, "https://github.com/DACS-Agent-commerce/DACS-Standard/issues/275");
  assert.throws(
    () => publisherRfqListing({ domainIdentity: { ...domainIdentity, claim: "domain:dacs.directory" } }),
    /current Demos GCR/,
  );
});

test("Sponsored Post listing rejects an unbound or non-canonical X account proof", () => {
  assert.throws(
    () => sponsoredPostLiveListing({ accountBinding: { ...xAccount, claim: "cci-web2:twitter:someoneElse" } }),
    /claim does not match/,
  );
  assert.throws(
    () => sponsoredPostLiveListing({ accountBinding: { ...xAccount, proofPostUrl: "https://example.com/not-proof" } }),
    /proof URL is not canonical/,
  );
});
