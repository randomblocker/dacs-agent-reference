import assert from "node:assert/strict";
import test from "node:test";
import { makeIdentity } from "../../src/identity.js";
import { MemorySubstrate } from "../../src/substrate/memory.js";
import { SellerAdapter } from "../dacs/seller-adapter.js";
import { VerifierAdapter } from "../dacs/verifier.js";
import { makePublisherWork, publisherObserveDelivered } from "../dacs/wire/publisher-agent.js";
import { canonicalPublisherDomain, validateDomainIdentityBinding } from "./domain-identity.js";
import { parsePublisherRfqRequest, type PublisherModerationPort } from "./policy.js";
import { MemoryPublisherActivationPort } from "./publisher-port.js";
import { MemoryPublisherReservations, buildPublisherQuote, negotiatePublisherRfq } from "./rfq.js";
import { PUBLISHER_SERVICE_ID } from "./types.js";

const NOW = 1_753_200_000_000;
const request = {
  creative: {
    headline: "Build verifiable agent commerce",
    body: "See DACS agents negotiate, settle and verify real work.",
    cta: "Try it" as const,
    destinationUrl: "https://dacs.directory/try",
  },
  preferredPlacement: "homepage-banner" as const,
  preferredDurationDays: 7,
  minimumDurationDays: 3,
  budgetDem: "20",
};
const slots = [
  { slotId: "home-top", placement: "homepage-banner" as const, dailyRateDem: "3", publicPath: "/" },
  { slotId: "docs-side", placement: "sidebar-card" as const, dailyRateDem: "1.50", publicPath: "/docs" },
];
const moderation: PublisherModerationPort = { async review() { return { allowed: true, decisionRef: "review:publisher:test" }; } };

test("Publisher RFQ accepts bounded creative and rejects active-content or private destinations", () => {
  assert.deepEqual(parsePublisherRfqRequest(request), request);
  assert.throws(
    () => parsePublisherRfqRequest({ ...request, creative: { ...request.creative, headline: "<script>alert(1)</script>" } }),
    /HTML delimiters/,
  );
  assert.throws(
    () => parsePublisherRfqRequest({ ...request, creative: { ...request.creative, destinationUrl: "https://127.0.0.1/steal" } }),
    /private or local/,
  );
  assert.throws(() => parsePublisherRfqRequest({ ...request, minimumDurationDays: 8 }), /cannot exceed/);
});

test("RFQ counters with the longest affordable duration and reserves it before payment", async () => {
  const reservations = new MemoryPublisherReservations();
  const result = await negotiatePublisherRfq({
    jobId: "publisher-job-1", domain: "dacs.directory", request, slots, reservations, now: NOW,
  });
  assert.equal(result.outcome, "agreed");
  assert.equal(result.quote.durationDays, 6);
  assert.equal(result.quote.priceDem, "18");
  assert.equal(result.transcript[1]?.kind, "counter");
  assert.deepEqual(await reservations.reserve(result.quote), { reserved: true });

  await assert.rejects(
    () => negotiatePublisherRfq({ jobId: "publisher-job-2", domain: "dacs.directory", request, slots, reservations, now: NOW }),
    /reserved concurrently/,
  );
});

test("RFQ walks before commitment when budget cannot buy the minimum duration", () => {
  assert.throws(
    () => buildPublisherQuote({
      jobId: "publisher-low-budget",
      domain: "dacs.directory",
      request: { ...request, budgetDem: "5" },
      slots,
      now: NOW,
    }),
    /cannot buy the minimum/,
  );
});

test("domain binding uses the real Demos well-known/GCR representation", () => {
  assert.equal(canonicalPublisherDomain("dacs.directory"), "dacs.directory");
  assert.deepEqual(validateDomainIdentityBinding({
    hostname: "dacs.directory",
    claim: "web2:domain:dacs.directory",
    proofUrl: "https://dacs.directory/.well-known/demos-cci.txt",
    gcrOwner: `did:demos:agent:${"a".repeat(64)}`,
  }).claim, "web2:domain:dacs.directory");
  assert.throws(() => canonicalPublisherDomain("https://dacs.directory"), /without URL components/);
});

test("negotiated campaign activates once and its signed DACS delivery verifies", async () => {
  const sellerIdentity = makeIdentity("publisher", 0x71);
  const substrate = new MemorySubstrate();
  const publisher = new MemoryPublisherActivationPort();
  const reservations = new MemoryPublisherReservations();
  const negotiation = await negotiatePublisherRfq({
    jobId: "publisher-paid-job", domain: "dacs.directory", request, slots, reservations, now: NOW,
  });
  const seller = new SellerAdapter(
    sellerIdentity,
    substrate,
    PUBLISHER_SERVICE_ID,
    makePublisherWork({ domain: "dacs.directory", publisher, moderation, now: () => NOW }),
  );
  const params = { request, quote: negotiation.quote };
  const first = await seller.deliver("publisher-paid-job", params);
  const second = await seller.deliver("publisher-paid-job", params);
  assert.equal(publisher.calls, 1);
  assert.deepEqual(second.result, first.result);
  assert.match(String(first.attestation.meta?.reportJson), /^[\x00-\x7F]*$/);

  const verification = await new VerifierAdapter(substrate).verifyDelivery("publisher-paid-job", {
    serviceId: PUBLISHER_SERVICE_ID,
    sellerDid: sellerIdentity.did,
    observeDelivered: publisherObserveDelivered("dacs.directory"),
  });
  assert.equal(verification.ok, true, verification.reason);
});

test("delivery verification catches a creative hash or domain substitution", async () => {
  const quote = buildPublisherQuote({ jobId: "tamper", domain: "dacs.directory", request, slots, now: NOW });
  const sellerIdentity = makeIdentity("publisher-tamper", 0x72);
  const substrate = new MemorySubstrate();
  const seller = new SellerAdapter(sellerIdentity, substrate, PUBLISHER_SERVICE_ID, makePublisherWork({
    domain: "dacs.directory",
    publisher: new MemoryPublisherActivationPort(),
    moderation,
    now: () => NOW,
  }));
  const delivered = await seller.deliver("tamper", { request, quote });
  const report = JSON.parse(String(delivered.attestation.meta?.reportJson));
  report.domain = "attacker.example";
  const tampered = structuredClone(delivered.attestation);
  tampered.meta = { ...tampered.meta, reportJson: JSON.stringify(report) };
  const observed = publisherObserveDelivered("dacs.directory");
  assert.ok(observed);
  assert.equal((await observed(tampered)).ok, false);
});
