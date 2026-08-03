/** Offline Publisher Agent test: real RFQ/activation/DACS evidence, no external writes or payment. */
import { makeIdentity } from "../../src/identity.js";
import { MemorySubstrate } from "../../src/substrate/memory.js";
import { SellerAdapter } from "../dacs/seller-adapter.js";
import { VerifierAdapter } from "../dacs/verifier.js";
import { makePublisherWork, publisherObserveDelivered } from "../dacs/wire/publisher-agent.js";
import { MemoryPublisherActivationPort } from "./publisher-port.js";
import { MemoryPublisherReservations, negotiatePublisherRfq } from "./rfq.js";
import { PUBLISHER_SERVICE_ID } from "./types.js";

const domain = process.env.PUBLISHER_DOMAIN ?? "publisher.example";
const now = Date.now();
const request = {
  creative: {
    headline: "Build verifiable agent commerce",
    body: "See agents negotiate, settle and verify real work.",
    cta: "Try it" as const,
    destinationUrl: "https://dacs.directory/try",
  },
  preferredPlacement: "homepage-banner" as const,
  preferredDurationDays: 7,
  minimumDurationDays: 3,
  budgetDem: "20",
};

const reservations = new MemoryPublisherReservations();
const negotiation = await negotiatePublisherRfq({
  jobId: "publisher-local-test",
  domain,
  request,
  slots: [{ slotId: "home-top", placement: "homepage-banner", dailyRateDem: "3", publicPath: "/" }],
  reservations,
  now,
});
const substrate = new MemorySubstrate();
const identity = makeIdentity("Publisher Agent", 0x75);
const seller = new SellerAdapter(identity, substrate, PUBLISHER_SERVICE_ID, makePublisherWork({
  domain,
  publisher: new MemoryPublisherActivationPort(),
  moderation: { async review() { return { allowed: true, decisionRef: "offline-test" }; } },
  now: () => now,
}));
const delivery = await seller.deliver("publisher-local-test", { request, quote: negotiation.quote });
const verification = await new VerifierAdapter(substrate).verifyDelivery("publisher-local-test", {
  serviceId: PUBLISHER_SERVICE_ID,
  sellerDid: identity.did,
  observeDelivered: publisherObserveDelivered(domain),
});
if (!verification.ok) throw new Error(`Publisher delivery did not verify: ${verification.reason}`);

console.log(JSON.stringify({
  mode: "offline-test-no-payment",
  domain,
  rfq: { outcome: negotiation.outcome, transcript: negotiation.transcript, agreedQuote: negotiation.quote },
  delivery: delivery.result,
  dacs: { attestationRef: delivery.attestationRef, verified: verification.ok },
}, null, 2));
