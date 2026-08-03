import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { makeIdentity } from "../../src/identity.js";
import { MemorySubstrate } from "../../src/substrate/memory.js";
import {
  addAgreementSignature,
  addAutoAcceptInstanceSignature,
  createAutoAcceptCommitment,
  createIdentityBundle,
  emptyRequirement,
  requestScopeHash,
  signListing,
  standardAnchorName,
  type AgreementDocument,
  type Listing,
} from "../dacs/standard-profile.js";
import { presentIdentity, sessionNonce, vetAndAnchor } from "./standard-session.js";
import { runFixedPriceNegotiation } from "./fixed-price.js";

const buyer = makeIdentity("fixed-buyer", 0x71);
const seller = makeIdentity("fixed-seller", 0x72);
const buyerParty = { primaryClaim: buyer.did, sign: buyer.sign };
const sellerParty = { primaryClaim: seller.did, sign: seller.sign };

async function setup(autoAccept: boolean) {
  const sub = new MemorySubstrate();
  const now = Date.now();
  const sellerIdentity = await createIdentityBundle(sellerParty, { presentedAt: now });
  const listing = await signListing({
    dacsVersion: "1",
    listingVersion: 1,
    listingId: autoAccept ? "oracle-auto" : "dd-live-fixed",
    requiredCapabilities: ["SR-1", "SR-2"],
    seller: { identity: sellerIdentity, displayName: autoAccept ? "Oracle Desk" : "DD Researcher" },
    offering: {
      title: autoAccept ? "Attested public data" : "Source-attested DD report",
      description: "A bounded production service with signed, independently verifiable delivery evidence.",
      category: autoAccept ? "data.oracle.attested" : "research.due_diligence.report",
      tags: autoAccept ? ["oracle", "attested"] : ["research", "attested"],
      deliverable: { kind: "attested-payload", payloadFormat: "application/json", verificationMethod: "seller-signature-and-content-hash" },
    },
    buyerRequirement: emptyRequirement(),
    pipeline: [
      { kind: "vet-credentials" },
      { kind: "negotiate-fixed-price" },
      { kind: "commit-agreement" },
      { kind: "pay-dem", parameters: { rail: "demos-native:DEM" } },
      { kind: "deliver-attested-payload" },
    ],
    pricing: { kind: "fixed", price: { amount: "1", currency: "DEM", unit: "per-job" } },
    acceptedRails: [{ railId: "demos-native:DEM", railVersion: 1 }],
    terms: {
      deadlineSecAfterCommit: 300,
      ...(autoAccept ? { acceptanceModel: "auto-accept" as const } : {}),
      cancellationPolicy: "pre-commit",
      transcriptDisclosurePolicy: "none",
    },
    validity: { notBefore: now - 1_000, notAfter: now + 86_400_000 },
  }, sellerParty);
  const listingName = standardAnchorName("listing", [seller.did, listing.listingId, "1"]);
  const listingReceipt = await sub.anchorWithReceipt(listingName, listing);

  const jobId = `fixed-${autoAccept ? "auto" : "live"}`;
  const buyerBundle = await presentIdentity(buyerParty, sessionNonce());
  const sellerBundle = await presentIdentity(sellerParty, sessionNonce());
  const buyerVetted = await vetAndAnchor({ party: sellerParty, sub }, jobId, buyerBundle, emptyRequirement());
  const sellerVetted = await vetAndAnchor({ party: buyerParty, sub }, jobId, sellerBundle, emptyRequirement());

  let autoAcceptCommitment;
  let autoAcceptCommitmentReceipt;
  if (autoAccept) {
    autoAcceptCommitment = await createAutoAcceptCommitment(listing, sellerParty, now + 60_000, now);
    autoAcceptCommitmentReceipt = await sub.anchorWithReceipt(
      standardAnchorName("auto-accept", [seller.did, listing.listingId, "1"]),
      autoAcceptCommitment,
    );
  }
  return {
    sub,
    now,
    jobId,
    listing,
    listingReceipt,
    buyerVetted,
    sellerVetted,
    autoAcceptCommitment,
    autoAcceptCommitmentReceipt,
  };
}

describe("fixed-price production negotiation", () => {
  test("collects a live seller co-signature and batches agreement plus commitment", async () => {
    const fx = await setup(false);
    const result = await runFixedPriceNegotiation({
      requestScope: { kind: "npm-package", subject: "express" },
      jobId: fx.jobId,
      listing: fx.listing,
      listingAnchorRef: fx.listingReceipt.address,
      listingReceipt: fx.listingReceipt,
      buyer: fx.buyerVetted,
      seller: fx.sellerVetted,
      buyerParty,
      buyerSubstrate: fx.sub,
      sellerSign: ({ agreement, requestHash }) => {
        assert.equal(requestHash, requestScopeHash({ kind: "npm-package", subject: "express" }));
        return addAgreementSignature(agreement, sellerParty);
      },
      generatedAt: fx.now,
    });
    assert.equal(result.agreement.derivedFromPattern, "fixed-price");
    assert.equal(result.agreement.signatures.length, 2);
    assert.equal(result.commitment.pattern, "fixed-price");
    assert.equal(result.agreement.terms.additionalTerms?.requestHash,
      requestScopeHash({ kind: "npm-package", subject: "express" }));
    assert.equal(result.agreementReceipt.inclusionLatencyMs, 0);
    assert.ok(await fx.sub.read(result.agreementRef.anchor.locator));
    assert.ok(await fx.sub.read(result.commitmentRef.anchor.locator));
  });

  test("uses a separately anchored template and a live agreement-bound auto-accept signature", async () => {
    const fx = await setup(true);
    assert.ok(fx.autoAcceptCommitment && fx.autoAcceptCommitmentReceipt);
    const result = await runFixedPriceNegotiation({
      requestScope: { product: "crypto-price", params: { id: "bitcoin" } },
      jobId: fx.jobId,
      listing: fx.listing,
      listingAnchorRef: fx.listingReceipt.address,
      listingReceipt: fx.listingReceipt,
      buyer: fx.buyerVetted,
      seller: fx.sellerVetted,
      buyerParty,
      buyerSubstrate: fx.sub,
      autoAcceptCommitment: fx.autoAcceptCommitment,
      autoAcceptCommitmentRef: fx.autoAcceptCommitmentReceipt.address,
      autoAcceptCommitmentReceipt: fx.autoAcceptCommitmentReceipt,
      sellerSign: ({ agreement, autoAcceptCommitment }) =>
        addAutoAcceptInstanceSignature(agreement, autoAcceptCommitment!, sellerParty),
      generatedAt: fx.now,
    });
    assert.equal(result.autoAcceptCommitmentRef, fx.autoAcceptCommitmentReceipt.address);
    assert.equal(result.agreement.signatures.length, 2);
  });

  test("rejects a seller that mutates price after the buyer signs", async () => {
    const fx = await setup(false);
    await assert.rejects(() => runFixedPriceNegotiation({
      requestScope: { kind: "npm-package", subject: "express" },
      jobId: fx.jobId,
      listing: fx.listing,
      listingAnchorRef: fx.listingReceipt.address,
      listingReceipt: fx.listingReceipt,
      buyer: fx.buyerVetted,
      seller: fx.sellerVetted,
      buyerParty,
      buyerSubstrate: fx.sub,
      sellerSign: async ({ agreement }) => {
        const changed: AgreementDocument = {
          ...agreement,
          terms: { ...agreement.terms, price: { ...agreement.terms.price, amount: "9" } },
        };
        return addAgreementSignature(changed, sellerParty);
      },
      generatedAt: fx.now,
    }), /changed the buyer-signed agreement scope/);
  });
});
