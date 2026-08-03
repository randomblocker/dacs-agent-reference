import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { describe, test } from "node:test";

import { baseUnits } from "@kynesyslabs/dacs";
import { makeIdentity, resolveFromDid, verify } from "../../src/identity.js";
import {
  addAgreementSignature,
  addAutoAcceptInstanceSignature,
  addBundleSignature,
  attestationRef,
  bundleHash,
  createCommitment,
  createAutoAcceptCommitment,
  createEmptyVetRecord,
  createIdentityBundle,
  createListingRevocation,
  createScopedListingRevocation,
  deliverableRef,
  emptyRequirement,
  listingRef,
  sameCanonicalBundle,
  signListing,
  signSettlementEvidence,
  standardHash,
  verifyAgreement,
  verifyAutoAcceptCommitment,
  verifyBundle,
  verifyCommitment,
  verifyEvidence,
  verifyIdentityBundle,
  verifyListing,
  verifyScopedListingRevocation,
  verifyVetRecord,
  type AgreementDocument,
  type AttestationBundle,
  type Listing,
} from "./standard-profile.js";

const buyer = makeIdentity("buyer", 31);
const seller = makeIdentity("seller", 47);
const buyerParty = { primaryClaim: buyer.did, sign: buyer.sign };
const sellerParty = { primaryClaim: seller.did, sign: seller.sign };
const cryptoDeps = { resolvePublicKey: async (claim: string) => resolveFromDid(claim), verify };

async function fixture() {
  const sellerPublication = await createIdentityBundle(sellerParty, { presentedAt: 1_780_000_000_000 });
  const requirement = emptyRequirement();
  const deliverable = {
    kind: "attested-payload" as const,
    payloadFormat: "application/vnd.dacs.security-audit+json;version=1",
    verificationMethod: "self-signed",
    expectedSizeBytes: 65_536,
  };
  const unsignedListing: Omit<Listing, "signature"> = {
    dacsVersion: "1",
    listingVersion: 1,
    listingId: "auditor-security-review",
    requiredCapabilities: ["SR-1", "SR-2", "SR-4"],
    seller: { identity: sellerPublication, displayName: "DACS Auditor" },
    offering: {
      title: "Signed source security review",
      description: "A bounded static review delivered as a signed, content-addressed report.",
      category: "software.security.audit",
      tags: ["security", "source-review"],
      deliverable,
    },
    buyerRequirement: requirement,
    pipeline: [
      { kind: "vet-credentials" },
      { kind: "negotiate-rfq", parameters: { maxTurns: 6, turnTimeoutMs: 35_000 } },
      { kind: "commit-agreement" },
      { kind: "pay-dem", parameters: { rail: "demos-native:DEM" } },
      { kind: "deliver-attested-payload" },
    ],
    pricing: { kind: "negotiable", bandCenter: { amount: "1", currency: "DEM", unit: "per-audit" }, minPct: 0, maxPct: 900 },
    acceptedRails: [{ railId: "demos-native:DEM", railVersion: 1 }],
    terms: { deadlineSecAfterCommit: 300, cancellationPolicy: "pre-commit", transcriptDisclosurePolicy: "none" },
    validity: { notBefore: 1_779_999_000_000, notAfter: 1_780_086_400_000 },
  };
  const listing = await signListing(unsignedListing, sellerParty);
  const listingVerdict = await verifyListing(listing, { now: 1_780_000_000_001, ...cryptoDeps });
  assert.equal(listingVerdict.ok, true, listingVerdict.reason);

  const buyerNonce = randomBytes(16).toString("hex");
  const sellerNonce = randomBytes(16).toString("hex");
  const buyerBundle = await createIdentityBundle(buyerParty, { sessionNonce: buyerNonce, presentedAt: 1_780_000_000_010 });
  const sellerBundle = await createIdentityBundle(sellerParty, { sessionNonce: sellerNonce, presentedAt: 1_780_000_000_011 });
  assert.equal((await verifyIdentityBundle(buyerBundle, { expectedNonce: buyerNonce, ...cryptoDeps })).ok, true);
  assert.equal((await verifyIdentityBundle(sellerBundle, { expectedNonce: sellerNonce, ...cryptoDeps })).ok, true);

  const jobId = "dacs-profile-test-1";
  const buyerVet = await createEmptyVetRecord(sellerParty, { jobId, bundle: buyerBundle, requirement, generatedAt: 1_780_000_000_020 });
  const sellerVet = await createEmptyVetRecord(buyerParty, { jobId, bundle: sellerBundle, requirement, generatedAt: 1_780_000_000_021 });
  assert.equal(await verifyVetRecord(buyerVet, { jobId, bundle: buyerBundle, requirement, verifier: seller.did, ...cryptoDeps }), true);
  assert.equal(await verifyVetRecord(sellerVet, { jobId, bundle: sellerBundle, requirement, verifier: buyer.did, ...cryptoDeps }), true);
  const buyerVetRef = attestationRef("stor-buyer-vet", buyerVet, seller.did);
  const sellerVetRef = attestationRef("stor-seller-vet", sellerVet, buyer.did);

  let agreement: AgreementDocument = {
    agreementVersion: "1",
    jobId,
    listingRef: listingRef(listing),
    parties: [
      { role: "buyer", bundleHash: standardHash(buyerBundle, ["presentation"]), primaryClaim: buyer.did, vetRecordRef: buyerVetRef },
      { role: "seller", bundleHash: standardHash(sellerBundle, ["presentation"]), primaryClaim: seller.did, vetRecordRef: sellerVetRef },
    ],
    terms: {
      deliverable: deliverableRef(deliverable),
      price: { amount: "1", currency: "DEM", unit: "per-audit" },
      rail: { railId: "demos-native:DEM", railVersion: 1 },
      deadline: 1_780_000_300_030,
      additionalTerms: { auditTier: "quick", auditDeadline: "standard" },
    },
    derivedFromPattern: "rfq",
    derivedFromChannel: { subnet: "unique-channel-1", lastMessageHash: "a".repeat(64) },
    generatedAt: 1_780_000_000_030,
    signatures: [],
  };
  agreement = await addAgreementSignature(agreement, sellerParty);
  agreement = await addAgreementSignature(agreement, buyerParty);
  const agreementVerdict = await verifyAgreement(agreement, listing, cryptoDeps);
  assert.equal(agreementVerdict.ok, true, agreementVerdict.reason);

  const commitment = await createCommitment(buyerParty, agreement, 1_780_000_000_040);
  assert.equal(await verifyCommitment(commitment, agreement, listing, cryptoDeps), true);

  const payment = await signSettlementEvidence({
    evidenceVersion: "1",
    jobId,
    phase: "pay-dem",
    outcome: "success",
    paymentTxRefs: [{ kind: "demos", txHash: "b".repeat(64), blockNumber: 91 }],
    paymentAmount: { amount: "1", currency: "DEM", unit: "per-audit" },
    settlementFinality: { model: "bft-final", finalityObservedAt: 1_780_000_000_050 },
    observedAt: 1_780_000_000_050,
  }, buyerParty);
  assert.equal(baseUnits(payment.paymentAmount!.amount, 9), "1000000000");
  const paymentVerdict = await verifyEvidence(payment, {
    orchestrator: buyer.did,
    agreement,
    railType: "demos-native",
    railId: "demos-native:DEM",
    ...cryptoDeps,
  });
  assert.equal(paymentVerdict.ok, true, paymentVerdict.reasons.join("; "));

  const delivery = await signSettlementEvidence({
    evidenceVersion: "1",
    jobId,
    phase: "deliver-attested-payload",
    outcome: "success",
    deliverableContentHash: "c".repeat(64),
    deliverableAnchor: { kind: "storage-program", locator: "stor-deliverable" },
    attestationRef: { anchor: { kind: "storage-program", locator: "stor-report-attestation" }, contentHash: "d".repeat(64), signer: seller.did },
    observedAt: 1_780_000_000_060,
  }, sellerParty);
  const deliveryVerdict = await verifyEvidence(delivery, {
    orchestrator: seller.did,
    agreement,
    railType: "demos-native",
    railId: "demos-native:DEM",
    ...cryptoDeps,
  });
  assert.equal(deliveryVerdict.ok, true, deliveryVerdict.reasons.join("; "));

  const body: AttestationBundle = {
    bundleVersion: "1",
    jobId,
    outcome: "completed",
    anchoredByRole: "buyer",
    listingRef: listingRef(listing),
    agreementRef: attestationRef("stor-agreement", agreement),
    parties: [
      { role: "buyer", bundleHash: standardHash(buyerBundle, ["presentation"]), primaryClaim: buyer.did },
      { role: "seller", bundleHash: standardHash(sellerBundle, ["presentation"]), primaryClaim: seller.did },
    ],
    phaseSummary: [
      { index: 0, kind: "vet-credentials", outcome: "ok", attestationRef: buyerVetRef },
      { index: 1, kind: "negotiate-rfq", outcome: "ok" },
      { index: 2, kind: "commit-agreement", outcome: "ok", attestationRef: attestationRef("stor-commitment", commitment, buyer.did) },
      { index: 3, kind: "pay-dem", outcome: "ok", txRefs: payment.paymentTxRefs, attestationRef: attestationRef("stor-payment", payment, buyer.did) },
      { index: 4, kind: "deliver-attested-payload", outcome: "ok", attestationRef: attestationRef("stor-delivery", delivery, seller.did) },
    ],
    vetRecords: [buyerVetRef, sellerVetRef],
    settlementEvidence: [attestationRef("stor-payment", payment, buyer.did), attestationRef("stor-delivery", delivery, seller.did)],
    recipeRegistryVersion: 1,
    railRegistryVersion: 1,
    finalisedAt: 1_780_000_000_070,
    signatures: [],
  };
  let signed = await addBundleSignature(body, buyerParty);
  signed = await addBundleSignature(signed, sellerParty);
  return { buyerNonce, buyerBundle, listing, agreement, commitment, payment, delivery, bundle: signed };
}

describe("DACS Standard profile", () => {
  test("builds and verifies one complete Identify→Vet→Negotiate→Settle→Verify artifact chain", async () => {
    const { bundle } = await fixture();
    const buyerCopy = { ...bundle, anchoredByRole: "buyer" as const };
    const sellerCopy = { ...bundle, anchoredByRole: "seller" as const };
    assert.equal(bundleHash(buyerCopy), bundleHash(sellerCopy));
    assert.equal(sameCanonicalBundle(buyerCopy, sellerCopy), true);
    assert.deepEqual(await verifyBundle(buyerCopy, { expectedRole: "buyer", ...cryptoDeps }), { ok: true });
    assert.deepEqual(await verifyBundle(sellerCopy, { expectedRole: "seller", ...cryptoDeps }), { ok: true });
  });

  test("fails closed on replay, listing tampering, and a one-signed completed bundle", async () => {
    const { buyerBundle, listing, agreement, commitment, bundle } = await fixture();
    const replay = await verifyIdentityBundle(buyerBundle, { expectedNonce: randomBytes(16).toString("hex"), ...cryptoDeps });
    assert.equal(replay.ok, false);

    const tampered = structuredClone(listing);
    tampered.offering.title = "attacker replacement";
    assert.equal((await verifyListing(tampered, { now: 1_780_000_000_001, ...cryptoDeps })).ok, false);

    const revocation = await createListingRevocation(listing, sellerParty, { revokedAt: 1_780_000_000_002 });
    assert.equal(await verifyScopedListingRevocation(revocation, {
      listingId: listing.listingId,
      listingVersion: listing.listingVersion,
      listingContentHash: standardHash(listing),
      signer: seller.did,
    }, cryptoDeps), true);
    for (const invalid of [
      { ...revocation, listingId: "other-listing" },
      { ...revocation, listingVersion: 2 },
      { ...revocation, listingContentHash: "0".repeat(64) },
      { ...revocation, revokedAt: -1 },
      { ...revocation, signature: { ...revocation.signature, signer: buyer.did } },
      { ...revocation, signature: { ...revocation.signature, value: "invalid" } },
    ]) {
      assert.equal(await verifyScopedListingRevocation(invalid, {
        listingId: listing.listingId,
        listingVersion: listing.listingVersion,
        listingContentHash: standardHash(listing),
        signer: seller.did,
      }, cryptoDeps), false);
    }
    const revoked = await verifyListing(listing, {
      now: 1_780_000_000_003,
      readRevocation: async () => revocation as unknown as Record<string, unknown>,
      ...cryptoDeps,
    });
    assert.equal(revoked.ok, false);
    assert.match(revoked.reason ?? "", /revoked/);

    const replayedMarker = { ...revocation, listingContentHash: "0".repeat(64) };
    const invalidMarker = await verifyListing(listing, {
      now: 1_780_000_000_003,
      readRevocation: async () => replayedMarker as unknown as Record<string, unknown>,
      ...cryptoDeps,
    });
    assert.equal(invalidMarker.ok, false);
    assert.match(invalidMarker.reason ?? "", /invalid marker/);

    const legacyMarker = await createScopedListingRevocation({
      listingId: "oracle-data",
      listingVersion: 1,
      listingContentHash: "A".repeat(64),
    }, sellerParty, {
      revokedAt: 1_780_000_000_004,
      reason: "Superseded by the structured current listing",
    });
    assert.equal(legacyMarker.listingContentHash, "a".repeat(64));
    assert.equal(legacyMarker.signature.signer, seller.did);
    await assert.rejects(
      createScopedListingRevocation({
        listingId: "oracle-data",
        listingVersion: 1,
        listingContentHash: "not-a-hash",
      }, sellerParty),
      /sha256 hex/,
    );

    assert.equal(await verifyCommitment(commitment, agreement, listing, {
      ...cryptoDeps,
      anchoredAt: listing.validity.notAfter! + 1,
    }), false, "a listing expiring between discovery and the SR-2 commit block must fail post-anchor");

    const oneSigned = { ...bundle, signatures: bundle.signatures.filter((signature) => signature.party === buyer.did) };
    const verdict = await verifyBundle(oneSigned, cryptoDeps);
    assert.equal(verdict.ok, false);
    assert.match(verdict.reason ?? "", /seller bundle signature/);
  });

  test("applies CD-1 and the §8.5.2 half-up negotiable band exactly", async () => {
    const base = await fixture();
    const { signature: _signature, ...listingBody } = structuredClone(base.listing);
    listingBody.pricing = {
      kind: "negotiable",
      bandCenter: { amount: "1.23", currency: "DEM", unit: "per-audit" },
      minPct: 10,
      maxPct: 10,
    };
    const listing = await signListing(listingBody, sellerParty);
    const makeAgreement = async (amount: string, pattern: "rfq" | "fixed-price" = "rfq") => {
      let agreement: AgreementDocument = {
        ...structuredClone(base.agreement),
        listingRef: listingRef(listing),
        terms: { ...structuredClone(base.agreement.terms), price: { amount, currency: "DEM", unit: "per-audit" } },
        derivedFromPattern: pattern,
        signatures: [],
      };
      agreement = await addAgreementSignature(agreement, sellerParty);
      return addAgreementSignature(agreement, buyerParty);
    };

    // 1.23 × 90% = 1.107, which rounds half-up to 1.11 at center scale 2.
    assert.match((await verifyAgreement(await makeAgreement("1.108"), listing, cryptoDeps)).reason ?? "", /rounded listing band/);
    assert.equal((await verifyAgreement(await makeAgreement("1.11"), listing, cryptoDeps)).ok, true);
    assert.match((await verifyAgreement(await makeAgreement("01.11"), listing, cryptoDeps)).reason ?? "", /CD-1/);

    const { signature: _fixedSignature, ...fixedBody } = structuredClone(listing);
    fixedBody.pipeline = fixedBody.pipeline.map((step) => step.kind === "negotiate-rfq" ? { kind: "negotiate-fixed-price" as const } : step);
    const fixedListing = await signListing(fixedBody, sellerParty);
    const fixedAgreement = async (amount: string) => {
      let agreement: AgreementDocument = {
        ...await makeAgreement(amount, "fixed-price"),
        listingRef: listingRef(fixedListing),
        signatures: [],
      };
      agreement = await addAgreementSignature(agreement, sellerParty);
      return addAgreementSignature(agreement, buyerParty);
    };
    assert.match((await verifyAgreement(await fixedAgreement("1.2"), fixedListing, cryptoDeps)).reason ?? "", /must equal.*center/);
    assert.equal((await verifyAgreement(await fixedAgreement("1.23"), fixedListing, cryptoDeps)).ok, true);
  });

  test("verifies auto-accept only with a live instance signature bound to the exact agreement and template", async () => {
    const base = await fixture();
    const { signature: _signature, ...listingBody } = structuredClone(base.listing);
    listingBody.pipeline = [
      { kind: "vet-credentials" },
      { kind: "negotiate-fixed-price" },
      { kind: "commit-agreement" },
      { kind: "pay-dem", parameters: { rail: "demos-native:DEM" } },
      { kind: "deliver-attested-payload" },
    ];
    listingBody.pricing = { kind: "fixed", price: { amount: "1", currency: "DEM", unit: "per-audit" } };
    listingBody.terms = { ...listingBody.terms, acceptanceModel: "auto-accept" };
    const listing = await signListing(listingBody, sellerParty);
    assert.equal((await verifyListing(listing, { now: 1_780_000_000_001, ...cryptoDeps })).ok, true);

    const commitment = await createAutoAcceptCommitment(
      listing,
      sellerParty,
      1_780_000_100_000,
      1_780_000_000_001,
    );
    assert.equal((await verifyAutoAcceptCommitment(commitment, listing, {
      now: 1_780_000_000_002,
      ...cryptoDeps,
    })).ok, true);

    let agreement: AgreementDocument = {
      ...structuredClone(base.agreement),
      listingRef: listingRef(listing),
      derivedFromPattern: "fixed-price",
      signatures: [],
    };
    delete agreement.derivedFromChannel;
    agreement = await addAgreementSignature(agreement, buyerParty);
    agreement = await addAutoAcceptInstanceSignature(agreement, commitment, sellerParty);

    const accepted = await verifyAgreement(agreement, listing, {
      autoAcceptCommitment: commitment,
      now: 1_780_000_000_003,
      committedAt: 1_780_000_000_004,
      ...cryptoDeps,
    });
    assert.equal(accepted.ok, true, accepted.reason);

    const confirmedAfterWallClockExpiry = await verifyAgreement(agreement, listing, {
      autoAcceptCommitment: commitment,
      now: commitment.validUntil + 10_000,
      committedAt: commitment.validUntil,
      ...cryptoDeps,
    });
    assert.equal(confirmedAfterWallClockExpiry.ok, true, confirmedAfterWallClockExpiry.reason);

    const missingTemplate = await verifyAgreement(agreement, listing, cryptoDeps);
    assert.equal(missingTemplate.ok, false);
    assert.match(missingTemplate.reason ?? "", /commitment is required/);

    let differentAgreement = {
      ...structuredClone(agreement),
      jobId: "different-job",
      signatures: agreement.signatures.filter((signature) => signature.party === seller.did),
    };
    differentAgreement = await addAgreementSignature(differentAgreement, buyerParty);
    const replayed = await verifyAgreement(differentAgreement, listing, {
      autoAcceptCommitment: commitment,
      now: 1_780_000_000_003,
      ...cryptoDeps,
    });
    assert.equal(replayed.ok, false);
    assert.match(replayed.reason ?? "", /instance signature/);

    const expiredAtCommit = await verifyAgreement(agreement, listing, {
      autoAcceptCommitment: commitment,
      now: 1_780_000_000_003,
      committedAt: commitment.validUntil + 1,
      ...cryptoDeps,
    });
    assert.equal(expiredAtCommit.ok, false);
    assert.match(expiredAtCommit.reason ?? "", /instance signature/);
  });
});
