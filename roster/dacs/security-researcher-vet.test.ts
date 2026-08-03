import assert from "node:assert/strict";
import test from "node:test";
import { makeIdentity, resolveFromDid, verify } from "../../src/identity.js";
import { createIdentityBundle } from "./standard-profile.js";
import {
  createSecurityResearcherVetRecord,
  securityResearcherRequirement,
  verifySecurityResearcherVetRecord,
  type SecurityResearcherProfile,
} from "./security-researcher-vet.js";

test("Auditor Vet binds key control, exact CCI GitHub identity and prior DACS-5 history", async () => {
  const seller = makeIdentity("security-researcher", 0x61);
  const buyer = makeIdentity("vetting-buyer", 0x62);
  const bundle = await createIdentityBundle(
    { primaryClaim: seller.did, sign: seller.sign },
    { sessionNonce: "ab".repeat(16) },
  );
  const profile: SecurityResearcherProfile = {
    profileVersion: "1",
    github: "dacs-security-researcher",
    operatorClaim: seller.did,
  };
  const record = await createSecurityResearcherVetRecord(
    { primaryClaim: buyer.did, sign: buyer.sign },
    {
      jobId: "vet-job-1",
      bundle,
      profile,
      boundGithub: "DACS-Security-Researcher",
      history: { completedAudits: 7, latestBundleRef: "stor-verified-prior-bundle" },
      generatedAt: 1_790_000_000_000,
    },
  );

  assert.equal(record.overallDecision, "pass");
  assert.equal(record.requirementHash.length, 64);
  assert.equal(
    await verifySecurityResearcherVetRecord(record, {
      jobId: "vet-job-1",
      bundle,
      profile,
      verifier: buyer.did,
      resolvePublicKey: resolveFromDid,
      verify,
    }),
    true,
  );
  assert.deepEqual(
    record.supplementary.map(({ source, signalType, value }) => ({ source, signalType, value })),
    [
      { source: "identity-presentation", signalType: "nonce-bound-key-control", value: "pass" },
      { source: "cci-web2", signalType: "github-control", value: "dacs-security-researcher" },
      { source: "dacs-5", signalType: "verified-completed-audits", value: 7 },
      { source: "dacs-5", signalType: "latest-verified-bundle", value: "stor-verified-prior-bundle" },
    ],
  );
  assert.equal(securityResearcherRequirement(profile).required[0]?.parameters?.github, profile.github);
});

test("Auditor Vet fails closed when the live CCI binding is absent or different", async () => {
  const seller = makeIdentity("unbound-researcher", 0x63);
  const buyer = makeIdentity("strict-vetter", 0x64);
  const bundle = await createIdentityBundle(
    { primaryClaim: seller.did, sign: seller.sign },
    { sessionNonce: "cd".repeat(16) },
  );
  const profile: SecurityResearcherProfile = {
    profileVersion: "1",
    github: "expected-researcher",
    operatorClaim: seller.did,
  };
  for (const boundGithub of [null, "different-researcher"]) {
    const record = await createSecurityResearcherVetRecord(
      { primaryClaim: buyer.did, sign: buyer.sign },
      { jobId: `vet-${boundGithub ?? "missing"}`, bundle, profile, boundGithub },
    );
    assert.equal(record.overallDecision, "fail");
    assert.equal(
      await verifySecurityResearcherVetRecord(record, {
        jobId: `vet-${boundGithub ?? "missing"}`,
        bundle,
        profile,
        verifier: buyer.did,
        resolvePublicKey: resolveFromDid,
        verify,
      }),
      false,
    );
  }
});

test("Auditor Vet rejects post-signature evidence tampering", async () => {
  const seller = makeIdentity("history-researcher", 0x65);
  const buyer = makeIdentity("history-vetter", 0x66);
  const bundle = await createIdentityBundle(
    { primaryClaim: seller.did, sign: seller.sign },
    { sessionNonce: "ef".repeat(16) },
  );
  const profile: SecurityResearcherProfile = {
    profileVersion: "1",
    github: "history-researcher",
    operatorClaim: seller.did,
  };
  const record = await createSecurityResearcherVetRecord(
    { primaryClaim: buyer.did, sign: buyer.sign },
    { jobId: "vet-history", bundle, profile, boundGithub: profile.github, history: { completedAudits: 1 } },
  );
  record.supplementary.find((signal) => signal.signalType === "verified-completed-audits")!.value = 999;
  assert.equal(
    await verifySecurityResearcherVetRecord(record, {
      jobId: "vet-history",
      bundle,
      profile,
      verifier: buyer.did,
      resolvePublicKey: resolveFromDid,
      verify,
    }),
    false,
  );
});
