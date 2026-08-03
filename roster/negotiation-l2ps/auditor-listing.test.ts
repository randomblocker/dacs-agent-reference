import { test } from "node:test";
import assert from "node:assert/strict";
import { makeIdentity } from "../../src/identity.js";
import { MemorySubstrate } from "../../src/substrate/memory.js";
import { auditNegotiatorStandardListingSpec } from "../dacs/wire/audit-negotiator.js";
import { standardAnchorName } from "../dacs/standard-profile.js";
import { ensureAuditorListing, isCurrentAuditorListing } from "./auditor-listing.js";

const RESEARCHER_GITHUB = "dacs-security-researcher";

test("Auditor publishes its DACS-1 listing and reuses the deterministic slot", async () => {
  const id = makeIdentity("persistent-auditor", 31);
  const sub = new MemorySubstrate();

  const first = await ensureAuditorListing(id, sub, RESEARCHER_GITHUB);
  assert.equal(first.published, true);
  const listing = await sub.read(first.ref);
  assert.ok(isCurrentAuditorListing(listing, id, RESEARCHER_GITHUB));
  assert.match(JSON.stringify(listing), /^[\x00-\x7F]*$/, "Demos storage listing must be ASCII-only");
  assert.equal(listing?.listingId, "audit-negotiator");
  assert.equal(listing?.listingVersion, 3);
  assert.deepEqual((listing?.pipeline as Array<{ kind: string }>).map((step) => step.kind), [
    "vet-credentials", "negotiate-rfq", "commit-agreement", "pay-dem", "deliver-attested-payload",
  ]);

  const second = await ensureAuditorListing(id, sub, RESEARCHER_GITHUB);
  assert.deepEqual(second, { ref: first.ref, published: false });
});

test("Auditor refuses to overwrite a conflicting immutable listing version", async () => {
  const id = makeIdentity("persistent-auditor-update", 32);
  const sub = new MemorySubstrate();
  const spec = auditNegotiatorStandardListingSpec({
    researcherGithub: RESEARCHER_GITHUB,
    operatorClaim: id.did,
  });
  const slot = standardAnchorName("listing", [id.did, spec.serviceId, String(spec.listingVersion)]);
  await sub.anchor(slot, { dacsVersion: "1", listingId: spec.serviceId, listingVersion: 1, offering: { title: "stale name" } });

  await assert.rejects(() => ensureAuditorListing(id, sub, RESEARCHER_GITHUB), /invalid artifact|immutable/);
});
