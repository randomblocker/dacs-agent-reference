import { describe, test } from "node:test";
import assert from "node:assert/strict";
import type { AnchorAcceptance, SubstratePort } from "../../src/ports.js";
import { standardHash } from "../dacs/standard-profile.js";
import { verifyAnchoredVet } from "./standard-session.js";

function acceptedFixture() {
  const record = { recordVersion: "1", decision: "pass", signatures: [] };
  const contentHash = standardHash(record, []);
  const acceptance: AnchorAcceptance = {
    address: "stor-" + "a".repeat(40),
    txRef: "b".repeat(64),
    contentHash,
    status: "accepted",
    acceptedAt: Date.now(),
  };
  return {
    record,
    acceptance,
    input: {
      jobId: "job-accepted-vet",
      bundle: { presentedBy: "did:demos:agent:" + "c".repeat(64) },
      requirement: {},
      verifier: "did:demos:agent:" + "d".repeat(64),
      record,
      ref: {
        anchor: { kind: "storage-program", locator: acceptance.address },
        contentHash: standardHash(record),
        signer: "did:demos:agent:" + "d".repeat(64),
      },
      receipt: acceptance,
      verifyRecord: async () => true,
    },
  };
}

describe("accepted Vet verification", () => {
  test("uses the signed transaction acceptance without consulting lagging public projections", async () => {
    const { input } = acceptedFixture();
    let acceptanceChecks = 0;
    let indexReads = 0;
    const sub = {
      async verifyAnchorAcceptance() {
        acceptanceChecks += 1;
        throw new Error("public transaction-status projection has not hydrated");
      },
      async anchorAddressFor() {
        indexReads += 1;
        throw new Error("public owner/name index has not hydrated");
      },
    } as unknown as SubstratePort;

    await verifyAnchoredVet({ sub }, input as never);
    assert.equal(acceptanceChecks, 0);
    assert.equal(indexReads, 0);
  });

  test("fails closed when the accepted address does not bind the signed reference", async () => {
    const { input } = acceptedFixture();
    const sub = {
      async anchorAddressFor() {
        throw new Error("must not be called");
      },
    } as unknown as SubstratePort;

    await assert.rejects(
      () => verifyAnchoredVet({ sub }, {
        ...input,
        receipt: { ...input.receipt, address: "stor-" + "e".repeat(40) },
      } as never),
      /does not bind the declared content/,
    );
  });
});
