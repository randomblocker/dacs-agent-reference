import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import { signedBytes } from "@kynesyslabs/dacs";
import { encodeFunctionData, parseAbi } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { dacsX402AuthorizationNonce } from "../../sdk/src/rails/x402.js";
import { makeIdentity } from "../../src/identity.js";
import { verifyX402Authorization } from "../gateway/x402-verifier.js";
import { createIdentityBundle, standardHash, standardPaymentAnchorName, type AgreementDocument } from "./standard-profile.js";
import {
  BASE_SEPOLIA_NETWORK,
  BASE_SEPOLIA_USDC,
  X402_RAIL_ID,
  loadX402RailDefinition,
  verifyX402IdentityBinding,
  x402GovernanceDisclosure,
  x402IdentityBinding,
  x402IdentityMessage,
  x402IdentityMetadata,
  x402RailRef,
  x402SdkDescriptor,
  type X402RailDefinition,
} from "./x402-production.js";

const KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784e7bf4f2ff80";
const OTHER = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const PAYEE = "0x1111111111111111111111111111111111111111";

function agreement(payer: string): AgreementDocument {
  return {
    agreementVersion: "1",
    jobId: "job-x402-identity-1",
    listingRef: { listingId: "oracle-data-x402", version: 1, contentHash: "a".repeat(64) },
    parties: [],
    terms: {
      deliverable: { deliverableType: "attested-payload", hash: "b".repeat(64) },
      price: { amount: "0.01", currency: "USDC" },
      rail: x402RailRef({ payTo: PAYEE, resourceBase: "https://seller.example/x402" }),
      deadline: Date.now() + 60_000,
      additionalTerms: {
        x402: {
          payer,
          resource: "https://seller.example/x402/job-x402-identity-1",
          protocolVersion: "2",
          phaseIndex: 3,
        },
      },
    },
    derivedFromPattern: "fixed-price",
    generatedAt: Date.now(),
    signatures: [],
  };
}

describe("production DACS pay-x402 bindings", () => {
  test("uses the canonical rail ref and keeps static chain/asset config out of the per-deal ref", () => {
    const rail = x402RailRef({ payTo: PAYEE, resourceBase: "https://seller.example/x402" });
    assert.equal(rail.railId, X402_RAIL_ID);
    assert.equal(rail.railVersion, 1);
    assert.deepEqual(Object.keys(rail.parameters ?? {}).sort(), ["payTo", "protocolVersion", "resourceBase", "scheme"]);
    assert.equal(
      Buffer.from(standardPaymentAnchorName("job-1", X402_RAIL_ID, 3), "base64url").toString("utf8"),
      "dacs4:payment:job-1:x402%3Adefault:3",
    );
  });

  test("loads only a full steward-signed PA-2 RailDefinition and adapts it to SDK dispatch", async () => {
    const steward = makeIdentity("steward", 91);
    const body: Omit<X402RailDefinition, "signature"> = {
      railVersion: 1,
      railId: X402_RAIL_ID,
      railType: "x402",
      asset: { kind: "erc20", chainId: 84532, contract: BASE_SEPOLIA_USDC, symbol: "USDC", decimals: 6 },
      network: { kind: "x402-resource", resourceBaseUrl: "https://seller.example/x402" },
      phaseHandler: "pay-x402",
      parameters: { scheme: "exact", protocolVersion: "2" },
      availability: "live",
      governance: { proposedBy: steward.did, acceptedAt: 1, anchoring: "single-signer" },
    };
    const signature = Buffer.from(await steward.sign(signedBytes("dacs-rail:v1:", standardHash(body, [])))).toString("base64url");
    const rail: X402RailDefinition = {
      ...body,
      signature: { algorithm: "ed25519", signer: steward.did, value: signature },
    };
    const dir = mkdtempSync(join(tmpdir(), "dacs-x402-rail-"));
    const path = join(dir, "registry.json");
    try {
      writeFileSync(path, JSON.stringify({ registryId: "dacs4:registry:v0.1", entries: [rail] }));
      const loaded = loadX402RailDefinition(path, steward.did.slice(-64));
      assert.deepEqual(x402SdkDescriptor(loaded), {
        id: X402_RAIL_ID,
        kind: "x402",
        availability: "live",
        params: {
          tokenAddress: BASE_SEPOLIA_USDC,
          network: BASE_SEPOLIA_NETWORK,
          protocolVersion: "2",
          railVersion: 1,
        },
      });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("accepts an explicitly disclosed operator-provisional registry only in provisional trust mode", async () => {
    const operator = makeIdentity("demo-operator", 92);
    const body: Omit<X402RailDefinition, "signature"> = {
      railVersion: 1,
      railId: X402_RAIL_ID,
      railType: "x402",
      asset: { kind: "erc20", chainId: 84532, contract: BASE_SEPOLIA_USDC, symbol: "USDC", decimals: 6 },
      network: { kind: "x402-resource", resourceBaseUrl: "https://butler.agentcommerce.network/demo/x402" },
      phaseHandler: "pay-x402",
      parameters: { scheme: "exact", protocolVersion: "2" },
      availability: "live",
      governance: {
        proposedBy: operator.did,
        acceptedAt: 1,
        anchoring: "single-signer",
        authorityScope: "operator-provisional",
        disclosure: "https://github.com/DACS-Agent-commerce/DACS-Standard/issues/274",
      },
    };
    const signature = Buffer.from(await operator.sign(signedBytes("dacs-rail:v1:", standardHash(body, [])))).toString("base64url");
    const rail: X402RailDefinition = { ...body, signature: { algorithm: "ed25519", signer: operator.did, value: signature } };
    const dir = mkdtempSync(join(tmpdir(), "dacs-x402-provisional-"));
    const path = join(dir, "registry.json");
    try {
      writeFileSync(path, JSON.stringify({ registryId: "dacs4:registry:v0.1", entries: [rail] }));
      assert.throws(
        () => loadX402RailDefinition(path, operator.did.slice(-64)),
        /does not match configured trust mode/,
      );
      const loaded = loadX402RailDefinition(path, operator.did.slice(-64), "operator-provisional");
      assert.deepEqual(x402GovernanceDisclosure(loaded), {
        status: "operator-provisional",
        conformantAuthority: false,
        signer: operator.did,
        disclosure: "https://github.com/DACS-Agent-commerce/DACS-Standard/issues/274",
      });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("DACS IdentityBundle and Base account prove the same payment-account binding", async () => {
    const dacs = makeIdentity("buyer", 43);
    const account = privateKeyToAccount(KEY);
    const message = x402IdentityMessage(dacs.did, account.address);
    const signature = await account.signMessage({ message });
    const metadata = x402IdentityMetadata(x402IdentityBinding({ dacsIdentity: dacs.did, account: account.address, signature }));
    const bundle = await createIdentityBundle({ primaryClaim: dacs.did, sign: dacs.sign }, { metadata });

    const verified = await verifyX402IdentityBinding(bundle, account.address);
    assert.equal(verified.account.toLowerCase(), account.address.toLowerCase());
    await assert.rejects(
      verifyX402IdentityBinding(bundle, privateKeyToAccount(OTHER).address),
      /no linked payment account/,
    );
  });

  test("EIP-3009 nonce is deterministic and the seller re-derives the job/phase binding", async () => {
    const payer = privateKeyToAccount(KEY).address;
    const agreed = agreement(payer);
    const nonce = await dacsX402AuthorizationNonce({
      jobId: agreed.jobId,
      phaseIndex: 3,
      payer,
      payee: PAYEE,
      amount: "10000",
      asset: BASE_SEPOLIA_USDC,
      network: BASE_SEPOLIA_NETWORK,
    });
    const abi = parseAbi([
      "function transferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce,uint8 v,bytes32 r,bytes32 s)",
    ]);
    const input = encodeFunctionData({
      abi,
      functionName: "transferWithAuthorization",
      args: [payer, PAYEE, 10_000n, 0n, 9999999999n, nonce, 27, `0x${"1".repeat(64)}`, `0x${"2".repeat(64)}`],
    });
    assert.deepEqual(
      await verifyX402Authorization(agreed, { to: BASE_SEPOLIA_USDC, input }),
      { ok: true },
    );

    const wrongNonce = await dacsX402AuthorizationNonce({
      jobId: "another-job",
      phaseIndex: 3,
      payer,
      payee: PAYEE,
      amount: "10000",
      asset: BASE_SEPOLIA_USDC,
      network: BASE_SEPOLIA_NETWORK,
    });
    assert.notEqual(nonce, wrongNonce);
  });
});
