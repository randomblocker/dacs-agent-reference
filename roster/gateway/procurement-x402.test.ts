import assert from "node:assert/strict";
import type { IncomingMessage } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  BASE_SEPOLIA_USDC,
  X402_RAIL_ID,
  type X402RailDefinition,
} from "../dacs/x402-production.js";
import { ProcurementX402 } from "./procurement-x402.js";

const RESOURCE_BASE = "https://butler.example/demo/x402";

function rail(): X402RailDefinition {
  return {
    railVersion: 1,
    railId: X402_RAIL_ID,
    railType: "x402",
    asset: {
      kind: "erc20",
      chainId: 84532,
      contract: BASE_SEPOLIA_USDC,
      symbol: "USDC",
      decimals: 6,
    },
    network: { kind: "x402-resource", resourceBaseUrl: RESOURCE_BASE },
    phaseHandler: "pay-x402",
    parameters: { scheme: "exact", protocolVersion: "2" },
    availability: "live",
    governance: {
      proposedBy: `did:demos:agent:${"1".repeat(64)}`,
      acceptedAt: 1,
      anchoring: "single-signer",
      authorityScope: "operator-provisional",
      disclosure: "https://example.test/governance",
    },
    signature: {
      algorithm: "ed25519",
      signer: `did:demos:agent:${"1".repeat(64)}`,
      value: "test-only",
    },
  };
}

test("x402 base URL is reachable machine discovery while per-job paths remain intent scoped", async () => {
  const dir = mkdtempSync(join(tmpdir(), "dacs-x402-discovery-"));
  try {
    const x402 = new ProcurementX402({
      buyerPrivateKey: `0x${"2".repeat(64)}`,
      publicResourceBase: RESOURCE_BASE,
      internalOrigin: "http://127.0.0.1:8402",
      statePath: join(dir, "state.json"),
      railDefinition: rail(),
    });
    assert.equal(x402.matches("/demo/x402"), true);
    assert.equal(x402.matches("/demo/x402/job-1"), true);
    assert.equal(x402.matches("/demo/x402/job-1/extra"), false);

    const response = await x402.handle({
      method: "GET",
      url: "/demo/x402",
      headers: {},
    } as IncomingMessage);
    assert.equal(response.status, 200);
    assert.deepEqual(response.body, {
      kind: "dacs-intent-scoped-x402-resource",
      resourceTemplate: "https://butler.example/demo/x402/{jobId}",
      createIntent: {
        method: "POST",
        href: "https://butler.example/demo/procurement",
      },
      executionControl: {
        model: "server-orchestrated",
        interactiveConfirmation: false,
      },
      buyerControl: {
        model: "gateway-custodied-demo",
        acceptsExternalDacsIdentity: false,
        acceptsExternalPaymentSigner: false,
      },
      note: "A signed agreement creates the job-specific x402 resource; the base URL is discovery, not a reusable quote.",
    });

    const missingIntent = await x402.handle({
      method: "GET",
      url: "/demo/x402/unknown",
      headers: {},
    } as IncomingMessage);
    assert.equal(missingIntent.status, 404);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
