/**
 * ReviewBot's x402 paywall — the SELLER half of the x402 rail, which the SDK
 * doesn't have (FINDINGS F3: the SDK ships only the buyer-side dance). This is
 * the missing piece built app-side: an HTTP endpoint where the *review job is
 * the paywalled resource*.
 *
 *   GET /review?jobId&repo&pr
 *     → 402 with payment requirements (USDC on Base Sepolia, payTo =
 *       ReviewBot's CCI-linked EVM wallet)
 *     → buyer retries with X-PAYMENT (EIP-3009 authorization, gasless)
 *     → we verify + settle via the hosted facilitator (it submits on-chain)
 *     → ReviewBot DOES THE WORK (posts the review on GitHub, anchors the
 *       DACS-X delivery attestation)
 *     → 200 with the review + X-PAYMENT-RESPONSE (settlement tx hash)
 *
 * Pay-and-deliver genuinely coupled — the deliverable exists on GitHub before
 * the paywall responds, and the buyer walks away with the settlement receipt.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

import {
  HTTPFacilitatorClient,
  x402HTTPResourceServer,
  x402ResourceServer,
  type HTTPAdapter,
} from "../../sdk/node_modules/@x402/core/dist/esm/server/index.mjs";
import { ExactEvmScheme } from "../../sdk/node_modules/@x402/evm/dist/esm/exact/server/index.mjs";

import type { SellerAgent } from "../agents/seller.js";

export interface PaywallConfig {
  port: number;
  /** ReviewBot's EVM payout address (its CCI-linked wallet). */
  payTo: string;
  /** CAIP-2 network (Base Sepolia). */
  network: `${string}:${string}`;
  /** Token contract (Base Sepolia USDC). */
  asset: string;
  /** Integer base-unit price (USDC has 6 decimals). */
  amount: string;
  facilitatorUrl: string;
}

function adapterFor(req: IncomingMessage, url: URL): HTTPAdapter {
  return {
    getHeader: (name) => (req.headers[name.toLowerCase()] as string | undefined),
    getMethod: () => req.method ?? "GET",
    getPath: () => url.pathname,
    getUrl: () => url.toString(),
    getAcceptHeader: () => (req.headers.accept as string) ?? "*/*",
    getUserAgent: () => (req.headers["user-agent"] as string) ?? "",
    getQueryParams: () => Object.fromEntries(url.searchParams.entries()),
    getQueryParam: (name) => url.searchParams.get(name) ?? undefined,
  };
}

export async function startPaywall(
  cfg: PaywallConfig,
  reviewBot: SellerAgent,
): Promise<{ server: Server; url: string; close: () => Promise<void> }> {
  const facilitator = new HTTPFacilitatorClient({ url: cfg.facilitatorUrl });
  const core = new x402ResourceServer(facilitator).register(
    cfg.network,
    new ExactEvmScheme(),
  );
  const httpServer = new x402HTTPResourceServer(core, {
    "GET /review": {
      accepts: {
        scheme: "exact",
        network: cfg.network,
        payTo: cfg.payTo,
        price: { amount: cfg.amount, asset: cfg.asset },
        maxTimeoutSeconds: 120,
        // EIP-712 domain of the token contract — required for the buyer's
        // EIP-3009 transferWithAuthorization signature (Circle USDC = USDC/2).
        extra: { name: "USDC", version: "2" },
      },
      description: "LLM code review, delivered as a GitHub PR review (DACS pay-x402)",
      mimeType: "application/json",
    },
  });
  await httpServer.initialize();

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async () => {
      const url = new URL(req.url ?? "/", `http://127.0.0.1:${cfg.port}`);
      if (url.pathname !== "/review") {
        res.writeHead(404).end();
        return;
      }
      const context = {
        adapter: adapterFor(req, url),
        path: url.pathname,
        method: req.method ?? "GET",
        paymentHeader: (req.headers["x-payment"] as string) ?? undefined,
        routePattern: "GET /review",
      };
      const result = await httpServer.processHTTPRequest(context);

      if (result.type === "payment-error") {
        const { status, headers, body } = result.response;
        res.writeHead(status, { "content-type": "application/json", ...headers });
        res.end(typeof body === "string" ? body : JSON.stringify(body ?? {}));
        return;
      }
      if (result.type === "no-payment-required") {
        res.writeHead(500).end(JSON.stringify({ error: "route unexpectedly unprotected" }));
        return;
      }

      // Payment verified — DO THE WORK before settling + responding.
      const jobId = url.searchParams.get("jobId") ?? "";
      const repo = url.searchParams.get("repo") ?? "";
      const pullNumber = Number(url.searchParams.get("pr") ?? "0");
      let delivered: { attestationRef: string; reviewBody: string };
      try {
        delivered = await reviewBot.deliverReview(jobId, { repo, pullNumber });
      } catch (e) {
        // Work failed — cancel the verified (unsettled) payment and report.
        await result.cancellationDispatcher?.cancel?.({ reason: "other" } as never).catch(() => {});
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: `review failed: ${(e as Error).message}` }));
        return;
      }

      const settle = await httpServer.processSettlement(
        result.paymentPayload,
        result.paymentRequirements,
        result.declaredExtensions,
        { request: context },
      );
      if (!settle.success) {
        res.writeHead(502, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: `settlement failed: ${settle.errorReason}` }));
        return;
      }
      res.writeHead(200, { "content-type": "application/json", ...(settle.headers ?? {}) });
      res.end(
        JSON.stringify({
          jobId,
          review: delivered.reviewBody,
          attestationRef: delivered.attestationRef,
        }),
      );
    })().catch((e) => {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: (e as Error).message }));
    });
  });

  await new Promise<void>((resolve) => server.listen(cfg.port, "127.0.0.1", resolve));
  return {
    server,
    url: `http://127.0.0.1:${cfg.port}/review`,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}
