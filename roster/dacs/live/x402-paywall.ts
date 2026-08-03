/**
 * Generalized LIVE x402 paywall — the SELLER half of the x402 rail against the
 * REAL hosted facilitator (Base Sepolia USDC), generalized from ReviewBot's
 * review-specific `src/live/paywall.ts`.
 *
 * Where the reference paywall hard-wired `GET /review` + `deliverReview`, this
 * one takes a configurable `route` and an injected `deliver(jobId, params)`
 * work callback — so ANY DACS service (here: the oracle desk) can be the
 * paywalled resource. It builds the x402 resource server from `@x402/core`
 * (`HTTPFacilitatorClient`, `x402ResourceServer`, `x402HTTPResourceServer`) +
 * `@x402/evm` (`ExactEvmScheme`), emits a real 402, and preserves the
 * load-bearing order:
 *
 *   verify(payment)  →  DO THE WORK  →  settle(on-chain)  →  200
 *
 * with cancel-on-work-failure (a verified-but-unsettled payment is released if
 * the work throws, so USDC never moves for undelivered work). This is a REAL
 * settlement path: the hosted facilitator submits the EIP-3009 transfer on
 * Base Sepolia and returns the settlement tx hash in X-PAYMENT-RESPONSE.
 *
 * This file does NOT touch the mock paywall (`roster/dacs/paywall.ts`) — the
 * mock demos/tests keep running on the zero-chain MockFacilitator.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

import {
  HTTPFacilitatorClient,
  x402HTTPResourceServer,
  x402ResourceServer,
  type HTTPAdapter,
} from "../../../sdk/node_modules/@x402/core/dist/esm/server/index.mjs";
import { ExactEvmScheme } from "../../../sdk/node_modules/@x402/evm/dist/esm/exact/server/index.mjs";

/** What the paywall's work callback hands back for the 200 response body. */
export interface X402PaywallDeliverResult {
  result: unknown;
  attestationRef?: string;
  [k: string]: unknown;
}

export interface X402PaywallConfig {
  /** Listen port (127.0.0.1). */
  port: number;
  /** The single paywalled route, e.g. "/oracle". */
  route: string;
  /** The seller's EVM payout address (receives the USDC). */
  payTo: string;
  /** CAIP-2 network (Base Sepolia = "eip155:84532"). */
  network: `${string}:${string}`;
  /** Token contract (Base Sepolia USDC). */
  asset: string;
  /** Integer base-unit price (USDC has 6 decimals; 1 USDC = "1000000"). */
  amount: string;
  /** Hosted facilitator base URL (public: https://x402.org/facilitator). */
  facilitatorUrl: string;
  /** Human description advertised on the 402. */
  description?: string;
  /**
   * Do the paid work. `jobId` + `params` come off the request query. Any throw
   * cancels the verified (unsettled) payment — the paywall relies on that for
   * work-before-settle money safety.
   */
  deliver: (
    jobId: string,
    params: Record<string, string>,
  ) => Promise<X402PaywallDeliverResult>;
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

export interface RunningX402Paywall {
  server: Server;
  /** Full URL including the route (host + port resolved). */
  url: string;
  close: () => Promise<void>;
}

export async function startX402Paywall(
  cfg: X402PaywallConfig,
): Promise<RunningX402Paywall> {
  const routePattern = `GET ${cfg.route}`;
  const facilitator = new HTTPFacilitatorClient({ url: cfg.facilitatorUrl });
  const core = new x402ResourceServer(facilitator).register(
    cfg.network,
    new ExactEvmScheme(),
  );
  const httpServer = new x402HTTPResourceServer(core, {
    [routePattern]: {
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
      description: cfg.description ?? "DACS paywalled resource (pay-x402)",
      mimeType: "application/json",
    },
  });
  await httpServer.initialize();

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async () => {
      const url = new URL(req.url ?? "/", `http://127.0.0.1:${cfg.port}`);
      if (url.pathname !== cfg.route) {
        res.writeHead(404).end();
        return;
      }
      const context = {
        adapter: adapterFor(req, url),
        path: url.pathname,
        method: req.method ?? "GET",
        paymentHeader: (req.headers["x-payment"] as string) ?? undefined,
        routePattern,
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
      const params: Record<string, string> = {};
      for (const [k, v] of url.searchParams) if (k !== "jobId") params[k] = v;

      let delivered: X402PaywallDeliverResult;
      try {
        delivered = await cfg.deliver(jobId, params);
      } catch (e) {
        // Work failed — cancel the verified (unsettled) payment and report.
        await result.cancellationDispatcher?.cancel?.({ reason: "other" } as never).catch(() => {});
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: `delivery failed: ${(e as Error).message}` }));
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
      res.end(JSON.stringify({ jobId, ...delivered }));
    })().catch((e) => {
      if (!res.headersSent) {
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: (e as Error).message }));
      } else {
        res.end();
      }
    });
  });

  await new Promise<void>((resolve) => server.listen(cfg.port, "127.0.0.1", resolve));
  return {
    server,
    url: `http://127.0.0.1:${cfg.port}${cfg.route}`,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}
