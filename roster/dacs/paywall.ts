/**
 * Generic x402 paywall — the SELLER half of the x402 rail, generalized from
 * `src/live/paywall.ts` (ReviewBot's review-specific endpoint).
 *
 * A real node:http server exposing one paywalled route. The request carries the
 * `jobId` and the work `params` (query for GET, JSON body for POST). The flow is
 * the load-bearing order:
 *
 *   1. no / invalid payment  → HTTP 402 with the FeeSchedule (`accepts.price`)
 *   2. verified payment      → DO THE WORK (`deliver(jobId, params)`)
 *   3. work succeeded        → SETTLE the payment
 *   4. settled               → HTTP 200 with the result + settlement headers
 *
 * If the work throws, the (verified-but-unsettled) payment is CANCELLED and the
 * settle step is skipped — money never moves for undelivered work.
 *
 * Payment verify/settle sits behind a `PaymentFacilitatorPort`:
 *   - MockFacilitator (this file) accepts a synthetic `X-PAYMENT: mock:<jobId>`
 *     proof and settles to `mock-x402-<jobId>` — zero chain, zero keys.
 *   - The live seam is @x402/core + @x402/evm's hosted facilitator (dynamic
 *     import — see the note on `LiveFacilitatorSeam` below; not required for mock).
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

/** The FeeSchedule surface advertised on the 402 (the on-wire x402 `accepts`). */
export interface PaywallAccepts {
  scheme?: string;
  /** CAIP-2 network (e.g. "eip155:84532"), advertised for the buyer's guard. */
  network?: string;
  /** Recipient address (the seller's payout wallet). */
  payTo?: string;
  /** The FeeSchedule: integer base-unit amount + asset id. */
  price: { amount: string; asset: string };
  maxTimeoutSeconds?: number;
  extra?: Record<string, unknown>;
}

export interface FacilitatorVerifyRequest {
  jobId: string;
  paymentHeader?: string;
  accepts: PaywallAccepts;
}
export interface FacilitatorVerifyResult {
  ok: boolean;
  reason?: string;
}
export interface FacilitatorSettleRequest {
  jobId: string;
  paymentHeader?: string;
  accepts: PaywallAccepts;
}
export interface FacilitatorSettleResult {
  ok: boolean;
  txHash: string;
  reason?: string;
}

/**
 * The payment seam. `verify` decides whether a presented proof is valid WITHOUT
 * moving funds; `settle` finalizes a previously-verified payment; `cancel`
 * releases a verified-but-unsettled payment when the work fails.
 */
export interface PaymentFacilitatorPort {
  verify(req: FacilitatorVerifyRequest): Promise<FacilitatorVerifyResult>;
  settle(req: FacilitatorSettleRequest): Promise<FacilitatorSettleResult>;
  /** Release a verified-but-unsettled payment (work failed). Optional. */
  cancel?(req: { jobId: string; reason: string }): Promise<void>;
}

/**
 * Mock facilitator: no chain, no facilitator service, no keys. Accepts a
 * synthetic `X-PAYMENT: mock:<jobId>` proof (the header must name the same job)
 * and settles to a synthetic `mock-x402-<jobId>` hash. Records every call so
 * tests can assert the verify→settle ordering.
 */
export class MockFacilitator implements PaymentFacilitatorPort {
  readonly verified: string[] = [];
  readonly settled: string[] = [];
  readonly cancelled: string[] = [];

  async verify(req: FacilitatorVerifyRequest): Promise<FacilitatorVerifyResult> {
    const expected = `mock:${req.jobId}`;
    if (req.paymentHeader !== expected) {
      return { ok: false, reason: `expected X-PAYMENT "${expected}"` };
    }
    this.verified.push(req.jobId);
    return { ok: true };
  }

  async settle(req: FacilitatorSettleRequest): Promise<FacilitatorSettleResult> {
    this.settled.push(req.jobId);
    return { ok: true, txHash: `mock-x402-${req.jobId}` };
  }

  async cancel(req: { jobId: string; reason: string }): Promise<void> {
    this.cancelled.push(req.jobId);
  }
}

/** The value a paywall's work callback hands back for the 200 response. */
export interface PaywallDeliverResult {
  result: unknown;
  attestationRef?: string;
  [k: string]: unknown;
}

export type PaywallPhase = "challenge" | "verify" | "work" | "settle" | "respond";

export interface PaywallConfig {
  /** Listen port. Omit / 0 for an ephemeral port. */
  port?: number;
  /** The single paywalled route, e.g. "/data" or "/review". */
  route: string;
  method?: "GET" | "POST";
  /** The FeeSchedule advertised on the 402. */
  accepts: PaywallAccepts;
  facilitator: PaymentFacilitatorPort;
  /** Do the paid work. `jobId` + `params` come off the request. */
  deliver: (jobId: string, params: Record<string, unknown>) => Promise<PaywallDeliverResult>;
  description?: string;
  /** Phase observer — lets a demo/test assert the work-before-settle order. */
  onPhase?: (phase: PaywallPhase, jobId: string) => void;
}

export interface RunningPaywall {
  server: Server;
  /** Full URL including the route (host + ephemeral port resolved). */
  url: string;
  close: () => Promise<void>;
}

function challengeBody(cfg: PaywallConfig, reason?: string): unknown {
  return {
    x402Version: 1,
    error: reason ?? "X-PAYMENT required",
    accepts: [
      {
        scheme: cfg.accepts.scheme ?? "exact",
        network: cfg.accepts.network,
        payTo: cfg.accepts.payTo,
        // FeeSchedule surface: integer base-unit amount + asset.
        maxAmountRequired: cfg.accepts.price.amount,
        price: cfg.accepts.price,
        asset: cfg.accepts.price.asset,
        maxTimeoutSeconds: cfg.accepts.maxTimeoutSeconds ?? 120,
        extra: cfg.accepts.extra,
        description: cfg.description,
      },
    ],
  };
}

async function readRequest(
  req: IncomingMessage,
  url: URL,
): Promise<{ jobId: string; params: Record<string, unknown> }> {
  const params: Record<string, unknown> = {};
  for (const [k, v] of url.searchParams) if (k !== "jobId") params[k] = v;
  let jobId = url.searchParams.get("jobId") ?? "";

  if (req.method === "POST") {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const raw = Buffer.concat(chunks).toString("utf8").trim();
    if (raw) {
      const body = JSON.parse(raw) as { jobId?: string; params?: Record<string, unknown> };
      if (body.jobId) jobId = body.jobId;
      if (body.params && typeof body.params === "object") Object.assign(params, body.params);
    }
  }
  return { jobId, params };
}

function send(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const payload = JSON.stringify(body ?? {});
  res.writeHead(status, { "content-type": "application/json", ...headers });
  res.end(payload);
}

export async function startPaywall(cfg: PaywallConfig): Promise<RunningPaywall> {
  const method = cfg.method ?? "GET";
  const onPhase = cfg.onPhase ?? (() => {});

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async () => {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      if (url.pathname !== cfg.route || (req.method ?? "GET") !== method) {
        send(res, 404, { error: `no route for ${req.method} ${url.pathname}` });
        return;
      }

      const { jobId, params } = await readRequest(req, url);
      const paymentHeader = (req.headers["x-payment"] as string | undefined) ?? undefined;

      // 1. No / invalid payment → 402 with the FeeSchedule.
      const verify = await cfg.facilitator.verify({ jobId, paymentHeader, accepts: cfg.accepts });
      if (!verify.ok) {
        onPhase("challenge", jobId);
        send(res, 402, challengeBody(cfg, verify.reason), { "x-accept-payment": "x402" });
        return;
      }
      onPhase("verify", jobId);

      // 2. Payment verified → DO THE WORK before settling.
      let delivered: PaywallDeliverResult;
      try {
        onPhase("work", jobId);
        delivered = await cfg.deliver(jobId, params);
      } catch (e) {
        // Work failed — cancel the verified (unsettled) payment; never settle.
        await cfg.facilitator.cancel?.({ jobId, reason: "work-failed" }).catch(() => {});
        send(res, 502, { error: `delivery failed: ${(e as Error).message}` });
        return;
      }

      // 3. Work succeeded → settle.
      onPhase("settle", jobId);
      const settle = await cfg.facilitator.settle({ jobId, paymentHeader, accepts: cfg.accepts });
      if (!settle.ok) {
        send(res, 502, { error: `settlement failed: ${settle.reason ?? "unknown"}` });
        return;
      }

      // 4. Settled → 200 with the result + settlement headers.
      onPhase("respond", jobId);
      send(
        res,
        200,
        { jobId, ...delivered, settlement: { txHash: settle.txHash } },
        { "x-payment-response": settle.txHash },
      );
    })().catch((e) => {
      if (!res.headersSent) send(res, 500, { error: (e as Error).message });
      else res.end();
    });
  });

  await new Promise<void>((resolve) => server.listen(cfg.port ?? 0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    server,
    url: `http://127.0.0.1:${port}${cfg.route}`,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

/**
 * LIVE facilitator seam (documented, NOT wired for mock).
 *
 * The live x402 facilitator is @x402/core's `HTTPFacilitatorClient` +
 * @x402/evm's `ExactEvmScheme`, exactly as `src/live/paywall.ts` builds it. It
 * must be behind a dynamic import so the mock path never loads viem / @x402 /
 * chain deps:
 *
 * ```ts
 * export async function createLiveFacilitator(cfg: {
 *   facilitatorUrl: string; network: `${string}:${string}`;
 * }): Promise<PaymentFacilitatorPort> {
 *   const { HTTPFacilitatorClient, x402ResourceServer } =
 *     await import("@x402/core/server");
 *   const { ExactEvmScheme } = await import("@x402/evm/exact/server");
 *   // …adapt processHTTPRequest / processSettlement to verify()/settle()/cancel().
 * }
 * ```
 *
 * Left as a seam: Build A proves the rail end-to-end on the mock facilitator;
 * the live wiring is the same shape the reference paywall already exercises.
 */
export type LiveFacilitatorSeam = (cfg: {
  facilitatorUrl: string;
  network: `${string}:${string}`;
}) => Promise<PaymentFacilitatorPort>;
