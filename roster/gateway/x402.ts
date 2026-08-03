/**
 * x402 settlement for the gateway — the SELLER half of the x402 rail (USDC on
 * Base Sepolia via the hosted facilitator, gasless EIP-3009 for the buyer).
 *
 * Reuses the PROVEN @x402/core + @x402/evm resource server (same as
 * roster/dacs/live/x402-paywall.ts, which settles live in l2/l4) but as a
 * gateway-mountable GATE rather than a standalone server. The @x402 packages are
 * imported DYNAMICALLY in init() so the default (unpaid) gateway carries no x402
 * dependency at load time.
 *
 * Flow per request:  challenge (402) → buyer pays → verify → DO THE WORK →
 * settle (facilitator submits on-chain) → 200. On work failure the verified but
 * unsettled payment is cancelled (work-before-settle money safety).
 *
 * The gateway needs only the payTo ADDRESS (it never signs); the facilitator
 * submits the buyer's signed transfer to payTo.
 */
import type { IncomingMessage } from "node:http";

export interface X402Config {
  /** EVM address that receives USDC. */
  payTo: string;
  /** CAIP-2 network — Base Sepolia = "eip155:84532". */
  network: `${string}:${string}`;
  /** Token symbol advertised in the price (e.g. "USDC"). */
  asset: string;
  /** Raw token amount per call (USDC has 6 decimals; "1000000" = 1 USDC). */
  amount: string;
  /** Hosted facilitator base URL. */
  facilitatorUrl: string;
}

/** A verified (but not yet settled) x402 payment, ready to settle after the work. */
export interface X402Verified {
  paymentPayload: unknown;
  paymentRequirements: unknown;
  declaredExtensions: unknown;
  cancel: () => Promise<void>;
  context: unknown;
}

/** Outcome of verifying a request: either a 402 challenge to relay, or a verified payment. */
export type X402VerifyOutcome =
  | { kind: "challenge"; status: number; headers: Record<string, string>; body: unknown }
  | { kind: "verified"; verified: X402Verified };

function adapterFor(req: IncomingMessage, url: URL): unknown {
  return {
    getHeader: (name: string) => req.headers[name.toLowerCase()] as string | undefined,
    getMethod: () => req.method ?? "GET",
    getPath: () => url.pathname,
    getUrl: () => url.toString(),
    getAcceptHeader: () => (req.headers.accept as string) ?? "*/*",
    getUserAgent: () => (req.headers["user-agent"] as string) ?? "",
    getQueryParams: () => Object.fromEntries(url.searchParams.entries()),
    getQueryParam: (name: string) => url.searchParams.get(name) ?? undefined,
  };
}

export class X402Gate {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private http: any;
  private ready = false;

  constructor(
    private readonly agents: readonly string[],
    private readonly cfg: X402Config,
  ) {}

  get payToAddress(): string {
    return this.cfg.payTo;
  }

  /** Dynamically load @x402 and register one paid resource per agent (POST route). */
  async init(): Promise<void> {
    const { HTTPFacilitatorClient, x402HTTPResourceServer, x402ResourceServer } = await import(
      "../../sdk/node_modules/@x402/core/dist/esm/server/index.mjs"
    );
    const { ExactEvmScheme } = await import("../../sdk/node_modules/@x402/evm/dist/esm/exact/server/index.mjs");

    const facilitator = new HTTPFacilitatorClient({ url: this.cfg.facilitatorUrl });
    const core = new x402ResourceServer(facilitator).register(this.cfg.network, new ExactEvmScheme());

    const routes: Record<string, unknown> = {};
    for (const a of this.agents) {
      routes[`POST /agents/${a}`] = {
        accepts: {
          scheme: "exact",
          network: this.cfg.network,
          payTo: this.cfg.payTo,
          price: { amount: this.cfg.amount, asset: this.cfg.asset },
          maxTimeoutSeconds: 120,
          // EIP-712 domain of the token (Circle USDC on Base Sepolia = USDC/2).
          extra: { name: "USDC", version: "2" },
        },
        description: `DACS agent: ${a}`,
        mimeType: "application/json",
      };
    }
    this.http = new x402HTTPResourceServer(core, routes);
    await this.http.initialize();
    this.ready = true;
  }

  /** True when the request carries an x402 payment header. */
  hasPayment(req: IncomingMessage): boolean {
    return !!req.headers["x-payment"];
  }

  /** Process an incoming request → a 402 challenge (no/invalid payment) or a verified payment. */
  async verify(req: IncomingMessage, name: string): Promise<X402VerifyOutcome> {
    if (!this.ready) throw new Error("X402Gate not initialized");
    const url = new URL(req.url ?? "/", "http://gateway.local");
    const context = {
      adapter: adapterFor(req, url),
      path: `/agents/${name}`,
      method: "POST",
      paymentHeader: (req.headers["x-payment"] as string) ?? undefined,
      routePattern: `POST /agents/${name}`,
    };
    const result = await this.http.processHTTPRequest(context);
    if (result.type === "payment-error") {
      const r = result.response;
      return { kind: "challenge", status: r.status ?? 402, headers: r.headers ?? {}, body: r.body };
    }
    if (result.type === "no-payment-required") {
      return { kind: "challenge", status: 500, headers: {}, body: { error: "x402 route unexpectedly unprotected" } };
    }
    return {
      kind: "verified",
      verified: {
        paymentPayload: result.paymentPayload,
        paymentRequirements: result.paymentRequirements,
        declaredExtensions: result.declaredExtensions,
        context,
        cancel: async () => {
          await result.cancellationDispatcher?.cancel?.({ reason: "other" }).catch(() => {});
        },
      },
    };
  }

  /** Settle a verified payment AFTER the work succeeded. Returns the facilitator's response headers (carry the settlement tx). */
  async settle(v: X402Verified): Promise<{ ok: boolean; headers?: Record<string, string>; reason?: string }> {
    const s = await this.http.processSettlement(v.paymentPayload, v.paymentRequirements, v.declaredExtensions, {
      request: v.context,
    });
    return { ok: !!s.success, headers: s.headers, reason: s.errorReason };
  }
}
