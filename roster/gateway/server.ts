/**
 * Gateway HTTP server — node:http, no framework.
 *
 * Routes:
 *   GET  /health          open   → { status, uptimeSec, agentCount, version }
 *   GET  /agents          open   → catalog of agent describes
 *   GET  /agents/:name    open   → single agent describe (404 unknown)
 *   POST /agents/:name    auth   → validate + invoke (401/400/413/502/504)
 *
 * Cross-cutting: a crypto.randomUUID request id, one structured JSON log line
 * per request to stdout (never the body or token), a per-agent invocation
 * timeout (504 on breach), and structured error envelopes that never leak a
 * stack trace. CORS is not reflected — same-origin / server-to-server use.
 */
import http from "node:http";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import type { GatewayConfig } from "./config.js";
import { isAuthorized } from "./auth.js";
import { AgentInputError, describeAgent, type AgentEndpoint, type OutputAnchor, type RequestContext } from "./types.js";
import { feeScheduleErr, type Settlement } from "./settlement.js";
import type { X402Gate, X402Verified } from "./x402.js";
import type { ProcurementX402 } from "./procurement-x402.js";
import { type MockDahrAttestor, sha256Hex } from "../oracle-desk/attested-fetch.js";
import { canonicalJson } from "../shared/attest-primitives.js";
import { ButlerDemoError, ButlerWebDemo, DemoRateLimiter } from "./butler-web.js";
import type { TextLlm } from "../llm/anthropic.js";
import { LiveProcurementError, LiveProcurementJobs, procurementIdempotencyKey } from "./live-procurement.js";
import { PROCUREMENT_PROFILES } from "./procurement-profiles.js";

const DEMO_INDEX = readFileSync(new URL("./web/index.html", import.meta.url), "utf8");
const DEMO_JS = readFileSync(new URL("./web/app.js", import.meta.url), "utf8");
const DEMO_CSS = readFileSync(new URL("./web/styles.css", import.meta.url), "utf8");

// ---------------------------------------------------------------------------
// Error envelope
// ---------------------------------------------------------------------------

type ErrorCode =
  | "not_found"
  | "method_not_allowed"
  | "unauthorized"
  | "payment_required"
  | "bad_request"
  | "payload_too_large"
  | "agent_error"
  | "agent_timeout"
  | "rate_limited"
  | "internal";

interface ErrorBody {
  error: { code: ErrorCode; message: string; details?: unknown };
}

// ---------------------------------------------------------------------------
// Agent-invocation timeout (Promise.race)
// ---------------------------------------------------------------------------

const AGENT_TIMEOUT = Symbol("agent-timeout");

type OutputAttestation = {
  scheme: "LIVE-ANCHOR-storage";
  digest: string;
  anchorName: string;
  anchorAddress: string;
  txRef?: string;
  committedBy: string;
  status: "broadcast" | "confirmed";
  note: string;
};

type ReceiptStatus = "queued" | "anchoring" | "broadcast" | "confirmed" | "failed";

type AsyncOutputAttestation = Omit<OutputAttestation, "status" | "note"> & {
  receiptId: string;
  statusUrl: string;
  status: ReceiptStatus;
  attempts: number;
  createdAt: string;
  updatedAt: string;
  error?: string;
  note: string;
};

type PendingReceipt = {
  public: AsyncOutputAttestation;
  value: object;
};

function outputAnchorValue(agent: string, requestId: string, result: unknown): {
  digest: string;
  anchorName: string;
  value: object;
} {
  const digest = sha256Hex(canonicalJson(result));
  const anchorName = `dacs:out:${agent}:${requestId}`;
  return { digest, anchorName, value: { digest, agent, requestId, at: new Date().toISOString() } };
}

class AsyncReceiptStore {
  private readonly receipts = new Map<string, PendingReceipt>();
  private readonly maxReceipts = 256;
  private readonly retentionMs = 30 * 60_000;

  constructor(private readonly outputAnchor: OutputAnchor) {}

  create(agent: string, requestId: string, result: unknown): AsyncOutputAttestation {
    this.prune();
    const receiptId = randomUUID();
    const now = new Date().toISOString();
    const prepared = outputAnchorValue(agent, requestId, result);
    const pending: PendingReceipt = {
      value: prepared.value,
      public: {
        scheme: "LIVE-ANCHOR-storage",
        receiptId,
        statusUrl: `/demo/butler/receipts/${encodeURIComponent(receiptId)}`,
        digest: prepared.digest,
        anchorName: prepared.anchorName,
        anchorAddress: this.outputAnchor.addressFor(prepared.anchorName),
        committedBy: this.outputAnchor.committerAddress,
        status: "queued",
        attempts: 1,
        createdAt: now,
        updatedAt: now,
        note: "The agent result is complete. Its receipt is queued for nonce-safe on-chain anchoring.",
      },
    };
    this.receipts.set(receiptId, pending);
    this.schedule(pending);
    return { ...pending.public };
  }

  get(receiptId: string): AsyncOutputAttestation | undefined {
    this.prune();
    const pending = this.receipts.get(receiptId);
    return pending ? { ...pending.public } : undefined;
  }

  retry(receiptId: string): AsyncOutputAttestation {
    const pending = this.receipts.get(receiptId);
    if (!pending) throw new Error("receipt not found");
    if (pending.public.status !== "failed") return { ...pending.public };
    if (pending.public.attempts >= 3) throw new Error("receipt retry limit reached");
    pending.public.attempts += 1;
    this.update(pending, "queued", "Receipt retry queued behind existing nonce-safe wallet work.");
    delete pending.public.error;
    this.schedule(pending);
    return { ...pending.public };
  }

  private schedule(pending: PendingReceipt): void {
    const lifecycle = {
      onStart: () => this.update(pending, "anchoring", "The wallet queue reached this receipt and is broadcasting its anchor."),
      onBroadcast: (result: { txRef?: string } | void) => {
        if (result && typeof result === "object") pending.public.txRef = result.txRef;
        this.update(pending, "broadcast", "The receipt was broadcast; the wallet queue is waiting for nonce confirmation.");
      },
      onConfirmed: (result: { txRef?: string } | void) => {
        if (result && typeof result === "object") pending.public.txRef = result.txRef;
        this.update(pending, "confirmed", "The result digest is anchored on-chain and nonce advancement is confirmed.");
      },
      onError: (error: unknown) => {
        pending.public.error = error instanceof Error ? error.message : "unknown anchoring failure";
        this.update(pending, "failed", "Receipt anchoring failed without changing the completed agent result. It can be retried safely.");
      },
    };

    if (this.outputAnchor.enqueue) {
      try {
        this.outputAnchor.enqueue(pending.public.anchorName, pending.value, lifecycle);
      } catch (error) {
        lifecycle.onError(error);
      }
      return;
    }

    // Compatibility for injected/custom anchors. Production adapters expose
    // enqueue(), which additionally reports start and confirmation transitions.
    const eager = this.outputAnchor.commitEager;
    try {
      const operation = eager
        ? eager.call(this.outputAnchor, pending.public.anchorName, pending.value)
        : this.outputAnchor.commit(pending.public.anchorName, pending.value);
      void operation.then((result) => {
        lifecycle.onBroadcast(result);
        if (!eager) lifecycle.onConfirmed(result);
      }, lifecycle.onError);
    } catch (error) {
      lifecycle.onError(error);
    }
  }

  private update(pending: PendingReceipt, status: ReceiptStatus, note: string): void {
    pending.public.status = status;
    pending.public.note = note;
    pending.public.updatedAt = new Date().toISOString();
  }

  private prune(): void {
    const cutoff = Date.now() - this.retentionMs;
    for (const [id, pending] of this.receipts) {
      if (Date.parse(pending.public.updatedAt) < cutoff) this.receipts.delete(id);
    }
    while (this.receipts.size >= this.maxReceipts) {
      const oldest = this.receipts.keys().next().value as string | undefined;
      if (!oldest) break;
      this.receipts.delete(oldest);
    }
  }
}

async function attestOutput(
  outputAnchor: OutputAnchor,
  agent: string,
  requestId: string,
  result: unknown,
  eager = false,
): Promise<OutputAttestation> {
  const { digest, anchorName, value } = outputAnchorValue(agent, requestId, result);
  const anchorAddress = outputAnchor.addressFor(anchorName);
  const useEager = eager && outputAnchor.commitEager !== undefined;
  const committed = useEager
    ? await outputAnchor.commitEager!(anchorName, value)
    : await outputAnchor.commit(anchorName, value);
  const txRef = committed && typeof committed === "object" ? committed.txRef : undefined;
  return {
    scheme: "LIVE-ANCHOR-storage",
    digest,
    anchorName,
    anchorAddress,
    txRef,
    committedBy: outputAnchor.committerAddress,
    status: useEager ? "broadcast" : "confirmed",
    note: useEager
      ? "The result digest was broadcast to Demos StorageProgram. The wallet queue remains locked until nonce confirmation."
      : "The result digest was anchored on-chain and wallet nonce advancement was confirmed before this response.",
  };
}

/** Race an agent invocation against a timeout; resolves to the timeout symbol on breach. */
export async function invokeWithTimeout(
  endpoint: AgentEndpoint,
  input: unknown,
  ctx: RequestContext,
  timeoutMs: number,
): Promise<unknown> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<typeof AGENT_TIMEOUT>((resolve) => {
    timer = setTimeout(() => resolve(AGENT_TIMEOUT), timeoutMs);
  });
  try {
    return await Promise.race([endpoint.invoke(input, ctx), timeout]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

export function createGatewayServer(
  config: GatewayConfig,
  registry: AgentEndpoint[],
  attestor: MockDahrAttestor,
  outputAnchor?: OutputAnchor,
  settlement?: Settlement,
  x402?: X402Gate,
  llm?: TextLlm,
  procurementX402?: ProcurementX402,
): http.Server {
  const byName = new Map(registry.map((a) => [a.name, a]));
  const butler = new ButlerWebDemo(registry, llm);
  const demoRate = new DemoRateLimiter();
  const procurementJobs = new LiveProcurementJobs(undefined, procurementX402);
  const receiptStore = outputAnchor ? new AsyncReceiptStore(outputAnchor) : undefined;
  const startedAtMs = Date.now();

  const server = http.createServer((req, res) => {
    void handle(req, res).catch((err: unknown) => {
      // Last-ditch guard — should not fire; handle() catches its own errors.
      if (!res.headersSent) {
        sendError(res, 500, { code: "internal", message: "internal error" }, {
          requestId: "unknown",
          method: req.method ?? "?",
          path: req.url ?? "/",
          ip: clientIp(req),
          startedAt: Date.now(),
        });
      } else {
        res.end();
      }
      void err;
    });
  });

  server.requestTimeout = config.requestTimeoutMs;

  async function handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const requestId = randomUUID();
    const startedAt = Date.now();
    const method = req.method ?? "GET";
    const url = new URL(req.url ?? "/", "http://gateway.local");
    const path = url.pathname;
    const logBase = { requestId, method, path, ip: clientIp(req), startedAt };

    // The Directory's Try DACS page is a separate origin in development. Only
    // the public, constrained Butler routes opt into an explicit CORS allowlist.
    if (path.startsWith("/demo/butler") || path.startsWith("/demo/procurement")) {
      const origin = req.headers.origin;
      const allowed = new Set((process.env.BUTLER_ALLOWED_ORIGINS ?? "http://localhost:3400,http://127.0.0.1:3400").split(",").map((v) => v.trim()).filter(Boolean));
      if (origin && allowed.has(origin)) {
        res.setHeader("access-control-allow-origin", origin);
        res.setHeader("vary", "origin");
        res.setHeader("access-control-allow-methods", "GET, POST, OPTIONS");
        res.setHeader("access-control-allow-headers", "content-type, idempotency-key, payment-signature, x-payment");
      }
      if (method === "OPTIONS") {
        res.statusCode = origin && allowed.has(origin) ? 204 : 403;
        return void res.end();
      }
    }

    res.setHeader("x-request-id", requestId);

    // Operator-only recovery for a paid job that failed after settlement. The
    // public demo cannot invoke this route, and the recovery implementation has
    // no code path that signs or broadcasts a second payment.
    if (path.startsWith("/admin/procurement/") && path.endsWith("/recover")) {
      if (method !== "POST") return void sendError(res, 405, methodErr(method, path), logBase);
      if (!isAuthorized(req.headers.authorization, config.token)) {
        return void sendError(res, 401, { code: "unauthorized", message: "missing or invalid bearer token" }, logBase);
      }
      try {
        const encoded = path.slice("/admin/procurement/".length, -"/recover".length);
        const id = decodeURIComponent(encoded);
        return void sendJson(res, 202, procurementJobs.recover(id), { ...logBase, agent: "procurement-recovery" });
      } catch (error) {
        if (error instanceof LiveProcurementError) {
          const code = error.status === 404 ? "not_found" : error.status === 409 ? "agent_error" : "bad_request";
          return void sendError(res, error.status, { code, message: error.message }, { ...logBase, agent: "procurement-recovery" });
        }
        return void sendError(res, 400, { code: "bad_request", message: (error as Error).message }, { ...logBase, agent: "procurement-recovery" });
      }
    }

    // --- Public Butler demo ------------------------------------------------
    if (path === "/" || path === "/demo") {
      if (method !== "GET") return void sendError(res, 405, methodErr(method, path), logBase);
      return void sendAsset(res, 200, DEMO_INDEX, "text/html; charset=utf-8", logBase, false);
    }
    if (path === "/demo/app.js") {
      if (method !== "GET") return void sendError(res, 405, methodErr(method, path), logBase);
      return void sendAsset(res, 200, DEMO_JS, "text/javascript; charset=utf-8", logBase, true);
    }
    if (path === "/demo/styles.css") {
      if (method !== "GET") return void sendError(res, 405, methodErr(method, path), logBase);
      return void sendAsset(res, 200, DEMO_CSS, "text/css; charset=utf-8", logBase, true);
    }
    if (path === "/demo/butler/agents") {
      if (method !== "GET") return void sendError(res, 405, methodErr(method, path), logBase);
      return void sendJson(res, 200, { agents: butler.catalog }, logBase);
    }
    if (path === "/demo/procurement/options") {
      if (method !== "GET") return void sendError(res, 405, methodErr(method, path), logBase);
      return void sendJson(res, 200, {
        profiles: PROCUREMENT_PROFILES.map((profile) => ({
          ...profile,
          ...procurementJobs.readiness(profile.id),
          railReadiness: Object.fromEntries(profile.paymentRails.map((rail) => [
            rail,
            procurementJobs.readiness(profile.id, rail),
          ])),
        })),
      }, { ...logBase, agent: "procurement-catalog" });
    }
    if (procurementX402?.matches(path)) {
      try {
        const response = await procurementX402.handle(req);
        for (const [key, value] of Object.entries(response.headers)) res.setHeader(key, value);
        return void sendJson(res, response.status, response.body, { ...logBase, agent: "procurement-x402" });
      } catch (error) {
        return void sendError(res, 502, { code: "agent_error", message: `x402 settlement resource failed: ${(error as Error).message}` }, { ...logBase, agent: "procurement-x402" });
      }
    }
    const receiptMatch = /^\/demo\/butler\/receipts\/([^/]+)$/.exec(path);
    if (receiptMatch) {
      if (method !== "GET") return void sendError(res, 405, methodErr(method, path), logBase);
      const receipt = receiptStore?.get(decodeURIComponent(receiptMatch[1]!));
      if (!receipt) return void sendError(res, 404, { code: "not_found", message: "receipt not found or expired" }, logBase);
      return void sendJson(res, 200, { outputAttestation: receipt }, { ...logBase, agent: "butler-receipt" });
    }
    const receiptRetryMatch = /^\/demo\/butler\/receipts\/([^/]+)\/retry$/.exec(path);
    if (receiptRetryMatch) {
      if (method !== "POST") return void sendError(res, 405, methodErr(method, path), logBase);
      try {
        const receipt = receiptStore?.retry(decodeURIComponent(receiptRetryMatch[1]!));
        if (!receipt) return void sendError(res, 404, { code: "not_found", message: "receipt not found or expired" }, logBase);
        return void sendJson(res, 202, { outputAttestation: receipt }, { ...logBase, agent: "butler-receipt" });
      } catch (error) {
        return void sendError(res, 409, { code: "agent_error", message: (error as Error).message }, { ...logBase, agent: "butler-receipt" });
      }
    }
    if (path === "/demo/procurement") {
      if (method !== "POST") return void sendError(res, 405, methodErr(method, path), logBase);
      let leave: (() => void) | undefined;
      try {
        const raw = await readBody(req, Math.min(config.bodyLimitBytes, 64 * 1024));
        const body = raw.trim() === "" ? {} : JSON.parse(raw);
        const key = procurementIdempotencyKey(req.headers["idempotency-key"], body);
        const started = procurementJobs.startRequest(body, key, () => {
          leave = demoRate.enter(logBase.ip);
        });
        res.setHeader("idempotency-replayed", String(started.replayed));
        return void sendJson(
          res,
          202,
          { ...started.job, idempotencyReplay: started.replayed },
          { ...logBase, agent: "procurement-butler" },
        );
      } catch (error) {
        if (error instanceof SyntaxError) return void sendError(res, 400, { code: "bad_request", message: "request body is not valid JSON" }, { ...logBase, agent: "procurement-butler" });
        if (error instanceof BodyTooLargeError) return void sendError(res, 413, { code: "payload_too_large", message: "procurement demo body exceeds 65536 bytes" }, { ...logBase, agent: "procurement-butler" });
        if (error instanceof LiveProcurementError) {
          const code = error.status === 404 ? "not_found" : error.status === 400 ? "bad_request" : "agent_error";
          return void sendError(res, error.status, { code, message: error.message }, { ...logBase, agent: "procurement-butler" });
        }
        // Rate-limit / concurrency backpressure from demoRate.enter() is a
        // ButlerDemoError (429 rate-limited / 503 busy). Map it to its real
        // status — NOT the 502 fallthrough, which the UI retries into forever.
        if (error instanceof ButlerDemoError) {
          const code = error.status === 429 ? "rate_limited" : error.status === 503 ? "busy" : error.status === 400 ? "bad_request" : "agent_error";
          return void sendError(res, error.status, { code, message: error.message, details: error.details }, { ...logBase, agent: "procurement-butler" });
        }
        return void sendError(res, 502, { code: "agent_error", message: (error as Error).message }, { ...logBase, agent: "procurement-butler" });
      } finally { leave?.(); }
    }
    if (path.startsWith("/demo/procurement/") && method === "GET") {
      try {
        const id = decodeURIComponent(path.slice("/demo/procurement/".length));
        return void sendJson(res, 200, procurementJobs.get(id), { ...logBase, agent: "procurement-butler" });
      } catch (error) {
        if (error instanceof LiveProcurementError) return void sendError(res, error.status, { code: "not_found", message: error.message }, { ...logBase, agent: "procurement-butler" });
        return void sendError(res, 400, { code: "bad_request", message: (error as Error).message }, { ...logBase, agent: "procurement-butler" });
      }
    }
    if (path === "/demo/butler/plan") {
      if (method !== "POST") return void sendError(res, 405, methodErr(method, path), logBase);
      let leave: (() => void) | undefined;
      try {
        leave = demoRate.enter(logBase.ip);
        const raw = await readBody(req, 32 * 1024);
        const body = raw.trim() === "" ? {} : JSON.parse(raw);
        return void sendJson(res, 200, await butler.plan(body), { ...logBase, agent: "butler-plan" });
      } catch (error) {
        if (error instanceof ButlerDemoError) {
          const code = error.status === 429 ? "rate_limited" : error.status === 400 ? "bad_request" : "agent_error";
          return void sendError(res, error.status, { code, message: error.message, details: error.details }, { ...logBase, agent: "butler-plan" });
        }
        return void sendError(res, 400, { code: "bad_request", message: error instanceof SyntaxError ? "request body is not valid JSON" : (error as Error).message }, { ...logBase, agent: "butler-plan" });
      } finally { leave?.(); }
    }
    if (path === "/demo/butler") {
      if (method !== "POST") return void sendError(res, 405, methodErr(method, path), logBase);
      let leave: (() => void) | undefined;
      try {
        leave = demoRate.enter(logBase.ip);
        const raw = await readBody(req, Math.min(config.bodyLimitBytes, 256 * 1024));
        const body = raw.trim() === "" ? {} : JSON.parse(raw);
        const invokeStart = Date.now();
        const result = await butler.run(body, { requestId, attestor }, config.agentTimeoutMs) as Record<string, unknown>;
        const selectedAgent = ((result.butler as { selectedAgent?: unknown } | undefined)?.selectedAgent);
        const agentName = typeof selectedAgent === "string" ? selectedAgent : "butler";
        const response: Record<string, unknown> = {
          ...result,
          execution: { requestId, durationMs: Date.now() - invokeStart },
        };
        if (receiptStore) response.outputAttestation = receiptStore.create(agentName, requestId, result.result);
        return void sendJson(res, 200, response, { ...logBase, agent: "butler" });
      } catch (error) {
        if (error instanceof SyntaxError) return void sendError(res, 400, { code: "bad_request", message: "request body is not valid JSON" }, { ...logBase, agent: "butler" });
        if (error instanceof BodyTooLargeError) return void sendError(res, 413, { code: "payload_too_large", message: "demo body exceeds 262144 bytes" }, { ...logBase, agent: "butler" });
        if (error instanceof ButlerDemoError) {
          const code = error.status === 429 ? "rate_limited" : error.status === 400 || error.status === 404 ? "bad_request" : "agent_error";
          return void sendError(res, error.status, { code, message: error.message, details: error.details }, { ...logBase, agent: "butler" });
        }
        return void sendError(res, 502, { code: "agent_error", message: (error as Error).message }, { ...logBase, agent: "butler" });
      } finally {
        leave?.();
      }
    }

    // --- GET /health ------------------------------------------------------
    if (path === "/health") {
      if (method !== "GET") return void sendError(res, 405, methodErr(method, path), logBase);
      return void sendJson(
        res,
        200,
        {
          status: "ok",
          uptimeSec: Math.round((Date.now() - startedAtMs) / 1000),
          agentCount: registry.length,
          version: config.version,
          llm: llm ? { status: "configured", provider: llm.provider, model: llm.model } : { status: "disabled" },
        },
        logBase,
      );
    }

    // --- GET /agents ------------------------------------------------------
    if (path === "/agents") {
      if (method !== "GET") return void sendError(res, 405, methodErr(method, path), logBase);
      return void sendJson(res, 200, { agents: registry.map(describeAgent) }, logBase);
    }

    // --- /agents/:name ----------------------------------------------------
    const m = /^\/agents\/([^/]+)$/.exec(path);
    if (m) {
      const name = decodeURIComponent(m[1]!);
      const endpoint = byName.get(name);

      if (method === "GET") {
        if (!endpoint) return void sendError(res, 404, { code: "not_found", message: `no agent "${name}"` }, logBase);
        return void sendJson(res, 200, describeAgent(endpoint), logBase);
      }

      if (method === "POST") {
        return void (await handlePost(req, res, endpoint, name, { requestId, logBase }));
      }

      return void sendError(res, 405, methodErr(method, path), logBase);
    }

    // --- unknown ----------------------------------------------------------
    return void sendError(res, 404, { code: "not_found", message: `no route for ${method} ${path}` }, logBase);
  }

  async function handlePost(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    endpoint: AgentEndpoint | undefined,
    name: string,
    meta: { requestId: string; logBase: LogBase },
  ): Promise<void> {
    const { requestId, logBase } = meta;
    const agentLog = { ...logBase, agent: name };

    // Unknown agent → 404 (the catalog is public via GET /agents anyway).
    if (!endpoint) {
      return void sendError(res, 404, { code: "not_found", message: `no agent "${name}"` }, agentLog);
    }

    // Access: an operator Bearer token is free/internal. Otherwise settle via
    // pay-dem (X-Payment-Tx header) or x402 (X-PAYMENT header); with neither,
    // return a 402 advertising the available rail(s).
    const bearerOk = isAuthorized(req.headers.authorization, config.token);
    let payment: { txHash: string; payer?: string; amountOs?: bigint } | undefined; // pay-dem
    let x402v: X402Verified | undefined; // x402
    if (!bearerOk) {
      const rawTx = req.headers["x-payment-tx"];
      const payDemTx = (Array.isArray(rawTx) ? rawTx[0] : rawTx) ?? "";

      if (payDemTx && settlement) {
        const priceOs = settlement.fee.priceOsFor(name);
        const v = await settlement.gate.verifyAndReserve(payDemTx, priceOs);
        if (!v.ok) {
          return void sendError(res, 402, feeScheduleErr(name, priceOs, settlement.gate.payToAddress, v.reason), agentLog);
        }
        payment = { txHash: payDemTx, payer: v.payer, amountOs: v.amountOs };
      } else if (x402) {
        // x402.verify handles both the no/invalid-payment 402 challenge AND a
        // valid X-PAYMENT. The challenge is x402-standard (clients auto-pay); a
        // pay-dem hint is merged for buyers preferring the DEM rail.
        const outcome = await x402.verify(req, name);
        if (outcome.kind === "challenge") {
          setRawHeaders(res, outcome.headers);
          return void sendJson(res, outcome.status, withPayDemHint(outcome.body, settlement, name), agentLog);
        }
        x402v = outcome.verified;
      } else if (settlement) {
        const priceOs = settlement.fee.priceOsFor(name);
        return void sendError(res, 402, feeScheduleErr(name, priceOs, settlement.gate.payToAddress), agentLog);
      } else {
        return void sendError(res, 401, { code: "unauthorized", message: "missing or invalid bearer token" }, agentLog);
      }
    }

    // A reserved payment is RELEASED on any non-200 outcome (bad input, agent
    // error, timeout) so the buyer can retry with the same payment; only a
    // delivered 200 consumes it.
    let committed = false;
    try {
      // Body — enforce the byte limit as we read.
      let body: string;
      try {
        body = await readBody(req, config.bodyLimitBytes);
      } catch (err) {
        if (err instanceof BodyTooLargeError) {
          return void sendError(res, 413, { code: "payload_too_large", message: `body exceeds ${config.bodyLimitBytes} bytes` }, agentLog);
        }
        return void sendError(res, 400, { code: "bad_request", message: "could not read request body" }, agentLog);
      }

      let input: unknown;
      try {
        input = body.trim() === "" ? {} : JSON.parse(body);
      } catch {
        return void sendError(res, 400, { code: "bad_request", message: "request body is not valid JSON" }, agentLog);
      }

      const validation = endpoint.validate(input);
      if (!validation.ok) {
        return void sendError(res, 400, { code: "bad_request", message: "input validation failed", details: validation.errors }, agentLog);
      }

      const ctx: RequestContext = { requestId, attestor };
      const invokeStart = Date.now();
      let result: unknown;
      try {
        result = await invokeWithTimeout(endpoint, input, ctx, config.agentTimeoutMs);
      } catch (err) {
        if (err instanceof AgentInputError) {
          return void sendError(res, 400, { code: "bad_request", message: err.message, details: err.details }, agentLog);
        }
        // Agent threw — surface the message only, never a stack.
        return void sendError(res, 502, { code: "agent_error", message: (err as Error).message }, agentLog);
      }

      if (result === AGENT_TIMEOUT) {
        return void sendError(res, 504, { code: "agent_timeout", message: `agent "${name}" exceeded ${config.agentTimeoutMs}ms` }, agentLog);
      }

      const responseBody: Record<string, unknown> = { agent: name, requestId, durationMs: Date.now() - invokeStart, result };

      // Real, third-party-verifiable output attestation: anchor the result digest
      // on-chain under the gateway's persistent identity. The deterministic anchor
      // address is deterministic, but success is returned only after the
      // serialized write is confirmed by nonce advancement. A failed anchor is
      // a failed delivery, so paid requests are released for a safe retry.
      if (outputAnchor) {
        try {
          responseBody.outputAttestation = await attestOutput(outputAnchor, name, requestId, result);
        } catch (e) {
          console.error(`[gateway] output attestation error (${name}): ${(e as Error).message}`);
          return void sendError(res, 502, { code: "agent_error", message: "output attestation failed; payment was not consumed" }, agentLog);
        }
      }

      // x402: settle AFTER the work succeeded (work-before-settle money safety).
      // A settlement failure leaves committed=false → the finally cancels the
      // verified-but-unsettled payment.
      if (x402v && x402) {
        const s = await x402.settle(x402v);
        if (!s.ok) {
          return void sendError(res, 502, { code: "agent_error", message: `x402 settlement failed: ${s.reason ?? "unknown"}` }, agentLog);
        }
        setRawHeaders(res, s.headers);
        responseBody.settlement = {
          rail: "x402",
          paid: true,
          payTo: x402.payToAddress,
          settlementResponse: s.headers?.["x-payment-response"] ?? s.headers?.["X-PAYMENT-RESPONSE"],
        };
      }
      if (payment) {
        responseBody.settlement = {
          rail: "pay-dem",
          paid: true,
          payer: payment.payer,
          txHash: payment.txHash.replace(/^0x/, "").toLowerCase(),
          amountOs: payment.amountOs?.toString(),
        };
      }

      committed = true; // a delivered 200 consumes the reserved/verified payment
      return void sendJson(res, 200, responseBody, agentLog);
    } finally {
      if (!committed) {
        if (payment) settlement?.gate.release(payment.txHash);
        if (x402v) await x402v.cancel();
      }
    }
  }

  return server;
}

// ---------------------------------------------------------------------------
// Body reading with a hard byte cap
// ---------------------------------------------------------------------------

class BodyTooLargeError extends Error {}

function readBody(req: http.IncomingMessage, limit: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let tooLarge = false;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > limit) {
        // Stop buffering but keep draining the socket so the response can be
        // written cleanly (destroying mid-body resets the connection → the
        // client sees "fetch failed" instead of a 413).
        tooLarge = true;
        chunks.length = 0;
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => (tooLarge ? reject(new BodyTooLargeError()) : resolve(Buffer.concat(chunks).toString("utf8"))));
    req.on("error", (err) => reject(err));
  });
}

// ---------------------------------------------------------------------------
// Responses + logging
// ---------------------------------------------------------------------------

interface LogBase {
  requestId: string;
  method: string;
  path: string;
  ip: string;
  startedAt: number;
  agent?: string;
}

function logLine(status: number, log: LogBase): void {
  const line = {
    ts: new Date().toISOString(),
    requestId: log.requestId,
    method: log.method,
    path: log.path,
    status,
    durationMs: Date.now() - log.startedAt,
    ...(log.agent ? { agent: log.agent } : {}),
    ip: log.ip,
  };
  process.stdout.write(JSON.stringify(line) + "\n");
}

function sendJson(res: http.ServerResponse, status: number, body: unknown, log: LogBase): void {
  const payload = JSON.stringify(body, null, 2);
  if (!res.headersSent) {
    res.writeHead(status, {
      "content-type": "application/json; charset=utf-8",
      "content-length": Buffer.byteLength(payload),
    });
  }
  res.end(payload);
  logLine(status, log);
}

function sendAsset(res: http.ServerResponse, status: number, body: string, contentType: string, log: LogBase, cache: boolean): void {
  if (!res.headersSent) {
    res.writeHead(status, {
      "content-type": contentType,
      "content-length": Buffer.byteLength(body),
      "cache-control": cache ? "public, max-age=300" : "no-store",
      "content-security-policy": "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
      "x-frame-options": "DENY",
    });
  }
  res.end(body);
  logLine(status, log);
}

function sendError(res: http.ServerResponse, status: number, error: ErrorBody["error"], log: LogBase): void {
  sendJson(res, status, { error } satisfies ErrorBody, log);
}

function methodErr(method: string, path: string): ErrorBody["error"] {
  return { code: "method_not_allowed", message: `${method} not allowed on ${path}` };
}

/** Set response headers (used to relay x402 challenge / settlement headers). */
function setRawHeaders(res: http.ServerResponse, headers?: Record<string, string>): void {
  if (!headers || res.headersSent) return;
  for (const [k, v] of Object.entries(headers)) {
    try { res.setHeader(k, v); } catch { /* ignore illegal header */ }
  }
}

/** Merge a pay-dem hint into an x402 402 body so buyers can pick either rail. */
function withPayDemHint(body: unknown, settlement: Settlement | undefined, name: string): unknown {
  if (!settlement || typeof body !== "object" || body === null) return body;
  const priceOs = settlement.fee.priceOsFor(name);
  return {
    ...(body as Record<string, unknown>),
    payDem: {
      rail: "pay-dem",
      asset: "DEM",
      amountOs: priceOs.toString(),
      payTo: settlement.gate.payToAddress,
      howToPay: `Alternatively pay in DEM: send >= ${priceOs} OS to ${settlement.gate.payToAddress}, then resubmit with header "X-Payment-Tx: <txHash>".`,
    },
  };
}

function clientIp(req: http.IncomingMessage): string {
  return req.socket.remoteAddress ?? "unknown";
}
