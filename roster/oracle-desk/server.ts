/**
 * Oracle Desk HTTP server — node:http, no framework.
 *
 *   GET /catalog            list products + prices
 *   GET /data/<id>?...      attested fetch -> extract -> sell the value
 *
 * Error mapping:
 *   unknown product      -> 404
 *   bad/missing params   -> 400
 *   upstream failure     -> 502 (network error, upstream >= 400, or bad shape)
 *
 * Every /data response carries `X-Payment-Stub: true` and a ChargeReceipt —
 * the payment seam is visible but nothing settles until DACS/x402 wiring.
 */
import http from "node:http";
import { randomUUID } from "node:crypto";
import { CATALOG, findProduct, validateParams } from "./catalog.js";
import { attestValue, resolveRequest, OracleError, PRESET_IDS } from "./attest-any.js";
import type {
  AttestedFetchPort,
  AttestedFetchResult,
  AttestResponse,
  CatalogResponse,
  ChargePolicyPort,
  ChargeReceipt,
  ChargeRequest,
  DataProduct,
  DataResponse,
  ErrorResponse,
} from "./types.js";

/** Flat per-call price for a generic attest-any-API request (USD). */
const GENERIC_ATTEST_PRICE = 0.1;

/** Map an OracleError code to an HTTP status for the wire. */
function statusForOracleError(code: OracleError["code"]): number {
  switch (code) {
    case "unsafe_url":
    case "bad_selector":
    case "bad_request":
      return 400;
    case "extract_failure":
      return 422;
    default:
      return 502; // upstream_failure / consensus_failure
  }
}

/** Map an OracleError code to a wire ErrorResponse code. */
function oracleErrorResponseCode(code: OracleError["code"]): ErrorResponse["error"]["code"] {
  switch (code) {
    case "unsafe_url":
      return "unsafe_url";
    case "bad_selector":
      return "bad_selector";
    case "extract_failure":
      return "extract_failure";
    case "bad_request":
      return "bad_params";
    default:
      return "upstream_failure";
  }
}

// ---------------------------------------------------------------------------
// Payment stub — always allows, records the would-be charge
// ---------------------------------------------------------------------------

export class StubChargePolicy implements ChargePolicyPort {
  /** Every would-be charge, in order. */
  readonly charges: ChargeReceipt[] = [];

  async authorize(req: ChargeRequest): Promise<ChargeReceipt> {
    const receipt: ChargeReceipt = {
      chargeId: `stub-${randomUUID()}`,
      productId: req.productId,
      price: req.price,
      settled: false,
      note: "payment stub — recorded, not settled (DACS/x402 wiring pending)",
    };
    this.charges.push(receipt);
    return receipt;
  }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

export interface OracleServerPorts {
  attestedFetch: AttestedFetchPort;
  chargePolicy: ChargePolicyPort;
  /** Defaults to the stock CATALOG. */
  catalog?: DataProduct[];
}

function sendJson(res: http.ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body, null, 2);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(payload),
    "x-payment-stub": "true",
  });
  res.end(payload);
}

function sendError(res: http.ServerResponse, status: number, error: ErrorResponse["error"]): void {
  sendJson(res, status, { error } satisfies ErrorResponse);
}

export function createOracleServer(ports: OracleServerPorts): http.Server {
  const catalog = ports.catalog ?? CATALOG;

  return http.createServer((req, res) => {
    void handle(req, res).catch((err: unknown) => {
      if (!res.headersSent) {
        sendError(res, 500, { code: "internal", message: (err as Error).message });
      } else {
        res.end();
      }
    });
  });

  async function handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const url = new URL(req.url ?? "/", "http://oracle.local");

    if (req.method !== "GET") {
      sendError(res, 404, { code: "not_found", message: `no route for ${req.method} ${url.pathname}` });
      return;
    }

    if (url.pathname === "/catalog") {
      const body: CatalogResponse = {
        service: "dahr-oracle-desk",
        paymentStub: true,
        products: catalog.map((p) => ({
          id: p.id,
          description: p.description,
          price: p.price,
          upstream: p.upstream,
          params: p.params.map(({ name, required, description, example }) => ({ name, required, description, example })),
        })),
      };
      sendJson(res, 200, body);
      return;
    }

    const dataMatch = /^\/data\/([^/]+)$/.exec(url.pathname);
    if (dataMatch) {
      await handleData(res, decodeURIComponent(dataMatch[1]!), url.searchParams);
      return;
    }

    if (url.pathname === "/attest") {
      await handleAttest(res, url.searchParams);
      return;
    }

    sendError(res, 404, { code: "not_found", message: `no route for GET ${url.pathname}` });
  }

  /**
   * attest-any-API: GET /attest?url=<https url>&extract=<selector>. The URL is
   * SSRF-guarded and the selector validated before any fetch; upstream failure
   * or a selector that does not resolve is a typed error, never a fabricated
   * value.
   */
  async function handleAttest(res: http.ServerResponse, search: URLSearchParams): Promise<void> {
    const params: Record<string, string> = {};
    for (const [k, v] of search) params[k] = v;
    try {
      const req = resolveRequest(params);
      const attested = await attestValue(ports.attestedFetch, req);
      // Payment seam (same stub as the presets): flat per-call attest price.
      const receipt = await ports.chargePolicy.authorize({
        productId: "attest-any",
        params: { url: attested.url, extract: attested.extract },
        price: GENERIC_ATTEST_PRICE,
      });
      const body: AttestResponse = {
        url: attested.url,
        extract: attested.extract,
        value: attested.value,
        attestation: attested.attestation,
        priceCharged: receipt.price,
        chargeId: receipt.chargeId,
      };
      sendJson(res, 200, body);
    } catch (err) {
      if (err instanceof OracleError) {
        sendError(res, statusForOracleError(err.code), {
          code: oracleErrorResponseCode(err.code),
          message: err.message,
          details: { presets: PRESET_IDS },
        });
        return;
      }
      throw err;
    }
  }

  async function handleData(res: http.ServerResponse, productId: string, search: URLSearchParams): Promise<void> {
    const product = findProduct(catalog, productId);
    if (!product) {
      sendError(res, 404, {
        code: "unknown_product",
        message: `no product "${productId}"`,
        details: { available: catalog.map((p) => p.id) },
      });
      return;
    }

    const raw: Record<string, string> = {};
    for (const [key, value] of search) raw[key] = value;
    const validated = validateParams(product, raw);
    if (!validated.ok) {
      sendError(res, 400, { code: "bad_params", message: "invalid params", details: validated.problems });
      return;
    }
    const params = validated.params;

    const upstreamUrl = product.buildUrl(params);
    let value: unknown;
    let attested: AttestedFetchResult;
    try {
      attested = await ports.attestedFetch.attestFetch(upstreamUrl);
      if (attested.status >= 400) {
        throw new Error(`upstream responded ${attested.status}`);
      }
      value = product.extract(attested.body, params);
    } catch (err) {
      sendError(res, 502, {
        code: "upstream_failure",
        message: `upstream fetch for "${productId}" failed: ${(err as Error).message}`,
        details: { upstream: product.upstream },
      });
      return;
    }

    // Payment seam: the stub always allows and records the would-be charge.
    const receipt = await ports.chargePolicy.authorize({ productId, params, price: product.price });

    const body: DataResponse = {
      product: productId,
      params,
      value,
      attestation: attested,
      priceCharged: receipt.price,
      chargeId: receipt.chargeId,
    };
    sendJson(res, 200, body);
  }
}
