/**
 * Oracle Desk catalog — the data products on sale.
 *
 * Every product is keyless public data: (upstream URL template, response
 * extractor, price). Extractors throw on shape mismatch; the server maps
 * that to a 502 (the upstream misbehaved, not the caller).
 */
import type { DataProduct } from "./types.js";

function parseJson(body: string, url: string): unknown {
  try {
    return JSON.parse(body);
  } catch {
    throw new Error(`upstream ${url} returned non-JSON body`);
  }
}

export const CATALOG: DataProduct[] = [
  {
    id: "crypto-price",
    description: "Spot USD price of a cryptocurrency (CoinGecko simple-price, keyless).",
    price: 0.05,
    upstream: "api.coingecko.com",
    params: [
      {
        name: "id",
        required: true,
        pattern: /^[a-z0-9][a-z0-9-]{0,63}$/,
        description: "CoinGecko coin id (lowercase slug)",
        example: "bitcoin",
      },
    ],
    buildUrl: (p) =>
      `https://api.coingecko.com/api/v3/simple/price?ids=${encodeURIComponent(p.id!)}&vs_currencies=usd`,
    extract(body, p) {
      const data = parseJson(body, "coingecko") as Record<string, { usd?: unknown } | undefined>;
      const usd = data[p.id!]?.usd;
      if (typeof usd !== "number") throw new Error(`no USD price for coin id "${p.id}" in upstream response`);
      return usd;
    },
  },
  {
    id: "fx-rate",
    description: "USD foreign-exchange rate for a currency symbol (Frankfurter/ECB, keyless).",
    price: 0.03,
    upstream: "api.frankfurter.dev",
    params: [
      {
        name: "symbol",
        required: true,
        pattern: /^[A-Z]{3}$/,
        description: "ISO-4217 currency code, uppercase",
        example: "EUR",
      },
    ],
    buildUrl: (p) => `https://api.frankfurter.dev/v1/latest?base=USD&symbols=${encodeURIComponent(p.symbol!)}`,
    extract(body, p) {
      const data = parseJson(body, "frankfurter") as { rates?: Record<string, unknown> };
      const rate = data.rates?.[p.symbol!];
      if (typeof rate !== "number") throw new Error(`no rate for symbol "${p.symbol}" in upstream response`);
      return rate;
    },
  },
  {
    id: "chain-height",
    description: "Current Bitcoin block height (blockchain.info/q/getblockcount, keyless).",
    price: 0.02,
    upstream: "blockchain.info",
    params: [],
    buildUrl: () => "https://blockchain.info/q/getblockcount",
    extract(body) {
      const height = Number(body.trim());
      if (!Number.isInteger(height) || height <= 0) {
        throw new Error("upstream returned a non-integer block count");
      }
      return height;
    },
  },
];

export function findProduct(catalog: DataProduct[], id: string): DataProduct | undefined {
  return catalog.find((p) => p.id === id);
}

/**
 * Validate raw query params against a product's spec.
 * Returns the validated params, or a list of human-readable problems.
 */
export function validateParams(
  product: DataProduct,
  raw: Record<string, string>,
): { ok: true; params: Record<string, string> } | { ok: false; problems: string[] } {
  const problems: string[] = [];
  const params: Record<string, string> = {};
  const known = new Set(product.params.map((s) => s.name));

  for (const key of Object.keys(raw)) {
    if (!known.has(key)) problems.push(`unknown param "${key}" (accepted: ${[...known].join(", ") || "none"})`);
  }
  for (const spec of product.params) {
    const value = raw[spec.name];
    if (value === undefined || value === "") {
      if (spec.required) problems.push(`missing required param "${spec.name}" — ${spec.description} (e.g. ${spec.example})`);
      continue;
    }
    if (!spec.pattern.test(value)) {
      problems.push(`param "${spec.name}"="${value}" does not match ${spec.pattern} — ${spec.description} (e.g. ${spec.example})`);
      continue;
    }
    params[spec.name] = value;
  }

  return problems.length > 0 ? { ok: false, problems } : { ok: true, params };
}
