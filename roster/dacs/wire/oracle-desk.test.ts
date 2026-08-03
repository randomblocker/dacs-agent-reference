import assert from "node:assert/strict";
import test from "node:test";
import { makeIdentity } from "../../../src/identity.js";
import { MemorySubstrate } from "../../../src/substrate/memory.js";
import { SellerAdapter } from "../seller-adapter.js";
import { requestScopeHash } from "../standard-profile.js";
import { normalizeOracleWorkParams } from "./oracle-desk.js";

test("Oracle work parameters normalize legacy nested paid jobs and current flat jobs", () => {
  assert.deepEqual(
    normalizeOracleWorkParams({ product: "crypto-price", params: { id: "bitcoin" } }),
    { product: "crypto-price", id: "bitcoin" },
  );
  assert.deepEqual(
    normalizeOracleWorkParams({ product: "fx-rate", symbol: "EUR" }),
    { product: "fx-rate", symbol: "EUR" },
  );
});

test("Oracle nested compatibility form stays closed and product-authoritative", () => {
  assert.deepEqual(
    normalizeOracleWorkParams({ product: "chain-height", params: { product: "crypto-price" } }),
    { product: "chain-height" },
  );
  assert.throws(
    () => normalizeOracleWorkParams({ product: "crypto-price", params: { id: "bitcoin" }, url: "https://example.com" }),
    /outside product and params/,
  );
  assert.throws(() => normalizeOracleWorkParams({ product: "crypto-price", params: [] }), /must be an object/);
});

test("normalized Oracle work preserves the exact hash of an already-signed nested request", async () => {
  const identity = makeIdentity("oracle-compat", 0x61);
  const nested = { product: "crypto-price", params: { id: "bitcoin" } };
  const flat = normalizeOracleWorkParams(nested);
  let observed: Record<string, unknown> | undefined;
  const seller = new SellerAdapter(identity, new MemorySubstrate(), "oracle-data", async (_jobId, params) => {
    observed = params;
    return { result: { value: "1" } };
  });
  const prepared = await seller.prepareDelivery("paid-oracle-job", flat, nested);
  assert.deepEqual(observed, { product: "crypto-price", id: "bitcoin" });
  assert.equal(prepared.attestation.requestHash, requestScopeHash(nested));
  assert.notEqual(prepared.attestation.requestHash, requestScopeHash(flat));
});
