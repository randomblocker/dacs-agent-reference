/**
 * Oracle Desk tests — fully offline via FakeAttestedFetch. node:test, run via:
 *   npx tsx --test roster/oracle-desk/oracle-desk.test.ts
 */
import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import type http from "node:http";
import { DirectHttpsAttestor, FakeAttestedFetch, sha256Hex, verifyAttestation, verifyAttestedRecord } from "./attested-fetch.js";
import {
  assertSafeUrl,
  extractBySelector,
  parseSelector,
  OracleError,
} from "./attest-any.js";
import { createOracleServer, StubChargePolicy } from "./server.js";
import type { AttestResponse, CatalogResponse, DataResponse, ErrorResponse } from "./types.js";

// Canned upstream bodies (route substring -> response).
const CANNED_BTC = JSON.stringify({ bitcoin: { usd: 67890.12 } });
const CANNED_FX = JSON.stringify({ amount: 1, base: "USD", rates: { EUR: 0.91 } });
const CANNED_HEIGHT = "901234\n";
// An arbitrary long-tail JSON endpoint for the generic attest-any path.
const CANNED_GENERIC = JSON.stringify({ data: { score: 4.2, label: "ok", arr: [10, 20] } });

function fakeFetch(): FakeAttestedFetch {
  return new FakeAttestedFetch([
    ["api.coingecko.com", { status: 200, body: CANNED_BTC }],
    ["api.frankfurter.dev", { status: 200, body: CANNED_FX }],
    ["blockchain.info", { status: 200, body: CANNED_HEIGHT }],
    ["api.example.com", { status: 200, body: CANNED_GENERIC }],
  ]);
}

test("direct HTTPS observations are explicitly labelled and verify offline", () => {
  const fetchedAt = new Date(0).toISOString();
  const bodyHash = sha256Hex(CANNED_BTC);
  const attestation = new DirectHttpsAttestor().attest("https://api.coingecko.com/test", fetchedAt, bodyHash);
  assert.equal(attestation.scheme, "DIRECT-HTTPS-ed25519");
  assert.match(attestation.note, /not TLSNotary/);
  assert.deepEqual(verifyAttestedRecord({ url: "https://api.coingecko.com/test", fetchedAt, bodyHash, attestation }), { valid: true });
});

let server: http.Server;
let base: string;
let charges: StubChargePolicy;
let fetchPort: FakeAttestedFetch;

before(async () => {
  charges = new StubChargePolicy();
  fetchPort = fakeFetch();
  server = createOracleServer({ attestedFetch: fetchPort, chargePolicy: charges });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
});

describe("GET /catalog", () => {
  test("lists all products with prices and param specs", async () => {
    const res = await fetch(`${base}/catalog`);
    assert.equal(res.status, 200);
    const body = (await res.json()) as CatalogResponse;

    assert.equal(body.paymentStub, true);
    const ids = body.products.map((p) => p.id);
    assert.deepEqual(ids, ["crypto-price", "fx-rate", "chain-height"]);
    for (const p of body.products) {
      assert.ok(p.price > 0, `${p.id} must have a positive price`);
      assert.ok(p.description.length > 0);
    }
    const crypto = body.products.find((p) => p.id === "crypto-price")!;
    assert.deepEqual(crypto.params.map((s) => s.name), ["id"]);
    assert.equal(crypto.params[0]!.required, true);
  });
});

describe("GET /data/<id> — happy path", () => {
  test("crypto-price: extracts the USD value and charges the stub price", async () => {
    const before = charges.charges.length;
    const res = await fetch(`${base}/data/crypto-price?id=bitcoin`);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-payment-stub"), "true");

    const body = (await res.json()) as DataResponse;
    assert.equal(body.product, "crypto-price");
    assert.deepEqual(body.params, { id: "bitcoin" });
    assert.equal(body.value, 67890.12);
    assert.equal(body.priceCharged, 0.05);

    // Charge recorded by the payment stub, matching the receipt in the response.
    assert.equal(charges.charges.length, before + 1);
    const charge = charges.charges.at(-1)!;
    assert.equal(charge.chargeId, body.chargeId);
    assert.equal(charge.productId, "crypto-price");
    assert.equal(charge.price, 0.05);
    assert.equal(charge.settled, false);
  });

  test("attestation verifies offline and its bodyHash matches the body", async () => {
    const res = await fetch(`${base}/data/fx-rate?symbol=EUR`);
    assert.equal(res.status, 200);
    const body = (await res.json()) as DataResponse;
    assert.equal(body.value, 0.91);

    const att = body.attestation;
    assert.equal(att.body, CANNED_FX);
    assert.equal(att.bodyHash, sha256Hex(CANNED_FX));
    assert.equal(att.attestation.scheme, "MOCK-DAHR-ed25519");
    assert.match(att.attestation.note, /MOCK/);

    const verdict = verifyAttestation(att);
    assert.equal(verdict.valid, true, verdict.reason ?? "attestation should verify");
  });

  test("a tampered body fails offline verification", async () => {
    const res = await fetch(`${base}/data/chain-height`);
    const body = (await res.json()) as DataResponse;
    assert.equal(body.value, 901234);

    const tampered = { ...body.attestation, body: "999999\n" };
    const verdict = verifyAttestation(tampered);
    assert.equal(verdict.valid, false);
    assert.match(verdict.reason!, /bodyHash/);
  });

  test("a forged digest fails offline verification", async () => {
    const res = await fetch(`${base}/data/chain-height`);
    const body = (await res.json()) as DataResponse;
    const forged = { ...body.attestation, attestation: { ...body.attestation.attestation, digest: "ab".repeat(32) } };
    assert.equal(verifyAttestation(forged).valid, false);
  });
});

describe("GET /data/<id> — error mapping", () => {
  test("404 unknown product, listing what IS available", async () => {
    const res = await fetch(`${base}/data/weather-report`);
    assert.equal(res.status, 404);
    const body = (await res.json()) as ErrorResponse;
    assert.equal(body.error.code, "unknown_product");
    assert.deepEqual((body.error.details as { available: string[] }).available, ["crypto-price", "fx-rate", "chain-height"]);
  });

  test("400 missing required param", async () => {
    const res = await fetch(`${base}/data/crypto-price`);
    assert.equal(res.status, 400);
    const body = (await res.json()) as ErrorResponse;
    assert.equal(body.error.code, "bad_params");
    assert.match(String(body.error.details), /missing required param "id"/);
  });

  test("400 malformed param value (pattern mismatch)", async () => {
    const res = await fetch(`${base}/data/fx-rate?symbol=euros!`);
    assert.equal(res.status, 400);
    const body = (await res.json()) as ErrorResponse;
    assert.equal(body.error.code, "bad_params");
    assert.match(String(body.error.details), /"symbol"/);
  });

  test("400 unknown extra param", async () => {
    const res = await fetch(`${base}/data/chain-height?chain=doge`);
    assert.equal(res.status, 400);
    const body = (await res.json()) as ErrorResponse;
    assert.match(String(body.error.details), /unknown param "chain"/);
  });

  test("502 when the upstream fetch fails at the network level", async () => {
    const broken = new FakeAttestedFetch([["api.coingecko.com", { fail: "ECONNRESET" }]]);
    const stub = new StubChargePolicy();
    const s = createOracleServer({ attestedFetch: broken, chargePolicy: stub });
    await new Promise<void>((resolve) => s.listen(0, "127.0.0.1", resolve));
    const b = `http://127.0.0.1:${(s.address() as AddressInfo).port}`;
    try {
      const res = await fetch(`${b}/data/crypto-price?id=bitcoin`);
      assert.equal(res.status, 502);
      const body = (await res.json()) as ErrorResponse;
      assert.equal(body.error.code, "upstream_failure");
      assert.match(body.error.message, /ECONNRESET/);
      // A failed call must not record a charge.
      assert.equal(stub.charges.length, 0);
    } finally {
      await new Promise<void>((resolve) => s.close(() => resolve()));
    }
  });

  test("502 when the upstream answers with an error status", async () => {
    const rateLimited = new FakeAttestedFetch([["api.coingecko.com", { status: 429, body: "slow down" }]]);
    const s = createOracleServer({ attestedFetch: rateLimited, chargePolicy: new StubChargePolicy() });
    await new Promise<void>((resolve) => s.listen(0, "127.0.0.1", resolve));
    const b = `http://127.0.0.1:${(s.address() as AddressInfo).port}`;
    try {
      const res = await fetch(`${b}/data/crypto-price?id=bitcoin`);
      assert.equal(res.status, 502);
      assert.match(((await res.json()) as ErrorResponse).error.message, /upstream responded 429/);
    } finally {
      await new Promise<void>((resolve) => s.close(() => resolve()));
    }
  });

  test("502 when the upstream body has the wrong shape", async () => {
    const weird = new FakeAttestedFetch([["api.coingecko.com", { status: 200, body: JSON.stringify({ dogecoin: {} }) }]]);
    const s = createOracleServer({ attestedFetch: weird, chargePolicy: new StubChargePolicy() });
    await new Promise<void>((resolve) => s.listen(0, "127.0.0.1", resolve));
    const b = `http://127.0.0.1:${(s.address() as AddressInfo).port}`;
    try {
      const res = await fetch(`${b}/data/crypto-price?id=bitcoin`);
      assert.equal(res.status, 502);
      assert.match(((await res.json()) as ErrorResponse).error.message, /no USD price/);
    } finally {
      await new Promise<void>((resolve) => s.close(() => resolve()));
    }
  });

  test("404 for unrouted paths", async () => {
    const res = await fetch(`${base}/frobnicate`);
    assert.equal(res.status, 404);
    assert.equal(((await res.json()) as ErrorResponse).error.code, "not_found");
  });
});

describe("GET /attest — attest-any-API (generic path)", () => {
  test("attests an arbitrary JSON endpoint and extracts the selected field", async () => {
    const q = new URLSearchParams({ url: "https://api.example.com/thing", extract: "data.score" });
    const res = await fetch(`${base}/attest?${q.toString()}`);
    assert.equal(res.status, 200);
    const body = (await res.json()) as AttestResponse;
    assert.equal(body.value, 4.2);
    assert.equal(body.extract, "data.score");
    assert.equal(body.attestation.body, CANNED_GENERIC);
    assert.equal(verifyAttestation(body.attestation).valid, true);
  });

  test("selector can index arrays", async () => {
    const q = new URLSearchParams({ url: "https://api.example.com/thing", extract: "data.arr.1" });
    const body = (await (await fetch(`${base}/attest?${q.toString()}`)).json()) as AttestResponse;
    assert.equal(body.value, 20);
  });

  test("blocks SSRF: cloud-metadata IP is refused before any fetch (400 unsafe_url)", async () => {
    const q = new URLSearchParams({ url: "http://169.254.169.254/latest/meta-data/", extract: "$" });
    const res = await fetch(`${base}/attest?${q.toString()}`);
    assert.equal(res.status, 400);
    assert.equal(((await res.json()) as ErrorResponse).error.code, "unsafe_url");
  });

  test("blocks SSRF: localhost and private ranges", async () => {
    for (const url of ["https://localhost/admin", "https://10.0.0.1/", "https://192.168.1.1/", "https://[::1]/"]) {
      const q = new URLSearchParams({ url, extract: "$" });
      const res = await fetch(`${base}/attest?${q.toString()}`);
      assert.equal(res.status, 400, `${url} should be blocked`);
      assert.equal(((await res.json()) as ErrorResponse).error.code, "unsafe_url");
    }
  });

  test("rejects non-https", async () => {
    const q = new URLSearchParams({ url: "http://api.example.com/thing", extract: "data.score" });
    const res = await fetch(`${base}/attest?${q.toString()}`);
    assert.equal(res.status, 400);
    assert.equal(((await res.json()) as ErrorResponse).error.code, "unsafe_url");
  });

  test("rejects an unsafe selector (400 bad_selector)", async () => {
    const q = new URLSearchParams({ url: "https://api.example.com/thing", extract: "data.__proto__.x" });
    const res = await fetch(`${base}/attest?${q.toString()}`);
    assert.equal(res.status, 400);
    assert.equal(((await res.json()) as ErrorResponse).error.code, "bad_selector");
  });

  test("extraction miss is a typed 422, never a guessed value", async () => {
    const q = new URLSearchParams({ url: "https://api.example.com/thing", extract: "data.nope" });
    const res = await fetch(`${base}/attest?${q.toString()}`);
    assert.equal(res.status, 422);
    assert.equal(((await res.json()) as ErrorResponse).error.code, "extract_failure");
  });

  test("upstream failure maps to 502 (attested-unavailable), records no charge", async () => {
    const broken = new FakeAttestedFetch([["api.example.com", { fail: "ETIMEDOUT" }]]);
    const stub = new StubChargePolicy();
    const s = createOracleServer({ attestedFetch: broken, chargePolicy: stub });
    await new Promise<void>((resolve) => s.listen(0, "127.0.0.1", resolve));
    const b = `http://127.0.0.1:${(s.address() as AddressInfo).port}`;
    try {
      const q = new URLSearchParams({ url: "https://api.example.com/thing", extract: "data.score" });
      const res = await fetch(`${b}/attest?${q.toString()}`);
      assert.equal(res.status, 502);
      assert.equal(stub.charges.length, 0);
    } finally {
      await new Promise<void>((resolve) => s.close(() => resolve()));
    }
  });
});

describe("unit — SSRF guard (assertSafeUrl)", () => {
  test("passes a public https URL", () => {
    assert.doesNotThrow(() => assertSafeUrl("https://api.coingecko.com/api/v3/simple/price?ids=bitcoin"));
  });

  test("rejects non-https, credentials, and internal/private/metadata targets", () => {
    const bad = [
      "http://api.example.com/", // not https
      "https://user:pass@api.example.com/", // credentials
      "https://localhost/", // loopback name
      "https://sub.localhost/", // *.localhost
      "https://127.0.0.1/", // loopback
      "https://10.1.2.3/", // 10/8
      "https://172.16.5.4/", // 172.16/12
      "https://192.168.0.1/", // 192.168/16
      "https://169.254.169.254/", // link-local / metadata
      "https://100.64.0.1/", // CGNAT
      "https://[::1]/", // v6 loopback
      "https://[fd00::1]/", // v6 ULA
      "https://metadata.google.internal/", // GCP metadata
    ];
    for (const url of bad) {
      assert.throws(() => assertSafeUrl(url), OracleError, `should reject ${url}`);
    }
  });
});

describe("unit — safe selector (parseSelector / extractBySelector)", () => {
  const root = { a: { b: [{ c: 7 }, { c: 8 }] }, price: 1.5 };

  test('"$" / "" returns the root', () => {
    assert.deepEqual(parseSelector("$"), []);
    assert.deepEqual(parseSelector(""), []);
    assert.deepEqual(extractBySelector(42, "$"), { ok: true, value: 42 });
  });

  test("navigates objects and array indices", () => {
    assert.deepEqual(extractBySelector(root, "price"), { ok: true, value: 1.5 });
    assert.deepEqual(extractBySelector(root, "a.b.1.c"), { ok: true, value: 8 });
  });

  test("a missing path is a typed miss, not a throw or a guess", () => {
    const r = extractBySelector(root, "a.z");
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.error.code, "extract_failure");
  });

  test("rejects prototype-pollution and out-of-charset segments", () => {
    assert.throws(() => parseSelector("a.__proto__.x"), OracleError);
    assert.throws(() => parseSelector("a.b;rm -rf"), OracleError);
    assert.throws(() => parseSelector("a[b]"), OracleError);
  });
});
