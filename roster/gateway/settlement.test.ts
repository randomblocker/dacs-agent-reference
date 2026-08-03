/**
 * Pay-dem settlement tests — the PaymentGate unit + the gateway's 402/paid HTTP
 * flow, all offline with a fake tx reader (no chain).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { createHash } from "node:crypto";
import { loadConfig, type GatewayConfig } from "./config.js";
import { createGatewayServer } from "./server.js";
import { defineAgent } from "./types.js";
import { MockDahrAttestor } from "../oracle-desk/attested-fetch.js";
import { PaymentGate, uniformFee, OS_PER_DEM, type DemTx, type TxReader, type Settlement } from "./settlement.js";

const TOKEN = "test-token-abcdef012345";
const GW = "0xgatewaywallet";
const BUYER = "0xbuyerwallet";

function fakeReader(txs: Record<string, DemTx>): TxReader {
  return { async getTxByHash(h) { return txs[h.toLowerCase()] ?? null; } };
}
function nativeTx(from: string, to: string, amountOs: bigint, status = "confirmed"): DemTx {
  return { status, blockNumber: 1, content: { type: "native", from, to, amount: amountOs.toString() } };
}

// ── Unit: PaymentGate ────────────────────────────────────────────────────────
test("PaymentGate reserves a valid payment, rejects replay, re-allows after release", async () => {
  const TX = "a".repeat(64);
  const gate = new PaymentGate(fakeReader({ [TX]: nativeTx(BUYER, GW, OS_PER_DEM) }), GW);
  const v = await gate.verifyAndReserve(TX, OS_PER_DEM);
  assert.equal(v.ok, true);
  assert.equal(v.payer, BUYER);
  assert.equal(v.amountOs, OS_PER_DEM);
  const replay = await gate.verifyAndReserve(TX, OS_PER_DEM);
  assert.equal(replay.ok, false);
  assert.match(replay.reason ?? "", /already been used/);
  gate.release(TX);
  assert.equal((await gate.verifyAndReserve(TX, OS_PER_DEM)).ok, true);
});

test("PaymentGate rejects underpaid / wrong recipient / unconfirmed / missing / bad hash", async () => {
  const under = "b".repeat(64);
  const g1 = new PaymentGate(fakeReader({ [under]: nativeTx(BUYER, GW, OS_PER_DEM / 2n) }), GW);
  assert.match((await g1.verifyAndReserve(under, OS_PER_DEM)).reason ?? "", /underpaid/);

  const wrong = "c".repeat(64);
  const g2 = new PaymentGate(fakeReader({ [wrong]: nativeTx(BUYER, "0xsomeoneelse", OS_PER_DEM) }), GW);
  assert.match((await g2.verifyAndReserve(wrong, OS_PER_DEM)).reason ?? "", /recipient/);

  const pending = "d".repeat(64);
  const g3 = new PaymentGate(fakeReader({ [pending]: nativeTx(BUYER, GW, OS_PER_DEM, "pending") }), GW);
  const r3 = await g3.verifyAndReserve(pending, OS_PER_DEM);
  assert.equal(r3.ok, false);
  assert.equal(r3.retriable, true);

  const g4 = new PaymentGate(fakeReader({}), GW);
  assert.equal((await g4.verifyAndReserve("e".repeat(64), OS_PER_DEM)).retriable, true); // not found
  assert.match((await g4.verifyAndReserve("nothex", OS_PER_DEM)).reason ?? "", /64-hex/);

  const hydrating = "f".repeat(64);
  const hydration = await new PaymentGate(fakeReader({
    [hydrating]: { status: "confirmed", blockNumber: 2, content: {} },
  }), GW).verifyAndReserve(hydrating, OS_PER_DEM);
  assert.equal(hydration.ok, false);
  assert.equal(hydration.retriable, true);
  assert.match(hydration.reason ?? "", /not readable yet/);

  // A confirmed native payment whose `type` is transiently misreported by the
  // node (present-but-wrong, with the data-kind marker still "native") must be
  // RETRIABLE, never a hard rejection — otherwise the buyer loses money on a
  // valid payment. Observed live 2026-07-20 (job ef0466d5): tx read non-native
  // at settle time, read "native" moments later.
  const misread = "a".repeat(64);
  const transient = await new PaymentGate(fakeReader({
    [misread]: { status: "confirmed", blockNumber: 3, content: { type: "", from: BUYER, to: GW, amount: OS_PER_DEM.toString(), data: ["native"] } },
  }), GW).verifyAndReserve(misread, OS_PER_DEM);
  assert.equal(transient.ok, false);
  assert.equal(transient.retriable, true, "a confirmed native payment misread as non-native must be retriable");

  // The retry converges: once the node serves the settled native content, the
  // same hash verifies. (A fresh gate models the later, consistent read.)
  const settled = await new PaymentGate(fakeReader({
    [misread]: nativeTx(BUYER, GW, OS_PER_DEM),
  }), GW).verifyAndReserve(misread, OS_PER_DEM);
  assert.equal(settled.ok, true, "the same payment verifies once the node's content view settles");
});

test("PaymentGate falls back to bounded recipient history and reserves only after a complete receipt", async () => {
  const TX = "7".repeat(64);
  const complete = { ...nativeTx(BUYER, GW, OS_PER_DEM), hash: TX, blockNumber: 44 };
  const reader: TxReader = {
    getTxByHash: async () => new Promise<DemTx | null>(() => undefined),
    getTransactionHistory: async (address) => {
      assert.equal(address, GW);
      return [complete];
    },
  };
  const gate = new PaymentGate(reader, GW, 5);
  const verified = await gate.verifyAndReserve(TX, OS_PER_DEM);
  assert.deepEqual(verified, { ok: true, payer: BUYER, amountOs: OS_PER_DEM, blockNumber: 44 });

  const incompleteTx = "8".repeat(64);
  let hydrated = false;
  const incompleteGate = new PaymentGate({
    async getTxByHash() {
      return hydrated
        ? { ...nativeTx(BUYER, GW, OS_PER_DEM), hash: incompleteTx, blockNumber: 45 }
        : { ...nativeTx(BUYER, GW, OS_PER_DEM), hash: incompleteTx, blockNumber: undefined };
    },
  }, GW, 5);
  const first = await incompleteGate.verifyAndReserve(incompleteTx, OS_PER_DEM);
  assert.equal(first.ok, false);
  assert.equal(first.retriable, true);
  hydrated = true;
  assert.equal((await incompleteGate.verifyAndReserve(incompleteTx, OS_PER_DEM)).ok, true,
    "an incomplete receipt must not consume the payment reservation");
});

test("PaymentGate verifies exact payment content from authoritative inclusion before indexes hydrate", async () => {
  const transactionContent = {
    type: "native",
    from: BUYER,
    to: GW,
    amount: OS_PER_DEM.toString(),
    nonce: 17,
  };
  const txHash = createHash("sha256").update(JSON.stringify(transactionContent), "utf8").digest("hex");
  let historyReads = 0;
  const gate = new PaymentGate({
    getTxByHash: async () => null,
    getTransactionHistory: async () => { historyReads += 1; return []; },
    call: async () => ({ state: "included", blockNumber: 55 }),
  }, GW);
  const result = await gate.verifyAndReserve(txHash, OS_PER_DEM, { transactionContent, blockNumber: 55 });
  assert.deepEqual(result, { ok: true, payer: BUYER, amountOs: OS_PER_DEM, blockNumber: 55 });
  assert.equal(historyReads, 1, "history remains a parallel fallback but is not required for the result");
});

test("PaymentGate rejects a forged inclusion proof before querying the chain", async () => {
  let reads = 0;
  const gate = new PaymentGate({
    getTxByHash: async () => { reads += 1; return null; },
    call: async () => ({ state: "included", blockNumber: 56 }),
  }, GW);
  const result = await gate.verifyAndReserve("e".repeat(64), OS_PER_DEM, {
    transactionContent: { type: "native", from: BUYER, to: GW, amount: OS_PER_DEM.toString(), nonce: 18 },
    blockNumber: 56,
  });
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /does not match/);
  assert.equal(reads, 0);
});

// ── Integration: gateway 402/paid flow ───────────────────────────────────────
const strictAgent = defineAgent({
  name: "strict",
  summary: "test agent that requires field x",
  mode: "test",
  fields: [{ name: "x", type: "string", required: true }],
  async invoke(input) {
    return { got: (input as { x: string }).x };
  },
});

async function listenPaid(reader: TxReader): Promise<{ base: string; server: http.Server }> {
  const settlement: Settlement = { gate: new PaymentGate(reader, GW), fee: uniformFee(OS_PER_DEM) };
  const config: GatewayConfig = { ...loadConfig({ GATEWAY_TOKEN: TOKEN }), port: 0 };
  const server = createGatewayServer(config, [strictAgent], new MockDahrAttestor(), undefined, settlement);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const addr = server.address() as { port: number };
  return { base: `http://127.0.0.1:${addr.port}`, server };
}

test("gateway: 402 without payment, 200 with valid payment, replay 402", async () => {
  const TX = "1".repeat(64);
  const { base, server } = await listenPaid(fakeReader({ [TX]: nativeTx(BUYER, GW, OS_PER_DEM) }));
  try {
    const r402 = await fetch(`${base}/agents/strict`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ x: "hi" }),
    });
    assert.equal(r402.status, 402);
    const b402 = (await r402.json()) as { error: { code: string; details: { fee: { payTo: string } } } };
    assert.equal(b402.error.code, "payment_required");
    assert.equal(b402.error.details.fee.payTo, GW);

    const r200 = await fetch(`${base}/agents/strict`, {
      method: "POST", headers: { "content-type": "application/json", "x-payment-tx": TX }, body: JSON.stringify({ x: "hi" }),
    });
    assert.equal(r200.status, 200);
    const b200 = (await r200.json()) as { result: { got: string }; settlement: { paid: boolean; payer: string } };
    assert.equal(b200.result.got, "hi");
    assert.equal(b200.settlement.paid, true);
    assert.equal(b200.settlement.payer, BUYER);

    const replay = await fetch(`${base}/agents/strict`, {
      method: "POST", headers: { "content-type": "application/json", "x-payment-tx": TX }, body: JSON.stringify({ x: "hi" }),
    });
    assert.equal(replay.status, 402);
  } finally {
    server.close();
  }
});

test("gateway: operator token is free; bad input RELEASES payment so retry succeeds", async () => {
  const TX = "2".repeat(64);
  const { base, server } = await listenPaid(fakeReader({ [TX]: nativeTx(BUYER, GW, OS_PER_DEM) }));
  try {
    const free = await fetch(`${base}/agents/strict`, {
      method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${TOKEN}` }, body: JSON.stringify({ x: "ok" }),
    });
    assert.equal(free.status, 200);
    assert.equal((await free.json() as { settlement?: unknown }).settlement, undefined);

    // Pay + BAD input → 400; the reservation must be released.
    const bad = await fetch(`${base}/agents/strict`, {
      method: "POST", headers: { "content-type": "application/json", "x-payment-tx": TX }, body: JSON.stringify({}),
    });
    assert.equal(bad.status, 400);

    // Same tx + GOOD input → 200 (proves the payment was released, not burned).
    const good = await fetch(`${base}/agents/strict`, {
      method: "POST", headers: { "content-type": "application/json", "x-payment-tx": TX }, body: JSON.stringify({ x: "recovered" }),
    });
    assert.equal(good.status, 200);
    assert.equal((await good.json() as { settlement: { paid: boolean } }).settlement.paid, true);
  } finally {
    server.close();
  }
});
