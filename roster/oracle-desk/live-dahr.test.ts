/**
 * Offline tests for the LiveDahr adapter and the on-chain anchor verifier.
 * No network: a FakeDahrProxy stands in for the Demos node's web2 proxy, and a
 * fake TxReader stands in for the chain. The point is to prove the adapter's
 * wire shape and the honest verify path — not to exercise the live node (that's
 * roster/oracle-desk/demo-live-dahr.ts).
 */
import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
import { test } from "node:test";

import { verifyAttestation, verifyAttestedRecord } from "./attested-fetch.js";
import {
  LiveDahr,
  verifyLiveAnchorOnChain,
  type DahrProxyPort,
  type DahrProxyResult,
  type TxReader,
} from "./live-dahr.js";

const sha256 = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");

const WALLET = "0x4401feab4dfc36e1166ad0dc1c4987dd0c728a57616fa496c25ca2a260651808";
const URL = "https://api.frankfurter.dev/v1/latest?base=USD&symbols=EUR";
const BODY = '{"amount":1.0,"base":"USD","date":"2026-07-09","rates":{"EUR":0.87451}}';
const TX = "3cabba89bf623067db1df699cda66c7fc95d5b28de017a72edab5c13806df5ce";

class FakeDahrProxy implements DahrProxyPort {
  readonly requested: string[] = [];
  constructor(private readonly result: (url: string) => DahrProxyResult) {}
  async proxy(url: string): Promise<DahrProxyResult> {
    this.requested.push(url);
    return this.result(url);
  }
  walletAddress(): string {
    return WALLET;
  }
}

/** A realistic node result: data is the raw body STRING (the documented gotcha),
 *  responseHash = sha256(body), plus an on-chain anchor txHash. */
function nodeResult(body = BODY): DahrProxyResult {
  return {
    status: 200,
    data: body,
    responseHash: sha256(body),
    responseHeadersHash: sha256("headers"),
    txHash: TX,
  };
}

test("LiveDahr emits a verifiable LIVE-DAHR-web2Request attestation", async () => {
  const port = new FakeDahrProxy(() => nodeResult());
  const res = await new LiveDahr(port).attestFetch(URL);

  assert.equal(res.status, 200);
  assert.equal(res.body, BODY);
  assert.equal(res.bodyHash, sha256(BODY));
  assert.equal(res.attestation.scheme, "LIVE-DAHR-web2Request");
  // digest = node responseHash = sha256(body) = bodyHash
  assert.equal(res.attestation.digest, res.bodyHash);
  assert.equal(res.attestation.anchorTxRef, TX);
  assert.equal(res.attestation.signature, TX); // commitment ref, not a node sig
  assert.equal(res.attestation.publicKey, WALLET); // committing identity
  assert.match(res.attestation.note, /self-observed commitment/i);
  assert.match(res.attestation.note, /NOT a consensus/i);

  // The existing offline verify path validates the live record.
  assert.deepEqual(verifyAttestation(res), { valid: true });
  assert.deepEqual(
    verifyAttestedRecord({
      url: res.url,
      fetchedAt: res.fetchedAt,
      bodyHash: res.bodyHash,
      attestation: res.attestation,
    }),
    { valid: true },
  );
});

test("verifyAttestation rejects a tampered live body", async () => {
  const port = new FakeDahrProxy(() => nodeResult());
  const res = await new LiveDahr(port).attestFetch(URL);
  const tampered = { ...res, body: res.body.replace("0.87451", "9.99999") };
  const v = verifyAttestation(tampered);
  assert.equal(v.valid, false);
  assert.match(v.reason ?? "", /bodyHash does not match body/);
});

test("verifyAttestedRecord rejects a live digest that isn't the body hash", () => {
  const v = verifyAttestedRecord({
    url: URL,
    fetchedAt: new Date().toISOString(),
    bodyHash: sha256(BODY),
    attestation: {
      scheme: "LIVE-DAHR-web2Request",
      note: "x",
      digest: sha256("something-else"),
      signature: TX,
      publicKey: WALLET,
      anchorTxRef: TX,
    },
  });
  assert.equal(v.valid, false);
  assert.match(v.reason ?? "", /responseHash.*bodyHash/);
});

test("LiveDahr refuses when the node's responseHash disagrees with the body", async () => {
  const port = new FakeDahrProxy(() => ({ ...nodeResult(), responseHash: sha256("lie") }));
  await assert.rejects(() => new LiveDahr(port).attestFetch(URL), /responseHash.*!=.*sha256\(body\)/);
});

test("LiveDahr handles a parsed-object data field (round-trips to the same hash)", async () => {
  // If the SDK hands back parsed JSON, LiveDahr stringifies it; the node's
  // responseHash must be over that same serialisation for it to pass.
  const obj = { a: 1, b: "two" };
  const serialised = JSON.stringify(obj);
  const port = new FakeDahrProxy(() => ({
    status: 200,
    data: obj,
    responseHash: sha256(serialised),
    txHash: TX,
  }));
  const res = await new LiveDahr(port).attestFetch(URL);
  assert.equal(res.body, serialised);
  assert.deepEqual(verifyAttestation(res), { valid: true });
});

test("LiveDahr enforces https-only / SSRF guard before hitting the node", async () => {
  const port = new FakeDahrProxy(() => nodeResult());
  await assert.rejects(() => new LiveDahr(port).attestFetch("http://169.254.169.254/latest/meta-data"));
  assert.equal(port.requested.length, 0, "guard must run before the node round-trip");
});

test("LiveDahr tolerates a non-broadcast anchor (empty txHash)", async () => {
  const port = new FakeDahrProxy(() => ({ ...nodeResult(), txHash: undefined }));
  const res = await new LiveDahr(port).attestFetch(URL);
  assert.equal(res.attestation.anchorTxRef, "");
  assert.equal(res.attestation.signature, "");
  // Offline body-integrity verification still holds.
  assert.deepEqual(verifyAttestation(res), { valid: true });
});

// --- on-chain anchor verifier ------------------------------------------------

/** The shape getTxByHash returns for a web2Request anchor (mirrors the live probe). */
function anchorTx(opts: { responseHash: string; url: string; from?: string; status?: string; block?: number }) {
  return {
    content: {
      type: "web2Request",
      from: opts.from ?? WALLET,
      data: [
        "web2Request",
        {
          message: {
            web2Request: {
              result: { targetUrl: opts.url, responseHash: opts.responseHash },
              signature: { type: "ed25519", data: "" }, // node does NOT sign — empty, as measured
            },
          },
        },
      ],
    },
    signature: { type: "ed25519", data: "0xe30b1aa6ef93a0808c6153ac65ca0222dbe" }, // client sig
    status: opts.status ?? "confirmed",
    blockNumber: opts.block ?? 61598,
  };
}

test("verifyLiveAnchorOnChain confirms a matching anchor and is honest about scope", async () => {
  const port = new FakeDahrProxy(() => nodeResult());
  const res = await new LiveDahr(port).attestFetch(URL);
  const reader: TxReader = {
    async getTxByHash() {
      return anchorTx({ responseHash: res.attestation.digest, url: URL });
    },
  };
  const v = await verifyLiveAnchorOnChain(res, reader);
  assert.equal(v.valid, true);
  assert.equal(v.committedBy, WALLET);
  assert.equal(v.blockNumber, 61598);
  assert.match(v.proves ?? "", /committed .*responseHash/i);
  assert.match(v.doesNotProve ?? "", /upstream.*actually returned/i);
});

test("verifyLiveAnchorOnChain rejects an anchor that commits a different hash", async () => {
  const port = new FakeDahrProxy(() => nodeResult());
  const res = await new LiveDahr(port).attestFetch(URL);
  const reader: TxReader = {
    async getTxByHash() {
      return anchorTx({ responseHash: sha256("different"), url: URL });
    },
  };
  const v = await verifyLiveAnchorOnChain(res, reader);
  assert.equal(v.valid, false);
  assert.match(v.reason ?? "", /responseHash.*!=.*digest/);
});

test("verifyLiveAnchorOnChain rejects a non-web2Request tx and a missing tx", async () => {
  const port = new FakeDahrProxy(() => nodeResult());
  const res = await new LiveDahr(port).attestFetch(URL);
  const wrongType: TxReader = { async getTxByHash() { return { content: { type: "native" } }; } };
  assert.equal((await verifyLiveAnchorOnChain(res, wrongType)).valid, false);
  const missing: TxReader = { async getTxByHash() { return null; } };
  assert.equal((await verifyLiveAnchorOnChain(res, missing)).valid, false);
});

test("verifyLiveAnchorOnChain refuses non-live (mock) attestations", async () => {
  const reader: TxReader = { async getTxByHash() { return anchorTx({ responseHash: "x", url: URL }); } };
  const v = await verifyLiveAnchorOnChain(
    { url: URL, attestation: { scheme: "MOCK-DAHR-ed25519", note: "", digest: "", signature: "", publicKey: "" } },
    reader,
  );
  assert.equal(v.valid, false);
  assert.match(v.reason ?? "", /not a live DAHR/);
});
