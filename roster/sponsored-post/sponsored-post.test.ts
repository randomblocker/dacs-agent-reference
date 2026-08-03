import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import type { DeliveryAttestation } from "../dacs/seller-adapter.js";
import { makeSponsoredPostWork, sponsoredPostObserveDelivered } from "../dacs/wire/sponsored-post.js";
import {
  FileSponsoredPostIdempotencyStore,
  MemorySponsoredPostIdempotencyStore,
} from "./idempotency.js";
import { parseSponsoredPostRequest, type SponsoredPostModerationPort } from "./policy.js";
import { HttpSponsoredPostModerationPort } from "./moderation.js";
import {
  SponsoredPostPublishError,
  XApiSponsoredPostPort,
  type SponsoredPostPort,
} from "./x-api.js";

const text = "DACS agents buy verifiable work on open rails. #DACS";

const moderation: SponsoredPostModerationPort = {
  async review() {
    return { allowed: true, decisionRef: "moderation:test:1" };
  },
};

function published(id = "1234567890123456789", postText = text) {
  return {
    postId: id,
    text: postText,
    handle: "DACSdemo",
    url: `https://x.com/DACSdemo/status/${id}`,
    publishedAt: 1_753_200_000_000,
    paidPartnership: true as const,
    madeWithAi: false as const,
  };
}

test("Sponsored Post request is exact, bounded and structurally abuse-resistant", () => {
  assert.deepEqual(parseSponsoredPostRequest({ text }), { text });
  assert.throws(() => parseSponsoredPostRequest({ text, url: "https://example.com" }), /only accepts text/);
  assert.throws(() => parseSponsoredPostRequest({ text: " https://example.com " }), /leading or trailing/);
  assert.throws(() => parseSponsoredPostRequest({ text: "Buy this https://example.com" }), /links are not accepted/);
  assert.throws(() => parseSponsoredPostRequest({ text: "Hello @someone" }), /mentions are not accepted/);
  assert.throws(() => parseSponsoredPostRequest({ text: "#one #two" }), /at most one hashtag/);
  assert.throws(() => parseSponsoredPostRequest({ text: "a".repeat(241) }), /1 to 240/);
  assert.throws(() => parseSponsoredPostRequest({ text: `key ${"a".repeat(64)}` }), /private key/);
});

test("X API adapter publishes only an exact, disclosed standalone post", async () => {
  let request: RequestInit | undefined;
  const port = new XApiSponsoredPostPort({
    userAccessToken: "secret-user-token",
    handle: "@DACSdemo",
    fetcher: async (url, init) => {
      assert.equal(url, "https://api.x.com/2/tweets");
      request = init;
      return new Response(JSON.stringify({ data: { id: "123", text } }), {
        status: 201,
        headers: { "content-type": "application/json" },
      });
    },
  });
  const result = await port.publish({ text });
  assert.equal(result.postId, "123");
  assert.equal(result.text, text);
  assert.equal(result.handle, "DACSdemo");
  assert.equal(result.url, "https://x.com/DACSdemo/status/123");
  assert.equal(result.paidPartnership, true);
  assert.equal(result.madeWithAi, false);
  assert.ok(Number.isSafeInteger(result.publishedAt));
  const body = JSON.parse(String(request?.body));
  assert.deepEqual(body, { text, paid_partnership: true, made_with_ai: false });
  assert.equal((request?.headers as Record<string, string>).authorization, "Bearer secret-user-token");
});

test("X OAuth token must control the DACS-linked account", async () => {
  const port = new XApiSponsoredPostPort({
    userAccessToken: "secret-user-token",
    handle: "DACSdemo",
    fetcher: async (url) => {
      assert.equal(url, "https://api.x.com/2/users/me");
      return new Response(JSON.stringify({ data: { id: "42", username: "DACSdemo" } }), { status: 200 });
    },
  });
  await port.verifyAccount("42");
  await assert.rejects(() => port.verifyAccount("43"), /does not control/);
});

test("HTTP moderation is fail-closed and returns only a bounded auditable decision", async () => {
  const port = new HttpSponsoredPostModerationPort({
    endpoint: "https://moderation.example/v1/review",
    bearerToken: "moderation-secret",
    fetcher: async (_url, init) => {
      assert.equal((init?.headers as Record<string, string>).authorization, "Bearer moderation-secret");
      return new Response(JSON.stringify({ allowed: true, decisionRef: "review:test-42" }), { status: 200 });
    },
  });
  assert.deepEqual(await port.review({ text, textHash: "a".repeat(64) }), {
    allowed: true,
    decisionRef: "review:test-42",
  });
  assert.throws(
    () => new HttpSponsoredPostModerationPort({ endpoint: "http://moderation.example", bearerToken: "secret" }),
    /must use https/,
  );
});

test("paid work publishes once and returns the same evidence for an idempotent retry", async () => {
  let calls = 0;
  const publisher: SponsoredPostPort = {
    async publish() {
      calls += 1;
      return published();
    },
  };
  const work = makeSponsoredPostWork(publisher, moderation, new MemorySponsoredPostIdempotencyStore());
  const first = await work("job-one", { text });
  const second = await work("job-one", { text });
  assert.equal(calls, 1);
  assert.deepEqual(second, first);

  const attestation = {
    kind: "dacs-x-delivery-attestation",
    serviceId: "sponsored-post",
    jobId: "job-one",
    resultHash: "a".repeat(64),
    meta: first.meta,
    deliveredAt: new Date().toISOString(),
  } satisfies DeliveryAttestation;
  assert.deepEqual(await sponsoredPostObserveDelivered("DACSdemo")!(attestation), { ok: true });
});

test("an indeterminate X response blocks retries instead of risking a duplicate post", async () => {
  let calls = 0;
  const publisher: SponsoredPostPort = {
    async publish() {
      calls += 1;
      throw new SponsoredPostPublishError("timeout after send", "indeterminate");
    },
  };
  const work = makeSponsoredPostWork(publisher, moderation, new MemorySponsoredPostIdempotencyStore());
  await assert.rejects(() => work("job-unknown", { text }), /timeout after send/);
  await assert.rejects(() => work("job-unknown", { text }), /reconcile the dedicated X account/);
  assert.equal(calls, 1);
});

test("Unicode is posted exactly but on-chain delivery evidence remains ASCII-safe", async () => {
  const unicodeText = "Café agents settle verifiable work. #DACS";
  const work = makeSponsoredPostWork({
    async publish(input) {
      assert.equal(input.text, unicodeText);
      return published("777", unicodeText);
    },
  }, moderation, new MemorySponsoredPostIdempotencyStore());
  const result = await work("job-unicode", { text: unicodeText });
  const reportJson = String(result.meta?.reportJson);
  assert.match(reportJson, /^[\x00-\x7F]*$/);
  assert.ok(!reportJson.includes("Café"));
  const attestation = {
    kind: "dacs-x-delivery-attestation",
    serviceId: "sponsored-post",
    jobId: "job-unicode",
    resultHash: "b".repeat(64),
    meta: result.meta,
    deliveredAt: new Date().toISOString(),
  } satisfies DeliveryAttestation;
  assert.deepEqual(await sponsoredPostObserveDelivered("DACSdemo")!(attestation), { ok: true });
});

test("a definite X rejection releases the reservation for a safe retry", async () => {
  let calls = 0;
  const publisher: SponsoredPostPort = {
    async publish() {
      calls += 1;
      if (calls === 1) throw new SponsoredPostPublishError("policy rejection", "rejected", 400);
      return published();
    },
  };
  const work = makeSponsoredPostWork(publisher, moderation, new MemorySponsoredPostIdempotencyStore());
  await assert.rejects(() => work("job-rejected", { text }), /policy rejection/);
  await work("job-rejected", { text });
  assert.equal(calls, 2);
});

test("file idempotency state is private and durable across store instances", async () => {
  const root = await mkdtemp(join(tmpdir(), "dacs-sponsored-post-"));
  try {
    const first = new FileSponsoredPostIdempotencyStore(root);
    assert.deepEqual(await first.begin("job-file", "a".repeat(64)), { kind: "new" });
    await first.complete("job-file", "a".repeat(64), published());
    const second = new FileSponsoredPostIdempotencyStore(root);
    assert.deepEqual(await second.begin("job-file", "a".repeat(64)), { kind: "complete", post: published() });
    const raw = JSON.parse(await readFile(join(root, "job-file.json"), "utf8"));
    assert.equal(raw.status, "complete");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
