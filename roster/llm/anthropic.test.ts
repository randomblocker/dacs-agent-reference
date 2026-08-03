import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AnthropicError, AnthropicLlm, AnthropicQuotaError } from "./anthropic.js";

test("Anthropic adapter sends bounded Messages API requests without leaking the key", async () => {
  let seen: RequestInit | undefined;
  const llm = new AnthropicLlm({ apiKey: "secret-key", model: "test-model", fetchFn: async (_url, init) => {
    seen = init;
    return new Response(JSON.stringify({ content: [{ type: "text", text: " answer " }], stop_reason: "end_turn" }), { status: 200, headers: { "request-id": "req-test" } });
  }});
  assert.equal(await llm.complete("hello", { maxTokens: 20 }), "answer");
  const body = JSON.parse(String(seen?.body)) as Record<string, unknown>;
  assert.equal(body.model, "test-model");
  assert.equal(body.max_tokens, 20);
  assert.equal((seen?.headers as Record<string, string>)["x-api-key"], "secret-key");
  assert.doesNotMatch(JSON.stringify(body), /secret-key/);
});

test("Anthropic adapter retries transient errors but not authentication errors", async () => {
  let calls = 0;
  const retrying = new AnthropicLlm({ apiKey: "k", fetchFn: async () => {
    calls += 1;
    return calls === 1
      ? new Response(JSON.stringify({ error: { type: "overloaded_error" } }), { status: 529 })
      : new Response(JSON.stringify({ content: [{ type: "text", text: "ok" }] }), { status: 200 });
  }});
  assert.equal(await retrying.complete("hello"), "ok");
  assert.equal(calls, 2);

  const denied = new AnthropicLlm({ apiKey: "bad", fetchFn: async () => new Response(JSON.stringify({ error: { type: "authentication_error" } }), { status: 401 }) });
  await assert.rejects(() => denied.complete("hello"), (error) => error instanceof AnthropicError && error.status === 401 && !error.retryable);
});

test("Anthropic quota persists reservations and fails closed", async () => {
  const directory = mkdtempSync(join(tmpdir(), "dacs-anthropic-quota-"));
  const usageFile = join(directory, "usage.json");
  let calls = 0;
  const fetchFn = async () => {
    calls += 1;
    return new Response(JSON.stringify({ content: [{ type: "text", text: "ok" }] }), { status: 200 });
  };
  const quota = {
    usageFile,
    maxCallsPerHour: 2,
    maxCallsPerDay: 3,
    maxInputCharsPerDay: 100,
    maxOutputTokensPerDay: 25,
  };
  try {
    const first = new AnthropicLlm({ apiKey: "k", fetchFn, quota });
    assert.equal(await first.complete("hello", { maxTokens: 10 }), "ok");
    const restarted = new AnthropicLlm({ apiKey: "k", fetchFn, quota });
    assert.equal(await restarted.complete("again", { maxTokens: 10 }), "ok");
    await assert.rejects(() => restarted.complete("blocked", { maxTokens: 1 }), AnthropicQuotaError);
    assert.equal(calls, 2);
    assert.deepEqual(restarted.quotaStatus().remaining, {
      callsThisHour: 0,
      callsToday: 1,
      inputCharsToday: 90,
      outputTokensToday: 5,
    });

    writeFileSync(usageFile, "not-json\n");
    const corrupt = new AnthropicLlm({ apiKey: "k", fetchFn, quota });
    await assert.rejects(() => corrupt.complete("no outbound call", { maxTokens: 1 }), AnthropicQuotaError);
    assert.equal(calls, 2);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
