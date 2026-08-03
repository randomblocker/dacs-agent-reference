import { test } from "node:test";
import assert from "node:assert/strict";
import { ButlerDemoError, DemoRateLimiter } from "./butler-web.js";

test("DemoRateLimiter enforces concurrency and releases slots", () => {
  const limiter = new DemoRateLimiter(3, 60_000, 1);
  const leave = limiter.enter("127.0.0.1");
  assert.throws(() => limiter.enter("127.0.0.2"), (error) => error instanceof ButlerDemoError && error.status === 503);
  leave();
  const leave2 = limiter.enter("127.0.0.2");
  leave2();
});

test("DemoRateLimiter enforces the per-address window", () => {
  const limiter = new DemoRateLimiter(2, 60_000, 2);
  limiter.enter("198.51.100.1")();
  limiter.enter("198.51.100.1")();
  assert.throws(() => limiter.enter("198.51.100.1"), (error) => error instanceof ButlerDemoError && error.status === 429);
});
