// sec-audit fixture — INTENTIONALLY VULNERABLE. Every value below is fake;
// the AWS key is the documented example key from AWS's own docs.
"use strict";
const { exec } = require("node:child_process");
const https = require("node:https");

// secret-aws-key: classic AWS docs example access key id (fake).
const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";

// code-eval: dynamic code execution over caller-supplied input.
function run(userInput) {
  return eval(userInput);
}

// code-exec-interpolation: shell command built by template interpolation.
function ping(host, done) {
  exec(`ping -c 1 ${host}`, done);
}

// crypto-math-random-token: predictable session token.
function newSession() {
  const sessionToken = "tok_" + Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
  return sessionToken;
}

// code-http-url: plaintext endpoint (this one is NOT suppressed).
const API_BASE = "http://api.fixture.internal/v1";

// tls-verification-disabled: MITM-able agent.
const insecureAgent = new https.Agent({ rejectUnauthorized: false });

// The next line demonstrates the inline suppression mechanism: the same
// rule as API_BASE, but acknowledged. Suppressions are counted, not silent.
// audit-ok code-http-url — legacy health endpoint, tracked in FIXTURE-42
const LEGACY_HEALTH_URL = "http://legacy.fixture.internal/healthz";

module.exports = { run, ping, newSession, API_BASE, insecureAgent, AWS_ACCESS_KEY_ID, LEGACY_HEALTH_URL };
