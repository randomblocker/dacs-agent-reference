/**
 * Gateway demo — starts the gateway on an ephemeral port in dev mode and
 * exercises the surface end to end:
 *
 *   GET  /health
 *   GET  /agents
 *   POST /agents/evalbot            (offline → expect a ruling)
 *   POST /agents/procurement-butler (offline stub → expect a decision)
 *   POST /agents/oracle-desk        (LIVE crypto-price bitcoin → warn+skip on upstream failure)
 *   POST without token on a SEPARATE authed instance → expect 401
 *   POST bad input → expect 400
 *
 *   npm run roster:gateway
 *
 * Exit 0 only if the offline expectations + auth/validation behaviour hold.
 * A failed LIVE oracle call warns and is skipped (upstream flakiness is not
 * a gateway defect).
 */
import type { AddressInfo } from "node:net";
import type http from "node:http";
import { randomBytes } from "node:crypto";
import { loadConfig, type GatewayConfig } from "./config.js";
import { buildRealPorts } from "./ports.js";
import { buildRegistry } from "./registry.js";
import { createGatewayServer } from "./server.js";
import type { GatewayPorts } from "./types.js";

const hr = (t: string) => console.log(`\n=== ${t} ${"=".repeat(Math.max(0, 58 - t.length))}`);
const ok = (m: string) => console.log(`  ✓ ${m}`);
const warn = (m: string) => console.log(`  ⚠ ${m}`);
const fail = (m: string) => console.log(`  ✗ ${m}`);

let failures = 0;
const expect = (cond: boolean, m: string): void => {
  if (cond) ok(m);
  else {
    fail(m);
    failures++;
  }
};

interface Running {
  base: string;
  server: http.Server;
}

function start(config: GatewayConfig, ports: GatewayPorts): Promise<Running> {
  const server = createGatewayServer(config, buildRegistry(ports), ports.attestor);
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      resolve({ base: `http://127.0.0.1:${port}`, server });
    });
  });
}

async function postJson(
  base: string,
  path: string,
  body: unknown,
  token?: string,
): Promise<{ status: number; json: unknown }> {
  const res = await fetch(`${base}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, json };
}

// ---------------------------------------------------------------------------

const ports = await buildRealPorts();

// Dev instance — localhost-only, POST open (no token).
const devConfig: GatewayConfig = { ...loadConfig({ GATEWAY_DEV: "1" }), port: 0 };
const dev = await start(devConfig, ports);

// Authed instance — a real token, for the 401-negative check.
const AUTH_TOKEN = randomBytes(32).toString("hex");
const authConfig: GatewayConfig = {
  ...loadConfig({ GATEWAY_TOKEN: AUTH_TOKEN }),
  port: 0,
};
const authed = await start(authConfig, ports);

try {
  hr("Gateway demo (dev mode, localhost)");
  console.log(`  dev instance:   ${dev.base}  (auth ${devConfig.authEnforced ? "on" : "OFF — dev"})`);
  console.log(`  authed instance:${authed.base}  (auth ${authConfig.authEnforced ? "ON" : "off"})`);

  // --- GET /health -------------------------------------------------------
  hr("GET /health");
  {
    const res = await fetch(`${dev.base}/health`);
    const j = (await res.json()) as { status: string; agentCount: number; version: string };
    console.log(`  ${JSON.stringify(j)}`);
    expect(res.status === 200 && j.status === "ok", "health returns ok");
    expect(j.agentCount === 10, "health reports 10 agents");
  }

  // --- GET /agents -------------------------------------------------------
  hr("GET /agents");
  {
    const res = await fetch(`${dev.base}/agents`);
    const j = (await res.json()) as { agents: Array<{ name: string; mode: string }> };
    for (const a of j.agents) console.log(`  - ${a.name.padEnd(20)} ${a.mode}`);
    expect(j.agents.length === 10, "catalog lists 10 agents");
  }

  // --- POST evalbot (offline) -------------------------------------------
  hr("POST /agents/evalbot  (offline, expect a ruling)");
  {
    const { status, json } = await postJson(dev.base, "/agents/evalbot", {
      rubric: {
        criteria: [
          { id: "has-intro", kind: "mechanical", weight: 2, description: "mentions an Introduction", test: { check: "content-includes", needle: "Introduction" } },
          { id: "min-len", kind: "mechanical", weight: 1, description: "at least 40 chars", test: { check: "min-length", minChars: 40 } },
        ],
        acceptThreshold: 80,
      },
      deliverable: { content: "# Introduction\nA sufficiently long deliverable body for the rubric to accept." },
    });
    const result = (json as { result?: { verdict?: string; aggregate?: number | null } }).result;
    console.log(`  status ${status}  verdict=${result?.verdict}  aggregate=${result?.aggregate}`);
    expect(status === 200 && result?.verdict === "accept", "evalbot returns an accept ruling");
  }

  // --- POST procurement-butler (offline stub) ---------------------------
  hr("POST /agents/procurement-butler  (offline stub, expect a decision)");
  {
    const { status, json } = await postJson(dev.base, "/agents/procurement-butler", {
      goal: "summarize this repository's architecture (code-analysis + summarization)",
      budgetUsd: 5,
    });
    const result = (json as { result?: { outcome?: string; winner?: { provider?: string; price?: number } } }).result;
    console.log(`  status ${status}  outcome=${result?.outcome}  winner=${result?.winner?.provider ?? "(none)"} @ $${result?.winner?.price ?? "-"}`);
    expect(status === 200 && (result?.outcome === "awarded" || result?.outcome === "no-award"), "butler returns a decision");
  }

  // --- POST oracle-desk (LIVE) ------------------------------------------
  hr("POST /agents/oracle-desk  (LIVE crypto-price bitcoin, tolerate upstream failure)");
  {
    const { status, json } = await postJson(dev.base, "/agents/oracle-desk", {
      product: "crypto-price",
      params: { id: "bitcoin" },
    });
    if (status === 200) {
      const result = (json as { result?: { value?: unknown } }).result;
      ok(`oracle-desk LIVE: bitcoin = $${result?.value} (attested)`);
    } else if (status === 502 || status === 504) {
      warn(`oracle-desk upstream unavailable (status ${status}) — skipped, not a gateway defect`);
    } else {
      expect(false, `oracle-desk returned unexpected status ${status}`);
    }
  }

  // --- auth-negative: POST without token on the authed instance ---------
  hr("POST without token → 401 (authed instance)");
  {
    const { status } = await postJson(authed.base, "/agents/evalbot", {
      rubric: { criteria: [{ id: "x", kind: "mechanical", weight: 1, description: "d", test: { check: "min-length", minChars: 1 } }], acceptThreshold: 50 },
      deliverable: { content: "hi" },
    });
    expect(status === 401, "unauthenticated POST is rejected with 401");
    const withToken = await postJson(authed.base, "/agents/evalbot", {
      rubric: { criteria: [{ id: "x", kind: "mechanical", weight: 1, description: "d", test: { check: "min-length", minChars: 1 } }], acceptThreshold: 50 },
      deliverable: { content: "hi" },
    }, AUTH_TOKEN);
    expect(withToken.status === 200, "the same POST with the bearer token succeeds (200)");
  }

  // --- validation-negative: bad input → 400 -----------------------------
  hr("POST bad input → 400");
  {
    const { status, json } = await postJson(dev.base, "/agents/procurement-butler", { goal: "no budget here" });
    const errs = (json as { error?: { details?: unknown } }).error?.details;
    console.log(`  status ${status}  details=${JSON.stringify(errs)}`);
    expect(status === 400, "missing required field yields 400 with errors");
  }

  hr("Result");
  if (failures === 0) {
    console.log("  ✓ all offline + auth/validation expectations held");
  } else {
    console.log(`  ✗ ${failures} expectation(s) failed`);
  }
} finally {
  await new Promise<void>((r) => dev.server.close(() => r()));
  await new Promise<void>((r) => authed.server.close(() => r()));
}

process.exit(failures === 0 ? 0 : 1);
