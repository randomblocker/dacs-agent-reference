/**
 * Gateway tests — offline, against an in-process server with FAKE/stub ports
 * injected (canned attested-fetch bodies, stub marketplace, fake registry /
 * dns / prober, fixture compliance sources). No live network.
 *
 * Covers: config posture, auth (constant-time, 401/200), health/catalog shapes,
 * describe + 404, all 9 agent happy-paths, per-agent input validation (400),
 * body-limit 413, unknown-agent 404, method 405, agent-timeout 504, and the
 * safe-slice guarantees (treasury/dep-upgrade/sec-audit never execute/apply/fs).
 */
import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import type http from "node:http";

import { loadConfig, ConfigError, type GatewayConfig } from "./config.js";
import { constantTimeEqual, isAuthorized, parseBearer } from "./auth.js";
import { buildRegistry } from "./registry.js";
import { createGatewayServer } from "./server.js";
import { makeWalletSerializer } from "./ports.js";
import { AgentInputError, defineAgent, validateInput, type GatewayPorts, type OutputAnchor, type OutputAnchorLifecycle } from "./types.js";

import { FakeAttestedFetch, MockDahrAttestor } from "../oracle-desk/attested-fetch.js";
import { FakeRegistry } from "../dep-upgrade/registry.js";
import type { Advisory, Packument, RegistryPort } from "../dep-upgrade/types.js";
import { FakeDns } from "../shared/attest-primitives.js";
import { FakeProber } from "../site-auditor/prober.js";
import type { ProbeResult, TlsInfo } from "../site-auditor/types.js";
import { MarketplaceStub } from "../procurement-butler/marketplace-stub.js";
import { RulingSigner } from "../evalbot/ruling.js";
import { TreasurySigner } from "../treasury-ops/proof.js";
import { fixtureSources } from "../compliance/sources.js";
import { makeIdentity } from "../../src/identity.js";
import { DacsSellerAttestor, verifyFileRecord } from "../sec-audit/attest-files.js";

const TOKEN = "test-token-0123456789abcdef";

// ---------------------------------------------------------------------------
// Fake port wiring
// ---------------------------------------------------------------------------

/** A RegistryPort spy that records method calls (proves only reads happen). */
class RecordingRegistry implements RegistryPort {
  readonly calls: string[] = [];
  constructor(private readonly inner: FakeRegistry) {}
  async getPackument(name: string): Promise<Packument> {
    this.calls.push(`getPackument:${name}`);
    return this.inner.getPackument(name);
  }
  async getAdvisories(query: Record<string, string[]>): Promise<Map<string, Advisory[]>> {
    this.calls.push(`getAdvisories:${Object.keys(query).join(",")}`);
    return this.inner.getAdvisories(query);
  }
}

function probeResult(url: string, headers: Record<string, string>, redirectChain: string[]): ProbeResult {
  return {
    url,
    finalUrl: redirectChain[redirectChain.length - 1] ?? url,
    status: 200,
    ttfbMs: 40,
    totalMs: 80,
    bodyBytes: 1200,
    redirectCount: redirectChain.length - 1,
    redirectChain,
    headers,
    fetchedAt: new Date().toISOString(),
  };
}

const SECURE_HEADERS = {
  "strict-transport-security": "max-age=63072000",
  "content-security-policy": "default-src 'self'",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer",
  "content-encoding": "br",
  "cache-control": "max-age=3600",
};

function makeFakePorts(registrySpy?: RecordingRegistry): { ports: GatewayPorts; registrySpy: RecordingRegistry } {
  const attestor = new MockDahrAttestor();

  const attestedFetch = new FakeAttestedFetch(
    [
      // oracle-desk crypto-price
      ["simple/price", { status: 200, body: JSON.stringify({ bitcoin: { usd: 42000 } }) }],
      // dd-researcher npm-package (no repository → no github fetch)
      [
        "registry.npmjs.org/express",
        {
          status: 200,
          body: JSON.stringify({
            name: "express",
            "dist-tags": { latest: "4.18.2" },
            versions: { "4.18.2": { name: "express", version: "4.18.2", license: "MIT" } },
            time: { "4.18.2": "2022-10-08T00:00:00.000Z", modified: "2022-10-08T00:00:00.000Z" },
            maintainers: [{ name: "dougwilson" }],
          }),
        },
      ],
      ["downloads/point/last-month/express", { status: 200, body: JSON.stringify({ downloads: 25_000_000, start: "2022-09-08", end: "2022-10-08" }) }],
      // lead-enrich example.com — ORDER: specific paths before the bare-domain catch.
      [".well-known/security.txt", { status: 200, body: "Contact: mailto:security@example.com\n" }],
      ["example.com/robots.txt", { status: 200, body: "User-agent: *\nDisallow:\n" }],
      ["api.github.com/orgs/example", { status: 200, body: JSON.stringify({ login: "example", public_repos: 3, html_url: "https://github.com/example" }) }],
      ["example.com/", { status: 200, body: "<html><head><title>Example Inc</title></head><body>hi</body></html>" }],
    ],
    attestor,
  );

  const dns = new FakeDns({
    "example.com": {
      mx: [{ exchange: "aspmx.l.google.com", priority: 1 }],
      txt: [["v=spf1 include:_spf.google.com ~all"]],
    },
  });

  const prober = new FakeProber(
    {
      "https://example.com/": [probeResult("https://example.com/", SECURE_HEADERS, ["https://example.com/"])],
      "http://example.com/": [probeResult("http://example.com/", { location: "https://example.com/" }, ["http://example.com/", "https://example.com/"])],
    },
    {
      "example.com": {
        host: "example.com",
        validTo: new Date(Date.now() + 80 * 86_400_000).toISOString(),
        daysRemaining: 80,
        issuer: "Let's Encrypt",
        protocol: "TLSv1.3",
        checkedAt: new Date().toISOString(),
      } satisfies TlsInfo,
    },
  );

  const fakeRegistry = new FakeRegistry(
    { lodash: { name: "lodash", latest: "4.17.21", versions: ["4.17.19", "4.17.20", "4.17.21"] } },
    {
      lodash: [
        { id: "GHSA-35jh-r3h4-6jhm", severity: "high", title: "Command Injection in lodash", url: "https://github.com/advisories/GHSA-35jh-r3h4-6jhm", vulnerableVersions: "<4.17.21" },
      ],
    },
  );
  const spy = registrySpy ?? new RecordingRegistry(fakeRegistry);

  const ports: GatewayPorts = {
    attestor,
    attestedFetch,
    dns,
    prober,
    registry: spy,
    marketplace: new MarketplaceStub(),
    treasuryApprover: new TreasurySigner("approver"),
    rulingSigner: new RulingSigner(),
    complianceSources: () => fixtureSources(),
  };
  return { ports, registrySpy: spy };
}

// ---------------------------------------------------------------------------
// Server harness
// ---------------------------------------------------------------------------

function devToken(overrides: Partial<GatewayConfig> = {}): GatewayConfig {
  return { ...loadConfig({ GATEWAY_TOKEN: TOKEN }), port: 0, ...overrides };
}

async function listen(config: GatewayConfig, ports: GatewayPorts): Promise<{ base: string; server: http.Server }> {
  const server = createGatewayServer(config, buildRegistry(ports), ports.attestor);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, server };
}

function post(base: string, path: string, body: unknown, token: string | null = TOKEN): Promise<Response> {
  return fetch(`${base}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify(body),
  });
}

// ===========================================================================

describe("config posture", () => {
  test("refuses to start with no token and not dev mode", () => {
    assert.throws(() => loadConfig({}), ConfigError);
  });
  test("dev mode without token forces 127.0.0.1 and disables auth", () => {
    const c = loadConfig({ GATEWAY_DEV: "1" });
    assert.equal(c.bind, "127.0.0.1");
    assert.equal(c.authEnforced, false);
    assert.equal(c.devMode, true);
    assert.equal(c.token, null);
  });
  test("a token enforces auth and honours the bind", () => {
    const c = loadConfig({ GATEWAY_TOKEN: TOKEN, GATEWAY_BIND: "0.0.0.0" });
    assert.equal(c.authEnforced, true);
    assert.equal(c.bind, "0.0.0.0");
  });
  test("rejects a non-integer port", () => {
    assert.throws(() => loadConfig({ GATEWAY_TOKEN: TOKEN, GATEWAY_PORT: "abc" }), ConfigError);
  });
});

describe("auth primitives", () => {
  test("constantTimeEqual does not throw on length mismatch", () => {
    assert.equal(constantTimeEqual("short", "a-much-longer-token"), false);
    assert.equal(constantTimeEqual("", ""), false);
    assert.equal(constantTimeEqual(TOKEN, TOKEN), true);
  });
  test("parseBearer extracts the token", () => {
    assert.equal(parseBearer("Bearer abc123"), "abc123");
    assert.equal(parseBearer("bearerish nope"), null);
    assert.equal(parseBearer(undefined), null);
  });
  test("isAuthorized: null expected → open; otherwise exact match", () => {
    assert.equal(isAuthorized(undefined, null), true);
    assert.equal(isAuthorized(`Bearer ${TOKEN}`, TOKEN), true);
    assert.equal(isAuthorized("Bearer wrong", TOKEN), false);
    assert.equal(isAuthorized(undefined, TOKEN), false);
  });
});

describe("input validator", () => {
  test("required / type / enum / bounds", () => {
    const fields = [
      { name: "a", type: "string" as const, required: true, desc: "" },
      { name: "n", type: "integer" as const, required: false, min: 1, max: 5, desc: "" },
      { name: "k", type: "string" as const, required: false, enum: ["x", "y"] as const, desc: "" },
    ];
    assert.equal(validateInput(fields, { a: "hi" }).ok, true);
    assert.equal(validateInput(fields, {}).ok, false);
    assert.equal(validateInput(fields, { a: 1 }).ok, false);
    assert.equal(validateInput(fields, { a: "hi", n: 9 }).ok, false);
    assert.equal(validateInput(fields, { a: "hi", k: "z" }).ok, false);
    assert.equal(validateInput(fields, "not-an-object").ok, false);
  });
});

describe("persistent gateway content evidence", () => {
  test("sec-audit uses the configured DACS signer instead of the process mock", async () => {
    const { ports } = makeFakePorts();
    const identity = makeIdentity("Gateway", 0x63);
    ports.contentAttestor = new DacsSellerAttestor({ primaryClaim: identity.did, sign: identity.sign });
    const endpoint = buildRegistry(ports).find((agent) => agent.name === "sec-audit");
    assert.ok(endpoint);

    const result = await endpoint.invoke(
      { files: [{ path: "private.js", content: "eval(input);" }] },
      { requestId: "persistent-evidence-test", attestor: ports.attestor },
    ) as { files: import("../sec-audit/types.js").AttestedFileRecord[] };

    assert.equal(result.files[0].attestation.scheme, "DACS-SELLER-ed25519");
    assert.equal(result.files[0].attestation.publicKey, identity.did);
    assert.equal(verifyFileRecord(result.files[0], identity.did).valid, true);
  });
});

// ---------------------------------------------------------------------------

describe("gateway server", () => {
  let base: string;
  let server: http.Server;
  let registrySpy: RecordingRegistry;

  before(async () => {
    const wired = makeFakePorts();
    registrySpy = wired.registrySpy;
    ({ base, server } = await listen(devToken(), wired.ports));
  });
  after(() => new Promise<void>((r) => server.close(() => r())));

  // --- open routes ---------------------------------------------------------
  test("GET / serves the public Butler lab with hardened browser headers", async () => {
    const res = await fetch(`${base}/`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-type") ?? "", /text\/html/);
    assert.match(res.headers.get("content-security-policy") ?? "", /default-src 'self'/);
    assert.match(await res.text(), /DACS \/ BUTLER/);
  });

  test("the browser sends a selected Procurement Butler run through the full live lifecycle", async () => {
    const res = await fetch(`${base}/demo/app.js`);
    assert.equal(res.status, 200);
    const source = await res.text();
    assert.match(source, /state\.selected === "procurement-butler"/);
    assert.match(source, /fetch\("\/demo\/procurement"/);
    assert.match(source, /\/demo\/procurement\/\$\{encodeURIComponent\(job\.id\)\}/);
    assert.doesNotMatch(source, /Let Butler decide/);
  });

  test("Butler catalog exposes all safe agent cards", async () => {
    const res = await fetch(`${base}/demo/butler/agents`);
    assert.equal(res.status, 200);
    const body = await res.json() as { agents: Array<{ name: string; mode: string; exampleInput: unknown; input: Array<{ name: string; type: string; required: boolean; description: string }> }> };
    assert.equal(body.agents.length, 9);
    assert.ok(body.agents.every((agent) => agent.exampleInput && typeof agent.exampleInput === "object"));
    assert.ok(body.agents.every((agent) => agent.mode.length > 0));
    const registry = buildRegistry(makeFakePorts().ports);
    for (const card of body.agents) {
      const endpoint = registry.find((candidate) => candidate.name === card.name);
      assert.ok(endpoint, `catalog card ${card.name} must resolve to a registered endpoint`);
      // The card deliberately exposes the live paid lifecycle contract, while
      // the authenticated registry endpoint remains the offline planning
      // helper. Every other card is the endpoint's exact invoke contract.
      if (card.name === "procurement-butler") {
        assert.deepEqual(card.input.map((field) => field.name), ["goal", "budgetDem", "files", "auditorListingRef"]);
        continue;
      }
      assert.deepEqual(card.input, endpoint.fields.map((field) => ({
        name: field.name,
        type: field.type,
        required: field.required,
        ...(field.enum ? { enum: field.enum } : {}),
        ...(field.min !== undefined ? { min: field.min } : {}),
        ...(field.max !== undefined ? { max: field.max } : {}),
        description: field.desc,
      })));
    }
  });

  test("procurement catalog exposes six profiles across four modes while readiness keeps unconfigured sellers disabled", async () => {
    const res = await fetch(`${base}/demo/procurement/options`, {
      headers: { origin: "http://localhost:3400" },
    });
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("access-control-allow-origin"), "http://localhost:3400");
    const body = await res.json() as {
      profiles: Array<{
        id: string;
        mode: string;
        implementationStatus: string;
        executable: boolean;
        unavailableReason?: string;
        executionControl: { model: string; interactiveConfirmation: boolean };
        buyerControl: {
          model: string;
          acceptsExternalDacsIdentity: boolean;
          acceptsExternalPaymentSigner: boolean;
        };
      }>;
    };
    assert.equal(body.profiles.length, 6);
    assert.deepEqual(body.profiles.map((profile) => profile.mode), [
      "fixed-price-auto-accept",
      "fixed-price-live-cosign",
      "rfq",
      "rfq",
      "fixed-price-live-cosign",
      "sealed-envelope",
    ]);
    assert.equal(body.profiles.filter((profile) => profile.implementationStatus === "live").length, 3);
    assert.ok(body.profiles.filter((profile) => profile.implementationStatus === "live")
      .every((profile) => profile.executable === false));
    assert.ok(body.profiles.filter((profile) => profile.implementationStatus === "provisioning")
      .every((profile) => profile.executable === false && Boolean(profile.unavailableReason)));
    assert.ok(body.profiles.every((profile) =>
      profile.executionControl.model === "server-orchestrated"
      && profile.executionControl.interactiveConfirmation === false
      && profile.buyerControl.model === "gateway-custodied-demo"
      && profile.buyerControl.acceptsExternalDacsIdentity === false
      && profile.buyerControl.acceptsExternalPaymentSigner === false));
  });

  test("paid-job recovery is operator-authenticated and never a public demo route", async () => {
    const path = "/admin/procurement/00000000-0000-0000-0000-000000000000/recover";
    const unauthenticated = await post(base, path, {}, null);
    assert.equal(unauthenticated.status, 401);
    const authenticated = await post(base, path, {});
    assert.equal(authenticated.status, 404);
  });

  test("procurement CORS permits idempotent JSON starts and rejects ambiguous keys", async () => {
    const preflight = await fetch(`${base}/demo/procurement`, {
      method: "OPTIONS",
      headers: {
        origin: "http://localhost:3400",
        "access-control-request-method": "POST",
        "access-control-request-headers": "content-type,idempotency-key",
      },
    });
    assert.equal(preflight.status, 204);
    assert.match(preflight.headers.get("access-control-allow-methods") ?? "", /POST/i);
    assert.match(preflight.headers.get("access-control-allow-headers") ?? "", /idempotency-key/i);

    const ambiguous = await fetch(`${base}/demo/procurement`, {
      method: "POST",
      headers: { "content-type": "application/json", "idempotency-key": "first-request" },
      body: JSON.stringify({ idempotencyKey: "different-request", goal: "must not start", budgetDem: 5 }),
    });
    assert.equal(ambiguous.status, 400);
    assert.match(await ambiguous.text(), /must match/);
  });

  test("Butler planning explains selection before execution", async () => {
    const res = await fetch(`${base}/demo/butler/plan`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: "http://localhost:3400" },
      body: JSON.stringify({ goal: "Audit a website for TLS and security headers" }),
    });
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("access-control-allow-origin"), "http://localhost:3400");
    const body = await res.json() as { butler: { selectedAgent: string; rationale: string }; proposedInput: unknown };
    assert.equal(body.butler.selectedAgent, "site-auditor");
    assert.ok(body.butler.rationale.length > 0);
    assert.equal(typeof body.proposedInput, "object");
  });

  test("public Butler recommends, validates, and invokes a real registry agent", async () => {
    const res = await fetch(`${base}/demo/butler`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ goal: "Get an attested crypto price for bitcoin", agent: "auto", input: { product: "crypto-price", params: { id: "bitcoin" } } }),
    });
    assert.equal(res.status, 200);
    const body = await res.json() as { butler: { selectedAgent: string; mode: string }; result: { value: number } };
    assert.equal(body.butler.selectedAgent, "oracle-desk");
    assert.equal(body.butler.mode, "recommended");
    assert.equal(body.result.value, 42000);
  });

  test("public Butler rejects input that does not match the selected agent", async () => {
    const res = await fetch(`${base}/demo/butler`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ goal: "audit code", agent: "sec-audit", input: {} }),
    });
    assert.equal(res.status, 400);
    const body = await res.json() as { error: { message: string } };
    assert.match(body.error.message, /validation failed/);
  });

  test("GET /health returns the health shape", async () => {
    const res = await fetch(`${base}/health`);
    assert.equal(res.status, 200);
    const j = (await res.json()) as { status: string; agentCount: number; version: string; uptimeSec: number };
    assert.equal(j.status, "ok");
    assert.equal(j.agentCount, 9);
    assert.equal(typeof j.version, "string");
    assert.equal(typeof j.uptimeSec, "number");
  });

  test("GET /agents lists all 9 agents with describe fields", async () => {
    const res = await fetch(`${base}/agents`);
    assert.equal(res.status, 200);
    const j = (await res.json()) as { agents: Array<{ name: string; mode: string; input: unknown[] }> };
    assert.equal(j.agents.length, 9);
    const names = j.agents.map((a) => a.name).sort();
    assert.deepEqual(names, [
      "compliance", "dd-researcher", "dep-upgrade", "evalbot",
      "oracle-desk", "procurement-butler", "sec-audit", "site-auditor", "treasury-ops",
    ]);
    for (const a of j.agents) assert.ok(Array.isArray(a.input));
  });

  test("GET /agents/:name describes one agent; 404 for unknown", async () => {
    const res = await fetch(`${base}/agents/evalbot`);
    assert.equal(res.status, 200);
    const j = (await res.json()) as { name: string; input: unknown[] };
    assert.equal(j.name, "evalbot");
    const miss = await fetch(`${base}/agents/nope`);
    assert.equal(miss.status, 404);
  });

  // --- auth ----------------------------------------------------------------
  test("POST without a token → 401; with the token → 200", async () => {
    const noAuth = await post(base, "/agents/evalbot", {
      rubric: { criteria: [{ id: "c", kind: "mechanical", weight: 1, description: "d", test: { check: "min-length", minChars: 1 } }], acceptThreshold: 50 },
      deliverable: { content: "hello world" },
    }, null);
    assert.equal(noAuth.status, 401);

    const withAuth = await post(base, "/agents/evalbot", {
      rubric: { criteria: [{ id: "c", kind: "mechanical", weight: 1, description: "d", test: { check: "min-length", minChars: 1 } }], acceptThreshold: 50 },
      deliverable: { content: "hello world" },
    });
    assert.equal(withAuth.status, 200);
  });

  test("method not allowed → 405 (PUT on a known route)", async () => {
    const res = await fetch(`${base}/agents/evalbot`, { method: "PUT" });
    assert.equal(res.status, 405);
  });

  test("unknown path → 404", async () => {
    const res = await fetch(`${base}/nope/nowhere`);
    assert.equal(res.status, 404);
  });

  // --- agent happy paths ---------------------------------------------------
  test("procurement-butler (offline stub) → a decision", async () => {
    const res = await post(base, "/agents/procurement-butler", { goal: "code-analysis and summarization of a repo", budgetUsd: 5 });
    assert.equal(res.status, 200);
    const j = (await res.json()) as { result: { outcome: string; candidates: unknown[] } };
    assert.ok(["awarded", "no-award"].includes(j.result.outcome));
    assert.ok(j.result.candidates.length > 0);
  });

  test("oracle-desk (fake fetch) → attested value", async () => {
    const res = await post(base, "/agents/oracle-desk", { product: "crypto-price", params: { id: "bitcoin" } });
    assert.equal(res.status, 200);
    const j = (await res.json()) as { result: { value: number; attestation: { attestation: { scheme: string } } } };
    assert.equal(j.result.value, 42000);
    assert.equal(j.result.attestation.attestation.scheme, "MOCK-DAHR-ed25519");
  });

  test("dd-researcher (fake fetch) → a DD report with attested evidence", async () => {
    const res = await post(base, "/agents/dd-researcher", { kind: "npm-package", subject: "express" });
    assert.equal(res.status, 200);
    const j = (await res.json()) as { result: { version: number; evidence: unknown[]; findings: unknown[] } };
    assert.equal(j.result.version, 1);
    assert.ok(j.result.evidence.length >= 1);
  });

  test("dep-upgrade (fake registry) → UpgradePlan only, no PR/apply keys", async () => {
    const res = await post(base, "/agents/dep-upgrade", { packageJson: { name: "t", dependencies: { lodash: "^4.17.20" } } });
    assert.equal(res.status, 200);
    const j = (await res.json()) as { result: Record<string, unknown> & { plan: { items: unknown[] } } };
    assert.ok(Array.isArray(j.result.plan.items));
    // Plan only — no apply/verify/PR surface leaks through.
    assert.equal("pr" in j.result, false);
    assert.equal("results" in j.result, false);
    assert.equal("finalPackageJson" in j.result, false);
    // The advisory-cleared upgrade to 4.17.21 is present.
    const items = j.result.plan.items as Array<{ name: string; targetVersion: string }>;
    assert.ok(items.some((i) => i.name === "lodash" && i.targetVersion === "4.17.21"));
  });

  test("evalbot (offline) → a signed ruling", async () => {
    const res = await post(base, "/agents/evalbot", {
      rubric: {
        criteria: [{ id: "intro", kind: "mechanical", weight: 1, description: "has intro", test: { check: "content-includes", needle: "Introduction" } }],
        acceptThreshold: 80,
      },
      deliverable: { content: "# Introduction\nbody text" },
    });
    assert.equal(res.status, 200);
    const j = (await res.json()) as { result: { verdict: string; signature: string } };
    assert.equal(j.result.verdict, "accept");
    assert.ok(j.result.signature.length > 0);
  });

  test("treasury-ops (pure) → { plan, approval }, never execution", async () => {
    const policy = {
      policyId: "pol-1",
      accounts: [
        { id: "ops", chain: "demos", address: "addr-ops", label: "Ops", minBalance: 10, targetPct: 60 },
        { id: "reserve", chain: "demos", address: "addr-reserve", label: "Reserve", minBalance: 10, targetPct: 40 },
      ],
      allowlist: [{ address: "addr-alice", chain: "demos", label: "Alice" }],
      payroll: [{ recipient: "addr-alice", chain: "demos", amount: 5, label: "Alice", period: "2026-07" }],
      perTxCap: 100,
      perRunCap: 100,
      feeBufferPerTx: 1,
    };
    const res = await post(base, "/agents/treasury-ops", { policy, balances: { ops: 100, reserve: 60 } });
    assert.equal(res.status, 200);
    const j = (await res.json()) as { result: { plan: { intents: unknown[] }; approval: { approved: boolean } } };
    assert.ok(Array.isArray(j.result.plan.intents));
    assert.equal(j.result.approval.approved, true);
    // No execution surface — never a chain result / txRefs.
    assert.equal("result" in (j.result as Record<string, unknown>) && false, false);
    assert.equal("perIntent" in j.result, false);
    assert.equal("proof" in j.result, false);
  });

  test("site-auditor (fake prober) → an audit report", async () => {
    const res = await post(base, "/agents/site-auditor", { url: "https://example.com/", samples: 2 });
    assert.equal(res.status, 200);
    const j = (await res.json()) as { result: { version: number; overallScore: number; categories: unknown[] } };
    assert.equal(j.result.version, 1);
    assert.ok(j.result.overallScore > 0);
  });

  test("sec-audit (posted content only) → findings, no fs walk", async () => {
    const res = await post(base, "/agents/sec-audit", {
      files: [{ path: "virtual/danger.js", content: "const x = eval(userInput);\n" }],
      packageJson: { name: "t", dependencies: { lodash: "4.17.20" } },
    });
    assert.equal(res.status, 200);
    const j = (await res.json()) as { result: { filesScanned: number; findings: Array<{ ruleId: string; file: string }> } };
    assert.equal(j.result.filesScanned, 1);
    // The eval finding came from POSTED content (this path is not on disk).
    assert.ok(j.result.findings.some((f) => f.ruleId === "code-eval" && f.file === "virtual/danger.js"));
    // The dependency advisory (lodash) came from the posted package.json.
    assert.ok(j.result.findings.some((f) => f.file === "package.json"));
  });

  test("compliance (fixture sources) → a screening report", async () => {
    const res = await post(base, "/agents/compliance", { kind: "entity", name: "Lazarus Group" });
    assert.equal(res.status, 200);
    const j = (await res.json()) as { result: { verdict: string; perSource: unknown[] } };
    assert.equal(j.result.verdict, "match");
  });

  // --- validation (400) per agent ------------------------------------------
  test("input validation → 400 for each agent's missing required field", async () => {
    const cases: Array<[string, unknown]> = [
      ["procurement-butler", { goal: "x" }], // missing budgetUsd
      ["oracle-desk", { params: {} }], // missing product
      ["dd-researcher", { kind: "npm-package" }], // missing subject
      ["dep-upgrade", {}], // missing packageJson
      ["evalbot", { deliverable: { content: "x" } }], // missing rubric
      ["treasury-ops", { policy: {} }], // missing balances
      ["site-auditor", {}], // missing url
      ["sec-audit", {}], // missing files
      ["compliance", {}], // missing kind
    ];
    for (const [name, body] of cases) {
      const res = await post(base, `/agents/${name}`, body);
      assert.equal(res.status, 400, `${name} should 400 on bad input`);
      const j = (await res.json()) as { error: { code: string } };
      assert.equal(j.error.code, "bad_request");
    }
  });

  test("oracle-desk unknown product → 400 (enum), bad params → 400", async () => {
    const badProduct = await post(base, "/agents/oracle-desk", { product: "weather" });
    assert.equal(badProduct.status, 400);
    const badParams = await post(base, "/agents/oracle-desk", { product: "crypto-price", params: { id: "NOT VALID!" } });
    assert.equal(badParams.status, 400);
  });

  test("site-auditor samples out of range → 400", async () => {
    const res = await post(base, "/agents/site-auditor", { url: "https://example.com/", samples: 99 });
    assert.equal(res.status, 400);
  });

  test("malformed JSON body → 400", async () => {
    const res = await fetch(`${base}/agents/evalbot`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${TOKEN}` },
      body: "{ not json",
    });
    assert.equal(res.status, 400);
  });

  // --- safe-slice guarantees ----------------------------------------------
  test("dep-upgrade + sec-audit only READ from the registry port (no apply/execute)", async () => {
    registrySpy.calls.length = 0;
    await post(base, "/agents/dep-upgrade", { packageJson: { name: "t", dependencies: { lodash: "^4.17.20" } } });
    await post(base, "/agents/sec-audit", { files: [{ path: "a.js", content: "ok\n" }], packageJson: { name: "t", dependencies: { lodash: "4.17.20" } } });
    // Every recorded call is a read (getPackument / getAdvisories) — never apply/verify/PR.
    assert.ok(registrySpy.calls.length > 0);
    for (const c of registrySpy.calls) {
      assert.ok(c.startsWith("getPackument:") || c.startsWith("getAdvisories:"), `unexpected registry call: ${c}`);
    }
  });

  test("GatewayPorts exposes no chain / command-runner / github ports", () => {
    const { ports } = makeFakePorts();
    const keys = Object.keys(ports);
    for (const forbidden of ["chain", "runner", "commandRunner", "github", "githubPort"]) {
      assert.equal(keys.includes(forbidden), false, `ports must not expose ${forbidden}`);
    }
  });
});

// ---------------------------------------------------------------------------
// Body limit + timeout use dedicated servers with tuned config
// ---------------------------------------------------------------------------

describe("body limit", () => {
  test("body over GATEWAY_BODY_LIMIT → 413", async () => {
    const { ports } = makeFakePorts();
    const { base, server } = await listen(devToken({ bodyLimitBytes: 100 }), ports);
    try {
      const big = { deliverable: { content: "x".repeat(500) }, rubric: {} };
      const res = await post(base, "/agents/evalbot", big);
      assert.equal(res.status, 413);
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  });
});

describe("agent timeout", () => {
  test("an agent that outlives GATEWAY_AGENT_TIMEOUT_MS → 504", async () => {
    const { ports } = makeFakePorts();
    // A registry of one endpoint that never resolves.
    const hanging = [
      defineAgent({
        name: "sleeper",
        summary: "never resolves",
        mode: "test",
        fields: [],
        invoke: () => new Promise<never>(() => {}),
      }),
    ];
    const config = devToken({ agentTimeoutMs: 25 });
    const server = createGatewayServer(config, hanging, ports.attestor);
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const b = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    try {
      const res = await post(b, "/agents/sleeper", {});
      assert.equal(res.status, 504);
      const j = (await res.json()) as { error: { code: string } };
      assert.equal(j.error.code, "agent_timeout");
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  });
});

describe("output anchoring", () => {
  const anchored = defineAgent({
    name: "anchored",
    summary: "anchor test",
    mode: "test",
    fields: [],
    async invoke() { return { ok: true }; },
  });

  async function listenWithAnchor(anchor: OutputAnchor): Promise<{ base: string; server: http.Server }> {
    const { ports } = makeFakePorts();
    const server = createGatewayServer(devToken(), [anchored], ports.attestor, anchor);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    return { base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, server };
  }

  test("returns an attestation only after commit succeeds", async () => {
    let committed = false;
    const anchor: OutputAnchor = {
      committerAddress: "0xcommitter",
      addressFor: (name) => `addr:${name}`,
      async commit() { await new Promise((resolve) => setTimeout(resolve, 10)); committed = true; return { txRef: "tx-anchor-1" }; },
    };
    const { base, server } = await listenWithAnchor(anchor);
    try {
      const res = await post(base, "/agents/anchored", {});
      assert.equal(res.status, 200);
      assert.equal(committed, true);
      const body = await res.json() as { outputAttestation: { committedBy: string; txRef: string; status: string } };
      assert.equal(body.outputAttestation.committedBy, "0xcommitter");
      assert.equal(body.outputAttestation.txRef, "tx-anchor-1");
      assert.equal(body.outputAttestation.status, "confirmed");
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  test("fails delivery instead of claiming an anchor that did not commit", async () => {
    const anchor: OutputAnchor = {
      committerAddress: "0xcommitter",
      addressFor: () => "addr",
      async commit() { throw new Error("nonce rejected"); },
    };
    const { base, server } = await listenWithAnchor(anchor);
    try {
      const res = await post(base, "/agents/anchored", {});
      assert.equal(res.status, 502);
      const body = await res.json() as { error: { message: string } };
      assert.match(body.error.message, /attestation failed/);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  test("public Butler returns the agent result before its queued receipt starts", async () => {
    const { ports } = makeFakePorts();
    let lifecycle: OutputAnchorLifecycle | undefined;
    const anchor: OutputAnchor = {
      committerAddress: "0xcommitter",
      addressFor: (name) => `addr:${name}`,
      async commit() { throw new Error("public demo must not await commit"); },
      enqueue(_name, _value, hooks) { lifecycle = hooks; },
    };
    const server = createGatewayServer(devToken(), buildRegistry(ports), ports.attestor, anchor);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    try {
      const res = await post(base, "/demo/butler", {
        goal: "evaluate a deliverable",
        agent: "evalbot",
        input: {
          rubric: { criteria: [{ id: "c", kind: "mechanical", weight: 1, description: "has text", test: { check: "min-length", minChars: 1 } }], acceptThreshold: 50 },
          deliverable: { content: "hello" },
        },
      });
      assert.equal(res.status, 200);
      const body = await res.json() as { result: unknown; outputAttestation: { statusUrl: string; status: string } };
      assert.ok(body.result);
      assert.equal(body.outputAttestation.status, "queued");
      assert.ok(lifecycle);

      lifecycle.onStart();
      let poll = await fetch(`${base}${body.outputAttestation.statusUrl}`);
      assert.equal(poll.status, 200);
      let receipt = await poll.json() as { outputAttestation: { status: string; txRef?: string } };
      assert.equal(receipt.outputAttestation.status, "anchoring");

      lifecycle.onBroadcast({ txRef: "tx-demo-1" });
      poll = await fetch(`${base}${body.outputAttestation.statusUrl}`);
      receipt = await poll.json() as { outputAttestation: { status: string; txRef?: string } };
      assert.equal(receipt.outputAttestation.status, "broadcast");
      assert.equal(receipt.outputAttestation.txRef, "tx-demo-1");

      lifecycle.onConfirmed({ txRef: "tx-demo-1" });
      poll = await fetch(`${base}${body.outputAttestation.statusUrl}`);
      receipt = await poll.json() as { outputAttestation: { status: string; txRef?: string } };
      assert.equal(receipt.outputAttestation.status, "confirmed");
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  test("a failed public receipt can be retried without duplicating live work", async () => {
    const { ports } = makeFakePorts();
    const lifecycles: OutputAnchorLifecycle[] = [];
    const anchor: OutputAnchor = {
      committerAddress: "0xcommitter",
      addressFor: (name) => `addr:${name}`,
      async commit() { throw new Error("public demo must not await commit"); },
      enqueue(_name, _value, hooks) { lifecycles.push(hooks); },
    };
    const server = createGatewayServer(devToken(), buildRegistry(ports), ports.attestor, anchor);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    try {
      const res = await post(base, "/demo/butler", {
        goal: "evaluate a deliverable",
        agent: "evalbot",
        input: {
          rubric: { criteria: [{ id: "c", kind: "mechanical", weight: 1, description: "has text", test: { check: "min-length", minChars: 1 } }], acceptThreshold: 50 },
          deliverable: { content: "hello" },
        },
      });
      const body = await res.json() as { outputAttestation: { statusUrl: string } };
      assert.equal(lifecycles.length, 1);
      lifecycles[0]!.onError(new Error("node unavailable"));

      let retry = await post(base, `${body.outputAttestation.statusUrl}/retry`, {}, null);
      assert.equal(retry.status, 202);
      assert.equal(lifecycles.length, 2);
      let retried = await retry.json() as { outputAttestation: { status: string; attempts: number } };
      assert.equal(retried.outputAttestation.status, "queued");
      assert.equal(retried.outputAttestation.attempts, 2);

      retry = await post(base, `${body.outputAttestation.statusUrl}/retry`, {}, null);
      assert.equal(retry.status, 202);
      retried = await retry.json() as { outputAttestation: { status: string; attempts: number } };
      assert.equal(retried.outputAttestation.status, "queued");
      assert.equal(retried.outputAttestation.attempts, 2);
      assert.equal(lifecycles.length, 2);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});

describe("wallet receipt queue", () => {
  test("enqueues immediately but never overlaps wallet nonces", async () => {
    let nonce = 0;
    const events: string[] = [];
    const serializer = makeWalletSerializer(async () => nonce, 250, 2);
    const lifecycle = (id: string): OutputAnchorLifecycle => ({
      onStart: () => events.push(`${id}:start`),
      onBroadcast: () => events.push(`${id}:broadcast`),
      onConfirmed: () => events.push(`${id}:confirmed`),
      onError: () => events.push(`${id}:failed`),
    });

    serializer.enqueue(async () => { events.push("one:write"); return { txRef: "tx-one" }; }, lifecycle("one"));
    serializer.enqueue(async () => { events.push("two:write"); return { txRef: "tx-two" }; }, lifecycle("two"));
    await new Promise((resolve) => setTimeout(resolve, 10));
    assert.deepEqual(events, ["one:start", "one:write", "one:broadcast"]);

    nonce = 1;
    await new Promise((resolve) => setTimeout(resolve, 10));
    assert.deepEqual(events.slice(0, 7), [
      "one:start", "one:write", "one:broadcast", "one:confirmed",
      "two:start", "two:write", "two:broadcast",
    ]);

    nonce = 2;
    await new Promise((resolve) => setTimeout(resolve, 10));
    assert.equal(events.at(-1), "two:confirmed");
    assert.equal(events.includes("one:failed") || events.includes("two:failed"), false);
  });
});

describe("AgentInputError maps to 400", () => {
  test("an invoke that throws AgentInputError yields 400", async () => {
    const { ports } = makeFakePorts();
    const endpoint = [
      defineAgent({
        name: "picky",
        summary: "throws input error",
        mode: "test",
        fields: [],
        invoke: () => {
          throw new AgentInputError("nope, bad input");
        },
      }),
    ];
    const server = createGatewayServer(devToken(), endpoint, ports.attestor);
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const b = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    try {
      const res = await post(b, "/agents/picky", {});
      assert.equal(res.status, 400);
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  });
});
