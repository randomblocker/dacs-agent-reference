/**
 * Oracle Desk demo — starts the service on an ephemeral port, hits /catalog
 * and all three data products against their REAL public upstreams, verifies
 * every attestation signature locally, and shuts down cleanly.
 *
 *   npm run roster:oracle
 *
 * A flaky/unreachable upstream prints a warning and the demo continues
 * (exit 0); an attestation that fails local verification is a hard failure
 * (exit 1) — that's OUR bug, not the internet's.
 */
import type { AddressInfo } from "node:net";
import { RealAttestedFetch, verifyAttestation } from "./attested-fetch.js";
import { MULTI_SOURCE_NOTE } from "./attest-any.js";
import { createOracleServer, StubChargePolicy } from "./server.js";
import type { AttestResponse, CatalogResponse, DataResponse, ErrorResponse } from "./types.js";

const hr = (title: string) => console.log(`\n=== ${title} ${"=".repeat(Math.max(0, 60 - title.length))}`);
const usd = (n: number) => `$${n.toFixed(2)}`;

const charges = new StubChargePolicy();
const server = createOracleServer({ attestedFetch: new RealAttestedFetch(), chargePolicy: charges });

await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
const { port } = server.address() as AddressInfo;
const base = `http://127.0.0.1:${port}`;

let attestationFailures = 0;
let upstreamWarnings = 0;

try {
  hr("DAHR Oracle Desk");
  console.log(`  Serving attested Web2 data on ${base} (payment stub — nothing settles)`);

  // -------------------------------------------------------------------------
  // Catalog
  // -------------------------------------------------------------------------
  hr("GET /catalog");
  const catalog = (await (await fetch(`${base}/catalog`)).json()) as CatalogResponse;
  for (const p of catalog.products) {
    const params = p.params.map((s) => `${s.name}${s.required ? "" : "?"}=${s.example}`).join("&") || "(no params)";
    console.log(`  ${p.id.padEnd(14)} ${usd(p.price)}  ${p.upstream.padEnd(20)} ${params}`);
    console.log(`  ${"".padEnd(14)}        ${p.description}`);
  }

  // -------------------------------------------------------------------------
  // Data calls — real upstreams
  // -------------------------------------------------------------------------
  const calls: Array<{ label: string; path: string; render: (v: unknown) => string }> = [
    { label: "BTC spot price", path: "/data/crypto-price?id=bitcoin", render: (v) => `$${Number(v).toLocaleString("en-US")}` },
    { label: "USD->EUR rate", path: "/data/fx-rate?symbol=EUR", render: (v) => `${v} EUR per USD` },
    { label: "BTC block height", path: "/data/chain-height", render: (v) => `block ${Number(v).toLocaleString("en-US")}` },
  ];

  for (const call of calls) {
    hr(`GET ${call.path}`);
    const res = await fetch(`${base}${call.path}`);
    if (!res.ok) {
      const err = (await res.json()) as ErrorResponse;
      console.warn(`  WARNING (${res.status} ${err.error.code}): ${err.error.message}`);
      console.warn("  Upstream unreachable/misbehaving — continuing; demo does not hard-fail on flaky upstreams.");
      upstreamWarnings += 1;
      continue;
    }
    const data = (await res.json()) as DataResponse;
    const att = data.attestation;
    console.log(`  ${call.label}: ${call.render(data.value)}`);
    console.log(`  priceCharged ${usd(data.priceCharged)} (${data.chargeId})   X-Payment-Stub: ${res.headers.get("x-payment-stub")}`);
    console.log(`  attested fetch: ${att.url}`);
    console.log(`    fetchedAt ${att.fetchedAt}  upstream status ${att.status}`);
    console.log(`    bodyHash  sha256:${att.bodyHash.slice(0, 16)}…  digest ${att.attestation.digest.slice(0, 16)}…`);
    console.log(`    scheme    ${att.attestation.scheme} (${att.attestation.note.split(" — ")[0]})`);

    const verdict = verifyAttestation(att);
    if (verdict.valid) {
      console.log("    local signature verification: OK");
    } else {
      console.error(`    local signature verification: FAILED — ${verdict.reason}`);
      attestationFailures += 1;
    }
  }

  // -------------------------------------------------------------------------
  // attest-any-API — the differentiator: attest an ARBITRARY Web2 JSON endpoint
  // (the long tail Chainlink/Pyth price feeds do not cover), via /attest.
  // -------------------------------------------------------------------------
  const attestCalls: Array<{ label: string; url: string; extract: string }> = [
    { label: "GitHub repo stars (nodejs/node)", url: "https://api.github.com/repos/nodejs/node", extract: "stargazers_count" },
    { label: "ISS orbital position (open-notify)", url: "https://api.wheretheiss.at/v1/satellites/25544", extract: "latitude" },
  ];
  for (const c of attestCalls) {
    hr(`GET /attest ${c.extract} <- ${c.url}`);
    const q = new URLSearchParams({ url: c.url, extract: c.extract });
    const res = await fetch(`${base}/attest?${q.toString()}`);
    if (!res.ok) {
      const err = (await res.json()) as ErrorResponse;
      console.warn(`  WARNING (${res.status} ${err.error.code}): ${err.error.message}`);
      console.warn("  Upstream unreachable/misbehaving — continuing; demo does not hard-fail on flaky upstreams.");
      upstreamWarnings += 1;
      continue;
    }
    const data = (await res.json()) as AttestResponse;
    console.log(`  ${c.label}: ${JSON.stringify(data.value)}  (extract "${data.extract}")`);
    console.log(`  attested fetch: ${data.attestation.url}`);
    console.log(`    bodyHash sha256:${data.attestation.bodyHash.slice(0, 16)}…  digest ${data.attestation.attestation.digest.slice(0, 16)}…`);
    const verdict = verifyAttestation(data.attestation);
    if (verdict.valid) {
      console.log("    local signature verification: OK — value provably came from this URL");
    } else {
      console.error(`    local signature verification: FAILED — ${verdict.reason}`);
      attestationFailures += 1;
    }
  }

  // -------------------------------------------------------------------------
  // SSRF guard — an internal/metadata target is refused BEFORE any fetch.
  // -------------------------------------------------------------------------
  hr("SSRF guard (attest-any is a fetch-arbitrary-URL surface)");
  for (const bad of ["http://169.254.169.254/latest/meta-data/", "https://localhost/admin", "https://10.0.0.1/"]) {
    const q = new URLSearchParams({ url: bad, extract: "$" });
    const res = await fetch(`${base}/attest?${q.toString()}`);
    const err = (await res.json()) as ErrorResponse;
    const ok = res.status === 400 && err.error.code === "unsafe_url";
    console.log(`  ${bad.padEnd(42)} -> ${res.status} ${err.error.code} ${ok ? "(blocked)" : "(UNEXPECTED)"}`);
    if (!ok) attestationFailures += 1;
  }

  // -------------------------------------------------------------------------
  // Payment seam
  // -------------------------------------------------------------------------
  hr("Payment stub ledger (would-be charges)");
  if (charges.charges.length === 0) console.log("  (no successful calls — nothing recorded)");
  for (const c of charges.charges) {
    console.log(`  ${c.chargeId}  ${c.productId.padEnd(14)} ${usd(c.price)}  settled=${c.settled}`);
  }

  hr("Trust model (honest)");
  console.log(`  ${MULTI_SOURCE_NOTE}`);

  hr("Done");
  console.log(
    `  products=${catalog.products.length}  served=${charges.charges.length}` +
      `  upstreamWarnings=${upstreamWarnings}  attestationFailures=${attestationFailures}`,
  );
} finally {
  await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
}

if (attestationFailures > 0) {
  console.error("Attestation verification failed — that is a local bug, failing the demo.");
  process.exit(1);
}
