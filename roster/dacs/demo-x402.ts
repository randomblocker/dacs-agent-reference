/**
 * Build A demo — the x402 rail, end-to-end, mock-first.
 *
 *   npm run dacs:x402
 *
 * A full DACS deal on the shared seller layer, wiring the oracle-desk core:
 *   seller publishes a DACS-1 listing (attested oracle data, pay-x402)
 *     → buyer discovers it, runs the session (vet skipped in mock)
 *     → buyer's x402 settle seam hits the seller's paywall: GET → 402 challenge
 *     → retries with the synthetic mock proof
 *     → paywall VERIFIES → does the WORK (oracle fetch + DACS-X attestation)
 *       → SETTLES (mock) → 200 with the value + settlement tx
 *     → buyer anchors the AttestationBundle; seller countersigns
 *     → a read-only verifier verifies the delivery attestation + bundle from
 *       anchors ALONE (the oracle attestation re-checked offline).
 *
 * The RAIL is mock (no chain, no facilitator, no keys). The oracle VALUE is a
 * live upstream fetch when reachable; a flaky upstream falls back to a canned
 * value with a warning — the rail + lifecycle are what's under test.
 *
 * Exit 0 only if the delivery verifies AND the settle order held (work-before-settle).
 */
import { makeIdentity } from "../../src/identity.js";
import { MemorySubstrate } from "../../src/substrate/memory.js";
import type { SessionTerms } from "@kynesyslabs/dacs";
import { FakeAttestedFetch, RealAttestedFetch } from "../oracle-desk/attested-fetch.js";
import type { AttestedFetchPort, AttestedFetchResult } from "../oracle-desk/types.js";
import { SellerAdapter } from "./seller-adapter.js";
import { BuyerAdapter, makeX402MockSettle } from "./buyer.js";
import { VerifierAdapter } from "./verifier.js";
import { MockFacilitator, startPaywall, type PaywallPhase } from "./paywall.js";
import {
  makeOracleWork,
  oracleListingSpec,
  oracleObserveDelivered,
  ORACLE_SERVICE_ID,
} from "./wire/oracle-desk.js";

const line = (s = "") => console.log(s);
const step = (n: string, msg: string) => console.log(`  ${n.padEnd(11)} ${msg}`);

/** Real upstream when reachable; canned fallback so a flaky internet can't fail the demo. */
function resilientOracleFetch(): AttestedFetchPort {
  const real = new RealAttestedFetch();
  const fake = new FakeAttestedFetch([
    // A FLOAT price — the JCS-float fix means this now signs + anchors + verifies
    // through the DACS-X delivery (pre-fix only the integer chain-height could).
    ["api.coingecko.com", { status: 200, body: JSON.stringify({ bitcoin: { usd: 68000.55 } }) }],
    ["api.frankfurter.dev", { status: 200, body: JSON.stringify({ rates: { EUR: 0.92 } }) }],
    ["blockchain.info", { status: 200, body: "901234" }],
  ]);
  return {
    async attestFetch(url: string): Promise<AttestedFetchResult> {
      try {
        return await real.attestFetch(url);
      } catch (e) {
        console.warn(`  ⚠ upstream fetch failed (${(e as Error).message}); using canned value — rail/lifecycle still under test`);
        return fake.attestFetch(url);
      }
    },
  };
}

async function main() {
  line("┌────────────────────────────────────────────────────────────────┐");
  line("│  DACS Build A — x402 rail end-to-end (oracle-desk, mock-first)  │");
  line("└────────────────────────────────────────────────────────────────┘");

  // ── World: one in-memory substrate, two identities ────────────────────────
  const substrate = new MemorySubstrate();
  const sellerId = makeIdentity("OracleDesk", 0x0a);
  const buyerId = makeIdentity("DataBuyer", 0x0b);
  step("identities", `seller ${sellerId.did.slice(0, 26)}…  buyer ${buyerId.did.slice(0, 26)}…`);

  // ── Seller: oracle-desk data lookup as the SellerAdapter work callback ─────
  const seller = new SellerAdapter(sellerId, substrate, ORACLE_SERVICE_ID, makeOracleWork(resilientOracleFetch()));
  const price = { amount: "50000", asset: "USDC" }; // 0.05 USDC (6 decimals)

  line("\n━━ DACS-1: publish listing ━━");
  const listingRef = await seller.publishListing(oracleListingSpec(price));
  step("listing", `signed + anchored → ${listingRef}`);
  const listingRaw = await substrate.read(listingRef);
  step("readable", `serviceId=${(listingRaw as { serviceId?: string })?.serviceId} rails=${JSON.stringify((listingRaw as { supportedPaymentRails?: string[] })?.supportedPaymentRails)}`);

  // ── Buyer discovers ───────────────────────────────────────────────────────
  const buyer = new BuyerAdapter(buyerId, substrate);
  const found = await buyer.discover([listingRef]);
  step("discover", `buyer resolved ${found.length} listing(s): "${found[0]?.listing.name}"`);

  // ── Paywall (seller half) on the mock facilitator ─────────────────────────
  const facilitator = new MockFacilitator();
  const phases: Array<{ phase: PaywallPhase; jobId: string }> = [];
  const paywall = await startPaywall({
    route: "/data",
    accepts: {
      network: "eip155:84532",
      payTo: sellerId.evm,
      price,
      extra: { name: "USDC", version: "2" },
    },
    facilitator,
    description: "Attested oracle data (DACS pay-x402)",
    deliver: async (jobId, params) => {
      const d = await seller.deliver(jobId, params);
      return { result: d.result, attestationRef: d.attestationRef };
    },
    onPhase: (phase, jobId) => phases.push({ phase, jobId }),
  });
  step("paywall", `oracle x402 endpoint up → ${paywall.url} (facilitator: MOCK, no chain)`);

  // ── Show the 402 challenge (FeeSchedule) ──────────────────────────────────
  line("\n━━ x402: 402 challenge (no payment) ━━");
  const chal = await fetch(`${paywall.url}?jobId=preview&product=crypto-price&id=bitcoin`);
  const chalBody = (await chal.json()) as { accepts: Array<{ price: { amount: string; asset: string }; payTo?: string }> };
  step("402", `status=${chal.status} accepts.price=${chalBody.accepts[0]?.price.amount} ${chalBody.accepts[0]?.price.asset} payTo=${chalBody.accepts[0]?.payTo?.slice(0, 14)}…`);

  // ── Buyer runs the session on the x402 rail ───────────────────────────────
  line("\n━━ DACS-2..5: session on the x402 rail ━━");
  const terms: SessionTerms = {
    price: { amount: price.amount, asset: price.asset, decimals: 6, rail: "pay-x402" },
    deliveryPhase: "deliver-crypto-price",
    deliveryFormat: "application/json",
  };
  const jobId = `x402-oracle-${Date.now()}`;
  const result = await buyer.buy(listingRef, terms, {
    jobId,
    settleFn: makeX402MockSettle({
      paywallUrl: paywall.url,
      sub: substrate,
      payerEvm: buyerId.evm,
      payeeEvm: sellerId.evm,
      params: { product: "crypto-price", id: "bitcoin" },
      network: "eip155:84532",
    }),
  });
  step("DACS-3", `agreement anchored → ${result.agreementRef}`);
  step("DACS-4", `x402 settled (mock) + delivery anchored → evidence ${result.settlementRef}`);
  step("DACS-5", `buyer bundle anchored → ${result.bundleRef} (outcome: ${result.outcome})`);

  // What the buyer walked away with (from the anchored delivery attestation).
  // `value` is the JCS-safe display string; the full deliverable (raw value,
  // attestation, body) rides in meta.reportJson for the offline re-check.
  const delivRaw = await substrate.read(await substrate.anchorAddress(`dacsx:delivery:${jobId}`));
  const deliv = delivRaw as { meta?: { value?: unknown; oracleDigest?: string }; deliverableRef?: string } | null;
  step("delivered", `value=${String(deliv?.meta?.value)} (float, anchored)  oracleDigest=${deliv?.meta?.oracleDigest?.slice(0, 16)}…`);

  // ── Seller countersigns; verifier audits from anchors alone ───────────────
  line("\n━━ fulfil + audit ━━");
  const sellerBundleRef = await seller.fulfil(jobId, buyerId.did);
  step("fulfil", `seller countersigned → ${sellerBundleRef}`);

  const verifier = new VerifierAdapter(substrate);
  const v = await verifier.verify(result.bundleRef);
  step("verify", `bundle: ok=${v.ok} fullyVerified=${v.fullyVerified}`);
  const dv = await verifier.verifyDelivery(jobId, {
    serviceId: ORACLE_SERVICE_ID,
    sellerDid: sellerId.did,
    observeDelivered: oracleObserveDelivered(),
  });
  step("delivery", `DACS-X attestation: ok=${dv.ok}${dv.ok ? "" : ` — ${dv.reason}`} (oracle attestation re-checked offline)`);
  const rec = await verifier.reconcile(result.bundleRef, sellerBundleRef);
  step("reconcile", `two-sided (§10.4.3): reconciled=${rec.reconciled}${rec.reason ? ` (${rec.reason})` : ""}`);

  await paywall.close();

  // ── Assertions: delivery verified + settle order held ─────────────────────
  const jobPhases = phases.filter((p) => p.jobId === jobId).map((p) => p.phase);
  const workIdx = jobPhases.indexOf("work");
  const settleIdx = jobPhases.indexOf("settle");
  const workBeforeSettle = workIdx >= 0 && settleIdx >= 0 && workIdx < settleIdx;
  step("order", `paywall phases [${jobPhases.join(" → ")}]  work-before-settle=${workBeforeSettle}`);

  const ok = dv.ok && result.outcome === "completed" && v.ok && rec.reconciled && workBeforeSettle;
  line(
    `\n${ok ? "✅" : "❌"} Build A x402 deal ${ok ? "held" : "FAILED"} — ` +
      `settled(mock) + delivered + verified from anchors alone.\n`,
  );
  process.exit(ok ? 0 : 1);
}

main().catch((e) => {
  console.error("\n❌ dacs:x402 demo failed:", e?.message ?? e);
  process.exit(1);
});
