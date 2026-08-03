/**
 * Build C demo — the Procurement Butler as a real DACS buyer, mock-first.
 *
 *   npm run dacs:market
 *
 * The full marketplace loop across rails. Three sellers publish ANCHORED DACS-1
 * listings; the Butler is handed goals + budgets and, for each, DISCOVERS the
 * real anchored listings, scores them, negotiates where allowed, picks a rail
 * per listing (via the eligibility policy), and EXECUTES a purchase on the
 * selected rail — then gates acceptance on BOTH the mechanical checks and the
 * verifier:
 *
 *   Purchase 1 — oracle desk, fixed-scope, pay-x402 → x402 paywall request.
 *   Purchase 2 — dd-researcher, parameterized, pay-dem → session/push (Pattern 2).
 *                (advertises x402 too; the policy drops it — params ⇒ session.)
 *   Purchase 3 — oracle desk, fixed-scope, pay-dem → memo-watcher (Pattern 1).
 *
 * The RAILS are mock (no chain, no facilitator, no keys). The oracle VALUES and
 * the DD REPORT are LIVE upstream fetches when reachable, with canned fallback.
 *
 * Exit 0 only if EACH purchase settles + delivers + verifies. The dd-researcher
 * report has no mechanical checks, so it ends `needs-evaluator` (EvalBot is
 * Build D) — that is a SUCCESSFUL lifecycle, just not auto-accepted.
 */
import { makeIdentity } from "../../src/identity.js";
import { MemorySubstrate } from "../../src/substrate/memory.js";
import { FakeAttestedFetch, RealAttestedFetch } from "../oracle-desk/attested-fetch.js";
import type { AttestedFetchPort, AttestedFetchResult } from "../oracle-desk/types.js";
import type { ProcurementDecision, ProcurementGoal } from "../procurement-butler/types.js";
import { SellerAdapter } from "./seller-adapter.js";
import { BuyerAdapter } from "./buyer.js";
import { VerifierAdapter } from "./verifier.js";
import { MockDemLedger, demosAddrFromDid } from "./rails.js";
import { MockLedgerWatch, SellerWatcher } from "./watcher.js";
import { MockFacilitator, startPaywall } from "./paywall.js";
import {
  ORACLE_SERVICE_ID,
  makeOracleWork,
  oracleListingSpec,
  oracleObserveDelivered,
} from "./wire/oracle-desk.js";
import {
  DD_DELIVERY_PHASE,
  DD_SERVICE_ID,
  ddListingSpec,
  ddObserveDelivered,
  makeDdWork,
} from "./wire/dd-researcher.js";
import {
  DacsButlerBuyer,
  type DacsOffer,
  type PurchaseOutcome,
  type SellerRuntime,
} from "./wire/butler.js";

const line = (s = "") => console.log(s);
const step = (n: string, msg: string) => console.log(`  ${n.padEnd(12)} ${msg}`);

const USDC = { amount: "50000", asset: "USDC", decimals: 6 };
const DEM = { amount: "1000000000", asset: "DEM", decimals: 9 };
const DEM_UNITS = BigInt(DEM.amount);

const ORACLE_ACCEPTANCE = {
  checks: [
    { kind: "content-includes" as const, needle: "oracleDigest" },
    { kind: "min-length" as const, minChars: 20 },
  ],
};

/** Real upstream when reachable; canned fallback so a flaky internet can't fail the demo. */
function resilientFetch(): AttestedFetchPort {
  const real = new RealAttestedFetch();
  const fake = new FakeAttestedFetch([
    // oracle desk chain-height — blockchain.info returns a bare integer (canonical-safe).
    ["blockchain.info", { status: 200, body: "901234" }],
    // dd-researcher (npm package "express") — minimal but structurally valid.
    [
      "registry.npmjs.org",
      {
        status: 200,
        body: JSON.stringify({
          name: "express",
          "dist-tags": { latest: "4.19.2" },
          versions: {
            "4.19.2": {
              name: "express",
              version: "4.19.2",
              license: "MIT",
              repository: { type: "git", url: "git+https://github.com/expressjs/express.git" },
            },
          },
          time: { "4.19.2": "2024-03-25T00:00:00.000Z", modified: "2024-03-25T00:00:00.000Z" },
          maintainers: [{ name: "dougwilson" }, { name: "wesleytodd" }],
          license: "MIT",
        }),
      },
    ],
    ["api.npmjs.org", { status: 200, body: JSON.stringify({ downloads: 120_000_000, start: "2024-02-01", end: "2024-02-29", package: "express" }) }],
    // Advisories route MUST precede the repos route: both live under api.github.com.
    ["api.github.com/advisories", { status: 200, body: "[]" }],
    [
      "api.github.com",
      {
        status: 200,
        body: JSON.stringify({
          full_name: "expressjs/express",
          stargazers_count: 65_000,
          open_issues_count: 150,
          forks_count: 11_000,
          pushed_at: "2024-03-25T00:00:00Z",
          archived: false,
          license: { spdx_id: "MIT" },
        }),
      },
    ],
  ]);
  return {
    async attestFetch(url: string): Promise<AttestedFetchResult> {
      try {
        return await real.attestFetch(url);
      } catch (e) {
        console.warn(`  ⚠ upstream fetch failed (${(e as Error).message}); using canned value — rails/lifecycle still under test`);
        return fake.attestFetch(url);
      }
    },
  };
}

/** Print a purchase's decision + rail rationale + refs + verdict. */
function reportPurchase(title: string, decision: ProcurementDecision, outcome: PurchaseOutcome): void {
  line(`\n── ${title} ──`);
  step("discovered", `${decision.candidates.length} candidate(s): ` +
    decision.candidates.map((c) => `${c.provider}${c.excluded ? " ✗" : " ✓"}`).join(", "));
  const w = decision.winner!;
  step("decision", `awarded ${w.provider} · price $${w.price.toFixed(2)} · negotiated=${w.negotiated} · rail=${w.rail}`);
  const nego = decision.negotiations.find((n) => n.result === "agreed" || n.rounds.length > 1);
  if (nego) {
    const t = nego.rounds
      .map((r) => `${r.actor === "buyer" ? "B" : "S"}:${r.action}${r.price !== undefined ? `@${r.price}` : ""}`)
      .join(" → ");
    step("negotiate", `${t}  ⇒ ${nego.result}${nego.agreedPrice !== undefined ? ` @$${nego.agreedPrice}` : ""}`);
  }
  step("rail", outcome.trail[0]!);
  step("settle", `mode=${outcome.mode} settlementRef=${outcome.settlementRef}`);
  step("deliver", `deliveryRef=${outcome.deliveryRef.slice(-28)}`);
  const verdict = outcome.accepted ? "ACCEPTED" : outcome.needsEvaluator ? "NEEDS-EVALUATOR" : "REJECTED";
  step("verdict", `verified=${outcome.verified} · acceptDeliverable=${outcome.acceptance.verdict} ⇒ ${verdict}`);
}

async function main() {
  line("┌──────────────────────────────────────────────────────────────────────┐");
  line("│  DACS Build C — Procurement Butler as a real DACS buyer (mock-first)   │");
  line("└──────────────────────────────────────────────────────────────────────┘");

  const sub = new MemorySubstrate();
  const ledger = new MockDemLedger();
  const fetchPort = resilientFetch();

  const buyerId = makeIdentity("Butler", 0x0b);
  const oracleX402Id = makeIdentity("OracleX402", 0x0a);
  const ddId = makeIdentity("DDResearcher", 0x0c);
  const oracleDemId = makeIdentity("OracleDem", 0x0d);

  const buyer = new BuyerAdapter(buyerId, sub);
  const verifier = new VerifierAdapter(sub);
  const bridge = new DacsButlerBuyer(buyer, verifier, sub);

  // ── Sellers publish ANCHORED DACS-1 listings ──────────────────────────────
  line("\n━━ sellers publish anchored DACS-1 listings ━━");
  const oracleX402 = new SellerAdapter(oracleX402Id, sub, ORACLE_SERVICE_ID, makeOracleWork(fetchPort));
  const oracleX402Ref = await oracleX402.publishListing({
    ...oracleListingSpec({ amount: USDC.amount, asset: USDC.asset }),
    supportedPaymentRails: ["pay-x402"],
  });
  step("oracle/x402", `${oracleX402Ref}  rails=[pay-x402]`);

  const dd = new SellerAdapter(ddId, sub, DD_SERVICE_ID, makeDdWork(fetchPort));
  const ddRef = await dd.publishListing({
    ...ddListingSpec({ amount: DEM.amount, asset: DEM.asset }),
    supportedPaymentRails: ["pay-dem", "pay-x402"], // advertises both; policy keeps pay-dem
  });
  step("dd/pay-dem", `${ddRef}  rails=[pay-dem, pay-x402]`);

  const oracleDem = new SellerAdapter(oracleDemId, sub, ORACLE_SERVICE_ID, makeOracleWork(fetchPort));
  const oracleDemRef = await oracleDem.publishListing({
    ...oracleListingSpec({ amount: DEM.amount, asset: DEM.asset }),
    supportedPaymentRails: ["pay-dem"],
  });
  step("oracle/dem", `${oracleDemRef}  rails=[pay-dem]`);

  // ── The Butler discovers the real anchored listings ───────────────────────
  const offers = await bridge.discoverOffers([
    { ref: oracleX402Ref, scope: "fixed", fee: { kind: "fixed", price: 0.05 }, negotiable: false, acceptance: ORACLE_ACCEPTANCE, quality: { rating: 4.9, completedJobs: 210, disputeRate: 0.0 } },
    { ref: ddRef, scope: "parameterized", fee: { kind: "fixed", price: 6 }, negotiable: true, floor: 4, quality: { rating: 4.6, completedJobs: 70, disputeRate: 0.02 } },
    { ref: oracleDemRef, scope: "fixed", fee: { kind: "fixed", price: 0.05 }, negotiable: false, acceptance: ORACLE_ACCEPTANCE, quality: { rating: 4.7, completedJobs: 90, disputeRate: 0.0 } },
  ]);
  line("\n━━ Butler discovered anchored listings ━━");
  for (const o of offers) {
    step("listing", `"${o.listing.name.slice(0, 40)}" serviceId=${o.listing.serviceId} eligibleRails=[${o.butlerListing.rails.join(", ")}]`);
  }

  // ── Seller runtimes (the seller halves the buyer drives) ──────────────────
  const paywall = await startPaywall({
    route: "/data",
    accepts: { network: "eip155:84532", payTo: oracleX402Id.evm, price: { amount: USDC.amount, asset: USDC.asset } },
    facilitator: new MockFacilitator(),
    deliver: async (jobId, params) => {
      const d = await oracleX402.deliver(jobId, params);
      return { result: d.result, attestationRef: d.attestationRef };
    },
  });
  const watcher = new SellerWatcher(oracleDem, sub, new MockLedgerWatch(ledger), {
    sellerAddr: demosAddrFromDid(oracleDemId.did)!,
    listingPrice: DEM_UNITS,
  });
  watcher.run();

  // ══ Purchase 1 — oracle desk on x402 (fixed scope) ════════════════════════
  const goalA: ProcurementGoal = { description: "attested BTC price", requiredCapabilities: ["oracle-data", "pay-x402"] };
  const decA = await bridge.procure(goalA, 1, offers);
  const runtimeA: SellerRuntime = {
    sellerDid: oracleX402Id.did,
    sellerEvm: oracleX402Id.evm,
    seller: oracleX402,
    observeDelivered: oracleObserveDelivered(),
    deliveryPhase: "deliver-chain-height",
    jobParams: { product: "chain-height" },
    onchainPrice: USDC,
    paywallUrl: paywall.url,
  };
  const outA = await bridge.execute(decA, offers, runtimeA);
  reportPurchase("Purchase 1 · oracle desk · x402", decA, outA);

  // ══ Purchase 2 — dd-researcher on pay-dem session (parameterized) ═════════
  const goalB: ProcurementGoal = { description: "DD report on bitcoin", requiredCapabilities: ["dd-research"] };
  const decB = await bridge.procure(goalB, 8, offers);
  const runtimeB: SellerRuntime = {
    sellerDid: ddId.did,
    sellerEvm: ddId.evm,
    seller: dd,
    observeDelivered: ddObserveDelivered(),
    deliveryPhase: DD_DELIVERY_PHASE,
    jobParams: { kind: "npm-package", subject: "express" },
    onchainPrice: DEM,
    ledger,
  };
  const outB = await bridge.execute(decB, offers, runtimeB);
  reportPurchase("Purchase 2 · dd-researcher · pay-dem session", decB, outB);

  // ══ Purchase 3 — oracle desk on pay-dem memo-watcher (fixed scope) ════════
  const goalC: ProcurementGoal = { description: "attested BTC price (pay-dem)", requiredCapabilities: ["oracle-data", "pay-dem"] };
  const decC = await bridge.procure(goalC, 1, offers);
  const runtimeC: SellerRuntime = {
    sellerDid: oracleDemId.did,
    sellerEvm: oracleDemId.evm,
    seller: oracleDem,
    observeDelivered: oracleObserveDelivered(),
    deliveryPhase: "deliver-chain-height",
    jobParams: { product: "chain-height" },
    onchainPrice: DEM,
    ledger,
  };
  const outC = await bridge.execute(decC, offers, runtimeC);
  reportPurchase("Purchase 3 · oracle desk · pay-dem watcher", decC, outC);

  await paywall.close();

  // ── Verdict: every purchase must settle + deliver + verify ────────────────
  const purchases = [
    { name: "x402", o: outA, expectAccept: true },
    { name: "pay-dem session", o: outB, expectAccept: false }, // needs-evaluator
    { name: "pay-dem watcher", o: outC, expectAccept: true },
  ];
  const lifecycleOk = (o: PurchaseOutcome) =>
    o.verified && o.settlementRef.length > 0 && o.deliveryRef.length > 0 && (o.accepted || o.needsEvaluator);
  const allOk = purchases.every((p) => lifecycleOk(p.o) && (p.expectAccept ? p.o.accepted : p.o.needsEvaluator));

  line("\n━━ marketplace loop ━━");
  for (const p of purchases) {
    const v = p.o.accepted ? "accepted" : p.o.needsEvaluator ? "needs-evaluator" : "REJECTED";
    step(p.name, `settle+deliver+verify=${lifecycleOk(p.o)} · verdict=${v}`);
  }

  line(
    `\n${allOk ? "✅" : "❌"} Build C marketplace ${allOk ? "held" : "FAILED"} — ` +
      `each seller bought on its selected rail; deliveries verified; ` +
      `dd-researcher routed to needs-evaluator (EvalBot = Build D).\n`,
  );
  process.exit(allOk ? 0 : 1);
}

main().catch((e) => {
  console.error("\n❌ dacs:market demo failed:", e?.message ?? e);
  process.exit(1);
});
