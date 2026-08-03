/**
 * Build B demo — the pay-dem rail, both patterns, mock-first.
 *
 *   npm run dacs:paydem
 *
 * Two acts on ONE in-memory DEM ledger (no chain, no keys):
 *
 *   Act 1 — Pattern 2 (session / push) on the dd-researcher. The buyer's
 *     session conveys {kind:"npm-package", subject:"express"} at session-open,
 *     settles DEM (memo=DACS:<jobId>) on the pay-dem rail, and the seller
 *     delivers the DD report + anchors a DACS-X attestation in the same flow.
 *     A read-only verifier re-checks the report OFFLINE from the anchor alone.
 *
 *   Act 2 — Pattern 1 (memo-watcher / chain-triggered) on the oracle desk. The
 *     buyer anchors a fixed-scope agreement (carrying the job params) and just
 *     settles DEM with a DACS memo — it NEVER calls the seller. The seller's
 *     running watcher observes the transfer, reads the params off the anchored
 *     agreement, delivers the attested price, and anchors it. The buyer/verifier
 *     then reads the seller's delivery anchor and verifies.
 *
 * The RAIL is mock. The report + price VALUES are live upstream fetches when
 * reachable; a flaky upstream falls back to canned values with a warning — the
 * rail + both settlement patterns are what's under test.
 *
 * Exit 0 only if BOTH acts verify AND Act 2's delivery was watcher-triggered
 * (no synchronous buyer→seller call).
 */
import type { SessionTerms } from "@kynesyslabs/dacs";
import { makeIdentity } from "../../src/identity.js";
import { MemorySubstrate } from "../../src/substrate/memory.js";
import { FakeAttestedFetch, RealAttestedFetch } from "../oracle-desk/attested-fetch.js";
import type { AttestedFetchPort, AttestedFetchResult } from "../oracle-desk/types.js";
import { SellerAdapter } from "./seller-adapter.js";
import { BuyerAdapter } from "./buyer.js";
import { VerifierAdapter } from "./verifier.js";
import { MockDemLedger, demMemoFor, demosAddrFromDid, payDemRail } from "./rails.js";
import { MockLedgerWatch, SellerWatcher } from "./watcher.js";
import {
  DD_DELIVERY_PHASE,
  DD_SERVICE_ID,
  ddListingSpec,
  ddObserveDelivered,
  makeDdWork,
} from "./wire/dd-researcher.js";
import {
  ORACLE_SERVICE_ID,
  makeOracleWork,
  oracleListingSpec,
  oracleObserveDelivered,
} from "./wire/oracle-desk.js";

const line = (s = "") => console.log(s);
const step = (n: string, msg: string) => console.log(`  ${n.padEnd(12)} ${msg}`);

/** 1 DEM in OS base units (§9.5.9: 1 DEM = 10^9 OS, integer arithmetic). */
const DEM_PRICE = { amount: "1000000000", asset: "DEM" };
const DEM_PRICE_UNITS = BigInt(DEM_PRICE.amount);

/** Real upstream when reachable; canned fallback so a flaky internet can't fail the demo. */
function resilientFetch(): AttestedFetchPort {
  const real = new RealAttestedFetch();
  const fake = new FakeAttestedFetch([
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
    // oracle desk crypto-price (bitcoin) — CoinGecko simple-price shape.
    ["api.coingecko.com", { status: 200, body: JSON.stringify({ bitcoin: { usd: 68000 } }) }],
  ]);
  return {
    async attestFetch(url: string): Promise<AttestedFetchResult> {
      try {
        return await real.attestFetch(url);
      } catch (e) {
        console.warn(`  ⚠ upstream fetch failed (${(e as Error).message}); using canned value — rail/pattern still under test`);
        return fake.attestFetch(url);
      }
    },
  };
}

async function main() {
  line("┌──────────────────────────────────────────────────────────────────┐");
  line("│  DACS Build B — pay-dem rail, both patterns (mock-first)          │");
  line("└──────────────────────────────────────────────────────────────────┘");

  const substrate = new MemorySubstrate();
  const ledger = new MockDemLedger();
  const buyerId = makeIdentity("DemBuyer", 0x0b);
  const buyer = new BuyerAdapter(buyerId, substrate);
  const verifier = new VerifierAdapter(substrate);
  const fetchPort = resilientFetch();

  // ══════════════════════════════════════════════════════════════════════════
  // Act 1 — Pattern 2 (session / push) on the dd-researcher
  // ══════════════════════════════════════════════════════════════════════════
  line("\n═══ ACT 1 — Pattern 2 (session/push): dd-researcher on pay-dem ═══");

  const ddSellerId = makeIdentity("DDResearcher", 0x0a);
  const ddSeller = new SellerAdapter(ddSellerId, substrate, DD_SERVICE_ID, makeDdWork(fetchPort));
  const ddListingRef = await ddSeller.publishListing(ddListingSpec(DEM_PRICE));
  step("DACS-1", `dd listing signed + anchored → ${ddListingRef}`);

  const foundDd = await buyer.discover([ddListingRef]);
  step("discover", `buyer resolved "${foundDd[0]?.listing.name}" (rails ${JSON.stringify(foundDd[0]?.listing.supportedPaymentRails)})`);

  const ddTerms: SessionTerms = {
    price: { amount: DEM_PRICE.amount, asset: DEM_PRICE.asset, decimals: 9, rail: "pay-dem" },
    deliveryPhase: DD_DELIVERY_PHASE,
    deliveryFormat: "application/json",
  };
  const ddJobId = `paydem-dd-${Date.now()}`;
  // The buyer conveys the job params at session-open (Pattern 2): it hands them
  // to the rail, which pushes them into the seller's delivery.
  const ddParams = { kind: "npm-package", subject: "express" };
  step("convey", `params conveyed at session-open: ${JSON.stringify(ddParams)}`);

  const ddResult = await buyer.buy(ddListingRef, ddTerms, {
    jobId: ddJobId,
    settleFn: payDemRail(ddSeller, {
      ledger,
      sub: substrate,
      payer: buyer.demosAddr,
      deliverParams: ddParams,
    }),
  });
  const ddTransfer = ledger.transfers.find((t) => t.memo === demMemoFor(ddJobId));
  step("pay-dem", `DEM settled (mock): ${ddTransfer?.amount} OS memo="${ddTransfer?.memo}" tx=${ddTransfer?.txHash}`);
  step("DACS-3/4/5", `agreement ${ddResult.agreementRef.slice(-8)} · evidence ${ddResult.settlementRef.slice(-8)} · bundle ${ddResult.bundleRef.slice(-8)} (outcome: ${ddResult.outcome})`);

  await ddSeller.fulfil(ddJobId, buyerId.did);
  const ddBundleV = await verifier.verify(ddResult.bundleRef);
  const ddDeliveryV = await verifier.verifyDelivery(ddJobId, {
    serviceId: DD_SERVICE_ID,
    sellerDid: ddSellerId.did,
    observeDelivered: ddObserveDelivered(),
  });
  // The full report rides as a JCS-safe JSON string in signed meta (reportMeta).
  const ddReportJson = (ddDeliveryV.attestation?.meta as { reportJson?: string } | undefined)?.reportJson;
  const ddReportMeta = ddReportJson
    ? (JSON.parse(ddReportJson) as { findings?: unknown[]; subject?: unknown })
    : undefined;
  step("verify", `bundle ok=${ddBundleV.ok} · delivery ok=${ddDeliveryV.ok}${ddDeliveryV.ok ? "" : ` (${ddDeliveryV.reason})`}`);
  step("delivered", `DD report: ${ddReportMeta?.findings?.length ?? "?"} finding(s), report re-verified OFFLINE from the anchor`);

  const act1Ok = ddResult.outcome === "completed" && ddBundleV.ok && ddDeliveryV.ok;

  // ══════════════════════════════════════════════════════════════════════════
  // Act 2 — Pattern 1 (memo-watcher / chain-triggered) on the oracle desk
  // ══════════════════════════════════════════════════════════════════════════
  line("\n═══ ACT 2 — Pattern 1 (memo-watcher): oracle desk on pay-dem ═══");

  const oracleSellerId = makeIdentity("OracleDesk", 0x0c);
  const oracleSeller = new SellerAdapter(oracleSellerId, substrate, ORACLE_SERVICE_ID, makeOracleWork(fetchPort));
  const oracleListingRef = await oracleSeller.publishListing({ ...oracleListingSpec(DEM_PRICE), supportedPaymentRails: ["pay-dem"] });
  const sellerAddr = demosAddrFromDid(oracleSeller.did)!;
  step("DACS-1", `oracle listing anchored → ${oracleListingRef}  seller@${sellerAddr.slice(0, 12)}…`);

  // The seller runs a watcher over inbound transfers — NO inbound endpoint.
  const watch = new MockLedgerWatch(ledger);
  const watcher = new SellerWatcher(oracleSeller, substrate, watch, {
    sellerAddr,
    listingPrice: DEM_PRICE_UNITS,
  });
  watcher.run();
  step("watcher", `SellerWatcher subscribed to transfers @${sellerAddr.slice(0, 12)}… (no inbound endpoint)`);

  // A stray, non-DACS transfer lands first — the watcher must PARK it, not deliver.
  await ledger.transfer({ from: "0x" + "ee".repeat(32), to: sellerAddr, amount: DEM_PRICE_UNITS, memo: "gm ser" });
  step("stray", `a non-DACS transfer landed (memo="gm ser") — watcher decision logged, not delivered`);

  // The BUYER side: anchor a fixed-scope agreement carrying params, then settle
  // DEM with a memo. It NEVER references the oracle seller adapter.
  const oracleJobId = `paydem-oracle-${Date.now()}`;
  const oracleTerms: SessionTerms = {
    price: { amount: DEM_PRICE.amount, asset: DEM_PRICE.asset, decimals: 9, rail: "pay-dem" },
    deliveryPhase: "deliver-crypto-price",
    deliveryFormat: "application/json",
  };
  const oracleParams = { product: "crypto-price", id: "bitcoin" };
  await buyer.openDemAgreement({ jobId: oracleJobId, sellerDid: oracleSellerId.did, listingRef: oracleListingRef, terms: oracleTerms, params: oracleParams });
  step("agreement", `buyer anchored a fixed-scope agreement with params ${JSON.stringify(oracleParams)}`);

  const oracleTx = await buyer.payDemBare(ledger, { jobId: oracleJobId, sellerDid: oracleSellerId.did, amount: DEM_PRICE_UNITS });
  step("pay-dem", `buyer settled DEM (memo="${demMemoFor(oracleJobId)}" tx=${oracleTx}) — and did NOT call the seller`);

  // The watcher (the ONLY subscriber) turned that transfer into a delivery.
  line("\n  ── watcher decision log ──");
  for (const d of watcher.decisions) {
    if (d.action === "delivered") console.log(`    ✔ delivered   job=${d.jobId.slice(-10)} from=${d.from.slice(0, 10)}… amount=${d.amount} → ${d.attestationRef.slice(-8)}`);
    else if (d.action === "skipped-replay") console.log(`    ↻ skipped     job=${d.jobId.slice(-10)} — ${d.reason}`);
    else console.log(`    ⓘ parked      job=${d.jobId ? d.jobId.slice(-10) : "—"} memo="${d.memo}" — ${d.reason}`);
  }

  // Buyer/verifier reads the SELLER's delivery anchor (no seller call) + verifies.
  const oracleDeliveryV = await verifier.verifyDelivery(oracleJobId, {
    serviceId: ORACLE_SERVICE_ID,
    sellerDid: oracleSellerId.did,
    observeDelivered: oracleObserveDelivered(),
  });
  const priceValue = (oracleDeliveryV.attestation?.meta as { value?: unknown } | undefined)?.value;
  step("\n  verify", `delivery ok=${oracleDeliveryV.ok}${oracleDeliveryV.ok ? "" : ` (${oracleDeliveryV.reason})`} · attested value=${JSON.stringify(priceValue)}`);

  const watcherTriggered = watcher.decisions.some((d) => d.action === "delivered" && d.jobId === oracleJobId);
  const strayParked = watcher.decisions.some((d) => d.action === "parked" && d.memo === "gm ser");
  step("decoupled", `delivery watcher-triggered=${watcherTriggered} (buyer made NO synchronous seller call); stray parked=${strayParked}`);

  const act2Ok = oracleDeliveryV.ok && watcherTriggered && strayParked;

  // ── Verdict ────────────────────────────────────────────────────────────────
  const ok = act1Ok && act2Ok;
  line(
    `\n${ok ? "✅" : "❌"} Build B pay-dem ${ok ? "held" : "FAILED"} — ` +
      `Act1(session/push)=${act1Ok} · Act2(memo-watcher, watcher-triggered)=${act2Ok}.\n`,
  );
  process.exit(ok ? 0 : 1);
}

main().catch((e) => {
  console.error("\n❌ dacs:paydem demo failed:", e?.message ?? e);
  process.exit(1);
});
