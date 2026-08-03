/**
 * Build D — the grand DACS ecosystem demo, mock-first.
 *
 *   npm run dacs:ecosystem
 *
 * ALL eight roster sellers publish ANCHORED DACS-1 listings into one in-memory
 * substrate; the Procurement Butler is handed goals + budgets and procures a
 * representative basket that spans all THREE settlement rails:
 *
 *   • pay-x402               — oracle desk, fixed scope (request/response paywall)
 *   • pay-dem session        — dep-upgrade, treasury, evalbot,
 *                              dd-researcher, site-auditor, sec-audit, compliance
 *                              (parameterized: params conveyed at session-open)
 *   • pay-dem memo-watcher   — oracle desk, fixed scope (chain-triggered)
 *
 * Mechanical deliverables (oracle value, upgrade plan, treasury approval, a
 * ruling) auto-accept against the listing's declared
 * checks. Judgment deliverables (DD report, site audit, sec audit, screening)
 * carry no mechanical policy, so the Butler ends them `needs-evaluator` and
 * they route through EvalBot, which issues a SIGNED ruling that flips
 * acceptance to accepted/rejected (wire/evaluator.ts).
 *
 * RAILS are mock (no chain, no facilitator, no keys). The oracle VALUE and the
 * DD REPORT are LIVE upstream fetches when reachable (canned fallback keeps the
 * demo deterministic); the other seven sellers run their FAKE adapters to stay
 * fast + deterministic. Exit 0 only if every commissioned job settles +
 * delivers + verifies AND every needs-evaluator job gets a valid signed ruling.
 */
import { makeIdentity } from "../../src/identity.js";
import { MemorySubstrate } from "../../src/substrate/memory.js";
import { FakeAttestedFetch, MockDahrAttestor, RealAttestedFetch } from "../oracle-desk/attested-fetch.js";
import type { AttestedFetchPort, AttestedFetchResult } from "../oracle-desk/types.js";
import { EvalBot } from "../evalbot/evalbot.js";
import { lodashFallbackRegistry } from "../dep-upgrade/registry.js";
import { FakeProber, type ProbeResult, type TlsInfo } from "../site-auditor/prober.js";
import { fixtureSources } from "../compliance/sources.js";
import type { EvaluationRuling } from "../evalbot/types.js";
import type { ProcurementDecision, ProcurementGoal } from "../procurement-butler/types.js";

import { SellerAdapter } from "./seller-adapter.js";
import { BuyerAdapter } from "./buyer.js";
import { VerifierAdapter } from "./verifier.js";
import { MockDemLedger, demosAddrFromDid } from "./rails.js";
import { MockLedgerWatch, SellerWatcher } from "./watcher.js";
import { MockFacilitator, startPaywall } from "./paywall.js";
import {
  DacsButlerBuyer,
  type DacsOffer,
  type PurchaseOutcome,
  type SellerRuntime,
} from "./wire/butler.js";
import { resolveWithEvaluator, type EvaluatorResolution } from "./wire/evaluator.js";
import { reportDeliverable } from "./wire/report-meta.js";

// --- seller wires -----------------------------------------------------------
import { ORACLE_SERVICE_ID, makeOracleWork, oracleListingSpec, oracleObserveDelivered } from "./wire/oracle-desk.js";
import { DD_DELIVERY_PHASE, DD_SERVICE_ID, ddListingSpec, ddObserveDelivered, makeDdWork } from "./wire/dd-researcher.js";
import {
  DEPUP_DELIVERY_PHASE,
  DEPUP_FEES,
  DEPUP_SERVICE_ID,
  depUpgradeListingSpec,
  depUpgradeObserveDelivered,
  depUpgradeUnitsFor,
  makeDepUpgradeWork,
} from "./wire/dep-upgrade.js";
import { computeFee, displayToBase, formatFeeSchedule, type FeeSchedule } from "./wire/pricing.js";
import {
  EVALBOT_DELIVERY_PHASE,
  EVALBOT_SERVICE_ID,
  evalBotListingSpec,
  evalBotObserveDelivered,
  makeEvalBotWork,
} from "./wire/evalbot.js";
import {
  TREASURY_DELIVERY_PHASE,
  TREASURY_SERVICE_ID,
  treasuryListingSpec,
  treasuryObserveDelivered,
  makeTreasuryWork,
} from "./wire/treasury-ops.js";
import {
  SITE_DELIVERY_PHASE,
  SITE_FEES,
  SITE_SERVICE_ID,
  siteAuditorListingSpec,
  siteAuditorObserveDelivered,
  siteAuditorUnitsFor,
  makeSiteAuditorWork,
} from "./wire/site-auditor.js";
import {
  SEC_AUDIT_DELIVERY_PHASE,
  SEC_AUDIT_FEES,
  SEC_AUDIT_SERVICE_ID,
  secAuditListingSpec,
  secAuditObserveDelivered,
  secAuditUnitsFor,
  makeSecAuditWork,
} from "./wire/sec-audit.js";
import {
  COMPLIANCE_DELIVERY_PHASE,
  COMPLIANCE_SERVICE_ID,
  complianceListingSpec,
  complianceObserveDelivered,
  makeComplianceWork,
} from "./wire/compliance.js";

const line = (s = "") => console.log(s);
const step = (n: string, msg: string) => console.log(`  ${n.padEnd(14)} ${msg}`);

const USDC = { amount: "50000", asset: "USDC", decimals: 6 };
const DEM = { amount: "1000000000", asset: "DEM", decimals: 9 };
const DEM_UNITS = BigInt(DEM.amount);

// ---------------------------------------------------------------------------
// LIVE-with-fallback fetch for the two live sellers (oracle, dd-researcher).
// ---------------------------------------------------------------------------
function resilientFetch(): AttestedFetchPort {
  const real = new RealAttestedFetch();
  const fake = new FakeAttestedFetch([
    ["blockchain.info", { status: 200, body: "901234" }],
    [
      "registry.npmjs.org",
      {
        status: 200,
        body: JSON.stringify({
          name: "express",
          "dist-tags": { latest: "4.19.2" },
          versions: {
            "4.19.2": { name: "express", version: "4.19.2", license: "MIT", repository: { type: "git", url: "git+https://github.com/expressjs/express.git" } },
          },
          time: { "4.19.2": "2024-03-25T00:00:00.000Z", modified: "2024-03-25T00:00:00.000Z" },
          maintainers: [{ name: "dougwilson" }, { name: "wesleytodd" }],
          license: "MIT",
        }),
      },
    ],
    ["api.npmjs.org", { status: 200, body: JSON.stringify({ downloads: 120_000_000, start: "2024-02-01", end: "2024-02-29", package: "express" }) }],
    [
      "api.github.com",
      { status: 200, body: JSON.stringify({ full_name: "expressjs/express", stargazers_count: 65_000, open_issues_count: 150, forks_count: 11_000, pushed_at: "2024-03-25T00:00:00Z", archived: false, license: { spdx_id: "MIT" } }) },
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

// ---------------------------------------------------------------------------
// FAKE fixtures for the seven deterministic sellers
// ---------------------------------------------------------------------------

/** site-auditor: a healthy FakeProber for https://acme.test/. */
function siteFixtures() {
  const TARGET = "https://acme.test/";
  const HTTP_VARIANT = "http://acme.test/";
  const HOST = "acme.test";
  const HEADERS: Record<string, string> = {
    "strict-transport-security": "max-age=63072000; includeSubDomains",
    "content-security-policy": "default-src 'self'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "content-encoding": "br",
    "cache-control": "public, max-age=3600",
    "content-type": "text/html",
  };
  const sample = (over: Partial<ProbeResult> = {}): ProbeResult => ({
    url: TARGET,
    finalUrl: TARGET,
    status: 200,
    ttfbMs: 80,
    totalMs: 150,
    bodyBytes: 12_345,
    redirectCount: 0,
    redirectChain: [TARGET],
    headers: { ...HEADERS },
    fetchedAt: "2026-07-08T00:00:00.000Z",
    ...over,
  });
  const tls: TlsInfo = { host: HOST, validTo: "2026-11-04T00:00:00.000Z", daysRemaining: 120, issuer: "Fake CA", protocol: "TLSv1.3", checkedAt: "2026-07-08T00:00:00.000Z" };
  const prober = new FakeProber(
    {
      [TARGET]: [sample({ totalMs: 120, ttfbMs: 60 }), sample({ totalMs: 150, ttfbMs: 80 }), sample({ totalMs: 180, ttfbMs: 90 })],
      [HTTP_VARIANT]: [sample({ url: HTTP_VARIANT, finalUrl: TARGET, redirectCount: 1, redirectChain: [HTTP_VARIANT, TARGET] })],
    },
    { [HOST]: tls },
  );
  return { prober, url: TARGET };
}

/** treasury-ops: a tiny policy + balances that plans + approves cleanly. */
function treasuryFixture() {
  const policy = {
    policyId: "eco-treasury-v1",
    accounts: [
      { id: "ops-demos", chain: "demos", address: "demos-treasury-1", label: "Demos ops", minBalance: 100, targetPct: 60 },
      { id: "ops-base", chain: "base", address: "0xTREASURYBASE", label: "Base ops", minBalance: 50, targetPct: 40 },
    ],
    allowlist: [{ address: "demos-alice", chain: "demos", label: "Alice" }],
    payroll: [{ recipient: "demos-alice", chain: "demos", amount: 200, label: "Alice", period: "2026-07" }],
    perTxCap: 5000,
    perRunCap: 20_000,
    feeBufferPerTx: 5,
  };
  const balances = { "ops-demos": 2000, "ops-base": 500 };
  return { policy, balances };
}

/**
 * sec-audit: six small clean posted files. Six files exercises the usage-based
 * (per-file) price: 6 x 0.5 DEM = 3 DEM (vs a 1-file audit that would floor at
 * 1 DEM). Zero findings still yields a sealed, verifiable report.
 */
const SEC_FILES = [
  { path: "src/util.ts", content: "export function add(a: number, b: number): number {\n  return a + b;\n}\n" },
  { path: "src/sub.ts", content: "export function sub(a: number, b: number): number {\n  return a - b;\n}\n" },
  { path: "src/mul.ts", content: "export function mul(a: number, b: number): number {\n  return a * b;\n}\n" },
  { path: "src/clamp.ts", content: "export function clamp(n: number): number {\n  return Math.max(0, n);\n}\n" },
  { path: "src/index.ts", content: "export * from './util.js';\nexport * from './sub.js';\n" },
  { path: "README.md", content: "# demo\n\nA tiny module used by the DACS ecosystem demo.\n" },
];

/** evalbot-as-seller: a rubric + a deliverable it will accept. */
const EVAL_JOB = {
  rubric: {
    criteria: [
      { id: "parses", description: "valid JSON", kind: "mechanical", weight: 2, test: { check: "json-parses" } },
      { id: "has-title", description: "mentions a title", kind: "mechanical", weight: 1, test: { check: "content-includes", needle: "title" } },
    ],
    acceptThreshold: 60,
  },
  deliverable: { content: JSON.stringify({ title: "Q3 summary", ok: true }) },
};

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

interface Row {
  seller: string;
  serviceId: string;
  rail: string;
  jobId: string;
  settlementRef: string;
  deliveryRef: string;
  verdict: string;
}

function verdictOf(o: PurchaseOutcome, ruling?: EvaluationRuling): string {
  if (ruling) return o.accepted ? `accepted (ruling ${ruling.verdict})` : `rejected (ruling ${ruling.verdict})`;
  return o.accepted ? "accepted" : o.needsEvaluator ? "needs-evaluator" : "REJECTED";
}

async function main() {
  line("┌──────────────────────────────────────────────────────────────────────────┐");
  line("│  DACS Build D — grand ecosystem: 8 sellers · Butler buyer · EvalBot gate    │");
  line("└──────────────────────────────────────────────────────────────────────────┘");

  const sub = new MemorySubstrate();
  const ledger = new MockDemLedger();
  const liveFetch = resilientFetch();

  // Shared EvalBot identity for the gate (stable evaluator DID across judgments).
  const gateBot = new EvalBot({ useLlm: false });

  // ── Identities ────────────────────────────────────────────────────────────
  const buyerId = makeIdentity("Butler", 0x0b);
  const oracleX402Id = makeIdentity("OracleX402", 0x0a);
  const oracleDemId = makeIdentity("OracleDem", 0x0d);
  const ddId = makeIdentity("DDResearcher", 0x0c);
  const depupId = makeIdentity("DepUpgrade", 0x1a);
  const evalId = makeIdentity("EvalBotSeller", 0x1b);
  const treasuryId = makeIdentity("Treasury", 0x1d);
  const siteId = makeIdentity("SiteAuditor", 0x1e);
  const secId = makeIdentity("SecAudit", 0x1f);
  const complyId = makeIdentity("Compliance", 0x20);

  const buyer = new BuyerAdapter(buyerId, sub);
  const verifier = new VerifierAdapter(sub);
  const bridge = new DacsButlerBuyer(buyer, verifier, sub);

  // ── Sellers + adapters ─────────────────────────────────────────────────────
  const site = siteFixtures();
  const treasury = treasuryFixture();

  const oracleX402 = new SellerAdapter(oracleX402Id, sub, ORACLE_SERVICE_ID, makeOracleWork(liveFetch));
  const oracleDem = new SellerAdapter(oracleDemId, sub, ORACLE_SERVICE_ID, makeOracleWork(liveFetch));
  const dd = new SellerAdapter(ddId, sub, DD_SERVICE_ID, makeDdWork(liveFetch));
  const depup = new SellerAdapter(depupId, sub, DEPUP_SERVICE_ID, makeDepUpgradeWork(lodashFallbackRegistry()));
  const evalSeller = new SellerAdapter(evalId, sub, EVALBOT_SERVICE_ID, makeEvalBotWork(new EvalBot({ useLlm: false })));
  const treasurySeller = new SellerAdapter(treasuryId, sub, TREASURY_SERVICE_ID, makeTreasuryWork());
  const siteSeller = new SellerAdapter(siteId, sub, SITE_SERVICE_ID, makeSiteAuditorWork(site.prober));
  const secSeller = new SellerAdapter(secId, sub, SEC_AUDIT_SERVICE_ID, makeSecAuditWork(new MockDahrAttestor()));
  const complySeller = new SellerAdapter(complyId, sub, COMPLIANCE_SERVICE_ID, makeComplianceWork(fixtureSources()));

  // ── Publish ANCHORED DACS-1 listings ───────────────────────────────────────
  line("\n━━ eight sellers publish anchored DACS-1 listings ━━");
  const oracleX402Ref = await oracleX402.publishListing({ ...oracleListingSpec({ amount: USDC.amount, asset: USDC.asset }), supportedPaymentRails: ["pay-x402"] });
  const oracleDemRef = await oracleDem.publishListing({ ...oracleListingSpec({ amount: DEM.amount, asset: DEM.asset }), supportedPaymentRails: ["pay-dem"] });
  const ddRef = await dd.publishListing({ ...ddListingSpec({ amount: DEM.amount, asset: DEM.asset }), supportedPaymentRails: ["pay-dem", "pay-x402"] });
  const depupRef = await depup.publishListing(depUpgradeListingSpec({ amount: DEM.amount, asset: DEM.asset }));
  const evalRef = await evalSeller.publishListing(evalBotListingSpec({ amount: DEM.amount, asset: DEM.asset }));
  const treasuryRef = await treasurySeller.publishListing(treasuryListingSpec({ amount: DEM.amount, asset: DEM.asset }));
  const siteRef = await siteSeller.publishListing(siteAuditorListingSpec({ amount: DEM.amount, asset: DEM.asset }));
  const secRef = await secSeller.publishListing(secAuditListingSpec({ amount: DEM.amount, asset: DEM.asset }));
  const complyRef = await complySeller.publishListing(complianceListingSpec({ amount: DEM.amount, asset: DEM.asset }));
  for (const [name, ref] of [
    ["oracle/x402", oracleX402Ref], ["oracle/pay-dem", oracleDemRef], ["dd-research", ddRef], ["dep-upgrade", depupRef],
    ["evalbot", evalRef], ["treasury", treasuryRef], ["site-auditor", siteRef],
    ["sec-audit", secRef], ["compliance", complyRef],
  ] as const) {
    step(name, ref);
  }

  // ── Mechanical acceptance policies (auto-accept sellers) ────────────────────
  const ORACLE_ACCEPTANCE = { checks: [{ kind: "content-includes" as const, needle: "oracleDigest" }, { kind: "min-length" as const, minChars: 20 }] };
  const DEPUP_ACCEPTANCE = { checks: [{ kind: "content-includes" as const, needle: "packageName" }, { kind: "min-length" as const, minChars: 20 }] };
  const EVAL_ACCEPTANCE = { checks: [{ kind: "content-includes" as const, needle: "verdict" }, { kind: "min-length" as const, minChars: 20 }] };
  const TREASURY_ACCEPTANCE = { checks: [{ kind: "content-includes" as const, needle: "planHash" }, { kind: "min-length" as const, minChars: 20 }] };

  // ── Discover offers ─────────────────────────────────────────────────────────
  const offers = await bridge.discoverOffers([
    { ref: oracleX402Ref, scope: "fixed", fee: { kind: "fixed", price: 0.05 }, negotiable: false, acceptance: ORACLE_ACCEPTANCE, quality: { rating: 4.9, completedJobs: 210, disputeRate: 0 } },
    { ref: oracleDemRef, scope: "fixed", fee: { kind: "fixed", price: 0.05 }, negotiable: false, acceptance: ORACLE_ACCEPTANCE, quality: { rating: 4.7, completedJobs: 90, disputeRate: 0 } },
    { ref: ddRef, scope: "parameterized", fee: { kind: "fixed", price: 6 }, negotiable: true, floor: 4, quality: { rating: 4.6, completedJobs: 70, disputeRate: 0.02 } },
    // dep-upgrade / site-auditor / sec-audit are USAGE-BASED: metered per
    // dependency / per sample / per file, so a big job costs proportionally more.
    { ref: depupRef, scope: "parameterized", fee: DEPUP_FEES, negotiable: false, acceptance: DEPUP_ACCEPTANCE, quality: { rating: 4.5, completedJobs: 40, disputeRate: 0.01 } },
    { ref: evalRef, scope: "parameterized", fee: { kind: "fixed", price: 2 }, negotiable: false, acceptance: EVAL_ACCEPTANCE, quality: { rating: 4.8, completedJobs: 120, disputeRate: 0 } },
    { ref: treasuryRef, scope: "parameterized", fee: { kind: "fixed", price: 4 }, negotiable: false, acceptance: TREASURY_ACCEPTANCE, quality: { rating: 4.7, completedJobs: 30, disputeRate: 0 } },
    { ref: siteRef, scope: "parameterized", fee: SITE_FEES, negotiable: false, quality: { rating: 4.6, completedJobs: 65, disputeRate: 0.01 } },
    { ref: secRef, scope: "parameterized", fee: SEC_AUDIT_FEES, negotiable: false, quality: { rating: 4.7, completedJobs: 48, disputeRate: 0.01 } },
    { ref: complyRef, scope: "parameterized", fee: { kind: "fixed", price: 5 }, negotiable: false, quality: { rating: 4.8, completedJobs: 33, disputeRate: 0 } },
  ]);

  // ── Seller runtimes (the seller halves the buyer drives) ────────────────────
  const paywall = await startPaywall({
    route: "/data",
    accepts: { network: "eip155:84532", payTo: oracleX402Id.evm, price: { amount: USDC.amount, asset: USDC.asset } },
    facilitator: new MockFacilitator(),
    deliver: async (jobId, params) => {
      const d = await oracleX402.deliver(jobId, params);
      return { result: d.result, attestationRef: d.attestationRef };
    },
  });
  const watcher = new SellerWatcher(oracleDem, sub, new MockLedgerWatch(ledger), { sellerAddr: demosAddrFromDid(oracleDemId.did)!, listingPrice: DEM_UNITS });
  watcher.run();

  // A pay-dem-session runtime for a parameterized report seller. `onchainPrice`
  // defaults to a flat 1 DEM; usage-based sellers pass the metered total so the
  // DEM actually settled matches the scaled quote.
  const session = (opts: { seller: SellerAdapter; id: { did: string; evm: string }; observeDelivered: SellerRuntime["observeDelivered"]; deliveryPhase: string; jobParams: Record<string, unknown>; deliverableOf?: SellerRuntime["deliverableOf"]; onchainPrice?: SellerRuntime["onchainPrice"] }): SellerRuntime => ({
    sellerDid: opts.id.did,
    sellerEvm: opts.id.evm,
    seller: opts.seller,
    observeDelivered: opts.observeDelivered,
    deliveryPhase: opts.deliveryPhase,
    jobParams: opts.jobParams,
    onchainPrice: opts.onchainPrice ?? DEM,
    ledger,
    ...(opts.deliverableOf ? { deliverableOf: opts.deliverableOf } : {}),
  });

  /** A usage-based DEM settlement price for `units` of a metered `fees`. */
  const meteredDem = (fees: FeeSchedule, units: number): SellerRuntime["onchainPrice"] => ({
    amount: displayToBase(computeFee(fees, units), "DEM"),
    asset: "DEM",
    decimals: 9,
  });

  // dd carries its report as an OBJECT in meta (Build B wire); project it to JSON.
  const ddDeliverableOf: SellerRuntime["deliverableOf"] = (att) => ({
    content: JSON.stringify((att.meta as { report?: unknown }).report ?? att.meta),
    meta: att.meta,
  });

  // ── Commission helper ───────────────────────────────────────────────────────
  const rows: Row[] = [];
  const rulings: Array<{ label: string; ruling?: EvaluationRuling; valid: boolean }> = [];
  let allOk = true;

  async function commission(
    label: string,
    seller: string,
    capability: string | string[],
    budget: number,
    runtime: SellerRuntime,
    serviceId?: string,
    pricing?: { units: number; unit: string; fees: FeeSchedule },
  ) {
    const goal: ProcurementGoal = {
      description: label,
      requiredCapabilities: Array.isArray(capability) ? capability : [capability],
      ...(pricing ? { estimatedUnits: pricing.units } : {}),
    };
    const dec: ProcurementDecision = await bridge.procure(goal, budget, offers);
    // Usage-based transparency: show the unit count -> scaled total in the transcript.
    if (pricing && pricing.fees.kind === "per-unit") {
      const total = dec.winner?.price ?? computeFee(pricing.fees, pricing.units);
      step(seller, `usage-based: ${pricing.units} ${pricing.unit} x ${pricing.fees.unitPrice} DEM = ${total} DEM (min ${pricing.fees.minTotal} DEM)`);
    }
    let outcome: PurchaseOutcome = await bridge.execute(dec, offers, runtime);
    let ruling: EvaluationRuling | undefined;

    if (outcome.needsEvaluator) {
      const res: EvaluatorResolution = await resolveWithEvaluator(outcome, { serviceId, evalbot: gateBot });
      outcome = res;
      ruling = res.ruling;
      rulings.push({ label, ruling, valid: res.rulingValid });
    }

    const lifecycleOk = outcome.verified && outcome.settlementRef.length > 0 && outcome.deliveryRef.length > 0 && outcome.accepted;
    if (!lifecycleOk) allOk = false;
    rows.push({
      seller,
      serviceId: dec.winner?.provider ? runtime.seller.did.slice(-8) : "?",
      rail: outcome.rail === "pay-dem" ? `pay-dem/${outcome.mode.replace("pay-dem-", "")}` : outcome.rail,
      jobId: outcome.jobId,
      settlementRef: outcome.settlementRef.slice(-20),
      deliveryRef: outcome.deliveryRef.slice(-20),
      verdict: verdictOf(outcome, ruling),
    });
    return outcome;
  }

  line("\n━━ Butler procures a basket spanning all three rails ━━");

  // pay-x402 (fixed) — oracle desk
  await commission("attested BTC price (x402)", "oracle-desk", ["oracle-data", "pay-x402"], 1, {
    sellerDid: oracleX402Id.did, sellerEvm: oracleX402Id.evm, seller: oracleX402,
    observeDelivered: oracleObserveDelivered(), deliveryPhase: "deliver-chain-height",
    jobParams: { product: "chain-height" }, onchainPrice: USDC, paywallUrl: paywall.url,
  });

  // pay-dem session (parameterized) — mechanical auto-accept sellers
  // dep-upgrade is USAGE-BASED (per dependency): this 1-dependency manifest
  // floors at the 1 DEM minimum; a 20-dependency manifest would bill 2 DEM.
  const depupPkg = { name: "target-app", version: "1.0.0", dependencies: { lodash: "^4.17.20" } };
  const depupUnits = depUpgradeUnitsFor(depupPkg);
  await commission("dependency upgrade plan", "dep-upgrade", DEPUP_SERVICE_ID, 6, session({
    seller: depup, id: depupId, observeDelivered: depUpgradeObserveDelivered(), deliveryPhase: DEPUP_DELIVERY_PHASE,
    jobParams: { packageJson: depupPkg },
    deliverableOf: reportDeliverable,
    onchainPrice: meteredDem(DEPUP_FEES, depupUnits),
  }), undefined, { units: depupUnits, unit: "dependency", fees: DEPUP_FEES });
  await commission("signed treasury plan", "treasury-ops", TREASURY_SERVICE_ID, 8, session({
    seller: treasurySeller, id: treasuryId, observeDelivered: treasuryObserveDelivered(), deliveryPhase: TREASURY_DELIVERY_PHASE,
    jobParams: { policy: treasury.policy, balances: treasury.balances }, deliverableOf: reportDeliverable,
  }));
  await commission("acceptance ruling for hire", "evalbot", EVALBOT_SERVICE_ID, 5, session({
    seller: evalSeller, id: evalId, observeDelivered: evalBotObserveDelivered(), deliveryPhase: EVALBOT_DELIVERY_PHASE,
    jobParams: EVAL_JOB, deliverableOf: reportDeliverable,
  }));

  // pay-dem session (parameterized) — judgment sellers → EvalBot gate
  await commission("DD report on express", "dd-researcher", DD_SERVICE_ID, 8, session({
    seller: dd, id: ddId, observeDelivered: ddObserveDelivered(), deliveryPhase: DD_DELIVERY_PHASE,
    jobParams: { kind: "npm-package", subject: "express" }, deliverableOf: ddDeliverableOf,
  }), DD_SERVICE_ID);
  // site-auditor is USAGE-BASED (per probe sample): 3 samples x 0.5 = 1.5 DEM.
  const siteUnits = siteAuditorUnitsFor({ samples: 3 });
  await commission("site reliability audit", "site-auditor", SITE_SERVICE_ID, 6, session({
    seller: siteSeller, id: siteId, observeDelivered: siteAuditorObserveDelivered(), deliveryPhase: SITE_DELIVERY_PHASE,
    jobParams: { url: site.url, samples: 3 }, deliverableOf: reportDeliverable,
    onchainPrice: meteredDem(SITE_FEES, siteUnits),
  }), SITE_SERVICE_ID, { units: siteUnits, unit: "sample", fees: SITE_FEES });
  // sec-audit is USAGE-BASED (per file scanned): 6 files x 0.5 = 3 DEM.
  const secUnits = secAuditUnitsFor(SEC_FILES);
  await commission("static security audit", "sec-audit", SEC_AUDIT_SERVICE_ID, 8, session({
    seller: secSeller, id: secId, observeDelivered: secAuditObserveDelivered(), deliveryPhase: SEC_AUDIT_DELIVERY_PHASE,
    jobParams: { files: SEC_FILES }, deliverableOf: reportDeliverable,
    onchainPrice: meteredDem(SEC_AUDIT_FEES, secUnits),
  }), SEC_AUDIT_SERVICE_ID, { units: secUnits, unit: "file", fees: SEC_AUDIT_FEES });
  await commission("sanctions screening", "compliance", COMPLIANCE_SERVICE_ID, 8, session({
    seller: complySeller, id: complyId, observeDelivered: complianceObserveDelivered(), deliveryPhase: COMPLIANCE_DELIVERY_PHASE,
    jobParams: { kind: "entity", name: "Acme Industrial Holdings" }, deliverableOf: reportDeliverable,
  }), COMPLIANCE_SERVICE_ID);

  // pay-dem memo-watcher (fixed) — oracle desk, chain-triggered
  await commission("attested BTC price (watcher)", "oracle-desk", ["oracle-data", "pay-dem"], 1, {
    sellerDid: oracleDemId.did, sellerEvm: oracleDemId.evm, seller: oracleDem,
    observeDelivered: oracleObserveDelivered(), deliveryPhase: "deliver-chain-height",
    jobParams: { product: "chain-height" }, onchainPrice: DEM, ledger,
  });

  await paywall.close();

  // ── Ecosystem summary table ─────────────────────────────────────────────────
  line("\n━━ ecosystem summary ━━");
  const pad = (s: string, n: number) => (s.length > n ? s.slice(0, n) : s.padEnd(n));
  line("  " + [pad("seller", 15), pad("rail", 20), pad("jobId", 30), pad("settle", 20), pad("delivery", 20), "verdict"].join(" "));
  line("  " + "─".repeat(120));
  for (const r of rows) {
    line("  " + [pad(r.seller, 15), pad(r.rail, 20), pad(r.jobId, 30), pad(r.settlementRef, 20), pad(r.deliveryRef, 20), r.verdict].join(" "));
  }

  // ── Evaluator gate summary ──────────────────────────────────────────────────
  line("\n━━ EvalBot gate (needs-evaluator → signed ruling) ━━");
  const everyRulingValid = rulings.every((r) => r.ruling !== undefined && r.valid && r.ruling.verdict === "accept");
  for (const r of rulings) {
    step(r.label, `ruling=${r.ruling?.verdict ?? "MISSING"} valid=${r.valid} aggregate=${r.ruling?.aggregate ?? "n/a"}`);
  }
  if (!everyRulingValid) allOk = false;
  if (rulings.length < 4) allOk = false; // dd + site + sec + compliance must all route through the gate

  const railsSeen = new Set(rows.map((r) => r.rail));
  const spansAllRails = railsSeen.has("pay-x402") && [...railsSeen].some((r) => r.includes("session")) && [...railsSeen].some((r) => r.includes("watcher"));
  if (!spansAllRails) allOk = false;

  line(
    `\n${allOk ? "✅" : "❌"} Build D ecosystem ${allOk ? "held" : "FAILED"} — ` +
      `${rows.length} commissions across [${[...railsSeen].join(", ")}]; ` +
      `${rulings.length} judgment deliverables resolved through the EvalBot gate.\n`,
  );
  process.exit(allOk ? 0 : 1);
}

main().catch((e) => {
  console.error("\n❌ dacs:ecosystem demo failed:", e?.stack ?? e?.message ?? e);
  process.exit(1);
});
