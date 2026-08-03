/**
 * DACS-buyer bridge — the Procurement Butler as a REAL DACS buyer.
 *
 * Build C. The Butler core (`roster/procurement-butler/`) is a pure decision
 * engine: capability filter → price/rail/quality scoring → bounded negotiation
 * → a ProcurementDecision. This module connects that decision to a real
 * anchored-listing marketplace and to an actual settlement + delivery + verify
 * over the shared `roster/dacs/` seller layer. The Butler's decision logic is
 * KEPT verbatim; everything here happens BEFORE it (discovery → mapping) and
 * AFTER it (rail-selection execution → accept + verify gating).
 *
 * Three moving parts:
 *
 *   1. Real discovery + mapping — `discoverOffers` resolves anchored DACS-1
 *      Listings (via the SDK `discoverListings`), and `toButlerListing` maps
 *      each into the Butler's internal Listing shape so its scoring/negotiation
 *      runs UNCHANGED against real listings. The stub marketplace stays the
 *      offline seam; here we feed it real anchored listings.
 *
 *   2. Rail-selection policy — `eligibleRails(supportedPaymentRails, scope)` is
 *      the capability/shape → rail-eligibility gate: a fixed-scope service may
 *      settle on x402 OR pay-dem; a parameterized service (params conveyed at
 *      session-open) is pay-dem-only; `pay-evm-erc8183` isn't wired in this
 *      build. The eligible set becomes the mapped listing's `rails`, so the
 *      Butler's own `bestRail` picks from policy-eligible rails and the choice
 *      is surfaced in the ProcurementDecision audit (chosenRail / exclusion).
 *      `executionModeFor(rail, scope)` then resolves the concrete execution.
 *
 *   3. Purchase execution — `execute` runs the awarded decision end-to-end on
 *      its selected rail (x402 paywall / pay-dem session push / pay-dem
 *      memo-watcher), then gates acceptance on BOTH the Butler's mechanical
 *      `acceptDeliverable` checks AND the verifier's delivery verification.
 */
import type { Listing as DacsListing } from "@kynesyslabs/dacs";
import type { SessionTerms } from "@kynesyslabs/dacs";
import type { SubstratePort } from "../../../src/ports.js";
import { ProcurementButler } from "../../procurement-butler/butler.js";
import { MarketplaceStub } from "../../procurement-butler/marketplace-stub.js";
import type {
  AcceptancePolicy,
  AcceptanceResult,
  ButlerConfig,
  Deliverable,
  FeeSchedule,
  Listing as ButlerListing,
  PaymentRail,
  ProcurementAgreement,
  ProcurementDecision,
  ProcurementGoal,
  QualityStats,
} from "../../procurement-butler/types.js";
import { BuyerAdapter } from "../buyer.js";
import { makeX402MockSettle } from "../buyer.js";
import { MockDemLedger, demMemoFor, type DemLedgerPort, type SettleSeam, payDemRail } from "../rails.js";
import type { DeliveryAttestation, SellerAdapter } from "../seller-adapter.js";
import { VerifierAdapter, type DeliveryVerifyOptions } from "../verifier.js";
import type { Listing as StandardListing } from "../standard-profile.js";
import { runStandardFixedSession, type StandardSettlementReceipt } from "../standard-runner.js";
import type { AgreementDocument, CommitmentRecord } from "../standard-profile.js";

type DacsListingLike = DacsListing | StandardListing;

function isStandardListing(listing: DacsListingLike): listing is StandardListing {
  return "dacsVersion" in listing && "offering" in listing;
}

function listingSurface(listing: DacsListingLike): {
  serviceId: string;
  name: string;
  description: string;
  negotiation: string[];
  paymentRails: string[];
  delivery: string[];
} {
  if (!isStandardListing(listing)) {
    return {
      serviceId: listing.serviceId,
      name: listing.name,
      description: listing.description,
      negotiation: listing.supportedNegotiation,
      paymentRails: listing.supportedPaymentRails,
      delivery: listing.supportedDelivery,
    };
  }
  return {
    serviceId: listing.listingId,
    name: listing.seller.displayName,
    description: listing.offering.description,
    negotiation: listing.pipeline.filter((step) => step.kind.startsWith("negotiate-")).map((step) => step.kind),
    paymentRails: listing.pipeline.filter((step) => step.kind.startsWith("pay-")).map((step) => step.kind),
    delivery: listing.pipeline.filter((step) => step.kind.startsWith("deliver-")).map((step) => step.kind),
  };
}

// ---------------------------------------------------------------------------
// Service scope + execution mode
// ---------------------------------------------------------------------------

/**
 * A service's scope. `fixed` = the job is fully specified by the listing (the
 * oracle desk: "give me bitcoin's price"). `parameterized` = the buyer conveys
 * per-job params during the signed DACS session. Both can settle through the
 * session-bound x402 resource or the native Demos rail.
 */
export type ServiceScope = "fixed" | "parameterized";

/** The concrete way a purchase is executed once a rail is chosen. */
export type ExecutionMode = "x402" | "pay-dem-session" | "pay-dem-watcher";

/** Butler rails this build can actually execute (pay-evm-erc8183 is unwired). */
export const EXECUTABLE_RAILS: readonly PaymentRail[] = ["pay-x402", "pay-dem"];

const KNOWN_RAILS: readonly PaymentRail[] = ["pay-dem", "pay-x402", "pay-evm-erc8183"];

function isPaymentRail(s: string): s is PaymentRail {
  return (KNOWN_RAILS as readonly string[]).includes(s);
}

/**
 * Rail-eligibility policy — the capability/shape gate. Given a DACS listing's
 * advertised rails and the service scope, return the rails the Butler may
 * actually choose from (deduped, in advertised order):
 *
 *   - unknown / unwired rails (`pay-evm-erc8183`) are dropped;
 *   - pay-x402 is eligible for either scope because the negotiated jobId and
 *     request are bound before the per-session HTTP resource is created;
 *   - pay-dem is eligible for either scope.
 *
 * The result becomes the mapped listing's `rails`, so an over-advertised but
 * ineligible rail simply never wins — and if the policy empties the set, the
 * Butler excludes the listing with "no supported payment rail".
 */
export function eligibleRails(supportedPaymentRails: string[], scope: ServiceScope): PaymentRail[] {
  const out: PaymentRail[] = [];
  for (const r of supportedPaymentRails) {
    if (!isPaymentRail(r)) continue;
    if (!EXECUTABLE_RAILS.includes(r)) continue; // pay-evm-erc8183: not wired
    if (!out.includes(r)) out.push(r);
  }
  return out;
}

/**
 * Resolve the concrete execution mode from the chosen rail + scope:
 *   - pay-x402 → x402 (a session-bound request-response paywall).
 *   - pay-dem + fixed → pay-dem-watcher (Pattern 1, chain-triggered).
 *   - pay-dem + parameterized → pay-dem-session (Pattern 2, params at open).
 */
export function executionModeFor(rail: PaymentRail, scope: ServiceScope): ExecutionMode {
  if (rail === "pay-x402") {
    return "x402";
  }
  if (rail === "pay-dem") {
    return scope === "parameterized" ? "pay-dem-session" : "pay-dem-watcher";
  }
  throw new Error(`rail policy: ${rail} is not executable in this build`);
}

/** One-line rationale for the audit trail: why this rail + mode were chosen. */
export function railRationale(
  offer: Pick<DacsOffer, "scope" | "listing">,
  rail: PaymentRail,
  mode: ExecutionMode,
): string {
  const advertised = listingSurface(offer.listing).paymentRails;
  const eligible = eligibleRails(advertised, offer.scope);
  return (
    `advertised [${advertised.join(", ")}] ∩ policy(${offer.scope}) ` +
    `= eligible [${eligible.join(", ")}] → chose ${rail} → ${mode}`
  );
}

// ---------------------------------------------------------------------------
// DACS Listing → Butler Listing mapping
// ---------------------------------------------------------------------------

/**
 * A discovered anchored listing plus the off-listing facts the Butler scores
 * on. The DACS-1 Listing carries no fee, quality, or scope — a real deployment
 * pairs those from a price surface + reputation index; here the caller supplies
 * them per offer. `floor` (+ `concessionStep`) is the seller's PRIVATE
 * walk-away used by the negotiation counterparty (never on the public listing).
 */
export interface DacsOffer {
  /** The anchored listing ref (unique per listing — the Butler listing id). */
  ref: string;
  /** The resolved, structurally-valid DACS-1 Listing. */
  listing: DacsListingLike;
  /** Fixed vs parameterized — drives rail eligibility + execution mode. */
  scope: ServiceScope;
  /** Price surface: the Butler's fee schedule for this service. */
  fee: FeeSchedule;
  /** Track record for scoring (neutral default if omitted). */
  quality?: QualityStats;
  /** Mechanical acceptance checks (absent ⇒ acceptance needs an evaluator). */
  acceptance?: AcceptancePolicy;
  /** Override negotiability (default: listing advertises negotiate-fixed-price). */
  negotiable?: boolean;
  /** Private seller floor for the negotiation counterparty (mock). */
  floor?: number;
  /** Per-round concession fraction for the counterparty (mock). */
  concessionStep?: number;
}

const NEUTRAL_QUALITY: QualityStats = { rating: 4, completedJobs: 25, disputeRate: 0.02 };

/** Lowercased, de-duplicated capability tags: serviceId + delivery + rails. */
function capabilitiesOf(listing: DacsListingLike): string[] {
  const surface = listingSurface(listing);
  const tags = [surface.serviceId, ...surface.delivery, ...surface.paymentRails];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const t of tags) {
    const lc = t.toLowerCase();
    if (!seen.has(lc)) {
      seen.add(lc);
      out.push(lc);
    }
  }
  return out;
}

/**
 * Map a discovered DACS-1 Listing into the Butler's internal Listing shape so
 * its EXISTING scoring/negotiation runs unchanged:
 *   - id            ← the anchored ref (unique; two listings can share serviceId)
 *   - provider      ← listing.name
 *   - capabilities  ← serviceId + supportedDelivery + supportedPaymentRails
 *   - fees          ← the supplied price surface
 *   - rails         ← eligibleRails(supportedPaymentRails, scope)  [policy gate]
 *   - negotiable    ← supportedNegotiation includes negotiate-fixed-price OR rfq
 *   - quality       ← supplied track record (neutral default)
 *   - acceptance    ← supplied mechanical checks (absent ⇒ needs-evaluator)
 */
export function toButlerListing(offer: DacsOffer): ButlerListing {
  const l = listingSurface(offer.listing);
  const negotiable =
    offer.negotiable ??
    (l.negotiation.includes("negotiate-fixed-price") ||
      // An "rfq" listing is negotiable too — via the multi-dimensional RFQ
      // engine (audit-negotiator), not the scalar negotiate-fixed-price path.
      l.negotiation.includes("negotiate-rfq"));
  return {
    id: offer.ref,
    provider: l.name,
    description: l.description,
    capabilities: capabilitiesOf(offer.listing),
    fees: offer.fee,
    rails: eligibleRails(l.paymentRails, offer.scope),
    negotiable,
    quality: offer.quality ?? NEUTRAL_QUALITY,
    acceptance: offer.acceptance,
  };
}

// ---------------------------------------------------------------------------
// Purchase execution
// ---------------------------------------------------------------------------

/**
 * The seller-side seams the bridge drives to actually execute a purchase. Only
 * the seam for the SELECTED mode is used; the caller (demo/tests) stands up the
 * seller half (paywall / running watcher) and passes it here.
 */
export interface SellerRuntime {
  sellerDid: string;
  /** Seller EVM coordinate, recorded as the x402 payee. */
  sellerEvm: string;
  /** Seller adapter — pushes delivery on the pay-dem session rail. */
  seller: SellerAdapter;
  /** The verifier's per-service `observeDelivered` re-check. */
  observeDelivered: DeliveryVerifyOptions["observeDelivered"];
  /** Delivery phase advertised by the listing (session terms). */
  deliveryPhase: string;
  /** Delivery format for the terms (default application/json). */
  deliveryFormat?: string;
  /** What to buy — oracle {product,id} / dd {kind,subject}. */
  jobParams: Record<string, unknown>;
  /** On-wire price (base-unit amount + asset + decimals) for terms/paywall. */
  onchainPrice: { amount: string; asset: string; decimals: number };
  /** x402 seam: the seller's running paywall URL. */
  paywallUrl?: string;
  /**
   * LIVE x402 override: a ready settle seam that runs the REAL buyer-side 402
   * dance against the hosted facilitator (Base Sepolia USDC). When present,
   * `runX402` uses it INSTEAD of the mock 402-dance — the caller closes it over
   * a running live paywall + `createX402Rail` buyer (see `roster/dacs/live`).
   * Absent ⇒ the mock path over `paywallUrl` (unchanged; keeps demos/tests green).
   */
  x402Settle?: SettleSeam;
  /**
   * LIVE pay-dem-session override: a ready settle seam that moves real DEM and
   * pushes delivery in the SAME flow. When present, `runPayDemSession` uses it
   * INSTEAD of the mock `payDemRail`. Needed live because the mock `payDemRail`
   * couples on `anchorAddress` (the buyer's OWN owner scope), but a live seller
   * anchors its delivery under the SELLER's owner — so the live seam must read
   * `anchorAddressFor(sellerDid, …)` itself. Absent ⇒ the mock ledger path.
   */
  payDemSessionSettle?: SettleSeam;
  /** pay-dem seam: the DEM ledger both patterns settle over. */
  ledger?: DemLedgerPort;
  /** CAIP-2 network for x402 (default eip155:84532). */
  network?: string;
  /** Project the delivered attestation into a mechanical-checkable artifact. */
  deliverableOf?: (att: DeliveryAttestation) => Deliverable;
  /**
   * Full-Standard settlement seam. Required when executing a Standard listing;
   * reduced SDK settle seams are intentionally not promoted because they omit
   * the finality/typed tx references needed by DACS-4 evidence.
   */
  standardSettle?: (input: { jobId: string; agreement: AgreementDocument; commitment: CommitmentRecord }) => Promise<StandardSettlementReceipt>;
}

export interface PurchaseOutcome {
  /** The Butler's full decision (candidates, negotiations, winner). */
  decision: ProcurementDecision;
  jobId: string;
  rail: PaymentRail;
  mode: ExecutionMode;
  /** Settlement reference: session evidence ref (x402/session) or DEM txHash (watcher). */
  settlementRef: string;
  /** The anchored DACS-X delivery attestation address. */
  deliveryRef: string;
  /** The verifier's delivery verification passed (signature + observeDelivered). */
  verified: boolean;
  /** The delivered artifact the Butler ran its mechanical checks against. */
  deliverable: Deliverable;
  /** The Butler's acceptDeliverable verdict (accept / reject / needs-evaluator). */
  acceptance: AcceptanceResult;
  /** True only if the delivery verified AND the mechanical checks accepted. */
  accepted: boolean;
  /** True when the deliverable isn't mechanically checkable (route to EvalBot, Build D). */
  needsEvaluator: boolean;
  /** Human-readable execution trail (rail rationale + each phase). */
  trail: string[];
}

/** Default projection: the signed delivery meta as the checkable artifact. */
function defaultDeliverable(att: DeliveryAttestation): Deliverable {
  const content = JSON.stringify(att.meta ?? { resultHash: att.resultHash });
  return { content, meta: att.meta };
}

// A market with no listings — acceptDeliverable is pure over the agreement, so
// any butler instance can run it; this avoids threading the procure-time one.
const EMPTY_MARKET = new MarketplaceStub([], { floors: {} });

/**
 * The Procurement Butler wired as a real DACS buyer: discover anchored listings,
 * decide, then execute + accept/verify across rails.
 */
export class DacsButlerBuyer {
  private readonly acceptor: ProcurementButler;

  constructor(
    private readonly buyer: BuyerAdapter,
    private readonly verifier: VerifierAdapter,
    private readonly sub: SubstratePort,
    private readonly config?: ButlerConfig,
  ) {
    this.acceptor = new ProcurementButler(EMPTY_MARKET, EMPTY_MARKET, config);
  }

  /** Resolve anchored listings and map each into a Butler-scored offer. */
  async discoverOffers(
    profiles: Array<Omit<DacsOffer, "listing"> & { ref: string }>,
  ): Promise<Array<DacsOffer & { butlerListing: ButlerListing }>> {
    const found = await this.buyer.discover(profiles.map((p) => p.ref));
    const byRef = new Map(found.map((f) => [f.ref, f.listing]));
    const offers: Array<DacsOffer & { butlerListing: ButlerListing }> = [];
    for (const p of profiles) {
      const listing = byRef.get(p.ref);
      if (!listing) continue; // unresolvable / malformed — skipped by discover
      const offer: DacsOffer = { ...p, listing };
      offers.push({ ...offer, butlerListing: toButlerListing(offer) });
    }
    return offers;
  }

  /** Standard-first discovery path for versioned, signed DACS-1 listings. */
  async discoverStandardOffers(
    profiles: Array<Omit<DacsOffer, "listing"> & { ref: string }>,
  ): Promise<Array<DacsOffer & { butlerListing: ButlerListing }>> {
    const found = await this.buyer.discoverStandard(profiles.map((profile) => profile.ref));
    const byRef = new Map(found.map((entry) => [entry.ref, entry.listing]));
    const offers: Array<DacsOffer & { butlerListing: ButlerListing }> = [];
    for (const profile of profiles) {
      const listing = byRef.get(profile.ref);
      if (!listing) continue;
      const offer: DacsOffer = { ...profile, listing };
      offers.push({ ...offer, butlerListing: toButlerListing(offer) });
    }
    return offers;
  }

  /**
   * Run the Butler's UNCHANGED decision logic over the mapped offers. The
   * offers back both marketplace ports (search + negotiation) via the stub, with
   * each offer's private floor fed to the negotiation counterparty.
   */
  async procure(
    goal: ProcurementGoal,
    budget: number,
    offers: DacsOffer[],
  ): Promise<ProcurementDecision> {
    const listings = offers.map((o) => toButlerListing(o));
    const floors: Record<string, number> = {};
    let concessionStep: number | undefined;
    for (const o of offers) {
      if (o.floor !== undefined) floors[o.ref] = o.floor;
      if (o.concessionStep !== undefined) concessionStep = o.concessionStep;
    }
    const market = new MarketplaceStub(listings, { floors, concessionStep });
    const butler = new ProcurementButler(market, market, this.config);
    return butler.procure(goal, budget);
  }

  /**
   * Execute an AWARDED decision end-to-end on its selected rail, then gate
   * acceptance on BOTH the mechanical checks and the verifier.
   */
  async execute(
    decision: ProcurementDecision,
    offers: DacsOffer[],
    runtime: SellerRuntime,
    opts: { jobId?: string } = {},
  ): Promise<PurchaseOutcome> {
    const winner = decision.winner;
    if (!winner) throw new Error("execute: decision has no award");
    const offer = offers.find((o) => o.ref === winner.listingId);
    if (!offer) throw new Error(`execute: no offer for awarded listing ${winner.listingId}`);

    if (isStandardListing(offer.listing)) {
      return this.executeStandard(decision, { ...offer, listing: offer.listing }, runtime, opts);
    }

    const rail = winner.rail;
    const mode = executionModeFor(rail, offer.scope);
    const jobId = opts.jobId ?? `${listingSurface(offer.listing).serviceId}-${mode}-${Date.now()}`;
    const trail: string[] = [railRationale(offer, rail, mode), `job ${jobId}`];

    let settlementRef: string;
    if (mode === "x402") {
      settlementRef = await this.runX402(offer, winner, runtime, jobId, trail);
    } else if (mode === "pay-dem-session") {
      settlementRef = await this.runPayDemSession(offer, winner, runtime, jobId, trail);
    } else {
      settlementRef = await this.runPayDemWatcher(offer, runtime, jobId, trail);
    }

    // --- Delivery: read the anchored DACS-X attestation the seller produced ---
    const deliveryRef = await this.sub.anchorAddressFor(runtime.sellerDid, `dacsx:delivery:${jobId}`);
    const delivRaw = await this.sub.read(deliveryRef);
    if (!delivRaw) throw new Error(`execute: no delivery anchored for job ${jobId}`);
    const att = delivRaw as unknown as DeliveryAttestation;

    // --- Gate 1: verifier delivery verification (signature + observeDelivered) ---
    const dv = await this.verifier.verifyDelivery(jobId, {
      serviceId: listingSurface(offer.listing).serviceId,
      sellerDid: runtime.sellerDid,
      observeDelivered: runtime.observeDelivered,
    });
    const verified = dv.ok;
    trail.push(`verifier.verifyDelivery ok=${verified}${verified ? "" : ` (${dv.reason})`}`);

    // --- Gate 2: the Butler's mechanical acceptance checks over the artifact ---
    const deliverable = (runtime.deliverableOf ?? defaultDeliverable)(att);
    const acceptance = this.acceptor.acceptDeliverable(deliverable, winner);
    trail.push(`acceptDeliverable verdict=${acceptance.verdict}`);

    const accepted = verified && acceptance.verdict === "accept";
    const needsEvaluator = verified && acceptance.verdict === "needs-evaluator";
    trail.push(`accepted=${accepted} needsEvaluator=${needsEvaluator}`);

    return {
      decision,
      jobId,
      rail,
      mode,
      settlementRef,
      deliveryRef,
      verified,
      deliverable,
      acceptance,
      accepted,
      needsEvaluator,
      trail,
    };
  }

  private async executeStandard(
    decision: ProcurementDecision,
    offer: DacsOffer & { listing: StandardListing },
    runtime: SellerRuntime,
    opts: { jobId?: string },
  ): Promise<PurchaseOutcome> {
    const winner = decision.winner!;
    if (!runtime.standardSettle) throw new Error("Standard listing execution requires runtime.standardSettle with typed tx refs and finality");
    const rail = winner.rail;
    const mode = executionModeFor(rail, offer.scope);
    const jobId = opts.jobId ?? `${offer.listing.listingId}-${mode}-${Date.now()}`;
    const trail = [railRationale(offer, rail, mode), `job ${jobId}`, "full Standard Identify→Vet→Negotiate→Commit→Settle→Deliver→Verify"];
    const result = await runStandardFixedSession({
      jobId,
      listingRef: offer.ref,
      listing: offer.listing,
      buyer: this.buyer,
      seller: runtime.seller,
      params: runtime.jobParams,
      settle: runtime.standardSettle,
    });
    const deliveryRef = result.delivery.attestationRef;
    const verification = await this.verifier.verifyDelivery(jobId, {
      serviceId: offer.listing.listingId,
      sellerDid: runtime.sellerDid,
      observeDelivered: runtime.observeDelivered,
    });
    const deliverable = (runtime.deliverableOf ?? defaultDeliverable)(result.delivery.attestation);
    const acceptance = this.acceptor.acceptDeliverable(deliverable, winner);
    const accepted = verification.ok && acceptance.verdict === "accept";
    const needsEvaluator = verification.ok && acceptance.verdict === "needs-evaluator";
    trail.push(`commitment=${result.commitmentRef.anchor.locator}`);
    trail.push(`paymentEvidence=${result.paymentEvidenceRef.anchor.locator}`);
    trail.push(`two-sided bundles buyer=${result.buyerBundleRef} seller=${result.sellerBundleRef}`);
    trail.push(`verifier.verifyDelivery ok=${verification.ok}${verification.ok ? "" : ` (${verification.reason})`}`);
    trail.push(`acceptDeliverable verdict=${acceptance.verdict}`);
    return {
      decision,
      jobId,
      rail,
      mode,
      settlementRef: result.paymentEvidenceRef.anchor.locator,
      deliveryRef,
      verified: verification.ok,
      deliverable,
      acceptance,
      accepted,
      needsEvaluator,
      trail,
    };
  }

  // -------------------------------------------------------------------------
  // Per-rail execution seams
  // -------------------------------------------------------------------------

  private termsFor(rail: PaymentRail, runtime: SellerRuntime): SessionTerms {
    return {
      price: {
        amount: runtime.onchainPrice.amount,
        asset: runtime.onchainPrice.asset,
        decimals: runtime.onchainPrice.decimals,
        rail,
      },
      deliveryPhase: runtime.deliveryPhase,
      deliveryFormat: runtime.deliveryFormat ?? "application/json",
    };
  }

  /** x402 request-response: run the session against the seller's paywall. */
  private async runX402(
    offer: DacsOffer,
    _winner: ProcurementAgreement,
    runtime: SellerRuntime,
    jobId: string,
    trail: string[],
  ): Promise<string> {
    let settleFn: SettleSeam;
    if (runtime.x402Settle) {
      // LIVE: real facilitator settlement (the seam closes over paywall + rail).
      settleFn = runtime.x402Settle;
      trail.push("x402 live settle seam (real hosted facilitator)");
    } else {
      if (!runtime.paywallUrl) throw new Error("x402 execution needs runtime.paywallUrl or runtime.x402Settle");
      const params: Record<string, string> = {};
      for (const [k, v] of Object.entries(runtime.jobParams)) params[k] = String(v);
      settleFn = makeX402MockSettle({
        paywallUrl: runtime.paywallUrl,
        sub: this.sub,
        payerEvm: this.buyer.evm,
        payeeEvm: runtime.sellerEvm,
        params,
        network: runtime.network,
      });
    }
    const res = await this.buyer.buy(offer.ref, this.termsFor("pay-x402", runtime), { jobId, settleFn });
    trail.push(`x402 session outcome=${res.outcome} evidence=${res.settlementRef}`);
    if (res.outcome !== "completed") throw new Error(`x402 session failed for job ${jobId}`);
    return res.settlementRef;
  }

  /** pay-dem session (Pattern 2): params conveyed at open, seller pushes delivery. */
  private async runPayDemSession(
    offer: DacsOffer,
    _winner: ProcurementAgreement,
    runtime: SellerRuntime,
    jobId: string,
    trail: string[],
  ): Promise<string> {
    let settleFn: SettleSeam;
    if (runtime.payDemSessionSettle) {
      // LIVE: real DEM transfer + seller-owner-scoped delivery coupling.
      settleFn = runtime.payDemSessionSettle;
      trail.push("pay-dem live session settle seam (real DEM transfer)");
    } else {
      if (!runtime.ledger) throw new Error("pay-dem session needs runtime.ledger or runtime.payDemSessionSettle");
      settleFn = payDemRail(runtime.seller, {
        ledger: runtime.ledger,
        sub: this.sub,
        payer: this.buyer.demosAddr,
        deliverParams: runtime.jobParams,
      });
    }
    const res = await this.buyer.buy(offer.ref, this.termsFor("pay-dem", runtime), { jobId, settleFn });
    trail.push(`pay-dem session outcome=${res.outcome} evidence=${res.settlementRef}`);
    if (res.outcome !== "completed") throw new Error(`pay-dem session failed for job ${jobId}`);
    return res.settlementRef;
  }

  /** pay-dem memo-watcher (Pattern 1): anchor the agreement, settle bare, watcher delivers. */
  private async runPayDemWatcher(
    offer: DacsOffer,
    runtime: SellerRuntime,
    jobId: string,
    trail: string[],
  ): Promise<string> {
    if (!runtime.ledger) throw new Error("pay-dem watcher needs runtime.ledger");
    await this.buyer.openDemAgreement({
      jobId,
      sellerDid: runtime.sellerDid,
      listingRef: offer.ref,
      terms: this.termsFor("pay-dem", runtime),
      params: runtime.jobParams,
    });
    const txHash = await this.buyer.payDemBare(runtime.ledger, {
      jobId,
      sellerDid: runtime.sellerDid,
      amount: BigInt(runtime.onchainPrice.amount),
    });
    trail.push(`pay-dem bare settle memo="${demMemoFor(jobId)}" tx=${txHash} (watcher-triggered)`);
    return txHash;
  }
}

/** Convenience: a fresh mock DEM ledger for demos/tests. */
export function newMockLedger(): MockDemLedger {
  return new MockDemLedger();
}
