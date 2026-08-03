/**
 * In-memory marketplace + seller-side negotiation counterparty.
 *
 * Implements both ports the butler needs so the demo runs with zero
 * credentials. The stock catalog is six deliberately varied listings that
 * exercise every branch of the butler: capability filtering, budget
 * exclusion, rail preference, a winnable negotiation, and a walk-away.
 *
 * The seller's walk-away floors are PRIVATE state here — they never appear
 * on the public listing, so the butler can only discover them by
 * negotiating. Seller concession policy (deterministic): at round r its
 * willingness drops from ask toward its floor by `concessionStep` of the
 * ask-floor gap per round; it accepts any offer at/above that willingness,
 * otherwise counters at it.
 */
import type {
  Listing,
  MarketplacePort,
  NegotiationPort,
  NegotiationResponse,
} from "./types.js";
import { askPriceOf, roundCents } from "./butler.js";

export interface SellerBook {
  /** Private minimum acceptable price per negotiable listing id. */
  floors: Record<string, number>;
  /** Fraction of the ask→floor gap conceded per round (default 0.3). */
  concessionStep?: number;
}

export class MarketplaceStub implements MarketplacePort, NegotiationPort {
  private readonly step: number;

  constructor(
    private readonly listings: Listing[] = STOCK_CATALOG,
    private readonly book: SellerBook = STOCK_SELLER_BOOK,
  ) {
    this.step = book.concessionStep ?? 0.3;
  }

  /** Naive marketplace search: returns anything sharing ≥1 requested tag —
   *  deliberately over-returns so the butler's own filtering has work to do. */
  async search(query: { capabilities: string[] }): Promise<Listing[]> {
    const wanted = new Set(query.capabilities.map((c) => c.toLowerCase()));
    const hits = this.listings.filter((l) =>
      l.capabilities.some((c) => wanted.has(c.toLowerCase())),
    );
    // Over-return: include everything else too (a sloppy marketplace), hits first.
    const misses = this.listings.filter((l) => !hits.includes(l));
    return [...hits, ...misses];
  }

  /** Deterministic seller concession policy. */
  async respond(listingId: string, offer: number, round: number): Promise<NegotiationResponse> {
    const listing = this.listings.find((l) => l.id === listingId);
    if (!listing || !listing.negotiable) return { type: "reject" };

    const ask = askPriceOf(listing.fees, 1);
    const floor = this.book.floors[listingId] ?? ask; // no floor on file = holds at ask
    const willingness = roundCents(Math.max(floor, ask - (ask - floor) * this.step * round));

    if (offer >= willingness) return { type: "accept", price: roundCents(offer) };
    return { type: "counter", price: willingness };
  }
}

// ---------------------------------------------------------------------------
// Stock catalog — six varied fake providers
// ---------------------------------------------------------------------------

export const STOCK_CATALOG: Listing[] = [
  {
    id: "lst-cartographer",
    provider: "Repo Cartographer",
    description: "Architecture summaries of TypeScript/JS repositories with module maps.",
    capabilities: ["code-analysis", "summarization", "documentation"],
    fees: { kind: "fixed", price: 4.8 },
    rails: ["pay-x402", "pay-dem"],
    negotiable: true,
    quality: { rating: 4.7, completedJobs: 230, disputeRate: 0.01 },
    acceptance: {
      checks: [
        { kind: "content-includes", needle: "## Architecture" },
        { kind: "min-length", minChars: 400 },
      ],
    },
  },
  {
    id: "lst-digest-bot",
    provider: "Digest Bot",
    description: "Fast bullet-point digests of any codebase or document set.",
    capabilities: ["summarization", "code-analysis"],
    fees: { kind: "fixed", price: 3.5 },
    rails: ["pay-evm-erc8183"],
    negotiable: false,
    quality: { rating: 3.9, completedJobs: 80, disputeRate: 0.05 },
    // No acceptance policy: subjective quality -> needs-evaluator.
  },
  {
    id: "lst-atlas",
    provider: "Atlas Consulting",
    description: "White-glove architecture review by senior consultants.",
    capabilities: ["code-analysis", "summarization", "architecture-review"],
    fees: { kind: "fixed", price: 12 },
    rails: ["pay-dem", "pay-evm-erc8183"],
    negotiable: false,
    quality: { rating: 4.8, completedJobs: 45, disputeRate: 0.0 },
    acceptance: { checks: [{ kind: "min-length", minChars: 2000 }] },
  },
  {
    id: "lst-pixel-forge",
    provider: "Pixel Forge",
    description: "Diagram and banner image generation for docs sites.",
    capabilities: ["image-generation", "summarization"],
    fees: { kind: "fixed", price: 2 },
    rails: ["pay-x402"],
    negotiable: false,
    quality: { rating: 4.1, completedJobs: 300, disputeRate: 0.02 },
  },
  {
    id: "lst-premium-insights",
    provider: "Premium Insights",
    description: "Deep architecture forensics with dependency-risk scoring.",
    capabilities: ["code-analysis", "summarization", "risk-scoring"],
    fees: { kind: "fixed", price: 9 },
    rails: ["pay-dem"],
    negotiable: true, // will haggle — but its private floor is above small budgets
    quality: { rating: 5.0, completedJobs: 120, disputeRate: 0.0 },
    acceptance: { checks: [{ kind: "min-length", minChars: 1500 }] },
  },
  {
    id: "lst-metered",
    provider: "Metered Summaries",
    description: "Pay-per-module summarization, billed per module analyzed.",
    capabilities: ["summarization", "code-analysis"],
    fees: { kind: "per-unit", unitPrice: 0.9, unit: "module", minTotal: 2.7 },
    rails: ["pay-x402"],
    negotiable: false,
    quality: { rating: 4.2, completedJobs: 40, disputeRate: 0.02 },
    acceptance: { checks: [{ kind: "min-length", minChars: 200 }] },
  },
];

export const STOCK_SELLER_BOOK: SellerBook = {
  floors: {
    "lst-cartographer": 3.2, // meets a $5 budget after a couple of rounds
    "lst-premium-insights": 7.5, // never meets a $5 budget -> butler walks
  },
  concessionStep: 0.3,
};
