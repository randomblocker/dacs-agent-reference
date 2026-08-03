import { emptyRequirement } from "../dacs/standard-profile.js";
import type { StandardListingSpec } from "../dacs/seller-adapter.js";
import { ORACLE_SERVICE_ID } from "../dacs/wire/oracle-desk.js";
import { DD_SERVICE_ID } from "../dacs/wire/dd-researcher.js";
import {
  SPONSORED_POST_PAYLOAD_FORMAT,
  SPONSORED_POST_SERVICE_ID,
  type XAccountBinding,
} from "../sponsored-post/types.js";
import { X402_RAIL_ID, usdcPrice, x402PublicEndpoint, x402RailRef } from "../dacs/x402-production.js";
import { domainIdentityMetadata } from "../publisher-agent/domain-identity.js";
import {
  PUBLISHER_PAYLOAD_FORMAT,
  PUBLISHER_SERVICE_ID,
  PUBLISHER_X402_SERVICE_ID,
  type DomainIdentityBinding,
} from "../publisher-agent/types.js";

export const DD_TENDER_SERVICE_ID = "dd-research-tender";
export const ORACLE_X402_SERVICE_ID = `${ORACLE_SERVICE_ID}-x402`;
export const DD_X402_SERVICE_ID = `${DD_SERVICE_ID}-x402`;
export const SPONSORED_POST_X402_SERVICE_ID = `${SPONSORED_POST_SERVICE_ID}-x402`;
const DEM_RAIL = { railId: "demos-native:DEM", railVersion: 1 } as const;
const DEM_PAYMENT = { kind: "pay-dem", parameters: { rail: DEM_RAIL.railId } } as const;
const x402Pipeline = (pipeline: StandardListingSpec["pipeline"]): StandardListingSpec["pipeline"] =>
  pipeline.map((phase) => phase.kind === "pay-dem"
    ? { kind: "pay-x402" as const, parameters: { rail: X402_RAIL_ID } }
    : phase);

/** RFQ inventory listing for a Demos-GCR-bound publisher domain. */
export function publisherRfqListing(input: {
  domainIdentity: DomainIdentityBinding;
  listingVersion?: number;
  notBefore?: number;
  priceCenterDem?: string;
  publicEndpoint?: string;
}): StandardListingSpec {
  const identityMetadata = domainIdentityMetadata(input.domainIdentity);
  return {
    serviceId: PUBLISHER_SERVICE_ID,
    listingVersion: input.listingVersion ?? 1,
    displayName: `Publisher Agent - ${input.domainIdentity.hostname}`,
    sellerIdentityMetadata: identityMetadata,
    publicEndpoint: input.publicEndpoint,
    title: `Negotiate disclosed advertising on ${input.domainIdentity.hostname}`,
    description: "RFQ-priced, policy-reviewed advertising inventory. The signed agreement binds the publisher domain, placement, exact creative hash, destination, campaign window and price before settlement; delivery publishes public activation evidence.",
    category: "marketing.publisher-inventory",
    tags: ["publisher", "advertising", "rfq", "domain-identity", "public-delivery"],
    deliverable: {
      kind: "attested-payload",
      payloadFormat: PUBLISHER_PAYLOAD_FORMAT,
      verificationMethod: "demos-gcr-domain-identity-public-evidence-url-and-seller-signature",
      expectedSizeBytes: 32_768,
    },
    buyerRequirement: emptyRequirement(),
    pipeline: [
      { kind: "vet-credentials" },
      { kind: "negotiate-rfq", parameters: { dimensions: ["placement", "durationDays", "price"], maxTurns: 4, turnTimeoutMs: 30_000 } },
      { kind: "commit-agreement" },
      DEM_PAYMENT,
      { kind: "deliver-attested-payload" },
    ],
    pricing: {
      kind: "negotiable",
      bandCenter: { amount: input.priceCenterDem ?? "7", currency: "DEM", unit: "per-campaign" },
      minPct: 50,
      maxPct: 500,
    },
    acceptedRails: [DEM_RAIL],
    terms: {
      deadlineSecAfterCommit: 180,
      cancellationPolicy: "pre-commit",
      transcriptDisclosurePolicy: "none",
    },
    validity: { notBefore: input.notBefore ?? 0 },
    requiredCapabilities: ["SR-1", "SR-2", "SR-4"],
  };
}

export function publisherRfqX402Listing(input: {
  domainIdentity: DomainIdentityBinding;
  payTo: string;
  resourceBase: string;
  identityMetadata: Record<string, unknown>;
  listingVersion?: number;
  notBefore?: number;
  priceCenterUsdc?: string;
  publicEndpoint?: string;
}): StandardListingSpec {
  const native = publisherRfqListing({
    domainIdentity: input.domainIdentity,
    ...(input.listingVersion === undefined ? {} : { listingVersion: input.listingVersion }),
    ...(input.notBefore === undefined ? {} : { notBefore: input.notBefore }),
    ...(input.publicEndpoint === undefined ? {} : { publicEndpoint: input.publicEndpoint }),
  });
  return {
    ...native,
    serviceId: PUBLISHER_X402_SERVICE_ID,
    publicEndpoint: x402PublicEndpoint(input.resourceBase, input.publicEndpoint),
    sellerIdentityMetadata: { ...native.sellerIdentityMetadata, ...input.identityMetadata },
    title: `${native.title} paid with x402`,
    description: `${native.description} The agreed amount settles as gasless Base Sepolia USDC through x402 exact-v2.`,
    tags: [...native.tags, "x402", "base-sepolia", "usdc"],
    pipeline: x402Pipeline(native.pipeline),
    pricing: {
      kind: "negotiable",
      bandCenter: usdcPrice(input.priceCenterUsdc ?? "0.07", "per-campaign"),
      minPct: 50,
      maxPct: 500,
    },
    acceptedRails: [x402RailRef({ payTo: input.payTo, resourceBase: input.resourceBase })],
  };
}

function sponsoredPostIdentityMetadata(binding: XAccountBinding): Record<string, unknown> {
  const handle = binding.handle.replace(/^@/, "");
  if (binding.platform !== "twitter") throw new Error("sponsored-post account binding must use the DACS twitter CCI platform id");
  if (!/^[A-Za-z0-9_]{1,15}$/.test(handle)) throw new Error("sponsored-post X handle is invalid");
  if (binding.claim !== `cci-web2:twitter:${handle}`) throw new Error("sponsored-post X claim does not match its handle");
  if (!/^[0-9]{1,19}$/.test(binding.userId) || !/^[0-9]{1,19}$/.test(binding.proofPostId)) {
    throw new Error("sponsored-post X account binding carries an invalid user or proof-post id");
  }
  if (binding.proofPostUrl !== `https://x.com/${handle}/status/${binding.proofPostId}`) {
    throw new Error("sponsored-post X proof URL is not canonical");
  }
  if (!/^[0-9a-f]{64}$/.test(binding.proofTextHash)) throw new Error("sponsored-post X proof text hash is invalid");
  return { linkedAccounts: [{ ...binding, handle }] };
}

/** Independent fixed-price seller for one policy-approved, disclosed X post. */
export function sponsoredPostLiveListing(input: {
  accountBinding: XAccountBinding;
  listingVersion?: number;
  notBefore?: number;
  priceDem?: string;
  publicEndpoint?: string;
}): StandardListingSpec {
  return {
    serviceId: SPONSORED_POST_SERVICE_ID,
    listingVersion: input.listingVersion ?? 1,
    displayName: "Sponsored Post Agent",
    sellerIdentityMetadata: sponsoredPostIdentityMetadata(input.accountBinding),
    publicEndpoint: input.publicEndpoint,
    title: "Publish one disclosed sponsored post",
    description: "Publish the exact policy-approved buyer text from the dedicated DACS demo X account, with X's paid-partnership disclosure and signed request-bound publication evidence.",
    category: "marketing.sponsored-post",
    tags: ["sponsored-post", "fixed-price", "live-cosign", "public-delivery"],
    deliverable: {
      kind: "attested-payload",
      payloadFormat: SPONSORED_POST_PAYLOAD_FORMAT,
      verificationMethod: "seller-signature-public-x-url-post-id-and-content-hash",
      expectedSizeBytes: 16_384,
    },
    buyerRequirement: emptyRequirement(),
    pipeline: [
      { kind: "vet-credentials" },
      { kind: "negotiate-fixed-price" },
      { kind: "commit-agreement" },
      DEM_PAYMENT,
      { kind: "deliver-attested-payload" },
    ],
    pricing: { kind: "fixed", price: { amount: input.priceDem ?? "1", currency: "DEM", unit: "per-post" } },
    acceptedRails: [DEM_RAIL],
    terms: {
      deadlineSecAfterCommit: 120,
      cancellationPolicy: "pre-commit",
      transcriptDisclosurePolicy: "none",
    },
    validity: { notBefore: input.notBefore ?? 0 },
    requiredCapabilities: ["SR-1", "SR-2", "SR-4"],
  };
}

/** Separately signed Base-Sepolia x402 listing for the Sponsored Post seller. */
export function sponsoredPostLiveX402Listing(input: {
  accountBinding: XAccountBinding;
  payTo: string;
  resourceBase: string;
  identityMetadata: Record<string, unknown>;
  listingVersion?: number;
  notBefore?: number;
  priceUsdc?: string;
  publicEndpoint?: string;
}): StandardListingSpec {
  const native = sponsoredPostLiveListing({
    accountBinding: input.accountBinding,
    ...(input.listingVersion === undefined ? {} : { listingVersion: input.listingVersion }),
    ...(input.notBefore === undefined ? {} : { notBefore: input.notBefore }),
    ...(input.publicEndpoint === undefined ? {} : { publicEndpoint: input.publicEndpoint }),
  });
  return {
    ...native,
    serviceId: SPONSORED_POST_X402_SERVICE_ID,
    publicEndpoint: x402PublicEndpoint(input.resourceBase, input.publicEndpoint),
    sellerIdentityMetadata: {
      ...native.sellerIdentityMetadata,
      ...input.identityMetadata,
    },
    title: "Publish one disclosed sponsored post paid with x402",
    description: `${native.description} Settlement is gasless USDC on Base Sepolia through x402 exact-v2.`,
    tags: [...native.tags, "x402", "base-sepolia", "usdc"],
    pipeline: x402Pipeline(native.pipeline),
    pricing: { kind: "fixed", price: usdcPrice(input.priceUsdc ?? "0.01", "per-post") },
    acceptedRails: [x402RailRef({ payTo: input.payTo, resourceBase: input.resourceBase })],
  };
}

/**
 * Oracle v2 is intentionally separate from the legacy v1 x402 listing: the
 * production demo uses native DEM and a bounded, expiring auto-accept signer.
 */
export function oracleAutoAcceptListing(input: {
  listingVersion: number;
  validUntil: number;
  notBefore?: number;
  priceDem?: string;
  publicEndpoint?: string;
}): StandardListingSpec {
  const notBefore = input.notBefore ?? Date.now();
  if (!Number.isSafeInteger(input.listingVersion) || input.listingVersion < 2) {
    throw new Error("Oracle auto-accept listingVersion must be >= 2");
  }
  if (!Number.isSafeInteger(input.validUntil) || input.validUntil <= notBefore) {
    throw new Error("Oracle auto-accept validity must end after notBefore");
  }
  return {
    serviceId: ORACLE_SERVICE_ID,
    listingVersion: input.listingVersion,
    displayName: "Oracle Desk",
    publicEndpoint: input.publicEndpoint,
    title: "Auto-accepted, source-attested public data",
    description: "A posted-price public data product with a live, rate-limited auto-accept instance signature and independently verifiable source attestation.",
    category: "data.public.attested",
    tags: ["oracle", "fixed-price", "auto-accept", "attested"],
    deliverable: {
      kind: "attested-payload",
      payloadFormat: "application/vnd.dacs.oracle-data+json;version=1",
      verificationMethod: "seller-signature-source-attestation-and-request-hash",
      expectedSizeBytes: 32_768,
    },
    buyerRequirement: emptyRequirement(),
    pipeline: [
      { kind: "vet-credentials" },
      { kind: "negotiate-fixed-price" },
      { kind: "commit-agreement" },
      DEM_PAYMENT,
      { kind: "deliver-attested-payload" },
    ],
    pricing: { kind: "fixed", price: { amount: input.priceDem ?? "1", currency: "DEM", unit: "per-datum" } },
    acceptedRails: [DEM_RAIL],
    terms: {
      acceptanceModel: "auto-accept",
      deadlineSecAfterCommit: 180,
      cancellationPolicy: "pre-commit",
      transcriptDisclosurePolicy: "none",
    },
    validity: { notBefore, notAfter: input.validUntil },
    autoAccept: { validUntil: input.validUntil },
    requiredCapabilities: ["SR-1", "SR-2", "SR-4"],
  };
}

export function ddLiveFixedListing(input: {
  listingVersion?: number;
  notBefore?: number;
  priceDem?: string;
  publicEndpoint?: string;
} = {}): StandardListingSpec {
  return {
    serviceId: DD_SERVICE_ID,
    listingVersion: input.listingVersion ?? 1,
    displayName: "Due-Diligence Researcher",
    publicEndpoint: input.publicEndpoint,
    title: "Live-co-signed, source-attested due-diligence report",
    description: "A posted-price npm package or crypto-token report; the seller signs the exact request-bound agreement live before payment.",
    category: "research.due-diligence",
    tags: ["due-diligence", "fixed-price", "live-cosign", "attested"],
    deliverable: {
      kind: "attested-payload",
      payloadFormat: "application/vnd.dacs.dd-research+json;version=1",
      verificationMethod: "seller-signature-cited-source-attestations-and-request-hash",
      expectedSizeBytes: 131_072,
    },
    buyerRequirement: emptyRequirement(),
    pipeline: [
      { kind: "vet-credentials" },
      { kind: "negotiate-fixed-price" },
      { kind: "commit-agreement" },
      DEM_PAYMENT,
      { kind: "deliver-attested-payload" },
    ],
    pricing: { kind: "fixed", price: { amount: input.priceDem ?? "2", currency: "DEM", unit: "per-report" } },
    acceptedRails: [DEM_RAIL],
    terms: {
      deadlineSecAfterCommit: 300,
      cancellationPolicy: "pre-commit",
      transcriptDisclosurePolicy: "none",
    },
    validity: { notBefore: input.notBefore ?? 0 },
    requiredCapabilities: ["SR-1", "SR-2", "SR-4"],
  };
}

/** Separately signed Base-Sepolia x402 listing; the native DEM listing remains available. */
export function oracleAutoAcceptX402Listing(input: {
  listingVersion: number;
  validUntil: number;
  payTo: string;
  resourceBase: string;
  notBefore?: number;
  priceUsdc?: string;
  publicEndpoint?: string;
  identityMetadata: Record<string, unknown>;
}): StandardListingSpec {
  const native = oracleAutoAcceptListing({
    listingVersion: input.listingVersion,
    validUntil: input.validUntil,
    ...(input.notBefore === undefined ? {} : { notBefore: input.notBefore }),
    ...(input.publicEndpoint === undefined ? {} : { publicEndpoint: input.publicEndpoint }),
  });
  return {
    ...native,
    serviceId: ORACLE_X402_SERVICE_ID,
    publicEndpoint: x402PublicEndpoint(input.resourceBase, input.publicEndpoint),
    sellerIdentityMetadata: input.identityMetadata,
    title: "Auto-accepted, source-attested public data paid with x402",
    description: `${native.description} Settlement is gasless USDC on Base Sepolia through x402 exact-v2.`,
    tags: [...native.tags, "x402", "base-sepolia", "usdc"],
    pipeline: x402Pipeline(native.pipeline),
    pricing: { kind: "fixed", price: usdcPrice(input.priceUsdc ?? "0.01", "per-datum") },
    acceptedRails: [x402RailRef({ payTo: input.payTo, resourceBase: input.resourceBase })],
  };
}

/** Separately signed Base-Sepolia x402 listing for the live-co-signed DD seller. */
export function ddLiveFixedX402Listing(input: {
  payTo: string;
  resourceBase: string;
  listingVersion?: number;
  notBefore?: number;
  priceUsdc?: string;
  publicEndpoint?: string;
  identityMetadata: Record<string, unknown>;
}): StandardListingSpec {
  const native = ddLiveFixedListing({
    ...(input.listingVersion === undefined ? {} : { listingVersion: input.listingVersion }),
    ...(input.notBefore === undefined ? {} : { notBefore: input.notBefore }),
    ...(input.publicEndpoint === undefined ? {} : { publicEndpoint: input.publicEndpoint }),
  });
  return {
    ...native,
    serviceId: DD_X402_SERVICE_ID,
    publicEndpoint: x402PublicEndpoint(input.resourceBase, input.publicEndpoint),
    sellerIdentityMetadata: input.identityMetadata,
    title: "Live-co-signed due-diligence report paid with x402",
    description: `${native.description} Settlement is gasless USDC on Base Sepolia through x402 exact-v2.`,
    tags: [...native.tags, "x402", "base-sepolia", "usdc"],
    pipeline: x402Pipeline(native.pipeline),
    pricing: { kind: "fixed", price: usdcPrice(input.priceUsdc ?? "0.02", "per-report") },
    acceptedRails: [x402RailRef({ payTo: input.payTo, resourceBase: input.resourceBase })],
  };
}

/**
 * Listing shape retained for conformance/UX work only. Execution is disabled:
 * The stable DACS release calls bidders `buyerBundles` and requires the
 * listing seller + winning bidder signatures; SDK 4.0.14 consequently builds
 * the winner as buyer. Adding pay-dem to a lowest-price reverse tender would
 * make the research provider pay the orchestrator. Never publish this shape as
 * an executable paid listing until DACS-3 v0.3's procurement phase is released
 * and implemented by the SDK (tracked in dacs-sdk #69).
 */
export function ddSealedTenderListing(input: {
  listingVersion?: number;
  notBefore?: number;
  reservePriceDem?: string;
  publicEndpoint?: string;
} = {}): StandardListingSpec {
  return {
    serviceId: DD_TENDER_SERVICE_ID,
    listingVersion: input.listingVersion ?? 1,
    displayName: "Competitive DD Tender",
    publicEndpoint: input.publicEndpoint,
    title: "Commit-reveal due-diligence tender",
    description: "A lowest-price sealed tender whose independently keyed bidders anchor their own commits and reveals before deterministic selection.",
    category: "research.due-diligence.tender",
    tags: ["due-diligence", "sealed-envelope", "commit-reveal", "attested"],
    deliverable: {
      kind: "attested-payload",
      payloadFormat: "application/vnd.dacs.dd-research+json;version=1",
      verificationMethod: "winning-bidder-signature-cited-source-attestations-and-request-hash",
      expectedSizeBytes: 131_072,
    },
    buyerRequirement: emptyRequirement(),
    pipeline: [
      { kind: "vet-credentials" },
      { kind: "negotiate-sealed-envelope", parameters: { revealWindow: 60, selectionRule: "lowest-price" } },
      { kind: "commit-agreement" },
      DEM_PAYMENT,
      { kind: "deliver-attested-payload" },
    ],
    pricing: {
      kind: "auction",
      reservePrice: { amount: input.reservePriceDem ?? "10", currency: "DEM", unit: "per-report" },
      selectionRule: "lowest-price",
    },
    acceptedRails: [DEM_RAIL],
    terms: {
      deadlineSecAfterCommit: 300,
      cancellationPolicy: "pre-commit",
      transcriptDisclosurePolicy: "none",
    },
    validity: { notBefore: input.notBefore ?? 0 },
    requiredCapabilities: ["SR-1", "SR-2", "SR-4"],
  };
}
