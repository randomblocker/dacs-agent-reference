/**
 * SellerAdapter — the shared, service-agnostic seller half of the DACS
 * lifecycle for the roster agents.
 *
 * It generalizes `src/agents/seller.ts` (ReviewBot): where the reference agent
 * hard-wired "review a GitHub PR", this adapter takes an injected **work
 * callback** and turns any service into a DACS seller:
 *
 *   - `publishListing(spec)` — build + sign + anchor a DACS-1 Listing
 *     (capability id, supported rails / negotiation / delivery).
 *   - `deliver(jobId, params)` — run the work callback, then sign + anchor a
 *     per-service DACS-X DeliveryAttestation (SIG-4 extension separator) over
 *     the delivered result. The GitHub specifics of the reference agent become
 *     the injected callback; the verifier's "observe delivered state" check
 *     becomes a hook it can carry in `meta`.
 *   - `fulfil(jobId, buyerOwner)` — anchor the seller's copy of the buyer's
 *     AttestationBundle over the SAME content-addressed refs (hand-rolled
 *     §10.4.3 two-sided form). Service-agnostic already; lifted verbatim.
 *
 * The mock↔live seam is the same one the reference uses: the adapter is written
 * against `SubstratePort` (MemorySubstrate in mock, DemosAdapter live) and
 * `Signer` — it cannot tell which world it's in.
 */
import {
  ARTIFACT_SEPARATORS,
  buildSignedArtifact,
  contentHash,
  dacsXSeparator,
  sha256Hex,
  signedBytes,
  stripSignature,
} from "@kynesyslabs/dacs";
import type {
  AttestationBundle,
  DomainSeparator,
  Listing,
  Signer,
} from "@kynesyslabs/dacs";
// FINDINGS F2: sessionAnchorName isn't on the public barrel — deep-import it so
// the seller can locate where the buyer anchored the bundle.
import { sessionAnchorName } from "../../sdk/dist/agent/runSessionCore.js";
import type { SubstratePort } from "../../src/ports.js";
import {
  createIdentityBundle,
  createAutoAcceptCommitment,
  signListing,
  requestScopeHash,
  standardAnchorName,
  standardHash,
  verifyListing,
  type BundleRequirement,
  type AutoAcceptCommitment,
  type DeliverableSpec,
  type Listing as StandardListing,
  type PaymentRailRef,
  type PhaseType,
  type PricingSpec,
} from "./standard-profile.js";
import { resolveFromDid, verify } from "../../src/identity.js";

/** The slice of an identity the seller needs (mock and live identities both fit). */
export interface SellerIdentity {
  did: string;
  sign: Signer;
}

/** The DACS-1 listing surface a service publishes. */
export interface ListingSpec {
  serviceId: string;
  name: string;
  description: string;
  claimRequirements?: Listing["claimRequirements"];
  supportedNegotiation?: string[];
  /** Default: ["pay-x402"] (the rail this build wires end-to-end). */
  supportedPaymentRails?: string[];
  supportedDelivery?: string[];
}

/** Full normative DACS-1 listing input used by public Standard flows. */
export interface StandardListingSpec {
  serviceId: string;
  listingVersion: number;
  displayName: string;
  /** Claims bound into and signed by the seller's DACS IdentityBundle. */
  sellerIdentityMetadata?: Record<string, unknown>;
  publicEndpoint?: string;
  title: string;
  description: string;
  category: string;
  tags: string[];
  deliverable: DeliverableSpec;
  buyerRequirement: BundleRequirement;
  pipeline: Array<{ kind: PhaseType; parameters?: Record<string, unknown> }>;
  pricing: PricingSpec;
  acceptedRails?: PaymentRailRef[];
  terms: StandardListing["terms"];
  validity: StandardListing["validity"];
  requiredCapabilities?: StandardListing["requiredCapabilities"];
  /** Required when terms.acceptanceModel is auto-accept. */
  autoAccept?: { validUntil: number };
}

export interface PublishedStandardListing {
  ref: string;
  listing: StandardListing;
  published: boolean;
  autoAcceptCommitment?: AutoAcceptCommitment;
  autoAcceptCommitmentRef?: string;
  autoAcceptCommitmentPublished?: boolean;
}

type LegacyListingSurface = ListingSpec & {
  fees?: { kind: "fixed"; price: number } | { kind: "per-unit"; unitPrice: number; unit: string; minTotal: number };
};

const ASSET_DECIMALS: Record<string, number> = { DEM: 9, USDC: 6, USDT: 6, DAI: 18, OS: 0 };

function baseAmountToDecimal(amount: string, asset: string): string {
  const decimals = ASSET_DECIMALS[asset.toUpperCase()] ?? 0;
  if (!/^\d+$/.test(amount)) throw new Error(`listing price ${amount} is not base-unit integer text`);
  if (decimals === 0) return BigInt(amount).toString();
  const padded = amount.padStart(decimals + 1, "0");
  const whole = padded.slice(0, -decimals).replace(/^0+(?=\d)/, "");
  const fraction = padded.slice(-decimals).replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : whole;
}

/**
 * Lift an existing roster listing onto the complete DACS-1 schema. This keeps
 * old demo surfaces readable while current indexer publication uses immutable,
 * versioned Standard listings. Custom `deliver-*` labels become the normative
 * `deliver-attested-payload` phase; the service-specific format remains in the
 * deliverable MIME type.
 */
export function standardListingSpecFromLegacy(
  legacy: LegacyListingSurface,
  price: { amount: string; asset: string },
  input: { listingVersion?: number; displayName?: string; category?: string; tags?: string[] } = {},
): StandardListingSpec {
  const payment = legacy.supportedPaymentRails?.[0] ?? "pay-dem";
  const rail: PaymentRailRef = payment === "pay-dem"
    ? { railId: "demos-native:DEM", railVersion: 1 }
    : payment === "pay-x402"
      ? { railId: "x402:http", railVersion: 1 }
      : { railId: payment.replace(/^pay-/, ""), railVersion: 1 };
  const fees = legacy.fees;
  const displayAmount = fees?.kind === "per-unit"
    ? String(fees.unitPrice)
    : fees?.kind === "fixed"
      ? String(fees.price)
      : baseAmountToDecimal(price.amount, price.asset);
  const unit = fees?.kind === "per-unit" ? `per-${fees.unit}` : "per-job";
  return {
    serviceId: legacy.serviceId,
    listingVersion: input.listingVersion ?? 1,
    displayName: input.displayName ?? legacy.name,
    title: legacy.name,
    description: legacy.description,
    category: input.category ?? `agent.${legacy.serviceId}`,
    tags: input.tags ?? [legacy.serviceId, "attested"],
    deliverable: {
      kind: "attested-payload",
      payloadFormat: `application/vnd.dacs.${legacy.serviceId}+json;version=1`,
      verificationMethod: "seller-signature-and-content-hash",
    },
    buyerRequirement: { requirementVersion: "1", required: [], preferredPresentation: "per-claim" },
    pipeline: [
      { kind: "vet-credentials" },
      { kind: "negotiate-fixed-price" },
      { kind: "commit-agreement" },
      { kind: payment as PhaseType, parameters: { rail: rail.railId } },
      { kind: "deliver-attested-payload" },
    ],
    pricing: { kind: "fixed", price: { amount: displayAmount, currency: price.asset, unit } },
    acceptedRails: [rail],
    terms: { cancellationPolicy: "pre-commit", transcriptDisclosurePolicy: "none" },
    validity: { notBefore: 0 },
    requiredCapabilities: ["SR-1", "SR-2", "SR-4"],
  };
}

/** What a service's work callback returns for one paid call. */
export interface WorkResult {
  /** The value sold to the buyer (echoed in the 200 body). */
  result: unknown;
  /** Optional pointer to a fuller deliverable (URL, anchor ref, upstream digest). */
  deliverableRef?: string;
  /**
   * Free-form, service-specific metadata carried INSIDE the signed delivery
   * attestation (e.g. the oracle's own attestation digest + value). Because it
   * is part of the signed scope, tampering with it fails verification — and a
   * per-service `observeDelivered` hook can re-check it offline.
   */
  meta?: Record<string, unknown>;
}

/** Do the paid work for one job. The load-bearing business logic seam. */
export type WorkCallback = (
  jobId: string,
  params: Record<string, unknown>,
) => Promise<WorkResult>;

/**
 * The DACS-X delivery attestation — the artifact kind the AttestationBundle
 * can't carry yet (FINDINGS F5). Generic over serviceId (vs the reference
 * agent's GitHub-specific shape).
 */
export interface DeliveryAttestation {
  kind: "dacs-x-delivery-attestation";
  serviceId: string;
  jobId: string;
  /** sha256 hex over the canonical delivered result (the content commitment). */
  resultHash: string;
  /** Binds this delivery to the concrete, agreement-committed work request. */
  requestHash?: string;
  deliverableRef?: string;
  meta?: Record<string, unknown>;
  deliveredAt: string;
}

/** Per-service DACS-X separator (SIG-4): distinct signing domain per serviceId. */
export function deliverySeparator(serviceId: string): DomainSeparator {
  return dacsXSeparator(`${serviceId}-delivery`) as DomainSeparator;
}

export interface DeliverResult {
  attestationRef: string;
  attestation: DeliveryAttestation;
  result: unknown;
  anchorReceipt?: import("../../src/ports.js").AnchorReceipt;
  anchoredAttestation?: Record<string, unknown>;
}

export interface PreparedDeliverResult extends DeliverResult {
  /** Deterministic logical slot and exact signed value, ready for an ordered batch. */
  anchorName: string;
  anchoredAttestation: Record<string, unknown>;
}

export class SellerAdapter {
  constructor(
    private readonly id: SellerIdentity,
    private readonly sub: SubstratePort,
    private readonly serviceId: string,
    private readonly work: WorkCallback,
  ) {}

  get did(): string {
    return this.id.did;
  }

  /** Standard-profile party used by the full artifact-chain adapter. */
  get standardParty() {
    return { primaryClaim: this.id.did, sign: this.id.sign };
  }

  /** The owner-scoped substrate view backing this seller. */
  get substrate(): SubstratePort {
    return this.sub;
  }

  /** Publish a signed, anchored fixed-price listing (DACS-1). Returns its ref. */
  async publishListing(spec: ListingSpec): Promise<string> {
    const listing: Listing = {
      agentId: this.id.did,
      serviceId: spec.serviceId,
      name: spec.name,
      description: spec.description,
      claimRequirements: spec.claimRequirements ?? [],
      supportedNegotiation: spec.supportedNegotiation ?? ["negotiate-fixed-price"],
      supportedPaymentRails: spec.supportedPaymentRails ?? ["pay-x402"],
      supportedDelivery: spec.supportedDelivery ?? [`deliver-${spec.serviceId}`],
    };
    const signed = await buildSignedArtifact(listing, ARTIFACT_SEPARATORS.Listing, this.id.sign);
    return this.sub.anchor(`dacs1:listing:${this.id.did}:${spec.serviceId}`, signed);
  }

  /**
   * Publish one immutable, versioned, fully-shaped DACS-1 listing. A populated
   * version slot is reused only when it already contains the exact same signed
   * scope; conflicting content fails closed instead of updating history.
   */
  async publishStandardListing(spec: StandardListingSpec): Promise<PublishedStandardListing> {
    const identity = await createIdentityBundle(
      { primaryClaim: this.id.did, sign: this.id.sign },
      { metadata: { displayName: spec.displayName, ...spec.sellerIdentityMetadata } },
    );
    const listing = await signListing({
      dacsVersion: "1",
      listingVersion: spec.listingVersion,
      listingId: spec.serviceId,
      requiredCapabilities: spec.requiredCapabilities,
      seller: { identity, displayName: spec.displayName, publicEndpoint: spec.publicEndpoint },
      offering: {
        title: spec.title,
        description: spec.description,
        category: spec.category,
        tags: spec.tags,
        deliverable: spec.deliverable,
      },
      buyerRequirement: spec.buyerRequirement,
      pipeline: spec.pipeline,
      pricing: spec.pricing,
      acceptedRails: spec.acceptedRails,
      terms: spec.terms,
      validity: spec.validity,
    }, { primaryClaim: this.id.did, sign: this.id.sign });

    const name = standardAnchorName("listing", [this.id.did, spec.serviceId, String(spec.listingVersion)]);
    const ref = await this.sub.anchorAddress(name);
    const existing = await this.sub.read(ref);
    if (existing) {
      const verdict = await verifyListing(existing as unknown as StandardListing, {
        resolvePublicKey: async (claim) => resolveFromDid(claim),
        verify,
      });
      if (!verdict.ok) throw new Error(`listing version slot contains an invalid artifact: ${verdict.reason}`);
      const actual = existing as unknown as StandardListing;
      const sameStaticSpec = actual.listingId === listing.listingId
        && actual.listingVersion === listing.listingVersion
        && actual.seller.identity.presentedBy === this.id.did
        && standardHash({ requiredCapabilities: actual.requiredCapabilities ?? [] }, []) === standardHash({ requiredCapabilities: listing.requiredCapabilities ?? [] }, [])
        && actual.seller.displayName === listing.seller.displayName
        && actual.seller.publicEndpoint === listing.seller.publicEndpoint
        && standardHash(actual.offering, []) === standardHash(listing.offering, [])
        && standardHash(actual.buyerRequirement, []) === standardHash(listing.buyerRequirement, [])
        && standardHash({ pipeline: actual.pipeline }, []) === standardHash({ pipeline: listing.pipeline }, [])
        && standardHash(actual.pricing, []) === standardHash(listing.pricing, [])
        && standardHash({ rails: actual.acceptedRails ?? [] }, []) === standardHash({ rails: listing.acceptedRails ?? [] }, [])
        && standardHash(actual.terms, []) === standardHash(listing.terms, [])
        && standardHash(actual.validity, []) === standardHash(listing.validity, []);
      if (!sameStaticSpec) throw new Error(`listing ${spec.serviceId} v${spec.listingVersion} is immutable and already contains different content`);
      return this.withAutoAccept(spec, ref, actual, false);
    }

    const verdict = await verifyListing(listing, {
      resolvePublicKey: async (claim) => resolveFromDid(claim),
      verify,
    });
    if (!verdict.ok) throw new Error(`refusing to publish invalid Standard listing: ${verdict.reason}`);
    const anchoredRef = await this.sub.anchor(name, listing);
    return this.withAutoAccept(spec, anchoredRef, listing, true);
  }

  private async withAutoAccept(
    spec: StandardListingSpec,
    ref: string,
    listing: StandardListing,
    published: boolean,
  ): Promise<PublishedStandardListing> {
    if (listing.terms.acceptanceModel !== "auto-accept") {
      if (spec.autoAccept) throw new Error("autoAccept configuration supplied for a non-auto-accept listing");
      return { ref, listing, published };
    }
    if (!spec.autoAccept) throw new Error("auto-accept listing omitted its commitment validity");
    const commitment = await createAutoAcceptCommitment(
      listing,
      this.standardParty,
      spec.autoAccept.validUntil,
    );
    const commitmentName = standardAnchorName("auto-accept", [this.id.did, spec.serviceId, String(spec.listingVersion)]);
    const commitmentRef = await this.sub.anchorAddress(commitmentName);
    const existing = await this.sub.read(commitmentRef);
    if (existing) {
      if (standardHash(existing) !== standardHash(commitment)) {
        throw new Error(`auto-accept commitment for ${spec.serviceId} v${spec.listingVersion} is immutable and already contains different content`);
      }
      return {
        ref,
        listing,
        published,
        autoAcceptCommitment: existing as unknown as AutoAcceptCommitment,
        autoAcceptCommitmentRef: commitmentRef,
        autoAcceptCommitmentPublished: false,
      };
    }
    return {
      ref,
      listing,
      published,
      autoAcceptCommitment: commitment,
      autoAcceptCommitmentRef: await this.sub.anchor(commitmentName, commitment),
      autoAcceptCommitmentPublished: true,
    };
  }

  /**
   * Do the paid work via the injected callback, then sign + anchor a per-service
   * DACS-X delivery attestation over the result. Returns the anchor ref and the
   * delivered value. Any throw from the work callback propagates UNANCHORED —
   * the paywall relies on that to cancel the payment (work-before-settle).
   */
  async prepareDelivery(
    jobId: string,
    workParams: Record<string, unknown>,
    /**
     * Exact request scope committed by the signed agreement. This normally is
     * the same object as `workParams`; an adapter may supply a normalized work
     * shape while preserving an already-signed compatibility encoding here.
     */
    boundRequestScope: Record<string, unknown> = workParams,
  ): Promise<PreparedDeliverResult> {
    const work = await this.work(jobId, workParams);

    const attestation: DeliveryAttestation = {
      kind: "dacs-x-delivery-attestation",
      serviceId: this.serviceId,
      jobId,
      resultHash: sha256Hex(contentHash(asHashable(work.result))),
      requestHash: requestScopeHash(boundRequestScope),
      deliverableRef: work.deliverableRef,
      meta: work.meta,
      deliveredAt: new Date().toISOString(),
    };
    const signed = await buildSignedArtifact(
      attestation,
      deliverySeparator(this.serviceId),
      this.id.sign,
    );
    const anchorName = `dacsx:delivery:${jobId}`;
    const attestationRef = await this.sub.anchorAddress(anchorName);
    return {
      anchorName,
      attestationRef,
      attestation,
      result: work.result,
      anchoredAttestation: signed,
    };
  }

  async deliver(jobId: string, params: Record<string, unknown>): Promise<DeliverResult> {
    const prepared = await this.prepareDelivery(jobId, params);
    const receipt = this.sub.anchorWithReceipt
      ? await this.sub.anchorWithReceipt(prepared.anchorName, prepared.anchoredAttestation)
      : undefined;
    const attestationRef = receipt?.address ?? await this.sub.anchor(prepared.anchorName, prepared.anchoredAttestation);
    if (attestationRef !== prepared.attestationRef) throw new Error("delivery anchor resolved to an unexpected address");
    return {
      ...prepared,
      attestationRef,
      ...(receipt ? { anchorReceipt: receipt } : {}),
    };
  }

  /**
   * Seller-side attestation of the completed deal: read the buyer's anchored
   * bundle, anchor a seller-signed copy over the SAME refs (hand-rolled
   * §10.4.3 two-sided form). Service-agnostic. Returns its ref.
   */
  async fulfil(jobId: string, buyerOwner: string): Promise<string> {
    const buyerBundleRaw = await this.sub.read(
      await this.sub.anchorAddressFor(buyerOwner, sessionAnchorName.bundle(jobId)),
    );
    if (!buyerBundleRaw) throw new Error(`seller.fulfil: no buyer bundle for job ${jobId}`);
    const buyer = stripSignature(buyerBundleRaw) as unknown as AttestationBundle;

    const body: AttestationBundle = {
      bundleVersion: buyer.bundleVersion,
      jobId: buyer.jobId,
      outcome: buyer.outcome,
      anchoredByRole: "seller",
      listingRef: buyer.listingRef,
      agreementRef: buyer.agreementRef,
      parties: [
        {
          role: "seller",
          bundleHash: sha256Hex(this.id.did),
          primaryClaim: this.id.did,
        },
      ],
      phaseSummary: buyer.phaseSummary,
      vetRecords: buyer.vetRecords,
      settlementEvidence: buyer.settlementEvidence,
      recipeRegistryVersion: buyer.recipeRegistryVersion,
      railRegistryVersion: buyer.railRegistryVersion,
      finalisedAt: buyer.finalisedAt,
    };
    const scope = { ...body };
    delete scope.anchoredByRole;
    const sig = await this.id.sign(
      signedBytes(ARTIFACT_SEPARATORS.AttestationBundle, contentHash(scope)),
    );

    const signedBundle = {
      ...body,
      signatures: [
        { party: this.id.did, algorithm: "ed25519", value: Buffer.from(sig).toString("base64url") },
      ],
    };
    return this.sub.anchor(`dacs5:bundle:seller:${jobId}`, signedBundle);
  }
}

/** contentHash wants a record; wrap primitives/arrays so any result hashes. */
function asHashable(value: unknown): Record<string, unknown> {
  return { v: value };
}
