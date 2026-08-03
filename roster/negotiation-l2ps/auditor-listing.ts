/** Publish the persistent Auditor's versioned, immutable DACS-1 listing. */
import type { SubstratePort } from "../../src/ports.js";
import { SellerAdapter, type SellerIdentity } from "../dacs/seller-adapter.js";
import type { Listing } from "../dacs/standard-profile.js";
import {
  AUDIT_NEGOTIATOR_SERVICE_ID,
  auditNegotiatorStandardListingSpec,
} from "../dacs/wire/audit-negotiator.js";
import { securityResearcherProfileFromListing } from "../dacs/security-researcher-vet.js";

/** Cheap shape/spec predicate; cryptographic validation happens on discovery. */
export function isCurrentAuditorListing(
  value: Record<string, unknown> | null,
  id: SellerIdentity,
  researcherGithub: string,
): value is Record<string, unknown> & Listing {
  if (!value) return false;
  const listing = value as unknown as Partial<Listing>;
  const spec = auditNegotiatorStandardListingSpec({ researcherGithub, operatorClaim: id.did });
  const researcher = securityResearcherProfileFromListing(value as unknown as Listing);
  return listing.dacsVersion === "1"
    && listing.listingVersion === spec.listingVersion
    && listing.listingId === spec.serviceId
    && listing.seller?.identity.presentedBy === id.did
    && researcher?.github === researcherGithub.toLowerCase().replace(/^@/, "")
    && researcher.operatorClaim === id.did
    && listing.offering?.title === spec.title
    && listing.offering?.category === spec.category
    && listing.pipeline?.some((step) => step.kind === "negotiate-rfq") === true
    && listing.pipeline?.some((step) => step.kind === "pay-dem") === true
    && listing.pipeline?.some((step) => step.kind === "deliver-attested-payload") === true;
}

/** Ensure the current immutable version exists; a conflict fails rather than mutating history. */
export async function ensureAuditorListing(
  id: SellerIdentity,
  sub: SubstratePort,
  researcherGithub: string,
): Promise<{ ref: string; published: boolean }> {
  const seller = new SellerAdapter(
    id,
    sub,
    AUDIT_NEGOTIATOR_SERVICE_ID,
    async () => ({ result: null }),
  );
  const result = await seller.publishStandardListing(auditNegotiatorStandardListingSpec({
    researcherGithub,
    operatorClaim: id.did,
  }));
  return { ref: result.ref, published: result.published };
}
