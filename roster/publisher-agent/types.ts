export const PUBLISHER_SERVICE_ID = "publisher-ad-rfq";
export const PUBLISHER_X402_SERVICE_ID = `${PUBLISHER_SERVICE_ID}-x402`;
export const PUBLISHER_PAYLOAD_FORMAT = "application/vnd.dacs.publisher-ad+json;version=1";

export type AdPlacement = "homepage-banner" | "sidebar-card";

export interface AdCreative {
  headline: string;
  body: string;
  cta: "Learn more" | "Try it" | "View details";
  destinationUrl: string;
}

export interface PublisherRfqRequest {
  creative: AdCreative;
  preferredPlacement: AdPlacement;
  preferredDurationDays: number;
  minimumDurationDays: number;
  budgetDem: string;
}

export interface PublisherQuote {
  quoteVersion: "1";
  jobId: string;
  domain: string;
  slotId: string;
  placement: AdPlacement;
  durationDays: number;
  priceDem: string;
  startsAt: number;
  endsAt: number;
  expiresAt: number;
  creativeHash: string;
  requestHash: string;
}

export interface DomainIdentityBinding {
  hostname: string;
  /** Current Demos GCR/DACS SDK representation; see DACS-Standard issue #275. */
  claim: string;
  proofUrl: string;
  gcrOwner: string;
}

export interface AdActivation {
  activationId: string;
  campaignId: string;
  domain: string;
  slotId: string;
  placement: AdPlacement;
  creative: AdCreative;
  creativeHash: string;
  startsAt: number;
  endsAt: number;
  publicPageUrl: string;
  evidenceUrl: string;
  activatedAt: number;
}

export interface PublisherDelivery {
  kind: "publisher-ad-activation";
  activationId: string;
  campaignId: string;
  domain: string;
  slotId: string;
  placement: AdPlacement;
  /** Canonical creative JSON encoded as base64url for ASCII-safe Demos anchoring. */
  creativeBase64: string;
  creativeHash: string;
  startsAt: number;
  endsAt: number;
  publicPageUrl: string;
  evidenceUrl: string;
  activatedAt: number;
  requestHash: string;
  quoteHash: string;
}
