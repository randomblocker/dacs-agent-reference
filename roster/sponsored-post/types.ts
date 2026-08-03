export const SPONSORED_POST_SERVICE_ID = "sponsored-post";
export const SPONSORED_POST_PAYLOAD_FORMAT = "application/vnd.dacs.sponsored-post+json;version=1";

export interface SponsoredPostRequest {
  text: string;
}

export interface PublishedSponsoredPost {
  postId: string;
  text: string;
  handle: string;
  url: string;
  publishedAt: number;
  /** X's native paid-promotion label was requested on publication. */
  paidPartnership: true;
  /** Buyer-supplied text is not represented as AI-generated media. */
  madeWithAi: false;
}

export interface SponsoredPostDeliverable {
  kind: "sponsored-post-publication";
  postId: string;
  /** Exact UTF-8 buyer text, base64url encoded to keep Demos anchor bytes ASCII-safe. */
  textBase64: string;
  handle: string;
  url: string;
  publishedAt: number;
  paidPartnership: true;
  madeWithAi: false;
  textHash: string;
  requestHash: string;
}

export interface XAccountBinding {
  claim: string;
  platform: "twitter";
  handle: string;
  userId: string;
  proofPostId: string;
  proofPostUrl: string;
  proofTextHash: string;
}
