import { createHash } from "node:crypto";
import type { SponsoredPostRequest } from "./types.js";

export interface ModerationDecision {
  allowed: boolean;
  reason?: string;
  decisionRef?: string;
}

/**
 * A real deployment must inject a fail-closed moderation service. Structural
 * checks below reduce abuse surface but deliberately do not pretend to detect
 * every unsafe or unlawful statement.
 */
export interface SponsoredPostModerationPort {
  review(input: { text: string; textHash: string }): Promise<ModerationDecision>;
}

export class SponsoredPostPolicyError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "SponsoredPostPolicyError";
    this.code = code;
  }
}

export function sponsoredPostTextHash(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function countMatches(text: string, pattern: RegExp): number {
  return Array.from(text.matchAll(pattern)).length;
}

/**
 * Parse the exact request that will be signed into the agreement. The service
 * rejects inputs that would need silent rewriting; what the buyer approves is
 * therefore byte-for-byte what the X API receives.
 */
export function parseSponsoredPostRequest(params: Record<string, unknown>): SponsoredPostRequest {
  if (Object.keys(params).some((key) => key !== "text")) {
    throw new SponsoredPostPolicyError("unsupported_fields", "sponsored post request only accepts text");
  }
  if (typeof params.text !== "string") {
    throw new SponsoredPostPolicyError("invalid_text", "sponsored post text must be a string");
  }
  const text = params.text;
  if (text !== text.trim()) {
    throw new SponsoredPostPolicyError("non_canonical_text", "sponsored post text must not have leading or trailing whitespace");
  }
  if (text !== text.normalize("NFC")) {
    throw new SponsoredPostPolicyError("non_canonical_text", "sponsored post text must use NFC Unicode normalization");
  }
  const length = Array.from(text).length;
  if (length < 1 || length > 240) {
    throw new SponsoredPostPolicyError("invalid_length", "sponsored post text must contain 1 to 240 Unicode characters");
  }
  if (/[\u0000-\u001f\u007f-\u009f]/u.test(text)) {
    throw new SponsoredPostPolicyError("control_character", "sponsored post text must be a single line without control characters");
  }
  if (/[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u.test(text)) {
    throw new SponsoredPostPolicyError("bidi_control", "sponsored post text must not contain bidirectional control characters");
  }
  if (/(?:https?:\/\/|www\.)/iu.test(text)) {
    throw new SponsoredPostPolicyError("url_not_allowed", "links are not accepted by the first sponsored-post product");
  }
  if (/(^|[^\p{L}\p{N}_])@[A-Za-z0-9_]{1,15}\b/u.test(text)) {
    throw new SponsoredPostPolicyError("mention_not_allowed", "mentions are not accepted by the first sponsored-post product");
  }
  if (countMatches(text, /(^|\s)#[\p{L}\p{N}_]+/gu) > 1) {
    throw new SponsoredPostPolicyError("too_many_hashtags", "at most one hashtag is accepted");
  }
  if (countMatches(text, /(^|\s)\$[A-Za-z]{1,8}\b/g) > 1) {
    throw new SponsoredPostPolicyError("too_many_cashtags", "at most one cashtag is accepted");
  }
  if (/\b(?:0x)?[0-9a-f]{64}\b/iu.test(text)) {
    throw new SponsoredPostPolicyError("secret_like_text", "text resembling a private key is not accepted");
  }
  return { text };
}

export async function approveSponsoredPost(
  request: SponsoredPostRequest,
  moderation: SponsoredPostModerationPort,
): Promise<{ textHash: string; decisionRef?: string }> {
  const textHash = sponsoredPostTextHash(request.text);
  const decision = await moderation.review({ text: request.text, textHash });
  if (!decision.allowed) {
    throw new SponsoredPostPolicyError("moderation_rejected", decision.reason ?? "sponsored post was rejected by moderation");
  }
  return {
    textHash,
    ...(decision.decisionRef === undefined ? {} : { decisionRef: decision.decisionRef }),
  };
}
