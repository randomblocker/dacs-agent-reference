import { createHash } from "node:crypto";
import type { AdCreative, AdPlacement, PublisherRfqRequest } from "./types.js";

export class PublisherPolicyError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "PublisherPolicyError";
  }
}

export interface PublisherModerationPort {
  review(input: { creative: AdCreative; creativeHash: string }): Promise<{ allowed: boolean; reason?: string; decisionRef?: string }>;
}

function exactText(value: unknown, name: string, max: number): string {
  if (typeof value !== "string" || value.length < 1 || Array.from(value).length > max) {
    throw new PublisherPolicyError("invalid_creative", `${name} must contain 1-${max} characters`);
  }
  if (value !== value.trim() || value !== value.normalize("NFC")) {
    throw new PublisherPolicyError("non_canonical_creative", `${name} must be trimmed NFC text`);
  }
  if (/[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069<>]/u.test(value)) {
    throw new PublisherPolicyError("unsafe_creative", `${name} contains controls, bidi overrides, or HTML delimiters`);
  }
  return value;
}

function destination(value: unknown): string {
  if (typeof value !== "string" || value.length > 500) throw new PublisherPolicyError("invalid_destination", "destinationUrl is invalid");
  let url: URL;
  try { url = new URL(value); } catch { throw new PublisherPolicyError("invalid_destination", "destinationUrl must be an absolute URL"); }
  if (url.protocol !== "https:" || url.username || url.password || url.port) {
    throw new PublisherPolicyError("invalid_destination", "destinationUrl must use HTTPS without credentials or a custom port");
  }
  const host = url.hostname.toLowerCase();
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")
    || /^(?:127\.|10\.|192\.168\.|169\.254\.)/.test(host)
    || /^172\.(?:1[6-9]|2\d|3[01])\./.test(host)
    || host === "::1") {
    throw new PublisherPolicyError("private_destination", "destinationUrl must not target a private or local address");
  }
  url.hash = "";
  if (url.toString() !== value) throw new PublisherPolicyError("non_canonical_destination", "destinationUrl must be canonical and contain no fragment");
  return value;
}

function parseDem(value: unknown): string {
  if (typeof value !== "string" || !/^(?:0|[1-9]\d*)(?:\.\d{1,2})?$/.test(value)) {
    throw new PublisherPolicyError("invalid_budget", "budgetDem must be canonical decimal text with at most two fractional digits");
  }
  const cents = demCents(value);
  if (cents < 100 || cents > 100_000) throw new PublisherPolicyError("invalid_budget", "budgetDem must be between 1 and 1000 DEM");
  return centsDem(cents);
}

export function demCents(value: string): number {
  const [whole, fraction = ""] = value.split(".");
  return Number(whole) * 100 + Number(fraction.padEnd(2, "0"));
}

export function centsDem(cents: number): string {
  if (!Number.isSafeInteger(cents) || cents < 0) throw new Error("DEM cents must be a non-negative safe integer");
  const whole = Math.floor(cents / 100);
  const fraction = String(cents % 100).padStart(2, "0");
  return fraction === "00" ? String(whole) : `${whole}.${fraction}`;
}

export function parsePublisherRfqRequest(value: unknown): PublisherRfqRequest {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new PublisherPolicyError("invalid_request", "publisher RFQ must be an object");
  const input = value as Record<string, unknown>;
  const allowed = new Set(["creative", "preferredPlacement", "preferredDurationDays", "minimumDurationDays", "budgetDem"]);
  if (Object.keys(input).some((key) => !allowed.has(key))) throw new PublisherPolicyError("unsupported_fields", "publisher RFQ contains unsupported fields");
  if (!input.creative || typeof input.creative !== "object" || Array.isArray(input.creative)) throw new PublisherPolicyError("invalid_creative", "creative must be an object");
  const raw = input.creative as Record<string, unknown>;
  if (Object.keys(raw).some((key) => !["headline", "body", "cta", "destinationUrl"].includes(key))) {
    throw new PublisherPolicyError("unsupported_creative_fields", "creative contains unsupported fields");
  }
  const cta = raw.cta;
  if (cta !== "Learn more" && cta !== "Try it" && cta !== "View details") throw new PublisherPolicyError("invalid_cta", "creative cta is unsupported");
  const placement = input.preferredPlacement;
  if (placement !== "homepage-banner" && placement !== "sidebar-card") throw new PublisherPolicyError("invalid_placement", "preferredPlacement is unsupported");
  const preferredDurationDays = input.preferredDurationDays;
  const minimumDurationDays = input.minimumDurationDays;
  if (!Number.isSafeInteger(preferredDurationDays) || Number(preferredDurationDays) < 1 || Number(preferredDurationDays) > 30
    || !Number.isSafeInteger(minimumDurationDays) || Number(minimumDurationDays) < 1
    || Number(minimumDurationDays) > Number(preferredDurationDays)) {
    throw new PublisherPolicyError("invalid_duration", "duration must be 1-30 days and minimumDurationDays cannot exceed the preference");
  }
  return {
    creative: {
      headline: exactText(raw.headline, "headline", 80),
      body: exactText(raw.body, "body", 160),
      cta,
      destinationUrl: destination(raw.destinationUrl),
    },
    preferredPlacement: placement,
    preferredDurationDays: Number(preferredDurationDays),
    minimumDurationDays: Number(minimumDurationDays),
    budgetDem: parseDem(input.budgetDem),
  };
}

export function hashPublisherValue(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value), "utf8").digest("hex");
}

export async function approveCreative(request: PublisherRfqRequest, moderation: PublisherModerationPort): Promise<string> {
  const creativeHash = hashPublisherValue(request.creative);
  const decision = await moderation.review({ creative: request.creative, creativeHash });
  if (!decision.allowed) throw new PublisherPolicyError("moderation_rejected", decision.reason ?? "advert creative was rejected");
  return creativeHash;
}

export function isPlacement(value: string): value is AdPlacement {
  return value === "homepage-banner" || value === "sidebar-card";
}
