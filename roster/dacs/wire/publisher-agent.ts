import type { WorkCallback } from "../seller-adapter.js";
import type { DeliveryVerifyOptions } from "../verifier.js";
import { readReportMeta, reportMeta } from "./report-meta.js";
import { hashPublisherValue, parsePublisherRfqRequest, approveCreative, type PublisherModerationPort } from "../../publisher-agent/policy.js";
import type { PublisherActivationPort } from "../../publisher-agent/publisher-port.js";
import {
  PUBLISHER_SERVICE_ID,
  type PublisherDelivery,
  type PublisherQuote,
} from "../../publisher-agent/types.js";

export { PUBLISHER_SERVICE_ID };

function quoteFrom(value: unknown): PublisherQuote {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("publisher delivery requires an agreed quote");
  const quote = value as PublisherQuote;
  if (quote.quoteVersion !== "1" || typeof quote.jobId !== "string" || typeof quote.domain !== "string"
    || typeof quote.slotId !== "string" || (quote.placement !== "homepage-banner" && quote.placement !== "sidebar-card")
    || !Number.isSafeInteger(quote.durationDays) || quote.durationDays < 1
    || typeof quote.priceDem !== "string" || !Number.isSafeInteger(quote.startsAt)
    || !Number.isSafeInteger(quote.endsAt) || quote.endsAt <= quote.startsAt
    || !Number.isSafeInteger(quote.expiresAt) || !/^[0-9a-f]{64}$/.test(quote.creativeHash)
    || !/^[0-9a-f]{64}$/.test(quote.requestHash)) {
    throw new Error("publisher agreed quote is invalid");
  }
  return structuredClone(quote);
}

export function makePublisherWork(input: {
  domain: string;
  publisher: PublisherActivationPort;
  moderation: PublisherModerationPort;
  now?: () => number;
}): WorkCallback {
  const now = input.now ?? Date.now;
  return async (jobId, params) => {
    const request = parsePublisherRfqRequest(params.request);
    const quote = quoteFrom(params.quote);
    if (quote.jobId !== jobId || quote.domain !== input.domain) throw new Error("publisher quote is bound to another job or domain");
    if (quote.requestHash !== hashPublisherValue(request) || quote.creativeHash !== hashPublisherValue(request.creative)) {
      throw new Error("publisher quote does not bind the delivered RFQ request");
    }
    if (quote.endsAt <= now()) throw new Error("publisher campaign already expired before activation");
    await approveCreative(request, input.moderation);
    const activation = await input.publisher.activate({
      campaignId: jobId,
      domain: quote.domain,
      slotId: quote.slotId,
      placement: quote.placement,
      creative: request.creative,
      creativeHash: quote.creativeHash,
      startsAt: quote.startsAt,
      endsAt: quote.endsAt,
    });
    const deliverable: PublisherDelivery = {
      kind: "publisher-ad-activation",
      activationId: activation.activationId,
      campaignId: activation.campaignId,
      domain: activation.domain,
      slotId: activation.slotId,
      placement: activation.placement,
      creativeBase64: Buffer.from(JSON.stringify(activation.creative), "utf8").toString("base64url"),
      creativeHash: activation.creativeHash,
      startsAt: activation.startsAt,
      endsAt: activation.endsAt,
      publicPageUrl: activation.publicPageUrl,
      evidenceUrl: activation.evidenceUrl,
      activatedAt: activation.activatedAt,
      requestHash: quote.requestHash,
      quoteHash: hashPublisherValue(quote),
    };
    const meta = reportMeta(deliverable);
    return {
      result: {
        domain: deliverable.domain,
        slotId: deliverable.slotId,
        placement: deliverable.placement,
        startsAt: deliverable.startsAt,
        endsAt: deliverable.endsAt,
        evidenceUrl: deliverable.evidenceUrl,
        creativeHash: deliverable.creativeHash,
        quoteHash: deliverable.quoteHash,
        reportHash: meta.reportHash,
      },
      deliverableRef: `https://${deliverable.domain}/.well-known/dacs-ads/${encodeURIComponent(jobId)}.json`,
      meta,
    };
  };
}

export function publisherObserveDelivered(expectedDomain: string): DeliveryVerifyOptions["observeDelivered"] {
  return async (attestation) => {
    const read = readReportMeta<PublisherDelivery>(attestation);
    if (!read.ok) return { ok: false, reason: read.reason };
    const ad = read.artifact;
    if (ad.kind !== "publisher-ad-activation" || ad.domain !== expectedDomain) return { ok: false, reason: "publisher delivery names the wrong artifact or domain" };
    if (ad.publicPageUrl !== `https://${expectedDomain}/`) return { ok: false, reason: "publisher public page URL is not canonical" };
    const expectedEvidence = `https://${expectedDomain}/.well-known/dacs-ads/${encodeURIComponent(ad.campaignId)}.json`;
    if (ad.evidenceUrl !== expectedEvidence) return { ok: false, reason: "publisher evidence URL is not canonical" };
    let creative: unknown;
    try {
      const bytes = Buffer.from(ad.creativeBase64, "base64url");
      if (bytes.toString("base64url") !== ad.creativeBase64) return { ok: false, reason: "publisher creative encoding is not canonical" };
      creative = JSON.parse(bytes.toString("utf8"));
      parsePublisherRfqRequest({
        creative,
        preferredPlacement: ad.placement,
        preferredDurationDays: 1,
        minimumDurationDays: 1,
        budgetDem: "1",
      });
    } catch {
      return { ok: false, reason: "publisher creative evidence is invalid" };
    }
    if (hashPublisherValue(creative) !== ad.creativeHash) return { ok: false, reason: "publisher creative does not match its hash" };
    if (!Number.isSafeInteger(ad.startsAt) || !Number.isSafeInteger(ad.endsAt) || ad.endsAt <= ad.startsAt
      || !Number.isSafeInteger(ad.activatedAt) || ad.activatedAt > ad.startsAt) {
      return { ok: false, reason: "publisher activation times are invalid" };
    }
    return { ok: true };
  };
}
