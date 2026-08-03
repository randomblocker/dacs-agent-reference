import { centsDem, demCents, hashPublisherValue } from "./policy.js";
import type { AdPlacement, PublisherQuote, PublisherRfqRequest } from "./types.js";

export interface PublisherSlot {
  slotId: string;
  placement: AdPlacement;
  dailyRateDem: string;
  publicPath: string;
}

export interface PublisherReservationPort {
  reserve(input: PublisherQuote): Promise<{ reserved: boolean; reason?: string }>;
  release(jobId: string): Promise<void>;
}

export class MemoryPublisherReservations implements PublisherReservationPort {
  private readonly quotes = new Map<string, PublisherQuote>();

  async reserve(input: PublisherQuote): Promise<{ reserved: boolean; reason?: string }> {
    if (this.quotes.has(input.jobId)) {
      return hashPublisherValue(this.quotes.get(input.jobId)) === hashPublisherValue(input)
        ? { reserved: true }
        : { reserved: false, reason: "job id was reused for another quote" };
    }
    const collision = Array.from(this.quotes.values()).some((quote) => quote.slotId === input.slotId
      && quote.startsAt < input.endsAt && input.startsAt < quote.endsAt);
    if (collision) return { reserved: false, reason: "requested inventory was reserved concurrently" };
    this.quotes.set(input.jobId, structuredClone(input));
    return { reserved: true };
  }

  async release(jobId: string): Promise<void> { this.quotes.delete(jobId); }
}

export function buildPublisherQuote(input: {
  jobId: string;
  domain: string;
  request: PublisherRfqRequest;
  slots: readonly PublisherSlot[];
  now: number;
}): PublisherQuote {
  const slot = input.slots.find((candidate) => candidate.placement === input.request.preferredPlacement);
  if (!slot) throw new Error(`publisher has no ${input.request.preferredPlacement} inventory`);
  const rate = demCents(slot.dailyRateDem);
  if (!Number.isSafeInteger(rate) || rate <= 0) throw new Error("publisher slot has an invalid daily rate");
  const budget = demCents(input.request.budgetDem);
  const affordable = Math.floor(budget / rate);
  const durationDays = Math.min(input.request.preferredDurationDays, affordable);
  if (durationDays < input.request.minimumDurationDays) throw new Error("RFQ budget cannot buy the minimum campaign duration");
  const startsAt = input.now + 60_000;
  const endsAt = startsAt + durationDays * 86_400_000;
  return {
    quoteVersion: "1",
    jobId: input.jobId,
    domain: input.domain,
    slotId: slot.slotId,
    placement: slot.placement,
    durationDays,
    priceDem: centsDem(rate * durationDays),
    startsAt,
    endsAt,
    expiresAt: input.now + 5 * 60_000,
    creativeHash: hashPublisherValue(input.request.creative),
    requestHash: hashPublisherValue(input.request),
  };
}

export async function negotiatePublisherRfq(input: {
  jobId: string;
  domain: string;
  request: PublisherRfqRequest;
  slots: readonly PublisherSlot[];
  reservations: PublisherReservationPort;
  now: number;
}): Promise<{ outcome: "agreed"; quote: PublisherQuote; transcript: Array<Record<string, unknown>> }> {
  const quote = buildPublisherQuote(input);
  const reserved = await input.reservations.reserve(quote);
  if (!reserved.reserved) throw new Error(reserved.reason ?? "publisher inventory could not be reserved");
  return {
    outcome: "agreed",
    quote,
    transcript: [
      { side: "buyer", kind: "rfq", requestHash: quote.requestHash, budgetDem: input.request.budgetDem },
      { side: "seller", kind: quote.durationDays === input.request.preferredDurationDays ? "offer" : "counter", quote },
      { side: "buyer", kind: "accept", quoteHash: hashPublisherValue(quote) },
    ],
  };
}
