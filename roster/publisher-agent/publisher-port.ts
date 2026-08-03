import { hashPublisherValue } from "./policy.js";
import type { AdActivation, AdCreative, AdPlacement } from "./types.js";

export interface PublisherActivationPort {
  activate(input: {
    campaignId: string;
    domain: string;
    slotId: string;
    placement: AdPlacement;
    creative: AdCreative;
    creativeHash: string;
    startsAt: number;
    endsAt: number;
  }): Promise<AdActivation>;
}

export class MemoryPublisherActivationPort implements PublisherActivationPort {
  private readonly activations = new Map<string, { inputHash: string; activation: AdActivation }>();
  calls = 0;

  async activate(input: {
    campaignId: string;
    domain: string;
    slotId: string;
    placement: AdPlacement;
    creative: AdCreative;
    creativeHash: string;
    startsAt: number;
    endsAt: number;
  }): Promise<AdActivation> {
    const inputHash = hashPublisherValue(input);
    const existing = this.activations.get(input.campaignId);
    if (existing) {
      if (existing.inputHash !== inputHash) throw new Error("campaign id was reused with different advert terms");
      return structuredClone(existing.activation);
    }
    this.calls += 1;
    const activation: AdActivation = {
      activationId: `activation-${input.campaignId}`,
      ...structuredClone(input),
      publicPageUrl: `https://${input.domain}/`,
      evidenceUrl: `https://${input.domain}/.well-known/dacs-ads/${encodeURIComponent(input.campaignId)}.json`,
      activatedAt: input.startsAt - 30_000,
    };
    this.activations.set(input.campaignId, { inputHash, activation });
    return structuredClone(activation);
  }
}
