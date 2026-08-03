import type { FetchLike } from "./x-api.js";
import type { ModerationDecision, SponsoredPostModerationPort } from "./policy.js";

/** Fail-closed adapter for an operator-owned moderation decision service. */
export class HttpSponsoredPostModerationPort implements SponsoredPostModerationPort {
  private readonly endpoint: string;
  private readonly token: string;
  private readonly timeoutMs: number;
  private readonly fetcher: FetchLike;

  constructor(input: { endpoint: string; bearerToken: string; timeoutMs?: number; fetcher?: FetchLike }) {
    const url = new URL(input.endpoint);
    if (url.protocol !== "https:") throw new Error("sponsored-post moderation endpoint must use https");
    this.endpoint = url.toString();
    this.token = input.bearerToken.trim();
    this.timeoutMs = input.timeoutMs ?? 5_000;
    this.fetcher = input.fetcher ?? fetch;
    if (!this.token) throw new Error("sponsored-post moderation bearer token is required");
    if (!Number.isSafeInteger(this.timeoutMs) || this.timeoutMs < 500 || this.timeoutMs > 15_000) {
      throw new Error("moderation timeout must be between 500 and 15000ms");
    }
  }

  async review(input: { text: string; textHash: string }): Promise<ModerationDecision> {
    let response: Response;
    try {
      response = await this.fetcher(this.endpoint, {
        method: "POST",
        headers: {
          authorization: `Bearer ${this.token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify(input),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (error) {
      throw new Error(`moderation service unavailable: ${error instanceof Error ? error.message : String(error)}`);
    }
    if (response.status !== 200) throw new Error(`moderation service failed closed with HTTP ${response.status}`);
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      throw new Error("moderation service returned invalid JSON");
    }
    if (!body || typeof body !== "object" || typeof (body as Record<string, unknown>).allowed !== "boolean") {
      throw new Error("moderation service returned an invalid decision");
    }
    const record = body as Record<string, unknown>;
    if (record.reason !== undefined && typeof record.reason !== "string") throw new Error("moderation reason is invalid");
    if (record.decisionRef !== undefined && (typeof record.decisionRef !== "string"
      || !/^[A-Za-z0-9._:/-]{1,200}$/.test(record.decisionRef))) {
      throw new Error("moderation decisionRef must be a bounded ASCII reference");
    }
    return {
      allowed: record.allowed as boolean,
      ...(record.reason === undefined ? {} : { reason: (record.reason as string).slice(0, 300) }),
      ...(record.decisionRef === undefined ? {} : { decisionRef: record.decisionRef as string }),
    };
  }
}
