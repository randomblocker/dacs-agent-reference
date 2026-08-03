import type { PublishedSponsoredPost } from "./types.js";

export type PublishOutcome = "rejected" | "indeterminate";

export class SponsoredPostPublishError extends Error {
  constructor(
    message: string,
    readonly outcome: PublishOutcome,
    readonly status?: number,
  ) {
    super(message);
    this.name = "SponsoredPostPublishError";
  }
}

export interface SponsoredPostPort {
  publish(input: { text: string }): Promise<PublishedSponsoredPost>;
}

export type FetchLike = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

function safeErrorBody(value: unknown): string {
  if (!value || typeof value !== "object") return "unstructured X API error";
  const record = value as Record<string, unknown>;
  if (typeof record.detail === "string") return record.detail.slice(0, 300);
  if (typeof record.title === "string") return record.title.slice(0, 300);
  if (Array.isArray(record.errors)) {
    const first = record.errors[0];
    if (first && typeof first === "object") {
      const detail = (first as Record<string, unknown>).detail;
      if (typeof detail === "string") return detail.slice(0, 300);
    }
  }
  return "X API rejected publication";
}

/** Official X API v2 adapter. It never logs or returns its OAuth token. */
export class XApiSponsoredPostPort implements SponsoredPostPort {
  private readonly token: string;
  private readonly handle: string;
  private readonly timeoutMs: number;
  private readonly fetcher: FetchLike;

  constructor(input: {
    userAccessToken: string;
    handle: string;
    timeoutMs?: number;
    fetcher?: FetchLike;
  }) {
    this.token = input.userAccessToken.trim();
    this.handle = input.handle.replace(/^@/, "");
    this.timeoutMs = input.timeoutMs ?? 12_000;
    this.fetcher = input.fetcher ?? fetch;
    if (!this.token) throw new Error("X user access token is required");
    if (!/^[A-Za-z0-9_]{1,15}$/.test(this.handle)) throw new Error("X handle is invalid");
    if (!Number.isSafeInteger(this.timeoutMs) || this.timeoutMs < 1_000 || this.timeoutMs > 30_000) {
      throw new Error("X publication timeout must be between 1000 and 30000ms");
    }
  }

  async publish(input: { text: string }): Promise<PublishedSponsoredPost> {
    let response: Response;
    try {
      response = await this.fetcher("https://api.x.com/2/tweets", {
        method: "POST",
        headers: {
          authorization: `Bearer ${this.token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          text: input.text,
          paid_partnership: true,
          made_with_ai: false,
        }),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (error) {
      throw new SponsoredPostPublishError(
        `X publication result is unknown: ${error instanceof Error ? error.message : String(error)}`,
        "indeterminate",
      );
    }

    let body: unknown;
    try {
      body = await response.json();
    } catch {
      body = undefined;
    }
    if (response.status !== 201) {
      const outcome: PublishOutcome = response.status >= 400 && response.status < 500 ? "rejected" : "indeterminate";
      throw new SponsoredPostPublishError(`X publication failed: ${safeErrorBody(body)}`, outcome, response.status);
    }
    const data = body && typeof body === "object" ? (body as Record<string, unknown>).data : undefined;
    if (!data || typeof data !== "object") {
      throw new SponsoredPostPublishError("X publication succeeded without a verifiable response body", "indeterminate", 201);
    }
    const id = (data as Record<string, unknown>).id;
    const text = (data as Record<string, unknown>).text;
    if (typeof id !== "string" || !/^[0-9]{1,19}$/.test(id) || text !== input.text) {
      throw new SponsoredPostPublishError("X publication response did not match the approved request", "indeterminate", 201);
    }
    return {
      postId: id,
      text,
      handle: this.handle,
      url: `https://x.com/${this.handle}/status/${id}`,
      publishedAt: Date.now(),
      paidPartnership: true,
      madeWithAi: false,
    };
  }

  /** Startup ownership check: the OAuth token must control the listed account. */
  async verifyAccount(expectedUserId: string): Promise<void> {
    let response: Response;
    try {
      response = await this.fetcher("https://api.x.com/2/users/me", {
        headers: { authorization: `Bearer ${this.token}` },
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (error) {
      throw new Error(`X account ownership check failed: ${error instanceof Error ? error.message : String(error)}`);
    }
    if (response.status !== 200) throw new Error(`X account ownership check failed with HTTP ${response.status}`);
    const body = await response.json() as { data?: { id?: unknown; username?: unknown } };
    if (body.data?.id !== expectedUserId || typeof body.data.username !== "string"
      || body.data.username.toLowerCase() !== this.handle.toLowerCase()) {
      throw new Error("X OAuth token does not control the DACS-linked account");
    }
  }
}
