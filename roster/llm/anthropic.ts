/** Minimal, dependency-free Anthropic Messages API adapter. */
import { chmodSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

export interface LlmCallOptions {
  system?: string;
  maxTokens?: number;
  timeoutMs?: number;
}

export interface TextLlm {
  readonly provider: "anthropic";
  readonly model: string;
  complete(prompt: string, opts?: LlmCallOptions): Promise<string>;
  quotaStatus?(): AnthropicQuotaStatus;
}

export interface AnthropicQuotaOptions {
  usageFile: string;
  maxCallsPerHour: number;
  maxCallsPerDay: number;
  maxInputCharsPerDay: number;
  maxOutputTokensPerDay: number;
  now?: () => Date;
}

export interface AnthropicQuotaStatus {
  enabled: boolean;
  window?: { day: string; hour: string };
  used?: { callsThisHour: number; callsToday: number; inputCharsToday: number; outputTokensToday: number };
  limits?: { callsPerHour: number; callsPerDay: number; inputCharsPerDay: number; outputTokensPerDay: number };
  remaining?: { callsThisHour: number; callsToday: number; inputCharsToday: number; outputTokensToday: number };
}

export interface AnthropicOptions {
  apiKey: string;
  model?: string;
  baseUrl?: string;
  maxInputChars?: number;
  maxOutputChars?: number;
  maxConcurrent?: number;
  fetchFn?: typeof fetch;
  quota?: AnthropicQuotaOptions;
}

interface MessageResponse {
  content?: Array<{ type?: string; text?: string }>;
  stop_reason?: string;
  error?: { type?: string; message?: string };
}

const RETRYABLE = new Set([429, 500, 502, 503, 504, 529]);

interface AnthropicUsageState {
  version: 1;
  day: string;
  hour: string;
  callsThisHour: number;
  callsToday: number;
  inputCharsToday: number;
  outputTokensToday: number;
  updatedAt: string;
}

export class AnthropicLlm implements TextLlm {
  readonly provider = "anthropic" as const;
  readonly model: string;
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly maxInputChars: number;
  private readonly maxOutputChars: number;
  private readonly maxConcurrent: number;
  private readonly fetchFn: typeof fetch;
  private readonly quota?: AnthropicQuotaOptions;
  private active = 0;

  constructor(opts: AnthropicOptions) {
    this.apiKey = opts.apiKey.trim();
    if (!this.apiKey) throw new Error("Anthropic API key is empty");
    this.model = opts.model?.trim() || "claude-sonnet-5";
    this.baseUrl = (opts.baseUrl?.trim() || "https://api.anthropic.com").replace(/\/$/, "");
    this.maxInputChars = opts.maxInputChars ?? 60_000;
    this.maxOutputChars = opts.maxOutputChars ?? 12_000;
    this.maxConcurrent = opts.maxConcurrent ?? 2;
    this.fetchFn = opts.fetchFn ?? fetch;
    this.quota = opts.quota;
    if (this.quota) validateQuota(this.quota);
  }

  async complete(prompt: string, opts: LlmCallOptions = {}): Promise<string> {
    if (!prompt.trim()) throw new Error("LLM prompt is empty");
    if (prompt.length > this.maxInputChars) throw new Error(`LLM prompt exceeds ${this.maxInputChars} characters`);
    if (this.active >= this.maxConcurrent) throw new Error("LLM concurrency limit reached");
    const maxTokens = boundedMaxTokens(opts.maxTokens);
    this.reserveQuota(prompt.length, maxTokens);
    this.active += 1;
    try {
      let last: unknown;
      for (let attempt = 0; attempt < 3; attempt++) {
        try {
          return await this.request(prompt, opts, maxTokens);
        } catch (error) {
          last = error;
          if (!(error instanceof AnthropicError) || !error.retryable || attempt === 2) throw error;
          await new Promise((resolve) => setTimeout(resolve, Math.min(error.retryAfterMs ?? 250 * 2 ** attempt, 2_000)));
        }
      }
      throw last;
    } finally {
      this.active -= 1;
    }
  }

  quotaStatus(): AnthropicQuotaStatus {
    if (!this.quota) return { enabled: false };
    const state = this.readUsage();
    const limits = {
      callsPerHour: this.quota.maxCallsPerHour,
      callsPerDay: this.quota.maxCallsPerDay,
      inputCharsPerDay: this.quota.maxInputCharsPerDay,
      outputTokensPerDay: this.quota.maxOutputTokensPerDay,
    };
    return {
      enabled: true,
      window: { day: state.day, hour: state.hour },
      used: {
        callsThisHour: state.callsThisHour,
        callsToday: state.callsToday,
        inputCharsToday: state.inputCharsToday,
        outputTokensToday: state.outputTokensToday,
      },
      limits,
      remaining: {
        callsThisHour: Math.max(0, limits.callsPerHour - state.callsThisHour),
        callsToday: Math.max(0, limits.callsPerDay - state.callsToday),
        inputCharsToday: Math.max(0, limits.inputCharsPerDay - state.inputCharsToday),
        outputTokensToday: Math.max(0, limits.outputTokensPerDay - state.outputTokensToday),
      },
    };
  }

  private reserveQuota(inputChars: number, outputTokens: number): void {
    if (!this.quota) return;
    const state = this.readUsage();
    const checks: Array<[number, number, string]> = [
      [state.callsThisHour + 1, this.quota.maxCallsPerHour, "hourly call"],
      [state.callsToday + 1, this.quota.maxCallsPerDay, "daily call"],
      [state.inputCharsToday + inputChars, this.quota.maxInputCharsPerDay, "daily input character"],
      [state.outputTokensToday + outputTokens, this.quota.maxOutputTokensPerDay, "daily output token"],
    ];
    for (const [next, limit, label] of checks) {
      if (next > limit) throw new AnthropicQuotaError(`Anthropic ${label} quota exceeded`);
    }
    state.callsThisHour += 1;
    state.callsToday += 1;
    state.inputCharsToday += inputChars;
    state.outputTokensToday += outputTokens;
    state.updatedAt = this.now().toISOString();
    this.writeUsage(state);
  }

  private readUsage(): AnthropicUsageState {
    if (!this.quota) throw new AnthropicQuotaError("Anthropic quota is not configured");
    const now = this.now();
    let state: AnthropicUsageState;
    try {
      state = JSON.parse(readFileSync(this.quota.usageFile, "utf8")) as AnthropicUsageState;
      validateUsageState(state);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        throw new AnthropicQuotaError("Anthropic usage ledger is unreadable or invalid; refusing request");
      }
      state = newUsageState(now);
    }
    const day = dayWindow(now);
    const hour = hourWindow(now);
    if (state.day !== day) {
      state.day = day;
      state.callsToday = 0;
      state.inputCharsToday = 0;
      state.outputTokensToday = 0;
    }
    if (state.hour !== hour) {
      state.hour = hour;
      state.callsThisHour = 0;
    }
    return state;
  }

  private writeUsage(state: AnthropicUsageState): void {
    if (!this.quota) return;
    const directory = dirname(this.quota.usageFile);
    const temporary = `${this.quota.usageFile}.${process.pid}.tmp`;
    try {
      mkdirSync(directory, { recursive: true, mode: 0o700 });
      chmodSync(directory, 0o700);
      writeFileSync(temporary, `${JSON.stringify(state, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
      chmodSync(temporary, 0o600);
      renameSync(temporary, this.quota.usageFile);
    } catch {
      throw new AnthropicQuotaError("Anthropic usage ledger could not be persisted; refusing request");
    }
  }

  private now(): Date {
    const value = this.quota?.now?.() ?? new Date();
    if (!Number.isFinite(value.getTime())) throw new AnthropicQuotaError("Anthropic quota clock is invalid");
    return value;
  }

  private async request(prompt: string, opts: LlmCallOptions, maxTokens: number): Promise<string> {
    let response: Response;
    try {
      response = await this.fetchFn(`${this.baseUrl}/v1/messages`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-api-key": this.apiKey,
          "anthropic-version": "2023-06-01",
        },
        body: JSON.stringify({
          model: this.model,
          max_tokens: maxTokens,
          ...(opts.system ? { system: opts.system } : {}),
          messages: [{ role: "user", content: prompt }],
        }),
        signal: AbortSignal.timeout(Math.min(Math.max(opts.timeoutMs ?? 45_000, 1_000), 120_000)),
      });
    } catch (error) {
      throw new AnthropicError(`Anthropic network error: ${(error as Error).message}`, true);
    }

    const requestId = response.headers.get("request-id") ?? undefined;
    let payload: MessageResponse;
    try { payload = await response.json() as MessageResponse; } catch { payload = {}; }
    if (!response.ok) {
      const retryAfter = Number(response.headers.get("retry-after"));
      throw new AnthropicError(
        `Anthropic ${response.status}${payload.error?.type ? ` ${payload.error.type}` : ""}${requestId ? ` (${requestId})` : ""}`,
        RETRYABLE.has(response.status),
        Number.isFinite(retryAfter) ? retryAfter * 1_000 : undefined,
        response.status,
      );
    }
    const text = (payload.content ?? []).filter((block) => block.type === "text").map((block) => block.text ?? "").join("\n").trim();
    if (!text) throw new AnthropicError(`Anthropic returned no text${requestId ? ` (${requestId})` : ""}`, false);
    if (text.length > this.maxOutputChars) throw new AnthropicError(`Anthropic output exceeds ${this.maxOutputChars} characters`, false);
    return text;
  }
}

export class AnthropicError extends Error {
  constructor(message: string, readonly retryable: boolean, readonly retryAfterMs?: number, readonly status?: number) {
    super(message);
    this.name = "AnthropicError";
  }
}

export class AnthropicQuotaError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AnthropicQuotaError";
  }
}

function boundedMaxTokens(value: number | undefined): number {
  return Math.min(Math.max(Math.trunc(value ?? 1_024), 1), 4_096);
}

function positiveInteger(value: string | undefined, fallback: number, name: string): number {
  const parsed = value === undefined ? fallback : Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) throw new Error(`${name} must be a positive integer`);
  return parsed;
}

function validateQuota(quota: AnthropicQuotaOptions): void {
  if (!quota.usageFile.trim()) throw new Error("Anthropic usage file is empty");
  for (const [name, value] of Object.entries({
    maxCallsPerHour: quota.maxCallsPerHour,
    maxCallsPerDay: quota.maxCallsPerDay,
    maxInputCharsPerDay: quota.maxInputCharsPerDay,
    maxOutputTokensPerDay: quota.maxOutputTokensPerDay,
  })) {
    if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`Anthropic ${name} must be a positive integer`);
  }
}

function validateUsageState(value: AnthropicUsageState): void {
  if (!value || value.version !== 1 || typeof value.day !== "string" || typeof value.hour !== "string" || typeof value.updatedAt !== "string") {
    throw new Error("invalid usage ledger");
  }
  for (const count of [value.callsThisHour, value.callsToday, value.inputCharsToday, value.outputTokensToday]) {
    if (!Number.isSafeInteger(count) || count < 0) throw new Error("invalid usage ledger count");
  }
}

function dayWindow(now: Date): string {
  return now.toISOString().slice(0, 10);
}

function hourWindow(now: Date): string {
  return now.toISOString().slice(0, 13);
}

function newUsageState(now: Date): AnthropicUsageState {
  return {
    version: 1,
    day: dayWindow(now),
    hour: hourWindow(now),
    callsThisHour: 0,
    callsToday: 0,
    inputCharsToday: 0,
    outputTokensToday: 0,
    updatedAt: now.toISOString(),
  };
}

/** Read a systemd credential without ever placing the key in argv or source. */
export function anthropicFromEnv(env: NodeJS.ProcessEnv = process.env): TextLlm | undefined {
  const credentialsDir = env.CREDENTIALS_DIRECTORY;
  const credentialName = env.ANTHROPIC_CREDENTIAL?.trim() || "anthropic_api_key";
  const path = credentialsDir ? `${credentialsDir}/${credentialName}` : undefined;
  let apiKey = "";
  try { apiKey = path ? readFileSync(path, "utf8").trim() : ""; } catch { return undefined; }
  if (!apiKey) return undefined;
  const usageFile = env.ANTHROPIC_USAGE_FILE?.trim()
    || (env.SELLER_STATE_PATH?.trim() ? join(dirname(env.SELLER_STATE_PATH.trim()), "anthropic-usage.json") : join(process.cwd(), "roster/llm/out/anthropic-usage.json"));
  return new AnthropicLlm({
    apiKey,
    model: env.ANTHROPIC_MODEL,
    baseUrl: env.ANTHROPIC_BASE_URL,
    maxConcurrent: positiveInteger(env.ANTHROPIC_MAX_CONCURRENT, 2, "ANTHROPIC_MAX_CONCURRENT"),
    quota: {
      usageFile,
      maxCallsPerHour: positiveInteger(env.ANTHROPIC_MAX_CALLS_HOUR, 20, "ANTHROPIC_MAX_CALLS_HOUR"),
      maxCallsPerDay: positiveInteger(env.ANTHROPIC_MAX_CALLS_DAY, 100, "ANTHROPIC_MAX_CALLS_DAY"),
      maxInputCharsPerDay: positiveInteger(env.ANTHROPIC_MAX_INPUT_CHARS_DAY, 500_000, "ANTHROPIC_MAX_INPUT_CHARS_DAY"),
      maxOutputTokensPerDay: positiveInteger(env.ANTHROPIC_MAX_OUTPUT_TOKENS_DAY, 30_000, "ANTHROPIC_MAX_OUTPUT_TOKENS_DAY"),
    },
  });
}
