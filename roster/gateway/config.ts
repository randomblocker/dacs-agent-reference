/**
 * Gateway configuration — env-driven, validated at startup.
 *
 * Auth posture (the load-bearing rule):
 *   - GATEWAY_TOKEN set                  → auth ENFORCED, bind honored.
 *   - no token, GATEWAY_DEV != "1"       → REFUSE to start (loadConfig throws
 *                                          ConfigError with a clear message).
 *   - no token, GATEWAY_DEV == "1"       → dev mode: force bind 127.0.0.1,
 *                                          auth NOT enforced (POST open),
 *                                          caller prints a loud warning.
 *
 * Everything here is pure: `loadConfig` reads a plain env record so tests can
 * drive it without touching process.env.
 */

/** Semantic version of the gateway service (surfaced by /health). */
export const GATEWAY_VERSION = "0.1.0";

export interface GatewayConfig {
  port: number;
  bind: string;
  /** Bearer token required for POST when auth is enforced; null in open dev mode. */
  token: string | null;
  /** True when GATEWAY_DEV=1 and no token — localhost-only, POST open. */
  devMode: boolean;
  /** True iff a token is configured; POST requires it. */
  authEnforced: boolean;
  /** Max POST body size in bytes (over → 413). */
  bodyLimitBytes: number;
  /** Socket-level request timeout in ms. */
  requestTimeoutMs: number;
  /** Per-agent invocation timeout in ms (over → 504). */
  agentTimeoutMs: number;
  version: string;
}

/** Thrown by loadConfig when the environment is unsafe to start in. */
export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

function intFromEnv(raw: string | undefined, fallback: number, label: string): number {
  if (raw === undefined || raw.trim() === "") return fallback;
  const n = Number(raw);
  if (!Number.isFinite(n) || !Number.isInteger(n) || n <= 0) {
    throw new ConfigError(`${label} must be a positive integer, got "${raw}"`);
  }
  return n;
}

const MIB = 1024 * 1024;

/**
 * Build the gateway config from an environment record. Throws ConfigError
 * when the posture is unsafe (production without a token).
 */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): GatewayConfig {
  const token = env.GATEWAY_TOKEN?.trim() ? env.GATEWAY_TOKEN.trim() : null;
  const devMode = env.GATEWAY_DEV === "1";

  if (!token && !devMode) {
    throw new ConfigError(
      "refusing to start: no GATEWAY_TOKEN set. Set a bearer token (e.g. `openssl rand -hex 32`) " +
        "for POST auth, or set GATEWAY_DEV=1 to run localhost-only in open dev mode.",
    );
  }

  // Dev mode without a token is localhost-only, no matter what GATEWAY_BIND says.
  const bind = !token && devMode ? "127.0.0.1" : (env.GATEWAY_BIND?.trim() || "0.0.0.0");

  return {
    port: intFromEnv(env.GATEWAY_PORT, 8402, "GATEWAY_PORT"),
    bind,
    token,
    devMode: devMode && !token,
    authEnforced: token !== null,
    bodyLimitBytes: intFromEnv(env.GATEWAY_BODY_LIMIT, MIB, "GATEWAY_BODY_LIMIT"),
    // Live output anchoring waits for wallet nonce advancement (up to 90s), so
    // the socket timeout must leave room for that post-invocation commit.
    requestTimeoutMs: intFromEnv(env.GATEWAY_REQUEST_TIMEOUT_MS, 120_000, "GATEWAY_REQUEST_TIMEOUT_MS"),
    agentTimeoutMs: intFromEnv(env.GATEWAY_AGENT_TIMEOUT_MS, 25_000, "GATEWAY_AGENT_TIMEOUT_MS"),
    version: GATEWAY_VERSION,
  };
}
