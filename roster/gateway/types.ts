/**
 * Gateway shared types — the AgentEndpoint contract, the injected ports
 * bundle, the per-request context, and a lightweight hand-written input
 * validator (required fields / types / enums / numeric bounds).
 *
 * No third-party deps: everything is node builtins + the agent cores.
 */
import type { MockDahrAttestor } from "../oracle-desk/attested-fetch.js";
import type { Settlement } from "./settlement.js";
import type { AttestedFetchPort } from "../oracle-desk/types.js";
import type { DataProduct } from "../oracle-desk/types.js";
import type { RegistryPort } from "../dep-upgrade/types.js";
import type { DnsPort } from "../shared/attest-primitives.js";
import type { ProberPort } from "../site-auditor/types.js";
import type { ListSourcePort } from "../compliance/types.js";
import type { MarketplacePort, NegotiationPort } from "../procurement-butler/types.js";
import type { RulingSigner } from "../evalbot/ruling.js";
import type { TreasurySigner } from "../treasury-ops/proof.js";
import type { TextLlm } from "../llm/anthropic.js";
import type { ContentAttestor } from "../sec-audit/attest-files.js";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/**
 * Thrown from inside an invoke() when the caller's input is bad in a way the
 * static field schema can't express (e.g. product-specific param validation).
 * The server maps this to 400, everything else an invoke throws maps to 502.
 */
export class AgentInputError extends Error {
  readonly details?: unknown;
  constructor(message: string, details?: unknown) {
    super(message);
    this.name = "AgentInputError";
    this.details = details;
  }
}

// ---------------------------------------------------------------------------
// Per-request context
// ---------------------------------------------------------------------------

export interface RequestContext {
  /** crypto.randomUUID per request; woven into intent/job/run ids. */
  requestId: string;
  /** Process-shared attestor so attestations are consistent across calls. */
  attestor: MockDahrAttestor;
}

// ---------------------------------------------------------------------------
// On-chain output anchor
// ---------------------------------------------------------------------------

/**
 * Anchors an agent's result digest on-chain under the gateway's persistent
 * identity. `addressFor` is the DETERMINISTIC storage address (sync, no write) so
 * the response can carry it immediately; `commit` performs the actual on-chain
 * write, SERIALIZED per-wallet (concurrent anchors from one wallet collide on
 * nonce — see the SDK's serial-nonce note). The caller awaits it so a response
 * never claims an anchor exists when the write failed.
 */
export interface OutputAnchor {
  /** The gateway's persistent committer (wallet) address. */
  readonly committerAddress: string;
  /** Deterministic on-chain storage address a name anchors to (no write). */
  addressFor(name: string): string;
  /** Commit a serialized on-chain anchor write. Rejects if broadcast/confirmation fails. */
  commit(name: string, value: object): Promise<{ txRef?: string } | void>;
  /**
   * Broadcast an anchor and return its transaction reference immediately while
   * keeping the wallet queue locked until the nonce advances. Public demos use
   * this path so chain inclusion does not add confirmation latency to the UI.
   */
  commitEager?(name: string, value: object): Promise<{ txRef?: string } | void>;
  /**
   * Enqueue a write without waiting for its turn in the wallet FIFO. Lifecycle
   * hooks make queue latency observable while the serializer retains exclusive
   * nonce ownership until confirmation.
   */
  enqueue?(name: string, value: object, lifecycle: OutputAnchorLifecycle): void;
}

export interface OutputAnchorLifecycle {
  onStart(): void;
  onBroadcast(result: { txRef?: string } | void): void;
  onConfirmed(result: { txRef?: string } | void): void;
  onError(error: unknown): void;
}

// ---------------------------------------------------------------------------
// Injected ports bundle
// ---------------------------------------------------------------------------

/**
 * Everything the registry's endpoints need, injected so tests can swap in
 * fakes (canned fetch/registry/dns/prober/compliance sources) and offline
 * agents keep their real cores.
 */
export interface GatewayPorts {
  /** Optional bounded LLM; agent cores retain deterministic fallbacks. */
  llm?: TextLlm;
  /** Shared MOCK-DAHR attestor for offline-safe core paths. */
  attestor: MockDahrAttestor;
  /** Persistent gateway identity evidence for private sec-audit content. */
  contentAttestor?: ContentAttestor;
  /** Attested HTTP fetch — oracle-desk, dd-researcher. */
  attestedFetch: AttestedFetchPort;
  /**
   * Optional LIVE-DAHR attested fetch for oracle-desk ONLY (real Demos
   * `web2Request` on-chain anchor via the node's DAHR proxy). When present,
   * oracle-desk uses this instead of the shared mock `attestedFetch`;
   * dd-researcher stays on the shared port (its GitHub egress isn't DAHR-viable
   * yet — kynesyslabs/node#959). Populated by buildRealPorts only when
   * GATEWAY_LIVE_DAHR=1 and a funded mnemonic is supplied; otherwise undefined
   * and oracle-desk transparently falls back to the mock attestor.
   */
  oracleAttestedFetch?: AttestedFetchPort;
  /**
   * Optional on-chain output anchor (real Demos StorageProgram write under the
   * gateway's persistent wallet identity). When present, EVERY agent response
   * gets an `outputAttestation` — the result digest anchored on-chain, verifiable
   * by any third party against the committer address. Populated by buildRealPorts
   * only when GATEWAY_LIVE_DAHR=1 + a funded mnemonic; otherwise undefined and
   * responses carry no output anchor (unchanged behaviour).
   */
  outputAnchor?: OutputAnchor;
  /**
   * Optional pay-dem settlement. When present, POST /agents/:name requires either
   * a valid operator Bearer token (free/internal) OR a verified DEM payment
   * (external buyer) — else 402 with a fee schedule. Populated by buildRealPorts
   * only when GATEWAY_SETTLEMENT=1 and a connected wallet is available.
   */
  settlement?: Settlement;
  /** DNS resolver (MX/TXT lookups). */
  dns: DnsPort;
  /** HTTP/TLS prober — site-auditor. */
  prober: ProberPort;
  /** npm registry + advisories — dep-upgrade + sec-audit deps audit. */
  registry: RegistryPort;
  /** Marketplace + negotiation counterparty — procurement-butler (offline stub). */
  marketplace: MarketplacePort & NegotiationPort;
  /** Shared approver identity — treasury-ops approve(). */
  treasuryApprover: TreasurySigner;
  /** Shared evaluator identity — evalbot rulings. */
  rulingSigner: RulingSigner;
  /** Compliance list sources factory (live realSources / offline fixtureSources). */
  complianceSources: () => ListSourcePort[];
  /** Oracle-desk product catalog; defaults to the stock CATALOG. */
  catalog?: DataProduct[];
}

// ---------------------------------------------------------------------------
// Lightweight input schema + validator
// ---------------------------------------------------------------------------

export type FieldType = "string" | "number" | "integer" | "boolean" | "object" | "array" | "string[]";

export interface FieldSpec {
  name: string;
  type: FieldType;
  required: boolean;
  /** For string fields: the closed set of allowed values. */
  enum?: readonly string[];
  /** For number/integer fields: inclusive bounds. */
  min?: number;
  max?: number;
  desc: string;
}

export interface ValidationResult {
  ok: boolean;
  errors: string[];
}

function typeOk(type: FieldType, v: unknown): boolean {
  switch (type) {
    case "string":
      return typeof v === "string";
    case "number":
      return typeof v === "number" && Number.isFinite(v);
    case "integer":
      return typeof v === "number" && Number.isInteger(v);
    case "boolean":
      return typeof v === "boolean";
    case "object":
      return typeof v === "object" && v !== null && !Array.isArray(v);
    case "array":
      return Array.isArray(v);
    case "string[]":
      return Array.isArray(v) && v.every((x) => typeof x === "string");
  }
}

/** Validate a decoded JSON body against a field schema. Pure, no throwing. */
export function validateInput(fields: readonly FieldSpec[], input: unknown): ValidationResult {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    return { ok: false, errors: ["request body must be a JSON object"] };
  }
  const obj = input as Record<string, unknown>;
  const errors: string[] = [];

  for (const f of fields) {
    const v = obj[f.name];
    if (v === undefined || v === null) {
      if (f.required) errors.push(`missing required field "${f.name}" (${f.type}) — ${f.desc}`);
      continue;
    }
    if (!typeOk(f.type, v)) {
      errors.push(`field "${f.name}" must be ${f.type} — ${f.desc}`);
      continue;
    }
    if (f.enum && typeof v === "string" && !f.enum.includes(v)) {
      errors.push(`field "${f.name}"="${v}" is not one of: ${f.enum.join(", ")}`);
    }
    if ((f.type === "number" || f.type === "integer") && typeof v === "number") {
      if (f.min !== undefined && v < f.min) errors.push(`field "${f.name}"=${v} is below minimum ${f.min}`);
      if (f.max !== undefined && v > f.max) errors.push(`field "${f.name}"=${v} is above maximum ${f.max}`);
    }
  }
  return { ok: errors.length === 0, errors };
}

// ---------------------------------------------------------------------------
// AgentEndpoint
// ---------------------------------------------------------------------------

export interface AgentEndpoint {
  name: string;
  summary: string;
  /** One-line note on the execution mode / safe-slice policy. */
  mode: string;
  fields: readonly FieldSpec[];
  validate(input: unknown): ValidationResult;
  invoke(input: unknown, ctx: RequestContext): Promise<unknown>;
}

/** Construct an endpoint, wiring `validate` to the field schema. */
export function defineAgent(spec: {
  name: string;
  summary: string;
  mode: string;
  fields: readonly FieldSpec[];
  invoke(input: unknown, ctx: RequestContext): Promise<unknown>;
}): AgentEndpoint {
  return {
    name: spec.name,
    summary: spec.summary,
    mode: spec.mode,
    fields: spec.fields,
    validate: (input) => validateInput(spec.fields, input),
    invoke: spec.invoke,
  };
}

/** Public describe shape for GET /agents and GET /agents/:name. */
export interface AgentDescribe {
  name: string;
  summary: string;
  mode: string;
  input: Array<{
    name: string;
    type: FieldType;
    required: boolean;
    enum?: readonly string[];
    min?: number;
    max?: number;
    description: string;
  }>;
}

export function describeAgent(a: AgentEndpoint): AgentDescribe {
  return {
    name: a.name,
    summary: a.summary,
    mode: a.mode,
    input: a.fields.map((f) => ({
      name: f.name,
      type: f.type,
      required: f.required,
      ...(f.enum ? { enum: f.enum } : {}),
      ...(f.min !== undefined ? { min: f.min } : {}),
      ...(f.max !== undefined ? { max: f.max } : {}),
      description: f.desc,
    })),
  };
}
