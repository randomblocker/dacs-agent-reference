/**
 * The on-wire negotiation envelope — a structural DACS-3 §8.3.3 `ChannelMessage`
 * carrying one `NegotiationMove` as its body, plus an injectable signer.
 *
 * This is the transport-layer twin of the in-process engine: where
 * `audit-negotiator/negotiate.ts` runs both policies in one process and trusts
 * the `Turn[]` array, here the two policies live in SEPARATE processes and every
 * move crosses a channel as a signed envelope. The envelope shape is verbatim
 * §8.3.3 (channelId, monotonic sequence, sender, type, body, signature) so that
 * swapping today's ed25519-over-messaging-identity signer for a full CCI-keyed
 * `l2ps.channel.ChannelSession` (the DACS-conformant Stage B) is a drop-in — the
 * bytes on the wire don't change shape.
 *
 * The `Signer` is injected so the distributed session loop is testable offline
 * with a trivial signer and runs live with the demosdk ed25519 signer.
 */
import type { NegotiationMove } from "../audit-negotiator/terms.js";
import { assertPositiveAmount, contentHash, signedBytes } from "@kynesyslabs/dacs";
import type { AuditTerms } from "../audit-negotiator/terms.js";

/** A signature bundle carried on the wire (hex-encoded for JSON transport). */
export interface WireSig {
  /** Hex ed25519 signature over the canonical unsigned envelope. */
  signature: string;
  /** Hex public key of the signer (verifier binds this to the expected sender). */
  publicKey: string;
  /** Signer scheme — "ed25519" today; PQC later without shape change. */
  scheme: string;
}

/** DACS-3 §8.3.3 envelope carrying a negotiation move. */
export interface ChannelEnvelope {
  channelId: string;
  /** Monotonic per-channel, starts at 1. */
  sequence: number;
  /** The sender's stable identity (clientId / public-key fingerprint). */
  sender: string;
  sentAt: number;
  type: NegotiationMove["kind"];
  body: WireNegotiationMove;
  signature: WireSig;
}

export type WireNegotiationMove =
  | { kind: "offer" | "counter" | "accept"; terms: { tier: AuditTerms["tier"]; deadline: AuditTerms["deadline"]; price: string }; rationale: string }
  | { kind: "reject"; rationale: string };

export type UnsignedEnvelope = Omit<ChannelEnvelope, "signature">;

/**
 * Deterministic canonical bytes of the unsigned envelope — stable key order so
 * both sides hash identical bytes. (Small, fixed schema; a sorted-key JSON is
 * sufficient and mirrors the JCS discipline the spec uses for anchored data.)
 */
export function canonicalBytes(env: UnsignedEnvelope): Uint8Array {
  return signedBytes(
    "dacs-channelmsg:v1:",
    contentHash(env as unknown as Record<string, unknown>),
  );
}

function encodeMove(move: NegotiationMove): WireNegotiationMove {
  if (move.kind === "reject") return move;
  return {
    ...move,
    terms: { ...move.terms, price: assertPositiveAmount(String(move.terms.price)) },
  };
}

/** Decode the wire's CD-1 price into the numeric policy engine boundary. */
export function decodeMove(move: WireNegotiationMove): NegotiationMove | null {
  if (move.kind === "reject") return move;
  try {
    const amount = assertPositiveAmount(move.terms.price);
    const price = Number(amount);
    if (!Number.isFinite(price) || price <= 0) return null;
    return { ...move, terms: { ...move.terms, price } };
  } catch {
    return null;
  }
}

/** Stable JSON with recursively sorted object keys. */
export function stableStringify(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(stableStringify).join(",")}]`;
  const keys = Object.keys(v as Record<string, unknown>).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify((v as Record<string, unknown>)[k])}`).join(",")}}`;
}

// ---------------------------------------------------------------------------
// Signer (injectable)
// ---------------------------------------------------------------------------

/**
 * Signs the canonical envelope bytes and verifies inbound envelopes. The session
 * loop depends only on this interface, so tests use a trivial signer and live
 * peers use the demosdk ed25519 signer (see `demosdk.ts`).
 */
export interface Signer {
  /** This signer's stable primary ClaimReference — becomes `sender`. */
  readonly id: string;
  sign(canonical: Uint8Array): Promise<WireSig>;
  /**
   * Verify a signature over `canonical`. `expectedSenderId` is the id the
   * transcript expects this move to come from; a signer MAY additionally bind
   * the sig's public key to that id (the live signer does).
   */
  verify(canonical: Uint8Array, sig: WireSig, expectedSenderId: string): Promise<boolean>;
}

/** Build + sign an outbound envelope. */
export async function sealEnvelope(
  signer: Signer,
  channelId: string,
  sequence: number,
  move: NegotiationMove,
  now: number,
): Promise<ChannelEnvelope> {
  const unsigned: UnsignedEnvelope = {
    channelId,
    sequence,
    sender: signer.id,
    sentAt: now,
    type: move.kind,
    body: encodeMove(move),
  };
  const signature = await signer.sign(canonicalBytes(unsigned));
  return { ...unsigned, signature };
}

export interface OpenVerdict {
  ok: boolean;
  reason?: string;
}

/**
 * Verify an inbound envelope against the four §8.3.3 invariants the transport is
 * responsible for: correct channel, the expected monotonic sequence, the
 * expected sender, and a valid signature over the canonical bytes.
 */
export async function openEnvelope(
  signer: Signer,
  env: ChannelEnvelope,
  expect: { channelId: string; sequence: number; sender: string },
): Promise<OpenVerdict> {
  if (env.channelId !== expect.channelId) return { ok: false, reason: `wrong channel ${env.channelId}` };
  if (env.sequence !== expect.sequence) return { ok: false, reason: `sequence ${env.sequence} != expected ${expect.sequence}` };
  if (env.sender !== expect.sender) return { ok: false, reason: `sender ${env.sender} != expected ${expect.sender}` };
  if (env.type !== env.body?.kind) return { ok: false, reason: `type/body mismatch` };
  let canonical: Uint8Array;
  try {
    canonical = canonicalBytes({
      channelId: env.channelId,
      sequence: env.sequence,
      sender: env.sender,
      sentAt: env.sentAt,
      type: env.type,
      body: env.body,
    });
  } catch {
    return { ok: false, reason: "signature invalid" };
  }
  const ok = await signer.verify(canonical, env.signature, expect.sender);
  if (!ok) return { ok: false, reason: "signature invalid" };
  if (!decodeMove(env.body)) return { ok: false, reason: "invalid negotiation body" };
  return { ok: true };
}
