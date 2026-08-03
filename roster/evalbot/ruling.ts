/**
 * Ruling hashing, signing, and third-party verification.
 *
 * rulingHash = sha256 over the CANONICAL JSON (recursively key-sorted,
 * undefined-stripped) of the ruling minus its `rulingHash` and `signature`
 * fields. The signature is ed25519 over the rulingHash bytes — the same
 * node:crypto discipline as the oracle desk's mock attestor, but under a
 * separate signer class because rulings are a different signing domain
 * from fetch attestations.
 *
 * `verifyRuling(ruling, publicKey)` lets a third party check a ruling
 * against a key THEY trust (defaulting to the embedded one, which is only
 * as trustworthy as wherever they got the ruling). Verification recomputes
 * the hash from the ruling body, so any field edit — verdict, aggregate,
 * per-criterion scores — invalidates the signature.
 */
import { createPublicKey, generateKeyPairSync, sign as edSign, verify as edVerify, type KeyObject } from "node:crypto";
import { sha256Hex } from "../oracle-desk/attested-fetch.js";
import type { EvaluationRuling, Rubric, UnsignedRuling } from "./types.js";
import { aggregateScores, decideVerdict } from "./verdict.js";

// ---------------------------------------------------------------------------
// Canonical JSON
// ---------------------------------------------------------------------------

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const v = (value as Record<string, unknown>)[key];
      if (v !== undefined) out[key] = canonicalize(v);
    }
    return out;
  }
  return value;
}

/** Deterministic serialization: recursively sorted keys, arrays in order. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

export function computeRulingHash(unsigned: UnsignedRuling): string {
  return sha256Hex(canonicalJson(unsigned));
}

// ---------------------------------------------------------------------------
// Signer
// ---------------------------------------------------------------------------

export class RulingSigner {
  private readonly privateKey: KeyObject;
  /** ed25519 SPKI DER, base64 — embedded in every ruling. */
  readonly publicKeyB64: string;
  /** Mock DID derived from the public key: stable per signer. */
  readonly did: string;

  constructor() {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    this.privateKey = privateKey;
    this.publicKeyB64 = publicKey.export({ type: "spki", format: "der" }).toString("base64");
    this.did = `did:evalbot:${sha256Hex(this.publicKeyB64).slice(0, 16)}`;
  }

  /** ed25519 over the hash bytes (hex-decoded), base64. */
  signHash(hashHex: string): string {
    return edSign(null, Buffer.from(hashHex, "hex"), this.privateKey).toString("base64");
  }
}

/** Hash + sign an unsigned ruling into the final EvaluationRuling. */
export function signRuling(unsigned: UnsignedRuling, signer: RulingSigner): EvaluationRuling {
  if (unsigned.evaluatorPublicKey !== signer.publicKeyB64) {
    throw new Error("ruling.evaluatorPublicKey does not match the signer's key");
  }
  const rulingHash = computeRulingHash(unsigned);
  return { ...unsigned, rulingHash, signature: signer.signHash(rulingHash) };
}

// ---------------------------------------------------------------------------
// Third-party verification
// ---------------------------------------------------------------------------

export interface VerifyRulingResult {
  valid: boolean;
  reason?: string;
}

/**
 * Check a ruling is INTERNALLY consistent — its verdict/aggregate/mode/scores
 * follow from its own perCriterion — independently of the signature. A valid
 * signature only proves the embedded signer issued this exact ruling; it does
 * NOT prove the ruling's judgment is sound. A buggy or malicious evaluator can
 * sign a ruling whose verdict contradicts its scores, so `verifyRuling` rejects
 * that here rather than fail open.
 *
 * Rubric-free invariants (always checked): score bounds + the scored/null
 * contract, the recomputed weighted aggregate, the mode, and the FORCED-
 * indeterminate rule (null aggregate or majority-unscored ⇒ verdict must be
 * indeterminate). When the caller supplies the `rubric` the ruling was issued
 * against, the FULL verdict (accept vs reject vs band) is re-derived and must
 * match — closing the accept/reject boundary a rubric-free check can't see.
 */
function verifyRulingConsistency(ruling: EvaluationRuling, rubric?: Rubric): VerifyRulingResult {
  for (const c of ruling.perCriterion) {
    if (!Number.isFinite(c.weight) || c.weight <= 0) {
      return { valid: false, reason: `criterion "${c.criterionId}" has non-positive weight ${c.weight}` };
    }
    if (c.scored) {
      if (typeof c.score !== "number" || !Number.isFinite(c.score) || c.score < 0 || c.score > 100) {
        return { valid: false, reason: `criterion "${c.criterionId}" is scored but score ${c.score} is not in 0-100` };
      }
    } else if (c.score !== null) {
      return { valid: false, reason: `criterion "${c.criterionId}" is unscored but carries score ${c.score}` };
    }
  }

  const agg = aggregateScores(ruling.perCriterion);
  if (agg.aggregate !== ruling.aggregate) {
    return { valid: false, reason: `aggregate ${ruling.aggregate} does not match the weighted mean of the scores (${agg.aggregate})` };
  }

  const expectedMode = ruling.perCriterion.some((c) => c.kind === "subjective" && !c.scored) ? "rubric-only" : "full";
  if (ruling.mode !== expectedMode) {
    return { valid: false, reason: `mode "${ruling.mode}" does not match the scored criteria (expected "${expectedMode}")` };
  }

  // Forced-indeterminate: with no scored weight or a majority unscored, the
  // verdict cannot be accept/reject regardless of the (possibly-absent) rubric.
  const unscoredWeight = agg.totalWeight - agg.scoredWeight;
  const mustBeIndeterminate = agg.aggregate === null || unscoredWeight > agg.totalWeight / 2;
  if (mustBeIndeterminate && ruling.verdict !== "indeterminate") {
    return { valid: false, reason: `verdict "${ruling.verdict}" is inconsistent: too little of the rubric was scored to decide (must be indeterminate)` };
  }

  if (rubric) {
    const expected = decideVerdict(agg, rubric);
    if (ruling.verdict !== expected) {
      return { valid: false, reason: `verdict "${ruling.verdict}" does not follow from aggregate ${ruling.aggregate} under the rubric (expected "${expected}")` };
    }
  }

  return { valid: true };
}

/**
 * Verify a ruling end to end: (1) the rulingHash matches the canonical body,
 * (2) the ed25519 signature is valid for `publicKeyB64` (the embedded key by
 * default — only as trustworthy as wherever the caller got the ruling), and
 * (3) the ruling is internally consistent (verdict/aggregate/mode follow from
 * the scores). Pass the `rubric` the ruling was issued against to also
 * re-derive the accept/reject boundary.
 */
export function verifyRuling(
  ruling: EvaluationRuling,
  publicKeyB64: string = ruling.evaluatorPublicKey,
  rubric?: Rubric,
): VerifyRulingResult {
  const { rulingHash, signature, ...unsigned } = ruling;
  const expectedHash = computeRulingHash(unsigned);
  if (rulingHash !== expectedHash) {
    return { valid: false, reason: "rulingHash does not match the canonical ruling body" };
  }
  try {
    const publicKey = createPublicKey({ key: Buffer.from(publicKeyB64, "base64"), format: "der", type: "spki" });
    const ok = edVerify(null, Buffer.from(rulingHash, "hex"), publicKey, Buffer.from(signature, "base64"));
    if (!ok) return { valid: false, reason: "ed25519 signature invalid for the given public key" };
  } catch (err) {
    return { valid: false, reason: `signature verification errored: ${(err as Error).message}` };
  }
  return verifyRulingConsistency(ruling, rubric);
}
