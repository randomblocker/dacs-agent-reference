/**
 * Signing domain for treasury ops: the approval gate's token signatures and
 * the executor's proof-of-execution — same node:crypto ed25519 + canonical
 * JSON discipline as the evalbot ruling signer, under a separate signer
 * class because approvals and proofs are their own signing domains.
 *
 * ProofOfExecution is the portable receipt: { planHash, approvalToken,
 * per-intent tx records with pre/post balances, executor signature }.
 * `verifyProof(proof, plan, keys)` re-checks BOTH signatures, that the
 * proof/token/plan hashes all agree, and that every executed intent was in
 * the approved plan — an executed-but-unplanned intent is detectable cold.
 */
import { createPublicKey, generateKeyPairSync, sign as edSign, verify as edVerify, type KeyObject } from "node:crypto";
import { sha256Hex } from "../oracle-desk/attested-fetch.js";
import { canonicalJson } from "../evalbot/ruling.js";
import { computePlanHash } from "./planner.js";
import type { ApprovalToken, ExecutionPlan, ExecutionResult, ProofOfExecution, ProofVerifyResult } from "./types.js";

// ---------------------------------------------------------------------------
// Signer + raw signature helpers
// ---------------------------------------------------------------------------

export class TreasurySigner {
  private readonly privateKey: KeyObject;
  /** ed25519 SPKI DER, base64. */
  readonly publicKeyB64: string;
  /** Mock DID, stable per signer: did:treasury-<role>:<hash16>. */
  readonly did: string;

  constructor(role: "approver" | "executor") {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    this.privateKey = privateKey;
    this.publicKeyB64 = publicKey.export({ type: "spki", format: "der" }).toString("base64");
    this.did = `did:treasury-${role}:${sha256Hex(this.publicKeyB64).slice(0, 16)}`;
  }

  /** ed25519 over the hash bytes (hex-decoded), base64. */
  signHash(hashHex: string): string {
    return edSign(null, Buffer.from(hashHex, "hex"), this.privateKey).toString("base64");
  }
}

/** Verify an ed25519 signature (base64) over a hex hash's bytes. */
export function verifyHashSignature(hashHex: string, signatureB64: string, publicKeyB64: string): boolean {
  try {
    const publicKey = createPublicKey({ key: Buffer.from(publicKeyB64, "base64"), format: "der", type: "spki" });
    return edVerify(null, Buffer.from(hashHex, "hex"), publicKey, Buffer.from(signatureB64, "base64"));
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Proof build + verify
// ---------------------------------------------------------------------------

export function computeProofHash(proof: Omit<ProofOfExecution, "proofHash" | "signature">): string {
  return sha256Hex(canonicalJson(proof));
}

export function buildProof(result: ExecutionResult, token: ApprovalToken, signer: TreasurySigner): ProofOfExecution {
  if (token.planHash !== result.planHash) {
    throw new Error("approval token does not cover the executed plan");
  }
  const body: Omit<ProofOfExecution, "proofHash" | "signature"> = {
    planHash: result.planHash,
    runId: result.runId,
    approvalToken: token,
    perIntent: result.perIntent,
    startedAt: result.startedAt,
    finishedAt: result.finishedAt,
    executorPublicKey: signer.publicKeyB64,
  };
  const proofHash = computeProofHash(body);
  return { ...body, proofHash, signature: signer.signHash(proofHash) };
}

/**
 * Cold verification against keys the VERIFIER trusts (defaulting to the
 * embedded ones, which are only as trustworthy as wherever the proof came
 * from). Collects all problems rather than stopping at the first.
 */
export function verifyProof(
  proof: ProofOfExecution,
  plan: ExecutionPlan,
  keys: { approverPublicKey?: string; executorPublicKey?: string } = {},
): ProofVerifyResult {
  const problems: string[] = [];
  const approverKey = keys.approverPublicKey ?? proof.approvalToken.approverPublicKey;
  const executorKey = keys.executorPublicKey ?? proof.executorPublicKey;

  // 1. All three hashes must be the same plan.
  const { planHash: embeddedPlanHash, ...planBody } = plan;
  const actualPlanHash = computePlanHash(planBody);
  if (embeddedPlanHash !== actualPlanHash) problems.push("plan.planHash does not match the plan body");
  if (proof.planHash !== actualPlanHash) problems.push("proof.planHash does not match the plan");
  if (proof.approvalToken.planHash !== actualPlanHash) problems.push("approval token covers a different plan");

  // 2. Approval signature.
  if (!verifyHashSignature(proof.approvalToken.planHash, proof.approvalToken.signature, approverKey)) {
    problems.push("approval token signature invalid");
  }

  // 3. Executor signature over the proof body.
  const { proofHash, signature, ...proofBody } = proof;
  if (proofHash !== computeProofHash(proofBody)) {
    problems.push("proofHash does not match the proof body");
  }
  if (!verifyHashSignature(proofHash, signature, executorKey)) {
    problems.push("executor signature invalid");
  }
  if (proof.executorPublicKey !== executorKey) {
    problems.push("proof's embedded executor key differs from the trusted key");
  }

  // 4. Every executed intent must have been in the approved plan.
  const planned = new Set(plan.intents.map((i) => i.intentId));
  const seen = new Set<string>();
  for (const record of proof.perIntent) {
    if (!planned.has(record.intentId)) {
      problems.push(`executed intent ${record.intentId.slice(0, 16)}… was NOT in the approved plan`);
    }
    if (seen.has(record.intentId)) {
      problems.push(`intent ${record.intentId.slice(0, 16)}… appears more than once in the proof`);
    }
    seen.add(record.intentId);
  }

  return { valid: problems.length === 0, problems };
}
