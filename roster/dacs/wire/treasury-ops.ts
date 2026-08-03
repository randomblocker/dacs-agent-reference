/**
 * Wire the treasury-ops core into the shared DACS seller layer on the pay-dem
 * session rail (Pattern 2), plan+approve-ONLY safe slice.
 *
 * The treasury agent's executor moves money on-chain — never sold blind. The
 * DACS listing sells the read-only slice the gateway exposes: a deterministic
 * `plan()` over a posted policy + balance snapshot, gated by the
 * deterministic `approve()` gate (which re-derives every check from the policy
 * and signs a token). NO ChainPort, no execution (registry.ts §7).
 *
 * Scope is `parameterized` (policy + balances conveyed at session-open) ⇒
 * pay-dem session rail. `observeDelivered` re-derives the plan hash from the
 * plan body and re-verifies the approver's ed25519 token signature offline —
 * the same cold check `verifyProof` runs on the approval half.
 */
import { computePlanHash, plan as treasuryPlan } from "../../treasury-ops/planner.js";
import { approve as treasuryApprove } from "../../treasury-ops/approval.js";
import { TreasurySigner, verifyHashSignature } from "../../treasury-ops/proof.js";
import type { ApprovalResult, BalanceSnapshot, ExecutionPlan, TreasuryPolicy } from "../../treasury-ops/types.js";
import type { WorkCallback } from "../seller-adapter.js";
import type { DeliveryVerifyOptions } from "../verifier.js";
import { readReportMeta, reportMeta } from "./report-meta.js";
import { formatFee, fixedFeeFromPrice } from "./pricing.js";

/** The DACS serviceId under which the treasury desk sells plan+approval. */
export const TREASURY_SERVICE_ID = "treasury-plan";
/** The delivery phase advertised (and required by the session terms). */
export const TREASURY_DELIVERY_PHASE = "deliver-treasury-plan";
/** Params (policy + balances) conveyed at session-open ⇒ pay-dem session rail. */
export const TREASURY_SCOPE = "parameterized" as const;

/** The listing surface the treasury desk advertises on the pay-dem rail. */
export function treasuryListingSpec(price: { amount: string; asset: string }) {
  return {
    serviceId: TREASURY_SERVICE_ID,
    name: "Treasury Ops Desk - signed payroll & rebalance plans",
    description:
      `Computes a payroll or rebalance plan over a posted policy and balances and ` +
      `returns it with a signed approval. Plan and approve only - never executes ` +
      `on-chain. Fee: ${formatFee(price.amount, price.asset)} per plan.`,
    supportedNegotiation: ["negotiate-fixed-price"],
    supportedPaymentRails: ["pay-dem"],
    supportedDelivery: [TREASURY_DELIVERY_PHASE],
    /** Uniform-effort desk: flat fee. Structured for a uniform Butler mapping (NOT anchored). */
    fees: fixedFeeFromPrice(price),
  };
}

/** The safe-slice deliverable: the plan and its approval decision. */
export interface TreasuryDeliverable {
  plan: ExecutionPlan;
  approval: ApprovalResult;
}

/**
 * Build the treasury work callback over an injected approver signer (a fresh
 * one per desk keeps a stable approver identity across jobs). The buyer conveys
 * `{ policy, balances }`; the deliverable is `{ plan, approval }`.
 */
export function makeTreasuryWork(approver: TreasurySigner = new TreasurySigner("approver")): WorkCallback {
  return async (jobId, params) => {
    const policy = params.policy as TreasuryPolicy | undefined;
    const balances = params.balances as BalanceSnapshot | undefined;
    if (!policy || typeof policy !== "object") throw new Error("treasury: params.policy is required");
    if (!balances || typeof balances !== "object") throw new Error("treasury: params.balances is required");

    let execPlan: ExecutionPlan;
    try {
      execPlan = treasuryPlan(policy, balances, { runId: jobId });
    } catch (err) {
      throw new Error(`treasury: plan rejected: ${(err as Error).message}`);
    }
    const approval = treasuryApprove(execPlan, policy, approver);
    const deliverable: TreasuryDeliverable = { plan: execPlan, approval };
    const meta = reportMeta(deliverable);

    return {
      // Amounts are integer base units already; counts/flags are JCS-safe.
      result: {
        policyId: execPlan.policyId,
        intents: execPlan.intents.length,
        shortfalls: execPlan.shortfalls.length,
        approved: approval.approved,
      },
      deliverableRef: `treasury:plan:${execPlan.planHash}`,
      meta,
    };
  };
}

/**
 * `observeDelivered`: re-derive the plan hash from the plan body and, when the
 * plan was approved, re-verify the approver's ed25519 token signature over that
 * hash — offline, from the delivered artifact alone.
 */
export function treasuryObserveDelivered(): DeliveryVerifyOptions["observeDelivered"] {
  return async (att) => {
    const read = readReportMeta<TreasuryDeliverable>(att);
    if (!read.ok) return { ok: false, reason: read.reason };
    const { plan, approval } = read.artifact;
    if (!plan || typeof plan.planHash !== "string" || !Array.isArray(plan.intents)) {
      return { ok: false, reason: "deliverable is not a structurally-valid ExecutionPlan" };
    }
    const { planHash, ...body } = plan;
    if (computePlanHash(body) !== planHash) {
      return { ok: false, reason: "planHash does not match the plan body" };
    }
    if (!approval || typeof approval.approved !== "boolean") {
      return { ok: false, reason: "deliverable carries no approval decision" };
    }
    if (approval.approved) {
      const token = approval.token;
      if (token.planHash !== planHash) return { ok: false, reason: "approval token covers a different plan" };
      if (!verifyHashSignature(token.planHash, token.signature, token.approverPublicKey)) {
        return { ok: false, reason: "approval token signature invalid" };
      }
    }
    return { ok: true };
  };
}
