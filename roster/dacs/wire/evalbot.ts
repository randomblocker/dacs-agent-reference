/**
 * Wire the evalbot core into the shared DACS seller layer on the pay-dem
 * session rail (Pattern 2) as evaluation-for-hire.
 *
 * EvalBot plays two roles in Build D. This module is the SELLER half: EvalBot
 * sells a signed acceptance ruling on a posted deliverable against a posted
 * weighted rubric (registry.ts §5 — LLM judging OFF, deterministic rubric
 * engine, ed25519-signed ruling). The evaluator-GATE half (the Butler
 * commissioning EvalBot to resolve a `needs-evaluator` verdict) lives in
 * `evaluator.ts` and reuses the same core.
 *
 * Scope is `parameterized` (rubric + deliverable conveyed at session-open) ⇒
 * pay-dem session rail. `observeDelivered` re-runs EvalBot's own `verifyRuling`
 * over the delivered ruling offline — recomputing the ruling hash and checking
 * the ed25519 signature, so any tamper to verdict/aggregate/scores fails.
 */
import { EvalBot, verifyRuling } from "../../evalbot/evalbot.js";
import type { Deliverable as EvalDeliverable, EvaluationRuling, Rubric } from "../../evalbot/types.js";
import { validateRubric } from "../../evalbot/evalbot.js";
import type { WorkCallback } from "../seller-adapter.js";
import type { DeliveryVerifyOptions } from "../verifier.js";
import { readReportMeta, reportMeta } from "./report-meta.js";
import { formatFee, fixedFeeFromPrice } from "./pricing.js";

/** The DACS serviceId under which EvalBot sells signed rulings. */
export const EVALBOT_SERVICE_ID = "evaluation-ruling";
/** The delivery phase advertised (and required by the session terms). */
export const EVALBOT_DELIVERY_PHASE = "deliver-evaluation-ruling";
/** Rubric + deliverable conveyed at session-open ⇒ pay-dem session rail. */
export const EVALBOT_SCOPE = "parameterized" as const;

/** The listing surface EvalBot advertises on the pay-dem rail. */
export function evalBotListingSpec(price: { amount: string; asset: string }) {
  return {
    serviceId: EVALBOT_SERVICE_ID,
    name: "EvalBot - portable, reputation-staked acceptance rulings",
    description:
      `A signed acceptance ruling you don't have to trust: scores a posted ` +
      `deliverable against a weighted rubric and returns an ed25519 verdict ` +
      `that anyone re-derives offline - hash, signature, AND that the verdict ` +
      `follows from the scores. Every ruling appends to a hash-chained ledger, ` +
      `so the evaluator's track record is a verifiable chain, not a claim. ` +
      `Deterministic (LLM judging off). Fee: ${formatFee(price.amount, price.asset)} per ruling.`,
    supportedNegotiation: ["negotiate-fixed-price"],
    supportedPaymentRails: ["pay-dem"],
    supportedDelivery: [EVALBOT_DELIVERY_PHASE],
    /** Uniform-effort desk: flat fee. Structured for a uniform Butler mapping (NOT anchored). */
    fees: fixedFeeFromPrice(price),
  };
}

/**
 * Build EvalBot's work callback over an injected bot (a fresh one per desk
 * keeps a stable evaluator identity across jobs; LLM judging stays off). The
 * buyer conveys `{ rubric, deliverable, context? }`; the ruling is delivered.
 */
export function makeEvalBotWork(bot: EvalBot = new EvalBot({ useLlm: false })): WorkCallback {
  return async (jobId, params) => {
    const rubric = params.rubric as Rubric | undefined;
    const deliverable = params.deliverable as EvalDeliverable | undefined;
    if (!rubric || typeof rubric !== "object") throw new Error("evalbot: params.rubric is required");
    if (!deliverable || typeof deliverable.content !== "string") {
      throw new Error("evalbot: params.deliverable.content must be a string");
    }
    try {
      validateRubric(rubric);
    } catch (err) {
      throw new Error(`evalbot: invalid rubric: ${(err as Error).message}`);
    }
    const context = typeof params.context === "string" ? params.context : undefined;
    const ruling = await bot.evaluate({ jobId, rubric, deliverable, context });
    const meta = reportMeta(ruling);

    return {
      // verdict/mode/counts are JCS-safe; aggregate (may be a float) stays in meta.
      result: {
        verdict: ruling.verdict,
        mode: ruling.mode,
        criteria: ruling.perCriterion.length,
        scored: ruling.perCriterion.filter((c) => c.scored).length,
      },
      deliverableRef: `evalbot:ruling:${ruling.rulingHash}`,
      meta,
    };
  };
}

/**
 * `observeDelivered`: re-run EvalBot's `verifyRuling` over the delivered ruling
 * offline — recompute the canonical ruling hash, verify the ed25519 signature,
 * and confirm the verdict/aggregate/mode are internally consistent with the
 * scores. When the buyer passes the `rubric` they posted at session-open, the
 * full accept/reject verdict is re-derived against it too, so a ruling whose
 * verdict doesn't follow from the rubric is rejected at delivery.
 */
export function evalBotObserveDelivered(rubric?: Rubric): DeliveryVerifyOptions["observeDelivered"] {
  return async (att) => {
    const read = readReportMeta<EvaluationRuling>(att);
    if (!read.ok) return { ok: false, reason: read.reason };
    const verdict = verifyRuling(read.artifact, undefined, rubric);
    return verdict.valid ? { ok: true } : { ok: false, reason: `ruling verification failed: ${verdict.reason}` };
  };
}
