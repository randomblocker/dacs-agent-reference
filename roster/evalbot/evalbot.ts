/**
 * EvalBot — orchestrating core.
 *
 * evaluate(job): run every mechanical criterion through the rubric engine
 * (pass -> 100, fail -> 0), score subjective criteria via the LLM judge when
 * the LLM path is enabled, aggregate the SCORED weight, and issue a signed
 * EvaluationRuling.
 *
 * Verdict rules, in order:
 *   1. indeterminate — when unscored weight exceeds 50% of total weight
 *      (too much of the rubric went unjudged to decide), or nothing scored.
 *   2. indeterminate — when indeterminateBand > 0 and the aggregate lands
 *      within that band of acceptThreshold (too close to call).
 *   3. accept when aggregate >= acceptThreshold, else reject.
 *
 * The LLM path is enabled by EVAL_USE_LLM=1 (or `useLlm: true`); when it is
 * disabled or fails, subjective criteria are `unscored`, EXCLUDED from the
 * aggregate, and the ruling carries `mode: "rubric-only"`.
 */
import { claudeCliJudge, type JudgeFn, type SubjectiveCriterion } from "./llm-judge.js";
import { runMechanicalCheck } from "./rubric-engine.js";
import { RulingSigner, signRuling } from "./ruling.js";
import { aggregateScores, decideVerdict } from "./verdict.js";
import type {
  CriterionResult,
  EvaluationJob,
  EvaluationRuling,
  PredicateRegistry,
  Rubric,
  UnsignedRuling,
} from "./types.js";

export { verifyRuling } from "./ruling.js";
// Verdict math lives in ./verdict.js (shared with the verifier); re-exported
// here so callers/tests keep a single import surface for the evaluator core.
export { aggregateScores, decideVerdict, round2, type AggregationResult } from "./verdict.js";

// ---------------------------------------------------------------------------
// Rubric validation
// ---------------------------------------------------------------------------

export function validateRubric(rubric: Rubric): void {
  if (rubric.criteria.length === 0) throw new Error("rubric has no criteria");
  const seen = new Set<string>();
  for (const c of rubric.criteria) {
    if (seen.has(c.id)) throw new Error(`duplicate criterion id "${c.id}"`);
    seen.add(c.id);
    if (!Number.isFinite(c.weight) || c.weight <= 0) {
      throw new Error(`criterion "${c.id}" has non-positive weight ${c.weight}`);
    }
  }
  if (!Number.isFinite(rubric.acceptThreshold) || rubric.acceptThreshold < 0 || rubric.acceptThreshold > 100) {
    throw new Error(`acceptThreshold ${rubric.acceptThreshold} is outside 0-100`);
  }
  const band = rubric.indeterminateBand ?? 0;
  if (!Number.isFinite(band) || band < 0) throw new Error(`indeterminateBand ${band} must be >= 0`);
}

// ---------------------------------------------------------------------------
// EvalBot
// ---------------------------------------------------------------------------

export interface EvalBotOptions {
  /** Named predicates that `custom-predicate` checks resolve against. */
  predicates?: PredicateRegistry;
  /** Provide a signer to keep one identity across rulings. Default: fresh. */
  signer?: RulingSigner;
  /** Clock injection for deterministic tests. Default: () => new Date(). */
  now?: () => Date;
  /** Enable the LLM judge. Default: process.env.EVAL_USE_LLM === "1". */
  useLlm?: boolean;
  /** Kill the judge call after this long. Default 45s. */
  llmTimeoutMs?: number;
  /** Judge implementation (injectable for tests). Default: `claude -p`. */
  judge?: JudgeFn;
}

export class EvalBot {
  readonly signer: RulingSigner;
  private readonly predicates: PredicateRegistry;
  private readonly judge: JudgeFn;

  constructor(private readonly opts: EvalBotOptions = {}) {
    this.signer = opts.signer ?? new RulingSigner();
    this.predicates = opts.predicates ?? {};
    this.judge = opts.judge ?? claudeCliJudge;
  }

  get evaluatorDid(): string {
    return this.signer.did;
  }

  async evaluate(job: EvaluationJob): Promise<EvaluationRuling> {
    validateRubric(job.rubric);
    const content = job.deliverable.content;

    // Subjective scores first (one judge call covers all subjective criteria).
    const useLlm = this.opts.useLlm ?? process.env.EVAL_USE_LLM === "1";
    const subjective = job.rubric.criteria.filter((c): c is SubjectiveCriterion => c.kind === "subjective");
    const llmScores =
      useLlm && subjective.length > 0
        ? await this.judge(subjective, content, job.context, this.opts.llmTimeoutMs ?? 45_000)
        : undefined;

    let subjectiveUnscored = false;
    const perCriterion: CriterionResult[] = job.rubric.criteria.map((c) => {
      if (c.kind === "mechanical") {
        const outcome = runMechanicalCheck(c.test, content, this.predicates);
        return {
          criterionId: c.id,
          kind: c.kind,
          weight: c.weight,
          scored: true,
          score: outcome.pass ? 100 : 0,
          reason: outcome.reason,
        };
      }
      const judged = llmScores?.get(c.id);
      if (judged === undefined) {
        subjectiveUnscored = true;
        return {
          criterionId: c.id,
          kind: c.kind,
          weight: c.weight,
          scored: false,
          score: null,
          reason: useLlm ? "unscored — LLM judge unavailable or returned no score" : "unscored — LLM judging disabled (EVAL_USE_LLM != 1)",
        };
      }
      return { criterionId: c.id, kind: c.kind, weight: c.weight, scored: true, score: judged.score, reason: judged.reason };
    });

    const agg = aggregateScores(perCriterion);
    const unsigned: UnsignedRuling = {
      jobId: job.jobId,
      evaluatorDid: this.signer.did,
      evaluatorPublicKey: this.signer.publicKeyB64,
      verdict: decideVerdict(agg, job.rubric),
      aggregate: agg.aggregate,
      perCriterion,
      mode: subjectiveUnscored ? "rubric-only" : "full",
      issuedAt: (this.opts.now?.() ?? new Date()).toISOString(),
    };
    return signRuling(unsigned, this.signer);
  }
}
