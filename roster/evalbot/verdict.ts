/**
 * Verdict math — the pure, deterministic core shared by the orchestrator
 * (`evalbot.ts`, which produces rulings) and the verifier (`ruling.ts`, which
 * re-derives them). Split into its own module so the verifier can recompute a
 * ruling's aggregate + verdict WITHOUT importing the orchestrator (which would
 * be a cycle: evalbot.ts → ruling.ts → verdict.ts, never back).
 *
 * A ruling is only as trustworthy as this being reproducible: given the same
 * perCriterion scores and rubric, aggregate and verdict are a pure function.
 * `verifyRuling` leans on that to reject an internally-inconsistent ruling
 * (verdict/aggregate/mode that don't follow from the scores) even when it
 * carries a valid signature.
 */
import type { CriterionResult, Rubric, Verdict } from "./types.js";

/** Round to 2 decimal places (the aggregate's canonical precision). */
export const round2 = (n: number): number => Math.round(n * 100) / 100;

export interface AggregationResult {
  /** Weighted mean over scored criteria, 2dp; null when nothing scored. */
  aggregate: number | null;
  totalWeight: number;
  scoredWeight: number;
}

/** Weighted mean over the SCORED criteria; unscored weight is tracked, not counted. */
export function aggregateScores(results: CriterionResult[]): AggregationResult {
  let totalWeight = 0;
  let scoredWeight = 0;
  let weightedSum = 0;
  for (const r of results) {
    totalWeight += r.weight;
    if (r.scored && r.score !== null) {
      scoredWeight += r.weight;
      weightedSum += r.score * r.weight;
    }
  }
  return {
    aggregate: scoredWeight > 0 ? round2(weightedSum / scoredWeight) : null,
    totalWeight,
    scoredWeight,
  };
}

/**
 * Decide the verdict from an aggregation + rubric:
 *   1. indeterminate when nothing scored, or unscored weight exceeds half the
 *      total (too much of the rubric went unjudged to decide);
 *   2. indeterminate when an indeterminateBand is set and the aggregate lands
 *      within it of the threshold (too close to call);
 *   3. accept when aggregate >= acceptThreshold, else reject.
 */
export function decideVerdict(agg: AggregationResult, rubric: Rubric): Verdict {
  const unscoredWeight = agg.totalWeight - agg.scoredWeight;
  if (agg.aggregate === null || unscoredWeight > agg.totalWeight / 2) return "indeterminate";
  const band = rubric.indeterminateBand ?? 0;
  if (band > 0 && Math.abs(agg.aggregate - rubric.acceptThreshold) <= band) return "indeterminate";
  return agg.aggregate >= rubric.acceptThreshold ? "accept" : "reject";
}
