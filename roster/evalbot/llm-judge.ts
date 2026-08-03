/**
 * LLM judge — scores `subjective` criteria via the `claude` CLI.
 *
 * Only invoked when the orchestrator's LLM path is enabled (EVAL_USE_LLM=1
 * or an explicit option). The CLI is instructed to return ONLY a JSON array
 * of per-criterion scores; the output is parsed defensively (fence-stripping,
 * bracket-slicing, clamping, unknown-id filtering) and ANY failure — CLI not
 * on PATH, timeout, garbage output — returns undefined, leaving the criteria
 * unscored. The judge can only score; it never decides the verdict and never
 * touches mechanical results.
 */
import { execFile } from "node:child_process";
import type { Criterion } from "./types.js";

export interface SubjectiveScore {
  /** Integer 0-100. */
  score: number;
  /** One-sentence justification from the judge. */
  reason: string;
}

export type SubjectiveCriterion = Extract<Criterion, { kind: "subjective" }>;

const MAX_DELIVERABLE_CHARS = 20_000;
const MAX_REASON_CHARS = 400;

// ---------------------------------------------------------------------------
// Prompt
// ---------------------------------------------------------------------------

export function buildJudgePrompt(criteria: SubjectiveCriterion[], content: string, context?: string): string {
  const lines: string[] = [];
  lines.push("You are EvalBot's scoring judge. Score the DELIVERABLE below against each criterion.");
  lines.push("Respond with ONLY a JSON array — no prose, no markdown fences, no keys beyond these —");
  lines.push('containing exactly one object per criterion: {"id":"<criterion id>","score":<integer 0-100>,"reason":"<one sentence>"}.');
  lines.push("");
  lines.push("Criteria:");
  for (const c of criteria) {
    lines.push(`- id: ${c.id} — ${c.description}${c.guidance ? ` (guidance: ${c.guidance})` : ""}`);
  }
  if (context) {
    lines.push("");
    lines.push(`Context: ${context}`);
  }
  lines.push("");
  lines.push("DELIVERABLE:");
  lines.push(content.length > MAX_DELIVERABLE_CHARS ? `${content.slice(0, MAX_DELIVERABLE_CHARS)}\n[truncated]` : content);
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Defensive parsing
// ---------------------------------------------------------------------------

/**
 * Parse the judge's raw stdout into a per-criterion score map. Tolerates
 * markdown fences and leading/trailing prose (slices first `[` … last `]`).
 * Entries with unknown ids or non-numeric scores are dropped; scores are
 * clamped to 0-100 and rounded. Returns undefined when nothing usable parsed.
 */
export function parseJudgeOutput(raw: string, expectedIds: readonly string[]): Map<string, SubjectiveScore> | undefined {
  const start = raw.indexOf("[");
  const end = raw.lastIndexOf("]");
  if (start === -1 || end <= start) return undefined;

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.slice(start, end + 1));
  } catch {
    return undefined;
  }
  if (!Array.isArray(parsed)) return undefined;

  const expected = new Set(expectedIds);
  const scores = new Map<string, SubjectiveScore>();
  for (const item of parsed) {
    if (item === null || typeof item !== "object") continue;
    const { id, score, reason } = item as Record<string, unknown>;
    if (typeof id !== "string" || !expected.has(id)) continue;
    if (typeof score !== "number" || !Number.isFinite(score)) continue;
    scores.set(id, {
      score: Math.round(Math.min(100, Math.max(0, score))),
      reason: typeof reason === "string" && reason.length > 0 ? reason.slice(0, MAX_REASON_CHARS) : "(no reason given)",
    });
  }
  return scores.size > 0 ? scores : undefined;
}

// ---------------------------------------------------------------------------
// Judge
// ---------------------------------------------------------------------------

/**
 * Function shape the orchestrator depends on — injectable so tests can fake
 * the judge without a CLI.
 */
export type JudgeFn = (
  criteria: SubjectiveCriterion[],
  content: string,
  context: string | undefined,
  timeoutMs: number,
) => Promise<Map<string, SubjectiveScore> | undefined>;

/**
 * Real judge: `claude -p <prompt>`. Undefined on ANY failure (ENOENT when
 * the CLI is not on PATH, timeout, non-zero exit, unparseable output).
 */
export const claudeCliJudge: JudgeFn = async (criteria, content, context, timeoutMs) => {
  if (criteria.length === 0) return new Map();
  const prompt = buildJudgePrompt(criteria, content, context);
  try {
    const stdout = await new Promise<string>((resolve, reject) => {
      execFile("claude", ["-p", prompt], { timeout: timeoutMs, maxBuffer: 1024 * 1024 }, (err, out) =>
        err ? reject(err) : resolve(out),
      );
    });
    return parseJudgeOutput(stdout, criteria.map((c) => c.id));
  } catch {
    return undefined;
  }
};
