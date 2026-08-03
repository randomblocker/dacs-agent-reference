/**
 * EvalBot as the evaluator gate — Build D, Part 2.
 *
 * Build C's Butler ends non-mechanically-checkable purchases (DD reports,
 * audits, screenings) at `needs-evaluator`: the delivery VERIFIED, but the
 * Butler has no mechanical `AcceptancePolicy` to decide accept/reject. This
 * module closes that gap: `resolveWithEvaluator(outcome)` commissions EvalBot
 * to produce a SIGNED `EvaluationRuling` against a rubric derived from the
 * listing/deliverable, re-verifies the ruling offline, and flips acceptance to
 * `accepted` / `rejected` from the verdict.
 *
 * Integration is DIRECT (EvalBot's core, deterministic, LLM off) — the
 * requirement. The recursive-purchase variant (the Butler BUYS EvalBot's
 * evaluation service over the same rails) is available too: EvalBot is a
 * first-class seller via `wire/evalbot.ts`, so a caller can instead run a
 * second DACS session whose deliverable IS the ruling and feed that ruling
 * here. We keep the gate itself direct so a `needs-evaluator` verdict always
 * resolves without a second settlement in the loop.
 */
import { EvalBot, verifyRuling } from "../../evalbot/evalbot.js";
import type { EvaluationRuling, PredicateRegistry, Rubric } from "../../evalbot/types.js";
import { scanFileContent } from "../../sec-audit/scanner.js";
import type { PostedFile } from "./sec-audit.js";
import type { PurchaseOutcome } from "./butler.js";

/** How the evaluator gate resolved a `needs-evaluator` outcome. */
export interface EvaluatorResolution extends PurchaseOutcome {
  /** The signed ruling EvalBot issued. */
  ruling: EvaluationRuling;
  /** EvalBot's own `verifyRuling` re-check passed (hash + ed25519 signature). */
  rulingValid: boolean;
  /** Final acceptance after the gate: accept ⇒ accepted, else rejected. */
  finalVerdict: "accepted" | "rejected";
  /** The rubric the deliverable was judged against. */
  rubric: Rubric;
}

export interface EvaluatorOptions {
  /** Reuse one EvalBot to keep a stable evaluator identity. Default: fresh, LLM off. */
  evalbot?: EvalBot;
  /** Override the derived rubric entirely. */
  rubric?: Rubric;
  /**
   * The serviceId behind the deliverable — used to derive the default rubric's
   * service-specific structural criterion. Falls back to a generic rubric.
   */
  serviceId?: string;
}

/**
 * A JSON dot-path that a VALID delivered report of each service must expose.
 * The evaluator gate uses it as a mechanical structural criterion — a truthful
 * report passes, a truncated/garbled one fails the JSON parse and rejects.
 */
const SERVICE_REQUIRED_PATH: Record<string, string> = {
  "dd-research": "findings",
  "site-audit": "categories",
  "sec-audit": "seal",
  "compliance-screening": "verdict",
  "treasury-plan": "planHash",
  "dep-upgrade-plan": "plan",
};

/**
 * Derive a deterministic, mechanical rubric for a judgment deliverable. All
 * criteria are mechanical (no LLM), so the ruling is fully scored and stable:
 * a well-formed report scores 100 and accepts; a malformed one fails the JSON
 * checks and rejects.
 */
export function rubricForOutcome(opts: { serviceId?: string } = {}): Rubric {
  const path = opts.serviceId ? SERVICE_REQUIRED_PATH[opts.serviceId] : undefined;
  const criteria: Rubric["criteria"] = [
    { id: "parses", description: "deliverable is valid JSON", kind: "mechanical", weight: 3, test: { check: "json-parses" } },
    { id: "substantive", description: "deliverable is substantive", kind: "mechanical", weight: 1, test: { check: "min-length", minChars: 50 } },
  ];
  if (path) {
    criteria.push({
      id: "well-formed",
      description: `deliverable exposes required field "${path}"`,
      kind: "mechanical",
      weight: 2,
      test: { check: "json-path-exists", path },
    });
  }
  return { criteria, acceptThreshold: 60 };
}

/**
 * Domain-specific acceptance policy for a security report over posted source.
 * Cryptographic delivery verification proves provenance/integrity; this extra
 * predicate proves that every deterministic finding independently reproduced
 * from the exact buyer input is present in the delivered report.
 */
export function securityAuditEvaluationPolicy(files: readonly PostedFile[]): {
  rubric: Rubric;
  predicates: PredicateRegistry;
} {
  const expected = files.flatMap((file) =>
    scanFileContent(file.path, Buffer.from(file.content, "utf8"), "auto").hits
      .map((hit) => `${hit.ruleId}\u0000${hit.file}\u0000${hit.line}`),
  );
  const predicateName = "security-audit-covers-posted-input";
  const base = rubricForOutcome({ serviceId: "sec-audit" });
  const rubric: Rubric = {
    ...base,
    criteria: [
      ...base.criteria,
      {
        id: "deterministic-coverage",
        description: "report includes every deterministic finding reproduced from the posted input",
        kind: "mechanical",
        weight: 7,
        test: { check: "custom-predicate", name: predicateName },
      },
    ],
    acceptThreshold: 70,
  };
  const predicates: PredicateRegistry = {
    [predicateName]: (content) => {
      let value: unknown;
      try { value = JSON.parse(content); }
      catch { return { pass: false, detail: "security report is not valid JSON" }; }
      if (!value || typeof value !== "object" || Array.isArray(value)) {
        return { pass: false, detail: "security report is not an object" };
      }
      const findings = (value as { findings?: unknown }).findings;
      if (!Array.isArray(findings)) return { pass: false, detail: "security report findings is not an array" };
      const delivered = new Set(findings.flatMap((finding) => {
        if (!finding || typeof finding !== "object" || Array.isArray(finding)) return [];
        const row = finding as { ruleId?: unknown; file?: unknown; line?: unknown };
        return typeof row.ruleId === "string" && typeof row.file === "string" && Number.isSafeInteger(row.line)
          ? [`${row.ruleId}\u0000${row.file}\u0000${row.line}`]
          : [];
      }));
      const missing = expected.filter((key) => !delivered.has(key));
      return missing.length === 0
        ? { pass: true, detail: `report covers all ${expected.length} independently reproduced deterministic findings` }
        : { pass: false, detail: `report omits ${missing.length}/${expected.length} independently reproduced deterministic findings` };
    },
  };
  return { rubric, predicates };
}

/**
 * Commission EvalBot to resolve a `needs-evaluator` purchase into an
 * accept/reject decision. Verifies the delivery first was already done by the
 * bridge; here we (1) build/accept a rubric, (2) run EvalBot's deterministic
 * evaluation over the delivered content, (3) re-verify the signed ruling, and
 * (4) flip acceptance from the verdict.
 */
export async function resolveWithEvaluator(
  outcome: PurchaseOutcome,
  opts: EvaluatorOptions = {},
): Promise<EvaluatorResolution> {
  const bot = opts.evalbot ?? new EvalBot({ useLlm: false });
  const rubric = opts.rubric ?? rubricForOutcome({ serviceId: opts.serviceId });

  const ruling = await bot.evaluate({
    jobId: `${outcome.jobId}-eval`,
    rubric,
    deliverable: { content: outcome.deliverable.content },
  });
  // Re-verify against the SAME rubric the gate judged with: this confirms the
  // signed verdict actually follows from the rubric + scores, not merely that
  // it is signed — the gate flips acceptance (and money) on this verdict.
  const rulingValid = verifyRuling(ruling, undefined, rubric).valid;
  const accepted = rulingValid && ruling.verdict === "accept";

  const trail = [
    ...outcome.trail,
    `evalbot commissioned (${bot.evaluatorDid}) verdict=${ruling.verdict} aggregate=${ruling.aggregate ?? "n/a"} rulingValid=${rulingValid}`,
    `evaluator gate ⇒ ${accepted ? "accepted" : "rejected"}`,
  ];

  return {
    ...outcome,
    // The gate has now decided: reflect it on the standard outcome fields.
    accepted,
    needsEvaluator: false,
    trail,
    ruling,
    rulingValid,
    rubric,
    finalVerdict: accepted ? "accepted" : "rejected",
  };
}
