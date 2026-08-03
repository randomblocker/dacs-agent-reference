/**
 * EvalBot — types.
 *
 * EvalBot is an evaluation-for-hire agent CORE: given an EvaluationJob
 * (a rubric + a deliverable), it scores every criterion, aggregates the
 * scored weight, and issues a SIGNED EvaluationRuling that any third party
 * can verify offline. It is the natural counterparty to the procurement
 * butler's `needs-evaluator` acceptance outcome.
 *
 * Two criterion kinds:
 *   - `mechanical`  — deterministic predicates run by the rubric engine.
 *   - `subjective`  — judged by the `claude` CLI when EVAL_USE_LLM=1 and the
 *     CLI is on PATH; otherwise left `unscored`, EXCLUDED from the weighted
 *     aggregate, and the ruling is flagged `mode: "rubric-only"`.
 *
 * No DACS lifecycle wiring. Signing reuses the repo's node:crypto ed25519
 * discipline (see roster/oracle-desk/attested-fetch.ts).
 */

// ---------------------------------------------------------------------------
// Rubric
// ---------------------------------------------------------------------------

export type NumericOp = ">=" | ">" | "<=" | "<" | "==";

/**
 * Deterministic checks the rubric engine can run. `json-path-*` checks parse
 * the deliverable as JSON and walk a dot-path ("a.b.0.c"); `.length` works on
 * both arrays and strings. `custom-predicate` names a function from the
 * PredicateRegistry injected into the engine — the rubric itself stays
 * JSON-serializable.
 */
export type MechanicalCheck =
  | { check: "content-includes"; needle: string }
  | { check: "regex-match"; pattern: string; flags?: string }
  | { check: "min-length"; minChars: number }
  | { check: "max-length"; maxChars: number }
  | { check: "sha256-equals"; expected: string }
  | { check: "json-parses" }
  | { check: "json-path-exists"; path: string }
  | { check: "numeric-threshold"; path: string; op: NumericOp; value: number }
  | { check: "custom-predicate"; name: string };

export type CriterionKind = "mechanical" | "subjective";

export interface CriterionBase {
  /** Unique within the rubric, e.g. "has-findings". */
  id: string;
  description: string;
  /** Relative weight (> 0); weights need not sum to anything particular. */
  weight: number;
}

export type Criterion =
  | (CriterionBase & { kind: "mechanical"; test: MechanicalCheck })
  | (CriterionBase & { kind: "subjective"; guidance?: string });

export interface Rubric {
  /** Ordered criteria; order is preserved in the ruling's perCriterion. */
  criteria: Criterion[];
  /** Accept when the weighted aggregate (0-100) reaches this. */
  acceptThreshold: number;
  /**
   * Half-width of the indeterminate zone around the threshold. When > 0 and
   * |aggregate - acceptThreshold| <= band, the verdict is `indeterminate`
   * (too close to call). Default 0 = no band; aggregate >= threshold accepts.
   */
  indeterminateBand?: number;
}

// ---------------------------------------------------------------------------
// Job
// ---------------------------------------------------------------------------

export interface Deliverable {
  content: string;
  /** Optional human label, echoed nowhere normative. */
  label?: string;
}

export interface EvaluationJob {
  jobId: string;
  rubric: Rubric;
  deliverable: Deliverable;
  /** Free-text background passed to the LLM judge (subjective criteria only). */
  context?: string;
}

// ---------------------------------------------------------------------------
// Custom predicates
// ---------------------------------------------------------------------------

export type PredicateResult = { pass: boolean; detail?: string };
export type CustomPredicate = (content: string) => PredicateResult;
export type PredicateRegistry = Record<string, CustomPredicate>;

// ---------------------------------------------------------------------------
// Ruling
// ---------------------------------------------------------------------------

export interface CriterionResult {
  criterionId: string;
  kind: CriterionKind;
  weight: number;
  /** False = excluded from the weighted aggregate (score is null). */
  scored: boolean;
  /** 0-100 when scored, null when unscored. */
  score: number | null;
  reason: string;
}

export type Verdict = "accept" | "reject" | "indeterminate";

/**
 * "full" = every subjective criterion received an LLM score (or there were
 * none). "rubric-only" = at least one subjective criterion went unscored
 * because the LLM path was disabled or failed.
 */
export type RulingMode = "full" | "rubric-only";

export interface EvaluationRuling {
  jobId: string;
  /** Derived from the evaluator's public key — a stable mock identifier. */
  evaluatorDid: string;
  /** ed25519 SPKI DER, base64 — what the signature verifies against. */
  evaluatorPublicKey: string;
  verdict: Verdict;
  /** Weighted aggregate over SCORED criteria only; null if nothing scored. */
  aggregate: number | null;
  perCriterion: CriterionResult[];
  mode: RulingMode;
  issuedAt: string;
  /** sha256 hex over the canonical JSON of the ruling minus hash+signature. */
  rulingHash: string;
  /** ed25519 over the rulingHash bytes, base64. */
  signature: string;
}

/** The ruling before hashing/signing — everything the hash covers. */
export type UnsignedRuling = Omit<EvaluationRuling, "rulingHash" | "signature">;

// ---------------------------------------------------------------------------
// Ledger
// ---------------------------------------------------------------------------

/** One append-only, hash-chained ledger line (JSONL). */
export interface LedgerEntry {
  /** 1-based, strictly increasing. */
  seq: number;
  /** entryHash of the previous entry; GENESIS_HASH for the first. */
  prevHash: string;
  /** sha256 hex over canonical JSON of { seq, prevHash, ruling }. */
  entryHash: string;
  ruling: EvaluationRuling;
}

export interface LedgerVerifyResult {
  valid: boolean;
  entries: number;
  problems: string[];
}

export interface ReputationSummary {
  totalRulings: number;
  byVerdict: Record<Verdict, number>;
  /**
   * Fraction of DECIDED rulings (accept + reject) that accepted;
   * null when no ruling was decided.
   */
  acceptanceRate: number | null;
  firstIssuedAt: string | null;
  lastIssuedAt: string | null;
}
