/**
 * Due-Diligence Researcher — types.
 *
 * The DD researcher is a buyer-side agent CORE: given a subject (an npm
 * package or a crypto token), it gathers evidence from REAL keyless public
 * sources through the shared AttestedFetchPort, derives typed findings with
 * deterministic rules, and emits a report where EVERY finding cites the
 * evidence items it was derived from. A finding with zero citations is
 * impossible by construction: the `citations` field is a non-empty tuple
 * type and `makeFinding` (the only constructor the rules use) throws on an
 * empty list at runtime too, so JSON smuggled past the compiler still fails.
 *
 * Attestation machinery is reused from the oracle desk (MOCK DAHR — an
 * ephemeral ed25519 signer, loudly labeled; real DAHR is a port swap there,
 * and this module inherits it for free). No DACS lifecycle wiring.
 */
import type { MockDahrAttestation } from "../oracle-desk/types.js";

export type { AttestedFetchPort, AttestedFetchResult, MockDahrAttestation } from "../oracle-desk/types.js";

// ---------------------------------------------------------------------------
// Subjects
// ---------------------------------------------------------------------------

export type Subject =
  | { kind: "npm-package"; name: string }
  | { kind: "crypto-token"; id: string };

export function subjectLabel(subject: Subject): string {
  return subject.kind === "npm-package"
    ? `npm package "${subject.name}"`
    : `crypto token "${subject.id}" (CoinGecko)`;
}

/** Filesystem-safe slug for the out/ directory name. */
export function subjectSlug(subject: Subject): string {
  const raw = subject.kind === "npm-package" ? subject.name : subject.id;
  return `${subject.kind}-${raw.toLowerCase().replace(/[^a-z0-9.-]+/g, "_")}`;
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

export type EvidenceSource =
  | "npm-registry" // https://registry.npmjs.org/<name>
  | "npm-downloads" // https://api.npmjs.org/downloads/point/last-month/<name>
  | "github-advisories" // https://api.github.com/advisories?ecosystem=npm&affects=<name>
  | "github-repo" // https://api.github.com/repos/<owner>/<repo>
  | "coingecko-coin"; // https://api.coingecko.com/api/v3/coins/<id>

/**
 * One attested upstream observation. `extracted` carries the typed fields
 * the finding rules read; the raw `body` is kept only when small (large
 * upstream documents — the npm registry doc easily exceeds 1 MB — are
 * represented by `bodyHash` alone). The attestation signature covers
 * url|fetchedAt|bodyHash, so a body-free item remains verifiable.
 */
export interface EvidenceItem {
  /** "E1", "E2", … — what findings cite. */
  id: string;
  source: EvidenceSource;
  url: string;
  /** ISO-8601 timestamp of the fetch. */
  fetchedAt: string;
  /** Upstream HTTP status. */
  status: number;
  /** True iff status was 2xx AND the body parsed into the expected shape. */
  ok: boolean;
  /** sha256 hex of the raw response body. */
  bodyHash: string;
  /** Raw body, present only when ≤ MAX_STORED_BODY_CHARS. */
  body?: string;
  /** Fields the rules read; `{ unavailable: true, … }` when not ok. */
  extracted: Record<string, unknown>;
  attestation: MockDahrAttestation;
}

/**
 * A source that could not be reached at all (network-level failure — the
 * fetch threw, so there is nothing to attest). HTTP-level failures (403
 * rate limit, 404, 5xx) DO produce an EvidenceItem with `ok: false`, so
 * even the unavailability is attested and citable.
 */
export interface SourceGap {
  source: EvidenceSource;
  url: string;
  reason: string;
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

export type Severity = "info" | "caution" | "red-flag";

export const SEVERITY_ORDER: readonly Severity[] = ["red-flag", "caution", "info"];

/** Non-empty citation list — the type-level half of the zero-citation ban. */
export type Citations = [string, ...string[]];

export interface Finding {
  /** "F1", "F2", … */
  id: string;
  /** Stable rule identifier, e.g. "npm-deprecated". */
  rule: string;
  severity: Severity;
  title: string;
  detail: string;
  /** EvidenceItem ids this finding is derived from. NEVER empty. */
  citations: Citations;
}

/**
 * The only sanctioned Finding constructor. Throws if `citations` is empty —
 * combined with the non-empty tuple type this makes an uncited finding
 * impossible by construction, not just by convention.
 */
export function makeFinding(input: {
  id: string;
  rule: string;
  severity: Severity;
  title: string;
  detail: string;
  citations: readonly string[];
}): Finding {
  if (input.citations.length === 0) {
    throw new Error(`finding ${input.id} (${input.rule}) has zero citations — every claim must cite evidence`);
  }
  return {
    id: input.id,
    rule: input.rule,
    severity: input.severity,
    title: input.title,
    detail: input.detail,
    citations: [...input.citations] as Citations,
  };
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

export interface ReportSummary {
  text: string;
  /**
   * "deterministic" = template over finding counts/titles (default,
   * reproducible). "llm" = `claude -p` prose over the findings JSON —
   * presentation only, findings are the substance either way.
   */
  method: "deterministic" | "llm";
}

export interface DDReport {
  version: 1;
  subject: Subject;
  generatedAt: string;
  evidence: EvidenceItem[];
  gaps: SourceGap[];
  findings: Finding[];
  summary: ReportSummary;
}

/** Result of the third-party re-verification of an emitted report. */
export interface VerifyReportResult {
  valid: boolean;
  problems: string[];
  /** How many attestation signatures were re-verified. */
  evidenceChecked: number;
  /** How many findings had their citations resolved. */
  findingsChecked: number;
}
