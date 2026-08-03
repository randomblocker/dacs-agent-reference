/**
 * Security-Audit Agent — types.
 *
 * Defensive static-analysis audits over a target directory: repo checks
 * (secrets, dangerous code, dependency advisories) and Solidity heuristics
 * over .sol files. Every scanned file gets an attested content record
 * (path, sha256, size — body hash-only), so findings bind to the exact
 * content that was scanned; `verifyReport` can later re-hash the target and
 * flag drift.
 *
 * Citation discipline is the dd-researcher's: a finding's `citations` is a
 * non-empty tuple of attested-file-record ids and `makeFinding` (the only
 * constructor) throws on an empty list, so an uncited finding is impossible
 * by construction. Production seller reports use the Auditor's persistent
 * DACS identity; offline demos may use the oracle desk's loudly-labelled mock.
 *
 * No DACS lifecycle wiring. Node builtins only.
 */
import type { MockDahrAttestation } from "../oracle-desk/types.js";

export type { MockDahrAttestation } from "../oracle-desk/types.js";

/**
 * Persistent identity evidence over private, buyer-posted content.
 *
 * This deliberately is NOT labelled DAHR: SR-3/DAHR attests public HTTP
 * fetches, while publishing buyer source merely to make it fetchable would be
 * a privacy regression. The digest is signed by the seller's DACS DID and the
 * enclosing delivery artifact is anchored through DACS-4/SR-2.
 */
export interface DacsSellerAttestation {
  scheme: "DACS-SELLER-ed25519";
  note: string;
  digest: string;
  /** base64url ed25519 signature over the 64-byte UTF-8 hex digest string. */
  signature: string;
  /** Self-describing seller DID containing the ed25519 public key. */
  publicKey: string;
}

export type SecAuditAttestation = MockDahrAttestation | DacsSellerAttestation;

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

export type AuditMode = "auto" | "repo" | "solidity";

export interface AuditInput {
  /** Directory to audit (absolute or cwd-relative). */
  targetDir: string;
  /**
   * "repo" = repo rules + dependency advisories; "solidity" = .sol
   * heuristics only; "auto" (default) = both, dispatched per file.
   */
  mode?: AuditMode;
}

// ---------------------------------------------------------------------------
// Attested file records
// ---------------------------------------------------------------------------

/**
 * One scanned file, content-bound: sha256 + byte size are what the
 * attestation signs (body is never stored — hash-only, like the
 * dd-researcher's oversized bodies). Findings cite these ids.
 */
export interface AttestedFileRecord {
  /** "A1", "A2", … — what findings cite. */
  id: string;
  /** Path relative to the audited directory, posix separators. */
  path: string;
  /** sha256 hex over the raw file bytes. */
  sha256: string;
  /** File size in bytes. */
  size: number;
  /** ISO-8601 timestamp of the read. */
  attestedAt: string;
  /** Content evidence over `file:<path>|attestedAt|sha256`. */
  attestation: SecAuditAttestation;
}

// ---------------------------------------------------------------------------
// Rules and findings
// ---------------------------------------------------------------------------

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export const SEVERITY_ORDER: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}

/** Static metadata every rule carries (the "rule table" row). */
export interface RuleMeta {
  id: string;
  severity: Severity;
  description: string;
}

/**
 * A raw detector hit, before id/citation assignment. Rules produce these;
 * the auditor turns them into Findings citing the file's attested record.
 */
export interface RawHit {
  ruleId: string;
  severity: Severity;
  /** Relative path of the file the hit is in. */
  file: string;
  /** 1-based line number. */
  line: number;
  /** The matched line, trimmed. */
  excerpt: string;
  rationale: string;
}

/** Non-empty citation list — the type-level half of the zero-citation ban. */
export type Citations = [string, ...string[]];

export type FindingOrigin = "deterministic" | "llm-suggested";

export interface Finding {
  /** "F1", … for deterministic findings; "L1", … for llm-suggested ones. */
  id: string;
  ruleId: string;
  severity: Severity;
  file: string;
  line: number;
  excerpt: string;
  rationale: string;
  /** AttestedFileRecord ids this finding is bound to. NEVER empty. */
  citations: Citations;
  origin: FindingOrigin;
}

/**
 * The only sanctioned Finding constructor. Throws if `citations` is empty —
 * combined with the non-empty tuple type this makes an uncited finding
 * impossible by construction, not just by convention.
 */
export function makeFinding(input: {
  id: string;
  ruleId: string;
  severity: Severity;
  file: string;
  line: number;
  excerpt: string;
  rationale: string;
  citations: readonly string[];
  origin: FindingOrigin;
}): Finding {
  if (input.citations.length === 0) {
    throw new Error(
      `finding ${input.id} (${input.ruleId}) has zero citations — every finding must bind to attested file content`,
    );
  }
  return {
    id: input.id,
    ruleId: input.ruleId,
    severity: input.severity,
    file: input.file,
    line: input.line,
    excerpt: input.excerpt,
    rationale: input.rationale,
    citations: [...input.citations] as Citations,
    origin: input.origin,
  };
}

// ---------------------------------------------------------------------------
// Suppressions
// ---------------------------------------------------------------------------

/**
 * An inline `// audit-ok <ruleId>` (same line or the line above a hit)
 * suppresses that hit — but is always COUNTED and listed, never silent.
 */
export interface SuppressionEntry {
  ruleId: string;
  file: string;
  /** 1-based line of the suppressed hit. */
  line: number;
  /** The suppressed line, trimmed. */
  excerpt: string;
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

export type DepsAuditMode = "live" | "canned" | "skipped" | "unreachable";

export interface DepsAuditStatus {
  mode: DepsAuditMode;
  note: string;
}

export interface RuleStat extends RuleMeta {
  /** Deterministic findings emitted for this rule (suppressed hits excluded). */
  count: number;
}

/**
 * One re-runner's signature in an M-of-N quorum: an ed25519 signature (base64)
 * over the quorum digest (`bodyHash|pinnedInputsDigest|normalizationVersion`),
 * bound to a staked signer identity (a DID / public key).
 */
export interface QuorumSignature {
  /** Signer identity — a DID or public key with a DACS-5 stake record. */
  signer: string;
  /** ed25519 signature (base64) over the agreed quorum digest. */
  signature: string;
}

/**
 * An M-of-N quorum attestation (the "quorum-attested" provenance tier).
 *
 * ADDITIVE + NOT-YET-LIVE. This is the SHAPE the seal carries when N staked
 * re-runners independently reproduce the pinned inputs and co-sign the agreed
 * digest — it replaces trusting a single self-seal. No live multi-signer
 * infrastructure exists yet (no operators): this type + the compare/adjudication
 * substrate are built now so the wire shape and verification path are fixed; the
 * live re-runner/staking network fills `signatures` later.
 *
 * A verifier checks: `signatures.length >= threshold`, signers are DISTINCT,
 * each signature is valid over `bodyHash|pinnedInputsDigest|normalizationVersion`,
 * and (given a stake oracle) each signer is currently staked. `normalizationVersion`
 * is bound in because two re-runners on different normalizers would false-diverge.
 */
export interface QuorumAttestation {
  scheme: "DACS-quorum-mofn";
  /** Loud label stating this is the shape, not a live multi-node proof yet. */
  note: string;
  /** Consensus parameter: the normalizer version the quorum agreed under. */
  normalizationVersion: string;
  /**
   * sha256 over the canonical pinned inputs every re-runner reproduced
   * (headSha, patchHash, image digest, check specs, sourceDateEpoch). A
   * signature is over `bodyHash|pinnedInputsDigest|normalizationVersion`.
   */
  pinnedInputsDigest: string;
  /** M — signatures required for the quorum to attest. */
  threshold: number;
  /** N — re-runners that participated. */
  total: number;
  /** The collected signatures (>= threshold distinct signers when live). */
  signatures: QuorumSignature[];
}

/**
 * Body-free attestation sealing the whole report (tamper evidence).
 *
 * `attestation` is the DEFAULT single self-seal (unchanged — old verifiers still
 * validate it). `quorum` is ADDITIVE and OPTIONAL: present only for a
 * "quorum-attested" artifact, carrying the M-of-N signature set over the same
 * `bodyHash`. Its absence means single-seal / self-attested, exactly as before.
 */
export interface ReportSeal {
  /** `report:sec-audit:<generatedAt>` pseudo-URL. */
  url: string;
  /** sha256 hex over the canonical JSON of the report core (all fields but the seal). */
  bodyHash: string;
  attestation: SecAuditAttestation;
  /** Additive M-of-N quorum set (present only when provenance is quorum-attested). */
  quorum?: QuorumAttestation;
}

export interface SecAuditReport {
  version: 1;
  /** The audited directory as given by the caller. */
  target: string;
  mode: AuditMode;
  generatedAt: string;
  /** Scanned-file manifest — every file the audit read, content-bound. */
  files: AttestedFileRecord[];
  /** Deterministic findings only (origin "deterministic"). */
  findings: Finding[];
  /**
   * LLM-suggested candidates (origin "llm-suggested"), clearly segregated:
   * deterministic findings never depend on these. Empty unless the optional
   * LLM pass ran.
   */
  llmFindings: Finding[];
  suppressions: SuppressionEntry[];
  /** Every rule in the tables with its firing count (0s included). */
  ruleStats: RuleStat[];
  deps: DepsAuditStatus;
  seal: ReportSeal;
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

export interface VerifySecReportResult {
  valid: boolean;
  problems: string[];
  /** File-record + seal attestation signatures re-verified. */
  attestationsChecked: number;
  /** Findings (deterministic + llm) whose citations were resolved. */
  findingsChecked: number;
  /** Files re-hashed against the manifest (0 when no targetDir given). */
  filesRehashed: number;
  /** Manifest entries whose on-disk content no longer matches (drift). */
  driftedFiles: string[];
}
