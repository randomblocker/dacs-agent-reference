/**
 * Report emission + third-party verification.
 *
 * `writeReport` emits report.json (the verifiable artifact) and report.md
 * (findings grouped by severity, rule stats, suppression list,
 * scanned-file manifest with hashes, evidence appendix).
 *
 * `verifyReport(reportJson, targetDir?)` never trusts the report about
 * itself. It re-checks, from scratch:
 *  - structure (mode/severities/origins sane, deterministic vs llm
 *    sections not cross-contaminated);
 *  - every attested file record's ed25519 signature;
 *  - every finding's citations resolve to file-record ids (non-empty);
 *  - ruleStats recounted against the findings;
 *  - the seal: canonical-JSON hash of the report core recomputed and the
 *    signature over it verified — ANY edit to a finding/file/suppression
 *    after emission breaks it;
 *  - and, when `targetDir` is given, every manifest file is RE-HASHED on
 *    disk and compared (sha256 + size) — content drift is flagged, so a
 *    verified report provably describes the exact bytes on disk.
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { canonicalJson, sha256HexBytes, verifyContentEvidence, verifyFileRecord } from "./attest-files.js";
import type {
  AttestedFileRecord,
  Finding,
  SecAuditReport,
  Severity,
  SuppressionEntry,
  VerifySecReportResult,
} from "./types.js";
import { SEVERITY_ORDER } from "./types.js";

// ---------------------------------------------------------------------------
// Markdown rendering
// ---------------------------------------------------------------------------

const SEVERITY_HEADING: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Informational",
};

function renderFindingList(lines: string[], findings: Finding[]): void {
  for (const severity of SEVERITY_ORDER) {
    const group = findings.filter((f) => f.severity === severity);
    lines.push("", `### ${SEVERITY_HEADING[severity]} (${group.length})`);
    if (group.length === 0) {
      lines.push("", "- (none)");
      continue;
    }
    for (const f of group) {
      lines.push(
        "",
        `- **${f.ruleId}** — ${f.file}:${f.line} ${f.citations.map((c) => `[${c}]`).join("")}`,
        `  \`${f.excerpt}\``,
        `  ${f.rationale}`,
      );
    }
  }
}

export function renderReportMarkdown(report: SecAuditReport): string {
  const counts = Object.fromEntries(
    SEVERITY_ORDER.map((s) => [s, report.findings.filter((f) => f.severity === s).length]),
  );
  const lines: string[] = [];

  lines.push(`# Security audit — ${report.target}`);
  lines.push("");
  lines.push(`- Generated: ${report.generatedAt} (mode: ${report.mode})`);
  lines.push(
    `- Findings: ${report.findings.length} deterministic (${SEVERITY_ORDER.map((s) => `${counts[s]} ${s}`).join(" / ")})`,
  );
  lines.push(`- Suppressions honored: ${report.suppressions.length}`);
  lines.push(`- Files scanned: ${report.files.length} (all content-attested, hash-only)`);
  lines.push(`- Dependency audit: ${report.deps.mode} — ${report.deps.note}`);
  lines.push("");
  lines.push("## Findings (deterministic)");
  renderFindingList(lines, report.findings);

  lines.push("", "## LLM-suggested candidates (segregated — NOT deterministic findings)");
  if (report.llmFindings.length === 0) {
    lines.push("", "- (none — LLM pass off or produced nothing)");
  } else {
    renderFindingList(lines, report.llmFindings);
  }

  lines.push("", "## Suppressions (inline `audit-ok`, honored and counted)");
  if (report.suppressions.length === 0) {
    lines.push("", "- (none)");
  } else {
    for (const s of report.suppressions) {
      lines.push("", `- \`${s.ruleId}\` at ${s.file}:${s.line} — \`${s.excerpt}\``);
    }
  }

  lines.push("", "## Rule stats");
  lines.push("", "| rule | severity | fired | description |", "|---|---|---|---|");
  for (const r of report.ruleStats) {
    lines.push(`| ${r.id} | ${r.severity} | ${r.count} | ${r.description} |`);
  }

  lines.push("", "## Scanned-file manifest (evidence appendix)");
  for (const f of report.files) {
    lines.push(
      "",
      `### ${f.id} — ${f.path}`,
      "",
      `- sha256: ${f.sha256} (${f.size} bytes; body hash-only)`,
      `- attested: ${f.attestedAt} under \`file:${f.path}\``,
      `- attestation digest: ${f.attestation.digest}`,
      `- scheme: ${f.attestation.scheme} — ${f.attestation.note.split(" — ")[0]}`,
    );
  }
  lines.push("", `## Report seal`, "", `- core hash: ${report.seal.bodyHash}`, `- sealed under: ${report.seal.url}`, "");

  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Emission
// ---------------------------------------------------------------------------

export interface EmittedReport {
  dir: string;
  jsonPath: string;
  mdPath: string;
}

export async function writeReport(report: SecAuditReport, dir: string): Promise<EmittedReport> {
  await mkdir(dir, { recursive: true });
  const jsonPath = join(dir, "report.json");
  const mdPath = join(dir, "report.md");
  await writeFile(jsonPath, JSON.stringify(report, null, 2) + "\n", "utf8");
  await writeFile(mdPath, renderReportMarkdown(report), "utf8");
  return { dir, jsonPath, mdPath };
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

const VALID_SEVERITIES: ReadonlySet<string> = new Set(SEVERITY_ORDER);
const VALID_MODES: ReadonlySet<string> = new Set(["auto", "repo", "solidity"]);
const VALID_DEPS_MODES: ReadonlySet<string> = new Set(["live", "canned", "skipped", "unreachable"]);

function checkFindings(
  list: unknown,
  section: "findings" | "llmFindings",
  expectOrigin: Finding["origin"],
  fileIds: ReadonlySet<string>,
  problems: string[],
): { checked: number; parsed: Finding[] } {
  if (!Array.isArray(list)) {
    problems.push(`${section} is not an array`);
    return { checked: 0, parsed: [] };
  }
  let checked = 0;
  const parsed: Finding[] = [];
  for (const [i, raw] of list.entries()) {
    if (!isObject(raw)) {
      problems.push(`${section}[${i}] is not an object`);
      continue;
    }
    const f = raw as unknown as Finding;
    const label = typeof f.id === "string" ? f.id : `${section}[${i}]`;
    if (!VALID_SEVERITIES.has(f.severity)) problems.push(`${label}: unknown severity "${String(f.severity)}"`);
    if (typeof f.ruleId !== "string" || f.ruleId.length === 0) problems.push(`${label}: missing ruleId`);
    if (typeof f.file !== "string" || typeof f.line !== "number") problems.push(`${label}: missing file/line`);
    if (typeof f.rationale !== "string" || f.rationale.length === 0) problems.push(`${label}: missing rationale`);
    if (f.origin !== expectOrigin) {
      problems.push(`${label}: origin "${String(f.origin)}" in the ${section} section (expected "${expectOrigin}")`);
    }
    if (!Array.isArray(f.citations) || f.citations.length === 0) {
      problems.push(`${label}: has zero citations — every finding must bind to attested file content`);
    } else {
      for (const c of f.citations) {
        if (typeof c !== "string" || !fileIds.has(c)) {
          problems.push(`${label}: citation "${String(c)}" does not resolve to an attested file record`);
        }
      }
    }
    checked += 1;
    parsed.push(f);
  }
  return { checked, parsed };
}

/**
 * Re-verify a parsed report.json as a third party. When `targetDir` is
 * given, additionally re-hash every manifest file on disk and flag drift.
 */
export async function verifyReport(
  reportJson: unknown,
  targetDir?: string,
  expectedSellerDid?: string,
): Promise<VerifySecReportResult> {
  const problems: string[] = [];
  let attestationsChecked = 0;
  let findingsChecked = 0;
  let filesRehashed = 0;
  const driftedFiles: string[] = [];

  const fail = (): VerifySecReportResult => ({
    valid: false,
    problems,
    attestationsChecked,
    findingsChecked,
    filesRehashed,
    driftedFiles,
  });

  if (!isObject(reportJson)) {
    problems.push("report is not a JSON object");
    return fail();
  }
  const report = reportJson;

  if (report.version !== 1) problems.push(`unknown report version ${String(report.version)}`);
  if (typeof report.target !== "string" || report.target.length === 0) problems.push("target is missing");
  if (!VALID_MODES.has(String(report.mode))) problems.push(`unknown mode "${String(report.mode)}"`);
  if (typeof report.generatedAt !== "string" || Number.isNaN(Date.parse(report.generatedAt))) {
    problems.push("generatedAt is not a valid timestamp");
  }
  const deps = report.deps;
  if (!isObject(deps) || !VALID_DEPS_MODES.has(String(deps.mode)) || typeof deps.note !== "string") {
    problems.push("deps status is missing or malformed");
  }

  // --- File records: signatures re-verified from scratch -----------------
  const fileIds = new Set<string>();
  const fileRecords: AttestedFileRecord[] = [];
  let reportSignerDid = expectedSellerDid;
  let reportEvidenceScheme: AttestedFileRecord["attestation"]["scheme"] | undefined;
  const filesRaw = Array.isArray(report.files) ? report.files : null;
  if (!filesRaw) {
    problems.push("files is not an array");
  } else {
    for (const [i, raw] of filesRaw.entries()) {
      if (!isObject(raw)) {
        problems.push(`files[${i}] is not an object`);
        continue;
      }
      const f = raw as unknown as AttestedFileRecord;
      if (typeof f.id !== "string" || f.id.length === 0) {
        problems.push(`files[${i}] has no id`);
        continue;
      }
      if (fileIds.has(f.id)) problems.push(`duplicate file record id ${f.id}`);
      fileIds.add(f.id);
      if (
        typeof f.path !== "string" ||
        typeof f.sha256 !== "string" ||
        typeof f.size !== "number" ||
        typeof f.attestedAt !== "string" ||
        !isObject(f.attestation)
      ) {
        problems.push(`file record ${f.id} is missing path/sha256/size/attestedAt/attestation`);
        continue;
      }
      if (f.attestation.scheme === "DACS-SELLER-ed25519") {
        reportSignerDid ??= f.attestation.publicKey;
      }
      if (reportEvidenceScheme && f.attestation.scheme !== reportEvidenceScheme) {
        problems.push(
          `file record ${f.id} (${f.path}): mixed evidence schemes (${reportEvidenceScheme} and ${f.attestation.scheme})`,
        );
      }
      reportEvidenceScheme ??= f.attestation.scheme;
      const verdict = verifyFileRecord(f, reportSignerDid);
      attestationsChecked += 1;
      if (!verdict.valid) problems.push(`file record ${f.id} (${f.path}): attestation invalid — ${verdict.reason}`);
      fileRecords.push(f);
    }
  }

  // --- Findings (both sections; segregation enforced) --------------------
  const det = checkFindings(report.findings, "findings", "deterministic", fileIds, problems);
  const llm = checkFindings(report.llmFindings, "llmFindings", "llm-suggested", fileIds, problems);
  findingsChecked = det.checked + llm.checked;

  // --- Suppressions listed with sane shape -------------------------------
  const suppressions = Array.isArray(report.suppressions) ? report.suppressions : null;
  if (!suppressions) {
    problems.push("suppressions is not an array");
  } else {
    for (const [i, raw] of suppressions.entries()) {
      const s = raw as SuppressionEntry;
      if (!isObject(raw) || typeof s.ruleId !== "string" || typeof s.file !== "string" || typeof s.line !== "number") {
        problems.push(`suppressions[${i}] is malformed`);
      }
    }
  }

  // --- Rule stats recounted ----------------------------------------------
  const ruleStats = Array.isArray(report.ruleStats) ? report.ruleStats : null;
  if (!ruleStats) {
    problems.push("ruleStats is not an array");
  } else {
    for (const raw of ruleStats) {
      if (!isObject(raw) || typeof raw.id !== "string" || typeof raw.count !== "number") {
        problems.push("ruleStats contains a malformed entry");
        continue;
      }
      const actual = det.parsed.filter((f) => f.ruleId === raw.id).length;
      if (actual !== raw.count) {
        problems.push(`ruleStats: ${String(raw.id)} claims ${raw.count} finding(s) but the report contains ${actual}`);
      }
    }
    for (const f of det.parsed) {
      if (typeof f.ruleId === "string" && !ruleStats.some((r) => isObject(r) && r.id === f.ruleId)) {
        problems.push(`finding ${f.id} fired rule ${f.ruleId} which is absent from ruleStats`);
      }
    }
  }

  // --- Seal: canonical core hash recomputed + signature verified ---------
  const seal = report.seal;
  if (!isObject(seal) || typeof seal.url !== "string" || typeof seal.bodyHash !== "string" || !isObject(seal.attestation)) {
    problems.push("seal is missing or malformed");
  } else {
    if (reportEvidenceScheme && seal.attestation.scheme !== reportEvidenceScheme) {
      problems.push(`seal: evidence scheme ${String(seal.attestation.scheme)} does not match file scheme ${reportEvidenceScheme}`);
    }
    const { seal: _dropped, ...core } = report;
    const expected = canonicalJson(core);
    const expectedHash = sha256HexBytes(Buffer.from(expected, "utf8"));
    if (expectedHash !== seal.bodyHash) {
      problems.push("seal: report content does not hash to the sealed core hash — the report was modified after sealing");
    }
    const verdict = verifyContentEvidence({
      url: seal.url as string,
      fetchedAt: String(report.generatedAt),
      bodyHash: seal.bodyHash as string,
      attestation: seal.attestation as unknown as AttestedFileRecord["attestation"],
    }, reportSignerDid);
    attestationsChecked += 1;
    if (!verdict.valid) problems.push(`seal: attestation invalid — ${verdict.reason}`);
  }

  // --- Optional drift check: re-hash the target --------------------------
  if (targetDir !== undefined) {
    for (const f of fileRecords) {
      filesRehashed += 1;
      try {
        const bytes = await readFile(join(targetDir, f.path));
        if (sha256HexBytes(bytes) !== f.sha256 || bytes.length !== f.size) {
          driftedFiles.push(f.path);
          problems.push(`drift: ${f.path} on disk no longer matches the attested sha256/size in the report`);
        }
      } catch (err) {
        driftedFiles.push(f.path);
        problems.push(`drift: ${f.path} could not be re-read (${(err as Error).message})`);
      }
    }
  }

  return {
    valid: problems.length === 0,
    problems,
    attestationsChecked,
    findingsChecked,
    filesRehashed,
    driftedFiles,
  };
}
