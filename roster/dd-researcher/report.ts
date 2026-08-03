/**
 * Report emission + third-party verification.
 *
 * `writeReport` emits report.json (the verifiable artifact) and report.md
 * (human-readable, findings grouped by severity with [E*] citation markers
 * and an evidence appendix).
 *
 * `verifyReport` is the third-party check: given ONLY the parsed
 * report.json, it re-verifies every evidence attestation signature (and the
 * body hash whenever the body is embedded) and resolves every finding's
 * citations against the evidence ids. It never trusts the report's own
 * claims about itself.
 */
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { sha256Hex, verifyAttestedRecord } from "../oracle-desk/attested-fetch.js";
import type { DDReport, EvidenceItem, Finding, Severity, VerifyReportResult } from "./types.js";
import { SEVERITY_ORDER, subjectLabel } from "./types.js";

// ---------------------------------------------------------------------------
// Markdown rendering
// ---------------------------------------------------------------------------

const SEVERITY_HEADING: Record<Severity, string> = {
  "red-flag": "Red flags",
  caution: "Cautions",
  info: "Informational",
};

function cite(finding: Finding): string {
  return finding.citations.map((id) => `[${id}]`).join("");
}

export function renderReportMarkdown(report: DDReport): string {
  const counts = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, report.findings.filter((f) => f.severity === s).length]));
  const lines: string[] = [];

  lines.push(`# Due-diligence report — ${subjectLabel(report.subject)}`);
  lines.push("");
  lines.push(`- Generated: ${report.generatedAt}`);
  lines.push(`- Findings: ${report.findings.length} (${counts["red-flag"]} red-flag / ${counts["caution"]} caution / ${counts["info"]} info)`);
  lines.push(`- Evidence: ${report.evidence.length} attested item(s), ${report.gaps.length} unreachable source(s)`);
  lines.push(`- Summary method: ${report.summary.method} (presentation only — findings below are the substance)`);
  lines.push("");
  lines.push("## Executive summary");
  lines.push("");
  lines.push(report.summary.text);
  lines.push("");
  lines.push("## Findings");

  for (const severity of SEVERITY_ORDER) {
    const group = report.findings.filter((f) => f.severity === severity);
    lines.push("");
    lines.push(`### ${SEVERITY_HEADING[severity]} (${group.length})`);
    if (group.length === 0) {
      lines.push("");
      lines.push("- (none)");
      continue;
    }
    for (const f of group) {
      lines.push("");
      lines.push(`- **${f.title}** ${cite(f)} \`${f.rule}\``);
      lines.push(`  ${f.detail}`);
    }
  }

  if (report.gaps.length > 0) {
    lines.push("");
    lines.push("## Unreachable sources (report degraded)");
    lines.push("");
    for (const gap of report.gaps) {
      lines.push(`- ${gap.source} — ${gap.url} — ${gap.reason}`);
    }
  }

  lines.push("");
  lines.push("## Evidence appendix");
  for (const e of report.evidence) {
    lines.push("");
    lines.push(`### ${e.id} — ${e.source}${e.ok ? "" : " (unavailable)"}`);
    lines.push("");
    lines.push(`- url: ${e.url}`);
    lines.push(`- fetchedAt: ${e.fetchedAt} (HTTP ${e.status})`);
    lines.push(`- bodyHash: sha256:${e.bodyHash}${e.body === undefined ? " (body omitted from report — oversized)" : ""}`);
    lines.push(`- attestation digest: ${e.attestation.digest}`);
    lines.push(`- attestation scheme: ${e.attestation.scheme} — ${e.attestation.note.split(" — ")[0]}`);
  }
  lines.push("");

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

/** Write report.json + report.md into `dir` (created recursively). */
export async function writeReport(report: DDReport, dir: string): Promise<EmittedReport> {
  await mkdir(dir, { recursive: true });
  const jsonPath = join(dir, "report.json");
  const mdPath = join(dir, "report.md");
  await writeFile(jsonPath, JSON.stringify(report, null, 2) + "\n", "utf8");
  await writeFile(mdPath, renderReportMarkdown(report), "utf8");
  return { dir, jsonPath, mdPath };
}

// ---------------------------------------------------------------------------
// Third-party verification
// ---------------------------------------------------------------------------

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

const SEVERITIES: readonly string[] = ["info", "caution", "red-flag"];

/**
 * Re-verify a parsed report.json. Checks, from scratch:
 *  - structural sanity (subject/evidence/findings/summary present and typed)
 *  - every evidence attestation: digest covers url|fetchedAt|bodyHash and
 *    the ed25519 signature verifies; when the body is embedded, its sha256
 *    must equal bodyHash
 *  - evidence ids unique; every finding has ≥1 citation and every citation
 *    resolves to an evidence id
 */
export function verifyReport(reportJson: unknown): VerifyReportResult {
  const problems: string[] = [];
  let evidenceChecked = 0;
  let findingsChecked = 0;

  if (!isObject(reportJson)) {
    return { valid: false, problems: ["report is not a JSON object"], evidenceChecked, findingsChecked };
  }
  const report = reportJson;

  if (report.version !== 1) problems.push(`unknown report version ${String(report.version)}`);
  const subject = report.subject;
  if (!isObject(subject) || (subject.kind !== "npm-package" && subject.kind !== "crypto-token")) {
    problems.push("subject is missing or has an unknown kind");
  }
  if (typeof report.generatedAt !== "string" || Number.isNaN(Date.parse(report.generatedAt))) {
    problems.push("generatedAt is not a valid timestamp");
  }
  const summary = report.summary;
  if (!isObject(summary) || typeof summary.text !== "string" || summary.text.trim().length === 0) {
    problems.push("summary.text is missing or empty");
  } else if (summary.method !== "deterministic" && summary.method !== "llm") {
    problems.push(`summary.method "${String(summary.method)}" is unknown`);
  }

  // Evidence: attestation signatures re-verified from scratch.
  const evidenceIds = new Set<string>();
  const evidence = Array.isArray(report.evidence) ? report.evidence : null;
  if (!evidence) {
    problems.push("evidence is not an array");
  } else {
    for (const [i, raw] of evidence.entries()) {
      if (!isObject(raw)) {
        problems.push(`evidence[${i}] is not an object`);
        continue;
      }
      const e = raw as unknown as EvidenceItem;
      if (typeof e.id !== "string" || e.id.length === 0) {
        problems.push(`evidence[${i}] has no id`);
        continue;
      }
      if (evidenceIds.has(e.id)) problems.push(`duplicate evidence id ${e.id}`);
      evidenceIds.add(e.id);

      if (typeof e.url !== "string" || typeof e.fetchedAt !== "string" || typeof e.bodyHash !== "string" || !isObject(e.attestation)) {
        problems.push(`evidence ${e.id} is missing url/fetchedAt/bodyHash/attestation`);
        continue;
      }
      if (e.body !== undefined) {
        if (typeof e.body !== "string") {
          problems.push(`evidence ${e.id} body is not a string`);
        } else if (sha256Hex(e.body) !== e.bodyHash) {
          problems.push(`evidence ${e.id}: embedded body does not match bodyHash`);
        }
      }
      const verdict = verifyAttestedRecord({ url: e.url, fetchedAt: e.fetchedAt, bodyHash: e.bodyHash, attestation: e.attestation });
      evidenceChecked += 1;
      if (!verdict.valid) problems.push(`evidence ${e.id}: attestation invalid — ${verdict.reason}`);
    }
  }

  // Findings: severities sane, citations non-empty and resolvable.
  const findings = Array.isArray(report.findings) ? report.findings : null;
  if (!findings) {
    problems.push("findings is not an array");
  } else {
    for (const [i, raw] of findings.entries()) {
      if (!isObject(raw)) {
        problems.push(`findings[${i}] is not an object`);
        continue;
      }
      const f = raw as unknown as Finding;
      const label = typeof f.id === "string" ? f.id : `findings[${i}]`;
      if (!SEVERITIES.includes(f.severity)) problems.push(`${label}: unknown severity "${String(f.severity)}"`);
      if (typeof f.title !== "string" || f.title.length === 0) problems.push(`${label}: missing title`);
      if (!Array.isArray(f.citations) || f.citations.length === 0) {
        problems.push(`${label}: has zero citations — every claim must cite evidence`);
      } else {
        for (const c of f.citations) {
          if (typeof c !== "string" || !evidenceIds.has(c)) {
            problems.push(`${label}: citation "${String(c)}" does not resolve to an evidence item`);
          }
        }
      }
      findingsChecked += 1;
    }
  }

  return { valid: problems.length === 0, problems, evidenceChecked, findingsChecked };
}
