/**
 * Report emission + third-party verification.
 *
 * `writeAuditReport` emits report.json (the verifiable artifact) and
 * report.md (human-readable, per-check [A*] citation markers + measurement
 * appendix) into `out/<host>-<timestamp>/`.
 *
 * `verifyAudit` is the third-party check: given ONLY parsed report JSON it
 *   1. re-verifies every measurement attestation (ed25519 over
 *      url|fetchedAt|bodyHash) and every body hash,
 *   2. ties the attested pseudo-URLs to the report's claimed target,
 *   3. resolves every check citation against the evidence ids, and
 *   4. RE-DERIVES all four categories and the overall score from the
 *      attested measurement bodies via the same pure `deriveAssessment`,
 *      requiring exact equality — an edited metric or score is a mismatch
 *      against the attestations, not just a plausible number.
 * It never trusts the report's own claims about itself.
 */
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { sha256Hex, verifyAttestedRecord } from "../oracle-desk/attested-fetch.js";
import { canonicalJson } from "../shared/attest-primitives.js";
import { CATEGORY_ORDER, CATEGORY_WEIGHTS, deriveAssessment } from "./checks.js";
import type { CategoryResult, MeasurementEvidence, MeasurementGap, SiteAuditReport, VerifyAuditResult } from "./types.js";

const MEASUREMENT_KINDS = new Set(["timing-sample", "tls", "http-redirect"]);

// ---------------------------------------------------------------------------
// Markdown rendering
// ---------------------------------------------------------------------------

const CATEGORY_HEADING: Record<string, string> = {
  performance: "Performance",
  tls: "TLS certificate",
  headers: "Security headers",
  hygiene: "Transport hygiene",
};

export function renderAuditMarkdown(report: SiteAuditReport): string {
  const lines: string[] = [];
  lines.push(`# Site audit — ${report.url}`);
  lines.push("");
  lines.push(`- Audited: ${report.auditedAt}`);
  lines.push(`- Timing samples requested: ${report.samples}`);
  lines.push(`- Overall score: **${report.overallScore}/100** (weighted over non-degraded categories)`);
  lines.push(`- Evidence: ${report.provenance.evidence.length} attested measurement(s), ${report.provenance.gaps.length} failed measurement(s)`);
  lines.push("");
  lines.push("## Category scores");
  lines.push("");
  lines.push("| Category | Weight | Score | Status |");
  lines.push("|---|---|---|---|");
  for (const c of report.categories) {
    const status = c.degraded ? `degraded — ${c.degradedReason ?? "measurement missing"}` : "measured";
    lines.push(`| ${CATEGORY_HEADING[c.category] ?? c.category} | ${CATEGORY_WEIGHTS[c.category]} | ${c.degraded ? "—" : `${c.score}/100`} | ${status} |`);
  }

  for (const c of report.categories) {
    lines.push("");
    lines.push(`## ${CATEGORY_HEADING[c.category] ?? c.category}${c.degraded ? " (degraded)" : ` — ${c.score}/100`}`);
    if (c.degraded) {
      lines.push("");
      lines.push(`- ${c.degradedReason ?? "measurement missing"}`);
    }
    if (c.metrics) {
      lines.push("");
      lines.push("| Metric | p50 | p95 | min | max |");
      lines.push("|---|---|---|---|---|");
      lines.push(`| total (ms) | ${c.metrics.p50TotalMs} | ${c.metrics.p95TotalMs} | ${c.metrics.minTotalMs} | ${c.metrics.maxTotalMs} |`);
      lines.push(`| ttfb (ms) | ${c.metrics.p50TtfbMs} | ${c.metrics.p95TtfbMs} | ${c.metrics.minTtfbMs} | ${c.metrics.maxTtfbMs} |`);
    }
    for (const check of c.checks) {
      lines.push("");
      lines.push(`- **${check.name}** — ${check.score}/100 ${check.citations.map((id) => `[${id}]`).join("")} \`${check.id}\``);
      lines.push(`  ${check.detail}`);
    }
  }

  if (report.provenance.gaps.length > 0) {
    lines.push("");
    lines.push("## Failed measurements (audit degraded)");
    lines.push("");
    for (const g of report.provenance.gaps) {
      lines.push(`- ${g.kind} — ${g.target} — ${g.reason}`);
    }
  }

  lines.push("");
  lines.push("## Measurement appendix");
  for (const e of report.provenance.evidence) {
    lines.push("");
    lines.push(`### ${e.id} — ${e.kind}`);
    lines.push("");
    lines.push(`- pseudo-url: ${e.url}`);
    lines.push(`- measuredAt: ${e.fetchedAt}`);
    lines.push(`- bodyHash: sha256:${e.bodyHash}`);
    lines.push(`- attestation digest: ${e.attestation.digest}`);
    lines.push(`- attestation scheme: ${e.attestation.scheme} — ${e.attestation.note.split(" — ")[0]}`);
  }
  lines.push("");

  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Emission
// ---------------------------------------------------------------------------

export interface EmittedAudit {
  dir: string;
  jsonPath: string;
  mdPath: string;
}

/** `roster/site-auditor/out` next to this module (gitignored). */
export function defaultOutRoot(): string {
  return join(dirname(fileURLToPath(import.meta.url)), "out");
}

/** `<outRoot>/<host>-<timestamp>` for a report. */
export function auditOutDir(report: SiteAuditReport, outRoot: string = defaultOutRoot()): string {
  const host = new URL(report.url).hostname;
  const stamp = report.auditedAt.replace(/[:.]/g, "-");
  return join(outRoot, `${host}-${stamp}`);
}

/** Write report.json + report.md into `dir` (created recursively). */
export async function writeAuditReport(report: SiteAuditReport, dir: string = auditOutDir(report)): Promise<EmittedAudit> {
  await mkdir(dir, { recursive: true });
  const jsonPath = join(dir, "report.json");
  const mdPath = join(dir, "report.md");
  await writeFile(jsonPath, JSON.stringify(report, null, 2) + "\n", "utf8");
  await writeFile(mdPath, renderAuditMarkdown(report), "utf8");
  return { dir, jsonPath, mdPath };
}

// ---------------------------------------------------------------------------
// Third-party verification
// ---------------------------------------------------------------------------

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function verifyAudit(reportJson: unknown): VerifyAuditResult {
  const problems: string[] = [];
  let attestationsChecked = 0;
  let checksChecked = 0;

  if (!isObject(reportJson)) {
    return { valid: false, problems: ["report is not a JSON object"], attestationsChecked, checksChecked };
  }
  const report = reportJson;

  if (report.version !== 1) problems.push(`unknown report version ${String(report.version)}`);
  let targetUrl: URL | null = null;
  if (typeof report.url !== "string") {
    problems.push("url is missing");
  } else {
    try {
      const u = new URL(report.url);
      if (u.protocol !== "https:" && u.protocol !== "http:") problems.push(`url has unsupported protocol ${u.protocol}`);
      else targetUrl = u;
    } catch {
      problems.push(`url "${report.url}" is not a valid URL`);
    }
  }
  if (typeof report.auditedAt !== "string" || Number.isNaN(Date.parse(report.auditedAt))) {
    problems.push("auditedAt is not a valid timestamp");
  }
  if (typeof report.samples !== "number" || !Number.isInteger(report.samples) || report.samples < 1) {
    problems.push("samples is not a positive integer");
  }

  // --- provenance: every attestation re-verified from scratch ----------------
  const evidenceIds = new Set<string>();
  const goodEvidence: MeasurementEvidence[] = [];
  const goodGaps: MeasurementGap[] = [];
  const provenance = isObject(report.provenance) ? report.provenance : null;
  if (!provenance) {
    problems.push("provenance is missing");
  } else {
    const evidence = Array.isArray(provenance.evidence) ? provenance.evidence : null;
    if (!evidence) {
      problems.push("provenance.evidence is not an array");
    } else {
      for (const [i, raw] of evidence.entries()) {
        if (!isObject(raw)) {
          problems.push(`evidence[${i}] is not an object`);
          continue;
        }
        const e = raw as unknown as MeasurementEvidence;
        if (typeof e.id !== "string" || e.id.length === 0) {
          problems.push(`evidence[${i}] has no id`);
          continue;
        }
        if (evidenceIds.has(e.id)) problems.push(`duplicate evidence id ${e.id}`);
        evidenceIds.add(e.id);
        if (typeof e.kind !== "string" || !MEASUREMENT_KINDS.has(e.kind)) {
          problems.push(`evidence ${e.id} has unknown kind "${String(e.kind)}"`);
          continue;
        }
        if (typeof e.url !== "string" || typeof e.fetchedAt !== "string" || typeof e.body !== "string" || typeof e.bodyHash !== "string" || !isObject(e.attestation)) {
          problems.push(`evidence ${e.id} is missing url/fetchedAt/body/bodyHash/attestation`);
          continue;
        }
        if (sha256Hex(e.body) !== e.bodyHash) {
          problems.push(`evidence ${e.id}: measurement body does not match bodyHash`);
        }
        // Tie the attested pseudo-URL to the report's claimed target.
        if (targetUrl !== null) {
          if (e.kind === "timing-sample" && !e.url.startsWith(`probe:timing:${report.url as string}#`)) {
            problems.push(`evidence ${e.id}: timing pseudo-URL "${e.url}" does not reference the report target`);
          }
          if (e.kind === "tls" && e.url !== `probe:tls:${targetUrl.hostname}`) {
            problems.push(`evidence ${e.id}: tls pseudo-URL "${e.url}" does not reference the report host`);
          }
          if (e.kind === "http-redirect" && e.url !== `probe:http-redirect:http://${targetUrl.host}/`) {
            problems.push(`evidence ${e.id}: http-redirect pseudo-URL "${e.url}" does not reference the report host`);
          }
        }
        const verdict = verifyAttestedRecord({ url: e.url, fetchedAt: e.fetchedAt, bodyHash: e.bodyHash, attestation: e.attestation });
        attestationsChecked += 1;
        if (!verdict.valid) {
          problems.push(`evidence ${e.id}: attestation invalid — ${verdict.reason}`);
          continue;
        }
        goodEvidence.push(e);
      }
    }
    const gaps = provenance.gaps;
    if (!Array.isArray(gaps)) {
      problems.push("provenance.gaps is not an array");
    } else {
      for (const [i, g] of gaps.entries()) {
        if (!isObject(g) || typeof g.kind !== "string" || typeof g.reason !== "string" || g.reason.trim().length === 0) {
          problems.push(`gaps[${i}] is missing a kind or a non-empty reason`);
          continue;
        }
        goodGaps.push(g as unknown as MeasurementGap);
      }
    }
  }

  // --- checks: citation resolution -------------------------------------------
  const categories = Array.isArray(report.categories) ? report.categories : null;
  if (!categories) {
    problems.push("categories is not an array");
  } else {
    for (const [i, raw] of categories.entries()) {
      if (!isObject(raw)) {
        problems.push(`categories[${i}] is not an object`);
        continue;
      }
      const c = raw as unknown as CategoryResult;
      if (typeof c.category !== "string" || !CATEGORY_ORDER.includes(c.category)) {
        problems.push(`categories[${i}] has unknown category "${String(c.category)}"`);
      }
      if (typeof c.score !== "number" || c.score < 0 || c.score > 100) {
        problems.push(`category ${String(c.category)}: score out of [0, 100]`);
      }
      const checks = Array.isArray(c.checks) ? c.checks : null;
      if (!checks) {
        problems.push(`category ${String(c.category)}: checks is not an array`);
        continue;
      }
      for (const check of checks) {
        checksChecked += 1;
        if (!isObject(check) || typeof check.id !== "string") {
          problems.push(`category ${String(c.category)}: malformed check`);
          continue;
        }
        const cites = check.citations;
        if (!Array.isArray(cites) || cites.length === 0) {
          problems.push(`check ${String(check.id)}: scored check with zero citations — every score must cite a measurement`);
          continue;
        }
        for (const cite of cites) {
          if (typeof cite !== "string" || !evidenceIds.has(cite)) {
            problems.push(`check ${String(check.id)}: citation "${String(cite)}" does not resolve to an attested measurement`);
          }
        }
      }
    }
  }

  // --- re-derivation: scores must equal what the attested evidence yields ----
  if (typeof report.url === "string" && targetUrl !== null && categories !== null) {
    try {
      const derived = deriveAssessment(goodEvidence, goodGaps, report.url);
      if (canonicalJson(categories) !== canonicalJson(derived.categories)) {
        problems.push("categories do not match re-derivation from the attested measurements (edited metric or score?)");
      }
      if (report.overallScore !== derived.overallScore) {
        problems.push(`overallScore ${String(report.overallScore)} does not match re-derived ${derived.overallScore}`);
      }
    } catch (err) {
      problems.push(`re-derivation from attested evidence failed: ${(err as Error).message}`);
    }
  }

  return { valid: problems.length === 0, problems, attestationsChecked, checksChecked };
}
