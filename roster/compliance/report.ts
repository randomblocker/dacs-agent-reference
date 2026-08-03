/**
 * Report emission + third-party verification.
 *
 * `writeScreeningReport` emits report.json (the verifiable artifact) and
 * report.md (human-readable match tables + list-version appendix).
 *
 * `verifyScreening` is the third-party check over ONLY the parsed
 * report.json: it re-verifies every list-download attestation signature,
 * requires every SCREENED source to cite ≥1 list version of its own source
 * (provable absence for clear verdicts), resolves every match's citations,
 * re-derives every match's severity from its (method, score) pair, and
 * recomputes the verdict from the recomputed severities. It never trusts
 * the report's own claims about itself — an edited score, a forged
 * attestation, or a downgraded verdict all surface as problems.
 */
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { verifyAttestedRecord } from "../oracle-desk/attested-fetch.js";
import { severityForMatch } from "./matching.js";
import { aggregateVerdict, sourceLabel } from "./screener.js";
import type {
  ListVersion,
  Match,
  MatchMethod,
  MatchSeverity,
  PerSourceResult,
  ScreeningReport,
  SourceId,
  Verdict,
  VerifyScreeningResult,
} from "./types.js";
import { SOURCE_IDS, SOURCE_META } from "./types.js";

// ---------------------------------------------------------------------------
// Markdown rendering
// ---------------------------------------------------------------------------

function cite(ids: readonly string[]): string {
  return ids.map((id) => `[${id}]`).join("");
}

export function renderScreeningMarkdown(report: ScreeningReport): string {
  const lines: string[] = [];
  const s = report.subject;

  lines.push(`# Screening report — ${s.name} (${s.kind})`);
  lines.push("");
  lines.push(`- Verdict: **${report.verdict.toUpperCase()}**`);
  lines.push(
    `- Screening: **${report.screeningComplete ? "COMPLETE" : "INCOMPLETE"}** ` +
      `(${report.panel.length} list source(s) on the panel; ` +
      `${report.perSource.filter((p) => p.status === "gap").length} gap(s))`,
  );
  if (!report.screeningComplete) {
    lines.push(`- WARNING: one or more sources were not screened — a CLEAR here is only clear on the lists that were reachable, not an all-clear.`);
  }
  lines.push(`- Screened at: ${report.screenedAt}`);
  if (s.aliases && s.aliases.length > 0) lines.push(`- Aliases screened: ${s.aliases.join(", ")}`);
  if (s.country) lines.push(`- Country: ${s.country}`);
  if (s.walletAddress) lines.push(`- Wallet address screened: \`${s.walletAddress}\``);
  lines.push("");

  for (const per of report.perSource) {
    const meta = SOURCE_META[per.sourceId];
    lines.push(`## ${sourceLabel(per.sourceId)} (${per.sourceId}) — ${meta.authority} [${meta.category}/${meta.provenance}]`);
    lines.push("");
    if (per.status === "gap") {
      lines.push(`- **GAP** — source not screened (NOT clear): ${per.reason}`);
      lines.push("");
      continue;
    }
    lines.push(`- Source verdict: **${per.sourceVerdict.toUpperCase()}**`);
    lines.push(`- Screened against list version(s) ${cite(per.listRefs)} — ${per.matches.length} match(es)`);
    if (per.matches.length === 0) {
      lines.push(`- CLEAR on this source (provable absence: the cited attested list versions did not contain the subject)`);
    } else {
      lines.push("");
      lines.push("| severity | score | method | subject name | matched | program | cites |");
      lines.push("|---|---|---|---|---|---|---|");
      for (const m of per.matches) {
        lines.push(
          `| ${m.severity} | ${m.score.toFixed(4)} | ${m.method} | ${m.subjectName} | ${m.listEntryExcerpt.replace(/\|/g, "\\|")} | ${m.program.replace(/\|/g, "\\|")} | ${cite(m.citations)} |`,
        );
      }
    }
    lines.push("");
  }

  lines.push("## List versions (attested downloads)");
  for (const v of report.listVersions) {
    lines.push("");
    lines.push(`### ${v.id} — ${v.label} (${v.sourceId}, ${v.mode})`);
    lines.push("");
    lines.push(`- authority: ${SOURCE_META[v.sourceId].authority} [${SOURCE_META[v.sourceId].category}/${SOURCE_META[v.sourceId].provenance}]`);
    lines.push(`- url: ${v.url}`);
    if (v.publicationDate) lines.push(`- list publication/generation date (declared by the source): ${v.publicationDate}`);
    lines.push(`- fetchedAt: ${v.fetchedAt}${v.mode === "cached" ? " (served from cache — original fetch time)" : ""}`);
    lines.push(`- bodyHash: sha256:${v.bodyHash} (body not embedded — lists are megabytes, hash-only)`);
    lines.push(`- attestation digest: ${v.attestation.digest}`);
    lines.push(`- attestation scheme: ${v.attestation.scheme} — ${v.attestation.note.split(" — ")[0]}`);
  }
  lines.push("");

  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Emission
// ---------------------------------------------------------------------------

export interface EmittedScreening {
  dir: string;
  jsonPath: string;
  mdPath: string;
}

export async function writeScreeningReport(report: ScreeningReport, dir: string): Promise<EmittedScreening> {
  await mkdir(dir, { recursive: true });
  const jsonPath = join(dir, "report.json");
  const mdPath = join(dir, "report.md");
  await writeFile(jsonPath, JSON.stringify(report, null, 2) + "\n", "utf8");
  await writeFile(mdPath, renderScreeningMarkdown(report), "utf8");
  return { dir, jsonPath, mdPath };
}

// ---------------------------------------------------------------------------
// Third-party verification
// ---------------------------------------------------------------------------

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

const METHODS: readonly string[] = ["exact", "jaro-winkler", "token-overlap", "wallet-exact", "edgar-registration", "pep-match"];
const SEVERITIES: readonly string[] = ["match", "potential-match", "info"];
const VERDICTS: readonly string[] = ["clear", "potential-match", "match"];
const MODES: readonly string[] = ["fresh", "cached", "fixture"];

/**
 * Third-party re-verification over ONLY the parsed report.json.
 *
 * @param expectedSources when the buyer knows the panel they commissioned,
 *   every id here MUST appear in the report's declared panel — this is the
 *   defense against "drop a whole source to hide a hit": internal consistency
 *   (panel == covered) is always checked, but only the caller knows the panel
 *   should have contained, say, the EU list.
 */
export function verifyScreening(reportJson: unknown, expectedSources: readonly SourceId[] = []): VerifyScreeningResult {
  const problems: string[] = [];
  let attestationsChecked = 0;
  let matchesChecked = 0;

  if (!isObject(reportJson)) {
    return { valid: false, problems: ["report is not a JSON object"], attestationsChecked, matchesChecked };
  }
  const report = reportJson;

  if (report.version !== 2) problems.push(`unknown report version ${String(report.version)}`);
  const subject = report.subject;
  if (!isObject(subject) || typeof subject.name !== "string" || subject.name.trim().length === 0) {
    problems.push("subject is missing or has no name");
  } else if (subject.kind !== "person" && subject.kind !== "entity" && subject.kind !== "wallet") {
    problems.push(`subject.kind "${String(subject.kind)}" is unknown`);
  }
  if (typeof report.screenedAt !== "string" || Number.isNaN(Date.parse(report.screenedAt))) {
    problems.push("screenedAt is not a valid timestamp");
  }

  // List versions: attestation signatures re-verified from scratch.
  const versionsById = new Map<string, { sourceId: string }>();
  const listVersions = Array.isArray(report.listVersions) ? report.listVersions : null;
  if (!listVersions) {
    problems.push("listVersions is not an array");
  } else {
    for (const [i, raw] of listVersions.entries()) {
      if (!isObject(raw)) {
        problems.push(`listVersions[${i}] is not an object`);
        continue;
      }
      const v = raw as unknown as ListVersion;
      const label = typeof v.id === "string" && v.id.length > 0 ? v.id : `listVersions[${i}]`;
      if (typeof v.id !== "string" || v.id.length === 0) {
        problems.push(`${label} has no id`);
        continue;
      }
      if (versionsById.has(v.id)) problems.push(`duplicate list version id ${v.id}`);
      if (!SOURCE_IDS.includes(v.sourceId as SourceId)) problems.push(`${label}: unknown sourceId "${String(v.sourceId)}"`);
      if (!MODES.includes(v.mode)) problems.push(`${label}: unknown mode "${String(v.mode)}"`);
      versionsById.set(v.id, { sourceId: String(v.sourceId) });

      if (typeof v.url !== "string" || typeof v.fetchedAt !== "string" || typeof v.bodyHash !== "string" || !isObject(v.attestation)) {
        problems.push(`${label} is missing url/fetchedAt/bodyHash/attestation`);
        continue;
      }
      if (v.publicationDate !== undefined && typeof v.publicationDate !== "string") {
        problems.push(`${label}: publicationDate present but not a string`);
      }
      const verdict = verifyAttestedRecord({ url: v.url, fetchedAt: v.fetchedAt, bodyHash: v.bodyHash, attestation: v.attestation });
      attestationsChecked += 1;
      if (!verdict.valid) problems.push(`${label}: attestation invalid — ${verdict.reason}`);
    }
  }

  // Per-source results: gaps have reasons; screened sources cite their own
  // list versions; matches resolve citations and re-derive severity. Each
  // source id may appear at most once (a hidden second entry could shadow a hit).
  const recomputedSeverities: MatchSeverity[] = [];
  const coveredStatus = new Map<SourceId, "screened" | "gap">();
  const perSource = Array.isArray(report.perSource) ? report.perSource : null;
  if (!perSource) {
    problems.push("perSource is not an array");
  } else {
    for (const [i, raw] of perSource.entries()) {
      if (!isObject(raw)) {
        problems.push(`perSource[${i}] is not an object`);
        continue;
      }
      const per = raw as unknown as PerSourceResult;
      const label = `perSource[${i}] (${String(per.sourceId)})`;
      if (!SOURCE_IDS.includes(per.sourceId as SourceId)) problems.push(`${label}: unknown sourceId`);
      else if (coveredStatus.has(per.sourceId)) problems.push(`${label}: source appears more than once in perSource`);

      if (per.status === "gap") {
        if (SOURCE_IDS.includes(per.sourceId as SourceId)) coveredStatus.set(per.sourceId, "gap");
        if (typeof per.reason !== "string" || per.reason.trim().length === 0) {
          problems.push(`${label}: gap has no reason`);
        }
        continue;
      }
      if (per.status !== "screened") {
        problems.push(`${label}: unknown status "${String((per as { status?: unknown }).status)}"`);
        continue;
      }
      if (SOURCE_IDS.includes(per.sourceId as SourceId)) coveredStatus.set(per.sourceId, "screened");
      const sourceSeverities: MatchSeverity[] = [];

      // Provable absence: even a clear source must cite what it screened against.
      if (!Array.isArray(per.listRefs) || per.listRefs.length === 0) {
        problems.push(`${label}: screened source cites no list versions — absence is unprovable`);
      } else {
        for (const ref of per.listRefs) {
          const v = typeof ref === "string" ? versionsById.get(ref) : undefined;
          if (!v) problems.push(`${label}: listRef "${String(ref)}" does not resolve to a list version`);
          else if (v.sourceId !== per.sourceId) problems.push(`${label}: listRef ${String(ref)} belongs to source ${v.sourceId}`);
        }
      }

      if (!Array.isArray(per.matches)) {
        problems.push(`${label}: matches is not an array`);
        continue;
      }
      for (const [j, rawMatch] of per.matches.entries()) {
        if (!isObject(rawMatch)) {
          problems.push(`${label}.matches[${j}] is not an object`);
          continue;
        }
        const m = rawMatch as unknown as Match;
        const mLabel = `${label}.matches[${j}]`;
        matchesChecked += 1;

        if (!METHODS.includes(m.method)) problems.push(`${mLabel}: unknown method "${String(m.method)}"`);
        if (!SEVERITIES.includes(m.severity)) problems.push(`${mLabel}: unknown severity "${String(m.severity)}"`);
        if (typeof m.score !== "number" || !(m.score >= 0 && m.score <= 1)) {
          problems.push(`${mLabel}: score ${String(m.score)} is not in [0, 1]`);
        }
        if (typeof m.matchedName !== "string" || m.matchedName.length === 0) problems.push(`${mLabel}: missing matchedName`);

        if (!Array.isArray(m.citations) || m.citations.length === 0) {
          problems.push(`${mLabel}: has zero citations — every match must cite an attested list download`);
        } else {
          for (const c of m.citations) {
            const v = typeof c === "string" ? versionsById.get(c) : undefined;
            if (!v) problems.push(`${mLabel}: citation "${String(c)}" does not resolve to a list version`);
            else if (v.sourceId !== per.sourceId) problems.push(`${mLabel}: citation ${String(c)} belongs to source ${v.sourceId}`);
          }
        }

        // Severity is DERIVED, not asserted: re-derive from (method, score).
        if (METHODS.includes(m.method) && typeof m.score === "number") {
          const derived = severityForMatch(m.method as MatchMethod, m.score);
          if (derived === null) {
            problems.push(`${mLabel}: score ${m.score} is below the potential-match threshold — this match should not exist`);
          } else {
            sourceSeverities.push(derived);
            if (derived !== m.severity) {
              problems.push(`${mLabel}: recorded severity "${String(m.severity)}" but (method=${m.method}, score=${m.score}) derives "${derived}"`);
            }
          }
        }
      }

      // Per-source verdict is DERIVED from this source's recomputed severities —
      // a source that recorded matches but claims "clear" (or vice versa) is
      // caught here, before the panel/overall aggregation.
      const derivedSourceVerdict = aggregateVerdict(sourceSeverities);
      if (!VERDICTS.includes(per.sourceVerdict as string)) {
        problems.push(`${label}: unknown sourceVerdict "${String(per.sourceVerdict)}"`);
      } else if (per.sourceVerdict !== derivedSourceVerdict) {
        problems.push(`${label}: recorded sourceVerdict "${String(per.sourceVerdict)}" but its matches recompute to "${derivedSourceVerdict}"`);
      }
      recomputedSeverities.push(...sourceSeverities);
    }
  }

  // Declared panel must be exactly the set of sources covered by perSource —
  // no missing source (a dropped list is the classic way to hide a hit) and no
  // phantom source. When the caller knows the commissioned panel, every
  // expected source must be present in the declared panel too.
  const panel = Array.isArray(report.panel) ? (report.panel as unknown[]) : null;
  if (!panel) {
    problems.push("panel is not an array");
  } else {
    const panelIds: SourceId[] = [];
    for (const p of panel) {
      if (typeof p !== "string" || !SOURCE_IDS.includes(p as SourceId)) {
        problems.push(`panel entry "${String(p)}" is not a known source id`);
      } else if (panelIds.includes(p as SourceId)) {
        problems.push(`panel lists source ${p} more than once`);
      } else {
        panelIds.push(p as SourceId);
      }
    }
    for (const id of panelIds) {
      if (!coveredStatus.has(id)) problems.push(`panel declares source ${id} but perSource has no result for it`);
    }
    for (const id of coveredStatus.keys()) {
      if (!panelIds.includes(id)) problems.push(`perSource covers source ${id} which is not in the declared panel`);
    }
    for (const id of expectedSources) {
      if (!panelIds.includes(id)) problems.push(`expected source ${id} is missing from the screening panel`);
    }
  }

  // Completeness recomputed from the recorded gaps: a "clear" that hides an
  // unreachable source behind screeningComplete=true is a false all-clear.
  const recomputedComplete = coveredStatus.size > 0 && [...coveredStatus.values()].every((s) => s === "screened") && (!panel || panel.length === coveredStatus.size);
  if (typeof report.screeningComplete !== "boolean") {
    problems.push("screeningComplete is not a boolean");
  } else if (report.screeningComplete !== recomputedComplete) {
    problems.push(`recorded screeningComplete=${report.screeningComplete} but recorded gaps recompute to ${recomputedComplete}`);
  }

  // Verdict recomputed from the recomputed severities — a downgraded (or
  // inflated) verdict cannot survive this.
  const recomputedVerdict: Verdict = aggregateVerdict(recomputedSeverities);
  if (!VERDICTS.includes(report.verdict as string)) {
    problems.push(`unknown verdict "${String(report.verdict)}"`);
  } else if (report.verdict !== recomputedVerdict) {
    problems.push(`recorded verdict "${String(report.verdict)}" but recorded matches recompute to "${recomputedVerdict}"`);
  }

  return { valid: problems.length === 0, problems, attestationsChecked, matchesChecked, recomputedVerdict, recomputedComplete };
}
