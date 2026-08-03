/**
 * DDResearcher — orchestrating core.
 *
 * research(subject): gather attested evidence → derive rule-based findings
 * (every one cites evidence) → synthesize an executive summary → DDReport.
 *
 * Summary synthesis is deterministic by default (template over finding
 * counts/titles, fully reproducible). When enabled (DD_USE_LLM=1 or
 * `useLlm: true`) and the `claude` CLI is on PATH, `claude -p` writes 5-8
 * sentences of prose over the findings JSON instead — guarded by try/catch
 * + timeout, and used for PRESENTATION ONLY: the LLM never adds, removes,
 * or edits findings, so it cannot introduce uncited claims into the
 * verifiable part of the report. Any LLM failure falls back silently to the
 * deterministic summary.
 */
import { execFile } from "node:child_process";
import { gatherEvidence } from "./evidence.js";
import { deriveFindings } from "./findings.js";
import type { AttestedFetchPort, DDReport, Finding, SourceGap, Subject } from "./types.js";
import { subjectLabel } from "./types.js";

export interface ResearcherOptions {
  /** Clock injection for deterministic tests. Default: () => new Date(). */
  now?: () => Date;
  /** Try `claude -p` for the summary. Default: process.env.DD_USE_LLM === "1". */
  useLlm?: boolean;
  /** Kill the LLM call after this long. Default 45s. */
  llmTimeoutMs?: number;
  /** Direct API seam; when absent the legacy claude CLI path is used. */
  llm?: (prompt: string, timeoutMs: number) => Promise<string>;
}

// ---------------------------------------------------------------------------
// Summaries
// ---------------------------------------------------------------------------

export function deterministicSummary(subject: Subject, findings: Finding[], gaps: SourceGap[]): string {
  const red = findings.filter((f) => f.severity === "red-flag");
  const caution = findings.filter((f) => f.severity === "caution");
  const info = findings.filter((f) => f.severity === "info");

  const sentences: string[] = [];
  sentences.push(
    `Due diligence on ${subjectLabel(subject)} produced ${findings.length} finding(s): ` +
      `${red.length} red-flag, ${caution.length} caution, ${info.length} informational.`,
  );
  if (red.length > 0) sentences.push(`Red flags: ${red.map((f) => f.title).join("; ")}.`);
  if (caution.length > 0) sentences.push(`Cautions: ${caution.map((f) => f.title).join("; ")}.`);
  if (gaps.length > 0) {
    sentences.push(
      `${gaps.length} source(s) could not be reached (${gaps.map((g) => g.source).join(", ")}), so the report is degraded.`,
    );
  }
  if (red.length > 0) {
    sentences.push("Recommendation: do not proceed until the red flags are resolved or accepted in writing.");
  } else if (caution.length > 0) {
    sentences.push("Recommendation: no red flags, but review the cautions before proceeding.");
  } else {
    sentences.push("Recommendation: no red flags or cautions surfaced from the gathered evidence.");
  }
  sentences.push("Every finding above cites attested evidence items; see the appendix for hashes and attestation digests.");
  return sentences.join(" ");
}

/**
 * Ask the `claude` CLI for a 5-8 sentence summary of the findings JSON.
 * Returns undefined on ANY failure (CLI missing, timeout, empty/garbage
 * output) — the caller then keeps the deterministic summary.
 */
export async function tryLlmSummary(subject: Subject, findings: Finding[], gaps: SourceGap[], timeoutMs: number, llm?: (prompt: string, timeoutMs: number) => Promise<string>): Promise<string | undefined> {
  const prompt =
    `You are writing the executive summary of a due-diligence report on ${subjectLabel(subject)}. ` +
    `Use ONLY the findings JSON below — do not add facts, numbers, or judgements that are not in it, ` +
    `and do not mention evidence that is not cited there. Write 5-8 plain-text sentences, no headings, no lists.\n\n` +
    `Findings JSON:\n${JSON.stringify({ findings, unreachableSources: gaps.map((g) => g.source) }, null, 2)}`;

  try {
    const stdout = llm
      ? await llm(prompt, timeoutMs)
      : await new Promise<string>((resolve, reject) => {
          execFile("claude", ["-p", prompt], { timeout: timeoutMs, maxBuffer: 1024 * 1024 }, (err, out) =>
            err ? reject(err) : resolve(out),
          );
        });
    const text = stdout.trim();
    // Sanity bounds — a summary, not an essay and not an error banner.
    if (text.length < 80 || text.length > 4_000) return undefined;
    return text;
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// Researcher
// ---------------------------------------------------------------------------

export class DDResearcher {
  constructor(
    private readonly fetchPort: AttestedFetchPort,
    private readonly opts: ResearcherOptions = {},
  ) {}

  async research(subject: Subject): Promise<DDReport> {
    const { evidence, gaps } = await gatherEvidence(this.fetchPort, subject);
    const now = this.opts.now?.() ?? new Date();
    const findings = deriveFindings(evidence, now);

    let summary: DDReport["summary"] = {
      text: deterministicSummary(subject, findings, gaps),
      method: "deterministic",
    };
    const useLlm = this.opts.useLlm ?? process.env.DD_USE_LLM === "1";
    if (useLlm) {
      const llmText = await tryLlmSummary(subject, findings, gaps, this.opts.llmTimeoutMs ?? 45_000, this.opts.llm);
      if (llmText !== undefined) summary = { text: llmText, method: "llm" };
    }

    return { version: 1, subject, generatedAt: now.toISOString(), evidence, gaps, findings, summary };
  }
}
