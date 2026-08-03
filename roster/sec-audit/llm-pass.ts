/**
 * Optional LLM pass — candidate ADDITIONAL findings from the `claude` CLI,
 * default OFF. Runs only when the caller wires it in (the demo does so when
 * SEC_USE_LLM=1 and the CLI is on PATH). Its output is marked
 * `origin: "llm-suggested"` and kept in a segregated report section —
 * deterministic findings never depend on it, and ANY failure (no CLI,
 * timeout, non-zero exit, unparseable JSON) degrades to zero suggestions.
 */
import { execFile, execFileSync } from "node:child_process";
import type { RawHit, Severity } from "./types.js";

const VALID_SEVERITIES: ReadonlySet<string> = new Set(["info", "low", "medium", "high", "critical"]);

export interface LlmPassInput {
  /** Files that already have deterministic hits, with their matched lines. */
  flagged: Array<{ path: string; excerpts: string[] }>;
  /** Every scanned relative path — suggestions outside this set are dropped. */
  scannedPaths: string[];
}

export type LlmPassFn = (input: LlmPassInput) => Promise<RawHit[]>;

export function buildLlmPrompt(input: LlmPassInput): string {
  const filesBlock = input.flagged
    .map((f) => `### ${f.path}\n${f.excerpts.map((e) => `- ${e}`).join("\n")}`)
    .join("\n\n");
  return [
    "You are a defensive security reviewer. Below are excerpts (already-flagged lines) from files in a static audit.",
    "Suggest ADDITIONAL candidate security findings ONLY — do not repeat the excerpts' own issues.",
    'Answer with a JSON array (no prose, no code fences): [{"ruleId":"llm-<slug>","severity":"info|low|medium|high|critical","file":"<one of the listed paths>","line":1,"excerpt":"<the suspect line>","rationale":"<why>"}]',
    "Return [] if you have nothing beyond the deterministic findings.",
    "",
    filesBlock,
  ].join("\n");
}

/** Defensive parse: keep only well-shaped entries pointing at scanned files. */
export function parseLlmOutput(stdout: string, scannedPaths: string[]): RawHit[] {
  const scanned = new Set(scannedPaths);
  let parsed: unknown;
  try {
    const start = stdout.indexOf("[");
    const end = stdout.lastIndexOf("]");
    if (start === -1 || end <= start) return [];
    parsed = JSON.parse(stdout.slice(start, end + 1));
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) return [];
  const hits: RawHit[] = [];
  for (const raw of parsed) {
    if (typeof raw !== "object" || raw === null) continue;
    const r = raw as Record<string, unknown>;
    if (typeof r.file !== "string" || !scanned.has(r.file)) continue;
    if (typeof r.rationale !== "string" || r.rationale.trim().length === 0) continue;
    const severity: Severity = VALID_SEVERITIES.has(String(r.severity)) ? (r.severity as Severity) : "info";
    const ruleId = typeof r.ruleId === "string" && /^[a-z][a-z0-9-]*$/.test(r.ruleId) ? r.ruleId : "llm-candidate";
    const line = typeof r.line === "number" && Number.isInteger(r.line) && r.line >= 1 ? r.line : 1;
    hits.push({
      ruleId: ruleId.startsWith("llm-") ? ruleId : `llm-${ruleId}`,
      severity,
      file: r.file,
      line,
      excerpt: typeof r.excerpt === "string" ? r.excerpt.trim() : "",
      rationale: r.rationale.trim(),
    });
  }
  return hits;
}

/** True when the `claude` CLI answers on PATH. */
export function claudeCliAvailable(): boolean {
  try {
    execFileSync("claude", ["--version"], { stdio: "ignore", timeout: 10_000 });
    return true;
  } catch {
    return false;
  }
}

/** The real pass: `claude -p <prompt>` with a hard timeout; [] on ANY failure. */
export const claudeCliPass: LlmPassFn = async (input) => {
  if (input.flagged.length === 0) return [];
  try {
    const stdout = await new Promise<string>((resolve, reject) => {
      execFile(
        "claude",
        ["-p", buildLlmPrompt(input)],
        { timeout: 90_000, maxBuffer: 1024 * 1024 },
        (err, out) => (err ? reject(err) : resolve(out)),
      );
    });
    return parseLlmOutput(stdout, input.scannedPaths);
  } catch {
    return [];
  }
};

/**
 * Env gate the demo (and any caller) uses: the pass is wired ONLY when
 * SEC_USE_LLM=1 AND the CLI is present. Undefined = pass disabled.
 */
export function maybeClaudeCliPass(env: NodeJS.ProcessEnv): LlmPassFn | undefined {
  if (env.SEC_USE_LLM !== "1") return undefined;
  return claudeCliAvailable() ? claudeCliPass : undefined;
}
