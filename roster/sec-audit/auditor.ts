/**
 * Auditor — the orchestrator. Walks the target, attests every scanned
 * file's content (path + sha256 + size, hash-only) under `file:`
 * pseudo-URLs, dispatches the deterministic rule tables per mode, runs the
 * dependency-advisory audit through dep-upgrade's RegistryPort, optionally
 * runs the segregated LLM pass, and seals the whole report with a signature
 * over its canonical JSON so any post-hoc tamper is detectable offline.
 */
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { RegistryPort } from "../dep-upgrade/types.js";
import { MockDahrAttestor, attestFileContent, canonicalJson } from "./attest-files.js";
import { sha256Hex } from "../oracle-desk/attested-fetch.js";
import { DEP_RULE, auditDependencies, type DepsAuditResult } from "./deps-audit.js";
import type { LlmPassFn } from "./llm-pass.js";
import { REPO_RULE_TABLE } from "./rules-repo.js";
import { SOL_RULE_TABLE } from "./rules-solidity.js";
import { readFileBytes, scanFileContent, walkFiles } from "./scanner.js";
import type {
  AttestedFileRecord,
  AuditInput,
  AuditMode,
  Finding,
  RawHit,
  ReportSeal,
  RuleStat,
  SecAuditReport,
  SuppressionEntry,
} from "./types.js";
import { makeFinding, severityRank } from "./types.js";

export interface AuditorOptions {
  /** dep-upgrade RegistryPort for advisory data; omit to skip the deps audit. */
  registry?: RegistryPort;
  /** Which adapter `registry` is, for the report banner. Default "live". */
  registryLabel?: "live" | "canned";
  /** Optional segregated LLM pass (default OFF — see llm-pass.ts). */
  llm?: LlmPassFn;
  attestor?: MockDahrAttestor;
  now?: () => Date;
}

function sortHits(hits: RawHit[]): RawHit[] {
  return [...hits].sort(
    (a, b) =>
      severityRank(a.severity) - severityRank(b.severity) ||
      a.file.localeCompare(b.file) ||
      a.line - b.line ||
      a.ruleId.localeCompare(b.ruleId),
  );
}

/** Seal = MOCK-DAHR signature over the canonical JSON of the report core. */
export function sealCoreHash(core: Omit<SecAuditReport, "seal">): string {
  return sha256Hex(canonicalJson(core));
}

export async function runAudit(input: AuditInput, opts: AuditorOptions = {}): Promise<SecAuditReport> {
  const mode: AuditMode = input.mode ?? "auto";
  const attestor = opts.attestor ?? new MockDahrAttestor();
  const now = opts.now ?? (() => new Date());
  const generatedAt = now().toISOString();

  // --- Walk + attest + deterministic scan -------------------------------
  const relPaths = await walkFiles(input.targetDir);
  const files: AttestedFileRecord[] = [];
  const recordIdByPath = new Map<string, string>();
  const hits: RawHit[] = [];
  const suppressions: SuppressionEntry[] = [];
  const scannedPaths: string[] = [];

  for (const relPath of relPaths) {
    const content = await readFileBytes(input.targetDir, relPath);
    const record = attestFileContent(attestor, `A${files.length + 1}`, relPath, content, now());
    files.push(record);
    recordIdByPath.set(relPath, record.id);

    const result = scanFileContent(relPath, content, mode);
    hits.push(...result.hits);
    suppressions.push(...result.suppressions);
    if (result.scanned) scannedPaths.push(relPath);
  }

  // --- Dependency advisories (repo/auto modes only) ----------------------
  let deps: DepsAuditResult = { mode: "skipped", note: "solidity mode — dependency audit not applicable", hits: [] };
  if (mode !== "solidity") {
    let pkgText: string | null = null;
    let lockText: string | undefined;
    if (recordIdByPath.has("package.json")) {
      pkgText = await readFile(join(input.targetDir, "package.json"), "utf8");
      if (recordIdByPath.has("package-lock.json")) {
        lockText = await readFile(join(input.targetDir, "package-lock.json"), "utf8");
      }
    }
    deps = await auditDependencies(pkgText, lockText, opts.registry ?? null, opts.registryLabel ?? "live");
    hits.push(...deps.hits);
  }

  // --- Hits → findings (citation-by-construction) ------------------------
  const toFinding = (hit: RawHit, id: string, origin: Finding["origin"]): Finding => {
    const recordId = recordIdByPath.get(hit.file);
    return makeFinding({
      id,
      ruleId: hit.ruleId,
      severity: hit.severity,
      file: hit.file,
      line: hit.line,
      excerpt: hit.excerpt,
      rationale: hit.rationale,
      citations: recordId ? [recordId] : [], // empty → makeFinding throws
      origin,
    });
  };

  const findings = sortHits(hits).map((hit, i) => toFinding(hit, `F${i + 1}`, "deterministic"));

  // --- Optional LLM pass (segregated; failures degrade to none) ----------
  let llmFindings: Finding[] = [];
  if (opts.llm) {
    try {
      const flaggedByPath = new Map<string, string[]>();
      for (const f of findings) {
        if (f.file === "package.json") continue;
        const list = flaggedByPath.get(f.file) ?? [];
        list.push(f.excerpt);
        flaggedByPath.set(f.file, list);
      }
      const suggestions = await opts.llm({
        flagged: [...flaggedByPath.entries()].map(([path, excerpts]) => ({ path, excerpts })),
        scannedPaths,
      });
      llmFindings = suggestions
        .filter((s) => recordIdByPath.has(s.file))
        .map((s, i) => toFinding(s, `L${i + 1}`, "llm-suggested"));
    } catch {
      llmFindings = [];
    }
  }

  // --- Rule stats over the deterministic tables --------------------------
  const tables = mode === "solidity" ? SOL_RULE_TABLE : mode === "repo" ? [...REPO_RULE_TABLE, DEP_RULE] : [...REPO_RULE_TABLE, ...SOL_RULE_TABLE, DEP_RULE];
  const ruleStats: RuleStat[] = tables.map((meta) => ({
    ...meta,
    count: findings.filter((f) => f.ruleId === meta.id).length,
  }));

  const core: Omit<SecAuditReport, "seal"> = {
    version: 1,
    target: input.targetDir,
    mode,
    generatedAt,
    files,
    findings,
    llmFindings,
    suppressions,
    ruleStats,
    deps: { mode: deps.mode, note: deps.note },
  };

  const bodyHash = sealCoreHash(core);
  const sealUrl = `report:sec-audit:${generatedAt}`;
  const seal: ReportSeal = { url: sealUrl, bodyHash, attestation: attestor.attest(sealUrl, generatedAt, bodyHash) };

  return { ...core, seal };
}
