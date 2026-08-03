/**
 * Wire the sec-audit core into the shared DACS seller layer on the pay-dem
 * session rail (Pattern 2), POSTED-content-only safe slice.
 *
 * The sec-audit agent's full run walks a filesystem tree. That is not safe to
 * sell blind, so — exactly like the gateway's content-only slice (registry.ts
 * §9) — this wire scans only the file content the buyer POSTS: no `walkFiles`,
 * no `fs` access. It reuses the core's own primitives (attest each posted
 * file, scan it with the deterministic rule tables, build citation-bound
 * findings) and seals the assembled `SecAuditReport` exactly as `runAudit`
 * does, so the core's own async `verifyReport` accepts it.
 *
 * Scope is `parameterized` (the files are conveyed at session-open) ⇒ pay-dem
 * session rail. `observeDelivered` re-runs `verifyReport` over the delivered
 * report offline (file-record signatures re-verified, finding citations
 * resolved, seal re-hashed).
 */
import {
  MockDahrAttestor,
  attestFileContentAsync,
  type ContentAttestor,
} from "../../sec-audit/attest-files.js";
import { sealCoreHash } from "../../sec-audit/auditor.js";
import { DEP_RULE } from "../../sec-audit/deps-audit.js";
import {
  formatDeepAuditPricing,
  runDeepAudit,
  verifyDeepAudit,
  type DeepAuditArtifact,
  type DeepAuditDeps,
  type DeepAuditTarget,
} from "../../sec-audit/deep-audit.js";
import { verifyReport } from "../../sec-audit/report.js";
import { REPO_RULE_TABLE } from "../../sec-audit/rules-repo.js";
import { SOL_RULE_TABLE } from "../../sec-audit/rules-solidity.js";
import { scanFileContent } from "../../sec-audit/scanner.js";
import {
  makeFinding,
  severityRank,
  type AttestedFileRecord,
  type Finding,
  type RawHit,
  type ReportSeal,
  type RuleStat,
  type SecAuditReport,
  type SuppressionEntry,
} from "../../sec-audit/types.js";
import type { WorkCallback } from "../seller-adapter.js";
import type { DeliveryVerifyOptions } from "../verifier.js";
import { readReportMeta, reportMeta } from "./report-meta.js";
import { formatFeeSchedule, type FeeSchedule } from "./pricing.js";

/** The DACS serviceId under which the sec-audit desk sells audits. */
export const SEC_AUDIT_SERVICE_ID = "sec-audit";
/** The delivery phase advertised (and required by the session terms). */
export const SEC_AUDIT_DELIVERY_PHASE = "deliver-sec-audit";
/** The files are conveyed at session-open ⇒ pay-dem session rail. */
export const SEC_AUDIT_SCOPE = "parameterized" as const;

/**
 * Usage-based pricing: billed per posted file scanned (a 6-file audit costs
 * proportionally more than a 1-file one), with a 1 DEM billing floor. Numbers
 * are DISPLAY units (DEM), like the Butler's FeeSchedule.
 */
export const SEC_AUDIT_FEES: FeeSchedule = { kind: "per-unit", unitPrice: 0.5, unit: "file", minTotal: 1 };

/** Units for a sec-audit job = the number of posted files to scan. */
export function secAuditUnitsFor(files: readonly unknown[]): number {
  return files.length;
}

/** One posted file to scan. */
export interface PostedFile {
  path: string;
  content: string;
}

/** The listing surface the sec-audit desk advertises on the pay-dem rail. */
export function secAuditListingSpec(price: { amount: string; asset: string }) {
  const fees = SEC_AUDIT_FEES;
  return {
    serviceId: SEC_AUDIT_SERVICE_ID,
    name: "Security-Audit Desk - content-bound static findings",
    description:
      `Defensive static analysis over posted source or Solidity files. Every ` +
      `finding binds to the exact attested content, and the sealed report ` +
      `re-verifies offline. Fee: ${formatFeeSchedule(fees, price.asset)}.`,
    supportedNegotiation: ["negotiate-fixed-price"],
    supportedPaymentRails: ["pay-dem"],
    supportedDelivery: [SEC_AUDIT_DELIVERY_PHASE],
    /** Structured usage-based fee (read by the in-process Butler; NOT anchored). */
    fees,
  };
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

/**
 * Build a sealed `SecAuditReport` over POSTED content only — the runAudit core
 * assembly minus the filesystem walk and the (side-effecting) dependency audit.
 * `verifyReport` accepts the result because the manifest, findings, rule stats,
 * and seal are produced identically.
 */
export async function auditPostedFiles(
  files: readonly PostedFile[],
  attestor: ContentAttestor = new MockDahrAttestor(),
  now: () => Date = () => new Date(),
): Promise<SecAuditReport> {
  const generatedAt = now().toISOString();
  const records: AttestedFileRecord[] = [];
  const recordIdByPath = new Map<string, string>();
  const hits: RawHit[] = [];
  const suppressions: SuppressionEntry[] = [];

  for (const [i, f] of files.entries()) {
    if (typeof f.path !== "string" || typeof f.content !== "string") {
      throw new Error(`sec-audit: files[${i}] needs string path + content`);
    }
    const buf = Buffer.from(f.content, "utf8");
    const record = await attestFileContentAsync(attestor, `A${records.length + 1}`, f.path, buf, now());
    records.push(record);
    recordIdByPath.set(f.path, record.id);
    const result = scanFileContent(f.path, buf, "auto");
    hits.push(...result.hits);
    suppressions.push(...result.suppressions);
  }

  const findings: Finding[] = sortHits(hits).map((hit, i) =>
    makeFinding({
      id: `F${i + 1}`,
      ruleId: hit.ruleId,
      severity: hit.severity,
      file: hit.file,
      line: hit.line,
      excerpt: hit.excerpt,
      rationale: hit.rationale,
      citations: [recordIdByPath.get(hit.file) ?? records[0]!.id],
      origin: "deterministic",
    }),
  );

  const tables = [...REPO_RULE_TABLE, ...SOL_RULE_TABLE, DEP_RULE];
  const ruleStats: RuleStat[] = tables.map((meta) => ({
    ...meta,
    count: findings.filter((f) => f.ruleId === meta.id).length,
  }));

  const core: Omit<SecAuditReport, "seal"> = {
    version: 1,
    target: "(posted content)",
    mode: "auto",
    generatedAt,
    files: records,
    findings,
    llmFindings: [],
    suppressions,
    ruleStats,
    deps: { mode: "skipped", note: "posted-content slice — dependency audit not applicable" },
  };
  const bodyHash = sealCoreHash(core);
  const sealUrl = `report:sec-audit:${generatedAt}`;
  const seal: ReportSeal = {
    url: sealUrl,
    bodyHash,
    attestation: await attestor.attest(sealUrl, generatedAt, bodyHash),
  };
  return { ...core, seal };
}

/**
 * Build the sec-audit work callback over an injected attestor. The buyer
 * conveys `{ files: [{ path, content }] }`; the sealed report is the
 * deliverable.
 */
export function makeSecAuditWork(attestor: ContentAttestor = new MockDahrAttestor()): WorkCallback {
  return async (_jobId, params) => {
    const raw = params.files;
    if (!Array.isArray(raw) || raw.length === 0) throw new Error("sec-audit: params.files must be a non-empty array");
    const files: PostedFile[] = raw.map((f) => ({ path: String((f as PostedFile).path), content: String((f as PostedFile).content) }));

    const report = await auditPostedFiles(files, attestor);
    const meta = reportMeta(report);

    return {
      result: {
        target: report.target,
        filesScanned: report.files.length,
        findings: report.findings.length,
      },
      deliverableRef: `sec-audit:report:${meta.reportHash}`,
      meta,
    };
  };
}

/**
 * `observeDelivered`: re-run the core's async `verifyReport` over the delivered
 * report offline (file-record signatures, finding citations, and seal). No
 * `targetDir` is passed — the posted-content slice has nothing on disk to drift.
 */
export function secAuditObserveDelivered(expectedSellerDid?: string): DeliveryVerifyOptions["observeDelivered"] {
  return async (att) => {
    const read = readReportMeta<SecAuditReport>(att);
    if (!read.ok) return { ok: false, reason: read.reason };
    const verdict = await verifyReport(read.artifact, undefined, expectedSellerDid);
    return verdict.valid
      ? { ok: true }
      : { ok: false, reason: `sec-audit verification failed: ${verdict.problems.join("; ")}` };
  };
}

// ===========================================================================
// DEEP TIER — reputation-staked auditor: real tools in a sandbox + attested
// findings. Sold as a SEPARATE service (heavier work, different pricing) that
// rides the SAME seller/verifier wiring; the buyer conveys a repo (+ optional
// PR/ref) at session open, so scope is `parameterized` ⇒ pay-dem session rail.
// ===========================================================================

/** The DACS serviceId under which the deep auditor sells sandboxed audits. */
export const SEC_AUDIT_DEEP_SERVICE_ID = "sec-audit-deep";
export const SEC_AUDIT_DEEP_DELIVERY_PHASE = "deliver-sec-audit-deep";
export const SEC_AUDIT_DEEP_SCOPE = "parameterized" as const;

/** The listing surface the deep auditor advertises on the pay-dem rail. */
export function secAuditDeepListingSpec() {
  return {
    serviceId: SEC_AUDIT_DEEP_SERVICE_ID,
    name: "Security-Audit Desk (deep) - real tools, attested findings",
    description:
      `Clones your repo and runs REAL security tools (Semgrep, Slither) in an ` +
      `isolated sandbox, plus a dependency-advisory scan and an LLM deep review, ` +
      `then delivers a reputation-staked, re-verifiable findings artifact: the ` +
      `tools provably ran (bound outputHash per tool at the audited headSha), ` +
      `every finding resolves to attested tool output, and the verdict cannot be ` +
      `cleaner than the tools support. Fee: ${formatDeepAuditPricing()}.`,
    supportedNegotiation: ["negotiate-fixed-price"],
    supportedPaymentRails: ["pay-dem"],
    supportedDelivery: [SEC_AUDIT_DEEP_DELIVERY_PHASE],
  };
}

/** The compact `result` digest carried in the 200 body + hashed into resultHash. */
export interface DeepAuditResult {
  target: string;
  ref: string;
  headSha: string;
  verdict: DeepAuditArtifact["verdict"];
  tools: string[];
  findings: number;
}

/**
 * Build the deep-audit work callback. The buyer conveys `{ repo, pullNumber?,
 * ref? }`; the sealed `DeepAuditArtifact` is the deliverable (carried as the
 * signed delivery-attestation meta via `reportMeta`). The heavy ports (sandbox,
 * repo fetch, registry, LLM) are injected here so tests/offline runs wire fakes.
 */
export function makeSecAuditDeepWork(deps: DeepAuditDeps): WorkCallback {
  return async (_jobId, params) => {
    const repo = typeof params.repo === "string" ? params.repo : "";
    if (!repo) throw new Error("sec-audit-deep: params.repo (owner/name) is required");
    const target: DeepAuditTarget = {
      repo,
      pullNumber: typeof params.pullNumber === "number" ? params.pullNumber : undefined,
      ref: typeof params.ref === "string" ? params.ref : undefined,
    };

    const artifact = await runDeepAudit(deps, target);
    const result: DeepAuditResult = {
      target: artifact.target,
      ref: artifact.ref,
      headSha: artifact.headSha,
      verdict: artifact.verdict,
      tools: artifact.tools.map((t) => t.name),
      findings: artifact.findings.length,
    };

    return {
      result,
      deliverableRef: `sec-audit-deep:${artifact.headSha}:${artifact.seal.bodyHash.slice(0, 12)}`,
      meta: reportMeta(artifact),
    };
  };
}

/**
 * `observeDelivered`: re-run `verifyDeepAudit` over the delivered artifact
 * offline — seal re-hashed, every finding's contentHash + tool binding checked,
 * each tool's findingsHash re-derived, and the verdict backbone re-enforced with
 * NO fail-open (an attested "clean" over a tool-reported critical is rejected).
 */
export function secAuditDeepObserveDelivered(): DeliveryVerifyOptions["observeDelivered"] {
  return async (att) => {
    const read = readReportMeta<DeepAuditArtifact>(att);
    if (!read.ok) return { ok: false, reason: read.reason };
    const verdict = verifyDeepAudit(read.artifact);
    return verdict.valid
      ? { ok: true }
      : { ok: false, reason: `sec-audit-deep verification failed: ${verdict.problems.join("; ")}` };
  };
}
