/**
 * Registry — the heart of the gateway. Wraps each of the 9 roster agent
 * cores as an AgentEndpoint exposing ONLY its safe / read-only slice:
 *
 *   procurement-butler  offline stub marketplace → ProcurementDecision
 *   oracle-desk         LIVE attested fetch      → attested data value
 *   dd-researcher       LIVE                     → DD report
 *   dep-upgrade         real registry            → UpgradePlan ONLY (no apply/PR)
 *   evalbot             offline deterministic    → EvaluationRuling
 *   treasury-ops        pure                     → { plan, approval } (NEVER execute)
 *   site-auditor        LIVE probes              → SiteAuditReport
 *   sec-audit           posted content only      → findings (NO fs walk)
 *   compliance          LIVE + cache             → ScreeningReport
 *
 * Each invoke is a thin adapter from the wire input to the core call. Nothing
 * writes to chain, filesystem, npm, GitHub, or a CRM.
 */
import type { AgentEndpoint, GatewayPorts, RequestContext } from "./types.js";
import { AgentInputError, defineAgent } from "./types.js";

// --- agent cores ------------------------------------------------------------
import { ProcurementButler, DEFAULT_CONFIG } from "../procurement-butler/butler.js";
import type { PaymentRail, ProcurementGoal } from "../procurement-butler/types.js";

import { CATALOG, findProduct, validateParams } from "../oracle-desk/catalog.js";
import type { DataProduct } from "../oracle-desk/types.js";

import { DDResearcher } from "../dd-researcher/researcher.js";
import type { Subject } from "../dd-researcher/types.js";

import { parseInventory } from "../dep-upgrade/inventory.js";
import { buildPlan, resolveCurrentVersion } from "../dep-upgrade/planner.js";
import type { Advisory, Packument } from "../dep-upgrade/types.js";

import { EvalBot, validateRubric } from "../evalbot/evalbot.js";
import { buildJudgePrompt, parseJudgeOutput, type JudgeFn } from "../evalbot/llm-judge.js";
import type { EvaluationJob, Rubric, Deliverable as EvalDeliverable } from "../evalbot/types.js";

import { plan as treasuryPlan } from "../treasury-ops/planner.js";
import { approve as treasuryApprove } from "../treasury-ops/approval.js";
import type { BalanceSnapshot, TreasuryPolicy } from "../treasury-ops/types.js";

import { SiteAuditor } from "../site-auditor/auditor.js";

import { attestFileContentAsync } from "../sec-audit/attest-files.js";
import { scanFileContent } from "../sec-audit/scanner.js";
import { auditDependencies } from "../sec-audit/deps-audit.js";
import { makeFinding, type AttestedFileRecord, type Finding, type RawHit } from "../sec-audit/types.js";
import { buildLlmPrompt, parseLlmOutput } from "../sec-audit/llm-pass.js";

import { loadAll, screenSubject } from "../compliance/screener.js";
import type { ScreeningSubject, SubjectKind } from "../compliance/types.js";

// ---------------------------------------------------------------------------
// Small input coercers
// ---------------------------------------------------------------------------

/** Coerce an arbitrary params object to Record<string,string> for the oracle. */
function stringifyParams(raw: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return out;
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (v === undefined || v === null) continue;
    out[k] = typeof v === "string" ? v : String(v);
  }
  return out;
}

/** Capability vocabulary the butler's stub marketplace understands. */
const CAPABILITY_VOCAB = [
  "code-analysis",
  "summarization",
  "documentation",
  "architecture-review",
  "image-generation",
  "risk-scoring",
];

/** Derive required capabilities from a free-text goal (fallback: summarization). */
function capabilitiesFromGoal(goal: string): string[] {
  const g = goal.toLowerCase();
  const hits = CAPABILITY_VOCAB.filter((c) => g.includes(c) || g.includes(c.replace(/-/g, " ")));
  return hits.length > 0 ? hits : ["summarization"];
}

// ---------------------------------------------------------------------------
// Registry builder
// ---------------------------------------------------------------------------

export function buildRegistry(ports: GatewayPorts): AgentEndpoint[] {
  const catalog: DataProduct[] = ports.catalog ?? CATALOG;

  return [
    // -----------------------------------------------------------------------
    // 1. procurement-butler — offline stub marketplace
    // -----------------------------------------------------------------------
    defineAgent({
      name: "procurement-butler",
      summary: "Buyer-side procurement over a stubbed marketplace: capability filter, scoring, bounded negotiation → ProcurementDecision.",
      mode: "offline — in-memory stub marketplace, deterministic, no network",
      fields: [
        { name: "goal", type: "string", required: true, desc: "what to procure, e.g. 'summarize this repository's architecture'" },
        { name: "budgetUsd", type: "number", required: true, min: 0, desc: "spending ceiling in USD" },
        { name: "railPreference", type: "string[]", required: false, desc: "payment rails in descending preference (pay-dem, pay-x402, pay-evm-erc8183)" },
      ],
      async invoke(input) {
        const { goal, budgetUsd, railPreference } = input as {
          goal: string;
          budgetUsd: number;
          railPreference?: string[];
        };
        const railPref = (railPreference ?? DEFAULT_CONFIG.railPreference) as PaymentRail[];
        const config = { ...DEFAULT_CONFIG, railPreference: railPref };
        const procurementGoal: ProcurementGoal = {
          description: goal,
          requiredCapabilities: capabilitiesFromGoal(goal),
        };
        const butler = new ProcurementButler(ports.marketplace, ports.marketplace, config);
        return butler.procure(procurementGoal, budgetUsd);
      },
    }),

    // -----------------------------------------------------------------------
    // 2. oracle-desk — LIVE attested fetch
    // -----------------------------------------------------------------------
    defineAgent({
      name: "oracle-desk",
      summary: "Per-call attested Web2 data: fetch a keyless public value and return it with a MOCK-DAHR attestation.",
      mode: "LIVE — real upstream fetch through the attested-fetch port",
      fields: [
        { name: "product", type: "string", required: true, enum: catalog.map((p) => p.id), desc: `data product id (${catalog.map((p) => p.id).join(", ")})` },
        { name: "params", type: "object", required: false, desc: "product params (e.g. { id: 'bitcoin' } for crypto-price)" },
      ],
      async invoke(input) {
        const { product, params } = input as { product: string; params?: unknown };
        const dp = findProduct(catalog, product);
        if (!dp) {
          throw new AgentInputError(`unknown product "${product}"`, { available: catalog.map((p) => p.id) });
        }
        const raw = stringifyParams(params);
        const validated = validateParams(dp, raw);
        if (!validated.ok) throw new AgentInputError("invalid product params", validated.problems);

        const upstreamUrl = dp.buildUrl(validated.params);
        // Prefer the real LIVE-DAHR attestor when wired (GATEWAY_LIVE_DAHR=1);
        // otherwise fall back to the shared mock attestor. Same result shape either way.
        const attested = await (ports.oracleAttestedFetch ?? ports.attestedFetch).attestFetch(upstreamUrl);
        if (attested.status >= 400) {
          throw new Error(`upstream ${dp.upstream} responded ${attested.status}`);
        }
        const value = dp.extract(attested.body, validated.params);
        return { product, params: validated.params, value, attestation: attested };
      },
    }),

    // -----------------------------------------------------------------------
    // 3. dd-researcher — LIVE
    // -----------------------------------------------------------------------
    defineAgent({
      name: "dd-researcher",
      summary: "Source-attested due-diligence report on an npm package or crypto token; every finding cites attested evidence.",
      mode: ports.llm ? `LIVE — attested public sources + ${ports.llm.model} evidence-bound summary` : "LIVE — real keyless public sources; deterministic summary fallback",
      fields: [
        { name: "kind", type: "string", required: true, enum: ["npm-package", "crypto-token"], desc: "subject kind" },
        { name: "subject", type: "string", required: true, desc: "npm package name, or CoinGecko coin id" },
      ],
      async invoke(input) {
        const { kind, subject } = input as { kind: "npm-package" | "crypto-token"; subject: string };
        const s: Subject = kind === "npm-package" ? { kind, name: subject } : { kind, id: subject };
        const researcher = new DDResearcher(ports.attestedFetch, {
          useLlm: ports.llm !== undefined,
          llmTimeoutMs: 20_000,
          llm: ports.llm ? (prompt, timeoutMs) => ports.llm!.complete(prompt, { maxTokens: 800, timeoutMs }) : undefined,
        });
        return researcher.research(s);
      },
    }),

    // -----------------------------------------------------------------------
    // 4. dep-upgrade — UpgradePlan ONLY (advisory-driven; no apply/verify/PR)
    // -----------------------------------------------------------------------
    defineAgent({
      name: "dep-upgrade",
      summary: "Advisory-driven dependency upgrade PLAN for a posted package.json. Plan only — never installs, verifies, or opens PRs.",
      mode: "advisory-only — real npm registry reads, NO apply / npm / GitHub side effects",
      fields: [
        { name: "packageJson", type: "object", required: true, desc: "the target package.json contents" },
        { name: "includeNextMajor", type: "boolean", required: false, desc: "also propose opt-in next-major bumps (default false)" },
      ],
      async invoke(input) {
        const { packageJson, includeNextMajor } = input as { packageJson: unknown; includeNextMajor?: boolean };
        let inventory;
        try {
          inventory = parseInventory("(posted)", JSON.stringify(packageJson));
        } catch (err) {
          throw new AgentInputError(`package.json could not be parsed: ${(err as Error).message}`);
        }

        // Registry intel — packuments then one bulk advisory query. No fs, no writes.
        const packuments = new Map<string, Packument>();
        for (const dep of inventory.deps) {
          if (!packuments.has(dep.name)) packuments.set(dep.name, await ports.registry.getPackument(dep.name));
        }
        const advisoryQuery: Record<string, string[]> = {};
        for (const dep of inventory.deps) {
          const current = resolveCurrentVersion(dep, packuments.get(dep.name)!);
          if (current) advisoryQuery[dep.name] = [...(advisoryQuery[dep.name] ?? []), current];
        }
        const advisories =
          Object.keys(advisoryQuery).length > 0
            ? await ports.registry.getAdvisories(advisoryQuery)
            : new Map<string, Advisory[]>();

        const plan = buildPlan(inventory, packuments, advisories, { proposeNextMajor: includeNextMajor === true });
        return { packageName: inventory.packageName, plan };
      },
    }),

    // -----------------------------------------------------------------------
    // 5. evalbot — offline deterministic ruling
    // -----------------------------------------------------------------------
    defineAgent({
      name: "evalbot",
      summary: "Signed, deterministic acceptance ruling on a deliverable against a weighted rubric.",
      mode: ports.llm ? `hybrid — deterministic checks + ${ports.llm.model} subjective scoring; signed ruling` : "offline — rubric engine only, LLM fallback off, signed ruling",
      fields: [
        { name: "rubric", type: "object", required: true, desc: "{ criteria: [...], acceptThreshold, indeterminateBand? }" },
        { name: "deliverable", type: "object", required: true, desc: "{ content: string, label? }" },
        { name: "context", type: "string", required: false, desc: "free-text background (unused when LLM judging is off)" },
      ],
      async invoke(input, ctx) {
        const { rubric, deliverable, context } = input as {
          rubric: Rubric;
          deliverable: EvalDeliverable;
          context?: string;
        };
        if (typeof deliverable.content !== "string") {
          throw new AgentInputError("deliverable.content must be a string");
        }
        try {
          validateRubric(rubric);
        } catch (err) {
          throw new AgentInputError(`invalid rubric: ${(err as Error).message}`);
        }
        const job: EvaluationJob = { jobId: ctx.requestId, rubric, deliverable, context };
        const judge: JudgeFn | undefined = ports.llm
          ? async (criteria, content, judgeContext, timeoutMs) => {
              try {
                const raw = await ports.llm!.complete(buildJudgePrompt(criteria, content, judgeContext), { maxTokens: 1_200, timeoutMs });
                return parseJudgeOutput(raw, criteria.map((criterion) => criterion.id));
              } catch { return undefined; }
            }
          : undefined;
        const bot = new EvalBot({ useLlm: ports.llm !== undefined, llmTimeoutMs: 20_000, signer: ports.rulingSigner, judge });
        return bot.evaluate(job);
      },
    }),

    // -----------------------------------------------------------------------
    // 6. treasury-ops — plan + approve ONLY (NEVER execute)
    // -----------------------------------------------------------------------
    defineAgent({
      name: "treasury-ops",
      summary: "Deterministic treasury plan + approval gate for payroll/rebalancing. Plan and approve only — never executes on-chain.",
      mode: "pure — plan() + approve() only, NO ChainPort / no execution / no chain access",
      fields: [
        { name: "policy", type: "object", required: true, desc: "TreasuryPolicy: accounts, allowlist, payroll, caps" },
        { name: "balances", type: "object", required: true, desc: "BalanceSnapshot: { accountId: number }" },
      ],
      async invoke(input, ctx) {
        const { policy, balances } = input as { policy: TreasuryPolicy; balances: BalanceSnapshot };
        let executionPlan;
        try {
          executionPlan = treasuryPlan(policy, balances, { runId: ctx.requestId });
        } catch (err) {
          throw new AgentInputError(`plan rejected: ${(err as Error).message}`);
        }
        const approval = treasuryApprove(executionPlan, policy, ports.treasuryApprover);
        return { plan: executionPlan, approval };
      },
    }),

    // -----------------------------------------------------------------------
    // 7. site-auditor — LIVE probes
    // -----------------------------------------------------------------------
    defineAgent({
      name: "site-auditor",
      summary: "Attested performance / TLS / security-header / transport audit of a live site.",
      mode: "LIVE — real HTTP + TLS probes through the prober port",
      fields: [
        { name: "url", type: "string", required: true, desc: "site URL or bare host to audit" },
        { name: "samples", type: "integer", required: false, min: 1, max: 5, desc: "timing samples to take (1-5, default 3)" },
      ],
      async invoke(input) {
        const { url, samples } = input as { url: string; samples?: number };
        const auditor = new SiteAuditor(ports.prober, ports.attestor);
        return auditor.audit({ url, ...(samples !== undefined ? { samples } : {}) });
      },
    }),

    // -----------------------------------------------------------------------
    // 8. sec-audit — POSTED content only (NO fs walk)
    // -----------------------------------------------------------------------
    defineAgent({
      name: "sec-audit",
      summary: "Defensive static analysis over POSTED file content (repo + Solidity rules) plus an optional advisory audit of a posted package.json.",
      mode:
        (ports.llm
          ? `hybrid — deterministic rules + segregated ${ports.llm.model} candidates over posted content only`
          : "content-only — deterministic rules, NO filesystem walk / NO fs access") +
        (ports.contentAttestor ? "; persistent DACS identity evidence over file hashes" : "; mock evidence in offline mode"),
      fields: [
        { name: "files", type: "array", required: true, desc: "[{ path: string, content: string }] to scan" },
        { name: "packageJson", type: "object", required: false, desc: "optional package.json object for a dependency-advisory audit" },
      ],
      async invoke(input, ctx) {
        const { files, packageJson } = input as {
          files: Array<{ path?: unknown; content?: unknown }>;
          packageJson?: unknown;
        };
        if (files.length === 0) throw new AgentInputError("files must be a non-empty array");

        const records: AttestedFileRecord[] = [];
        const hits: RawHit[] = [];
        const recordIdByPath = new Map<string, string>();
        for (const [i, f] of files.entries()) {
          if (typeof f.path !== "string" || typeof f.content !== "string") {
            throw new AgentInputError(`files[${i}] must have string "path" and string "content"`);
          }
          const buf = Buffer.from(f.content, "utf8");
          const record = await attestFileContentAsync(
            ports.contentAttestor ?? ctx.attestor,
            `A${records.length + 1}`,
            f.path,
            buf,
          );
          records.push(record);
          recordIdByPath.set(f.path, record.id);
          hits.push(...scanFileContent(f.path, buf, "auto").hits);
        }

        // Optional advisory audit over the POSTED package.json (no fs, no lockfile).
        const pkgText = packageJson !== undefined ? JSON.stringify(packageJson) : null;
        const deps = await auditDependencies(pkgText, undefined, ports.registry, "live");
        hits.push(...deps.hits);

        const findings: Finding[] = hits
          .sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.ruleId.localeCompare(b.ruleId))
          .map((hit, i) =>
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

        let llmFindings: Finding[] = [];
        if (ports.llm && hits.length > 0) {
          const flagged = [...new Set(hits.map((hit) => hit.file))].map((path) => ({
            path,
            excerpts: hits.filter((hit) => hit.file === path).map((hit) => `${hit.line}: ${hit.excerpt}`).slice(0, 30),
          }));
          try {
            const raw = await ports.llm.complete(buildLlmPrompt({ flagged, scannedPaths: [...recordIdByPath.keys()] }), { maxTokens: 1_200, timeoutMs: 20_000 });
            llmFindings = parseLlmOutput(raw, [...recordIdByPath.keys()]).map((hit, i) => makeFinding({
              id: `L${i + 1}`, ruleId: hit.ruleId, severity: hit.severity, file: hit.file, line: hit.line,
              excerpt: hit.excerpt, rationale: hit.rationale,
              citations: [recordIdByPath.get(hit.file) ?? records[0]!.id], origin: "llm-suggested",
            }));
          } catch { /* deterministic findings remain authoritative */ }
        }

        return {
          filesScanned: records.length,
          files: records,
          deps: { mode: deps.mode, note: deps.note },
          findingCount: findings.length,
          findings,
          llmFindingCount: llmFindings.length,
          llmFindings,
        };
      },
    }),

    // -----------------------------------------------------------------------
    // 9. compliance — LIVE + cache
    // -----------------------------------------------------------------------
    defineAgent({
      name: "compliance",
      summary: "Defensive sanctions/registry screening against OFAC SDN + UN consolidated + SEC EDGAR, with attested list downloads.",
      mode: "LIVE + 24h body cache — attested public-list lookups; read-only",
      fields: [
        { name: "kind", type: "string", required: true, enum: ["person", "entity", "wallet"], desc: "subject kind" },
        { name: "name", type: "string", required: false, desc: "primary name (required unless kind=wallet)" },
        { name: "aliases", type: "string[]", required: false, desc: "additional names to screen under" },
        { name: "country", type: "string", required: false, desc: "subject country (informational)" },
        { name: "walletAddress", type: "string", required: false, desc: "wallet address (required when kind=wallet)" },
      ],
      async invoke(input) {
        const { kind, name, aliases, country, walletAddress } = input as {
          kind: SubjectKind;
          name?: string;
          aliases?: string[];
          country?: string;
          walletAddress?: string;
        };
        if (kind === "wallet") {
          if (!walletAddress) throw new AgentInputError("kind=wallet requires walletAddress");
        } else if (!name) {
          throw new AgentInputError(`kind=${kind} requires name`);
        }
        const subject: ScreeningSubject = {
          kind,
          name: name ?? walletAddress ?? "",
          ...(aliases ? { aliases } : {}),
          ...(country ? { country } : {}),
          ...(walletAddress ? { walletAddress } : {}),
        };
        const inputs = await loadAll(ports.complianceSources());
        return screenSubject(subject, inputs);
      },
    }),
  ];
}
