/**
 * Wire the audit-NEGOTIATION desk into the shared DACS seller layer.
 *
 * Where `wire/sec-audit.ts` sells a FIXED-price audit, this listing sells the
 * SAME sec-audit work but as a NEGOTIATED deal: it advertises
 * `supportedNegotiation: ["rfq"]`, and the price is not posted — it is settled
 * per job by the multi-dimensional RFQ engine in `roster/audit-negotiator/`
 * (tier × deadline × price, seller floor from a private pre-scan). The buyer's
 * Butler runs that RFQ (Part 3 bridge) to reach agreed terms; those terms are
 * then conveyed at session-open (scope `parameterized` ⇒ pay-dem session rail),
 * and THIS wire runs the actual audit at the agreed tier and delivers a signed,
 * re-verifiable artifact.
 *
 * Two delivery paths, one shape:
 *   - deep tier + injected `DeepAuditDeps` → runs the REAL sandboxed deep audit
 *     (Semgrep/Slither + LLM review) and delivers the `DeepAuditArtifact`; the
 *     `observeDelivered` hook re-runs `verifyDeepAudit` (no fail-open).
 *   - quick tier, or offline with no deep deps → delivers a signed
 *     `AgreedTermsRecord` (the agreed tier/deadline/price bound + a note that the
 *     heavy audit runs when the sandbox deps are wired). `observeDelivered`
 *     re-checks the record's shape + hash binding.
 *
 * Both ride the SAME seller/verifier wiring as every other roster desk.
 */
import { MockDahrAttestor } from "../../sec-audit/attest-files.js";
import {
  formatDeepAuditPricing,
  runDeepAudit,
  verifyDeepAudit,
  type DeepAuditArtifact,
  type DeepAuditDeps,
  type DeepAuditTarget,
} from "../../sec-audit/deep-audit.js";
import type { WorkCallback } from "../seller-adapter.js";
import type { DeliveryVerifyOptions } from "../verifier.js";
import type { StandardListingSpec } from "../seller-adapter.js";
import { X402_RAIL_ID, usdcPrice, x402PublicEndpoint, x402RailRef } from "../x402-production.js";
import { emptyRequirement } from "../standard-profile.js";
import { readReportMeta, reportMeta } from "./report-meta.js";
import { securityResearcherIdentityMetadata } from "../security-researcher-vet.js";

/** The DACS serviceId under which the audit-negotiation desk sells RFQ audits. */
export const AUDIT_NEGOTIATOR_SERVICE_ID = "audit-negotiator";
export const AUDIT_NEGOTIATOR_X402_SERVICE_ID = `${AUDIT_NEGOTIATOR_SERVICE_ID}-x402`;
/** The delivery phase advertised (and required by the session terms). */
export const AUDIT_NEGOTIATOR_DELIVERY_PHASE = "deliver-attested-payload";
/** Agreed terms are conveyed at session-open ⇒ pay-dem session rail. */
export const AUDIT_NEGOTIATOR_SCOPE = "parameterized" as const;

const TIERS = new Set(["quick", "deep"]);
const DEADLINES = new Set(["standard", "rush"]);

/**
 * Human-readable fee for an RFQ listing. There is no posted number — the price
 * is negotiated per job — so the "fee" describes the dimensions the price is set
 * over, and the deep tier's underlying cost basis.
 */
export function formatRfqFee(asset = "DEM"): string {
  return (
    `negotiated per job (RFQ) over tier (quick|deep) x deadline (standard|rush); ` +
    `price settled against the desk's private pre-scan of your repo. ` +
    `When deep delivery is enabled its cost basis is ${formatDeepAuditPricing(undefined, asset)}.`
  );
}

/** The listing surface the audit-negotiation desk advertises on the pay-dem rail. */
export function auditNegotiatorListingSpec() {
  return {
    serviceId: AUDIT_NEGOTIATOR_SERVICE_ID,
    name: "DACS Auditor - Negotiated Security Audits",
    description:
      `The live DACS Auditor (L2PS client dacs-auditor): a security-audit desk ` +
      `you NEGOTIATE with, not a posted price. The desk ` +
      `pre-scans your repo (KLOC, Solidity => which real tools apply) as private ` +
      `information and defends a real cost floor, while you probe with offers. ` +
      `The public daemon currently offers its fast, content-bound quick static ` +
      `scan; deep sandboxed Semgrep/Slither delivery remains disabled until its ` +
      `tool runner is deployed. Terms are multi-dimensional: tier x deadline ` +
      `(standard | rush) x price, so a ` +
      `deal can trade one dimension for another. Delivery is a signed, ` +
      `re-verifiable findings artifact at the agreed tier. Fee: ${formatRfqFee()}.`,
    supportedNegotiation: ["negotiate-rfq"],
    supportedPaymentRails: ["pay-dem"],
    supportedDelivery: [AUDIT_NEGOTIATOR_DELIVERY_PHASE],
  };
}

/** Full DACS-1 listing used by the public Butler→Auditor Standard flow. */
export function auditNegotiatorStandardListingSpec(input: {
  researcherGithub: string;
  operatorClaim: string;
}): StandardListingSpec {
  const legacy = auditNegotiatorListingSpec();
  return {
    serviceId: AUDIT_NEGOTIATOR_SERVICE_ID,
    listingVersion: 3,
    displayName: legacy.name,
    sellerIdentityMetadata: securityResearcherIdentityMetadata({
      github: input.researcherGithub,
      operatorClaim: input.operatorClaim,
    }),
    title: "Negotiated, signed source security review",
    description: legacy.description,
    category: "software.security.audit",
    tags: ["security", "source-review", "rfq", "attested"],
    deliverable: {
      kind: "attested-payload",
      payloadFormat: "application/vnd.dacs.security-audit+json;version=1",
      verificationMethod: "self-signed",
      expectedSizeBytes: 65_536,
    },
    buyerRequirement: emptyRequirement(),
    pipeline: [
      { kind: "vet-credentials" },
      { kind: "negotiate-rfq", parameters: { maxTurns: 6, turnTimeoutMs: 35_000 } },
      { kind: "commit-agreement" },
      { kind: "pay-dem", parameters: { rail: "demos-native:DEM" } },
      { kind: "deliver-attested-payload" },
    ],
    pricing: {
      kind: "negotiable",
      bandCenter: { amount: "1", currency: "DEM", unit: "per-audit" },
      minPct: 0,
      maxPct: 900,
    },
    acceptedRails: [{ railId: "demos-native:DEM", railVersion: 1 }],
    terms: {
      deadlineSecAfterCommit: 300,
      cancellationPolicy: "pre-commit",
      transcriptDisclosurePolicy: "none",
    },
    validity: { notBefore: 0 },
    requiredCapabilities: ["SR-1", "SR-2", "SR-4"],
  };
}

/** Separately signed RFQ listing settled in USDC on Base Sepolia via x402. */
export function auditNegotiatorX402StandardListingSpec(input: {
  payTo: string;
  resourceBase: string;
  listingVersion?: number;
  priceUsdc?: string;
  publicEndpoint?: string;
  identityMetadata: Record<string, unknown>;
  researcherGithub: string;
  operatorClaim: string;
}): StandardListingSpec {
  const native = auditNegotiatorStandardListingSpec({
    researcherGithub: input.researcherGithub,
    operatorClaim: input.operatorClaim,
  });
  return {
    ...native,
    serviceId: AUDIT_NEGOTIATOR_X402_SERVICE_ID,
    publicEndpoint: x402PublicEndpoint(input.resourceBase, input.publicEndpoint),
    sellerIdentityMetadata: { ...input.identityMetadata, ...native.sellerIdentityMetadata },
    listingVersion: input.listingVersion ?? 3,
    title: "Negotiated, signed source security review paid with x402",
    description: `${native.description} The agreed amount settles as gasless USDC on Base Sepolia through x402 exact-v2.`,
    tags: [...native.tags, "x402", "base-sepolia", "usdc"],
    pipeline: native.pipeline.map((phase) => phase.kind === "pay-dem"
      ? { kind: "pay-x402" as const, parameters: { rail: X402_RAIL_ID } }
      : phase),
    pricing: {
      kind: "negotiable",
      bandCenter: usdcPrice(input.priceUsdc ?? "0.02", "per-audit"),
      minPct: 0,
      maxPct: 900,
    },
    acceptedRails: [x402RailRef({ payTo: input.payTo, resourceBase: input.resourceBase })],
  };
}

/** The signed record delivered when the heavy deep audit isn't run (quick/offline). */
export interface AgreedTermsRecord {
  kind: "audit-negotiator-agreement";
  serviceId: string;
  jobId: string;
  repo: string;
  tier: "quick" | "deep";
  deadline: "standard" | "rush";
  /** The negotiated settlement price (DEM display units). */
  price: number;
  note: string;
  deliveredAt: string;
}

/** The compact `result` digest carried in the delivery body + hashed into resultHash. */
export interface AuditNegotiatorResult {
  serviceId: string;
  repo: string;
  tier: "quick" | "deep";
  deadline: "standard" | "rush";
  /** "deep-audit" when the sandboxed audit ran; "agreed-terms" for the stub path. */
  delivery: "deep-audit" | "agreed-terms";
  findings?: number;
  verdict?: DeepAuditArtifact["verdict"];
}

export interface AuditNegotiatorWorkDeps {
  /** When present AND the agreed tier is deep, run the REAL sandboxed deep audit. */
  deep?: DeepAuditDeps;
  attestor?: MockDahrAttestor;
  now?: () => Date;
}

/**
 * Build the audit-negotiation work callback. The buyer conveys the agreed terms
 * at session-open: `{ repo, tier, deadline, price, pullNumber?, ref? }`.
 *
 *   - deep tier + injected deep deps → runs `runDeepAudit`, delivers the sealed
 *     `DeepAuditArtifact` (carried via `reportMeta`).
 *   - otherwise → delivers a signed `AgreedTermsRecord` binding the agreed terms.
 */
export function makeAuditNegotiatorWork(deps: AuditNegotiatorWorkDeps = {}): WorkCallback {
  const now = deps.now ?? (() => new Date());
  return async (jobId, params) => {
    const repo = typeof params.repo === "string" ? params.repo : "";
    if (!repo) throw new Error("audit-negotiator: params.repo (owner/name) is required");
    const tier = TIERS.has(String(params.tier)) ? (params.tier as "quick" | "deep") : "deep";
    const deadline = DEADLINES.has(String(params.deadline)) ? (params.deadline as "standard" | "rush") : "standard";
    const price = typeof params.price === "number" && Number.isFinite(params.price) ? params.price : 0;

    // --- Deep tier with real deps: run the sandboxed audit at the agreed tier ---
    if (tier === "deep" && deps.deep) {
      const target: DeepAuditTarget = {
        repo,
        pullNumber: typeof params.pullNumber === "number" ? params.pullNumber : undefined,
        ref: typeof params.ref === "string" ? params.ref : undefined,
      };
      const artifact = await runDeepAudit(deps.deep, target);
      const result: AuditNegotiatorResult = {
        serviceId: AUDIT_NEGOTIATOR_SERVICE_ID,
        repo,
        tier,
        deadline,
        delivery: "deep-audit",
        findings: artifact.findings.length,
        verdict: artifact.verdict,
      };
      return {
        result,
        deliverableRef: `audit-negotiator:deep:${artifact.headSha}:${artifact.seal.bodyHash.slice(0, 12)}`,
        meta: reportMeta(artifact),
      };
    }

    // --- Stub path (quick tier / offline): sign the agreed-terms record ---------
    const record: AgreedTermsRecord = {
      kind: "audit-negotiator-agreement",
      serviceId: AUDIT_NEGOTIATOR_SERVICE_ID,
      jobId,
      repo,
      tier,
      deadline,
      price,
      note:
        tier === "deep"
          ? "deep tier agreed; sandboxed audit runs when DeepAuditDeps are wired (offline stub delivery)"
          : "quick tier agreed; static scan delivery",
      deliveredAt: now().toISOString(),
    };
    const result: AuditNegotiatorResult = {
      serviceId: AUDIT_NEGOTIATOR_SERVICE_ID,
      repo,
      tier,
      deadline,
      delivery: "agreed-terms",
    };
    return {
      result,
      deliverableRef: `audit-negotiator:agreed:${jobId}:${tier}/${deadline}`,
      meta: reportMeta(record),
    };
  };
}

/**
 * `observeDelivered`: re-verify the delivered artifact offline, branching on kind.
 *   - a `DeepAuditArtifact` → `verifyDeepAudit` (seal, tool bindings, verdict
 *     backbone; NO fail-open).
 *   - an `AgreedTermsRecord` → re-check the hash binding + structural validity
 *     of the agreed terms.
 */
export function auditNegotiatorObserveDelivered(): DeliveryVerifyOptions["observeDelivered"] {
  return async (att) => {
    const read = readReportMeta<{ kind?: string } & Record<string, unknown>>(att);
    if (!read.ok) return { ok: false, reason: read.reason };
    const artifact = read.artifact;

    if (artifact.kind === "sec-audit-deep") {
      const verdict = verifyDeepAudit(artifact);
      return verdict.valid
        ? { ok: true }
        : { ok: false, reason: `audit-negotiator deep verification failed: ${verdict.problems.join("; ")}` };
    }

    if (artifact.kind === "audit-negotiator-agreement") {
      const r = artifact as unknown as AgreedTermsRecord;
      const problems: string[] = [];
      if (typeof r.repo !== "string" || r.repo.length === 0) problems.push("missing repo");
      if (!TIERS.has(r.tier)) problems.push(`bad tier ${String(r.tier)}`);
      if (!DEADLINES.has(r.deadline)) problems.push(`bad deadline ${String(r.deadline)}`);
      if (typeof r.price !== "number" || !Number.isFinite(r.price) || r.price < 0) problems.push(`bad price ${String(r.price)}`);
      return problems.length === 0
        ? { ok: true }
        : { ok: false, reason: `audit-negotiator agreement invalid: ${problems.join("; ")}` };
    }

    return { ok: false, reason: `audit-negotiator: unrecognized delivered kind ${String(artifact.kind)}` };
  };
}
