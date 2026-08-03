/**
 * ReviewBot — the seller agent. Sells LLM code review: "pay me, I post a
 * review on your PR, from my CCI-verified GitHub identity."
 *
 * The SDK gives the seller exactly ONE verb — `publishListing`. Everything else
 * about being a seller (fulfilment, delivery attestation, attesting to the deal
 * from the seller's side) is not in the SDK today: `runSession` is buyer-only
 * and the AttestationBundle it emits is one-sided (the buyer's copy,
 * `anchoredByRole: "buyer"`). See FINDINGS.md F3/F5.
 *
 * So this agent carries the seller-side lifecycle app-side:
 *   - `deliverReview()` — do the work (post the review on GitHub as the
 *     CCI-bound login) and sign+anchor a DACS-X delivery attestation over the
 *     resulting GitHub state (SIG-4 extension separator — the standard's
 *     mechanism for artifact kinds outside the v0.1 registry).
 *   - `fulfil()` — anchor the seller's copy of the attestation bundle over the
 *     same content-addressed refs (the hand-rolled §10.4.3 two-sided form).
 */
import {
  ARTIFACT_SEPARATORS,
  buildSignedArtifact,
  contentHash,
  dacsXSeparator,
  sha256Hex,
  signedBytes,
  stripSignature,
} from "@kynesyslabs/dacs";
import type { AttestationBundle, Listing } from "@kynesyslabs/dacs";
import { computeFee, formatFeeSchedule, roundFee, type FeeSchedule } from "../../roster/dacs/wire/pricing.js";
import { renderVerdictMarkdown, type EvaluationDecision, type EvaluationVerdict } from "./evaluator.js";
// FINDINGS F2: sessionAnchorName isn't exported from the public barrel, so we
// can't reconstruct where the buyer anchored each artifact without reaching in.
import { sessionAnchorName } from "../../sdk/dist/agent/runSessionCore.js";
import type { Signer } from "@kynesyslabs/dacs";
import type { GitHubPort, SubstratePort } from "../ports.js";
import { countChangedLines, heuristicReview } from "./review-llm.js";

/** The slice of an identity the seller needs (mock and live identities both fit). */
export interface SellerIdentity {
  did: string;
  sign: Signer;
}

export interface ReviewService {
  serviceId: string;
  name: string;
  description: string;
  /** The GitHub login this seller CLAIMS to control (proven — or not — via CCI). */
  githubLogin: string;
  /** Payment rails offered (default: pay-x402). Live mode offers pay-dem (§9.5.9). */
  rails?: string[];
  /**
   * Usage-based fee to advertise in the listing description (a big review costs
   * proportionally more than a tiny one). Priced per 100 diff lines; sized by
   * `reviewBotUnitsFor` at buy time. Omit to advertise no explicit fee.
   */
  fees?: FeeSchedule;
  /** Display asset label for the advertised fee (default DEM). */
  feeAsset?: string;
}

/**
 * ReviewBot's usage-based fee: billed per 100 CHANGED lines of the PR diff
 * (units are `ceil(changedLines / 100)`), with a 1-DEM billing floor. Sizing
 * by changed lines — not total diff lines — is the fair effort metric: a
 * context-heavy diff (hundreds of unchanged context lines around a two-line
 * fix) is a two-line review, and shouldn't bill like a 500-line rewrite.
 * Numbers are DISPLAY units, like the Butler's FeeSchedule.
 */
export const REVIEWBOT_FEES: FeeSchedule = {
  kind: "per-unit",
  unitPrice: 0.5,
  unit: "100-changed-lines",
  minTotal: 1,
};

/**
 * Units for a review job = ceil(changedLines / 100). Changed lines are the
 * `+`/`-` body lines only (excludes the `+++`/`---` file headers, `@@` hunk
 * headers and unchanged context). The per-review price floor lives in
 * `computeFee` (minTotal), so tiny/empty diffs still bill the 1-DEM minimum.
 */
export function reviewBotUnitsFor(diff: string): number {
  return Math.ceil(countChangedLines(diff) / 100);
}

/** The advertised total (display units) for a review sized by its diff. */
export function reviewBotPriceFor(diff: string, fees: FeeSchedule = REVIEWBOT_FEES): number {
  return computeFee(fees, reviewBotUnitsFor(diff));
}

/**
 * Evaluator pricing — the evaluator does real compute (clones, sandboxes, runs
 * the check suite), so it is priced by WORK DONE, not diff size: a small base
 * plus a per-check fee. Deterministic given the number of checks that ran
 * (`evaluatorPriceFor(checks.length)`), so the bill is reproducible from the
 * attested verdict's check list. Numbers are DISPLAY units (like FeeSchedule).
 */
export interface EvaluatorPricing {
  /** Flat base fee for accepting the job (fetch + review). */
  base: number;
  /** Per mechanical check actually run (install/build/test/typecheck/advisory). */
  perCheck: number;
}

export const EVALUATOR_PRICING: EvaluatorPricing = { base: 2, perCheck: 1 };

/** Total bill (display units) = base + perCheck × (checks that ran). */
export function evaluatorPriceFor(numChecks: number, p: EvaluatorPricing = EVALUATOR_PRICING): number {
  return roundFee(p.base + p.perCheck * Math.max(0, numChecks));
}

/** Human-readable evaluator fee for a listing description. */
export function formatEvaluatorPricing(p: EvaluatorPricing = EVALUATOR_PRICING, asset = "DEM"): string {
  return `${p.base} ${asset} base + ${p.perCheck} ${asset} per check`;
}

/** DACS-X delivery attestation — the artifact kind the bundle can't carry yet (F5). */
export const DELIVERY_ATTESTATION_SEPARATOR = dacsXSeparator("delivery-attestation");

/**
 * DACS-X EVALUATION-VERDICT attestation — the settleable deliverable. Unlike the
 * review attestation (which only proves "a review was posted"), this carries the
 * ACTUAL mechanical results: per-check {name, exitCode, passed, outputHash}, the
 * headSha, and the final verdict, signed from the seller's CCI identity. A third
 * party re-verifies the signature and — given the same headSha + workspace — can
 * re-run to reproduce the checks. v1 is self-attested-from-identity; the seam for
 * stronger DAHR / attested-compute proofs is documented on `provenance` below.
 */
export const EVALUATION_ATTESTATION_SEPARATOR = dacsXSeparator("evaluation-verdict");

/** The reproducibility-bearing slice of a CheckResult that rides in the attestation. */
export interface AttestedCheck {
  name: string;
  exitCode: number;
  passed: boolean;
  /** sha256 of the check's full stdout+stderr — re-run and compare to reproduce. */
  outputHash: string;
}

export interface EvaluationAttestation {
  kind: "dacs-x-evaluation-verdict";
  jobId: string;
  repo: string;
  pullNumber: number;
  /** PR head commit the checks ran against. */
  headSha: string;
  verdict: EvaluationDecision;
  checks: AttestedCheck[];
  /**
   * v1 = "self-attested-from-identity": the seller signs its own claim that it
   * ran these checks. A stronger form (DAHR-attested compute / a TEE receipt
   * over the sandbox run) slots in here later WITHOUT changing the bound fields.
   */
  provenance: "self-attested-from-identity";
  /** GitHub review id posted alongside (0 when only the artifact was delivered). */
  reviewId: number;
  /** Author login of the companion review (the seller's CCI-bound login), or "". */
  ghAuthor: string;
  deliveredAt: string;
}

export interface DeliveryAttestation {
  kind: "dacs-x-delivery-attestation";
  jobId: string;
  repo: string;
  pullNumber: number;
  reviewId: number;
  /** GitHub login that authored the review (must be the seller's CCI-bound login). */
  ghAuthor: string;
  /** DAHR attestation commitment over the PR's reviews endpoint after delivery. */
  ghStateHash: string;
  deliveredAt: string;
}

export class SellerAgent {
  constructor(
    private readonly id: SellerIdentity,
    private readonly sub: SubstratePort,
    private readonly gh: GitHubPort,
    private readonly githubLogin: string,
    /**
     * Override the review generator (live mode: a real LLM call via
     * `makeReviewer()`). May be sync or async. Defaults to the deterministic
     * `heuristicReview` so tests/offline runs need no LLM. Whatever is injected,
     * `deliverReview` still falls back to the heuristic if it throws — a
     * prompt-injected diff must not crash delivery.
     */
    private readonly generateReviewFn: (
      title: string,
      diff: string,
    ) => string | Promise<string> = heuristicReview,
  ) {}

  get did(): string {
    return this.id.did;
  }

  /** Publish a signed, anchored usage-based listing (DACS-1). Returns its ref. */
  async publishListing(service: ReviewService): Promise<string> {
    // The advertised fee lives in the human description — the anchored DACS-1
    // Listing schema has no fee field, so a live buyer reads the rate here (an
    // in-process buyer reads the structured FeeSchedule directly). ASCII-only.
    const feeText = service.fees
      ? ` Fee: ${formatFeeSchedule(service.fees, service.feeAsset ?? "DEM")}.`
      : "";
    const listing: Listing = {
      agentId: this.id.did,
      serviceId: service.serviceId,
      name: service.name,
      // The GitHub claim rides in the description for now: the seller's claims
      // have no first-class home until IdentityBundle (DACS-1) lands upstream
      // (dacs-sdk#9). The buyer does NOT trust this string — it checks the
      // claim against CCI during Vet.
      description: `${service.description}${feeText} [github:${service.githubLogin}]`,
      claimRequirements: [],
      supportedNegotiation: ["negotiate-fixed-price"],
      supportedPaymentRails: service.rails ?? ["pay-x402"],
      supportedDelivery: ["deliver-github-pr-review"],
    };
    const signed = await buildSignedArtifact(listing, ARTIFACT_SEPARATORS.Listing, this.id.sign);
    return this.sub.anchor(`dacs1:listing:${this.id.did}:${service.serviceId}`, signed);
  }

  /**
   * Do the paid work: review the PR and post it on GitHub as this seller's
   * login, then sign + anchor the DACS-X delivery attestation.
   *
   * Idempotent per jobId: if a delivery attestation is already anchored for
   * this job AND its review is still on the PR, return that instead of posting
   * a second review — so a retry after an anchor/network failure (e.g. the
   * review posted but the anchor didn't) doesn't double-post or re-charge.
   *
   * The review body comes from `generateReviewFn` (a real LLM in live mode,
   * the deterministic heuristic offline). The diff is UNTRUSTED input, so the
   * generator is wrapped in try/catch: a prompt-injected diff that makes the
   * generator throw degrades to the heuristic; delivery never crashes on it,
   * and no payment decision depends on the review's content.
   */
  async deliverReview(jobId: string, target: { repo: string; pullNumber: number }): Promise<{
    attestationRef: string;
    reviewBody: string;
    reused: boolean;
  }> {
    const pull = this.gh.getPull(target.repo, target.pullNumber);
    if (!pull) throw new Error(`deliverReview: no PR ${target.repo}#${target.pullNumber}`);

    // Idempotency: reuse a prior delivery for this job if its review survives.
    const priorAddr = await this.sub.anchorAddress(`dacsx:delivery:${jobId}`);
    const priorRaw = await this.sub.read(priorAddr);
    if (priorRaw) {
      const prior = stripSignature(priorRaw) as unknown as DeliveryAttestation;
      const priorReview = this.gh
        .listReviews(target.repo, target.pullNumber)
        .find((r) => r.id === prior.reviewId && r.user.login === this.githubLogin);
      if (priorReview) return { attestationRef: priorAddr, reviewBody: priorReview.body, reused: true };
      // Attestation exists but the review is gone — fall through and re-deliver.
    }

    let reviewBody: string;
    try {
      reviewBody = await this.generateReviewFn(pull.title, pull.diff);
    } catch {
      reviewBody = heuristicReview(pull.title, pull.diff);
    }
    const review = this.gh.postReview(this.githubLogin, target.repo, target.pullNumber, reviewBody);

    // Attest the delivered state: DAHR-shaped commitment over the reviews
    // endpoint, signed under the DACS-X separator, anchored on the substrate.
    const reviewsUrl = `https://api.github.com/repos/${target.repo}/pulls/${target.pullNumber}/reviews`;
    const attestation: DeliveryAttestation = {
      kind: "dacs-x-delivery-attestation",
      jobId,
      repo: target.repo,
      pullNumber: target.pullNumber,
      reviewId: review.id,
      ghAuthor: this.githubLogin,
      ghStateHash: this.gh.stateHash(reviewsUrl),
      deliveredAt: review.submitted_at,
    };
    const signed = await buildSignedArtifact(
      attestation,
      DELIVERY_ATTESTATION_SEPARATOR as never,
      this.id.sign,
    );
    const attestationRef = await this.sub.anchor(`dacsx:delivery:${jobId}`, signed);
    return { attestationRef, reviewBody, reused: false };
  }

  /**
   * Deliver an ATTESTED EVALUATION VERDICT — the settleable product. Given a
   * verdict computed by the EvaluatorAgent (fetch → sandboxed checks → LLM
   * review), this signs + anchors a DACS-X evaluation attestation that carries
   * the actual per-check {name, exitCode, passed, outputHash}, the headSha, and
   * the verdict. Optionally also posts a human summary review on the PR (when
   * `postReview` is true and the verdict names a real head).
   *
   * Idempotent per jobId: a retry after an anchor/network failure reuses the
   * prior attestation instead of re-posting or re-charging.
   */
  async deliverEvaluation(
    jobId: string,
    target: { repo: string; pullNumber: number; title?: string },
    verdict: EvaluationVerdict,
    opts: { postReview?: boolean } = {},
  ): Promise<{ attestationRef: string; reviewId: number; reused: boolean }> {
    // Idempotency: reuse a prior evaluation attestation for this job.
    const priorAddr = await this.sub.anchorAddress(`dacsx:evaluation:${jobId}`);
    const priorRaw = await this.sub.read(priorAddr);
    if (priorRaw) {
      const prior = stripSignature(priorRaw) as unknown as EvaluationAttestation;
      return { attestationRef: priorAddr, reviewId: prior.reviewId, reused: true };
    }

    // Optionally post the human companion review on the PR as the CCI-bound
    // login. GitHub is only touched when a review is actually requested — an
    // artifact-only delivery needs no GitHub port at all.
    let reviewId = 0;
    let ghAuthor = "";
    let deliveredAt = new Date().toISOString();
    if (opts.postReview) {
      const pull = this.gh.getPull(target.repo, target.pullNumber);
      if (pull) {
        const body = renderVerdictMarkdown(target.title ?? `${target.repo}#${target.pullNumber}`, verdict);
        const review = this.gh.postReview(this.githubLogin, target.repo, target.pullNumber, body);
        reviewId = review.id;
        ghAuthor = this.githubLogin;
        deliveredAt = review.submitted_at;
      }
    }

    const attestation: EvaluationAttestation = {
      kind: "dacs-x-evaluation-verdict",
      jobId,
      repo: target.repo,
      pullNumber: target.pullNumber,
      headSha: verdict.headSha,
      verdict: verdict.verdict,
      checks: verdict.checks.map((c) => ({
        name: c.name,
        exitCode: c.exitCode,
        passed: c.passed,
        outputHash: c.outputHash,
      })),
      provenance: "self-attested-from-identity",
      reviewId,
      ghAuthor,
      deliveredAt,
    };
    const signed = await buildSignedArtifact(
      attestation,
      EVALUATION_ATTESTATION_SEPARATOR as never,
      this.id.sign,
    );
    const attestationRef = await this.sub.anchor(`dacsx:evaluation:${jobId}`, signed);
    return { attestationRef, reviewId, reused: false };
  }

  /**
   * Seller-side attestation of the completed deal: read the buyer's anchored
   * bundle for the deal's content-addressed refs, anchor a seller-signed copy
   * over the SAME refs (hand-rolled §10.4.3 two-sided form). Returns its ref.
   */
  async fulfil(jobId: string, buyerOwner: string): Promise<string> {
    // The buyer's bundle lives at a BUYER-owned anchor address (owner-scoped
    // on the real substrate; same shared namespace in memory).
    const buyerBundleRaw = await this.sub.read(
      await this.sub.anchorAddressFor(buyerOwner, sessionAnchorName.bundle(jobId)),
    );
    if (!buyerBundleRaw) throw new Error(`seller.fulfil: no buyer bundle for job ${jobId}`);
    const buyer = stripSignature(buyerBundleRaw) as unknown as AttestationBundle;

    const body: AttestationBundle = {
      bundleVersion: buyer.bundleVersion,
      jobId: buyer.jobId,
      outcome: buyer.outcome,
      anchoredByRole: "seller",
      listingRef: buyer.listingRef,
      agreementRef: buyer.agreementRef,
      parties: [
        {
          role: "seller",
          bundleHash: sha256Hex(this.id.did),
          primaryClaim: this.id.did,
        },
      ],
      phaseSummary: buyer.phaseSummary,
      vetRecords: buyer.vetRecords,
      settlementEvidence: buyer.settlementEvidence,
      recipeRegistryVersion: buyer.recipeRegistryVersion,
      railRegistryVersion: buyer.railRegistryVersion,
      finalisedAt: buyer.finalisedAt,
    };
    const scope = { ...body };
    delete scope.anchoredByRole;
    const sig = await this.id.sign(signedBytes(ARTIFACT_SEPARATORS.AttestationBundle, contentHash(scope)));

    const signedBundle = {
      ...body,
      signatures: [
        { party: this.id.did, algorithm: "ed25519", value: Buffer.from(sig).toString("base64url") },
      ],
    };
    return this.sub.anchor(`dacs5:bundle:seller:${jobId}`, signedBundle);
  }
}
