/**
 * Verifier / auditor agent — the "anyone" role in DACS.
 *
 * Read-only: no keys that move money, no rails. It (1) independently verifies
 * an anchored attestation bundle (DACS-5: signature over the §10.4.1 signed
 * scope PLUS dereferencing every referenced artifact and hash-checking it),
 * (2) verifies the DACS-X delivery attestation against BOTH its signature and
 * the live GitHub state (the fulfilment proof the bundle can't carry yet —
 * FINDINGS F5), (3) reconciles the buyer's and seller's two copies
 * (a hand-rolled §10.4.3 check), and (4) derives reputation from bundles.
 *
 * This agent is the scene with no centralized equivalent: it audits deals it
 * never participated in, from anchored artifacts alone.
 */
import {
  computeReputation,
  stripSignature,
  verifyBundleCore,
  verifySignedArtifact,
} from "@kynesyslabs/dacs";
import type {
  AttestationBundle,
  BundleVerification,
  Reputation,
  VerifyBundleDeps,
} from "@kynesyslabs/dacs";
// FINDINGS F2: needed to map (kind, jobId) -> anchor address; not public.
import { sessionAnchorName } from "../../sdk/dist/agent/runSessionCore.js";
import { resolveFromDid, verify } from "../identity.js";
import type { CciPort, SubstratePort } from "../ports.js";
import {
  DELIVERY_ATTESTATION_SEPARATOR,
  EVALUATION_ATTESTATION_SEPARATOR,
  type DeliveryAttestation,
  type EvaluationAttestation,
} from "./seller.js";
import { verdictConsistentWithChecks } from "./evaluator.js";
import type { GhReview } from "../github.js";

export interface Reconciliation {
  reconciled: boolean;
  reason?: string;
  jobId?: string;
}

export interface DeliveryVerification {
  ok: boolean;
  reason?: string;
  attestation?: DeliveryAttestation;
}

export interface EvaluationVerification {
  ok: boolean;
  reason?: string;
  attestation?: EvaluationAttestation;
}

/**
 * Who anchored what — needed on the real substrate, where anchor addresses are
 * owner-scoped. The session artifacts (vet/agreement/evidence/bundle) are
 * buyer-anchored; the delivery attestation + the bundle copy are seller-anchored.
 * In memory mode the owner is ignored (one shared namespace).
 */
export interface DealOwners {
  buyer: string;
  seller: string;
}

export class VerifierAgent {
  constructor(
    private readonly sub: SubstratePort,
    private readonly cci: CciPort,
  ) {}

  private deps(owners?: DealOwners): VerifyBundleDeps {
    return {
      readArtifact: (r) => this.sub.read(r),
      resolveRef: async (kind, jobId) => {
        const name =
          kind === "dacs-3-agreement"
            ? sessionAnchorName.agreement(jobId)
            : kind === "dacs-4-evidence"
              ? sessionAnchorName.evidence(jobId)
              : kind === "dacs-2-verifyresult"
                ? sessionAnchorName.vet(jobId)
                : null;
        if (!name) return null;
        const addr = owners
          ? await this.sub.anchorAddressFor(owners.buyer, name)
          : await this.sub.anchorAddress(name);
        return this.sub.read(addr);
      },
      resolvePublicKey: async (did) => resolveFromDid(did),
      verify,
    };
  }

  /** Independently verify an anchored bundle (signature + referenced-artifact integrity). */
  async verify(bundleRef: string, owners?: DealOwners): Promise<BundleVerification> {
    return verifyBundleCore(bundleRef, this.deps(owners));
  }

  /**
   * Verify the DACS-X delivery attestation for a job: (a) the seller's
   * signature over the attestation (SIG-4 separator), (b) the seller's DID is
   * CCI-bound to the login the attestation names, and (c) the review is
   * actually on GitHub — right PR, right author, and the attested state hash
   * matches what the verifier's OWN attested fetch sees now.
   */
  async verifyDelivery(jobId: string, sellerDid: string): Promise<DeliveryVerification> {
    // The attestation is a SELLER-owned anchor (owner-scoped on-chain).
    const raw = await this.sub.read(
      await this.sub.anchorAddressFor(sellerDid, `dacsx:delivery:${jobId}`),
    );
    if (!raw) return { ok: false, reason: "no delivery attestation anchored" };

    const key = resolveFromDid(sellerDid);
    if (!key) return { ok: false, reason: "seller key unresolvable" };
    const sigOk = await verifySignedArtifact(raw, DELIVERY_ATTESTATION_SEPARATOR as never, key, verify);
    if (!sigOk) return { ok: false, reason: "attestation signature invalid (tampered or wrong signer)" };

    const att = stripSignature(raw) as unknown as DeliveryAttestation;

    // The attestation binds its own jobId — check it matches the job asked for,
    // so a signed-but-mis-addressed attestation (wrong job) can't pass here.
    if (att.jobId !== jobId)
      return { ok: false, reason: `attestation jobId ${att.jobId} does not match ${jobId}`, attestation: att };

    const boundLogin = await this.cci.githubLoginFor(sellerDid);
    if (boundLogin !== att.ghAuthor)
      return { ok: false, reason: `attested author ${att.ghAuthor} is not CCI-bound to the seller`, attestation: att };

    const reviewsUrl = `https://api.github.com/repos/${att.repo}/pulls/${att.pullNumber}/reviews`;
    const state = await this.sub.proxyFetch({ url: reviewsUrl });
    // Guard the shape: a 404 (missing PR) returns a non-array body — treat it
    // as "no reviews" (a clean fail) rather than throwing on `.some`.
    const reviews: GhReview[] = Array.isArray(state.body) ? (state.body as GhReview[]) : [];
    const present = reviews.some((r) => r.id === att.reviewId && r.user.login === att.ghAuthor);
    if (!present)
      return { ok: false, reason: "attested review not found on GitHub (or wrong author)", attestation: att };
    if (state.responseHash !== att.ghStateHash)
      return { ok: false, reason: "GitHub state hash diverged from the attested state", attestation: att };

    return { ok: true, attestation: att };
  }

  /**
   * Verify the DACS-X EVALUATION-VERDICT attestation for a job — the settleable
   * check. Enforces, with NO fail-open:
   *   (a) the seller's signature over the attestation (SIG-4 separator),
   *   (b) the attestation's jobId matches the job asked for,
   *   (c) it binds a non-empty headSha and a check list,
   *   (d) BACKBONE CONSISTENCY: an "approve" verdict is only valid if every
   *       bound gating check passed — the objective, LLM-independent invariant a
   *       third party can enforce (a seller can't sign "approve" over a red suite),
   *   (e) if a companion review was posted (reviewId>0), its author is CCI-bound
   *       to the seller and the review is actually on GitHub.
   *
   * A verdict artifact with reviewId===0 (artifact-only delivery) is fully valid
   * — the bound check results + verdict ARE the product.
   */
  async verifyEvaluation(jobId: string, sellerDid: string): Promise<EvaluationVerification> {
    const raw = await this.sub.read(
      await this.sub.anchorAddressFor(sellerDid, `dacsx:evaluation:${jobId}`),
    );
    if (!raw) return { ok: false, reason: "no evaluation attestation anchored" };

    const key = resolveFromDid(sellerDid);
    if (!key) return { ok: false, reason: "seller key unresolvable" };
    const sigOk = await verifySignedArtifact(raw, EVALUATION_ATTESTATION_SEPARATOR as never, key, verify);
    if (!sigOk) return { ok: false, reason: "attestation signature invalid (tampered or wrong signer)" };

    const att = stripSignature(raw) as unknown as EvaluationAttestation;

    if (att.jobId !== jobId)
      return { ok: false, reason: `attestation jobId ${att.jobId} does not match ${jobId}`, attestation: att };
    if (!att.headSha || att.headSha.length === 0)
      return { ok: false, reason: "attestation binds no headSha", attestation: att };
    if (!Array.isArray(att.checks))
      return { ok: false, reason: "attestation binds no check list", attestation: att };

    // Backbone consistency — the crux of settleability: the attested verdict must
    // not contradict the attested mechanical results.
    if (!verdictConsistentWithChecks(att.verdict, att.checks))
      return { ok: false, reason: "verdict 'approve' contradicts a failed gating check", attestation: att };

    // Companion review (if any) must be on GitHub, authored by the CCI-bound login.
    if (att.reviewId > 0) {
      const boundLogin = await this.cci.githubLoginFor(sellerDid);
      if (boundLogin !== att.ghAuthor)
        return { ok: false, reason: `attested review author ${att.ghAuthor} is not CCI-bound to the seller`, attestation: att };
      const reviewsUrl = `https://api.github.com/repos/${att.repo}/pulls/${att.pullNumber}/reviews`;
      const state = await this.sub.proxyFetch({ url: reviewsUrl });
      const reviews: GhReview[] = Array.isArray(state.body) ? (state.body as GhReview[]) : [];
      const present = reviews.some((r) => r.id === att.reviewId && r.user.login === att.ghAuthor);
      if (!present)
        return { ok: false, reason: "attested companion review not found on GitHub (or wrong author)", attestation: att };
    }

    return { ok: true, attestation: att };
  }

  /**
   * Two-sided reconcile (§10.4.3, hand-rolled): both copies must verify, and
   * must agree on jobId, the agreement they reference, and the outcome. Because
   * the signed scope excludes `anchoredByRole`, buyer and seller copies of the
   * same deal share the same agreement/evidence refs by construction.
   */
  async reconcile(
    buyerBundleRef: string,
    sellerBundleRef: string,
    owners?: DealOwners,
  ): Promise<Reconciliation> {
    const [vb, vs] = await Promise.all([
      this.verify(buyerBundleRef, owners),
      this.verify(sellerBundleRef, owners),
    ]);
    if (!vb.ok) return { reconciled: false, reason: `buyer copy failed: ${vb.reason}` };
    if (!vs.ok) return { reconciled: false, reason: `seller copy failed: ${vs.reason}` };

    const b = vb.bundle!;
    const s = vs.bundle!;
    if (b.jobId !== s.jobId) return { reconciled: false, reason: "jobId mismatch" };
    if (b.agreementRef.contentHash !== s.agreementRef.contentHash)
      return { reconciled: false, reason: "agreementRef content-hash mismatch" };
    if (b.outcome !== s.outcome) return { reconciled: false, reason: "outcome mismatch" };
    return { reconciled: true, jobId: b.jobId };
  }

  /** Derive a claim's reputation from a set of anchored bundles (DACS-5). */
  async reputation(primaryClaim: string, bundleRefs: string[]): Promise<Reputation> {
    const bundles: AttestationBundle[] = [];
    for (const ref of bundleRefs) {
      const raw = await this.sub.read(ref);
      if (raw) bundles.push(stripSignature(raw) as unknown as AttestationBundle);
    }
    return computeReputation(primaryClaim, bundles);
  }
}
