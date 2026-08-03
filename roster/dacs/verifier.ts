/**
 * VerifierAdapter — the shared "anyone" role, generalized from
 * `src/agents/verifier.ts`.
 *
 * Read-only: no keys that move money, no rails. It (1) independently verifies an
 * anchored AttestationBundle (DACS-5), (2) verifies a per-service DACS-X
 * delivery attestation (signature + optional CCI binding + a per-service
 * `observeDelivered` hook that replaces the reference agent's GitHub-state
 * check), and (3) reconciles buyer/seller copies + derives reputation.
 *
 * The GitHub-specific "is the review really on GitHub" check becomes the
 * injected `observeDelivered(attestation)` hook — e.g. the oracle wire re-checks
 * the embedded DAHR attestation offline.
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
// FINDINGS F2: map (kind, jobId) → anchor address; not public.
import { sessionAnchorName } from "../../sdk/dist/agent/runSessionCore.js";
import { resolveFromDid, verify } from "../../src/identity.js";
import type { CciPort, SubstratePort } from "../../src/ports.js";
import { deliverySeparator, type DeliveryAttestation } from "./seller-adapter.js";

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

/** Who anchored what — owner-scoped on the real substrate; ignored in memory. */
export interface DealOwners {
  buyer: string;
  seller: string;
}

/** Options for verifying one service's delivery attestation. */
export interface DeliveryVerifyOptions {
  serviceId: string;
  sellerDid: string;
  /** Inline signed artifact, accepted only when its anchor receipt was checked by the caller. */
  attestation?: Record<string, unknown>;
  /**
   * Optional CCI-binding requirement: the seller DID must resolve (via the CCI
   * port) to this bound subject. Omit to skip (services without a Web2 claim).
   */
  requireCciBinding?: string;
  /**
   * Per-service "observe delivered state" hook — the generalization of the
   * reference agent's GitHub check. Returns ok/reason over the attestation
   * (e.g. re-verify an embedded oracle attestation). Omit to skip.
   */
  observeDelivered?: (
    attestation: DeliveryAttestation,
  ) => Promise<{ ok: boolean; reason?: string }>;
}

export class VerifierAdapter {
  constructor(
    private readonly sub: SubstratePort,
    private readonly cci?: CciPort,
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
   * Verify a service's DACS-X delivery attestation: (a) the seller's signature
   * over the attestation (per-service SIG-4 separator), (b) optional CCI
   * binding, (c) the optional per-service `observeDelivered` hook.
   */
  async verifyDelivery(jobId: string, opts: DeliveryVerifyOptions): Promise<DeliveryVerification> {
    const raw = opts.attestation ?? await this.sub.read(
      await this.sub.anchorAddressFor(opts.sellerDid, `dacsx:delivery:${jobId}`),
    );
    if (!raw) return { ok: false, reason: "no delivery attestation anchored" };

    const key = resolveFromDid(opts.sellerDid);
    if (!key) return { ok: false, reason: "seller key unresolvable" };
    const sigOk = await verifySignedArtifact(
      raw,
      deliverySeparator(opts.serviceId),
      key,
      verify,
    );
    if (!sigOk) {
      return { ok: false, reason: "attestation signature invalid (tampered or wrong signer)" };
    }

    const att = stripSignature(raw) as unknown as DeliveryAttestation;
    if (att.serviceId !== opts.serviceId) {
      return { ok: false, reason: `serviceId mismatch: attestation is ${att.serviceId}`, attestation: att };
    }

    if (opts.requireCciBinding !== undefined) {
      const bound = this.cci ? await this.cci.githubLoginFor(opts.sellerDid) : null;
      if (bound !== opts.requireCciBinding) {
        return {
          ok: false,
          reason: `CCI binding mismatch: seller bound to ${bound ?? "nothing"}, required ${opts.requireCciBinding}`,
          attestation: att,
        };
      }
    }

    if (opts.observeDelivered) {
      const observed = await opts.observeDelivered(att);
      if (!observed.ok) {
        return { ok: false, reason: observed.reason ?? "delivered state not observed", attestation: att };
      }
    }

    return { ok: true, attestation: att };
  }

  /** Two-sided reconcile (§10.4.3, hand-rolled). */
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
    if (b.agreementRef.contentHash !== s.agreementRef.contentHash) {
      return { reconciled: false, reason: "agreementRef content-hash mismatch" };
    }
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
