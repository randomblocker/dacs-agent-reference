/**
 * Buyer agent — a repo owner paying for a PR review.
 *
 * A thin wrapper over the SDK's `runSessionCore`, which drives the whole buyer
 * flow: discover -> Vet (DACS-2) -> fixed-price negotiate (DACS-3) -> Settle
 * (DACS-4) -> emit + anchor the AttestationBundle (DACS-5). Everything except
 * the substrate, the identity resolution, and the payment rail is the SDK's;
 * we inject those.
 *
 * Two design moves worth reading:
 *
 * 1. Vet = CCI + GitHub, composed. The listing merely CLAIMS a GitHub login;
 *    the buyer resolves the seller's DID through CCI (does this DID actually
 *    control that login?) and only then probes the login's GitHub profile via
 *    the DAHR proxy (`vetCore` consensus-backed-proxy). An impostor claiming
 *    someone else's login dies at the CCI step — before any payment.
 *
 * 2. Settle = pay-then-await-delivery, inside the SDK's `settle` seam. Same
 *    pattern the x402 rail uses to couple payment with delivery: the injected
 *    settle only reports ok after the review is observably on GitHub, authored
 *    by the CCI-bound login. So the bundle's `outcome: "completed"` genuinely
 *    means DELIVERED, money-safely — with no SDK changes.
 *
 * NOTE (FINDINGS F1): `runSessionCore` is NOT re-exported from the public
 * `@kynesyslabs/dacs` barrel — imported from the built SDK internals.
 */
import {
  ARTIFACT_SEPARATORS,
  buildSignedArtifact,
  discoverListings,
  isListing,
  stripSignature,
  verifySignedArtifact,
  vetCore,
} from "@kynesyslabs/dacs";
import type {
  CompositeVerificationRecord,
  Listing,
  SessionResult,
  SessionTerms,
  Signer,
} from "@kynesyslabs/dacs";
import {
  runSessionCore,
  type SessionDeps,
} from "../../sdk/dist/agent/runSessionCore.js";
import type { CciPort, SubstratePort } from "../ports.js";
import type { GhReview } from "../github.js";
import { resolveFromDid, verify } from "../identity.js";

/** The slice of an identity the buyer needs (mock and live identities both fit). */
export interface BuyerIdentity {
  did: string;
  evm: string;
  sign: Signer;
}

export interface ReviewOrder {
  jobId: string;
  /** The login the seller's listing claims (checked against CCI, not trusted). */
  claimedGithubLogin: string;
  repo: string;
  pullNumber: number;
  /**
   * Fires after payment lands — "the seller's watcher notices the payment and
   * does the work". In-process this is wired to the seller's deliverReview;
   * against real infrastructure it's simply waiting.
   */
  awaitDelivery: () => Promise<void>;
  /**
   * Optional Vet override. Default is the consensus-backed-proxy recipe against
   * the DAHR-mounted GitHub profile; live mode passes a `cci-claim` recipe
   * (dacs-sdk #13) that checks the on-chain CCI binding directly.
   */
  vetFn?: (subject: string) => Promise<CompositeVerificationRecord>;
  /** Optional settle override (e.g. a real rail). Defaults to the mock rail. */
  settleFn?: SessionDeps["settle"];
}

export class BuyerAgent {
  constructor(
    private readonly id: BuyerIdentity,
    private readonly sub: SubstratePort,
    private readonly cci: CciPort,
  ) {}

  get did(): string {
    return this.id.did;
  }

  /** Resolve + structurally validate anchored listings (DACS-1 discover). */
  async discover(refs: string[]): Promise<Array<{ ref: string; listing: Listing }>> {
    return discoverListings(refs, (r) => this.sub.read(r), {
      resolvePublicKey: async (claim) => resolveFromDid(claim),
      verify,
    });
  }

  /** Run one fixed-price review session against a listing. */
  async buy(listingRef: string, terms: SessionTerms, order: ReviewOrder): Promise<SessionResult> {
    const reviewsUrl = `https://api.github.com/repos/${order.repo}/pulls/${order.pullNumber}/reviews`;

    const deps: SessionDeps = {
      buyerId: this.id.did,
      readListing: (r) => this.sub.read(r),
      sign: (artifact, sep) => buildSignedArtifact(artifact, sep as never, this.id.sign),
      signBytes: async (bytes) => this.id.sign(bytes),
      anchor: (name, value) => this.sub.anchor(name, value),
      resolveAnchor: async (name) => {
        try {
          const ref = await this.sub.anchorAddress(name);
          const value = await this.sub.read(ref);
          return value ? { status: "present" as const, ref, value } : { status: "absent" as const };
        } catch (error) {
          return {
            status: "indeterminate" as const,
            reason: error instanceof Error ? error.message : String(error),
          };
        }
      },
      verifyListing: async (raw, sellerClaim) => {
        const key = resolveFromDid(sellerClaim);
        return Boolean(
          key
          && isListing(stripSignature(raw))
          && await verifySignedArtifact(raw, ARTIFACT_SEPARATORS.Listing, key, verify),
        );
      },

      // Vet (DACS-2): CCI first — resolve which GitHub login this DID PROVED
      // it controls. If the binding is missing or doesn't match the listing's
      // claim, we probe an unresolvable authority so the recipe records a
      // clean `fail` (vetCore's methods are status-code-only today; a
      // CCI-aware recipe method is FINDINGS F6). On a CCI match, the authority
      // is the login's real GitHub profile via the DAHR proxy.
      // Live mode overrides this with a real `cci-claim` recipe via vetFn.
      vet: order.vetFn ?? (async (subject) => {
        const boundLogin = await this.cci.githubLoginFor(subject);
        const cciOk = boundLogin !== null && boundLogin === order.claimedGithubLogin;
        const authorityUrl = cciOk
          ? `https://api.github.com/users/${boundLogin}`
          : `cci:unbound-claim/${order.claimedGithubLogin}`;
        return vetCore(
          {
            subject,
            recipe: {
              id: "github-identity-via-cci",
              method: "consensus-backed-proxy",
              availability: "live",
              params: { authorityUrl },
            },
          },
          {
            // vetCore wants body?: string — stringify whatever the port returns.
            proxyFetch: async (req) => {
              const r = await this.sub.proxyFetch(req);
              return {
                status: r.status,
                responseHash: r.responseHash,
                body: typeof r.body === "string" ? r.body : JSON.stringify(r.body ?? null),
              };
            },
            now: () => new Date().toISOString(),
          },
        );
      }),

      // Settle (DACS-4): pay, then await delivery, then confirm it on GitHub.
      // ok=true ONLY once a review authored by the CCI-bound login exists on
      // the agreed PR — the x402 coupling pattern, applied to review-work.
      settle: order.settleFn ?? (async (req) => {
        const txHash =
          "0x" + Buffer.from(`${req.jobId}:${req.payee}`).toString("hex").padEnd(64, "0").slice(0, 64);

        await order.awaitDelivery();

        const boundLogin = await this.cci.githubLoginFor(req.payee);
        const state = await this.sub.proxyFetch({ url: reviewsUrl });
        // Guard the shape: a 404 body isn't an array — treat as "not delivered"
        // (a clean unpaid-ok=false) rather than throwing inside settle. A null
        // CCI binding also yields delivered=false, so no payment is confirmed.
        const reviews: GhReview[] = Array.isArray(state.body) ? (state.body as GhReview[]) : [];
        const delivered = boundLogin !== null && reviews.some((r) => r.user.login === boundLogin);

        return {
          ok: delivered,
          txHash,
          chainId: "eip155:84532",
          payer: this.id.evm,
          payee: req.payee,
        };
      }),

      newJobId: () => order.jobId,
      now: () => new Date().toISOString(),
      nowMs: () => Date.now(),
    };

    return runSessionCore(listingRef, terms, deps);
  }
}
