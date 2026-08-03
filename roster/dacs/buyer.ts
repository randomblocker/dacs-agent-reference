/**
 * BuyerAdapter — the shared buyer half, generalized from `src/agents/buyer.ts`.
 *
 * A thin wrapper over the SDK's `runSessionCore` (the whole buyer flow:
 * discover → Vet → fixed-price negotiate → Settle → anchor the
 * AttestationBundle). Everything except the substrate and the payment rail is
 * the SDK's; we inject those. The rail (settle seam) is injected wholesale per
 * deal, so the buyer stays service- and rail-agnostic.
 *
 * `makeX402MockSettle` is the x402 settle seam for the mock facilitator: it runs
 * the buyer-side 402 dance against a paywall (GET → 402 → retry with the
 * synthetic proof → 200), then applies the independent delivery check
 * (`ok = pay.ok && delivered`) that the reference agent uses to keep
 * `outcome: "completed"` money-safe.
 *
 * NOTE (FINDINGS F1): `runSessionCore` is NOT on the public `@kynesyslabs/dacs`
 * barrel — deep-imported from the built SDK internals.
 */
import {
  ARTIFACT_SEPARATORS,
  CounterpartyError,
  discoverListings,
  isListing,
  stripSignature,
  verifySignedArtifact,
} from "@kynesyslabs/dacs";
import type {
  CompositeVerificationRecord,
  Listing,
  SessionResult,
  SessionTerms,
  Signer,
} from "@kynesyslabs/dacs";
import { buildSignedArtifact } from "@kynesyslabs/dacs";
import {
  runSessionCore,
  sessionAnchorName,
  type SessionDeps,
} from "../../sdk/dist/agent/runSessionCore.js";
import type { SubstratePort } from "../../src/ports.js";
import { demMemoFor, demosAddrFromDid, type DemLedgerPort } from "./rails.js";
import { resolveFromDid, verify } from "../../src/identity.js";
import {
  standardAnchorName,
  verifyListing,
  type Listing as StandardListing,
} from "./standard-profile.js";

/** The slice of an identity the buyer needs (mock and live identities both fit). */
export interface BuyerIdentity {
  did: string;
  evm: string;
  sign: Signer;
}

export interface BuyOrder {
  jobId: string;
  /** The rail: how this session pays. Injected wholesale (x402, pay-dem, …). */
  settleFn: SessionDeps["settle"];
  /** Optional Vet (DACS-2). Omit to skip vetting (mock demo). */
  vetFn?: (subject: string) => Promise<CompositeVerificationRecord>;
}

export class BuyerAdapter {
  constructor(
    private readonly id: BuyerIdentity,
    private readonly sub: SubstratePort,
  ) {}

  get did(): string {
    return this.id.did;
  }

  /** Standard-profile party used by the full artifact-chain adapter. */
  get standardParty() {
    return { primaryClaim: this.id.did, sign: this.id.sign };
  }

  /** The owner-scoped substrate view backing this buyer. */
  get substrate(): SubstratePort {
    return this.sub;
  }

  /** The buyer's EVM settlement coordinate (recorded as the x402 payer). */
  get evm(): string {
    return this.id.evm;
  }

  /** The buyer's Demos payout coordinate (`0x…`), derived from its DID. */
  get demosAddr(): string {
    const addr = demosAddrFromDid(this.id.did);
    if (!addr) throw new Error(`buyer DID ${this.id.did} has no resolvable Demos address`);
    return addr;
  }

  /** Resolve + structurally validate anchored listings (DACS-1 discover). */
  async discover(refs: string[]): Promise<Array<{ ref: string; listing: Listing }>> {
    return discoverListings(refs, (r) => this.sub.read(r), {
      resolvePublicKey: async (claim) => resolveFromDid(claim),
      verify,
    });
  }

  /**
   * DACS-1 normative discovery: schema/version/window, presentation + listing
   * signatures, revocation, pipeline, pricing and rail checks all fail closed.
   */
  async discoverStandard(refs: string[]): Promise<Array<{ ref: string; listing: StandardListing }>> {
    const found: Array<{ ref: string; listing: StandardListing }> = [];
    for (const ref of refs) {
      const raw = await this.sub.read(ref);
      if (!raw) continue;
      const listing = raw as unknown as StandardListing;
      let verdict;
      try {
        verdict = await verifyListing(listing, {
          resolvePublicKey: async (claim) => resolveFromDid(claim),
          verify,
          readRevocation: async (candidate) => {
            const name = standardAnchorName("revocation", [
              candidate.seller.identity.presentedBy,
              candidate.listingId,
              String(candidate.listingVersion),
            ]);
            if (this.sub.readAnchorFor) {
              return this.sub.readAnchorFor(candidate.seller.identity.presentedBy, name);
            }
            return this.sub.read(await this.sub.anchorAddressFor(candidate.seller.identity.presentedBy, name));
          },
        });
      } catch {
        continue;
      }
      if (verdict.ok) found.push({ ref, listing });
    }
    return found;
  }

  /**
   * Pattern 1 (chain-triggered) — open a fixed-scope agreement carrying the job
   * params, anchored at the session's deterministic agreement slot. Unlike a
   * full `runSessionCore` agreement, this one embeds `params` so the seller's
   * `SellerWatcher` can read WHAT to deliver off the chain alone — there is no
   * synchronous channel to convey them. Returns the anchor ref.
   */
  async openDemAgreement(input: {
    jobId: string;
    sellerDid: string;
    listingRef: string;
    terms: SessionTerms;
    params: Record<string, unknown>;
  }): Promise<string> {
    const agreement = {
      jobId: input.jobId,
      pattern: "pay-dem-fixed-scope",
      buyer: this.id.did,
      seller: input.sellerDid,
      listingRef: input.listingRef,
      price: input.terms.price,
      delivery: { phase: input.terms.deliveryPhase, format: input.terms.deliveryFormat },
      params: input.params,
      expiresAt: new Date().toISOString(),
    };
    const signed = await buildSignedArtifact(agreement, ARTIFACT_SEPARATORS.AgreementDocument, this.id.sign);
    return this.sub.anchor(sessionAnchorName.agreement(input.jobId), signed);
  }

  /**
   * Pattern 1 — settle DEM with a `DACS:<jobId>` memo and NOTHING else. The
   * buyer never calls the seller; the seller's watcher observes this transfer
   * and delivers. Returns the transfer's txHash.
   */
  async payDemBare(
    ledger: DemLedgerPort,
    input: { jobId: string; sellerDid: string; amount: bigint },
  ): Promise<string> {
    const to = demosAddrFromDid(input.sellerDid);
    if (!to) throw new Error(`pay-dem: seller ${input.sellerDid} has no resolvable Demos address`);
    const { txHash } = await ledger.transfer({
      from: this.demosAddr,
      to,
      amount: input.amount,
      memo: demMemoFor(input.jobId),
    });
    return txHash;
  }

  /** Run one fixed-price session against a listing on the injected rail. */
  async buy(listingRef: string, terms: SessionTerms, order: BuyOrder): Promise<SessionResult> {
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
      vet: order.vetFn,
      settle: order.settleFn,
      newJobId: () => order.jobId,
      now: () => new Date().toISOString(),
      nowMs: () => Date.now(),
    };
    return runSessionCore(listingRef, terms, deps);
  }
}

export interface X402MockSettleOptions {
  /** The paywall base URL (without query), e.g. "http://127.0.0.1:PORT/data". */
  paywallUrl: string;
  /** Substrate to run the independent delivery check against. */
  sub: SubstratePort;
  /** Buyer EVM address, recorded as `payer`. */
  payerEvm: string;
  /** Seller payout EVM address, recorded as `payee`. */
  payeeEvm: string;
  /** Work params to pass through on the paywall URL (product id, etc.). */
  params?: Record<string, string>;
  /** Negotiated CAIP-2 network (recorded as chainId). */
  network?: string;
  /** Override fetch (tests). Defaults to global fetch. */
  fetchImpl?: typeof fetch;
}

/**
 * x402 settle seam over the mock facilitator. Runs the 402 dance against the
 * paywall, then couples the receipt to an independent delivery check: the
 * result is `ok` only when the payment settled AND the seller's DACS-X delivery
 * attestation is anchored for this job.
 */
export function makeX402MockSettle(opts: X402MockSettleOptions): SessionDeps["settle"] {
  const fetchImpl = opts.fetchImpl ?? fetch;
  return async (req) => {
    const qs = new URLSearchParams({ jobId: req.jobId, ...(opts.params ?? {}) }).toString();
    const url = `${opts.paywallUrl}?${qs}`;

    // 1. Initial request — expect a 402 challenge (the FeeSchedule).
    const challenge = await fetchImpl(url);
    if (challenge.status !== 402) {
      throw new CounterpartyError(
        `x402 mock: expected HTTP 402 from ${opts.paywallUrl}, got ${challenge.status}`,
      );
    }
    await challenge.text();

    // 2. Retry with the synthetic proof; the seller verifies → works → settles.
    const paid = await fetchImpl(url, { headers: { "x-payment": `mock:${req.jobId}` } });
    const settlementTx =
      paid.headers.get("x-payment-response") ??
      ((await paid
        .clone()
        .json()
        .catch(() => null)) as { settlement?: { txHash?: string } } | null)?.settlement?.txHash ??
      "";

    // 3. Independent delivery check: the seller's attestation must be anchored.
    const anchor = await opts.sub.read(await opts.sub.anchorAddress(`dacsx:delivery:${req.jobId}`));
    const delivered = anchor !== null;

    return {
      ok: paid.ok && settlementTx.trim().length > 0 && delivered,
      txHash: settlementTx,
      chainId: opts.network ?? "eip155:84532",
      payer: opts.payerEvm,
      payee: opts.payeeEvm,
    };
  };
}
