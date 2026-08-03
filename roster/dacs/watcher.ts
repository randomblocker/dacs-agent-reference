/**
 * Pattern 1 — memo-watcher settlement (chain-triggered, fixed-scope).
 *
 * The seller runs NO inbound endpoint. Instead it watches the chain for DEM
 * transfers landing at its own address and turns "a payment landed" into
 * "deliver the job" — with zero synchronous buyer↔seller call. This is how a
 * fixed-scope seller (the oracle desk) learns someone bought:
 *
 *   buyer anchors a fixed-scope agreement (carrying the job params) + settles
 *   DEM with a `DACS:<jobId>` memo  ─────────────────────────────────────────┐
 *                                                                             │ (chain)
 *   SellerWatcher observes the transfer → resolves the buyer's agreement ◄────┘
 *     from the anchored slot → reads the params → checks the amount → runs
 *     the oracle work callback → anchors the DACS-X delivery attestation.
 *
 * The buyer never calls the seller; it later just READS the seller's anchored
 * delivery attestation and verifies it. Every observed transfer gets a logged
 * decision — delivered, skipped (replay), or parked (with a reason). No silent
 * drops.
 *
 * `WatchPort` is the mock↔live seam. The mock subscribes to `MockDemLedger`; the
 * live seam polls `getTransactions` / address history filtering DACS memos —
 * documented below, NOT wired, because there is no list-txs RPC today (a node
 * dependency to verify before enabling).
 */
import { stripSignature } from "@kynesyslabs/dacs";
import { sessionAnchorName } from "../../sdk/dist/agent/runSessionCore.js";
import type { SubstratePort } from "../../src/ports.js";
import type { SellerAdapter } from "./seller-adapter.js";
import {
  didFromDemosAddr,
  jobIdFromMemo,
  type DemLedgerPort,
  type DemTransfer,
  type TransferListener,
} from "./rails.js";

/**
 * The watch seam: subscribe to DEM transfers landing at `address`. Mock impl
 * wraps a `MockDemLedger`; the live impl polls the node (see the live seam).
 */
export interface WatchPort {
  watchTransfersTo(address: string, onTransfer: TransferListener): void;
}

/** Mock watch: subscribe directly to the in-memory ledger's transfer feed. */
export class MockLedgerWatch implements WatchPort {
  constructor(private readonly ledger: DemLedgerPort) {}
  watchTransfersTo(address: string, onTransfer: TransferListener): void {
    this.ledger.onTransferTo(address, onTransfer);
  }
}

/** One logged watcher decision — every observed transfer produces exactly one. */
export type WatchDecision =
  | { action: "delivered"; jobId: string; from: string; amount: string; attestationRef: string }
  | { action: "skipped-replay"; jobId: string; reason: string }
  | { action: "parked"; jobId: string | null; memo: string; reason: string };

export interface SellerWatcherOptions {
  /** The seller's own Demos address (`0x…`) — the inbound-transfer target. */
  sellerAddr: string;
  /** Minimum acceptable settlement, in OS base units (the listing price). */
  listingPrice: bigint;
}

/**
 * Turns inbound DEM transfers into deliveries. `run()` subscribes; each transfer
 * is resolved to a job and either delivered, skipped (idempotent replay), or
 * parked (non-DACS memo, unresolvable agreement, or underpayment).
 */
export class SellerWatcher {
  /** Append-only decision log — the audit trail of every observed transfer. */
  readonly decisions: WatchDecision[] = [];
  private readonly handled = new Set<string>();

  constructor(
    private readonly adapter: SellerAdapter,
    private readonly sub: SubstratePort,
    private readonly watch: WatchPort,
    private readonly opts: SellerWatcherOptions,
  ) {}

  /** Subscribe to inbound transfers at the seller's address. */
  run(): void {
    this.watch.watchTransfersTo(this.opts.sellerAddr, (t) => this.onTransfer(t));
  }

  private log(d: WatchDecision): void {
    this.decisions.push(d);
  }

  private async onTransfer(t: DemTransfer): Promise<void> {
    // 1. Only DACS-tagged transfers name a job. Anything else is parked, loudly.
    const jobId = jobIdFromMemo(t.memo);
    if (!jobId) {
      this.log({ action: "parked", jobId: null, memo: t.memo, reason: "memo is not DACS-tagged" });
      return;
    }

    // 2. Idempotency: a replayed / duplicated transfer for a handled job is a
    //    no-op. Belt-and-suspenders: an already-anchored delivery counts as
    //    handled too (survives a watcher restart with a cold `handled` set).
    if (this.handled.has(jobId)) {
      this.log({ action: "skipped-replay", jobId, reason: "jobId already handled (idempotent)" });
      return;
    }
    const already = await this.sub.read(
      await this.sub.anchorAddressFor(this.adapter.did, `dacsx:delivery:${jobId}`),
    );
    if (already) {
      this.handled.add(jobId);
      this.log({ action: "skipped-replay", jobId, reason: "delivery already anchored (idempotent)" });
      return;
    }

    // 3. Resolve the payer DID → derive the buyer's agreement slot → read it.
    const buyerDid = didFromDemosAddr(t.from);
    if (!buyerDid) {
      this.log({ action: "parked", jobId, memo: t.memo, reason: `payer ${t.from} has no resolvable DID` });
      return;
    }
    const agreementRaw = await this.sub.read(
      await this.sub.anchorAddressFor(buyerDid, sessionAnchorName.agreement(jobId)),
    );
    if (!agreementRaw) {
      this.log({ action: "parked", jobId, memo: t.memo, reason: "no resolvable agreement for this memo" });
      return;
    }
    const params = (stripSignature(agreementRaw) as { params?: Record<string, unknown> }).params;
    if (!params || typeof params !== "object") {
      this.log({ action: "parked", jobId, memo: t.memo, reason: "agreement carries no job params" });
      return;
    }

    // 4. Underpayment guard: never deliver for less than the listing price.
    if (t.amount < this.opts.listingPrice) {
      this.log({
        action: "parked",
        jobId,
        memo: t.memo,
        reason: `underpayment: ${t.amount.toString()} < listing price ${this.opts.listingPrice.toString()}`,
      });
      return;
    }

    // 5. Deliver: run the oracle work callback + anchor the DACS-X attestation.
    let attestationRef: string;
    try {
      const d = await this.adapter.deliver(jobId, params);
      attestationRef = d.attestationRef;
    } catch (e) {
      this.log({ action: "parked", jobId, memo: t.memo, reason: `delivery failed: ${(e as Error).message}` });
      return;
    }
    this.handled.add(jobId);
    this.log({ action: "delivered", jobId, from: t.from, amount: t.amount.toString(), attestationRef });
  }
}

/**
 * LIVE watch seam (documented, NOT wired for mock).
 *
 * There is no list-txs / enumerate-anchors RPC on the Demos node today, so a
 * live `WatchPort` must poll the payer/recipient address history and filter for
 * DACS memos:
 *
 * ```ts
 * export function createLivePoller(cfg: {
 *   demos: { getTransactions: (q: object) => Promise<Array<{ from: string; to: string; amount: string; memo?: string; hash: string }>> };
 *   intervalMs?: number;
 * }): WatchPort {
 *   return {
 *     watchTransfersTo(address, onTransfer) {
 *       const seen = new Set<string>();
 *       setInterval(async () => {
 *         const txs = await cfg.demos.getTransactions({ to: address });
 *         for (const tx of txs) {
 *           if (seen.has(tx.hash) || !tx.memo?.startsWith("DACS:")) continue;
 *           seen.add(tx.hash);
 *           await onTransfer({ from: tx.from, to: tx.to, amount: BigInt(tx.amount), memo: tx.memo, txHash: tx.hash });
 *         }
 *       }, cfg.intervalMs ?? 5_000);
 *     },
 *   };
 * }
 * ```
 *
 * The exact `getTransactions` shape + whether the node exposes an inbound filter
 * at all is the dependency to verify against the node before enabling. The
 * decision logic in `SellerWatcher` is chain-agnostic — only this feed changes.
 */
export type LiveWatchSeam = (cfg: { intervalMs?: number }) => WatchPort;
