/**
 * Rail factories for the shared seller layer.
 *
 * Build A wired the x402 rail end-to-end — see `paywall.ts` (seller half) and
 * `buyer.ts#makeX402MockSettle` (buyer half).
 *
 * Build B (this build) wires the native-DEM settlement rail (§9.5.9): a real
 * DEM transfer on the Demos substrate to the vetted seller, on the same chain
 * that anchors the evidence. Two shapes ride this rail:
 *
 *   - **Pattern 2 (session / push)** — `payDemRail(adapter, opts)`: the buyer's
 *     session settles DEM and the seller delivers in the SAME synchronous flow
 *     (the buyer conveyed the job params at session-open). This generalizes
 *     `src/live/run.ts#payDemSettle` (transfer → couple to delivery → ok).
 *   - **Pattern 1 (memo-watcher / chain-triggered)** — `payDemBare` on the
 *     buyer plus a `SellerWatcher` (see `watcher.ts`): the buyer just settles
 *     DEM with a `DACS:<jobId>` memo and never calls the seller; the seller's
 *     watcher observes the transfer and delivers. This module ships the ledger
 *     + memo binding both patterns share.
 *
 * The on-chain DEM transfer carries NO jobId by itself, so we bind it via the
 * transfer **memo** (`DACS:<jobId>`), the way SuperColony binds bets with a
 * `HIVE_BET:` memo. Everything here is behind a `DemLedgerPort` so the mock
 * path needs no chain; the live seam (documented, dynamic-import) is the only
 * place that touches a real wallet.
 */
import type { SettleRequest, SettleResult } from "../../sdk/dist/agent/runSessionCore.js";
import type { SellerAdapter } from "./seller-adapter.js";

/** A rail is a settle seam runSessionCore drives (`deps.settle`). */
export type SettleSeam = (req: SettleRequest) => Promise<SettleResult>;

/**
 * The memo prefix that binds an otherwise-anonymous DEM transfer to a DACS job.
 * A transfer whose memo starts with this carries the jobId in the remainder.
 */
export const DEM_MEMO_PREFIX = "DACS:";

/** Build the transfer memo for a job (`DACS:<jobId>`). */
export function demMemoFor(jobId: string): string {
  return `${DEM_MEMO_PREFIX}${jobId}`;
}

/** Extract a jobId from a DACS-tagged memo, or null if the memo isn't ours. */
export function jobIdFromMemo(memo: string): string | null {
  return memo.startsWith(DEM_MEMO_PREFIX) ? memo.slice(DEM_MEMO_PREFIX.length) : null;
}

/**
 * Resolve a Demos payout address from a self-describing DID. A
 * `did:demos:agent:<64hex>` (or any string ending in 64 hex chars) maps to the
 * `0x…` Demos address — the same strip the reference `payDemSettle` does.
 */
export function demosAddrFromDid(did: string): string | null {
  const hex = did.match(/([0-9a-fA-F]{64})$/)?.[1];
  return hex ? `0x${hex.toLowerCase()}` : null;
}

/** Inverse of `demosAddrFromDid`: `0x<64hex>` → the self-describing agent DID. */
export function didFromDemosAddr(addr: string): string | null {
  const hex = addr.match(/^0x([0-9a-fA-F]{64})$/)?.[1];
  return hex ? `did:demos:agent:${hex.toLowerCase()}` : null;
}

/** One recorded native-DEM transfer. Amounts are OS base units (§9.5.9). */
export interface DemTransfer {
  /** Payer Demos address (`0x…`). */
  from: string;
  /** Payee Demos address (`0x…`). */
  to: string;
  /** Settled amount in OS base units. */
  amount: bigint;
  /** The `DACS:<jobId>` binding (or any string, for non-DACS transfers). */
  memo: string;
  /** Synthetic (`mock-dem-<jobId>`) or real (broadcast) transaction hash. */
  txHash: string;
}

export type TransferListener = (t: DemTransfer) => void | Promise<void>;

/**
 * The settlement seam both patterns drive. `transfer` moves DEM and records the
 * memo; on the real substrate it broadcasts a native transfer, in mock it
 * appends to an in-memory ledger. Watchers subscribe via `onTransferTo`.
 */
export interface DemLedgerPort {
  transfer(req: { from: string; to: string; amount: bigint; memo: string }): Promise<{ txHash: string }>;
  /** Subscribe to new transfers landing at `to` (the seller's own address). */
  onTransferTo(to: string, cb: TransferListener): void;
}

/**
 * In-memory DEM ledger — no chain, no keys. Records every transfer and fires
 * per-address listeners so a `SellerWatcher` can react to a payment landing.
 * The txHash is synthetic (`mock-dem-<jobId>` for DACS-tagged transfers) so the
 * watcher and tests can correlate a transfer to its job.
 */
export class MockDemLedger implements DemLedgerPort {
  /** Every recorded transfer, in order. Public so tests/watchers can inspect it. */
  readonly transfers: DemTransfer[] = [];
  private readonly listeners: Array<{ to: string; cb: TransferListener }> = [];

  async transfer(req: { from: string; to: string; amount: bigint; memo: string }): Promise<{ txHash: string }> {
    const jobId = jobIdFromMemo(req.memo);
    const txHash = jobId ? `mock-dem-${jobId}` : `mock-dem-${this.transfers.length}`;
    const t: DemTransfer = { from: req.from, to: req.to, amount: req.amount, memo: req.memo, txHash };
    this.transfers.push(t);
    // Notify subscribers watching this recipient (models the chain's tx feed).
    for (const l of this.listeners) {
      if (l.to === req.to) await l.cb(t);
    }
    return { txHash };
  }

  onTransferTo(to: string, cb: TransferListener): void {
    this.listeners.push({ to, cb });
  }
}

/**
 * Pattern 2 — native-DEM settlement rail (session / push).
 *
 * The buyer's session settles DEM to the vetted seller, then the seller
 * delivers in the SAME flow (the buyer conveyed the job params at session-open,
 * so the rail hands them straight to `adapter.deliver`). Coupling mirrors the
 * x402 rail's `ok = pay.ok && delivered`: the settlement is `ok` only when the
 * transfer landed AND the seller's DACS-X delivery attestation is anchored.
 *
 * This is the mock-first generalization of `src/live/run.ts#payDemSettle`
 * (transfer → serialise nonce → await delivery → confirm the deliverable → ok).
 */
export interface PayDemRailOptions {
  /** The DEM ledger (mock in tests/demo, live seam on the real substrate). */
  ledger: DemLedgerPort;
  /** Substrate to run the independent delivery check against. */
  sub: SubLike;
  /** Buyer's Demos address (recorded as `payer`). */
  payer: string;
  /**
   * The job params the seller needs to deliver. In Pattern 2 the buyer conveys
   * these at session-open (the whole point vs the chain-triggered Pattern 1),
   * so the rail carries them straight into the push delivery.
   */
  deliverParams: Record<string, unknown>;
}

/** The slice of a substrate the delivery-coupling check needs. */
export interface SubLike {
  anchorAddress(name: string): Promise<string>;
  read(ref: string): Promise<Record<string, unknown> | null>;
}

export function payDemRail(adapter: SellerAdapter, opts: PayDemRailOptions): SettleSeam {
  return async (req: SettleRequest): Promise<SettleResult> => {
    const payee = demosAddrFromDid(req.payee);
    if (!payee) throw new Error(`pay-dem: payee ${req.payee} has no resolvable Demos address`);

    // 1. Move DEM, binding the transfer to the job via the memo.
    const { txHash } = await opts.ledger.transfer({
      from: opts.payer,
      to: payee,
      amount: BigInt(req.amount),
      memo: demMemoFor(req.jobId),
    });

    // 2. Push: the seller delivers now (session model), then couple to it.
    await adapter.deliver(req.jobId, opts.deliverParams);
    const delivered =
      (await opts.sub.read(await opts.sub.anchorAddress(`dacsx:delivery:${req.jobId}`))) !== null;

    // 3. ok only when the transfer landed AND the deliverable is anchored.
    return {
      ok: delivered && txHash.trim().length > 0,
      txHash,
      chainId: "demos",
      payer: opts.payer,
      payee,
    };
  };
}

/**
 * LIVE DEM ledger seam (documented, NOT wired for mock).
 *
 * The real settlement is `src/live/run.ts#payDemSettle`, lifted behind the
 * `DemLedgerPort`: a native `transfer(payee, BigInt(amount))` → `confirm(signed)`
 * → `broadcastAndWait(validity, { timeoutMs })`, with txHash from
 * `broadcast.response.hash`. The load-bearing serialisation the mock doesn't
 * need: after the transfer, POLL `getAddressInfo(payer).nonce` until it advances
 * before the next anchor, or the evidence anchor self-resolves a stale nonce and
 * the (nonce-enforcing since 2026-07) testnet rejects it.
 *
 * The memo carries the jobId exactly as the mock does (`DACS:<jobId>`). The
 * Pattern-1 watch side (see `watcher.ts`) is the seam that still needs node
 * support: there is no list-txs / enumerate-anchors RPC today, so the live
 * watcher must poll `getTransactions` / address history and filter DACS memos —
 * a dependency to verify against the node before enabling. Must be a dynamic
 * import so the mock path never loads chain deps:
 *
 * ```ts
 * export async function createLiveDemLedger(cfg: {
 *   demos: DemosWalletHandle; payerAddr: string; timeoutMs?: number;
 * }): Promise<DemLedgerPort> {
 *   return {
 *     async transfer({ to, amount, memo }) {
 *       const nonceBefore = Number((await cfg.demos.getAddressInfo(cfg.payerAddr))?.nonce ?? 0);
 *       const signed = await cfg.demos.transfer(to, amount, { memo });
 *       const validity = await cfg.demos.confirm(signed);
 *       const broadcast = await cfg.demos.broadcastAndWait(validity, { timeoutMs: cfg.timeoutMs ?? 90_000 });
 *       // serialise the wallet: wait for the nonce to advance before returning
 *       for (let i = 0; i < 24; i++) {
 *         const now = Number((await cfg.demos.getAddressInfo(cfg.payerAddr))?.nonce ?? 0);
 *         if (now > nonceBefore) break;
 *         await new Promise((r) => setTimeout(r, 2500));
 *       }
 *       return { txHash: broadcast?.response?.hash ?? signed?.hash ?? "" };
 *     },
 *     onTransferTo() { throw new Error("live watch: poll getTransactions — see watcher.ts live seam"); },
 *   };
 * }
 * ```
 *
 * Left as a seam: Build B proves both patterns on `MockDemLedger`; the live
 * wiring is the same transfer/confirm/broadcast shape `src/live/run.ts` already
 * exercises, plus a memo argument and the getTransactions watch dependency.
 */
export interface DemosWalletHandle {
  transfer: (to: string, amount: bigint, opts?: { memo?: string }) => Promise<{ hash?: string }>;
  confirm: (tx: unknown) => Promise<unknown>;
  broadcastAndWait: (v: unknown, opts?: { timeoutMs?: number }) => Promise<{ response?: { hash?: string } }>;
  getAddressInfo: (addr: string) => Promise<{ nonce?: number; balance?: bigint | number } | null>;
}
export type LiveDemLedgerSeam = (cfg: {
  demos: DemosWalletHandle;
  payerAddr: string;
  timeoutMs?: number;
}) => Promise<DemLedgerPort>;
