/**
 * Live substrate — the real Demos testnet behind the same structural surface
 * the agents already use (anchor / anchorAddress / read / proxyFetch), so the
 * agents built against MemorySubstrate run unchanged.
 *
 * Anchors are REAL storage-program transactions (each costs a broadcast).
 * Addresses are owner-scoped and include the create-time wallet nonce, so they
 * cannot be re-derived from owner + name. Reads resolve the SDK's colon-free
 * program name through the owner-bound name index and preserve indeterminate
 * lookup failures separately from authoritative absence (#70).
 */
import { createHash } from "node:crypto";
import { DemosAdapter } from "@kynesyslabs/dacs/substrate";
import type { AnchorAcceptance, AnchorReceipt, AnchorResolveOptions } from "../ports.js";

/**
 * Per-deal slots contain the job id, so a fresh idempotency key gives each
 * operation a deterministic address that cannot legitimately pre-exist.
 * Listings, revocations and auto-accept commitments are intentionally absent:
 * those long-lived slots must retain read-before-write immutability checks.
 */
export function isKnownNewJobAnchorName(name: string): boolean {
  if (/^dacsx:delivery:[^:]+$/.test(name)) return true;
  let logical: string;
  try {
    logical = Buffer.from(name, "base64url").toString("utf8");
  } catch {
    return false;
  }
  return /^dacs2:composite:[^:]+:/.test(logical)
    || /^dacs3:(?:agreement|commit):[^:]+$/.test(logical)
    || /^dacs4:evidence:[^:]+:/.test(logical)
    || /^dacs5:bundle:[^:]+:/.test(logical);
}

function anchorOptions(name: string, nonce?: number): { nonce?: number; writeMode?: "known-new" } {
  return {
    ...(nonce === undefined ? {} : { nonce }),
    ...(isKnownNewJobAnchorName(name) ? { writeMode: "known-new" as const } : {}),
  };
}

interface AnchorVisibilityTuning {
  maxBroadcasts: number;
  unconfirmedReadPolls: number;
  confirmedReadPolls: number;
  pollIntervalMs: number;
  retryDelayMs: number;
}

export interface AnchorObservation extends AnchorReceipt {
  name: string;
  storageStatus: "confirmed" | "visible" | "delayed";
}

class DroppedAnchorTransactionError extends Error {
  constructor(readonly txRef: string) {
    super(`Demos anchor transaction ${txRef} was dropped before inclusion`);
    this.name = "DroppedAnchorTransactionError";
  }
}

const DEFAULT_VISIBILITY_TUNING: AnchorVisibilityTuning = {
  maxBroadcasts: 3,
  // A transaction can remain in the future-nonce mempool until its reference
  // block expires. Keep watching long enough to observe that terminal failure;
  // the explicit status RPC below then permits a safe, freshly-signed retry.
  unconfirmedReadPolls: 150,
  // Public Demos nodes can include a storage transaction well before their
  // storage read API exposes the new value. Once inclusion is authoritative,
  // wait up to five minutes instead of paying to rebroadcast the same write.
  confirmedReadPolls: 250,
  pollIntervalMs: 1_200,
  retryDelayMs: 2_500,
};

/**
 * Demos currently serialises consensus block timestamps as unix seconds while
 * DACS SR-2 receipts use unix milliseconds. Accept either wire representation
 * at this adapter boundary and always return the DACS unit.
 */
export function demosBlockTimestampMs(value: unknown): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0) {
    throw new Error("Demos inclusion block omitted its consensus timestamp");
  }
  const timestamp = Number(value);
  // 100,000,000,000 seconds is well beyond any realistic unix timestamp, but
  // below contemporary millisecond values. This keeps the unit test explicit
  // without using the local wall clock as an authority.
  const milliseconds = timestamp < 100_000_000_000 ? timestamp * 1_000 : timestamp;
  if (!Number.isSafeInteger(milliseconds)) {
    throw new Error("Demos inclusion block returned an out-of-range consensus timestamp");
  }
  return milliseconds;
}

function compactTransactionContent(content: { to?: string; data?: unknown; nonce?: number }): {
  content: Record<string, unknown>;
  valueOmitted: boolean;
} {
  const cloned = JSON.parse(JSON.stringify(content)) as Record<string, unknown>;
  const values = Array.isArray(cloned.data) ? cloned.data : undefined;
  const payload = values?.[0] === "storageProgram" ? values[1] : undefined;
  if (payload && typeof payload === "object" && !Array.isArray(payload)
    && Object.prototype.hasOwnProperty.call(payload, "data")) {
    (payload as Record<string, unknown>).data = null;
    return { content: cloned, valueOmitted: true };
  }
  return { content: cloned, valueOmitted: false };
}

function materializeTransactionContent(options: Pick<AnchorResolveOptions,
  "transactionContent" | "transactionContentValueOmitted" | "anchorValue"
>): Record<string, unknown> | undefined {
  if (!options.transactionContent) return undefined;
  if (!options.transactionContentValueOmitted) return options.transactionContent;
  if (!options.anchorValue) return undefined;
  const cloned = JSON.parse(JSON.stringify(options.transactionContent)) as Record<string, unknown>;
  const values = Array.isArray(cloned.data) ? cloned.data : undefined;
  const payload = values?.[0] === "storageProgram" ? values[1] : undefined;
  if (!payload || typeof payload !== "object" || Array.isArray(payload)
    || !Object.prototype.hasOwnProperty.call(payload, "data")) return undefined;
  (payload as Record<string, unknown>).data = JSON.parse(JSON.stringify(options.anchorValue));
  return cloned;
}

export class LiveSubstrate {
  private readonly visibility: AnchorVisibilityTuning;
  private readonly localWrites = new Map<string, Record<string, unknown>>();
  private readonly acceptedLocal = new Map<string, { name: string; value: Record<string, unknown>; canonical: string }>();
  private readonly visibilityTasks = new Map<string, Promise<void>>();
  /**
   * Serialize on-chain writes per-wallet. One Demos wallet cannot broadcast
   * concurrent anchors: Demos enforces serial nonces, so a second write signed
   * against nonce N while the first still holds it fails at confirm. The queue
   * is released at authoritative transaction inclusion; public storage-view
   * replication is deliberately not part of nonce safety.
   */
  private anchorTail: Promise<unknown> = Promise.resolve();
  /** Next locally-reserved nonce after an accepted, not-yet-included write. */
  private nextNonce: number | undefined;

  /** Advance the local reservation after a payment or other external write. */
  noteExternalNonce(nonce: number): void {
    if (!Number.isSafeInteger(nonce) || nonce < 0) throw new Error("external wallet nonce must be a non-negative safe integer");
    if (this.nextNonce === undefined || nonce >= this.nextNonce) this.nextNonce = nonce + 1;
  }

  constructor(
    readonly adapter: DemosAdapter,
    private readonly onAnchor?: (record: AnchorObservation) => void,
    visibility: Partial<AnchorVisibilityTuning> = {},
    private readonly onVisibility?: (record: AnchorObservation) => void,
  ) {
    this.visibility = { ...DEFAULT_VISIBILITY_TUNING, ...visibility };
  }

  /** Demos address (0x + 64 hex) of this substrate view's wallet. */
  async address(): Promise<string> {
    return this.adapter.getAddress();
  }

  /**
   * Anchor under OUR wallet and return at consensus inclusion. The node's
   * public StorageProgram read view is a separate, eventually-consistent
   * projection tracked in the background.
   */
  private async anchorConfirmed(name: string, value: object): Promise<AnchorReceipt> {
    const run = this.anchorTail.then(
      () => this.anchorConfirmedUnsafe(name, value),
      () => this.anchorConfirmedUnsafe(name, value),
    );
    this.anchorTail = run.then(() => undefined, () => undefined);
    return run;
  }

  private async anchorConfirmedUnsafe(name: string, value: object, initialNonce?: number): Promise<AnchorReceipt> {
    const { canonicalize, sha256Hex } = await import("@kynesyslabs/dacs");
    const localValue = JSON.parse(JSON.stringify(value)) as Record<string, unknown>;
    const want = canonicalize(localValue);
    const contentHash = sha256Hex(want);
    let address = "";
    let retryNonce = initialNonce ?? this.nextNonce;
    for (let attempt = 0; attempt < this.visibility.maxBroadcasts; attempt++) {
      // Since the testnet enforces nonces (2026-07), a stale-nonce write now
      // THROWS (SubstrateError) instead of silently evicting — treat it as
      // transient and retry after a beat.
      let ref;
      try {
        ref = await this.adapter.anchor(name, value, anchorOptions(name, retryNonce));
      } catch (e) {
        if (attempt === this.visibility.maxBroadcasts - 1) throw e;
        await new Promise((r) => setTimeout(r, this.visibility.retryDelayMs));
        continue;
      }
      address = typeof ref === "string" ? ref : ref.address;
      const txRef = typeof ref === "string" ? undefined : ref.txRef;
      const expectedConfirmationBlock = typeof ref === "string" ? undefined : ref.expectedConfirmationBlock;
      const broadcastAt = typeof ref === "string" ? undefined : ref.broadcastAt;
      const nonce = typeof ref === "string" ? undefined : ref.nonce;
      if (retryNonce !== undefined && nonce !== retryNonce) {
        throw new Error("anchor retry changed the reserved wallet nonce");
      }
      retryNonce = nonce;
      if (nonce !== undefined && (this.nextNonce === undefined || nonce >= this.nextNonce)) {
        this.nextNonce = nonce + 1;
      }
      if (!txRef) throw new Error("Demos anchor did not return a transaction reference");
      let failed = false;
      for (let i = 0; i < this.visibility.unconfirmedReadPolls; i++) {
        const tx = await this.findWalletTransaction(txRef, undefined, { transactionContent: ref.transactionContent });
        failed ||= tx?.status === "failed";
        if (tx && (tx.status === "confirmed" || tx.status === "included")) {
          const receipt = await this.receiptFromTransaction(txRef, tx, expectedConfirmationBlock, contentHash, broadcastAt, nonce);
          if (receipt.address !== address) throw new Error("Demos anchor receipt points at a different storage program");
          this.localWrites.set(address, localValue);
          const observation: AnchorObservation = { name, ...receipt, storageStatus: "confirmed" };
          this.onAnchor?.(observation);
          this.trackPublicVisibility(observation, want);
          return receipt;
        }
        if (!failed && expectedConfirmationBlock !== undefined && i % 3 === 2) {
          failed = await this.transactionWasDropped(txRef, expectedConfirmationBlock);
        }
        if (failed) break;
        if (i + 1 < this.visibility.unconfirmedReadPolls) await new Promise((r) => setTimeout(r, this.visibility.pollIntervalMs));
      }
      if (!failed) {
        throw new Error(`anchor transaction ${txRef} remained pending; refusing a duplicate broadcast`);
      }
    }
    throw new Error(`anchor ${address} did not reach confirmed inclusion after ${this.visibility.maxBroadcasts} broadcasts`);
  }

  /**
   * A broadcast can be accepted and then disappear during a fork. Once the
   * chain is more than two blocks past the node's promised inclusion block,
   * an authoritative `unknown` status means there is no tx to execute. The
   * caller may safely rebuild with the SAME nonce; using the next nonce would
   * create the permanent future-nonce gap the retry is meant to avoid.
   */
  private async transactionWasDropped(txRef: string, expectedBlock: number): Promise<boolean> {
    try {
      const [head, status] = await Promise.all([
        this.adapter.raw.getLastBlockNumber(),
        this.adapter.raw.call("nodeCall", "getTransactionStatus", { hash: txRef.replace(/^0x/, "") }),
      ]) as [number, { state?: unknown }];
      return Number.isSafeInteger(head)
        && Number(head) > expectedBlock + 2
        && status?.state === "unknown";
    } catch {
      return false;
    }
  }

  private trackPublicVisibility(observation: AnchorObservation, want: string): void {
    const key = observation.txRef;
    if (this.visibilityTasks.has(key)) return;
    const task = (async () => {
      const { canonicalize } = await import("@kynesyslabs/dacs");
      for (let i = 0; i < this.visibility.confirmedReadPolls; i++) {
        const back = await this.adapter.readAnchor(observation.address).catch(() => null);
        if (back != null && canonicalize(back) === want) {
          this.onVisibility?.({ ...observation, storageStatus: "visible" });
          return;
        }
        if (i + 1 < this.visibility.confirmedReadPolls) await new Promise((r) => setTimeout(r, this.visibility.pollIntervalMs));
      }
      this.onVisibility?.({ ...observation, storageStatus: "delayed" });
    })().finally(() => this.visibilityTasks.delete(key));
    this.visibilityTasks.set(key, task);
  }

  async anchor(name: string, value: object): Promise<string> {
    return (await this.anchorConfirmed(name, value)).address;
  }

  /**
   * Temporary dacs-sdk#54 receipt adapter: recover the objective SR-2 clock
   * from the confirmed Demos inclusion block rather than trusting Date.now().
   */
  async anchorWithReceipt(name: string, value: object): Promise<AnchorReceipt> {
    return this.anchorConfirmed(name, value);
  }

  private async anchorAcceptedUnsafe(name: string, value: object, explicitNonce?: number): Promise<AnchorAcceptance> {
    const { canonicalize, sha256Hex } = await import("@kynesyslabs/dacs");
    const nonce = explicitNonce ?? this.nextNonce;
    let ref: Awaited<ReturnType<DemosAdapter["anchor"]>> | undefined;
    let lastError: unknown;
    for (let attempt = 0; attempt < this.visibility.maxBroadcasts; attempt++) {
      try {
        ref = await this.adapter.anchor(name, value, anchorOptions(name, nonce));
        break;
      } catch (error) {
        lastError = error;
        if (attempt + 1 < this.visibility.maxBroadcasts) {
          await new Promise((resolve) => setTimeout(resolve, this.visibility.retryDelayMs));
        }
      }
    }
    if (!ref) throw lastError instanceof Error ? lastError : new Error("anchor admission failed");
    if (typeof ref === "string" || !ref.txRef) throw new Error("Demos admission omitted its transaction reference");
    if (nonce !== undefined && ref.nonce !== nonce) throw new Error("anchor admission changed the reserved wallet nonce");
    if (ref.nonce !== undefined && (this.nextNonce === undefined || ref.nonce >= this.nextNonce)) {
      this.nextNonce = ref.nonce + 1;
    }
    const acceptedAt = ref.broadcastAt ?? Date.now();
    return {
      address: ref.address,
      txRef: ref.txRef,
      contentHash: sha256Hex(canonicalize(value as Record<string, unknown>)),
      status: "accepted",
      acceptedAt,
      ...(ref.expectedConfirmationBlock === undefined ? {} : { expectedConfirmationBlock: ref.expectedConfirmationBlock }),
      ...(ref.nonce === undefined ? {} : { nonce: ref.nonce }),
      ...(ref.transactionContent === undefined ? {} : { transactionContent: ref.transactionContent }),
    };
  }

  /** Return after the node has explicitly admitted a non-value Storage write. */
  async anchorAccepted(name: string, value: object): Promise<AnchorAcceptance> {
    const run = this.anchorTail.then(
      () => this.anchorAcceptedUnsafe(name, value),
      () => this.anchorAcceptedUnsafe(name, value),
    );
    this.anchorTail = run.then(() => undefined, () => undefined);
    const accepted = await run;
    const localValue = JSON.parse(JSON.stringify(value)) as Record<string, unknown>;
    this.acceptedLocal.set(accepted.txRef, {
      name,
      value: localValue,
      canonical: (await import("@kynesyslabs/dacs")).canonicalize(localValue),
    });
    return accepted;
  }

  async verifyAnchorAcceptance(acceptance: AnchorAcceptance): Promise<void> {
    const statusReader = this.adapter.raw.call;
    const hash = acceptance.txRef.replace(/^0x/, "");
    for (let attempt = 0; attempt < 20; attempt++) {
      try {
        const status = await statusReader.call(this.adapter.raw, "nodeCall", "getTransactionStatus", { hash }) as { state?: unknown };
        if (typeof status?.state === "string" && status.state !== "unknown") {
          if (status.state === "failed") throw new Error("substrate rejected the admitted anchor");
          return;
        }
      } catch (error) {
        if (error instanceof Error && error.message.includes("rejected the admitted")) throw error;
      }
      if (attempt < 19) await new Promise((resolve) => setTimeout(resolve, 250));
    }
    throw new Error("anchor admission was not independently visible in the GCR queue");
  }

  async confirmAcceptedAnchor(acceptance: AnchorAcceptance, owner?: string): Promise<AnchorReceipt> {
    let current = acceptance;
    let local = this.acceptedLocal.get(current.txRef);
    let resolved: AnchorReceipt | undefined;
    for (let attempt = 0; attempt < this.visibility.maxBroadcasts; attempt++) {
      try {
        resolved = await this.resolveAnchorReceipt(current.txRef, owner, {
          expectedConfirmationBlock: current.expectedConfirmationBlock,
          transactionContent: current.transactionContent,
        });
        break;
      } catch (error) {
        if (!(error instanceof DroppedAnchorTransactionError)
          || local === undefined
          || current.nonce === undefined
          || attempt + 1 >= this.visibility.maxBroadcasts) throw error;
        await new Promise((resolve) => setTimeout(resolve, this.visibility.retryDelayMs));
        this.acceptedLocal.delete(current.txRef);
        const retried = await this.anchorAcceptedUnsafe(local.name, local.value, current.nonce);
        if (retried.nonce !== current.nonce || retried.address !== current.address || retried.contentHash !== current.contentHash) {
          throw new Error("anchor receipt retry changed the reserved nonce or accepted artifact");
        }
        current = retried;
        this.acceptedLocal.set(current.txRef, local);
      }
    }
    if (!resolved) throw new Error(`Demos anchor ${current.txRef} did not resolve after bounded rebroadcasts`);
    const receipt: AnchorReceipt = {
      ...resolved,
      broadcastAt: current.acceptedAt,
      ...(current.nonce === undefined ? {} : { nonce: current.nonce }),
      ...(current.expectedConfirmationBlock === undefined ? {} : {
        expectedConfirmationBlock: current.expectedConfirmationBlock,
        confirmationBlockDelta: resolved.blockNumber === undefined
          ? undefined
          : resolved.blockNumber - current.expectedConfirmationBlock,
      }),
      confirmedAt: Date.now(),
      inclusionLatencyMs: Math.max(0, Date.now() - current.acceptedAt),
    };
    if (receipt.address !== current.address || receipt.contentHash !== current.contentHash) {
      throw new Error("confirmed anchor does not match its admitted address/content");
    }
    local = this.acceptedLocal.get(current.txRef) ?? local;
    if (local) {
      this.acceptedLocal.delete(current.txRef);
      this.localWrites.set(receipt.address, local.value);
      const observation: AnchorObservation = { name: local.name, ...receipt, storageStatus: "confirmed" };
      this.onAnchor?.(observation);
      this.trackPublicVisibility(observation, local.canonical);
    }
    return receipt;
  }

  async anchorBatchWithReceipts(entries: Array<{ name: string; value: object }>): Promise<AnchorReceipt[]> {
    if (entries.length === 0) return [];
    const perform = async (): Promise<AnchorReceipt[]> => {
      // Admission is deterministic and nonces are explicitly reserved. Submit
      // N..N+k in order, then observe all inclusions together. If an earlier
      // nonce fails, later writes cannot be mistaken for final because every
      // returned receipt is independently resolved from its consensus tx.
      const accepted: AnchorAcceptance[] = [];
      for (const { name, value } of entries) {
        const acceptance = await this.anchorAcceptedUnsafe(name, value);
        const localValue = JSON.parse(JSON.stringify(value)) as Record<string, unknown>;
        this.acceptedLocal.set(acceptance.txRef, {
          name,
          value: localValue,
          canonical: (await import("@kynesyslabs/dacs")).canonicalize(localValue),
        });
        accepted.push(acceptance);
      }
      const receipts = await Promise.all(accepted.map((entry) => this.confirmAcceptedAnchor(entry)));
      return receipts;
    };
    // Keep the entire reservation+broadcast group ordered relative to other
    // writes made through this wallet view.
    const run = this.anchorTail.then(perform, perform);
    this.anchorTail = run.then(() => undefined, () => undefined);
    return run;
  }

  async resolveAnchorReceipt(txRef: string, owner?: string, options: AnchorResolveOptions = {}): Promise<AnchorReceipt> {
    const hash = txRef.replace(/^0x/, "");
    const { expectedConfirmationBlock } = options;
    // Counterparties do not own this transaction, so their wallet-history
    // projection cannot fill a lagging public hash index. Allow the same
    // bounded window used for confirmation tracking before rejecting an
    // otherwise valid cross-wallet receipt.
    for (let attempt = 0; attempt < this.visibility.unconfirmedReadPolls; attempt++) {
      const tx = await this.findWalletTransaction(hash, owner, options);
      const blockNumber = tx?.blockNumber;
      if (tx && (tx.status === "confirmed" || tx.status === "included") && Number.isSafeInteger(blockNumber) && Number(blockNumber) >= 0) {
        return this.receiptFromTransaction(hash, tx);
      }
      if (tx?.status === "failed") throw new DroppedAnchorTransactionError(hash);
      if (expectedConfirmationBlock !== undefined && attempt % 3 === 0
        && await this.transactionWasDropped(hash, expectedConfirmationBlock)) {
        throw new DroppedAnchorTransactionError(hash);
      }
      if (attempt + 1 < this.visibility.unconfirmedReadPolls) {
        await new Promise((resolve) => setTimeout(resolve, this.visibility.pollIntervalMs));
      }
    }
    if (expectedConfirmationBlock !== undefined
      && await this.transactionWasDropped(hash, expectedConfirmationBlock)) {
      throw new DroppedAnchorTransactionError(hash);
    }
    throw new Error(`Demos anchor ${hash} did not resolve to a confirmed inclusion block`);
  }

  /**
   * The public node's hash index can lag confirmed inclusion by tens of
   * seconds and has returned the literal string `"error"` during that window.
   * Address history is an independent confirmed-state projection, so consult
   * it before classifying a broadcast as unresolved. This preserves the
   * no-duplicate-broadcast rule without making the happy path wait for the
   * slower hash index.
   */
  private async findWalletTransaction(txRef: string, historyOwner?: string, proof: AnchorResolveOptions = {}): Promise<{
    status?: string;
    blockNumber?: number | null;
    content?: { to?: string; data?: unknown };
  } | null> {
    const hash = txRef.replace(/^0x/, "");
    const transactionContent = materializeTransactionContent(proof);
    const direct = await this.adapter.raw.getTxByHash(hash).catch(() => null) as unknown;
    if (direct && typeof direct === "object" && !Array.isArray(direct)) {
      const transaction = direct as {
        status?: string;
        blockNumber?: number | null;
        content?: { to?: string; data?: unknown };
      };
      if (transaction.status === "confirmed" || transaction.status === "included" || transaction.status === "failed") {
        return transaction;
      }
    }

    // getTxByHash and wallet history are eventually-consistent projections.
    // getTransactionStatus is the authoritative mempool/inclusion state used
    // by demosdk's own broadcastAndWait implementation. It omits transaction
    // content, so an included status is usable only when the writer supplied
    // the exact public content and its UTF-8 JSON hash matches this txRef.
    const statusReader = (this.adapter.raw as unknown as {
      call?: (method: string, message: string, data: { hash: string }) => Promise<unknown>;
    }).call;
    if (typeof statusReader === "function") {
      try {
        const status = await statusReader.call(this.adapter.raw, "nodeCall", "getTransactionStatus", { hash });
        if (status && typeof status === "object" && !Array.isArray(status)) {
          const state = (status as { state?: unknown }).state;
          const blockNumber = Number.isSafeInteger((status as { blockNumber?: unknown }).blockNumber)
            ? Number((status as { blockNumber?: unknown }).blockNumber)
            : null;
          if ((state === "included" || state === "confirmed") && blockNumber !== null && transactionContent) {
            const proofHash = createHash("sha256")
              .update(JSON.stringify(transactionContent), "utf8")
              .digest("hex");
            if (proofHash.toLowerCase() !== hash.toLowerCase()) {
              throw new Error(`transaction content proof does not match ${hash}`);
            }
            return {
              status: String(state),
              blockNumber,
              content: transactionContent as { to?: string; data?: unknown },
            };
          }
          if (state === "failed") {
            return {
              status: "failed",
              blockNumber,
            };
          }
        }
      } catch (error) {
        if (error instanceof Error && error.message.startsWith("transaction content proof does not match")) throw error;
        /* public status lookup is advisory; history may still resolve */
      }
    }

    const historyReader = (this.adapter.raw as unknown as {
      getTransactionHistory?: (
        address: string,
        type?: "all",
        options?: { start?: number; limit?: number },
      ) => Promise<Array<{
        hash?: string;
        status?: string;
        blockNumber?: number | null;
        content?: { to?: string; data?: unknown };
      }>>;
    }).getTransactionHistory;
    if (typeof historyReader !== "function") return null;
    let history: Array<{
      hash?: string;
      status?: string;
      blockNumber?: number | null;
      content?: { to?: string; data?: unknown };
    }> = [];
    try {
      const ownerHex = historyOwner?.match(/([0-9a-fA-F]{64})$/)?.[1];
      const address = historyOwner
        ? (ownerHex ? `0x${ownerHex}` : historyOwner)
        : await this.address();
      const result = await historyReader.call(this.adapter.raw, address, "all", { start: 0, limit: 20 });
      if (Array.isArray(result)) history = result;
    } catch { /* the next poll retries both independent projections */ }
    return history.find((transaction) => transaction.hash?.replace(/^0x/, "").toLowerCase() === hash.toLowerCase()) ?? null;
  }

  private async receiptFromTransaction(
    txRef: string,
    tx: { blockNumber?: number | null; content?: { to?: string; data?: unknown; nonce?: number } },
    expectedConfirmationBlock?: number,
    knownContentHash?: string,
    broadcastAt?: number,
    knownNonce?: number,
  ): Promise<AnchorReceipt> {
    const blockNumber = tx.blockNumber;
    if (!Number.isSafeInteger(blockNumber) || Number(blockNumber) < 0) throw new Error("Demos anchor transaction omitted its inclusion block");
    const block = await this.adapter.raw.getBlockByNumber(Number(blockNumber)) as { content?: { timestamp?: number } };
    const anchoredAt = demosBlockTimestampMs(block?.content?.timestamp);
    const address = tx.content?.to;
    if (!address || !/^stor-[0-9a-f]{40}$/i.test(address)) throw new Error("Demos anchor transaction omitted its storage-program address");
    const contentHash = knownContentHash ?? await this.contentHashFromTransaction(tx.content?.data);
    const nonce = knownNonce ?? (Number.isSafeInteger(tx.content?.nonce) ? Number(tx.content?.nonce) : undefined);
    const confirmedAt = Date.now();
    const compact = tx.content === undefined ? undefined : compactTransactionContent(tx.content);
    return {
      address,
      txRef: txRef.replace(/^0x/, ""),
      anchoredAt,
      blockNumber: Number(blockNumber),
      confirmedAt,
      ...(broadcastAt === undefined ? {} : {
        broadcastAt,
        inclusionLatencyMs: Math.max(0, confirmedAt - broadcastAt),
      }),
      ...(contentHash ? { contentHash } : {}),
      ...(nonce === undefined ? {} : { nonce }),
      ...(compact === undefined ? {} : { transactionContent: compact.content }),
      ...(compact?.valueOmitted ? { transactionContentValueOmitted: true } : {}),
      ...(expectedConfirmationBlock === undefined ? {} : {
        expectedConfirmationBlock,
        confirmationBlockDelta: Number(blockNumber) - expectedConfirmationBlock,
      }),
    };
  }

  private async contentHashFromTransaction(data: unknown): Promise<string | undefined> {
    const values = Array.isArray(data) ? data : undefined;
    const payload = values?.[0] === "storageProgram" ? values[1] : undefined;
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) return undefined;
    const value = (payload as { data?: unknown }).data;
    if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
    const { canonicalize, sha256Hex } = await import("@kynesyslabs/dacs");
    return sha256Hex(canonicalize(value as Record<string, unknown>));
  }

  private ownerAddress(owner: string): string {
    const hex = owner.match(/([0-9a-fA-F]{64})$/)?.[1];
    return hex ? `0x${hex}` : owner;
  }

  private async resolvedAddress(owner: string, name: string): Promise<string | null> {
    const resolution = await this.adapter.resolveAnchorByName(name, this.ownerAddress(owner));
    if (resolution.status === "present") return resolution.address;
    if (resolution.status === "absent") return null;
    throw new Error(`anchor ${name} resolution is indeterminate: ${resolution.reason}`);
  }

  /** Existing address for our anchor, or the correctly nonced address of a new write. */
  async anchorAddress(name: string): Promise<string> {
    const existing = await this.resolvedAddress(this.adapter.getAddress(), name);
    if (existing) return existing;
    return this.adapter.anchorAddress(name);
  }

  /**
   * Resolve another owner's existing anchor by logical name. `owner` may be a
   * Demos address or `did:demos:agent:<hex>`.
   */
  async anchorAddressFor(owner: string, name: string): Promise<string> {
    const address = await this.resolvedAddress(owner, name);
    if (!address) throw new Error(`anchor ${name} is absent for ${owner}`);
    return address;
  }

  async readAnchorFor(owner: string, name: string): Promise<Record<string, unknown> | null> {
    const address = await this.resolvedAddress(owner, name);
    return address ? this.read(address) : null;
  }

  /** Read any anchored artifact by address (chain state is shared). */
  async read(ref: string): Promise<Record<string, unknown> | null> {
    const remote = await this.adapter.readAnchor(ref);
    const local = this.localWrites.get(ref);
    if (!local) return remote;
    if (!remote) return local;
    const { canonicalize } = await import("@kynesyslabs/dacs");
    return canonicalize(remote) === canonicalize(local) ? remote : local;
  }

  /**
   * Attested fetch. Non-GitHub URLs go through the real DAHR proxy. GitHub
   * URLs are SHIMMED to a direct authenticated fetch because the public
   * nodes' GitHub egress is broken (stale token / mangled path —
   * kynesyslabs/node#959): the returned responseHash is then a self-observed
   * commitment, not a consensus attestation. One place to delete when the
   * node is fixed.
   */
  async proxyFetch(req: { url: string; method?: string }): Promise<{
    status: number;
    responseHash: string;
    body: unknown;
  }> {
    const isGithub = /^https:\/\/(api\.github\.com|raw\.githubusercontent\.com|github\.com)\//.test(req.url);
    if (isGithub) {
      const { execFileSync } = await import("node:child_process");
      const { sha256Hex } = await import("@kynesyslabs/dacs");
      try {
        // `gh api` authenticates (private repos) and normalises errors.
        const path = req.url.replace(/^https:\/\/api\.github\.com/, "");
        const out = execFileSync("gh", ["api", path], {
          encoding: "utf8",
          maxBuffer: 4 * 1024 * 1024,
        });
        const body = JSON.parse(out);
        return { status: 200, responseHash: sha256Hex(JSON.stringify(body)), body };
      } catch {
        return { status: 404, responseHash: "", body: null };
      }
    }
    const res = await this.adapter.proxyFetch({
      url: req.url,
      method: (req.method as "GET" | "POST") ?? "GET",
    });
    return {
      status: res.status,
      responseHash: res.responseHash ?? "",
      body: (res as { body?: unknown }).body ?? null,
    };
  }
}
