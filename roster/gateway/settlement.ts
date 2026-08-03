/**
 * Pay-dem settlement for the gateway — "present-txHash" flow.
 *
 * An external buyer pays the gateway wallet in DEM, then calls an agent with the
 * payment's txHash in the `X-Payment-Tx` header. The gate verifies the payment is
 * a CONFIRMED native transfer to the gateway wallet for >= the agent's price, and
 * reserves the txHash so one payment buys exactly one successful call (anti-replay).
 * No on-chain memo is needed, which sidesteps the blocked memo-watcher rail (DEP-A).
 *
 * Reservation is released on any non-200 outcome (bad input, agent error, timeout)
 * so a paid buyer can retry without paying again; only a delivered 200 consumes it.
 */

export const OS_PER_DEM = 1_000_000_000n;

/** Subset of a getTxByHash result the gate reads. */
export interface DemTx {
  hash?: string;
  status?: string;
  blockNumber?: number;
  content?: { type?: string; from?: string; to?: string; amount?: string | number; data?: unknown };
}

export interface TxReader {
  getTxByHash(hash: string): Promise<DemTx | null>;
  call?(method: string, message: string, data: { hash: string }): Promise<unknown>;
  getTransactionHistory?(
    address: string,
    type?: "all",
    options?: { start?: number; limit?: number },
  ): Promise<DemTx[]>;
}

/** Public content plus the authoritative inclusion block reported for its hash. */
export interface PaymentInclusionProof {
  transactionContent: Record<string, unknown>;
  blockNumber: number;
}

/** x402 response receipt bound to the independently verified Base transaction. */
export interface X402SettlementProof {
  kind: "x402";
  paymentReceiptHash: string;
}

export type SettlementProof = PaymentInclusionProof | X402SettlementProof;

export interface PaymentResult {
  ok: boolean;
  payer?: string;
  amountOs?: bigint;
  blockNumber?: number;
  reason?: string;
  /** true when the failure is transient (e.g. not yet confirmed) and the buyer can retry. */
  retriable?: boolean;
}

/** Per-agent price lookup. Uniform default now; per-agent overrides can layer on later. */
export interface FeeSchedule {
  priceOsFor(agent: string): bigint;
}

export function uniformFee(priceOs: bigint): FeeSchedule {
  return { priceOsFor: () => priceOs };
}

const HEX64 = /^[0-9a-fA-F]{64}$/;

export class PaymentGate {
  /** txHashes reserved/consumed for a call (in-memory; resets on restart). */
  private readonly reserved = new Set<string>();

  constructor(
    private readonly reader: TxReader,
    private readonly payTo: string,
    private readonly lookupTimeoutMs = 5_000,
  ) {}

  private async bounded<T>(operation: Promise<T>): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        operation,
        new Promise<never>((_resolve, reject) => {
          timer = setTimeout(() => reject(new Error("payment lookup timed out")), this.lookupTimeoutMs);
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  /**
   * The public hash index and address history are independently hydrated. Read
   * both in parallel and prefer whichever already exposes the complete native
   * transfer. This is still a chain read: no buyer-supplied payment fields are
   * trusted, and both projections must name the exact transaction hash.
   */
  private async readPayment(hash: string, proof?: PaymentInclusionProof): Promise<DemTx | null> {
    const direct = this.bounded(this.reader.getTxByHash(hash)).catch(() => null);
    const history = this.reader.getTransactionHistory
      ? this.bounded(this.reader.getTransactionHistory(this.payTo, "all", { start: 0, limit: 100 })).catch(() => [])
      : Promise.resolve([] as DemTx[]);
    const status = proof && this.reader.call
      ? this.bounded(this.reader.call("nodeCall", "getTransactionStatus", { hash })).catch(() => null)
      : Promise.resolve(null);
    const [rawByHash, recipientHistory, rawStatus] = await Promise.all([direct, history, status]);
    const byHash = rawByHash && typeof rawByHash === "object" && !Array.isArray(rawByHash)
      ? rawByHash
      : null;
    const historical = recipientHistory.find((candidate) =>
      candidate.hash?.replace(/^0x/, "").toLowerCase() === hash
    );
    const state = rawStatus && typeof rawStatus === "object" && !Array.isArray(rawStatus)
      ? String((rawStatus as { state?: unknown }).state ?? "")
      : "";
    const statusBlock = rawStatus && typeof rawStatus === "object" && !Array.isArray(rawStatus)
      && Number.isSafeInteger((rawStatus as { blockNumber?: unknown }).blockNumber)
      ? Number((rawStatus as { blockNumber?: unknown }).blockNumber)
      : undefined;
    const proven = proof
      && (state === "included" || state === "confirmed")
      && statusBlock === proof.blockNumber
      ? {
          hash,
          status: "confirmed",
          blockNumber: statusBlock,
          content: proof.transactionContent as DemTx["content"],
        }
      : null;
    const complete = [proven, byHash, historical].find((candidate) =>
      candidate?.status === "confirmed"
      && candidate.content?.type === "native"
      && typeof candidate.content.from === "string"
      && typeof candidate.content.to === "string"
      && candidate.content.amount !== undefined
      && Number.isSafeInteger(candidate.blockNumber)
    );
    return complete ?? byHash ?? historical ?? null;
  }

  /** The DEM address buyers pay to (the gateway's wallet). */
  get payToAddress(): string {
    return this.payTo;
  }

  /**
   * Verify a presented payment and, if valid+sufficient+unused, RESERVE it.
   * Reservation is atomic here (single-threaded JS) so concurrent presentations
   * of the same txHash can't double-spend. Release with `release()` on failure.
   */
  async verifyAndReserve(txHash: string, priceOs: bigint, proof?: PaymentInclusionProof): Promise<PaymentResult> {
    const h = String(txHash ?? "").trim().replace(/^0x/, "").toLowerCase();
    if (!HEX64.test(h)) return { ok: false, reason: "X-Payment-Tx must be a 64-hex tx hash" };
    if (this.reserved.has(h)) return { ok: false, reason: "this payment has already been used" };
    if (proof) {
      if (!Number.isSafeInteger(proof.blockNumber) || proof.blockNumber < 0
        || !proof.transactionContent || typeof proof.transactionContent !== "object" || Array.isArray(proof.transactionContent)) {
        return { ok: false, reason: "payment inclusion proof is malformed" };
      }
      const { createHash } = await import("node:crypto");
      const proofHash = createHash("sha256")
        .update(JSON.stringify(proof.transactionContent), "utf8")
        .digest("hex");
      if (proofHash !== h) return { ok: false, reason: "payment inclusion proof does not match the transaction hash" };
    }

    let tx: DemTx | null;
    try {
      tx = await this.readPayment(h, proof);
    } catch {
      return { ok: false, reason: "payment lookup failed — retry shortly", retriable: true };
    }
    if (!tx) return { ok: false, reason: "payment tx not found yet (unconfirmed?) — retry shortly", retriable: true };
    if (tx.status && tx.status !== "confirmed") {
      return { ok: false, reason: `payment tx status is "${tx.status}" — wait for confirmation`, retriable: true };
    }
    const c = tx.content ?? {};
    // Public nodes can expose the inclusion/status record — and even a
    // partially-hydrated content object — a few seconds before the content's
    // canonical fields settle. A confirmed tx is immutable, so its true type
    // WILL eventually read correctly; a transiently wrong/missing `type` on a
    // confirmed payment is read lag, not evidence of a non-native payment.
    // Treat it as retriable (bounded by verifyPaymentWithRetry's budget) so the
    // buyer is never asked to pay twice for a native payment the node briefly
    // misreported. A genuinely non-native payment reads non-native on every
    // re-read and is still rejected once the retry budget is exhausted — the
    // `data[0]` transaction-kind marker is cross-checked as corroboration.
    const dataKind = Array.isArray(c.data) ? c.data[0] : undefined;
    if (c.type !== "native") {
      const looksNativeElsewhere = dataKind === "native";
      return {
        ok: false,
        reason: looksNativeElsewhere || c.type === undefined
          ? "confirmed payment details are not readable yet — retry shortly"
          : `payment must be a native DEM transfer (read type "${String(c.type)}")`,
        // Retry a confirmed tx whose type reads non-native: the canonical
        // content will settle. Only a fully-unconfirmed/never-found tx (handled
        // above) or a stable non-native reading after the budget is a real reject.
        retriable: true,
      };
    }
    if (String(c.to) !== this.payTo) return { ok: false, reason: "payment recipient is not the gateway wallet" };

    let amountOs: bigint;
    try {
      amountOs = BigInt(c.amount ?? 0);
    } catch {
      return { ok: false, reason: "payment amount is not an integer" };
    }
    if (amountOs < priceOs) {
      return { ok: false, reason: `underpaid: ${amountOs} < ${priceOs} OS required` };
    }

    // All checks passed — reserve the txHash so it buys exactly one call.
    if (!Number.isSafeInteger(tx.blockNumber) || Number(tx.blockNumber) < 0) return { ok: false, reason: "confirmed payment omitted its inclusion block", retriable: true };
    this.reserved.add(h);
    return { ok: true, payer: String(c.from), amountOs, blockNumber: Number(tx.blockNumber) };
  }

  /** Release a reservation so the buyer can retry with the same payment (non-200 outcomes). */
  release(txHash: string): void {
    this.reserved.delete(String(txHash ?? "").trim().replace(/^0x/, "").toLowerCase());
  }
}

/** Everything the gateway needs to gate a request on payment. */
export interface Settlement {
  gate: PaymentGate;
  fee: FeeSchedule;
}

/** The inner error object for a 402 — the fee schedule + how to pay (goes into sendError). */
export function feeScheduleErr(
  agent: string,
  priceOs: bigint,
  payTo: string,
  reason?: string,
): { code: "payment_required"; message: string; details: unknown } {
  return {
    code: "payment_required",
    message: reason ?? "payment required",
    details: {
      fee: {
        rail: "pay-dem",
        asset: "DEM",
        amountOs: priceOs.toString(),
        amountDem: (Number(priceOs) / Number(OS_PER_DEM)).toString(),
        payTo,
        agent,
      },
      howToPay:
        `Send >= ${priceOs} OS DEM to ${payTo} on the Demos chain, then resubmit this ` +
        `request with header "X-Payment-Tx: <txHash>". One payment buys one successful call.`,
    },
  };
}
