/**
 * Bounded public Procurement Butler demo over the real DACS pay-dem lifecycle.
 * The buyer and seller use dedicated funded testnet wallets. Each job discovers
 * an anchored listing, selects it through the Butler, anchors the agreement,
 * settles DEM, receives a hash-bound report, verifies the delivery and both
 * bundle copies, and returns every chain reference for the UI.
 */
import { createHash, randomUUID } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, renameSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { connectIdentity, LiveCci, type LiveIdentity } from "../../src/live/identity.js";
import { LiveSubstrate } from "../../src/live/substrate.js";
import type { AnchorReceipt } from "../../src/ports.js";
import { BuyerAdapter } from "../dacs/buyer.js";
import type { DeliveryAttestation } from "../dacs/seller-adapter.js";
import { VerifierAdapter } from "../dacs/verifier.js";
import { DacsButlerBuyer, type DacsOffer } from "../dacs/wire/butler.js";
import { rubricForOutcome, securityAuditEvaluationPolicy } from "../dacs/wire/evaluator.js";
import {
  secAuditObserveDelivered,
  type PostedFile,
} from "../dacs/wire/sec-audit.js";
import { EvalBot, verifyRuling } from "../evalbot/evalbot.js";
import type { EvaluationRuling } from "../evalbot/types.js";
import type { ProcurementDecision, ProcurementGoal } from "../procurement-butler/types.js";
import { MessagingPeer, initIdentity, primaryClaimSigner } from "../negotiation-l2ps/demosdk.js";
import { RfqBuyerClient } from "../negotiation-l2ps/buyer-client.js";
import { AUDIT_NEGOTIATOR_SERVICE_ID } from "../dacs/wire/audit-negotiator.js";
import { readReportMeta } from "../dacs/wire/report-meta.js";
import {
  listingRef as standardListingRef,
  sameCanonicalBundle,
  standardHash,
  verifyBundle,
  type AgreementDocument,
  type AttestationBundle,
  type AttestationRef,
  type CommitmentRecord,
  type SessionRecord,
  type SessionState,
} from "../dacs/standard-profile.js";
import { confirmVettedParty, cryptoDeps } from "../negotiation-l2ps/standard-session.js";
import { isStandardAgreement } from "../negotiation-l2ps/bind.js";
import { procurementProfile } from "./procurement-profiles.js";
import type { ProcurementX402 } from "./procurement-x402.js";
import {
  isX402Rail,
  paymentPhaseForAgreement,
  verifyX402IdentityBinding,
  x402AgreementTerms,
  x402ListingTerms,
} from "../dacs/x402-production.js";
import { ORACLE_SERVICE_ID, oracleObserveDelivered } from "../dacs/wire/oracle-desk.js";
import { DD_SERVICE_ID, ddObserveDelivered } from "../dacs/wire/dd-researcher.js";
import { sponsoredPostObserveDelivered, SPONSORED_POST_SERVICE_ID } from "../dacs/wire/sponsored-post.js";
import { parseSponsoredPostRequest } from "../sponsored-post/policy.js";
import type { AutoAcceptCommitment, Listing } from "../dacs/standard-profile.js";
import { ORACLE_X402_SERVICE_ID, DD_X402_SERVICE_ID, SPONSORED_POST_X402_SERVICE_ID } from "./procurement-listings.js";
import { AUDIT_NEGOTIATOR_X402_SERVICE_ID } from "../dacs/wire/audit-negotiator.js";
import {
  securityResearcherProfileFromListing,
  securityResearcherVetEvidence,
  type SecurityResearcherHistory,
} from "../dacs/security-researcher-vet.js";

const RPC = process.env.DEMOS_RPC ?? "https://demosnode.discus.sh/";
const OS_PER_DEM = 1_000_000_000n;
const MAX_FILES = 3;
const MAX_FILE_BYTES = 12_000;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export type ProcurementPhase =
  | "queued" | "connecting" | "discovering" | "selecting" | "agreeing"
  | "settling" | "delivering" | "verifying" | "evaluating" | "recovering" | "complete" | "failed";

export interface ProcurementEvent {
  phase: ProcurementPhase;
  label: string;
  at: string;
  txRef?: string;
  anchorRef?: string;
  storageStatus?: "confirmed" | "visible" | "delayed";
  expectedBlock?: number;
  actualBlock?: number;
  blockDelta?: number;
  broadcastAt?: string;
  confirmedAt?: string;
  inclusionMs?: number;
  nonce?: number;
}

export interface ProcurementJob {
  id: string;
  profileId?: string;
  negotiationMode?: string;
  status: "running" | "complete" | "failed";
  phase: ProcurementPhase;
  createdAt: string;
  updatedAt: string;
  events: ProcurementEvent[];
  /** Verified deliverable available while mandatory final DACS-5 anchors continue. */
  preview?: unknown;
  /**
   * Durable, explicitly nonterminal DACS-5 work. `preview` is usable delivery
   * evidence; only `complete` means both bundle copies reconciled.
   */
  finalisation?: {
    status: "running" | "complete" | "failed";
    startedAt: string;
    updatedAt: string;
    attempts: number;
    lastError?: string;
  };
  result?: unknown;
  error?: string;
  /**
   * Set when the job fails: true only when NO payment was broadcast, so a
   * client may safely start a fresh purchase. Absent/false means a payment
   * may exist and the job must be recovered, never re-purchased.
   */
  failedBeforePayment?: boolean;
  sessionRecord?: SessionRecord;
  recovery?: {
    status: "running" | "complete" | "failed";
    startedAt: string;
    updatedAt: string;
    originalError: string;
    originalAbortAnchor?: string;
    originalAbortTxRef?: string;
  };
  /** Persisted hashes make a lost start response replay-safe across restarts. */
  idempotency?: {
    keyHash: string;
    inputHash: string;
  };
  /**
   * Public, non-secret FIFO state for the single buyer-wallet execution lane.
   * Only waiting jobs have a position; active/finished records retain timings
   * so clients can explain queue latency separately from protocol latency.
   */
  queue?: {
    status: "waiting" | "active" | "finished";
    enqueuedAt: string;
    position?: number;
    startedAt?: string;
    waitMs?: number;
    finishedAt?: string;
  };
}

/**
 * Conservative payment marker. The "Paying …" settling event is PERSISTED
 * (push → persist) before the wallet transfer/confirm/broadcast calls run, so
 * any persisted settling-phase event means a broadcast MAY have happened —
 * including a crash inside the broadcast window before the txRef event was
 * written. Only jobs that never reached settling are provably unpaid.
 */
function paymentMayHaveBroadcast(job: ProcurementJob): boolean {
  return job.events.some((event) => event.phase === "settling");
}

/**
 * Return the persisted payment receipt only when this job is safe to resume.
 * Recovery is intentionally stricter than `paymentMayHaveBroadcast`: a
 * settling-window crash without a txRef must stay stopped for operator
 * inspection because there is no specific payment transaction to bind.
 */
function recoverablePayment(job: ProcurementJob): ProcurementEvent | undefined {
  if (job.status !== "failed"
    || !job.sessionRecord
    || job.sessionRecord.state !== "aborted-by-self") return undefined;
  return [...job.events].reverse().find(
    (event) => event.label === "Payment broadcast on Demos" && event.txRef,
  );
}

export function verifiedListingAnchor(events: ProcurementEvent[]): string | undefined {
  return events.find((event) =>
    event.phase === "discovering"
    && event.label.startsWith("Verified the ")
    && event.label.includes(" listing")
    && event.anchorRef,
  )?.anchorRef;
}

export interface ProcurementStartResult {
  job: ProcurementJob;
  replayed: boolean;
}

export interface ProcurementReadiness {
  executable: boolean;
  reasons: string[];
  railGovernance?: {
    status: "normative-pa2" | "operator-provisional";
    conformantAuthority: boolean;
    signer: string;
    disclosure?: string;
  };
}

export type ProcurementPaymentRail = "pay-dem" | "pay-x402";

interface RfqStartInput {
  profileId: "security-audit-rfq";
  goal: string;
  budgetDem: number;
  paymentRail: ProcurementPaymentRail;
  files: PostedFile[];
  auditorListingRef?: string;
}

interface OracleStartInput {
  profileId: "oracle-auto-accept";
  product: "crypto-price" | "fx-rate" | "chain-height";
  params: Record<string, unknown>;
  paymentRail: ProcurementPaymentRail;
}

interface DdFixedStartInput {
  profileId: "dd-live-fixed";
  kind: "npm-package" | "crypto-token";
  subject: string;
  paymentRail: ProcurementPaymentRail;
}

interface SponsoredPostStartInput {
  profileId: "sponsored-post-live";
  text: string;
  paymentRail: ProcurementPaymentRail;
}

interface DdTenderStartInput {
  profileId: "dd-sealed-tender";
  kind: "npm-package" | "crypto-token";
  subject: string;
  maxPriceDem: number;
}

type StartInput = RfqStartInput | OracleStartInput | DdFixedStartInput | SponsoredPostStartInput | DdTenderStartInput;

interface PendingProcurement {
  job: ProcurementJob;
  execute: () => Promise<void>;
  fail: (error: unknown) => void;
}

/** Convert the demo HTTP shape into the Oracle catalog's protocol work shape. */
export function oracleProtocolRequest(input: OracleStartInput): Record<string, unknown> {
  return { ...structuredClone(input.params), product: input.product };
}

interface AnchorTx {
  kind: "anchor";
  owner: "buyer" | "seller";
  name: string;
  address: string;
  txRef?: string;
  storageStatus?: "confirmed" | "visible" | "delayed";
  expectedConfirmationBlock?: number;
  blockNumber?: number;
  confirmationBlockDelta?: number;
  broadcastAt?: number;
  confirmedAt?: number;
  inclusionLatencyMs?: number;
  nonce?: number;
}

interface WalletLike {
  transfer(to: string, amount: bigint, options?: { nonce?: number }): Promise<{
    hash?: string;
    content?: Record<string, unknown> & { nonce?: number };
  }>;
  confirm(tx: unknown): Promise<unknown>;
  broadcast(tx: unknown): Promise<{ result?: number; response?: { hash?: string; message?: string }; extra?: { confirmationBlock?: number } }>;
  getAddressInfo(address: string): Promise<{ balance?: bigint; nonce?: number } | null>;
  getLastBlockNumber?(): Promise<number>;
  getTxByHash?(hash: string): Promise<unknown>;
  call?(method: string, message: string, data: { hash: string }): Promise<unknown>;
}

export interface NativePaymentReceipt {
  txHash: string;
  nonce: number;
  expectedBlock?: number;
  attempt: number;
  /** Exact public transaction body whose hash is `txHash`. */
  transactionContent: Record<string, unknown>;
  /** Authoritative inclusion block, once reported by transaction status. */
  blockNumber?: number;
}

interface NativePaymentRetryOptions {
  /** Explicit next wallet nonce after locally-confirmed ordered anchors. */
  nonce?: number;
  attempts?: number;
  confirmTimeoutMs?: number;
  attemptTimeoutMs?: number;
  rpcTimeoutMs?: number;
  pollIntervalMs?: number;
  /**
   * Prefer the exact confirmed transaction record over the eventually
   * consistent status projection. Disabled by default for a safe canary.
   */
  directConfirmation?: boolean;
  onBroadcast?: (receipt: NativePaymentReceipt) => void;
}

class IndeterminatePaymentError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "IndeterminatePaymentError";
  }
}

async function bounded<T>(operation: Promise<T>, timeoutMs: number, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      operation,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} timed out after ${timeoutMs}ms`)), timeoutMs);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function normalizedTransactionHash(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.replace(/^0x/, "").toLowerCase();
  return /^[0-9a-f]{64}$/.test(normalized) ? normalized : undefined;
}

/**
 * A direct lookup is load-bearing payment evidence, so accept it only when
 * the node returns the exact transaction we signed, at a concrete inclusion
 * block. A malformed or content-mismatched confirmed response fails closed.
 */
function directPaymentInclusion(
  raw: unknown,
  receipt: NativePaymentReceipt,
  from: string,
  to: string,
  amount: bigint,
): number | undefined {
  if (raw === null || raw === undefined || raw === "error") return undefined;
  if (typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const tx = raw as {
    hash?: unknown;
    status?: unknown;
    blockNumber?: unknown;
    content?: unknown;
  };
  const state = String(tx.status ?? "");
  if (state !== "confirmed" && state !== "included") return undefined;
  if (!Number.isSafeInteger(tx.blockNumber) || Number(tx.blockNumber) < 0) {
    throw new IndeterminatePaymentError(`confirmed pay-dem transaction ${receipt.txHash} omitted its inclusion block`);
  }
  const returnedHash = normalizedTransactionHash(tx.hash);
  if (returnedHash !== receipt.txHash) {
    throw new IndeterminatePaymentError(`confirmed pay-dem lookup returned the wrong transaction hash`);
  }
  if (!tx.content || typeof tx.content !== "object" || Array.isArray(tx.content)) {
    throw new IndeterminatePaymentError(`confirmed pay-dem transaction ${receipt.txHash} omitted its public content`);
  }
  const content = tx.content as Record<string, unknown>;
  const normalizeAddress = (value: unknown): string => String(value ?? "").replace(/^0x/, "").toLowerCase();
  const expectedFrom = normalizeAddress(from);
  const expectedTo = normalizeAddress(to);
  const contentFrom = normalizeAddress(content.from);
  const contentTo = normalizeAddress(content.to);
  let contentAmount: bigint;
  try {
    contentAmount = BigInt(content.amount as string | number | bigint);
  } catch {
    throw new IndeterminatePaymentError(`confirmed pay-dem transaction ${receipt.txHash} had an invalid amount`);
  }
  const data = Array.isArray(content.data) ? content.data : [];
  const operation = data[1] && typeof data[1] === "object" && !Array.isArray(data[1])
    ? data[1] as { nativeOperation?: unknown; args?: unknown }
    : undefined;
  const args = Array.isArray(operation?.args) ? operation.args : [];
  let dataAmount: bigint | undefined;
  try {
    if (args[1] !== undefined) dataAmount = BigInt(args[1] as string | number | bigint);
  } catch {
    throw new IndeterminatePaymentError(`confirmed pay-dem transaction ${receipt.txHash} had invalid native send data`);
  }
  if (content.type !== "native"
    || contentFrom !== expectedFrom
    || contentTo !== expectedTo
    || contentAmount !== amount
    || Number(content.nonce) !== receipt.nonce) {
    throw new IndeterminatePaymentError(`confirmed pay-dem transaction ${receipt.txHash} did not match the intended payment`);
  }
  if (data.length > 0 && (data[0] !== "native"
    || operation?.nativeOperation !== "send"
    || normalizeAddress(args[0]) !== expectedTo
    || dataAmount !== amount)) {
    throw new IndeterminatePaymentError(`confirmed pay-dem transaction ${receipt.txHash} had inconsistent native send data`);
  }
  return Number(tx.blockNumber);
}

function nativePaymentCanaryOptions(): Pick<NativePaymentRetryOptions, "directConfirmation" | "attemptTimeoutMs"> {
  if (process.env.DACS_PAYMENT_DIRECT_CONFIRMATION !== "1") return {};
  const configured = Number(process.env.DACS_PAYMENT_PENDING_DEADLINE_MS);
  const attemptTimeoutMs = Number.isSafeInteger(configured) && configured >= 60_000 && configured <= 300_000
    ? configured
    : 180_000;
  return { directConfirmation: true, attemptTimeoutMs };
}

function durableFinalisationEnabled(): boolean {
  return process.env.DACS_DURABLE_ASYNC_FINALISATION === "1";
}

function transientFinalisationFailure(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /Target peer .* not found|timed out|disconnect|ECONN|network|substrate|did not resolve to a confirmed inclusion block/i.test(message);
}

/**
 * Broadcast one native payment with a stable nonce and retry only after the
 * authoritative status RPC proves the prior hash was dropped. A pending or
 * indeterminate hash is never duplicated. This mirrors the anchor retry rule
 * while keeping payment-specific state visible to the procurement journal.
 */
export async function broadcastNativePayment(
  w: WalletLike,
  from: string,
  to: string,
  amount: bigint,
  options: NativePaymentRetryOptions = {},
): Promise<NativePaymentReceipt> {
  const attempts = options.attempts ?? 3;
  const confirmTimeoutMs = options.confirmTimeoutMs ?? 15_000;
  const attemptTimeoutMs = options.attemptTimeoutMs ?? 60_000;
  const rpcTimeoutMs = options.rpcTimeoutMs ?? 4_000;
  const pollIntervalMs = options.pollIntervalMs ?? 1_000;
  const directConfirmation = options.directConfirmation === true;
  let reservedNonce: number | undefined = options.nonce;
  let lastError: Error | undefined;

  for (let attempt = 1; attempt <= attempts; attempt++) {
    let signed: Awaited<ReturnType<WalletLike["transfer"]>>;
    let accepted = false;
    try {
      signed = await w.transfer(to, amount, reservedNonce === undefined ? undefined : { nonce: reservedNonce });
      const candidateNonce = Number(signed.content?.nonce);
      if (!Number.isSafeInteger(candidateNonce)) throw new Error("pay-dem transaction omitted its sequential nonce");
      if (reservedNonce !== undefined && candidateNonce !== reservedNonce) throw new Error("pay-dem retry changed its reserved nonce");
      reservedNonce = candidateNonce;
      const validity = await bounded(w.confirm(signed), confirmTimeoutMs, "pay-dem pre-broadcast confirmation");
      let broadcast: Awaited<ReturnType<WalletLike["broadcast"]>>;
      try {
        broadcast = await bounded(w.broadcast(validity), rpcTimeoutMs, "pay-dem broadcast");
      } catch (error) {
        // A transport timeout does not prove whether the node accepted the tx.
        throw new IndeterminatePaymentError((error as Error).message);
      }
      if (broadcast.result !== 200) {
        lastError = new Error(`pay-dem broadcast rejected: ${broadcast.response?.message ?? "unknown error"}`);
        continue;
      }
      accepted = true;
      const txHash = broadcast.response?.hash ?? signed.hash ?? "";
      if (!/^[0-9a-f]{64}$/i.test(txHash)) throw new IndeterminatePaymentError("pay-dem broadcast was accepted without a transaction hash");
      const receipt: NativePaymentReceipt = {
        txHash: txHash.replace(/^0x/, "").toLowerCase(),
        nonce: reservedNonce,
        transactionContent: JSON.parse(JSON.stringify(signed.content)) as Record<string, unknown>,
        ...(Number.isSafeInteger(broadcast.extra?.confirmationBlock) ? { expectedBlock: Number(broadcast.extra!.confirmationBlock) } : {}),
        attempt,
      };
      options.onBroadcast?.(receipt);

      const deadline = Date.now() + attemptTimeoutMs;
      while (Date.now() < deadline) {
        const [info, status, head, direct] = await Promise.all([
          bounded(w.getAddressInfo(from), rpcTimeoutMs, "buyer nonce lookup").catch(() => null),
          w.call
            ? bounded(w.call("nodeCall", "getTransactionStatus", { hash: receipt.txHash }), rpcTimeoutMs, "payment status lookup").catch(() => null)
            : Promise.resolve(null),
          w.getLastBlockNumber
            ? bounded(w.getLastBlockNumber(), rpcTimeoutMs, "chain head lookup").catch(() => null)
            : Promise.resolve(null),
          directConfirmation && w.getTxByHash
            ? bounded(w.getTxByHash(receipt.txHash), rpcTimeoutMs, "direct payment lookup").catch(() => null)
            : Promise.resolve(null),
        ]);
        if (directConfirmation) {
          const directBlock = directPaymentInclusion(direct, receipt, from, to, amount);
          if (directBlock !== undefined) {
            receipt.blockNumber = directBlock;
            return receipt;
          }
        }
        const state = status && typeof status === "object" && !Array.isArray(status)
          ? String((status as { state?: unknown }).state ?? "")
          : "";
        const statusBlock = status && typeof status === "object" && !Array.isArray(status)
          && Number.isSafeInteger((status as { blockNumber?: unknown }).blockNumber)
          ? Number((status as { blockNumber?: unknown }).blockNumber)
          : undefined;
        if ((state === "included" || state === "confirmed") && statusBlock !== undefined) {
          receipt.blockNumber = statusBlock;
          return receipt;
        }
        if (!w.call && reservedNonce !== undefined && Number(info?.nonce ?? -1) > reservedNonce) return receipt;
        const pastExpectedWindow = receipt.expectedBlock !== undefined
          && Number.isSafeInteger(head)
          && Number(head) > receipt.expectedBlock + 2;
        const dropped = (state === "failed" || state === "unknown") && pastExpectedWindow;
        if (dropped) {
          if (reservedNonce !== undefined && Number(info?.nonce ?? -1) > reservedNonce) {
            throw new IndeterminatePaymentError(
              `pay-dem transaction ${receipt.txHash} is absent but buyer nonce advanced; refusing a duplicate payment`,
            );
          }
          lastError = new Error(`pay-dem transaction ${receipt.txHash} was dropped before inclusion`);
          break;
        }
        await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
      }
      if (Date.now() >= deadline) {
        throw new IndeterminatePaymentError(`pay-dem transaction ${receipt.txHash} remained pending; refusing a duplicate payment`);
      }
    } catch (error) {
      if (error instanceof IndeterminatePaymentError) throw error;
      if (accepted) throw new IndeterminatePaymentError((error as Error).message);
      lastError = error as Error;
      // A confirmation/broadcast rejection has not produced an accepted tx;
      // a proven-dropped tx is also safe to rebuild with the same nonce.
    }
  }
  throw lastError ?? new Error("pay-dem could not be broadcast safely");
}

export class LiveProcurementError extends Error {
  constructor(readonly status: 400 | 404 | 409 | 503, message: string) {
    super(message);
    this.name = "LiveProcurementError";
  }
}

function keyFile(envName: string, secureName: string, localName: string): string | undefined {
  const explicit = process.env[envName];
  const candidates = [
    explicit,
    join(homedir(), ".config", "dacs", secureName),
    join(process.cwd(), "roster", "dacs", "live", localName),
  ].filter((value): value is string => typeof value === "string" && value.length > 0);
  return candidates.find((candidate) => existsSync(candidate));
}

function boundedSubject(value: unknown): string {
  const subject = typeof value === "string" ? value.trim() : "";
  if (!subject || subject.length > 120 || !/^[A-Za-z0-9@._:/-]+$/.test(subject)) {
    throw new LiveProcurementError(400, "subject must be 1-120 safe package/id characters");
  }
  return subject;
}

function procurementKind(value: unknown): "npm-package" | "crypto-token" {
  if (value !== "npm-package" && value !== "crypto-token") {
    throw new LiveProcurementError(400, "kind must be npm-package or crypto-token");
  }
  return value;
}

function plainParams(value: unknown): Record<string, unknown> {
  if (value === undefined) return {};
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new LiveProcurementError(400, "params must be a JSON object");
  }
  const encoded = JSON.stringify(value);
  if (Buffer.byteLength(encoded, "utf8") > 2_048) {
    throw new LiveProcurementError(400, "params exceeds 2048 bytes");
  }
  return structuredClone(value as Record<string, unknown>);
}

export function parseProcurementInput(value: unknown): StartInput {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new LiveProcurementError(400, "request body must be an object");
  const body = value as Record<string, unknown>;
  const profileId = body.profileId === undefined ? "security-audit-rfq" : body.profileId;
  if (typeof profileId !== "string") throw new LiveProcurementError(400, "profileId must be a string");
  const profile = procurementProfile(profileId);
  if (!profile) throw new LiveProcurementError(400, `unknown procurement profile "${profileId}"`);
  if (profile.implementationStatus !== "live") {
    throw new LiveProcurementError(503, `${profile.title} is not executable yet: ${profile.unavailableReason ?? "seller is not provisioned"}`);
  }
  const paymentRail = body.paymentRail === undefined ? "pay-dem" : body.paymentRail;
  if (paymentRail !== "pay-dem" && paymentRail !== "pay-x402") {
    throw new LiveProcurementError(400, "paymentRail must be pay-dem or pay-x402");
  }
  if (profileId === "oracle-auto-accept") {
    if (body.product !== "crypto-price" && body.product !== "fx-rate" && body.product !== "chain-height") {
      throw new LiveProcurementError(400, "product must be crypto-price, fx-rate, or chain-height");
    }
    return { profileId, product: body.product, params: plainParams(body.params), paymentRail };
  }
  if (profileId === "dd-live-fixed") {
    return { profileId, kind: procurementKind(body.kind), subject: boundedSubject(body.subject), paymentRail };
  }
  if (profileId === "sponsored-post-live") {
    try {
      return { profileId, ...parseSponsoredPostRequest({ text: body.text }), paymentRail };
    } catch (error) {
      throw new LiveProcurementError(400, error instanceof Error ? error.message : "invalid sponsored post request");
    }
  }
  if (profileId === "dd-sealed-tender") {
    const maxPriceDem = typeof body.maxPriceDem === "number" ? body.maxPriceDem : Number.NaN;
    if (!Number.isFinite(maxPriceDem) || maxPriceDem < 1 || maxPriceDem > 10) {
      throw new LiveProcurementError(400, "maxPriceDem must be between 1 and 10");
    }
    return { profileId, kind: procurementKind(body.kind), subject: boundedSubject(body.subject), maxPriceDem };
  }
  const goal = typeof body.goal === "string" ? body.goal.trim() : "";
  if (!goal || goal.length > 300) throw new LiveProcurementError(400, "goal must be 1-300 characters");
  const budgetRaw = paymentRail === "pay-x402" ? body.budgetUsdc : (body.budgetDem ?? body.budgetUsd);
  const budgetDem = typeof budgetRaw === "number" ? budgetRaw : Number.NaN;
  const minimumBudget = paymentRail === "pay-x402" ? 0.000001 : 1;
  if (!Number.isFinite(budgetDem) || budgetDem < minimumBudget || budgetDem > 10) {
    throw new LiveProcurementError(400, `${paymentRail === "pay-x402" ? "budgetUsdc" : "budgetDem"} must be between ${minimumBudget} and 10`);
  }
  const rawFiles = body.files ?? [{ path: "server.js", content: "const userInput = process.argv[2];\neval(userInput);\n" }];
  if (!Array.isArray(rawFiles) || rawFiles.length === 0 || rawFiles.length > MAX_FILES) {
    throw new LiveProcurementError(400, `files must contain 1-${MAX_FILES} posted files`);
  }
  const files = rawFiles.map((raw, index) => {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new LiveProcurementError(400, `files[${index}] must be an object`);
    const file = raw as Record<string, unknown>;
    if (typeof file.path !== "string" || !file.path.trim() || file.path.length > 160 || typeof file.content !== "string") {
      throw new LiveProcurementError(400, `files[${index}] needs a path and string content`);
    }
    if (Buffer.byteLength(file.content, "utf8") > MAX_FILE_BYTES) throw new LiveProcurementError(400, `files[${index}] exceeds ${MAX_FILE_BYTES} bytes`);
    return { path: file.path, content: file.content };
  });
  const auditorListingRef = body.auditorListingRef;
  if (auditorListingRef !== undefined && (typeof auditorListingRef !== "string" || !/^stor-[0-9a-f]{40,}$/i.test(auditorListingRef))) {
    throw new LiveProcurementError(400, "auditorListingRef must be a Demos storage address");
  }
  return { profileId: "security-audit-rfq", goal, budgetDem, files, paymentRail, ...(auditorListingRef ? { auditorListingRef } : {}) };
}

function normalizeIdempotencyKey(value: string): string {
  const key = value.trim();
  if (!IDEMPOTENCY_KEY.test(key)) {
    throw new LiveProcurementError(400, "idempotency key must be 1-128 URL-safe characters");
  }
  return key;
}

/**
 * Accept the standard request header and a JSON-body fallback. Supplying both
 * is allowed only when they name the same logical request.
 */
export function procurementIdempotencyKey(
  headerValue: string | string[] | undefined,
  body: unknown,
): string | undefined {
  if (Array.isArray(headerValue) && headerValue.length !== 1) {
    throw new LiveProcurementError(400, "send exactly one Idempotency-Key header");
  }
  const rawHeader = Array.isArray(headerValue) ? headerValue[0] : headerValue;
  const record = body && typeof body === "object" && !Array.isArray(body)
    ? body as Record<string, unknown>
    : undefined;
  const rawBody = record?.idempotencyKey;
  if (rawBody !== undefined && typeof rawBody !== "string") {
    throw new LiveProcurementError(400, "idempotencyKey must be a string");
  }
  const headerKey = rawHeader === undefined ? undefined : normalizeIdempotencyKey(rawHeader);
  const bodyKey = rawBody === undefined ? undefined : normalizeIdempotencyKey(rawBody);
  if (headerKey !== undefined && bodyKey !== undefined && headerKey !== bodyKey) {
    throw new LiveProcurementError(400, "Idempotency-Key header and idempotencyKey body field must match");
  }
  return headerKey ?? bodyKey;
}

function requestHash(input: StartInput): string {
  // parseInput has already normalized aliases and defaults. Constructing this
  // object in a fixed order makes JSON encoding deterministic for this schema.
  // Preserve the original RFQ encoding so accepted idempotency keys survive a
  // rolling deployment; new profiles include their selector in the hash.
  const scope = input.profileId === "security-audit-rfq" ? {
    // Preserve the original RFQ encoding so accepted idempotency keys survive
    // rolling deployment of the multi-profile gateway.
    goal: input.goal,
    budgetDem: input.budgetDem,
    files: input.files.map((file) => ({ path: file.path, content: file.content })),
    auditorListingRef: input.auditorListingRef ?? null,
    ...(input.paymentRail === "pay-x402" ? { paymentRail: input.paymentRail } : {}),
  } : input.profileId === "oracle-auto-accept" ? {
    profileId: input.profileId,
    product: input.product,
    params: input.params,
    ...(input.paymentRail === "pay-x402" ? { paymentRail: input.paymentRail } : {}),
  } : input.profileId === "dd-live-fixed" ? {
    profileId: input.profileId,
    kind: input.kind,
    subject: input.subject,
    ...(input.paymentRail === "pay-x402" ? { paymentRail: input.paymentRail } : {}),
  } : input.profileId === "sponsored-post-live" ? {
    profileId: input.profileId,
    text: input.text,
    ...(input.paymentRail === "pay-x402" ? { paymentRail: input.paymentRail } : {}),
  } : {
    profileId: input.profileId,
    kind: input.kind,
    subject: input.subject,
    maxPriceDem: input.maxPriceDem,
  };
  return createHash("sha256").update(JSON.stringify(scope)).digest("hex");
}

function keyHash(key: string): string {
  return createHash("sha256").update(key).digest("hex");
}

function wallet(identity: LiveIdentity): WalletLike {
  return (identity.adapter as unknown as { raw: WalletLike }).raw;
}

export class LiveProcurementJobs {
  private readonly jobs = new Map<string, ProcurementJob>();
  private readonly jobsByIdempotencyKey = new Map<string, string>();
  /**
   * Ids whose in-memory record is a slim index entry (status + idempotency
   * only) with the full body left on disk. Keeps startup memory bounded while
   * the idempotency/recovery index stays complete: only OLD COMPLETE jobs are
   * ever slimmed — running/failed/recent jobs stay fully loaded.
   */
  private readonly archived = new Set<string>();
  private activeJobId?: string;
  private readonly pending: PendingProcurement[] = [];
  private starts: number[] = [];

  constructor(
    private readonly jobsDir = process.env.DACS_PROCUREMENT_JOBS_DIR ?? join(process.cwd(), "roster", "gateway", "out", "procurement-jobs"),
    private readonly procurementX402?: ProcurementX402,
  ) {
    mkdirSync(this.jobsDir, { recursive: true, mode: 0o700 });
    chmodSync(this.jobsDir, 0o700);
    // Load EVERY persisted job. The idempotency index and any potentially-paid
    // record must be complete: UUID filenames sort in random order, so any cap
    // here could silently drop an unresolved paid job's idempotency record and
    // let a lost-response retry create a second paid purchase. Demo volume is
    // rate-limited (3 starts/hour), so the file count stays small.
    const files = readdirSync(this.jobsDir).filter((name) => /^[0-9a-f-]+\.json$/i.test(name)).sort();
    const KEEP_FULL_COMPLETE = 100;
    const completeIndex: Array<{ id: string; createdAt: string }> = [];
    const restartFinalisation = new Set<string>();
    for (const name of files) {
      try {
        const job = JSON.parse(readFileSync(join(this.jobsDir, name), "utf8")) as ProcurementJob;
        if (!job?.id || !Array.isArray(job.events)) continue;
        if (job.status === "running") {
          const recovering = job.recovery?.status === "running";
          const resumableFinalisation = durableFinalisationEnabled()
            && job.finalisation?.status === "running"
            && job.preview !== undefined
            && job.events.some((event) => event.label === "Payment broadcast on Demos" && event.txRef);
          job.status = "failed";
          job.phase = "failed";
          job.failedBeforePayment = !recovering && !paymentMayHaveBroadcast(job);
          job.error = recovering
            ? "gateway restarted before paid-job recovery completed; the original payment remains reserved and recovery can be resumed"
            : "gateway restarted before the run completed; anchored phases remain safe to inspect";
          job.updatedAt = new Date().toISOString();
          job.events.push({ phase: "failed", label: recovering ? "Recovery stopped safely after gateway restart" : "Stopped safely after gateway restart", at: job.updatedAt });
          if (recovering && job.recovery) {
            job.recovery.status = "failed";
            job.recovery.updatedAt = job.updatedAt;
          }
          if (job.finalisation?.status === "running") {
            job.finalisation.status = resumableFinalisation ? "running" : "failed";
            job.finalisation.updatedAt = job.updatedAt;
            if (!resumableFinalisation) job.finalisation.lastError = job.error;
          }
          if (job.sessionRecord && job.sessionRecord.state !== "finalised") {
            const endedAt = Date.now();
            job.sessionRecord.state = "aborted-by-self";
            job.sessionRecord.lastUpdatedAt = endedAt;
            job.sessionRecord.endedAt = endedAt;
          }
          this.persist(job);
          if (resumableFinalisation) restartFinalisation.add(job.id);
        }
        if (job.status === "failed"
          && durableFinalisationEnabled()
          && job.finalisation?.status === "running"
          && job.finalisation.attempts < 3
          && job.preview !== undefined
          && job.sessionRecord?.state === "aborted-by-self"
          && job.events.some((event) => event.label === "Payment broadcast on Demos" && event.txRef)) {
          restartFinalisation.add(job.id);
        }
        // Startup memory is bounded WHILE streaming, not after the fact:
        // COMPLETE jobs are slimmed to their index entry (status +
        // idempotency + timestamps) immediately, so at most one complete
        // body is held at a time during the scan. Non-complete jobs
        // (running-now-failed, failed) always stay fully loaded — they are
        // the recovery-relevant ones and their count stays small. The
        // newest KEEP_FULL_COMPLETE complete jobs are re-hydrated below.
        if (job.status === "complete") {
          this.jobs.set(job.id, {
            id: job.id, status: job.status, phase: job.phase,
            createdAt: job.createdAt, updatedAt: job.updatedAt,
            events: [],
            ...(job.idempotency ? { idempotency: job.idempotency } : {}),
          });
          this.archived.add(job.id);
          completeIndex.push({ id: job.id, createdAt: job.createdAt });
        } else {
          this.jobs.set(job.id, job);
        }
        if (job.idempotency) {
          const incumbentId = this.jobsByIdempotencyKey.get(job.idempotency.keyHash);
          const incumbent = incumbentId ? this.jobs.get(incumbentId) : undefined;
          // If old data somehow contains a duplicate key, preserve the first
          // accepted request rather than ever directing a retry to a later job.
          if (!incumbent || Date.parse(job.createdAt) < Date.parse(incumbent.createdAt)) {
            this.jobsByIdempotencyKey.set(job.idempotency.keyHash, job.id);
          }
        }
        const started = Date.parse(job.createdAt);
        if (Number.isFinite(started) && Date.now() - started < 60 * 60_000) this.starts.push(started);
      } catch { /* an invalid file is ignored, never trusted as a receipt */ }
    }
    // Keep the newest complete jobs fully loaded for fast reads; everything
    // older stays a slim entry hydrated from disk on access.
    completeIndex.sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
    for (const { id } of completeIndex.slice(0, KEEP_FULL_COMPLETE)) {
      try {
        const full = JSON.parse(readFileSync(join(this.jobsDir, `${id}.json`), "utf8")) as ProcurementJob;
        if (full?.id === id) {
          this.jobs.set(id, full);
          this.archived.delete(id);
        }
      } catch { /* stays slim; hydrated on demand instead */ }
    }
    // A verified preview has already crossed the payment and delivery
    // boundaries. Resume it through the existing payment-free recovery path
    // after the complete idempotency index has been rebuilt. This remains on
    // the single buyer-wallet lane, so nonce safety is unchanged.
    for (const id of restartFinalisation) {
      queueMicrotask(() => {
        try {
          this.recover(id);
        } catch (error) {
          const job = this.jobs.get(id);
          if (!job?.finalisation) return;
          job.finalisation.status = "failed";
          job.finalisation.updatedAt = new Date().toISOString();
          job.finalisation.lastError = error instanceof Error ? error.message : String(error);
          this.persist(job);
        }
      });
    }
  }

  available(): boolean {
    return this.readiness("security-audit-rfq").executable;
  }

  /**
   * Fail-closed production preflight. It reports configuration classes only;
   * paths, key contents and wallet material are never returned to the caller.
   */
  readiness(profileId: string, paymentRail: ProcurementPaymentRail = "pay-dem"): ProcurementReadiness {
    const profile = procurementProfile(profileId);
    const reasons: string[] = [];
    if (!profile) return { executable: false, reasons: ["unknown procurement profile"] };
    if (profile.implementationStatus !== "live") {
      reasons.push(profile.unavailableReason ?? "production executor is not installed");
    }
    if (paymentRail === "pay-x402" && !this.procurementX402) {
      reasons.push("Base Sepolia x402 buyer/resource is not configured");
    }
    const buyerPath = keyFile("DACS_PROCUREMENT_BUYER_KEY_FILE", "procurement-buyer.key", ".l1-buyer-key");
    if (!buyerPath) {
      reasons.push("buyer wallet is not installed");
    } else {
      try {
        if ((statSync(buyerPath).mode & 0o077) !== 0) reasons.push("buyer wallet permissions are not 0600");
        if (!readFileSync(buyerPath, "utf8").trim()) reasons.push("buyer wallet is empty");
      } catch {
        reasons.push("buyer wallet is unreadable");
      }
    }
    if (profileId === "security-audit-rfq") {
      const listingName = paymentRail === "pay-x402" ? "DACS_AUDITOR_X402_LISTING_REF" : "DACS_AUDITOR_LISTING_REF";
      if (!/^stor-[0-9a-f]{40,}$/i.test(process.env[listingName]?.trim() ?? "")) {
        reasons.push(`Auditor ${paymentRail} DACS-1 listing binding is not configured`);
      }
      const did = process.env.DACS_AUDITOR_DID?.trim() ?? "";
      if (!/^did:demos:agent:[0-9a-f]{64}$/i.test(did)) reasons.push("Auditor DID is invalid");
      if (!/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/.test(
        (process.env.DACS_AUDITOR_RESEARCHER_GITHUB ?? "").trim().replace(/^@/, ""),
      )) {
        reasons.push("Auditor researcher GitHub identity is not configured");
      }
    } else if (profileId === "oracle-auto-accept" || profileId === "dd-live-fixed" || profileId === "sponsored-post-live") {
      const prefix = profileId === "oracle-auto-accept" ? "DACS_ORACLE"
        : profileId === "dd-live-fixed" ? "DACS_DD"
        : "DACS_SPONSORED_POST";
      const name = profileId === "oracle-auto-accept" ? "Oracle"
        : profileId === "dd-live-fixed" ? "DD"
        : "Sponsored Post";
      const listingName = `${prefix}${paymentRail === "pay-x402" ? "_X402" : ""}_LISTING_REF`;
      if (!/^stor-[0-9a-f]{40,}$/i.test(process.env[listingName]?.trim() ?? "")) {
        reasons.push(`${name} ${paymentRail === "pay-x402" ? "pay-x402 " : ""}DACS-1 listing binding is not configured`);
      }
      if (!/^did:demos:agent:[0-9a-f]{64}$/i.test(process.env[`${prefix}_DID`]?.trim() ?? "")) {
        reasons.push(`${name} DID is not configured`);
      }
      if (profileId === "oracle-auto-accept"
        && !/^stor-[0-9a-f]{40,}$/i.test(process.env[paymentRail === "pay-x402" ? "DACS_ORACLE_X402_AUTO_ACCEPT_REF" : "DACS_ORACLE_AUTO_ACCEPT_REF"]?.trim() ?? "")) {
        reasons.push(`Oracle ${paymentRail} AutoAcceptCommitment binding is not configured`);
      }
    }
    return {
      executable: reasons.length === 0,
      reasons,
      ...(paymentRail === "pay-x402" && this.procurementX402
        ? { railGovernance: this.procurementX402.governance }
        : {}),
    };
  }

  start(raw: unknown): ProcurementJob {
    return this.startRequest(raw).job;
  }

  /**
   * Start a new paid lifecycle or return the original receipt for a replay.
   * beforeCreate is deliberately invoked only for a genuinely new job so an
   * HTTP retry does not consume the public demo's rate/concurrency allowance.
   */
  startRequest(raw: unknown, idempotencyKey?: string, beforeCreate?: () => void): ProcurementStartResult {
    const input = parseProcurementInput(raw);
    const idempotency = idempotencyKey === undefined
      ? undefined
      : { keyHash: keyHash(normalizeIdempotencyKey(idempotencyKey)), inputHash: requestHash(input) };
    if (idempotency) {
      const existingId = this.jobsByIdempotencyKey.get(idempotency.keyHash);
      const existing = existingId ? this.jobs.get(existingId) : undefined;
      if (existing) {
        const replay = this.hydrate(existing);
        if (replay.idempotency?.inputHash !== idempotency.inputHash) {
          throw new LiveProcurementError(409, "idempotency key was already used for a different procurement request");
        }
        // An exact replay is also the user's recovery authority for this one
        // purchase. Recovery is bound to the persisted payment tx/agreement
        // and contains no payment path, so it can never spend twice.
        if (recoverablePayment(replay)) {
          return { job: this.recover(replay.id), replayed: true };
        }
        return { job: structuredClone(replay), replayed: true };
      }
    }
    const readiness = this.readiness(input.profileId, "paymentRail" in input ? input.paymentRail : "pay-dem");
    if (!readiness.executable) throw new LiveProcurementError(503, `procurement profile is unavailable: ${readiness.reasons.join("; ")}`);
    this.assertQueueCapacity();
    const nowMs = Date.now();
    this.starts = this.starts.filter((started) => nowMs - started < 60 * 60_000);
    // Each start spends real DEM (~13 with anchors), so the public demo stays
    // rate-limited — but generously enough that a testing session isn't
    // blocked. Operators can tune it without a code change.
    const hourlyLimit = Math.max(1, Number(process.env.DACS_PROCUREMENT_HOURLY_LIMIT) || 6);
    if (this.starts.length >= hourlyLimit) throw new LiveProcurementError(503, "live procurement hourly demo limit reached; try again later");
    beforeCreate?.();
    const now = new Date().toISOString();
    const job: ProcurementJob = {
      id: randomUUID(),
      profileId: input.profileId,
      negotiationMode: procurementProfile(input.profileId)!.mode,
      status: "running", phase: "queued", createdAt: now, updatedAt: now,
      events: [
        { phase: "queued", label: `${procurementProfile(input.profileId)!.title} queued`, at: now },
        ...("paymentRail" in input && input.paymentRail === "pay-x402" && this.procurementX402
          ? [{
              phase: "queued" as const,
              label: this.procurementX402.governance.status === "operator-provisional"
                ? "x402 rail selected under the disclosed operator-provisional trust profile"
                : "x402 rail selected under the normative PA-2 trust profile",
              at: now,
            }]
          : []),
      ],
      queue: { status: "waiting", enqueuedAt: now },
      ...(idempotency ? { idempotency } : {}),
    };
    this.persist(job);
    this.jobs.set(job.id, job);
    if (idempotency) this.jobsByIdempotencyKey.set(idempotency.keyHash, job.id);
    this.starts.push(nowMs);
    this.enqueue({
      job,
      execute: () => this.run(job, input),
      fail: (error) => {
        job.status = "failed";
        job.error = (error as Error).message;
        job.failedBeforePayment = !paymentMayHaveBroadcast(job);
        if (job.sessionRecord && job.sessionRecord.state !== "finalised") {
          const endedAt = Date.now();
          job.sessionRecord.state = "aborted-by-self";
          job.sessionRecord.lastUpdatedAt = endedAt;
          job.sessionRecord.endedAt = endedAt;
        }
        this.push(job, "failed", `Stopped safely: ${(error as Error).message}`);
      },
    });
    return { job: structuredClone(job), replayed: false };
  }

  /**
   * Resume an already-paid failed job. This path cannot negotiate, broadcast a
   * payment, or create a second agreement: it is bound to the persisted
   * agreement hash, payment tx and original Butler client id.
   */
  recover(id: string): ProcurementJob {
    const job = this.jobs.get(id);
    if (!job) throw new LiveProcurementError(404, "procurement job not found");
    const payment = recoverablePayment(job);
    if (!payment) {
      if (job.status === "failed" && job.sessionRecord?.state === "aborted-by-self") {
        throw new LiveProcurementError(409, "failed job has no broadcast payment to recover");
      }
      throw new LiveProcurementError(409, "only a terminally aborted paid procurement job can be recovered");
    }
    this.assertQueueCapacity();
    const abort = [...job.events].reverse().find((event) => event.label === "Buyer attestation bundle anchored" && event.anchorRef);
    const previousRecovery = job.recovery;
    const now = new Date().toISOString();
    job.recovery = {
      status: "running",
      startedAt: now,
      updatedAt: now,
      // A transport-level recovery retry must not replace the original paid-job
      // failure or its terminal abort evidence with the prior retry's error.
      originalError: previousRecovery?.originalError ?? job.error ?? "unknown failure",
      ...(previousRecovery?.originalAbortAnchor || abort?.anchorRef
        ? { originalAbortAnchor: previousRecovery?.originalAbortAnchor ?? abort?.anchorRef }
        : {}),
      ...(previousRecovery?.originalAbortTxRef || abort?.txRef
        ? { originalAbortTxRef: previousRecovery?.originalAbortTxRef ?? abort?.txRef }
        : {}),
    };
    job.status = "running";
    delete job.error;
    if (job.finalisation) {
      job.finalisation.status = "running";
      job.finalisation.updatedAt = now;
      job.finalisation.attempts += 1;
      delete job.finalisation.lastError;
    }
    job.queue = { status: "waiting", enqueuedAt: now };
    this.push(job, "recovering", "Recovering the paid agreement without negotiating or paying again", { txRef: payment.txRef });
    this.enqueue({
      job,
      execute: () => this.runRecovery(job, payment.txRef!),
      fail: (error) => {
        job.status = "failed";
        job.error = `Recovery failed: ${(error as Error).message}`;
        job.failedBeforePayment = false;
        if (job.finalisation) {
          job.finalisation.status = "failed";
          job.finalisation.updatedAt = new Date().toISOString();
          job.finalisation.lastError = job.error;
        }
        if (job.recovery) {
          job.recovery.status = "failed";
          job.recovery.updatedAt = new Date().toISOString();
        }
        this.push(job, "failed", job.error);
        this.scheduleDurableFinalisationRetry(job, error);
      },
    });
    return structuredClone(job);
  }

  /**
   * Retry only availability failures. Correctness failures (signature,
   * canonical bundle, payment or reconciliation mismatches) remain terminal.
   * State is persisted as running before the timer so a process restart can
   * pick the same payment-free recovery back up.
   */
  private scheduleDurableFinalisationRetry(job: ProcurementJob, error: unknown): void {
    if (!durableFinalisationEnabled()
      || !job.finalisation
      || job.preview === undefined
      || job.finalisation.attempts >= 3
      || !transientFinalisationFailure(error)
      || !recoverablePayment(job)) return;
    job.finalisation.status = "running";
    job.finalisation.updatedAt = new Date().toISOString();
    job.finalisation.lastError = error instanceof Error ? error.message : String(error);
    this.persist(job);
    const timer = setTimeout(() => {
      if (job.status !== "failed" || job.finalisation?.status !== "running") return;
      try {
        this.recover(job.id);
      } catch (retryError) {
        job.finalisation.status = "failed";
        job.finalisation.updatedAt = new Date().toISOString();
        job.finalisation.lastError = retryError instanceof Error ? retryError.message : String(retryError);
        this.persist(job);
      }
    }, 5_000);
    timer.unref?.();
  }

  /** Maximum jobs waiting behind the one active buyer wallet operation. */
  private queueLimit(): number {
    const configured = Number(process.env.DACS_PROCUREMENT_QUEUE_LIMIT);
    return Number.isSafeInteger(configured) && configured >= 0 ? configured : 3;
  }

  private assertQueueCapacity(): void {
    const willWait = this.activeJobId !== undefined || this.pending.length > 0;
    const limit = this.queueLimit();
    if (willWait && this.pending.length >= limit) {
      throw new LiveProcurementError(503, `live procurement queue is full (${limit} waiting); retry later with the same idempotency key`);
    }
  }

  private enqueue(item: PendingProcurement): void {
    this.pending.push(item);
    this.refreshQueuePositions();
    this.pumpQueue();
  }

  private refreshQueuePositions(): void {
    for (let index = 0; index < this.pending.length; index += 1) {
      const job = this.pending[index]!.job;
      if (!job.queue) job.queue = { status: "waiting", enqueuedAt: job.createdAt };
      job.queue.status = "waiting";
      job.queue.position = index + 1;
      this.persist(job);
    }
  }

  private pumpQueue(): void {
    if (this.activeJobId) return;
    const item = this.pending.shift();
    if (!item) return;
    this.activeJobId = item.job.id;
    const startedAt = new Date().toISOString();
    const enqueuedAtMs = Date.parse(item.job.queue?.enqueuedAt ?? item.job.createdAt);
    item.job.queue = {
      status: "active",
      enqueuedAt: item.job.queue?.enqueuedAt ?? item.job.createdAt,
      startedAt,
      waitMs: Math.max(0, Date.parse(startedAt) - enqueuedAtMs),
    };
    this.push(item.job, item.job.phase, item.job.queue.waitMs > 0
      ? `Procurement lane started after ${item.job.queue.waitMs}ms in queue`
      : "Procurement lane started");
    this.refreshQueuePositions();
    void item.execute().catch(item.fail).finally(() => {
      const finishedAt = new Date().toISOString();
      if (item.job.queue) {
        item.job.queue.status = "finished";
        item.job.queue.finishedAt = finishedAt;
      }
      this.persist(item.job);
      if (this.activeJobId === item.job.id) this.activeJobId = undefined;
      this.pumpQueue();
    });
  }

  get(id: string): ProcurementJob {
    const job = this.jobs.get(id);
    if (!job) throw new LiveProcurementError(404, "procurement job not found");
    return structuredClone(this.hydrate(job));
  }

  /** Re-read an archived job's full body from disk; the slim entry is the fallback. */
  private hydrate(job: ProcurementJob): ProcurementJob {
    if (!this.archived.has(job.id)) return job;
    try {
      const full = JSON.parse(readFileSync(join(this.jobsDir, `${job.id}.json`), "utf8")) as ProcurementJob;
      if (full?.id === job.id) return full;
    } catch { /* disk record unreadable — serve the slim entry */ }
    return job;
  }

  /** Only previously completed, two-sided and reconciled Auditor bundles count as history. */
  private securityAuditHistoryFor(sellerDid: string): SecurityResearcherHistory {
    const verified: Array<{ at: number; bundleRef: string }> = [];
    for (const stored of this.jobs.values()) {
      const job = this.hydrate(stored);
      if (job.status !== "complete" || job.profileId !== "security-audit-rfq" || !job.result
        || typeof job.result !== "object" || Array.isArray(job.result)) continue;
      const result = job.result as Record<string, unknown>;
      const parties = result.parties as Record<string, unknown> | undefined;
      const bundleVerification = result.bundleVerification as Record<string, unknown> | undefined;
      const reconciliation = result.reconciliation as Record<string, unknown> | undefined;
      const anchors = result.anchors as Record<string, unknown> | undefined;
      const sellerBundle = anchors?.sellerBundle;
      if (result.status !== "settled-and-accepted"
        || parties?.seller !== sellerDid
        || bundleVerification?.ok !== true
        || reconciliation?.reconciled !== true
        || typeof sellerBundle !== "string"
        || !sellerBundle.startsWith("stor-")) continue;
      verified.push({ at: Date.parse(job.updatedAt), bundleRef: sellerBundle });
    }
    verified.sort((a, b) => b.at - a.at);
    return {
      completedAudits: verified.length,
      ...(verified[0] ? { latestBundleRef: verified[0].bundleRef } : {}),
    };
  }

  private push(job: ProcurementJob, phase: ProcurementPhase, label: string, refs: Partial<ProcurementEvent> = {}): void {
    const at = new Date().toISOString();
    job.phase = phase;
    job.updatedAt = at;
    job.events.push({
      phase, label, at,
      ...(refs.txRef ? { txRef: refs.txRef } : {}),
      ...(refs.anchorRef ? { anchorRef: refs.anchorRef } : {}),
      ...(refs.storageStatus ? { storageStatus: refs.storageStatus } : {}),
      ...(refs.expectedBlock === undefined ? {} : { expectedBlock: refs.expectedBlock }),
      ...(refs.actualBlock === undefined ? {} : { actualBlock: refs.actualBlock }),
      ...(refs.blockDelta === undefined ? {} : { blockDelta: refs.blockDelta }),
      ...(refs.broadcastAt ? { broadcastAt: refs.broadcastAt } : {}),
      ...(refs.confirmedAt ? { confirmedAt: refs.confirmedAt } : {}),
      ...(refs.inclusionMs === undefined ? {} : { inclusionMs: refs.inclusionMs }),
      ...(refs.nonce === undefined ? {} : { nonce: refs.nonce }),
    });
    this.persist(job);
  }

  private persist(job: ProcurementJob): void {
    const path = join(this.jobsDir, `${job.id}.json`);
    const temporary = `${path}.${process.pid}.tmp`;
    writeFileSync(temporary, `${JSON.stringify(job, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
    chmodSync(temporary, 0o600);
    renameSync(temporary, path);
  }

  private updateSession(
    job: ProcurementJob,
    state: SessionState,
    phaseEntries: SessionRecord["phaseResults"] = [],
    terminal = false,
  ): void {
    if (!job.sessionRecord) return;
    const lastUpdatedAt = Date.now();
    job.sessionRecord.phaseResults.push(...phaseEntries);
    job.sessionRecord.state = state;
    job.sessionRecord.lastUpdatedAt = lastUpdatedAt;
    if (terminal) job.sessionRecord.endedAt = lastUpdatedAt;
    this.persist(job);
  }

  private async runRecovery(job: ProcurementJob, paymentTx: string): Promise<void> {
    const session = job.sessionRecord;
    if (!session) throw new Error("recovery session record is missing");
    const profileId = job.profileId ?? "security-audit-rfq";
    const fixed = profileId === "oracle-auto-accept" || profileId === "dd-live-fixed" || profileId === "sponsored-post-live";
    const oracle = profileId === "oracle-auto-accept";
    const sponsored = profileId === "sponsored-post-live";
    const serviceId = oracle ? ORACLE_SERVICE_ID : sponsored ? SPONSORED_POST_SERVICE_ID : fixed ? DD_SERVICE_ID : AUDIT_NEGOTIATOR_SERVICE_ID;
    const sellerName = oracle ? "Oracle" : sponsored ? "Sponsored Post Agent" : fixed ? "DD Researcher" : "Auditor";
    const configuredSellerDid = fixed
      ? (oracle ? process.env.DACS_ORACLE_DID : sponsored ? process.env.DACS_SPONSORED_POST_DID : process.env.DACS_DD_DID)?.trim()
      : process.env.DACS_AUDITOR_DID?.trim();
    const sellerClientId = fixed
      ? ((oracle ? process.env.DACS_ORACLE_CLIENT_ID : sponsored ? process.env.DACS_SPONSORED_POST_CLIENT_ID : process.env.DACS_DD_CLIENT_ID)?.trim()
        || (oracle ? "dacs-oracle-fixed" : sponsored ? "dacs-sponsored-post" : "dacs-dd-fixed"))
      : (process.env.DACS_AUDITOR_CLIENT_ID ?? "dacs-auditor");
    const listingAnchorRef = verifiedListingAnchor(job.events);
    if (!listingAnchorRef) throw new Error("recovery listing anchor is missing");
    const commitmentPhase = session.phaseResults.find((phase) => phase.step.kind === "commit-agreement");
    const agreementPhase = session.phaseResults.find((phase) => phase.step.kind === (fixed ? "negotiate-fixed-price" : "negotiate-rfq"));
    const context = commitmentPhase?.contextDelta;
    const agreementRef = context?.agreementRef as AttestationRef | undefined;
    const commitmentRef = context?.commitmentRef as AttestationRef | undefined;
    const committedAt = Number(context?.committedAt);
    const agreementAnchorTxRef = typeof context?.agreementAnchorTxRef === "string"
      ? context.agreementAnchorTxRef
      : (job.events.find((event) => event.anchorRef === agreementRef?.anchor.locator && event.txRef)?.txRef ?? "");
    const anchorTxRef = typeof context?.anchorTxRef === "string" ? context.anchorTxRef : "";
    const commitmentBlockNumber = context?.blockNumber === undefined ? undefined : Number(context.blockNumber);
    const agreementHash = typeof agreementPhase?.contextDelta.agreementHash === "string"
      ? agreementPhase.contextDelta.agreementHash
      : "";
    if (agreementRef?.anchor.kind !== "storage-program" || commitmentRef?.anchor.kind !== "storage-program"
      || !Number.isSafeInteger(committedAt) || committedAt < 0 || !agreementAnchorTxRef || !anchorTxRef || !/^[0-9a-f]{64}$/i.test(agreementHash)
      || (commitmentBlockNumber !== undefined && (!Number.isSafeInteger(commitmentBlockNumber) || commitmentBlockNumber < 0))) {
      throw new Error("recovery agreement or commitment references are incomplete");
    }

    const buyerPath = keyFile("DACS_PROCUREMENT_BUYER_KEY_FILE", "procurement-buyer.key", ".l1-buyer-key")!;
    const buyerMnemonic = readFileSync(buyerPath, "utf8").trim();
    this.push(job, "connecting", "Reconnecting the original Butler buyer identity for paid-job recovery");
    const buyer = await connectIdentity("Public Procurement Buyer", RPC, buyerMnemonic);
    const recoveryAnchors: AnchorTx[] = [];
    const buyerSub = new LiveSubstrate(buyer.adapter, (record) => {
      recoveryAnchors.push({ kind: "anchor", owner: "buyer", ...record });
    });
    const buyerAgent = new BuyerAdapter(buyer, buyerSub);
    const verifier = new VerifierAdapter(buyerSub);
    const discovered = await buyerAgent.discoverStandard([listingAnchorRef]);
    const listing = discovered[0]?.listing;
    if (!listing || listing.listingId !== serviceId || listing.seller.identity.presentedBy !== configuredSellerDid) {
      throw new Error(`recovery ${sellerName} listing no longer verifies`);
    }

    const [agreementRaw, commitmentRaw] = await Promise.all([
      buyerSub.read(agreementRef.anchor.locator),
      buyerSub.read(commitmentRef.anchor.locator),
    ]);
    if (!agreementRaw || !isStandardAgreement(agreementRaw) || standardHash(agreementRaw) !== agreementHash) {
      throw new Error("recovery agreement is absent or does not match the paid agreement hash");
    }
    if (!commitmentRaw || standardHash(commitmentRaw) !== commitmentRef.contentHash) {
      throw new Error("recovery commitment is absent or content-mismatched");
    }
    const agreement = agreementRaw as AgreementDocument;
    const commitment = commitmentRaw as unknown as CommitmentRecord;
    if (agreement.jobId !== session.jobId) throw new Error("recovery agreement job id does not match the failed session");
    const standardCommit = {
      agreementRef,
      agreementAnchorTxRef,
      commitment,
      commitmentRef,
      anchorTxRef,
      committedAt,
      ...(commitmentBlockNumber === undefined ? {} : { commitmentBlockNumber }),
    };

    const seed = Buffer.concat([
      createHash("sha512").update("dacs-butler-l2ps-v1\x00").update(buyerMnemonic).digest(),
      createHash("sha512").update("dacs-butler-l2ps-v1\x01").update(buyerMnemonic).digest(),
    ]);
    const l2Identity = await initIdentity(seed);
    const messaging = new MessagingPeer({
      serverUrl: process.env.SERVER_URL ?? "ws://demosnode.discus.sh:3005",
      // The seller's anti-replay record binds the settlement to this exact id.
      clientId: `dacs-butler-${job.id.slice(0, 8)}`,
      publicKey: l2Identity.mlkemPublicKey,
    });
    const rfq = new RfqBuyerClient(
      messaging,
      l2Identity,
      sellerClientId,
      primaryClaimSigner(buyer.did, buyer.sign),
      {
        party: { primaryClaim: buyer.did, sign: buyer.sign },
        sub: buyerSub,
        listing,
        listingAnchorRef,
      },
    );
    const recoveryBundleName = Buffer.from(
      `dacs5:recovery:${session.jobId}:buyer:paid-delivery-v1`,
      "utf8",
    ).toString("base64url");
    let autoAcceptCommitment: AutoAcceptCommitment | undefined;
    if (oracle) {
      const autoRef = process.env.DACS_ORACLE_AUTO_ACCEPT_REF!.trim();
      const autoRaw = await buyerSub.read(autoRef);
      if (!autoRaw) throw new Error("recovery Oracle AutoAcceptCommitment is not read-visible");
      autoAcceptCommitment = autoRaw as unknown as AutoAcceptCommitment;
    }
    this.push(job, "recovering", `Requesting delivery against the ${sellerName}'s persisted settlement`, { txRef: paymentTx });
    await rfq.connect();
    let recovered: Awaited<ReturnType<typeof rfq.recoverStandard>>;
    try {
      recovered = await rfq.recoverStandard({
        agreement,
        agreementHash,
        txHash: paymentTx,
        standardCommit,
        buyerBundleAnchorName: recoveryBundleName,
        ...(autoAcceptCommitment ? { autoAcceptCommitment } : {}),
      });
    } finally {
      rfq.close();
    }

    const deliveryRef = recovered.delivery.deliveryRef;
    const deliveryEvidenceRef = recovered.delivery.deliveryEvidenceRef;
    if (!deliveryEvidenceRef) throw new Error("recovered delivery omitted its Standard evidence reference");
    this.push(job, "delivering", `${sellerName} delivered the signed, content-bound result`, { anchorRef: deliveryRef });
    this.push(job, "verifying", `${sellerName} anchored successful delivery evidence`, { anchorRef: deliveryEvidenceRef.anchor.locator });
    this.push(job, "verifying", "Buyer anchored the original payment evidence without paying again", {
      anchorRef: recovered.completion.paymentEvidenceRef.anchor.locator,
    });
    this.push(job, "verifying", `Buyer and ${sellerName} signed reconciliable completion bundles`);

    const deliveryVerification = await verifier.verifyDelivery(session.jobId, {
      serviceId,
      sellerDid: listing.seller.identity.presentedBy,
      attestation: recovered.delivery.attestation,
      observeDelivered: oracle ? oracleObserveDelivered()
        : sponsored ? sponsoredPostObserveDelivered(process.env.DACS_SPONSORED_POST_X_HANDLE)
        : fixed ? ddObserveDelivered()
        : secAuditObserveDelivered(listing.seller.identity.presentedBy),
    });
    const buyerBundle = recovered.completion.bundle;
    const sellerBundle = recovered.completion.sellerBundle;
    const buyerBundleVerification = await verifyBundle(buyerBundle, { expectedRole: "buyer", ...cryptoDeps });
    const sellerBundleVerification = await verifyBundle(sellerBundle, { expectedRole: "seller", ...cryptoDeps });
    const reconciliation = {
      reconciled: buyerBundleVerification.ok && sellerBundleVerification.ok && sameCanonicalBundle(buyerBundle, sellerBundle),
      reason: buyerBundleVerification.reason ?? sellerBundleVerification.reason,
    };
    const parsedReport = readReportMeta(recovered.delivery.attestation as unknown as DeliveryAttestation);
    if (!parsedReport.ok) throw new Error(`recovered ${sellerName} deliverable could not be decoded: ${parsedReport.reason}`);
    if (!deliveryVerification.ok || !reconciliation.reconciled) {
      throw new Error(`recovered DACS verification failed (delivery=${deliveryVerification.ok}, reconciled=${reconciliation.reconciled})`);
    }

    let evaluation: Record<string, unknown> | undefined;
    if (!fixed) {
      this.push(job, "evaluating", "EvalBot applying the acceptance rubric to the recovered report");
      const rubric = rubricForOutcome({ serviceId: AUDIT_NEGOTIATOR_SERVICE_ID });
      const ruling = await new EvalBot({ useLlm: false }).evaluate({
        jobId: `${session.jobId}-recovery-eval`, rubric, deliverable: { content: JSON.stringify(parsedReport.artifact) },
      });
      const rulingValid = verifyRuling(ruling, undefined, rubric).valid;
      const accepted = rulingValid && ruling.verdict === "accept";
      if (!accepted) throw new Error(`EvalBot rejected the recovered report (${rulingValid}/${ruling.verdict})`);
      evaluation = { ruling, rulingValid, accepted };
    }

    job.result = {
      kind: "dacs-paid-job-recovery-report",
      status: "recovered-after-terminal-abort",
      jobId: session.jobId,
      originalFailure: {
        error: job.recovery?.originalError,
        sessionState: session.state,
        abortBundle: job.recovery?.originalAbortAnchor,
        abortTxRef: job.recovery?.originalAbortTxRef,
      },
      settlement: {
        rail: "pay-dem",
        txHash: paymentTx,
        blockNumber: Number(recovered.settlement.blockNumber),
        amount: agreement.terms.price,
        paidAgain: false,
      },
      anchors: {
        listing: listingAnchorRef,
        agreement: agreementRef.anchor.locator,
        commitment: commitmentRef.anchor.locator,
        delivery: deliveryRef,
        deliveryEvidence: deliveryEvidenceRef.anchor.locator,
        paymentEvidence: recovered.completion.paymentEvidenceRef.anchor.locator,
        buyerRecoveryBundle: recovered.completion.buyerBundleRef,
        sellerBundle: recovered.completion.sellerBundleRef,
        originalAbortBundle: job.recovery?.originalAbortAnchor,
      },
      transactions: [
        { kind: "payment", owner: "buyer", name: "original pay-dem settlement", txRef: paymentTx },
        ...recoveryAnchors,
      ],
      profileId,
      delivery: { verified: deliveryVerification.ok, report: parsedReport.artifact },
      ...(evaluation ? { evaluation } : {}),
      bundleVerification: {
        ok: buyerBundleVerification.ok && sellerBundleVerification.ok,
        buyer: buyerBundleVerification,
        seller: sellerBundleVerification,
      },
      reconciliation,
      historicalSessionPreserved: true,
      parties: { buyer: buyer.did, seller: listing.seller.identity.presentedBy },
    };
    job.status = "complete";
    if (job.finalisation) {
      job.finalisation.status = "complete";
      job.finalisation.updatedAt = new Date().toISOString();
      delete job.finalisation.lastError;
    }
    delete job.preview;
    if (job.recovery) {
      job.recovery.status = "complete";
      job.recovery.updatedAt = new Date().toISOString();
    }
    this.push(job, "complete", "Paid job recovered: report delivered and verified; original abort record preserved");
  }

  private async runFixed(job: ProcurementJob, input: OracleStartInput | DdFixedStartInput | SponsoredPostStartInput): Promise<void> {
    const oracle = input.profileId === "oracle-auto-accept";
    const sponsored = input.profileId === "sponsored-post-live";
    const x402 = input.paymentRail === "pay-x402";
    const label = oracle ? "Oracle" : sponsored ? "Sponsored Post Agent" : "DD Researcher";
    const deliveryServiceId = oracle ? ORACLE_SERVICE_ID : sponsored ? SPONSORED_POST_SERVICE_ID : DD_SERVICE_ID;
    const listingServiceId = oracle
      ? (x402 ? ORACLE_X402_SERVICE_ID : ORACLE_SERVICE_ID)
      : sponsored
        ? (x402 ? SPONSORED_POST_X402_SERVICE_ID : SPONSORED_POST_SERVICE_ID)
        : (x402 ? DD_X402_SERVICE_ID : DD_SERVICE_ID);
    const listingRef = (oracle
      ? process.env[x402 ? "DACS_ORACLE_X402_LISTING_REF" : "DACS_ORACLE_LISTING_REF"]
      : sponsored
        ? process.env[x402 ? "DACS_SPONSORED_POST_X402_LISTING_REF" : "DACS_SPONSORED_POST_LISTING_REF"]
        : process.env[x402 ? "DACS_DD_X402_LISTING_REF" : "DACS_DD_LISTING_REF"])!.trim();
    const configuredDid = (oracle ? process.env.DACS_ORACLE_DID : sponsored ? process.env.DACS_SPONSORED_POST_DID : process.env.DACS_DD_DID)!.trim();
    const sellerClientId = (oracle ? process.env.DACS_ORACLE_CLIENT_ID : sponsored ? process.env.DACS_SPONSORED_POST_CLIENT_ID : process.env.DACS_DD_CLIENT_ID)?.trim()
      || (oracle ? "dacs-oracle-fixed" : sponsored ? "dacs-sponsored-post" : "dacs-dd-fixed");
    const requestScope = oracle
      ? oracleProtocolRequest(input as OracleStartInput)
      : sponsored
        ? { text: input.text }
        : { kind: input.kind, subject: input.subject };
    const buyerPath = keyFile("DACS_PROCUREMENT_BUYER_KEY_FILE", "procurement-buyer.key", ".l1-buyer-key")!;
    const buyerMnemonic = readFileSync(buyerPath, "utf8").trim();
    this.push(job, "connecting", `Connecting the Butler buyer wallet to the ${label}`);
    const buyer = await connectIdentity("Public Procurement Buyer", RPC, buyerMnemonic);
    const buyerWallet = wallet(buyer);
    const buyerBefore = BigInt((await buyerWallet.getAddressInfo(buyer.address))?.balance ?? 0n);
    if (buyerBefore < 8n * OS_PER_DEM) throw new Error("procurement buyer needs at least 8 DEM for payment and DACS anchors");

    const anchorTransactions: AnchorTx[] = [];
    const buyerSub = new LiveSubstrate(buyer.adapter, (record) => {
      anchorTransactions.push({ kind: "anchor", owner: "buyer", ...record });
      this.push(job, job.phase, "Buyer DACS artifact confirmed on chain", {
        txRef: record.txRef,
        anchorRef: record.address,
        storageStatus: record.storageStatus,
        expectedBlock: record.expectedConfirmationBlock,
        actualBlock: record.blockNumber,
        blockDelta: record.confirmationBlockDelta,
        inclusionMs: record.inclusionLatencyMs,
        nonce: record.nonce,
      });
    }, {}, (record) => {
      this.push(job, job.phase, record.storageStatus === "visible"
        ? "Indexer can now read the confirmed DACS artifact"
        : "Confirmed DACS artifact is still syncing to the Indexer", {
        txRef: record.txRef, anchorRef: record.address, storageStatus: record.storageStatus,
      });
    });
    const buyerAgent = new BuyerAdapter(buyer, buyerSub);
    const verifier = new VerifierAdapter(buyerSub);
    this.push(job, "discovering", `Resolving and verifying the ${label}'s signed DACS-1 listing`);
    const listing = (await buyerAgent.discoverStandard([listingRef]))[0]?.listing as Listing | undefined;
    if (!listing || listing.listingId !== listingServiceId || listing.seller.identity.presentedBy !== configuredDid
      || !listing.pipeline.some((phase) => phase.kind === "negotiate-fixed-price")) {
      throw new Error(`${label} listing failed identity, service, or fixed-price verification`);
    }
    if (x402) {
      await verifyX402IdentityBinding(listing.seller.identity, x402ListingTerms(listing.acceptedRails?.[0]).payTo);
    }
    this.push(job, "discovering", `Verified the ${label} listing from chain`, { anchorRef: listingRef });
    let autoAcceptCommitment: AutoAcceptCommitment | undefined;
    let autoAcceptCommitmentRef: string | undefined;
    if (oracle) {
      autoAcceptCommitmentRef = process.env[x402 ? "DACS_ORACLE_X402_AUTO_ACCEPT_REF" : "DACS_ORACLE_AUTO_ACCEPT_REF"]!.trim();
      const raw = await buyerSub.read(autoAcceptCommitmentRef);
      if (!raw) throw new Error("Oracle AutoAcceptCommitment is not read-visible");
      autoAcceptCommitment = raw as unknown as AutoAcceptCommitment;
      this.push(job, "discovering", "Verified the bounded Oracle auto-accept template", { anchorRef: autoAcceptCommitmentRef });
    }

    this.push(job, "selecting", `Butler selected the posted ${listing.pricing.kind === "fixed" ? listing.pricing.price.amount : ""} ${x402 ? "USDC on Base Sepolia" : "DEM"} ${label} offer`);
    const jobId = `web-${oracle ? "oracle" : sponsored ? "sponsored-post" : "dd"}-${job.id}`;
    const channelId = `fixed-${job.id}`;
    const seed = Buffer.concat([
      createHash("sha512").update("dacs-butler-l2ps-v1\x00").update(buyerMnemonic).digest(),
      createHash("sha512").update("dacs-butler-l2ps-v1\x01").update(buyerMnemonic).digest(),
    ]);
    const l2Identity = await initIdentity(seed);
    const messaging = new MessagingPeer({
      serverUrl: process.env.SERVER_URL ?? "ws://demosnode.discus.sh:3005",
      clientId: `dacs-butler-${job.id.slice(0, 8)}`,
      publicKey: l2Identity.mlkemPublicKey,
    });
    const buyerIdentityMetadata = x402 ? await this.procurementX402!.identityMetadata(buyer.did) : undefined;
    const fixedClient = new RfqBuyerClient(
      messaging,
      l2Identity,
      sellerClientId,
      primaryClaimSigner(buyer.did, buyer.sign),
      {
        party: { primaryClaim: buyer.did, sign: buyer.sign },
        sub: buyerSub,
        listing,
        listingAnchorRef: listingRef,
        ...(buyerIdentityMetadata ? { identityMetadata: buyerIdentityMetadata } : {}),
      },
    );
    await fixedClient.connect();
    this.push(job, "selecting", `Opened an authenticated fixed-price channel with ${label}`);
    const startedAt = Date.now();
    let deal: Awaited<ReturnType<typeof fixedClient.negotiateFixed>>;
    try {
      deal = await fixedClient.negotiateFixed({
        channelId,
        jobId,
        requestScope,
        ...(x402 ? { x402Payer: this.procurementX402!.buyerAddress } : {}),
        ...(autoAcceptCommitment ? { autoAcceptCommitment } : {}),
        ...(autoAcceptCommitmentRef ? { autoAcceptCommitmentRef } : {}),
      });
    } catch (error) {
      fixedClient.close();
      throw error;
    }
    const phaseIndex = (kind: string): number => {
      const index = listing.pipeline.findIndex((phase) => phase.kind === kind);
      if (index < 0) throw new Error(`${label} listing omitted ${kind}`);
      return index;
    };
    const phaseEntry = (kind: string, invokedAt: number, result: SessionRecord["phaseResults"][number]["result"], contextDelta: Record<string, unknown> = result.contextDelta ?? {}): SessionRecord["phaseResults"][number] => ({
      index: phaseIndex(kind), step: structuredClone(listing.pipeline[phaseIndex(kind)]!), invokedAt,
      result: { ...result, ...(Object.keys(contextDelta).length ? { contextDelta } : {}) }, contextDelta,
    });
    job.sessionRecord = {
      recordVersion: "1",
      jobId,
      state: "commit-completed",
      listingRef: standardListingRef(listing),
      parties: deal.agreement.parties,
      pipeline: structuredClone(listing.pipeline),
      phaseResults: [
        phaseEntry("vet-credentials", startedAt, { ok: true, attestationRef: deal.identity.buyer.vetRecordRef }, {
          buyerVetRecordRef: deal.identity.buyer.vetRecordRef, sellerVetRecordRef: deal.identity.seller.vetRecordRef,
        }),
        phaseEntry("negotiate-fixed-price", startedAt, { ok: true }, { agreementHash: deal.agreementHash }),
        phaseEntry("commit-agreement", Date.now(), { ok: true, attestationRef: deal.standardCommit.commitmentRef }, {
          agreementRef: deal.standardCommit.agreementRef,
          agreementAnchorTxRef: deal.standardCommit.agreementAnchorTxRef,
          commitmentRef: deal.standardCommit.commitmentRef,
          committedAt: deal.standardCommit.committedAt,
          anchorTxRef: deal.standardCommit.anchorTxRef,
          ...(deal.standardCommit.commitmentBlockNumber === undefined ? {} : { blockNumber: deal.standardCommit.commitmentBlockNumber }),
        }),
      ],
      startedAt,
      lastUpdatedAt: Date.now(),
      recipeRegistryVersion: 1,
      railRegistryVersion: 1,
    };
    this.persist(job);
    this.push(job, "agreeing", `${oracle ? "Auto-accepted" : "Live-co-signed"} request-bound agreement committed before payment`, {
      anchorRef: deal.standardCommit.commitmentRef.anchor.locator,
    });

    let settlementTx = "";
    let paymentNonce: number | undefined;
    let completed = false;
    try {
      await Promise.all([
        confirmVettedParty(buyerSub, deal.identity.buyer),
        confirmVettedParty(buyerSub, deal.identity.seller),
      ]);
      this.push(job, "agreeing", "Both accepted DACS-2 Vet records reached consensus before payment");
      this.push(job, "settling", `Paying ${deal.terms.price.amount} ${x402 ? "USDC on Base Sepolia via x402" : "DEM"} to ${label}`);
      this.updateSession(job, "settle-pending");
      const settleAt = Date.now();
      let settlement: Awaited<ReturnType<typeof deal.settle>>;
      if (x402) {
        const paid = await this.procurementX402!.pay(deal.agreement);
        settlementTx = String(paid.txHash ?? "");
        this.push(job, "settling", "x402 facilitator settled USDC on Base Sepolia", { txRef: settlementTx });
        settlement = await deal.settle(settlementTx, undefined, {
          kind: "x402",
          paymentReceiptHash: String(paid.paymentReceiptHash ?? ""),
        });
      } else {
        const paymentAttempt = await broadcastNativePayment(buyerWallet, buyer.address, deal.payTo, BigInt(deal.amountOs), {
          ...(deal.standardCommit.commitmentNonce === undefined ? {} : { nonce: deal.standardCommit.commitmentNonce + 1 }),
          ...nativePaymentCanaryOptions(),
          onBroadcast: (receipt) => this.push(job, "settling", "Payment broadcast on Demos", {
            txRef: receipt.txHash,
            expectedBlock: receipt.expectedBlock,
            nonce: receipt.nonce,
          }),
        });
        settlementTx = paymentAttempt.txHash;
        paymentNonce = paymentAttempt.nonce;
        buyerSub.noteExternalNonce?.(paymentNonce);
        settlement = await deal.settle(settlementTx, undefined, paymentAttempt.blockNumber === undefined ? undefined : {
          transactionContent: paymentAttempt.transactionContent,
          blockNumber: paymentAttempt.blockNumber,
        });
      }
      this.push(job, "settling", `${x402 ? "Seller independently verified the Base USDC receipt" : "Payment reached confirmed inclusion"}`, { txRef: settlementTx, actualBlock: Number(settlement.blockNumber) });
      const payment = await deal.anchorPaymentEvidence(settlement);
      this.push(job, "settling", "Confirmed payment evidence anchored before delivery", { anchorRef: payment.paymentEvidenceRef.anchor.locator, txRef: payment.paymentEvidenceReceipt?.txRef });
      this.push(job, "delivering", `${label} verified payment evidence and is producing the requested deliverable`);
      const delivery = await deal.requestDelivery(payment);
      const deliveryVerification = await verifier.verifyDelivery(jobId, {
        serviceId: deliveryServiceId,
        sellerDid: configuredDid,
        attestation: delivery.attestation,
        observeDelivered: oracle ? oracleObserveDelivered()
          : sponsored ? sponsoredPostObserveDelivered(process.env.DACS_SPONSORED_POST_X_HANDLE)
          : ddObserveDelivered(),
      });
      const artifact = readReportMeta(delivery.attestation as unknown as DeliveryAttestation);
      if (!deliveryVerification.ok || !artifact.ok) throw new Error(`${label} delivery failed offline signature/source verification`);
      job.preview = {
        kind: "dacs-procurement-delivery-preview", status: "delivery-verified-finalising-dacs5", jobId,
        delivery: { verified: true, report: artifact.artifact },
        anchors: { listing: listingRef, agreement: deal.standardCommit.agreementRef.anchor.locator, commitment: deal.standardCommit.commitmentRef.anchor.locator, paymentEvidence: payment.paymentEvidenceRef.anchor.locator, delivery: delivery.deliveryRef, deliveryEvidence: delivery.deliveryEvidenceRef?.anchor.locator },
      };
      const finalisationAt = new Date().toISOString();
      job.finalisation = {
        status: "running",
        startedAt: finalisationAt,
        updatedAt: finalisationAt,
        attempts: 1,
      };
      this.push(job, "delivering", "Verified deliverable ready; final DACS-5 copies are anchoring", { anchorRef: delivery.deliveryRef });
      const completion = await deal.completeStandard(settlement, delivery, payment);
      completed = true;
      const buyerBundleVerification = await verifyBundle(completion.bundle, { expectedRole: "buyer", ...cryptoDeps });
      const sellerBundleVerification = await verifyBundle(completion.sellerBundle, { expectedRole: "seller", ...cryptoDeps });
      const reconciled = buyerBundleVerification.ok && sellerBundleVerification.ok
        && sameCanonicalBundle(completion.bundle, completion.sellerBundle);
      if (!reconciled) throw new Error("fixed-price DACS-5 copies did not verify and reconcile");
      this.updateSession(job, "settle-pending", [
        phaseEntry(x402 ? "pay-x402" : "pay-dem", settleAt, { ok: true, txRefs: completion.paymentEvidence.paymentTxRefs, attestationRef: completion.paymentEvidenceRef }),
        phaseEntry("deliver-attested-payload", settleAt, { ok: true, attestationRef: delivery.deliveryEvidenceRef! }),
      ]);
      this.updateSession(job, "settle-completed");
      this.updateSession(job, "finalised", [], true);
      const buyerAfter = BigInt((await buyerWallet.getAddressInfo(buyer.address))?.balance ?? 0n);
      job.result = {
        kind: "dacs-full-procurement-report",
        status: "settled-and-accepted",
        jobId,
        profileId: input.profileId,
        request: requestScope,
        negotiation: { protocol: "dacs-fixed/1", mode: oracle ? "auto-accept" : "live-cosign", agreementHash: deal.agreementHash, terms: deal.terms },
        settlement: {
          rail: input.paymentRail,
          amount: deal.terms.price,
          amountOs: deal.amountOs,
          txHash: settlementTx,
          chainId: x402 ? "eip155:84532" : "demos",
          payer: x402 ? this.procurementX402!.buyerAddress : buyer.address,
          payee: deal.payTo,
          ...(x402 ? { railGovernance: this.procurementX402!.governance } : {}),
        },
        anchors: {
          listing: listingRef,
          ...(autoAcceptCommitmentRef ? { autoAcceptCommitment: autoAcceptCommitmentRef } : {}),
          agreement: deal.standardCommit.agreementRef.anchor.locator,
          commitment: deal.standardCommit.commitmentRef.anchor.locator,
          paymentEvidence: completion.paymentEvidenceRef.anchor.locator,
          delivery: delivery.deliveryRef,
          deliveryEvidence: delivery.deliveryEvidenceRef!.anchor.locator,
          buyerBundle: completion.buyerBundleRef,
          sellerBundle: completion.sellerBundleRef,
        },
        transactions: [...anchorTransactions, { kind: "payment", owner: "buyer", name: `${input.paymentRail} settlement`, txRef: settlementTx, ...(paymentNonce === undefined ? {} : { nonce: paymentNonce }) }],
        delivery: { verified: true, report: artifact.artifact },
        bundleVerification: { ok: true, buyer: buyerBundleVerification, seller: sellerBundleVerification },
        reconciliation: { reconciled: true },
        balances: { buyer: { beforeOs: buyerBefore.toString(), afterOs: buyerAfter.toString() } },
        parties: { buyer: buyer.did, seller: configuredDid },
      };
      job.finalisation.status = "complete";
      job.finalisation.updatedAt = new Date().toISOString();
      delete job.preview;
      job.status = "complete";
      this.push(job, "complete", `${label} purchase settled, delivered, and fully reconciled`);
    } catch (error) {
      const message = (error as Error).message.replace(/^(?:Auditor|Seller) /, `${label} `);
      if (job.finalisation?.status === "running") {
        job.finalisation.status = "failed";
        job.finalisation.updatedAt = new Date().toISOString();
        job.finalisation.lastError = message;
      }
      if (!completed) await deal.abortStandard(message, job.phase === "settling" ? (x402 ? "pay-x402" : "pay-dem") : "deliver-attested-payload").catch(() => undefined);
      throw new Error(message, { cause: error });
    } finally {
      deal.close();
    }
  }

  protected async run(job: ProcurementJob, input: StartInput): Promise<void> {
    if (input.profileId === "oracle-auto-accept" || input.profileId === "dd-live-fixed" || input.profileId === "sponsored-post-live") {
      return this.runFixed(job, input);
    }
    if (input.profileId !== "security-audit-rfq") {
      // parseProcurementInput currently keeps unprovisioned profiles out. This
      // guard is the final fail-closed boundary if catalog status is changed
      // without installing a matching production executor.
      throw new Error(`no production executor installed for ${input.profileId}`);
    }
    const x402 = input.paymentRail === "pay-x402";
    const buyerPath = keyFile("DACS_PROCUREMENT_BUYER_KEY_FILE", "procurement-buyer.key", ".l1-buyer-key")!;
    const buyerMnemonic = readFileSync(buyerPath, "utf8").trim();
    this.push(job, "connecting", "Connecting the Butler buyer wallet and live L2PS transport");
    const buyer = await connectIdentity("Public Procurement Buyer", RPC, buyerMnemonic);
    const buyerWallet = wallet(buyer);
    const buyerBefore = BigInt((await buyerWallet.getAddressInfo(buyer.address))?.balance ?? 0n);
    if (buyerBefore < 8n * OS_PER_DEM) throw new Error("procurement buyer needs at least 8 DEM for payment and DACS anchors");

    const anchorTransactions: AnchorTx[] = [];
    const observeAnchor = (record: import("../../src/live/substrate.js").AnchorObservation) => {
      anchorTransactions.push({ kind: "anchor", owner: "buyer", ...record });
      let logicalName = record.name;
      try {
        const decoded = Buffer.from(record.name, "base64url").toString("utf8");
        if (decoded.startsWith("dacs")) logicalName = decoded;
      } catch { /* legacy anchor name */ }
      const label = logicalName.startsWith("dacs1:") ? "Seller listing anchored"
        : logicalName.startsWith("dacs2:") ? "Identity Vet record anchored"
        : logicalName.startsWith("dacs3:agreement") ? "Buyer/seller agreement anchored"
        : logicalName.startsWith("dacs3:commit") ? "Commitment anchored before payment"
        : logicalName.startsWith("dacs4:") ? "Settlement evidence anchored"
        : logicalName.startsWith("dacsx:") ? "Security report hash anchored"
        : logicalName.includes(":seller:") ? "Seller bundle anchored"
        : logicalName.startsWith("dacs5:") ? "Buyer attestation bundle anchored"
        : "DACS artifact anchored";
      this.push(job, job.phase, label, {
        txRef: record.txRef,
        anchorRef: record.address,
        storageStatus: record.storageStatus,
        expectedBlock: record.expectedConfirmationBlock,
        actualBlock: record.blockNumber,
        blockDelta: record.confirmationBlockDelta,
        broadcastAt: record.broadcastAt === undefined ? undefined : new Date(record.broadcastAt).toISOString(),
        confirmedAt: record.confirmedAt === undefined ? undefined : new Date(record.confirmedAt).toISOString(),
        inclusionMs: record.inclusionLatencyMs,
        nonce: record.nonce,
      });
    };
    const observeVisibility = (record: import("../../src/live/substrate.js").AnchorObservation) => {
      const transaction = anchorTransactions.find((candidate) => candidate.txRef === record.txRef);
      if (transaction) transaction.storageStatus = record.storageStatus;
      this.push(
        job,
        job.phase,
        record.storageStatus === "visible" ? "Indexer can now read the confirmed DACS artifact" : "Confirmed DACS artifact is still syncing to the Indexer",
        { txRef: record.txRef, anchorRef: record.address, storageStatus: record.storageStatus },
      );
    };
    const observeSellerReceipt = (name: string, label: string, receipt?: AnchorReceipt) => {
      if (!receipt) return;
      anchorTransactions.push({
        kind: "anchor",
        owner: "seller",
        name,
        address: receipt.address,
        txRef: receipt.txRef,
        storageStatus: "confirmed",
        expectedConfirmationBlock: receipt.expectedConfirmationBlock,
        blockNumber: receipt.blockNumber,
        confirmationBlockDelta: receipt.confirmationBlockDelta,
        broadcastAt: receipt.broadcastAt,
        confirmedAt: receipt.confirmedAt,
        inclusionLatencyMs: receipt.inclusionLatencyMs,
        nonce: receipt.nonce,
      });
      this.push(job, job.phase, label, {
        txRef: receipt.txRef,
        anchorRef: receipt.address,
        storageStatus: "confirmed",
        expectedBlock: receipt.expectedConfirmationBlock,
        actualBlock: receipt.blockNumber,
        blockDelta: receipt.confirmationBlockDelta,
        broadcastAt: receipt.broadcastAt === undefined ? undefined : new Date(receipt.broadcastAt).toISOString(),
        confirmedAt: receipt.confirmedAt === undefined ? undefined : new Date(receipt.confirmedAt).toISOString(),
        inclusionMs: receipt.inclusionLatencyMs,
        nonce: receipt.nonce,
      });
    };
    const buyerSub = new LiveSubstrate(buyer.adapter, observeAnchor, {}, observeVisibility);
    const buyerAgent = new BuyerAdapter(buyer, buyerSub);
    const verifier = new VerifierAdapter(buyerSub);
    const bridge = new DacsButlerBuyer(buyerAgent, verifier, buyerSub);

    this.push(job, "discovering", "Resolving the indexed Auditor's signed DACS-1 listing from chain");
    const configuredAuditorDid = process.env.DACS_AUDITOR_DID?.trim();
    if (!configuredAuditorDid) throw new LiveProcurementError(503, "DACS_AUDITOR_DID is not configured");
    // Demos native addresses include write-time/deployer inputs. DACS-1
    // therefore requires discovery through the published logical→native index
    // binding; it must not be guessed from the logical address alone.
    // The caller-supplied ref is a HINT from the discovery surface; the
    // gateway independently verifies it and, when it fails (e.g. the index
    // still binds a legacy-profile anchor), falls back to its own configured
    // binding rather than failing the run. All of this is pre-payment and
    // each attempt is reported in the event stream.
    const configuredListingRef = process.env[x402 ? "DACS_AUDITOR_X402_LISTING_REF" : "DACS_AUDITOR_LISTING_REF"]?.trim();
    const listingServiceId = x402 ? AUDIT_NEGOTIATOR_X402_SERVICE_ID : AUDIT_NEGOTIATOR_SERVICE_ID;
    const candidateRefs = [...new Set([input.auditorListingRef, configuredListingRef]
      .filter((ref): ref is string => typeof ref === "string" && /^stor-[0-9a-f]{40,}$/i.test(ref)))];
    if (candidateRefs.length === 0) {
      throw new LiveProcurementError(503, "the DACS index has not supplied a valid Auditor listing binding");
    }
    let listing: Awaited<ReturnType<typeof buyerAgent.discoverStandard>>[number]["listing"] | undefined;
    let listingRef = candidateRefs[0]!;
    for (const candidate of candidateRefs) {
      const resolved = (await buyerAgent.discoverStandard([candidate]).catch(() => []))[0]?.listing;
      if (resolved && resolved.listingId === listingServiceId && resolved.seller.identity.presentedBy === configuredAuditorDid && resolved.pipeline.some((step) => step.kind === "negotiate-rfq")) {
        listing = resolved;
        listingRef = candidate;
        break;
      }
      this.push(job, "discovering", `Listing at ${candidate.slice(0, 16)}… failed current-standard verification — trying the gateway's configured binding`);
    }
    if (!listing) {
      throw new Error("the indexed audit-negotiator listing could not be verified from chain");
    }
    if (x402) {
      await verifyX402IdentityBinding(listing.seller.identity, x402ListingTerms(listing.acceptedRails?.[0]).payTo);
    }
    const auditorDid = listing.seller.identity.presentedBy;
    const configuredResearcherGithub = (process.env.DACS_AUDITOR_RESEARCHER_GITHUB ?? "").trim().replace(/^@/, "").toLowerCase();
    const listedResearcher = securityResearcherProfileFromListing(listing);
    if (!listedResearcher || listedResearcher.github !== configuredResearcherGithub) {
      throw new Error("the Auditor listing's signed researcher identity does not match gateway configuration");
    }
    this.push(job, "discovering", listingRef === input.auditorListingRef ? "Verified the Auditor listing advertised by the indexer" : "Verified the Auditor listing from the gateway's configured binding", { anchorRef: listingRef });
    const centerPrice = listing.pricing.kind === "negotiable" ? Number(listing.pricing.bandCenter.amount)
      : listing.pricing.kind === "fixed" ? Number(listing.pricing.price.amount) : input.budgetDem;
    const discovered = await bridge.discoverStandardOffers([{
      ref: listingRef,
      scope: "parameterized",
      fee: { kind: "fixed", price: centerPrice },
      negotiable: true,
      // No verified DACS-5 history is available yet. Zero observations is
      // honest and prevents demo placeholder reputation influencing selection.
      quality: { rating: 0, completedJobs: 0, disputeRate: 0 },
    }]);
    if (discovered.length !== 1) throw new Error("the anchored Auditor listing could not be mapped for selection");
    const offers: DacsOffer[] = discovered;

    this.push(job, "selecting", "Butler scoring the verified listing against budget, capability, quality and rail");
    const goal: ProcurementGoal = {
      description: input.goal,
      requiredCapabilities: [listingServiceId],
      estimatedUnits: input.files.length,
    };
    const decision: ProcurementDecision = await bridge.procure(goal, input.budgetDem, offers);
    if (decision.outcome !== "awarded" || !decision.winner || decision.winner.listingId !== listingRef) {
      throw new Error(`Butler returned ${decision.outcome}; no eligible Auditor purchase was awarded`);
    }

    const jobId = `web-auditor-${job.id}`;
    const sessionStartedAt = Date.now();
    const channelId = `rfq-${job.id}`;
    const seed = Buffer.concat([
      createHash("sha512").update("dacs-butler-l2ps-v1\x00").update(buyerMnemonic).digest(),
      createHash("sha512").update("dacs-butler-l2ps-v1\x01").update(buyerMnemonic).digest(),
    ]);
    const l2Identity = await initIdentity(seed);
    const messaging = new MessagingPeer({
      serverUrl: process.env.SERVER_URL ?? "ws://demosnode.discus.sh:3005",
      clientId: `dacs-butler-${job.id.slice(0, 8)}`,
      publicKey: l2Identity.mlkemPublicKey,
    });
    const buyerIdentityMetadata = x402 ? await this.procurementX402!.identityMetadata(buyer.did) : undefined;
    const cci = new LiveCci(buyer.adapter);
    const rfq = new RfqBuyerClient(
      messaging,
      l2Identity,
      process.env.DACS_AUDITOR_CLIENT_ID ?? "dacs-auditor",
      primaryClaimSigner(buyer.did, buyer.sign),
      {
        party: { primaryClaim: buyer.did, sign: buyer.sign },
        sub: buyerSub,
        listing,
        listingAnchorRef: listingRef,
        ...(buyerIdentityMetadata ? { identityMetadata: buyerIdentityMetadata } : {}),
        securityResearcherVet: {
          githubLoginFor: (did) => cci.githubLoginFor(did),
          historyFor: async (did) => this.securityAuditHistoryFor(did),
        },
      },
    );
    await rfq.connect();
    this.push(job, "selecting", "Butler opened a signed RFQ channel with dacs-auditor");
    const deal = await rfq.negotiate({
      channelId, jobId, repo: `posted/${job.id}`, files: input.files,
      budgetDem: input.budgetDem, preferredTier: "quick", acceptableTiers: ["quick"], maxTurns: 6,
      ...(x402 ? { x402Payer: this.procurementX402!.buyerAddress } : {}),
    });
    if (!deal.identity || !deal.standardCommit) throw new Error("the public RFQ did not produce the Standard identity, Vet, agreement and commitment artifacts");
    const researcherProfile = securityResearcherProfileFromListing(listing);
    const researcherVet = researcherProfile
      ? securityResearcherVetEvidence(deal.identity.seller.vetRecord, researcherProfile)
      : null;
    if (!researcherVet) throw new Error("the Auditor DACS-2 researcher Vet evidence is incomplete");
    this.push(
      job,
      "selecting",
      `Verified Auditor key control and CCI GitHub @${researcherVet.profile.github}; ${researcherVet.history.completedAudits} prior reconciled DACS-5 audit${researcherVet.history.completedAudits === 1 ? "" : "s"}`,
      { anchorRef: deal.identity.seller.vetRecordRef.anchor.locator },
    );
    const phaseIndex = (kind: string): number => {
      const index = listing.pipeline.findIndex((step) => step.kind === kind);
      if (index < 0) throw new Error(`the Auditor listing omitted ${kind}`);
      return index;
    };
    const phaseEntry = (
      kind: string,
      invokedAt: number,
      result: SessionRecord["phaseResults"][number]["result"],
      contextDelta: Record<string, unknown> = result.contextDelta ?? {},
    ): SessionRecord["phaseResults"][number] => {
      const index = phaseIndex(kind);
      return {
        index,
        step: structuredClone(listing.pipeline[index]!),
        invokedAt,
        result: { ...result, ...(Object.keys(contextDelta).length > 0 ? { contextDelta } : {}) },
        contextDelta,
      };
    };
    const recordedAt = Date.now();
    const buyerBundleHash = standardHash(deal.identity.buyer.bundle, ["presentation"]);
    const sellerBundleHash = standardHash(deal.identity.seller.bundle, ["presentation"]);
    job.sessionRecord = {
      recordVersion: "1",
      jobId,
      state: "commit-completed",
      listingRef: standardListingRef(listing),
      parties: [
        { role: "buyer", bundleHash: buyerBundleHash, primaryClaim: buyer.did, vetRecordRef: deal.identity.buyer.vetRecordRef },
        { role: "seller", bundleHash: sellerBundleHash, primaryClaim: auditorDid, vetRecordRef: deal.identity.seller.vetRecordRef },
      ],
      pipeline: structuredClone(listing.pipeline),
      phaseResults: [
        phaseEntry("vet-credentials", sessionStartedAt, { ok: true, attestationRef: deal.identity.buyer.vetRecordRef }, {
          buyerVetRecordRef: deal.identity.buyer.vetRecordRef,
          sellerVetRecordRef: deal.identity.seller.vetRecordRef,
        }),
        phaseEntry("negotiate-rfq", sessionStartedAt, { ok: true }, { agreementHash: deal.agreementHash }),
        phaseEntry("commit-agreement", recordedAt, { ok: true, attestationRef: deal.standardCommit.commitmentRef }, {
          agreementRef: deal.standardCommit.agreementRef,
          agreementAnchorTxRef: deal.standardCommit.agreementAnchorTxRef,
          commitmentRef: deal.standardCommit.commitmentRef,
          committedAt: deal.standardCommit.committedAt,
          anchorTxRef: deal.standardCommit.anchorTxRef,
          ...(deal.standardCommit.commitmentBlockNumber === undefined ? {} : { blockNumber: deal.standardCommit.commitmentBlockNumber }),
        }),
      ],
      startedAt: sessionStartedAt,
      lastUpdatedAt: recordedAt,
      recipeRegistryVersion: 1,
      railRegistryVersion: 1,
    };
    this.persist(job);
    decision.winner.price = deal.terms.price;
    decision.winner.negotiated = true;
    decision.winner.agreedTerms = deal.terms;
    const chosen = decision.candidates.find((candidate) => candidate.listingId === listingRef);
    if (chosen) chosen.askPrice = deal.terms.price;
    decision.negotiations.push({
      listingId: listingRef, ask: deal.terms.price, reservation: input.budgetDem,
      rounds: [], result: "agreed", agreedPrice: deal.terms.price,
      rfq: { result: "agreed", terms: deal.terms, reason: deal.negotiation.reason, rounds: deal.negotiation.turns },
    });
    this.push(job, "agreeing", `Buyer and Auditor agreed ${deal.terms.tier}/${deal.terms.deadline} at ${deal.terms.price} ${x402 ? "USDC" : "DEM"}`);

    this.push(job, "agreeing", "Dual-signed agreement and commitment anchored before payment", {
      anchorRef: deal.standardCommit.commitmentRef.anchor.locator,
    });
    let settlementTx = "";
    // Kept in the outer lifecycle scope because the completed response is
    // assembled after the settlement/delivery try block. A block-scoped const
    // here previously let the paid DACS session finalise and then crashed the
    // gateway while formatting job.result (`paymentNonce is not defined`).
    let paymentNonce: number | undefined;
    let paymentTelemetry: { expectedBlock?: number; actualBlock?: number; blockDelta?: number } = {};
    let settlement: Awaited<ReturnType<typeof deal.settle>>;
    let delivery: Awaited<ReturnType<typeof deal.requestDelivery>>;
    let paymentEvidence: Awaited<ReturnType<typeof deal.anchorPaymentEvidence>>;
    let standardCompletion: Awaited<ReturnType<typeof deal.completeStandard>>;
    let deliveryVerification: Awaited<ReturnType<typeof verifier.verifyDelivery>>;
    let parsedReport: ReturnType<typeof readReportMeta>;
    let completedBundlesAnchored = false;
    try {
      if (!deal.identity) throw new Error("Auditor deal omitted its DACS-2 identity evidence");
      await Promise.all([
        confirmVettedParty(buyerSub, deal.identity.buyer),
        confirmVettedParty(buyerSub, deal.identity.seller),
      ]);
      this.push(job, "agreeing", "Both accepted DACS-2 Vet records reached consensus before payment");
      this.push(job, "settling", `Paying ${deal.terms.price} ${x402 ? "USDC on Base Sepolia via x402" : "DEM"} to the negotiated Auditor`);
      this.updateSession(job, "settle-pending");
      const settleInvokedAt = Date.now();
      if (x402) {
        const paid = await this.procurementX402!.pay(deal.agreement as AgreementDocument);
        settlementTx = String(paid.txHash ?? "");
        this.push(job, "settling", "x402 facilitator settled USDC on Base Sepolia", { txRef: settlementTx });
        settlement = await deal.settle(settlementTx, undefined, {
          kind: "x402",
          paymentReceiptHash: String(paid.paymentReceiptHash ?? ""),
        });
        this.push(job, "settling", "Auditor independently verified the Base USDC receipt", {
          txRef: settlementTx,
          actualBlock: Number(settlement.blockNumber),
        });
      } else {
        const paymentAttempt = await broadcastNativePayment(buyerWallet, buyer.address, deal.payTo, BigInt(deal.amountOs), {
          ...(deal.standardCommit?.commitmentNonce === undefined ? {} : { nonce: deal.standardCommit.commitmentNonce + 1 }),
          ...nativePaymentCanaryOptions(),
          onBroadcast: (receipt) => this.push(job, "settling", "Payment broadcast on Demos", {
            txRef: receipt.txHash,
            expectedBlock: receipt.expectedBlock,
            nonce: receipt.nonce,
          }),
        });
        settlementTx = paymentAttempt.txHash;
        paymentNonce = paymentAttempt.nonce;
        buyerSub.noteExternalNonce?.(paymentNonce);
        const expectedPaymentBlock = paymentAttempt.expectedBlock;
        this.push(job, "settling", "Auditor is verifying the confirmed payment");
        settlement = await deal.settle(settlementTx, undefined, paymentAttempt.blockNumber === undefined ? undefined : {
          transactionContent: paymentAttempt.transactionContent,
          blockNumber: paymentAttempt.blockNumber,
        });
        const actualPaymentBlock = Number(settlement.blockNumber);
        paymentTelemetry = {
          ...(expectedPaymentBlock === undefined ? {} : { expectedBlock: expectedPaymentBlock }),
          actualBlock: actualPaymentBlock,
          ...(expectedPaymentBlock === undefined ? {} : { blockDelta: actualPaymentBlock - expectedPaymentBlock }),
        };
        this.push(job, "settling", "Payment reached confirmed inclusion", {
          txRef: settlementTx,
          expectedBlock: expectedPaymentBlock,
          actualBlock: actualPaymentBlock,
          blockDelta: expectedPaymentBlock === undefined ? undefined : actualPaymentBlock - expectedPaymentBlock,
        });
      }
      this.push(job, "settling", `Buyer is anchoring ${x402 ? "x402" : "native-payment"} evidence before delivery`);
      paymentEvidence = await deal.anchorPaymentEvidence(settlement);
      this.push(job, "settling", "Payment evidence anchored on Demos", {
        txRef: paymentEvidence.paymentEvidenceReceipt?.txRef,
        anchorRef: paymentEvidence.paymentEvidenceRef.anchor.locator,
      });
      this.push(job, "delivering", "Auditor verified the on-chain payment evidence and is scanning the posted source");
      delivery = await deal.requestDelivery(paymentEvidence);
      observeSellerReceipt("dacsx:delivery", "Auditor delivery attestation confirmed on chain", delivery.anchorReceipt);
      observeSellerReceipt("dacs4:evidence:deliver-attested-payload", "Auditor delivery evidence confirmed on chain", delivery.deliveryEvidenceReceipt);
      deliveryVerification = await verifier.verifyDelivery(jobId, {
        serviceId: AUDIT_NEGOTIATOR_SERVICE_ID,
        sellerDid: auditorDid,
        attestation: delivery.attestation,
        observeDelivered: secAuditObserveDelivered(auditorDid),
      });
      parsedReport = readReportMeta(delivery.attestation as unknown as DeliveryAttestation);
      if (!deliveryVerification.ok) throw new Error("the delivered security report failed signature/content verification");
      if (!parsedReport.ok) throw new Error(`verified security report could not be decoded: ${parsedReport.reason}`);
      job.preview = {
        kind: "dacs-procurement-delivery-preview",
        status: "report-verified-finalising-dacs5",
        jobId,
        delivery: { verified: true, report: parsedReport.artifact },
        anchors: {
          listing: listingRef,
          agreement: deal.standardCommit.agreementRef.anchor.locator,
          commitment: deal.standardCommit.commitmentRef.anchor.locator,
          paymentEvidence: paymentEvidence.paymentEvidenceRef.anchor.locator,
          delivery: delivery.deliveryRef,
          deliveryEvidence: delivery.deliveryEvidenceRef?.anchor.locator,
        },
      };
      const finalisationAt = new Date().toISOString();
      job.finalisation = {
        status: "running",
        startedAt: finalisationAt,
        updatedAt: finalisationAt,
        attempts: 1,
      };
      this.push(job, "delivering", "Verified report ready; both parties are anchoring their final DACS-5 copies", { anchorRef: delivery.deliveryRef });
      this.push(job, "verifying", "Buyer and Auditor are anchoring the two mandatory completion bundles");
      standardCompletion = await deal.completeStandard(settlement, delivery, paymentEvidence);
      observeSellerReceipt("dacs5:bundle:seller", "Auditor DACS-5 bundle confirmed on chain", standardCompletion.sellerBundleReceipt);
      completedBundlesAnchored = true;
      this.updateSession(job, "settle-pending", [
        phaseEntry(x402 ? "pay-x402" : "pay-dem", settleInvokedAt, {
          ok: true,
          txRefs: standardCompletion.paymentEvidence.paymentTxRefs,
          attestationRef: standardCompletion.paymentEvidenceRef,
        }),
        phaseEntry("deliver-attested-payload", settleInvokedAt, {
          ok: true,
          attestationRef: delivery.deliveryEvidenceRef!,
        }),
      ]);
    } catch (error) {
      if (job.finalisation?.status === "running") {
        job.finalisation.status = "failed";
        job.finalisation.updatedAt = new Date().toISOString();
        job.finalisation.lastError = (error as Error).message;
      }
      if (!completedBundlesAnchored) {
        await deal.abortStandard(
          (error as Error).message,
          job.phase === "settling" ? (x402 ? "pay-x402" : "pay-dem") : "deliver-attested-payload",
        ).catch(() => undefined);
      }
      deal.close();
      throw error;
    }
    deal.close();
    const anchors = {
      listing: listingRef,
      agreement: deal.standardCommit.agreementRef.anchor.locator,
      commitment: deal.standardCommit.commitmentRef.anchor.locator,
      paymentEvidence: standardCompletion.paymentEvidenceRef.anchor.locator,
      deliveryEvidence: delivery.deliveryEvidenceRef!.anchor.locator,
      bundle: standardCompletion.buyerBundleRef,
      delivery: delivery.deliveryRef,
      sellerBundle: standardCompletion.sellerBundleRef,
    };
    const buyerBundle = standardCompletion.bundle;
    const sellerBundle = standardCompletion.sellerBundle;
    const buyerBundleVerification = await verifyBundle(buyerBundle, { expectedRole: "buyer", ...cryptoDeps });
    const sellerBundleVerification = await verifyBundle(sellerBundle, { expectedRole: "seller", ...cryptoDeps });
    const reconciliation = {
      reconciled: buyerBundleVerification.ok && sellerBundleVerification.ok && sameCanonicalBundle(buyerBundle, sellerBundle),
      reason: buyerBundleVerification.reason ?? sellerBundleVerification.reason,
    };
    const bundleVerification = { ok: buyerBundleVerification.ok && sellerBundleVerification.ok, buyer: buyerBundleVerification, seller: sellerBundleVerification };

    if (!deliveryVerification.ok || !bundleVerification.ok || !reconciliation.reconciled) {
      throw new Error(`DACS final verification rejected the deal (delivery=${deliveryVerification.ok}, bundle=${bundleVerification.ok}, reconciled=${reconciliation.reconciled})`);
    }
    this.updateSession(job, "settle-completed");
    this.updateSession(job, "finalised", [], true);

    this.push(job, "evaluating", "EvalBot applying and signing the acceptance rubric");
    const evaluationPolicy = securityAuditEvaluationPolicy(input.files);
    const rubric = evaluationPolicy.rubric;
    const evalbot = new EvalBot({ useLlm: false, predicates: evaluationPolicy.predicates });
    const ruling: EvaluationRuling = await evalbot.evaluate({
      jobId: `${jobId}-eval`, rubric, deliverable: { content: JSON.stringify(parsedReport.artifact) },
    });
    const rulingValid = verifyRuling(ruling, undefined, rubric).valid;
    const accepted = rulingValid && ruling.verdict === "accept";
    if (!accepted) throw new Error(`final verification rejected the deal (delivery=${deliveryVerification.ok}, bundle=${bundleVerification.ok}, reconciled=${reconciliation.reconciled}, ruling=${rulingValid}/${ruling.verdict})`);

    const buyerAfter = BigInt((await buyerWallet.getAddressInfo(buyer.address))?.balance ?? 0n);
    job.result = {
      kind: "dacs-full-procurement-report",
      status: "settled-and-accepted",
      jobId,
      goal: input.goal,
      decision,
      negotiation: {
        protocol: "dacs-rfq/1", channelId, agreementHash: deal.agreementHash,
        terms: deal.terms, sellerSignature: deal.sellerSignature, buyerSignature: deal.buyerSignature,
        transcript: deal.negotiation.transcript,
      },
      settlement: {
        rail: input.paymentRail,
        amount: { amount: String(deal.terms.price), currency: x402 ? "USDC" : "DEM" },
        amountOs: deal.amountOs,
        txHash: settlementTx,
        chainId: x402 ? "eip155:84532" : "demos",
        payer: x402 ? this.procurementX402!.buyerAddress : buyer.address,
        payee: x402 ? x402AgreementTerms(deal.agreement as AgreementDocument).payTo : deal.payTo,
        ...(x402 ? { railGovernance: this.procurementX402!.governance } : {}),
      },
      anchors,
      transactions: [
        ...anchorTransactions,
        { kind: "payment", owner: "buyer", name: `${input.paymentRail} settlement`, txRef: settlementTx, ...(paymentNonce === undefined ? {} : { nonce: paymentNonce }), ...paymentTelemetry },
      ],
      delivery: { verified: deliveryVerification.ok, report: parsedReport.artifact },
      vet: {
        recordRef: deal.identity.seller.vetRecordRef.anchor.locator,
        keyControl: true,
        cciGithub: researcherVet.profile.github,
        completedAudits: researcherVet.history.completedAudits,
        ...(researcherVet.history.latestBundleRef ? { latestBundleRef: researcherVet.history.latestBundleRef } : {}),
      },
      evaluation: { ruling, rulingValid, accepted },
      bundleVerification,
      reconciliation,
      balances: {
        buyer: { beforeOs: buyerBefore.toString(), afterOs: buyerAfter.toString() },
      },
      parties: { buyer: buyer.did, seller: auditorDid },
    };
    job.finalisation!.status = "complete";
    job.finalisation!.updatedAt = new Date().toISOString();
    delete job.preview;
    job.status = "complete";
    this.push(job, "complete", "Purchase settled, report delivered, and full DACS bundle verified");
  }
}
