/** Persistent, multi-session L2PS seller with bound pay-dem settlement. */
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { MailboxChannel, type Channel } from "./channel.js";
import { type MessagingPeerInstance, type PeerIdentity } from "./demosdk.js";
import { decodePayload } from "./live-peer.js";
import {
  agreementHash,
  buildChannelAgreement,
  buildStandardAgreement,
  isStandardAgreement,
  signAgreement,
  signStandardAgreement,
  standardAgreementHash,
  verifyAgreementSignature,
  verifyStandardAgreement,
  type AgreementSignature,
  type ChannelAgreement,
} from "./bind.js";
import { runSide } from "./session.js";
import type { ChannelEnvelope, Signer } from "./wire.js";
import { DEFAULT_ECONOMICS, sellerMaySettle, toolsForScan, type AuditTier, type ScanFacts } from "../audit-negotiator/terms.js";
import { deterministicSeller, sellerGuardFor } from "../audit-negotiator/policies.js";
import { llmSeller, type LlmFn } from "../audit-negotiator/llm-policy.js";
import {
  addAgreementSignature,
  addAutoAcceptInstanceSignature,
  emptyRequirement,
  standardAnchorName,
  standardPaymentAnchorName,
  standardHash,
  attestationRef,
  addBundleSignature,
  listingRef,
  requestScopeHash,
  signSettlementEvidence,
  verifyEvidence,
  verifyAgreement,
  verifyAutoAcceptCommitment,
  verifyBundle,
  verifyCommitment,
  type AgreementDocument,
  type AttestationBundle,
  type AttestationRef,
  type CommitmentRecord,
  type CompositeVerificationRecord,
  type IdentityBundle,
  type Listing,
  type SettlementEvidence,
} from "../dacs/standard-profile.js";
import { baseUnits } from "@kynesyslabs/dacs";
import type { AnchorAcceptance, AnchorReceipt } from "../../src/ports.js";
import type { PaymentInclusionProof, X402SettlementProof } from "../gateway/settlement.js";
import type { VerifiedX402Payment } from "../gateway/x402-verifier.js";
import {
  BASE_SEPOLIA_CHAIN_ID,
  isX402Rail,
  paymentPhaseForAgreement,
  verifyX402IdentityBinding,
  x402AgreementTerms,
  x402ListingTerms,
} from "../dacs/x402-production.js";
import {
  securityResearcherProfileFromListing,
  securityResearcherRequirement,
  verifySecurityResearcherVetRecord,
} from "../dacs/security-researcher-vet.js";
type VetReceipt = AnchorReceipt | AnchorAcceptance;
import {
  presentIdentity,
  sessionNonce,
  verifyAnchoredVet,
  verifyPresentation,
  verifyConfirmedAnchor,
  vetAndAnchor,
  cryptoDeps,
  type StandardSellerSessionContext,
  type VettedParty,
} from "./standard-session.js";

const PROTOCOL = "dacs-rfq/1";
const OS_PER_DEM = 1_000_000_000n;
// Identity exchange includes two independently confirmed DACS-2 writes. The
// Demos pre-broadcast confirmation RPC can consume two 12s retries before a
// validator answers, so the old 30s control-frame deadline could expire even
// when the eventual transaction was included in its expected block.
const IDENTITY_EXCHANGE_TIMEOUT_MS = 90_000;

export interface PaymentVerifier {
  verifyAndReserve(txHash: string, amountOs: bigint, proof?: PaymentInclusionProof): Promise<{ ok: boolean; payer?: string; amountOs?: bigint; blockNumber?: number; reason?: string; retriable?: boolean }>;
}

export async function verifyPaymentWithRetry(
  payments: PaymentVerifier,
  txHash: string,
  amountOs: bigint,
  options: { attempts?: number; delayMs?: number; proof?: PaymentInclusionProof } = {},
): Promise<Awaited<ReturnType<PaymentVerifier["verifyAndReserve"]>>> {
  const attempts = options.attempts ?? 30;
  const delayMs = options.delayMs ?? 1_000;
  let result = await payments.verifyAndReserve(txHash, amountOs, options.proof);
  for (let attempt = 1; !result.ok && result.retriable && attempt < attempts; attempt++) {
    await new Promise((resolve) => setTimeout(resolve, delayMs));
    result = await payments.verifyAndReserve(txHash, amountOs, options.proof);
  }
  return result;
}

interface OpenFrame {
  kind: "dacs-rfq-open";
  protocol: typeof PROTOCOL;
  channelId: string;
  jobId: string;
  buyerSignerId: string;
  repo: string;
  scan: { kloc: number; fileCount: number; hasSolidity: boolean };
  files?: Array<{ path: string; content: string }>;
  maxTurns?: number;
  listingAnchorRef?: string;
  buyerPrimaryClaim?: string;
  sellerNonce?: string;
  x402Payer?: string;
}

interface AcceptedRecord {
  channelId: string;
  buyerClientId: string;
  buyerSignerId: string;
  agreement: ChannelAgreement | AgreementDocument;
  amountOs: string;
  listingAnchorRef?: string;
  repo: string;
  files?: Array<{ path: string; content: string }>;
  /** Exact work request for fixed-price services. */
  params?: Record<string, unknown>;
  standardCommit?: {
    agreementRef: AttestationRef;
    agreementAnchorTxRef: string;
    commitment: CommitmentRecord;
    commitmentRef: AttestationRef;
    anchorTxRef: string;
    committedAt: number;
    commitmentBlockNumber?: number;
    commitmentNonce?: number;
    agreementTransactionContent?: Record<string, unknown>;
    commitmentTransactionContent?: Record<string, unknown>;
    agreementExpectedConfirmationBlock?: number;
    commitmentExpectedConfirmationBlock?: number;
    agreementTransactionContentValueOmitted?: boolean;
    commitmentTransactionContentValueOmitted?: boolean;
  };
}

export interface SellerDeliveryResult {
  deliveryRef: string;
  attestation: Record<string, unknown>;
  result: unknown;
  deliverableContentHash?: string;
  anchorReceipt?: AnchorReceipt;
  /** Signed delivery prepared for a same-wallet ordered SR-2 batch. Never persisted. */
  preparedAnchor?: { name: string; value: Record<string, unknown> };
}

export interface SellerDeliveryInput {
  agreementHash: string;
  agreement: ChannelAgreement | AgreementDocument;
  txHash: string;
  payer?: string;
  amountOs: string;
  repo: string;
  files?: Array<{ path: string; content: string }>;
  params?: Record<string, unknown>;
}

export type SellerDelivery = (input: SellerDeliveryInput) => Promise<SellerDeliveryResult>;
export type SellerFulfil = (jobId: string, buyerDid: string) => Promise<string>;

interface SettledRecord extends AcceptedRecord {
  txHash: string;
  payer?: string;
  paidAmountOs: string;
  blockNumber?: number;
  logIndex?: number;
  paymentReceiptHash?: string;
  delivery?: SellerDeliveryResult;
  deliveryEvidence?: SettlementEvidence;
  deliveryEvidenceRef?: AttestationRef;
  deliveryEvidenceReceipt?: AnchorReceipt;
  sellerBundleRef?: string;
  sellerBundle?: AttestationBundle;
  sellerBundleReceipt?: AnchorReceipt;
}

interface State {
  offered: Record<string, AcceptedRecord>;
  accepted: Record<string, AcceptedRecord>;
  settledAgreementHashes: string[];
  settledTxHashes: string[];
  settled: Record<string, SettledRecord>;
  usedChannelIds: string[];
}

const EMPTY_STATE: State = { offered: {}, accepted: {}, settledAgreementHashes: [], settledTxHashes: [], settled: {}, usedChannelIds: [] };

/** Small durable anti-replay/pending-agreement store; writes are atomic rename-over. */
export class SellerStateStore {
  private state: State;

  constructor(private readonly path: string) {
    try {
      const parsed = JSON.parse(readFileSync(path, "utf8")) as Partial<State>;
      this.state = {
        offered: parsed.offered ?? {},
        accepted: parsed.accepted ?? {},
        settledAgreementHashes: parsed.settledAgreementHashes ?? [],
        settledTxHashes: parsed.settledTxHashes ?? [],
        settled: parsed.settled ?? {},
        usedChannelIds: parsed.usedChannelIds ?? [],
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") this.state = structuredClone(EMPTY_STATE);
      else throw new Error("seller state is unreadable or invalid; refusing to lose anti-replay history");
    }
  }

  getAccepted(hash: string): AcceptedRecord | undefined { return this.state.accepted[hash]; }
  getOffered(hash: string): AcceptedRecord | undefined { return this.state.offered[hash]; }
  hasSettledAgreement(hash: string): boolean { return this.state.settledAgreementHashes.includes(hash); }
  hasSettledTx(txHash: string): boolean { return this.state.settledTxHashes.includes(normalizeTx(txHash)); }
  getSettled(hash: string): SettledRecord | undefined { return this.state.settled[hash]; }
  hasUsedChannel(channelId: string): boolean { return this.state.usedChannelIds.includes(channelId); }

  reserveChannel(channelId: string): boolean {
    if (this.hasUsedChannel(channelId)) return false;
    this.state.usedChannelIds.push(channelId);
    this.flush();
    return true;
  }

  offer(hash: string, record: AcceptedRecord): void {
    this.state.offered[hash] = record;
    this.flush();
  }

  accept(hash: string, record: AcceptedRecord): void {
    delete this.state.offered[hash];
    this.state.accepted[hash] = record;
    this.flush();
  }

  settle(hash: string, txHash: string, payer: string | undefined, paidAmountOs: string, blockNumber?: number, paymentReceiptHash?: string, logIndex?: number): SettledRecord {
    const accepted = this.state.accepted[hash];
    if (!accepted) throw new Error("cannot settle an unknown agreement");
    delete this.state.accepted[hash];
    this.state.settledAgreementHashes.push(hash);
    this.state.settledTxHashes.push(normalizeTx(txHash));
    const record: SettledRecord = { ...accepted, txHash: normalizeTx(txHash), payer, paidAmountOs, blockNumber, ...(paymentReceiptHash ? { paymentReceiptHash } : {}), ...(logIndex === undefined ? {} : { logIndex }) };
    this.state.settled[hash] = record;
    this.flush();
    return record;
  }

  delivered(hash: string, delivery: SellerDeliveryResult, evidence?: SettlementEvidence, evidenceRef?: AttestationRef): void {
    const settled = this.state.settled[hash];
    if (!settled) throw new Error("cannot deliver an unsettled agreement");
    settled.delivery = delivery;
    settled.deliveryEvidence = evidence;
    settled.deliveryEvidenceRef = evidenceRef;
    this.flush();
  }

  fulfilled(hash: string, sellerBundleRef: string, sellerBundle?: AttestationBundle, sellerBundleReceipt?: AnchorReceipt): void {
    const settled = this.state.settled[hash];
    if (!settled) throw new Error("cannot fulfil an unsettled agreement");
    settled.sellerBundleRef = sellerBundleRef;
    settled.sellerBundle = sellerBundle;
    settled.sellerBundleReceipt = sellerBundleReceipt;
    this.flush();
  }

  private flush(): void {
    mkdirSync(dirname(this.path), { recursive: true, mode: 0o700 });
    const tmp = `${this.path}.tmp`;
    writeFileSync(tmp, JSON.stringify(this.state, null, 2) + "\n", { mode: 0o600 });
    renameSync(tmp, this.path);
  }
}

class RoutedChannel extends MailboxChannel {
  constructor(private readonly peer: MessagingPeerInstance, private readonly buyerClientId: string) { super(); }
  override async send(env: ChannelEnvelope): Promise<void> {
    if (this.closed) throw new Error("channel closed");
    await this.peer.sendMessage(this.buyerClientId, JSON.stringify(env));
  }
}

interface ActiveSession {
  buyerClientId: string;
  buyerSignerId: string;
  channel: RoutedChannel;
  controlFrames: Array<Record<string, unknown>>;
  controlWaiter?: () => void;
}

interface FixedSession {
  buyerClientId: string;
  buyerSignerId: string;
  channelId: string;
  jobId: string;
  requestScope: Record<string, unknown>;
  x402Payer?: string;
  exchange: StandardExchange;
  expiresAt: number;
}

interface StandardExchange {
  listing: Listing;
  listingAnchorRef: string;
  buyer: VettedParty;
  seller: VettedParty;
}

export class SellerDaemon {
  private readonly sessions = new Map<string, ActiveSession>();
  private readonly fixedSessions = new Map<string, FixedSession>();

  constructor(
    private readonly peer: MessagingPeerInstance,
    private readonly identity: PeerIdentity,
    private readonly payTo: string,
    private readonly payments: PaymentVerifier,
    private readonly store: SellerStateStore,
    private readonly maxSessions = 8,
    private readonly log: (line: string) => void = console.error,
    private readonly llm?: LlmFn,
    private readonly delivery?: SellerDelivery,
    private readonly fulfil?: SellerFulfil,
    private readonly offeredTiers: AuditTier[] = ["quick", "deep"],
    private readonly channelSigner: Signer = identity.signer,
    private readonly standard?: StandardSellerSessionContext,
    private readonly fixedRequestGuard?: (request: Record<string, unknown>) => void | Promise<void>,
    private readonly x402Payments?: { verify(txHash: string, agreement: AgreementDocument): Promise<VerifiedX402Payment> },
  ) {}

  listen(): void {
    // Messaging callbacks are invoked outside an awaitable call chain. A
    // disconnected counterparty can make an error response fail too; contain
    // that rejection here so one abandoned demo session cannot terminate the
    // long-running seller process.
    this.peer.onMessage((message, fromId) => {
      void this.handleMessage(message, fromId).catch((error) => {
        this.log(`[transport] session handler failed: ${(error as Error).message}`);
      });
    });
  }

  async handleMessage(message: unknown, fromId: string): Promise<void> {
    this.pruneFixedSessions();
    const raw = decodePayload(message);
    if (!raw || !safeId(fromId)) return;
    let frame: Record<string, unknown>;
    try { frame = JSON.parse(raw) as Record<string, unknown>; } catch { return; }

    if (isEnvelope(frame)) {
      const active = this.sessions.get(frame.channelId);
      if (active?.buyerClientId === fromId) active.channel.deliver(frame);
      return;
    }

    if ((frame.kind === "dacs-rfq-identify-start" || frame.kind === "dacs-rfq-identify"
      || frame.kind === "dacs-fixed-identify-start" || frame.kind === "dacs-fixed-identify")
      && typeof frame.channelId === "string") {
      const active = this.sessions.get(frame.channelId);
      if (active?.buyerClientId === fromId) {
        active.controlFrames.push(frame);
        active.controlWaiter?.();
        active.controlWaiter = undefined;
      }
      return;
    }

    if (frame.kind === "dacs-rfq-open") return void this.open(frame, fromId);
    if (frame.kind === "dacs-fixed-open") return void this.openFixed(frame, fromId);
    if (frame.kind === "dacs-fixed-sign") return void (await this.signFixed(frame, fromId));
    if (frame.kind === "dacs-rfq-agreement-accept") return void (await this.acceptAgreement(frame, fromId));
    if (frame.kind === "dacs-rfq-settle") return void (await this.settle(frame, fromId));
    if (frame.kind === "dacs-rfq-delivery-request") return void (await this.retryDelivery(frame, fromId));
    if (frame.kind === "dacs-rfq-fulfil") {
      // Fulfilment deliberately continues after the transport handler returns:
      // the seller sends the fully signed canonical bundle first, allowing the
      // buyer and seller to anchor their two required DACS-5 copies in parallel
      // on their independent wallets. Any failure is still returned in-band.
      void this.fulfilBundle(frame, fromId).catch(async (error) => {
        this.log(`[${stringField(frame, "agreementHash")}] fulfilment failed: ${(error as Error).message}`);
        await this.send(fromId, {
          kind: "dacs-rfq-error",
          protocol: PROTOCOL,
          agreementHash: stringField(frame, "agreementHash"),
          code: "fulfilment_failed",
          reason: (error as Error).message,
          retriable: true,
        }).catch(() => undefined);
      });
      return;
    }
  }

  private pruneFixedSessions(now = Date.now()): void {
    for (const [channelId, session] of this.fixedSessions) {
      if (session.expiresAt <= now) this.fixedSessions.delete(channelId);
    }
  }

  /** Open a bounded fixed-price session and perform the same DACS-1/2 exchange as RFQ. */
  private async openFixed(frame: Record<string, unknown>, fromId: string): Promise<void> {
    const channelId = stringField(frame, "channelId");
    const jobId = stringField(frame, "jobId");
    const buyerSignerId = stringField(frame, "buyerSignerId");
    const requestScope = frame.requestScope;
    const listingAnchorRef = stringField(frame, "listingAnchorRef");
    const buyerPrimaryClaim = stringField(frame, "buyerPrimaryClaim");
    const sellerNonce = stringField(frame, "sellerNonce");
    const x402Payer = stringField(frame, "x402Payer") || undefined;
    if (frame.protocol !== "dacs-fixed/1" || !safeId(channelId) || !safeId(jobId)
      || !buyerSignerId || !requestScope || typeof requestScope !== "object" || Array.isArray(requestScope)
      || Buffer.byteLength(JSON.stringify(requestScope), "utf8") > 4_096
      || !listingAnchorRef || !buyerPrimaryClaim || !sellerNonce) {
      return void this.send(fromId, { kind: "dacs-fixed-error", protocol: "dacs-fixed/1", code: "bad_open" });
    }
    if (x402Payer && !/^0x[0-9a-fA-F]{40}$/.test(x402Payer)) {
      return void this.send(fromId, { kind: "dacs-fixed-error", protocol: "dacs-fixed/1", channelId, code: "bad_x402_payer" });
    }
    if (!this.standard) return void this.send(fromId, { kind: "dacs-fixed-error", protocol: "dacs-fixed/1", channelId, code: "standard_unavailable" });
    if (this.sessions.size + this.fixedSessions.size >= this.maxSessions) return void this.send(fromId, { kind: "dacs-fixed-error", protocol: "dacs-fixed/1", channelId, code: "busy" });
    if (this.sessions.has(channelId) || this.fixedSessions.has(channelId) || !this.store.reserveChannel(channelId)) {
      return void this.send(fromId, { kind: "dacs-fixed-error", protocol: "dacs-fixed/1", channelId, code: "duplicate_channel" });
    }
    const channel = new RoutedChannel(this.peer, fromId);
    const active: ActiveSession = { buyerClientId: fromId, buyerSignerId, channel, controlFrames: [] };
    this.sessions.set(channelId, active);
    try {
      const exchange = await this.exchangeIdentity({
        kind: "dacs-rfq-open",
        protocol: PROTOCOL,
        channelId,
        jobId,
        buyerSignerId,
        repo: "fixed-price",
        scan: { kloc: 0, fileCount: 0, hasSolidity: false },
        listingAnchorRef,
        buyerPrimaryClaim,
        sellerNonce,
        ...(x402Payer ? { x402Payer } : {}),
      }, fromId, active, "fixed");
      this.fixedSessions.set(channelId, {
        buyerClientId: fromId,
        buyerSignerId,
        channelId,
        jobId,
        requestScope: structuredClone(requestScope as Record<string, unknown>),
        ...(x402Payer ? { x402Payer } : {}),
        exchange,
        expiresAt: Date.now() + 60_000,
      });
      await this.send(fromId, { kind: "dacs-fixed-ready", protocol: "dacs-fixed/1", channelId });
    } catch (error) {
      this.log(`[${channelId}] fixed-price identify/vet failed: ${(error as Error).message}`);
      await this.send(fromId, { kind: "dacs-fixed-error", protocol: "dacs-fixed/1", channelId, code: "identity_failed", reason: (error as Error).message });
    } finally {
      this.sessions.delete(channelId);
      await channel.close().catch(() => undefined);
    }
  }

  /** Verify the exact buyer-signed scope and add the live/auto seller signature. */
  private async signFixed(frame: Record<string, unknown>, fromId: string): Promise<void> {
    const channelId = stringField(frame, "channelId");
    const pending = this.fixedSessions.get(channelId);
    if (!pending || pending.expiresAt <= Date.now() || pending.buyerClientId !== fromId) {
      return void this.send(fromId, { kind: "dacs-fixed-error", protocol: "dacs-fixed/1", channelId, code: "unknown_session" });
    }
    try {
      if (!this.standard) throw new Error("Standard session context is unavailable");
      await this.fixedRequestGuard?.(pending.requestScope);
      const agreement = frame.agreement as AgreementDocument | undefined;
      const requestHash = stringField(frame, "requestHash");
      if (!agreement || requestHash !== requestScopeHash(pending.requestScope)) throw new Error("request scope hash mismatch");
      if (agreement.jobId !== pending.jobId || agreement.derivedFromPattern !== "fixed-price") throw new Error("fixed agreement session binding mismatch");
      if (agreement.terms.additionalTerms?.requestHash !== requestHash) throw new Error("agreement does not bind the exact request");
      const buyer = agreement.parties.find((party) => party.role === "buyer");
      const seller = agreement.parties.find((party) => party.role === "seller");
      if (buyer?.primaryClaim !== pending.buyerSignerId || seller?.primaryClaim !== this.standard.party.primaryClaim) {
        throw new Error("agreement parties do not match the authenticated channel");
      }
      if (standardHash(buyer.vetRecordRef ?? {}) !== standardHash(pending.exchange.buyer.vetRecordRef)
        || standardHash(seller.vetRecordRef ?? {}) !== standardHash(pending.exchange.seller.vetRecordRef)) {
        throw new Error("agreement Vet bindings do not match this session");
      }
      const published = pending.exchange;
      const buyerVerdict = await verifyAgreement(agreement, published.listing, { ...cryptoDeps, requiredRoles: ["buyer"] });
      if (!buyerVerdict.ok) throw new Error(`buyer agreement rejected: ${buyerVerdict.reason}`);
      if (isX402Rail(agreement.terms.rail)) {
        const terms = x402AgreementTerms(agreement);
        if (!pending.x402Payer || terms.payer.toLowerCase() !== pending.x402Payer.toLowerCase()) {
          throw new Error("agreement x402 payer does not match the authenticated session open");
        }
      } else if (pending.x402Payer) {
        throw new Error("native agreement unexpectedly received an x402 payer");
      }
      let signed: AgreementDocument;
      if (published.listing.terms.acceptanceModel === "auto-accept") {
        const auto = published.autoAcceptCommitment;
        if (!auto || !published.autoAcceptCommitmentRef) throw new Error("seller auto-accept commitment is unavailable");
        const autoVerdict = await verifyAutoAcceptCommitment(auto, published.listing, cryptoDeps);
        if (!autoVerdict.ok) throw new Error(`auto-accept commitment rejected: ${autoVerdict.reason}`);
        signed = await addAutoAcceptInstanceSignature(agreement, auto, this.standard.party);
      } else {
        signed = await addAgreementSignature(agreement, this.standard.party);
      }
      const verdict = await verifyAgreement(signed, published.listing, {
        ...cryptoDeps,
        ...(published.autoAcceptCommitment ? { autoAcceptCommitment: published.autoAcceptCommitment } : {}),
      });
      if (!verdict.ok || !verdict.hash) throw new Error(`seller-signed agreement rejected: ${verdict.reason}`);
      const amountOs = isX402Rail(signed.terms.rail)
        ? x402AgreementTerms(signed).amount
        : baseUnits(signed.terms.price.amount, 9);
      this.store.offer(verdict.hash, {
        channelId,
        buyerClientId: fromId,
        buyerSignerId: pending.buyerSignerId,
        agreement: signed,
        amountOs,
        listingAnchorRef: pending.exchange.listingAnchorRef,
        repo: "fixed-price",
        params: pending.requestScope,
      });
      await this.send(fromId, {
        kind: "dacs-fixed-agreement",
        protocol: "dacs-fixed/1",
        channelId,
        agreement: signed,
        agreementHash: verdict.hash,
        ...paymentRequiredFields(signed, this.payTo, amountOs),
      });
    } catch (error) {
      this.log(`[${channelId}] fixed-price signing failed: ${(error as Error).message}`);
      await this.send(fromId, { kind: "dacs-fixed-error", protocol: "dacs-fixed/1", channelId, code: "agreement_rejected", reason: (error as Error).message });
    } finally {
      this.fixedSessions.delete(channelId);
    }
  }

  private async open(frame: Record<string, unknown>, fromId: string): Promise<void> {
    const parsed = parseOpen(frame);
    if (!parsed) return void this.send(fromId, { kind: "dacs-rfq-error", protocol: PROTOCOL, code: "bad_open" });
    if (this.sessions.size >= this.maxSessions) return void this.send(fromId, { kind: "dacs-rfq-error", protocol: PROTOCOL, channelId: parsed.channelId, code: "busy" });
    if (this.sessions.has(parsed.channelId) || !this.store.reserveChannel(parsed.channelId)) return void this.send(fromId, { kind: "dacs-rfq-error", protocol: PROTOCOL, channelId: parsed.channelId, code: "duplicate_channel" });

    const channel = new RoutedChannel(this.peer, fromId);
    const active: ActiveSession = { buyerClientId: fromId, buyerSignerId: parsed.buyerSignerId, channel, controlFrames: [] };
    this.sessions.set(parsed.channelId, active);
    try {
      const exchange = this.standard ? await this.exchangeIdentity(parsed, fromId, active) : undefined;
      if (!this.standard) {
        await this.send(fromId, {
          kind: "dacs-rfq-hello", protocol: PROTOCOL, channelId: parsed.channelId,
          sellerSignerId: this.channelSigner.id, payTo: this.payTo,
        });
      }
      await this.run(parsed, fromId, channel, exchange);
    } catch (error) {
      this.log(`[${parsed.channelId}] identify/vet failed: ${(error as Error).message}`);
      await this.send(fromId, { kind: "dacs-rfq-error", protocol: PROTOCOL, channelId: parsed.channelId, code: "identity_failed" });
      this.sessions.delete(parsed.channelId);
      await channel.close().catch(() => undefined);
    }
  }

  private async exchangeIdentity(open: OpenFrame, fromId: string, active: ActiveSession, mode: "rfq" | "fixed" = "rfq"): Promise<StandardExchange> {
    if (!this.standard) throw new Error("Standard session context is unavailable");
    if (!open.listingAnchorRef || !open.buyerPrimaryClaim || !open.sellerNonce) throw new Error("open frame omitted Standard identity/listing fields");
    if (open.buyerPrimaryClaim !== open.buyerSignerId) throw new Error("buyer channel signer is not its presented primary claim");
    if (this.standard.party.primaryClaim !== this.channelSigner.id) throw new Error("seller channel signer is not its Standard primary claim");
    if (!sameDemosParty(this.standard.party.primaryClaim, this.payTo)) throw new Error("seller payment address does not match its Standard primary claim");
    const published = await this.standard.getListing(open.listingAnchorRef);
    if (published.listingAnchorRef !== open.listingAnchorRef) throw new Error("buyer selected a different listing anchor");
    if (published.listing.seller.identity.presentedBy !== this.standard.party.primaryClaim) throw new Error("published listing belongs to a different seller");

    const buyerNonce = sessionNonce();
    const sellerBundle = await presentIdentity(this.standard.party, open.sellerNonce, this.standard.identityMetadata);
    await this.send(fromId, {
      kind: mode === "rfq" ? "dacs-rfq-hello" : "dacs-fixed-hello",
      protocol: mode === "rfq" ? PROTOCOL : "dacs-fixed/1",
      channelId: open.channelId,
      sellerSignerId: this.channelSigner.id,
      payTo: this.payTo,
      buyerNonce,
      sellerBundle,
    });
    const identifyStart = await this.takeControl(active, (candidate) => candidate.kind === `dacs-${mode}-identify-start` && candidate.channelId === open.channelId, IDENTITY_EXCHANGE_TIMEOUT_MS);
    const buyerBundle = identifyStart.buyerBundle as IdentityBundle | undefined;
    if (!buyerBundle) throw new Error("identify-start frame omitted the buyer presentation");
    await verifyPresentation(buyerBundle, buyerNonce, open.buyerPrimaryClaim);
    if (isX402Rail(published.listing.acceptedRails?.[0])) {
      if (!open.x402Payer) throw new Error("x402 buyer omitted its linked payer account");
      const terms = x402ListingTerms(published.listing.acceptedRails?.[0]);
      await Promise.all([
        verifyX402IdentityBinding(published.listing.seller.identity, terms.payTo),
        verifyX402IdentityBinding(sellerBundle, terms.payTo),
        verifyX402IdentityBinding(buyerBundle, open.x402Payer),
      ]);
    }
    const buyerVettedPromise = vetAndAnchor(this.standard, open.jobId, buyerBundle, published.listing.buyerRequirement);

    const identify = await this.takeControl(active, (candidate) => candidate.kind === `dacs-${mode}-identify` && candidate.channelId === open.channelId, IDENTITY_EXCHANGE_TIMEOUT_MS);
    const sellerVetRecord = identify.sellerVetRecord as CompositeVerificationRecord | undefined;
    const sellerVetRecordRef = identify.sellerVetRecordRef as AttestationRef | undefined;
    const sellerVetReceipt = identify.sellerVetReceipt as VetReceipt | undefined;
    if (!sellerVetRecord || !sellerVetRecordRef) {
      throw new Error(`identify frame is incomplete (sellerVetRecord=${Boolean(sellerVetRecord)}, sellerVetRecordRef=${Boolean(sellerVetRecordRef)})`);
    }
    const researcherProfile = securityResearcherProfileFromListing(published.listing);
    if (published.listing.listingId.startsWith("audit-negotiator") && !researcherProfile) {
      throw new Error("Auditor listing does not carry a signed security researcher profile");
    }
    const sellerRequirement = researcherProfile
      ? securityResearcherRequirement(researcherProfile)
      : emptyRequirement();
    const [, buyerVetted] = await Promise.all([
      verifyAnchoredVet(this.standard, {
        jobId: open.jobId,
        bundle: sellerBundle,
        requirement: sellerRequirement,
        verifier: open.buyerPrimaryClaim,
        record: sellerVetRecord,
        ref: sellerVetRecordRef,
        receipt: sellerVetReceipt,
        ...(researcherProfile ? {
          verifyRecord: ({ record, jobId, bundle, verifier }) => verifySecurityResearcherVetRecord(record, {
            jobId,
            bundle,
            profile: researcherProfile,
            verifier,
            ...cryptoDeps,
          }),
        } : {}),
      }),
      buyerVettedPromise,
    ]);
    await this.send(fromId, {
      kind: mode === "rfq" ? "dacs-rfq-identified" : "dacs-fixed-identified",
      protocol: mode === "rfq" ? PROTOCOL : "dacs-fixed/1",
      channelId: open.channelId,
      buyerVetRecord: buyerVetted.vetRecord,
      buyerVetRecordRef: buyerVetted.vetRecordRef,
      buyerVetReceipt: buyerVetted.anchorReceipt,
    });
    return {
      ...published,
      buyer: buyerVetted,
      seller: { bundle: sellerBundle, vetRecord: sellerVetRecord, vetRecordRef: sellerVetRecordRef, ...(sellerVetReceipt ? { anchorReceipt: sellerVetReceipt } : {}) },
    };
  }

  private async takeControl(active: ActiveSession, predicate: (frame: Record<string, unknown>) => boolean, timeoutMs: number): Promise<Record<string, unknown>> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const index = active.controlFrames.findIndex(predicate);
      if (index >= 0) return active.controlFrames.splice(index, 1)[0]!;
      await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, Math.min(100, Math.max(1, deadline - Date.now())));
        active.controlWaiter = () => { clearTimeout(timer); resolve(); };
      });
    }
    throw new Error(`identify response timed out after ${timeoutMs}ms`);
  }

  private async run(open: OpenFrame, fromId: string, channel: Channel, exchange?: StandardExchange): Promise<void> {
    try {
      const measured = open.files ? scanPostedFiles(open.files) : open.scan;
      const scan: ScanFacts = { repo: open.repo, ...measured, numTools: toolsForScan(measured.hasSolidity) };
      const x402 = isX402Rail(exchange?.listing.acceptedRails?.[0]);
      const center = x402 && exchange?.listing.pricing.kind === "negotiable"
        ? Number(exchange.listing.pricing.bandCenter.amount)
        : 1;
      if (!Number.isFinite(center) || center <= 0) throw new Error("RFQ listing has an invalid negotiation price center");
      const economics = x402 ? {
        ...DEFAULT_ECONOMICS,
        quickBase: center,
        quickPerKloc: center * DEFAULT_ECONOMICS.quickPerKloc,
      } : DEFAULT_ECONOMICS;
      const guard = sellerGuardFor(scan, this.offeredTiers, ["standard", "rush"], economics);
      const anchorTier: AuditTier = this.offeredTiers.includes("deep") ? "deep" : "quick";
      const sellerBrief = { scan, guard, econ: economics, anchorTier };
      const result = await runSide({
        role: "seller", channelId: open.channelId,
        // The current LLM negotiation prompt is denominated in DEM. Keep x402
        // deterministic until the prompt carries an explicit currency field.
        policy: this.llm && !x402
          ? llmSeller(sellerBrief, { llm: this.llm })
          : deterministicSeller(sellerBrief),
        maySettle: (terms) => sellerMaySettle(terms, guard),
        peerSenderId: open.buyerSignerId, signer: this.channelSigner, channel,
        maxTurns: open.maxTurns ?? 6, recvTimeoutMs: 30_000,
        log: (line) => this.log(`[${open.channelId}] ${line}`),
      });
      if (result.outcome !== "agreed" || !result.agreed) {
        await this.send(fromId, { kind: "dacs-rfq-outcome", protocol: PROTOCOL, channelId: open.channelId, outcome: "walked", reason: result.reason });
        return;
      }
      const agreement = exchange
        ? await signStandardAgreement(buildStandardAgreement({
            jobId: open.jobId,
            channelId: open.channelId,
            agreed: result.agreed,
            listing: exchange.listing,
            buyer: exchange.buyer,
            seller: exchange.seller,
            envelopes: result.envelopes,
            requestHash: requestScopeHash({ files: open.files ?? [], negotiatedTerms: result.agreed, repo: open.repo }),
            ...(open.x402Payer ? { x402Payer: open.x402Payer } : {}),
          }), this.standard!.party)
        : buildChannelAgreement({
            jobId: open.jobId, channelId: open.channelId, agreed: result.agreed,
            sellerId: this.channelSigner.id, buyerId: open.buyerSignerId,
            envelopes: result.envelopes, generatedAt: new Date().toISOString(),
          });
      const hash = isStandardAgreement(agreement) ? standardAgreementHash(agreement) : agreementHash(agreement);
      const sellerSignature = isStandardAgreement(agreement)
        ? agreement.signatures.find((signature) => signature.party === this.channelSigner.id)
        : await signAgreement(this.channelSigner, "seller", agreement);
      if (!sellerSignature) throw new Error("seller agreement signature was not produced");
      const amountOs = isStandardAgreement(agreement)
        ? isX402Rail(agreement.terms.rail)
          ? x402AgreementTerms(agreement).amount
          : baseUnits(agreement.terms.price.amount, 9)
        : priceToOs(agreement.terms.price).toString();
      this.store.offer(hash, {
        channelId: open.channelId,
        buyerClientId: fromId,
        buyerSignerId: open.buyerSignerId,
        agreement,
        amountOs,
        repo: open.repo,
        files: open.files,
        ...(exchange ? { listingAnchorRef: exchange.listingAnchorRef } : {}),
      });
      await this.send(fromId, {
        kind: "dacs-rfq-agreement", protocol: PROTOCOL, channelId: open.channelId,
        agreement, agreementHash: hash, sellerSignature,
        ...paymentRequiredFields(agreement, this.payTo, amountOs),
      });
    } catch (error) {
      this.log(`[${open.channelId}] failed: ${(error as Error).message}`);
      await this.send(fromId, { kind: "dacs-rfq-error", protocol: PROTOCOL, channelId: open.channelId, code: "session_failed" });
    } finally {
      this.sessions.delete(open.channelId);
      await channel.close().catch(() => undefined);
    }
  }

  private async acceptAgreement(frame: Record<string, unknown>, fromId: string): Promise<void> {
    const hash = stringField(frame, "agreementHash");
    const agreement = frame.agreement as ChannelAgreement | AgreementDocument | undefined;
    if (!hash || !agreement) return void this.send(fromId, { kind: "dacs-rfq-error", protocol: PROTOCOL, code: "bad_agreement" });
    const offered = this.store.getOffered(hash);
    if (!offered || offered.buyerClientId !== fromId) return void this.send(fromId, { kind: "dacs-rfq-error", protocol: PROTOCOL, code: "unknown_agreement" });
    if (isStandardAgreement(agreement)) {
      if (!isStandardAgreement(offered.agreement) || !this.standard || standardAgreementHash(agreement) !== hash || standardAgreementHash(offered.agreement) !== hash) return void this.send(fromId, { kind: "dacs-rfq-error", protocol: PROTOCOL, code: "bad_agreement" });
      const published = await this.standard.getListing(offered.listingAnchorRef);
      const verdict = await verifyAgreement(agreement, published.listing, {
        ...cryptoDeps,
        ...(published.autoAcceptCommitment ? { autoAcceptCommitment: published.autoAcceptCommitment } : {}),
      });
      const buyer = agreement.parties.find((party) => party.role === "buyer")?.primaryClaim;
      if (!verdict.ok || buyer !== offered.buyerSignerId) return void this.send(fromId, { kind: "dacs-rfq-error", protocol: PROTOCOL, code: "bad_buyer_signature", reason: verdict.reason });
      const agreementRef = frame.agreementRef as AttestationRef | undefined;
      const agreementAnchorTxRef = stringField(frame, "agreementAnchorTxRef");
      const commitment = frame.commitment as CommitmentRecord | undefined;
      const commitmentRef = frame.commitmentRef as AttestationRef | undefined;
      const anchorTxRef = stringField(frame, "anchorTxRef");
      const committedAt = frame.committedAt;
      const commitmentBlockNumber = frame.commitmentBlockNumber;
      const agreementTransactionContent = recordField(frame, "agreementTransactionContent");
      const commitmentTransactionContent = recordField(frame, "commitmentTransactionContent");
      const agreementExpectedConfirmationBlock = frame.agreementExpectedConfirmationBlock;
      const commitmentExpectedConfirmationBlock = frame.commitmentExpectedConfirmationBlock;
      const agreementTransactionContentValueOmitted = frame.agreementTransactionContentValueOmitted === true;
      const commitmentTransactionContentValueOmitted = frame.commitmentTransactionContentValueOmitted === true;
      if (!buyer || !agreementRef || !agreementAnchorTxRef || !commitment || !commitmentRef || !anchorTxRef
        || !Number.isSafeInteger(committedAt) || Number(committedAt) < 0
        || (commitmentBlockNumber !== undefined && (!Number.isSafeInteger(commitmentBlockNumber) || Number(commitmentBlockNumber) < 0))) {
        return void this.send(fromId, { kind: "dacs-rfq-error", protocol: PROTOCOL, code: "missing_commitment" });
      }
      const agreementAddress = await this.standard.sub.anchorAddressFor(buyer, standardAnchorName("agreement", [agreement.jobId]));
      const commitmentAddress = await this.standard.sub.anchorAddressFor(buyer, standardAnchorName("commitment", [agreement.jobId]));
      if (!this.standard.sub.resolveAnchorReceipt) return void this.send(fromId, { kind: "dacs-rfq-error", protocol: PROTOCOL, code: "bad_commitment", reason: "seller substrate cannot verify the SR-2 receipt" });
      let receipt: AnchorReceipt;
      let agreementReceipt: AnchorReceipt;
      try {
        [agreementReceipt, receipt] = await Promise.all([
          this.standard.sub.resolveAnchorReceipt(agreementAnchorTxRef, buyer, {
            ...(Number.isSafeInteger(agreementExpectedConfirmationBlock) ? { expectedConfirmationBlock: Number(agreementExpectedConfirmationBlock) } : {}),
            ...(agreementTransactionContent ? { transactionContent: agreementTransactionContent } : {}),
            ...(agreementTransactionContentValueOmitted ? { transactionContentValueOmitted: true, anchorValue: agreement as unknown as Record<string, unknown> } : {}),
          }),
          this.standard.sub.resolveAnchorReceipt(anchorTxRef, buyer, {
            ...(Number.isSafeInteger(commitmentExpectedConfirmationBlock) ? { expectedConfirmationBlock: Number(commitmentExpectedConfirmationBlock) } : {}),
            ...(commitmentTransactionContent ? { transactionContent: commitmentTransactionContent } : {}),
            ...(commitmentTransactionContentValueOmitted ? { transactionContentValueOmitted: true, anchorValue: commitment as unknown as Record<string, unknown> } : {}),
          }),
        ]);
      } catch {
        return void this.send(fromId, { kind: "dacs-rfq-error", protocol: PROTOCOL, code: "bad_commitment", reason: "SR-2 receipt is not independently resolvable" });
      }
      const refsValid = agreementRef.anchor.kind === "storage-program"
        && agreementRef.anchor.locator === agreementAddress
        && agreementRef.contentHash === standardHash(agreement)
        && commitmentRef.anchor.kind === "storage-program"
        && commitmentRef.anchor.locator === commitmentAddress
        && commitmentRef.contentHash === standardHash(commitment)
        && agreementReceipt.address === agreementAddress
        && agreementReceipt.contentHash === standardHash(agreement, [])
        && receipt.address === commitmentAddress
        && receipt.contentHash === standardHash(commitment, [])
        && receipt.txRef.replace(/^0x/, "") === anchorTxRef.replace(/^0x/, "")
        && receipt.anchoredAt === committedAt
        && (commitmentBlockNumber === undefined || receipt.blockNumber === commitmentBlockNumber);
      const anchoredAgreement = await verifyAgreement(agreement, published.listing, {
        ...cryptoDeps,
        committedAt: Number(committedAt),
        ...(published.autoAcceptCommitment ? { autoAcceptCommitment: published.autoAcceptCommitment } : {}),
      });
      if (!refsValid || !anchoredAgreement.ok || !(await verifyCommitment(commitment, agreement, published.listing, { ...cryptoDeps, anchoredAt: Number(committedAt) }))) {
        return void this.send(fromId, { kind: "dacs-rfq-error", protocol: PROTOCOL, code: "bad_commitment" });
      }
      this.store.accept(hash, {
        ...offered,
        agreement,
        standardCommit: {
          agreementRef,
          agreementAnchorTxRef,
          commitment,
          commitmentRef,
          anchorTxRef,
          committedAt: Number(committedAt),
          ...(commitmentBlockNumber === undefined ? {} : { commitmentBlockNumber: Number(commitmentBlockNumber) }),
          ...(agreementTransactionContent ? { agreementTransactionContent } : {}),
          ...(commitmentTransactionContent ? { commitmentTransactionContent } : {}),
          ...(Number.isSafeInteger(agreementExpectedConfirmationBlock) ? { agreementExpectedConfirmationBlock: Number(agreementExpectedConfirmationBlock) } : {}),
          ...(Number.isSafeInteger(commitmentExpectedConfirmationBlock) ? { commitmentExpectedConfirmationBlock: Number(commitmentExpectedConfirmationBlock) } : {}),
          ...(agreementTransactionContentValueOmitted ? { agreementTransactionContentValueOmitted: true } : {}),
          ...(commitmentTransactionContentValueOmitted ? { commitmentTransactionContentValueOmitted: true } : {}),
        },
      });
    } else {
      const signature = frame.buyerSignature as AgreementSignature | undefined;
      if (!signature || isStandardAgreement(offered.agreement) || agreementHash(agreement) !== hash || agreementHash(offered.agreement) !== hash) return void this.send(fromId, { kind: "dacs-rfq-error", protocol: PROTOCOL, code: "bad_agreement" });
      if (agreement.parties.buyer !== signature.signerId || signature.role !== "buyer") return void this.send(fromId, { kind: "dacs-rfq-error", protocol: PROTOCOL, code: "bad_buyer_signature" });
      const ok = await verifyAgreementSignature(this.channelSigner, agreement, signature);
      if (!ok) return void this.send(fromId, { kind: "dacs-rfq-error", protocol: PROTOCOL, code: "bad_buyer_signature" });
      this.store.accept(hash, offered);
    }
    const channelId = offered.channelId;
    await this.send(fromId, {
      kind: "dacs-rfq-payment-required",
      protocol: PROTOCOL,
      channelId,
      agreementHash: hash,
      ...paymentRequiredFields(agreement, this.payTo, offered.amountOs),
    });
  }

  private async settle(frame: Record<string, unknown>, fromId: string): Promise<void> {
    const hash = stringField(frame, "agreementHash");
    const txHash = stringField(frame, "txHash");
    if (!hash || !txHash) return void this.send(fromId, { kind: "dacs-rfq-error", protocol: PROTOCOL, code: "bad_settlement" });
    const already = this.store.getSettled(hash);
    if (already && already.buyerClientId === fromId && already.txHash === normalizeTx(txHash)) {
      await this.sendSettled(hash, already, fromId);
      if ((!isStandardAgreement(already.agreement) || !this.standard) && already.delivery) {
        await this.sendDelivered(hash, already, fromId);
      }
      return;
    }
    if (this.store.hasSettledAgreement(hash) || this.store.hasSettledTx(txHash)) return void this.send(fromId, { kind: "dacs-rfq-error", protocol: PROTOCOL, code: "payment_replayed" });
    const accepted = this.store.getAccepted(hash);
    if (!accepted || accepted.buyerClientId !== fromId) return void this.send(fromId, { kind: "dacs-rfq-error", protocol: PROTOCOL, code: "unknown_agreement" });
    const x402 = isStandardAgreement(accepted.agreement) && isX402Rail(accepted.agreement.terms.rail);
    const paymentProof = paymentProofField(frame);
    const x402Proof = x402PaymentProofField(frame);
    const result = x402
      ? this.x402Payments
        ? await this.x402Payments.verify(txHash, accepted.agreement as AgreementDocument)
        : { ok: false, reason: "seller x402 verifier is not configured" }
      : await verifyPaymentWithRetry(this.payments, txHash, BigInt(accepted.amountOs), { proof: paymentProof });
    if (!result.ok) return void this.send(fromId, { kind: "dacs-rfq-payment-rejected", protocol: PROTOCOL, channelId: accepted.channelId, agreementHash: hash, reason: result.reason, retriable: result.retriable === true });
    if (isStandardAgreement(accepted.agreement) && !Number.isSafeInteger(result.blockNumber)) return void this.send(fromId, { kind: "dacs-rfq-payment-rejected", protocol: PROTOCOL, channelId: accepted.channelId, agreementHash: hash, reason: "confirmed payment omitted its inclusion block", retriable: true });
    if (x402 && !x402Proof) return void this.send(fromId, { kind: "dacs-rfq-payment-rejected", protocol: PROTOCOL, channelId: accepted.channelId, agreementHash: hash, reason: "x402 payment receipt hash is missing" });
    const settled = this.store.settle(
      hash,
      txHash,
      result.payer,
      result.amountOs?.toString() ?? accepted.amountOs,
      result.blockNumber,
      x402Proof?.paymentReceiptHash,
      x402 ? (result as VerifiedX402Payment).logIndex : undefined,
    );
    await this.sendSettled(hash, settled, fromId);
    // DACS-4 PC-2/PC-3: Standard delivery cannot begin until the buyer has
    // produced and anchored native-payment SettlementEvidence. Legacy RFQ
    // sessions retain their original automatic-delivery behaviour.
    if (!isStandardAgreement(settled.agreement) || !this.standard) {
      await this.runDelivery(hash, settled, fromId);
    }
  }

  private async retryDelivery(frame: Record<string, unknown>, fromId: string): Promise<void> {
    const hash = stringField(frame, "agreementHash");
    const settled = this.store.getSettled(hash);
    if (!settled || settled.buyerClientId !== fromId) return void this.send(fromId, { kind: "dacs-rfq-error", protocol: PROTOCOL, code: "unknown_agreement" });
    if (isStandardAgreement(settled.agreement) && this.standard) {
      try {
        await this.verifyAnchoredPaymentEvidence(frame, settled);
      } catch (error) {
        return void this.send(fromId, {
          kind: "dacs-rfq-error",
          protocol: PROTOCOL,
          channelId: settled.channelId,
          agreementHash: hash,
          code: "payment_evidence_invalid",
          reason: (error as Error).message,
        }).catch((sendError) => this.log(`[${stringField(frame, "agreementHash")}] could not return fulfilment error: ${(sendError as Error).message}`));
      }
    }
    if (settled.delivery) return void (await this.sendDelivered(hash, settled, fromId));
    await this.runDelivery(hash, settled, fromId, frame.recovery === true);
  }

  private async verifyAnchoredPaymentEvidence(frame: Record<string, unknown>, settled: SettledRecord): Promise<void> {
    if (!this.standard || !isStandardAgreement(settled.agreement)) throw new Error("Standard payment evidence is unavailable");
    const evidence = frame.paymentEvidence as SettlementEvidence | undefined;
    const ref = frame.paymentEvidenceRef as AttestationRef | undefined;
    const receipt = frame.paymentEvidenceReceipt as AnchorReceipt | undefined;
    const buyerClaim = settled.agreement.parties.find((party) => party.role === "buyer")?.primaryClaim;
    const x402 = isX402Rail(settled.agreement.terms.rail);
    const payerMatches = x402
      ? settled.payer?.toLowerCase() === x402AgreementTerms(settled.agreement).payer.toLowerCase()
      : sameDemosParty(buyerClaim ?? "", settled.payer);
    if (!evidence || !ref || !buyerClaim || !payerMatches) {
      throw new Error("buyer payment evidence is missing or payer-mismatched");
    }
    const paymentPhase = paymentPhaseForAgreement(settled.agreement);
    const published = await this.standard.getListing(settled.listingAnchorRef);
    const paymentPhaseIndex = published.listing.pipeline.findIndex((phase) => phase.kind === paymentPhase);
    const railId = settled.agreement.terms.rail?.railId;
    if (paymentPhaseIndex < 0 || !railId) throw new Error("listing/agreement omitted the selected payment rail phase");
    if (x402 && x402AgreementTerms(settled.agreement).phaseIndex !== paymentPhaseIndex) {
      throw new Error("x402 agreement phaseIndex does not match the selected listing phase");
    }
    const expected = await this.standard.sub.anchorAddressFor(
      buyerClaim,
      standardPaymentAnchorName(settled.agreement.jobId, railId, paymentPhaseIndex),
    );
    if (ref.anchor.kind !== "storage-program"
      || ref.anchor.locator !== expected
      || ref.signer !== buyerClaim
      || ref.contentHash !== standardHash(evidence)) {
      throw new Error("payment evidence reference is not buyer-bound to the expected anchor");
    }
    await verifyConfirmedAnchor(
      this.standard.sub,
      expected,
      evidence as unknown as Record<string, unknown>,
      receipt,
      buyerClaim,
    );
    const verdict = await verifyEvidence(evidence, {
      orchestrator: buyerClaim,
      agreement: settled.agreement,
      railType: x402 ? "x402" : "demos-native",
      railId: settled.agreement.terms.rail?.railId ?? "",
      ...cryptoDeps,
    });
    const exactPayment = settlementEvidenceMatches(evidence, settled);
    if (!verdict.ok || !exactPayment) {
      throw new Error(`payment evidence does not prove the accepted settlement: ${verdict.reasons.join("; ")}`);
    }
  }

  private async fulfilBundle(frame: Record<string, unknown>, fromId: string): Promise<void> {
    const hash = stringField(frame, "agreementHash");
    const buyerDid = stringField(frame, "buyerDid");
    const settled = this.store.getSettled(hash);
    if (!settled || settled.buyerClientId !== fromId || !settled.delivery) return void this.send(fromId, { kind: "dacs-rfq-error", protocol: PROTOCOL, code: "unknown_agreement" });
    const x402 = isStandardAgreement(settled.agreement) && isX402Rail(settled.agreement.terms.rail);
    const buyerClaim = isStandardAgreement(settled.agreement)
      ? settled.agreement.parties.find((party) => party.role === "buyer")?.primaryClaim
      : undefined;
    const buyerMatches = /^did:demos:agent:[0-9a-fA-F]{64}$/.test(buyerDid)
      && (x402 ? buyerDid === buyerClaim : sameDemosParty(buyerDid, settled.payer));
    if (!buyerMatches) {
      return void this.send(fromId, { kind: "dacs-rfq-error", protocol: PROTOCOL, code: "buyer_payment_mismatch" });
    }
    if (isStandardAgreement(settled.agreement) && this.standard) {
      if (settled.sellerBundleRef) {
        const bundle = settled.sellerBundle ?? await this.standard.sub.read(settled.sellerBundleRef);
        return void this.send(fromId, { kind: "dacs-rfq-fulfilled", protocol: PROTOCOL, channelId: settled.channelId, agreementHash: hash, sellerBundleRef: settled.sellerBundleRef, bundle, sellerBundleReceipt: settled.sellerBundleReceipt });
      }
      const buyerBundle = frame.bundle as AttestationBundle | undefined;
      const buyerClaim = settled.agreement.parties.find((party) => party.role === "buyer")?.primaryClaim;
      const sellerClaim = settled.agreement.parties.find((party) => party.role === "seller")?.primaryClaim;
      if (!buyerBundle || !buyerClaim || !sellerClaim || !settled.standardCommit || !settled.deliveryEvidenceRef) return void this.send(fromId, { kind: "dacs-rfq-error", protocol: PROTOCOL, code: "bad_bundle" });
      const partialVerdict = await verifyBundle(buyerBundle, { expectedRole: "buyer", requiredRoles: ["buyer"], ...cryptoDeps });
      const expectedPaymentPhase = paymentPhaseForAgreement(settled.agreement);
      const paymentPhase = buyerBundle.phaseSummary.find((phase) => phase.kind === expectedPaymentPhase);
      const deliveryPhase = buyerBundle.phaseSummary.find((phase) => phase.kind === "deliver-attested-payload");
      const commitmentPhase = buyerBundle.phaseSummary.find((phase) => phase.kind === "commit-agreement");
      const paymentRef = paymentPhase?.attestationRef;
      const suppliedPaymentEvidence = frame.paymentEvidence as SettlementEvidence | undefined;
      const paymentEvidenceReceipt = frame.paymentEvidenceReceipt as AnchorReceipt | undefined;
      let suppliedPaymentVerified = false;
      if (paymentRef?.anchor.kind === "storage-program" && suppliedPaymentEvidence) {
        try {
          await verifyConfirmedAnchor(
            this.standard.sub,
            paymentRef.anchor.locator,
            suppliedPaymentEvidence as unknown as Record<string, unknown>,
            paymentEvidenceReceipt,
            buyerClaim,
          );
          suppliedPaymentVerified = true;
        } catch { /* fall back to the independently readable copy below */ }
      }
      const paymentRaw = suppliedPaymentVerified
        ? suppliedPaymentEvidence
        : (paymentRef?.anchor.kind === "storage-program" ? await this.standard.sub.read(paymentRef.anchor.locator) : null);
      const paymentEvidence = paymentRaw as unknown as SettlementEvidence | null;
      const paymentVerdict = paymentEvidence ? await verifyEvidence(paymentEvidence, {
        orchestrator: buyerClaim,
        agreement: settled.agreement,
        railType: x402 ? "x402" : "demos-native",
        railId: settled.agreement.terms.rail?.railId ?? "",
        ...cryptoDeps,
      }) : { ok: false, reasons: ["payment evidence is absent"] };
      const published = await this.standard.getListing(settled.listingAnchorRef);
      const expectedParties = new Map(settled.agreement.parties.map((party) => [party.primaryClaim, party.bundleHash]));
      const expectedPartyRoles = new Map(settled.agreement.parties.map((party) => [party.primaryClaim, party.role]));
      const expectedVetRecords = settled.agreement.parties.flatMap((party) => party.vetRecordRef ? [party.vetRecordRef] : []);
      const refSetMatches = (actual: AttestationRef[], expected: AttestationRef[]): boolean =>
        actual.length === expected.length
        && new Set(actual.map((ref) => standardHash(ref, []))).size === actual.length
        && actual.every((ref) => expected.some((candidate) => standardHash(candidate, []) === standardHash(ref, [])));
      const phasesValid = buyerBundle.phaseSummary.length === published.listing.pipeline.length
        && buyerBundle.phaseSummary.every((phase, index) =>
          phase.index === index
          && phase.kind === published.listing.pipeline[index]?.kind
          && phase.outcome === "ok"
        );
      const expectedPaymentPhaseIndex = published.listing.pipeline.findIndex((phase) => phase.kind === expectedPaymentPhase);
      const paymentRailId = settled.agreement.terms.rail?.railId;
      if (expectedPaymentPhaseIndex < 0 || !paymentRailId) throw new Error("listing/agreement omitted the selected payment rail phase");
      const [expectedPaymentAddress, expectedDeliveryAddress] = await Promise.all([
        this.standard.sub.anchorAddressFor(buyerClaim, standardPaymentAnchorName(settled.agreement.jobId, paymentRailId, expectedPaymentPhaseIndex)),
        this.standard.sub.anchorAddressFor(sellerClaim, standardAnchorName("evidence", [settled.agreement.jobId, "deliver-attested-payload"])),
      ]);
      const structureValid = partialVerdict.ok
        && buyerBundle.jobId === settled.agreement.jobId
        && buyerBundle.outcome === "completed"
        && standardHash(buyerBundle.listingRef, []) === standardHash(listingRef(published.listing), [])
        && standardHash(buyerBundle.agreementRef ?? {}, []) === standardHash(settled.standardCommit.agreementRef, [])
        && phasesValid
        && buyerBundle.parties.length === 2
        && buyerBundle.parties.every((party) => expectedParties.get(party.primaryClaim) === party.bundleHash && expectedPartyRoles.get(party.primaryClaim) === party.role)
        && refSetMatches(buyerBundle.vetRecords, expectedVetRecords)
        && standardHash(commitmentPhase?.attestationRef ?? {}, []) === standardHash(settled.standardCommit.commitmentRef, [])
        && paymentRef?.anchor.locator === expectedPaymentAddress
        && paymentRef?.signer === buyerClaim
        && paymentRef?.contentHash === (paymentEvidence ? standardHash(paymentEvidence) : "")
        && (paymentEvidence ? settlementEvidenceMatches(paymentEvidence, settled) : false)
        && deliveryPhase?.attestationRef?.anchor.locator === expectedDeliveryAddress
        && deliveryPhase?.attestationRef?.signer === sellerClaim
        && standardHash(deliveryPhase?.attestationRef ?? {}, []) === standardHash(settled.deliveryEvidenceRef, [])
        && refSetMatches(buyerBundle.settlementEvidence, [paymentRef!, settled.deliveryEvidenceRef])
        && paymentVerdict.ok;
      if (!structureValid) return void this.send(fromId, { kind: "dacs-rfq-error", protocol: PROTOCOL, code: "bad_bundle", reason: paymentVerdict.reasons.join("; ") });
      const sellerCopy = await addBundleSignature({ ...buyerBundle, anchoredByRole: "seller" }, this.standard.party);
      const fullVerdict = await verifyBundle(sellerCopy, { expectedRole: "seller", ...cryptoDeps });
      if (!fullVerdict.ok) return void this.send(fromId, { kind: "dacs-rfq-error", protocol: PROTOCOL, code: "bad_bundle", reason: fullVerdict.reason });
      const bundleName = standardAnchorName("bundle", [settled.agreement.jobId, "seller"]);
      const plannedRef = await this.standard.sub.anchorAddress(bundleName);
      // Both signatures now exist. The buyer does not need to wait for this
      // seller-wallet transaction before starting its own independent SR-2
      // copy; it still waits for dacs-rfq-fulfilled before declaring DACS-5
      // complete, so both on-chain copies remain mandatory.
      await this.send(fromId, {
        kind: "dacs-rfq-fulfil-ready",
        protocol: PROTOCOL,
        channelId: settled.channelId,
        agreementHash: hash,
        sellerBundleRef: plannedRef,
        bundle: sellerCopy,
      });
      const bundleReceipt = this.standard.sub.anchorWithReceipt
        ? await this.standard.sub.anchorWithReceipt(bundleName, sellerCopy)
        : undefined;
      const ref = bundleReceipt?.address ?? await this.standard.sub.anchor(bundleName, sellerCopy);
      if (ref !== plannedRef) throw new Error("seller bundle anchor resolved to an unexpected address");
      this.store.fulfilled(hash, ref, sellerCopy, bundleReceipt);
      return void this.send(fromId, { kind: "dacs-rfq-fulfilled", protocol: PROTOCOL, channelId: settled.channelId, agreementHash: hash, sellerBundleRef: ref, bundle: sellerCopy, sellerBundleReceipt: bundleReceipt });
    }
    if (settled.sellerBundleRef) return void this.send(fromId, { kind: "dacs-rfq-fulfilled", protocol: PROTOCOL, channelId: settled.channelId, agreementHash: hash, sellerBundleRef: settled.sellerBundleRef });
    if (!this.fulfil) return void this.send(fromId, { kind: "dacs-rfq-error", protocol: PROTOCOL, code: "fulfilment_unavailable" });
    try {
      const ref = await this.fulfil(settled.agreement.jobId, buyerDid);
      this.store.fulfilled(hash, ref);
      await this.send(fromId, { kind: "dacs-rfq-fulfilled", protocol: PROTOCOL, channelId: settled.channelId, agreementHash: hash, sellerBundleRef: ref });
    } catch (error) {
      this.log(`[${settled.channelId}] fulfilment failed: ${(error as Error).message}`);
      await this.send(fromId, { kind: "dacs-rfq-error", protocol: PROTOCOL, channelId: settled.channelId, agreementHash: hash, code: "fulfilment_failed", retriable: true });
    }
  }

  private async runDelivery(hash: string, settled: SettledRecord, to: string, reuseExisting = false): Promise<void> {
    if (!this.delivery) return;
    try {
      this.log(`[${settled.channelId}] preparing deliverable for ${settled.agreement.jobId}`);
      const delivery = await this.delivery({
        agreementHash: hash, agreement: settled.agreement, txHash: settled.txHash,
        payer: settled.payer, amountOs: settled.paidAmountOs, repo: settled.repo,
        files: settled.files, params: settled.params,
      });
      let deliveryEvidence: SettlementEvidence | undefined;
      let deliveryEvidenceRef: AttestationRef | undefined;
      if (isStandardAgreement(settled.agreement) && this.standard) {
        let deliveryAlreadyAnchored = false;
        if (reuseExisting) {
          const existingDelivery = await this.standard.sub.read(delivery.deliveryRef);
          if (existingDelivery) {
            delivery.attestation = existingDelivery;
            deliveryAlreadyAnchored = true;
            this.log(`[${settled.channelId}] reusing the existing confirmed delivery anchor`);
          }
        }
        const agreedRequestHash = settled.agreement.terms.additionalTerms?.requestHash;
        if (typeof agreedRequestHash === "string" && delivery.attestation.requestHash !== agreedRequestHash) {
          throw new Error("delivery does not bind the exact request in the signed agreement");
        }
        if (agreedRequestHash === undefined) {
          // Rolling-deploy compatibility for an agreement that was already
          // accepted/paid before requestHash existed. New buyers reject such
          // agreements before signing, so this branch can only recover legacy
          // persisted state and cannot create a new unbound purchase.
          this.log(`[${settled.channelId}] recovering legacy paid agreement without requestHash`);
        }
        const deliverableContentHash = delivery.deliverableContentHash
          ?? (typeof delivery.attestation.resultHash === "string" ? delivery.attestation.resultHash : "");
        if (!/^[0-9a-f]{64}$/i.test(deliverableContentHash)) throw new Error("delivery omitted a canonical content hash");
        const evidenceName = standardAnchorName("evidence", [settled.agreement.jobId, "deliver-attested-payload"]);
        const evidenceAddress = await this.standard.sub.anchorAddress(evidenceName);
        const existingEvidence = reuseExisting
          ? await this.standard.sub.read(evidenceAddress) as unknown as SettlementEvidence | null
          : null;
        if (existingEvidence && !deliveryAlreadyAnchored) {
          throw new Error("delivery evidence exists without its expected delivery artifact");
        }
        deliveryEvidence = existingEvidence ?? await signSettlementEvidence({
            evidenceVersion: "1",
            jobId: settled.agreement.jobId,
            phase: "deliver-attested-payload",
            outcome: "success",
            deliverableContentHash,
            deliverableAnchor: { kind: "storage-program", locator: delivery.deliveryRef },
            attestationRef: attestationRef(delivery.deliveryRef, delivery.attestation, this.standard.party.primaryClaim),
            observedAt: Date.now(),
          }, this.standard.party);
        const evidenceVerdict = await verifyEvidence(deliveryEvidence, {
          orchestrator: this.standard.party.primaryClaim,
          agreement: settled.agreement,
          railType: isX402Rail(settled.agreement.terms.rail) ? "x402" : "demos-native",
          railId: settled.agreement.terms.rail?.railId ?? "",
          ...cryptoDeps,
        });
        const exactExistingEvidence = deliveryEvidence.deliverableContentHash === deliverableContentHash
          && deliveryEvidence.deliverableAnchor?.kind === "storage-program"
          && deliveryEvidence.deliverableAnchor.locator === delivery.deliveryRef
          && deliveryEvidence.attestationRef?.anchor.kind === "storage-program"
          && deliveryEvidence.attestationRef.anchor.locator === delivery.deliveryRef
          && deliveryEvidence.attestationRef.contentHash === standardHash(delivery.attestation);
        if (!evidenceVerdict.ok || !exactExistingEvidence) {
          throw new Error(`delivery evidence failed Standard verification: ${evidenceVerdict.reasons.join("; ")}`);
        }
        let evidenceReceipt: AnchorReceipt | undefined;
        if (existingEvidence) {
          this.log(`[${settled.channelId}] reusing the existing confirmed delivery evidence`);
        } else if (deliveryAlreadyAnchored) {
          evidenceReceipt = this.standard.sub.anchorWithReceipt
            ? await this.standard.sub.anchorWithReceipt(evidenceName, deliveryEvidence)
            : undefined;
        } else if (delivery.preparedAnchor && this.standard.sub.anchorBatchWithReceipts) {
          // Both signed payloads and deterministic addresses are known. The
          // substrate preserves their order and, on Demos, confirms the first
          // same-wallet nonce before broadcasting the second so a dropped
          // predecessor cannot strand future-nonce evidence in the mempool.
          this.log(`[${settled.channelId}] anchoring delivery then delivery evidence`);
          const [deliveryReceipt, batchedEvidenceReceipt] = await this.standard.sub.anchorBatchWithReceipts([
            delivery.preparedAnchor,
            { name: evidenceName, value: deliveryEvidence },
          ]);
          if (deliveryReceipt.address !== delivery.deliveryRef) throw new Error("batched delivery anchor resolved to an unexpected address");
          delivery.anchorReceipt = deliveryReceipt;
          evidenceReceipt = batchedEvidenceReceipt;
          this.log(`[${settled.channelId}] delivery and evidence reached confirmed inclusion`);
        } else {
          if (delivery.preparedAnchor) {
            const deliveryReceipt = this.standard.sub.anchorWithReceipt
              ? await this.standard.sub.anchorWithReceipt(delivery.preparedAnchor.name, delivery.preparedAnchor.value)
              : undefined;
            const deliveryLocator = deliveryReceipt?.address
              ?? await this.standard.sub.anchor(delivery.preparedAnchor.name, delivery.preparedAnchor.value);
            if (deliveryLocator !== delivery.deliveryRef) throw new Error("prepared delivery anchor resolved to an unexpected address");
            if (deliveryReceipt) delivery.anchorReceipt = deliveryReceipt;
          }
          evidenceReceipt = this.standard.sub.anchorWithReceipt
            ? await this.standard.sub.anchorWithReceipt(evidenceName, deliveryEvidence)
            : undefined;
        }
        const locator = existingEvidence
          ? evidenceAddress
          : evidenceReceipt?.address ?? await this.standard.sub.anchor(evidenceName, deliveryEvidence);
        deliveryEvidenceRef = attestationRef(locator, deliveryEvidence, this.standard.party.primaryClaim);
        if (evidenceReceipt) settled.deliveryEvidenceReceipt = evidenceReceipt;
      }
      delete delivery.preparedAnchor;
      this.store.delivered(hash, delivery, deliveryEvidence, deliveryEvidenceRef);
      const saved = this.store.getSettled(hash)!;
      await this.sendDelivered(hash, saved, to);
    } catch (error) {
      this.log(`[${settled.channelId}] delivery failed: ${(error as Error).message}`);
      await this.send(to, { kind: "dacs-rfq-error", protocol: PROTOCOL, channelId: settled.channelId, agreementHash: hash, code: "delivery_failed", retriable: true })
        .catch((sendError) => this.log(`[${settled.channelId}] could not return delivery error: ${(sendError as Error).message}`));
    }
  }

  private async sendSettled(hash: string, settled: SettledRecord, to: string): Promise<void> {
    await this.send(to, { kind: "dacs-rfq-settled", protocol: PROTOCOL, channelId: settled.channelId, agreementHash: hash, txHash: settled.txHash, payer: settled.payer, amountOs: settled.paidAmountOs, blockNumber: settled.blockNumber, ...(settled.logIndex === undefined ? {} : { logIndex: settled.logIndex }), ...(settled.paymentReceiptHash ? { paymentReceiptHash: settled.paymentReceiptHash } : {}) });
  }

  private async sendDelivered(hash: string, settled: SettledRecord, to: string): Promise<void> {
    const delivery = settled.delivery!;
    const wireDelivery = {
      ...delivery,
      ...(delivery.anchorReceipt ? { anchorReceipt: compactReceiptForTransport(delivery.anchorReceipt) } : {}),
    };
    await this.send(to, {
      kind: "dacs-rfq-delivered", protocol: PROTOCOL, channelId: settled.channelId,
      agreementHash: hash, txHash: settled.txHash, ...wireDelivery,
      deliveryEvidence: settled.deliveryEvidence,
      deliveryEvidenceRef: settled.deliveryEvidenceRef,
      deliveryEvidenceReceipt: settled.deliveryEvidenceReceipt
        ? compactReceiptForTransport(settled.deliveryEvidenceReceipt)
        : undefined,
    });
  }

  private async send(to: string, frame: object): Promise<void> { await this.peer.sendMessage(to, JSON.stringify(frame)); }
}

function parseOpen(frame: Record<string, unknown>): OpenFrame | undefined {
  const channelId = stringField(frame, "channelId");
  const jobId = stringField(frame, "jobId");
  const buyerSignerId = stringField(frame, "buyerSignerId");
  const repo = stringField(frame, "repo");
  const scan = frame.scan as Record<string, unknown> | undefined;
  if (frame.protocol !== PROTOCOL || !safeId(channelId) || !safeId(jobId) || !buyerSignerId || buyerSignerId.length > 256 || !repo || repo.length > 500 || !scan) return undefined;
  const kloc = Number(scan.kloc); const fileCount = Number(scan.fileCount); const hasSolidity = scan.hasSolidity;
  if (!Number.isFinite(kloc) || kloc < 0 || kloc > 1_000_000 || !Number.isInteger(fileCount) || fileCount < 0 || fileCount > 10_000_000 || typeof hasSolidity !== "boolean") return undefined;
  const maxTurns = frame.maxTurns === undefined ? undefined : Number(frame.maxTurns);
  if (maxTurns !== undefined && (!Number.isInteger(maxTurns) || maxTurns < 2 || maxTurns > 20)) return undefined;
  const files = parsePostedFiles(frame.files);
  if (frame.files !== undefined && !files) return undefined;
  const listingAnchorRef = stringField(frame, "listingAnchorRef") || undefined;
  const buyerPrimaryClaim = stringField(frame, "buyerPrimaryClaim") || undefined;
  const sellerNonce = stringField(frame, "sellerNonce") || undefined;
  const x402Payer = stringField(frame, "x402Payer") || undefined;
  if (sellerNonce !== undefined && !/^[0-9a-f]{32,}$/i.test(sellerNonce)) return undefined;
  if (x402Payer !== undefined && !/^0x[0-9a-fA-F]{40}$/.test(x402Payer)) return undefined;
  return { kind: "dacs-rfq-open", protocol: PROTOCOL, channelId, jobId, buyerSignerId, repo, scan: { kloc, fileCount, hasSolidity }, files, maxTurns, listingAnchorRef, buyerPrimaryClaim, sellerNonce, x402Payer };
}

function parsePostedFiles(value: unknown): Array<{ path: string; content: string }> | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length < 1 || value.length > 3) return undefined;
  const files: Array<{ path: string; content: string }> = [];
  for (const raw of value) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
    const path = (raw as { path?: unknown }).path;
    const content = (raw as { content?: unknown }).content;
    if (typeof path !== "string" || !path || path.length > 160 || typeof content !== "string" || Buffer.byteLength(content, "utf8") > 12_000) return undefined;
    files.push({ path, content });
  }
  return files;
}

function scanPostedFiles(files: Array<{ path: string; content: string }>): { kloc: number; fileCount: number; hasSolidity: boolean } {
  const lines = files.reduce((sum, file) => sum + file.content.split("\n").length, 0);
  return { kloc: Math.round((lines / 1_000) * 1_000) / 1_000, fileCount: files.length, hasSolidity: files.some((file) => /\.sol$/i.test(file.path)) };
}

function isEnvelope(frame: Record<string, unknown>): frame is Record<string, unknown> & ChannelEnvelope {
  return typeof frame.channelId === "string" && typeof frame.sequence === "number" && typeof frame.body === "object" && frame.body !== null && typeof frame.signature === "object";
}
function stringField(frame: Record<string, unknown>, key: string): string { return typeof frame[key] === "string" ? frame[key] as string : ""; }
function recordField(frame: Record<string, unknown>, key: string): Record<string, unknown> | undefined {
  const value = frame[key];
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}
function paymentProofField(frame: Record<string, unknown>): PaymentInclusionProof | undefined {
  const proof = recordField(frame, "paymentProof");
  const transactionContent = proof && recordField(proof, "transactionContent");
  const blockNumber = proof?.blockNumber;
  return transactionContent && Number.isSafeInteger(blockNumber) && Number(blockNumber) >= 0
    ? { transactionContent, blockNumber: Number(blockNumber) }
    : undefined;
}
function x402PaymentProofField(frame: Record<string, unknown>): X402SettlementProof | undefined {
  const proof = recordField(frame, "paymentProof");
  const paymentReceiptHash = typeof proof?.paymentReceiptHash === "string"
    ? proof.paymentReceiptHash.replace(/^0x/, "").toLowerCase()
    : "";
  return proof?.kind === "x402" && /^[0-9a-f]{64}$/.test(paymentReceiptHash)
    ? { kind: "x402", paymentReceiptHash }
    : undefined;
}
function compactReceiptForTransport(receipt: AnchorReceipt): AnchorReceipt {
  if (!receipt.transactionContent || receipt.transactionContentValueOmitted) return receipt;
  const transactionContent = JSON.parse(JSON.stringify(receipt.transactionContent)) as Record<string, unknown>;
  const values = Array.isArray(transactionContent.data) ? transactionContent.data : undefined;
  const payload = values?.[0] === "storageProgram" ? values[1] : undefined;
  if (!payload || typeof payload !== "object" || Array.isArray(payload)
    || !Object.prototype.hasOwnProperty.call(payload, "data")) return receipt;
  (payload as Record<string, unknown>).data = null;
  return { ...receipt, transactionContent, transactionContentValueOmitted: true };
}
function safeId(value: string): boolean { return /^[A-Za-z0-9._:-]{1,160}$/.test(value); }
function normalizeTx(value: string): string { return value.trim().replace(/^0x/, "").toLowerCase(); }
function settlementEvidenceMatches(evidence: SettlementEvidence, settled: SettledRecord): boolean {
  if (!isStandardAgreement(settled.agreement)) return false;
  if (isX402Rail(settled.agreement.terms.rail)) {
    return Boolean(settled.paymentReceiptHash) && evidence.phase === "pay-x402"
      && evidence.paymentTxRefs?.some((ref) => ref.kind === "x402"
        && ref.settlementTxHash?.replace(/^0x/, "").toLowerCase() === settled.txHash
        && ref.paymentReceiptHash.replace(/^0x/, "").toLowerCase() === settled.paymentReceiptHash
        && ref.chainId === BASE_SEPOLIA_CHAIN_ID
        && ref.logIndex === settled.logIndex) === true;
  }
  return evidence.phase === "pay-dem"
    && evidence.paymentTxRefs?.some((ref) => ref.kind === "demos"
      && ref.txHash.replace(/^0x/, "").toLowerCase() === settled.txHash
      && ref.blockNumber === settled.blockNumber) === true;
}
function paymentRequiredFields(
  agreement: ChannelAgreement | AgreementDocument,
  demosPayTo: string,
  amountOs: string,
): Record<string, unknown> {
  if (!isStandardAgreement(agreement) || !isX402Rail(agreement.terms.rail)) {
    return { rail: "pay-dem", payTo: demosPayTo, amountOs };
  }
  const terms = x402AgreementTerms(agreement);
  if (terms.amount !== amountOs) throw new Error("x402 base-unit amount does not match the agreement");
  return {
    rail: "pay-x402",
    payTo: terms.payTo,
    amountOs,
    payer: terms.payer,
    network: terms.network,
    asset: terms.asset,
    resource: terms.resource,
    protocolVersion: terms.protocolVersion,
  };
}
function sameDemosParty(did: string, address: string | undefined): boolean {
  if (!address) return false;
  return did.slice(-64).toLowerCase() === address.replace(/^0x/, "").toLowerCase();
}
function priceToOs(price: number): bigint {
  if (!Number.isFinite(price) || price <= 0) throw new Error("invalid agreement price");
  return BigInt(Math.round(price * Number(OS_PER_DEM)));
}
