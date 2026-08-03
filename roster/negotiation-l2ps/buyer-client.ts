/** Buyer-side client for the persistent `dacs-rfq/1` Auditor protocol. */
import { buyerMaySettle, type AuditTier, type BuyerGuard, type Deadline } from "../audit-negotiator/terms.js";
import { deterministicBuyer } from "../audit-negotiator/policies.js";
import {
  agreementHash,
  auditTermsFromStandardAgreement,
  isStandardAgreement,
  signAgreement,
  signStandardAgreement,
  standardAgreementHash,
  verifyAgreementSignature,
  verifyStandardAgreement,
  type AgreementSignature,
  type ChannelAgreement,
} from "./bind.js";
import { MailboxChannel } from "./channel.js";
import { decodePayload } from "./live-peer.js";
import { runSide, type NetworkedResult } from "./session.js";
import type { MessagingPeerInstance, PeerIdentity } from "./demosdk.js";
import type { ChannelEnvelope, Signer } from "./wire.js";
import {
  attestationRef,
  addBundleSignature,
  createCommitment,
  emptyRequirement,
  listingRef,
  requestScopeHash,
  sameCanonicalBundle,
  signSettlementEvidence,
  standardAnchorName,
  standardPaymentAnchorName,
  standardHash,
  verifyBundle,
  verifyCommitment,
  verifyEvidence,
  verifyAgreement,
  type AttestationBundle,
  type AgreementDocument,
  type AttestationRef,
  type CommitmentRecord,
  type CompositeVerificationRecord,
  type IdentityBundle,
  type AutoAcceptCommitment,
} from "../dacs/standard-profile.js";
import { cryptoDeps } from "./standard-session.js";
import type { AnchorAcceptance, AnchorReceipt } from "../../src/ports.js";
import type { SettlementProof } from "../gateway/settlement.js";
type VetReceipt = AnchorReceipt | AnchorAcceptance;

// Each side independently confirms its DACS-2 Vet record before the identified
// frame can be returned. The public Demos confirmation RPC can exceed 30s even
// when inclusion succeeds at the promised block, so this protocol deadline
// matches the seller's bounded identity-exchange window.
const IDENTITY_RESPONSE_TIMEOUT_MS = 90_000;
import type { AuditTerms } from "../audit-negotiator/terms.js";
import {
  anchorAbortBundle,
  presentIdentity,
  sessionNonce,
  verifyAnchoredVet,
  verifyConfirmedAnchor,
  verifyPresentation,
  vetAndAnchor,
  type StandardSessionContext,
  type VettedParty,
} from "./standard-session.js";
import { runFixedPriceNegotiation } from "./fixed-price.js";
import {
  BASE_SEPOLIA_CHAIN_ID,
  isX402Rail,
  paymentPhaseForAgreement,
  verifyX402IdentityBinding,
  x402AgreementTerms,
  x402ListingTerms,
} from "../dacs/x402-production.js";
import {
  createSecurityResearcherVetRecord,
  securityResearcherProfileFromListing,
  securityResearcherRequirement,
} from "../dacs/security-researcher-vet.js";

const PROTOCOL = "dacs-rfq/1";

export interface BuyerPostedFile { path: string; content: string }

export interface RfqBuyerInput {
  channelId: string;
  jobId: string;
  repo: string;
  files: BuyerPostedFile[];
  budgetDem: number;
  /** Required only when the selected listing uses pay-x402. */
  x402Payer?: string;
  preferredTier?: AuditTier;
  preferredDeadline?: Deadline;
  acceptableTiers?: AuditTier[];
  maxTurns?: number;
}

export interface RfqDelivery {
  agreementHash: string;
  txHash: string;
  deliveryRef: string;
  attestation: Record<string, unknown>;
  result: unknown;
  deliveryEvidence?: import("../dacs/standard-profile.js").SettlementEvidence;
  deliveryEvidenceRef?: AttestationRef;
  anchorReceipt?: AnchorReceipt;
  deliveryEvidenceReceipt?: AnchorReceipt;
}

export interface AnchoredPaymentEvidence {
  paymentEvidence: import("../dacs/standard-profile.js").SettlementEvidence;
  paymentEvidenceRef: AttestationRef;
  paymentEvidenceReceipt?: AnchorReceipt;
}

export interface PreparedRfqDeal {
  agreement: ChannelAgreement | AgreementDocument;
  agreementHash: string;
  sellerSignature: AgreementSignature | AgreementDocument["signatures"][number];
  buyerSignature: AgreementSignature | AgreementDocument["signatures"][number];
  terms: AuditTerms;
  payTo: string;
  amountOs: string;
  negotiation: NetworkedResult;
  identity?: { buyer: VettedParty; seller: VettedParty };
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
  settle(txHash: string, timeoutMs?: number, proof?: SettlementProof): Promise<Record<string, unknown>>;
  anchorPaymentEvidence(settlement: Record<string, unknown>): Promise<AnchoredPaymentEvidence>;
  requestDelivery(payment: AnchoredPaymentEvidence, timeoutMs?: number): Promise<RfqDelivery>;
  completeStandard(settlement: Record<string, unknown>, delivery: RfqDelivery, payment: AnchoredPaymentEvidence, timeoutMs?: number): Promise<{
    paymentEvidence: import("../dacs/standard-profile.js").SettlementEvidence;
    paymentEvidenceRef: AttestationRef;
    bundle: AttestationBundle;
    buyerBundleRef: string;
    sellerBundleRef: string;
    sellerBundle: AttestationBundle;
    sellerBundleReceipt?: AnchorReceipt;
  }>;
  abortStandard(reason: string, failedPhase?: import("../dacs/standard-profile.js").PhaseType): Promise<string | undefined>;
  fulfil(buyerDid: string, timeoutMs?: number): Promise<string>;
  close(): void;
}

export interface FixedBuyerInput {
  channelId: string;
  jobId: string;
  requestScope: Record<string, unknown>;
  /** Required only when the selected listing uses pay-x402. */
  x402Payer?: string;
  autoAcceptCommitment?: AutoAcceptCommitment;
  autoAcceptCommitmentRef?: string;
  autoAcceptCommitmentReceipt?: AnchorReceipt;
}

export interface PreparedFixedDeal {
  agreement: AgreementDocument;
  agreementHash: string;
  terms: AgreementDocument["terms"];
  payTo: string;
  amountOs: string;
  identity: NonNullable<PreparedRfqDeal["identity"]>;
  standardCommit: NonNullable<PreparedRfqDeal["standardCommit"]>;
  settle(txHash: string, timeoutMs?: number, proof?: SettlementProof): Promise<Record<string, unknown>>;
  anchorPaymentEvidence(settlement: Record<string, unknown>): Promise<AnchoredPaymentEvidence>;
  requestDelivery(payment: AnchoredPaymentEvidence, timeoutMs?: number): Promise<RfqDelivery>;
  completeStandard(settlement: Record<string, unknown>, delivery: RfqDelivery, payment: AnchoredPaymentEvidence, timeoutMs?: number): Promise<StandardCompletionResult>;
  abortStandard(reason: string, failedPhase?: import("../dacs/standard-profile.js").PhaseType): Promise<string | undefined>;
  close(): void;
}

export interface StandardCompletionResult {
  paymentEvidence: import("../dacs/standard-profile.js").SettlementEvidence;
  paymentEvidenceRef: AttestationRef;
  bundle: AttestationBundle;
  buyerBundleRef: string;
  sellerBundleRef: string;
  sellerBundle: AttestationBundle;
  sellerBundleReceipt?: AnchorReceipt;
}

export interface RecoverStandardInput {
  agreement: AgreementDocument;
  agreementHash: string;
  txHash: string;
  standardCommit: NonNullable<PreparedRfqDeal["standardCommit"]>;
  /** A distinct anchor preserves the original terminal abort bundle. */
  buyerBundleAnchorName: string;
  autoAcceptCommitment?: AutoAcceptCommitment;
}

export interface RecoveredStandardDeal {
  settlement: Record<string, unknown>;
  delivery: RfqDelivery;
  completion: StandardCompletionResult;
}

type Frame = Record<string, unknown>;

class BuyerChannel extends MailboxChannel {
  constructor(
    private readonly sendFrame: (frame: object) => Promise<void>,
    private readonly receiveFrame: (timeoutMs: number) => Promise<ChannelEnvelope>,
  ) { super(); }
  override async send(env: ChannelEnvelope): Promise<void> { await this.sendFrame(env); }
  override receive(timeoutMs = 30_000): Promise<ChannelEnvelope> { return this.receiveFrame(timeoutMs); }
}

export class RfqBuyerClient {
  private readonly frames: Frame[] = [];
  private waiter?: () => void;

  constructor(
    private readonly peer: MessagingPeerInstance,
    private readonly identity: PeerIdentity,
    private readonly sellerClientId = "dacs-auditor",
    private readonly channelSigner: Signer = identity.signer,
    private readonly standard?: StandardSessionContext,
  ) {
    this.peer.onMessage((message, fromId) => this.onMessage(message, fromId));
  }

  async connect(): Promise<void> {
    await this.peer.connect();
    await this.peer.discoverPeers?.();
  }

  close(): void {
    this.peer.disconnect?.();
  }

  /**
   * Resume a seller-persisted paid agreement without negotiating or paying
   * again. The seller first proves it still recognises the exact settlement,
   * then performs its idempotent delivery retry. Completion uses a distinct
   * buyer bundle anchor so a prior terminal abort record remains immutable.
   */
  async recoverStandard(input: RecoverStandardInput): Promise<RecoveredStandardDeal> {
    if (!this.standard) throw new Error("Standard recovery is unavailable for this client");
    const { agreement, agreementHash: hash, standardCommit } = input;
    if (standardAgreementHash(agreement) !== hash) throw new Error("recovery agreement hash is invalid");
    const agreementVerdict = await verifyAgreement(
      agreement,
      this.standard.listing,
      { ...cryptoDeps, ...(input.autoAcceptCommitment ? { autoAcceptCommitment: input.autoAcceptCommitment } : {}) },
    );
    if (!agreementVerdict.ok) throw new Error(`recovery agreement is invalid: ${agreementVerdict.reason}`);

    const buyerParty = agreement.parties.find((party) => party.role === "buyer");
    if (buyerParty?.primaryClaim !== this.standard.party.primaryClaim) throw new Error("recovery buyer does not match the connected wallet");
    const [agreementAddress, commitmentAddress] = await Promise.all([
      this.standard.sub.anchorAddressFor(buyerParty.primaryClaim, standardAnchorName("agreement", [agreement.jobId])),
      this.standard.sub.anchorAddressFor(buyerParty.primaryClaim, standardAnchorName("commitment", [agreement.jobId])),
    ]);
    const [anchoredAgreement, anchoredCommitment] = await Promise.all([
      this.standard.sub.read(agreementAddress),
      this.standard.sub.read(commitmentAddress),
    ]);
    const refsValid = standardCommit.agreementRef.anchor.kind === "storage-program"
      && standardCommit.agreementRef.anchor.locator === agreementAddress
      && standardCommit.agreementRef.contentHash === standardHash(agreement)
      && standardCommit.commitmentRef.anchor.kind === "storage-program"
      && standardCommit.commitmentRef.anchor.locator === commitmentAddress
      && standardCommit.commitmentRef.contentHash === standardHash(standardCommit.commitment)
      && anchoredAgreement !== null
      && standardHash(anchoredAgreement) === standardHash(agreement)
      && anchoredCommitment !== null
      && standardHash(anchoredCommitment) === standardHash(standardCommit.commitment);
    if (!refsValid || !(await verifyCommitment(
      standardCommit.commitment,
      agreement,
      this.standard.listing,
      { ...cryptoDeps, anchoredAt: standardCommit.committedAt },
    ))) {
      throw new Error("recovery commitment is invalid or not read-visible");
    }

    await this.send({ kind: "dacs-rfq-settle", protocol: PROTOCOL, agreementHash: hash, txHash: input.txHash });
    const settlement = await this.take(
      (frame) => frame.kind === "dacs-rfq-settled" && frame.agreementHash === hash,
      60_000,
    );
    if (stringField(settlement, "txHash").replace(/^0x/, "").toLowerCase() !== input.txHash.replace(/^0x/, "").toLowerCase()) {
      throw new Error("Auditor recovery settlement does not match the original payment");
    }

    const payment = await this.anchorStandardPaymentEvidence(agreement, settlement, true);
    await this.send({
      kind: "dacs-rfq-delivery-request",
      protocol: PROTOCOL,
      agreementHash: hash,
      recovery: true,
      paymentEvidence: payment.paymentEvidence,
      paymentEvidenceRef: payment.paymentEvidenceRef,
      paymentEvidenceReceipt: payment.paymentEvidenceReceipt,
    });
    const delivered = await this.take(
      (frame) => frame.kind === "dacs-rfq-delivered" && frame.agreementHash === hash,
      180_000,
    );
    const deliveryRef = stringField(delivered, "deliveryRef");
    if (!deliveryRef || !delivered.attestation || typeof delivered.attestation !== "object") {
      throw new Error("Auditor recovery delivery response is incomplete");
    }
    const delivery: RfqDelivery = {
      agreementHash: hash,
      txHash: stringField(delivered, "txHash"),
      deliveryRef,
      attestation: delivered.attestation as Record<string, unknown>,
      result: delivered.result,
      ...(delivered.deliveryEvidence ? { deliveryEvidence: delivered.deliveryEvidence as import("../dacs/standard-profile.js").SettlementEvidence } : {}),
      ...(delivered.deliveryEvidenceRef ? { deliveryEvidenceRef: delivered.deliveryEvidenceRef as AttestationRef } : {}),
      ...(delivered.anchorReceipt ? { anchorReceipt: delivered.anchorReceipt as AnchorReceipt } : {}),
      ...(delivered.deliveryEvidenceReceipt ? { deliveryEvidenceReceipt: delivered.deliveryEvidenceReceipt as AnchorReceipt } : {}),
    };
    const completion = await this.completeStandardDeal(
      agreement,
      hash,
      standardCommit,
      settlement,
      delivery,
      payment,
      180_000,
      input.buyerBundleAnchorName,
    );
    return { settlement, delivery, completion };
  }

  async negotiate(input: RfqBuyerInput): Promise<PreparedRfqDeal> {
    try {
      return await this.negotiateInner(input);
    } catch (error) {
      if (this.standard) await anchorAbortBundle(this.standard, input.jobId, (error as Error).message, "negotiate-rfq").catch(() => undefined);
      throw error;
    }
  }

  /**
   * Accept a posted fixed price over a live authenticated channel. Identity/Vet
   * remain two-sided, the seller signs the exact request-bound agreement, and
   * the durable RFQ settlement protocol is deliberately reused after DACS-3.
   */
  async negotiateFixed(input: FixedBuyerInput): Promise<PreparedFixedDeal> {
    if (!this.standard) throw new Error("fixed-price negotiation requires a Standard session context");
    if (this.standard.party.primaryClaim !== this.channelSigner.id) throw new Error("buyer channel signer is not its Standard primary claim");
    const sellerNonce = sessionNonce();
    await this.send({
      kind: "dacs-fixed-open",
      protocol: "dacs-fixed/1",
      channelId: input.channelId,
      jobId: input.jobId,
      buyerSignerId: this.channelSigner.id,
      requestScope: input.requestScope,
      listingAnchorRef: this.standard.listingAnchorRef,
      buyerPrimaryClaim: this.standard.party.primaryClaim,
      sellerNonce,
      ...(input.x402Payer ? { x402Payer: input.x402Payer } : {}),
    });
    const hello = await this.take((frame) => frame.kind === "dacs-fixed-hello" && frame.channelId === input.channelId, 30_000);
    const sellerSignerId = stringField(hello, "sellerSignerId");
    const payTo = stringField(hello, "payTo");
    const expectedSeller = this.standard.listing.seller.identity.presentedBy;
    if (sellerSignerId !== expectedSeller || !sameDemosParty(expectedSeller, payTo)) {
      throw new Error("fixed-price seller identity or payment address does not match its listing");
    }
    const buyerNonce = stringField(hello, "buyerNonce");
    const sellerBundle = hello.sellerBundle as IdentityBundle | undefined;
    if (!buyerNonce || !sellerBundle) throw new Error("fixed-price seller omitted the identity challenge exchange");
    await verifyPresentation(sellerBundle, sellerNonce, expectedSeller);
    if (isX402Rail(this.standard.listing.acceptedRails?.[0])) {
      await verifyX402IdentityBinding(sellerBundle, x402ListingTerms(this.standard.listing.acceptedRails?.[0]).payTo);
    }
    const buyerBundle = await presentIdentity(this.standard.party, buyerNonce, this.standard.identityMetadata);
    await this.send({
      kind: "dacs-fixed-identify-start",
      protocol: "dacs-fixed/1",
      channelId: input.channelId,
      buyerBundle,
    });
    const sellerVetted = await vetAndAnchor(this.standard, input.jobId, sellerBundle, emptyRequirement());
    await this.send({
      kind: "dacs-fixed-identify",
      protocol: "dacs-fixed/1",
      channelId: input.channelId,
      buyerBundle,
      sellerVetRecord: sellerVetted.vetRecord,
      sellerVetRecordRef: sellerVetted.vetRecordRef,
      sellerVetReceipt: sellerVetted.anchorReceipt,
    });
    const identified = await this.take((frame) => frame.kind === "dacs-fixed-identified" && frame.channelId === input.channelId, IDENTITY_RESPONSE_TIMEOUT_MS);
    const buyerVetRecord = identified.buyerVetRecord as CompositeVerificationRecord | undefined;
    const buyerVetRecordRef = identified.buyerVetRecordRef as AttestationRef | undefined;
    const buyerVetReceipt = identified.buyerVetReceipt as VetReceipt | undefined;
    if (!buyerVetRecord || !buyerVetRecordRef) throw new Error("fixed-price seller omitted the buyer Vet result");
    await verifyAnchoredVet(this.standard, {
      jobId: input.jobId,
      bundle: buyerBundle,
      requirement: this.standard.listing.buyerRequirement,
      verifier: expectedSeller,
      record: buyerVetRecord,
      ref: buyerVetRecordRef,
      receipt: buyerVetReceipt,
    });
    const identity = {
      buyer: { bundle: buyerBundle, vetRecord: buyerVetRecord, vetRecordRef: buyerVetRecordRef, ...(buyerVetReceipt ? { anchorReceipt: buyerVetReceipt } : {}) },
      seller: sellerVetted,
    };
    await this.take((frame) => frame.kind === "dacs-fixed-ready" && frame.channelId === input.channelId, 30_000);

    let offeredFrame: Frame | undefined;
    const fixed = await runFixedPriceNegotiation({
      jobId: input.jobId,
      listing: this.standard.listing,
      listingAnchorRef: this.standard.listingAnchorRef,
      buyer: identity.buyer,
      seller: identity.seller,
      buyerParty: this.standard.party,
      buyerSubstrate: this.standard.sub,
      requestScope: input.requestScope,
      ...(input.x402Payer ? { x402Payer: input.x402Payer } : {}),
      ...(input.autoAcceptCommitment ? { autoAcceptCommitment: input.autoAcceptCommitment } : {}),
      ...(input.autoAcceptCommitmentRef ? { autoAcceptCommitmentRef: input.autoAcceptCommitmentRef } : {}),
      ...(input.autoAcceptCommitmentReceipt ? { autoAcceptCommitmentReceipt: input.autoAcceptCommitmentReceipt } : {}),
      sellerSign: async ({ agreement, requestHash }) => {
        await this.send({
          kind: "dacs-fixed-sign",
          protocol: "dacs-fixed/1",
          channelId: input.channelId,
          agreement,
          requestHash,
        });
        offeredFrame = await this.take((frame) => frame.kind === "dacs-fixed-agreement" && frame.channelId === input.channelId, 30_000);
        const signed = offeredFrame.agreement;
        if (!signed || typeof signed !== "object" || !isStandardAgreement(signed)) throw new Error("fixed-price seller returned an invalid agreement");
        return signed;
      },
    });
    if (!offeredFrame) throw new Error("fixed-price seller did not return payment terms");
    if (stringField(offeredFrame, "agreementHash") !== fixed.agreementHash) throw new Error("fixed-price seller changed the agreement hash");
    const amountOs = stringField(offeredFrame, "amountOs");
    const paymentTerms = validatePaymentRequiredFrame(fixed.agreement, offeredFrame, payTo, amountOs);
    const standardCommit: NonNullable<PreparedRfqDeal["standardCommit"]> = {
      agreementRef: fixed.agreementRef,
      agreementAnchorTxRef: fixed.agreementReceipt.txRef,
      commitment: fixed.commitment,
      commitmentRef: fixed.commitmentRef,
      anchorTxRef: fixed.commitmentReceipt.txRef,
      committedAt: fixed.commitmentReceipt.anchoredAt,
      ...(fixed.commitmentReceipt.blockNumber === undefined ? {} : { commitmentBlockNumber: fixed.commitmentReceipt.blockNumber }),
      ...(fixed.commitmentReceipt.nonce === undefined ? {} : { commitmentNonce: fixed.commitmentReceipt.nonce }),
      ...(fixed.agreementReceipt.transactionContent === undefined ? {} : { agreementTransactionContent: fixed.agreementReceipt.transactionContent }),
      ...(fixed.commitmentReceipt.transactionContent === undefined ? {} : { commitmentTransactionContent: fixed.commitmentReceipt.transactionContent }),
      ...(fixed.agreementReceipt.expectedConfirmationBlock === undefined ? {} : { agreementExpectedConfirmationBlock: fixed.agreementReceipt.expectedConfirmationBlock }),
      ...(fixed.commitmentReceipt.expectedConfirmationBlock === undefined ? {} : { commitmentExpectedConfirmationBlock: fixed.commitmentReceipt.expectedConfirmationBlock }),
      ...(fixed.agreementReceipt.transactionContentValueOmitted ? { agreementTransactionContentValueOmitted: true } : {}),
      ...(fixed.commitmentReceipt.transactionContentValueOmitted ? { commitmentTransactionContentValueOmitted: true } : {}),
    };
    await this.send({
      kind: "dacs-rfq-agreement-accept",
      protocol: PROTOCOL,
      agreementHash: fixed.agreementHash,
      agreement: fixed.agreement,
      ...standardCommit,
    });
    const required = await this.take((frame) => frame.kind === "dacs-rfq-payment-required" && frame.agreementHash === fixed.agreementHash, 30_000);
    validatePaymentRequiredFrame(fixed.agreement, required, payTo, amountOs);

    return {
      agreement: fixed.agreement,
      agreementHash: fixed.agreementHash,
      terms: fixed.agreement.terms,
      payTo: paymentTerms.payTo,
      amountOs,
      identity,
      standardCommit,
      settle: async (txHash, timeoutMs = 180_000, proof) => {
        await this.send({ kind: "dacs-rfq-settle", protocol: PROTOCOL, agreementHash: fixed.agreementHash, txHash, ...(proof ? { paymentProof: proof } : {}) });
        return this.take((frame) => frame.kind === "dacs-rfq-settled" && frame.agreementHash === fixed.agreementHash, timeoutMs);
      },
      anchorPaymentEvidence: async (settlement) => this.anchorStandardPaymentEvidence(fixed.agreement, settlement),
      requestDelivery: async (payment, timeoutMs = 180_000) => {
        await this.send({
          kind: "dacs-rfq-delivery-request",
          protocol: PROTOCOL,
          agreementHash: fixed.agreementHash,
          paymentEvidence: payment.paymentEvidence,
          paymentEvidenceRef: payment.paymentEvidenceRef,
          paymentEvidenceReceipt: payment.paymentEvidenceReceipt,
        });
        const delivered = await this.take((frame) => frame.kind === "dacs-rfq-delivered" && frame.agreementHash === fixed.agreementHash, timeoutMs);
        const deliveryRef = stringField(delivered, "deliveryRef");
        if (!deliveryRef || !delivered.attestation || typeof delivered.attestation !== "object") throw new Error("fixed-price seller delivery response is incomplete");
        return {
          agreementHash: fixed.agreementHash,
          txHash: stringField(delivered, "txHash"),
          deliveryRef,
          attestation: delivered.attestation as Record<string, unknown>,
          result: delivered.result,
          ...(delivered.deliveryEvidence ? { deliveryEvidence: delivered.deliveryEvidence as import("../dacs/standard-profile.js").SettlementEvidence } : {}),
          ...(delivered.deliveryEvidenceRef ? { deliveryEvidenceRef: delivered.deliveryEvidenceRef as AttestationRef } : {}),
          ...(delivered.anchorReceipt ? { anchorReceipt: delivered.anchorReceipt as AnchorReceipt } : {}),
          ...(delivered.deliveryEvidenceReceipt ? { deliveryEvidenceReceipt: delivered.deliveryEvidenceReceipt as AnchorReceipt } : {}),
        };
      },
      completeStandard: async (settlement, delivery, payment, timeoutMs = 180_000) => this.completeStandardDeal(
        fixed.agreement,
        fixed.agreementHash,
        standardCommit,
        settlement,
        delivery,
        payment,
        timeoutMs,
      ),
      abortStandard: async (reason, failedPhase = "deliver-attested-payload") => anchorAbortBundle(this.standard!, fixed.agreement.jobId, reason, failedPhase),
      close: () => this.peer.disconnect?.(),
    };
  }

  private async negotiateInner(input: RfqBuyerInput): Promise<PreparedRfqDeal> {
    if (this.standard && this.standard.party.primaryClaim !== this.channelSigner.id) throw new Error("buyer channel signer is not its Standard primary claim");
    const maxTurns = input.maxTurns ?? 6;
    const channel = new BuyerChannel(
      (frame) => this.send(frame),
      async (timeoutMs) => await this.take(
        (candidate) => candidate.channelId === input.channelId && typeof candidate.sequence === "number" && candidate.body !== undefined,
        timeoutMs,
      ) as unknown as ChannelEnvelope,
    );
    const sellerNonce = this.standard ? sessionNonce() : undefined;
    await this.send({
      kind: "dacs-rfq-open", protocol: PROTOCOL, channelId: input.channelId,
      jobId: input.jobId, buyerSignerId: this.channelSigner.id, repo: input.repo,
      files: input.files, scan: scanFor(input.files), maxTurns,
      ...(this.standard ? {
        listingAnchorRef: this.standard.listingAnchorRef,
        buyerPrimaryClaim: this.standard.party.primaryClaim,
        sellerNonce,
        ...(input.x402Payer ? { x402Payer: input.x402Payer } : {}),
      } : {}),
    });
    const hello = await this.take((frame) => frame.kind === "dacs-rfq-hello" && frame.channelId === input.channelId, 30_000);
    const sellerSignerId = stringField(hello, "sellerSignerId");
    const payTo = stringField(hello, "payTo");
    if (!sellerSignerId || !payTo) throw new Error("Auditor hello omitted its signer or payment address");

    let exchangedIdentity: PreparedRfqDeal["identity"];
    if (this.standard) {
      const expectedSeller = this.standard.listing.seller.identity.presentedBy;
      if (sellerSignerId !== expectedSeller) throw new Error("Auditor channel signer does not match its anchored listing");
      if (!sameDemosParty(expectedSeller, payTo)) throw new Error("Auditor payment address does not match its Standard primary claim");
      const buyerNonce = stringField(hello, "buyerNonce");
      const sellerBundle = hello.sellerBundle as IdentityBundle | undefined;
      if (!buyerNonce || !sellerBundle || !sellerNonce) throw new Error("Auditor omitted the Standard identity challenge exchange");
      await verifyPresentation(sellerBundle, sellerNonce, expectedSeller);
      if (isX402Rail(this.standard.listing.acceptedRails?.[0])) {
        await verifyX402IdentityBinding(sellerBundle, x402ListingTerms(this.standard.listing.acceptedRails?.[0]).payTo);
      }
      const buyerBundle = await presentIdentity(this.standard.party, buyerNonce, this.standard.identityMetadata);
      // Give the seller our nonce-bound presentation immediately. It can Vet
      // and anchor the buyer on its own wallet while this buyer independently
      // Vets and anchors the seller. No same-wallet nonce ordering is relaxed.
      await this.send({
        kind: "dacs-rfq-identify-start",
        protocol: PROTOCOL,
        channelId: input.channelId,
        buyerBundle,
      });
      const researcherProfile = securityResearcherProfileFromListing(this.standard.listing);
      if (this.standard.listing.listingId.startsWith("audit-negotiator") && !researcherProfile) {
        throw new Error("Auditor listing does not carry a signed security researcher profile");
      }
      if (researcherProfile && !this.standard.securityResearcherVet) {
        throw new Error("buyer cannot evaluate the Auditor security researcher profile");
      }
      const researcherEvidence = researcherProfile && this.standard.securityResearcherVet
        ? await Promise.all([
          this.standard.securityResearcherVet.githubLoginFor(expectedSeller),
          this.standard.securityResearcherVet.historyFor(expectedSeller),
        ])
        : undefined;
      const sellerRequirement = researcherProfile
        ? securityResearcherRequirement(researcherProfile)
        : emptyRequirement();
      const sellerVetted = await vetAndAnchor(
        this.standard,
        input.jobId,
        sellerBundle,
        sellerRequirement,
        researcherProfile && researcherEvidence
          ? ({ verifier, jobId, bundle }) => createSecurityResearcherVetRecord(verifier, {
            jobId,
            bundle,
            profile: researcherProfile,
            boundGithub: researcherEvidence[0],
            history: researcherEvidence[1],
          })
          : undefined,
      );
      await this.send({
        kind: "dacs-rfq-identify",
        protocol: PROTOCOL,
        channelId: input.channelId,
        // Repeat the small signed presentation for rolling deployments. New
        // sellers already started Vet from identify-start; an older seller can
        // still complete the safe serial exchange instead of failing closed.
        buyerBundle,
        sellerVetRecord: sellerVetted.vetRecord,
        sellerVetRecordRef: sellerVetted.vetRecordRef,
        sellerVetReceipt: sellerVetted.anchorReceipt,
      });
      const identified = await this.take((frame) => frame.kind === "dacs-rfq-identified" && frame.channelId === input.channelId, IDENTITY_RESPONSE_TIMEOUT_MS);
      const buyerVetRecord = identified.buyerVetRecord as CompositeVerificationRecord | undefined;
      const buyerVetRecordRef = identified.buyerVetRecordRef as AttestationRef | undefined;
      const buyerVetReceipt = identified.buyerVetReceipt as VetReceipt | undefined;
      if (!buyerVetRecord || !buyerVetRecordRef) throw new Error("Auditor omitted the buyer Vet result");
      await verifyAnchoredVet(this.standard, {
        jobId: input.jobId,
        bundle: buyerBundle,
        requirement: this.standard.listing.buyerRequirement,
        verifier: expectedSeller,
        record: buyerVetRecord,
        ref: buyerVetRecordRef,
        receipt: buyerVetReceipt,
      });
      exchangedIdentity = {
        buyer: { bundle: buyerBundle, vetRecord: buyerVetRecord, vetRecordRef: buyerVetRecordRef, ...(buyerVetReceipt ? { anchorReceipt: buyerVetReceipt } : {}) },
        seller: sellerVetted,
      };
    }

    const acceptableTiers = input.acceptableTiers ?? [input.preferredTier ?? "quick"];
    const guard: BuyerGuard = {
      offeredTiers: ["quick", "deep"], offeredDeadlines: ["standard", "rush"],
      budget: input.budgetDem, acceptableTiers,
    };
    const negotiation = await runSide({
      role: "buyer", channelId: input.channelId,
      policy: deterministicBuyer({ guard, preferredTier: input.preferredTier ?? "quick", preferredDeadline: input.preferredDeadline ?? "standard" }),
      maySettle: (terms) => buyerMaySettle(terms, guard), peerSenderId: sellerSignerId,
      signer: this.channelSigner, channel, maxTurns, recvTimeoutMs: 35_000,
    });
    if (negotiation.outcome !== "agreed" || !negotiation.agreed) throw new Error(`Auditor negotiation ${negotiation.outcome}: ${negotiation.reason}`);

    const offered = await this.take((frame) => frame.kind === "dacs-rfq-agreement" && frame.channelId === input.channelId, 30_000);
    const offeredAgreement = offered.agreement as ChannelAgreement | AgreementDocument | undefined;
    const hash = stringField(offered, "agreementHash");
    const offeredSellerSignature = offered.sellerSignature as AgreementSignature | AgreementDocument["signatures"][number] | undefined;
    const amountOs = stringField(offered, "amountOs");
    if (!offeredAgreement || !offeredSellerSignature || !hash || !amountOs) throw new Error("Auditor returned an incomplete agreement");
    const offeredPaymentTerms = validatePaymentRequiredFrame(offeredAgreement, offered, payTo, amountOs);
    let agreement: ChannelAgreement | AgreementDocument;
    let sellerSignature: PreparedRfqDeal["sellerSignature"];
    let buyerSignature: PreparedRfqDeal["buyerSignature"];
    let agreedTerms: AuditTerms;
    let standardCommit: PreparedRfqDeal["standardCommit"];
    if (this.standard) {
      if (!isStandardAgreement(offeredAgreement) || !exchangedIdentity) throw new Error("Auditor did not return a Standard AgreementDocument");
      if (standardAgreementHash(offeredAgreement) !== hash || offeredAgreement.jobId !== input.jobId || offeredAgreement.derivedFromChannel?.subnet !== input.channelId) throw new Error("Auditor agreement binding is invalid");
      const buyerAgreementParty = offeredAgreement.parties.find((party) => party.role === "buyer");
      const sellerAgreementParty = offeredAgreement.parties.find((party) => party.role === "seller");
      if (buyerAgreementParty?.primaryClaim !== this.channelSigner.id || sellerAgreementParty?.primaryClaim !== sellerSignerId) throw new Error("Auditor agreement parties do not match the channel");
      const identityBindingsValid = buyerAgreementParty.bundleHash === standardHash(exchangedIdentity.buyer.bundle, ["presentation"])
        && sellerAgreementParty.bundleHash === standardHash(exchangedIdentity.seller.bundle, ["presentation"])
        && standardHash(buyerAgreementParty.vetRecordRef) === standardHash(exchangedIdentity.buyer.vetRecordRef)
        && standardHash(sellerAgreementParty.vetRecordRef) === standardHash(exchangedIdentity.seller.vetRecordRef);
      if (!identityBindingsValid) throw new Error("Auditor agreement does not bind the exchanged identity and Vet artifacts");
      agreedTerms = auditTermsFromStandardAgreement(offeredAgreement);
      if (JSON.stringify(agreedTerms) !== JSON.stringify(negotiation.agreed)) throw new Error("Auditor agreement terms differ from the signed transcript");
      const expectedRequestHash = requestScopeHash({ files: input.files, negotiatedTerms: negotiation.agreed, repo: input.repo });
      if (offeredAgreement.terms.additionalTerms?.requestHash !== expectedRequestHash) {
        throw new Error("Auditor agreement does not bind the posted work request");
      }
      const sellerVerdict = await verifyStandardAgreement(offeredAgreement, this.standard.listing, ["seller"]);
      if (!sellerVerdict.ok) throw new Error(`Auditor agreement signature is invalid: ${sellerVerdict.reason}`);
      agreement = await signStandardAgreement(offeredAgreement, this.standard.party);
      sellerSignature = agreement.signatures.find((signature) => signature.party === sellerSignerId)!;
      buyerSignature = agreement.signatures.find((signature) => signature.party === this.channelSigner.id)!;
      const agreementName = standardAnchorName("agreement", [input.jobId]);
      const commitmentName = standardAnchorName("commitment", [input.jobId]);
      const [agreementAddress, commitmentAddress] = await Promise.all([
        this.standard.sub.anchorAddress(agreementName),
        this.standard.sub.anchorAddress(commitmentName),
      ]);
      const [existingAgreement, existingCommitment] = await Promise.all([
        this.standard.sub.read(agreementAddress),
        this.standard.sub.read(commitmentAddress),
      ]);
      if (existingAgreement || existingCommitment) throw new Error("Commitment rejected: jobId already has an agreement or commitment anchor");
      if (!this.standard.sub.anchorWithReceipt) throw new Error("the buyer substrate cannot return objective SR-2 receipts");
      const commitment = await createCommitment(this.standard.party, agreement);
      if (!(await verifyCommitment(commitment, agreement, this.standard.listing, cryptoDeps))) throw new Error("locally produced commitment failed Standard verification");
      const [agreementReceipt, receipt] = this.standard.sub.anchorBatchWithReceipts
        ? await this.standard.sub.anchorBatchWithReceipts([
          { name: agreementName, value: agreement },
          { name: commitmentName, value: commitment },
        ])
        : [
          await this.standard.sub.anchorWithReceipt(agreementName, agreement),
          await this.standard.sub.anchorWithReceipt(commitmentName, commitment),
        ];
      const agreementRef = attestationRef(agreementReceipt.address, agreement, this.standard.party.primaryClaim);
      if (!(await verifyCommitment(commitment, agreement, this.standard.listing, { ...cryptoDeps, anchoredAt: receipt.anchoredAt }))) {
        throw new Error("commitment failed the authoritative post-anchor timing checks");
      }
      standardCommit = {
        agreementRef,
        agreementAnchorTxRef: agreementReceipt.txRef,
        commitment,
        commitmentRef: attestationRef(receipt.address, commitment, this.standard.party.primaryClaim),
        anchorTxRef: receipt.txRef,
        committedAt: receipt.anchoredAt,
        ...(receipt.blockNumber === undefined ? {} : { commitmentBlockNumber: receipt.blockNumber }),
        ...(receipt.nonce === undefined ? {} : { commitmentNonce: receipt.nonce }),
        ...(agreementReceipt.transactionContent === undefined ? {} : { agreementTransactionContent: agreementReceipt.transactionContent }),
        ...(receipt.transactionContent === undefined ? {} : { commitmentTransactionContent: receipt.transactionContent }),
        ...(agreementReceipt.expectedConfirmationBlock === undefined ? {} : { agreementExpectedConfirmationBlock: agreementReceipt.expectedConfirmationBlock }),
        ...(receipt.expectedConfirmationBlock === undefined ? {} : { commitmentExpectedConfirmationBlock: receipt.expectedConfirmationBlock }),
        ...(agreementReceipt.transactionContentValueOmitted ? { agreementTransactionContentValueOmitted: true } : {}),
        ...(receipt.transactionContentValueOmitted ? { commitmentTransactionContentValueOmitted: true } : {}),
      };
    } else {
      if (isStandardAgreement(offeredAgreement)) throw new Error("Auditor unexpectedly returned a Standard agreement on a legacy session");
      const legacySellerSignature = offeredSellerSignature as AgreementSignature;
      if (agreementHash(offeredAgreement) !== hash || offeredAgreement.jobId !== input.jobId || offeredAgreement.channelId !== input.channelId) throw new Error("Auditor agreement binding is invalid");
      if (offeredAgreement.parties.buyer !== this.channelSigner.id || offeredAgreement.parties.seller !== sellerSignerId) throw new Error("Auditor agreement parties do not match the channel");
      if (JSON.stringify(offeredAgreement.terms) !== JSON.stringify(negotiation.agreed)) throw new Error("Auditor agreement terms differ from the signed transcript");
      if (!(await verifyAgreementSignature(this.channelSigner, offeredAgreement, legacySellerSignature))) throw new Error("Auditor agreement signature is invalid");
      agreement = offeredAgreement;
      agreedTerms = offeredAgreement.terms;
      sellerSignature = legacySellerSignature;
      buyerSignature = await signAgreement(this.channelSigner, "buyer", offeredAgreement);
    }
    await this.send({
      kind: "dacs-rfq-agreement-accept",
      protocol: PROTOCOL,
      agreementHash: hash,
      agreement,
      buyerSignature,
      ...(standardCommit ?? {}),
    });
    const required = await this.take((frame) => frame.kind === "dacs-rfq-payment-required" && frame.agreementHash === hash, 30_000);
    validatePaymentRequiredFrame(agreement, required, payTo, amountOs);

    return {
      agreement, agreementHash: hash, sellerSignature, buyerSignature, terms: agreedTerms, payTo: offeredPaymentTerms.payTo, amountOs, negotiation,
      ...(exchangedIdentity ? { identity: exchangedIdentity } : {}),
      ...(standardCommit ? { standardCommit } : {}),
      settle: async (txHash, timeoutMs = 180_000, proof) => {
        await this.send({ kind: "dacs-rfq-settle", protocol: PROTOCOL, agreementHash: hash, txHash, ...(proof ? { paymentProof: proof } : {}) });
        return this.take((frame) => frame.kind === "dacs-rfq-settled" && frame.agreementHash === hash, timeoutMs);
      },
      anchorPaymentEvidence: async (settlement) => {
        if (!this.standard || !isStandardAgreement(agreement)) throw new Error("Standard payment evidence is unavailable for this session");
        return this.anchorStandardPaymentEvidence(agreement, settlement);
      },
      requestDelivery: async (payment, timeoutMs = 180_000) => {
        await this.send({
          kind: "dacs-rfq-delivery-request",
          protocol: PROTOCOL,
          agreementHash: hash,
          paymentEvidence: payment.paymentEvidence,
          paymentEvidenceRef: payment.paymentEvidenceRef,
          paymentEvidenceReceipt: payment.paymentEvidenceReceipt,
        });
        const delivered = await this.take((frame) => frame.kind === "dacs-rfq-delivered" && frame.agreementHash === hash, timeoutMs);
        const deliveryRef = stringField(delivered, "deliveryRef");
        if (!deliveryRef || !delivered.attestation || typeof delivered.attestation !== "object") throw new Error("Auditor delivery response is incomplete");
        return {
          agreementHash: hash,
          txHash: stringField(delivered, "txHash"),
          deliveryRef,
          attestation: delivered.attestation as Record<string, unknown>,
          result: delivered.result,
          ...(delivered.deliveryEvidence ? { deliveryEvidence: delivered.deliveryEvidence as import("../dacs/standard-profile.js").SettlementEvidence } : {}),
          ...(delivered.deliveryEvidenceRef ? { deliveryEvidenceRef: delivered.deliveryEvidenceRef as AttestationRef } : {}),
          ...(delivered.anchorReceipt ? { anchorReceipt: delivered.anchorReceipt as AnchorReceipt } : {}),
          ...(delivered.deliveryEvidenceReceipt ? { deliveryEvidenceReceipt: delivered.deliveryEvidenceReceipt as AnchorReceipt } : {}),
        };
      },
      completeStandard: async (settlement, delivery, payment, timeoutMs = 180_000) => {
        if (!this.standard || !isStandardAgreement(agreement) || !exchangedIdentity || !standardCommit) throw new Error("Standard completion is unavailable for this session");
        return this.completeStandardDeal(agreement, hash, standardCommit, settlement, delivery, payment, timeoutMs);
      },
      abortStandard: async (reason, failedPhase = "deliver-attested-payload") => this.standard
        ? anchorAbortBundle(this.standard, agreement.jobId, reason, failedPhase)
        : undefined,
      fulfil: async (buyerDid, timeoutMs = 180_000) => {
        await this.send({ kind: "dacs-rfq-fulfil", protocol: PROTOCOL, agreementHash: hash, buyerDid });
        const frame = await this.take((candidate) => candidate.kind === "dacs-rfq-fulfilled" && candidate.agreementHash === hash, timeoutMs);
        const ref = stringField(frame, "sellerBundleRef");
        if (!ref) throw new Error("Auditor fulfilment response omitted its seller bundle");
        return ref;
      },
      close: () => this.peer.disconnect?.(),
    };
  }

  private async anchorStandardPaymentEvidence(
    agreement: AgreementDocument,
    settlement: Record<string, unknown>,
    reuseExisting = false,
  ): Promise<AnchoredPaymentEvidence> {
    if (!this.standard) throw new Error("Standard payment evidence is unavailable for this session");
    const buyerParty = agreement.parties.find((party) => party.role === "buyer");
    if (buyerParty?.primaryClaim !== this.standard.party.primaryClaim) throw new Error("payment evidence buyer does not match the connected wallet");
    const txHash = stringField(settlement, "txHash").replace(/^0x/, "").toLowerCase();
    const x402 = isX402Rail(agreement.terms.rail);
    const blockNumber = Number(settlement.blockNumber);
    const logIndex = Number(settlement.logIndex);
    const receiptHash = stringField(settlement, "paymentReceiptHash").replace(/^0x/, "").toLowerCase();
    if (!/^[0-9a-f]{64}$/i.test(txHash)) throw new Error("settlement receipt omitted its transaction hash");
    if (x402) {
      if (!/^[0-9a-f]{64}$/i.test(receiptHash)) throw new Error("x402 settlement omitted its payment receipt hash");
      if (!Number.isSafeInteger(logIndex) || logIndex < 0) throw new Error("x402 settlement omitted its USDC Transfer log index");
    } else if (!Number.isSafeInteger(blockNumber) || blockNumber < 0) {
      throw new Error("settlement receipt omitted its Demos inclusion proof");
    }

    const paymentPhase = paymentPhaseForAgreement(agreement);
    const paymentPhaseIndex = this.standard.listing.pipeline.findIndex((phase) => phase.kind === paymentPhase);
    if (paymentPhaseIndex < 0) throw new Error(`listing omitted its ${paymentPhase} phase`);
    if (x402 && x402AgreementTerms(agreement).phaseIndex !== paymentPhaseIndex) {
      throw new Error("x402 agreement phaseIndex does not match the selected listing phase");
    }
    const railId = agreement.terms.rail?.railId;
    if (!railId) throw new Error("agreement omitted its payment rail id");
    const paymentName = standardPaymentAnchorName(agreement.jobId, railId, paymentPhaseIndex);
    const railType = x402 ? "x402" : "demos-native";
    if (reuseExisting) {
      const existingLocator = await this.standard.sub.anchorAddress(paymentName);
      const raw = await this.standard.sub.read(existingLocator);
      if (raw) {
        const existing = raw as unknown as import("../dacs/standard-profile.js").SettlementEvidence;
        const existingVerdict = await verifyEvidence(existing, {
          orchestrator: this.standard.party.primaryClaim,
          agreement,
          railType,
          railId: agreement.terms.rail?.railId ?? "",
          ...cryptoDeps,
        });
        const exactPayment = existing.phase === paymentPhase
          && existing.outcome === "success"
          && existing.paymentTxRefs?.some((candidate) => x402
            ? candidate.kind === "x402"
              && candidate.settlementTxHash?.replace(/^0x/, "").toLowerCase() === txHash
              && candidate.paymentReceiptHash.replace(/^0x/, "").toLowerCase() === receiptHash
              && candidate.chainId === BASE_SEPOLIA_CHAIN_ID
              && candidate.logIndex === logIndex
            : candidate.kind === "demos"
              && candidate.txHash.replace(/^0x/, "").toLowerCase() === txHash
              && candidate.blockNumber === blockNumber) === true;
        if (!existingVerdict.ok || !exactPayment) {
          throw new Error(`existing payment evidence does not prove this settlement: ${existingVerdict.reasons.join("; ")}`);
        }
        return {
          paymentEvidence: existing,
          paymentEvidenceRef: attestationRef(existingLocator, existing, this.standard.party.primaryClaim),
        };
      }
    }
    const paymentEvidence = await signSettlementEvidence({
      evidenceVersion: "1",
      jobId: agreement.jobId,
      phase: paymentPhase,
      outcome: "success",
      paymentTxRefs: x402
        ? [{
            kind: "x402",
            httpResource: x402AgreementTerms(agreement).resource,
            paymentReceiptHash: receiptHash,
            settlementTxHash: `0x${txHash}`,
            chainId: BASE_SEPOLIA_CHAIN_ID,
            logIndex,
            protocolVersion: "2",
          }]
        : [{ kind: "demos", txHash, blockNumber }],
      paymentAmount: agreement.terms.price,
      settlementFinality: x402
        ? { model: "block-depth", finalityBlocks: 1, finalityObservedAt: Date.now() }
        : { model: "bft-final", finalityObservedAt: Date.now() },
      observedAt: Date.now(),
    }, this.standard.party);
    const paymentVerdict = await verifyEvidence(paymentEvidence, {
      orchestrator: this.standard.party.primaryClaim,
      agreement,
      railType,
      railId: agreement.terms.rail?.railId ?? "",
      ...cryptoDeps,
    });
    if (!paymentVerdict.ok) throw new Error(`payment evidence failed Standard verification: ${paymentVerdict.reasons.join("; ")}`);
    const paymentReceipt = this.standard.sub.anchorWithReceipt
      ? await this.standard.sub.anchorWithReceipt(paymentName, paymentEvidence)
      : undefined;
    const locator = paymentReceipt?.address ?? await this.standard.sub.anchor(paymentName, paymentEvidence);
    return {
      paymentEvidence,
      paymentEvidenceRef: attestationRef(locator, paymentEvidence, this.standard.party.primaryClaim),
      ...(paymentReceipt ? { paymentEvidenceReceipt: paymentReceipt } : {}),
    };
  }

  private async completeStandardDeal(
    agreement: AgreementDocument,
    hash: string,
    standardCommit: NonNullable<PreparedRfqDeal["standardCommit"]>,
    settlement: Record<string, unknown>,
    delivery: RfqDelivery,
    payment: AnchoredPaymentEvidence,
    timeoutMs: number,
    buyerBundleAnchorName = standardAnchorName("bundle", [agreement.jobId, "buyer"]),
  ): Promise<StandardCompletionResult> {
        if (!this.standard) throw new Error("Standard completion is unavailable for this session");
        const buyerParty = agreement.parties.find((party) => party.role === "buyer");
        const sellerParty = agreement.parties.find((party) => party.role === "seller");
        if (!buyerParty?.vetRecordRef || !sellerParty?.vetRecordRef) throw new Error("Standard agreement omitted its vetted party bindings");
        void settlement;
        const { paymentEvidence, paymentEvidenceRef, paymentEvidenceReceipt } = payment;

        if (!delivery.deliveryEvidence || !delivery.deliveryEvidenceRef) throw new Error("Auditor omitted Standard delivery evidence");
        const finalisedAt = Number(delivery.deliveryEvidence.observedAt);
        if (!Number.isSafeInteger(finalisedAt) || finalisedAt < 0) {
          throw new Error("delivery evidence omitted its stable observedAt timestamp");
        }
        const deliveryVerdict = await verifyEvidence(delivery.deliveryEvidence, {
          orchestrator: this.standard.listing.seller.identity.presentedBy,
          agreement,
          railType: isX402Rail(agreement.terms.rail) ? "x402" : "demos-native",
          railId: agreement.terms.rail?.railId ?? "",
          ...cryptoDeps,
        });
        await verifyConfirmedAnchor(
          this.standard.sub,
          delivery.deliveryEvidenceRef.anchor.locator,
          delivery.deliveryEvidence as unknown as Record<string, unknown>,
          delivery.deliveryEvidenceReceipt,
          sellerParty.primaryClaim,
        );
        if (delivery.anchorReceipt) {
          await verifyConfirmedAnchor(
            this.standard.sub,
            delivery.deliveryRef,
            delivery.attestation,
            delivery.anchorReceipt,
            sellerParty.primaryClaim,
          );
        }
        if (!deliveryVerdict.ok || standardHash(delivery.deliveryEvidence) !== delivery.deliveryEvidenceRef.contentHash) {
          throw new Error(`delivery evidence failed Standard verification: ${deliveryVerdict.reasons.join("; ")}`);
        }

        const phaseIndex = (kind: string): number => {
          const index = this.standard!.listing.pipeline.findIndex((phase) => phase.kind === kind);
          if (index < 0) throw new Error(`selected listing omitted ${kind}`);
          return index;
        };
        const negotiationPhase = this.standard.listing.pipeline.find((phase) => phase.kind.startsWith("negotiate-"))?.kind;
        if (!negotiationPhase) throw new Error("selected listing omitted its negotiation phase");
        const bundleBody: AttestationBundle = {
          bundleVersion: "1",
          jobId: agreement.jobId,
          outcome: "completed",
          anchoredByRole: "buyer",
          listingRef: listingRef(this.standard.listing),
          agreementRef: standardCommit.agreementRef,
          parties: [
            { role: "buyer", bundleHash: buyerParty.bundleHash, primaryClaim: buyerParty.primaryClaim },
            { role: "seller", bundleHash: sellerParty.bundleHash, primaryClaim: sellerParty.primaryClaim },
          ],
          phaseSummary: [
            { index: phaseIndex("vet-credentials"), kind: "vet-credentials", outcome: "ok" },
            { index: phaseIndex(negotiationPhase), kind: negotiationPhase, outcome: "ok" },
            { index: phaseIndex("commit-agreement"), kind: "commit-agreement", outcome: "ok", attestationRef: standardCommit.commitmentRef },
            { index: phaseIndex(paymentPhaseForAgreement(agreement)), kind: paymentPhaseForAgreement(agreement), outcome: "ok", txRefs: paymentEvidence.paymentTxRefs, attestationRef: paymentEvidenceRef },
            { index: phaseIndex("deliver-attested-payload"), kind: "deliver-attested-payload", outcome: "ok", attestationRef: delivery.deliveryEvidenceRef },
          ],
          vetRecords: [buyerParty.vetRecordRef, sellerParty.vetRecordRef],
          settlementEvidence: [paymentEvidenceRef, delivery.deliveryEvidenceRef],
          recipeRegistryVersion: 1,
          railRegistryVersion: 1,
          // A lost fulfilment response must reconstruct byte-identical bundle
          // content. Delivery evidence is signed and idempotently persisted by
          // the seller, so its observedAt is the stable completion clock;
          // Date.now() made restart recovery produce a different bundle hash.
          finalisedAt,
          signatures: [],
        };
        const buyerSigned = await addBundleSignature(bundleBody, this.standard.party);
        await this.send({
          kind: "dacs-rfq-fulfil",
          protocol: PROTOCOL,
          agreementHash: hash,
          buyerDid: this.standard.party.primaryClaim,
          bundle: buyerSigned,
          paymentEvidence,
          paymentEvidenceReceipt,
        });
        const first = await this.take(
          (candidate) =>
            (candidate.kind === "dacs-rfq-fulfil-ready" || candidate.kind === "dacs-rfq-fulfilled")
            && candidate.agreementHash === hash,
          timeoutMs,
        );
        const sellerCopy = first.bundle as AttestationBundle | undefined;
        if (!sellerCopy || !sameCanonicalBundle(buyerSigned, sellerCopy)) throw new Error("Auditor fulfilment response is not the same canonical bundle");
        const buyerCopy = { ...sellerCopy, anchoredByRole: "buyer" as const };
        const bundleVerdict = await verifyBundle(buyerCopy, { expectedRole: "buyer", ...cryptoDeps });
        if (!bundleVerdict.ok) throw new Error(`completed bundle failed verification: ${bundleVerdict.reason}`);
        const buyerAnchor = this.standard.sub.anchor(buyerBundleAnchorName, buyerCopy);
        const sellerFinal = first.kind === "dacs-rfq-fulfilled"
          ? Promise.resolve(first)
          : this.take((candidate) => candidate.kind === "dacs-rfq-fulfilled" && candidate.agreementHash === hash, timeoutMs);
        // These writes use different wallets and therefore different nonce
        // domains. Await them together instead of serialising buyer behind
        // seller confirmation.
        const [buyerBundleRef, frame] = await Promise.all([buyerAnchor, sellerFinal]);
        const sellerBundleRef = stringField(frame, "sellerBundleRef");
        const finalSellerCopy = frame.bundle as AttestationBundle | undefined;
        const sellerBundleReceipt = frame.sellerBundleReceipt as AnchorReceipt | undefined;
        if (!sellerBundleRef || !finalSellerCopy || !sameCanonicalBundle(sellerCopy, finalSellerCopy)) {
          throw new Error("Auditor confirmed a different completion bundle");
        }
        await verifyConfirmedAnchor(
          this.standard.sub,
          sellerBundleRef,
          finalSellerCopy as unknown as Record<string, unknown>,
          sellerBundleReceipt,
          sellerParty.primaryClaim,
        );
        return { paymentEvidence, paymentEvidenceRef, bundle: buyerCopy, buyerBundleRef, sellerBundleRef, sellerBundle: finalSellerCopy, ...(sellerBundleReceipt ? { sellerBundleReceipt } : {}) };
  }

  private onMessage(message: unknown, fromId: string): void {
    if (fromId !== this.sellerClientId) return;
    const raw = decodePayload(message);
    if (!raw) return;
    try {
      const frame = JSON.parse(raw) as Frame;
      if (!frame || typeof frame !== "object") return;
      this.frames.push(frame);
      this.waiter?.(); this.waiter = undefined;
    } catch { /* unrelated relay message */ }
  }

  private async send(frame: object): Promise<void> {
    await this.peer.sendMessage(this.sellerClientId, JSON.stringify(frame));
  }

  private async take(predicate: (frame: Frame) => boolean, timeoutMs: number): Promise<Frame> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const errorIndex = this.frames.findIndex((frame) => frame.kind === "dacs-rfq-error"
        || frame.kind === "dacs-rfq-payment-rejected" || frame.kind === "dacs-fixed-error");
      if (errorIndex >= 0) {
        const frame = this.frames.splice(errorIndex, 1)[0]!;
        throw new Error(`Seller ${String(frame.code ?? frame.kind)}${frame.reason ? `: ${String(frame.reason)}` : ""}`);
      }
      const index = this.frames.findIndex(predicate);
      if (index >= 0) return this.frames.splice(index, 1)[0]!;
      await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, Math.min(100, Math.max(1, deadline - Date.now())));
        this.waiter = () => { clearTimeout(timer); resolve(); };
      });
    }
    throw new Error(`Seller response timed out after ${timeoutMs}ms`);
  }
}

function scanFor(files: BuyerPostedFile[]): { kloc: number; fileCount: number; hasSolidity: boolean } {
  const lines = files.reduce((sum, file) => sum + file.content.split("\n").length, 0);
  return { kloc: Math.round((lines / 1_000) * 1_000) / 1_000, fileCount: files.length, hasSolidity: files.some((file) => /\.sol$/i.test(file.path)) };
}

function stringField(frame: Frame, key: string): string { return typeof frame[key] === "string" ? frame[key] as string : ""; }
function validatePaymentRequiredFrame(
  agreement: ChannelAgreement | AgreementDocument,
  frame: Frame,
  demosPayTo: string,
  amountOs: string,
): { payTo: string } {
  if (!amountOs || stringField(frame, "amountOs") !== amountOs) {
    throw new Error("seller changed the payment amount after agreement");
  }
  if (!isStandardAgreement(agreement) || !isX402Rail(agreement.terms.rail)) {
    if (stringField(frame, "rail") && stringField(frame, "rail") !== "pay-dem") throw new Error("seller changed the native payment rail");
    if (stringField(frame, "payTo") !== demosPayTo) throw new Error("seller changed the native payment recipient");
    return { payTo: demosPayTo };
  }
  const terms = x402AgreementTerms(agreement);
  const exact = stringField(frame, "rail") === "pay-x402"
    && stringField(frame, "payTo").toLowerCase() === terms.payTo.toLowerCase()
    && stringField(frame, "payer").toLowerCase() === terms.payer.toLowerCase()
    && stringField(frame, "network") === terms.network
    && stringField(frame, "asset").toLowerCase() === terms.asset.toLowerCase()
    && stringField(frame, "resource") === terms.resource
    && stringField(frame, "protocolVersion") === terms.protocolVersion
    && amountOs === terms.amount;
  if (!exact) throw new Error("seller x402 payment request does not match the signed agreement");
  return { payTo: terms.payTo };
}
function sameDemosParty(did: string, address: string): boolean {
  return /^did:demos:agent:[0-9a-f]{64}$/i.test(did)
    && did.slice(-64).toLowerCase() === address.replace(/^0x/, "").toLowerCase();
}
