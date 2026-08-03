import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { SellerDaemon, SellerStateStore, verifyPaymentWithRetry } from "./seller-daemon.js";
import { runSide } from "./session.js";
import { auditTermsFromStandardAgreement, signAgreement } from "./bind.js";
import type { Channel } from "./channel.js";
import type { MessagingPeerInstance, PeerIdentity } from "./demosdk.js";
import type { ChannelEnvelope, Signer, WireSig } from "./wire.js";
import { buyerMaySettle, type BuyerGuard } from "../audit-negotiator/terms.js";
import { deterministicBuyer } from "../audit-negotiator/policies.js";
import { RfqBuyerClient } from "./buyer-client.js";
import { makeIdentity } from "../../src/identity.js";
import { MemorySubstrate } from "../../src/substrate/memory.js";
import { SellerAdapter } from "../dacs/seller-adapter.js";
import { auditNegotiatorStandardListingSpec, AUDIT_NEGOTIATOR_SERVICE_ID } from "../dacs/wire/audit-negotiator.js";
import { primaryClaimSigner } from "./demosdk.js";
import type { AgreementDocument } from "../dacs/standard-profile.js";
import { ddLiveFixedListing, ddLiveFixedX402Listing, oracleAutoAcceptListing } from "../gateway/procurement-listings.js";
import { x402AgreementTerms, x402IdentityBinding, x402IdentityMessage, x402IdentityMetadata } from "../dacs/x402-production.js";
import { privateKeyToAccount } from "viem/accounts";

const RESEARCHER_GITHUB = "dacs-security-researcher";

function auditorListingFor(party: { did: string }) {
  return auditNegotiatorStandardListingSpec({
    researcherGithub: RESEARCHER_GITHUB,
    operatorClaim: party.did,
  });
}

function researcherVetSources(sellerDid: string) {
  return {
    async githubLoginFor(did: string) {
      return did === sellerDid ? RESEARCHER_GITHUB : null;
    },
    async historyFor(did: string) {
      assert.equal(did, sellerDid);
      return { completedAudits: 2, latestBundleRef: "stor-prior-audit-bundle" };
    },
  };
}

function fakeSigner(id: string): Signer {
  const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");
  return {
    id,
    async sign(bytes) { return { signature: hex(bytes), publicKey: id, scheme: "test" } satisfies WireSig; },
    async verify(bytes, sig, expected) { return sig.publicKey === expected && sig.signature === hex(bytes); },
  };
}

class FakePeer implements MessagingPeerInstance {
  private sent: Array<{ to: string; frame: Record<string, unknown> }> = [];
  private wake: (() => void) | undefined;
  async connect(): Promise<void> {}
  onMessage(): void {}
  async sendMessage(to: string, raw: string): Promise<void> {
    this.sent.push({ to, frame: JSON.parse(raw) as Record<string, unknown> });
    this.wake?.(); this.wake = undefined;
  }
  async take(predicate: (frame: Record<string, unknown>) => boolean, timeoutMs = 2_000): Promise<Record<string, unknown>> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const index = this.sent.findIndex((item) => predicate(item.frame));
      if (index >= 0) return this.sent.splice(index, 1)[0]!.frame;
      await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, 10);
        this.wake = () => { clearTimeout(timer); resolve(); };
      });
    }
    throw new Error("timed out waiting for seller frame");
  }
}

class ConcurrentBundleSubstrate extends MemorySubstrate {
  readonly bundleStartedAt = new Map<"buyer" | "seller", number>();
  readonly anchorBatches: string[][] = [];
  private readonly bundleWaiters: Array<() => void> = [];

  override async anchorBatchWithReceipts(entries: Array<{ name: string; value: object }>) {
    this.anchorBatches.push(entries.map(({ name }) => name));
    return super.anchorBatchWithReceipts(entries);
  }

  override async anchor(name: string, value: object): Promise<string> {
    const logicalName = Buffer.from(name, "base64url").toString("utf8");
    const match = /^dacs5:bundle:.*:(buyer|seller)$/.exec(logicalName);
    if (match) {
      const role = match[1] as "buyer" | "seller";
      this.bundleStartedAt.set(role, Date.now());
      await new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(
          () => reject(new Error("buyer and seller DACS-5 anchors did not start concurrently")),
          1_000,
        );
        this.bundleWaiters.push(() => {
          clearTimeout(timeout);
          resolve();
        });
        if (this.bundleStartedAt.size === 2) {
          for (const release of this.bundleWaiters.splice(0)) release();
        }
      });
    }
    return super.anchor(name, value);
  }
}

test("persistent seller negotiates, dual-binds, verifies payment, and idempotently replays receipts", async () => {
  const dir = mkdtempSync(join(tmpdir(), "dacs-seller-"));
  try {
    const peer = new FakePeer();
    const sellerSigner = fakeSigner("seller-signer");
    const buyerSigner = fakeSigner("buyer-signer");
    const identity: PeerIdentity = { mlkemPublicKey: new Uint8Array(), signerId: sellerSigner.id, signer: sellerSigner };
    let verifiedAmount = 0n;
    let deliveries = 0;
    const daemon = new SellerDaemon(
      peer, identity, "0xseller-wallet",
      { async verifyAndReserve(_tx, amount) { verifiedAmount = amount; return { ok: true, payer: "0xbuyer", amountOs: amount }; } },
      new SellerStateStore(join(dir, "state.json")), 2, () => {}, undefined,
      async ({ agreement }) => {
        deliveries += 1;
        return { deliveryRef: "stor-delivery-1", attestation: { kind: "dacs-x-delivery-attestation", jobId: agreement.jobId }, result: { findings: 1 } };
      },
    );

    const channelId = "channel-1";
    const fromId = "buyer-client";
    await daemon.handleMessage(JSON.stringify({
      kind: "dacs-rfq-open", protocol: "dacs-rfq/1", channelId, jobId: "job-1",
      buyerSignerId: buyerSigner.id, repo: "acme/repo",
      scan: { kloc: 9, fileCount: 60, hasSolidity: true }, maxTurns: 6,
    }), fromId);
    const hello = await peer.take((frame) => frame.kind === "dacs-rfq-hello");
    assert.equal(hello.payTo, "0xseller-wallet");

    const buyerChannel: Channel = {
      async send(env) { await daemon.handleMessage(JSON.stringify(env), fromId); },
      async receive() { return await peer.take((frame) => frame.channelId === channelId && typeof frame.sequence === "number") as unknown as ChannelEnvelope; },
      async close() {},
    };
    const guard: BuyerGuard = { offeredTiers: ["quick", "deep"], offeredDeadlines: ["standard", "rush"], budget: 30, acceptableTiers: ["deep"] };
    const buyerResult = await runSide({
      role: "buyer", channelId, policy: deterministicBuyer({ guard, preferredTier: "deep", preferredDeadline: "standard" }),
      maySettle: (terms) => buyerMaySettle(terms, guard), peerSenderId: sellerSigner.id,
      signer: buyerSigner, channel: buyerChannel, maxTurns: 6,
    });
    assert.equal(buyerResult.outcome, "agreed");

    const offered = await peer.take((frame) => frame.kind === "dacs-rfq-agreement");
    const agreement = offered.agreement as Parameters<typeof signAgreement>[2];
    const hash = String(offered.agreementHash);
    const buyerSignature = await signAgreement(buyerSigner, "buyer", agreement);
    await daemon.handleMessage(JSON.stringify({ kind: "dacs-rfq-agreement-accept", protocol: "dacs-rfq/1", agreementHash: hash, agreement, buyerSignature }), fromId);
    const required = await peer.take((frame) => frame.kind === "dacs-rfq-payment-required");
    assert.equal(required.agreementHash, hash);

    const txHash = "a".repeat(64);
    await daemon.handleMessage(JSON.stringify({ kind: "dacs-rfq-settle", protocol: "dacs-rfq/1", agreementHash: hash, txHash }), fromId);
    const settled = await peer.take((frame) => frame.kind === "dacs-rfq-settled");
    assert.equal(settled.txHash, txHash);
    const delivered = await peer.take((frame) => frame.kind === "dacs-rfq-delivered");
    assert.equal(delivered.deliveryRef, "stor-delivery-1");
    assert.ok(verifiedAmount > 0n);
    assert.equal(deliveries, 1);

    const restarted = new SellerDaemon(peer, identity, "0xseller-wallet", { async verifyAndReserve() { throw new Error("must not reverify"); } }, new SellerStateStore(join(dir, "state.json")), 2, () => {}, undefined, async () => { throw new Error("must not redeliver"); });
    await restarted.handleMessage(JSON.stringify({ kind: "dacs-rfq-settle", protocol: "dacs-rfq/1", agreementHash: hash, txHash }), fromId);
    assert.equal((await peer.take((frame) => frame.kind === "dacs-rfq-settled")).txHash, txHash);
    assert.equal((await peer.take((frame) => frame.kind === "dacs-rfq-delivered")).deliveryRef, "stor-delivery-1");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("buyer client completes negotiate, dual-sign, settle, and concurrently anchors both DACS-5 copies", async () => {
  const dir = mkdtempSync(join(tmpdir(), "dacs-buyer-client-"));
  try {
    const sellerParty = makeIdentity("seller", 0x41);
    const buyerParty = makeIdentity("buyer", 0x42);
    const sellerSigner = primaryClaimSigner(sellerParty.did, sellerParty.sign);
    const buyerSigner = primaryClaimSigner(buyerParty.did, buyerParty.sign);
    const sub = new ConcurrentBundleSubstrate();
    const sellerAdapter = new SellerAdapter(sellerParty, sub, AUDIT_NEGOTIATOR_SERVICE_ID, async () => ({ result: { findings: 1 } }));
    const published = await sellerAdapter
      .publishStandardListing(auditorListingFor(sellerParty));
    let buyerInbound: ((message: unknown, fromId: string) => void) | undefined;
    let daemon!: SellerDaemon;
    let deliveries = 0;
    const sellerPeer: MessagingPeerInstance = {
      async connect() {}, onMessage() {},
      async sendMessage(_to, message) { buyerInbound?.(message, "dacs-auditor"); },
    };
    const buyerPeer: MessagingPeerInstance = {
      async connect() {}, async discoverPeers() { return ["dacs-auditor"]; },
      onMessage(handler) { buyerInbound = handler; },
      async sendMessage(_to, message) { await daemon.handleMessage(message, "buyer-client"); },
    };
    daemon = new SellerDaemon(
      sellerPeer,
      { mlkemPublicKey: new Uint8Array(), signerId: sellerSigner.id, signer: sellerSigner },
      `0x${sellerParty.did.slice(-64)}`,
      { async verifyAndReserve(_tx, amount) { return { ok: true, payer: `0x${buyerParty.did.slice(-64)}`, amountOs: amount, blockNumber: 91 }; } },
      new SellerStateStore(join(dir, "state.json")), 2, () => {}, undefined,
      async ({ agreement, files, repo }) => {
        deliveries += 1;
        const prepared = await sellerAdapter.prepareDelivery(agreement.jobId, {
          files,
          negotiatedTerms: auditTermsFromStandardAgreement(agreement as AgreementDocument),
          repo,
        });
        return {
          deliveryRef: prepared.attestationRef,
          attestation: prepared.anchoredAttestation,
          result: prepared.result,
          preparedAnchor: { name: prepared.anchorName, value: prepared.anchoredAttestation },
          deliverableContentHash: prepared.attestation.resultHash,
        };
      },
      async () => "stor-seller-bundle",
      ["quick"],
      sellerSigner,
      {
        party: { primaryClaim: sellerParty.did, sign: sellerParty.sign },
        sub,
        async getListing() { return { listing: published.listing, listingAnchorRef: published.ref }; },
      },
    );
    const client = new RfqBuyerClient(
      buyerPeer,
      { mlkemPublicKey: new Uint8Array(), signerId: buyerSigner.id, signer: buyerSigner },
      "dacs-auditor",
      buyerSigner,
      {
        party: { primaryClaim: buyerParty.did, sign: buyerParty.sign },
        sub,
        listing: published.listing,
        listingAnchorRef: published.ref,
        securityResearcherVet: researcherVetSources(sellerParty.did),
      },
    );
    await client.connect();
    const deal = await client.negotiate({
      channelId: "channel-public-1", jobId: "job-public-1", repo: "posted/job-public-1",
      files: [{ path: "server.js", content: "eval(input);\n" }], budgetDem: 5,
      preferredTier: "quick", acceptableTiers: ["quick"],
    });
    assert.equal(deal.terms.tier, "quick");
    assert.equal(deal.identity?.buyer.bundle.presentedBy, buyerParty.did);
    assert.equal(deal.identity?.seller.bundle.presentedBy, sellerParty.did);
    assert.equal(await sub.read(deal.identity!.buyer.vetRecordRef.anchor.locator) !== null, true);
    assert.equal(await sub.read(deal.identity!.seller.vetRecordRef.anchor.locator) !== null, true);
    assert.ok(BigInt(deal.amountOs) > 0n);
    const settlement = await deal.settle("b".repeat(64));
    assert.equal(deliveries, 0, "Standard delivery must wait for anchored payment evidence");
    const payment = await deal.anchorPaymentEvidence(settlement);
    assert.equal(await sub.read(payment.paymentEvidenceRef.anchor.locator) !== null, true);
    const delivery = await deal.requestDelivery(payment);
    assert.equal(delivery.deliveryRef, "stor:dacsx:delivery:job-public-1");
    assert.deepEqual(delivery.result, { findings: 1 });
    assert.ok(delivery.anchorReceipt, "delivery batch must return the delivery SR-2 receipt");
    assert.ok(delivery.deliveryEvidenceReceipt, "delivery batch must return the evidence SR-2 receipt");
    assert.equal(await sub.read(delivery.deliveryRef) !== null, true);
    assert.equal(await sub.read(delivery.deliveryEvidenceRef!.anchor.locator) !== null, true);
    const deliveryBatch = sub.anchorBatches.find((names) => names[0] === "dacsx:delivery:job-public-1");
    assert.ok(deliveryBatch, "seller must batch delivery with its dependent evidence");
    assert.equal(Buffer.from(deliveryBatch[1]!, "base64url").toString("utf8"), "dacs4:evidence:job-public-1:deliver-attested-payload");
    const standard = await deal.completeStandard(settlement, delivery, payment);
    assert.equal(await sub.read(standard.buyerBundleRef) !== null, true);
    assert.equal(await sub.read(standard.sellerBundleRef) !== null, true);
    assert.equal(standard.bundle.signatures.length, 2);
    assert.deepEqual([...sub.bundleStartedAt.keys()].sort(), ["buyer", "seller"]);
    assert.ok(
      Math.abs(sub.bundleStartedAt.get("buyer")! - sub.bundleStartedAt.get("seller")!) < 100,
      "independent-wallet DACS-5 writes should begin together",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("fixed-price live seller binds real input and reuses the durable paid DACS-4/5 lifecycle", async () => {
  const dir = mkdtempSync(join(tmpdir(), "dacs-fixed-seller-"));
  try {
    const sellerParty = makeIdentity("fixed-seller", 0x61);
    const buyerParty = makeIdentity("fixed-buyer", 0x62);
    const sellerSigner = primaryClaimSigner(sellerParty.did, sellerParty.sign);
    const buyerSigner = primaryClaimSigner(buyerParty.did, buyerParty.sign);
    const sub = new MemorySubstrate();
    const adapter = new SellerAdapter(sellerParty, sub, "dd-research", async (_jobId, params) => ({ result: { subject: params.subject } }));
    const published = await adapter.publishStandardListing(ddLiveFixedListing());
    let buyerInbound: ((message: unknown, fromId: string) => void) | undefined;
    let daemon!: SellerDaemon;
    let deliveredParams: Record<string, unknown> | undefined;
    let paymentChecks = 0;
    const sellerPeer: MessagingPeerInstance = {
      async connect() {}, onMessage() {},
      async sendMessage(_to, message) { buyerInbound?.(message, "dacs-dd-fixed"); },
    };
    const buyerPeer: MessagingPeerInstance = {
      async connect() {}, async discoverPeers() { return ["dacs-dd-fixed"]; },
      onMessage(handler) { buyerInbound = handler; },
      async sendMessage(_to, message) { await daemon.handleMessage(message, "fixed-buyer-client"); },
    };
    daemon = new SellerDaemon(
      sellerPeer,
      { mlkemPublicKey: new Uint8Array(), signerId: sellerSigner.id, signer: sellerSigner },
      `0x${sellerParty.did.slice(-64)}`,
      { async verifyAndReserve(_tx, amount) { paymentChecks += 1; return { ok: true, payer: `0x${buyerParty.did.slice(-64)}`, amountOs: amount, blockNumber: 101 }; } },
      new SellerStateStore(join(dir, "state.json")),
      2,
      () => {},
      undefined,
      async ({ agreement, params }) => {
        deliveredParams = params;
        const prepared = await adapter.prepareDelivery(agreement.jobId, params ?? {});
        return {
          deliveryRef: prepared.attestationRef,
          attestation: prepared.anchoredAttestation,
          result: prepared.result,
          preparedAnchor: { name: prepared.anchorName, value: prepared.anchoredAttestation },
          deliverableContentHash: prepared.attestation.resultHash,
        };
      },
      undefined,
      ["quick"],
      sellerSigner,
      {
        party: { primaryClaim: sellerParty.did, sign: sellerParty.sign },
        sub,
        async getListing() { return { listing: published.listing, listingAnchorRef: published.ref }; },
      },
    );
    const client = new RfqBuyerClient(
      buyerPeer,
      { mlkemPublicKey: new Uint8Array(), signerId: buyerSigner.id, signer: buyerSigner },
      "dacs-dd-fixed",
      buyerSigner,
      {
        party: { primaryClaim: buyerParty.did, sign: buyerParty.sign },
        sub,
        listing: published.listing,
        listingAnchorRef: published.ref,
      },
    );
    const requestScope = { kind: "npm-package", subject: "express" };
    await client.connect();
    const deal = await client.negotiateFixed({ channelId: "fixed-channel-1", jobId: "fixed-job-1", requestScope });
    assert.equal(deal.agreement.derivedFromPattern, "fixed-price");
    assert.equal(deal.agreement.signatures.length, 2);
    const settlement = await deal.settle("d".repeat(64));
    const payment = await deal.anchorPaymentEvidence(settlement);
    const delivery = await deal.requestDelivery(payment);
    assert.deepEqual(deliveredParams, requestScope);
    assert.deepEqual(delivery.result, { subject: "express" });
    assert.equal(delivery.attestation.requestHash, deal.agreement.terms.additionalTerms?.requestHash);
    const completion = await deal.completeStandard(settlement, delivery, payment);
    assert.equal(completion.bundle.signatures.length, 2);
    assert.equal(paymentChecks, 1);

    assert.ok(new SellerStateStore(join(dir, "state.json")).getSettled(deal.agreementHash));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("fixed-price x402 carries the buyer payer binding into the seller identity exchange", async () => {
  const dir = mkdtempSync(join(tmpdir(), "dacs-fixed-x402-"));
  try {
    const sellerParty = makeIdentity("fixed-x402-seller", 0x63);
    const buyerParty = makeIdentity("fixed-x402-buyer", 0x64);
    const sellerSigner = primaryClaimSigner(sellerParty.did, sellerParty.sign);
    const buyerSigner = primaryClaimSigner(buyerParty.did, buyerParty.sign);
    const sellerAccount = privateKeyToAccount("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784e7bf4f2ff80");
    const buyerAccount = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");
    const metadata = async (did: string, account: typeof sellerAccount) => x402IdentityMetadata(x402IdentityBinding({
      dacsIdentity: did,
      account: account.address,
      signature: await account.signMessage({ message: x402IdentityMessage(did, account.address) }),
    }));
    const sellerMetadata = await metadata(sellerParty.did, sellerAccount);
    const buyerMetadata = await metadata(buyerParty.did, buyerAccount);
    const sub = new MemorySubstrate();
    const adapter = new SellerAdapter(sellerParty, sub, "dd-research-x402", async () => ({ result: {} }));
    const published = await adapter.publishStandardListing(ddLiveFixedX402Listing({
      payTo: sellerAccount.address,
      resourceBase: "https://seller.example/x402",
      identityMetadata: sellerMetadata,
    }));
    let buyerInbound: ((message: unknown, fromId: string) => void) | undefined;
    let daemon!: SellerDaemon;
    const sellerPeer: MessagingPeerInstance = {
      async connect() {}, onMessage() {},
      async sendMessage(_to, message) { buyerInbound?.(message, "dacs-dd-fixed"); },
    };
    const buyerPeer: MessagingPeerInstance = {
      async connect() {}, async discoverPeers() { return ["dacs-dd-fixed"]; },
      onMessage(handler) { buyerInbound = handler; },
      async sendMessage(_to, message) { await daemon.handleMessage(message, "fixed-x402-buyer-client"); },
    };
    daemon = new SellerDaemon(
      sellerPeer,
      { mlkemPublicKey: new Uint8Array(), signerId: sellerSigner.id, signer: sellerSigner },
      `0x${sellerParty.did.slice(-64)}`,
      { async verifyAndReserve() { return { ok: false, reason: "not exercised" }; } },
      new SellerStateStore(join(dir, "state.json")), 2, () => {}, undefined,
      async () => { throw new Error("delivery is not exercised"); },
      undefined, ["quick"], sellerSigner,
      {
        party: { primaryClaim: sellerParty.did, sign: sellerParty.sign },
        sub,
        identityMetadata: sellerMetadata,
        async getListing() { return { listing: published.listing, listingAnchorRef: published.ref }; },
      },
    );
    const client = new RfqBuyerClient(
      buyerPeer,
      { mlkemPublicKey: new Uint8Array(), signerId: buyerSigner.id, signer: buyerSigner },
      "dacs-dd-fixed",
      buyerSigner,
      {
        party: { primaryClaim: buyerParty.did, sign: buyerParty.sign },
        sub,
        listing: published.listing,
        listingAnchorRef: published.ref,
        identityMetadata: buyerMetadata,
      },
    );
    await client.connect();
    const deal = await client.negotiateFixed({
      channelId: "fixed-x402-channel-1",
      jobId: "fixed-x402-job-1",
      requestScope: { kind: "npm-package", subject: "express" },
      x402Payer: buyerAccount.address,
    });
    assert.equal(x402AgreementTerms(deal.agreement).payer.toLowerCase(), buyerAccount.address.toLowerCase());
    assert.equal(deal.identity.buyer.bundle.claims[0]?.metadata?.paymentAccounts !== undefined, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("auto-accept seller uses the separately anchored bounded template and a live instance signature", async () => {
  const dir = mkdtempSync(join(tmpdir(), "dacs-auto-seller-"));
  try {
    const sellerParty = makeIdentity("auto-seller", 0x71);
    const buyerParty = makeIdentity("auto-buyer", 0x72);
    const sellerSigner = primaryClaimSigner(sellerParty.did, sellerParty.sign);
    const buyerSigner = primaryClaimSigner(buyerParty.did, buyerParty.sign);
    const sub = new MemorySubstrate();
    const adapter = new SellerAdapter(sellerParty, sub, "oracle-data", async () => ({ result: { value: "42" } }));
    const published = await adapter.publishStandardListing(oracleAutoAcceptListing({ listingVersion: 2, notBefore: Date.now() - 1_000, validUntil: Date.now() + 60_000 }));
    assert.ok(published.autoAcceptCommitment && published.autoAcceptCommitmentRef);
    let buyerInbound: ((message: unknown, fromId: string) => void) | undefined;
    let daemon!: SellerDaemon;
    const sellerPeer: MessagingPeerInstance = {
      async connect() {}, onMessage() {},
      async sendMessage(_to, message) { buyerInbound?.(message, "dacs-oracle-fixed"); },
    };
    const buyerPeer: MessagingPeerInstance = {
      async connect() {}, async discoverPeers() { return ["dacs-oracle-fixed"]; },
      onMessage(handler) { buyerInbound = handler; },
      async sendMessage(_to, message) { await daemon.handleMessage(message, "auto-buyer-client"); },
    };
    daemon = new SellerDaemon(
      sellerPeer,
      { mlkemPublicKey: new Uint8Array(), signerId: sellerSigner.id, signer: sellerSigner },
      `0x${sellerParty.did.slice(-64)}`,
      { async verifyAndReserve(_tx, amount) { return { ok: true, payer: `0x${buyerParty.did.slice(-64)}`, amountOs: amount, blockNumber: 102 }; } },
      new SellerStateStore(join(dir, "state.json")), 2, () => {}, undefined,
      async ({ agreement, params }) => {
        const prepared = await adapter.prepareDelivery(agreement.jobId, params ?? {});
        return { deliveryRef: prepared.attestationRef, attestation: prepared.anchoredAttestation, result: prepared.result, preparedAnchor: { name: prepared.anchorName, value: prepared.anchoredAttestation }, deliverableContentHash: prepared.attestation.resultHash };
      },
      undefined,
      ["quick"],
      sellerSigner,
      {
        party: { primaryClaim: sellerParty.did, sign: sellerParty.sign }, sub,
        async getListing() { return { listing: published.listing, listingAnchorRef: published.ref, autoAcceptCommitment: published.autoAcceptCommitment, autoAcceptCommitmentRef: published.autoAcceptCommitmentRef }; },
      },
    );
    const client = new RfqBuyerClient(
      buyerPeer,
      { mlkemPublicKey: new Uint8Array(), signerId: buyerSigner.id, signer: buyerSigner },
      "dacs-oracle-fixed",
      buyerSigner,
      { party: { primaryClaim: buyerParty.did, sign: buyerParty.sign }, sub, listing: published.listing, listingAnchorRef: published.ref },
    );
    await client.connect();
    const deal = await client.negotiateFixed({
      channelId: "auto-channel-1", jobId: "auto-job-1", requestScope: { product: "chain-height", params: {} },
      autoAcceptCommitment: published.autoAcceptCommitment,
      autoAcceptCommitmentRef: published.autoAcceptCommitmentRef,
    });
    assert.equal(deal.agreement.signatures.length, 2);
    const settlement = await deal.settle("e".repeat(64));
    const payment = await deal.anchorPaymentEvidence(settlement);
    const delivery = await deal.requestDelivery(payment);
    const completion = await deal.completeStandard(settlement, delivery, payment);
    assert.equal(completion.bundle.signatures.length, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("fixed-price paid delivery resumes after failure without a second payment", async () => {
  const dir = mkdtempSync(join(tmpdir(), "dacs-fixed-recovery-"));
  try {
    const sellerParty = makeIdentity("fixed-recovery-seller", 0x73);
    const buyerParty = makeIdentity("fixed-recovery-buyer", 0x74);
    const sellerSigner = primaryClaimSigner(sellerParty.did, sellerParty.sign);
    const buyerSigner = primaryClaimSigner(buyerParty.did, buyerParty.sign);
    const sub = new MemorySubstrate();
    const adapter = new SellerAdapter(sellerParty, sub, "dd-research", async () => ({ result: { ok: true } }));
    const published = await adapter.publishStandardListing(ddLiveFixedListing());
    let buyerInbound: ((message: unknown, fromId: string) => void) | undefined;
    let daemon!: SellerDaemon;
    let paymentChecks = 0;
    let deliveries = 0;
    const sellerPeer: MessagingPeerInstance = { async connect() {}, onMessage() {}, async sendMessage(_to, message) { buyerInbound?.(message, "dacs-dd-fixed"); } };
    const buyerPeer: MessagingPeerInstance = {
      async connect() {}, async discoverPeers() { return ["dacs-dd-fixed"]; }, onMessage(handler) { buyerInbound = handler; },
      async sendMessage(_to, message) { await daemon.handleMessage(message, "fixed-recovery-client"); },
    };
    daemon = new SellerDaemon(
      sellerPeer,
      { mlkemPublicKey: new Uint8Array(), signerId: sellerSigner.id, signer: sellerSigner },
      `0x${sellerParty.did.slice(-64)}`,
      { async verifyAndReserve(_tx, amount) { paymentChecks += 1; return { ok: true, payer: `0x${buyerParty.did.slice(-64)}`, amountOs: amount, blockNumber: 103 }; } },
      new SellerStateStore(join(dir, "state.json")), 2, () => {}, undefined,
      async ({ agreement, params }) => {
        deliveries += 1;
        if (deliveries === 1) throw new Error("injected fixed delivery failure");
        const prepared = await adapter.prepareDelivery(agreement.jobId, params ?? {});
        return { deliveryRef: prepared.attestationRef, attestation: prepared.anchoredAttestation, result: prepared.result, preparedAnchor: { name: prepared.anchorName, value: prepared.anchoredAttestation }, deliverableContentHash: prepared.attestation.resultHash };
      },
      undefined,
      ["quick"],
      sellerSigner,
      { party: { primaryClaim: sellerParty.did, sign: sellerParty.sign }, sub, async getListing() { return { listing: published.listing, listingAnchorRef: published.ref }; } },
    );
    const client = new RfqBuyerClient(
      buyerPeer,
      { mlkemPublicKey: new Uint8Array(), signerId: buyerSigner.id, signer: buyerSigner },
      "dacs-dd-fixed",
      buyerSigner,
      { party: { primaryClaim: buyerParty.did, sign: buyerParty.sign }, sub, listing: published.listing, listingAnchorRef: published.ref },
    );
    await client.connect();
    const deal = await client.negotiateFixed({ channelId: "fixed-recover-channel", jobId: "fixed-recover-job", requestScope: { kind: "npm-package", subject: "express" } });
    const txHash = "f".repeat(64);
    const settlement = await deal.settle(txHash);
    const payment = await deal.anchorPaymentEvidence(settlement);
    await assert.rejects(deal.requestDelivery(payment), /delivery_failed/);
    const recovered = await client.recoverStandard({
      agreement: deal.agreement,
      agreementHash: deal.agreementHash,
      txHash,
      standardCommit: deal.standardCommit,
      buyerBundleAnchorName: "fixed-recovery-buyer-bundle",
    });
    assert.equal(paymentChecks, 1);
    assert.equal(deliveries, 2);
    assert.deepEqual(recovered.delivery.result, { ok: true });
    assert.equal(recovered.completion.bundle.signatures.length, 2);
    const replayed = await client.recoverStandard({
      agreement: deal.agreement,
      agreementHash: deal.agreementHash,
      txHash,
      standardCommit: deal.standardCommit,
      buyerBundleAnchorName: "fixed-recovery-buyer-bundle-replay",
    });
    assert.equal(paymentChecks, 1, "a fulfilment-response retry must not re-verify or repeat payment");
    assert.equal(deliveries, 2, "the seller must reuse its persisted delivery");
    assert.deepEqual(replayed.completion.bundle, recovered.completion.bundle,
      "restart recovery must reconstruct the byte-identical canonical DACS-5 bundle");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("buyer recovers a persisted paid delivery without repaying or overwriting its abort bundle", async () => {
  const dir = mkdtempSync(join(tmpdir(), "dacs-buyer-recovery-"));
  try {
    const sellerParty = makeIdentity("seller-recovery", 0x51);
    const buyerParty = makeIdentity("buyer-recovery", 0x52);
    const sellerSigner = primaryClaimSigner(sellerParty.did, sellerParty.sign);
    const buyerSigner = primaryClaimSigner(buyerParty.did, buyerParty.sign);
    const sub = new MemorySubstrate();
    const published = await new SellerAdapter(sellerParty, sub, AUDIT_NEGOTIATOR_SERVICE_ID, async () => ({ result: null }))
      .publishStandardListing(auditorListingFor(sellerParty));
    let buyerInbound: ((message: unknown, fromId: string) => void) | undefined;
    let daemon!: SellerDaemon;
    let paymentChecks = 0;
    let deliveryAttempts = 0;
    const sellerPeer: MessagingPeerInstance = {
      async connect() {}, onMessage() {},
      async sendMessage(_to, message) { buyerInbound?.(message, "dacs-auditor"); },
    };
    const buyerPeer: MessagingPeerInstance = {
      async connect() {}, async discoverPeers() { return ["dacs-auditor"]; },
      onMessage(handler) { buyerInbound = handler; },
      async sendMessage(_to, message) { await daemon.handleMessage(message, "buyer-client-recovery"); },
    };
    daemon = new SellerDaemon(
      sellerPeer,
      { mlkemPublicKey: new Uint8Array(), signerId: sellerSigner.id, signer: sellerSigner },
      `0x${sellerParty.did.slice(-64)}`,
      {
        async verifyAndReserve(_tx, amount) {
          paymentChecks += 1;
          return { ok: true, payer: `0x${buyerParty.did.slice(-64)}`, amountOs: amount, blockNumber: 92 };
        },
      },
      new SellerStateStore(join(dir, "state.json")), 2, () => {}, undefined,
      async ({ agreement }) => {
        deliveryAttempts += 1;
        if (deliveryAttempts === 1) throw new Error("simulated post-payment delivery failure");
        return {
          deliveryRef: "stor-recovered-delivery",
          attestation: {
            kind: "dacs-x-delivery-attestation",
            jobId: agreement.jobId,
            resultHash: "e".repeat(64),
            requestHash: (agreement as AgreementDocument).terms.additionalTerms?.requestHash,
          },
          result: { findings: 1 },
        };
      },
      async () => "unused-legacy-bundle",
      ["quick"],
      sellerSigner,
      {
        party: { primaryClaim: sellerParty.did, sign: sellerParty.sign },
        sub,
        async getListing() { return { listing: published.listing, listingAnchorRef: published.ref }; },
      },
    );
    const client = new RfqBuyerClient(
      buyerPeer,
      { mlkemPublicKey: new Uint8Array(), signerId: buyerSigner.id, signer: buyerSigner },
      "dacs-auditor",
      buyerSigner,
      {
        party: { primaryClaim: buyerParty.did, sign: buyerParty.sign },
        sub,
        listing: published.listing,
        listingAnchorRef: published.ref,
        securityResearcherVet: researcherVetSources(sellerParty.did),
      },
    );
    await client.connect();
    const deal = await client.negotiate({
      channelId: "channel-recovery-1",
      jobId: "job-recovery-1",
      repo: "posted/job-recovery-1",
      files: [{ path: "server.js", content: "eval(input);\n" }],
      budgetDem: 5,
      preferredTier: "quick",
      acceptableTiers: ["quick"],
    });
    assert.ok(deal.standardCommit);
    const txHash = "c".repeat(64);
    const settlement = await deal.settle(txHash);
    const payment = await deal.anchorPaymentEvidence(settlement);
    await assert.rejects(deal.requestDelivery(payment), /delivery_failed/);
    const abortRef = await deal.abortStandard("simulated failure", "deliver-attested-payload");
    assert.ok(abortRef);
    const abortBefore = await sub.read(abortRef!);

    const recovered = await client.recoverStandard({
      agreement: deal.agreement as AgreementDocument,
      agreementHash: deal.agreementHash,
      txHash,
      standardCommit: deal.standardCommit!,
      buyerBundleAnchorName: "recovery-buyer-bundle-v1",
    });
    assert.equal(recovered.delivery.deliveryRef, "stor-recovered-delivery");
    assert.equal(String(recovered.settlement.txHash), txHash);
    assert.equal(paymentChecks, 1, "the persisted settlement must not be re-verified or repaid");
    assert.equal(deliveryAttempts, 2);
    assert.deepEqual(await sub.read(abortRef!), abortBefore, "terminal abort anchor must remain unchanged");
    assert.equal(await sub.read(recovered.completion.buyerBundleRef) !== null, true);
    assert.equal(await sub.read(recovered.completion.sellerBundleRef) !== null, true);
    assert.equal(recovered.completion.bundle.signatures.length, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
test("seller retries transiently incomplete confirmed payment records", async () => {
  let attempts = 0;
  const result = await verifyPaymentWithRetry({
    async verifyAndReserve(_txHash, amountOs) {
      attempts += 1;
      return attempts < 3
        ? { ok: false, reason: "details pending", retriable: true }
        : { ok: true, payer: "0xbuyer", amountOs, blockNumber: 7 };
    },
  }, "a".repeat(64), 2_300_000_000n, { attempts: 3, delayMs: 0 });
  assert.equal(result.ok, true);
  assert.equal(attempts, 3);
});
