/**
 * Binding tests — node:test:
 *   npx tsx --test roster/negotiation-l2ps/bind.test.ts
 *
 * The load-bearing property: BOTH parties, from their own transcript view,
 * derive the SAME agreementHash and lastMessageHash — a mutual commitment
 * neither can unilaterally restate. Plus: the session-open params carry the
 * agreed terms, dual signatures verify, and tampering the transcript changes the
 * hash.
 */
import { describe, test } from "node:test";
import assert from "node:assert/strict";
import {
  DEFAULT_ECONOMICS,
  buyerMaySettle,
  sellerMaySettle,
  toolsForScan,
  type AuditTier,
  type BuyerGuard,
  type Deadline,
  type ScanFacts,
} from "../audit-negotiator/terms.js";
import { deterministicBuyer, deterministicSeller, sellerGuardFor } from "../audit-negotiator/policies.js";
import { InProcessChannelPair } from "./channel.js";
import { runSide, type NetworkedResult } from "./session.js";
import type { Signer, WireSig } from "./wire.js";
import {
  agreementHash,
  buildChannelAgreement,
  lastMessageHash,
  sessionOpenParams,
  signAgreement,
  verifyAgreementSignature,
} from "./bind.js";

const TIERS: AuditTier[] = ["quick", "deep"];
const DEADLINES: Deadline[] = ["standard", "rush"];
const CHANNEL = "chan-bind-1";
const JOB = "job-bind-1";
const AT = "2026-07-10T00:00:00.000Z";

function fakeSigner(id: string): Signer {
  const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
  return {
    id,
    async sign(c) {
      return { signature: hex(c), publicKey: id, scheme: "test" } satisfies WireSig;
    },
    async verify(c, sig, expected) {
      return sig.publicKey === expected && sig.signature === hex(c);
    },
  };
}

function scanOf(over: Partial<ScanFacts> = {}): ScanFacts {
  const hasSolidity = over.hasSolidity ?? false;
  return { repo: "acme/x", kloc: 8, fileCount: 40, hasSolidity, numTools: toolsForScan(hasSolidity), ...over };
}

async function negotiate(): Promise<{ seller: NetworkedResult; buyer: NetworkedResult; sellerId: string; buyerId: string }> {
  const scan = scanOf({ kloc: 8 });
  const sellerGuard = sellerGuardFor(scan, TIERS, DEADLINES, DEFAULT_ECONOMICS);
  const buyerGuard: BuyerGuard = { offeredTiers: TIERS, offeredDeadlines: DEADLINES, budget: 30, acceptableTiers: ["deep"] };
  const [chanS, chanB] = InProcessChannelPair();
  const [seller, buyer] = await Promise.all([
    runSide({
      role: "seller",
      channelId: CHANNEL,
      policy: deterministicSeller({ scan, guard: sellerGuard, econ: DEFAULT_ECONOMICS }),
      maySettle: (t) => sellerMaySettle(t, sellerGuard),
      peerSenderId: "buyer-peer",
      signer: fakeSigner("seller-peer"),
      channel: chanS,
      maxTurns: 6,
    }),
    runSide({
      role: "buyer",
      channelId: CHANNEL,
      policy: deterministicBuyer({ guard: buyerGuard, preferredTier: "deep", preferredDeadline: "standard" }),
      maySettle: (t) => buyerMaySettle(t, buyerGuard),
      peerSenderId: "seller-peer",
      signer: fakeSigner("buyer-peer"),
      channel: chanB,
      maxTurns: 6,
    }),
  ]);
  return { seller, buyer, sellerId: "seller-peer", buyerId: "buyer-peer" };
}

describe("mutual agreement binding", () => {
  test("both parties derive the SAME agreementHash + lastMessageHash", async () => {
    const { seller, buyer, sellerId, buyerId } = await negotiate();
    assert.equal(seller.outcome, "agreed");
    assert.ok(seller.agreed && buyer.agreed);

    const mk = (r: NetworkedResult) =>
      buildChannelAgreement({ jobId: JOB, channelId: CHANNEL, agreed: r.agreed!, sellerId, buyerId, envelopes: r.envelopes, generatedAt: AT });

    const sellerAgreement = mk(seller);
    const buyerAgreement = mk(buyer);

    // The two independently-built agreements are byte-identical…
    assert.deepEqual(sellerAgreement, buyerAgreement);
    // …hence the same anchor hash and the same channel-derivation link.
    assert.equal(agreementHash(sellerAgreement), agreementHash(buyerAgreement));
    assert.equal(sellerAgreement.derivedFromChannel.lastMessageHash, buyerAgreement.derivedFromChannel.lastMessageHash);
    // lastMessageHash is the hash of the (identical) final envelope both saw.
    assert.equal(sellerAgreement.derivedFromChannel.lastMessageHash, lastMessageHash(seller.envelopes));
    assert.equal(lastMessageHash(seller.envelopes), lastMessageHash(buyer.envelopes));
  });

  test("session-open params carry the negotiated terms", async () => {
    const { seller, sellerId, buyerId } = await negotiate();
    const a = buildChannelAgreement({ jobId: JOB, channelId: CHANNEL, agreed: seller.agreed!, sellerId, buyerId, envelopes: seller.envelopes, generatedAt: AT });
    const params = sessionOpenParams(a, "acme/x");
    assert.equal(params.jobId, JOB);
    assert.equal(params.repo, "acme/x");
    assert.equal(params.tier, seller.agreed!.tier);
    assert.equal(params.price, seller.agreed!.price);
  });

  test("dual signatures over the agreement verify", async () => {
    const { seller, sellerId, buyerId } = await negotiate();
    const a = buildChannelAgreement({ jobId: JOB, channelId: CHANNEL, agreed: seller.agreed!, sellerId, buyerId, envelopes: seller.envelopes, generatedAt: AT });
    const sSig = await signAgreement(fakeSigner("seller-peer"), "seller", a);
    const bSig = await signAgreement(fakeSigner("buyer-peer"), "buyer", a);
    assert.ok(await verifyAgreementSignature(fakeSigner("seller-peer"), a, sSig));
    assert.ok(await verifyAgreementSignature(fakeSigner("buyer-peer"), a, bSig));
    // A signature over a different agreement must not verify.
    const a2 = { ...a, terms: { ...a.terms, price: a.terms.price + 1 } };
    assert.equal(await verifyAgreementSignature(fakeSigner("seller-peer"), a2, sSig), false);
  });

  test("tampering the transcript changes the transcript hash", async () => {
    const { seller, sellerId, buyerId } = await negotiate();
    const a = buildChannelAgreement({ jobId: JOB, channelId: CHANNEL, agreed: seller.agreed!, sellerId, buyerId, envelopes: seller.envelopes, generatedAt: AT });
    const mutated = seller.envelopes.slice();
    mutated[0] = { ...mutated[0]!, body: { kind: "reject", rationale: "injected" } };
    const a2 = buildChannelAgreement({ jobId: JOB, channelId: CHANNEL, agreed: seller.agreed!, sellerId, buyerId, envelopes: mutated, generatedAt: AT });
    assert.notEqual(a.derivedFromChannel.transcriptHash, a2.derivedFromChannel.transcriptHash);
  });

  test("agreement is anchor-safe: canonical form is pure ASCII even with unicode rationale", async () => {
    const { seller, sellerId, buyerId } = await negotiate();
    // Inject a non-ASCII rationale into an envelope (LLM output can contain em-dashes etc.).
    const env = seller.envelopes.map((e) => ({ ...e, body: e.body.kind === "reject" ? e.body : { ...e.body, rationale: "concédé — 9 DEM ✓" } }));
    const a = buildChannelAgreement({ jobId: JOB, channelId: CHANNEL, agreed: seller.agreed!, sellerId, buyerId, envelopes: env, generatedAt: AT });
    // The agreement embeds only the transcript HASH, not raw rationale, so its
    // own canonical form is ASCII (safe to anchor).
    const canonical = JSON.stringify(a);
    // eslint-disable-next-line no-control-regex
    assert.ok(/^[\x00-\x7F]*$/.test(canonical), "agreement canonical form must be ASCII for anchoring");
  });
});
