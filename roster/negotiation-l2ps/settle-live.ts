/**
 * End-to-end: NEGOTIATE → BIND → SETTLE on live pay-dem.
 *
 *   npx tsx roster/negotiation-l2ps/settle-live.ts              # DRY RUN (no tx)
 *   SETTLE_CONFIRM=1 npx tsx roster/negotiation-l2ps/settle-live.ts   # broadcast
 *
 * Runs a two-sided RFQ (over an in-process channel, producing the real signed
 * envelope transcript), binds it into a `ChannelAgreement` (agreementHash +
 * derivedFromChannel.lastMessageHash), then settles the deal buyer → seller as a
 * native DEM transfer on the live Demos testnet — reusing the SAME wallet
 * machinery (`connectIdentity`, transfer/confirm/broadcast) and persisted L1
 * wallets the working L1 pay-dem run uses.
 *
 * Money-safety: DRY RUN by default (connects, reads balances, prints the plan);
 * only `SETTLE_CONFIRM=1` broadcasts. The settled amount is a small testnet token
 * (`SETTLE_OS`, default 0.01 DEM) representing the deal — the full negotiated
 * price + agreementHash travel in the printed settlement record, not the raw OS
 * amount, so a demo run can't drain a test wallet.
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { connectIdentity } from "../../src/live/identity.js";
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
import { agreementHash, buildChannelAgreement, sessionOpenParams } from "./bind.js";

const RPC = process.env.DEMOS_RPC ?? "https://demosnode.discus.sh/";
const BUYER_KEY = join(process.cwd(), "roster/dacs/live/.l1-buyer-key");
const SELLER_KEY = join(process.cwd(), "roster/dacs/live/.l1-seller-key");
const SETTLE_OS = BigInt(process.env.SETTLE_OS ?? "10000000"); // 0.01 DEM default
const CONFIRM = process.env.SETTLE_CONFIRM === "1";
const CHANNEL = `chan-settle-${Date.now()}`;
const JOB = `job-${Date.now()}`;
const REPO = "acme/payments-core";

const TIERS: AuditTier[] = ["quick", "deep"];
const DEADLINES: Deadline[] = ["standard", "rush"];
const osToDem = (os: bigint) => `${(Number(os) / 1e9).toFixed(4)} DEM`;

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

async function negotiate(): Promise<{ seller: NetworkedResult; sellerId: string; buyerId: string }> {
  const scan: ScanFacts = { repo: REPO, kloc: 9, fileCount: 60, hasSolidity: true, numTools: toolsForScan(true) };
  const sellerGuard = sellerGuardFor(scan, TIERS, DEADLINES, DEFAULT_ECONOMICS);
  const buyerGuard: BuyerGuard = { offeredTiers: TIERS, offeredDeadlines: DEADLINES, budget: 30, acceptableTiers: ["deep"] };
  const [chanS, chanB] = InProcessChannelPair();
  const [seller] = await Promise.all([
    runSide({
      role: "seller", channelId: CHANNEL, policy: deterministicSeller({ scan, guard: sellerGuard, econ: DEFAULT_ECONOMICS }),
      maySettle: (t) => sellerMaySettle(t, sellerGuard), peerSenderId: "buyer-peer", signer: fakeSigner("seller-peer"), channel: chanS, maxTurns: 6,
    }),
    runSide({
      role: "buyer", channelId: CHANNEL, policy: deterministicBuyer({ guard: buyerGuard, preferredTier: "deep", preferredDeadline: "standard" }),
      maySettle: (t) => buyerMaySettle(t, buyerGuard), peerSenderId: "seller-peer", signer: fakeSigner("buyer-peer"), channel: chanB, maxTurns: 6,
    }),
  ]);
  return { seller, sellerId: "seller-peer", buyerId: "buyer-peer" };
}

async function main() {
  console.log(`\n=== NEGOTIATE → BIND → SETTLE (${CONFIRM ? "LIVE BROADCAST" : "DRY RUN"}) ===\n`);

  // 1. Negotiate.
  const { seller, sellerId, buyerId } = await negotiate();
  if (seller.outcome !== "agreed" || !seller.agreed) {
    console.log(`negotiation did not agree: ${seller.reason}`);
    process.exit(1);
  }
  console.log(`1. negotiated: ${seller.agreed.tier}/${seller.agreed.deadline} @ ${seller.agreed.price} DEM (${seller.turns} turns)`);

  // 2. Bind.
  const agreement = buildChannelAgreement({
    jobId: JOB, channelId: CHANNEL, agreed: seller.agreed, sellerId, buyerId,
    envelopes: seller.envelopes, generatedAt: new Date().toISOString(),
  });
  const aHash = agreementHash(agreement);
  const params = sessionOpenParams(agreement, REPO);
  console.log(`2. bound: agreementHash ${aHash.slice(0, 16)}…  lastMessageHash ${agreement.derivedFromChannel.lastMessageHash.slice(0, 16)}…`);
  console.log(`   session-open params: ${JSON.stringify(params)}`);

  // 3. Connect wallets.
  if (!existsSync(BUYER_KEY) || !existsSync(SELLER_KEY)) {
    console.log(`\n⚠ persisted L1 wallets not found (${BUYER_KEY}). Run \`npm run dacs:l1\` once to create+fund them, then retry.`);
    process.exit(2);
  }
  const buyer = await connectIdentity("Buyer", RPC, readFileSync(BUYER_KEY, "utf8").trim());
  const seller2 = await connectIdentity("Seller", RPC, readFileSync(SELLER_KEY, "utf8").trim());
  const buyerW = (buyer.adapter as unknown as { raw: WalletLike }).raw;
  const sellerAddr = seller2.address;
  const buyerBal = BigInt((await buyerW.getAddressInfo(buyer.address))?.balance ?? 0n);
  console.log(`\n3. wallets:`);
  console.log(`   buyer  ${buyer.address}  balance ${osToDem(buyerBal)}`);
  console.log(`   seller ${sellerAddr}`);
  console.log(`   would settle ${osToDem(SETTLE_OS)} (${SETTLE_OS} OS) buyer → seller, bound to job ${JOB}`);

  // 4. Settle (only when confirmed).
  if (!CONFIRM) {
    console.log(`\nDRY RUN — set SETTLE_CONFIRM=1 to broadcast. No transaction sent.`);
    process.exit(0);
  }
  if (buyerBal < SETTLE_OS) {
    console.log(`\n❌ buyer balance ${osToDem(buyerBal)} < settle amount ${osToDem(SETTLE_OS)}. Fund the buyer wallet (faucet or \`npm run dacs:l1\`) and retry.`);
    process.exit(3);
  }

  console.log(`\n4. broadcasting pay-dem settlement…`);
  const signed = await buyerW.transfer(sellerAddr, SETTLE_OS);
  const validity = await buyerW.confirm(signed);
  const broadcast = await buyerW.broadcast(validity);
  if (broadcast?.result !== 200) {
    console.log(`❌ broadcast rejected: ${JSON.stringify(broadcast?.response ?? broadcast)}`);
    process.exit(4);
  }
  const txHash = broadcast.response?.hash ?? signed?.hash ?? "";
  console.log(`\n✅ SETTLED on-chain`);
  console.log(`   settlement record: ${JSON.stringify({ jobId: JOB, agreedPrice: seller.agreed.price, tier: seller.agreed.tier, settledOs: SETTLE_OS.toString(), agreementHash: aHash, lastMessageHash: agreement.derivedFromChannel.lastMessageHash, txHash })}`);
  console.log(`   explorer: https://explorer.demos.sh/tx/${txHash}`);
  process.exit(0);
}

interface WalletLike {
  transfer: (to: string, amount: bigint, opts?: { nonce?: number }) => Promise<{ hash?: string }>;
  confirm: (tx: unknown) => Promise<unknown>;
  broadcast: (v: unknown) => Promise<{ result?: number; response?: { hash?: string; message?: string } }>;
  getAddressInfo: (a: string) => Promise<{ balance?: bigint; nonce?: number } | null>;
}

main().catch((err) => {
  console.error("settle-live failed:", err?.message ?? err);
  process.exit(1);
});
