/**
 * L2 — ONE real x402 deal for the oracle desk, end to end.
 *
 *   npm run dacs:l2
 *
 * The sibling of L1 (`roster/dacs/live/l1-paydem.ts`): SAME oracle-desk DACS
 * lifecycle, SAME real DEM anchoring of every artifact (listing / agreement /
 * evidence / delivery / bundle) on the Demos testnet — but the SETTLEMENT rail
 * is swapped from native pay-dem to **pay-x402**: real USDC on **Base Sepolia**
 * through the public hosted facilitator (`https://x402.org/facilitator`), gasless
 * via EIP-3009. Vet on Demos, settle on Base — one vetted lifecycle, two chains.
 *
 * Wallets (all persisted; key files git-ignored):
 *   - DEM anchoring identities REUSE L1's established wallets
 *     (`.l1-seller-key`, `.l1-buyer-key`) — they anchor cleanly and are
 *     established across runs. Funded from the shared funder only if low.
 *   - The buyer's USDC payer is the persisted EVM wallet `.l2-buyer-evm-key`
 *     (address 0xA0a1…ba2B). Loaded, never regenerated.
 *   - The seller's USDC payout address is a persisted EVM wallet
 *     `.l2-seller-evm-key` — only its address is needed as the paywall `payTo`.
 *
 * CRITICAL — funding gate (no partial deals): before ANY on-chain action we read
 * the buyer's USDC balance on Base Sepolia. If it is < 1 USDC we print the
 * funding instructions and EXIT 0 without touching either chain — a clean gate,
 * not a failure. Only when USDC ≥ 1 does the full deal run.
 *
 * Flow (when funded): reduced-mode (no CCI vet). Seller publishes an oracle-desk
 * listing advertising `supportedPaymentRails:["pay-x402"]` (anchored on DEM) →
 * buyer forms the agreement (anchored on DEM) → buyer settles via the seller's
 * x402 paywall (real USDC on Base Sepolia through the facilitator); the paywall
 * delivers the oracle chain-height value + anchors the DACS-X delivery
 * attestation on DEM → verifier verifies the delivery + reads the x402
 * SettlementEvidence (carrying `settlementTxHash` + `chainId` from the
 * facilitator's PAYMENT-RESPONSE).
 *
 * Every real Base Sepolia settlement tx hash, DEM anchor address, USDC balance
 * before/after, and the final verify result is printed AND written to
 * `roster/dacs/live/L2-run.log` (git-ignored).
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import type { SessionTerms } from "@kynesyslabs/dacs";
import type {
  SettleRequest,
  SettleResult,
} from "../../../sdk/dist/agent/runSessionCore.js";

import { connectIdentity, type LiveIdentity } from "../../../src/live/identity.js";
import { LiveSubstrate } from "../../../src/live/substrate.js";
import { SellerAdapter } from "../seller-adapter.js";
import { BuyerAdapter } from "../buyer.js";
import { VerifierAdapter } from "../verifier.js";
import {
  ORACLE_SERVICE_ID,
  makeOracleWork,
  oracleListingSpec,
  oracleObserveDelivered,
} from "../wire/oracle-desk.js";
import { RealAttestedFetch } from "../../oracle-desk/attested-fetch.js";
import { startX402Paywall } from "./x402-paywall.js";

// ── x402 / Base Sepolia ground truth (proven in ReviewBot's live Deal B) ─────
const X402_NETWORK = "eip155:84532" as const;
const USDC_BASE_SEPOLIA = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const FACILITATOR_URL = process.env.X402_FACILITATOR ?? "https://x402.org/facilitator";
const BASE_SEPOLIA_RPC = process.env.BASE_SEPOLIA_RPC ?? "https://sepolia.base.org";
/** Price: 1 USDC (6 decimals). */
const USDC_AMOUNT = "1000000";
/** Funding-gate threshold: the buyer must hold ≥ 1 USDC to run the deal. */
const USDC_MIN = 1_000_000n;
const PAYWALL_PORT = Number(process.env.L2_PAYWALL_PORT ?? 4022);

// ── DEM ground truth (identical to L1 — reuse the established wallets) ───────
const RPC = process.env.DEMOS_RPC ?? "https://demosnode.discus.sh/";
const FUNDER_MNEMONIC = (() => {
  const value = process.env.FUNDER_MNEMONIC?.trim();
  if (!value) throw new Error("FUNDER_MNEMONIC is required; never embed wallet mnemonics in source");
  return value;
})();

/** 1 DEM = 10^9 OS (§9.5.9, integer arithmetic). */
const OS_PER_DEM = 1_000_000_000n;
/** Seed for a first-run DEM wallet (only used if a reused wallet runs low). */
const SELLER_SEED_OS = 10n * OS_PER_DEM;
const SELLER_MIN_OS = 5n * OS_PER_DEM;
const BUYER_SEED_OS = 12n * OS_PER_DEM;
const BUYER_MIN_OS = 6n * OS_PER_DEM;

// Reuse L1's established DEM wallets (they anchor cleanly; established across runs).
const SELLER_KEY_PATH = join(process.cwd(), "roster/dacs/live/.l1-seller-key");
const BUYER_KEY_PATH = join(process.cwd(), "roster/dacs/live/.l1-buyer-key");
// The buyer's USDC payer (already generated + persisted; never regenerated).
const BUYER_EVM_KEY_PATH = join(process.cwd(), "roster/dacs/live/.l2-buyer-evm-key");
// The seller's USDC payout (generated + persisted here; only its address is used).
const SELLER_EVM_KEY_PATH = join(process.cwd(), "roster/dacs/live/.l2-seller-evm-key");

/** The minimal demosdk wallet surface (via `adapter.raw`). */
interface Wallet {
  transfer: (to: string, amount: bigint, opts?: { nonce?: number }) => Promise<{ hash?: string }>;
  confirm: (tx: unknown) => Promise<unknown>;
  broadcast: (v: unknown) => Promise<{
    result?: number;
    response?: { hash?: string; message?: string };
    extra?: { confirmationBlock?: number };
  }>;
  getAddressInfo: (a: string) => Promise<{ balance?: bigint; nonce?: number } | null>;
  getAddressNonce: (a: string) => Promise<number>;
  getLastBlockNumber: () => Promise<number>;
  getAddress: () => string;
}

const wallet = (id: LiveIdentity): Wallet =>
  (id.adapter as unknown as { raw: Wallet }).raw;

/**
 * A substrate view that retries `anchor` harder than `LiveSubstrate` does — the
 * public node's fresh-account state is racy (transient "hash mismatch" /
 * "Insufficient balance"); wrapping the SDK's own 3 internal retries in a
 * longer backoff loop gives the node time to reach a consistent view. Lifted
 * verbatim from L1 (T9: substrate fault ≠ party fault).
 */
class RetryingSubstrate {
  constructor(
    private readonly inner: LiveSubstrate,
    private readonly attempts = 4,
    private readonly backoffMs = 6000,
  ) {}
  async anchor(name: string, value: object): Promise<string> {
    let last: unknown;
    for (let i = 0; i < this.attempts; i++) {
      try {
        return await this.inner.anchor(name, value);
      } catch (e) {
        last = e;
        const msg = (e as Error)?.message ?? String(e);
        step("anchor-retry", `"${name}" attempt ${i + 1}/${this.attempts} failed (${msg.slice(0, 60)}…) — backing off`);
        await sleep(this.backoffMs);
      }
    }
    throw last;
  }
  async anchorWithReceipt(name: string, value: object): ReturnType<LiveSubstrate["anchorWithReceipt"]> {
    let last: unknown;
    for (let i = 0; i < this.attempts; i++) {
      try { return await this.inner.anchorWithReceipt(name, value); }
      catch (e) { last = e; await sleep(this.backoffMs); }
    }
    throw last;
  }
  resolveAnchorReceipt(txRef: string): ReturnType<LiveSubstrate["resolveAnchorReceipt"]> {
    return this.inner.resolveAnchorReceipt(txRef);
  }
  anchorAddress(name: string): Promise<string> {
    return this.inner.anchorAddress(name);
  }
  anchorAddressFor(owner: string, name: string): Promise<string> {
    return this.inner.anchorAddressFor(owner, name);
  }
  readAnchorFor(owner: string, name: string): Promise<Record<string, unknown> | null> {
    return this.inner.readAnchorFor(owner, name);
  }
  read(ref: string): Promise<Record<string, unknown> | null> {
    return this.inner.read(ref);
  }
  proxyFetch(req: { url: string; method?: string }): ReturnType<LiveSubstrate["proxyFetch"]> {
    return this.inner.proxyFetch(req);
  }
}

const osToDem = (os: bigint): string => `${(Number(os) / 1e9).toFixed(4)} DEM`;
const rawToUsdc = (raw: bigint): string => `${(Number(raw) / 1e6).toFixed(6)} USDC`;

// ── Log sink: everything printed also lands in L2-run.log ───────────────────
const logLines: string[] = [];
const line = (s = ""): void => {
  console.log(s);
  logLines.push(s);
};
const step = (n: string, msg: string): void => line(`  ${n.padEnd(12)} ${msg}`);
const LOG_PATH = join(process.cwd(), "roster/dacs/live/L2-run.log");
function flushLog(): void {
  try {
    writeFileSync(LOG_PATH, logLines.join("\n") + "\n");
  } catch {
    /* best-effort */
  }
}

async function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

interface TxRecord {
  hash: string;
  confirmationBlock?: number;
}

/** The verified DEM settlement path: transfer → confirm → broadcast. */
async function payDem(w: Wallet, to: string, amountOs: bigint): Promise<TxRecord> {
  const signed = await w.transfer(to, amountOs);
  const validity = await w.confirm(signed);
  const broadcast = await w.broadcast(validity);
  if (broadcast?.result !== 200) {
    throw new Error(`pay-dem broadcast rejected: ${JSON.stringify(broadcast?.response ?? broadcast)}`);
  }
  return {
    hash: broadcast.response?.hash ?? (signed as { hash?: string })?.hash ?? "",
    confirmationBlock: broadcast.extra?.confirmationBlock,
  };
}

/** Poll until an address's nonce strictly exceeds `before` (serial-nonce discipline). */
async function waitNonceAdvance(w: Wallet, addr: string, before: number, tries = 40): Promise<boolean> {
  for (let i = 0; i < tries; i++) {
    const now = Number((await w.getAddressInfo(addr).catch(() => null))?.nonce ?? before);
    if (now > before) return true;
    await sleep(3000);
  }
  return false;
}

/** Poll until an address's balance reaches at least `min`. */
async function waitBalanceAtLeast(w: Wallet, addr: string, min: bigint, tries = 40): Promise<bigint> {
  let bal = 0n;
  for (let i = 0; i < tries; i++) {
    bal = BigInt((await w.getAddressInfo(addr).catch(() => null))?.balance ?? 0n);
    if (bal >= min) return bal;
    await sleep(3000);
  }
  return bal;
}

/**
 * Robustly ESTABLISH a freshly-funded DEM wallet before it anchors (settled
 * outgoing-nonce baseline + a stability gate). Only reached on a first-run /
 * low-balance top-up; the reused L1 wallets are already established. Lifted
 * from L1.
 */
async function establishWallet(w: Wallet, addr: string, fundingBlock: number): Promise<{ warmups: TxRecord[]; stable: boolean }> {
  const warmups: TxRecord[] = [];
  for (let i = 0; i < 3; i++) {
    const before = Number((await w.getAddressInfo(addr))?.nonce ?? 0);
    const tx = await payDem(w, addr, 1n);
    await waitNonceAdvance(w, addr, before);
    warmups.push(tx);
  }
  const startBlock = fundingBlock || Number(await w.getLastBlockNumber().catch(() => 0));
  for (let attempt = 0; attempt < 40; attempt++) {
    const reads: Array<{ balance?: bigint; nonce?: number } | null> = [];
    for (let k = 0; k < 3; k++) {
      reads.push(await w.getAddressInfo(addr).catch(() => null));
      await sleep(1500);
    }
    const nonces = reads.map((r) => Number(r?.nonce ?? -1));
    const nonceStable = nonces.every((n) => n >= 0 && n === nonces[0]);
    const balOk = reads.every((r) => BigInt(r?.balance ?? 0n) > 0n);
    const block = Number(await w.getLastBlockNumber().catch(() => startBlock));
    const blocksAdvanced = block >= startBlock + 5;
    if (nonceStable && balOk && blocksAdvanced) return { warmups, stable: true };
    await sleep(5000);
  }
  return { warmups, stable: false };
}

interface EstablishResult {
  fundTx?: TxRecord;
  warmups: TxRecord[];
}

/** Ensure a DEDICATED DEM wallet is funded + established (top-up only if low). */
async function ensureEstablished(
  funderW: Wallet,
  funderAddr: string,
  w: Wallet,
  addr: string,
  seedOs: bigint,
  minOs: bigint,
  label: string,
): Promise<EstablishResult> {
  const out: EstablishResult = { warmups: [] };
  const bal0 = BigInt((await w.getAddressInfo(addr))?.balance ?? 0n);
  step(`${label} bal`, `${osToDem(bal0)}`);
  if (bal0 >= minOs) {
    step(label, "reusing established persisted wallet (sufficient balance) — no funding/warm-up");
    return out;
  }

  const fundNonce = await funderW.getAddressNonce(funderAddr);
  const fundTx = await payDem(funderW, addr, seedOs);
  out.fundTx = fundTx;
  step(`fund→${label}`, `${osToDem(seedOs)}  tx ${fundTx.hash}  block ${fundTx.confirmationBlock ?? "?"}`);
  if (!(await waitNonceAdvance(funderW, funderAddr, fundNonce))) {
    throw new Error(`funder nonce did not advance after funding ${label}`);
  }
  const funded = await waitBalanceAtLeast(w, addr, bal0 + seedOs - OS_PER_DEM);
  step("", `${label} balance landed: ${osToDem(funded)}`);

  // A reused-but-drained wallet is already established; only a genuinely fresh
  // one needs the warm-up gate. Reuse L1's stability gate defensively.
  const est = await establishWallet(w, addr, fundTx.confirmationBlock ?? 0);
  out.warmups = est.warmups;
  for (const t of est.warmups) step(`warm ${label}`, `self-tx ${t.hash}  block ${t.confirmationBlock ?? "?"}`);
  step("establish", `${label} stable=${est.stable}`);
  if (!est.stable) {
    throw new Error(`${label} account did not stabilise on the node (nonce/balance/block gate) — see L2-run.log`);
  }
  return out;
}

// ── EVM wallet helpers (viem, lazily imported so DEM-only paths stay light) ──
async function loadOrCreateSellerEvm(): Promise<{ address: string; isNew: boolean }> {
  // @ts-expect-error — viem ships no co-located ESM types at this deep vendored path
  const { privateKeyToAccount, generatePrivateKey } = await import("../../../sdk/node_modules/viem/_esm/accounts/index.js");
  if (existsSync(SELLER_EVM_KEY_PATH)) {
    const key = readFileSync(SELLER_EVM_KEY_PATH, "utf8").trim();
    return { address: privateKeyToAccount(key as `0x${string}`).address, isNew: false };
  }
  const key = generatePrivateKey();
  writeFileSync(SELLER_EVM_KEY_PATH, key + "\n", { mode: 0o600 });
  return { address: privateKeyToAccount(key).address, isNew: true };
}

async function readUsdcBalance(address: string): Promise<bigint> {
  // @ts-expect-error — viem ships no co-located ESM types at this deep vendored path
  const { createPublicClient, http } = await import("../../../sdk/node_modules/viem/_esm/index.js");
  const client = createPublicClient({ transport: http(BASE_SEPOLIA_RPC) });
  return (await client.readContract({
    address: USDC_BASE_SEPOLIA as `0x${string}`,
    abi: [
      {
        name: "balanceOf",
        type: "function",
        stateMutability: "view",
        inputs: [{ name: "a", type: "address" }],
        outputs: [{ type: "uint256" }],
      },
    ] as const,
    functionName: "balanceOf",
    args: [address as `0x${string}`],
  })) as bigint;
}

async function main(): Promise<void> {
  line("┌────────────────────────────────────────────────────────────────────────┐");
  line("│  L2 — real x402 deal (USDC on Base Sepolia) for the oracle desk          │");
  line("│       DACS artifacts anchored on the Demos testnet (same as L1)          │");
  line("└────────────────────────────────────────────────────────────────────────┘");
  line(`  demos rpc    ${RPC}`);
  line(`  base rpc     ${BASE_SEPOLIA_RPC}`);
  line(`  facilitator  ${FACILITATOR_URL}`);
  line(`  when         ${new Date().toISOString()}`);

  // ── 0. EVM coordinates (local only — no chain yet) ────────────────────────
  const buyerEvmKey = readFileSync(BUYER_EVM_KEY_PATH, "utf8").trim();
  // @ts-expect-error — viem ships no co-located ESM types at this deep vendored path
  const { privateKeyToAccount } = await import("../../../sdk/node_modules/viem/_esm/accounts/index.js");
  const buyerEvmAddr = privateKeyToAccount(buyerEvmKey as `0x${string}`).address;
  const sellerEvm = await loadOrCreateSellerEvm();
  step("buyer EVM", `${buyerEvmAddr}  (USDC payer, persisted)`);
  step("seller EVM", `${sellerEvm.address}  (USDC payout / payTo, ${sellerEvm.isNew ? "new this run" : "persisted"})`);

  // ── 1. FUNDING GATE — read USDC on Base Sepolia BEFORE touching any chain ──
  line("\n── funding gate: buyer USDC balance on Base Sepolia ──");
  const usdc = await readUsdcBalance(buyerEvmAddr);
  step("USDC bal", `${rawToUsdc(usdc)}  (raw ${usdc})`);
  if (usdc < USDC_MIN) {
    line("\n════════════════════ L2 FUNDING GATE ════════════════════");
    line(`  status            FUNDING-GATE (buyer unfunded — no deal started)`);
    line(`  buyer EVM address ${buyerEvmAddr}`);
    line(`  USDC balance      ${rawToUsdc(usdc)}  (need ≥ 1 USDC)`);
    line("");
    line(`  → Fund ${buyerEvmAddr} with ≥2 USDC on Base Sepolia`);
    line(`    via https://faucet.circle.com (select Base Sepolia),`);
    line(`    then re-run \`npm run dacs:l2\`.`);
    line("");
    line("  Nothing was anchored on either chain — this is a clean gate, not a failure.");
    line("══════════════════════════════════════════════════════════");
    flushLog();
    console.log(`\n  (report written → ${LOG_PATH})`);
    process.exit(0);
  }

  // ── 2. FUNDED: connect DEM wallets (reuse L1's established seller + buyer) ──
  line("\n── funded: assembling the DEM anchoring identities (reused from L1) ──");
  const funder = await connectIdentity("Funder", RPC, FUNDER_MNEMONIC);
  const funderW = wallet(funder);
  const funderBal0 = BigInt((await funderW.getAddressInfo(funder.address))?.balance ?? 0n);
  step("funder", `${funder.address}  (funding source only)  balance ${osToDem(funderBal0)}`);

  if (!existsSync(SELLER_KEY_PATH) || !existsSync(BUYER_KEY_PATH)) {
    throw new Error("expected L1's established DEM wallets (.l1-seller-key / .l1-buyer-key) — run `npm run dacs:l1` first");
  }
  const seller = await connectIdentity("OracleDesk", RPC, readFileSync(SELLER_KEY_PATH, "utf8").trim());
  const buyer = await connectIdentity("Buyer", RPC, readFileSync(BUYER_KEY_PATH, "utf8").trim());
  const sellerW = wallet(seller);
  const buyerW = wallet(buyer);
  step("seller", `${seller.address}  [persisted/established from L1]`);
  step("", `did ${seller.did}`);
  step("buyer", `${buyer.address}  [persisted/established from L1]`);
  step("", `did ${buyer.did}`);

  // ── 3. Top up the DEM wallets only if low (funder txs serialised) ─────────
  const sellerEst = await ensureEstablished(funderW, funder.address, sellerW, seller.address, SELLER_SEED_OS, SELLER_MIN_OS, "seller");
  const buyerEst = await ensureEstablished(funderW, funder.address, buyerW, buyer.address, BUYER_SEED_OS, BUYER_MIN_OS, "buyer");

  // ── 4. Agents on the live substrate ───────────────────────────────────────
  const sellerSub = new RetryingSubstrate(new LiveSubstrate(seller.adapter));
  const buyerSub = new RetryingSubstrate(new LiveSubstrate(buyer.adapter));
  const sellerAgent = new SellerAdapter(
    seller,
    sellerSub,
    ORACLE_SERVICE_ID,
    makeOracleWork(new RealAttestedFetch()), // LIVE upstream fetch
  );
  const buyerAgent = new BuyerAdapter(buyer, buyerSub);
  const verifier = new VerifierAdapter(buyerSub);

  // ── 4a. Publish the listing (real on-chain DEM anchor), pay-x402 rail ─────
  line("\n── deal: oracle desk sells an attested chain-height lookup on pay-x402 ──");
  const USDC_PRICE = { amount: USDC_AMOUNT, asset: "USDC" };
  const listingRef = await sellerAgent.publishListing({
    ...oracleListingSpec(USDC_PRICE),
    supportedPaymentRails: ["pay-x402"],
  });
  step("DACS-1", `listing anchored on DEM → ${listingRef}`);

  const found = await buyerAgent.discover([listingRef]);
  step("discover", `buyer resolved "${found[0]?.listing.name}" (rails ${JSON.stringify(found[0]?.listing.supportedPaymentRails)})`);

  // ── 4b. Seller's x402 paywall — the SELLER half against the hosted facilitator ─
  const jobId = `l2-${Date.now()}`;
  const params = { product: "chain-height" };
  let deliveredValue: unknown;

  const paywall = await startX402Paywall({
    port: PAYWALL_PORT,
    route: "/oracle",
    payTo: sellerEvm.address,
    network: X402_NETWORK,
    asset: USDC_BASE_SEPOLIA,
    amount: USDC_AMOUNT,
    facilitatorUrl: FACILITATOR_URL,
    description: "Attested oracle chain-height lookup (DACS pay-x402)",
    // The work callback: run the oracle-desk delivery (live upstream fetch) +
    // anchor the DACS-X delivery attestation on DEM. Runs BEFORE settlement.
    deliver: async (jid, p) => {
      const d = await sellerAgent.deliver(jid, { ...params, ...p });
      deliveredValue = (d.attestation.meta as { value?: unknown } | undefined)?.value;
      step("deliver", `seller anchored DACS-X delivery on DEM → ${d.attestationRef}  (value ${JSON.stringify(deliveredValue)})`);
      return { result: d.result, attestationRef: d.attestationRef };
    },
  });
  step("paywall", `seller x402 endpoint up → ${paywall.url}`);

  // ── 4c. Buyer's x402 rail — the SDK's real EIP-3009 dance ─────────────────
  const { createX402Rail } = await import("@kynesyslabs/dacs");
  const rail = await createX402Rail({ evmPrivateKey: buyerEvmKey });
  step("rail", `buyer x402 rail ready (payer ${rail.address}, gasless EIP-3009)`);

  // Balances just before settlement.
  const usdcBefore = await readUsdcBalance(buyerEvmAddr);
  const sellerUsdcBefore = await readUsdcBalance(sellerEvm.address);

  // ── 4d. The deal (reduced-mode, no vet) ───────────────────────────────────
  const terms: SessionTerms = {
    price: { amount: USDC_PRICE.amount, asset: USDC_PRICE.asset, decimals: 6, rail: "pay-x402" },
    deliveryPhase: "deliver-chain-height",
    deliveryFormat: "application/json",
  };

  const settleTx: { record?: SettleResult } = {};

  /**
   * x402 settle seam — the SDK's real buyer-side 402-dance against the seller's
   * paywall (GET → 402 → EIP-3009 sign → retry → facilitator settles on Base
   * Sepolia → 200 with X-PAYMENT-RESPONSE). x402 COUPLES pay+deliver: by the
   * time this returns, the paywall has already delivered + anchored the DACS-X
   * attestation on DEM, so we couple the receipt to an independent delivery
   * check (money-safe: ok only if settled AND the delivery is anchored).
   */
  const settle = async (req: SettleRequest): Promise<SettleResult> => {
    const url = `${paywall.url}?jobId=${encodeURIComponent(req.jobId)}&product=chain-height`;
    const pay = await rail.settle({
      paywallUrl: url,
      network: X402_NETWORK,
      recipientEvm: sellerEvm.address,
      amount: req.amount,
      asset: USDC_BASE_SEPOLIA, // §4.1 asset guard: the on-chain token id
    });
    settleTx.record = pay;
    step("x402", `402-dance settled: ok=${pay.ok}  tx ${pay.txHash}  (${pay.chainId})`);

    // Independent delivery check: the seller's DACS-X attestation must be
    // read-visible on DEM (the paywall anchored it during the dance).
    const deliveredAnchor = await buyerSub.read(
      await buyerSub.anchorAddressFor(seller.did, `dacsx:delivery:${req.jobId}`),
    );
    const delivered = deliveredAnchor !== null;

    return { ...pay, ok: pay.ok && delivered, payer: rail.address };
  };

  let result;
  try {
    result = await buyerAgent.buy(listingRef, terms, { jobId, settleFn: settle });
  } finally {
    await paywall.close();
  }
  step("DACS-3", `agreement anchored on DEM → ${result.agreementRef}`);
  step("DACS-4", `x402 settlement evidence anchored on DEM → ${result.settlementRef}`);
  step("DACS-5", `buyer bundle anchored on DEM → ${result.bundleRef}  (outcome: ${result.outcome})`);

  const sellerBundleRef = await sellerAgent.fulfil(jobId, buyer.did);
  step("fulfil", `seller countersigned bundle on DEM → ${sellerBundleRef}`);

  // ── 5. Verify from anchors alone + read the x402 evidence ─────────────────
  line("\n── verify (read-only, from DEM anchors) ──");
  const owners = { buyer: buyer.did, seller: seller.did };
  const bundleV = await verifier.verify(result.bundleRef, owners);
  step("bundle", `ok=${bundleV.ok} fullyVerified=${bundleV.fullyVerified ?? "-"}`);
  const deliveryV = await verifier.verifyDelivery(jobId, {
    serviceId: ORACLE_SERVICE_ID,
    sellerDid: seller.did,
    observeDelivered: oracleObserveDelivered(),
  });
  const attestedValue = (deliveryV.attestation?.meta as { value?: unknown } | undefined)?.value;
  step("delivery", `ok=${deliveryV.ok}${deliveryV.ok ? "" : ` (${deliveryV.reason})`}  attested value=${JSON.stringify(attestedValue)}`);
  const rec = await verifier.reconcile(result.bundleRef, sellerBundleRef, owners);
  step("reconcile", `two-sided (§10.4.3): reconciled=${rec.reconciled}${rec.reason ? ` (${rec.reason})` : ""}`);

  // Read the anchored x402 SettlementEvidence: its paymentTxRef carries the
  // Base Sepolia settlement tx hash + chainId (per the SDK's x402 evidence shape).
  const evidenceRaw = await buyerSub.read(
    await buyerSub.anchorAddressFor(buyer.did, `dacs4:evidence:${jobId}`),
  );
  const evidenceTx = (evidenceRaw as { paymentTxRefs?: Array<{ rail?: string; txHash?: string; kind?: string }> } | null)
    ?.paymentTxRefs?.[0];
  step("evidence", `x402 paymentTxRef → rail=${evidenceTx?.rail} txHash=${evidenceTx?.txHash}`);

  // ── 6. USDC balances after ────────────────────────────────────────────────
  await sleep(3000);
  const usdcAfter = await readUsdcBalance(buyerEvmAddr);
  const sellerUsdcAfter = await readUsdcBalance(sellerEvm.address);

  const verified =
    result.outcome === "completed" && bundleV.ok && deliveryV.ok && rec.reconciled;
  const settlementTxHash = settleTx.record?.txHash ?? evidenceTx?.txHash ?? "—";

  // ── Report ─────────────────────────────────────────────────────────────────
  line("\n════════════════════ L2 REPORT ════════════════════");
  line(`  status            ${verified ? "SETTLED-LIVE ✓" : "COMPLETED-WITH-CAVEAT (see verify)"}`);
  line(`  demos rpc         ${RPC}`);
  line(`  base sepolia rpc  ${BASE_SEPOLIA_RPC}`);
  line(`  facilitator       ${FACILITATOR_URL}`);
  line("");
  line("  settlement (pay-x402 §SR-4 — REAL USDC on Base Sepolia via hosted facilitator)");
  line(`    tx hash         ${settlementTxHash}`);
  line(`    chainId         ${settleTx.record?.chainId ?? X402_NETWORK}`);
  line(`    amount          ${rawToUsdc(BigInt(USDC_AMOUNT))}  (${USDC_AMOUNT} base units, 6dp)`);
  line(`    payer → payee   ${buyerEvmAddr}  →  ${sellerEvm.address}`);
  line("");
  line("  DEM anchoring identities (all DACS artifacts anchored on Demos, reused from L1)");
  line(`    seller          ${seller.address}`);
  line(`    seller did      ${seller.did}`);
  line(`    buyer           ${buyer.address}`);
  line(`    buyer did       ${buyer.did}`);
  if (sellerEst.fundTx) line(`    seller top-up   ${sellerEst.fundTx.hash}`);
  if (buyerEst.fundTx) line(`    buyer top-up    ${buyerEst.fundTx.hash}`);
  line("");
  line("  anchor addresses (on-chain-checkable via storage-program read)");
  line(`    DACS-1 listing   ${listingRef}`);
  line(`    DACS-3 agreement ${result.agreementRef}`);
  line(`    DACS-4 evidence  ${result.settlementRef}`);
  line(`    DACS-5 bundle    ${result.bundleRef}`);
  line(`    DACS-5 seller    ${sellerBundleRef}`);
  line(`    DACS-X delivery  ${await buyerSub.anchorAddressFor(seller.did, `dacsx:delivery:${jobId}`)}`);
  line("");
  line("  delivered value (LIVE upstream: current Bitcoin block height)");
  line(`    value           ${JSON.stringify(deliveredValue)}`);
  line("");
  line("  USDC balances on Base Sepolia (6dp base units)");
  line(`    buyer before    ${usdcBefore}  (${rawToUsdc(usdcBefore)})`);
  line(`    buyer after     ${usdcAfter}  (${rawToUsdc(usdcAfter)})   Δ ${rawToUsdc(usdcAfter - usdcBefore)}`);
  line(`    seller before   ${sellerUsdcBefore}  (${rawToUsdc(sellerUsdcBefore)})`);
  line(`    seller after    ${sellerUsdcAfter}  (${rawToUsdc(sellerUsdcAfter)})   Δ ${rawToUsdc(sellerUsdcAfter - sellerUsdcBefore)}`);
  line("");
  line("  verify");
  line(`    outcome         ${result.outcome}`);
  line(`    bundle ok       ${bundleV.ok}`);
  line(`    delivery ok     ${deliveryV.ok}`);
  line(`    reconciled      ${rec.reconciled}`);
  line("════════════════════════════════════════════════════");
  line(`\n${verified ? "✅" : "⚠"} L2 ${verified ? "settled live (USDC on Base Sepolia) and verified end-to-end." : "ran but a verify gate did not pass — see above."}\n`);

  flushLog();
  console.log(`  (report written → ${LOG_PATH})`);
  process.exit(verified ? 0 : 1);
}

main().catch((e) => {
  const msg = (e as Error)?.stack ?? (e as Error)?.message ?? String(e);
  console.error("\n❌ L2 failed:", msg);
  logLines.push(`\n❌ L2 failed: ${msg}`);
  flushLog();
  process.exit(1);
});
