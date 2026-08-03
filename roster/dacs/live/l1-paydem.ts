/**
 * L1 — ONE real pay-dem session deal on the Demos testnet, end to end.
 *
 *   npm run dacs:l1
 *
 * This is a REAL on-chain run (testnet, low stakes). It assembles the proven
 * pieces — `LiveSubstrate` for real anchoring, the `roster/dacs/` seller/buyer/
 * verifier layer, the oracle-desk wire — and settles a single fixed-price deal
 * over the native-DEM rail (§9.5.9), Pattern 2 (session / push).
 *
 * Both deal parties are DEDICATED, PERSISTED, ESTABLISHED wallets — never the
 * shared funder. The funder is a high-traffic wallet (ReviewBot's `npm run live`,
 * other operators, ad-hoc probes all use it); making it a transacting party lets
 * a concurrent funder tx move its nonce under one of our anchors, and the node
 * then rejects the anchor with "[SIGNATURE ERROR] Transaction hash mismatch"
 * (the serial-nonce collision documented in the Demos notes). So:
 *
 *   - FUNDER = one-time funding source ONLY; it never transacts in the deal.
 *   - SELLER = a persisted wallet (`roster/dacs/live/.l1-seller-key`, git-ignored):
 *     publishes the listing, delivers, and anchors the DACS-X attestation.
 *   - BUYER  = a persisted wallet (`roster/dacs/live/.l1-buyer-key`, git-ignored):
 *     runs the session, settles, and anchors agreement/evidence/bundle.
 *
 *   First run: each dedicated wallet is generated, funded once from the funder
 *   (funder txs strictly serialised on its own nonce), then ESTABLISHED robustly
 *   (warm-up self-transfers + a stability gate: balance > 0, identical nonce
 *   across 3 consecutive reads, ≥5 blocks advanced since funding). Subsequent
 *   runs reuse the already-established keys directly. Every tx is serialised
 *   per-wallet (nonce read fresh, wait for on-chain advance before the next).
 *
 * Flow: seller `publishListing` → buyer `runSessionCore` (reduced-mode, no vet)
 * settles DEM to the seller via `transfer → confirm → broadcast` → seller does a
 * LIVE upstream fetch (current Bitcoin block height) + anchors the DACS-X
 * delivery attestation → verifier verifies delivery + bundle + two-sided
 * reconcile from chain anchors alone.
 *
 * Every real tx hash (settlement + fundings + warm-ups), anchor address, balance
 * before/after, the settlement amount, and the final verify result are printed
 * AND written to `roster/dacs/live/L1-run.log` (git-ignored) — on-chain-checkable.
 *
 * The `chain-height` product returns a bare integer body (block count), so the
 * delivery result hashes cleanly (Build C/D noted the non-integer JSON hash
 * constraint on the JSON products — this side-steps it).
 */
import { randomBytes } from "node:crypto";
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

// ── Ground truth (verified live this session) ──────────────────────────────
const RPC = process.env.DEMOS_RPC ?? "https://demosnode.discus.sh/";
const FUNDER_MNEMONIC = (() => {
  const value = process.env.FUNDER_MNEMONIC?.trim();
  if (!value) throw new Error("FUNDER_MNEMONIC is required; never embed wallet mnemonics in source");
  return value;
})();

/** 1 DEM = 10^9 OS (§9.5.9, integer arithmetic). */
const OS_PER_DEM = 1_000_000_000n;
/** Deal price: 1 DEM. */
const PRICE_OS = 1n * OS_PER_DEM;
/**
 * Buyer seed. Each Demos tx costs ~1 DEM in fees, and a first-run buyer spends
 * on: ~3 warm-up self-txs (establishment) + agreement anchor + 1-DEM settlement
 * + evidence anchor + bundle anchor. 12 DEM gives comfortable headroom (funder
 * holds ~67k; still tidy).
 */
const BUYER_SEED_OS = 12n * OS_PER_DEM;
/** Reuse the persisted buyer without a top-up while it holds at least this much. */
const BUYER_MIN_OS = 6n * OS_PER_DEM;
/** Persisted buyer key (git-ignored). Present ⇒ an established wallet to reuse. */
const BUYER_KEY_PATH = join(process.cwd(), "roster/dacs/live/.l1-buyer-key");

/**
 * Seller seed. First-run seller spends on: ~3 warm-up self-txs (establishment)
 * + listing anchor + delivery anchor + fulfil anchor. 10 DEM gives headroom.
 * The seller is a DEDICATED wallet — never the shared funder — so its nonce is
 * uncontended (the funder is a high-traffic shared wallet; using it as a
 * transacting party lets a concurrent funder tx move the nonce under an anchor
 * → "[SIGNATURE ERROR] Transaction hash mismatch").
 */
const SELLER_SEED_OS = 10n * OS_PER_DEM;
/** Reuse the persisted seller without a top-up while it holds at least this much. */
const SELLER_MIN_OS = 5n * OS_PER_DEM;
/** Persisted seller key (git-ignored). Present ⇒ an established wallet to reuse. */
const SELLER_KEY_PATH = join(process.cwd(), "roster/dacs/live/.l1-seller-key");

/** The minimal wallet surface the demosdk `Demos` instance exposes (via `adapter.raw`). */
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
 * A substrate view that retries `anchor` harder than `LiveSubstrate` does.
 *
 * The public node's account-state accounting for freshly-created wallets is
 * racy: `getAddressNonce` briefly disagrees with the node's own expected
 * nonce, so the node rehashes a storage-program tx with a different nonce and
 * rejects it ("[SIGNATURE ERROR] Transaction hash mismatch"); balance reads
 * also flap to 0 ("Insufficient balance"). Both are transient node faults
 * (T9: substrate fault ≠ party fault). `LiveSubstrate.anchor` re-signs (fresh
 * nonce) on each of its 3 internal retries; wrapping it in a longer outer loop
 * with backoff gives the node time to reach a consistent view. All other
 * SubstratePort methods delegate straight through.
 */
class RetryingSubstrate {
  constructor(
    private readonly inner: LiveSubstrate,
    private readonly attempts = 4,
    private readonly backoffMs = 3000,
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

// ── Log sink: everything printed also lands in L1-run.log ──────────────────
const logLines: string[] = [];
const line = (s = ""): void => {
  console.log(s);
  logLines.push(s);
};
const step = (n: string, msg: string): void => line(`  ${n.padEnd(12)} ${msg}`);

async function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/** Poll until an address's nonce strictly exceeds `before` (serial-nonce discipline). */
async function waitNonceAdvance(w: Wallet, addr: string, before: number, tries = 80): Promise<boolean> {
  for (let i = 0; i < tries; i++) {
    const now = Number((await w.getAddressInfo(addr).catch(() => null))?.nonce ?? before);
    if (now > before) return true;
    await sleep(1500);
  }
  return false;
}

/** Poll until an address's balance reaches at least `min`. */
async function waitBalanceAtLeast(w: Wallet, addr: string, min: bigint, tries = 80): Promise<bigint> {
  let bal = 0n;
  for (let i = 0; i < tries; i++) {
    bal = BigInt((await w.getAddressInfo(addr).catch(() => null))?.balance ?? 0n);
    if (bal >= min) return bal;
    await sleep(1500);
  }
  return bal;
}

/**
 * Robustly ESTABLISH a freshly-funded wallet before it anchors anything.
 *
 * A brand-new account's state on the public node is racy — `getAddressNonce`
 * disagrees with the node's own expected nonce and the first storage-program
 * anchor is rejected ("hash mismatch"). Establishing = giving the account a
 * settled outgoing-nonce baseline: a few native self-transfers, then GATE on
 * genuine stability: balance > 0, an IDENTICAL nonce across 3 consecutive reads,
 * and ≥5 blocks advanced since funding. Returns the warm-up txs + whether stable.
 */
async function establishWallet(
  w: Wallet,
  addr: string,
  fundingBlock: number,
): Promise<{ warmups: TxRecord[]; stable: boolean }> {
  const warmups: TxRecord[] = [];
  for (let i = 0; i < 3; i++) {
    const before = Number((await w.getAddressInfo(addr))?.nonce ?? 0);
    const tx = await payDem(w, addr, 1n); // 1 OS to self
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

interface TxRecord {
  hash: string;
  confirmationBlock?: number;
}

/**
 * The verified settlement path: `transfer → confirm → broadcast`. Returns the
 * broadcast tx hash + confirmation block. Does NOT wait for nonce advance — the
 * caller decides when to serialise (funding vs. in-session settle differ).
 */
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

/** Load a persisted mnemonic, or generate + persist a new one (0600). */
async function loadOrCreateKey(path: string): Promise<{ mnemonic: string; isNew: boolean }> {
  if (existsSync(path)) return { mnemonic: readFileSync(path, "utf8").trim(), isNew: false };
  // @ts-expect-error — bip39 ships no ESM types at this deep path
  const { generateMnemonic } = await import("../../../sdk/node_modules/bip39/src/index.js");
  const mnemonic = generateMnemonic(128, () => randomBytes(16)) as string;
  writeFileSync(path, mnemonic + "\n", { mode: 0o600 });
  return { mnemonic, isNew: true };
}

interface EstablishResult {
  fundTx?: TxRecord;
  warmups: TxRecord[];
}

/**
 * Ensure a DEDICATED wallet is funded + established. The funder is used ONLY as
 * a one-time funding source here (never as a transacting party in the deal), and
 * its two funding txs are strictly serialised on the funder's own nonce (read
 * fresh, wait for advance) so nothing moves the nonce under a subsequent tx.
 */
async function ensureEstablished(
  funderW: Wallet,
  funderAddr: string,
  w: Wallet,
  addr: string,
  seedOs: bigint,
  minOs: bigint,
  isNew: boolean,
  label: string,
): Promise<EstablishResult> {
  const out: EstablishResult = { warmups: [] };
  const bal0 = BigInt((await w.getAddressInfo(addr))?.balance ?? 0n);
  step(`${label} bal`, `${osToDem(bal0)}`);
  if (!isNew && bal0 >= minOs) {
    step(label, "reusing established persisted wallet (sufficient balance) — no funding/warm-up");
    return out;
  }

  // Fund from the funder — serialise on the FUNDER's nonce (read fresh, advance).
  const fundNonce = await funderW.getAddressNonce(funderAddr);
  const fundTx = await payDem(funderW, addr, seedOs);
  out.fundTx = fundTx;
  step(`fund→${label}`, `${osToDem(seedOs)}  tx ${fundTx.hash}  block ${fundTx.confirmationBlock ?? "?"}`);
  if (!(await waitNonceAdvance(funderW, funderAddr, fundNonce))) {
    throw new Error(`funder nonce did not advance after funding ${label}`);
  }
  const funded = await waitBalanceAtLeast(w, addr, bal0 + seedOs - OS_PER_DEM);
  step("", `${label} balance landed: ${osToDem(funded)}`);

  if (isNew) {
    const est = await establishWallet(w, addr, fundTx.confirmationBlock ?? 0);
    out.warmups = est.warmups;
    for (const t of est.warmups) step(`warm ${label}`, `self-tx ${t.hash}  block ${t.confirmationBlock ?? "?"}`);
    step("establish", `${label} stable=${est.stable}`);
    if (!est.stable) {
      throw new Error(
        `${label} account did not stabilise on the node (nonce/balance/block gate) — public-node fresh-account flap; see L1-run.log`,
      );
    }
  }
  return out;
}

async function main(): Promise<void> {
  line("┌────────────────────────────────────────────────────────────────────────┐");
  line("│  L1 — real pay-dem session deal on the Demos testnet (oracle desk)       │");
  line("└────────────────────────────────────────────────────────────────────────┘");
  line(`  rpc          ${RPC}`);
  line(`  when         ${new Date().toISOString()}`);

  // ── 1. Wallets: DEDICATED persisted seller + buyer; funder only funds ─────
  // The FUNDER is a high-traffic SHARED wallet (ReviewBot's `npm run live`,
  // other operators, ad-hoc probes all use it). Using it as a transacting party
  // in the deal lets a concurrent funder tx move its nonce under one of our
  // anchors → "[SIGNATURE ERROR] Transaction hash mismatch". So the funder is
  // ONLY a one-time funding source; both deal parties are dedicated wallets.
  const funder = await connectIdentity("Funder", RPC, FUNDER_MNEMONIC);
  const funderW = wallet(funder);
  const funderBal0 = BigInt((await funderW.getAddressInfo(funder.address))?.balance ?? 0n);
  step("funder", `${funder.address}  (funding source only)  balance ${osToDem(funderBal0)}`);

  const sellerKey = await loadOrCreateKey(SELLER_KEY_PATH);
  const buyerKey = await loadOrCreateKey(BUYER_KEY_PATH);
  const seller = await connectIdentity("OracleDesk", RPC, sellerKey.mnemonic);
  const buyer = await connectIdentity("Buyer", RPC, buyerKey.mnemonic);
  const sellerW = wallet(seller);
  const buyerW = wallet(buyer);
  step("seller", `${seller.address}  [${sellerKey.isNew ? "new this run" : "persisted/established"}]`);
  step("", `did ${seller.did}`);
  step("buyer", `${buyer.address}  [${buyerKey.isNew ? "new this run" : "persisted/established"}]`);
  step("", `did ${buyer.did}`);

  // ── 2. Fund + establish BOTH dedicated wallets (funder txs serialised) ────
  line("\n── funding + establishing dedicated seller + buyer wallets ──");
  const sellerEst = await ensureEstablished(
    funderW, funder.address, sellerW, seller.address, SELLER_SEED_OS, SELLER_MIN_OS, sellerKey.isNew, "seller",
  );
  const buyerEst = await ensureEstablished(
    funderW, funder.address, buyerW, buyer.address, BUYER_SEED_OS, BUYER_MIN_OS, buyerKey.isNew, "buyer",
  );

  // ── 3. Agents on the live substrate ──────────────────────────────────────
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

  // ── 3a. Publish the listing (real on-chain anchor) ───────────────────────
  line("\n── deal: oracle desk sells an attested chain-height lookup on pay-dem ──");
  const DEM_PRICE = { amount: PRICE_OS.toString(), asset: "DEM" };
  const listingRef = await sellerAgent.publishListing({
    ...oracleListingSpec(DEM_PRICE),
    supportedPaymentRails: ["pay-dem"],
  });
  step("DACS-1", `listing anchored → ${listingRef}`);

  const found = await buyerAgent.discover([listingRef]);
  step("discover", `buyer resolved "${found[0]?.listing.name}" (rails ${JSON.stringify(found[0]?.listing.supportedPaymentRails)})`);

  // Balances just before settlement.
  const sellerBefore = BigInt((await sellerW.getAddressInfo(seller.address))?.balance ?? 0n);
  const buyerBefore = BigInt((await buyerW.getAddressInfo(buyer.address))?.balance ?? 0n);

  // ── 3b. The deal ─────────────────────────────────────────────────────────
  const terms: SessionTerms = {
    price: { amount: DEM_PRICE.amount, asset: DEM_PRICE.asset, decimals: 9, rail: "pay-dem" },
    deliveryPhase: "deliver-chain-height",
    deliveryFormat: "application/json",
  };
  const jobId = `l1-${Date.now()}`;
  const params = { product: "chain-height" };

  // Captured by the settle seam so we can report the money-movement tx.
  const settleTx: { record?: TxRecord; amountOs: bigint } = { amountOs: PRICE_OS };
  let deliveredValue: unknown;

  /**
   * pay-dem settle seam (Pattern 2, session/push) — the verified
   * transfer→confirm→broadcast path, buyer → seller, then couple to the
   * seller's live delivery. Serialise the buyer wallet after paying (the next
   * buyer tx is the SDK's evidence anchor, which self-resolves its nonce).
   */
  const settle = async (req: SettleRequest): Promise<SettleResult> => {
    const payeeHex = req.payee.match(/([0-9a-fA-F]{64})$/)?.[1];
    if (!payeeHex) throw new Error(`pay-dem: payee ${req.payee} has no resolvable Demos address`);
    const payee = `0x${payeeHex}`;

    const nonceBefore = Number((await buyerW.getAddressInfo(buyer.address))?.nonce ?? 0);
    const tx = await payDem(buyerW, payee, BigInt(req.amount));
    settleTx.record = tx;
    step("pay-dem", `settled ${osToDem(BigInt(req.amount))} buyer → seller  tx ${tx.hash}  block ${tx.confirmationBlock ?? "?"}`);

    // Serialise: wait for the buyer nonce to advance before the SDK anchors evidence.
    if (!(await waitNonceAdvance(buyerW, buyer.address, nonceBefore))) {
      throw new Error("buyer nonce did not advance after settlement — evidence anchor would collide");
    }

    // Push: the seller delivers now (live upstream fetch + on-chain DACS-X anchor).
    const delivery = await sellerAgent.deliver(req.jobId, params);
    deliveredValue = (delivery.attestation.meta as { value?: unknown } | undefined)?.value;
    step("deliver", `seller anchored DACS-X delivery → ${delivery.attestationRef}  (value ${JSON.stringify(deliveredValue)})`);

    // Independent delivery check: the seller's attestation must be read-visible.
    const deliveredAnchor = await buyerSub.read(
      await buyerSub.anchorAddressFor(seller.did, `dacsx:delivery:${req.jobId}`),
    );
    const delivered = deliveredAnchor !== null;

    return {
      ok: delivered && tx.hash.trim().length > 0,
      txHash: tx.hash,
      chainId: "demos",
      payer: buyer.address,
      payee,
    };
  };

  const result = await buyerAgent.buy(listingRef, terms, { jobId, settleFn: settle });
  step("DACS-3", `agreement anchored → ${result.agreementRef}`);
  step("DACS-4", `settlement evidence anchored → ${result.settlementRef}`);
  step("DACS-5", `buyer bundle anchored → ${result.bundleRef}  (outcome: ${result.outcome})`);

  const sellerBundleRef = await sellerAgent.fulfil(jobId, buyer.did);
  step("fulfil", `seller countersigned bundle → ${sellerBundleRef}`);

  // ── 4. Verify from anchors alone ─────────────────────────────────────────
  line("\n── verify (read-only, from chain anchors) ──");
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

  // ── 5. Balances after ────────────────────────────────────────────────────
  await sleep(3000);
  const sellerAfter = BigInt((await sellerW.getAddressInfo(seller.address))?.balance ?? 0n);
  const buyerAfter = BigInt((await buyerW.getAddressInfo(buyer.address))?.balance ?? 0n);

  const verified =
    result.outcome === "completed" && bundleV.ok && deliveryV.ok && rec.reconciled;

  // ── Report ───────────────────────────────────────────────────────────────
  line("\n════════════════════ L1 REPORT ════════════════════");
  line(`  status            ${verified ? "SETTLED-LIVE ✓" : "COMPLETED-WITH-CAVEAT (see verify)"}`);
  line(`  rpc               ${RPC}`);
  line("");
  line("  wallets (funder funds only; deal parties are dedicated wallets)");
  line(`    funder          ${funder.address}  [funding source only]`);
  line(`    seller          ${seller.address}  [${sellerKey.isNew ? "new this run" : "persisted/established"}]`);
  line(`    seller did      ${seller.did}`);
  line(`    buyer           ${buyer.address}  [${buyerKey.isNew ? "new this run" : "persisted/established"}]`);
  line(`    buyer did       ${buyer.did}`);
  line("");
  line("  funding + warm-up tx hashes (real, on-chain)");
  const fundLine = (label: string, est: EstablishResult, seed: bigint) => {
    if (est.fundTx) {
      line(`    fund→${label.padEnd(7)} ${est.fundTx.hash}  (${osToDem(seed)}, block ${est.fundTx.confirmationBlock ?? "?"})`);
      if (est.warmups.length) line(`    ${label} warm-ups ${est.warmups.map((t) => t.hash).join(", ")}`);
    } else {
      line(`    ${label}          reused established persisted wallet — no funding/warm-up this run`);
    }
  };
  fundLine("seller", sellerEst, SELLER_SEED_OS);
  fundLine("buyer", buyerEst, BUYER_SEED_OS);
  line("");
  line("  settlement (pay-dem §9.5.9, real transfer)");
  line(`    amount          ${osToDem(settleTx.amountOs)}  (${settleTx.amountOs} OS)`);
  line(`    tx hash         ${settleTx.record?.hash ?? "—"}  (block ${settleTx.record?.confirmationBlock ?? "?"})`);
  line(`    payer → payee   ${buyer.address}  →  ${seller.address}`);
  line("");
  line("  anchor addresses (on-chain-checkable via storage-program read)");
  line(`    DACS-1 listing  ${listingRef}`);
  line(`    DACS-3 agreement ${result.agreementRef}`);
  line(`    DACS-4 evidence ${result.settlementRef}`);
  line(`    DACS-5 bundle   ${result.bundleRef}`);
  line(`    DACS-5 seller   ${sellerBundleRef}`);
  line(`    DACS-X delivery ${await buyerSub.anchorAddressFor(seller.did, `dacsx:delivery:${jobId}`)}`);
  line("");
  line("  delivered value (LIVE upstream: current Bitcoin block height)");
  line(`    value           ${JSON.stringify(deliveredValue)}`);
  line("");
  line("  balances (OS base units)");
  line(`    seller before   ${sellerBefore}  (${osToDem(sellerBefore)})`);
  line(`    seller after    ${sellerAfter}  (${osToDem(sellerAfter)})   Δ ${osToDem(sellerAfter - sellerBefore)}`);
  line(`    buyer before    ${buyerBefore}  (${osToDem(buyerBefore)})`);
  line(`    buyer after     ${buyerAfter}  (${osToDem(buyerAfter)})   Δ ${osToDem(buyerAfter - buyerBefore)}`);
  line("");
  line("  verify");
  line(`    outcome         ${result.outcome}`);
  line(`    bundle ok       ${bundleV.ok}`);
  line(`    delivery ok     ${deliveryV.ok}`);
  line(`    reconciled      ${rec.reconciled}`);
  line("════════════════════════════════════════════════════");
  line(`\n${verified ? "✅" : "⚠"} L1 ${verified ? "settled live and verified end-to-end." : "ran but a verify gate did not pass — see above."}\n`);

  const logPath = join(process.cwd(), "roster/dacs/live/L1-run.log");
  writeFileSync(logPath, logLines.join("\n") + "\n");
  console.log(`  (report written → ${logPath})`);

  process.exit(verified ? 0 : 1);
}

main().catch((e) => {
  const msg = (e as Error)?.stack ?? (e as Error)?.message ?? String(e);
  console.error("\n❌ L1 failed:", msg);
  logLines.push(`\n❌ L1 failed: ${msg}`);
  try {
    writeFileSync(join(process.cwd(), "roster/dacs/live/L1-run.log"), logLines.join("\n") + "\n");
  } catch {
    /* best-effort */
  }
  process.exit(1);
});
