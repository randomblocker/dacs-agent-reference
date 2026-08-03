/**
 * L3 — the Procurement Butler drives a LIVE multi-seller basket across BOTH
 * settlement rails on the real chains, with the EvalBot gate live too.
 *
 *   npm run dacs:l3
 *
 * This composes the three proven pieces:
 *   - L1 (`l1-paydem.ts`): real DEM settlement + DACS anchoring on the Demos
 *     testnet via `transfer → confirm → broadcast`, strict per-wallet nonce
 *     serialisation, established/persisted wallets.
 *   - L2 (`l2-x402.ts` + `x402-paywall.ts`): real USDC settlement on Base
 *     Sepolia through the hosted facilitator (`https://x402.org/facilitator`).
 *   - Build C (`wire/butler.ts`, `DacsButlerBuyer`): anchored-listing discovery,
 *     rail-selection policy, purchase execution, accept + verify gating.
 *   - Build D (`wire/evaluator.ts` + `wire/evalbot.ts`): the EvalBot signed
 *     ruling gate for judgment deliverables.
 *
 * The Butler is the REAL Build-C decision engine: it discovers the two live
 * anchored listings, scores them, selects a rail per service (oracle → pay-x402,
 * dd-researcher → pay-dem), and EXECUTES each purchase through its own
 * `execute()` — but with LIVE settle seams injected: the oracle leg settles real
 * USDC on Base Sepolia through the L2 paywall + facilitator, and the dd leg
 * settles real DEM on Demos through the L1 transfer path (a live `DemLedgerPort`).
 * All DACS artifacts (listing / agreement / evidence / delivery / bundle) are
 * anchored on Demos for both. The dd report is a judgment deliverable, so the
 * Butler ends it `needs-evaluator`; EvalBot is then commissioned as a LIVE
 * seller (`wire/evalbot.ts`) to produce + anchor a signed `EvaluationRuling` on
 * Demos from a dedicated evalbot wallet, and dd acceptance flips on that ruling.
 *
 * REDUCED-MODE: no CCI vet (same as L1/L2).
 *
 * ⚠ Non-ASCII anchor bug: the Demos node rejects any storage-anchor payload
 * containing non-ASCII UTF-8 ("[SIGNATURE ERROR] Transaction hash mismatch").
 * The oracle delivery is ASCII (block height + ASCII attestation note — proven
 * in L1/L2). The dd-researcher report is REAL web text full of em-dashes/curly
 * quotes, so its DACS-X delivery attestation anchors ONLY the report's
 * content-HASH (ASCII hex) + ASCII-safe counts — NEVER the raw report body. The
 * full report is the OFF-CHAIN deliverable the buyer receives and hash-checks
 * (and feeds to EvalBot). The EvalBot ruling anchors only the ruling's own
 * verdict/scores/reasons (all ASCII, rubric-controlled) — never the report.
 *
 * Every real settlement tx hash (Base Sepolia USDC for oracle, Demos DEM for
 * dd), every anchor address, the Butler's decision + chosen rail, the
 * accept / needs-evaluator → ruling verdict, and balances before/after are
 * printed AND written to `roster/dacs/live/L3-run.log` (git-ignored).
 */
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { sha256Hex } from "@kynesyslabs/dacs";
import type { SessionTerms } from "@kynesyslabs/dacs";
import type {
  SettleRequest,
  SettleResult,
} from "../../../sdk/dist/agent/runSessionCore.js";
import { sessionAnchorName } from "../../../sdk/dist/agent/runSessionCore.js";

import { connectIdentity, type LiveIdentity } from "../../../src/live/identity.js";
import { LiveSubstrate } from "../../../src/live/substrate.js";
import { SellerAdapter, type WorkCallback, type DeliveryAttestation } from "../seller-adapter.js";
import { BuyerAdapter } from "../buyer.js";
import { VerifierAdapter, type DeliveryVerifyOptions, type DealOwners } from "../verifier.js";
import type { SettleSeam } from "../rails.js";
import {
  DacsButlerBuyer,
  type DacsOffer,
  type PurchaseOutcome,
  type SellerRuntime,
} from "../wire/butler.js";
import { rubricForOutcome } from "../wire/evaluator.js";
import type { ProcurementDecision, ProcurementGoal } from "../../procurement-butler/types.js";

// seller wires
import {
  ORACLE_SERVICE_ID,
  makeOracleWork,
  oracleListingSpec,
  oracleObserveDelivered,
} from "../wire/oracle-desk.js";
import {
  DD_SERVICE_ID,
  DD_DELIVERY_PHASE,
  ddListingSpec,
  subjectFromParams,
} from "../wire/dd-researcher.js";
import {
  EVALBOT_SERVICE_ID,
  EVALBOT_DELIVERY_PHASE,
  makeEvalBotWork,
  evalBotObserveDelivered,
} from "../wire/evalbot.js";
import { EvalBot, verifyRuling } from "../../evalbot/evalbot.js";
import type { EvaluationRuling } from "../../evalbot/types.js";
import { readReportMeta } from "../wire/report-meta.js";
import { DDResearcher } from "../../dd-researcher/researcher.js";
import { verifyReport } from "../../dd-researcher/report.js";
import type { DDReport } from "../../dd-researcher/types.js";
import { subjectSlug } from "../../dd-researcher/types.js";
import { RealAttestedFetch } from "../../oracle-desk/attested-fetch.js";
import { startX402Paywall } from "./x402-paywall.js";

// ── x402 / Base Sepolia ground truth (proven in L2) ──────────────────────────
const X402_NETWORK = "eip155:84532" as const;
const USDC_BASE_SEPOLIA = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const FACILITATOR_URL = process.env.X402_FACILITATOR ?? "https://x402.org/facilitator";
const BASE_SEPOLIA_RPC = process.env.BASE_SEPOLIA_RPC ?? "https://sepolia.base.org";
/** Oracle price: 1 USDC (6 decimals). */
const USDC_AMOUNT = "1000000";
/** Funding gate: the buyer must hold ≥ 1 USDC to run the oracle (x402) leg. */
const USDC_MIN = 1_000_000n;
const PAYWALL_PORT = Number(process.env.L3_PAYWALL_PORT ?? 4033);

// ── DEM ground truth (identical to L1/L2) ────────────────────────────────────
const RPC = process.env.DEMOS_RPC ?? "https://demosnode.discus.sh/";
const FUNDER_MNEMONIC = (() => {
  const value = process.env.FUNDER_MNEMONIC?.trim();
  if (!value) throw new Error("FUNDER_MNEMONIC is required; never embed wallet mnemonics in source");
  return value;
})();

/** 1 DEM = 10^9 OS (§9.5.9, integer arithmetic). */
const OS_PER_DEM = 1_000_000_000n;
/** dd deal price: 1 DEM. */
const DD_PRICE_OS = 1n * OS_PER_DEM;

// The buyer anchors agreement/evidence/bundle for BOTH deals + settles 1 DEM to
// dd; give it comfortable headroom.
const BUYER_SEED_OS = 24n * OS_PER_DEM;
const BUYER_MIN_OS = 14n * OS_PER_DEM;
// The oracle seller (reused from L1) publishes a listing + anchors delivery.
const ORACLE_SEED_OS = 12n * OS_PER_DEM;
const ORACLE_MIN_OS = 5n * OS_PER_DEM;
// New dedicated wallets for dd-researcher + evalbot: fund + establish.
const DD_SEED_OS = 12n * OS_PER_DEM;
const DD_MIN_OS = 5n * OS_PER_DEM;
const EVAL_SEED_OS = 12n * OS_PER_DEM;
const EVAL_MIN_OS = 5n * OS_PER_DEM;

// Persisted key files (all git-ignored).
const ORACLE_KEY_PATH = join(process.cwd(), "roster/dacs/live/.l1-seller-key"); // reuse L1's established seller
const BUYER_KEY_PATH = join(process.cwd(), "roster/dacs/live/.l1-buyer-key");
const BUYER_EVM_KEY_PATH = join(process.cwd(), "roster/dacs/live/.l2-buyer-evm-key");
const SELLER_EVM_KEY_PATH = join(process.cwd(), "roster/dacs/live/.l2-seller-evm-key");
const DD_KEY_PATH = join(process.cwd(), "roster/dacs/live/.l3-dd-seller-key");
const EVAL_KEY_PATH = join(process.cwd(), "roster/dacs/live/.l3-evalbot-key");

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

// ── Log sink ─────────────────────────────────────────────────────────────────
const logLines: string[] = [];
const line = (s = ""): void => {
  console.log(s);
  logLines.push(s);
};
const step = (n: string, msg: string): void => line(`  ${n.padEnd(13)} ${msg}`);
const LOG_PATH = join(process.cwd(), "roster/dacs/live/L3-run.log");
function flushLog(): void {
  try {
    writeFileSync(LOG_PATH, logLines.join("\n") + "\n");
  } catch {
    /* best-effort */
  }
}

/**
 * A substrate view that retries `anchor` harder than `LiveSubstrate` (the public
 * node's fresh-account state is racy). Lifted verbatim from L1/L2 (T9: substrate
 * fault ≠ party fault).
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

/**
 * Fold a string to pure ASCII so it can ride an anchored storage-program tx (the
 * Demos node rejects non-ASCII UTF-8 payloads with "[SIGNATURE ERROR] Transaction
 * hash mismatch"). Maps the common typographic offenders (em/en dashes, curly
 * quotes, arrows, ellipsis) to ASCII equivalents, strips anything else non-ASCII.
 * Used to normalise seller listing metadata before anchoring — e.g. the
 * dd-researcher wire's listing NAME carries an em-dash.
 */
function asciiSafe(s: string): string {
  return s
    .replace(/[‐-―−]/g, "-") // hyphens/dashes/minus
    .replace(/[‘’‛]/g, "'") // single curly quotes
    .replace(/[“”]/g, '"') // double curly quotes
    .replace(/…/g, "...") // ellipsis
    .replace(/[←-⇿]/g, "->") // arrows
    .replace(/[^\x00-\x7F]/g, ""); // strip any remaining non-ASCII
}

/** ASCII-normalise a listing spec's human-facing text (name/description). */
function asciiListing<T extends { name: string; description: string }>(spec: T): T {
  return { ...spec, name: asciiSafe(spec.name), description: asciiSafe(spec.description) };
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

/** Robustly ESTABLISH a freshly-funded wallet before it anchors (lifted from L1). */
async function establishWallet(w: Wallet, addr: string, fundingBlock: number): Promise<{ warmups: TxRecord[]; stable: boolean }> {
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
 * Ensure a DEDICATED wallet is funded + established. The funder is used ONLY as a
 * one-time funding source (never a transacting party), its funding tx strictly
 * serialised on the funder's own nonce. Lifted from L1.
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
    for (const t of est.warmups) step(`warm ${label}`, `self-tx ${t.hash}`);
    step("establish", `${label} stable=${est.stable}`);
    if (!est.stable) {
      throw new Error(`${label} account did not stabilise on the node (nonce/balance/block gate) — see L3-run.log`);
    }
  }
  return out;
}

// ── EVM helpers (viem, lazily imported) ──────────────────────────────────────
async function evmAddressOf(privKey: string): Promise<string> {
  // @ts-expect-error — viem ships no co-located ESM types at this deep vendored path
  const { privateKeyToAccount } = await import("../../../sdk/node_modules/viem/_esm/accounts/index.js");
  return privateKeyToAccount(privKey as `0x${string}`).address;
}

async function readUsdcBalance(address: string): Promise<bigint> {
  // @ts-expect-error — viem ships no co-located ESM types at this deep vendored path
  const { createPublicClient, http } = await import("../../../sdk/node_modules/viem/_esm/index.js");
  const client = createPublicClient({ transport: http(BASE_SEPOLIA_RPC) });
  return (await client.readContract({
    address: USDC_BASE_SEPOLIA as `0x${string}`,
    abi: [
      { name: "balanceOf", type: "function", stateMutability: "view", inputs: [{ name: "a", type: "address" }], outputs: [{ type: "uint256" }] },
    ] as const,
    functionName: "balanceOf",
    args: [address as `0x${string}`],
  })) as bigint;
}

// ── Per-deal captured state (for the report) ─────────────────────────────────
interface DealAnchors {
  listing: string;
  agreement: string;
  evidence: string;
  bundle: string;
  delivery: string;
  sellerBundle?: string;
}

async function main(): Promise<void> {
  line("┌────────────────────────────────────────────────────────────────────────┐");
  line("│  L3 — Butler drives a LIVE multi-seller basket (x402 + pay-dem + EvalBot) │");
  line("└────────────────────────────────────────────────────────────────────────┘");
  line(`  demos rpc    ${RPC}`);
  line(`  base rpc     ${BASE_SEPOLIA_RPC}`);
  line(`  facilitator  ${FACILITATOR_URL}`);
  line(`  when         ${new Date().toISOString()}`);

  // ── 0. EVM coordinates + funding gate on buyer USDC ───────────────────────
  const buyerEvmKey = readFileSync(BUYER_EVM_KEY_PATH, "utf8").trim();
  const buyerEvmAddr = await evmAddressOf(buyerEvmKey);
  const sellerEvmAddr = await evmAddressOf(readFileSync(SELLER_EVM_KEY_PATH, "utf8").trim());
  step("buyer EVM", `${buyerEvmAddr}  (USDC payer, persisted)`);
  step("seller EVM", `${sellerEvmAddr}  (USDC payout / payTo, persisted)`);

  line("\n── funding gate: buyer USDC balance on Base Sepolia (oracle leg) ──");
  const usdc0 = await readUsdcBalance(buyerEvmAddr);
  step("USDC bal", `${rawToUsdc(usdc0)}  (raw ${usdc0})`);
  if (usdc0 < USDC_MIN) {
    line("\n════════════════════ L3 FUNDING GATE ════════════════════");
    line(`  status            FUNDING-GATE (buyer unfunded — no deal started)`);
    line(`  buyer EVM address ${buyerEvmAddr}`);
    line(`  USDC balance      ${rawToUsdc(usdc0)}  (need ≥ 1 USDC)`);
    line(`  → Fund ${buyerEvmAddr} with ≥2 USDC on Base Sepolia (https://faucet.circle.com), then re-run.`);
    line("  Nothing was anchored on either chain — a clean gate, not a failure.");
    line("══════════════════════════════════════════════════════════");
    flushLog();
    console.log(`\n  (report written → ${LOG_PATH})`);
    process.exit(0);
  }

  // ── 1. Wallets ────────────────────────────────────────────────────────────
  const funder = await connectIdentity("Funder", RPC, FUNDER_MNEMONIC);
  const funderW = wallet(funder);
  const funderBal0 = BigInt((await funderW.getAddressInfo(funder.address))?.balance ?? 0n);
  step("funder", `${funder.address}  (funding source only)  balance ${osToDem(funderBal0)}`);

  if (!existsSync(ORACLE_KEY_PATH) || !existsSync(BUYER_KEY_PATH)) {
    throw new Error("expected L1's established DEM wallets (.l1-seller-key / .l1-buyer-key) — run `npm run dacs:l1` first");
  }
  const oracleKey = await loadOrCreateKey(ORACLE_KEY_PATH);
  const buyerKey = await loadOrCreateKey(BUYER_KEY_PATH);
  const ddKey = await loadOrCreateKey(DD_KEY_PATH);
  const evalKey = await loadOrCreateKey(EVAL_KEY_PATH);

  const oracleSeller = await connectIdentity("OracleDesk", RPC, oracleKey.mnemonic);
  const buyer = await connectIdentity("Buyer", RPC, buyerKey.mnemonic);
  const ddSeller = await connectIdentity("DDResearcher", RPC, ddKey.mnemonic);
  const evalbot = await connectIdentity("EvalBot", RPC, evalKey.mnemonic);
  const oracleW = wallet(oracleSeller);
  const buyerW = wallet(buyer);
  const ddW = wallet(ddSeller);
  const evalW = wallet(evalbot);
  step("oracle", `${oracleSeller.address}  [${oracleKey.isNew ? "new" : "persisted/established"}]`);
  step("buyer", `${buyer.address}  [${buyerKey.isNew ? "new" : "persisted/established"}]`);
  step("dd", `${ddSeller.address}  [${ddKey.isNew ? "new this run" : "persisted/established"}]`);
  step("evalbot", `${evalbot.address}  [${evalKey.isNew ? "new this run" : "persisted/established"}]`);

  // ── 2. Fund + establish all wallets (funder txs serialised) ───────────────
  line("\n── funding + establishing wallets ──");
  const oracleEst = await ensureEstablished(funderW, funder.address, oracleW, oracleSeller.address, ORACLE_SEED_OS, ORACLE_MIN_OS, oracleKey.isNew, "oracle");
  const ddEst = await ensureEstablished(funderW, funder.address, ddW, ddSeller.address, DD_SEED_OS, DD_MIN_OS, ddKey.isNew, "dd");
  const evalEst = await ensureEstablished(funderW, funder.address, evalW, evalbot.address, EVAL_SEED_OS, EVAL_MIN_OS, evalKey.isNew, "evalbot");
  const buyerEst = await ensureEstablished(funderW, funder.address, buyerW, buyer.address, BUYER_SEED_OS, BUYER_MIN_OS, buyerKey.isNew, "buyer");

  // ── 3. Agents on the live substrate ───────────────────────────────────────
  const buyerSub = new RetryingSubstrate(new LiveSubstrate(buyer.adapter));
  const oracleSub = new RetryingSubstrate(new LiveSubstrate(oracleSeller.adapter));
  const ddSub = new RetryingSubstrate(new LiveSubstrate(ddSeller.adapter));
  const evalSub = new RetryingSubstrate(new LiveSubstrate(evalbot.adapter));

  const oracleAgent = new SellerAdapter(oracleSeller, oracleSub, ORACLE_SERVICE_ID, makeOracleWork(new RealAttestedFetch()));

  // dd LIVE work callback: research live, keep the full report OFF-CHAIN (the
  // buyer's deliverable), anchor only the ASCII content-hash + counts.
  const ddResearcher = new DDResearcher(new RealAttestedFetch());
  const ddReportStash = new Map<string, DDReport>();
  const ddLiveWork: WorkCallback = async (jobId, params) => {
    const subject = subjectFromParams(params);
    const report = await ddResearcher.research(subject);
    const reportHash = sha256Hex(JSON.stringify(report));
    ddReportStash.set(jobId, report);
    // ASCII-only anchored content: slug + integer counts + hex hash. The raw
    // report (em-dashes, curly quotes) NEVER touches the anchor.
    return {
      result: {
        serviceId: DD_SERVICE_ID,
        subject: subjectSlug(subject),
        findings: report.findings.length,
        evidence: report.evidence.length,
        gaps: report.gaps.length,
        reportHash,
      },
      deliverableRef: `dd:report:${reportHash}`,
      meta: { reportHash },
    };
  };
  const ddAgent = new SellerAdapter(ddSeller, ddSub, DD_SERVICE_ID, ddLiveWork);

  // Shared, deterministic (LLM-off) EvalBot identity for the live gate seller.
  const gateBot = new EvalBot({ useLlm: false });
  const evalAgent = new SellerAdapter(evalbot, evalSub, EVALBOT_SERVICE_ID, makeEvalBotWork(gateBot));

  const buyerAgent = new BuyerAdapter(buyer, buyerSub);
  const verifier = new VerifierAdapter(buyerSub);
  const bridge = new DacsButlerBuyer(buyerAgent, verifier, buyerSub);

  // ── 4. Sellers publish anchored listings (real DEM anchors) ───────────────
  line("\n── sellers publish anchored DACS-1 listings on Demos ──");
  // ASCII-fold every anchored listing (the dd wire's NAME carries an em-dash;
  // a non-ASCII payload is un-settleable on the live node).
  const oracleListingRef = await oracleAgent.publishListing({
    ...asciiListing(oracleListingSpec({ amount: USDC_AMOUNT, asset: "USDC" })),
    supportedPaymentRails: ["pay-x402"],
  });
  step("oracle DACS-1", oracleListingRef);
  const ddListingRef = await ddAgent.publishListing({
    ...asciiListing(ddListingSpec({ amount: DD_PRICE_OS.toString(), asset: "DEM" })),
    supportedPaymentRails: ["pay-dem"],
  });
  step("dd DACS-1", ddListingRef);

  // ── 5. Butler discovers the two live anchored listings ────────────────────
  line("\n── Butler discovers + scores the live anchored basket ──");
  const ORACLE_ACCEPTANCE = {
    checks: [
      { kind: "content-includes" as const, needle: "oracleDigest" },
      { kind: "min-length" as const, minChars: 20 },
    ],
  };
  const offers: DacsOffer[] = await bridge.discoverOffers([
    { ref: oracleListingRef, scope: "fixed", fee: { kind: "fixed", price: 0.05 }, negotiable: false, acceptance: ORACLE_ACCEPTANCE, quality: { rating: 4.9, completedJobs: 210, disputeRate: 0 } },
    { ref: ddListingRef, scope: "parameterized", fee: { kind: "fixed", price: 6 }, negotiable: true, floor: 4, quality: { rating: 4.6, completedJobs: 70, disputeRate: 0.02 } },
  ]);
  for (const o of offers) {
    step("offer", `"${o.listing.name}" rails=${JSON.stringify(o.listing.supportedPaymentRails)} scope=${o.scope}`);
  }

  const owners = (sellerDid: string): DealOwners => ({ buyer: buyer.did, seller: sellerDid });

  // ── 6a. ORACLE leg — pay-x402 (real USDC on Base Sepolia) ─────────────────
  line("\n══ deal 1: oracle desk (attested chain-height) — pay-x402 ══");
  const oracleJobId = `l3-oracle-${Date.now()}`;
  let oracleDeliveredValue: unknown;

  const paywall = await startX402Paywall({
    port: PAYWALL_PORT,
    route: "/oracle",
    payTo: sellerEvmAddr,
    network: X402_NETWORK,
    asset: USDC_BASE_SEPOLIA,
    amount: USDC_AMOUNT,
    facilitatorUrl: FACILITATOR_URL,
    description: "Attested oracle chain-height lookup (DACS pay-x402, L3)",
    deliver: async (jid, p) => {
      const d = await oracleAgent.deliver(jid, { product: "chain-height", ...p });
      oracleDeliveredValue = (d.attestation.meta as { value?: unknown } | undefined)?.value;
      step("deliver", `oracle anchored DACS-X on DEM → ${d.attestationRef}  (value ${JSON.stringify(oracleDeliveredValue)})`);
      return { result: d.result, attestationRef: d.attestationRef };
    },
  });
  step("paywall", `seller x402 endpoint up → ${paywall.url}`);

  const { createX402Rail } = await import("@kynesyslabs/dacs");
  const oracleRail = await createX402Rail({ evmPrivateKey: buyerEvmKey });
  step("rail", `buyer x402 rail ready (payer ${oracleRail.address}, gasless EIP-3009)`);

  const oracleSettleTx: { record?: SettleResult } = {};
  // LIVE x402 settle seam (mirrors L2) — injected into the Butler's execute().
  const oracleX402Settle: SettleSeam = async (req: SettleRequest): Promise<SettleResult> => {
    const url = `${paywall.url}?jobId=${encodeURIComponent(req.jobId)}&product=chain-height`;
    const pay = await oracleRail.settle({
      paywallUrl: url,
      network: X402_NETWORK,
      recipientEvm: sellerEvmAddr,
      amount: req.amount,
      asset: USDC_BASE_SEPOLIA,
    });
    oracleSettleTx.record = pay;
    step("x402", `402-dance settled: ok=${pay.ok}  tx ${pay.txHash}  (${pay.chainId})`);
    const deliveredAnchor = await buyerSub.read(
      await buyerSub.anchorAddressFor(oracleSeller.did, `dacsx:delivery:${req.jobId}`),
    );
    return { ...pay, ok: pay.ok && deliveredAnchor !== null, payer: oracleRail.address };
  };

  const usdcBuyerBefore = await readUsdcBalance(buyerEvmAddr);
  const usdcSellerBefore = await readUsdcBalance(sellerEvmAddr);

  const oracleGoal: ProcurementGoal = { description: "attested chain-height lookup", requiredCapabilities: ["oracle-data", "pay-x402"] };
  const oracleDecision: ProcurementDecision = await bridge.procure(oracleGoal, 1, offers);
  step("decision", `outcome=${oracleDecision.outcome} winner=${oracleDecision.winner?.provider ?? "-"} rail=${oracleDecision.winner?.rail ?? "-"}`);

  let oracleOutcome: PurchaseOutcome;
  try {
    oracleOutcome = await bridge.execute(oracleDecision, offers, {
      sellerDid: oracleSeller.did,
      sellerEvm: sellerEvmAddr,
      seller: oracleAgent,
      observeDelivered: oracleObserveDelivered(),
      deliveryPhase: "deliver-chain-height",
      jobParams: { product: "chain-height" },
      onchainPrice: { amount: USDC_AMOUNT, asset: "USDC", decimals: 6 },
      x402Settle: oracleX402Settle,
      network: X402_NETWORK,
    }, { jobId: oracleJobId });
  } finally {
    await paywall.close();
  }
  step("execute", `rail=${oracleOutcome.rail} mode=${oracleOutcome.mode} verified=${oracleOutcome.verified} verdict=${oracleOutcome.acceptance.verdict} accepted=${oracleOutcome.accepted}`);
  const oracleSellerBundle = await oracleAgent.fulfil(oracleJobId, buyer.did);
  const oracleAnchors: DealAnchors = {
    listing: oracleListingRef,
    agreement: await buyerSub.anchorAddressFor(buyer.did, sessionAnchorName.agreement(oracleJobId)),
    evidence: await buyerSub.anchorAddressFor(buyer.did, sessionAnchorName.evidence(oracleJobId)),
    bundle: await buyerSub.anchorAddressFor(buyer.did, sessionAnchorName.bundle(oracleJobId)),
    delivery: oracleOutcome.deliveryRef,
    sellerBundle: oracleSellerBundle,
  };
  const oracleBundleV = await verifier.verify(oracleAnchors.bundle, owners(oracleSeller.did));
  const oracleRec = await verifier.reconcile(oracleAnchors.bundle, oracleSellerBundle, owners(oracleSeller.did));
  step("verify", `bundle ok=${oracleBundleV.ok}  reconciled=${oracleRec.reconciled}${oracleRec.reason ? ` (${oracleRec.reason})` : ""}`);

  const usdcBuyerAfter = await readUsdcBalance(buyerEvmAddr);
  const usdcSellerAfter = await readUsdcBalance(sellerEvmAddr);
  const oracleSettled = oracleOutcome.accepted && oracleBundleV.ok && (oracleSettleTx.record?.ok ?? false);

  // ── 6b. DD leg — pay-dem session (real DEM on Demos) ──────────────────────
  line("\n══ deal 2: dd-researcher (attested DD report) — pay-dem session ══");
  const ddJobId = `l3-dd-${Date.now()}`;

  // LIVE pay-dem-session settle seam (mirrors L1's payDemSettle): move real DEM
  // buyer → dd via transfer→confirm→broadcast with strict buyer-nonce
  // serialisation, then push the seller's delivery and couple on the SELLER's
  // owner-scoped delivery anchor (the live substrate scopes anchors by owner —
  // the mock payDemRail's `anchorAddress` self-scope would read null here).
  const ddSettleTx: { record?: TxRecord } = {};
  const ddSettleSeam: SettleSeam = async (req: SettleRequest): Promise<SettleResult> => {
    const payeeHex = req.payee.match(/([0-9a-fA-F]{64})$/)?.[1];
    if (!payeeHex) throw new Error(`pay-dem: payee ${req.payee} has no resolvable Demos address`);
    const payee = `0x${payeeHex}`;
    const nonceBefore = Number((await buyerW.getAddressInfo(buyer.address))?.nonce ?? 0);
    const tx = await payDem(buyerW, payee, BigInt(req.amount));
    ddSettleTx.record = tx;
    step("pay-dem", `settled ${osToDem(BigInt(req.amount))} buyer → dd  tx ${tx.hash}  block ${tx.confirmationBlock ?? "?"}`);
    if (!(await waitNonceAdvance(buyerW, buyer.address, nonceBefore))) {
      throw new Error("buyer nonce did not advance after dd settlement — evidence anchor would collide");
    }
    // Push: the seller researches live + anchors the ASCII (hash-only) DACS-X.
    const delivery = await ddAgent.deliver(req.jobId, { kind: "npm-package", subject: "express" });
    step("deliver", `dd anchored DACS-X (hash-only) on DEM → ${delivery.attestationRef}`);
    const delivered = await buyerSub.read(
      await buyerSub.anchorAddressFor(ddSeller.did, `dacsx:delivery:${req.jobId}`),
    );
    return {
      ok: delivered !== null && tx.hash.trim().length > 0,
      txHash: tx.hash,
      chainId: "demos",
      payer: buyer.address,
      payee,
    };
  };

  // dd deliverable projection: the FULL off-chain report (only the hash is
  // anchored), so the Butler's checks + EvalBot judge the real report.
  const ddDeliverableOf: SellerRuntime["deliverableOf"] = (att: DeliveryAttestation) => {
    const report = ddReportStash.get(att.jobId);
    return { content: report ? JSON.stringify(report) : JSON.stringify(att.meta ?? {}), meta: att.meta };
  };
  // dd delivery observation: hash-bind the off-chain report to the anchored hash
  // and re-run the researcher's own verifyReport (offline, meaningful check).
  const ddObserveLive: DeliveryVerifyOptions["observeDelivered"] = async (att) => {
    const anchoredHash = (att.meta as { reportHash?: string } | undefined)?.reportHash;
    if (typeof anchoredHash !== "string" || !/^[0-9a-f]{64}$/.test(anchoredHash)) {
      return { ok: false, reason: "delivery meta carries no valid reportHash" };
    }
    const report = ddReportStash.get(att.jobId);
    if (!report) return { ok: false, reason: "off-chain report unavailable for hash-check" };
    if (sha256Hex(JSON.stringify(report)) !== anchoredHash) {
      return { ok: false, reason: "off-chain report does not match anchored reportHash" };
    }
    const v = verifyReport(report);
    return v.valid ? { ok: true } : { ok: false, reason: `report verification failed: ${v.problems.join("; ")}` };
  };

  const ddSellerDemBefore = BigInt((await ddW.getAddressInfo(ddSeller.address))?.balance ?? 0n);
  const buyerDemBefore = BigInt((await buyerW.getAddressInfo(buyer.address))?.balance ?? 0n);

  const ddGoal: ProcurementGoal = { description: "due-diligence report on an npm package", requiredCapabilities: [DD_SERVICE_ID] };
  const ddDecision: ProcurementDecision = await bridge.procure(ddGoal, 8, offers);
  step("decision", `outcome=${ddDecision.outcome} winner=${ddDecision.winner?.provider ?? "-"} rail=${ddDecision.winner?.rail ?? "-"} price=${ddDecision.winner?.price ?? "-"}`);

  const ddOutcome: PurchaseOutcome = await bridge.execute(ddDecision, offers, {
    sellerDid: ddSeller.did,
    sellerEvm: "0x0000000000000000000000000000000000000000",
    seller: ddAgent,
    observeDelivered: ddObserveLive,
    deliveryPhase: DD_DELIVERY_PHASE,
    jobParams: { kind: "npm-package", subject: "express" },
    onchainPrice: { amount: DD_PRICE_OS.toString(), asset: "DEM", decimals: 9 },
    payDemSessionSettle: ddSettleSeam,
    deliverableOf: ddDeliverableOf,
  }, { jobId: ddJobId });
  step("execute", `rail=${ddOutcome.rail} mode=${ddOutcome.mode} verified=${ddOutcome.verified} verdict=${ddOutcome.acceptance.verdict} needsEvaluator=${ddOutcome.needsEvaluator}`);

  const ddSellerBundle = await ddAgent.fulfil(ddJobId, buyer.did);
  const ddAnchors: DealAnchors = {
    listing: ddListingRef,
    agreement: await buyerSub.anchorAddressFor(buyer.did, sessionAnchorName.agreement(ddJobId)),
    evidence: await buyerSub.anchorAddressFor(buyer.did, sessionAnchorName.evidence(ddJobId)),
    bundle: await buyerSub.anchorAddressFor(buyer.did, sessionAnchorName.bundle(ddJobId)),
    delivery: ddOutcome.deliveryRef,
    sellerBundle: ddSellerBundle,
  };
  const ddBundleV = await verifier.verify(ddAnchors.bundle, owners(ddSeller.did));
  const ddRec = await verifier.reconcile(ddAnchors.bundle, ddSellerBundle, owners(ddSeller.did));
  step("verify", `bundle ok=${ddBundleV.ok}  reconciled=${ddRec.reconciled}${ddRec.reason ? ` (${ddRec.reason})` : ""}`);

  // ── 6c. EvalBot gate LIVE — commission EvalBot as a seller, anchor the ruling
  line("\n══ EvalBot gate (dd report is a judgment deliverable → needs-evaluator) ══");
  let evalRuling: EvaluationRuling | undefined;
  let evalRulingValid = false;
  let evalDeliveryRef = "";
  let ddFinalAccepted = ddOutcome.accepted;
  if (ddOutcome.needsEvaluator) {
    // The report EvalBot judges is the off-chain deliverable (real web text).
    const ddReportContent = ddOutcome.deliverable.content;
    const rubric = rubricForOutcome({ serviceId: DD_SERVICE_ID });
    const evalJobId = `${ddJobId}-eval`;
    // Commission EvalBot as a LIVE DACS seller: it evaluates + signs an
    // EvaluationRuling and anchors the DACS-X delivery on Demos from the
    // dedicated evalbot wallet. Only the ruling (ASCII verdict/scores/reasons)
    // is anchored — never the report body.
    const evalDelivery = await evalAgent.deliver(evalJobId, {
      rubric,
      deliverable: { content: ddReportContent },
    });
    evalDeliveryRef = evalDelivery.attestationRef;
    evalRuling = readReportMeta<EvaluationRuling>(evalDelivery.attestation).ok
      ? readReportMeta<EvaluationRuling>(evalDelivery.attestation).artifact as EvaluationRuling
      : undefined;
    step("evalbot", `ruling anchored on DEM → ${evalDeliveryRef}  verdict=${evalRuling?.verdict ?? "?"} aggregate=${evalRuling?.aggregate ?? "n/a"}`);

    // Verify the anchored ruling two ways: EvalBot's own verifyRuling, and the
    // verifier reading it back from the anchor (evalBotObserveDelivered).
    const dvEval = await verifier.verifyDelivery(evalJobId, {
      serviceId: EVALBOT_SERVICE_ID,
      sellerDid: evalbot.did,
      observeDelivered: evalBotObserveDelivered(),
    });
    evalRulingValid = dvEval.ok && !!evalRuling && verifyRuling(evalRuling).valid;
    step("gate", `verifier.verifyDelivery ok=${dvEval.ok}  rulingValid=${evalRulingValid}`);

    // Acceptance flips on the anchored ruling.
    ddFinalAccepted = ddOutcome.verified && evalRulingValid && evalRuling?.verdict === "accept";
    step("gate", `dd acceptance ⇒ ${ddFinalAccepted ? "ACCEPTED" : "rejected"} (ruling ${evalRuling?.verdict ?? "?"})`);
  }

  const ddSettled =
    ddOutcome.verified && ddBundleV.ok && (ddSettleTx.record?.hash?.length ?? 0) > 0 && ddFinalAccepted;

  await sleep(3000);
  const ddSellerDemAfter = BigInt((await ddW.getAddressInfo(ddSeller.address))?.balance ?? 0n);
  const buyerDemAfter = BigInt((await buyerW.getAddressInfo(buyer.address))?.balance ?? 0n);

  // ── 7. Report ─────────────────────────────────────────────────────────────
  line("\n════════════════════════ L3 REPORT ════════════════════════");
  line(`  status            oracle/x402 ${oracleSettled ? "SETTLED-LIVE ✓" : "CAVEAT"} · dd/pay-dem ${ddSettled ? "SETTLED-LIVE ✓" : "CAVEAT"} · EvalBot gate ${evalRulingValid ? "LIVE ✓" : "not-live"}`);
  line(`  demos rpc         ${RPC}`);
  line(`  base sepolia rpc  ${BASE_SEPOLIA_RPC}`);
  line(`  facilitator       ${FACILITATOR_URL}`);
  line("");
  line("  wallets (funder funds only; deal parties dedicated/persisted)");
  line(`    funder          ${funder.address}  [funding source only]`);
  line(`    buyer           ${buyer.address}  (DEM anchoring)`);
  line(`    buyer EVM       ${buyerEvmAddr}  (USDC payer)`);
  line(`    oracle seller   ${oracleSeller.address}`);
  line(`    oracle EVM      ${sellerEvmAddr}  (USDC payout)`);
  line(`    dd seller       ${ddSeller.address}  [${ddKey.isNew ? "new this run" : "persisted"}]`);
  line(`    evalbot         ${evalbot.address}  [${evalKey.isNew ? "new this run" : "persisted"}]`);
  const fundLine = (label: string, est: EstablishResult) => {
    if (est.fundTx) line(`    fund→${label.padEnd(8)} ${est.fundTx.hash}${est.warmups.length ? `  warm-ups ${est.warmups.map((t) => t.hash).join(", ")}` : ""}`);
  };
  fundLine("oracle", oracleEst);
  fundLine("dd", ddEst);
  fundLine("evalbot", evalEst);
  fundLine("buyer", buyerEst);
  line("");
  line("  ── DEAL 1: oracle desk — Butler chose pay-x402 (REAL USDC on Base Sepolia) ──");
  line(`    butler decision outcome=${oracleDecision.outcome} winner=${oracleDecision.winner?.provider} chosenRail=${oracleDecision.winner?.rail}`);
  line(`    settlement tx   ${oracleSettleTx.record?.txHash ?? "—"}  (${oracleSettleTx.record?.chainId ?? X402_NETWORK})`);
  line(`    amount          ${rawToUsdc(BigInt(USDC_AMOUNT))}  payer ${buyerEvmAddr} → payee ${sellerEvmAddr}`);
  line(`    delivered value ${JSON.stringify(oracleDeliveredValue)}  (LIVE Bitcoin block height)`);
  line(`    verdict         ${oracleOutcome.acceptance.verdict} · verified=${oracleOutcome.verified} · accepted=${oracleOutcome.accepted}`);
  line(`    DEM anchors     listing ${oracleAnchors.listing}`);
  line(`                    agreement ${oracleAnchors.agreement}`);
  line(`                    evidence  ${oracleAnchors.evidence}`);
  line(`                    delivery  ${oracleAnchors.delivery}`);
  line(`                    bundle    ${oracleAnchors.bundle}`);
  line(`                    seller    ${oracleAnchors.sellerBundle}`);
  line(`    bundle ok       ${oracleBundleV.ok} · reconciled ${oracleRec.reconciled}`);
  line(`    USDC buyer      ${usdcBuyerBefore} → ${usdcBuyerAfter}  (Δ ${rawToUsdc(usdcBuyerAfter - usdcBuyerBefore)})`);
  line(`    USDC seller     ${usdcSellerBefore} → ${usdcSellerAfter}  (Δ ${rawToUsdc(usdcSellerAfter - usdcSellerBefore)})`);
  line("");
  line("  ── DEAL 2: dd-researcher — Butler chose pay-dem session (REAL DEM on Demos) ──");
  line(`    butler decision outcome=${ddDecision.outcome} winner=${ddDecision.winner?.provider} chosenRail=${ddDecision.winner?.rail} price=${ddDecision.winner?.price}`);
  line(`    settlement tx   ${ddSettleTx.record?.hash ?? "—"}  (block ${ddSettleTx.record?.confirmationBlock ?? "?"})`);
  line(`    amount          ${osToDem(DD_PRICE_OS)}  payer ${buyer.address} → payee ${ddSeller.address}`);
  line(`    report          ${ddReportStash.get(ddJobId) ? `${ddReportStash.get(ddJobId)!.findings.length} findings, ${ddReportStash.get(ddJobId)!.evidence.length} evidence (full report OFF-CHAIN; only content-hash anchored)` : "unavailable"}`);
  line(`    delivery verdict ${ddOutcome.acceptance.verdict} · verified=${ddOutcome.verified} · needsEvaluator=${ddOutcome.needsEvaluator}`);
  line(`    DEM anchors     listing ${ddAnchors.listing}`);
  line(`                    agreement ${ddAnchors.agreement}`);
  line(`                    evidence  ${ddAnchors.evidence}`);
  line(`                    delivery  ${ddAnchors.delivery}`);
  line(`                    bundle    ${ddAnchors.bundle}`);
  line(`                    seller    ${ddAnchors.sellerBundle}`);
  line(`    bundle ok       ${ddBundleV.ok} · reconciled ${ddRec.reconciled}`);
  line(`    DEM buyer       ${buyerDemBefore} → ${buyerDemAfter}  (Δ ${osToDem(buyerDemAfter - buyerDemBefore)})`);
  line(`    DEM dd seller   ${ddSellerDemBefore} → ${ddSellerDemAfter}  (Δ ${osToDem(ddSellerDemAfter - ddSellerDemBefore)})`);
  line("");
  line("  ── EvalBot gate (LIVE, anchored on Demos from the evalbot wallet) ──");
  line(`    ruling anchor   ${evalDeliveryRef || "—"}`);
  line(`    ruling verdict  ${evalRuling?.verdict ?? "—"}  aggregate=${evalRuling?.aggregate ?? "n/a"}  valid=${evalRulingValid}`);
  line(`    dd final accept ${ddFinalAccepted}`);
  line("════════════════════════════════════════════════════════════");

  const allLive = oracleSettled && ddSettled && evalRulingValid;
  line(`\n${allLive ? "✅" : "⚠"} L3 ${allLive ? "drove a live 2-seller basket across both rails with a live EvalBot gate." : "ran with a caveat — see per-deal status above."}\n`);

  flushLog();
  console.log(`  (report written → ${LOG_PATH})`);
  process.exit(allLive ? 0 : 1);
}

main().catch((e) => {
  const msg = (e as Error)?.stack ?? (e as Error)?.message ?? String(e);
  console.error("\n❌ L3 failed:", msg);
  logLines.push(`\n❌ L3 failed: ${msg}`);
  flushLog();
  process.exit(1);
});
