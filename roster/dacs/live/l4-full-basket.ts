/**
 * L4 — the Procurement Butler procures from the ENTIRE remaining seller roster
 * LIVE on-chain, across BOTH settlement rails, with the EvalBot gate live for
 * every judgment deliverable.
 *
 *   npm run dacs:l4
 *
 * This scales the proven L3 basket (`l3-butler-basket.ts`) from 2 sellers to
 * ALL of them. The moving parts are IDENTICAL to L3 — established/persisted DEM
 * wallets, the DEM funder, strict per-wallet nonce serialisation, `LiveSubstrate`
 * anchoring with the harder `RetryingSubstrate`, the `asciiSafe`/`asciiListing`
 * fold, hash-only delivery attestations for every report body, `DacsButlerBuyer`
 * (Build C) with the live seam overrides (`x402Settle`, `payDemSessionSettle`
 * reading `anchorAddressFor(sellerDid,…)`), and the live EvalBot gate
 * (`wire/evaluator.ts` rubric + `wire/evalbot.ts` seller). Only the roster grew.
 *
 * The full roster (reduced-mode — no CCI vet, same as L1/L2/L3):
 *
 *   seller          rail            acceptance
 *   ─────────────────────────────────────────────────────────────
 *   oracle-desk     pay-x402        mechanical (auto-accept)
 *   dd-researcher   pay-dem session judgment  → live EvalBot gate
 *   dep-upgrade     pay-dem session mechanical (plan structure)
 *   treasury-ops    pay-dem session mechanical (approver-signed)
 *   site-auditor    pay-dem session judgment  → live EvalBot gate
 *   sec-audit       pay-dem session judgment  → live EvalBot gate
 *   compliance      pay-dem session judgment  → live EvalBot gate
 *
 * Per-seller flow (same as L3): the seller publishes an ASCII-safe anchored
 * DACS-1 listing on Demos → the Butler discovers the whole listing set, scores,
 * negotiates where allowed, picks the rail, and settles LIVE (x402 USDC on Base
 * Sepolia for oracle; pay-dem DEM on Demos for the other six) → the seller
 * delivers; its anchored DACS-X delivery attestation carries ONLY the ASCII
 * content-hash + ASCII counts (NEVER the raw report body — these agents emit
 * real non-ASCII web/report text, so a raw body would fail the Demos
 * non-ASCII anchor bug: "[SIGNATURE ERROR] Transaction hash mismatch"). The
 * full report is the OFF-CHAIN deliverable the buyer receives, hash-checks, and
 * feeds to the acceptance checks / EvalBot. Mechanical deliverables auto-accept;
 * the four judgment ones route through the LIVE EvalBot gate (a signed,
 * ASCII-only, rubric-controlled EvaluationRuling anchored on Demos).
 *
 * CONTINUE-ON-ERROR: every seller's deal is wrapped in try/catch over its OWN
 * wallet. A blocked deal records `{status:"blocked", error, …}` and the basket
 * moves to the next seller — one bad deal never aborts the run. The process
 * exits 0 as long as the run completes and reports every seller's outcome.
 *
 * Incremental per-seller results stream to `roster/dacs/live/L4-run.log` as the
 * run proceeds (git-ignored), so partial progress survives an interruption.
 */
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { sha256Hex } from "@kynesyslabs/dacs";
import type {
  SettleRequest,
  SettleResult,
} from "../../../sdk/dist/agent/runSessionCore.js";
import { sessionAnchorName } from "../../../sdk/dist/agent/runSessionCore.js";

import { connectIdentity, type LiveIdentity } from "../../../src/live/identity.js";
import { LiveSubstrate } from "../../../src/live/substrate.js";
import {
  SellerAdapter,
  type WorkCallback,
  type WorkResult,
  type DeliveryAttestation,
} from "../seller-adapter.js";
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
import { readReportMeta } from "../wire/report-meta.js";
import type {
  AcceptancePolicy,
  ProcurementDecision,
  ProcurementGoal,
  QualityStats,
} from "../../procurement-butler/types.js";

// ── seller wires ─────────────────────────────────────────────────────────────
import {
  ORACLE_SERVICE_ID,
  makeOracleWork,
  oracleListingSpec,
  oracleObserveDelivered,
} from "../wire/oracle-desk.js";
import {
  DD_SERVICE_ID,
  DD_DELIVERY_PHASE,
  makeDdWork,
  ddListingSpec,
  ddObserveDelivered,
} from "../wire/dd-researcher.js";
import {
  DEPUP_SERVICE_ID,
  DEPUP_DELIVERY_PHASE,
  makeDepUpgradeWork,
  depUpgradeListingSpec,
  depUpgradeObserveDelivered,
} from "../wire/dep-upgrade.js";
import {
  TREASURY_SERVICE_ID,
  TREASURY_DELIVERY_PHASE,
  makeTreasuryWork,
  treasuryListingSpec,
  treasuryObserveDelivered,
} from "../wire/treasury-ops.js";
import {
  SITE_SERVICE_ID,
  SITE_DELIVERY_PHASE,
  makeSiteAuditorWork,
  siteAuditorListingSpec,
  siteAuditorObserveDelivered,
} from "../wire/site-auditor.js";
import {
  SEC_AUDIT_SERVICE_ID,
  SEC_AUDIT_DELIVERY_PHASE,
  makeSecAuditWork,
  secAuditListingSpec,
  secAuditObserveDelivered,
  type PostedFile,
} from "../wire/sec-audit.js";
import {
  COMPLIANCE_SERVICE_ID,
  COMPLIANCE_DELIVERY_PHASE,
  makeComplianceWork,
  complianceListingSpec,
  complianceObserveDelivered,
} from "../wire/compliance.js";
import {
  EVALBOT_SERVICE_ID,
  makeEvalBotWork,
  evalBotObserveDelivered,
} from "../wire/evalbot.js";

// ── seller cores + real ports ────────────────────────────────────────────────
import { EvalBot, verifyRuling } from "../../evalbot/evalbot.js";
import type { EvaluationRuling } from "../../evalbot/types.js";
import { RealAttestedFetch } from "../../oracle-desk/attested-fetch.js";
import { RealRegistry, lodashFallbackRegistry } from "../../dep-upgrade/registry.js";
import type { RegistryPort } from "../../dep-upgrade/types.js";
import { RealProber } from "../../site-auditor/prober.js";
import { loadAll } from "../../compliance/screener.js";
import { realSources, fixtureSources, RealComplianceFetch } from "../../compliance/sources.js";
import type { ListSourcePort } from "../../compliance/types.js";
import type { TreasuryPolicy, BalanceSnapshot } from "../../treasury-ops/types.js";

// ── x402 / Base Sepolia ground truth (proven in L2/L3) ───────────────────────
const X402_NETWORK = "eip155:84532" as const;
const USDC_BASE_SEPOLIA = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const FACILITATOR_URL = process.env.X402_FACILITATOR ?? "https://x402.org/facilitator";
const BASE_SEPOLIA_RPC = process.env.BASE_SEPOLIA_RPC ?? "https://sepolia.base.org";
/** Oracle price: 1 USDC (6 decimals). */
const USDC_AMOUNT = "1000000";
/** The buyer must hold ≥ 1 USDC to run the oracle (x402) leg; else it's blocked. */
const USDC_MIN = 1_000_000n;
const PAYWALL_PORT = Number(process.env.L4_PAYWALL_PORT ?? 4044);

// ── DEM ground truth (identical to L1/L2/L3) ─────────────────────────────────
const RPC = process.env.DEMOS_RPC ?? "https://demosnode.discus.sh/";
const FUNDER_MNEMONIC = (() => {
  const value = process.env.FUNDER_MNEMONIC?.trim();
  if (!value) throw new Error("FUNDER_MNEMONIC is required; never embed wallet mnemonics in source");
  return value;
})();

/** 1 DEM = 10^9 OS (§9.5.9, integer arithmetic). */
const OS_PER_DEM = 1_000_000_000n;
/** Every pay-dem deal settles 1 DEM (uniform, like L3's dd leg). */
const DEAL_PRICE_OS = 1n * OS_PER_DEM;

// Fund the buyer generously up front: it settles ~6 pay-dem deals + anchors
// agreement/evidence/bundle for 7 deals + the 4 EvalBot-gate evidence reads.
// A judgment deal costs the buyer ~8 DEM (1 DEM settle + agreement/evidence/
// bundle anchors); at a 60 DEM float the first L4 run's buyer ran dry on the
// 8th deal (compliance bundle anchor: "Insufficient balance: required 2,
// available 0"). Float to ≥120 DEM, established/confirmed on-chain BEFORE the
// basket, so the buyer survives all six pay-dem deals + every anchor without
// a mid-run top-up.
const BUYER_SEED_OS = 130n * OS_PER_DEM;
const BUYER_MIN_OS = 110n * OS_PER_DEM;
// EVERY seller wallet must also cover its OWN anchors — listing publish +
// delivery attestation + seller-bundle ≈ 5-6 DEM per deal, and the EvalBot
// wallet anchors up to 4 rulings — on top of establishment. The 7/8 run's
// compliance SELLER (.l4-compliance-key) ran dry on its `dacs5:bundle:seller:…`
// anchor ("Failed to apply GCREdit: Insufficient balance"). Float every seller
// (reused + new) to ≥15 DEM, confirmed on-chain before the basket.
const REUSE_SEED_OS = 18n * OS_PER_DEM;
const REUSE_MIN_OS = 15n * OS_PER_DEM;
// The five NEW pay-dem sellers: each publishes a listing + delivers + fulfils.
const SELLER_SEED_OS = 18n * OS_PER_DEM;
const SELLER_MIN_OS = 15n * OS_PER_DEM;

// Persisted key files (all git-ignored). Reuse L1/L2/L3 wallets where possible.
const LIVE = (f: string) => join(process.cwd(), "roster/dacs/live", f);
const ORACLE_KEY_PATH = LIVE(".l1-seller-key"); // reuse L1's established oracle seller
const BUYER_KEY_PATH = LIVE(".l1-buyer-key");
const BUYER_EVM_KEY_PATH = LIVE(".l2-buyer-evm-key");
const SELLER_EVM_KEY_PATH = LIVE(".l2-seller-evm-key");
const DD_KEY_PATH = LIVE(".l3-dd-seller-key");
const EVAL_KEY_PATH = LIVE(".l3-evalbot-key");

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
const step = (n: string, msg: string): void => line(`  ${n.padEnd(14)} ${msg}`);
const LOG_PATH = LIVE("L4-run.log");
function flushLog(): void {
  try {
    writeFileSync(LOG_PATH, logLines.join("\n") + "\n");
  } catch {
    /* best-effort */
  }
}

/**
 * A substrate view that retries `anchor` harder than `LiveSubstrate` (the public
 * node's fresh-account state is racy). Lifted verbatim from L1/L2/L3 (T9:
 * substrate fault ≠ party fault).
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
 * Demos node rejects non-ASCII UTF-8 payloads with "[SIGNATURE ERROR]
 * Transaction hash mismatch"). Verbatim from L3 — used to normalise every seller
 * listing's human-facing text before anchoring.
 */
function asciiSafe(s: string): string {
  return s
    .replace(/[‐-―−]/g, "-")
    .replace(/[‘’‛]/g, "'")
    .replace(/[“”]/g, '"')
    .replace(/…/g, "...")
    .replace(/[←-⇿]/g, "->")
    .replace(/[^\x00-\x7F]/g, "");
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
 * serialised on the funder's own nonce. Lifted from L1/L3.
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
  step(`fund->${label}`, `${osToDem(seedOs)}  tx ${fundTx.hash}  block ${fundTx.confirmationBlock ?? "?"}`);
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
      throw new Error(`${label} account did not stabilise on the node (nonce/balance/block gate) — see L4-run.log`);
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
  listing?: string;
  agreement?: string;
  evidence?: string;
  bundle?: string;
  delivery?: string;
  sellerBundle?: string;
  ruling?: string;
}

/** The final per-seller line the report table renders. */
interface SellerReport {
  seller: string;
  rail: "pay-x402" | "pay-dem";
  status: "settled" | "blocked";
  settlementTx: string;
  chainId: string;
  anchors: DealAnchors;
  verdict: string;
  balanceDelta: string;
  gate: string;
  error?: string;
}

// ── The off-chain deliverable stash (hash-only anchoring) ─────────────────────
// The seller anchors ONLY the ASCII content-hash; the full (often non-ASCII)
// artifact lives here for the buyer's acceptance checks + the EvalBot gate.
interface StashEntry {
  json: string;
  artifact: unknown;
}
type Stash = Map<string, StashEntry>;

/**
 * How each seller's inner work-callback carries the full artifact in its `meta`,
 * so L4 can lift it off-chain and anchor a hash-only attestation instead.
 *   - "report-json": the report-meta.ts wires ({ reportJson, reportHash }).
 *   - "dd-report":   the dd wire ({ report, reportHash }).
 */
type MetaShape = "report-json" | "dd-report";

function extractArtifact(shape: MetaShape, meta: Record<string, unknown> | undefined): StashEntry & { hash: string } {
  if (!meta) throw new Error("live work produced no meta to lift off-chain");
  if (shape === "dd-report") {
    const report = (meta as { report?: unknown }).report;
    const hash = String((meta as { reportHash?: string }).reportHash ?? "");
    const json = JSON.stringify(report);
    if (!report || !/^[0-9a-f]{64}$/.test(hash)) throw new Error("dd meta missing report/reportHash");
    return { artifact: report, json, hash };
  }
  const reportJson = (meta as { reportJson?: string }).reportJson;
  const hash = String((meta as { reportHash?: string }).reportHash ?? "");
  if (typeof reportJson !== "string" || !/^[0-9a-f]{64}$/.test(hash)) {
    throw new Error("report meta missing reportJson/reportHash");
  }
  return { artifact: JSON.parse(reportJson), json: reportJson, hash };
}

function rebuildMeta(shape: MetaShape, entry: StashEntry, hash: string): Record<string, unknown> {
  return shape === "dd-report"
    ? { report: entry.artifact, reportHash: hash }
    : { reportJson: entry.json, reportHash: hash };
}

/**
 * Wrap a seller's inner work-callback so the ANCHORED delivery attestation
 * carries only the ASCII content-hash (`meta = { reportHash }`), while the full
 * artifact is stashed OFF-CHAIN for acceptance + evaluation. The `result` is only
 * hashed into `resultHash` (never anchored), so its counts stay JCS-safe.
 */
function liveWork(inner: WorkCallback, shape: MetaShape, stash: Stash): WorkCallback {
  return async (jobId, params): Promise<WorkResult> => {
    const w = await inner(jobId, params);
    const { artifact, json, hash } = extractArtifact(shape, w.meta);
    stash.set(jobId, { json, artifact });
    return { result: w.result, deliverableRef: w.deliverableRef, meta: { reportHash: hash } };
  };
}

/** Project the off-chain artifact as the checkable deliverable content. */
function liveDeliverableOf(stash: Stash): (att: DeliveryAttestation) => { content: string; meta?: Record<string, unknown> } {
  return (att) => {
    const s = stash.get(att.jobId);
    return { content: s ? s.json : JSON.stringify(att.meta ?? {}), meta: att.meta };
  };
}

/**
 * Live `observeDelivered`: bind the off-chain artifact to the anchored hash, then
 * re-run the seller wire's OWN offline verifier over a reconstructed full-meta
 * attestation (verifyReport / verifyRecord / verifyAudit / verifyScreening / the
 * treasury signature check / the plan-structure check — all reused verbatim).
 */
function liveObserve(
  shape: MetaShape,
  stash: Stash,
  wireObserve: DeliveryVerifyOptions["observeDelivered"],
): DeliveryVerifyOptions["observeDelivered"] {
  return async (att) => {
    const anchoredHash = (att.meta as { reportHash?: string } | undefined)?.reportHash;
    if (typeof anchoredHash !== "string" || !/^[0-9a-f]{64}$/.test(anchoredHash)) {
      return { ok: false, reason: "delivery meta carries no valid reportHash" };
    }
    const s = stash.get(att.jobId);
    if (!s) return { ok: false, reason: "off-chain artifact unavailable for hash-check" };
    if (sha256Hex(s.json) !== anchoredHash) {
      return { ok: false, reason: "off-chain artifact does not match anchored reportHash" };
    }
    const fullAtt = { ...att, meta: rebuildMeta(shape, s, anchoredHash) } as DeliveryAttestation;
    return wireObserve ? wireObserve(fullAtt) : { ok: true };
  };
}

// ── Pay-dem seller descriptor ────────────────────────────────────────────────
interface PayDemSeller {
  label: string;
  serviceId: string;
  deliveryPhase: string;
  keyPath: string;
  seedOs: bigint;
  minOs: bigint;
  reuse: boolean;
  listingSpec: { serviceId: string; name: string; description: string; supportedNegotiation?: string[]; supportedPaymentRails?: string[]; supportedDelivery?: string[] };
  metaShape: MetaShape;
  /** Build the inner work callback lazily (real ports resolved at run time). */
  buildWork: () => Promise<WorkCallback>;
  wireObserve: DeliveryVerifyOptions["observeDelivered"];
  jobParams: Record<string, unknown>;
  butlerPrice: number;
  budget: number;
  negotiable: boolean;
  floor?: number;
  quality: QualityStats;
  /** Mechanical acceptance checks; absent ⇒ judgment (→ EvalBot gate). */
  acceptance?: AcceptancePolicy;
  goalCaps: string[];
  goalDescription: string;
  note: string;
}

async function main(): Promise<void> {
  line("┌──────────────────────────────────────────────────────────────────────────┐");
  line("│  L4 — Butler procures the ENTIRE roster LIVE (x402 + pay-dem + EvalBot ×4)  │");
  line("└──────────────────────────────────────────────────────────────────────────┘");
  line(`  demos rpc    ${RPC}`);
  line(`  base rpc     ${BASE_SEPOLIA_RPC}`);
  line(`  facilitator  ${FACILITATOR_URL}`);
  line(`  when         ${new Date().toISOString()}`);

  const results: SellerReport[] = [];
  const recordAndFlush = (r: SellerReport): void => {
    results.push(r);
    line(`  » ${r.seller.padEnd(13)} ${r.rail.padEnd(8)} ${r.status.toUpperCase()}${r.error ? `  (${r.error})` : ""}`);
    flushLog();
  };

  // ── 0. EVM coordinates + oracle funding probe (no hard gate — continue) ────
  const buyerEvmKey = readFileSync(BUYER_EVM_KEY_PATH, "utf8").trim();
  const buyerEvmAddr = await evmAddressOf(buyerEvmKey);
  const sellerEvmAddr = await evmAddressOf(readFileSync(SELLER_EVM_KEY_PATH, "utf8").trim());
  step("buyer EVM", `${buyerEvmAddr}  (USDC payer, persisted)`);
  step("seller EVM", `${sellerEvmAddr}  (USDC payout / payTo, persisted)`);
  const usdc0 = await readUsdcBalance(buyerEvmAddr).catch(() => 0n);
  const oracleFundable = usdc0 >= USDC_MIN;
  step("USDC bal", `${rawToUsdc(usdc0)}  (raw ${usdc0}) — oracle/x402 ${oracleFundable ? "FUNDED" : "UNFUNDED (will be blocked)"}`);

  // ── 1. Funder + reused/dedicated wallets ──────────────────────────────────
  const funder = await connectIdentity("Funder", RPC, FUNDER_MNEMONIC);
  const funderW = wallet(funder);
  const funderBal0 = BigInt((await funderW.getAddressInfo(funder.address))?.balance ?? 0n);
  step("funder", `${funder.address}  (funding source only)  balance ${osToDem(funderBal0)}`);

  if (!existsSync(ORACLE_KEY_PATH) || !existsSync(BUYER_KEY_PATH)) {
    throw new Error("expected L1's established DEM wallets (.l1-seller-key / .l1-buyer-key) — run `npm run dacs:l1` first");
  }
  const oracleKey = await loadOrCreateKey(ORACLE_KEY_PATH);
  const buyerKey = await loadOrCreateKey(BUYER_KEY_PATH);
  const buyer = await connectIdentity("Buyer", RPC, buyerKey.mnemonic);
  const oracleSeller = await connectIdentity("OracleDesk", RPC, oracleKey.mnemonic);
  const buyerW = wallet(buyer);
  const oracleW = wallet(oracleSeller);
  step("buyer", `${buyer.address}  [${buyerKey.isNew ? "new" : "persisted/established"}]`);
  step("oracle", `${oracleSeller.address}  [${oracleKey.isNew ? "new" : "persisted/established"}]`);

  // ── 2. Resolve pay-dem seller descriptors (real ports) ────────────────────
  // dep-upgrade registry: probe the live npm advisory endpoint, else fall back.
  let depRegistry: RegistryPort;
  let depRegistryMode: string;
  try {
    const real = new RealRegistry(10_000);
    const probe = await real.getAdvisories({ lodash: ["4.17.20"] });
    if ((probe.get("lodash") ?? []).length === 0) throw new Error("advisory endpoint returned no lodash advisories");
    depRegistry = real;
    depRegistryMode = "REAL (live npm registry + advisory endpoint)";
  } catch (e) {
    depRegistry = lodashFallbackRegistry();
    depRegistryMode = `FALLBACK canned registry (${(e as Error).message.slice(0, 48)})`;
  }
  step("dep registry", depRegistryMode);

  // compliance sources: probe real (cache-aware) list loads, else fixtures.
  let complianceSources: ListSourcePort[];
  let complianceMode: string;
  try {
    const real = realSources({ port: new RealComplianceFetch(), cacheDir: LIVE("../../compliance/out/cache") });
    await loadAll(real);
    complianceSources = real;
    complianceMode = "REAL (OFAC SDN + UN consolidated + SEC EDGAR, cache-aware)";
  } catch (e) {
    complianceSources = fixtureSources();
    complianceMode = `FALLBACK fixture lists (${(e as Error).message.slice(0, 48)})`;
  }
  step("compliance src", complianceMode);

  // sec-audit posted files: real fixture source (posted content is never anchored).
  const secFixtureDir = join(process.cwd(), "roster/sec-audit/fixture");
  const postedFiles: PostedFile[] = ["Vault.sol", "app.js"]
    .map((f) => ({ path: f, dir: join(secFixtureDir, f) }))
    .filter((f) => existsSync(f.dir))
    .map((f) => ({ path: f.path, content: readFileSync(f.dir, "utf8") }));

  // treasury posted policy + balances (from the treasury demo walkthrough).
  const TREASURY_POLICY: TreasuryPolicy = {
    policyId: "l4-treasury-v1",
    accounts: [
      { id: "ops-demos", chain: "demos", address: "demos-treasury-1", label: "Demos ops", minBalance: 200, targetPct: 50 },
      { id: "ops-base", chain: "base", address: "0xTREASURYBASE", label: "Base ops", minBalance: 100, targetPct: 30 },
      { id: "ops-solana", chain: "solana", address: "SoLTREASURY", label: "Solana ops", minBalance: 50, targetPct: 20 },
    ],
    allowlist: [
      { address: "demos-alice", chain: "demos", label: "Alice (eng)" },
      { address: "0xB0B", chain: "base", label: "Bob (eng)" },
      { address: "0xCAR01", chain: "base", label: "Carol (design)" },
      { address: "SoLDAVE", chain: "solana", label: "Dave (ops)" },
    ],
    payroll: [
      { recipient: "demos-alice", chain: "demos", amount: 800, label: "Alice (eng)", period: "2026-07" },
      { recipient: "0xB0B", chain: "base", amount: 500, label: "Bob (eng)", period: "2026-07" },
      { recipient: "0xCAR01", chain: "base", amount: 450, label: "Carol (design)", period: "2026-07" },
      { recipient: "SoLDAVE", chain: "solana", amount: 300, label: "Dave (ops)", period: "2026-07" },
    ],
    perTxCap: 5000,
    perRunCap: 20_000,
    feeBufferPerTx: 2,
  };
  const TREASURY_BALANCES: BalanceSnapshot = { "ops-demos": 10_000, "ops-base": 2_400, "ops-solana": 800 };

  const goodQuality: QualityStats = { rating: 4.7, completedJobs: 90, disputeRate: 0.01 };

  const sellers: PayDemSeller[] = [
    {
      label: "dd-researcher",
      serviceId: DD_SERVICE_ID,
      deliveryPhase: DD_DELIVERY_PHASE,
      keyPath: DD_KEY_PATH,
      seedOs: REUSE_SEED_OS,
      minOs: REUSE_MIN_OS,
      reuse: existsSync(DD_KEY_PATH),
      listingSpec: ddListingSpec({ amount: DEAL_PRICE_OS.toString(), asset: "DEM" }),
      // makeDdWork carries the report as a JCS-safe JSON STRING via reportMeta
      // ({ reportJson, reportHash }) — the "report-json" shape. (Was wrongly
      // "dd-report", which looks for meta.report and threw "dd meta missing…".)
      metaShape: "report-json",
      buildWork: async () => makeDdWork(new RealAttestedFetch()),
      wireObserve: ddObserveDelivered(),
      jobParams: { kind: "npm-package", subject: "express" },
      butlerPrice: 6,
      budget: 8,
      negotiable: true,
      floor: 4,
      quality: { rating: 4.6, completedJobs: 70, disputeRate: 0.02 },
      goalCaps: [DD_SERVICE_ID],
      goalDescription: "due-diligence report on an npm package",
      note: "judgment (attested DD report) -> EvalBot gate",
    },
    {
      label: "dep-upgrade",
      serviceId: DEPUP_SERVICE_ID,
      deliveryPhase: DEPUP_DELIVERY_PHASE,
      keyPath: LIVE(".l4-depup-key"),
      seedOs: SELLER_SEED_OS,
      minOs: SELLER_MIN_OS,
      reuse: existsSync(LIVE(".l4-depup-key")),
      listingSpec: depUpgradeListingSpec({ amount: DEAL_PRICE_OS.toString(), asset: "DEM" }),
      metaShape: "report-json",
      buildWork: async () => makeDepUpgradeWork(depRegistry),
      wireObserve: depUpgradeObserveDelivered(),
      jobParams: { packageJson: { name: "l4-target", version: "1.0.0", dependencies: { lodash: "4.17.20" } }, includeNextMajor: false },
      butlerPrice: 5,
      budget: 8,
      negotiable: false,
      quality: goodQuality,
      acceptance: { checks: [{ kind: "content-includes", needle: "unactionable" }, { kind: "min-length", minChars: 20 }] },
      goalCaps: [DEPUP_SERVICE_ID],
      goalDescription: "advisory-driven dependency upgrade plan for a posted package.json",
      note: "mechanical (plan hash + structure)",
    },
    {
      label: "treasury-ops",
      serviceId: TREASURY_SERVICE_ID,
      deliveryPhase: TREASURY_DELIVERY_PHASE,
      keyPath: LIVE(".l4-treasury-key"),
      seedOs: SELLER_SEED_OS,
      minOs: SELLER_MIN_OS,
      reuse: existsSync(LIVE(".l4-treasury-key")),
      listingSpec: treasuryListingSpec({ amount: DEAL_PRICE_OS.toString(), asset: "DEM" }),
      metaShape: "report-json",
      buildWork: async () => makeTreasuryWork(),
      wireObserve: treasuryObserveDelivered(),
      jobParams: { policy: TREASURY_POLICY, balances: TREASURY_BALANCES },
      butlerPrice: 5,
      budget: 8,
      negotiable: false,
      quality: goodQuality,
      acceptance: { checks: [{ kind: "content-includes", needle: "planHash" }, { kind: "content-includes", needle: "approved" }, { kind: "min-length", minChars: 20 }] },
      goalCaps: [TREASURY_SERVICE_ID],
      goalDescription: "signed payroll/rebalance plan + approval over a posted policy",
      note: "mechanical (approver-signed plan)",
    },
    {
      label: "site-auditor",
      serviceId: SITE_SERVICE_ID,
      deliveryPhase: SITE_DELIVERY_PHASE,
      keyPath: LIVE(".l4-site-key"),
      seedOs: SELLER_SEED_OS,
      minOs: SELLER_MIN_OS,
      reuse: existsSync(LIVE(".l4-site-key")),
      listingSpec: siteAuditorListingSpec({ amount: DEAL_PRICE_OS.toString(), asset: "DEM" }),
      metaShape: "report-json",
      buildWork: async () => makeSiteAuditorWork(new RealProber()),
      wireObserve: siteAuditorObserveDelivered(),
      jobParams: { url: "https://example.com/", samples: 3 },
      butlerPrice: 5,
      budget: 8,
      negotiable: false,
      quality: goodQuality,
      goalCaps: [SITE_SERVICE_ID],
      goalDescription: "attested performance/TLS/security-header site audit",
      note: "judgment (attested site audit) -> EvalBot gate",
    },
    {
      label: "sec-audit",
      serviceId: SEC_AUDIT_SERVICE_ID,
      deliveryPhase: SEC_AUDIT_DELIVERY_PHASE,
      keyPath: LIVE(".l4-sec-key"),
      seedOs: SELLER_SEED_OS,
      minOs: SELLER_MIN_OS,
      reuse: existsSync(LIVE(".l4-sec-key")),
      listingSpec: secAuditListingSpec({ amount: DEAL_PRICE_OS.toString(), asset: "DEM" }),
      metaShape: "report-json",
      buildWork: async () => makeSecAuditWork(),
      wireObserve: secAuditObserveDelivered(),
      jobParams: { files: postedFiles },
      butlerPrice: 5,
      budget: 8,
      negotiable: false,
      quality: goodQuality,
      goalCaps: [SEC_AUDIT_SERVICE_ID],
      goalDescription: "content-bound static security findings over posted files",
      note: "judgment (posted-content sec audit) -> EvalBot gate",
    },
    {
      label: "compliance",
      serviceId: COMPLIANCE_SERVICE_ID,
      deliveryPhase: COMPLIANCE_DELIVERY_PHASE,
      keyPath: LIVE(".l4-compliance-key"),
      seedOs: SELLER_SEED_OS,
      minOs: SELLER_MIN_OS,
      reuse: existsSync(LIVE(".l4-compliance-key")),
      listingSpec: complianceListingSpec({ amount: DEAL_PRICE_OS.toString(), asset: "DEM" }),
      metaShape: "report-json",
      buildWork: async () => makeComplianceWork(complianceSources),
      wireObserve: complianceObserveDelivered(),
      jobParams: { kind: "entity", name: "Lazarus Group" },
      butlerPrice: 5,
      budget: 8,
      negotiable: false,
      quality: goodQuality,
      goalCaps: [COMPLIANCE_SERVICE_ID],
      goalDescription: "attested sanctions/registry screening of a subject",
      note: "judgment (attested screening) -> EvalBot gate",
    },
  ];

  // dedicated EvalBot wallet (reused from L3).
  const evalKey = await loadOrCreateKey(EVAL_KEY_PATH);
  const evalbot = await connectIdentity("EvalBot", RPC, evalKey.mnemonic);
  const evalW = wallet(evalbot);

  // ── 3. Fund + establish every wallet (funder txs serialised) ──────────────
  // Per-wallet try/catch: a wallet that fails to establish blocks only ITS seller.
  line("\n── funding + establishing wallets (funder txs strictly serialised) ──");
  const establishFail = new Map<string, string>(); // label -> reason

  async function establish(w: Wallet, addr: string, seed: bigint, min: bigint, isNew: boolean, label: string): Promise<boolean> {
    try {
      await ensureEstablished(funderW, funder.address, w, addr, seed, min, isNew, label);
      return true;
    } catch (e) {
      const reason = (e as Error)?.message ?? String(e);
      establishFail.set(label, reason);
      step(`establish!`, `${label} FAILED: ${reason.slice(0, 80)}`);
      return false;
    }
  }

  // Buyer first (everything depends on it); then oracle, evalbot, then sellers.
  const buyerOk = await establish(buyerW, buyer.address, BUYER_SEED_OS, BUYER_MIN_OS, buyerKey.isNew, "buyer");
  if (!buyerOk) {
    line("\n❌ buyer wallet could not be established — no deal can settle. Reporting all sellers blocked.");
  }
  await establish(oracleW, oracleSeller.address, REUSE_SEED_OS, REUSE_MIN_OS, oracleKey.isNew, "oracle");
  await establish(evalW, evalbot.address, REUSE_SEED_OS, REUSE_MIN_OS, evalKey.isNew, "evalbot");

  // Connect + establish each pay-dem seller wallet.
  interface SellerRt extends PayDemSeller {
    identity: LiveIdentity;
    w: Wallet;
    isNew: boolean;
    established: boolean;
    sub: RetryingSubstrate;
    stash: Stash;
    agent?: SellerAdapter;
  }
  const rts: SellerRt[] = [];
  for (const s of sellers) {
    const key = await loadOrCreateKey(s.keyPath);
    const identity = await connectIdentity(s.label, RPC, key.mnemonic);
    const w = wallet(identity);
    step(s.label, `${identity.address}  [${key.isNew ? "new this run" : "persisted/established"}]`);
    const established = buyerOk ? await establish(w, identity.address, s.seedOs, s.minOs, key.isNew, s.label) : false;
    rts.push({
      ...s,
      identity,
      w,
      isNew: key.isNew,
      established,
      sub: new RetryingSubstrate(new LiveSubstrate(identity.adapter)),
      stash: new Map(),
    });
  }

  // ── 4. Shared buyer-side agents ───────────────────────────────────────────
  const buyerSub = new RetryingSubstrate(new LiveSubstrate(buyer.adapter));
  const oracleSub = new RetryingSubstrate(new LiveSubstrate(oracleSeller.adapter));
  const evalSub = new RetryingSubstrate(new LiveSubstrate(evalbot.adapter));
  const buyerAgent = new BuyerAdapter(buyer, buyerSub);
  const verifier = new VerifierAdapter(buyerSub);
  const bridge = new DacsButlerBuyer(buyerAgent, verifier, buyerSub);
  const owners = (sellerDid: string): DealOwners => ({ buyer: buyer.did, seller: sellerDid });

  const gateBot = new EvalBot({ useLlm: false });
  const evalAgent = new SellerAdapter(evalbot, evalSub, EVALBOT_SERVICE_ID, makeEvalBotWork(gateBot));

  // Build the seller agents (live hash-only work wrapper) for established sellers.
  const oracleAgent = new SellerAdapter(oracleSeller, oracleSub, ORACLE_SERVICE_ID, makeOracleWork(new RealAttestedFetch()));
  for (const rt of rts) {
    if (!rt.established) continue;
    const inner = await rt.buildWork();
    rt.agent = new SellerAdapter(rt.identity, rt.sub, rt.serviceId, liveWork(inner, rt.metaShape, rt.stash));
  }

  // ── 5. Publish anchored DACS-1 listings (ASCII-folded) ────────────────────
  line("\n── sellers publish ASCII-safe anchored DACS-1 listings on Demos ──");
  const publishFail = new Map<string, string>();
  let oracleListingRef = "";
  if (!establishFail.has("oracle")) {
    try {
      oracleListingRef = await oracleAgent.publishListing({
        ...asciiListing(oracleListingSpec({ amount: USDC_AMOUNT, asset: "USDC" })),
        supportedPaymentRails: ["pay-x402"],
      });
      step("oracle DACS-1", oracleListingRef);
    } catch (e) {
      publishFail.set("oracle-desk", (e as Error).message);
      step("oracle DACS-1!", `publish FAILED: ${(e as Error).message.slice(0, 70)}`);
    }
  }
  for (const rt of rts) {
    if (!rt.agent) continue;
    try {
      const ref = await rt.agent.publishListing({
        ...asciiListing(rt.listingSpec),
        supportedPaymentRails: ["pay-dem"],
      });
      (rt as { listingRef?: string }).listingRef = ref;
      step(`${rt.label} DACS-1`, ref);
    } catch (e) {
      publishFail.set(rt.label, (e as Error).message);
      step(`${rt.label} DACS-1!`, `publish FAILED: ${(e as Error).message.slice(0, 70)}`);
    }
  }

  // ── 6. Butler discovers the whole live basket ─────────────────────────────
  line("\n── Butler discovers + scores the full anchored basket ──");
  const ORACLE_ACCEPTANCE: AcceptancePolicy = {
    checks: [
      { kind: "content-includes", needle: "oracleDigest" },
      { kind: "min-length", minChars: 20 },
    ],
  };
  const profiles: Array<Omit<DacsOffer, "listing"> & { ref: string }> = [];
  if (oracleListingRef) {
    profiles.push({ ref: oracleListingRef, scope: "fixed", fee: { kind: "fixed", price: 0.05 }, negotiable: false, acceptance: ORACLE_ACCEPTANCE, quality: { rating: 4.9, completedJobs: 210, disputeRate: 0 } });
  }
  for (const rt of rts) {
    const ref = (rt as { listingRef?: string }).listingRef;
    if (!ref) continue;
    profiles.push({
      ref,
      scope: "parameterized",
      fee: { kind: "fixed", price: rt.butlerPrice },
      negotiable: rt.negotiable,
      ...(rt.floor !== undefined ? { floor: rt.floor } : {}),
      ...(rt.acceptance ? { acceptance: rt.acceptance } : {}),
      quality: rt.quality,
    });
  }
  const offers: DacsOffer[] = profiles.length ? await bridge.discoverOffers(profiles) : [];
  for (const o of offers) {
    step("offer", `"${o.listing.name}" rails=${JSON.stringify(o.listing.supportedPaymentRails)} scope=${o.scope}`);
  }
  const offerByRef = new Map(offers.map((o) => [o.ref, o]));

  // ── 7a. ORACLE leg — pay-x402 (real USDC on Base Sepolia) ─────────────────
  line("\n══ deal: oracle-desk (attested chain-height) — pay-x402 ══");
  if (!oracleFundable || !oracleListingRef || !offerByRef.has(oracleListingRef)) {
    const reason = !oracleFundable ? "buyer USDC unfunded (need >= 1 USDC)" : establishFail.get("oracle") ?? publishFail.get("oracle-desk") ?? "oracle listing unavailable";
    recordAndFlush({ seller: "oracle-desk", rail: "pay-x402", status: "blocked", settlementTx: "-", chainId: X402_NETWORK, anchors: { listing: oracleListingRef || undefined }, verdict: "-", balanceDelta: "-", gate: "-", error: reason });
  } else {
    try {
      const oracleJobId = `l4-oracle-${Date.now()}`;
      let oracleDeliveredValue: unknown;
      const { startX402Paywall } = await import("./x402-paywall.js");
      const paywall = await startX402Paywall({
        port: PAYWALL_PORT,
        route: "/oracle",
        payTo: sellerEvmAddr,
        network: X402_NETWORK,
        asset: USDC_BASE_SEPOLIA,
        amount: USDC_AMOUNT,
        facilitatorUrl: FACILITATOR_URL,
        description: "Attested oracle chain-height lookup (DACS pay-x402, L4)",
        deliver: async (jid, p) => {
          const d = await oracleAgent.deliver(jid, { product: "chain-height", ...p });
          oracleDeliveredValue = (d.attestation.meta as { value?: unknown } | undefined)?.value;
          step("deliver", `oracle anchored DACS-X on DEM -> ${d.attestationRef}  (value ${JSON.stringify(oracleDeliveredValue)})`);
          return { result: d.result, attestationRef: d.attestationRef };
        },
      });
      step("paywall", `seller x402 endpoint up -> ${paywall.url}`);

      const { createX402Rail } = await import("@kynesyslabs/dacs");
      const oracleRail = await createX402Rail({ evmPrivateKey: buyerEvmKey });
      step("rail", `buyer x402 rail ready (payer ${oracleRail.address}, gasless EIP-3009)`);

      const oracleSettleTx: { record?: SettleResult } = {};
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
      const oracleGoal: ProcurementGoal = { description: "attested chain-height lookup", requiredCapabilities: ["oracle-data", "pay-x402"] };
      const oracleDecision = await bridge.procure(oracleGoal, 1, offers);
      step("decision", `outcome=${oracleDecision.outcome} winner=${oracleDecision.winner?.provider ?? "-"} rail=${oracleDecision.winner?.rail ?? "-"}`);

      // The x402 402-dance settled cleanly in L2/L3; a lone L4 run saw a
      // transient facilitator/dance hiccup (`ok=false`). Bound-retry it (fresh
      // jobId per attempt so the failed attempt's agreement anchor never
      // collides), and if it still won't settle, block-and-CONTINUE the basket.
      let oracleOutcome: PurchaseOutcome | undefined;
      let usedJobId = oracleJobId;
      const ORACLE_ATTEMPTS = 3;
      try {
        for (let attempt = 1; attempt <= ORACLE_ATTEMPTS; attempt++) {
          usedJobId = `${oracleJobId}-a${attempt}`;
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
            }, { jobId: usedJobId });
            break; // 402 dance + delivery coupling succeeded
          } catch (err) {
            step("x402-retry", `attempt ${attempt}/${ORACLE_ATTEMPTS} failed (${(err as Error).message.slice(0, 56)}) — ${attempt < ORACLE_ATTEMPTS ? "backing off 5s" : "giving up"}`);
            if (attempt < ORACLE_ATTEMPTS) await sleep(5000);
          }
        }
      } finally {
        await paywall.close();
      }

      if (!oracleOutcome) {
        const usdcBuyerAfter = await readUsdcBalance(buyerEvmAddr).catch(() => usdcBuyerBefore);
        recordAndFlush({
          seller: "oracle-desk",
          rail: "pay-x402",
          status: "blocked",
          settlementTx: oracleSettleTx.record?.txHash ?? "-",
          chainId: oracleSettleTx.record?.chainId ?? X402_NETWORK,
          anchors: { listing: oracleListingRef },
          verdict: "-",
          balanceDelta: `USDC ${rawToUsdc(usdcBuyerAfter - usdcBuyerBefore)}`,
          gate: "-",
          error: `x402 402-dance did not settle after ${ORACLE_ATTEMPTS} attempts (transient facilitator/dance hiccup; last ok=${oracleSettleTx.record?.ok ?? false})`,
        });
      } else {
        step("execute", `rail=${oracleOutcome.rail} verified=${oracleOutcome.verified} verdict=${oracleOutcome.acceptance.verdict} accepted=${oracleOutcome.accepted}`);
        const oracleSellerBundle = await oracleAgent.fulfil(usedJobId, buyer.did);
        const anchors: DealAnchors = {
          listing: oracleListingRef,
          agreement: await buyerSub.anchorAddressFor(buyer.did, sessionAnchorName.agreement(usedJobId)),
          evidence: await buyerSub.anchorAddressFor(buyer.did, sessionAnchorName.evidence(usedJobId)),
          bundle: await buyerSub.anchorAddressFor(buyer.did, sessionAnchorName.bundle(usedJobId)),
          delivery: oracleOutcome.deliveryRef,
          sellerBundle: oracleSellerBundle,
        };
        const bundleV = await verifier.verify(anchors.bundle!, owners(oracleSeller.did));
        const usdcBuyerAfter = await readUsdcBalance(buyerEvmAddr);
        const settled = oracleOutcome.accepted && bundleV.ok && (oracleSettleTx.record?.ok ?? false);
        recordAndFlush({
          seller: "oracle-desk",
          rail: "pay-x402",
          status: settled ? "settled" : "blocked",
          settlementTx: oracleSettleTx.record?.txHash ?? "-",
          chainId: oracleSettleTx.record?.chainId ?? X402_NETWORK,
          anchors,
          verdict: `${oracleOutcome.acceptance.verdict} (auto-accept)`,
          balanceDelta: `USDC ${rawToUsdc(usdcBuyerAfter - usdcBuyerBefore)}  delivered=${JSON.stringify(oracleDeliveredValue)}`,
          gate: "n/a (mechanical)",
          ...(settled ? {} : { error: `accepted=${oracleOutcome.accepted} bundleOk=${bundleV.ok} payOk=${oracleSettleTx.record?.ok}` }),
        });
      }
    } catch (e) {
      recordAndFlush({ seller: "oracle-desk", rail: "pay-x402", status: "blocked", settlementTx: "-", chainId: X402_NETWORK, anchors: { listing: oracleListingRef }, verdict: "-", balanceDelta: "-", gate: "-", error: (e as Error).message.slice(0, 120) });
    }
  }

  // ── 7b. Each pay-dem seller — pay-dem session (real DEM on Demos) ──────────
  for (const rt of rts) {
    line(`\n══ deal: ${rt.label} (${rt.note}) — pay-dem session ══`);
    const listingRef = (rt as { listingRef?: string }).listingRef;
    if (!rt.established || !rt.agent || !listingRef || !offerByRef.has(listingRef) || !buyerOk) {
      const reason = establishFail.get(rt.label) ?? publishFail.get(rt.label) ?? (!buyerOk ? "buyer wallet unestablished" : "listing unavailable / not discovered");
      recordAndFlush({ seller: rt.label, rail: "pay-dem", status: "blocked", settlementTx: "-", chainId: "demos", anchors: { listing: listingRef }, verdict: "-", balanceDelta: "-", gate: rt.acceptance ? "n/a (mechanical)" : "would gate", error: reason });
      continue;
    }

    try {
      const jobId = `l4-${rt.label}-${Date.now()}`;
      const sellerDid = rt.identity.did;
      const sellerAgent = rt.agent;

      // LIVE pay-dem-session settle seam (mirrors L3's dd leg): move real DEM
      // buyer -> seller with strict buyer-nonce serialisation, then push the
      // seller's hash-only delivery and couple on the SELLER's owner-scoped anchor.
      const settleTx: { record?: TxRecord } = {};
      const settleSeam: SettleSeam = async (req: SettleRequest): Promise<SettleResult> => {
        const payeeHex = req.payee.match(/([0-9a-fA-F]{64})$/)?.[1];
        if (!payeeHex) throw new Error(`pay-dem: payee ${req.payee} has no resolvable Demos address`);
        const payee = `0x${payeeHex}`;
        const nonceBefore = Number((await buyerW.getAddressInfo(buyer.address))?.nonce ?? 0);
        const tx = await payDem(buyerW, payee, BigInt(req.amount));
        settleTx.record = tx;
        step("pay-dem", `settled ${osToDem(BigInt(req.amount))} buyer -> ${rt.label}  tx ${tx.hash}  block ${tx.confirmationBlock ?? "?"}`);
        if (!(await waitNonceAdvance(buyerW, buyer.address, nonceBefore))) {
          throw new Error("buyer nonce did not advance after settlement — evidence anchor would collide");
        }
        const delivery = await sellerAgent.deliver(req.jobId, rt.jobParams);
        step("deliver", `${rt.label} anchored DACS-X (hash-only) on DEM -> ${delivery.attestationRef}`);
        const delivered = await buyerSub.read(
          await buyerSub.anchorAddressFor(sellerDid, `dacsx:delivery:${req.jobId}`),
        );
        return { ok: delivered !== null && tx.hash.trim().length > 0, txHash: tx.hash, chainId: "demos", payer: buyer.address, payee };
      };

      const sellerDemBefore = BigInt((await rt.w.getAddressInfo(rt.identity.address))?.balance ?? 0n);
      const buyerDemBefore = BigInt((await buyerW.getAddressInfo(buyer.address))?.balance ?? 0n);

      const goal: ProcurementGoal = { description: rt.goalDescription, requiredCapabilities: rt.goalCaps };
      const decision: ProcurementDecision = await bridge.procure(goal, rt.budget, offers);
      step("decision", `outcome=${decision.outcome} winner=${decision.winner?.provider ?? "-"} rail=${decision.winner?.rail ?? "-"} price=${decision.winner?.price ?? "-"}`);
      if (decision.outcome !== "awarded" || !decision.winner || decision.winner.listingId !== listingRef) {
        throw new Error(`butler did not award ${rt.label} (outcome=${decision.outcome}, winner=${decision.winner?.listingId ?? "none"})`);
      }

      const outcome: PurchaseOutcome = await bridge.execute(decision, offers, {
        sellerDid,
        sellerEvm: "0x0000000000000000000000000000000000000000",
        seller: sellerAgent,
        observeDelivered: liveObserve(rt.metaShape, rt.stash, rt.wireObserve),
        deliveryPhase: rt.deliveryPhase,
        deliveryFormat: rt.metaShape === "report-json" ? "application/json" : "application/json",
        jobParams: rt.jobParams,
        onchainPrice: { amount: DEAL_PRICE_OS.toString(), asset: "DEM", decimals: 9 },
        payDemSessionSettle: settleSeam,
        deliverableOf: liveDeliverableOf(rt.stash),
      }, { jobId });
      step("execute", `rail=${outcome.rail} verified=${outcome.verified} verdict=${outcome.acceptance.verdict} accepted=${outcome.accepted} needsEvaluator=${outcome.needsEvaluator}`);

      const sellerBundle = await sellerAgent.fulfil(jobId, buyer.did);
      const anchors: DealAnchors = {
        listing: listingRef,
        agreement: await buyerSub.anchorAddressFor(buyer.did, sessionAnchorName.agreement(jobId)),
        evidence: await buyerSub.anchorAddressFor(buyer.did, sessionAnchorName.evidence(jobId)),
        bundle: await buyerSub.anchorAddressFor(buyer.did, sessionAnchorName.bundle(jobId)),
        delivery: outcome.deliveryRef,
        sellerBundle,
      };
      const bundleV = await verifier.verify(anchors.bundle!, owners(sellerDid));
      step("verify", `bundle ok=${bundleV.ok}`);

      // ── EvalBot gate (LIVE) for judgment deliverables ──────────────────────
      let gate = "n/a (mechanical)";
      let finalAccepted = outcome.accepted;
      let verdictStr = `${outcome.acceptance.verdict}`;
      if (outcome.needsEvaluator) {
        const rubric = rubricForOutcome({ serviceId: rt.serviceId });
        const evalJobId = `${jobId}-eval`;
        const evalDelivery = await evalAgent.deliver(evalJobId, {
          rubric,
          deliverable: { content: outcome.deliverable.content },
        });
        anchors.ruling = evalDelivery.attestationRef;
        const readRuling = readReportMeta<EvaluationRuling>(evalDelivery.attestation);
        const ruling = readRuling.ok ? readRuling.artifact : undefined;
        step("evalbot", `ruling anchored on DEM -> ${anchors.ruling}  verdict=${ruling?.verdict ?? "?"} aggregate=${ruling?.aggregate ?? "n/a"}`);
        const dvEval = await verifier.verifyDelivery(evalJobId, {
          serviceId: EVALBOT_SERVICE_ID,
          sellerDid: evalbot.did,
          observeDelivered: evalBotObserveDelivered(),
        });
        const rulingValid = dvEval.ok && !!ruling && verifyRuling(ruling).valid;
        finalAccepted = outcome.verified && rulingValid && ruling?.verdict === "accept";
        gate = `EvalBot LIVE: verdict=${ruling?.verdict ?? "?"} valid=${rulingValid}`;
        verdictStr = `needs-evaluator -> ruling ${ruling?.verdict ?? "?"}`;
        step("gate", `${rt.label} acceptance => ${finalAccepted ? "ACCEPTED" : "rejected"} (ruling ${ruling?.verdict ?? "?"})`);
      }

      await sleep(2000);
      const sellerDemAfter = BigInt((await rt.w.getAddressInfo(rt.identity.address))?.balance ?? 0n);
      const buyerDemAfter = BigInt((await buyerW.getAddressInfo(buyer.address))?.balance ?? 0n);
      const settled = outcome.verified && bundleV.ok && (settleTx.record?.hash?.length ?? 0) > 0 && finalAccepted;
      recordAndFlush({
        seller: rt.label,
        rail: "pay-dem",
        status: settled ? "settled" : "blocked",
        settlementTx: settleTx.record?.hash ?? "-",
        chainId: "demos",
        anchors,
        verdict: verdictStr,
        balanceDelta: `buyer ${osToDem(buyerDemAfter - buyerDemBefore)} · seller ${osToDem(sellerDemAfter - sellerDemBefore)}`,
        gate,
        ...(settled ? {} : { error: `verified=${outcome.verified} bundleOk=${bundleV.ok} finalAccepted=${finalAccepted}` }),
      });
    } catch (e) {
      const lastGood = settleStateNote((e as Error).message);
      recordAndFlush({ seller: rt.label, rail: "pay-dem", status: "blocked", settlementTx: "-", chainId: "demos", anchors: { listing: listingRef }, verdict: "-", balanceDelta: "-", gate: rt.acceptance ? "n/a (mechanical)" : "would gate", error: `${(e as Error).message.slice(0, 110)}${lastGood}` });
    }
  }

  // ── 8. Final report table ─────────────────────────────────────────────────
  const settledCount = results.filter((r) => r.status === "settled").length;
  const gatedJudgment = results.filter((r) => r.status === "settled" && r.gate.startsWith("EvalBot LIVE")).length;
  line("\n════════════════════════════════ L4 REPORT ════════════════════════════════");
  line(`  status            ${settledCount}/${results.length} sellers SETTLED-LIVE · ${gatedJudgment} judgment deals gated by live EvalBot`);
  line(`  demos rpc         ${RPC}`);
  line(`  base sepolia rpc  ${BASE_SEPOLIA_RPC}`);
  line(`  facilitator       ${FACILITATOR_URL}`);
  line("");
  line("  wallets (funder funds only; every deal party dedicated/persisted)");
  line(`    funder          ${funder.address}  [funding source only]`);
  line(`    buyer           ${buyer.address}  (DEM anchoring; established=${!establishFail.has("buyer")})`);
  line(`    buyer EVM       ${buyerEvmAddr}  (USDC payer)`);
  line(`    oracle seller   ${oracleSeller.address}`);
  line(`    oracle EVM      ${sellerEvmAddr}  (USDC payout)`);
  for (const rt of rts) line(`    ${rt.label.padEnd(13)} ${rt.identity.address}  [${rt.isNew ? "new this run" : "persisted"}${rt.established ? "" : ", UNESTABLISHED"}]`);
  line(`    evalbot         ${evalbot.address}`);
  line("");
  line("  ── per-seller outcomes ──");
  for (const r of results) {
    line("");
    line(`  ${r.seller}  [${r.rail}]  ${r.status.toUpperCase()}`);
    line(`    settlement tx   ${r.settlementTx}  (${r.chainId})`);
    line(`    verdict         ${r.verdict}`);
    line(`    eval gate       ${r.gate}`);
    line(`    balances Δ      ${r.balanceDelta}`);
    if (r.anchors.listing) line(`    listing anchor  ${r.anchors.listing}`);
    if (r.anchors.agreement) line(`    agreement       ${r.anchors.agreement}`);
    if (r.anchors.evidence) line(`    evidence        ${r.anchors.evidence}`);
    if (r.anchors.delivery) line(`    delivery        ${r.anchors.delivery}`);
    if (r.anchors.bundle) line(`    bundle          ${r.anchors.bundle}`);
    if (r.anchors.sellerBundle) line(`    seller bundle   ${r.anchors.sellerBundle}`);
    if (r.anchors.ruling) line(`    ruling anchor   ${r.anchors.ruling}`);
    if (r.error) line(`    note            ${r.error}`);
  }
  line("");
  line("  ── settlement table ──");
  line("  seller         rail      status    settlement tx / anchor");
  line("  ─────────────────────────────────────────────────────────────────────────");
  for (const r of results) {
    // Full, untruncated settlement hash (Base Sepolia for oracle, Demos for the
    // rest) so every row is directly verifiable on-chain.
    const ref = r.settlementTx !== "-" ? r.settlementTx : (r.anchors.listing ?? "-");
    line(`  ${r.seller.padEnd(13)}  ${r.rail.padEnd(8)}  ${r.status.padEnd(8)}  ${ref}`);
  }
  line("════════════════════════════════════════════════════════════════════════════");
  line(`\n${settledCount === results.length ? "✅" : "◑"} L4 completed: ${settledCount}/${results.length} sellers procured live by the Butler` +
    ` (${gatedJudgment} judgment deals resolved by the live EvalBot gate).\n`);

  flushLog();
  console.log(`  (report written -> ${LOG_PATH})`);
  // Continue-on-error contract: exit 0 whenever the run COMPLETED and reported
  // every seller's outcome, regardless of how many individually settled.
  process.exit(0);
}

/** Best-effort last-good-state annotation for a blocked deal's error line. */
function settleStateNote(msg: string): string {
  if (/nonce did not advance/.test(msg)) return " [lastGood: settlement tx broadcast, evidence anchor aborted]";
  if (/no delivery anchored|deliver/.test(msg)) return " [lastGood: DEM settled, delivery anchor failed]";
  if (/did not award/.test(msg)) return " [lastGood: listing published + discovered]";
  return "";
}

main().catch((e) => {
  const msg = (e as Error)?.stack ?? (e as Error)?.message ?? String(e);
  console.error("\n❌ L4 aborted before completion:", msg);
  logLines.push(`\n❌ L4 aborted before completion: ${msg}`);
  flushLog();
  process.exit(1);
});
