/**
 * Re-publish (re-anchor) every DACS seller's DACS-1 Listing with its CURRENT,
 * cleaned-up, per-unit description — so the directory's next `npm run index`
 * picks up fresh cards.
 *
 *   npm run dacs:republish
 *
 * This is a RE-ANCHOR of existing listings ONLY — NO deals, NO settlements, NO
 * EvalBot gate. The listings on-chain were anchored during the L4 run with OLD
 * descriptions (raw "1000000000 DEM", cluttered copy, no per-unit pricing). The
 * listing specs in `roster/dacs/wire/*.ts` have since been fixed (human-readable
 * `formatFee`/`formatFeeSchedule`, ASCII names, per-unit pricing for
 * sec-audit / dep-upgrade / site-auditor). Re-publishing anchors at the SAME
 * owner-scoped address — `deriveStorageAddress(sellerAddr, "dacs1:listing:<did>:
 * <serviceId>")` — so it is an UPDATE: registrations stay valid, only the
 * human-facing content refreshes.
 *
 * The moving parts are lifted VERBATIM from `l4-full-basket.ts`: the exact
 * wallet→seller mapping, the per-seller price passed to each `<agent>ListingSpec`
 * (so the anchor address is byte-identical), the funder mnemonic / RPC, the
 * `LiveSubstrate` + `SellerAdapter` construction, the established persisted keys
 * (`.l1-seller-key`, `.l3-dd-seller-key`, `.l4-{depup,treasury,site,sec,
 * compliance}-key`), the strict per-wallet nonce serialisation, and the
 * ASCII-fold (`asciiSafe`/`asciiListing`). Only the intent differs: publish, then
 * read the anchor back and confirm the on-chain description now equals the new
 * text (the `LiveSubstrate.anchor` read-visibility loop already waits for the
 * update to be read-visible before returning).
 *
 * CONTINUE-ON-ERROR: each seller's re-anchor is wrapped in its own try/catch over
 * its OWN wallet. A blocked re-anchor records `{status:"blocked", error}` and the
 * run moves to the next seller — one failure never aborts the rest. The process
 * exits 0 as long as the run completes and reports every seller's outcome.
 *
 * ReviewBot (`src/agents/seller.ts`) is re-anchored LAST, from the funder wallet
 * (its DID is the funder's), with its updated per-unit fee schedule.
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { connectIdentity, type LiveIdentity } from "../../../src/live/identity.js";
import { LiveSubstrate } from "../../../src/live/substrate.js";
import { SellerAdapter, standardListingSpecFromLegacy, type WorkResult } from "../seller-adapter.js";

// ── seller wires (the CURRENT, already-clean specs) ──────────────────────────
import { ORACLE_SERVICE_ID, oracleListingSpec } from "../wire/oracle-desk.js";
import { DD_SERVICE_ID, ddListingSpec } from "../wire/dd-researcher.js";
import { DEPUP_SERVICE_ID, depUpgradeListingSpec } from "../wire/dep-upgrade.js";
import { TREASURY_SERVICE_ID, treasuryListingSpec } from "../wire/treasury-ops.js";
import { SITE_SERVICE_ID, siteAuditorListingSpec } from "../wire/site-auditor.js";
import { SEC_AUDIT_SERVICE_ID, secAuditListingSpec } from "../wire/sec-audit.js";
import { COMPLIANCE_SERVICE_ID, complianceListingSpec } from "../wire/compliance.js";

// ── ReviewBot (the reference seller) ─────────────────────────────────────────
import { REVIEWBOT_FEES } from "../../../src/agents/seller.js";
import { LiveGitHub } from "../../../src/live/github.js";

// ── DEM ground truth (identical to L1/L2/L3/L4) ──────────────────────────────
const RPC = process.env.DEMOS_RPC ?? "https://demosnode.discus.sh/";
const FUNDER_MNEMONIC = (() => {
  const value = process.env.FUNDER_MNEMONIC?.trim();
  if (!value) throw new Error("FUNDER_MNEMONIC is required; never embed wallet mnemonics in source");
  return value;
})();

/** 1 DEM = 10^9 OS (§9.5.9, integer arithmetic). */
const OS_PER_DEM = 1_000_000_000n;
/** Every pay-dem deal settled 1 DEM in L4 — the price each ListingSpec renders. */
const DEAL_PRICE_OS = 1n * OS_PER_DEM;
/** Oracle price in L4: 1 USDC (6 decimals). */
const USDC_AMOUNT = "1000000";

/** An anchor UPDATE costs ~1 DEM; top up any wallet that has fallen below this. */
const TOPUP_MIN_OS = 3n * OS_PER_DEM;
/** How much to send when a top-up is needed (comfortably above the anchor cost). */
const TOPUP_SEED_OS = 5n * OS_PER_DEM;

// Persisted key files (all git-ignored) — the SAME wallets L4 used.
const LIVE = (f: string) => join(process.cwd(), "roster/dacs/live", f);
const ORACLE_KEY_PATH = LIVE(".l1-seller-key");
const DD_KEY_PATH = LIVE(".l3-dd-seller-key");

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
const step = (n: string, msg: string): void => line(`  ${n.padEnd(16)} ${msg}`);
const LOG_PATH = LIVE("republish-run.log");
function flushLog(): void {
  try {
    writeFileSync(LOG_PATH, logLines.join("\n") + "\n");
  } catch {
    /* best-effort */
  }
}

const osToDem = (os: bigint): string => `${(Number(os) / 1e9).toFixed(4)} DEM`;

async function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * Fold a string to pure ASCII so it can ride an anchored storage-program tx (the
 * Demos node rejects non-ASCII UTF-8 payloads with "[SIGNATURE ERROR]
 * Transaction hash mismatch"). Verbatim from L4. The specs are already ASCII —
 * this is idempotent belt-and-suspenders (never reintroduces em-dashes).
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

interface TxRecord {
  hash: string;
  confirmationBlock?: number;
}

/** The verified DEM settlement path: transfer -> confirm -> broadcast. */
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
 * Ensure a seller wallet can afford an anchor update: if it holds < TOPUP_MIN_OS,
 * send TOPUP_SEED_OS from the funder, strictly serialised on the funder's nonce.
 * Returns the funding tx (if any) and the confirmed balance.
 */
async function topUpIfLow(
  funderW: Wallet,
  funderAddr: string,
  w: Wallet,
  addr: string,
  label: string,
): Promise<{ fundTx?: TxRecord; balance: bigint }> {
  const bal0 = BigInt((await w.getAddressInfo(addr))?.balance ?? 0n);
  step(`${label} bal`, osToDem(bal0));
  if (bal0 >= TOPUP_MIN_OS) return { balance: bal0 };

  step(`fund->${label}`, `balance ${osToDem(bal0)} < ${osToDem(TOPUP_MIN_OS)} — topping up ${osToDem(TOPUP_SEED_OS)}`);
  const fundNonce = await funderW.getAddressNonce(funderAddr);
  const fundTx = await payDem(funderW, addr, TOPUP_SEED_OS);
  step(`fund->${label}`, `tx ${fundTx.hash}  block ${fundTx.confirmationBlock ?? "?"}`);
  if (!(await waitNonceAdvance(funderW, funderAddr, fundNonce))) {
    throw new Error(`funder nonce did not advance after funding ${label}`);
  }
  const funded = await waitBalanceAtLeast(w, addr, bal0 + TOPUP_SEED_OS - OS_PER_DEM);
  step("", `${label} balance landed: ${osToDem(funded)}`);
  return { fundTx, balance: funded };
}

// ── Seller descriptor: the SAME DID/serviceId/price L4 used per wallet ────────
interface SellerDesc {
  label: string;
  serviceId: string;
  keyPath: string;
  rails: string[];
  /** The current (clean, per-unit-where-applicable) listing spec, ASCII-folded. */
  spec: { serviceId: string; name: string; description: string };
  price: { amount: string; asset: string };
}

/** No-op work callback — republish only calls `publishListing`, never `deliver`. */
const noopWork = async (): Promise<WorkResult> => ({ result: null });

interface Row {
  seller: string;
  serviceId: string;
  anchor: string;
  updated: boolean;
  status: "updated" | "blocked";
  description: string;
  error?: string;
}

/** Retry a re-anchor 2-3 times before giving up (transient node lag). */
async function publishWithRetry(agent: SellerAdapter, spec: SellerDesc): Promise<string> {
  const legacy = { ...asciiListing(spec.spec), supportedPaymentRails: spec.rails };
  const listingSpec = standardListingSpecFromLegacy(legacy, spec.price, { displayName: legacy.name });
  let last: unknown;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      return (await agent.publishStandardListing(listingSpec)).ref;
    } catch (e) {
      last = e;
      step(`${spec.label} retry`, `attempt ${attempt}/3 failed (${(e as Error).message.slice(0, 60)})`);
      await sleep(6000);
    }
  }
  throw last;
}

async function main(): Promise<void> {
  line("+--------------------------------------------------------------------------+");
  line("|  RE-PUBLISH LISTINGS — re-anchor every DACS seller with the CLEAN spec    |");
  line("|  (directory refresh; NO deals, NO settlements)                           |");
  line("+--------------------------------------------------------------------------+");
  line(`  demos rpc    ${RPC}`);
  line(`  when         ${new Date().toISOString()}`);

  const rows: Row[] = [];
  const record = (r: Row): void => {
    rows.push(r);
    line(`  >> ${r.seller.padEnd(13)} ${r.status.toUpperCase()}${r.error ? `  (${r.error})` : ""}`);
    flushLog();
  };

  // ── Funder (funding source AND ReviewBot's own wallet) ─────────────────────
  const funder = await connectIdentity("Funder", RPC, FUNDER_MNEMONIC);
  const funderW = wallet(funder);
  const funderBal0 = BigInt((await funderW.getAddressInfo(funder.address))?.balance ?? 0n);
  step("funder", `${funder.address}  balance ${osToDem(funderBal0)}`);

  if (!existsSync(ORACLE_KEY_PATH) || !existsSync(DD_KEY_PATH)) {
    throw new Error("expected the established L1/L3 seller wallets — run the L-series first");
  }

  // ── The 8 roster sellers — exact L4 mapping (price -> description only) ─────
  const sellers: SellerDesc[] = [
    {
      label: "oracle-desk",
      serviceId: ORACLE_SERVICE_ID,
      keyPath: ORACLE_KEY_PATH,
      rails: ["pay-x402"],
      spec: oracleListingSpec({ amount: USDC_AMOUNT, asset: "USDC" }),
      price: { amount: USDC_AMOUNT, asset: "USDC" },
    },
    {
      label: "dd-researcher",
      serviceId: DD_SERVICE_ID,
      keyPath: DD_KEY_PATH,
      rails: ["pay-dem"],
      spec: ddListingSpec({ amount: DEAL_PRICE_OS.toString(), asset: "DEM" }),
      price: { amount: DEAL_PRICE_OS.toString(), asset: "DEM" },
    },
    {
      label: "dep-upgrade",
      serviceId: DEPUP_SERVICE_ID,
      keyPath: LIVE(".l4-depup-key"),
      rails: ["pay-dem"],
      spec: depUpgradeListingSpec({ amount: DEAL_PRICE_OS.toString(), asset: "DEM" }),
      price: { amount: DEAL_PRICE_OS.toString(), asset: "DEM" },
    },
    {
      label: "treasury-ops",
      serviceId: TREASURY_SERVICE_ID,
      keyPath: LIVE(".l4-treasury-key"),
      rails: ["pay-dem"],
      spec: treasuryListingSpec({ amount: DEAL_PRICE_OS.toString(), asset: "DEM" }),
      price: { amount: DEAL_PRICE_OS.toString(), asset: "DEM" },
    },
    {
      label: "site-auditor",
      serviceId: SITE_SERVICE_ID,
      keyPath: LIVE(".l4-site-key"),
      rails: ["pay-dem"],
      spec: siteAuditorListingSpec({ amount: DEAL_PRICE_OS.toString(), asset: "DEM" }),
      price: { amount: DEAL_PRICE_OS.toString(), asset: "DEM" },
    },
    {
      label: "sec-audit",
      serviceId: SEC_AUDIT_SERVICE_ID,
      keyPath: LIVE(".l4-sec-key"),
      rails: ["pay-dem"],
      spec: secAuditListingSpec({ amount: DEAL_PRICE_OS.toString(), asset: "DEM" }),
      price: { amount: DEAL_PRICE_OS.toString(), asset: "DEM" },
    },
    {
      label: "compliance",
      serviceId: COMPLIANCE_SERVICE_ID,
      keyPath: LIVE(".l4-compliance-key"),
      rails: ["pay-dem"],
      spec: complianceListingSpec({ amount: DEAL_PRICE_OS.toString(), asset: "DEM" }),
      price: { amount: DEAL_PRICE_OS.toString(), asset: "DEM" },
    },
  ];

  line("\n-- re-anchoring the 8 roster sellers (funder top-ups serialised) --");
  for (const s of sellers) {
    line(`\n== re-anchor: ${s.label} (${s.serviceId}) ==`);
    try {
      if (!existsSync(s.keyPath)) {
        record({ seller: s.label, serviceId: s.serviceId, anchor: "-", updated: false, status: "blocked", description: "-", error: `missing key file ${s.keyPath}` });
        continue;
      }
      const mnemonic = readFileSync(s.keyPath, "utf8").trim();
      const id = await connectIdentity(s.label, RPC, mnemonic);
      const w = wallet(id);
      step(s.label, `${id.address}  did ${id.did}`);

      await topUpIfLow(funderW, funder.address, w, id.address, s.label);

      const sub = new LiveSubstrate(id.adapter);
      const agent = new SellerAdapter(id, sub, s.serviceId, noopWork);

      const anchor = await publishWithRetry(agent, s);
      const wantDesc = asciiListing(s.spec).description;

      // Read the anchor back and CONFIRM the on-chain description now equals the
      // new text. (LiveSubstrate.anchor already waited for read-visibility, but
      // this is an explicit content assertion + captures what was anchored.)
      const back = await sub.read(anchor);
      const gotDesc = typeof (back?.offering as Record<string, unknown> | undefined)?.description === "string"
        ? (back!.offering as Record<string, unknown>).description as string
        : "";
      const updated = gotDesc === wantDesc;
      step(`${s.label} anchor`, anchor);
      step(`${s.label} desc`, gotDesc || "(read-back empty)");
      if (!updated) {
        step(`${s.label} WARN`, `read-back description does not match expected:\n      expected: ${wantDesc}\n      got:      ${gotDesc}`);
      }
      record({
        seller: s.label,
        serviceId: s.serviceId,
        anchor,
        updated,
        status: updated ? "updated" : "blocked",
        description: gotDesc,
        ...(updated ? {} : { error: "read-back description mismatch" }),
      });
    } catch (e) {
      record({ seller: s.label, serviceId: s.serviceId, anchor: "-", updated: false, status: "blocked", description: "-", error: (e as Error).message.slice(0, 120) });
    }
  }

  // ── ReviewBot — re-anchor from the funder wallet (its DID), per-unit fee ────
  line(`\n== re-anchor: reviewbot (pr-review) ==`);
  try {
    // Anchor cost from the funder wallet — ensure it can still afford one.
    const funderBalNow = BigInt((await funderW.getAddressInfo(funder.address))?.balance ?? 0n);
    step("reviewbot bal", `funder wallet ${osToDem(funderBalNow)}`);
    if (funderBalNow < TOPUP_MIN_OS) {
      throw new Error(`funder/ReviewBot wallet below ${osToDem(TOPUP_MIN_OS)} (${osToDem(funderBalNow)}) — cannot anchor`);
    }

    // The GitHub login embedded in the description (matches the L4/live anchor).
    let authedLogin = "unknown";
    try {
      const lg = new LiveGitHub();
      authedLogin = lg.authedLogin;
    } catch (e) {
      step("reviewbot gh", `gh CLI unavailable (${(e as Error).message.slice(0, 50)}) — embedding placeholder login`);
    }

    const sub = new LiveSubstrate(funder.adapter);
    const reviewBot = new SellerAdapter(funder, sub, "pr-review", noopWork);
    if (REVIEWBOT_FEES.kind !== "per-unit") throw new Error("ReviewBot listing requires its per-unit fee schedule");
    const reviewFees = REVIEWBOT_FEES;
    const service = {
      serviceId: "pr-review",
      name: "LLM code review from a CCI-verified GitHub identity",
      description:
        `Automated LLM code review delivered as a GitHub PR review, authored from a CCI-verified GitHub identity. ` +
        `Fee: ${reviewFees.unitPrice} DEM per ${reviewFees.unit} (min ${reviewFees.minTotal} DEM). [github:${authedLogin}]`,
      supportedNegotiation: ["negotiate-fixed-price"],
      supportedPaymentRails: ["pay-dem", "pay-x402"],
      supportedDelivery: ["deliver-pr-review"],
      fees: reviewFees,
    };
    const standardService = standardListingSpecFromLegacy(service, { amount: DEAL_PRICE_OS.toString(), asset: "DEM" }, { displayName: service.name, category: "software.code-review", tags: ["code-review", "github", "attested"] });
    let anchor = "";
    let last: unknown;
    for (let attempt = 1; attempt <= 3 && !anchor; attempt++) {
      try {
        anchor = (await reviewBot.publishStandardListing(standardService)).ref;
      } catch (e) {
        last = e;
        step("reviewbot retry", `attempt ${attempt}/3 failed (${(e as Error).message.slice(0, 60)})`);
        await sleep(6000);
      }
    }
    if (!anchor) throw last;

    const back = await sub.read(anchor);
    const gotDesc = typeof (back?.offering as Record<string, unknown> | undefined)?.description === "string"
      ? (back!.offering as Record<string, unknown>).description as string
      : "";
    // The seller.ts publishListing composes: `${description}${feeText} [github:<login>]`.
    const updated = gotDesc.includes("100-diff-lines") && gotDesc.includes("Automated LLM code review");
    step("reviewbot anchor", anchor);
    step("reviewbot desc", gotDesc || "(read-back empty)");
    record({
      seller: "reviewbot",
      serviceId: "pr-review",
      anchor,
      updated,
      status: updated ? "updated" : "blocked",
      description: gotDesc,
      ...(updated ? {} : { error: "read-back missing per-unit fee text" }),
    });
  } catch (e) {
    record({ seller: "reviewbot", serviceId: "pr-review", anchor: "-", updated: false, status: "blocked", description: "-", error: (e as Error).message.slice(0, 120) });
  }

  // ── Final table ────────────────────────────────────────────────────────────
  const ok = rows.filter((r) => r.status === "updated").length;
  line("\n================================ REPUBLISH REPORT ==============================");
  line(`  status   ${ok}/${rows.length} listings re-anchored + read-back confirmed`);
  line(`  demos rpc ${RPC}`);
  line("");
  line("  seller         serviceId              updated  anchor address");
  line("  ------------------------------------------------------------------------------");
  for (const r of rows) {
    const mark = r.updated ? "  ok   " : " BLOCK ";
    line(`  ${r.seller.padEnd(13)}  ${r.serviceId.padEnd(21)}  ${mark}  ${r.anchor}`);
  }
  line("");
  line("  -- anchored descriptions --");
  for (const r of rows) {
    line("");
    line(`  ${r.seller}  [${r.serviceId}]  ${r.status.toUpperCase()}`);
    line(`    anchor  ${r.anchor}`);
    line(`    desc    ${r.description}`);
    if (r.error) line(`    note    ${r.error}`);
  }
  line("================================================================================");
  line(`\n${ok === rows.length ? "OK" : "PARTIAL"}: ${ok}/${rows.length} listings re-anchored with clean per-unit descriptions.\n`);

  flushLog();
  console.log(`  (report written -> ${LOG_PATH})`);
  process.exit(0);
}

main().catch((e) => {
  const msg = (e as Error)?.stack ?? (e as Error)?.message ?? String(e);
  console.error("\nX republish aborted before completion:", msg);
  logLines.push(`\nX republish aborted before completion: ${msg}`);
  flushLog();
  process.exit(1);
});
