/**
 * LIVE entrypoint scaffold for the roster DACS seller layer — Build D, Part 4.
 *
 *   DACS_LIVE=1 npm run dacs:live      (wires the real seams; see README.md)
 *   npm run dacs:live                  (no-op: prints the credential + node-dep brief)
 *
 * This mirrors `src/live/run.ts` but for the generalized `roster/dacs/` layer.
 * It swaps the mock seams for their live counterparts BEHIND env gating, so the
 * file TYPES and is fully wired yet **no-ops without credentials** and NEVER
 * attempts a real settlement:
 *
 *   substrate  → `DemosAdapter` (`@kynesyslabs/dacs/substrate`) via `LiveSubstrate`
 *   x402 rail  → the SDK's real `createX402Rail` (EIP-3009 gasless USDC)
 *   pay-dem    → `createLiveDemLedger` — a native DEM transfer carrying the
 *                `DACS:<jobId>` memo (the same binding the mock ledger uses)
 *   watcher    → `createLivePoller` — polls `getTransactions` / address history
 *                and filters DACS memos (Pattern-1 chain-triggered delivery)
 *
 * The two seams marked (DEP-A) / (DEP-B) below are LIVE DEPENDENCIES to verify
 * against the node before enabling — see README.md. Until then the live branch
 * only CONNECTS + WIRES the ports and prints the plan; it deliberately stops
 * before publishing, settling, or delivering anything on-chain.
 */
import type { DemLedgerPort } from "../rails.js";
import type { WatchPort } from "../watcher.js";
import { demMemoFor } from "../rails.js";

// ---------------------------------------------------------------------------
// Env gating
// ---------------------------------------------------------------------------

interface LiveEnv {
  rpc: string;
  sellerMnemonic: string;
  buyerMnemonic: string;
  buyerEvmKey?: string;
}

const REQUIRED = ["SELLER_MNEMONIC", "BUYER_MNEMONIC"] as const;

function readEnv(): { ok: true; env: LiveEnv } | { ok: false; missing: string[] } {
  const missing = REQUIRED.filter((k) => !process.env[k]);
  if (missing.length > 0) return { ok: false, missing };
  return {
    ok: true,
    env: {
      rpc: process.env.DEMOS_RPC ?? "https://demosnode.discus.sh/",
      sellerMnemonic: process.env.SELLER_MNEMONIC!,
      buyerMnemonic: process.env.BUYER_MNEMONIC!,
      buyerEvmKey: process.env.BUYER_EVM_KEY,
    },
  };
}

const line = (s = "") => console.log(s);
const step = (n: string, msg: string) => console.log(`  ${n.padEnd(12)} ${msg}`);

/** The credential + node-dependency brief printed when live mode is off. */
function printBrief(): void {
  line("┌────────────────────────────────────────────────────────────────────────┐");
  line("│  roster/dacs LIVE scaffold — wired, but no-op without DACS_LIVE=1 + creds │");
  line("└────────────────────────────────────────────────────────────────────────┘");
  line("\nThis entrypoint TYPES and is wired to the real seams, but it will not");
  line("publish, settle, or deliver anything until you opt in AND supply creds.\n");
  line("Enable with:");
  step("env", "DACS_LIVE=1");
  step("env", "SELLER_MNEMONIC=\"<12-word BIP-39 mnemonic, funded>\"");
  step("env", "BUYER_MNEMONIC=\"<12-word BIP-39 mnemonic, funded>\"");
  step("env", "DEMOS_RPC=https://demosnode.discus.sh/   (default)");
  step("env", "BUYER_EVM_KEY=0x…   (only for the x402 rail on Base Sepolia)");
  line("\nFaucets:");
  step("DEM", "https://faucet.demos.sh/            — fund both wallets before a real run");
  step("Base ETH", "https://www.alchemy.com/faucets/base-sepolia   (x402 gas)");
  step("USDC", "Circle Base-Sepolia testnet USDC 0x036CbD53842c5426634e7929541eC2318f3dCF7e");
  line("\nLive dependencies to verify against the node BEFORE enabling settlement:");
  step("DEP-A", "Does Demos native `transfer(to, amount)` accept a MEMO? The pay-dem");
  step("", "rail binds a transfer to a job via `DACS:<jobId>` in the memo. demosdk's");
  step("", "`transfer` has no documented memo arg yet — confirm the wallet/node carry");
  step("", "it end-to-end (or bind the job another way) before real settlement.");
  step("DEP-B", "Is there a `getTransactions` / address-history RPC for the Pattern-1");
  step("", "watcher? There is no list-txs / enumerate-anchors RPC today; the live");
  step("", "poller must read inbound transfers and filter DACS memos — verify the");
  step("", "node exposes this feed (and an inbound filter) before enabling the watcher.");
  line("\nSee roster/dacs/live/README.md for the full walkthrough.\n");
}

// ---------------------------------------------------------------------------
// Live seams (documented shapes lifted from rails.ts / watcher.ts). Dynamic
// import keeps the chain deps off the mock path; these only load in live mode.
// ---------------------------------------------------------------------------

/** Minimal slice of the wallet handle DemosAdapter exposes for native transfers. */
interface DemosWalletHandle {
  transfer: (to: string, amount: bigint, opts?: { memo?: string; nonce?: number }) => Promise<{ hash?: string }>;
  confirm: (tx: unknown) => Promise<unknown>;
  broadcast: (v: unknown) => Promise<{ result?: number; response?: { hash?: string }; extra?: { confirmationBlock?: number } }>;
  getAddressInfo: (addr: string) => Promise<{ nonce?: number } | null>;
  getTransactions?: (q: object) => Promise<Array<{ from: string; to: string; amount: string; memo?: string; hash: string }>>;
}

/**
 * (DEP-A) Live pay-dem ledger: a native DEM transfer, then a nonce-advance wait
 * to serialise the wallet (the anchor that follows self-resolves its nonce; the
 * testnet rejects a stale one). Watch side throws — it belongs to the poller.
 *
 * The settlement path is the one L1 proved live end-to-end (see
 * `l1-paydem.ts`): `transfer → confirm → broadcast` (NOT d402 /
 * `broadcastNativeTransaction`, which the node answers `{"error":"Unknown
 * message"}`, and NOT `broadcastAndWait` — plain `broadcast` returns
 * `{result:200, response:{message}, extra:{confirmationBlock}}` and we serialise
 * on the nonce ourselves). The txHash comes from `broadcast.response.hash`.
 *
 * NOTE (DEP-A, still open): the memo passthrough is unverified against the node
 * — L1 settles Pattern 2 (session/push), where the params are conveyed in-band
 * and the transfer needs no memo. The Pattern-1 memo-watcher path below still
 * depends on a memo the node carries end-to-end.
 */
function createLiveDemLedger(cfg: { demos: DemosWalletHandle; payerAddr: string }): DemLedgerPort {
  return {
    async transfer({ to, amount, memo }) {
      const before = Number((await cfg.demos.getAddressInfo(cfg.payerAddr))?.nonce ?? 0);
      const signed = await cfg.demos.transfer(to, amount, { memo });
      const validity = await cfg.demos.confirm(signed);
      const broadcast = await cfg.demos.broadcast(validity);
      if (broadcast?.result !== 200) {
        throw new Error(`pay-dem broadcast rejected: ${JSON.stringify(broadcast?.response ?? broadcast)}`);
      }
      for (let i = 0; i < 24; i++) {
        const now = Number((await cfg.demos.getAddressInfo(cfg.payerAddr))?.nonce ?? 0);
        if (now > before) break;
        await new Promise((r) => setTimeout(r, 2500));
      }
      return { txHash: broadcast?.response?.hash ?? signed?.hash ?? "" };
    },
    onTransferTo() {
      throw new Error("live watch: use createLivePoller (getTransactions) — see watcher.ts live seam");
    },
  };
}

/**
 * (DEP-B) Live Pattern-1 watcher feed: poll inbound address history and surface
 * DACS-tagged transfers. The `SellerWatcher` decision logic is chain-agnostic —
 * only this feed changes.
 */
function createLivePoller(cfg: { demos: DemosWalletHandle; intervalMs?: number }): WatchPort {
  return {
    watchTransfersTo(address, onTransfer) {
      if (!cfg.demos.getTransactions) {
        throw new Error("live watch (DEP-B): node exposes no getTransactions / address-history RPC");
      }
      const seen = new Set<string>();
      setInterval(async () => {
        const txs = await cfg.demos.getTransactions!({ to: address });
        for (const tx of txs) {
          if (seen.has(tx.hash) || !tx.memo?.startsWith("DACS:")) continue;
          seen.add(tx.hash);
          await onTransfer({ from: tx.from, to: tx.to, amount: BigInt(tx.amount), memo: tx.memo, txHash: tx.hash });
        }
      }, cfg.intervalMs ?? 5_000);
    },
  };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const live = process.env.DACS_LIVE === "1";
  const env = readEnv();

  if (!live || !env.ok) {
    if (live && !env.ok) {
      line(`\n⚠ DACS_LIVE=1 but missing env: ${env.missing.join(", ")}\n`);
    }
    printBrief();
    process.exit(0);
  }

  // --- LIVE: wire the real seams (no settlement) ---------------------------
  line("┌────────────────────────────────────────────────────────────────────────┐");
  line("│  roster/dacs LIVE — wiring real seams (DemosAdapter + rails + watcher)   │");
  line("└────────────────────────────────────────────────────────────────────────┘\n");

  // Substrate + identities behind the SAME SubstratePort the mock demos use.
  const { connectIdentity } = await import("../../../src/live/identity.js");
  const { LiveSubstrate } = await import("../../../src/live/substrate.js");
  const { SellerAdapter } = await import("../seller-adapter.js");
  const { BuyerAdapter } = await import("../buyer.js");
  const { VerifierAdapter } = await import("../verifier.js");
  const { ORACLE_SERVICE_ID, makeOracleWork } = await import("../wire/oracle-desk.js");
  const { RealAttestedFetch } = await import("../../oracle-desk/attested-fetch.js");

  const seller = await connectIdentity("OracleDesk", env.env.rpc, env.env.sellerMnemonic);
  const buyer = await connectIdentity("Buyer", env.env.rpc, env.env.buyerMnemonic);
  const sellerSub = new LiveSubstrate(seller.adapter);
  const buyerSub = new LiveSubstrate(buyer.adapter);
  step("substrate", `DemosAdapter connected — seller ${seller.address.slice(0, 18)}… buyer ${buyer.address.slice(0, 18)}…`);

  const sellerAgent = new SellerAdapter(seller, sellerSub, ORACLE_SERVICE_ID, makeOracleWork(new RealAttestedFetch()));
  const buyerAgent = new BuyerAdapter(buyer, buyerSub);
  const verifier = new VerifierAdapter(buyerSub);
  void sellerAgent;
  void buyerAgent;
  void verifier;
  step("agents", "SellerAdapter + BuyerAdapter + VerifierAdapter bound to the live substrate");

  // pay-dem ledger + Pattern-1 poller over the live wallet handle.
  const demosHandle = (buyer.adapter as unknown as { demos: DemosWalletHandle }).demos;
  const ledger = createLiveDemLedger({ demos: demosHandle, payerAddr: buyer.address });
  const poller = createLivePoller({ demos: (seller.adapter as unknown as { demos: DemosWalletHandle }).demos });
  void ledger;
  void poller;
  step("pay-dem", `live DEM ledger wired (memo binding: ${demMemoFor("<jobId>")}) — DEP-A unverified`);
  step("watcher", "live getTransactions poller wired — DEP-B unverified");

  // x402 rail (only if an EVM key is present).
  if (env.env.buyerEvmKey) {
    const { createX402Rail } = await import("@kynesyslabs/dacs");
    const rail = await createX402Rail({ evmPrivateKey: env.env.buyerEvmKey });
    void rail;
    step("x402", "createX402Rail ready (gasless EIP-3009)");
  } else {
    step("x402", "skipped — set BUYER_EVM_KEY to wire the Base-Sepolia x402 rail");
  }

  line("\n✅ Live seams wired. This scaffold STOPS before publish/settle/deliver by");
  line("   design (Build D Part 4). Resolve DEP-A (transfer memo) and DEP-B");
  line("   (getTransactions watch) against the node, then extend main() to run a");
  line("   real session — mirroring roster/dacs/demo-ecosystem.ts on the live ports.\n");
  process.exit(0);
}

main().catch((e) => {
  console.error("\n❌ dacs:live scaffold failed:", (e as Error)?.stack ?? (e as Error)?.message ?? e);
  process.exit(1);
});
