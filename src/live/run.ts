/**
 * LIVE run — the PR-review-for-hire lifecycle against real infrastructure:
 *
 *   substrate  → Demos testnet (storage-program anchors, real txs)
 *   identity   → real wallets; ReviewBot's DID is the wallet whose CCI record
 *                carries an on-chain GitHub proof (Web2 identity)
 *   vet        → dacs-sdk #13 `cci-claim` recipe against the on-chain GCR
 *   delivery   → a real review posted on a real GitHub PR via `gh`
 *   review     → a real LLM (claude CLI)
 *   rail       → mock settle for this milestone (evm-erc20 next); everything
 *                else is live
 *
 * Run: npm run live   (idempotent: reuses the arena repo/PR; new jobId per run)
 */
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { parseCciRecord, vetCore } from "@kynesyslabs/dacs";
import type { SessionTerms } from "@kynesyslabs/dacs";

import { BuyerAgent } from "../agents/buyer.js";
import { SellerAgent } from "../agents/seller.js";
import { makeReviewer } from "../agents/review-llm.js";
import { VerifierAgent } from "../agents/verifier.js";
import { connectIdentity, LiveCci } from "./identity.js";
import { LiveGitHub } from "./github.js";
import { LiveSubstrate } from "./substrate.js";
import { startPaywall } from "./paywall.js";

// Base Sepolia (x402 rail): CAIP-2 network + Circle testnet USDC.
const X402_NETWORK = "eip155:84532" as const;
const USDC_BASE_SEPOLIA = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const FACILITATOR_URL = "https://x402.org/facilitator";

const RPC = process.env.DEMOS_RPC ?? "https://demosnode.discus.sh/";
/** ReviewBot = the wallet whose CCI record is GitHub-bound (the shared test wallet). */
const REVIEWBOT_MNEMONIC = (() => {
  const value = process.env.REVIEWBOT_MNEMONIC?.trim();
  if (!value) throw new Error("REVIEWBOT_MNEMONIC is required; never embed wallet mnemonics in source");
  return value;
})();
const ARENA_REPO = (() => {
  const value = process.env.ARENA_REPO?.trim();
  if (!value) throw new Error("ARENA_REPO is required for the live GitHub example");
  return value;
})();

const line = (s = "") => console.log(s);
const step = (n: string, msg: string) => console.log(`  ${n.padEnd(10)} ${msg}`);
const sh = (cmd: string, args: string[], opts: object = {}): string =>
  execFileSync(cmd, args, { encoding: "utf8", maxBuffer: 8 * 1024 * 1024, ...opts });

/** Buyer wallet persists across runs (fund once). demosdk wants a BIP-39 mnemonic. */
async function buyerSecret(): Promise<string> {
  const envPath = join(process.cwd(), ".buyer-key");
  if (existsSync(envPath)) return readFileSync(envPath, "utf8").trim();
  // @ts-expect-error — bip39 ships no ESM types at this deep path
  const { generateMnemonic } = await import("../../sdk/node_modules/bip39/src/index.js");
  const mnemonic = generateMnemonic(128, () => randomBytes(16)) as string;
  writeFileSync(envPath, mnemonic + "\n", { mode: 0o600 });
  return mnemonic;
}

/**
 * Real LLM review via the `claude` CLI: a STRUCTURED review (findings +
 * verdict, rendered to Markdown), with the untrusted PR title/diff piped on
 * stdin (never shell-interpolated) and a deterministic fallback if the CLI is
 * absent or errors. See src/agents/review-llm.ts.
 */
const llmReview = makeReviewer();

/** Ensure the arena repo + a reviewable PR exist; returns the PR number. */
function ensureArenaPr(): number {
  const repoExists = (() => {
    try { sh("gh", ["repo", "view", ARENA_REPO, "--json", "name"]); return true; } catch { return false; }
  })();
  if (!repoExists) {
    sh("gh", ["repo", "create", ARENA_REPO, "--private", "--description",
      "Scratch arena for the DACS agent-commerce PR-review ecosystem (live demo)"]);
    step("github", `created private repo ${ARENA_REPO}`);
  }
  // An open PR?
  try {
    const open = JSON.parse(sh("gh", ["pr", "list", "--repo", ARENA_REPO, "--state", "open", "--json", "number"]));
    if (Array.isArray(open) && open.length > 0) return open[0].number as number;
  } catch { /* fall through to create */ }

  // Seed main + a feature branch with a reviewable diff, then open the PR.
  const work = `/tmp/dacs-arena-${Date.now()}`;
  sh("git", ["clone", `https://github.com/${ARENA_REPO}.git`, work]);
  const g = (args: string[]) => sh("git", ["-C", work, ...args]);
  if (!existsSync(join(work, "settle.js"))) {
    writeFileSync(join(work, "settle.js"), "export const settleOnce = (req) => settle(req);\n");
    writeFileSync(join(work, "README.md"), "# dacs-review-arena\nScratch repo for DACS live demo reviews.\n");
    g(["add", "."]); g(["commit", "-m", "seed: settleOnce"]);
    g(["push", "origin", "HEAD:main"]);
  }
  g(["checkout", "-b", `retry-loop-${Date.now()}`]);
  writeFileSync(join(work, "settle.js"), [
    "export async function settleWithRetry(req) {",
    "  for (let i = 0; i < 5; i++) {",
    "    const r = await settle(req);",
    "    if (r.ok) return r;",
    "    console.log('retrying', i);",
    "  }",
    "  // TODO: surface a typed error",
    "  return { ok: false };",
    "}",
    "",
  ].join("\n"));
  g(["add", "."]); g(["commit", "-m", "feat: settlement retry loop"]);
  g(["push", "origin", "HEAD"]);
  const out = sh("gh", ["pr", "create", "--repo", ARENA_REPO, "--title", "Add settlement retry loop",
    "--body", "Requesting a paid ReviewBot review via the DACS ecosystem.", "--base", "main",
    "--head", g(["branch", "--show-current"]).trim()]);
  const m = out.match(/\/pull\/(\d+)/);
  if (!m) throw new Error("could not create arena PR");
  return Number(m[1]);
}

async function main() {
  line("┌────────────────────────────────────────────────────────────────┐");
  line("│  DACS ecosystem — LIVE: Demos testnet + real GitHub + real LLM  │");
  line("└────────────────────────────────────────────────────────────────┘");

  // ── Identities (real wallets) ─────────────────────────────────────────────
  const reviewBotId = await connectIdentity("ReviewBot", RPC, REVIEWBOT_MNEMONIC);
  const buyerId = await connectIdentity("AcmeOwner", RPC, await buyerSecret());
  step("wallets", `ReviewBot ${reviewBotId.address.slice(0, 18)}…  buyer ${buyerId.address.slice(0, 18)}…`);

  const cci = new LiveCci(reviewBotId.adapter);
  const github = new LiveGitHub();
  const claimedLogin = github.authedLogin;

  // The CCI proof is the demo's foundation — resolve it up front.
  const boundLogin = await cci.githubLoginFor(reviewBotId.did);
  step("CCI", `ReviewBot DID is on-chain bound to github:${boundLogin} (gh authed as ${claimedLogin})`);
  if (!boundLogin || boundLogin.toLowerCase() !== claimedLogin.toLowerCase()) {
    throw new Error("ReviewBot's CCI GitHub binding does not match the gh identity — cannot deliver as the bound login");
  }

  // ── Fund the buyer (one-time): DEM transfer so its anchors broadcast ─────
  const buyerInfo = await (buyerId.adapter as unknown as { demos: { getAddressInfo: (a: string) => Promise<{ balance?: bigint | number } | null> } }).demos
    .getAddressInfo(buyerId.address).catch(() => null);
  const buyerBalance = BigInt(buyerInfo?.balance ?? 0);
  step("funding", `buyer balance: ${buyerBalance}`);
  if (buyerBalance < 1_000_000_000n) {
    step("funding", "transferring DEM ReviewBot → buyer…");
    await fundFromReviewBot(reviewBotId, buyerId.address, 2_000_000_000_000n);
    // Demos wallets have SERIAL nonce semantics: a follow-up tx broadcast
    // before this one is included can evict it from the mempool. Block until
    // the credit is visible before ReviewBot (or the buyer) sends anything else.
    let credited = false;
    for (let i = 0; i < 24 && !credited; i++) {
      await new Promise((r) => setTimeout(r, 2500));
      const info = await (buyerId.adapter as unknown as { demos: { getAddressInfo: (a: string) => Promise<{ balance?: bigint | number } | null> } }).demos
        .getAddressInfo(buyerId.address).catch(() => null);
      credited = BigInt(info?.balance ?? 0) > 0n;
    }
    if (!credited) throw new Error("funding transfer not visible after 60s — check the tx landed");
    step("funding", "transfer included — buyer credited ✓");
  }

  // ── The arena: a real repo + PR that wants review ─────────────────────────
  const pullNumber = ensureArenaPr();
  step("github", `arena PR: https://github.com/${ARENA_REPO}/pull/${pullNumber}`);

  // ── Agents on the live ports ──────────────────────────────────────────────
  const reviewBotSub = new LiveSubstrate(reviewBotId.adapter);
  const buyerSub = new LiveSubstrate(buyerId.adapter);
  const reviewBot = new SellerAgent(reviewBotId, reviewBotSub, github, claimedLogin, llmReview);
  const buyer = new BuyerAgent(buyerId, buyerSub, cci);
  const verifier = new VerifierAgent(buyerSub, cci); // read-only usage

  // Price: 1 DEM, in OS base units (§9.5.9: 1 DEM = 10^9 OS, integer arithmetic).
  const terms: SessionTerms = {
    price: { amount: "1000000000", asset: "DEM", decimals: 9, rail: "pay-dem" },
    deliveryPhase: "deliver-github-pr-review",
    deliveryFormat: "text/markdown",
  };
  const jobId = `live-${Date.now()}`;

  /**
   * pay-dem settle (§9.5.9) — REAL native-DEM transfer on the Demos substrate,
   * to the same DID the buyer just vetted, on the same chain that anchors the
   * evidence. Pay → await the seller's work → confirm the review is on GitHub
   * by the CCI-bound login → only then ok (the coupling pattern).
   *
   * Known SDK gap (FINDINGS F7): SettleResult can't carry blockNumber and
   * runSessionCore hardcodes settlementFinality "provider-receipt", so the
   * evidence can't yet express §9.5.9's `bft-final` + txRef kind `demos`.
   */
  const payDemSettle = (order: { repo: string; pullNumber: number; awaitDelivery: () => Promise<void> }) =>
    async (req: { amount: string; payee: string; jobId: string }) => {
      const payeeHex = req.payee.match(/([0-9a-fA-F]{64})$/)?.[1];
      if (!payeeHex) throw new Error(`pay-dem: payee ${req.payee} has no resolvable Demos address`);
      const payeeAddress = `0x${payeeHex}`;

      const demos = (buyerId.adapter as unknown as {
        demos: {
          transfer: (to: string, amount: bigint) => Promise<{ hash?: string }>;
          confirm: (tx: unknown) => Promise<unknown>;
          broadcastAndWait: (v: unknown, opts?: object) => Promise<{ response?: { hash?: string } }>;
        };
      }).demos;
      const info = (await (buyerId.adapter as unknown as { demos: { getAddressInfo: (a: string) => Promise<{ nonce?: number } | null> } }).demos
        .getAddressInfo(buyerId.address).catch(() => null));
      const nonceBefore = Number(info?.nonce ?? 0);

      const signed = await demos.transfer(payeeAddress, BigInt(req.amount));
      const validity = await demos.confirm(signed);
      const broadcast = await demos.broadcastAndWait(validity, { timeoutMs: 90_000 });
      const txHash = broadcast?.response?.hash ?? signed?.hash ?? "";
      step("pay-dem", `paid ${req.amount} OS (1 DEM) → ${payeeAddress.slice(0, 18)}… tx ${String(txHash).slice(0, 18)}…`);

      // Serialise the wallet: the next tx (the evidence anchor, via the
      // dacs-sdk adapter) SELF-resolves its nonce from chain — the adapter has
      // no explicit-nonce passthrough yet (noted on dacs-sdk#23). If the node
      // hasn't reflected this transfer, the anchor gets a stale nonce and now
      // FAILS LOUDLY (testnet enforces nonces since 2026-07; previously it
      // silently evicted). Wait for the nonce to advance before returning.
      for (let i = 0; i < 24; i++) {
        const now = (await (buyerId.adapter as unknown as { demos: { getAddressInfo: (a: string) => Promise<{ nonce?: number } | null> } }).demos
          .getAddressInfo(buyerId.address).catch(() => null));
        if (Number(now?.nonce ?? 0) > nonceBefore) break;
        await new Promise((r) => setTimeout(r, 2500));
      }

      await order.awaitDelivery();

      const boundLogin = await cci.githubLoginFor(req.payee);
      const delivered = github
        .listReviews(order.repo, order.pullNumber)
        .some((r) => r.user.login.toLowerCase() === (boundLogin ?? "").toLowerCase());

      return {
        ok: delivered && String(txHash).length > 0,
        txHash: String(txHash),
        chainId: "demos",
        payer: buyerId.address,
        payee: payeeAddress,
      };
    };

  // ── Scene: full lifecycle, on-chain ───────────────────────────────────────
  line("\n━━ LIVE deal: ReviewBot reviews a real PR, anchored on the Demos testnet ━━");
  const listingRef = await reviewBot.publishListing({
    serviceId: "pr-review",
    name: "LLM code review from a CCI-verified GitHub identity",
    description: "1 DEM per review; delivered as a GitHub PR review.",
    githubLogin: claimedLogin,
    rails: ["pay-dem", "pay-x402"],
  });
  step("DACS-1", `listing anchored on-chain → ${listingRef.slice(0, 40)}…`);

  const found = await buyer.discover([listingRef]);
  step("discover", `buyer resolved ${found.length} listing(s) from chain: "${found[0]?.listing.name}"`);

  const awaitDelivery = async () => {
    await reviewBot.deliverReview(jobId, { repo: ARENA_REPO, pullNumber });
  };
  const result = await buyer.buy(listingRef, terms, {
    jobId,
    claimedGithubLogin: claimedLogin,
    repo: ARENA_REPO,
    pullNumber,
    awaitDelivery,
    settleFn: payDemSettle({ repo: ARENA_REPO, pullNumber, awaitDelivery }),
    // Vet: the REAL cci-claim recipe (dacs-sdk #13) against the on-chain GCR.
    vetFn: (subject) =>
      vetCore(
        {
          subject,
          recipe: {
            id: "github-identity-cci-claim",
            method: "cci-claim",
            availability: "live",
            params: { requiredClaim: `web2:github:${claimedLogin}` },
          },
        },
        {
          proxyFetch: async (req) => {
            const r = await buyerSub.proxyFetch(req);
            return {
              status: r.status,
              responseHash: r.responseHash,
              body: typeof r.body === "string" ? r.body : JSON.stringify(r.body ?? null),
            };
          },
          now: () => new Date().toISOString(),
          resolveCci: async (s) => {
            const hex = s.match(/([0-9a-fA-F]{64})$/)?.[1] ?? s;
            const resolved = await buyerId.adapter.resolveIdentity(hex);
            return parseCciRecord(s, resolved.raw);
          },
        },
      ),
  });
  step("DACS-2", `vet passed → on-chain CCI proof for github:${claimedLogin} ✓`);
  step("DACS-3", `agreement anchored on-chain → ${result.agreementRef.slice(0, 40)}…`);
  step("DACS-4", `paid 1 DEM (pay-dem §9.5.9, real tx) + delivery confirmed on GitHub → ${result.settlementRef.slice(0, 40)}…`);
  step("DACS-5", `buyer bundle anchored on-chain → ${result.bundleRef.slice(0, 40)}… (outcome: ${result.outcome})`);

  const reviews = github.listReviews(ARENA_REPO, pullNumber);
  const latest = reviews[reviews.length - 1];
  step("github", `PR now carries a review by @${latest?.user.login}:`);
  for (const l of (latest?.body ?? "").split("\n").slice(0, 12)) line(`             │ ${l}`);

  const sellerBundleRef = await reviewBot.fulfil(jobId, buyerId.did);
  step("fulfil", `seller countersigned on-chain → ${sellerBundleRef.slice(0, 40)}…`);

  const owners = { buyer: buyerId.did, seller: reviewBotId.did };
  const v = await verifier.verify(result.bundleRef, owners);
  step("verify", `bundle: ok=${v.ok} fullyVerified=${v.fullyVerified}`);
  step("refs", v.refs.map((r) => `${r.kind}=${r.verdict}`).join(", "));
  const dv = await verifier.verifyDelivery(jobId, reviewBotId.did);
  step("delivery", `DACS-X attestation: ok=${dv.ok}${dv.ok ? ` (review #${dv.attestation?.reviewId} by @${dv.attestation?.ghAuthor})` : ` — ${dv.reason}`}`);
  const rec = await verifier.reconcile(result.bundleRef, sellerBundleRef, owners);
  step("reconcile", `two-sided (§10.4.3): reconciled=${rec.reconciled}${rec.reason ? ` (${rec.reason})` : ""}`);

  // ══ Deal B — SAME identity, DIFFERENT chain: x402 on Base Sepolia ═════════
  line("\n━━ LIVE deal B: x402 rail — USDC on Base Sepolia, payee from CCI ━━");

  // The payout address comes from the SAME on-chain identity record the buyer
  // vetted: ReviewBot's CCI-linked EVM wallet. Vet on Demos, settle on Base.
  const cciRecord = parseCciRecord(
    reviewBotId.did,
    (await reviewBotId.adapter.resolveIdentity(reviewBotId.address.replace(/^0x/, ""))).raw,
  );
  const payoutEvm = cciRecord.wallets.find((w) => w.chainType === "evm")?.address;
  if (!payoutEvm) throw new Error("ReviewBot's CCI record has no linked EVM wallet");
  step("CCI", `payout resolved from the vetted identity → ${payoutEvm.slice(0, 14)}… (xm:evm)`);

  // ReviewBot's x402 paywall — the seller half the SDK lacks (FINDINGS F3).
  const jobIdB = `live-x402-${Date.now()}`;
  const paywall = await startPaywall(
    {
      port: 4021,
      payTo: payoutEvm,
      network: X402_NETWORK,
      asset: USDC_BASE_SEPOLIA,
      amount: "1000000", // 1 USDC (6 decimals)
      facilitatorUrl: FACILITATOR_URL,
    },
    reviewBot,
  );
  step("paywall", `ReviewBot x402 endpoint up → ${paywall.url} (facilitator: ${FACILITATOR_URL})`);

  const { createX402Rail } = await import("@kynesyslabs/dacs");
  const buyerEvmKey = readFileSync(join(process.cwd(), ".buyer-evm-key"), "utf8").trim();
  const rail = await createX402Rail({ evmPrivateKey: buyerEvmKey });
  step("rail", `buyer x402 rail ready (payer ${rail.address.slice(0, 14)}…, gasless EIP-3009)`);

  const termsB: SessionTerms = {
    price: { amount: "1000000", asset: "USDC", decimals: 6, rail: "pay-x402" },
    deliveryPhase: "deliver-github-pr-review",
    deliveryFormat: "text/markdown",
  };
  const resultB = await buyer.buy(listingRef, termsB, {
    jobId: jobIdB,
    claimedGithubLogin: claimedLogin,
    repo: ARENA_REPO,
    pullNumber,
    // x402 couples pay+deliver: the paywall does the work before responding.
    awaitDelivery: async () => {},
    vetFn: (subject) =>
      vetCore(
        {
          subject,
          recipe: {
            id: "github-identity-cci-claim",
            method: "cci-claim",
            availability: "live",
            params: { requiredClaim: `web2:github:${claimedLogin}` },
          },
        },
        {
          proxyFetch: async (req) => {
            const r = await buyerSub.proxyFetch(req);
            return { status: r.status, responseHash: r.responseHash, body: typeof r.body === "string" ? r.body : JSON.stringify(r.body ?? null) };
          },
          now: () => new Date().toISOString(),
          resolveCci: async (s) => {
            const hex = s.match(/([0-9a-fA-F]{64})$/)?.[1] ?? s;
            const resolved = await buyerId.adapter.resolveIdentity(hex);
            return parseCciRecord(s, resolved.raw);
          },
        },
      ),
    // Settle = the SDK's REAL x402 buyer dance against ReviewBot's paywall.
    settleFn: async (req) => {
      const pay = await rail.settle({
        paywallUrl: `${paywall.url}?jobId=${encodeURIComponent(req.jobId)}&repo=${encodeURIComponent(ARENA_REPO)}&pr=${pullNumber}`,
        network: X402_NETWORK,
        recipientEvm: payoutEvm,
        amount: req.amount,
        asset: USDC_BASE_SEPOLIA, // resolved on-chain token id (§4.1 guard, dacs-sdk#10)
      });
      step("x402", `402-dance settled: ok=${pay.ok} tx ${pay.txHash.slice(0, 18)}… (Base Sepolia)`);
      // Independent delivery check on GitHub, same as the pay-dem deal.
      const boundLoginB = await cci.githubLoginFor(req.payee);
      const delivered = github
        .listReviews(ARENA_REPO, pullNumber)
        .some((r) => r.user.login.toLowerCase() === (boundLoginB ?? "").toLowerCase());
      return { ...pay, ok: pay.ok && delivered, payer: rail.address };
    },
  });
  step("DACS-4", `x402 settled on Base Sepolia + delivered → evidence ${resultB.settlementRef.slice(0, 40)}…`);
  step("DACS-5", `buyer bundle anchored → ${resultB.bundleRef.slice(0, 40)}… (outcome: ${resultB.outcome})`);

  const sellerBundleRefB = await reviewBot.fulfil(jobIdB, buyerId.did);
  const vB = await verifier.verify(resultB.bundleRef, owners);
  const dvB = await verifier.verifyDelivery(jobIdB, reviewBotId.did);
  const recB = await verifier.reconcile(resultB.bundleRef, sellerBundleRefB, owners);
  step("audit", `bundle ok=${vB.ok}, delivery attestation ok=${dvB.ok}, reconciled=${recB.reconciled}`);
  await paywall.close();

  const rep = await verifier.reputation(reviewBotId.did, [
    result.bundleRef,
    sellerBundleRef,
    resultB.bundleRef,
    sellerBundleRefB,
  ]);
  step("DACS-5", `ReviewBot reputation across BOTH rails: ${rep.completed}/${rep.totalAgreements} completed`);

  // Emit a machine-readable ledger of this run's deals — the seller's own
  // index of anchored artifacts (feeds the DACS Directory catalog seed).
  const ledgerPath = join(process.cwd(), "runs.json");
  const ledger = existsSync(ledgerPath) ? JSON.parse(readFileSync(ledgerPath, "utf8")) : { deals: [] };
  ledger.seller = { did: reviewBotId.did, address: reviewBotId.address, github: claimedLogin };
  ledger.buyer = { did: buyerId.did, address: buyerId.address };
  ledger.listingRef = listingRef;
  ledger.deals.push(
    { jobId, rail: "pay-dem", buyerBundleRef: result.bundleRef, sellerBundleRef, agreementRef: result.agreementRef, settlementRef: result.settlementRef, owners },
    { jobId: jobIdB, rail: "pay-x402", buyerBundleRef: resultB.bundleRef, sellerBundleRef: sellerBundleRefB, agreementRef: resultB.agreementRef, settlementRef: resultB.settlementRef, owners },
  );
  writeFileSync(ledgerPath, JSON.stringify(ledger, null, 2) + "\n");
  step("ledger", `run recorded → ${ledgerPath} (${ledger.deals.length} deals total)`);

  line("\n✅ LIVE two-rail run complete — one deal settled in DEM on Demos, one in USDC on Base");
  line("   Sepolia via x402; same vetted identity, all artifacts on-chain, all audited.\n");
  process.exit(0);
}

/**
 * Native DEM transfer via demosdk ≥4.0.12's `transfer()` — which only SIGNS;
 * the caller must confirm + broadcast. `broadcastAndWait` polls until the tx
 * reaches a terminal state, which also serialises the wallet's nonce (a
 * follow-up tx broadcast before inclusion can evict this one).
 */
async function fundFromReviewBot(
  from: Awaited<ReturnType<typeof connectIdentity>>,
  toAddress: string,
  amount: bigint,
): Promise<void> {
  const demos = (from.adapter as unknown as {
    demos: {
      getAddress: () => string;
      getAddressNonce: (a: string) => Promise<number>;
      transfer: (to: string, amount: bigint, options?: { nonce?: number }) => Promise<unknown>;
      confirm: (tx: unknown) => Promise<unknown>;
      broadcastAndWait: (validity: unknown, opts?: object) => Promise<unknown>;
    };
  }).demos;
  // Official nonce pattern (testnet fails wrong-nonce txs since 2026-07;
  // demosdk >=4.0.14): fetch the account nonce and construct explicitly.
  const nonce = await demos.getAddressNonce(demos.getAddress());
  const signed = await demos.transfer(toAddress, amount, { nonce: nonce + 1 });
  const validity = await demos.confirm(signed);
  await demos.broadcastAndWait(validity, { timeoutMs: 90_000 });
}

main().catch((e) => {
  console.error("\n❌ live run failed:", e?.message ?? e);
  process.exit(1);
});
