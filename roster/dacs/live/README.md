# roster/dacs — LIVE entrypoint scaffold

`run-live.ts` is the typed, wired live counterpart of the mock-first ecosystem
demo (`roster/dacs/demo-ecosystem.ts`). It swaps the mock seams for their real
counterparts **behind env gating**, so it TYPES and is fully wired yet **no-ops
without credentials** and never attempts a real settlement.

```bash
npm run dacs:live            # no-op: prints the credential + node-dependency brief
DACS_LIVE=1 SELLER_MNEMONIC=… BUYER_MNEMONIC=… npm run dacs:live   # wires real seams
```

Even with `DACS_LIVE=1`, this scaffold deliberately **stops before
publish / settle / deliver**. It connects the `DemosAdapter`, binds the
seller/buyer/verifier to the live substrate, and wires the pay-dem ledger, the
Pattern-1 watcher, and (optionally) the x402 rail — then prints the plan. Extend
`main()` to run a real session. Of the two live dependencies below (probed
2026-07-08): DEP-B is resolved; DEP-A is **blocked** (the memo rail isn't live),
so x402 + pay-dem Pattern 2 are viable but Pattern 1 (memo-watcher) is not yet.

## The seam swap

| Concern     | Mock (demo-ecosystem.ts)      | Live (run-live.ts)                                            |
|-------------|-------------------------------|--------------------------------------------------------------|
| substrate   | `MemorySubstrate`             | `DemosAdapter` (`@kynesyslabs/dacs/substrate`) via `LiveSubstrate` |
| identity    | `makeIdentity(seed)`          | `connectIdentity(rpc, mnemonic)` — real funded wallets       |
| x402 rail   | `MockFacilitator` + paywall   | the SDK's real `createX402Rail` (EIP-3009 gasless USDC)       |
| pay-dem     | `MockDemLedger`               | bare native `transfer`→`confirm`→`broadcast` (works live; **no memo** — fine for Pattern 2 session, whose jobId binds off-chain via anchored evidence) |
| watcher     | `MockLedgerWatch`             | `getTransactionHistory` is live, but Pattern 1 is **blocked**: no on-chain memo to key payments to a jobId until the D402 rail is enabled |
| work (data) | canned / resilient fetch      | `RealAttestedFetch` (real upstream)                          |

The seller layer itself is written against `SubstratePort` + `Signer`, so the
adapters cannot tell which world they are in — only the injected ports change.

## Credentials

| Var              | Required | Purpose                                                        |
|------------------|----------|----------------------------------------------------------------|
| `DACS_LIVE`      | yes      | Must be `1` to leave no-op mode.                               |
| `SELLER_MNEMONIC`| yes      | 12-word BIP-39 mnemonic for the seller wallet (funded).       |
| `BUYER_MNEMONIC` | yes      | 12-word BIP-39 mnemonic for the buyer wallet (funded).        |
| `DEMOS_RPC`      | no       | Demos RPC (default `https://demosnode.discus.sh/`).           |
| `BUYER_EVM_KEY`  | no       | `0x…` EVM private key — only to wire the Base-Sepolia x402 rail.|

### Faucets

- **DEM** (fund both Demos wallets before any real run): <https://faucet.demos.sh/>
- **Base Sepolia ETH** (x402 gas): <https://www.alchemy.com/faucets/base-sepolia>
- **USDC** (x402 asset): Circle Base-Sepolia testnet USDC
  `0x036CbD53842c5426634e7929541eC2318f3dCF7e`

## Live dependencies — TESTED against live nodes 2026-07-08 (one resolved, one blocked)

Probed with the test wallet against `demosnode.discus.sh` (funded, nonce 37) and
`dev.node2.demos.sh`, by actually broadcasting txs. Result: **DEP-B works;
DEP-A does NOT — the memo-carrying rail is not live on the node.** Net effect:
x402 and pay-dem **Pattern 2 (session)** are viable live; pay-dem **Pattern 1
(memo-watcher)** is **blocked** until the D402 rail is enabled on the node.

### DEP-A — on-chain memo binding: NOT AVAILABLE today (BLOCKED)

Two things are true and together block it:
- **d402 (the only memo-carrying payment) does not broadcast.** `D402Client.settle`
  calls `nodeCall("broadcastNativeTransaction", …)`; the live node replies
  `{"error":"Unknown message","message":"broadcastNativeTransaction"}` — the RPC is
  not implemented. The tx never landed; nonce stayed 37. (Separately, the shipped
  `D402Client.createPayment` also leaves top-level `content.to` empty → the client
  fails with `"Invalid To address: 0x"` even before broadcast.)
- **the working DEM settlement has no memo.** The bare native transfer path
  (`transfer` → `confirm` → `broadcast`) IS live and confirmed
  (`confirm` → 200 "signature verified"; `broadcast` → 200 "received during
  consensus, confirmation in next block"), but its payload is
  `nativeOperation:"send", args:[to, amount]` — no memo field.

So there is **no way to bind a jobId into an on-chain DEM payment today**. The
`pay-d402` rail the ROADMAP anticipates would fix this, but it is not live on the
current nodes. Consequences:
- **Pattern 2 (session) is unaffected** — it does NOT need an on-chain memo; the
  jobId binds via the off-chain anchored `SettlementEvidence` at the deterministic
  `sessionAnchorName.evidence(jobId)` slot (exactly what `runSessionCore` does), and
  it settles with the working bare transfer.
- **Pattern 1 (zero-inbound memo-watcher) is not viable on-chain yet** — the watcher
  can see payments (DEP-B) but has nothing to key them to a jobId. Options: wait for
  pay-d402 to go live, or fall back to a weaker heuristic (match incoming transfer by
  payer+amount+timing to a buyer-anchored agreement — the coincidental-citation risk
  the DACS threat model flags). `createLiveDemLedger`/`createLivePoller` are left as
  scaffolds pending pay-d402.

### DEP-B — address-history RPC for the watcher (RESOLVED)

`demos.getTransactionHistory(address, type, {start, limit})`
(`websdk/demosclass.js:1085`, nodeCall `getTransactionHistory`) is **live on both
nodes** — "transaction history of an address, most-recent first", with a `type`
filter. Probe returned real address-scoped history (5 and 3 txs) with readable
`content.type`/`content.data`. The watcher's *query* primitive is therefore
available; it is only the memo *binding* (DEP-A) that blocks Pattern 1. So
`createLivePoller` can poll `getTransactionHistory(payoutAddr, …)`,
tracks the last-seen tx, and fires `SellerWatcher` on new payments — no
new node primitive needed. (`getTransactions(start, limit)` also exists but is
global, not address-scoped; use `getTransactionHistory`.)

## Notes

- Demos wallets have **serial nonce** semantics (testnet enforces nonces since
  2026-07): after a transfer, `createLiveDemLedger` waits for the payer nonce to
  advance before returning, so the following anchor doesn't self-resolve a stale
  nonce and get rejected. Same discipline as `src/live/run.ts#payDemSettle`.
- The x402 buyer dance (`createX402Rail().settle`) is the SDK's real EIP-3009
  flow; the seller half (paywall) is the one the SDK still lacks — reuse
  `roster/dacs/paywall.ts`'s shape against a real facilitator when you extend this.
