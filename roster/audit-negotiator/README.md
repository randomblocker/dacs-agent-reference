# Negotiated Security-Audit Desk

An autonomous seller agent that provides real value (security audits) but where
the **deal genuinely requires negotiation** — because the seller's cost varies
per job and is private, and the terms are multi-dimensional (price × tier ×
deadline). This is the first flow in the ecosystem to exercise DACS-3's RFQ
pattern with actual back-and-forth rather than fixed-price accept.

## Why this needs negotiation (and most services don't)

The live agent-commerce economy today (x402 Bazaar, Olas Mech Marketplace) is
almost entirely **fixed posted-price micropayments** — a weather API can't
haggle. Negotiation only earns its place when cost is job-specific and legible:

- The seller **pre-scans** the target (KLOC, whether Solidity ⇒ how many real
  tools apply). That scan is the seller's **private information**; the buyer sees
  only the public rate formula.
- The seller's floor is a real function of the scan
  (`floorFor` → `deepAuditPriceFor`, the same number the delivered artifact
  bills), so the seller quotes from true cost while the buyer can only probe by
  negotiating.
- Terms are **multi-dimensional**: `tier` (quick static scan vs deep sandboxed
  Semgrep/Slither + LLM review) × `deadline` (standard vs rush) × `price`. A
  policy can trade one for another ("can't do rush at that price, but standard
  yes, or rush for +N DEM").

## What's here

| File | Purpose |
|------|---------|
| `terms.ts` | Deal dimensions, the honest cost model (reuses `deepAuditPriceFor`), and the deterministic **guard** (seller never below floor, buyer never above budget). |
| `policies.ts` | Deterministic seller + buyer policies. Correct, terminating, offline. The seller extrapolates the buyer's concession trajectory to choose hold-deep vs downgrade-to-quick on the final turn. |
| `llm-policy.ts` | LLM-driven policies via `claude -p` (same defensive-parse pattern as `evalbot/llm-judge.ts`). Falls back to the deterministic policy on any failure or out-of-guard move. |
| `negotiate.ts` | The RFQ harness: alternating turns, `maxTurns` cap (DACS-3 RFQ-1), guard enforced on every move, acceptance bound to the counterparty's on-table terms. |
| `scan.ts` | Pre-scan ports: deterministic fake (offline) + real local-directory scanner. |
| `demo.ts` | Runnable: `npm run roster:negotiate` (deterministic) or `NEGOTIATE_USE_LLM=1 npm run roster:negotiate` (live LLM). |
| `negotiate.test.ts` | 16 tests: cost model, agreement/walk/downgrade, guard-unbreachable (rogue policies), LLM parse + fallback, termination. |

## The guard is the safety net

Every move a policy emits — deterministic or LLM — is validated against that
side's guard before it reaches the counterparty. An LLM adds *strategy* (tone,
concession pacing, dimension trades, reading the counterparty's arguments) but
**can never settle out of bounds**: a hallucinated below-floor offer is rejected
and the turn falls back deterministically. This is the SafeAgent principle — the
LLM proposes, a deterministic gate disposes.

## Status

**Built and verified (this phase):** the negotiation core. Deterministic path:
523/523 roster tests green. Live path: verified end-to-end against the real
`claude` CLI — a 5-turn LLM-vs-LLM negotiation that traded rush→standard and
closed at a price distinct from the deterministic outcome, guard intact.

**Follow-on phases:**
1. **L2PS transport** — run buyer and seller as two processes exchanging signed
   `ChannelMessage`s over `l2ps.channel.ChannelSession` (legacy signaling server
   on `demosnode.discus.sh:3005` works today; the true L2PS messaging server on
   3006 is opt-in node config). The `Turn[]` transcript here is exactly what the
   channel carries.
2. **DACS settlement** — feed the agreed `AuditTerms` into the existing
   `sec-audit`/`sec-audit-deep` delivery + dual-rail settlement
   (pay-dem / x402, buyer's choice), with the negotiated price as the agreement
   price and `derivedFromChannel.lastMessageHash` binding the transcript.
3. **VPS deployment** — own systemd user next to clawdbot, own wallet, 24/7
   seller registered on the channel (outbound WS ⇒ no inbound ports).
