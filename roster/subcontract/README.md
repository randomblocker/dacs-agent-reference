# Sub-contracting General Contractor (nested negotiation + revenue split)

A buyer wants a **compound deliverable** no single agent does best — e.g. a full
security review = general code audit + Solidity deep-dive + dependency advisory.
A **General Contractor (GC)** agent sources each part, assembles a cost floor
from what it actually agreed to pay, then sells the bundle. This composition —
an inner negotiation feeding an outer one — is something fixed-price agent
markets (x402, Olas) cannot express at all.

    npm run roster:subcontract

## The two-level negotiation

```
                 sources (GC is BUYER)              sells (GC is SELLER)
   specialist A  ◄── RFQ ──►  ┌──────────────┐  ◄── RFQ ──►  buyer
   specialist B  ◄── RFQ ──►  │  General     │
   specialist C  ◄── RFQ ──►  │  Contractor  │   margin = bundle price
                              └──────────────┘            − Σ sub-prices
```

1. **Source (inner RFQs).** The GC sub-negotiates each component against a
   specialist audit desk — the GC is the **buyer** there, haggling each down.
2. **Assemble the floor.** Only after sourcing does the GC know its true cost
   (Σ agreed sub-prices). That floor is the *outcome* of the inner negotiations —
   private information that compounds — so the GC's buyer-facing floor is honest.
3. **Sell (outer RFQ).** The GC negotiates the bundle with the buyer as the
   **seller**, floor = sourced cost × (1 + coordination margin).
4. **Split.** Margin = bundle price − Σ sub-prices, itemised in the plan.

## Built on the audit desk, unchanged

Every negotiation — inner and outer — runs on `audit-negotiator`'s existing
engine (`runNegotiation`, `deterministicSeller`/`deterministicBuyer`). Each
specialist is a real audit desk with its own private scan and floor; the GC is
just orchestration on top. `gc.ts` adds no new engine — only the bundle-seller
policy (a fixed-floor seller whose floor is the sourced cost) and the sourcing →
assemble → sell loop.

| File | Purpose |
|------|---------|
| `gc.ts` | `Specialist`/`SubcontractJob`/`SubcontractPlan` types, `gcBundleSeller` policy, and `runSubcontract` orchestration. |
| `demo.ts` | Runnable full-review scenario with the itemised revenue split. |
| `gc.test.ts` | 8 tests: sub-prices sit within `[specialist floor, GC allocation]`, margin ≥ 0 (GC never loses money), split identity, clean failure when the budget can't source or can't clear the assembled floor. |

## Invariants

- **The GC never loses money.** It sells only at or above its *sourced* floor, so
  `bundlePrice ≥ Σ sub-prices × (1 + coordMargin)` and margin ≥ 0.
- **Every sub is honestly priced.** Each agreed sub-price is at or above that
  specialist's private floor (the specialist's guard) and at or below the GC's
  sourcing allocation (the GC's guard).
- **Failure is clean, never a loss.** If a component can't be sourced →
  `no-source`; if the assembled floor exceeds the buyer's budget → `no-deal`.
  Neither claims a margin.

## Follow-ons

- LLM policies on both levels (the audit desk's `llmSeller`/`llmBuyer` already
  slot into the inner RFQs; an LLM bundle-seller is a small addition).
- Sell-then-source (bid the bundle first, then source under commitment — real GC
  risk-taking) as an alternative to today's source-then-sell.
- Wire onto L2PS transport + DACS settlement so each inner and outer negotiation
  is a signed channel with its own anchored agreement (same follow-on as the
  audit desk).
