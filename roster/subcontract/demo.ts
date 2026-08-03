/**
 * Sub-contracting General Contractor — runnable demo.
 *
 *   npx tsx roster/subcontract/demo.ts
 *
 * A buyer wants a full security review of a DeFi protocol. No single desk does
 * every part best, so a General Contractor sources three specialists — a general
 * code auditor, a Solidity deep-dive, and a dependency advisory — each via its
 * own RFQ (the GC is the buyer there), assembles its cost floor from what it
 * actually agreed to pay, then negotiates the bundle with the buyer (the GC is
 * the seller there). The plan shows every nested negotiation and the revenue
 * split. This composition — sub-negotiation feeding an outer negotiation — is
 * something the fixed-price agent markets (x402, Olas) cannot express at all.
 */
import { DEFAULT_ECONOMICS, roundCents, type DeskEconomics } from "../audit-negotiator/terms.js";
import { formatTranscript } from "../audit-negotiator/negotiate.js";
import { fakeScan } from "../audit-negotiator/scan.js";
import { runSubcontract, type Specialist, type SubcontractJob } from "./gc.js";

// Specialty economics: the Solidity deep-dive is pricier per unit of work.
const SOLIDITY_ECON: DeskEconomics = { ...DEFAULT_ECONOMICS, minMarginPct: 0.2, listMarginPct: 0.7 };

async function buildJob(): Promise<SubcontractJob> {
  const specialists: Specialist[] = [
    {
      id: "code-audit",
      label: "General code audit",
      scan: await fakeScan("defi/protocol#app"),
      econ: DEFAULT_ECONOMICS,
      requiredTier: "deep",
    },
    {
      id: "solidity-deepdive",
      label: "Solidity specialist deep-dive",
      scan: { ...(await fakeScan("defi/protocol#contracts")), hasSolidity: true, numTools: 2 },
      econ: SOLIDITY_ECON,
      requiredTier: "deep",
    },
    {
      id: "deps-advisory",
      label: "Dependency / supply-chain advisory",
      scan: await fakeScan("defi/protocol#deps"),
      econ: DEFAULT_ECONOMICS,
      requiredTier: "quick",
    },
  ];
  return { buyerBudget: 90, deadline: "standard", specialists, coordMarginPct: 0.2, sourcingFraction: 0.75 };
}

async function main() {
  console.log(`\n=== Sub-contracting General Contractor — full security review ===\n`);
  const job = await buildJob();
  console.log(`Buyer wants: full review of defi/protocol by ${job.deadline}, budget ${job.buyerBudget} DEM`);
  console.log(`GC will source ${job.specialists.length} specialists, then sell the bundle.\n`);

  const plan = await runSubcontract(job);

  console.log("--- INNER: sourcing the specialists (GC is the buyer) ---\n");
  for (const sub of plan.subs) {
    console.log(`[${sub.label}]  (GC sourcing budget: ${sub.allocation} DEM)`);
    console.log(formatTranscript(sub.negotiation));
    console.log();
  }

  if (plan.bundleNegotiation) {
    console.log("--- OUTER: selling the assembled bundle (GC is the seller) ---\n");
    console.log(`GC sourced cost = ${plan.bundleCost} DEM; bundle floor = ${plan.bundleFloor} DEM (cost + coordination margin)`);
    console.log(formatTranscript(plan.bundleNegotiation));
    console.log();
  }

  console.log("--- PLAN ---");
  console.log(`outcome: ${plan.outcome.toUpperCase()} — ${plan.reason}`);
  if (plan.outcome === "awarded") {
    console.log(`\n  buyer pays:        ${plan.bundlePrice} DEM`);
    for (const sub of plan.subs) console.log(`  → ${sub.label.padEnd(34)} ${sub.price} DEM`);
    console.log(`  ${"".padEnd(36)} ${"—".padEnd(8)}`);
    console.log(`  specialists total: ${plan.bundleCost} DEM`);
    console.log(`  GC margin:         ${plan.gcMargin} DEM  (${roundCents((plan.gcMargin! / plan.bundlePrice!) * 100)}% of bundle)`);
  }
  console.log();
}

main().catch((err) => {
  console.error("demo failed:", err);
  process.exit(1);
});
