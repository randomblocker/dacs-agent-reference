/**
 * Negotiated Security-Audit Desk — runnable demo.
 *
 *   npx tsx roster/audit-negotiator/demo.ts            # deterministic policies
 *   NEGOTIATE_USE_LLM=1 npx tsx roster/audit-negotiator/demo.ts   # LLM policies (needs `claude` on PATH)
 *
 * Scans several targets, then negotiates each as buyer-vs-seller. Because the
 * seller's floor comes from the (private) scan and the buyer's budget is fixed,
 * different targets produce genuinely different outcomes — some close on the
 * deep tier, some get downgraded to quick, some walk. With the LLM on, the same
 * targets can close at different prices run to run: that variance IS the point —
 * it is real negotiation, not a formula.
 */
import { DEFAULT_ECONOMICS, type AuditTier, type Deadline } from "./terms.js";
import { deterministicBuyer, deterministicSeller, sellerGuardFor, type BuyerBrief, type SellerBrief } from "./policies.js";
import { llmBuyer, llmSeller } from "./llm-policy.js";
import { formatTranscript, runNegotiation, type NegotiationConfig } from "./negotiate.js";
import { fakeScan } from "./scan.js";

const OFFERED_TIERS: AuditTier[] = ["quick", "deep"];
const OFFERED_DEADLINES: Deadline[] = ["standard", "rush"];
const MAX_TURNS = 6; // DACS-3 RFQ-1 default

const useLlm = process.env.NEGOTIATE_USE_LLM === "1";

interface Scenario {
  repo: string;
  budget: number;
  acceptableTiers: AuditTier[];
  preferredTier: AuditTier;
  preferredDeadline: Deadline;
}

const SCENARIOS: Scenario[] = [
  // Generous budget on a deep-only goal → closes on the deep tier after haggling.
  { repo: "acme/payments-api", budget: 40, acceptableTiers: ["deep"], preferredTier: "deep", preferredDeadline: "standard" },
  // Tight budget, deep-only goal → no tier the seller can offer fits → walks.
  { repo: "acme/marketing-site", budget: 6, acceptableTiers: ["deep"], preferredTier: "deep", preferredDeadline: "standard" },
  // Rush deadline lifts the floor; a mid budget still closes deep/rush.
  { repo: "defi/vault-contracts", budget: 30, acceptableTiers: ["deep"], preferredTier: "deep", preferredDeadline: "rush" },
  // Budget can't reach the deep floor but the buyer accepts quick → downgraded deal.
  { repo: "tiny/cli-tool", budget: 12, acceptableTiers: ["quick", "deep"], preferredTier: "deep", preferredDeadline: "standard" },
];

async function main() {
  console.log(`\n=== Negotiated Security-Audit Desk — ${useLlm ? "LLM" : "deterministic"} policies ===\n`);

  let agreed = 0;
  let walked = 0;

  for (const s of SCENARIOS) {
    const scan = await fakeScan(s.repo);
    const sellerGuard = sellerGuardFor(scan, OFFERED_TIERS, OFFERED_DEADLINES, DEFAULT_ECONOMICS);
    const buyerGuard = {
      offeredTiers: OFFERED_TIERS,
      offeredDeadlines: OFFERED_DEADLINES,
      budget: s.budget,
      acceptableTiers: s.acceptableTiers,
    };

    const sellerBrief: SellerBrief = { scan, guard: sellerGuard, econ: DEFAULT_ECONOMICS };
    const buyerBrief: BuyerBrief = {
      guard: buyerGuard,
      preferredTier: s.preferredTier,
      preferredDeadline: s.preferredDeadline,
    };

    const seller = useLlm ? llmSeller(sellerBrief) : deterministicSeller(sellerBrief);
    const buyer = useLlm ? llmBuyer(buyerBrief) : deterministicBuyer(buyerBrief);

    const cfg: NegotiationConfig = { maxTurns: MAX_TURNS, sellerGuard, buyerGuard };

    console.log(`--- ${s.repo}  (budget ${s.budget} DEM, wants ${s.preferredTier}/${s.preferredDeadline}) ---`);
    console.log(
      `    scan(private): ${scan.kloc} KLOC, ${scan.fileCount} files, ${scan.numTools} tool(s)` +
        `${scan.hasSolidity ? " (Solidity)" : ""}; deep floor(std) = ${sellerGuard.floor("deep", "standard")} DEM`,
    );
    const result = await runNegotiation(seller, buyer, cfg);
    console.log(formatTranscript(result));
    console.log();
    if (result.outcome === "agreed") agreed++;
    else walked++;
  }

  console.log(`=== ${agreed} agreed, ${walked} walked across ${SCENARIOS.length} scenarios ===\n`);
}

main().catch((err) => {
  console.error("demo failed:", err);
  process.exit(1);
});
