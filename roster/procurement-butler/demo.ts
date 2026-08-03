/**
 * Procurement Butler demo — narrated end-to-end run against the stub
 * marketplace. Zero credentials, fully deterministic.
 *
 *   npm run roster:butler
 *
 * Goal: "summarize this repository's architecture", budget $5.
 * Expected story: the top-scoring provider (Premium Insights) won't come
 * down to budget -> butler walks; runner-up (Repo Cartographer) negotiates
 * down from $4.80 -> award; then the deliverable acceptance hooks fire.
 */
import { createHash } from "node:crypto";
import { ProcurementButler, DEFAULT_CONFIG } from "./butler.js";
import { MarketplaceStub } from "./marketplace-stub.js";
import type { Deliverable, ProcurementGoal } from "./types.js";

const usd = (n: number) => `$${n.toFixed(2)}`;
const hr = (title: string) => console.log(`\n=== ${title} ${"=".repeat(Math.max(0, 60 - title.length))}`);

const goal: ProcurementGoal = {
  description: "summarize this repository's architecture",
  requiredCapabilities: ["code-analysis", "summarization"],
  estimatedUnits: 4, // ~4 modules, for per-unit fee schedules
};
const budget = 5;

const market = new MarketplaceStub();
const butler = new ProcurementButler(market, market, DEFAULT_CONFIG);

const decision = await butler.procure(goal, budget);

hr("Procurement Butler");
console.log(`Goal:   "${goal.description}"`);
console.log(`Needs:  [${goal.requiredCapabilities.join(", ")}]`);
console.log(`Budget: ${usd(budget)}   Rail preference: ${DEFAULT_CONFIG.railPreference.join(" > ")}`);

hr("Candidates considered");
for (const c of decision.candidates) {
  const head = `${c.provider.padEnd(18)} ask ${usd(c.askPrice).padStart(7)}`;
  if (c.excluded) {
    console.log(`  x ${head}  EXCLUDED — ${c.excluded}`);
  } else {
    const s = c.scores!;
    console.log(
      `  + ${head}  rail ${c.chosenRail}  ` +
        `score ${s.total.toFixed(3)} (price ${s.price.toFixed(2)} / rail ${s.rail.toFixed(2)} / quality ${s.quality.toFixed(2)})`,
    );
  }
}

hr("Negotiations (in attempt order)");
for (const n of decision.negotiations) {
  console.log(`  ${n.listingId} — ask ${usd(n.ask)}, buyer reservation ${usd(n.reservation)}`);
  for (const r of n.rounds) {
    const price = r.price !== undefined ? ` ${usd(r.price)}` : "";
    console.log(`    round ${r.round}  ${r.actor.padEnd(6)} ${r.action.toUpperCase()}${price}`);
  }
  console.log(
    n.result === "agreed"
      ? `    -> AGREED at ${usd(n.agreedPrice!)} (${usd(n.ask - n.agreedPrice!)} below ask)`
      : `    -> WALKED (seller never met the ${usd(n.reservation)} reservation)`,
  );
}

hr("Decision");
if (decision.outcome === "awarded" && decision.winner) {
  const w = decision.winner;
  console.log(`  AWARDED to ${w.provider} (${w.listingId})`);
  console.log(`  Price: ${usd(w.price)}${w.negotiated ? " (negotiated)" : " (list price)"}   Rail: ${w.rail}`);
  console.log(`  Under budget by ${usd(budget - w.price)}`);
} else {
  console.log("  NO AWARD — no candidate concluded within budget");
}

// ---------------------------------------------------------------------------
// Acceptance hooks — the three outcomes, mechanically
// ---------------------------------------------------------------------------

hr("Deliverable acceptance");
if (decision.winner) {
  const good: Deliverable = {
    content:
      "## Architecture\n\n" +
      "This repository is a ports-and-adapters agent ecosystem. `src/ports.ts` defines the " +
      "substrate/GitHub/CCI seams; `src/agents/*` hold pure agent cores (buyer, seller, verifier) " +
      "that are injected with either mock adapters (in-memory substrate, fake GitHub) or live " +
      "adapters (testnet substrate, real GitHub). `roster/` hosts standalone agent cores built " +
      "the same way. The demo entrypoints wire everything in-process so runs need no credentials.",
  };
  const tampered: Deliverable = { content: "lgtm." };

  const r1 = butler.acceptDeliverable(good, decision.winner);
  console.log(`  good deliverable      -> ${r1.verdict}` + ("checksRun" in r1 ? ` (checks: ${r1.checksRun.join(", ")})` : ""));

  const r2 = butler.acceptDeliverable(tampered, decision.winner);
  console.log(`  tampered deliverable  -> ${r2.verdict}` + (r2.verdict === "reject" ? ` — ${r2.reason}` : ""));

  // A listing with no mechanical checks defers to an evaluator.
  const subjective = { ...decision.winner, listingId: "lst-digest-bot", acceptance: undefined };
  const r3 = butler.acceptDeliverable(good, subjective);
  console.log(`  no checks declared    -> ${r3.verdict}` + (r3.verdict === "needs-evaluator" ? ` — ${r3.reason}` : ""));

  // sha256 example: pin the exact bytes you expect.
  const pinned = {
    ...decision.winner,
    acceptance: { checks: [{ kind: "sha256" as const, expected: createHash("sha256").update(good.content, "utf8").digest("hex") }] },
  };
  const r4 = butler.acceptDeliverable(good, pinned);
  console.log(`  pinned sha256 match   -> ${r4.verdict}`);
}

hr("Done");
console.log(`  outcome=${decision.outcome}  candidates=${decision.candidates.length}  negotiations=${decision.negotiations.length}`);
