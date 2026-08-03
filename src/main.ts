/**
 * "PR review for hire" — a little DACS agent ecosystem on the mock substrate.
 *
 * The service: ReviewBot sells LLM code review. Its DID is CCI-bound to a
 * GitHub identity; delivery is a review posted ON GitHub by that identity;
 * fulfilment is attested (DACS-X) and independently auditable.
 *
 * The arc is built to show the things that CANNOT be done without DACS (or a
 * reinvention of it):
 *   Scene 1 — full lifecycle: vet via CCI+GitHub, pay, review lands on the PR,
 *             delivery attested, seller countersigns; a third-party verifier
 *             audits a deal it never participated in.
 *   Scene 2 — impostor: claims a GitHub login it never CCI-proved. Vet fails
 *             BEFORE any payment (the money-safety branch).
 *   Scene 3 — the counterfactual: tamper the anchored evidence. A bare JSON
 *             receipt would shrug; the DACS bundle fails cryptographically.
 *   Scene 4 — portable reputation: a NEW buyer who has never met ReviewBot
 *             derives its track record from anchored bundles alone.
 */
import type { SessionTerms } from "@kynesyslabs/dacs";
import { CounterpartyError } from "@kynesyslabs/dacs";
import { CciDirectory, makeIdentity } from "./identity.js";
import { MemorySubstrate } from "./substrate/memory.js";
import { MockGitHub } from "./github.js";
import { BuyerAgent } from "./agents/buyer.js";
import { SellerAgent, REVIEWBOT_FEES, reviewBotUnitsFor, reviewBotPriceFor } from "./agents/seller.js";
import { countChangedLines, maybeReviewer } from "./agents/review-llm.js";
import { VerifierAgent } from "./agents/verifier.js";
import { displayToBase, formatFeeSchedule } from "../roster/dacs/wire/pricing.js";

const line = (s = "") => console.log(s);
const step = (n: string, msg: string) => console.log(`  ${n.padEnd(10)} ${msg}`);

async function main() {
  line("┌──────────────────────────────────────────────────────────────┐");
  line("│  DACS ecosystem — PR review for hire (mock substrate + GitHub) │");
  line("└──────────────────────────────────────────────────────────────┘");

  // ── The world: one substrate, one GitHub, one CCI directory ───────────────
  const substrate = new MemorySubstrate();
  const github = new MockGitHub();
  const cci = new CciDirectory();
  // GitHub sits behind the DAHR proxy: every check any agent makes against it
  // goes through an attested-fetch surface (the real-DAHR swap point).
  substrate.mount("https://api.github.com", (url) => github.apiFetch(url));

  // GitHub accounts + the buyer's repo with a PR that wants review.
  github.addUser({ login: "reviewbot-x", created_at: "2023-04-01T00:00:00Z", public_repos: 42 });
  github.addUser({ login: "acme-owner", created_at: "2021-01-15T00:00:00Z", public_repos: 7 });
  const reviewDiff = [
    "+ export async function settleWithRetry(req) {",
    "+   for (let i = 0; i < 5; i++) {",
    "+     const r = await settle(req);",
    "+     if (r.ok) return r;",
    "+     console.log('retrying', i);",
    "+   }",
    "+   // TODO: surface a typed error",
    "+   return { ok: false };",
    "+ }",
    "- export const settleOnce = settle;",
  ].join("\n");
  github.addPull("acme/payments", {
    number: 17,
    title: "Add settlement retry loop",
    diff: reviewDiff,
  });

  // ── The cast ───────────────────────────────────────────────────────────────
  const reviewBotId = makeIdentity("ReviewBot", 0x11);
  const impostorId = makeIdentity("Impostor", 0x22);
  const buyerId = makeIdentity("AcmeOwner", 0x33);

  // CCI: ReviewBot PROVED control of its GitHub account (Web2 identity proof).
  // The impostor proved nothing — it will merely *claim* a login it doesn't own.
  cci.bind(reviewBotId.did, "reviewbot-x");

  // Default review generator is the deterministic heuristic (fast, offline).
  // Set REVIEWBOT_USE_LLM=1 (with the `claude` CLI on PATH) to run the REAL
  // structured LLM review instead — it falls back to the heuristic on failure.
  const reviewer = maybeReviewer(process.env);
  const reviewBot = new SellerAgent(reviewBotId, substrate, github, "reviewbot-x", reviewer);
  const impostor = new SellerAgent(impostorId, substrate, github, "reviewbot-x" /* claimed, never proven */);
  const buyer = new BuyerAgent(buyerId, substrate, cci);
  const verifier = new VerifierAgent(substrate, cci);

  // Usage-based pricing: the review is sized by the PR's diff, so a big review
  // costs proportionally more than a tiny one. `terms.price` is the computed
  // total for THIS PR's diff (per 100 diff lines, with a 1-unit floor).
  const reviewUnits = reviewBotUnitsFor(reviewDiff);
  const reviewPrice = reviewBotPriceFor(reviewDiff); // display units
  const terms: SessionTerms = {
    price: { amount: displayToBase(reviewPrice, "USDC"), asset: "USDC", decimals: 6, rail: "pay-x402" },
    deliveryPhase: "deliver-github-pr-review",
    deliveryFormat: "text/markdown",
  };

  // ══ Scene 1 — the real deal: full lifecycle, review lands on the PR ═══════
  line("\n━━ Scene 1: ReviewBot reviews acme/payments#17 (full lifecycle) ━━");
  const listingRef = await reviewBot.publishListing({
    serviceId: "pr-review",
    name: "LLM code review, on your PR, from a verified GitHub identity",
    description: "Pay per review; delivered as a GitHub PR review.",
    githubLogin: "reviewbot-x",
    fees: REVIEWBOT_FEES,
    feeAsset: "USDC",
  });
  step("DACS-1", `ReviewBot published listing → ${listingRef}`);
  step("pricing", `usage-based ${formatFeeSchedule(REVIEWBOT_FEES, "USDC")}`);
  step(
    "quote",
    `PR #17 diff = ${countChangedLines(reviewDiff)} changed lines → ${reviewUnits} unit(s) x 0.5 = ${reviewPrice} USDC ` +
      `(a 350-changed-line PR would bill ${reviewBotPriceFor("+x\n".repeat(350))} USDC; ` +
      `350 lines of unchanged context bill just ${reviewBotPriceFor("  x\n".repeat(350))})`,
  );

  const found = await buyer.discover([listingRef]);
  step("discover", `buyer found ${found.length} listing(s): "${found[0]?.listing.name}"`);

  const result = await buyer.buy(listingRef, terms, {
    jobId: "job-review-17",
    claimedGithubLogin: "reviewbot-x",
    repo: "acme/payments",
    pullNumber: 17,
    // "payment lands → the seller's watcher does the work"
    awaitDelivery: async () => {
      await reviewBot.deliverReview("job-review-17", { repo: "acme/payments", pullNumber: 17 });
    },
  });
  step("DACS-2", "vet passed → CCI binding matches the claimed login; GitHub profile attested");
  step("DACS-3", `agreement anchored → ${result.agreementRef}`);
  step("DACS-4", `paid + delivery confirmed on GitHub → evidence ${result.settlementRef}`);
  step("DACS-5", `buyer bundle anchored → ${result.bundleRef} (outcome: ${result.outcome})`);

  const reviews = github.listReviews("acme/payments", 17);
  step("github", `PR #17 now has ${reviews.length} review by @${reviews[0]?.user.login}:`);
  for (const l of (reviews[0]?.body ?? "").split("\n")) line(`             │ ${l}`);

  const sellerBundleRef = await reviewBot.fulfil(result.jobId, buyer.did);
  step("fulfil", `seller countersigned the deal → ${sellerBundleRef}`);

  // The third party audits a deal it never participated in — from artifacts alone.
  const v = await verifier.verify(result.bundleRef);
  step("verify", `bundle: ok=${v.ok} fullyVerified=${v.fullyVerified}`);
  step("refs", `referenced-artifact integrity: ${v.refs.map((r) => `${r.kind}=${r.verdict}`).join(", ")}`);
  const dv = await verifier.verifyDelivery(result.jobId, reviewBot.did);
  step("delivery", `DACS-X attestation: ok=${dv.ok} (review #${dv.attestation?.reviewId} by @${dv.attestation?.ghAuthor}, state hash matches)`);
  const rec = await verifier.reconcile(result.bundleRef, sellerBundleRef);
  step("reconcile", `two-sided (§10.4.3): reconciled=${rec.reconciled}${rec.reason ? ` (${rec.reason})` : ""}`);

  // ══ Scene 2 — the impostor: claims a login it never proved ════════════════
  line("\n━━ Scene 2: an impostor claims @reviewbot-x (must abort before pay) ━━");
  const impostorListing = await impostor.publishListing({
    serviceId: "pr-review-cheap",
    name: "Same reviews, half price!",
    description: "Trust me.",
    githubLogin: "reviewbot-x", // claimed — but CCI has no proof for this DID
  });
  step("DACS-1", `impostor published listing → ${impostorListing}`);
  try {
    await buyer.buy(impostorListing, terms, {
      jobId: "job-impostor",
      claimedGithubLogin: "reviewbot-x",
      repo: "acme/payments",
      pullNumber: 17,
      awaitDelivery: async () => {},
    });
    step("DACS-2", "❌ UNEXPECTED: session did not abort");
  } catch (e) {
    const kind = e instanceof CounterpartyError ? "CounterpartyError" : (e as Error).constructor.name;
    step("DACS-2", `vet FAILED (DID not CCI-bound to the claimed login) → aborted as ${kind} ✓`);
    const paid = await substrate.read("stor:dacs4:evidence:job-impostor");
    step("safety", `no settlement evidence anchored: ${paid === null ? "confirmed — not a cent moved ✓" : "LEAK ✗"}`);
  }

  // ══ Scene 3 — the counterfactual: tamper with the anchored evidence ═══════
  line("\n━━ Scene 3: tamper the evidence (what a bare receipt can't catch) ━━");
  const bundleAddr = result.bundleRef;
  const original = { ...(await substrate.read(bundleAddr))! };
  const tampered = { ...original, outcome: "failed" };
  substrate.store.set(bundleAddr, tampered);
  const vt = await verifier.verify(bundleAddr);
  step("tamper", `flipped bundle outcome to "failed" in storage`);
  step("verify", `verifier: ok=${vt.ok} → "${vt.reason}" ✓ (caught cryptographically)`);
  substrate.store.set(bundleAddr, original);

  const attAddr = await substrate.anchorAddress("dacsx:delivery:job-review-17");
  const attOriginal = { ...(await substrate.read(attAddr))! };
  substrate.store.set(attAddr, { ...attOriginal, reviewId: 31337 });
  const dvt = await verifier.verifyDelivery("job-review-17", reviewBot.did);
  step("tamper", `pointed the delivery attestation at a different review id`);
  step("delivery", `verifier: ok=${dvt.ok} → "${dvt.reason}" ✓`);
  substrate.store.set(attAddr, attOriginal);
  line(`             (a plain JSON receipt has no signed scope, no content-addressed refs,`);
  line(`              no third-party check — both forgeries would have passed unnoticed)`);

  // ══ Scene 4 — portable reputation: a stranger checks the track record ═════
  line("\n━━ Scene 4: a NEW buyer derives ReviewBot's reputation from artifacts alone ━━");
  const rep = await verifier.reputation(reviewBot.did, [result.bundleRef, sellerBundleRef]);
  step("DACS-5", `ReviewBot: ${rep.completed}/${rep.totalAgreements} completed (avgRating: ${rep.avgRating})`);
  line(`             (no platform, no account, no API key — the bundles ARE the reputation,`);
  line(`              verifiable offline and portable to any marketplace)`);

  line("\n✅ ecosystem run complete — vet → pay → deliver-on-GitHub → attest → audit, closed loop.\n");
}

main().catch((e) => {
  console.error("\n❌ ecosystem run failed:", e);
  process.exit(1);
});
