/**
 * ReviewBot tests — fully offline (no network, no LLM). node:test, run:
 *   npx tsx --test src/agents/reviewbot.test.ts
 *
 * Covers the quality-pass surfaces: real-vs-fallback review selection,
 * structured-review parse + render, changed-line pricing (context-heavy diffs
 * must not over-bill), delivery idempotency + fallback, and every
 * tampered/missing binding the verifier must reject.
 */
import { describe, test } from "node:test";
import assert from "node:assert/strict";

import { buildSignedArtifact } from "@kynesyslabs/dacs";

import { CciDirectory, makeIdentity } from "../identity.js";
import { MemorySubstrate } from "../substrate/memory.js";
import { MockGitHub } from "../github.js";
import { SellerAgent, DELIVERY_ATTESTATION_SEPARATOR, reviewBotUnitsFor, reviewBotPriceFor, type DeliveryAttestation } from "./seller.js";
import { VerifierAgent } from "./verifier.js";
import {
  buildReviewPrompt,
  changedLineSplit,
  countChangedLines,
  heuristicReview,
  makeReviewer,
  parseReviewOutput,
  renderReviewMarkdown,
  type ReviewLlmFn,
  type StructuredReview,
} from "./review-llm.js";

// ---------------------------------------------------------------------------
// World harness — one substrate, one GitHub, seller + verifier
// ---------------------------------------------------------------------------

const REPO = "acme/payments";
const PR = 17;

/** A diff with a 2-line change buried in lots of unchanged context + headers. */
function contextHeavyDiff(context = 300): string {
  const lines = ["diff --git a/x.js b/x.js", "--- a/x.js", "+++ b/x.js", "@@ -1,300 +1,300 @@"];
  for (let i = 0; i < context; i++) lines.push(`   const stays${i} = ${i};`); // context (leading space)
  lines.push("-const old = 1;", "+const neww = 2;");
  return lines.join("\n");
}

function makeWorld(opts: { sellerLogin?: string; bindSellerTo?: string | null; generateReviewFn?: (t: string, d: string) => string | Promise<string> } = {}) {
  const sellerLogin = opts.sellerLogin ?? "reviewbot-x";
  const substrate = new MemorySubstrate();
  const github = new MockGitHub();
  const cci = new CciDirectory();
  substrate.mount("https://api.github.com", (url) => github.apiFetch(url));

  github.addUser({ login: sellerLogin, created_at: "2023-01-01T00:00:00Z", public_repos: 10 });
  github.addUser({ login: "eve", created_at: "2024-01-01T00:00:00Z", public_repos: 1 });
  github.addPull(REPO, { number: PR, title: "Add settlement retry loop", diff: "+ const a = 1;\n- const b = 2;" });

  const sellerId = makeIdentity("ReviewBot", 0x11);
  // Default binding: seller DID proved control of its login (unless overridden).
  const bound = opts.bindSellerTo === undefined ? sellerLogin : opts.bindSellerTo;
  if (bound !== null) cci.bind(sellerId.did, bound);

  const seller = new SellerAgent(sellerId, substrate, github, sellerLogin, opts.generateReviewFn);
  const verifier = new VerifierAgent(substrate, cci);
  return { substrate, github, cci, sellerId, seller, verifier };
}

// ---------------------------------------------------------------------------
// Changed-line accounting + pricing (fairness)
// ---------------------------------------------------------------------------

describe("countChangedLines / pricing", () => {
  test("counts +/- body lines, excludes +++/---/@@/context", () => {
    const diff = [
      "diff --git a/x b/x",
      "--- a/x",
      "+++ b/x",
      "@@ -1,2 +1,3 @@",
      " context line",
      "+added one",
      "+added two",
      "-removed one",
      "\\ No newline at end of file",
    ].join("\n");
    assert.equal(countChangedLines(diff), 3); // 2 added + 1 removed; headers/context excluded
    assert.deepEqual(changedLineSplit(diff), { added: 2, removed: 1 });
  });

  test("empty diff → 0 changed lines", () => {
    assert.equal(countChangedLines(""), 0);
  });

  test("context-heavy diff is NOT over-billed (bills the floor, not the context)", () => {
    const heavy = contextHeavyDiff(300); // 2 changed lines among 300 context lines
    assert.equal(countChangedLines(heavy), 2);
    assert.equal(reviewBotUnitsFor(heavy), 1); // ceil(2/100)
    assert.equal(reviewBotPriceFor(heavy), 1); // floored to the 1-unit minimum
    // A total-line counter would have billed ~3 units for the same 2-line review.
  });

  test("changed lines scale linearly; floor covers tiny diffs", () => {
    assert.equal(reviewBotUnitsFor("+x\n".repeat(350)), 4); // ceil(350/100)
    assert.equal(reviewBotPriceFor("+x\n".repeat(350)), 2); // 0.5 * 4
    assert.equal(reviewBotPriceFor("+x\n"), 1); // 1 changed line → floor 1
  });
});

// ---------------------------------------------------------------------------
// Structured review: parse + render
// ---------------------------------------------------------------------------

const CANNED: StructuredReview = {
  verdict: "request-changes",
  summary: "Retry loop swallows errors.",
  findings: [
    { severity: "nit", location: "settle.js:5", issue: "console.log left in", suggestion: "remove it" },
    { severity: "blocker", location: "settle.js:7", issue: "no typed error surfaced", suggestion: "throw a typed error" },
  ],
};

describe("parseReviewOutput", () => {
  test("parses a clean JSON object", () => {
    const r = parseReviewOutput(JSON.stringify(CANNED));
    assert.ok(r);
    assert.equal(r.verdict, "request-changes");
    assert.equal(r.findings.length, 2);
  });

  test("tolerates prose + markdown fences around the JSON", () => {
    const raw = "Here you go:\n```json\n" + JSON.stringify(CANNED) + "\n```\nThanks!";
    const r = parseReviewOutput(raw);
    assert.ok(r);
    assert.equal(r.findings.length, 2);
  });

  test("drops malformed findings and defaults bad severities", () => {
    const raw = JSON.stringify({
      verdict: "comment",
      summary: "ok",
      findings: [{ severity: "explosive", issue: "weird" }, { issue: "" }, { severity: "nit", issue: "real" }],
    });
    const r = parseReviewOutput(raw);
    assert.ok(r);
    assert.equal(r.findings.length, 2); // empty-issue one dropped
    assert.equal(r.findings[0]!.severity, "warning"); // "explosive" → default
  });

  test("returns undefined on garbage / missing required fields", () => {
    assert.equal(parseReviewOutput("not json at all"), undefined);
    assert.equal(parseReviewOutput(JSON.stringify({ verdict: "approve" })), undefined); // no summary
    assert.equal(parseReviewOutput(JSON.stringify({ summary: "x", verdict: "nope" })), undefined); // bad verdict
  });
});

describe("renderReviewMarkdown", () => {
  test("renders verdict, sorted severities, and suggestions", () => {
    const md = renderReviewMarkdown("Add retry loop", CANNED);
    assert.match(md, /Verdict: Request changes/);
    assert.match(md, /Retry loop swallows errors\./);
    // blocker sorts before nit
    assert.ok(md.indexOf("[BLOCKER]") < md.indexOf("[NIT]"));
    assert.match(md, /LLM-generated/);
    assert.match(md, /_Suggestion:_ throw a typed error/);
  });

  test("clean review renders a no-issues line", () => {
    const md = renderReviewMarkdown("T", { verdict: "approve", summary: "LGTM", findings: [] });
    assert.match(md, /No blocking issues found/);
  });
});

// ---------------------------------------------------------------------------
// makeReviewer: real → fallback selection (never throws)
// ---------------------------------------------------------------------------

describe("makeReviewer real-vs-fallback", () => {
  const diff = "+ const a = 1;\n- const b = 2;";

  test("valid LLM JSON → structured markdown", async () => {
    const llm: ReviewLlmFn = async () => JSON.stringify(CANNED);
    const md = await makeReviewer({ llm })("T", diff);
    assert.match(md, /LLM-generated/);
    assert.match(md, /\[BLOCKER\]/);
  });

  test("LLM returns undefined (CLI absent) → heuristic fallback", async () => {
    const md = await makeReviewer({ llm: async () => undefined })("T", diff);
    assert.match(md, /heuristic fallback/);
  });

  test("LLM throws → heuristic fallback (never propagates)", async () => {
    const md = await makeReviewer({
      llm: async () => {
        throw new Error("boom");
      },
    })("T", diff);
    assert.match(md, /heuristic fallback/);
  });

  test("LLM returns garbage → heuristic fallback", async () => {
    const md = await makeReviewer({ llm: async () => "sorry I can't help" })("T", diff);
    assert.match(md, /heuristic fallback/);
  });

  test("prompt carries title + diff as data (untrusted)", () => {
    const p = buildReviewPrompt("My PR", "+evil();");
    assert.match(p, /=== PR TITLE ===/);
    assert.match(p, /=== PR DIFF ===/);
    assert.match(p, /UNTRUSTED/);
  });
});

// ---------------------------------------------------------------------------
// deliverReview: happy path, idempotency, fallback, missing PR
// ---------------------------------------------------------------------------

describe("deliverReview", () => {
  test("posts a review + anchors a verifiable delivery attestation", async () => {
    const { seller, verifier, github, sellerId } = makeWorld();
    const { attestationRef, reused } = await seller.deliverReview("job-1", { repo: REPO, pullNumber: PR });
    assert.ok(attestationRef);
    assert.equal(reused, false);
    assert.equal(github.listReviews(REPO, PR).length, 1);
    const dv = await verifier.verifyDelivery("job-1", sellerId.did);
    assert.equal(dv.ok, true);
  });

  test("is idempotent per jobId — a retry does not double-post or re-anchor", async () => {
    const { seller, github } = makeWorld();
    const first = await seller.deliverReview("job-1", { repo: REPO, pullNumber: PR });
    const second = await seller.deliverReview("job-1", { repo: REPO, pullNumber: PR });
    assert.equal(second.reused, true);
    assert.equal(second.attestationRef, first.attestationRef);
    assert.equal(github.listReviews(REPO, PR).length, 1); // still ONE review
  });

  test("a review generator that throws still delivers (falls back to heuristic)", async () => {
    const { seller, github } = makeWorld({
      generateReviewFn: () => {
        throw new Error("prompt-injected diff exploded the generator");
      },
    });
    const { reviewBody } = await seller.deliverReview("job-1", { repo: REPO, pullNumber: PR });
    assert.match(reviewBody, /heuristic fallback/);
    assert.equal(github.listReviews(REPO, PR).length, 1);
  });

  test("missing PR throws loudly", async () => {
    const { seller } = makeWorld();
    await assert.rejects(() => seller.deliverReview("job-1", { repo: REPO, pullNumber: 999 }), /no PR/);
  });
});

// ---------------------------------------------------------------------------
// verifyDelivery: rejects every tampered / missing binding (no fail-open)
// ---------------------------------------------------------------------------

describe("verifyDelivery rejects tampered/missing bindings", () => {
  test("no attestation anchored → ok:false", async () => {
    const { verifier, sellerId } = makeWorld();
    const dv = await verifier.verifyDelivery("nope", sellerId.did);
    assert.equal(dv.ok, false);
    assert.match(dv.reason!, /no delivery attestation/);
  });

  test("tampered attestation body → signature invalid", async () => {
    const { seller, verifier, substrate, sellerId } = makeWorld();
    await seller.deliverReview("job-1", { repo: REPO, pullNumber: PR });
    const addr = await substrate.anchorAddress("dacsx:delivery:job-1");
    const stored = substrate.store.get(addr)!;
    substrate.store.set(addr, { ...stored, reviewId: 31337 }); // flip a field, sig no longer matches
    const dv = await verifier.verifyDelivery("job-1", sellerId.did);
    assert.equal(dv.ok, false);
    assert.match(dv.reason!, /signature invalid/);
  });

  test("attestation jobId not matching the requested job → rejected", async () => {
    const { seller, verifier, substrate, sellerId } = makeWorld();
    await seller.deliverReview("job-A", { repo: REPO, pullNumber: PR });
    // Copy the validly-signed job-A attestation to the job-B address.
    const addrA = await substrate.anchorAddress("dacsx:delivery:job-A");
    const addrB = await substrate.anchorAddress("dacsx:delivery:job-B");
    substrate.store.set(addrB, substrate.store.get(addrA)!);
    const dv = await verifier.verifyDelivery("job-B", sellerId.did);
    assert.equal(dv.ok, false);
    assert.match(dv.reason!, /jobId .* does not match/);
  });

  test("attested author not CCI-bound to the seller → rejected", async () => {
    // Verifier's CCI binds the seller DID to a DIFFERENT login than it posted as.
    const { seller, verifier, sellerId } = makeWorld({ bindSellerTo: "eve" });
    await seller.deliverReview("job-1", { repo: REPO, pullNumber: PR });
    const dv = await verifier.verifyDelivery("job-1", sellerId.did);
    assert.equal(dv.ok, false);
    assert.match(dv.reason!, /not CCI-bound/);
  });

  test("seller key unresolvable → rejected", async () => {
    const { seller, verifier } = makeWorld();
    await seller.deliverReview("job-1", { repo: REPO, pullNumber: PR });
    const dv = await verifier.verifyDelivery("job-1", "did:demos:agent:not-a-key");
    assert.equal(dv.ok, false);
    assert.match(dv.reason!, /key unresolvable|no delivery attestation/);
  });

  test("attested review not on GitHub → rejected (validly signed, bogus reviewId)", async () => {
    const { seller, verifier, substrate, sellerId } = makeWorld();
    const att: DeliveryAttestation = {
      kind: "dacs-x-delivery-attestation",
      jobId: "job-1",
      repo: REPO,
      pullNumber: PR,
      reviewId: 999999, // never posted
      ghAuthor: "reviewbot-x",
      ghStateHash: "deadbeef",
      deliveredAt: new Date().toISOString(),
    };
    const signed = await buildSignedArtifact(att, DELIVERY_ATTESTATION_SEPARATOR as never, sellerId.sign);
    await substrate.anchor("dacsx:delivery:job-1", signed);
    void seller; // (seller unused here — we anchored a hand-signed attestation)
    const dv = await verifier.verifyDelivery("job-1", sellerId.did);
    assert.equal(dv.ok, false);
    assert.match(dv.reason!, /not found on GitHub/);
  });

  test("GitHub state diverged since delivery → rejected", async () => {
    const { seller, verifier, github, sellerId } = makeWorld();
    await seller.deliverReview("job-1", { repo: REPO, pullNumber: PR });
    // A later review changes the reviews-endpoint state → attested hash diverges.
    github.postReview("eve", REPO, PR, "drive-by comment");
    const dv = await verifier.verifyDelivery("job-1", sellerId.did);
    assert.equal(dv.ok, false);
    assert.match(dv.reason!, /state hash diverged/);
  });

  test("missing PR at verify time → clean ok:false, does not throw", async () => {
    // Hand-sign an attestation pointing at a non-existent PR (404 body isn't an array).
    const { verifier, substrate, sellerId } = makeWorld();
    const att: DeliveryAttestation = {
      kind: "dacs-x-delivery-attestation",
      jobId: "job-1",
      repo: REPO,
      pullNumber: 4040,
      reviewId: 1,
      ghAuthor: "reviewbot-x",
      ghStateHash: "deadbeef",
      deliveredAt: new Date().toISOString(),
    };
    const signed = await buildSignedArtifact(att, DELIVERY_ATTESTATION_SEPARATOR as never, sellerId.sign);
    await substrate.anchor("dacsx:delivery:job-1", signed);
    const dv = await verifier.verifyDelivery("job-1", sellerId.did);
    assert.equal(dv.ok, false); // and crucially: no throw
    assert.match(dv.reason!, /not found on GitHub/);
  });

  test("happy path still verifies after all the negatives", async () => {
    const { seller, verifier, sellerId } = makeWorld();
    await seller.deliverReview("job-1", { repo: REPO, pullNumber: PR });
    const dv = await verifier.verifyDelivery("job-1", sellerId.did);
    assert.equal(dv.ok, true);
    assert.equal(dv.attestation?.ghAuthor, "reviewbot-x");
  });
});

// ---------------------------------------------------------------------------
// heuristic fallback shape
// ---------------------------------------------------------------------------

describe("heuristicReview", () => {
  test("flags TODO + console.log and reports changed-line split", () => {
    const md = heuristicReview("T", "+ console.log('x')\n+ // TODO fix\n- gone");
    assert.match(md, /TODO\/FIXME/);
    assert.match(md, /console\.log/);
    assert.match(md, /\+2\/−1 changed lines/);
    assert.match(md, /heuristic fallback/);
  });
});
