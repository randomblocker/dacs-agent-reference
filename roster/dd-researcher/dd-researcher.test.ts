/**
 * DD Researcher tests — fully offline via FakeAttestedFetch. node:test, run:
 *   npx tsx --test roster/dd-researcher/dd-researcher.test.ts
 */
import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FakeAttestedFetch, verifyAttestedRecord } from "../oracle-desk/attested-fetch.js";
import type { FakeUpstream } from "../oracle-desk/attested-fetch.js";
import { MAX_STORED_BODY_CHARS, parseGithubRepo } from "./evidence.js";
import { DDResearcher } from "./researcher.js";
import { verifyReport, writeReport } from "./report.js";
import type { DDReport, Finding, Subject } from "./types.js";
import { makeFinding } from "./types.js";

// Pinned clock so age-based rules are deterministic.
const NOW = new Date("2026-07-07T00:00:00.000Z");
const NPM: Subject = { kind: "npm-package", name: "express" };
const TOKEN: Subject = { kind: "crypto-token", id: "bitcoin" };

// ---------------------------------------------------------------------------
// Canned upstream bodies
// ---------------------------------------------------------------------------

const REG_HEALTHY = JSON.stringify({
  name: "express",
  "dist-tags": { latest: "4.19.2" },
  versions: {
    "4.18.0": { version: "4.18.0" },
    "4.19.2": { version: "4.19.2", license: "MIT", repository: { type: "git", url: "git+https://github.com/expressjs/express.git" } },
  },
  time: { created: "2010-12-29T19:38:25Z", modified: "2026-05-01T00:00:00Z", "4.19.2": "2026-05-01T00:00:00.000Z" },
  maintainers: [{ name: "a" }, { name: "b" }, { name: "c" }],
  license: "MIT",
});

// Brand-new package: `created` is recent relative to NOW.
const REG_NEW = JSON.stringify({
  name: "shiny-new-thing",
  "dist-tags": { latest: "1.0.0" },
  versions: { "1.0.0": { version: "1.0.0", license: "MIT" } },
  time: { created: "2026-06-20T00:00:00Z", "1.0.0": "2026-06-20T00:00:00.000Z" },
  maintainers: [{ name: "a" }, { name: "b" }],
  license: "MIT",
});

// GitHub Global Advisory DB responses (arrays).
const ADV_NONE = "[]";
const ADV_HITS = JSON.stringify([
  {
    ghsa_id: "GHSA-aaaa-bbbb-cccc",
    cve_id: "CVE-2026-0001",
    severity: "high",
    summary: "Prototype pollution in the parser",
    vulnerabilities: [{ package: { ecosystem: "npm", name: "express" }, vulnerable_version_range: "< 4.19.0" }],
  },
  {
    ghsa_id: "GHSA-dddd-eeee-ffff",
    severity: "moderate",
    summary: "ReDoS in a header matcher",
    vulnerabilities: [{ package: { ecosystem: "npm", name: "express" }, vulnerable_version_range: ">= 4.0.0, < 4.18.0" }],
  },
]);
const ADV_MODERATE_ONLY = JSON.stringify([
  { ghsa_id: "GHSA-1111-2222-3333", severity: "low", summary: "Minor info leak", vulnerabilities: [] },
]);
const ADV_RATE_LIMITED = JSON.stringify({ message: "API rate limit exceeded for 1.2.3.4.", documentation_url: "https://docs.github.com" });

const REG_RISKY = JSON.stringify({
  name: "left-pad-ng",
  "dist-tags": { latest: "0.0.3" },
  versions: { "0.0.3": { version: "0.0.3", deprecated: "use padStart instead" } },
  time: { "0.0.3": "2021-01-01T00:00:00.000Z" },
  maintainers: [{ name: "solo" }],
});

const DL_HEALTHY = JSON.stringify({ downloads: 5_000_000, start: "2026-06-07", end: "2026-07-06", package: "express" });
const DL_LOW = JSON.stringify({ downloads: 200, start: "2026-06-07", end: "2026-07-06", package: "left-pad-ng" });

const GH_HEALTHY = JSON.stringify({
  full_name: "expressjs/express",
  stargazers_count: 65_000,
  open_issues_count: 100,
  forks_count: 12_000,
  pushed_at: "2026-06-20T00:00:00Z",
  archived: false,
  license: { spdx_id: "MIT" },
});

const GH_BAD = JSON.stringify({
  full_name: "ghost/dead-project",
  stargazers_count: 1_000,
  open_issues_count: 800,
  forks_count: 40,
  pushed_at: "2020-01-01T00:00:00Z",
  archived: true,
  license: null,
});

const GH_RATE_LIMITED = JSON.stringify({ message: "API rate limit exceeded for 1.2.3.4.", documentation_url: "https://docs.github.com" });

const CG_HEALTHY = JSON.stringify({
  id: "bitcoin",
  symbol: "btc",
  name: "Bitcoin",
  market_cap_rank: 1,
  market_data: {
    current_price: { usd: 100_000 },
    market_cap: { usd: 1.3e12 },
    total_volume: { usd: 3e10 },
    fully_diluted_valuation: { usd: 1.36e12 },
    ath: { usd: 126_000 },
    ath_change_percentage: { usd: -20.6 },
  },
  community_data: { twitter_followers: 6_500_000, telegram_channel_user_count: null },
  developer_data: { stars: 80_000, forks: 36_000, commit_count_4_weeks: 300, pull_request_contributors: 900 },
});

const CG_RISKY = JSON.stringify({
  id: "rugcoin",
  symbol: "rug",
  name: "RugCoin",
  market_cap_rank: 900,
  market_data: {
    current_price: { usd: 0.0001 },
    market_cap: { usd: 1_000_000 },
    total_volume: { usd: 500 },
    fully_diluted_valuation: { usd: 10_000_000 },
    ath: { usd: 0.01 },
    ath_change_percentage: { usd: -95.2 },
  },
  community_data: { twitter_followers: 100, telegram_channel_user_count: 50 },
  developer_data: { stars: 3, forks: 0, commit_count_4_weeks: 0, pull_request_contributors: 1 },
});

type Routes = Array<[string, FakeUpstream]>;
const npmRoutes = (
  reg: string,
  dl: FakeUpstream,
  gh?: FakeUpstream,
  adv: FakeUpstream = { status: 200, body: ADV_NONE },
): Routes => [
  ["registry.npmjs.org", { status: 200, body: reg }],
  ["api.npmjs.org/downloads", dl],
  // Distinct substrings: /advisories never collides with /repos.
  ["api.github.com/advisories", adv],
  ...(gh ? ([["api.github.com/repos", gh]] as Routes) : []),
];

async function research(subject: Subject, routes: Routes): Promise<DDReport> {
  const researcher = new DDResearcher(new FakeAttestedFetch(routes), { now: () => NOW, useLlm: false });
  return researcher.research(subject);
}

const byRule = (report: DDReport, rule: string): Finding | undefined => report.findings.find((f) => f.rule === rule);

// ---------------------------------------------------------------------------
// Evidence gathering
// ---------------------------------------------------------------------------

describe("evidence gathering", () => {
  test("npm subject yields registry, downloads, advisories, and github evidence with attestations that verify", async () => {
    const report = await research(NPM, npmRoutes(REG_HEALTHY, { status: 200, body: DL_HEALTHY }, { status: 200, body: GH_HEALTHY }));

    assert.deepEqual(report.evidence.map((e) => e.id), ["E1", "E2", "E3", "E4"]);
    assert.deepEqual(report.evidence.map((e) => e.source), ["npm-registry", "npm-downloads", "github-advisories", "github-repo"]);
    assert.ok(report.evidence[0]!.url.includes("registry.npmjs.org/express"));
    assert.ok(report.evidence[1]!.url.includes("downloads/point/last-month/express"));
    assert.ok(report.evidence[2]!.url.includes("api.github.com/advisories?ecosystem=npm&affects=express"));
    assert.ok(report.evidence[3]!.url.includes("api.github.com/repos/expressjs/express"));
    assert.equal(report.gaps.length, 0);

    for (const e of report.evidence) {
      assert.equal(e.ok, true);
      const verdict = verifyAttestedRecord(e);
      assert.equal(verdict.valid, true, `${e.id}: ${verdict.reason ?? ""}`);
    }
    const reg = report.evidence[0]!;
    assert.equal(reg.extracted.latestVersion, "4.19.2");
    assert.equal(reg.extracted.license, "MIT");
    assert.equal(reg.extracted.maintainersCount, 3);
    assert.equal(reg.extracted.githubRepo, "expressjs/express");
    assert.equal(reg.extracted.createdAt, "2010-12-29T19:38:25Z");
    assert.equal(report.evidence[1]!.extracted.downloadsLastMonth, 5_000_000);
    assert.equal(report.evidence[2]!.extracted.advisoryCount, 0);
    assert.equal(report.evidence[3]!.extracted.stars, 65_000);
  });

  test("token subject yields one coingecko evidence item with market/community/dev fields", async () => {
    const report = await research(TOKEN, [["api.coingecko.com", { status: 200, body: CG_HEALTHY }]]);
    assert.equal(report.evidence.length, 1);
    const e = report.evidence[0]!;
    assert.equal(e.source, "coingecko-coin");
    assert.ok(e.url.includes("/coins/bitcoin?"));
    assert.equal(e.extracted.marketCapRank, 1);
    assert.equal(e.extracted.volume24hUsd, 3e10);
    assert.equal(e.extracted.devCommits4w, 300);
    assert.equal(verifyAttestedRecord(e).valid, true);
  });

  test("oversized bodies are dropped from evidence but the hash-only record still verifies", async () => {
    const big = JSON.stringify({ ...JSON.parse(REG_HEALTHY), padding: "x".repeat(MAX_STORED_BODY_CHARS + 1) });
    const report = await research(NPM, npmRoutes(big, { status: 200, body: DL_HEALTHY }, { status: 200, body: GH_HEALTHY }));
    const reg = report.evidence[0]!;
    assert.equal(reg.body, undefined);
    assert.equal(reg.extracted.latestVersion, "4.19.2"); // extraction happened before the drop
    assert.equal(verifyAttestedRecord(reg).valid, true);
    assert.equal(verifyReport(JSON.parse(JSON.stringify(report))).valid, true);
  });

  test("parseGithubRepo handles git+https/.git/ssh forms and rejects non-github urls", () => {
    assert.equal(parseGithubRepo("git+https://github.com/expressjs/express.git"), "expressjs/express");
    assert.equal(parseGithubRepo("git@github.com:foo/bar.git"), "foo/bar");
    assert.equal(parseGithubRepo("https://github.com/foo/bar#readme"), "foo/bar");
    assert.equal(parseGithubRepo("https://gitlab.com/foo/bar"), null);
    assert.equal(parseGithubRepo(null), null);
  });
});

// ---------------------------------------------------------------------------
// Finding rules
// ---------------------------------------------------------------------------

describe("npm finding rules", () => {
  test("healthy package: all informational, no red flags or cautions", async () => {
    const report = await research(NPM, npmRoutes(REG_HEALTHY, { status: 200, body: DL_HEALTHY }, { status: 200, body: GH_HEALTHY }));
    assert.equal(report.findings.filter((f) => f.severity !== "info").length, 0);
    assert.match(byRule(report, "npm-publish-age")!.title, /Actively published/);
    assert.match(byRule(report, "npm-downloads")!.title, /Widely adopted/);
    assert.match(byRule(report, "npm-license")!.title, /MIT/);
    assert.match(byRule(report, "gh-push-age")!.title, /active/);
    for (const f of report.findings) assert.ok(f.citations.length >= 1, `${f.id} must cite evidence`);
  });

  test("risky package fires deprecated, no-license, single-maintainer, stale-publish, no-repo, low-downloads", async () => {
    const report = await research(NPM, npmRoutes(REG_RISKY, { status: 200, body: DL_LOW }));

    const deprecated = byRule(report, "npm-deprecated")!;
    assert.equal(deprecated.severity, "red-flag");
    assert.match(deprecated.detail, /use padStart instead/);

    assert.equal(byRule(report, "npm-license")!.severity, "red-flag");
    assert.equal(byRule(report, "npm-single-maintainer")!.severity, "caution");
    const stale = byRule(report, "npm-publish-age")!;
    assert.equal(stale.severity, "caution");
    assert.match(stale.title, /No release in \d+ days/);
    assert.equal(byRule(report, "npm-no-repo")!.severity, "caution");
    assert.equal(byRule(report, "npm-downloads")!.severity, "caution");

    // No repo link → github must not have been fetched.
    assert.equal(report.evidence.some((e) => e.source === "github-repo"), false);
    // Every finding cites the evidence item it came from.
    const regId = report.evidence.find((e) => e.source === "npm-registry")!.id;
    assert.deepEqual(deprecated.citations, [regId]);
  });

  test("bad github repo fires archived (red-flag), stale-push and issue-ratio (cautions)", async () => {
    const report = await research(NPM, npmRoutes(REG_HEALTHY, { status: 200, body: DL_HEALTHY }, { status: 200, body: GH_BAD }));
    assert.equal(byRule(report, "gh-archived")!.severity, "red-flag");
    assert.equal(byRule(report, "gh-push-age")!.severity, "caution");
    const ratio = byRule(report, "gh-issue-ratio")!;
    assert.equal(ratio.severity, "caution");
    assert.match(ratio.detail, /0\.80/);
  });
});

describe("npm security advisories (GitHub Global Advisory DB)", () => {
  test("high-severity advisory fires a red-flag citing the attested advisory evidence", async () => {
    const report = await research(
      NPM,
      npmRoutes(REG_HEALTHY, { status: 200, body: DL_HEALTHY }, { status: 200, body: GH_HEALTHY }, { status: 200, body: ADV_HITS }),
    );
    const adv = byRule(report, "gh-advisories")!;
    assert.equal(adv.severity, "red-flag");
    assert.match(adv.title, /2 known security advisories \(worst: high\)/);
    assert.match(adv.detail, /GHSA-aaaa-bbbb-cccc/);
    assert.match(adv.detail, /affects < 4\.19\.0/);
    // Cites exactly the advisories evidence item, which itself attests.
    const advEvidence = report.evidence.find((e) => e.source === "github-advisories")!;
    assert.deepEqual(adv.citations, [advEvidence.id]);
    assert.equal(verifyAttestedRecord(advEvidence).valid, true);
    assert.equal(verifyReport(JSON.parse(JSON.stringify(report))).valid, true);
  });

  test("moderate-only advisory is a caution, not a red-flag", async () => {
    const report = await research(
      NPM,
      npmRoutes(REG_HEALTHY, { status: 200, body: DL_HEALTHY }, { status: 200, body: GH_HEALTHY }, { status: 200, body: ADV_MODERATE_ONLY }),
    );
    const adv = byRule(report, "gh-advisories")!;
    assert.equal(adv.severity, "caution");
    assert.match(adv.title, /1 known security advisory \(worst: low\)/);
  });

  test("no advisories is an informational finding", async () => {
    const report = await research(NPM, npmRoutes(REG_HEALTHY, { status: 200, body: DL_HEALTHY }, { status: 200, body: GH_HEALTHY }));
    const adv = byRule(report, "gh-advisories")!;
    assert.equal(adv.severity, "info");
    assert.match(adv.title, /No known security advisories/);
  });

  test("advisory endpoint 403 degrades to an attested unavailability caution, not a fabricated finding", async () => {
    const report = await research(
      NPM,
      npmRoutes(REG_HEALTHY, { status: 200, body: DL_HEALTHY }, { status: 200, body: GH_HEALTHY }, { status: 403, body: ADV_RATE_LIMITED }),
    );
    const advEvidence = report.evidence.find((e) => e.source === "github-advisories")!;
    assert.equal(advEvidence.ok, false);
    assert.equal(verifyAttestedRecord(advEvidence).valid, true, "even the 403 is attested");
    // No security claim is manufactured: only the generic unavailable caution.
    assert.equal(byRule(report, "gh-advisories"), undefined);
    const unavailable = byRule(report, "github-advisories-unavailable")!;
    assert.equal(unavailable.severity, "caution");
    assert.deepEqual(unavailable.citations, [advEvidence.id]);
    assert.equal(verifyReport(JSON.parse(JSON.stringify(report))).valid, true);
  });
});

describe("npm package age", () => {
  test("a brand-new package fires a supply-chain caution", async () => {
    const report = await research(NPM, npmRoutes(REG_NEW, { status: 200, body: DL_HEALTHY }));
    const age = byRule(report, "npm-package-age")!;
    assert.equal(age.severity, "caution");
    assert.match(age.title, /New package/);
    assert.deepEqual(age.citations, [report.evidence.find((e) => e.source === "npm-registry")!.id]);
  });

  test("an old package is informational", async () => {
    const report = await research(NPM, npmRoutes(REG_HEALTHY, { status: 200, body: DL_HEALTHY }, { status: 200, body: GH_HEALTHY }));
    const age = byRule(report, "npm-package-age")!;
    assert.equal(age.severity, "info");
    assert.match(age.title, /Established package/);
  });
});

describe("token finding rules", () => {
  test("healthy token: rank/liquidity/overhang/contributors/dev/community/drawdown all informational", async () => {
    const report = await research(TOKEN, [["api.coingecko.com", { status: 200, body: CG_HEALTHY }]]);
    for (const rule of ["cg-rank", "cg-liquidity", "cg-supply-overhang", "cg-dev-contributors", "cg-dev-activity", "cg-community", "cg-drawdown"]) {
      const f = byRule(report, rule);
      assert.ok(f, `${rule} should fire`);
      assert.equal(f.severity, "info", `${rule} should be info, got ${f.severity}`);
    }
  });

  test("risky token fires long-tail rank, thin liquidity, dilution overhang, thin dev base, dormant dev, tiny community, ATH-collapse red-flag", async () => {
    const report = await research({ kind: "crypto-token", id: "rugcoin" }, [["api.coingecko.com", { status: 200, body: CG_RISKY }]]);
    assert.equal(byRule(report, "cg-rank")!.severity, "caution");
    assert.equal(byRule(report, "cg-liquidity")!.severity, "caution");
    const overhang = byRule(report, "cg-supply-overhang")!;
    assert.equal(overhang.severity, "caution");
    assert.match(overhang.title, /10\.0x market cap/);
    assert.equal(byRule(report, "cg-dev-contributors")!.severity, "caution");
    assert.equal(byRule(report, "cg-dev-activity")!.severity, "caution");
    assert.equal(byRule(report, "cg-community")!.severity, "caution");
    const drawdown = byRule(report, "cg-drawdown")!;
    assert.equal(drawdown.severity, "red-flag");
    assert.match(drawdown.title, /95\.2% below all-time high/);
  });

  test("absent community stats are reported as unassessed (info), not manufactured into a caution", async () => {
    const body = JSON.parse(CG_HEALTHY) as { community_data: Record<string, unknown> };
    body.community_data = { twitter_followers: null, telegram_channel_user_count: null };
    const report = await research(TOKEN, [["api.coingecko.com", { status: 200, body: JSON.stringify(body) }]]);
    const f = byRule(report, "cg-community")!;
    assert.equal(f.severity, "info");
    assert.match(f.title, /not reported/);
  });
});

// ---------------------------------------------------------------------------
// Zero-citation ban
// ---------------------------------------------------------------------------

describe("citations are mandatory", () => {
  test("makeFinding throws on an empty citations list", () => {
    assert.throws(
      () => makeFinding({ id: "F1", rule: "bogus", severity: "info", title: "t", detail: "d", citations: [] }),
      /zero citations/,
    );
  });

  test("verifyReport rejects a finding whose citations were stripped", async () => {
    const report = await research(TOKEN, [["api.coingecko.com", { status: 200, body: CG_HEALTHY }]]);
    const raw = JSON.parse(JSON.stringify(report)) as { findings: Array<{ citations: string[] }> };
    raw.findings[0]!.citations = [];
    const verdict = verifyReport(raw);
    assert.equal(verdict.valid, false);
    assert.ok(verdict.problems.some((p) => /zero citations/.test(p)));
  });

  test("the summary is presentation-only: prose cannot smuggle a verifiable claim past verifyReport", async () => {
    // The executive summary (deterministic OR llm) is never part of the
    // verifiable substance — only cited findings are. So even an adversarial
    // summary asserting an uncited claim leaves the report valid, and the
    // findings (the audit-grade part) are untouched.
    const report = await research(TOKEN, [["api.coingecko.com", { status: 200, body: CG_HEALTHY }]]);
    const tampered = JSON.parse(JSON.stringify(report)) as DDReport;
    const findingsBefore = JSON.stringify(tampered.findings);
    tampered.summary = { text: "This token is a confirmed rug pull that steals user funds.", method: "llm" };
    const verdict = verifyReport(tampered);
    assert.equal(verdict.valid, true, verdict.problems.join("; "));
    // The claim exists ONLY in prose — no finding backs it, so nothing changed.
    assert.equal(JSON.stringify(tampered.findings), findingsBefore);
    assert.equal(tampered.findings.some((f) => /rug pull|steals/.test(f.title) || /rug pull|steals/.test(f.detail)), false);
  });
});

// ---------------------------------------------------------------------------
// Graceful degradation
// ---------------------------------------------------------------------------

describe("degraded modes", () => {
  test("github 403 rate limit becomes attested unavailability + a caution finding, not a crash", async () => {
    const report = await research(NPM, npmRoutes(REG_HEALTHY, { status: 200, body: DL_HEALTHY }, { status: 403, body: GH_RATE_LIMITED }));
    const gh = report.evidence.find((e) => e.source === "github-repo")!;
    assert.equal(gh.ok, false);
    assert.equal(gh.status, 403);
    assert.equal(verifyAttestedRecord(gh).valid, true, "even the 403 response is attested");

    const finding = byRule(report, "github-repo-unavailable")!;
    assert.equal(finding.severity, "caution");
    assert.deepEqual(finding.citations, [gh.id]);
    // No repo-content rules may fire off an unavailable source.
    assert.equal(byRule(report, "gh-archived"), undefined);
    assert.equal(verifyReport(JSON.parse(JSON.stringify(report))).valid, true);
  });

  test("a network-level failure is recorded as a SourceGap and the report still verifies", async () => {
    const report = await research(NPM, npmRoutes(REG_HEALTHY, { fail: "ECONNRESET" }, { status: 200, body: GH_HEALTHY }));
    assert.equal(report.gaps.length, 1);
    assert.equal(report.gaps[0]!.source, "npm-downloads");
    assert.match(report.gaps[0]!.reason, /ECONNRESET/);
    assert.equal(byRule(report, "npm-downloads"), undefined);
    assert.match(report.summary.text, /could not be reached/);
    assert.equal(verifyReport(JSON.parse(JSON.stringify(report))).valid, true);
  });
});

// ---------------------------------------------------------------------------
// Report round trip + tamper detection
// ---------------------------------------------------------------------------

describe("report emission and verification", () => {
  test("emitted report.json round-trips through verifyReport; report.md carries citations and appendix", async () => {
    const report = await research(NPM, npmRoutes(REG_HEALTHY, { status: 200, body: DL_HEALTHY }, { status: 200, body: GH_HEALTHY }));
    const dir = await mkdtemp(join(tmpdir(), "dd-researcher-test-"));
    try {
      const emitted = await writeReport(report, dir);
      const parsed = JSON.parse(await readFile(emitted.jsonPath, "utf8"));
      const verdict = verifyReport(parsed);
      assert.equal(verdict.valid, true, verdict.problems.join("; "));
      assert.equal(verdict.evidenceChecked, 4);
      assert.equal(verdict.findingsChecked, report.findings.length);

      const md = await readFile(emitted.mdPath, "utf8");
      assert.match(md, /# Due-diligence report — npm package "express"/);
      assert.match(md, /\[E1\]/);
      assert.match(md, /## Evidence appendix/);
      assert.match(md, /attestation digest: [0-9a-f]{64}/);
      assert.match(md, /MOCK-DAHR-ed25519/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("tampering is caught: dangling citation, forged bodyHash, edited body, forged signature", async () => {
    const report = await research(TOKEN, [["api.coingecko.com", { status: 200, body: CG_HEALTHY }]]);
    const clone = () => JSON.parse(JSON.stringify(report)) as DDReport;

    const danglingCitation = clone();
    danglingCitation.findings[0]!.citations = ["E99"];
    assert.equal(verifyReport(danglingCitation).valid, false);

    const forgedHash = clone();
    forgedHash.evidence[0]!.bodyHash = "ab".repeat(32);
    const hashVerdict = verifyReport(forgedHash);
    assert.equal(hashVerdict.valid, false);
    assert.ok(hashVerdict.problems.some((p) => /attestation invalid|does not match bodyHash/.test(p)));

    const editedBody = clone();
    editedBody.evidence[0]!.body = CG_RISKY; // swap the underlying evidence body
    assert.equal(verifyReport(editedBody).valid, false);

    const forgedSig = clone();
    forgedSig.evidence[0]!.attestation.signature = Buffer.alloc(64).toString("base64");
    const sigVerdict = verifyReport(forgedSig);
    assert.equal(sigVerdict.valid, false);
    assert.ok(sigVerdict.problems.some((p) => /signature/.test(p)));

    // Untampered control still passes.
    assert.equal(verifyReport(clone()).valid, true);
  });
});
