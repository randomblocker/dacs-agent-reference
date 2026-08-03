/**
 * Site-Reliability Auditor tests — fully offline via FakeProber.
 * node:test, run: npx tsx --test roster/site-auditor/site-auditor.test.ts
 */
import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { MockDahrAttestor } from "../oracle-desk/attested-fetch.js";
import { SiteAuditor, normalizeTargetUrl } from "./auditor.js";
import {
  compressionNegotiated,
  httpsRedirectAchieved,
  percentile,
  scoreHeaders,
  scoreHygiene,
  scorePerformance,
  scoreTls,
} from "./checks.js";
import { compareAudits, evaluatePayOnImprovement, renderDeltaMarkdown, verifyDelta, verifyPayOnImprovement } from "./compare.js";
import type { ImprovementTarget } from "./types.js";
import { assertSafeProbeUrl, FakeProber, type FakeProbe, type FakeTls } from "./prober.js";
import { renderAuditMarkdown, verifyAudit } from "./report.js";
import type { CategoryName, Citations, ProbeResult, SiteAuditReport, TlsInfo } from "./types.js";
import { makeCheck } from "./types.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const TARGET = "https://acme.test/";
const HTTP_VARIANT = "http://acme.test/";
const HOST = "acme.test";

const FULL_HEADERS: Record<string, string> = {
  "strict-transport-security": "max-age=63072000; includeSubDomains",
  "content-security-policy": "default-src 'self'",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer",
  "content-encoding": "br",
  "cache-control": "public, max-age=3600",
  "content-type": "text/html",
};

function sample(over: Partial<ProbeResult> = {}): ProbeResult {
  return {
    url: TARGET,
    finalUrl: TARGET,
    status: 200,
    ttfbMs: 80,
    totalMs: 150,
    bodyBytes: 12_345,
    redirectCount: 0,
    redirectChain: [TARGET],
    headers: { ...FULL_HEADERS },
    fetchedAt: "2026-07-07T00:00:00.000Z",
    ...over,
  };
}

const TLS_GOOD: TlsInfo = {
  host: HOST,
  validTo: "2026-11-04T00:00:00.000Z",
  daysRemaining: 120,
  issuer: "Fake CA",
  protocol: "TLSv1.3",
  checkedAt: "2026-07-07T00:00:00.000Z",
};

const HTTP_REDIRECTS = sample({ url: HTTP_VARIANT, finalUrl: TARGET, redirectCount: 1, redirectChain: [HTTP_VARIANT, TARGET] });
const HTTP_NO_REDIRECT = sample({ url: HTTP_VARIANT, finalUrl: HTTP_VARIANT, redirectChain: [HTTP_VARIANT] });

const FAST_TIMING = [sample({ totalMs: 120, ttfbMs: 60 }), sample({ totalMs: 150, ttfbMs: 80 }), sample({ totalMs: 180, ttfbMs: 90 })];
const SLOW_TIMING = [sample({ totalMs: 2900, ttfbMs: 900 }), sample({ totalMs: 3000, ttfbMs: 1000 }), sample({ totalMs: 3100, ttfbMs: 1100 })];

interface FakeOpts {
  timing?: FakeProbe[];
  tls?: FakeTls;
  http?: FakeProbe;
}

function fakeProber(opts: FakeOpts = {}): FakeProber {
  return new FakeProber(
    { [TARGET]: opts.timing ?? FAST_TIMING, [HTTP_VARIANT]: [opts.http ?? HTTP_REDIRECTS] },
    { [HOST]: opts.tls ?? TLS_GOOD },
  );
}

async function runAudit(opts: FakeOpts & { samples?: number } = {}): Promise<SiteAuditReport> {
  const auditor = new SiteAuditor(fakeProber(opts), new MockDahrAttestor(), { sampleGapMs: 0 });
  return auditor.audit({ url: TARGET, samples: opts.samples ?? 3 });
}

function clone<T>(v: T): T {
  return JSON.parse(JSON.stringify(v)) as T;
}

function category(report: SiteAuditReport, name: CategoryName) {
  const c = report.categories.find((x) => x.category === name);
  assert.ok(c, `category ${name} missing`);
  return c;
}

// ---------------------------------------------------------------------------
// Percentile math
// ---------------------------------------------------------------------------

describe("percentile", () => {
  test("odd sample count: p50 is the middle value", () => {
    assert.equal(percentile([300, 100, 200], 50), 200);
  });

  test("even sample count: p50 interpolates between the middle pair", () => {
    assert.equal(percentile([100, 400, 200, 300], 50), 250);
  });

  test("p95 interpolates linearly", () => {
    // rank = 3 * 0.95 = 2.85 → 30 + 0.85 * 10
    assert.equal(percentile([10, 20, 30, 40], 95), 38.5);
  });

  test("single sample: every percentile is that value", () => {
    assert.equal(percentile([42], 50), 42);
    assert.equal(percentile([42], 95), 42);
  });

  test("p0/p100 are min/max", () => {
    assert.equal(percentile([5, 1, 9], 0), 1);
    assert.equal(percentile([5, 1, 9], 100), 9);
  });

  test("throws on an empty sample set and out-of-range p", () => {
    assert.throws(() => percentile([], 50), /empty/);
    assert.throws(() => percentile([1], 101), /not in \[0, 100\]/);
  });
});

// ---------------------------------------------------------------------------
// Scoring rules at boundary values
// ---------------------------------------------------------------------------

describe("scoring rules", () => {
  test("scorePerformance thresholds are inclusive at each boundary", () => {
    assert.equal(scorePerformance(200), 100);
    assert.equal(scorePerformance(200.1), 85);
    assert.equal(scorePerformance(500), 85);
    assert.equal(scorePerformance(500.1), 70);
    assert.equal(scorePerformance(1000), 70);
    assert.equal(scorePerformance(2000), 50);
    assert.equal(scorePerformance(4000), 25);
    assert.equal(scorePerformance(4000.1), 10);
  });

  test("scoreTls thresholds are inclusive at each boundary", () => {
    assert.equal(scoreTls(60), 100);
    assert.equal(scoreTls(59), 80);
    assert.equal(scoreTls(30), 80);
    assert.equal(scoreTls(29), 60);
    assert.equal(scoreTls(14), 60);
    assert.equal(scoreTls(13), 40);
    assert.equal(scoreTls(7), 40);
    assert.equal(scoreTls(6), 20);
    assert.equal(scoreTls(1), 20);
    assert.equal(scoreTls(0), 0);
    assert.equal(scoreTls(-5), 0); // expired
  });

  test("scoreHeaders is the weighted present-count", () => {
    assert.equal(scoreHeaders([]), 0);
    assert.equal(
      scoreHeaders(["strict-transport-security", "content-security-policy", "x-content-type-options", "x-frame-options", "referrer-policy"]),
      100,
    );
    assert.equal(scoreHeaders(["strict-transport-security", "content-security-policy"]), 60);
    assert.equal(scoreHeaders(["x-content-type-options", "x-frame-options", "referrer-policy"]), 40);
  });

  test("scoreHygiene weights and n/a renormalization", () => {
    assert.equal(scoreHygiene({ compression: true, cacheControl: true, httpsRedirect: true }), 100);
    assert.equal(scoreHygiene({ compression: true, cacheControl: false, httpsRedirect: false }), 40);
    assert.equal(scoreHygiene({ compression: true, cacheControl: true, httpsRedirect: false }), 60);
    // plain-http target: redirect not applicable, remaining parts renormalize
    assert.equal(scoreHygiene({ compression: true, cacheControl: true, httpsRedirect: "n/a" }), 100);
    assert.equal(scoreHygiene({ compression: false, cacheControl: true, httpsRedirect: "n/a" }), 33.3);
  });

  test("compressionNegotiated reads content-encoding", () => {
    assert.equal(compressionNegotiated({ "content-encoding": "gzip" }), true);
    assert.equal(compressionNegotiated({ "content-encoding": "br" }), true);
    assert.equal(compressionNegotiated({}), false);
    assert.equal(compressionNegotiated({ "content-encoding": "identity" }), false);
  });

  test("httpsRedirectAchieved requires a redirect that lands on https", () => {
    assert.equal(httpsRedirectAchieved({ finalUrl: TARGET, redirectCount: 1 }), true);
    assert.equal(httpsRedirectAchieved({ finalUrl: HTTP_VARIANT, redirectCount: 0 }), false);
    assert.equal(httpsRedirectAchieved({ finalUrl: "http://elsewhere.test/", redirectCount: 2 }), false);
    // 200 straight over https without a redirect is not a redirect
    assert.equal(httpsRedirectAchieved({ finalUrl: TARGET, redirectCount: 0 }), false);
  });
});

// ---------------------------------------------------------------------------
// Citation by construction
// ---------------------------------------------------------------------------

describe("citation by construction", () => {
  test("makeCheck throws on an empty citation list", () => {
    assert.throws(() => makeCheck("x.y", "x", 50, "detail", []), /without a citation is forbidden/);
  });

  test("makeCheck throws on out-of-range or non-finite scores", () => {
    assert.throws(() => makeCheck("x.y", "x", 101, "detail", ["A1"]), /not in \[0, 100\]/);
    assert.throws(() => makeCheck("x.y", "x", -1, "detail", ["A1"]), /not in \[0, 100\]/);
    assert.throws(() => makeCheck("x.y", "x", Number.NaN, "detail", ["A1"]), /not in \[0, 100\]/);
  });
});

// ---------------------------------------------------------------------------
// Audit behaviour (offline, FakeProber)
// ---------------------------------------------------------------------------

describe("audit", () => {
  test("happy path: all categories measured, every check cites attested evidence", async () => {
    const report = await runAudit();

    const perf = category(report, "performance");
    assert.equal(perf.degraded, false);
    assert.equal(perf.metrics!.p50TotalMs, 150);
    assert.equal(perf.metrics!.p95TotalMs, 177); // 150 + 0.9 * 30
    assert.equal(perf.metrics!.minTotalMs, 120);
    assert.equal(perf.metrics!.maxTotalMs, 180);
    assert.equal(perf.score, 100);

    assert.equal(category(report, "tls").score, 100);
    assert.equal(category(report, "headers").score, 100);
    assert.equal(category(report, "hygiene").score, 100);
    assert.equal(report.overallScore, 100);

    // 3 timing + 1 tls + 1 http-redirect, all attested
    assert.equal(report.provenance.evidence.length, 5);
    assert.equal(report.provenance.gaps.length, 0);
    const ids = new Set(report.provenance.evidence.map((e) => e.id));
    for (const c of report.categories) {
      for (const check of c.checks) {
        assert.ok(check.citations.length > 0, `${check.id} has citations`);
        for (const cite of check.citations) assert.ok(ids.has(cite), `${check.id} cites real evidence`);
      }
    }
    assert.match(renderAuditMarkdown(report), /Measurement appendix/);
  });

  test("absent security headers score 0 per header and 0 for the category", async () => {
    const bare = { "content-type": "text/html" };
    const report = await runAudit({ timing: [sample({ headers: bare }), sample({ headers: bare }), sample({ headers: bare })] });
    const headers = category(report, "headers");
    assert.equal(headers.degraded, false);
    assert.equal(headers.score, 0);
    assert.equal(headers.checks.length, 5);
    for (const check of headers.checks) {
      assert.equal(check.score, 0);
      assert.match(check.detail, /absent/);
    }
  });

  test("present security headers carry their value in the check detail", async () => {
    const report = await runAudit();
    const hsts = category(report, "headers").checks.find((c) => c.id === "headers.strict-transport-security");
    assert.ok(hsts);
    assert.equal(hsts.score, 100);
    assert.match(hsts.detail, /max-age=63072000/);
  });

  test("http:// variant not redirecting to https fails the hygiene sub-check", async () => {
    const report = await runAudit({ http: HTTP_NO_REDIRECT });
    const hygiene = category(report, "hygiene");
    assert.equal(hygiene.degraded, false);
    assert.equal(hygiene.score, 60); // compression 40 + cache 20, redirect 0
    const redirect = hygiene.checks.find((c) => c.id === "hygiene.https-redirect");
    assert.ok(redirect);
    assert.equal(redirect.score, 0);
    assert.match(redirect.detail, /without reaching https/);
  });

  test("degraded mode: tls inspection failure degrades ONLY tls and the report still verifies", async () => {
    const report = await runAudit({ tls: { fail: "handshake refused" } });
    const tls = category(report, "tls");
    assert.equal(tls.degraded, true);
    assert.match(tls.degradedReason!, /handshake refused/);
    assert.equal(tls.checks.length, 0);
    assert.equal(category(report, "performance").degraded, false);
    // overall renormalizes over the remaining 80 weight
    assert.equal(report.overallScore, 100);
    assert.ok(report.provenance.gaps.some((g) => g.kind === "tls"));

    const verdict = verifyAudit(clone(report));
    assert.equal(verdict.valid, true, verdict.problems.join("; "));
    assert.equal(verdict.attestationsChecked, 4); // 3 timing + http-redirect
  });

  test("plain-http target: no tls / http-redirect probes, tls marked not applicable, hygiene renormalized", async () => {
    const url = "http://plain.test/";
    const prober = new FakeProber({ [url]: [sample({ url, finalUrl: url, redirectChain: [url] })] });
    const auditor = new SiteAuditor(prober, new MockDahrAttestor(), { sampleGapMs: 0 });
    const report = await auditor.audit({ url, samples: 3 });

    assert.deepEqual(prober.probed, [url, url, url]); // never touched tls or an http variant
    const tls = category(report, "tls");
    assert.equal(tls.degraded, true);
    assert.match(tls.degradedReason!, /not applicable/);
    const hygiene = category(report, "hygiene");
    assert.equal(hygiene.degraded, false);
    assert.equal(hygiene.checks.length, 2); // no https-redirect check
    assert.equal(hygiene.score, 100); // compression + cache renormalized over 60
    assert.equal(verifyAudit(clone(report)).valid, true);
  });

  test("partial sample failure: survivors are used, gap recorded, performance not degraded", async () => {
    const report = await runAudit({ timing: [{ fail: "connection reset" }, sample({ totalMs: 100 }), sample({ totalMs: 200 })] });
    const perf = category(report, "performance");
    assert.equal(perf.degraded, false);
    assert.equal(perf.metrics!.p50TotalMs, 150); // even count → interpolated
    assert.match(perf.checks[0].detail, /1 sample\(s\) failed/);
    assert.equal(report.provenance.gaps.filter((g) => g.kind === "timing-sample").length, 1);
    assert.equal(verifyAudit(clone(report)).valid, true);
  });

  test("all timing samples failing degrades performance AND headers but not tls", async () => {
    const report = await runAudit({ timing: [{ fail: "blocked" }] });
    assert.equal(category(report, "performance").degraded, true);
    assert.equal(category(report, "headers").degraded, true);
    assert.equal(category(report, "tls").degraded, false);
    const hygiene = category(report, "hygiene");
    assert.equal(hygiene.degraded, true); // compression/cache unmeasurable
    assert.equal(hygiene.checks.length, 1); // redirect part still measured
    assert.equal(report.overallScore, 100); // only tls (100) remains in the weighting
    assert.equal(verifyAudit(clone(report)).valid, true);
  });

  test("sample count is honored and validated", async () => {
    const report = await runAudit({ samples: 4, timing: [sample({ totalMs: 100 }), sample({ totalMs: 200 }), sample({ totalMs: 300 }), sample({ totalMs: 400 })] });
    assert.equal(report.samples, 4);
    assert.equal(report.provenance.evidence.filter((e) => e.kind === "timing-sample").length, 4);
    assert.equal(category(report, "performance").metrics!.p50TotalMs, 250);
    assert.equal(category(report, "performance").metrics!.p95TotalMs, 385);

    await assert.rejects(runAudit({ samples: 0 }), /samples must be an integer/);
    await assert.rejects(runAudit({ samples: 11 }), /samples must be an integer/);
  });

  test("target URL validation", () => {
    assert.equal(normalizeTargetUrl(" https://acme.test/#frag "), TARGET);
    assert.throws(() => normalizeTargetUrl("ftp://acme.test/"), /unsupported protocol/);
    assert.throws(() => normalizeTargetUrl("not a url"), /not a valid URL/);
  });

  test("real probe guard rejects local, private, metadata, credentialed, and non-http targets", () => {
    for (const url of [
      "http://localhost:8402/health",
      "https://sub.localhost/admin",
      "http://127.0.0.1/",
      "http://10.0.0.1/",
      "http://169.254.169.254/latest/meta-data/",
      "https://[::1]/",
      "https://user:pass@example.com/",
      "file:///etc/passwd",
    ]) {
      assert.throws(() => assertSafeProbeUrl(url), /blocked|credentials|unsafe/);
    }
    assert.equal(assertSafeProbeUrl("http://example.com/path").hostname, "example.com");
    assert.equal(assertSafeProbeUrl("https://example.com/path").hostname, "example.com");
  });
});

// ---------------------------------------------------------------------------
// Report round-trip verification + tamper variants
// ---------------------------------------------------------------------------

describe("verifyAudit", () => {
  test("genuine report verifies on a cold JSON round-trip", async () => {
    const report = await runAudit();
    const verdict = verifyAudit(clone(report));
    assert.equal(verdict.valid, true, verdict.problems.join("; "));
    assert.equal(verdict.attestationsChecked, 5);
    assert.equal(verdict.checksChecked, 10); // 1 perf + 1 tls + 5 headers + 3 hygiene
  });

  test("tamper: an edited metric is caught by re-derivation from the attested evidence", async () => {
    const tampered = clone(await runAudit());
    category(tampered, "performance").metrics!.p95TotalMs = 1;
    const verdict = verifyAudit(tampered);
    assert.equal(verdict.valid, false);
    assert.ok(verdict.problems.some((p) => /re-derivation/.test(p)), verdict.problems.join("; "));
  });

  test("tamper: an edited category score is caught", async () => {
    const tampered = clone(await runAudit({ http: HTTP_NO_REDIRECT }));
    category(tampered, "hygiene").score = 100; // was 60
    const verdict = verifyAudit(tampered);
    assert.equal(verdict.valid, false);
    assert.ok(verdict.problems.some((p) => /re-derivation/.test(p)));
  });

  test("tamper: an edited overall score is caught", async () => {
    const tampered = clone(await runAudit({ http: HTTP_NO_REDIRECT }));
    tampered.overallScore = 100;
    const verdict = verifyAudit(tampered);
    assert.equal(verdict.valid, false);
    assert.ok(verdict.problems.some((p) => /overallScore/.test(p)));
  });

  test("tamper: a forged attestation signature is caught", async () => {
    const tampered = clone(await runAudit());
    const sig = tampered.provenance.evidence[0].attestation.signature;
    tampered.provenance.evidence[0].attestation.signature = (sig.startsWith("A") ? "B" : "A") + sig.slice(1);
    const verdict = verifyAudit(tampered);
    assert.equal(verdict.valid, false);
    assert.ok(verdict.problems.some((p) => /attestation invalid/.test(p)), verdict.problems.join("; "));
  });

  test("tamper: an edited measurement body is caught by the body hash", async () => {
    const tampered = clone(await runAudit());
    const timing = tampered.provenance.evidence.find((e) => e.kind === "timing-sample")!;
    timing.body = timing.body.replace('"totalMs":', '"totalMs":0,"x":'); // change the bytes
    const verdict = verifyAudit(tampered);
    assert.equal(verdict.valid, false);
    assert.ok(verdict.problems.some((p) => /does not match bodyHash/.test(p)));
  });

  test("tamper: a dangling citation is caught", async () => {
    const tampered = clone(await runAudit());
    category(tampered, "headers").checks[0].citations = ["A99"] as Citations;
    const verdict = verifyAudit(tampered);
    assert.equal(verdict.valid, false);
    assert.ok(verdict.problems.some((p) => /"A99" does not resolve/.test(p)));
  });

  test("tamper: pseudo-URLs must reference the report target", async () => {
    const tampered = clone(await runAudit());
    tampered.url = "https://victim.test/"; // claim the audit was of someone else
    const verdict = verifyAudit(tampered);
    assert.equal(verdict.valid, false);
    assert.ok(verdict.problems.some((p) => /does not reference the report/.test(p)));
  });
});

// ---------------------------------------------------------------------------
// Before/after comparison + delta verification
// ---------------------------------------------------------------------------

describe("compareAudits / verifyDelta", () => {
  test("faster + fully-headered current run: improved verdicts with metric deltas", async () => {
    const baseline = await runAudit({ timing: SLOW_TIMING }); // perf 25
    const current = await runAudit(); // perf 100
    const delta = compareAudits(baseline, current);

    const perf = delta.categories.find((c) => c.category === "performance")!;
    assert.equal(perf.verdict, "improved");
    assert.equal(perf.scoreDelta, 75);
    const p95 = perf.metricDeltas.find((m) => m.metric === "p95TotalMs")!;
    assert.equal(p95.baseline, 3090);
    assert.equal(p95.current, 177);
    assert.equal(p95.delta, -2913);

    assert.equal(delta.categories.find((c) => c.category === "tls")!.verdict, "unchanged");
    assert.equal(delta.overall.verdict, "improved");
    assert.match(renderDeltaMarkdown(delta), /▲ improved/);
  });

  test("slower current run: regressed verdicts", async () => {
    const delta = compareAudits(await runAudit(), await runAudit({ timing: SLOW_TIMING }));
    assert.equal(delta.categories.find((c) => c.category === "performance")!.verdict, "regressed");
    assert.equal(delta.overall.verdict, "regressed");
  });

  test("identical runs: unchanged everywhere", async () => {
    const delta = compareAudits(await runAudit(), await runAudit());
    for (const c of delta.categories) assert.equal(c.verdict, "unchanged");
    assert.equal(delta.overall.verdict, "unchanged");
    assert.equal(delta.overall.scoreDelta, 0);
  });

  test("a header regression shows up as a regressed headers category", async () => {
    const fewer = { ...FULL_HEADERS };
    delete fewer["content-security-policy"];
    const current = await runAudit({ timing: [sample({ headers: fewer }), sample({ headers: fewer }), sample({ headers: fewer })] });
    const delta = compareAudits(await runAudit(), current);
    const headers = delta.categories.find((c) => c.category === "headers")!;
    assert.equal(headers.verdict, "regressed");
    assert.equal(headers.scoreDelta, -30);
  });

  test("refuses to compare audits of different targets", async () => {
    const url = "http://plain.test/";
    const other = await new SiteAuditor(new FakeProber({ [url]: [sample({ url, finalUrl: url, redirectChain: [url] })] }), new MockDahrAttestor(), {
      sampleGapMs: 0,
    }).audit({ url, samples: 1 });
    const mine = await runAudit();
    assert.throws(() => compareAudits(mine, other), /different targets/);
  });

  test("verifyDelta: genuine delta verifies end to end", async () => {
    const baseline = await runAudit({ timing: SLOW_TIMING });
    const current = await runAudit();
    const delta = compareAudits(baseline, current);
    const verdict = verifyDelta(clone(delta), clone(baseline), clone(current));
    assert.equal(verdict.valid, true, verdict.problems.join("; "));
  });

  test("verifyDelta: a doctored verdict or delta number is caught", async () => {
    const baseline = await runAudit();
    const current = await runAudit({ timing: SLOW_TIMING });
    const delta = compareAudits(baseline, current); // genuinely regressed

    const doctoredVerdict = clone(delta);
    doctoredVerdict.overall.verdict = "improved";
    const v1 = verifyDelta(doctoredVerdict, clone(baseline), clone(current));
    assert.equal(v1.valid, false);
    assert.ok(v1.problems.some((p) => /doctored/.test(p)));

    const doctoredNumber = clone(delta);
    doctoredNumber.categories.find((c) => c.category === "performance")!.scoreDelta = 75;
    const v2 = verifyDelta(doctoredNumber, clone(baseline), clone(current));
    assert.equal(v2.valid, false);
  });

  test("verifyDelta: a tampered underlying report invalidates the delta", async () => {
    const baseline = await runAudit();
    const current = await runAudit();
    const delta = compareAudits(baseline, current);
    const tamperedCurrent = clone(current);
    const sig = tamperedCurrent.provenance.evidence[0].attestation.signature;
    tamperedCurrent.provenance.evidence[0].attestation.signature = (sig.startsWith("A") ? "B" : "A") + sig.slice(1);
    const verdict = verifyDelta(clone(delta), clone(baseline), tamperedCurrent);
    assert.equal(verdict.valid, false);
    assert.ok(verdict.problems.some((p) => /^current report:/.test(p)));
  });
});

// ---------------------------------------------------------------------------
// Pay-on-improvement — the settleable outcome a pay-on-outcome contract pays on
// ---------------------------------------------------------------------------

describe("pay-on-improvement", () => {
  const OVERALL_GAIN: ImprovementTarget = { kind: "overall-score-gain", minGain: 20 };

  test("overall-score-gain: met when the attested overall clears the target", async () => {
    const baseline = await runAudit({ timing: SLOW_TIMING }); // overall 70
    const current = await runAudit(); // overall 100
    const result = evaluatePayOnImprovement(compareAudits(baseline, current), OVERALL_GAIN);
    assert.equal(result.met, true);
    assert.equal(result.observed, 30);
    assert.equal(result.required, 20);
    assert.match(result.detail, /overall rose \+30/);
  });

  test("overall-score-gain: not met when the gain falls short of the target", async () => {
    const baseline = await runAudit({ timing: SLOW_TIMING }); // overall 70
    const current = await runAudit({ timing: SLOW_TIMING }); // overall 70, no change
    const result = evaluatePayOnImprovement(compareAudits(baseline, current), OVERALL_GAIN);
    assert.equal(result.met, false);
    assert.equal(result.observed, 0);
  });

  test("anti-gaming: dropping a measured category cannot credit an overall gain", async () => {
    // Baseline measures everything (perf slow → overall 70). Current fails ALL
    // timing, so performance+headers+hygiene degrade and are EXCLUDED, leaving
    // only tls (100) → renormalized overall 100. The overall number rose +30,
    // but performance was measured in the baseline and is degraded now, so the
    // gain is not creditable.
    const baseline = await runAudit({ timing: SLOW_TIMING });
    const current = await runAudit({ timing: [{ fail: "blocked" }] });
    assert.equal(current.overallScore, 100);
    const result = evaluatePayOnImprovement(compareAudits(baseline, current), OVERALL_GAIN);
    assert.equal(result.met, false);
    assert.match(result.detail, /shrunk measurement set|degraded/);
  });

  test("category-score-gain: met on a real category improvement, not met when a side is degraded", async () => {
    const target: ImprovementTarget = { kind: "category-score-gain", category: "performance", minGain: 50 };
    const baseline = await runAudit({ timing: SLOW_TIMING }); // perf 25
    const current = await runAudit(); // perf 100
    assert.equal(evaluatePayOnImprovement(compareAudits(baseline, current), target).met, true);

    // Current perf degraded → not comparable, never "met".
    const degraded = await runAudit({ timing: [{ fail: "blocked" }] });
    const r = evaluatePayOnImprovement(compareAudits(baseline, degraded), target);
    assert.equal(r.met, false);
    assert.match(r.detail, /degraded in the current run/);
  });

  test("metric-drop-pct: met when p95 drops enough; not met when the metric is absent", async () => {
    const target: ImprovementTarget = { kind: "metric-drop-pct", category: "performance", metric: "p95TotalMs", minDropPct: 50 };
    const baseline = await runAudit({ timing: SLOW_TIMING }); // p95 3090
    const current = await runAudit(); // p95 177
    const met = evaluatePayOnImprovement(compareAudits(baseline, current), target);
    assert.equal(met.met, true);
    assert.ok(met.observed > 90); // ~94% drop

    // Wrong metric name → absent on both sides → not met.
    const absent: ImprovementTarget = { kind: "metric-drop-pct", category: "performance", metric: "nope", minDropPct: 1 };
    const r = evaluatePayOnImprovement(compareAudits(baseline, current), absent);
    assert.equal(r.met, false);
    assert.match(r.detail, /not present on both sides/);
  });

  test("verifyPayOnImprovement: a genuine outcome re-verifies from the two attested reports", async () => {
    const baseline = await runAudit({ timing: SLOW_TIMING });
    const current = await runAudit();
    const result = evaluatePayOnImprovement(compareAudits(baseline, current), OVERALL_GAIN);
    const v = verifyPayOnImprovement(clone(result), OVERALL_GAIN, clone(baseline), clone(current));
    assert.equal(v.valid, true, v.problems.join("; "));
    assert.equal(v.met, true);
  });

  test("verifyPayOnImprovement: a fudged `met`/observed is caught by recomputation", async () => {
    const baseline = await runAudit({ timing: SLOW_TIMING });
    const current = await runAudit({ timing: SLOW_TIMING }); // no real gain
    const honest = evaluatePayOnImprovement(compareAudits(baseline, current), OVERALL_GAIN);
    assert.equal(honest.met, false);

    const fudged = clone(honest);
    fudged.met = true;
    fudged.observed = 40;
    fudged.detail = "overall rose +40 points";
    const v = verifyPayOnImprovement(fudged, OVERALL_GAIN, clone(baseline), clone(current));
    assert.equal(v.valid, false);
    assert.ok(v.problems.some((p) => /doctored result/.test(p)), v.problems.join("; "));
  });

  test("verifyPayOnImprovement: a tampered delta cannot fake meeting the target", async () => {
    // The seller wants to be paid but the site did NOT improve. They hand over a
    // result claiming met:true. Verification recomputes the outcome from the two
    // reports' own attestations, so the lie cannot survive.
    const baseline = await runAudit(); // overall 100
    const current = await runAudit({ timing: SLOW_TIMING }); // overall 70 — regressed
    const forged = {
      version: 1 as const,
      url: baseline.url,
      target: OVERALL_GAIN,
      met: true,
      observed: 25,
      required: 20,
      detail: "overall rose +25 points",
    };
    const v = verifyPayOnImprovement(forged, OVERALL_GAIN, clone(baseline), clone(current));
    assert.equal(v.valid, false);
    assert.equal(v.met, false);
  });

  test("verifyPayOnImprovement: a tampered underlying report invalidates the outcome", async () => {
    const baseline = await runAudit({ timing: SLOW_TIMING });
    const current = await runAudit();
    const result = evaluatePayOnImprovement(compareAudits(baseline, current), OVERALL_GAIN);
    const tamperedCurrent = clone(current);
    tamperedCurrent.provenance.evidence[0].body = tamperedCurrent.provenance.evidence[0].body.replace('"totalMs":', '"totalMs":0,"x":');
    const v = verifyPayOnImprovement(clone(result), OVERALL_GAIN, clone(baseline), tamperedCurrent);
    assert.equal(v.valid, false);
    assert.ok(v.problems.some((p) => /^current report:/.test(p)));
  });
});
