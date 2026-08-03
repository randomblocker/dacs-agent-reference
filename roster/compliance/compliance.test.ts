/**
 * Compliance Screener tests — fully offline via FakeAttestedFetch + canned
 * list excerpts. node:test, run: npx tsx --test roster/compliance/compliance.test.ts
 */
import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FakeAttestedFetch, MockDahrAttestor, sha256Hex } from "../oracle-desk/attested-fetch.js";
import { cacheEntryPath, readCachedBody, writeCachedBody, CACHE_TTL_MS } from "./cache.js";
import {
  classifyScore,
  coreTokens,
  diceTokenOverlap,
  jaroWinkler,
  MATCH_THRESHOLD,
  normalizeName,
  POTENTIAL_THRESHOLD,
  prepareName,
  bestNameMatch,
  scoreNames,
  severityForMatch,
  stripDiacritics,
  tokenSortKey,
  transliterate,
  walletsEqual,
} from "./matching.js";
import { verifyScreening, writeScreeningReport, renderScreeningMarkdown } from "./report.js";
import { aggregateVerdict, loadAll, screenSubject } from "./screener.js";
import {
  decodeXmlEntities,
  extractDigitalCurrencyAddresses,
  fetchListBody,
  FIXTURE_ALT_CSV,
  FIXTURE_EDGAR_JSON,
  FIXTURE_EU_XML,
  FIXTURE_PEP_CSV,
  FIXTURE_SDN_CSV,
  FIXTURE_UK_CSV,
  FIXTURE_UN_XML,
  fixtureSources,
  parseCsv,
  parseEdgarTickers,
  parseEuConsolidatedXml,
  parseOpenSanctionsPepCsv,
  parseSdnCsv,
  parseUkHmtCsv,
  parseUnConsolidatedXml,
} from "./sources.js";
import type { ListSourcePort, ScreeningReport, SourceId, SourceInput } from "./types.js";
import { makeMatch } from "./types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function fixtureInputs(): Promise<SourceInput[]> {
  return loadAll(fixtureSources());
}

// ---------------------------------------------------------------------------
// CSV parsing
// ---------------------------------------------------------------------------

describe("CSV parser", () => {
  test("quoted fields with commas and escaped quotes", () => {
    const rows = parseCsv(`1,"SMITH, John ""JJ""",plain\r\n2,"multi\nline",x`);
    assert.deepEqual(rows, [
      ["1", 'SMITH, John "JJ"', "plain"],
      ["2", "multi\nline", "x"],
    ]);
  });

  test("trailing newline does not produce a phantom row", () => {
    assert.equal(parseCsv("a,b\nc,d\n").length, 2);
  });

  test("empty input parses to zero rows", () => {
    assert.deepEqual(parseCsv(""), []);
  });
});

// ---------------------------------------------------------------------------
// OFAC SDN parsing
// ---------------------------------------------------------------------------

describe("SDN parsing", () => {
  test("entries, programs, kinds, and -0- nulls", () => {
    const { entries, malformedRows } = parseSdnCsv(FIXTURE_SDN_CSV, FIXTURE_ALT_CSV);
    assert.equal(malformedRows, 0);
    const lazarus = entries.find((e) => e.name === "LAZARUS GROUP");
    assert.ok(lazarus);
    assert.equal(lazarus.entryId, "SDN-30393");
    assert.equal(lazarus.program, "DPRK3");
    assert.equal(lazarus.entryKind, "entity");
    const aero = entries.find((e) => e.name === "AEROCARIBBEAN AIRLINES");
    assert.ok(aero);
    assert.equal(aero.entryKind, "unknown"); // "-0-" type → unknown
  });

  test("ALT.CSV aliases merge onto the right entries", () => {
    const { entries } = parseSdnCsv(FIXTURE_SDN_CSV, FIXTURE_ALT_CSV);
    const lazarus = entries.find((e) => e.entryId === "SDN-30393")!;
    assert.deepEqual(lazarus.aliases, ["LABYRINTH CHOLLIMA", "HIDDEN COBRA"]);
  });

  test("digital-currency addresses extracted from remarks AND alt remarks", () => {
    const { addresses } = parseSdnCsv(FIXTURE_SDN_CSV, FIXTURE_ALT_CSV);
    const byAddr = new Map(addresses.map((a) => [a.address, a]));
    assert.ok(byAddr.has("1EfMVkxQQuZfBdocpJu6RUsCJvenQWbQyE")); // remarks, first of two
    assert.ok(byAddr.has("1G9CKRHA3mx22DoT1QyNYrh85VSQ19Y1em")); // remarks, second ("alt." prefix)
    assert.ok(byAddr.has("0x098B716B8Aaf21512996dC57EB0615e2383E2f96")); // ETH
    assert.ok(byAddr.has("bc1qexamplefixture000000000000000000000")); // from ALT.CSV remarks
    assert.equal(byAddr.get("1EfMVkxQQuZfBdocpJu6RUsCJvenQWbQyE")!.currency, "XBT");
    assert.equal(byAddr.get("0x098B716B8Aaf21512996dC57EB0615e2383E2f96")!.entryName, "EXAMPLESKI, Ivan Petrovich");
  });

  test("malformed rows are counted and skipped, header row is tolerated", () => {
    const csv = [
      `ent_num,SDN_Name,SDN_Type,Program,a,b,c,d,e,f,g,Remarks`, // header (row 0, not malformed)
      `1,"GOOD ENTITY","Entity","TEST",-0-,-0-,-0-,-0-,-0-,-0-,-0-,"-0-"`,
      `2,"TOO FEW COLUMNS","Entity"`, // <12 cols
      `not-a-number,"JUNK","Entity","TEST",-0-,-0-,-0-,-0-,-0-,-0-,-0-,"-0-"`, // non-numeric id
      `3,"-0-","Entity","TEST",-0-,-0-,-0-,-0-,-0-,-0-,-0-,"-0-"`, // null name
    ].join("\n");
    const { entries, malformedRows } = parseSdnCsv(csv);
    assert.equal(entries.length, 1);
    assert.equal(entries[0].name, "GOOD ENTITY");
    assert.equal(malformedRows, 3);
  });

  test("standalone address extraction handles multiple currencies per blob", () => {
    const found = extractDigitalCurrencyAddresses(
      "Digital Currency Address - XBT 12QtD5BFwRsdNsAZY76UVE1xyCGNTojH9h; alt. Digital Currency Address - ETH 0xfEC8A60023265364D066a1212fDE3930F6Ae8da7.",
      "SDN-1",
      "X",
    );
    assert.deepEqual(
      found.map((f) => [f.currency, f.address]),
      [
        ["XBT", "12QtD5BFwRsdNsAZY76UVE1xyCGNTojH9h"],
        ["ETH", "0xfEC8A60023265364D066a1212fDE3930F6Ae8da7"],
      ],
    );
  });
});

// ---------------------------------------------------------------------------
// UN XML parsing
// ---------------------------------------------------------------------------

describe("UN consolidated XML parsing", () => {
  test("individual names assemble from FIRST/SECOND names, entities from FIRST_NAME", () => {
    const { entries, malformedRows } = parseUnConsolidatedXml(FIXTURE_UN_XML);
    assert.equal(malformedRows, 0);
    const ri = entries.find((e) => e.entryId === "UN-KPi.033");
    assert.ok(ri);
    assert.equal(ri.name, "RI WON HO");
    assert.equal(ri.entryKind, "individual");
    assert.equal(ri.program, "DPRK");
    const komid = entries.find((e) => e.entryId === "UN-KPe.001");
    assert.ok(komid);
    assert.equal(komid.name, "KOREA MINING DEVELOPMENT TRADING CORPORATION");
    assert.equal(komid.entryKind, "entity");
  });

  test("aliases extracted, deduped, and never equal to the primary name", () => {
    const { entries } = parseUnConsolidatedXml(FIXTURE_UN_XML);
    const komid = entries.find((e) => e.entryId === "UN-KPe.001")!;
    assert.deepEqual(komid.aliases, ["KOMID", "CHANGGWANG SINYONG CORPORATION"]);
    const ri = entries.find((e) => e.entryId === "UN-KPi.033")!;
    assert.deepEqual(ri.aliases, ["Ri Won-ho"]);
  });

  test("a block with no extractable name is counted as malformed", () => {
    const xml = `<X><INDIVIDUAL><UN_LIST_TYPE>DPRK</UN_LIST_TYPE></INDIVIDUAL><INDIVIDUAL><FIRST_NAME>OK</FIRST_NAME></INDIVIDUAL></X>`;
    const { entries, malformedRows } = parseUnConsolidatedXml(xml);
    assert.equal(entries.length, 1);
    assert.equal(malformedRows, 1);
  });

  test("XML entities decode (incl. numeric) and THIRD_NAME participates", () => {
    assert.equal(decodeXmlEntities("A &amp; B &lt;&gt; &quot;C&quot; &#65;&#x42; &unknown;"), 'A & B <> "C" AB &unknown;');
    const xml = `<X><ENTITY><FIRST_NAME>SMITH &amp; SONS</FIRST_NAME></ENTITY><INDIVIDUAL><FIRST_NAME>ABU</FIRST_NAME><SECOND_NAME>BAKR</SECOND_NAME><THIRD_NAME>AL-EXAMPLE</THIRD_NAME></INDIVIDUAL></X>`;
    const { entries } = parseUnConsolidatedXml(xml);
    assert.ok(entries.some((e) => e.name === "SMITH & SONS"));
    assert.ok(entries.some((e) => e.name === "ABU BAKR AL-EXAMPLE"));
  });
});

// ---------------------------------------------------------------------------
// EDGAR parsing
// ---------------------------------------------------------------------------

describe("EDGAR tickers parsing", () => {
  test("happy path", () => {
    const { filers, malformedRows } = parseEdgarTickers(FIXTURE_EDGAR_JSON);
    assert.equal(malformedRows, 0);
    assert.deepEqual(filers.find((f) => f.ticker === "COIN"), { cik: "1679788", ticker: "COIN", title: "Coinbase Global, Inc." });
  });

  test("malformed rows are counted and skipped; non-object body throws", () => {
    const body = JSON.stringify({ "0": { cik_str: 1, ticker: "A", title: "Alpha" }, "1": { ticker: "B" }, "2": null, "3": "junk" });
    const { filers, malformedRows } = parseEdgarTickers(body);
    assert.equal(filers.length, 1);
    assert.equal(malformedRows, 3);
    assert.throws(() => parseEdgarTickers("[1,2,3]"), /expected a JSON object/);
  });
});

// ---------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------

describe("name normalization", () => {
  test("diacritics strip via NFD", () => {
    assert.equal(normalizeName("José-María Ñíguez"), "jose maria niguez");
    assert.equal(normalizeName("Müller, François"), "muller francois");
  });

  test("punctuation collapses and token order is neutralized by the sort key", () => {
    assert.equal(normalizeName("  LAZARUS   GROUP, "), "lazarus group");
    assert.equal(tokenSortKey("GROUP, LAZARUS"), tokenSortKey("Lazarus Group"));
    assert.notEqual(tokenSortKey("Lazarus Group"), tokenSortKey("Lazarus Grouped"));
  });
});

// ---------------------------------------------------------------------------
// Jaro-Winkler + thresholds
// ---------------------------------------------------------------------------

describe("Jaro-Winkler", () => {
  const close = (actual: number, expected: number) => assert.ok(Math.abs(actual - expected) < 0.001, `${actual} !≈ ${expected}`);

  test("known reference values", () => {
    close(jaroWinkler("martha", "marhta"), 0.9611);
    close(jaroWinkler("dixon", "dicksonx"), 0.8133);
    close(jaroWinkler("dwayne", "duane"), 0.84);
  });

  test("identity, disjoint, and empty edges", () => {
    assert.equal(jaroWinkler("abc", "abc"), 1);
    assert.equal(jaroWinkler("abc", "xyz"), 0);
    assert.equal(jaroWinkler("", "abc"), 0);
    assert.equal(jaroWinkler("", ""), 0);
  });
});

describe("threshold classification (boundary values)", () => {
  test("both thresholds, inclusive lower edge", () => {
    assert.equal(classifyScore(MATCH_THRESHOLD), "match"); // 0.93
    assert.equal(classifyScore(MATCH_THRESHOLD - 0.0001), "potential-match"); // 0.9299
    assert.equal(classifyScore(POTENTIAL_THRESHOLD), "potential-match"); // 0.85
    assert.equal(classifyScore(POTENTIAL_THRESHOLD - 0.0001), null); // 0.8499
    assert.equal(classifyScore(1), "match");
  });

  test("severityForMatch derives from method + score", () => {
    assert.equal(severityForMatch("exact", 1), "match");
    assert.equal(severityForMatch("wallet-exact", 1), "match");
    assert.equal(severityForMatch("edgar-registration", 0.9), "info");
    assert.equal(severityForMatch("jaro-winkler", 0.95), "match");
    assert.equal(severityForMatch("jaro-winkler", 0.88), "potential-match");
    assert.equal(severityForMatch("token-overlap", 0.5), null);
  });
});

// ---------------------------------------------------------------------------
// Scoring + alias sets
// ---------------------------------------------------------------------------

describe("name scoring", () => {
  test("exact after normalization + token sort", () => {
    const s = scoreNames("GROUP, LAZARUS", "Lazarus Group");
    assert.equal(s.method, "exact");
    assert.equal(s.score, 1);
  });

  test("fuzzy typo lands in jaro-winkler territory", () => {
    const s = scoreNames("Lazarus Gruop", "LAZARUS GROUP");
    assert.equal(s.method, "jaro-winkler");
    assert.ok(s.score >= POTENTIAL_THRESHOLD && s.score < 1);
  });

  test("token overlap wins when many tokens shared but strings differ", () => {
    const s = scoreNames("Korea Mining Development Trading Corporation Pyongyang", "KOREA MINING DEVELOPMENT TRADING CORPORATION");
    assert.ok(s.score >= POTENTIAL_THRESHOLD);
  });

  test("dice edge cases", () => {
    assert.equal(diceTokenOverlap(new Set(), new Set(["a"])), 0);
    assert.equal(diceTokenOverlap(new Set(["a", "b"]), new Set(["a", "b"])), 1);
  });

  test("alias sets match in BOTH directions", () => {
    // subject alias ↔ entry primary name
    const viaSubjectAlias = bestNameMatch([prepareName("Some Shell Co"), prepareName("Hidden Cobra")], ["LAZARUS GROUP", "HIDDEN COBRA"]);
    assert.ok(viaSubjectAlias);
    assert.equal(viaSubjectAlias.subjectName, "Hidden Cobra");
    assert.equal(viaSubjectAlias.method, "exact");
    // subject primary ↔ entry alias
    const viaEntryAlias = bestNameMatch([prepareName("Labyrinth Chollima")], ["LAZARUS GROUP", "LABYRINTH CHOLLIMA"]);
    assert.ok(viaEntryAlias);
    assert.equal(viaEntryAlias.entryName, "LABYRINTH CHOLLIMA");
    assert.equal(viaEntryAlias.method, "exact");
  });

  test("nothing above the potential threshold → null", () => {
    assert.equal(bestNameMatch([prepareName("Totally Unrelated Plumbing")], ["LAZARUS GROUP"]), null);
  });
});

describe("wallet matching", () => {
  test("exact and case-insensitive", () => {
    assert.ok(walletsEqual("0xABCdef0123", "0xabcDEF0123"));
    assert.ok(walletsEqual(" 1EfMVkxQQuZfBdocpJu6RUsCJvenQWbQyE ", "1EfMVkxQQuZfBdocpJu6RUsCJvenQWbQyE"));
  });

  test("near-miss (one character off) does NOT match", () => {
    assert.ok(!walletsEqual("1EfMVkxQQuZfBdocpJu6RUsCJvenQWbQyE", "1EfMVkxQQuZfBdocpJu6RUsCJvenQWbQyF"));
    assert.ok(!walletsEqual("", ""));
  });
});

// ---------------------------------------------------------------------------
// Screening + verdicts
// ---------------------------------------------------------------------------

describe("screening (fixture sources end to end)", () => {
  test("sanctioned entity → match on SDN and UN, with citations", async () => {
    const report = screenSubject({ name: "Lazarus Group", kind: "entity" }, await fixtureInputs());
    assert.equal(report.verdict, "match");
    const sdn = report.perSource.find((p) => p.sourceId === "ofac-sdn")!;
    assert.equal(sdn.status, "screened");
    assert.ok(sdn.status === "screened" && sdn.matches.some((m) => m.method === "exact" && m.severity === "match"));
    const un = report.perSource.find((p) => p.sourceId === "un-consolidated")!;
    assert.ok(un.status === "screened" && un.matches.length > 0);
    for (const per of report.perSource) {
      if (per.status !== "screened") continue;
      for (const m of per.matches) {
        assert.ok(m.citations.length > 0);
        for (const c of m.citations) assert.ok(report.listVersions.some((v) => v.id === c));
      }
    }
  });

  test("wallet subject → wallet-exact match, no fuzzy garbage from the address-as-name", async () => {
    const inputs = await fixtureInputs();
    const report = screenSubject(
      { name: "1EfMVkxQQuZfBdocpJu6RUsCJvenQWbQyE", walletAddress: "1EfMVkxQQuZfBdocpJu6RUsCJvenQWbQyE", kind: "wallet" },
      inputs,
    );
    assert.equal(report.verdict, "match");
    const sdn = report.perSource.find((p) => p.sourceId === "ofac-sdn")!;
    assert.ok(sdn.status === "screened");
    assert.equal(sdn.status === "screened" ? sdn.matches.length : -1, 1);
    assert.equal(sdn.status === "screened" ? sdn.matches[0].method : "", "wallet-exact");
    const un = report.perSource.find((p) => p.sourceId === "un-consolidated")!;
    assert.equal(un.status === "screened" ? un.matches.length : -1, 0);
  });

  test("clear subject → clear verdict WITH provable-absence citations per screened source", async () => {
    const report = screenSubject({ name: "Bluewater Example Consulting Ltd", kind: "entity" }, await fixtureInputs());
    assert.equal(report.verdict, "clear");
    for (const per of report.perSource) {
      assert.equal(per.status, "screened");
      if (per.status === "screened") {
        assert.ok(per.listRefs.length > 0, `${per.sourceId} must cite the list versions it screened against`);
        assert.equal(per.matches.length, 0);
      }
    }
    assert.ok(report.listVersions.length >= 4); // SDN+ALT+UN+EDGAR
  });

  test("EDGAR gives an info-level registration signal that never escalates the verdict", async () => {
    const report = screenSubject({ name: "Coinbase", kind: "entity" }, await fixtureInputs());
    const edgar = report.perSource.find((p) => p.sourceId === "sec-edgar")!;
    assert.ok(edgar.status === "screened" && edgar.matches.length === 1);
    if (edgar.status === "screened") {
      assert.equal(edgar.matches[0].severity, "info");
      assert.equal(edgar.matches[0].method, "edgar-registration");
      assert.match(edgar.matches[0].listEntryExcerpt, /Coinbase Global/);
    }
    assert.equal(report.verdict, "clear");
  });

  test("EDGAR only screens entity subjects; ticker equality also hits", async () => {
    const inputs = await fixtureInputs();
    const person = screenSubject({ name: "Coinbase", kind: "person" }, inputs);
    const edgarForPerson = person.perSource.find((p) => p.sourceId === "sec-edgar")!;
    assert.equal(edgarForPerson.status === "screened" ? edgarForPerson.matches.length : -1, 0);

    const byTicker = screenSubject({ name: "TSLA", kind: "entity" }, inputs);
    const edgar = byTicker.perSource.find((p) => p.sourceId === "sec-edgar")!;
    assert.ok(edgar.status === "screened" && edgar.matches.some((m) => m.score === 1));
  });

  test("EDGAR requires a STRONG correspondence — a mid-band fuzzy title is not a registration signal", async () => {
    // jw("apple bananas", "apple inc") ≈ 0.86: above the potential band but
    // neither a token subset nor ≥ MATCH_THRESHOLD, so no info match.
    const report = screenSubject({ name: "Apple Bananas", kind: "entity" }, await fixtureInputs());
    const edgar = report.perSource.find((p) => p.sourceId === "sec-edgar")!;
    assert.equal(edgar.status === "screened" ? edgar.matches.length : -1, 0);
  });

  test("verdict aggregation is worst-wins", () => {
    assert.equal(aggregateVerdict([]), "clear");
    assert.equal(aggregateVerdict(["info"]), "clear");
    assert.equal(aggregateVerdict(["info", "potential-match"]), "potential-match");
    assert.equal(aggregateVerdict(["potential-match", "match", "info"]), "match");
  });

  test("makeMatch throws on zero citations (citation-by-construction)", () => {
    assert.throws(
      () =>
        makeMatch({
          listEntryExcerpt: "x",
          matchedName: "x",
          subjectName: "x",
          score: 1,
          method: "exact",
          program: "TEST",
          severity: "match",
          citations: [],
        }),
      /zero citations/,
    );
  });
});

// ---------------------------------------------------------------------------
// Degraded (gap) mode
// ---------------------------------------------------------------------------

describe("degraded mode", () => {
  test("an unreachable source becomes a typed gap; the report still verifies", async () => {
    const failing: ListSourcePort = {
      id: "un-consolidated",
      load: async () => {
        throw new Error("connect ETIMEDOUT");
      },
    };
    const working = fixtureSources().filter((s) => s.id !== "un-consolidated");
    const inputs = await loadAll([...working, failing]);
    const report = screenSubject({ name: "Lazarus Group", kind: "entity" }, inputs);

    const gap = report.perSource.find((p) => p.sourceId === "un-consolidated")!;
    assert.equal(gap.status, "gap");
    assert.match(gap.status === "gap" ? gap.reason : "", /ETIMEDOUT/);
    assert.equal(report.verdict, "match"); // SDN still hit

    const verdict = verifyScreening(JSON.parse(JSON.stringify(report)));
    assert.ok(verdict.valid, verdict.problems.join("; "));
  });
});

// ---------------------------------------------------------------------------
// Report round-trip + tamper detection
// ---------------------------------------------------------------------------

describe("report round-trip and tamper detection", () => {
  async function emitAndRead(report: ScreeningReport): Promise<{ json: ScreeningReport; dir: string }> {
    const dir = await mkdtemp(join(tmpdir(), "compliance-report-"));
    const emitted = await writeScreeningReport(report, dir);
    const json = JSON.parse(await readFile(emitted.jsonPath, "utf8")) as ScreeningReport;
    return { json, dir };
  }

  test("emitted report round-trips through verifyScreening", async () => {
    const report = screenSubject({ name: "Lazarus Group", aliases: ["Hidden Cobra"], kind: "entity" }, await fixtureInputs());
    const { json, dir } = await emitAndRead(report);
    try {
      const verdict = verifyScreening(json);
      assert.ok(verdict.valid, verdict.problems.join("; "));
      assert.ok(verdict.attestationsChecked >= 4);
      assert.ok(verdict.matchesChecked >= 1);
      assert.equal(verdict.recomputedVerdict, "match");
      const md = renderScreeningMarkdown(json);
      assert.match(md, /Verdict: \*\*MATCH\*\*/);
      assert.match(md, /provable absence|match\(es\)/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("edited score is caught (severity re-derivation mismatch)", async () => {
    const report = screenSubject({ name: "Lazarus Group", kind: "entity" }, await fixtureInputs());
    const { json, dir } = await emitAndRead(report);
    try {
      const per = json.perSource.find((p) => p.sourceId === "ofac-sdn")!;
      assert.ok(per.status === "screened");
      if (per.status === "screened") per.matches[0] = { ...per.matches[0], method: "jaro-winkler", score: 0.86 }; // severity still "match"
      const verdict = verifyScreening(json);
      assert.ok(!verdict.valid);
      assert.ok(verdict.problems.some((p) => p.includes('derives "potential-match"')));
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("forged attestation signature is caught", async () => {
    const report = screenSubject({ name: "Bluewater Example Consulting Ltd", kind: "entity" }, await fixtureInputs());
    const { json, dir } = await emitAndRead(report);
    try {
      const sig = json.listVersions[0].attestation.signature;
      json.listVersions[0].attestation.signature = (sig[0] === "A" ? "B" : "A") + sig.slice(1);
      const verdict = verifyScreening(json);
      assert.ok(!verdict.valid);
      assert.ok(verdict.problems.some((p) => p.includes("attestation invalid")));
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("tampered list body (bodyHash edit) breaks the attestation digest", async () => {
    const report = screenSubject({ name: "Bluewater Example Consulting Ltd", kind: "entity" }, await fixtureInputs());
    const { json, dir } = await emitAndRead(report);
    try {
      json.listVersions[0].bodyHash = sha256Hex("a different list body");
      const verdict = verifyScreening(json);
      assert.ok(!verdict.valid);
      assert.ok(verdict.problems.some((p) => p.includes("attestation invalid")));
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("verdict downgrade is caught by recomputation", async () => {
    const report = screenSubject({ name: "Lazarus Group", kind: "entity" }, await fixtureInputs());
    const { json, dir } = await emitAndRead(report);
    try {
      json.verdict = "clear";
      const verdict = verifyScreening(json);
      assert.ok(!verdict.valid);
      assert.ok(verdict.problems.some((p) => p.includes('recompute to "match"')));
      assert.equal(verdict.recomputedVerdict, "match");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("stripped citations on a match are caught", async () => {
    const report = screenSubject({ name: "Lazarus Group", kind: "entity" }, await fixtureInputs());
    const json = JSON.parse(JSON.stringify(report)) as ScreeningReport;
    const per = json.perSource.find((p) => p.sourceId === "ofac-sdn")!;
    if (per.status === "screened") (per.matches[0] as { citations: string[] }).citations = [];
    const verdict = verifyScreening(json);
    assert.ok(!verdict.valid);
    assert.ok(verdict.problems.some((p) => p.includes("zero citations")));
  });

  test("stripped provable-absence listRefs on a clear source are caught", async () => {
    const report = screenSubject({ name: "Bluewater Example Consulting Ltd", kind: "entity" }, await fixtureInputs());
    const json = JSON.parse(JSON.stringify(report)) as ScreeningReport;
    const per = json.perSource[0];
    if (per.status === "screened") (per as { listRefs: string[] }).listRefs = [];
    const verdict = verifyScreening(json);
    assert.ok(!verdict.valid);
    assert.ok(verdict.problems.some((p) => p.includes("absence is unprovable")));
  });

  test("citation pointing at another source's list version is caught", async () => {
    const report = screenSubject({ name: "Lazarus Group", kind: "entity" }, await fixtureInputs());
    const json = JSON.parse(JSON.stringify(report)) as ScreeningReport;
    const edgarVersion = json.listVersions.find((v) => v.sourceId === "sec-edgar")!;
    const per = json.perSource.find((p) => p.sourceId === "ofac-sdn")!;
    if (per.status === "screened") (per.matches[0] as { citations: string[] }).citations = [edgarVersion.id];
    const verdict = verifyScreening(json);
    assert.ok(!verdict.valid);
    assert.ok(verdict.problems.some((p) => p.includes("belongs to source sec-edgar")));
  });

  test("non-report JSON is rejected structurally", () => {
    assert.equal(verifyScreening(null).valid, false);
    assert.equal(verifyScreening([1, 2]).valid, false);
    const junk = verifyScreening({ version: 2, subject: {}, perSource: "x", listVersions: "y" });
    assert.ok(!junk.valid);
    assert.ok(junk.problems.length >= 3);
  });
});

// ---------------------------------------------------------------------------
// Cache TTL
// ---------------------------------------------------------------------------

describe("cache", () => {
  const URL = "https://example.test/list.csv";

  test("fresh entry hits; stale entry misses", async () => {
    const dir = await mkdtemp(join(tmpdir(), "compliance-cache-"));
    try {
      const now = Date.now();
      const fetchedAt = new Date(now - 60 * 60 * 1000).toISOString(); // 1h old
      await writeCachedBody(dir, URL, fetchedAt, "body-bytes");
      const hit = await readCachedBody(dir, URL, CACHE_TTL_MS, now);
      assert.deepEqual(hit, { url: URL, fetchedAt, body: "body-bytes" });
      // Same entry read 25h later → stale.
      const stale = await readCachedBody(dir, URL, CACHE_TTL_MS, now + 24 * 60 * 60 * 1000);
      assert.equal(stale, null);
      // Fetched "in the future" → miss too.
      const future = await readCachedBody(dir, URL, CACHE_TTL_MS, now - 2 * 60 * 60 * 1000);
      assert.equal(future, null);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("corrupt or shape-invalid entries read as misses", async () => {
    const dir = await mkdtemp(join(tmpdir(), "compliance-cache-"));
    try {
      await writeFile(cacheEntryPath(dir, URL), "{not json", "utf8");
      assert.equal(await readCachedBody(dir, URL), null);
      await writeFile(cacheEntryPath(dir, URL), JSON.stringify({ version: 1, url: URL, fetchedAt: new Date().toISOString() }), "utf8"); // no body
      assert.equal(await readCachedBody(dir, URL), null);
      await writeFile(cacheEntryPath(dir, URL), JSON.stringify({ version: 1, url: "https://other.test/", fetchedAt: new Date().toISOString(), body: "x" }), "utf8");
      assert.equal(await readCachedBody(dir, URL), null);
      await writeFile(cacheEntryPath(dir, URL), JSON.stringify({ version: 9, url: URL, fetchedAt: new Date().toISOString(), body: "x" }), "utf8");
      assert.equal(await readCachedBody(dir, URL), null);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("fetchListBody: fresh → cached second read, attestation over cached bytes verifies with original fetchedAt", async () => {
    const dir = await mkdtemp(join(tmpdir(), "compliance-cache-"));
    try {
      const port = new FakeAttestedFetch([["list.csv", { status: 200, body: "the,list,body" }]]);
      const ctx = { port, cacheDir: dir, attestor: new MockDahrAttestor() };

      const first = await fetchListBody(ctx, "https://example.test/list.csv", "list.csv");
      assert.equal(first.download.mode, "fresh");

      const second = await fetchListBody(ctx, "https://example.test/list.csv", "list.csv");
      assert.equal(second.download.mode, "cached");
      assert.equal(second.body, "the,list,body");
      assert.equal(second.download.fetchedAt, first.download.fetchedAt); // original fetch time preserved
      assert.equal(second.download.bodyHash, sha256Hex("the,list,body"));
      assert.equal(port.requested.length, 1); // network touched exactly once

      const { verifyAttestedRecord } = await import("../oracle-desk/attested-fetch.js");
      const check = verifyAttestedRecord(second.download);
      assert.ok(check.valid, check.reason ?? "attestation over cached bytes should verify");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("fetchListBody: non-2xx throws (so url fallback / gap logic can engage)", async () => {
    const port = new FakeAttestedFetch([["missing.csv", { status: 404, body: "not found" }]]);
    await assert.rejects(fetchListBody({ port }, "https://example.test/missing.csv", "missing.csv"), /HTTP 404/);
  });
});

// ===========================================================================
// EU consolidated FSD XML v1.1 parsing (names + aliases live in ATTRIBUTES)
// ===========================================================================

describe("EU consolidated (FSD XML v1.1) parsing", () => {
  test("names + aliases from attributes, kind, program, and generationDate", () => {
    const { entries, malformedRows, publicationDate } = parseEuConsolidatedXml(FIXTURE_EU_XML);
    assert.equal(malformedRows, 0);
    assert.equal(publicationDate, "2026-06-05T15:51:25.849+02:00"); // root <export generationDate>

    const lazarus = entries.find((e) => e.entryId === "EU-EU.9999.1");
    assert.ok(lazarus);
    assert.equal(lazarus.name, "LAZARUS GROUP"); // first <nameAlias wholeName>
    assert.deepEqual(lazarus.aliases, ["APT38"]); // subsequent nameAlias
    assert.equal(lazarus.entryKind, "entity"); // subjectType code="enterprise"
    assert.equal(lazarus.program, "DPRK"); // regulation programme

    const person = entries.find((e) => e.entryId === "EU-EU.9999.2");
    assert.ok(person);
    assert.equal(person.entryKind, "individual"); // code="person"
    assert.equal(person.program, "SYR");
  });

  test("firstName/middleName/lastName compose when wholeName is absent", () => {
    const xml = `<export generationDate="2026-01-01">
      <sanctionEntity euReferenceNumber="EU.1">
        <subjectType code="person"/>
        <nameAlias firstName="Ada" middleName="B" lastName="Lovelace"/>
      </sanctionEntity>
    </export>`;
    const { entries } = parseEuConsolidatedXml(xml);
    assert.equal(entries.length, 1);
    assert.equal(entries[0].name, "Ada B Lovelace");
  });

  test("a sanctionEntity with no usable nameAlias is counted malformed, not fatal", () => {
    const xml = `<export generationDate="2026-01-01">
      <sanctionEntity euReferenceNumber="EU.BAD">
        <subjectType code="person"/>
        <nameAlias strong="true"/>
      </sanctionEntity>
      <sanctionEntity euReferenceNumber="EU.OK">
        <subjectType code="enterprise"/>
        <nameAlias wholeName="Good Entity Co"/>
      </sanctionEntity>
    </export>`;
    const { entries, malformedRows } = parseEuConsolidatedXml(xml);
    assert.equal(entries.length, 1);
    assert.equal(entries[0].name, "Good Entity Co");
    assert.equal(malformedRows, 1);
  });

  test("no root export tag → no publicationDate, still parses entities", () => {
    const xml = `<foo><sanctionEntity euReferenceNumber="EU.9"><nameAlias wholeName="X Y"/></sanctionEntity></foo>`;
    const { entries, publicationDate } = parseEuConsolidatedXml(xml);
    assert.equal(publicationDate, undefined);
    assert.equal(entries.length, 1);
  });
});

// ===========================================================================
// UK OFSI / HM Treasury ConList.csv (2022 format) parsing
// ===========================================================================

describe("UK OFSI ConList.csv parsing", () => {
  test("grouped rows collapse to one designation; Name-6-last ordering; Last Updated + regime", () => {
    const { entries, malformedRows, publicationDate } = parseUkHmtCsv(FIXTURE_UK_CSV);
    assert.equal(malformedRows, 0);
    assert.equal(publicationDate, "05/06/2026"); // "Last Updated" preamble

    const lazarus = entries.find((e) => e.entryId === "UK-90001");
    assert.ok(lazarus);
    assert.equal(lazarus.name, "LAZARUS GROUP");
    assert.deepEqual(lazarus.aliases, ["APT38"]); // AKA row, same Group ID
    assert.equal(lazarus.entryKind, "entity");
    assert.equal(lazarus.program, "Cyber (Global)"); // Regime column

    // Name 6 (family) is the FIRST column but is placed LAST per OFSI order.
    const person = entries.find((e) => e.entryId === "UK-90002");
    assert.ok(person);
    assert.equal(person.name, "Ivan EXAMPLEVICH");
    assert.deepEqual(person.aliases, ["Ivan EXAMPLEVIC"]);
    assert.equal(person.entryKind, "individual");
  });

  test("rows with empty Group ID or empty name are counted malformed and skipped", () => {
    const csv = [
      `Name 6,Name 1,Group Type,Alias Type,Regime,Group ID`,
      `,GOOD ENTITY,Entity,Primary name variation,Test,100`,
      `,,Entity,Primary name variation,Test,101`, // empty name
      `,ORPHAN,Entity,Primary name variation,Test,`, // empty Group ID
    ].join("\r\n");
    const { entries, malformedRows } = parseUkHmtCsv(csv);
    assert.equal(entries.length, 1);
    assert.equal(entries[0].name, "GOOD ENTITY");
    assert.equal(malformedRows, 2);
  });

  test("drifted/unrecognizable header → zero entries + all-malformed (never a false clear)", () => {
    const csv = [`col_a,col_b,col_c`, `1,foo,bar`, `2,baz,qux`].join("\r\n");
    const { entries, malformedRows } = parseUkHmtCsv(csv);
    assert.equal(entries.length, 0);
    assert.ok(malformedRows > 0); // the live floor trips → source degrades, not a clean pass
  });
});

// ===========================================================================
// OpenSanctions PEP "simple" CSV (AGGREGATOR) parsing
// ===========================================================================

describe("OpenSanctions PEP CSV parsing", () => {
  test("names, ;-separated aliases, schema→kind, dataset provenance as program", () => {
    const { entries, malformedRows } = parseOpenSanctionsPepCsv(FIXTURE_PEP_CSV);
    assert.equal(malformedRows, 0);

    const jens = entries.find((e) => e.entryId === "PEP-NK-PEPFIX01");
    assert.ok(jens);
    assert.equal(jens.name, "Jens Stoltenberg");
    assert.deepEqual(jens.aliases, ["Stoltenberg, Jens"]);
    assert.equal(jens.entryKind, "individual"); // schema Person
    assert.equal(jens.program, "PEP: Norway State Officials"); // dataset provenance

    const amara = entries.find((e) => e.entryId === "PEP-NK-PEPFIX02")!;
    assert.deepEqual(amara.aliases, ["Kone, Amara", "Amara D. Kone"]); // ";"-separated
  });

  test("empty-name rows are counted malformed and skipped", () => {
    const csv = [
      `"id","schema","name","aliases","dataset"`,
      `"1","Person","Real Person","","DS"`,
      `"2","Person","","","DS"`, // empty name
    ].join("\r\n");
    const { entries, malformedRows } = parseOpenSanctionsPepCsv(csv);
    assert.equal(entries.length, 1);
    assert.equal(malformedRows, 1);
  });

  test("no name column or header-only → zero entries (degrade, not crash)", () => {
    assert.deepEqual(parseOpenSanctionsPepCsv(`"id","dataset"\n"1","DS"`).entries, []);
    assert.deepEqual(parseOpenSanctionsPepCsv(`"id","schema","name"`).entries, []); // header only
  });

  test("non-Person schema maps to entity; missing schema → unknown", () => {
    const csv = [
      `"id","schema","name","dataset"`,
      `"1","Organization","Some PAC","DS"`,
      `"2","","Nameless Schema","DS"`,
    ].join("\r\n");
    const { entries } = parseOpenSanctionsPepCsv(csv);
    assert.equal(entries.find((e) => e.entryId === "PEP-1")!.entryKind, "entity");
    assert.equal(entries.find((e) => e.entryId === "PEP-2")!.entryKind, "unknown");
  });
});

// ===========================================================================
// Matching robustness — diacritics/transliteration, alias sets, order,
// company suffixes, and the JW/token thresholds at each boundary.
// ===========================================================================

describe("matching robustness", () => {
  test("diacritics normalize away and score as exact", () => {
    assert.equal(normalizeName("Łukasz Kowalski"), "lukasz kowalski");
    assert.equal(scoreNames("Łukasz Kowalski", "Lukasz Kowalski").method, "exact");
    assert.equal(scoreNames("José María", "Jose Maria").score, 1);
    assert.equal(scoreNames("Straße", "Strasse").score, 1); // ß → ss
  });

  test("stroked/ligature letters are transliterated, not deleted (no screening miss)", () => {
    // NFD does NOT decompose a stroked ł; the plain diacritic strip would leave
    // it and the [^a-z0-9] pass would DELETE it → "ukasz" (a miss). transliterate
    // maps it to its ASCII carrier first.
    assert.equal(stripDiacritics("łukasz".normalize("NFD")).replace(/[^a-z0-9]+/g, " ").trim(), "ukasz"); // the corruption guarded against
    assert.equal(normalizeName("Łukasz"), "lukasz"); // guard works
    assert.equal(transliterate("łøæœ ß þ ð đ ħ ı ĸ ŋ ſ"), "loaeoe ss th d d h i k n s");
  });

  test("alias sets match in BOTH directions across the new lists", () => {
    // subject alias ↔ EU entry primary name
    const a = bestNameMatch([prepareName("Some Cover Name"), prepareName("APT38")], ["LAZARUS GROUP", "APT38"]);
    assert.ok(a && a.subjectName === "APT38" && a.method === "exact");
    // subject primary ↔ entry alias
    const b = bestNameMatch([prepareName("APT38")], ["LAZARUS GROUP", "APT38"]);
    assert.ok(b && b.entryName === "APT38" && b.method === "exact");
  });

  test("name order is neutralized (comma-inverted and reordered tokens)", () => {
    assert.equal(scoreNames("Kone, Amara", "Amara Kone").score, 1);
    assert.equal(scoreNames("EXAMPLEVICH, Ivan", "Ivan Examplevich").score, 1);
  });

  test("company-suffix handling raises a real match but never fabricates one", () => {
    assert.equal(scoreNames("Acme Trading Ltd", "Acme Trading").score, 1); // suffix-stripped core → exact
    assert.equal(scoreNames("Acme Trading LLC", "Acme Trading Limited").score, 1);
    // Two unrelated names that share ONLY a legal suffix must NOT match.
    const shared = scoreNames("Acme Trading Ltd", "Beta Holdings Ltd");
    assert.ok(shared.score < POTENTIAL_THRESHOLD);
    assert.equal(classifyScore(shared.score), null);
    // coreTokens never empties a name that is nothing but a suffix.
    assert.deepEqual(coreTokens(["llc"]), ["llc"]);
  });

  test("JW/token scores classify at the match / potential / clear boundaries", () => {
    // match: fuzzy at or above MATCH_THRESHOLD (0.93)
    const m = scoreNames("Al-Qassam Brigades", "Al Qassam Brigade");
    assert.ok(m.score >= MATCH_THRESHOLD);
    assert.equal(classifyScore(m.score), "match");

    // potential-match: in [POTENTIAL, MATCH)
    for (const [a, b] of [["Petrov", "Petroff"], ["Smith", "Smyth"], ["Mohammad Reza", "Muhammad Rida"]]) {
      const s = scoreNames(a, b);
      assert.ok(s.score >= POTENTIAL_THRESHOLD && s.score < MATCH_THRESHOLD, `${a}/${b} = ${s.score}`);
      assert.equal(classifyScore(s.score), "potential-match");
    }

    // clear: below POTENTIAL_THRESHOLD → no match at all
    const clear = scoreNames("Acme Trading", "Zenith Logistics");
    assert.ok(clear.score < POTENTIAL_THRESHOLD);
    assert.equal(classifyScore(clear.score), null);
    assert.equal(bestNameMatch([prepareName("Acme Trading")], ["Zenith Logistics"]), null);
  });
});

// ===========================================================================
// Evidence-chain completeness over ALL fixture lists (incl. EU/UK/PEP) +
// re-verification rejections.
// ===========================================================================

describe("evidence chain (all six fixture lists)", () => {
  const ISO = /^\d{4}-\d{2}-\d{2}T/;
  const SHA256 = /^[0-9a-f]{64}$/;

  test("every screened list appears with an attested snapshot; clear cites its snapshot (provable absence)", async () => {
    // A subject clear on the sanctions/PEP lists but present on EDGAR — so most
    // sources are CLEAR and must still cite the attested version screened against.
    const report = screenSubjectOverAll("Bluewater Example Consulting Ltd", "entity", await fixtureInputs());

    // All six panel sources present exactly once, each screened (no gaps here).
    assert.deepEqual([...report.panel].sort(), [...SOURCE_PANEL].sort());
    for (const id of SOURCE_PANEL) {
      const per = report.perSource.find((p) => p.sourceId === id)!;
      assert.equal(per.status, "screened", `${id} should be screened`);
      if (per.status !== "screened") continue;
      // Provable absence: even a clear source cites the attested list version(s).
      assert.ok(per.listRefs.length > 0, `${id} must cite what it screened against`);
      for (const ref of per.listRefs) {
        const v = report.listVersions.find((lv) => lv.id === ref)!;
        assert.ok(v, `${id} listRef ${ref} resolves to a list version`);
        assert.equal(v.sourceId, id);
        assert.ok(["fresh", "cached", "fixture"].includes(v.mode));
        assert.match(v.bodyHash, SHA256); // snapshot content hash
        assert.match(v.fetchedAt, ISO);
        assert.ok(v.attestation && typeof v.attestation.signature === "string");
      }
    }

    // The lists whose format carries a declared version/date attest it.
    const eu = report.listVersions.find((v) => v.sourceId === "eu-consolidated")!;
    const uk = report.listVersions.find((v) => v.sourceId === "uk-hmt")!;
    assert.ok(eu.publicationDate, "EU version must carry its declared generationDate");
    assert.ok(uk.publicationDate, "UK version must carry its declared Last Updated date");
  });

  test("verifyScreening re-verifies the attestation of EVERY list version", async () => {
    const report = screenSubjectOverAll("Lazarus Group", "entity", await fixtureInputs());
    const json = roundTrip(report);
    const v = verifyScreening(json);
    assert.ok(v.valid, v.problems.join("; "));
    // one attestation checked per list version (SDN, ALT, UN, EU, UK, PEP, EDGAR = 7)
    assert.equal(v.attestationsChecked, report.listVersions.length);
    assert.ok(v.attestationsChecked >= 7);
  });

  test("a tampered score on a NEW-list (EU) match is rejected", async () => {
    const report = screenSubjectOverAll("Lazarus Group", "entity", await fixtureInputs());
    const json = roundTrip(report);
    const eu = json.perSource.find((p) => p.sourceId === "eu-consolidated")!;
    assert.ok(eu.status === "screened" && eu.matches.length > 0);
    if (eu.status === "screened") eu.matches[0] = { ...eu.matches[0], method: "jaro-winkler", score: 0.8 }; // severity still "match"
    const v = verifyScreening(json);
    assert.ok(!v.valid);
    assert.ok(v.problems.some((p) => p.includes("below the potential-match threshold") || p.includes("recompute")));
  });

  test("a forged attestation on the UK list version is rejected", async () => {
    const report = screenSubjectOverAll("Lazarus Group", "entity", await fixtureInputs());
    const json = roundTrip(report);
    const uk = json.listVersions.find((v) => v.sourceId === "uk-hmt")!;
    const sig = uk.attestation.signature;
    uk.attestation.signature = (sig[0] === "A" ? "B" : "A") + sig.slice(1);
    const v = verifyScreening(json);
    assert.ok(!v.valid);
    assert.ok(v.problems.some((p) => p.includes("attestation invalid")));
  });

  test("an ABSENT snapshot (a cited list version removed) is rejected — no evidence, no pass", async () => {
    const report = screenSubjectOverAll("Lazarus Group", "entity", await fixtureInputs());
    const json = roundTrip(report);
    const euVersion = json.listVersions.find((v) => v.sourceId === "eu-consolidated")!;
    json.listVersions = json.listVersions.filter((v) => v.id !== euVersion.id);
    const v = verifyScreening(json);
    assert.ok(!v.valid);
    assert.ok(v.problems.some((p) => p.includes("does not resolve to a list version")));
  });

  test("a sourceVerdict inconsistent with its own recorded matches is rejected", async () => {
    const report = screenSubjectOverAll("Lazarus Group", "entity", await fixtureInputs());
    const json = roundTrip(report);
    const uk = json.perSource.find((p) => p.sourceId === "uk-hmt")!;
    if (uk.status === "screened") (uk as { sourceVerdict: string }).sourceVerdict = "clear"; // it has a match
    const v = verifyScreening(json);
    assert.ok(!v.valid);
    assert.ok(v.problems.some((p) => p.includes("sourceVerdict") && p.includes("recompute")));
  });
});

// ===========================================================================
// THE CRITICAL INVARIANT — a failed/unreachable source becomes a typed GAP,
// and NEVER a false CLEAR. This is the compliance failure mode that matters.
// ===========================================================================

describe("no-false-clear invariant", () => {
  /** Build a panel where one source throws on load. */
  async function withOneFailing(failId: SourceId): Promise<SourceInput[]> {
    const failing: ListSourcePort = {
      id: failId,
      load: async () => {
        throw new Error("connect ECONNREFUSED");
      },
    };
    const working = fixtureSources().filter((s) => s.id !== failId);
    return loadAll([...working, failing]);
  }

  test("a clear subject + one unreachable source is a typed GAP and an INCOMPLETE (not all-clear) report", async () => {
    const inputs = await withOneFailing("eu-consolidated");
    const report = screenSubject({ name: "Bluewater Example Consulting Ltd", kind: "entity" }, inputs);

    const eu = report.perSource.find((p) => p.sourceId === "eu-consolidated")!;
    assert.equal(eu.status, "gap"); // NOT "screened", NOT a clear
    assert.notEqual(eu.status, "screened");
    assert.match(eu.status === "gap" ? eu.reason : "", /ECONNREFUSED/);

    // No source that failed is silently reported as a screened+clear.
    assert.ok(!report.perSource.some((p) => p.sourceId === "eu-consolidated" && p.status === "screened"));

    // The verdict may read "clear" on reachable lists, but the report is NOT a
    // clean all-clear: completeness is false and the verifier agrees.
    assert.equal(report.screeningComplete, false);
    const v = verifyScreening(roundTrip(report));
    assert.ok(v.valid, v.problems.join("; "));
    assert.equal(v.recomputedComplete, false);

    const md = renderScreeningMarkdown(report);
    assert.match(md, /INCOMPLETE/);
    assert.match(md, /GAP/);
    assert.match(md, /not an all-clear/);
  });

  test("verifyScreening REJECTS a gap forged into a screened+clear with empty listRefs (absence unprovable)", async () => {
    const inputs = await withOneFailing("uk-hmt");
    const report = screenSubject({ name: "Bluewater Example Consulting Ltd", kind: "entity" }, inputs);
    const json = roundTrip(report);
    const idx = json.perSource.findIndex((p) => p.sourceId === "uk-hmt");
    // Forge the gap into a "clean" screened result — but a gapped source has NO
    // attested list version to cite, so provable-absence has nothing to point at.
    json.perSource[idx] = { sourceId: "uk-hmt", status: "screened", listRefs: [], matches: [], sourceVerdict: "clear" } as never;
    const v = verifyScreening(json);
    assert.ok(!v.valid);
    assert.ok(v.problems.some((p) => p.includes("absence is unprovable") || p.includes("screeningComplete")));
  });

  test("verifyScreening REJECTS a forged clear-for-gap that borrows another source's attested snapshot", async () => {
    const inputs = await withOneFailing("uk-hmt");
    const report = screenSubject({ name: "Bluewater Example Consulting Ltd", kind: "entity" }, inputs);
    const json = roundTrip(report);
    const otherVersion = json.listVersions.find((v) => v.sourceId === "ofac-sdn")!;
    const idx = json.perSource.findIndex((p) => p.sourceId === "uk-hmt");
    json.perSource[idx] = { sourceId: "uk-hmt", status: "screened", listRefs: [otherVersion.id], matches: [], sourceVerdict: "clear" } as never;
    const v = verifyScreening(json);
    assert.ok(!v.valid);
    assert.ok(v.problems.some((p) => p.includes("belongs to source ofac-sdn") || p.includes("screeningComplete")));
  });

  test("verifyScreening REJECTS dropping the failed source entirely to fake a complete pass (expectedSources)", async () => {
    const inputs = await withOneFailing("uk-hmt");
    const report = screenSubject({ name: "Bluewater Example Consulting Ltd", kind: "entity" }, inputs);
    const json = roundTrip(report);
    // Attacker removes the gapped source from BOTH the panel and perSource so the
    // report looks internally consistent and complete — the buyer's known panel
    // (expectedSources) is what catches the missing list.
    json.panel = json.panel.filter((id) => id !== "uk-hmt");
    json.perSource = json.perSource.filter((p) => p.sourceId !== "uk-hmt");
    json.screeningComplete = true; // with UK erased, the remaining panel is all-screened
    const asClean = verifyScreening(json); // internally consistent now...
    assert.ok(asClean.valid);
    assert.equal(asClean.recomputedComplete, true);
    // ...but the commissioned panel included UK OFSI, so the omission is caught.
    const vsExpected = verifyScreening(json, ["uk-hmt"]);
    assert.ok(!vsExpected.valid);
    assert.ok(vsExpected.problems.some((p) => p.includes("uk-hmt") && p.includes("missing from the screening panel")));
  });

  test("even when OTHER lists hit, a gapped source never contributes a false clear", async () => {
    // Lazarus hits SDN/UN/EU/UK; fail the UK list. Verdict stays match, UK is a gap.
    const inputs = await withOneFailing("uk-hmt");
    const report = screenSubject({ name: "Lazarus Group", kind: "entity" }, inputs);
    assert.equal(report.verdict, "match");
    const uk = report.perSource.find((p) => p.sourceId === "uk-hmt")!;
    assert.equal(uk.status, "gap");
    assert.equal(report.screeningComplete, false); // a match report can still be INCOMPLETE
    const v = verifyScreening(roundTrip(report));
    assert.ok(v.valid, v.problems.join("; "));
    assert.equal(v.recomputedComplete, false);
  });
});

// ===========================================================================
// Worst-wins aggregation across all 5+ sanctions/PEP lists (+ EDGAR info).
// ===========================================================================

describe("worst-wins aggregation across lists", () => {
  test("a match on ANY single list dominates potential-matches on others", async () => {
    // "Ivan Examplevich" is a potential-match on SDN (Ivan Petrovich) but an
    // exact/near-exact match on EU and UK → overall MATCH.
    const report = screenSubject({ name: "Ivan Examplevich", kind: "person" }, await fixtureInputs());
    const sdn = report.perSource.find((p) => p.sourceId === "ofac-sdn")!;
    const eu = report.perSource.find((p) => p.sourceId === "eu-consolidated")!;
    assert.ok(sdn.status === "screened" && sdn.sourceVerdict === "potential-match");
    assert.ok(eu.status === "screened" && eu.sourceVerdict === "match");
    assert.equal(report.verdict, "match"); // worst wins
  });

  test("a PEP exact hit escalates to match; EDGAR/info never escalates", async () => {
    const inputs = await fixtureInputs();
    // PEP exact → match
    const pep = screenSubject({ name: "Jens Stoltenberg", kind: "person" }, inputs);
    const pepSrc = pep.perSource.find((p) => p.sourceId === "opensanctions-pep")!;
    assert.ok(pepSrc.status === "screened" && pepSrc.matches.some((m) => m.method === "pep-match" && m.severity === "match"));
    assert.equal(pep.verdict, "match");

    // EDGAR registration signal only → info, verdict stays clear.
    const edgarOnly = screenSubject({ name: "Coinbase", kind: "entity" }, inputs);
    const edgar = edgarOnly.perSource.find((p) => p.sourceId === "sec-edgar")!;
    assert.ok(edgar.status === "screened" && edgar.matches.some((m) => m.severity === "info"));
    assert.equal(edgar.status === "screened" ? edgar.sourceVerdict : "", "clear"); // info doesn't move the source verdict
    assert.equal(edgarOnly.verdict, "clear");
  });

  test("a fuzzy PEP hit is capped at potential-match (routes to EDD, never an auto-block)", async () => {
    // "Amara Diallo Kone" is an exact aggregator hit in the fixture, but a fuzzy
    // PEP score is capped: severityForMatch is the single source of truth.
    assert.equal(severityForMatch("pep-match", 0.99), "potential-match");
    assert.equal(severityForMatch("pep-match", 1), "match");
    assert.equal(severityForMatch("pep-match", 0.5), null);
  });
});

// ===========================================================================
// Cache TTL boundary (fresh / stale) — complements the existing cache suite.
// ===========================================================================

describe("cache TTL boundary", () => {
  const URL = "https://example.test/boundary.csv";

  test("age exactly at the TTL is still fresh; one ms past is stale", async () => {
    const dir = await mkdtemp(join(tmpdir(), "compliance-cache-"));
    try {
      const now = Date.now();
      const fetchedAt = new Date(now - CACHE_TTL_MS).toISOString(); // age == TTL
      await writeCachedBody(dir, URL, fetchedAt, "bytes");
      assert.ok(await readCachedBody(dir, URL, CACHE_TTL_MS, now), "age == TTL is fresh");
      assert.equal(await readCachedBody(dir, URL, CACHE_TTL_MS, now + 1), null, "age > TTL is stale");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// Shared helpers for the appended suites
// ---------------------------------------------------------------------------

const SOURCE_PANEL: readonly SourceId[] = ["ofac-sdn", "un-consolidated", "eu-consolidated", "uk-hmt", "opensanctions-pep", "sec-edgar"];

function screenSubjectOverAll(name: string, kind: "person" | "entity" | "wallet", inputs: SourceInput[]): ScreeningReport {
  return screenSubject({ name, kind }, inputs);
}

function roundTrip(report: ScreeningReport): ScreeningReport {
  return JSON.parse(JSON.stringify(report)) as ScreeningReport;
}

import { clearComplianceMemo, realSources, warmCompliance } from "./sources.js";

// ---------------------------------------------------------------------------
// In-process parsed-snapshot memo (the primary perf fix).
// ---------------------------------------------------------------------------

/** Same fixture bodies as fixtureSources(), but over a caller-supplied port set. */
function fixtureRoutes(): Array<[string, { status: number; body: string }]> {
  return [
    ["exports/SDN.CSV", { status: 200, body: FIXTURE_SDN_CSV }],
    ["exports/ALT.CSV", { status: 200, body: FIXTURE_ALT_CSV }],
    ["scsanctions.un.org", { status: 200, body: FIXTURE_UN_XML }],
    ["xmlFullSanctionsList", { status: 200, body: FIXTURE_EU_XML }],
    ["ConList.csv", { status: 200, body: FIXTURE_UK_CSV }],
    ["targets.simple.csv", { status: 200, body: FIXTURE_PEP_CSV }],
    ["company_tickers.json", { status: 200, body: FIXTURE_EDGAR_JSON }],
  ];
}

describe("parsed-snapshot memo", () => {
  test("cacheDir sources reuse the parsed snapshot until the memo is cleared", async () => {
    const dir = await mkdtemp(join(tmpdir(), "compliance-memo-"));
    clearComplianceMemo();
    try {
      const port = new FakeAttestedFetch(fixtureRoutes());
      const sources = realSources({ port, cacheDir: dir, fixture: true });
      const pep = sources.find((s) => s.id === "opensanctions-pep")!;

      const a = await pep.load();
      const b = await pep.load();
      // Same object reference → the second request did NOT re-read + re-parse.
      assert.equal(a, b, "second load should return the memoized snapshot (no re-parse)");

      clearComplianceMemo();
      const c = await pep.load();
      assert.notEqual(a, c, "after clearComplianceMemo the snapshot is parsed fresh");
      // Fresh parse is still behavior-identical.
      assert.deepEqual(c.entries, a.entries);
    } finally {
      clearComplianceMemo();
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("fixture (no cacheDir) sources are never memoized", async () => {
    clearComplianceMemo();
    const sources = fixtureSources();
    const pep = sources.find((s) => s.id === "opensanctions-pep")!;
    const a = await pep.load();
    const b = await pep.load();
    assert.notEqual(a, b, "no-cacheDir loads parse fresh each time (memo disabled)");
    assert.deepEqual(a.entries, b.entries);
  });

  test("warmCompliance parses every source without throwing and reports outcomes", async () => {
    clearComplianceMemo();
    const outcomes = await warmCompliance(fixtureSources());
    assert.equal(outcomes.length, 6);
    assert.ok(outcomes.every((o) => o.ok), `all fixture sources should warm ok: ${JSON.stringify(outcomes)}`);
  });
});
