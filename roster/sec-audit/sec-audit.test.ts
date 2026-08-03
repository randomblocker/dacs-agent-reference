/**
 * Security-Audit Agent tests — node:test + node:assert, fully offline
 * (fake registry, temp-dir targets, crafted file contents).
 *
 *   npx tsx --test roster/sec-audit/sec-audit.test.ts
 */
import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FakeRegistry } from "../dep-upgrade/registry.js";
import type { Advisory, RegistryPort } from "../dep-upgrade/types.js";
import { makeIdentity } from "../../src/identity.js";
import { auditPostedFiles } from "../dacs/wire/sec-audit.js";
import {
  DacsSellerAttestor,
  MockDahrAttestor,
  attestFileContent,
  canonicalJson,
  verifyFileRecord,
} from "./attest-files.js";
import { runAudit } from "./auditor.js";
import { auditDependencies, bareVersionFromRange, findDepLine } from "./deps-audit.js";
import { parseLlmOutput } from "./llm-pass.js";
import { verifyReport, writeReport } from "./report.js";
import {
  looksLikeSecretLiteral,
  runRepoFileRules,
  runRepoLineRules,
  shannonEntropy,
} from "./rules-repo.js";
import { blankCommentsAndStrings, extractFunctions, runSolidityRules } from "./rules-solidity.js";
import { applySuppressions, collectSuppressionMarkers, scanFileContent, walkFiles } from "./scanner.js";
import { makeFinding } from "./types.js";
import type { RawHit } from "./types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function ruleIdsOf(hits: RawHit[]): string[] {
  return hits.map((h) => h.ruleId);
}

function repoHits(text: string, path = "app.js"): RawHit[] {
  return runRepoLineRules(path, text);
}

function solHits(text: string, path = "C.sol"): RawHit[] {
  return runSolidityRules(path, text);
}

const LODASH_ADVISORIES: Advisory[] = [
  {
    id: "GHSA-35jh-r3h4-6jhm",
    severity: "high",
    title: "Command Injection in lodash",
    url: "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
    vulnerableVersions: "<4.17.21",
  },
  {
    id: "GHSA-29mw-wpgm-hmr9",
    severity: "moderate",
    title: "ReDoS in lodash",
    url: "https://github.com/advisories/GHSA-29mw-wpgm-hmr9",
    vulnerableVersions: "<4.17.21",
  },
];

function fakeLodashRegistry(): FakeRegistry {
  return new FakeRegistry(
    { lodash: { name: "lodash", latest: "4.17.21", versions: ["4.17.20", "4.17.21"] } },
    { lodash: LODASH_ADVISORIES },
  );
}

const PKG_JSON = `{
  "name": "t",
  "dependencies": {
    "lodash": "4.17.20"
  }
}`;

// ---------------------------------------------------------------------------
// Attested file records
// ---------------------------------------------------------------------------

describe("attested file records", () => {
  test("attest + verify round-trip; record is body-free", () => {
    const attestor = new MockDahrAttestor();
    const record = attestFileContent(attestor, "A1", "src/x.js", Buffer.from("hello"));
    assert.equal(record.size, 5);
    assert.equal(verifyFileRecord(record).valid, true);
    assert.ok(!("body" in record), "record must not carry the content");
  });

  test("tampered sha256 or path breaks verification", () => {
    const attestor = new MockDahrAttestor();
    const record = attestFileContent(attestor, "A1", "src/x.js", Buffer.from("hello"));
    assert.equal(verifyFileRecord({ ...record, sha256: "0".repeat(64) }).valid, false);
    assert.equal(verifyFileRecord({ ...record, path: "src/other.js" }).valid, false);
  });
});

describe("persistent seller content evidence", () => {
  const seller = makeIdentity("Auditor", 0x61);
  const otherSeller = makeIdentity("Impostor", 0x62);
  const posted = [{ path: "src/app.js", content: "eval(userInput);\n" }];

  test("production report signs every file hash and seal with the Auditor DID", async () => {
    const asciiOnlySigner = (bytes: Uint8Array) => {
      assert.match(Buffer.from(bytes).toString("utf8"), /^[0-9a-f]{64}$/);
      return seller.sign(bytes);
    };
    const report = await auditPostedFiles(
      posted,
      new DacsSellerAttestor({ primaryClaim: seller.did, sign: asciiOnlySigner }),
      () => new Date("2026-07-15T12:00:00.000Z"),
    );
    assert.ok(report.files.every((file) => file.attestation.scheme === "DACS-SELLER-ed25519"));
    assert.equal(report.seal.attestation.scheme, "DACS-SELLER-ed25519");
    assert.equal(report.files[0].attestation.publicKey, seller.did);

    const verdict = await verifyReport(report, undefined, seller.did);
    assert.equal(verdict.valid, true, verdict.problems.join("; "));
  });

  test("verification rejects a different DID or a tampered identity signature", async () => {
    const report = await auditPostedFiles(
      posted,
      new DacsSellerAttestor({ primaryClaim: seller.did, sign: seller.sign }),
    );
    const wrongDid = await verifyReport(report, undefined, otherSeller.did);
    assert.equal(wrongDid.valid, false);
    assert.match(wrongDid.problems.join("; "), /seller DID mismatch/);

    const tampered = structuredClone(report);
    tampered.files[0].attestation.signature = "AA";
    const badSignature = await verifyReport(tampered, undefined, seller.did);
    assert.equal(badSignature.valid, false);
    assert.match(badSignature.problems.join("; "), /invalid persistent seller signature/);
  });

  test("production verification rejects an otherwise-valid mock report", async () => {
    const report = await auditPostedFiles(posted, new MockDahrAttestor());
    const verdict = await verifyReport(report, undefined, seller.did);
    assert.equal(verdict.valid, false);
    assert.match(verdict.problems.join("; "), /expected persistent seller evidence/);
  });
});

// ---------------------------------------------------------------------------
// Repo rules — every rule fires on crafted content, not on benign near-misses
// ---------------------------------------------------------------------------

describe("repo rules", () => {
  test("secret-aws-key: fires on AKIA id, not on a shorter lookalike", () => {
    assert.ok(ruleIdsOf(repoHits('const k = "AKIAIOSFODNN7EXAMPLE";')).includes("secret-aws-key"));
    assert.ok(!ruleIdsOf(repoHits('const k = "AKIA1234";')).includes("secret-aws-key"));
  });

  test("secret-aws-key: fires even inside a comment (secrets are leaks anywhere)", () => {
    assert.ok(ruleIdsOf(repoHits("// old key: AKIAIOSFODNN7EXAMPLE")).includes("secret-aws-key"));
  });

  test("secret-assignment: high-entropy literal fires; env refs/placeholders/short don't", () => {
    assert.ok(ruleIdsOf(repoHits('const apiKey = "sk9fJ3nA8qLm2xTz71bQ4w";')).includes("secret-assignment"));
    assert.ok(!ruleIdsOf(repoHits("const apiKey = process.env.API_KEY;")).includes("secret-assignment"));
    assert.ok(!ruleIdsOf(repoHits('const apiKey = "your-api-key-goes-here";')).includes("secret-assignment"));
    assert.ok(!ruleIdsOf(repoHits('const password = "hunter2";')).includes("secret-assignment"));
    assert.ok(!ruleIdsOf(repoHits('const token = "AAAAAAAAAAAAAAAAAAAAAA";')).includes("secret-assignment"));
  });

  test("entropy/placeholder helpers", () => {
    assert.ok(shannonEntropy("aaaa") < 1);
    assert.ok(shannonEntropy("sk9fJ3nA8qLm2xTz71bQ4w") > 3.2);
    assert.equal(looksLikeSecretLiteral("EXAMPLE_KEY_1234567890"), false);
  });

  test("secret-pem-block: private key fires, public key doesn't", () => {
    assert.ok(ruleIdsOf(repoHits("-----BEGIN RSA PRIVATE KEY-----")).includes("secret-pem-block"));
    assert.ok(ruleIdsOf(repoHits("-----BEGIN OPENSSH PRIVATE KEY-----")).includes("secret-pem-block"));
    assert.ok(!ruleIdsOf(repoHits("-----BEGIN PUBLIC KEY-----")).includes("secret-pem-block"));
  });

  test("secret-mnemonic: exactly 12 or 24 words fire; 11 and 13 don't", () => {
    const words = (n: number) => Array.from({ length: n }, (_, i) => ["abandon", "ability", "coyote", "spice", "noodle", "arrow", "blouse", "pass", "rather", "sand", "meat", "divide", "auction"][i % 13]).join(" ");
    assert.ok(ruleIdsOf(repoHits(`const m = "${words(12)}";`)).includes("secret-mnemonic"));
    assert.ok(ruleIdsOf(repoHits(`const m = "${words(24)}";`)).includes("secret-mnemonic"));
    assert.ok(!ruleIdsOf(repoHits(`const m = "${words(11)}";`)).includes("secret-mnemonic"));
    assert.ok(!ruleIdsOf(repoHits(`const m = "${words(13)}";`)).includes("secret-mnemonic"));
  });

  test("code-eval: eval()/new Function() fire; evaluate() doesn't; comments skipped", () => {
    assert.ok(ruleIdsOf(repoHits("return eval(userInput);")).includes("code-eval"));
    assert.ok(ruleIdsOf(repoHits("const f = new Function(body);")).includes("code-eval"));
    assert.ok(!ruleIdsOf(repoHits("return evaluate(expr);")).includes("code-eval"));
    assert.ok(!ruleIdsOf(repoHits("// eval(userInput) was removed in v2")).includes("code-eval"));
  });

  test("code-exec-interpolation: template interpolation fires; static string doesn't", () => {
    assert.ok(ruleIdsOf(repoHits("exec(`ping -c 1 ${host}`, cb);")).includes("code-exec-interpolation"));
    assert.ok(ruleIdsOf(repoHits("execSync(`rm -rf ${dir}`);")).includes("code-exec-interpolation"));
    assert.ok(!ruleIdsOf(repoHits('exec("ls -la", cb);')).includes("code-exec-interpolation"));
    assert.ok(!ruleIdsOf(repoHits('execFile("ping", ["-c", "1", host]);')).includes("code-exec-interpolation"));
  });

  test("code-http-url: plaintext endpoint fires; https/localhost/xml-namespaces don't", () => {
    assert.ok(ruleIdsOf(repoHits('const u = "http://api.example.net/v1";')).includes("code-http-url"));
    assert.ok(!ruleIdsOf(repoHits('const u = "https://api.example.net/v1";')).includes("code-http-url"));
    assert.ok(!ruleIdsOf(repoHits('const u = "http://localhost:3000/dev";')).includes("code-http-url"));
    assert.ok(!ruleIdsOf(repoHits('const u = "http://127.0.0.1:8545";')).includes("code-http-url"));
    assert.ok(!ruleIdsOf(repoHits('svg.setAttribute("xmlns", "http://www.w3.org/2000/svg");')).includes("code-http-url"));
  });

  test("crypto-weak-hash: md5/sha1 fire; sha256 doesn't", () => {
    assert.ok(ruleIdsOf(repoHits('createHash("md5").update(x)')).includes("crypto-weak-hash"));
    assert.ok(ruleIdsOf(repoHits("createHmac('sha1', key)")).includes("crypto-weak-hash"));
    assert.ok(!ruleIdsOf(repoHits('createHash("sha256").update(x)')).includes("crypto-weak-hash"));
  });

  test("crypto-math-random-token: secret-context Math.random fires; jitter doesn't", () => {
    assert.ok(ruleIdsOf(repoHits("const sessionToken = Math.random().toString(36);")).includes("crypto-math-random-token"));
    assert.ok(!ruleIdsOf(repoHits("const jitterMs = Math.random() * 100;")).includes("crypto-math-random-token"));
  });

  test("tls-verification-disabled: both forms fire; enabled doesn't", () => {
    assert.ok(ruleIdsOf(repoHits("new https.Agent({ rejectUnauthorized: false })")).includes("tls-verification-disabled"));
    assert.ok(ruleIdsOf(repoHits('process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";')).includes("tls-verification-disabled"));
    assert.ok(!ruleIdsOf(repoHits("new https.Agent({ rejectUnauthorized: true })")).includes("tls-verification-disabled"));
  });

  test("secret-file-committed: .env/id_rsa/*.pem fire; .env.example and normal files don't", () => {
    assert.ok(ruleIdsOf(runRepoFileRules(".env")).includes("secret-file-committed"));
    assert.ok(ruleIdsOf(runRepoFileRules("config/.env.production")).includes("secret-file-committed"));
    assert.ok(ruleIdsOf(runRepoFileRules("keys/id_rsa")).includes("secret-file-committed"));
    assert.ok(ruleIdsOf(runRepoFileRules("certs/server.pem")).includes("secret-file-committed"));
    assert.equal(runRepoFileRules(".env.example").length, 0);
    assert.equal(runRepoFileRules("src/index.ts").length, 0);
  });
});

// ---------------------------------------------------------------------------
// Solidity rules
// ---------------------------------------------------------------------------

describe("solidity rules", () => {
  const wrap = (body: string) => `pragma solidity 0.8.20;\ncontract C {\n${body}\n}\n`;

  test("blankCommentsAndStrings preserves lines and blanks comments/strings", () => {
    const src = 'uint a; // tx.origin here\nstring s = "eval(x)";\n/* block\ncomment */ uint b;';
    const blanked = blankCommentsAndStrings(src);
    assert.equal(blanked.split("\n").length, src.split("\n").length);
    assert.ok(!blanked.includes("tx.origin"));
    assert.ok(!blanked.includes("eval"));
    assert.ok(blanked.includes("uint b;"));
  });

  test("extractFunctions maps headers, bodies, and line numbers", () => {
    const src = wrap("  function f(uint x) public {\n    x += 1;\n  }\n  function g() external view returns (uint) { return 1; }");
    const fns = extractFunctions(blankCommentsAndStrings(src));
    assert.deepEqual(fns.map((f) => f.name), ["f", "g"]);
    assert.equal(fns[0].headerLine, 3);
    assert.ok(fns[0].header.includes("public"));
  });

  test("sol-tx-origin: fires in code, not in comments, not on msg.sender", () => {
    assert.ok(ruleIdsOf(solHits(wrap("  function a() public view returns (bool) { return tx.origin == address(1); }"))).includes("sol-tx-origin"));
    assert.ok(!ruleIdsOf(solHits(wrap("  // tx.origin must never be used\n  function a() public {}"))).includes("sol-tx-origin"));
    assert.ok(!ruleIdsOf(solHits(wrap("  function a() public view returns (bool) { return msg.sender == address(1); }"))).includes("sol-tx-origin"));
  });

  test("sol-unchecked-call: bare .send/.call fire; checked forms don't", () => {
    assert.ok(ruleIdsOf(solHits(wrap("  function s(address payable to) external {\n    to.send(1);\n  }"))).includes("sol-unchecked-call"));
    assert.ok(!ruleIdsOf(solHits(wrap('  function s(address payable to) external {\n    (bool ok, ) = to.call{value: 1}("");\n    require(ok);\n  }'))).includes("sol-unchecked-call"));
    assert.ok(!ruleIdsOf(solHits(wrap("  function s(address payable to) external {\n    require(to.send(1));\n  }"))).includes("sol-unchecked-call"));
  });

  test("sol-delegatecall-variable: variable target fires; ALL_CAPS constant doesn't", () => {
    assert.ok(ruleIdsOf(solHits(wrap("  function d(address target, bytes memory data) external {\n    (bool ok, ) = target.delegatecall(data);\n    require(ok);\n  }"))).includes("sol-delegatecall-variable"));
    assert.ok(!ruleIdsOf(solHits(wrap("  address constant IMPL = address(1);\n  function d(bytes memory data) external {\n    (bool ok, ) = IMPL.delegatecall(data);\n    require(ok);\n  }"))).includes("sol-delegatecall-variable"));
  });

  test("sol-selfdestruct: fires on the call, not on the word", () => {
    assert.ok(ruleIdsOf(solHits(wrap("  function k() external { selfdestruct(payable(msg.sender)); }"))).includes("sol-selfdestruct"));
    assert.ok(!ruleIdsOf(solHits(wrap("  uint selfdestructCount;"))).includes("sol-selfdestruct"));
  });

  test("sol-reentrancy: call-then-write fires; write-then-call doesn't", () => {
    const bad = wrap('  mapping(address => uint) balances;\n  function w(uint amt) external {\n    (bool ok, ) = msg.sender.call{value: amt}("");\n    require(ok);\n    balances[msg.sender] -= amt;\n  }');
    const good = wrap('  mapping(address => uint) balances;\n  function w(uint amt) external {\n    balances[msg.sender] -= amt;\n    (bool ok, ) = msg.sender.call{value: amt}("");\n    require(ok);\n  }');
    assert.ok(ruleIdsOf(solHits(bad)).includes("sol-reentrancy"));
    assert.ok(!ruleIdsOf(solHits(good)).includes("sol-reentrancy"));
  });

  test("sol-floating-pragma: ^ fires; pinned doesn't", () => {
    assert.ok(ruleIdsOf(solHits("pragma solidity ^0.8.0;\ncontract C {}")).includes("sol-floating-pragma"));
    assert.ok(!ruleIdsOf(solHits("pragma solidity 0.8.20;\ncontract C {}")).includes("sol-floating-pragma"));
  });

  test("sol-timestamp-condition: require/if fire; plain read doesn't", () => {
    assert.ok(ruleIdsOf(solHits(wrap("  function t(uint d) external view { require(block.timestamp > d, \"early\"); }"))).includes("sol-timestamp-condition"));
    assert.ok(ruleIdsOf(solHits(wrap("  function t(uint d) external view returns (bool) { if (block.timestamp > d) { return true; } return false; }"))).includes("sol-timestamp-condition"));
    assert.ok(!ruleIdsOf(solHits(wrap("  function t() external view returns (uint) { uint x = block.timestamp; return x; }"))).includes("sol-timestamp-condition"));
  });

  test("sol-missing-access-control: unguarded owner write fires; modifier/require/msg.sender-index don't", () => {
    const bare = wrap("  address owner;\n  function setOwner(address n) public {\n    owner = n;\n  }");
    const withModifier = wrap("  address owner;\n  function setOwner(address n) public onlyOwner {\n    owner = n;\n  }");
    const withRequire = wrap("  address owner;\n  function setOwner(address n) public {\n    require(msg.sender == owner);\n    owner = n;\n  }");
    const selfBalance = wrap("  mapping(address => uint) balances;\n  function deposit() external payable {\n    balances[msg.sender] += msg.value;\n  }");
    const otherBalance = wrap("  mapping(address => uint) balances;\n  function grant(address to) external {\n    balances[to] += 1 ether;\n  }");
    assert.ok(ruleIdsOf(solHits(bare)).includes("sol-missing-access-control"));
    assert.ok(!ruleIdsOf(solHits(withModifier)).includes("sol-missing-access-control"));
    assert.ok(!ruleIdsOf(solHits(withRequire)).includes("sol-missing-access-control"));
    assert.ok(!ruleIdsOf(solHits(selfBalance)).includes("sol-missing-access-control"));
    assert.ok(ruleIdsOf(solHits(otherBalance)).includes("sol-missing-access-control"));
  });
});

// ---------------------------------------------------------------------------
// Suppressions
// ---------------------------------------------------------------------------

describe("suppressions", () => {
  test("audit-ok on the hit line or the line above suppresses AND counts", () => {
    const text = [
      "// audit-ok code-eval — reviewed, sandboxed input",
      "eval(a);",
      "eval(b); // audit-ok code-eval",
      "eval(c);",
    ].join("\n");
    const hits = runRepoLineRules("x.js", text);
    const { kept, suppressed } = applySuppressions(hits, collectSuppressionMarkers(text));
    assert.equal(suppressed.length, 2);
    assert.deepEqual(suppressed.map((s) => s.line), [2, 3]);
    assert.deepEqual(kept.map((h) => h.line), [4]);
    assert.ok(suppressed.every((s) => s.ruleId === "code-eval"));
  });

  test("audit-ok for a different rule does NOT suppress", () => {
    const text = "eval(a); // audit-ok code-http-url";
    const hits = runRepoLineRules("x.js", text);
    const { kept, suppressed } = applySuppressions(hits, collectSuppressionMarkers(text));
    assert.equal(kept.length, 1);
    assert.equal(suppressed.length, 0);
  });
});

// ---------------------------------------------------------------------------
// Citation-by-construction
// ---------------------------------------------------------------------------

describe("citation-by-construction", () => {
  test("makeFinding throws on zero citations", () => {
    assert.throws(
      () =>
        makeFinding({
          id: "F1",
          ruleId: "code-eval",
          severity: "high",
          file: "x.js",
          line: 1,
          excerpt: "eval(a)",
          rationale: "r",
          citations: [],
          origin: "deterministic",
        }),
      /zero citations/,
    );
  });
});

// ---------------------------------------------------------------------------
// Dependency audit (fake registry)
// ---------------------------------------------------------------------------

describe("dependency audit", () => {
  test("vulnerable pin produces one hit citing package.json, max severity, all advisory ids", async () => {
    const result = await auditDependencies(PKG_JSON, undefined, fakeLodashRegistry(), "canned");
    assert.equal(result.mode, "canned");
    assert.equal(result.hits.length, 1);
    const hit = result.hits[0];
    assert.equal(hit.ruleId, "dep-vulnerable");
    assert.equal(hit.severity, "high"); // max of high + moderate
    assert.equal(hit.file, "package.json");
    assert.equal(hit.line, 4);
    assert.ok(hit.rationale.includes("GHSA-35jh-r3h4-6jhm"));
    assert.ok(hit.rationale.includes("GHSA-29mw-wpgm-hmr9"));
  });

  test("clean version produces no hit (satisfies filter applied)", async () => {
    const pkg = PKG_JSON.replace("4.17.20", "4.17.21");
    const result = await auditDependencies(pkg, undefined, fakeLodashRegistry(), "canned");
    assert.equal(result.hits.length, 0);
  });

  test("no package.json → skipped silently", async () => {
    const result = await auditDependencies(null, undefined, fakeLodashRegistry(), "canned");
    assert.equal(result.mode, "skipped");
    assert.equal(result.hits.length, 0);
  });

  test("unreachable endpoint degrades gracefully", async () => {
    const broken: RegistryPort = {
      getPackument: async () => {
        throw new Error("offline");
      },
      getAdvisories: async () => {
        throw new Error("ENOTFOUND registry.npmjs.org");
      },
    };
    const result = await auditDependencies(PKG_JSON, undefined, broken, "live");
    assert.equal(result.mode, "unreachable");
    assert.equal(result.hits.length, 0);
    assert.ok(result.note.includes("ENOTFOUND"));
  });

  test("bareVersionFromRange handles pins/carets/tildes and rejects complex ranges", () => {
    assert.equal(bareVersionFromRange("4.17.20"), "4.17.20");
    assert.equal(bareVersionFromRange("^4.17.20"), "4.17.20");
    assert.equal(bareVersionFromRange("~1.2.3"), "1.2.3");
    assert.equal(bareVersionFromRange(">=1.0.0 <2.0.0"), null);
    assert.equal(bareVersionFromRange("*"), null);
  });

  test("findDepLine pins the declaration line", () => {
    assert.equal(findDepLine(PKG_JSON, "lodash").line, 4);
  });
});

// ---------------------------------------------------------------------------
// Scanner: walk skips, mode dispatch
// ---------------------------------------------------------------------------

describe("scanner", () => {
  test("walker skips node_modules, .git, and out", async () => {
    const dir = await mkdtemp(join(tmpdir(), "sec-audit-walk-"));
    try {
      await mkdir(join(dir, "node_modules"), { recursive: true });
      await mkdir(join(dir, ".git"), { recursive: true });
      await mkdir(join(dir, "out"), { recursive: true });
      await mkdir(join(dir, "src"), { recursive: true });
      await writeFile(join(dir, "node_modules", "evil.js"), "eval(x);");
      await writeFile(join(dir, ".git", "config"), "");
      await writeFile(join(dir, "out", "old.json"), "{}");
      await writeFile(join(dir, "src", "ok.js"), "const a = 1;");
      const files = await walkFiles(dir);
      assert.deepEqual(files, ["src/ok.js"]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("mode dispatch: solidity mode ignores js content, repo mode ignores .sol", () => {
    const js = Buffer.from("eval(x);");
    const sol = Buffer.from("pragma solidity ^0.8.0;\ncontract C {}");
    assert.equal(scanFileContent("a.js", js, "solidity").hits.length, 0);
    assert.equal(scanFileContent("C.sol", sol, "repo").hits.length, 0);
    assert.ok(scanFileContent("a.js", js, "repo").hits.length > 0);
    assert.ok(scanFileContent("C.sol", sol, "solidity").hits.length > 0);
    assert.ok(scanFileContent("a.js", js, "auto").hits.length > 0);
    assert.ok(scanFileContent("C.sol", sol, "auto").hits.length > 0);
  });

  test("binary content is attest-only (no scan, no crash)", () => {
    const binary = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x00, 0x01, 0x02]);
    const result = scanFileContent("blob.js", binary, "auto");
    assert.equal(result.scanned, false);
    assert.equal(result.hits.length, 0);
  });
});

// ---------------------------------------------------------------------------
// End-to-end: audit → report → verify → tamper → drift
// ---------------------------------------------------------------------------

describe("report round-trip", () => {
  async function makeTarget(): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), "sec-audit-e2e-"));
    await writeFile(join(dir, "app.js"), 'const t = eval(input);\nconst u = "http://api.example.net";\n');
    await writeFile(
      join(dir, "V.sol"),
      "pragma solidity ^0.8.0;\ncontract V {\n  function k() external { selfdestruct(payable(msg.sender)); }\n}\n",
    );
    await writeFile(join(dir, "package.json"), PKG_JSON);
    return dir;
  }

  test("audit report verifies (attestations, citations, stats, seal) and re-hash matches", async () => {
    const dir = await makeTarget();
    try {
      const report = await runAudit({ targetDir: dir }, { registry: fakeLodashRegistry(), registryLabel: "canned" });
      assert.equal(report.files.length, 3);
      assert.ok(report.findings.length >= 4); // eval, http, pragma, selfdestruct, dep
      assert.ok(report.findings.every((f) => f.origin === "deterministic"));
      assert.equal(report.deps.mode, "canned");

      const outDir = await mkdtemp(join(tmpdir(), "sec-audit-out-"));
      try {
        const emitted = await writeReport(report, outDir);
        const parsed = JSON.parse(JSON.stringify(report)) as unknown;
        const verdict = await verifyReport(parsed, dir);
        assert.equal(verdict.valid, true, verdict.problems.join("; "));
        assert.equal(verdict.attestationsChecked, 4); // 3 files + seal
        assert.equal(verdict.filesRehashed, 3);
        assert.deepEqual(verdict.driftedFiles, []);
        assert.ok(emitted.jsonPath.endsWith("report.json"));
      } finally {
        await rm(outDir, { recursive: true, force: true });
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("tampering a finding after emission breaks the seal", async () => {
    const dir = await makeTarget();
    try {
      const report = await runAudit({ targetDir: dir }, { registry: fakeLodashRegistry(), registryLabel: "canned" });
      const tampered = JSON.parse(JSON.stringify(report)) as { findings: Array<{ severity: string }> };
      tampered.findings[0].severity = "info";
      const verdict = await verifyReport(tampered);
      assert.equal(verdict.valid, false);
      assert.ok(verdict.problems.some((p) => p.includes("sealed core hash")));
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("dropping a citation is caught even before the seal", async () => {
    const dir = await makeTarget();
    try {
      const report = await runAudit({ targetDir: dir }, { registry: fakeLodashRegistry(), registryLabel: "canned" });
      const tampered = JSON.parse(JSON.stringify(report)) as { findings: Array<{ citations: string[] }> };
      tampered.findings[0].citations = [];
      const verdict = await verifyReport(tampered);
      assert.equal(verdict.valid, false);
      assert.ok(verdict.problems.some((p) => p.includes("zero citations")));
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("file drift after the audit is flagged by the re-hash check", async () => {
    const dir = await makeTarget();
    try {
      const report = await runAudit({ targetDir: dir }, { registry: fakeLodashRegistry(), registryLabel: "canned" });
      await writeFile(join(dir, "app.js"), "const clean = 1;\n"); // rewrite AFTER the audit
      const verdict = await verifyReport(JSON.parse(JSON.stringify(report)), dir);
      assert.equal(verdict.valid, false);
      assert.deepEqual(verdict.driftedFiles, ["app.js"]);
      assert.ok(verdict.problems.some((p) => p.includes("drift")));
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("ruleStats mismatch is caught", async () => {
    const dir = await makeTarget();
    try {
      const report = await runAudit({ targetDir: dir }, { registry: fakeLodashRegistry(), registryLabel: "canned" });
      const tampered = JSON.parse(JSON.stringify(report)) as { ruleStats: Array<{ id: string; count: number }> };
      const evalStat = tampered.ruleStats.find((r) => r.id === "code-eval");
      assert.ok(evalStat);
      evalStat.count = 0;
      const verdict = await verifyReport(tampered);
      assert.equal(verdict.valid, false);
      assert.ok(verdict.problems.some((p) => p.includes("ruleStats")));
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("suppression flows into the report and the suppressed line has no finding", async () => {
    const dir = await mkdtemp(join(tmpdir(), "sec-audit-sup-"));
    try {
      await writeFile(join(dir, "a.js"), "// audit-ok code-eval — reviewed\neval(x);\neval(y);\n");
      const report = await runAudit({ targetDir: dir });
      assert.equal(report.suppressions.length, 1);
      assert.equal(report.suppressions[0].line, 2);
      assert.deepEqual(report.findings.filter((f) => f.ruleId === "code-eval").map((f) => f.line), [3]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("canonicalJson is key-order independent", () => {
    assert.equal(canonicalJson({ b: 1, a: [{ y: 2, x: 3 }] }), canonicalJson({ a: [{ x: 3, y: 2 }], b: 1 }));
  });
});

// ---------------------------------------------------------------------------
// LLM pass (offline: parser + segregation via a fake pass)
// ---------------------------------------------------------------------------

describe("llm pass", () => {
  test("parseLlmOutput keeps well-shaped entries, drops unknown files, clamps severity", () => {
    const stdout = `Here you go:\n[
      {"ruleId":"llm-open-redirect","severity":"medium","file":"a.js","line":3,"excerpt":"res.redirect(q)","rationale":"unvalidated redirect"},
      {"ruleId":"llm-x","severity":"apocalyptic","file":"a.js","line":1,"excerpt":"","rationale":"weird severity"},
      {"ruleId":"llm-ghost","severity":"high","file":"not-scanned.js","line":1,"excerpt":"","rationale":"drop me"},
      {"nonsense":true}
    ]`;
    const hits = parseLlmOutput(stdout, ["a.js"]);
    assert.equal(hits.length, 2);
    assert.equal(hits[0].ruleId, "llm-open-redirect");
    assert.equal(hits[1].severity, "info"); // clamped
  });

  test("garbage output → no suggestions", () => {
    assert.deepEqual(parseLlmOutput("I cannot help with that.", ["a.js"]), []);
    assert.deepEqual(parseLlmOutput('{"not":"an array"}', ["a.js"]), []);
  });

  test("fake pass: suggestions land segregated as llm-suggested; deterministic set unchanged; throwing pass degrades", async () => {
    const dir = await mkdtemp(join(tmpdir(), "sec-audit-llm-"));
    try {
      await writeFile(join(dir, "a.js"), "eval(x);\n");
      const withLlm = await runAudit(
        { targetDir: dir },
        {
          llm: async (input) => [
            { ruleId: "llm-guess", severity: "low", file: input.scannedPaths[0], line: 1, excerpt: "eval(x);", rationale: "candidate only" },
          ],
        },
      );
      assert.equal(withLlm.llmFindings.length, 1);
      assert.equal(withLlm.llmFindings[0].origin, "llm-suggested");
      assert.equal(withLlm.llmFindings[0].id, "L1");
      assert.ok(withLlm.findings.every((f) => f.origin === "deterministic"));

      const without = await runAudit({ targetDir: dir });
      assert.deepEqual(without.findings.map((f) => f.ruleId), withLlm.findings.map((f) => f.ruleId));

      const throwing = await runAudit(
        { targetDir: dir },
        {
          llm: async () => {
            throw new Error("cli exploded");
          },
        },
      );
      assert.deepEqual(throwing.llmFindings, []);
      assert.deepEqual(throwing.findings.map((f) => f.ruleId), without.findings.map((f) => f.ruleId));
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
