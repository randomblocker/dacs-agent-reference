import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const files = execFileSync("git", ["ls-files", "--cached", "--others", "--exclude-standard", "-z"], { encoding: "utf8" })
  .split("\0")
  .filter(Boolean)
  .filter((file) => file !== "package-lock.json");

const checks = [
  ["private-key block", /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g],
  ["GitHub token", /\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g],
  ["Anthropic key", /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g],
  ["AWS access key", /\bAKIA[0-9A-Z]{16}\b/g],
  [
    "hardcoded secret variable",
    /(?:MNEMONIC|PRIVATE_KEY|API_KEY|API_SECRET|ACCESS_TOKEN|BEARER_TOKEN|GATEWAY_TOKEN)\s*=\s*["'`][^"'`\n]{8,}["'`]/g,
  ],
  [
    "secret environment fallback",
    /process\.env\.(?:[A-Z0-9_]*(?:MNEMONIC|PRIVATE_KEY|API_KEY|SECRET|TOKEN)[A-Z0-9_]*)\s*(?:\?\?|\|\|)\s*["'`][^"'`\n]{8,}["'`]/g,
  ],
  ["literal wallet passed to an adapter", /\bsecret\s*:\s*["'`](?:[a-z]{3,12}\s+){11,23}[a-z]{3,12}["'`]/g],
];

// Exact hashes of intentional scanner fixtures. A whole-file exemption would
// let a real credential hide beside a test case, so only these known matches
// are allowed. Values remain absent from this script and from its output.
const allowedFixtureHashes = new Set([
  "95d34dcdd6bc4be3c15151d0baea062c75def9d982caa3ce551060d5d822b657",
  "361255d1b0f4b0501318c5bf9cacb64e39fcdef9af60ced00fc8569fb76697f6",
  "f4c9ef8a9ba9b27cc20aff6d6b2ca6b2363947010d51c187c35a82fd27a5d28d",
  "2cd4d0f7f957046eebc64afd657c32c759724d973ab46ffed3eee9f85ec14b0b",
]);

function fixtureHash(file, label, value) {
  return createHash("sha256").update(`${file}\0${label}\0${value}`).digest("hex");
}

const findings = [];
for (const file of files) {
  let content;
  try {
    content = readFileSync(file, "utf8");
  } catch {
    continue;
  }
  for (const [label, pattern] of checks) {
    pattern.lastIndex = 0;
    for (const match of content.matchAll(pattern)) {
      if (allowedFixtureHashes.has(fixtureHash(file, label, match[0]))) continue;
      const line = content.slice(0, match.index).split("\n").length;
      findings.push(`${file}:${line}: ${label}`);
    }
  }
}

if (findings.length) {
  console.error("Potential committed secrets found (values intentionally suppressed):");
  for (const finding of findings) console.error(`- ${finding}`);
  process.exit(1);
}

console.log(`Secret hygiene check passed (${files.length} tracked files scanned; values never printed).`);
