/**
 * Normalizer conformance — the DETERMINISM GATE (D1/D3/D4).
 *
 *   npx tsx --test src/agents/normalize.test.ts
 *
 * The crux proof: two RAW check outputs that differ ONLY in provably-non-
 * deterministic noise (timestamps, durations, npm progress/notice chatter,
 * ANSI, carriage-return spinners, mount/cache paths, trailing whitespace)
 * collapse to a BYTE-IDENTICAL normalized string and therefore the identical
 * `normalizedOutputHash`. Conversely, any difference in REAL signal (a failing
 * test, a different dependency VERSION — the D4 toolchain-drift case) must NOT
 * be masked. Plus the D3 env pins on buildDockerArgs, with the security flags
 * proven intact.
 */
import { describe, test } from "node:test";
import assert from "node:assert/strict";

import {
  NORMALIZATION_VERSION,
  normalizeOutput,
  normalizedOutputHash,
  stripAnsi,
} from "./normalize.js";
import { buildDockerArgs, DEFAULT_SOURCE_DATE_EPOCH, type CheckSpec } from "./sandbox.js";

// A realistic `npm test` transcript, parameterized so we can vary ONLY the
// non-deterministic noise between two "independent re-runs".
function transcript(noise: {
  iso: string;
  epochMs: string;
  perTest: string;
  suiteTime: string;
  npmNoticeVersion: string;
  addedIn: string;
  doneIn: string;
  cacheSuffix: string;
  ansi: boolean;
  spinnerFrames: string[];
}): string {
  const g = noise.ansi ? "\x1B[32m" : "";
  const r = noise.ansi ? "\x1B[0m" : "";
  const spinner = noise.spinnerFrames.join("\r"); // carriage-return redraw
  return [
    `${g}$ npm test${r}`,
    `${noise.iso} run started (${noise.epochMs})`,
    `npm notice New minor version of npm available! ${noise.npmNoticeVersion}`,
    `npm timing npm:load Completed in 42ms`,
    `${spinner}`,
    `> vuln-app@1.0.0 test /workspace`,
    `> node test.js`,
    ``,
    `PASS /workspace/sum.test.js (${noise.perTest})`,
    `  ${g}✓${r} adds numbers (${noise.perTest})   `, // trailing whitespace
    `writing cache /tmp/.npm/_cacache/index-v5/${noise.cacheSuffix}`,
    ``,
    `Test Suites: 1 passed, 1 total`,
    `Tests:       1 passed, 1 total`,
    `Time:        ${noise.suiteTime}`,
    `added 12 packages in ${noise.addedIn}`,
    `Done in ${noise.doneIn}.`,
    ``,
  ].join("\n");
}

const RUN_A = transcript({
  iso: "2026-07-09T12:34:56.789Z",
  epochMs: "1752064496789",
  perTest: "5 ms",
  suiteTime: "1.234 s",
  npmNoticeVersion: "10.2.4 -> 10.9.0",
  addedIn: "3s",
  doneIn: "1.42s",
  cacheSuffix: "aa/bb/deadbeef",
  ansi: true,
  spinnerFrames: ["⠉ building", "⠋ building", "⠒ done building"],
});

// Same run, DIFFERENT operator/time: every noise token differs; signal identical.
const RUN_B = transcript({
  iso: "2026-07-10T09:01:02.003Z",
  epochMs: "1752147662003",
  perTest: "8 ms",
  suiteTime: "2.011 s",
  npmNoticeVersion: "10.5.0 -> 10.9.1",
  addedIn: "5s",
  doneIn: "2.30s",
  cacheSuffix: "cc/dd/feedface",
  ansi: false,
  spinnerFrames: ["⠹ building", "done building"],
});

describe("normalizeOutput — the determinism gate", () => {
  test("noise-only differences collapse to a byte-identical normalized string", () => {
    const na = normalizeOutput(RUN_A);
    const nb = normalizeOutput(RUN_B);
    assert.equal(na, nb, `normalized outputs diverge:\n---A---\n${na}\n---B---\n${nb}`);
  });

  test("=> identical normalizedOutputHash (the quorum commitment)", () => {
    assert.equal(normalizedOutputHash(RUN_A), normalizedOutputHash(RUN_B));
  });

  test("real signal is preserved — a FAILING test does not collapse into a pass", () => {
    const failed = RUN_A.replace("Tests:       1 passed, 1 total", "Tests:       1 failed, 1 total").replace(
      "PASS /workspace/sum.test.js",
      "FAIL /workspace/sum.test.js",
    );
    assert.notEqual(normalizedOutputHash(failed), normalizedOutputHash(RUN_A));
  });

  test("D4 guard — a dependency VERSION difference is NOT masked (toolchain drift stays visible)", () => {
    const v20 = "> vuln-app@1.0.0 test /workspace\nresolved lodash@4.17.20";
    const v21 = "> vuln-app@1.0.0 test /workspace\nresolved lodash@4.17.21";
    assert.notEqual(normalizedOutputHash(v20), normalizedOutputHash(v21));
  });

  test("normalizer is idempotent and stable", () => {
    assert.equal(normalizeOutput(normalizeOutput(RUN_A)), normalizeOutput(RUN_A));
  });

  test("NORMALIZATION_VERSION is a pinned consensus parameter", () => {
    assert.equal(NORMALIZATION_VERSION, "1");
  });
});

describe("normalizer building blocks", () => {
  test("stripAnsi removes colour + cursor sequences", () => {
    assert.equal(stripAnsi("\x1B[32mok\x1B[0m \x1B[2K\x1B[1Gdone"), "ok done");
  });

  test("carriage-return progress collapses to the final frame", () => {
    assert.equal(normalizeOutput("a\rbb\rccc"), "ccc");
  });

  test("trailing whitespace and EOF blank lines are trimmed", () => {
    assert.equal(normalizeOutput("line one   \n\n\n"), "line one");
  });

  test("internal blank lines are preserved (structure is signal)", () => {
    assert.equal(normalizeOutput("a\n\nb"), "a\n\nb");
  });
});

describe("buildDockerArgs — D3 determinism env pins (security intact)", () => {
  const spec: CheckSpec = {
    name: "test",
    image: "node:20-alpine",
    workspaceDir: "/srv/jobs/x",
    cmd: ["npm", "test"],
    timeoutMs: 1000,
    network: "none",
    limits: { cpus: "1", memory: "1g", pids: 256 },
  };

  const pairs = (args: string[]): string[] => {
    // Collect the values that follow each "-e" flag.
    const env: string[] = [];
    for (let i = 0; i < args.length - 1; i++) if (args[i] === "-e") env.push(args[i + 1]);
    return env;
  };

  test("pins clock, timezone, locale and silences npm chatter", () => {
    const env = pairs(buildDockerArgs(spec));
    assert.ok(env.includes("TZ=UTC"));
    assert.ok(env.includes("LANG=C.UTF-8"));
    assert.ok(env.includes("LC_ALL=C.UTF-8"));
    assert.ok(env.includes(`SOURCE_DATE_EPOCH=${DEFAULT_SOURCE_DATE_EPOCH}`));
    assert.ok(env.includes("npm_config_update_notifier=false"));
    assert.ok(env.includes("npm_config_fund=false"));
    assert.ok(env.includes("npm_config_audit=false"));
  });

  test("a CheckSpec-provided sourceDateEpoch overrides the default", () => {
    const env = pairs(buildDockerArgs({ ...spec, sourceDateEpoch: 1_600_000_000 }));
    assert.ok(env.includes("SOURCE_DATE_EPOCH=1600000000"));
    assert.ok(!env.includes(`SOURCE_DATE_EPOCH=${DEFAULT_SOURCE_DATE_EPOCH}`));
  });

  test("existing HOME + npm cache pins are not regressed", () => {
    const env = pairs(buildDockerArgs(spec));
    assert.ok(env.includes("HOME=/tmp"));
    assert.ok(env.includes("npm_config_cache=/tmp/.npm"));
  });

  test("security flags remain intact (env pins are not a relaxation)", () => {
    const args = buildDockerArgs(spec);
    assert.ok(args.includes("--read-only"));
    assert.ok(args.includes("--cap-drop") && args.includes("ALL"));
    assert.ok(args.includes("no-new-privileges"));
    assert.ok(args.includes("--network") && args.includes("none"));
  });
});
