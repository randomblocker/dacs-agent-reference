/**
 * Apply + verify — mutate package.json one upgrade item at a time and prove
 * each change green before keeping it.
 *
 * Per item: write the new range into package.json, run the verify commands
 * (`npm install` then `npm test` via the injected CommandRunner), and
 *  - green (both exit 0) → keep the change, record the evidence;
 *  - red → restore package.json to its pre-item content and record the
 *    failing command + the tail of its output.
 *
 * Items are applied cumulatively, so a later item is verified on top of all
 * earlier green ones — exactly the state the PR will ship.
 *
 * Formatting note: package.json is re-serialized with 2-space indentation
 * (JSON round-trip); comment-free npm manifests survive this losslessly.
 */
import { readFile, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { join } from "node:path";
import type {
  ApplyVerifyResult,
  CommandResult,
  CommandRunner,
  ItemResult,
  UpgradeItem,
} from "./types.js";

const OUTPUT_TAIL_CHARS = 1_200;

export function outputTail(output: string): string {
  return output.length <= OUTPUT_TAIL_CHARS ? output : `…${output.slice(-OUTPUT_TAIL_CHARS)}`;
}

/** Rewrite one dep's declared range in package.json text. */
export function applyItemToPackageJson(pkgJsonText: string, item: UpgradeItem): string {
  const pkg = JSON.parse(pkgJsonText) as Record<string, unknown>;
  const section = pkg[item.section] as Record<string, string> | undefined;
  if (!section || !(item.name in section)) {
    throw new Error(`apply: ${item.name} not found in ${item.section}`);
  }
  section[item.name] = item.newRange;
  return `${JSON.stringify(pkg, null, 2)}\n`;
}

export const VERIFY_COMMANDS: ReadonlyArray<{ cmd: string; args: string[] }> = [
  { cmd: "npm", args: ["install"] },
  { cmd: "npm", args: ["test"] },
];

export async function applyAndVerify(
  dir: string,
  items: UpgradeItem[],
  runner: CommandRunner,
): Promise<ApplyVerifyResult> {
  const pkgPath = join(dir, "package.json");
  let currentText = await readFile(pkgPath, "utf8");
  const results: ItemResult[] = [];
  let changed = false;

  for (const item of items) {
    const beforeText = currentText;
    const afterText = applyItemToPackageJson(currentText, item);
    await writeFile(pkgPath, afterText, "utf8");

    const verify: CommandResult[] = [];
    let failedAt: string | undefined;
    let tail: string | undefined;
    for (const { cmd, args } of VERIFY_COMMANDS) {
      const result = await runner.run(cmd, args, dir);
      verify.push(result);
      if (result.exitCode !== 0) {
        failedAt = result.command;
        tail = outputTail(result.output);
        break;
      }
    }

    if (failedAt !== undefined) {
      await writeFile(pkgPath, beforeText, "utf8"); // revert this item only
      results.push({ item, applied: false, verify, failedAt, outputTail: tail });
    } else {
      currentText = afterText;
      changed = true;
      results.push({ item, applied: true, verify });
    }
  }

  return { results, finalPackageJson: currentText, changed };
}

// ---------------------------------------------------------------------------
// CommandRunner adapters
// ---------------------------------------------------------------------------

/** Real adapter — spawns the command in `cwd`, capturing combined output. */
export class RealCommandRunner implements CommandRunner {
  constructor(private readonly timeoutMs = 300_000) {}

  run(cmd: string, args: string[], cwd: string): Promise<CommandResult> {
    return new Promise((resolve) => {
      const command = [cmd, ...args].join(" ");
      const child = spawn(cmd, args, {
        cwd,
        shell: false,
        env: { ...process.env, NO_COLOR: "1" },
        timeout: this.timeoutMs,
      });
      let output = "";
      child.stdout.on("data", (chunk: Buffer) => (output += chunk.toString()));
      child.stderr.on("data", (chunk: Buffer) => (output += chunk.toString()));
      child.on("error", (err) => resolve({ command, exitCode: 127, output: `${output}\n${err.message}` }));
      child.on("close", (code, signal) =>
        resolve({
          command,
          exitCode: code ?? (signal ? 124 : 1),
          output: signal ? `${output}\n(killed by ${signal})` : output,
        }),
      );
    });
  }
}

/**
 * Fake adapter — scripted exit codes for tests. `script` maps a command
 * string (e.g. `npm test`) to a queue of results; unlisted commands succeed.
 */
export class FakeCommandRunner implements CommandRunner {
  readonly calls: Array<{ command: string; cwd: string }> = [];

  constructor(private readonly script: Record<string, Array<{ exitCode: number; output: string }>> = {}) {}

  async run(cmd: string, args: string[], cwd: string): Promise<CommandResult> {
    const command = [cmd, ...args].join(" ");
    this.calls.push({ command, cwd });
    const queued = this.script[command]?.shift();
    return { command, exitCode: queued?.exitCode ?? 0, output: queued?.output ?? `(fake) ${command} ok` };
  }
}
