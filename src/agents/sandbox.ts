/**
 * SandboxPort — the seam that runs a PR's build/test commands.
 *
 * Running a pull request's `npm ci`/`npm test` means executing UNTRUSTED,
 * attacker-controlled code. The whole evaluator is written against this port so
 * that execution ALWAYS goes through an isolated container — there is no
 * host-execution path anywhere in the evaluator.
 *
 *   - `DockerSandbox` (real): one ephemeral `--rm` container per check, network
 *     DISABLED by default (only the explicitly-flagged install step may take
 *     `network:"limited"`), CPU/memory/pids/time caps, a non-root user, a
 *     read-only root fs with a small writable tmpfs, ALL Linux capabilities
 *     dropped, `no-new-privileges`, and NO host mounts except the per-job
 *     workspace. If the Docker daemon is unreachable it reports `available()
 *     === false` and `run()` THROWS — it never shells out to the host.
 *   - `FakeSandbox` (scripted): returns canned CheckResults for offline tests.
 *     It records every `run()` call so a test can assert the host is never
 *     asked to execute untrusted code when the sandbox is unavailable.
 *
 * FAIL-SAFE CONTRACT: the evaluator checks `available()` first and, when the
 * sandbox is down, returns an `indeterminate` verdict — it MUST NEVER fall back
 * to running untrusted commands on the host (contrast the LLM fallback, which
 * is safe). Nothing in this file ever runs `spec.cmd` outside a container.
 */
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { normalizedOutputHash } from "./normalize.js";
export { NORMALIZATION_VERSION, normalizeOutput, normalizedOutputHash } from "./normalize.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Resource caps applied to every sandboxed check. */
export interface SandboxLimits {
  /** CPU quota, docker `--cpus` (e.g. "1"). */
  cpus: string;
  /** Memory cap, docker `--memory` (e.g. "512m"). */
  memory: string;
  /** Max process count, docker `--pids-limit`. */
  pids: number;
}

export const DEFAULT_LIMITS: SandboxLimits = { cpus: "1", memory: "1g", pids: 256 };

/**
 * Default `SOURCE_DATE_EPOCH` when a CheckSpec does not pin one: 2023-11-14T
 * 22:13:20Z. It is a DETERMINISM parameter, not a security one — a fixed clock
 * so timestamp-sensitive build steps produce identical output across re-runners.
 * A re-runner participating in a quorum SHOULD set `CheckSpec.sourceDateEpoch`
 * to the commit time of `headSha` so every operator pins the same clock.
 */
export const DEFAULT_SOURCE_DATE_EPOCH = 1_700_000_000;

/** One check to run in isolation. */
export interface CheckSpec {
  /** Logical name: "install" | "build" | "test" | "typecheck". */
  name: string;
  /**
   * Container image. For a quorum-attested run this SHOULD be a digest-pinned
   * ref (e.g. "node@sha256:…") so every re-runner drives a bit-identical
   * toolchain (D4); a re-runner MUST refuse a mismatched toolchain. A bare tag
   * ("node:20-alpine") is accepted for self-attested runs but does not pin the
   * toolchain across operators.
   */
  image: string;
  /** Host dir mounted read-write at /workspace (the ONLY host mount). */
  workspaceDir: string;
  /** argv — executed WITHOUT a shell (no `sh -c`, no interpolation). */
  cmd: string[];
  timeoutMs: number;
  /** "none" (default, no network) or "limited" (only the install step). */
  network: "none" | "limited";
  limits: SandboxLimits;
  /**
   * Frozen clock for reproducibility (Unix seconds). Pinned into the container
   * env as `SOURCE_DATE_EPOCH`; defaults to `DEFAULT_SOURCE_DATE_EPOCH`. See D3.
   */
  sourceDateEpoch?: number;
}

/** The settleable, content-addressed result of one check. */
export interface CheckResult {
  name: string;
  cmd: string[];
  exitCode: number;
  passed: boolean;
  durationMs: number;
  /** Last chars of combined stdout+stderr (bounded). */
  outputTail: string;
  /**
   * sha256 of the FULL RAW combined stdout+stderr. Kept for human forensics —
   * it will NOT match across independent re-runners (it carries timestamps,
   * durations, ANSI, etc.). Do NOT compare this across operators.
   */
  outputHash: string;
  /**
   * sha256 of `normalizeOutput(output)` (see normalize.ts) — the
   * reproducibility commitment a quorum compares. Two honest re-runners on the
   * same pinned inputs produce the SAME `normalizedOutputHash`. Computed under
   * `NORMALIZATION_VERSION`, which is a consensus parameter.
   */
  normalizedOutputHash: string;
}

export interface SandboxPort {
  /** True only when untrusted code CAN be isolated (Docker daemon reachable). */
  available(): Promise<boolean>;
  /** Run one check in isolation. Rejects if isolation cannot be guaranteed. */
  run(spec: CheckSpec): Promise<CheckResult>;
}

const OUTPUT_TAIL_CHARS = 2_000;

export function sandboxOutputTail(output: string): string {
  return output.length <= OUTPUT_TAIL_CHARS ? output : `…${output.slice(-OUTPUT_TAIL_CHARS)}`;
}

export function hashOutput(output: string): string {
  return createHash("sha256").update(output, "utf8").digest("hex");
}

// ---------------------------------------------------------------------------
// DockerSandbox — the real isolation adapter
// ---------------------------------------------------------------------------

/**
 * Build the `docker run` argv for a check. Pure + exported so the command
 * construction (the security-critical part) is unit-testable WITHOUT a daemon.
 *
 * Isolation flags, every run:
 *   --rm                         ephemeral container, removed on exit
 *   --network none|bridge        no network by default; bridge only for install
 *   --cpus/--memory/--pids-limit resource caps (DoS containment)
 *   --user 1000:1000             non-root
 *   --read-only + --tmpfs        read-only root fs; writable scratch on tmpfs
 *   --cap-drop ALL               drop all Linux capabilities
 *   --security-opt no-new-privileges  no setuid escalation
 *   -v <workspace>:/workspace    the ONLY host mount (per-job, read-write)
 *   -w /workspace
 * The untrusted command is passed as trailing argv AFTER `image` — never through
 * a shell.
 */
export function buildDockerArgs(spec: CheckSpec): string[] {
  // Run as the INVOKING host user (who owns the mounted workspace). A hardcoded
  // uid mismatches the workspace owner, so every workspace read fails EACCES and
  // npm/tool checks die (proven on a uid-1001 host). Never root: fall back to a
  // non-privileged uid if the invoker is root or uid is unavailable (non-POSIX).
  const hostUid = typeof process.getuid === "function" ? process.getuid() : 0;
  const hostGid = typeof process.getgid === "function" ? process.getgid() : 0;
  const uid = hostUid && hostUid !== 0 ? hostUid : 1000;
  const gid = hostGid && hostGid !== 0 ? hostGid : 1000;
  const args = [
    "run",
    "--rm",
    "--network",
    spec.network === "limited" ? "bridge" : "none",
    "--cpus",
    spec.limits.cpus,
    "--memory",
    spec.limits.memory,
    "--memory-swap",
    spec.limits.memory, // disallow swap growth beyond the memory cap
    "--pids-limit",
    String(spec.limits.pids),
    "--user",
    `${uid}:${gid}`,
    "--read-only",
    // Writable scratch the toolchain needs, on tmpfs (not the host):
    "--tmpfs",
    "/tmp:rw,noexec,nosuid,size=256m",
    "--tmpfs",
    "/workspace/node_modules:rw,nosuid,size=1g",
    // A writable HOME + package-manager cache (read-only root would otherwise
    // EACCES npm's config/cache writes).
    "-e",
    "HOME=/tmp",
    "-e",
    "npm_config_cache=/tmp/.npm",
    // DETERMINISM pins (D3) — a frozen clock/timezone/locale + silenced npm
    // chatter so independent re-runners produce byte-identical output. These are
    // reproducibility parameters, NOT security flags; they do not relax the
    // isolation above. `SOURCE_DATE_EPOCH` defaults to DEFAULT_SOURCE_DATE_EPOCH
    // but a quorum re-runner should pin it to the headSha commit time.
    "-e",
    "TZ=UTC",
    "-e",
    "LANG=C.UTF-8",
    "-e",
    "LC_ALL=C.UTF-8",
    "-e",
    `SOURCE_DATE_EPOCH=${spec.sourceDateEpoch ?? DEFAULT_SOURCE_DATE_EPOCH}`,
    "-e",
    "npm_config_update_notifier=false",
    "-e",
    "npm_config_fund=false",
    "-e",
    "npm_config_audit=false",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges",
    "-v",
    `${spec.workspaceDir}:/workspace`,
    "-w",
    "/workspace",
    spec.image,
    ...spec.cmd,
  ];
  return args;
}

export interface DockerSandboxOptions {
  /** Override the docker binary (default "docker"). */
  dockerBin?: string;
}

export class DockerSandbox implements SandboxPort {
  private readonly dockerBin: string;

  constructor(opts: DockerSandboxOptions = {}) {
    this.dockerBin = opts.dockerBin ?? "docker";
  }

  /** Reachable Docker daemon? `docker version --format` fails fast if not. */
  async available(): Promise<boolean> {
    return new Promise((resolve) => {
      const child = execFile(
        this.dockerBin,
        ["version", "--format", "{{.Server.Version}}"],
        { timeout: 10_000 },
        (err, out) => resolve(!err && String(out).trim().length > 0),
      );
      child.on("error", () => resolve(false));
    });
  }

  /**
   * Run one check in an ephemeral container. NEVER executes on the host: the
   * only process spawned is `docker run`, which isolates the untrusted command.
   * If the daemon has become unreachable, this REJECTS (fail-safe) rather than
   * degrading to a host run.
   */
  async run(spec: CheckSpec): Promise<CheckResult> {
    if (!(await this.available())) {
      throw new Error(
        "DockerSandbox.run: no sandbox available — refusing to execute untrusted code on host",
      );
    }
    const args = buildDockerArgs(spec);
    const started = Date.now();
    return new Promise<CheckResult>((resolve) => {
      const child = execFile(
        this.dockerBin,
        args,
        {
          // Container's own time cap is enforced by killing the docker client;
          // a small grace over the spec keeps `docker` from lingering.
          timeout: spec.timeoutMs + 5_000,
          maxBuffer: 8 * 1024 * 1024,
        },
        (err, stdout, stderr) => {
          const output = `${stdout ?? ""}${stderr ?? ""}`;
          // execFile's err.code is the child's exit code (number) on non-zero
          // exit; a string code (e.g. "ETIMEDOUT") means the client was killed.
          const rawCode = (err as (NodeJS.ErrnoException & { code?: number | string }) | null)?.code;
          const exitCode = typeof rawCode === "number" ? rawCode : err ? 124 : 0;
          resolve({
            name: spec.name,
            cmd: spec.cmd,
            exitCode,
            passed: exitCode === 0,
            durationMs: Date.now() - started,
            outputTail: sandboxOutputTail(output),
            outputHash: hashOutput(output),
            normalizedOutputHash: normalizedOutputHash(output),
          });
        },
      );
      child.on("error", () => {
        // docker binary missing / spawn failure → a failed check, not a host run.
        resolve({
          name: spec.name,
          cmd: spec.cmd,
          exitCode: 127,
          passed: false,
          durationMs: Date.now() - started,
          outputTail: "docker spawn failed",
          outputHash: hashOutput("docker spawn failed"),
          normalizedOutputHash: normalizedOutputHash("docker spawn failed"),
        });
      });
    });
  }
}

// ---------------------------------------------------------------------------
// FakeSandbox — scripted results for offline tests
// ---------------------------------------------------------------------------

/** A scripted check outcome (by check name). */
export interface ScriptedCheck {
  exitCode: number;
  output?: string;
  durationMs?: number;
}

/**
 * Offline sandbox. `available` is fixed at construction (set false to exercise
 * the fail-safe path). `script` maps a check name → outcome; unlisted checks
 * pass. Every `run()` is recorded in `calls` so a test can assert the sandbox
 * is NOT invoked when it reports unavailable.
 */
export class FakeSandbox implements SandboxPort {
  readonly calls: CheckSpec[] = [];

  constructor(
    private readonly script: Record<string, ScriptedCheck> = {},
    private readonly isAvailable = true,
  ) {}

  async available(): Promise<boolean> {
    return this.isAvailable;
  }

  async run(spec: CheckSpec): Promise<CheckResult> {
    this.calls.push(spec);
    const scripted = this.script[spec.name];
    const exitCode = scripted?.exitCode ?? 0;
    const output = scripted?.output ?? `(fake) ${spec.name} ${exitCode === 0 ? "ok" : "failed"}`;
    return {
      name: spec.name,
      cmd: spec.cmd,
      exitCode,
      passed: exitCode === 0,
      durationMs: scripted?.durationMs ?? 1,
      outputTail: sandboxOutputTail(output),
      outputHash: hashOutput(output),
      normalizedOutputHash: normalizedOutputHash(output),
    };
  }
}
