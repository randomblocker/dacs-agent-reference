/**
 * RepoFetchPort — fetch a PR into a mountable workspace + capture its diff.
 *
 *   - `LiveRepo` (real): `gh pr view` for the head SHA, `gh pr diff` for the
 *     unified diff, a shallow `git clone` + checkout of the head commit for the
 *     workspace the sandbox mounts, and manifest-based project-type detection.
 *   - `FakeRepo` (canned): a fixture workspace dir + a canned diff/head/manifest
 *     for offline tests — no `gh`, no `git`, no network.
 *
 * The workspace is the ONLY host artifact the sandbox is allowed to touch, and
 * the caller MUST `cleanup()` it when the evaluation is done.
 */
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export type ProjectType = "node" | "unknown";

export interface FetchedPr {
  /** Absolute path of the checked-out working copy (mounted into the sandbox). */
  workspaceDir: string;
  /** The PR head commit SHA — bound into the attested verdict. */
  headSha: string;
  /** Unified diff of the PR (untrusted; fed to the LLM as data via stdin). */
  diff: string;
  projectType: ProjectType;
  /** Raw package.json text when projectType==="node" (drives check planning + advisory scan). */
  packageJson?: string;
  /** Raw package-lock.json text when present (lets the advisory scan pin versions). */
  packageLock?: string;
}

export interface RepoFetchPort {
  fetchPr(repo: string, prNumber: number): Promise<FetchedPr>;
  /**
   * Clone a repo at an optional ref (default: the cloned HEAD) for a WHOLE-REPO
   * audit — the sec-audit deep tier's entry point when no PR is given. Returns
   * the same `FetchedPr` shape with `diff: ""` (there is no PR diff to review;
   * the deep auditor works over the checked-out tree). The workspace is the only
   * host artifact the sandbox mounts, and the caller MUST `cleanup()` it.
   */
  fetchRef(repo: string, ref?: string): Promise<FetchedPr>;
  /** Remove a workspace produced by fetchPr/fetchRef. Safe with an unknown dir. */
  cleanup(workspaceDir: string): Promise<void>;
}

/** package.json present ⇒ node; otherwise unknown (degrade gracefully). */
export function detectProjectType(files: { hasPackageJson: boolean }): ProjectType {
  return files.hasPackageJson ? "node" : "unknown";
}

// ---------------------------------------------------------------------------
// LiveRepo — real gh/git adapter
// ---------------------------------------------------------------------------

function run(cmd: string, args: string[], opts: { cwd?: string; timeoutMs?: number } = {}): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(
      cmd,
      args,
      { cwd: opts.cwd, timeout: opts.timeoutMs ?? 120_000, maxBuffer: 16 * 1024 * 1024, encoding: "utf8" },
      (err, stdout) => (err ? reject(err) : resolve(stdout)),
    );
  });
}

export interface LiveRepoOptions {
  /** Skip the (heavy) clone and return a placeholder workspace. Used by the
   *  offline-sandbox demo, which only needs diff+headSha+manifest. */
  skipClone?: boolean;
}

export class LiveRepo implements RepoFetchPort {
  constructor(private readonly opts: LiveRepoOptions = {}) {}

  async fetchPr(repo: string, prNumber: number): Promise<FetchedPr> {
    // Metadata + diff via `gh` (works with the ambient gh auth).
    const view = JSON.parse(
      await run("gh", ["pr", "view", String(prNumber), "--repo", repo, "--json", "headRefOid,headRepository,headRepositoryOwner"]),
    ) as { headRefOid?: string };
    const headSha = view.headRefOid ?? "";
    if (!headSha) throw new Error(`LiveRepo: could not resolve head SHA for ${repo}#${prNumber}`);
    const diff = await run("gh", ["pr", "diff", String(prNumber), "--repo", repo]);

    let workspaceDir = `(not cloned: ${repo}#${prNumber})`;
    let packageJson: string | undefined;
    let packageLock: string | undefined;
    let hasPackageJson = false;

    if (this.opts.skipClone) {
      // Read the manifest at the PR head WITHOUT cloning, via the contents API.
      packageJson = await this.tryFetchFile(repo, headSha, "package.json");
      packageLock = await this.tryFetchFile(repo, headSha, "package-lock.json");
      hasPackageJson = packageJson !== undefined;
    } else {
      workspaceDir = await mkdtemp(join(tmpdir(), "dacs-eval-"));
      // Shallow-clone the head repo/ref so the sandbox has a real tree to mount.
      const cloneUrl = `https://github.com/${repo}.git`;
      await run("git", ["clone", "--depth", "1", cloneUrl, workspaceDir], { timeoutMs: 180_000 });
      // Fetch + check out the exact PR head SHA (detached) for reproducibility.
      await run("git", ["-C", workspaceDir, "fetch", "--depth", "1", "origin", headSha], { timeoutMs: 120_000 }).catch(
        () => {},
      );
      await run("git", ["-C", workspaceDir, "checkout", headSha], { timeoutMs: 60_000 }).catch(() => {});
      const pkgPath = join(workspaceDir, "package.json");
      if (existsSync(pkgPath)) {
        hasPackageJson = true;
        packageJson = await readFile(pkgPath, "utf8");
        const lockPath = join(workspaceDir, "package-lock.json");
        if (existsSync(lockPath)) packageLock = await readFile(lockPath, "utf8");
      }
    }

    return {
      workspaceDir,
      headSha,
      diff,
      projectType: detectProjectType({ hasPackageJson }),
      packageJson,
      packageLock,
    };
  }

  /**
   * Clone a repo at `ref` (default: whatever the shallow clone lands on) into a
   * temp workspace for a whole-repo deep audit. Resolves the checked-out SHA via
   * `git rev-parse HEAD` so the attested artifact binds the exact tree the tools
   * scan. `diff` is empty — a whole-repo audit has no PR diff.
   */
  async fetchRef(repo: string, ref?: string): Promise<FetchedPr> {
    const workspaceDir = await mkdtemp(join(tmpdir(), "dacs-secaudit-"));
    const cloneUrl = `https://github.com/${repo}.git`;
    await run("git", ["clone", "--depth", "1", cloneUrl, workspaceDir], { timeoutMs: 180_000 });
    if (ref) {
      await run("git", ["-C", workspaceDir, "fetch", "--depth", "1", "origin", ref], { timeoutMs: 120_000 }).catch(
        () => {},
      );
      await run("git", ["-C", workspaceDir, "checkout", ref], { timeoutMs: 60_000 }).catch(() => {});
    }
    const headSha = (await run("git", ["-C", workspaceDir, "rev-parse", "HEAD"], { timeoutMs: 30_000 }).catch(() => "")).trim();

    let packageJson: string | undefined;
    let packageLock: string | undefined;
    let hasPackageJson = false;
    const pkgPath = join(workspaceDir, "package.json");
    if (existsSync(pkgPath)) {
      hasPackageJson = true;
      packageJson = await readFile(pkgPath, "utf8");
      const lockPath = join(workspaceDir, "package-lock.json");
      if (existsSync(lockPath)) packageLock = await readFile(lockPath, "utf8");
    }

    return {
      workspaceDir,
      headSha,
      diff: "",
      projectType: detectProjectType({ hasPackageJson }),
      packageJson,
      packageLock,
    };
  }

  private async tryFetchFile(repo: string, ref: string, path: string): Promise<string | undefined> {
    try {
      // gh api with -H raw returns the file bytes at the given ref.
      return await run("gh", ["api", `repos/${repo}/contents/${path}?ref=${ref}`, "-H", "Accept: application/vnd.github.raw+json"]);
    } catch {
      return undefined;
    }
  }

  async cleanup(workspaceDir: string): Promise<void> {
    if (!workspaceDir.startsWith(tmpdir())) return; // never rm a non-temp path
    await rm(workspaceDir, { recursive: true, force: true }).catch(() => {});
  }
}

// ---------------------------------------------------------------------------
// FakeRepo — canned fixture for tests
// ---------------------------------------------------------------------------

export class FakeRepo implements RepoFetchPort {
  cleaned: string[] = [];

  constructor(private readonly canned: FetchedPr) {}

  async fetchPr(_repo: string, _prNumber: number): Promise<FetchedPr> {
    return { ...this.canned };
  }

  async fetchRef(_repo: string, _ref?: string): Promise<FetchedPr> {
    return { ...this.canned };
  }

  async cleanup(workspaceDir: string): Promise<void> {
    this.cleaned.push(workspaceDir);
  }
}
