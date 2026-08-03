/**
 * GitHubPort — PR delivery surface, mock adapter only today.
 *
 * Follows src/github.ts's approach: an in-memory host that exposes the same
 * URL shapes as api.github.com (`/repos/:owner/:repo`, `.../git/refs`,
 * `.../contents/:path`, `.../pulls`), so every write the agent performs is
 * recorded as the exact HTTP call a real adapter would make. Going real is
 * an adapter swap that needs an authed `gh` CLI or a token — nothing above
 * the port moves.
 */
import type { GitHubPort, RepoRef } from "./types.js";

interface MockRepo {
  full_name: string;
  default_branch: string;
  /** branch name → files (path → content) at branch head. */
  branches: Map<string, Map<string, string>>;
}

export interface MockCommit {
  sha: string;
  branch: string;
  message: string;
  files: Array<{ path: string; content: string }>;
}

export interface MockPr {
  number: number;
  head: string;
  base: string;
  title: string;
  body: string;
  html_url: string;
}

export class MockGitHubHost implements GitHubPort {
  private readonly repos = new Map<string, MockRepo>();
  private readonly commits = new Map<string, MockCommit[]>();
  private readonly prs = new Map<string, MockPr[]>();
  /** Every api.github.com-shaped call the port made, in order. */
  readonly callLog: string[] = [];
  private nextPrNumber = 1;
  private nextSha = 0xc0de;

  addRepo(ref: RepoRef, default_branch = "main"): void {
    const key = `${ref.owner}/${ref.repo}`;
    this.repos.set(key, {
      full_name: key,
      default_branch,
      branches: new Map([[default_branch, new Map()]]),
    });
    this.commits.set(key, []);
    this.prs.set(key, []);
  }

  private repo(ref: RepoRef): MockRepo {
    const repo = this.repos.get(`${ref.owner}/${ref.repo}`);
    if (!repo) throw new Error(`github: unknown repo ${ref.owner}/${ref.repo}`);
    return repo;
  }

  async getRepo(ref: RepoRef): Promise<{ full_name: string; default_branch: string }> {
    this.callLog.push(`GET https://api.github.com/repos/${ref.owner}/${ref.repo}`);
    const { full_name, default_branch } = this.repo(ref);
    return { full_name, default_branch };
  }

  async createBranch(ref: RepoRef, branch: string, fromBranch: string): Promise<void> {
    this.callLog.push(`POST https://api.github.com/repos/${ref.owner}/${ref.repo}/git/refs`);
    const repo = this.repo(ref);
    const from = repo.branches.get(fromBranch);
    if (!from) throw new Error(`github: base branch ${fromBranch} not found`);
    repo.branches.set(branch, new Map(from));
  }

  async commitFiles(
    ref: RepoRef,
    branch: string,
    message: string,
    files: Array<{ path: string; content: string }>,
  ): Promise<{ sha: string }> {
    const repo = this.repo(ref);
    const tree = repo.branches.get(branch);
    if (!tree) throw new Error(`github: branch ${branch} not found`);
    for (const f of files) {
      this.callLog.push(
        `PUT https://api.github.com/repos/${ref.owner}/${ref.repo}/contents/${f.path}?branch=${branch}`,
      );
      tree.set(f.path, f.content);
    }
    const sha = (this.nextSha++).toString(16).padStart(40, "0");
    this.commits.get(repo.full_name)!.push({ sha, branch, message, files });
    return { sha };
  }

  async openPR(
    ref: RepoRef,
    params: { head: string; base: string; title: string; body: string },
  ): Promise<{ number: number; html_url: string }> {
    this.callLog.push(`POST https://api.github.com/repos/${ref.owner}/${ref.repo}/pulls`);
    const repo = this.repo(ref);
    if (!repo.branches.has(params.head)) throw new Error(`github: head branch ${params.head} not found`);
    const number = this.nextPrNumber++;
    const pr: MockPr = {
      number,
      ...params,
      html_url: `https://github.com/${repo.full_name}/pull/${number}`,
    };
    this.prs.get(repo.full_name)!.push(pr);
    return { number, html_url: pr.html_url };
  }

  // -------------------------------------------------------------------------
  // Read surface — api.github.com URL shapes, mirroring src/github.ts
  // -------------------------------------------------------------------------

  apiFetch(url: string): { status: number; body: unknown } {
    const u = new URL(url);
    const mRepo = u.pathname.match(/^\/repos\/([^/]+)\/([^/]+)$/);
    if (mRepo) {
      const repo = this.repos.get(`${mRepo[1]}/${mRepo[2]}`);
      return repo
        ? { status: 200, body: { full_name: repo.full_name, default_branch: repo.default_branch } }
        : { status: 404, body: { message: "Not Found" } };
    }
    const mPull = u.pathname.match(/^\/repos\/([^/]+\/[^/]+)\/pulls\/(\d+)$/);
    if (mPull) {
      const pr = this.prs.get(mPull[1]!)?.find((p) => p.number === Number(mPull[2]));
      return pr ? { status: 200, body: pr } : { status: 404, body: { message: "Not Found" } };
    }
    return { status: 404, body: { message: "Not Found" } };
  }

  listCommits(ref: RepoRef): MockCommit[] {
    return this.commits.get(`${ref.owner}/${ref.repo}`) ?? [];
  }

  getPr(ref: RepoRef, number: number): MockPr | null {
    return this.prs.get(`${ref.owner}/${ref.repo}`)?.find((p) => p.number === number) ?? null;
  }

  /** Render a PR the way a human would first see it. */
  renderPr(ref: RepoRef, number: number): string {
    const pr = this.getPr(ref, number);
    if (!pr) throw new Error(`github: no PR #${number} in ${ref.owner}/${ref.repo}`);
    return [
      `PR #${pr.number}: ${pr.title}`,
      `${pr.head} -> ${pr.base}   ${pr.html_url}`,
      "-".repeat(72),
      pr.body,
    ].join("\n");
  }
}
