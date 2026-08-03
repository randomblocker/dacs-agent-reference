/**
 * Live GitHub — the real delivery surface, structurally matching the slice of
 * MockGitHub the agents use (getPull / postReview / listReviews / stateHash),
 * so SellerAgent runs unchanged.
 *
 * Writes go through the authenticated `gh` CLI — the seller's GitHub identity,
 * the same account its DID is CCI-bound to. Reads go through `gh api` (authed,
 * works for private repos). DAHR-attested GitHub reads are blocked node-side
 * (kynesyslabs/node#959), so state hashes are self-observed commitments until
 * that's fixed (see LiveSubstrate.proxyFetch).
 */
import { execFileSync } from "node:child_process";
import { sha256Hex } from "@kynesyslabs/dacs";

export interface LiveReview {
  id: number;
  user: { login: string };
  body: string;
  submitted_at: string;
}

const gh = (args: string[], input?: string): string =>
  execFileSync("gh", args, {
    encoding: "utf8",
    input,
    maxBuffer: 4 * 1024 * 1024,
    timeout: 60_000,
  });

const ghApi = (path: string): unknown => JSON.parse(gh(["api", path]));

export class LiveGitHub {
  /** The gh CLI's authenticated login (the only identity we can post as). */
  readonly authedLogin: string = gh(["api", "user", "--jq", ".login"]).trim();

  getPull(repo: string, number: number): { number: number; title: string; diff: string } | null {
    try {
      const meta = ghApi(`/repos/${repo}/pulls/${number}`) as { title?: string };
      const diff = gh(["pr", "diff", String(number), "--repo", repo]);
      return { number, title: meta?.title ?? "", diff };
    } catch {
      return null;
    }
  }

  /**
   * Post a PR review as `login`. The gh CLI can only post as its authenticated
   * user — a mismatch would silently forge authorship, so it throws instead.
   */
  postReview(login: string, repo: string, number: number, body: string): LiveReview {
    if (login.toLowerCase() !== this.authedLogin.toLowerCase()) {
      throw new Error(
        `postReview: asked to post as ${login} but gh is authenticated as ${this.authedLogin}`,
      );
    }
    gh(["pr", "review", String(number), "--repo", repo, "--comment", "--body-file", "-"], body);
    const after = this.listReviews(repo, number);
    const mine = [...after].reverse().find((r) => r.user.login.toLowerCase() === login.toLowerCase());
    if (!mine) throw new Error("postReview: review did not appear on the PR");
    return mine;
  }

  listReviews(repo: string, number: number): LiveReview[] {
    try {
      const res = ghApi(`/repos/${repo}/pulls/${number}/reviews`);
      return Array.isArray(res) ? (res as LiveReview[]) : [];
    } catch {
      return [];
    }
  }

  /** Commitment over a GitHub API URL's current state (self-observed; see header). */
  stateHash(url: string): string {
    const path = url.replace(/^https:\/\/api\.github\.com/, "");
    try {
      return sha256Hex(JSON.stringify(ghApi(path)));
    } catch {
      return sha256Hex("null");
    }
  }
}
