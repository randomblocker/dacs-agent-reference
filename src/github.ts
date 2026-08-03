/**
 * Mock GitHub — the delivery surface for the "PR review for hire" service.
 *
 * Exposes the same URL shapes as api.github.com (`/users/:login`,
 * `/repos/:owner/:repo/pulls/:n`, `.../reviews`), so every agent that talks to
 * it does so through an HTTP-shaped `apiFetch` — the exact surface a DAHR
 * proxy attests. Going real is a transport swap (point the substrate's DAHR
 * at the real api.github.com + a posting token), not a redesign.
 */
import { sha256Hex } from "@kynesyslabs/dacs";

export interface GhUser {
  login: string;
  created_at: string;
  public_repos: number;
}

export interface GhReview {
  id: number;
  user: { login: string };
  body: string;
  submitted_at: string;
}

export interface GhPull {
  number: number;
  title: string;
  diff: string;
}

export class MockGitHub {
  private readonly users = new Map<string, GhUser>();
  /** key: `owner/repo#number` */
  private readonly pulls = new Map<string, GhPull>();
  private readonly reviews = new Map<string, GhReview[]>();
  private nextReviewId = 9001;

  addUser(user: GhUser): void {
    this.users.set(user.login, user);
  }

  addPull(repo: string, pull: GhPull): void {
    this.pulls.set(`${repo}#${pull.number}`, pull);
    this.reviews.set(`${repo}#${pull.number}`, []);
  }

  getPull(repo: string, number: number): GhPull | null {
    return this.pulls.get(`${repo}#${number}`) ?? null;
  }

  listReviews(repo: string, number: number): GhReview[] {
    return this.reviews.get(`${repo}#${number}`) ?? [];
  }

  /** Post a review as `login` (the authenticated identity — cannot be forged). */
  postReview(login: string, repo: string, number: number, body: string): GhReview {
    if (!this.users.has(login)) throw new Error(`github: unknown user ${login}`);
    const key = `${repo}#${number}`;
    if (!this.pulls.has(key)) throw new Error(`github: no PR ${key}`);
    const review: GhReview = {
      id: this.nextReviewId++,
      user: { login },
      body,
      submitted_at: new Date().toISOString(),
    };
    this.reviews.get(key)!.push(review);
    return review;
  }

  /**
   * api.github.com-shaped read surface. Everything the ecosystem *checks*
   * (vet, delivery confirmation, third-party audit) goes through here — the
   * same URLs a DAHR proxy would attest for real.
   */
  apiFetch(url: string): { status: number; body: unknown } {
    const u = new URL(url);
    const medUser = u.pathname.match(/^\/users\/([^/]+)$/);
    if (medUser) {
      const user = this.users.get(medUser[1]!);
      return user ? { status: 200, body: user } : { status: 404, body: { message: "Not Found" } };
    }
    const mPull = u.pathname.match(/^\/repos\/([^/]+\/[^/]+)\/pulls\/(\d+)$/);
    if (mPull) {
      const pull = this.getPull(mPull[1]!, Number(mPull[2]));
      return pull ? { status: 200, body: pull } : { status: 404, body: { message: "Not Found" } };
    }
    const mReviews = u.pathname.match(/^\/repos\/([^/]+\/[^/]+)\/pulls\/(\d+)\/reviews$/);
    if (mReviews) {
      return { status: 200, body: this.listReviews(mReviews[1]!, Number(mReviews[2])) };
    }
    return { status: 404, body: { message: "Not Found" } };
  }

  /** Canonical hash of a GET's body — what the DAHR attestation commits to. */
  stateHash(url: string): string {
    return sha256Hex(JSON.stringify(this.apiFetch(url).body));
  }
}
