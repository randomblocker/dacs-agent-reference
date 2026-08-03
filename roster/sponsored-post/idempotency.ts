import { mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import { dirname } from "node:path";
import type { PublishedSponsoredPost } from "./types.js";

export type SponsoredPostJobState =
  | { status: "publishing"; requestHash: string; startedAt: number }
  | { status: "complete"; requestHash: string; post: PublishedSponsoredPost; moderationDecisionRef?: string };

export type BeginPublication =
  | { kind: "new" }
  | { kind: "pending" }
  | { kind: "complete"; post: PublishedSponsoredPost; moderationDecisionRef?: string };

export interface SponsoredPostIdempotencyStore {
  begin(jobId: string, requestHash: string): Promise<BeginPublication>;
  complete(jobId: string, requestHash: string, post: PublishedSponsoredPost, moderationDecisionRef?: string): Promise<void>;
  releaseRejected(jobId: string, requestHash: string): Promise<void>;
}

function assertKey(value: string, name: string): void {
  if (!/^[A-Za-z0-9._:-]{1,160}$/.test(value)) throw new Error(`${name} is not a safe state key`);
}

export class MemorySponsoredPostIdempotencyStore implements SponsoredPostIdempotencyStore {
  private readonly jobs = new Map<string, SponsoredPostJobState>();

  async begin(jobId: string, requestHash: string): Promise<BeginPublication> {
    const state = this.jobs.get(jobId);
    if (!state) {
      this.jobs.set(jobId, { status: "publishing", requestHash, startedAt: Date.now() });
      return { kind: "new" };
    }
    if (state.requestHash !== requestHash) throw new Error("job id was reused with different sponsored-post text");
    return state.status === "complete"
      ? { kind: "complete", post: state.post, ...(state.moderationDecisionRef === undefined ? {} : { moderationDecisionRef: state.moderationDecisionRef }) }
      : { kind: "pending" };
  }

  async complete(jobId: string, requestHash: string, post: PublishedSponsoredPost, moderationDecisionRef?: string): Promise<void> {
    const state = this.jobs.get(jobId);
    if (!state || state.requestHash !== requestHash) throw new Error("sponsored-post reservation is missing or mismatched");
    this.jobs.set(jobId, { status: "complete", requestHash, post, ...(moderationDecisionRef === undefined ? {} : { moderationDecisionRef }) });
  }

  async releaseRejected(jobId: string, requestHash: string): Promise<void> {
    const state = this.jobs.get(jobId);
    if (state?.status === "publishing" && state.requestHash === requestHash) this.jobs.delete(jobId);
  }
}

/** One JSON file per paid job. Atomic rename makes completed evidence durable. */
export class FileSponsoredPostIdempotencyStore implements SponsoredPostIdempotencyStore {
  constructor(private readonly directory: string) {
    if (!directory.startsWith("/")) throw new Error("sponsored-post state directory must be absolute");
  }

  private path(jobId: string): string {
    assertKey(jobId, "jobId");
    return `${this.directory}/${jobId}.json`;
  }

  private async read(jobId: string): Promise<SponsoredPostJobState | undefined> {
    try {
      return JSON.parse(await readFile(this.path(jobId), "utf8")) as SponsoredPostJobState;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      throw error;
    }
  }

  async begin(jobId: string, requestHash: string): Promise<BeginPublication> {
    assertKey(requestHash, "requestHash");
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    const path = this.path(jobId);
    const state = await this.read(jobId);
    if (state) {
      if (state.requestHash !== requestHash) throw new Error("job id was reused with different sponsored-post text");
      return state.status === "complete"
        ? { kind: "complete", post: state.post, ...(state.moderationDecisionRef === undefined ? {} : { moderationDecisionRef: state.moderationDecisionRef }) }
        : { kind: "pending" };
    }
    const handle = await open(path, "wx", 0o600);
    try {
      await handle.writeFile(JSON.stringify({ status: "publishing", requestHash, startedAt: Date.now() }));
      await handle.sync();
    } finally {
      await handle.close();
    }
    return { kind: "new" };
  }

  async complete(jobId: string, requestHash: string, post: PublishedSponsoredPost, moderationDecisionRef?: string): Promise<void> {
    const state = await this.read(jobId);
    if (!state || state.requestHash !== requestHash) throw new Error("sponsored-post reservation is missing or mismatched");
    const path = this.path(jobId);
    const temp = `${path}.${process.pid}.${Date.now()}.tmp`;
    await mkdir(dirname(temp), { recursive: true, mode: 0o700 });
    const handle = await open(temp, "wx", 0o600);
    try {
      await handle.writeFile(JSON.stringify({
        status: "complete",
        requestHash,
        post,
        ...(moderationDecisionRef === undefined ? {} : { moderationDecisionRef }),
      }));
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(temp, path);
  }

  async releaseRejected(jobId: string, requestHash: string): Promise<void> {
    const state = await this.read(jobId);
    if (state?.status !== "publishing" || state.requestHash !== requestHash) return;
    await unlink(this.path(jobId));
  }
}
