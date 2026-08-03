import { createHash } from "node:crypto";
import type { WorkCallback } from "../seller-adapter.js";
import type { DeliveryVerifyOptions } from "../verifier.js";
import { readReportMeta, reportMeta } from "./report-meta.js";
import type { SponsoredPostIdempotencyStore } from "../../sponsored-post/idempotency.js";
import {
  approveSponsoredPost,
  parseSponsoredPostRequest,
  type SponsoredPostModerationPort,
} from "../../sponsored-post/policy.js";
import { SponsoredPostPublishError, type SponsoredPostPort } from "../../sponsored-post/x-api.js";
import {
  SPONSORED_POST_SERVICE_ID,
  type SponsoredPostDeliverable,
} from "../../sponsored-post/types.js";

export { SPONSORED_POST_SERVICE_ID };

function requestHash(text: string): string {
  return createHash("sha256").update(JSON.stringify({ text }), "utf8").digest("hex");
}

/** Paid work callback with durable, fail-closed exactly-once publication semantics. */
export function makeSponsoredPostWork(
  publisher: SponsoredPostPort,
  moderation: SponsoredPostModerationPort,
  state: SponsoredPostIdempotencyStore,
): WorkCallback {
  let tail: Promise<unknown> = Promise.resolve();
  const serialize = <T>(fn: () => Promise<T>): Promise<T> => {
    const current = tail.then(fn, fn);
    tail = current.then(() => undefined, () => undefined);
    return current;
  };

  return (jobId, params) => serialize(async () => {
    const request = parseSponsoredPostRequest(params);
    const hash = requestHash(request.text);
    const reservation = await state.begin(jobId, hash);
    if (reservation.kind === "pending") {
      throw new Error("sponsored-post publication is indeterminate; reconcile the dedicated X account before retrying");
    }
    let approved: { textHash: string; decisionRef?: string } = {
      textHash: createHash("sha256").update(request.text, "utf8").digest("hex"),
      ...(reservation.kind === "complete" && reservation.moderationDecisionRef !== undefined
        ? { decisionRef: reservation.moderationDecisionRef }
        : {}),
    };
    let post = reservation.kind === "complete" ? reservation.post : undefined;
    if (!post) {
      try {
        approved = await approveSponsoredPost(request, moderation);
        post = await publisher.publish({ text: request.text });
      } catch (error) {
        if (!(error instanceof SponsoredPostPublishError) || error.outcome === "rejected") {
          await state.releaseRejected(jobId, hash);
        }
        throw error;
      }
      await state.complete(jobId, hash, post, approved.decisionRef);
    }
    if (post.text !== request.text || post.paidPartnership !== true) {
      throw new Error("published post does not match the approved paid-partnership request");
    }
    const deliverable: SponsoredPostDeliverable = {
      kind: "sponsored-post-publication",
      postId: post.postId,
      textBase64: Buffer.from(post.text, "utf8").toString("base64url"),
      handle: post.handle,
      url: post.url,
      publishedAt: post.publishedAt,
      paidPartnership: true,
      madeWithAi: false,
      textHash: approved.textHash,
      requestHash: hash,
    };
    const meta = {
      ...reportMeta(deliverable),
      textHash: approved.textHash,
      postId: post.postId,
      postUrl: post.url,
      ...(approved.decisionRef === undefined ? {} : { moderationDecisionRef: approved.decisionRef }),
    };
    return {
      result: {
        postId: post.postId,
        url: post.url,
        handle: post.handle,
        textHash: approved.textHash,
        reportHash: meta.reportHash,
        paidPartnership: true,
      },
      deliverableRef: `x:post:${post.postId}`,
      meta,
    };
  });
}

/** Offline validation of the seller-signed publication evidence. */
export function sponsoredPostObserveDelivered(
  expectedHandle?: string,
): DeliveryVerifyOptions["observeDelivered"] {
  return async (att) => {
    const read = readReportMeta<SponsoredPostDeliverable>(att);
    if (!read.ok) return { ok: false, reason: read.reason };
    const post = read.artifact;
    if (post.kind !== "sponsored-post-publication") return { ok: false, reason: "delivery is not sponsored-post publication evidence" };
    if (!/^[0-9]{1,19}$/.test(post.postId)) return { ok: false, reason: "publication evidence carries an invalid X post id" };
    if (!/^[A-Za-z0-9_]{1,15}$/.test(post.handle)) return { ok: false, reason: "publication evidence carries an invalid X handle" };
    if (expectedHandle && post.handle.toLowerCase() !== expectedHandle.replace(/^@/, "").toLowerCase()) {
      return { ok: false, reason: "publication evidence names the wrong X account" };
    }
    if (post.url !== `https://x.com/${post.handle}/status/${post.postId}`) return { ok: false, reason: "publication URL is not canonical" };
    let text: string;
    try {
      const decoded = Buffer.from(post.textBase64, "base64url");
      if (decoded.toString("base64url") !== post.textBase64) return { ok: false, reason: "published text encoding is not canonical" };
      text = decoded.toString("utf8");
      parseSponsoredPostRequest({ text });
    } catch {
      return { ok: false, reason: "published text encoding or policy shape is invalid" };
    }
    if (post.textHash !== createHash("sha256").update(text, "utf8").digest("hex")) return { ok: false, reason: "published text does not match its text hash" };
    if (post.requestHash !== requestHash(text)) return { ok: false, reason: "published text does not match its request hash" };
    if (post.paidPartnership !== true || post.madeWithAi !== false) return { ok: false, reason: "required X disclosure flags are missing" };
    if (!Number.isSafeInteger(post.publishedAt) || post.publishedAt <= 0) return { ok: false, reason: "publication timestamp is invalid" };
    return { ok: true };
  };
}
