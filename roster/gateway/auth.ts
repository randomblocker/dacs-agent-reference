/**
 * Bearer-token auth — constant-time comparison, length-guarded.
 *
 * `Authorization: Bearer <token>` is required for POST when a token is
 * configured. The compare uses crypto.timingSafeEqual, which THROWS on a
 * length mismatch — so we length-guard first and only call it on equal-length
 * buffers, keeping the comparison constant-time without leaking length via an
 * exception path.
 */
import { timingSafeEqual } from "node:crypto";

/** Extract the raw token from an Authorization header, or null. */
export function parseBearer(header: string | undefined): string | null {
  if (!header) return null;
  const m = /^Bearer[ ]+(.+)$/.exec(header.trim());
  return m ? m[1]!.trim() : null;
}

/**
 * Constant-time string equality. Returns false (never throws) on a length
 * mismatch or when either side is empty.
 */
export function constantTimeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length === 0 || bb.length === 0) return false;
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

/**
 * Decide whether a request is authorized to POST.
 *   - expected === null → auth not enforced (open dev mode): always true.
 *   - otherwise the header must carry a Bearer token equal to `expected`.
 */
export function isAuthorized(authHeader: string | undefined, expected: string | null): boolean {
  if (expected === null) return true;
  const presented = parseBearer(authHeader);
  if (presented === null) return false;
  return constantTimeEqual(presented, expected);
}
