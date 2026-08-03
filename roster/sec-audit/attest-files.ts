/**
 * File-content evidence. Production reports sign each hash with the persistent
 * seller DACS identity; offline demos retain the loudly-labelled mock. Posted
 * source is never published merely to route it through public-HTTP DAHR.
 */
import { createHash } from "node:crypto";
import { MockDahrAttestor, verifyAttestedRecord } from "../oracle-desk/attested-fetch.js";
import { resolveFromDid, verify } from "../../src/identity.js";
import type { AttestedFileRecord, SecAuditAttestation } from "./types.js";

export { MockDahrAttestor } from "../oracle-desk/attested-fetch.js";

const CONTENT_EVIDENCE_DOMAIN = "DACS-SEC-AUDIT-CONTENT-EVIDENCE-V1\x00";

export interface ContentAttestor {
  attest(url: string, attestedAt: string, bodyHash: string): SecAuditAttestation | Promise<SecAuditAttestation>;
}

export interface PersistentSellerParty {
  primaryClaim: string;
  sign(bytes: Uint8Array): Uint8Array | Promise<Uint8Array>;
}

/** Domain-separated digest shared by the persistent signer and verifier. */
export function contentEvidenceDigest(url: string, attestedAt: string, bodyHash: string): string {
  return sha256HexBytes(Buffer.from(`${CONTENT_EVIDENCE_DOMAIN}${url}|${attestedAt}|${bodyHash}`, "utf8"));
}

/** Production content attestor backed by the seller's long-lived DACS identity. */
export class DacsSellerAttestor implements ContentAttestor {
  constructor(private readonly party: PersistentSellerParty) {}

  async attest(url: string, attestedAt: string, bodyHash: string): Promise<SecAuditAttestation> {
    const digest = contentEvidenceDigest(url, attestedAt, bodyHash);
    // Sign the canonical ASCII hex representation, not arbitrary binary hash
    // bytes. Besides making the wire input inspectable, this is required by the
    // current Demos SDK signer, whose ed25519 path signs UTF-8 message content.
    const signature = await this.party.sign(Buffer.from(digest, "utf8"));
    return {
      scheme: "DACS-SELLER-ed25519",
      note:
        "Persistent DACS seller identity signature over private content metadata; " +
        "the enclosing delivery artifact is anchored through DACS-4/SR-2. This is not a DAHR public-Web2 fetch.",
      digest,
      signature: Buffer.from(signature).toString("base64url"),
      publicKey: this.party.primaryClaim,
    };
  }
}

/** Files have no URL; attest them under a stable pseudo-URL. */
export function filePseudoUrl(relPath: string): string {
  return `file:${relPath}`;
}

/** sha256 hex over raw bytes (files may be binary; never hash via utf8 text). */
export function sha256HexBytes(data: Buffer | Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

/**
 * Attest one file's content. The body (the file bytes) is hashed and
 * dropped — the record carries path, sha256, size, and the signature only.
 */
export function attestFileContent(
  attestor: MockDahrAttestor,
  id: string,
  relPath: string,
  content: Buffer,
  now: Date = new Date(),
): AttestedFileRecord {
  const attestedAt = now.toISOString();
  const sha256 = sha256HexBytes(content);
  return {
    id,
    path: relPath,
    sha256,
    size: content.length,
    attestedAt,
    attestation: attestor.attest(filePseudoUrl(relPath), attestedAt, sha256),
  };
}

/** Async variant used by production identity-backed attestors. */
export async function attestFileContentAsync(
  attestor: ContentAttestor,
  id: string,
  relPath: string,
  content: Buffer,
  now: Date = new Date(),
): Promise<AttestedFileRecord> {
  const attestedAt = now.toISOString();
  const sha256 = sha256HexBytes(content);
  return {
    id,
    path: relPath,
    sha256,
    size: content.length,
    attestedAt,
    attestation: await attestor.attest(filePseudoUrl(relPath), attestedAt, sha256),
  };
}

/** Verify either offline mock evidence or a persistent DACS seller signature. */
export function verifyContentEvidence(
  record: { url: string; fetchedAt: string; bodyHash: string; attestation: SecAuditAttestation },
  expectedSellerDid?: string,
): { valid: boolean; reason?: string } {
  const att = record.attestation;
  if (att.scheme !== "DACS-SELLER-ed25519") {
    if (expectedSellerDid) {
      return { valid: false, reason: `expected persistent seller evidence from ${expectedSellerDid}, got ${att.scheme}` };
    }
    return verifyAttestedRecord(record as Parameters<typeof verifyAttestedRecord>[0]);
  }

  if (expectedSellerDid && att.publicKey !== expectedSellerDid) {
    return { valid: false, reason: `seller DID mismatch: expected ${expectedSellerDid}, got ${att.publicKey}` };
  }
  const key = resolveFromDid(att.publicKey);
  if (!key) return { valid: false, reason: `seller DID does not contain a resolvable ed25519 key: ${att.publicKey}` };
  const digest = contentEvidenceDigest(record.url, record.fetchedAt, record.bodyHash);
  if (att.digest !== digest) return { valid: false, reason: "content evidence digest mismatch" };
  try {
    const signature = Buffer.from(att.signature, "base64url");
    return verify(Buffer.from(digest, "utf8"), signature, key)
      ? { valid: true }
      : { valid: false, reason: "invalid persistent seller signature" };
  } catch (error) {
    return { valid: false, reason: `malformed persistent seller signature: ${(error as Error).message}` };
  }
}

/**
 * Offline third-party check of a file record: recompute the digest over
 * `file:<path>|attestedAt|sha256` and verify the ed25519 signature.
 */
export function verifyFileRecord(
  record: AttestedFileRecord,
  expectedSellerDid?: string,
): { valid: boolean; reason?: string } {
  return verifyContentEvidence({
    url: filePseudoUrl(record.path),
    fetchedAt: record.attestedAt,
    bodyHash: record.sha256,
    attestation: record.attestation,
  }, expectedSellerDid);
}

/**
 * Deterministic JSON: keys sorted recursively. Used for the report seal so
 * the same report content always hashes identically.
 */
export function canonicalJson(v: unknown): string {
  const sortValue = (x: unknown): unknown => {
    if (Array.isArray(x)) return x.map(sortValue);
    if (x !== null && typeof x === "object") {
      const rec = x as Record<string, unknown>;
      return Object.fromEntries(
        Object.keys(rec)
          .sort()
          .map((k) => [k, sortValue(rec[k])]),
      );
    }
    return x;
  };
  return JSON.stringify(sortValue(v));
}
