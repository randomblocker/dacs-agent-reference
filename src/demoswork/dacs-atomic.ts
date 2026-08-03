import { canonicalize, sha256Hex } from "@kynesyslabs/dacs";
import {
  ed25519Sign,
  ed25519Verify,
  privateKeyFromSeed,
  publicKeyFromRaw,
} from "@kynesyslabs/dacs/crypto";

export type DacsWorkProfile = "dacs-purchase-v1" | "dacs-completion-v1";

export type OperationAuthorization = {
  signer: string;
  algorithm: "ed25519";
  signature: string;
  signedPayloadHash: string;
  expiresAt: number;
};

type OperationBase = {
  operationId: string;
  critical: true;
  dependsOn: string[];
  requiredSigners: string[];
  authorizations: OperationAuthorization[];
};

export type AssertArtifactOperation = OperationBase & {
  type: "assertArtifact";
  domain: string;
  canonicalContentHash: string;
};

export type StorageProgramPutOperation = OperationBase & {
  type: "storageProgramPut";
  logicalAddress: string;
  contentHash: string;
  content?: Record<string, unknown>;
  externalContent?: { uri: string; contentHash: string };
  writeMode: "create-only" | "compare-and-set";
  expectedCurrentHash?: string;
};

export type NativeTransferOperation = OperationBase & {
  type: "nativeTransfer";
  payer: string;
  payee: string;
  amount: string;
  asset: "demos-native:DEM";
  jobId: string;
  phaseIndex: number;
};

export type DacsWorkOperation =
  | AssertArtifactOperation
  | StorageProgramPutOperation
  | NativeTransferOperation;

export type DacsAtomicWork = {
  version: "dacs-demoswork-poc-v1";
  profile: DacsWorkProfile;
  chainId: string;
  jobId: string;
  expiresAt: number;
  workId: string;
  operations: DacsWorkOperation[];
};

export type OperationSigner = {
  signer: string;
  seed: Uint8Array;
};

const HEX_64 = /^[0-9a-f]{64}$/;
const ID = /^[a-z][a-z0-9-]{0,63}$/;
const DOMAIN = "demoswork-operation:v1";
const MAX_INLINE_CONTENT_BYTES = 16_384;
const MAX_INTENT_BYTES = 131_072;

function withoutAuthorizations(operation: DacsWorkOperation): Record<string, unknown> {
  const { authorizations: _authorizations, ...payload } = operation;
  return payload;
}

export function operationPayloadHash(operation: DacsWorkOperation): string {
  return sha256Hex(canonicalize(withoutAuthorizations(operation)));
}

export function canonicalWorkIntent(work: Omit<DacsAtomicWork, "workId"> | DacsAtomicWork): Record<string, unknown> {
  return {
    version: work.version,
    profile: work.profile,
    chainId: work.chainId,
    jobId: work.jobId,
    expiresAt: work.expiresAt,
    operations: work.operations.map((operation) => ({
      operationId: operation.operationId,
      type: operation.type,
      critical: operation.critical,
      dependsOn: operation.dependsOn,
      requiredSigners: operation.requiredSigners,
      payloadHash: operationPayloadHash(operation),
    })),
  };
}

export function calculateWorkId(work: Omit<DacsAtomicWork, "workId"> | DacsAtomicWork): string {
  return sha256Hex(`demoswork-intent:v1:${canonicalize(canonicalWorkIntent(work))}`);
}

export function operationReference(workId: string, operationId: string): string {
  if (!HEX_64.test(workId) || !ID.test(operationId)) throw new Error("invalid Demos Work operation reference");
  return `demoswork:${workId}:${operationId}`;
}

export function predictedStorageLocator(workId: string, operationId: string, logicalAddress: string): string {
  const digest = sha256Hex(canonicalize({ domain: "demoswork-storage:v1", workId, operationId, logicalAddress }));
  return `stor-${digest.slice(0, 40)}`;
}

export function operationAuthorizationPayloadHash(
  work: DacsAtomicWork,
  operation: DacsWorkOperation,
  expiresAt: number,
): string {
  return sha256Hex(canonicalize({
    domain: DOMAIN,
    chainId: work.chainId,
    workId: work.workId,
    operationId: operation.operationId,
    operationType: operation.type,
    canonicalOperationPayloadHash: operationPayloadHash(operation),
    jobId: work.jobId,
    expiresAt,
  }));
}

export function authorizeWork(work: DacsAtomicWork, signers: readonly OperationSigner[]): DacsAtomicWork {
  assertWorkShape(work, false);
  const seeds = new Map(signers.map((entry) => [entry.signer, entry.seed]));
  const operations = work.operations.map((operation) => {
    const authorizations = operation.requiredSigners.map((signer) => {
      const seed = seeds.get(signer);
      if (!seed) throw new Error(`missing operation signer ${signer}`);
      const signedPayloadHash = operationAuthorizationPayloadHash(work, operation, work.expiresAt);
      const signature = ed25519Sign(
        Buffer.from(signedPayloadHash, "ascii"),
        privateKeyFromSeed(seed),
      );
      return {
        signer,
        algorithm: "ed25519" as const,
        signature: Buffer.from(signature).toString("base64url"),
        signedPayloadHash,
        expiresAt: work.expiresAt,
      };
    });
    return { ...operation, authorizations } as DacsWorkOperation;
  });
  return { ...work, operations };
}

export function verifyOperationAuthorization(
  work: DacsAtomicWork,
  operation: DacsWorkOperation,
  authorization: OperationAuthorization,
  publicKey: Uint8Array,
  now: number,
): boolean {
  if (authorization.algorithm !== "ed25519"
    || authorization.expiresAt !== work.expiresAt
    || authorization.expiresAt < now) return false;
  const expected = operationAuthorizationPayloadHash(work, operation, authorization.expiresAt);
  if (authorization.signedPayloadHash !== expected) return false;
  try {
    return ed25519Verify(
      Buffer.from(expected, "ascii"),
      Buffer.from(authorization.signature, "base64url"),
      publicKeyFromRaw(publicKey),
    );
  } catch {
    return false;
  }
}

function assertCommonOperation(operation: DacsWorkOperation): void {
  if (!ID.test(operation.operationId)) throw new Error(`invalid operationId ${operation.operationId}`);
  if (operation.critical !== true) throw new Error(`${operation.operationId} must be critical`);
  if (!Array.isArray(operation.dependsOn) || new Set(operation.dependsOn).size !== operation.dependsOn.length) {
    throw new Error(`${operation.operationId} has invalid dependencies`);
  }
  if (!Array.isArray(operation.requiredSigners)
    || operation.requiredSigners.length === 0
    || new Set(operation.requiredSigners).size !== operation.requiredSigners.length
    || operation.requiredSigners.some((signer) => typeof signer !== "string" || !signer)) {
    throw new Error(`${operation.operationId} has invalid required signers`);
  }
}

export function assertWorkShape(work: DacsAtomicWork, requireAuthorizations = true): void {
  if (work.version !== "dacs-demoswork-poc-v1") throw new Error("unsupported Demos Work version");
  if (work.profile !== "dacs-purchase-v1" && work.profile !== "dacs-completion-v1") {
    throw new Error("unsupported DACS Demos Work profile");
  }
  if (!work.chainId || !work.jobId || !Number.isSafeInteger(work.expiresAt) || work.expiresAt <= 0) {
    throw new Error("invalid Demos Work identity or expiry");
  }
  if (!Array.isArray(work.operations) || work.operations.length === 0 || work.operations.length > 16) {
    throw new Error("Demos Work must contain 1..16 operations");
  }
  const seen = new Set<string>();
  for (const operation of work.operations) {
    assertCommonOperation(operation);
    if (seen.has(operation.operationId)) throw new Error(`duplicate operationId ${operation.operationId}`);
    for (const dependency of operation.dependsOn) {
      if (!seen.has(dependency)) throw new Error(`${operation.operationId} depends on an unavailable operation`);
    }
    seen.add(operation.operationId);
    if (operation.type === "assertArtifact") {
      if (!operation.domain || !HEX_64.test(operation.canonicalContentHash)) throw new Error("invalid artifact assertion");
    } else if (operation.type === "storageProgramPut") {
      if (!operation.logicalAddress || !HEX_64.test(operation.contentHash)) throw new Error("invalid storage operation");
      if (operation.writeMode !== "create-only" && operation.writeMode !== "compare-and-set") {
        throw new Error("invalid storage write mode");
      }
      if ((operation.content === undefined) === (operation.externalContent === undefined)) {
        throw new Error("storage operation requires exactly one content source");
      }
      if (operation.content && sha256Hex(canonicalize(operation.content)) !== operation.contentHash) {
        throw new Error("storage operation content hash mismatch");
      }
      if (operation.content && Buffer.byteLength(canonicalize(operation.content), "utf8") > MAX_INLINE_CONTENT_BYTES) {
        throw new Error("storage operation inline content exceeds 16384 bytes; use externalContent");
      }
      if (operation.externalContent && operation.externalContent.contentHash !== operation.contentHash) {
        throw new Error("external storage content hash mismatch");
      }
      if (operation.externalContent && !operation.externalContent.uri) {
        throw new Error("external storage content requires a URI");
      }
      if (operation.writeMode === "compare-and-set" && !HEX_64.test(operation.expectedCurrentHash ?? "")) {
        throw new Error("compare-and-set requires expectedCurrentHash");
      }
    } else if (operation.type === "nativeTransfer") {
      if (!operation.payer || !operation.payee || operation.jobId !== work.jobId
        || operation.asset !== "demos-native:DEM"
        || !Number.isSafeInteger(operation.phaseIndex) || operation.phaseIndex < 0
        || !/^(0|[1-9][0-9]*)$/.test(operation.amount) || BigInt(operation.amount) <= 0n) {
        throw new Error("invalid native transfer");
      }
      if (!operation.requiredSigners.includes(operation.payer)) throw new Error("native transfer requires payer signature");
    } else {
      const neverOperation: never = operation;
      throw new Error(`unsupported operation ${(neverOperation as { type: string }).type}`);
    }
    if (requireAuthorizations) {
      const actual = operation.authorizations.map((authorization) => authorization.signer);
      if (actual.length !== operation.requiredSigners.length
        || actual.some((signer, index) => signer !== operation.requiredSigners[index])) {
        throw new Error(`${operation.operationId} authorizations do not match required signers`);
      }
    }
  }
  if (calculateWorkId(work) !== work.workId) throw new Error("Demos Work id does not match its frozen intent");
  const nativeTransfers = work.operations.filter((operation) => operation.type === "nativeTransfer").length;
  if (work.profile === "dacs-purchase-v1" && nativeTransfers !== 1) {
    throw new Error("Purchase Work requires exactly one native transfer");
  }
  if (work.profile === "dacs-completion-v1" && nativeTransfers !== 0) {
    throw new Error("Completion Work cannot move value");
  }
  if (Buffer.byteLength(canonicalize(canonicalWorkIntent(work)), "utf8") > MAX_INTENT_BYTES) {
    throw new Error("Demos Work intent exceeds 131072 bytes");
  }
}

type NewOperation<T extends DacsWorkOperation> = Omit<T, keyof OperationBase | "type"> & {
  operationId: string;
  dependsOn?: string[];
  requiredSigners: string[];
};

export class DacsAtomicWorkBuilder {
  private readonly operations: DacsWorkOperation[] = [];

  constructor(private readonly header: {
    profile: DacsWorkProfile;
    chainId: string;
    jobId: string;
    expiresAt: number;
  }) {}

  assertArtifact(input: NewOperation<AssertArtifactOperation>): this {
    this.operations.push({ ...input, type: "assertArtifact", critical: true, dependsOn: input.dependsOn ?? [], authorizations: [] });
    return this;
  }

  storageProgramPut(input: NewOperation<StorageProgramPutOperation>): this {
    this.operations.push({ ...input, type: "storageProgramPut", critical: true, dependsOn: input.dependsOn ?? [], authorizations: [] });
    return this;
  }

  nativeTransfer(input: NewOperation<NativeTransferOperation>): this {
    this.operations.push({ ...input, type: "nativeTransfer", critical: true, dependsOn: input.dependsOn ?? [], authorizations: [] });
    return this;
  }

  seal(): DacsAtomicWork {
    const unsigned = {
      version: "dacs-demoswork-poc-v1" as const,
      ...this.header,
      operations: structuredClone(this.operations),
    };
    const work: DacsAtomicWork = { ...unsigned, workId: calculateWorkId(unsigned) };
    assertWorkShape(work, false);
    return work;
  }
}
