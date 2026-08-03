import { canonicalize, sha256Hex } from "@kynesyslabs/dacs";
import {
  assertWorkShape,
  operationPayloadHash,
  predictedStorageLocator,
  verifyOperationAuthorization,
  type DacsAtomicWork,
  type DacsWorkOperation,
} from "./dacs-atomic.js";

export type WorkFailureCode =
  | "expired"
  | "invalid-authorization"
  | "dependency-failure"
  | "insufficient-funds"
  | "conflicting-storage"
  | "conflicting-job"
  | "payment-slot-consumed"
  | "nonce-conflict"
  | "future-nonce"
  | "invalid-work";

export class DemosWorkExecutionError extends Error {
  constructor(
    readonly code: WorkFailureCode,
    message: string,
    readonly operationId?: string,
  ) {
    super(message);
    this.name = "DemosWorkExecutionError";
  }
}

export type DemosWorkOperationResult = {
  operationId: string;
  type: DacsWorkOperation["type"];
  status: "success";
  outputHash: string;
  storageRef?: { locator: string; contentHash: string };
  transferRef?: { payer: string; payee: string; amount: string; asset: string };
};

export type DemosWorkReceipt = {
  version: "1";
  workId: string;
  txHash: string;
  blockNumber: number;
  blockTimestamp: number;
  state: "included";
  receiptRoot: string;
  operationResults: DemosWorkOperationResult[];
  stateChangesRoot: string;
  feeCharged: string;
  nonceConsumed: number;
};

export type StoredValue = {
  locator: string;
  contentHash: string;
  content?: Record<string, unknown>;
  externalContent?: { uri: string; contentHash: string };
};

type MutableState = {
  balances: Map<string, bigint>;
  storage: Map<string, StoredValue>;
  paymentSlots: Map<string, string>;
  jobSlots: Map<string, string>;
  nextNonces: Map<string, number>;
};

export type AtomicDemosWorkSnapshot = {
  version: "1";
  blockNumber: number;
  balances: Array<[string, string]>;
  storage: Array<[string, StoredValue]>;
  paymentSlots: Array<[string, string]>;
  jobSlots: Array<[string, string]>;
  nextNonces: Array<[string, number]>;
  receipts: DemosWorkReceipt[];
};

function byteCompare(a: string, b: string): number {
  return Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}

function cloneState(state: MutableState): MutableState {
  return {
    balances: new Map(state.balances),
    storage: new Map([...state.storage].map(([key, value]) => [key, structuredClone(value)])),
    paymentSlots: new Map(state.paymentSlots),
    jobSlots: new Map(state.jobSlots),
    nextNonces: new Map(state.nextNonces),
  };
}

function stateRoot(state: MutableState): string {
  return sha256Hex(canonicalize({
    balances: [...state.balances].sort(([a], [b]) => byteCompare(a, b)).map(([address, amount]) => [address, amount.toString()]),
    storage: [...state.storage].sort(([a], [b]) => byteCompare(a, b)),
    paymentSlots: [...state.paymentSlots].sort(([a], [b]) => byteCompare(a, b)),
    jobSlots: [...state.jobSlots].sort(([a], [b]) => byteCompare(a, b)),
    nextNonces: [...state.nextNonces].sort(([a], [b]) => byteCompare(a, b)),
  }));
}

type ReceiptBody = Omit<DemosWorkReceipt, "receiptRoot">;

function receiptRoot(receipt: ReceiptBody): string {
  return sha256Hex(canonicalize({ domain: "demoswork-receipt:v1", ...receipt }));
}

export class AtomicDemosWorkMemoryExecutor {
  private state: MutableState;
  private readonly receipts = new Map<string, DemosWorkReceipt>();
  private blockNumber = 0;

  constructor(
    private readonly publicKeys: ReadonlyMap<string, Uint8Array>,
    snapshot?: AtomicDemosWorkSnapshot,
  ) {
    if (!snapshot) {
      this.state = {
        balances: new Map(),
        storage: new Map(),
        paymentSlots: new Map(),
        jobSlots: new Map(),
        nextNonces: new Map(),
      };
      return;
    }
    if (snapshot.version !== "1" || !Number.isSafeInteger(snapshot.blockNumber) || snapshot.blockNumber < 0) {
      throw new Error("invalid Demos Work snapshot");
    }
    this.state = {
      balances: new Map(snapshot.balances.map(([address, amount]) => [address, BigInt(amount)])),
      storage: new Map(structuredClone(snapshot.storage)),
      paymentSlots: new Map(snapshot.paymentSlots),
      jobSlots: new Map(snapshot.jobSlots),
      nextNonces: new Map(snapshot.nextNonces),
    };
    this.blockNumber = snapshot.blockNumber;
    for (const receipt of snapshot.receipts) {
      if (!verifyDemosWorkReceipt(receipt)) throw new Error("snapshot contains an invalid Demos Work receipt");
      this.receipts.set(receipt.workId, structuredClone(receipt));
    }
  }

  setBalance(address: string, amount: bigint): void {
    if (amount < 0n) throw new Error("balance cannot be negative");
    this.state.balances.set(address, amount);
  }

  balance(address: string): bigint {
    return this.state.balances.get(address) ?? 0n;
  }

  stored(logicalAddress: string): StoredValue | undefined {
    const value = this.state.storage.get(logicalAddress);
    return value ? structuredClone(value) : undefined;
  }

  getReceipt(workId: string): DemosWorkReceipt | undefined {
    const receipt = this.receipts.get(workId);
    return receipt ? structuredClone(receipt) : undefined;
  }

  snapshot(): AtomicDemosWorkSnapshot {
    return {
      version: "1",
      blockNumber: this.blockNumber,
      balances: [...this.state.balances].map(([address, amount]) => [address, amount.toString()]),
      storage: structuredClone([...this.state.storage]),
      paymentSlots: [...this.state.paymentSlots],
      jobSlots: [...this.state.jobSlots],
      nextNonces: [...this.state.nextNonces],
      receipts: [...this.receipts.values()].map((receipt) => structuredClone(receipt)),
    };
  }

  execute(work: DacsAtomicWork, options: { now: number; nonce: number; submitter?: string }): DemosWorkReceipt {
    const prior = this.receipts.get(work.workId);
    if (prior) return structuredClone(prior);
    try {
      assertWorkShape(work);
    } catch (error) {
      throw new DemosWorkExecutionError("invalid-work", (error as Error).message);
    }
    if (!Number.isSafeInteger(options.now) || options.now < 0) {
      throw new DemosWorkExecutionError("invalid-work", "execution time must be a non-negative unix millisecond integer");
    }
    if (work.expiresAt < options.now) throw new DemosWorkExecutionError("expired", "Demos Work expired");
    if (!Number.isSafeInteger(options.nonce) || options.nonce < 0) {
      throw new DemosWorkExecutionError("nonce-conflict", "Demos Work nonce must be a non-negative safe integer");
    }
    const submitter = options.submitter ?? "__default__";
    const expectedNonce = this.state.nextNonces.get(submitter);
    if (expectedNonce !== undefined && options.nonce < expectedNonce) {
      throw new DemosWorkExecutionError("nonce-conflict", `nonce ${options.nonce} is below expected nonce ${expectedNonce}`);
    }
    if (expectedNonce !== undefined && options.nonce > expectedNonce) {
      throw new DemosWorkExecutionError("future-nonce", `nonce ${options.nonce} is above expected nonce ${expectedNonce}`);
    }
    const jobSlot = `${work.profile}:${work.jobId}`;
    const priorJob = this.state.jobSlots.get(jobSlot);
    if (priorJob && priorJob !== work.workId) {
      throw new DemosWorkExecutionError("conflicting-job", "a different Work already committed this job/profile slot");
    }

    const overlay = cloneState(this.state);
    const results: DemosWorkOperationResult[] = [];
    const succeeded = new Set<string>();

    for (const operation of work.operations) {
      if (operation.dependsOn.some((dependency) => !succeeded.has(dependency))) {
        throw new DemosWorkExecutionError("dependency-failure", "operation dependency did not succeed", operation.operationId);
      }
      this.verifyAuthorizations(work, operation, options.now);
      const result = this.executeOperation(work, operation, overlay);
      results.push(result);
      succeeded.add(operation.operationId);
    }

    overlay.jobSlots.set(jobSlot, work.workId);
    overlay.nextNonces.set(submitter, options.nonce + 1);
    const nextBlock = this.blockNumber + 1;
    const txHash = sha256Hex(canonicalize({
      domain: "demoswork-memory-tx:v1",
      workId: work.workId,
      nonce: options.nonce,
      blockNumber: nextBlock,
    }));
    const receiptBody: ReceiptBody = {
      version: "1",
      workId: work.workId,
      txHash,
      blockNumber: nextBlock,
      blockTimestamp: options.now,
      state: "included",
      operationResults: results,
      stateChangesRoot: stateRoot(overlay),
      feeCharged: "0",
      nonceConsumed: options.nonce,
    };
    const receipt: DemosWorkReceipt = { ...receiptBody, receiptRoot: receiptRoot(receiptBody) };
    this.state = overlay;
    this.blockNumber = nextBlock;
    this.receipts.set(work.workId, structuredClone(receipt));
    return receipt;
  }

  private verifyAuthorizations(work: DacsAtomicWork, operation: DacsWorkOperation, now: number): void {
    for (const authorization of operation.authorizations) {
      const publicKey = this.publicKeys.get(authorization.signer);
      if (!publicKey || !verifyOperationAuthorization(work, operation, authorization, publicKey, now)) {
        throw new DemosWorkExecutionError(
          "invalid-authorization",
          `invalid authorization from ${authorization.signer}`,
          operation.operationId,
        );
      }
    }
  }

  private executeOperation(
    work: DacsAtomicWork,
    operation: DacsWorkOperation,
    overlay: MutableState,
  ): DemosWorkOperationResult {
    if (operation.type === "assertArtifact") {
      return {
        operationId: operation.operationId,
        type: operation.type,
        status: "success",
        outputHash: operation.canonicalContentHash,
      };
    }
    if (operation.type === "storageProgramPut") {
      const current = overlay.storage.get(operation.logicalAddress);
      if (operation.writeMode === "create-only" && current) {
        throw new DemosWorkExecutionError("conflicting-storage", "create-only storage slot is occupied", operation.operationId);
      }
      if (operation.writeMode === "compare-and-set"
        && current?.contentHash !== operation.expectedCurrentHash) {
        throw new DemosWorkExecutionError("conflicting-storage", "compare-and-set storage hash mismatch", operation.operationId);
      }
      const locator = predictedStorageLocator(work.workId, operation.operationId, operation.logicalAddress);
      overlay.storage.set(operation.logicalAddress, {
        locator,
        contentHash: operation.contentHash,
        ...(operation.content ? { content: structuredClone(operation.content) } : {}),
        ...(operation.externalContent ? { externalContent: structuredClone(operation.externalContent) } : {}),
      });
      return {
        operationId: operation.operationId,
        type: operation.type,
        status: "success",
        outputHash: operation.contentHash,
        storageRef: { locator, contentHash: operation.contentHash },
      };
    }
    if (operation.type === "nativeTransfer") {
      const slot = `${operation.jobId}:${operation.phaseIndex}`;
      const consumedBy = overlay.paymentSlots.get(slot);
      if (consumedBy && consumedBy !== work.workId) {
        throw new DemosWorkExecutionError("payment-slot-consumed", "payment slot already consumed", operation.operationId);
      }
      const amount = BigInt(operation.amount);
      const payerBalance = overlay.balances.get(operation.payer) ?? 0n;
      if (payerBalance < amount) {
        throw new DemosWorkExecutionError("insufficient-funds", "native transfer has insufficient funds", operation.operationId);
      }
      overlay.balances.set(operation.payer, payerBalance - amount);
      overlay.balances.set(operation.payee, (overlay.balances.get(operation.payee) ?? 0n) + amount);
      overlay.paymentSlots.set(slot, work.workId);
      const transferRef = {
        payer: operation.payer,
        payee: operation.payee,
        amount: operation.amount,
        asset: operation.asset,
      };
      return {
        operationId: operation.operationId,
        type: operation.type,
        status: "success",
        outputHash: sha256Hex(canonicalize(transferRef)),
        transferRef,
      };
    }
    const neverOperation: never = operation;
    throw new DemosWorkExecutionError("invalid-work", `unsupported operation ${(neverOperation as { type: string }).type}`);
  }
}

export function verifyDemosWorkReceipt(receipt: DemosWorkReceipt): boolean {
  if (receipt.version !== "1" || receipt.state !== "included"
    || !/^[0-9a-f]{64}$/.test(receipt.workId)
    || !/^[0-9a-f]{64}$/.test(receipt.txHash)
    || !/^[0-9a-f]{64}$/.test(receipt.receiptRoot)
    || !/^[0-9a-f]{64}$/.test(receipt.stateChangesRoot)
    || !Number.isSafeInteger(receipt.blockNumber) || receipt.blockNumber < 1
    || !Number.isSafeInteger(receipt.blockTimestamp) || receipt.blockTimestamp < 0
    || !/^(0|[1-9][0-9]*)$/.test(receipt.feeCharged)
    || !Number.isSafeInteger(receipt.nonceConsumed) || receipt.nonceConsumed < 0) return false;
  if (!Array.isArray(receipt.operationResults)
    || receipt.operationResults.length === 0
    || receipt.operationResults.length > 16
    || new Set(receipt.operationResults.map((result) => result.operationId)).size !== receipt.operationResults.length) {
    return false;
  }
  const { receiptRoot: claimedRoot, ...body } = receipt;
  if (claimedRoot !== receiptRoot(body)) return false;
  return receipt.operationResults.every((result) => {
    if (!/^[a-z][a-z0-9-]{0,63}$/.test(result.operationId)
      || (result.type !== "assertArtifact" && result.type !== "storageProgramPut" && result.type !== "nativeTransfer")
      || result.status !== "success"
      || !/^[0-9a-f]{64}$/.test(result.outputHash)) return false;
    if (result.storageRef && (result.type !== "storageProgramPut"
      || !/^stor-[0-9a-f]{40}$/.test(result.storageRef.locator)
      || result.outputHash !== result.storageRef.contentHash)) return false;
    if (result.transferRef && (result.type !== "nativeTransfer"
      || !result.transferRef.payer
      || !result.transferRef.payee
      || !/^(0|[1-9][0-9]*)$/.test(result.transferRef.amount)
      || BigInt(result.transferRef.amount) <= 0n
      || result.transferRef.asset !== "demos-native:DEM")) return false;
    return result.type === "storageProgramPut" ? result.storageRef !== undefined
      : result.type === "nativeTransfer" ? result.transferRef !== undefined
        : result.storageRef === undefined && result.transferRef === undefined;
  });
}

export function receiptContentHash(receipt: DemosWorkReceipt): string {
  return sha256Hex(canonicalize(receipt));
}

export function operationResult(receipt: DemosWorkReceipt, operationId: string): DemosWorkOperationResult {
  const result = receipt.operationResults.find((candidate) => candidate.operationId === operationId);
  if (!result) throw new Error(`receipt omitted operation ${operationId}`);
  return result;
}
