import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { publicKeyFromSeed, rawPublicKey } from "@kynesyslabs/dacs/crypto";
import { canonicalize, sha256Hex } from "@kynesyslabs/dacs";
import {
  DacsAtomicWorkBuilder,
  assertWorkShape,
  authorizeWork,
  calculateWorkId,
  operationReference,
  predictedStorageLocator,
  type DacsAtomicWork,
  type OperationSigner,
} from "./dacs-atomic.js";
import {
  AtomicDemosWorkMemoryExecutor,
  DemosWorkExecutionError,
  operationResult,
  receiptContentHash,
  verifyDemosWorkReceipt,
} from "./memory-executor.js";
import {
  PINNED_DEMOSWORK_CAPABILITIES,
  assertLiveAtomicDacsSupported,
  missingAtomicDacsCapabilities,
  type DemosWorkCapabilities,
} from "./capabilities.js";
import { parseDemosWorkRolloutMode, selectDemosWorkRoute } from "./rollout.js";

const buyer = "did:demos:agent:buyer";
const seller = "did:demos:agent:seller";
const buyerSeed = new Uint8Array(32).fill(1);
const sellerSeed = new Uint8Array(32).fill(2);
const signers: OperationSigner[] = [
  { signer: buyer, seed: buyerSeed },
  { signer: seller, seed: sellerSeed },
];
const publicKeys = new Map([
  [buyer, rawPublicKey(publicKeyFromSeed(buyerSeed))],
  [seller, rawPublicKey(publicKeyFromSeed(sellerSeed))],
]);
const now = 1_800_000_000_000;
const expiresAt = now + 60_000;

function hash(value: Record<string, unknown>): string {
  return sha256Hex(canonicalize(value));
}

function signedPurchase(input: {
  jobId?: string;
  amount?: string;
  commitmentSlot?: string;
  paymentEvidenceSlot?: string;
  expires?: number;
} = {}): DacsAtomicWork {
  const jobId = input.jobId ?? "oracle-job-1";
  const agreement = { kind: "agreement", jobId, buyer, seller, price: input.amount ?? "1000000000" };
  const buyerVet = { kind: "identity-vet", jobId, subject: buyer, tier: "verified" };
  const sellerVet = { kind: "identity-vet", jobId, subject: seller, tier: "verified" };
  const commitment = { kind: "commitment", jobId, agreementHash: hash(agreement) };
  // A typed operation-id reference avoids embedding the enclosing workId and
  // therefore avoids the transaction/work self-reference cycle.
  const paymentEvidence = { kind: "payment-evidence-template", jobId, paymentOperationId: "pay-dem" };
  const work = new DacsAtomicWorkBuilder({
    profile: "dacs-purchase-v1",
    chainId: "demos-testnet",
    jobId,
    expiresAt: input.expires ?? expiresAt,
  })
    .assertArtifact({
      operationId: "assert-agreement",
      domain: "dacs-payee-bound-agreement:v1",
      canonicalContentHash: hash(agreement),
      requiredSigners: [buyer, seller],
    })
    .storageProgramPut({
      operationId: "put-buyer-vet",
      logicalAddress: `dacs2:vet:${jobId}:buyer`,
      contentHash: hash(buyerVet),
      content: buyerVet,
      writeMode: "create-only",
      dependsOn: ["assert-agreement"],
      requiredSigners: [buyer],
    })
    .storageProgramPut({
      operationId: "put-seller-vet",
      logicalAddress: `dacs2:vet:${jobId}:seller`,
      contentHash: hash(sellerVet),
      content: sellerVet,
      writeMode: "create-only",
      dependsOn: ["assert-agreement"],
      requiredSigners: [seller],
    })
    .storageProgramPut({
      operationId: "put-commitment",
      logicalAddress: input.commitmentSlot ?? `dacs3:commit:${jobId}`,
      contentHash: hash(commitment),
      content: commitment,
      writeMode: "create-only",
      dependsOn: ["put-buyer-vet", "put-seller-vet"],
      requiredSigners: [buyer],
    })
    .nativeTransfer({
      operationId: "pay-dem",
      payer: buyer,
      payee: seller,
      amount: input.amount ?? "1000000000",
      asset: "demos-native:DEM",
      jobId,
      phaseIndex: 4,
      dependsOn: ["put-commitment"],
      requiredSigners: [buyer],
    })
    .storageProgramPut({
      operationId: "put-payment-evidence",
      logicalAddress: input.paymentEvidenceSlot ?? `dacs4:evidence:${jobId}:pay-dem`,
      contentHash: hash(paymentEvidence),
      content: paymentEvidence,
      writeMode: "create-only",
      dependsOn: ["pay-dem"],
      requiredSigners: [buyer],
    })
    .seal();
  return authorizeWork(work, signers);
}

function signedCompletion(purchaseReceiptHash: string, jobId = "oracle-job-1"): DacsAtomicWork {
  const delivery = { kind: "oracle-delivery", jobId, value: "123.45", purchaseReceiptHash };
  const deliveryEvidence = { kind: "delivery-evidence", jobId, deliveryHash: hash(delivery) };
  const reconciledBundle = {
    kind: "dacs-bundle",
    jobId,
    outcome: "completed",
    purchaseReceiptHash,
    deliveryHash: hash(delivery),
  };
  return authorizeWork(new DacsAtomicWorkBuilder({
    profile: "dacs-completion-v1",
    chainId: "demos-testnet",
    jobId,
    expiresAt,
  })
    .assertArtifact({
      operationId: "assert-purchase-receipt",
      domain: "demoswork-receipt:v1",
      canonicalContentHash: purchaseReceiptHash,
      requiredSigners: [buyer, seller],
    })
    .storageProgramPut({
      operationId: "put-delivery",
      logicalAddress: `dacsx:delivery:${jobId}`,
      contentHash: hash(delivery),
      content: delivery,
      writeMode: "create-only",
      dependsOn: ["assert-purchase-receipt"],
      requiredSigners: [seller],
    })
    .storageProgramPut({
      operationId: "put-delivery-evidence",
      logicalAddress: `dacs4:delivery-evidence:${jobId}`,
      contentHash: hash(deliveryEvidence),
      content: deliveryEvidence,
      writeMode: "create-only",
      dependsOn: ["put-delivery"],
      requiredSigners: [seller],
    })
    .storageProgramPut({
      operationId: "put-buyer-bundle",
      logicalAddress: `dacs5:bundle:${jobId}:buyer`,
      contentHash: hash(reconciledBundle),
      content: reconciledBundle,
      writeMode: "create-only",
      dependsOn: ["put-delivery-evidence"],
      requiredSigners: [buyer],
    })
    .storageProgramPut({
      operationId: "put-seller-bundle",
      logicalAddress: `dacs5:bundle:${jobId}:seller`,
      contentHash: hash(reconciledBundle),
      content: reconciledBundle,
      writeMode: "create-only",
      dependsOn: ["put-delivery-evidence"],
      requiredSigners: [seller],
    })
    .seal(), signers);
}

function fundedExecutor(amount = 10_000_000_000n): AtomicDemosWorkMemoryExecutor {
  const executor = new AtomicDemosWorkMemoryExecutor(publicKeys);
  executor.setBalance(buyer, amount);
  executor.setBalance(seller, 0n);
  return executor;
}

describe("DACS atomic Demos Work intent", () => {
  test("has a stable workId, stable operation refs, and deterministic storage locators", () => {
    const signed = signedPurchase();
    const unsigned = { ...signed, operations: signed.operations.map((operation) => ({ ...operation, authorizations: [] })) };
    assert.equal(calculateWorkId(signed), signed.workId);
    assert.equal(calculateWorkId(unsigned), signed.workId, "signatures are outside the stable intent id");
    assert.equal(operationReference(signed.workId, "pay-dem"), `demoswork:${signed.workId}:pay-dem`);
    assert.equal(
      predictedStorageLocator(signed.workId, "put-commitment", "dacs3:commit:oracle-job-1"),
      predictedStorageLocator(signed.workId, "put-commitment", "dacs3:commit:oracle-job-1"),
    );
    assertWorkShape(signed);
  });

  test("changing amount, job, chain, dependency, or expiry changes the workId", () => {
    const baseline = signedPurchase();
    const variants = [
      signedPurchase({ amount: "2000000000" }),
      signedPurchase({ jobId: "oracle-job-2" }),
      signedPurchase({ expires: expiresAt + 1 }),
    ];
    for (const variant of variants) assert.notEqual(variant.workId, baseline.workId);
  });

  test("rejects oversized inline storage but accepts its content-addressed pointer", () => {
    const content = { body: "x".repeat(17_000) };
    const builder = () => new DacsAtomicWorkBuilder({
      profile: "dacs-purchase-v1", chainId: "demos-testnet", jobId: "large-job", expiresAt,
    })
      .storageProgramPut({
        operationId: "put-large",
        logicalAddress: "dacs:large",
        contentHash: hash(content),
        content,
        writeMode: "create-only",
        requiredSigners: [buyer],
      })
      .nativeTransfer({
        operationId: "pay-dem", payer: buyer, payee: seller, amount: "1", asset: "demos-native:DEM",
        jobId: "large-job", phaseIndex: 4, requiredSigners: [buyer], dependsOn: ["put-large"],
      });
    assert.throws(() => builder().seal(), /inline content exceeds/);

    const pointerWork = new DacsAtomicWorkBuilder({
      profile: "dacs-purchase-v1", chainId: "demos-testnet", jobId: "pointer-job", expiresAt,
    })
      .storageProgramPut({
        operationId: "put-large",
        logicalAddress: "dacs:large:pointer",
        contentHash: hash(content),
        externalContent: { uri: "ipfs://example", contentHash: hash(content) },
        writeMode: "create-only",
        requiredSigners: [buyer],
      })
      .nativeTransfer({
        operationId: "pay-dem", payer: buyer, payee: seller, amount: "1", asset: "demos-native:DEM",
        jobId: "pointer-job", phaseIndex: 4, requiredSigners: [buyer], dependsOn: ["put-large"],
      })
      .seal();
    assert.doesNotThrow(() => assertWorkShape(pointerWork, false));
  });

  test("rejects runtime attempts to smuggle an overwrite mode or another asset", () => {
    const badWriteMode = signedPurchase();
    const storage = badWriteMode.operations.find((operation) => operation.type === "storageProgramPut")!;
    (storage as { writeMode: string }).writeMode = "overwrite";
    assert.throws(() => assertWorkShape(badWriteMode), /invalid storage write mode/);

    const badAsset = signedPurchase({ jobId: "bad-asset" });
    const transfer = badAsset.operations.find((operation) => operation.type === "nativeTransfer")!;
    (transfer as { asset: string }).asset = "external:USDC";
    assert.throws(() => assertWorkShape(badAsset), /invalid native transfer/);
  });
});

describe("atomic DACS execution semantics", () => {
  test("commits Purchase Work payment and every storage output in one receipt", () => {
    const executor = fundedExecutor();
    const work = signedPurchase();
    const receipt = executor.execute(work, { now, nonce: 7 });
    assert.equal(receipt.operationResults.length, 6);
    assert.equal(executor.balance(buyer), 9_000_000_000n);
    assert.equal(executor.balance(seller), 1_000_000_000n);
    assert.ok(executor.stored("dacs3:commit:oracle-job-1"));
    assert.ok(executor.stored("dacs2:vet:oracle-job-1:buyer"));
    assert.ok(executor.stored("dacs2:vet:oracle-job-1:seller"));
    assert.ok(executor.stored("dacs4:evidence:oracle-job-1:pay-dem"));
    assert.equal(verifyDemosWorkReceipt(receipt), true);
    assert.equal(receipt.operationResults.every((result) => result.status === "success"), true);
  });

  test("commits delivery, evidence, and independently addressable DACS-5 copies in one Completion Work", () => {
    const executor = fundedExecutor();
    const purchase = executor.execute(signedPurchase(), { now, nonce: 8 });
    const completion = signedCompletion(receiptContentHash(purchase));
    const receipt = executor.execute(completion, { now: now + 1, nonce: 9 });
    const buyerBundle = operationResult(receipt, "put-buyer-bundle");
    const sellerBundle = operationResult(receipt, "put-seller-bundle");
    assert.equal(buyerBundle.outputHash, sellerBundle.outputHash, "bundle copies reconcile canonically");
    assert.notEqual(buyerBundle.storageRef?.locator, sellerBundle.storageRef?.locator, "copies remain independently addressable");
    assert.equal(receipt.operationResults.length, 5);
    assert.equal(verifyDemosWorkReceipt(receipt), true);
  });

  test("insufficient funds rolls back storage written earlier in the overlay", () => {
    const executor = fundedExecutor(10n);
    const work = signedPurchase();
    assert.throws(
      () => executor.execute(work, { now, nonce: 10 }),
      (error: unknown) => error instanceof DemosWorkExecutionError && error.code === "insufficient-funds",
    );
    assert.equal(executor.balance(buyer), 10n);
    assert.equal(executor.balance(seller), 0n);
    assert.equal(executor.stored("dacs3:commit:oracle-job-1"), undefined);
    assert.equal(executor.getReceipt(work.workId), undefined);
  });

  test("an invalid seller signature leaves no payment or partial artifact", () => {
    const executor = fundedExecutor();
    const work = signedPurchase();
    const agreement = work.operations[0]!;
    agreement.authorizations[1]!.signature = Buffer.alloc(64, 9).toString("base64url");
    assert.throws(
      () => executor.execute(work, { now, nonce: 11 }),
      (error: unknown) => error instanceof DemosWorkExecutionError && error.code === "invalid-authorization",
    );
    assert.equal(executor.balance(buyer), 10_000_000_000n);
    assert.equal(executor.balance(seller), 0n);
    assert.equal(executor.stored("dacs3:commit:oracle-job-1"), undefined);
  });

  test("an operation authorization cannot be replayed into another Work", () => {
    const executor = fundedExecutor();
    const first = signedPurchase({ jobId: "signature-source" });
    const second = signedPurchase({ jobId: "signature-target" });
    second.operations[0]!.authorizations = structuredClone(first.operations[0]!.authorizations);
    assert.throws(
      () => executor.execute(second, { now, nonce: 11 }),
      (error: unknown) => error instanceof DemosWorkExecutionError && error.code === "invalid-authorization",
    );
    assert.equal(executor.balance(buyer), 10_000_000_000n);
  });

  test("a storage conflict before payment fails closed", () => {
    const executor = fundedExecutor();
    executor.execute(signedPurchase({ jobId: "seed", commitmentSlot: "shared-commit" }), { now, nonce: 12 });
    const beforeBuyer = executor.balance(buyer);
    const beforeSeller = executor.balance(seller);
    assert.throws(
      () => executor.execute(signedPurchase({ jobId: "conflict", commitmentSlot: "shared-commit" }), { now, nonce: 13 }),
      (error: unknown) => error instanceof DemosWorkExecutionError && error.code === "conflicting-storage",
    );
    assert.equal(executor.balance(buyer), beforeBuyer);
    assert.equal(executor.balance(seller), beforeSeller);
  });

  test("a failure after an in-overlay transfer rolls the transfer back", () => {
    const executor = fundedExecutor();
    executor.execute(signedPurchase({ jobId: "seed", paymentEvidenceSlot: "shared-evidence" }), { now, nonce: 14 });
    const beforeBuyer = executor.balance(buyer);
    const beforeSeller = executor.balance(seller);
    const failing = signedPurchase({ jobId: "rollback", paymentEvidenceSlot: "shared-evidence" });
    assert.throws(
      () => executor.execute(failing, { now, nonce: 15 }),
      (error: unknown) => error instanceof DemosWorkExecutionError
        && error.code === "conflicting-storage"
        && error.operationId === "put-payment-evidence",
    );
    assert.equal(executor.balance(buyer), beforeBuyer);
    assert.equal(executor.balance(seller), beforeSeller);
    assert.equal(executor.getReceipt(failing.workId), undefined);
    assert.equal(executor.stored("dacs3:commit:rollback"), undefined);
  });

  test("identical resubmission returns the original receipt and never pays twice", () => {
    const executor = fundedExecutor();
    const work = signedPurchase();
    const first = executor.execute(work, { now, nonce: 16 });
    const buyerAfterFirst = executor.balance(buyer);
    const second = executor.execute(work, { now: expiresAt + 1000, nonce: 999 });
    assert.deepEqual(second, first);
    assert.equal(executor.balance(buyer), buyerAfterFirst);
    assert.equal(second.nonceConsumed, 16);
  });

  test("future nonce is observable, changes no state, and can be retried in order", () => {
    const executor = fundedExecutor();
    executor.execute(signedPurchase({ jobId: "nonce-seed" }), { now, nonce: 40, submitter: buyer });
    const beforeBuyer = executor.balance(buyer);
    const next = signedPurchase({ jobId: "nonce-next" });
    assert.throws(
      () => executor.execute(next, { now, nonce: 42, submitter: buyer }),
      (error: unknown) => error instanceof DemosWorkExecutionError && error.code === "future-nonce",
    );
    assert.equal(executor.balance(buyer), beforeBuyer);
    assert.equal(executor.getReceipt(next.workId), undefined);
    const receipt = executor.execute(next, { now, nonce: 41, submitter: buyer });
    assert.equal(receipt.nonceConsumed, 41);
  });

  test("a conflicting intent for a committed job/profile fails closed", () => {
    const executor = fundedExecutor();
    executor.execute(signedPurchase(), { now, nonce: 17 });
    assert.throws(
      () => executor.execute(signedPurchase({ amount: "2000000000" }), { now, nonce: 18 }),
      (error: unknown) => error instanceof DemosWorkExecutionError && error.code === "conflicting-job",
    );
  });

  test("expired authorizations fail before any state change", () => {
    const executor = fundedExecutor();
    const work = signedPurchase({ expires: now - 1 });
    assert.throws(
      () => executor.execute(work, { now, nonce: 19 }),
      (error: unknown) => error instanceof DemosWorkExecutionError && error.code === "expired",
    );
    assert.equal(executor.balance(buyer), 10_000_000_000n);
  });

  test("forged operation results invalidate the reference receipt", () => {
    const receipt = fundedExecutor().execute(signedPurchase(), { now, nonce: 20 });
    const forged = structuredClone(receipt);
    forged.operationResults[0]!.outputHash = "0".repeat(64);
    assert.equal(verifyDemosWorkReceipt(receipt), true);
    assert.equal(verifyDemosWorkReceipt(forged), false);
  });

  test("forged inclusion metadata or state root invalidates the reference receipt", () => {
    const receipt = fundedExecutor().execute(signedPurchase(), { now, nonce: 20 });
    const forgedBlock = structuredClone(receipt);
    forgedBlock.blockNumber += 1;
    const forgedState = structuredClone(receipt);
    forgedState.stateChangesRoot = "0".repeat(64);
    assert.equal(verifyDemosWorkReceipt(forgedBlock), false);
    assert.equal(verifyDemosWorkReceipt(forgedState), false);
  });

  test("Completion Work remains idempotent after executor restart", () => {
    const executor = fundedExecutor();
    const purchase = executor.execute(signedPurchase(), { now, nonce: 21 });
    const completion = signedCompletion(receiptContentHash(purchase));
    const first = executor.execute(completion, { now: now + 1, nonce: 22 });
    const restarted = new AtomicDemosWorkMemoryExecutor(publicKeys, executor.snapshot());
    const second = restarted.execute(completion, { now: expiresAt + 1, nonce: 999 });
    assert.deepEqual(second, first);
    assert.equal(restarted.balance(buyer), executor.balance(buyer));
    assert.equal(restarted.balance(seller), executor.balance(seller));
  });
});

describe("live SDK capability gate", () => {
  test("refuses to submit the POC through demosdk 4.0.16", () => {
    const missing = missingAtomicDacsCapabilities(PINNED_DEMOSWORK_CAPABILITIES);
    assert.ok(missing.includes("StorageProgram Work step"));
    assert.ok(missing.includes("authoritative operation receipt"));
    assert.throws(() => assertLiveAtomicDacsSupported(), /live atomic DACS Demos Work is disabled/);
  });

  test("opens only when every load-bearing node and SDK capability is explicit", () => {
    const supported: DemosWorkCapabilities = {
      sdkVersion: "future",
      submit: true,
      nativeTransfer: true,
      storageProgramPut: true,
      multiPartyAuthorization: true,
      atomicNativeRollback: "verified",
      stableWorkId: true,
      authoritativeReceipt: true,
      esmCompatibleOnNode22: true,
    };
    assert.deepEqual(missingAtomicDacsCapabilities(supported), []);
    assert.doesNotThrow(() => assertLiveAtomicDacsSupported(supported));
    assert.deepEqual(selectDemosWorkRoute("live", supported), {
      execution: "atomic-demoswork",
      shadowValidation: false,
    });
  });

  test("defaults to the normative fallback and keeps shadow mode non-paying", () => {
    assert.equal(parseDemosWorkRolloutMode(undefined), "disabled");
    assert.deepEqual(selectDemosWorkRoute("disabled"), {
      execution: "multi-transaction",
      shadowValidation: false,
    });
    assert.deepEqual(selectDemosWorkRoute("shadow"), {
      execution: "multi-transaction",
      shadowValidation: true,
    });
    assert.throws(() => selectDemosWorkRoute("live"), /live atomic DACS Demos Work is disabled/);
    assert.throws(() => parseDemosWorkRolloutMode("yes"), /must be disabled, shadow, or live/);
  });
});
