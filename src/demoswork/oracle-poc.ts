import { performance } from "node:perf_hooks";
import { canonicalize, sha256Hex } from "@kynesyslabs/dacs";
import { publicKeyFromSeed, rawPublicKey } from "@kynesyslabs/dacs/crypto";
import {
  DacsAtomicWorkBuilder,
  authorizeWork,
  operationReference,
  type DacsAtomicWork,
  type OperationSigner,
} from "./dacs-atomic.js";
import {
  PINNED_DEMOSWORK_CAPABILITIES,
  missingAtomicDacsCapabilities,
} from "./capabilities.js";
import {
  AtomicDemosWorkMemoryExecutor,
  receiptContentHash,
} from "./memory-executor.js";

const buyer = "did:demos:agent:poc-buyer";
const seller = "did:demos:agent:oracle-desk";
const buyerSeed = new Uint8Array(32).fill(31);
const sellerSeed = new Uint8Array(32).fill(47);
const signers: OperationSigner[] = [
  { signer: buyer, seed: buyerSeed },
  { signer: seller, seed: sellerSeed },
];
const publicKeys = new Map([
  [buyer, rawPublicKey(publicKeyFromSeed(buyerSeed))],
  [seller, rawPublicKey(publicKeyFromSeed(sellerSeed))],
]);

function hash(value: Record<string, unknown>): string {
  return sha256Hex(canonicalize(value));
}

function purchaseWork(jobId: string, expiresAt: number): DacsAtomicWork {
  const agreement = { kind: "agreement", jobId, buyer, seller, priceAtomic: "1000000000" };
  const buyerVet = { kind: "identity-vet", jobId, subject: buyer, tier: "verified" };
  const sellerVet = { kind: "identity-vet", jobId, subject: seller, tier: "verified" };
  const commitment = { kind: "commitment", jobId, agreementHash: hash(agreement) };
  const paymentEvidence = { kind: "payment-evidence-template", jobId, paymentOperationId: "pay-dem" };
  const work = new DacsAtomicWorkBuilder({
    profile: "dacs-purchase-v1",
    chainId: "demos-testnet",
    jobId,
    expiresAt,
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
      logicalAddress: `dacs3:commit:${jobId}`,
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
      amount: "1000000000",
      asset: "demos-native:DEM",
      jobId,
      phaseIndex: 4,
      dependsOn: ["put-commitment"],
      requiredSigners: [buyer],
    })
    .storageProgramPut({
      operationId: "put-payment-evidence",
      logicalAddress: `dacs4:evidence:${jobId}:pay-dem`,
      contentHash: hash(paymentEvidence),
      content: paymentEvidence,
      writeMode: "create-only",
      dependsOn: ["pay-dem"],
      requiredSigners: [buyer],
    })
    .seal();
  return authorizeWork(work, signers);
}

function completionWork(jobId: string, purchaseReceiptHash: string, expiresAt: number): DacsAtomicWork {
  const delivery = { kind: "oracle-delivery", jobId, value: "123.45", purchaseReceiptHash };
  const deliveryHash = hash(delivery);
  const evidence = { kind: "delivery-evidence", jobId, deliveryHash };
  const bundle = { kind: "dacs-bundle", jobId, outcome: "completed", purchaseReceiptHash, deliveryHash };
  const work = new DacsAtomicWorkBuilder({
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
      contentHash: deliveryHash,
      content: delivery,
      writeMode: "create-only",
      dependsOn: ["assert-purchase-receipt"],
      requiredSigners: [seller],
    })
    .storageProgramPut({
      operationId: "put-delivery-evidence",
      logicalAddress: `dacs4:delivery-evidence:${jobId}`,
      contentHash: hash(evidence),
      content: evidence,
      writeMode: "create-only",
      dependsOn: ["put-delivery"],
      requiredSigners: [seller],
    })
    .storageProgramPut({
      operationId: "put-buyer-bundle",
      logicalAddress: `dacs5:bundle:${jobId}:buyer`,
      contentHash: hash(bundle),
      content: bundle,
      writeMode: "create-only",
      dependsOn: ["put-delivery-evidence"],
      requiredSigners: [buyer],
    })
    .storageProgramPut({
      operationId: "put-seller-bundle",
      logicalAddress: `dacs5:bundle:${jobId}:seller`,
      contentHash: hash(bundle),
      content: bundle,
      writeMode: "create-only",
      dependsOn: ["put-delivery-evidence"],
      requiredSigners: [seller],
    })
    .seal();
  return authorizeWork(work, signers);
}

const startedAt = performance.now();
const now = Date.now();
const jobId = `oracle-atomic-poc-${now}`;
const executor = new AtomicDemosWorkMemoryExecutor(publicKeys);
executor.setBalance(buyer, 10_000_000_000n);
const purchase = purchaseWork(jobId, now + 60_000);
const purchaseReceipt = executor.execute(purchase, { now, nonce: 1 });
const completion = completionWork(jobId, receiptContentHash(purchaseReceipt), now + 60_000);
const completionReceipt = executor.execute(completion, { now: now + 1, nonce: 2 });
const elapsedMs = performance.now() - startedAt;

process.stdout.write(`${JSON.stringify({
  status: "offline-proof-complete",
  warning: "No transaction was submitted. The pinned SDK/node contract lacks the capabilities below.",
  sdk: PINNED_DEMOSWORK_CAPABILITIES.sdkVersion,
  missingLiveCapabilities: missingAtomicDacsCapabilities(PINNED_DEMOSWORK_CAPABILITIES),
  localExecutionMs: Number(elapsedMs.toFixed(3)),
  proposedConsensusTransactions: 2,
  purchase: {
    workId: purchase.workId,
    paymentRef: operationReference(purchase.workId, "pay-dem"),
    operations: purchaseReceipt.operationResults.length,
    receiptRoot: purchaseReceipt.receiptRoot,
  },
  completion: {
    workId: completion.workId,
    operations: completionReceipt.operationResults.length,
    receiptRoot: completionReceipt.receiptRoot,
  },
  finalBalances: {
    buyer: executor.balance(buyer).toString(),
    seller: executor.balance(seller).toString(),
  },
}, null, 2)}\n`);
