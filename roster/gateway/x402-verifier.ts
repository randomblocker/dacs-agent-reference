/** Independent seller-side verification of x402 USDC settlement on Base Sepolia. */
import { createPublicClient, decodeFunctionData, http, parseAbi, type Log, type TransactionReceipt } from "viem";
import { baseSepolia } from "viem/chains";
import type { AgreementDocument } from "../dacs/standard-profile.js";
import { BASE_SEPOLIA_USDC, x402AgreementTerms } from "../dacs/x402-production.js";
import { dacsX402AuthorizationNonce } from "../../sdk/src/rails/x402.js";

// keccak256("Transfer(address,address,uint256)")
const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const TX_HASH = /^(?:0x)?[0-9a-fA-F]{64}$/;

export interface X402ReceiptReader {
  getTransactionReceipt(input: { hash: `0x${string}` }): Promise<Pick<TransactionReceipt, "status" | "blockNumber" | "logs">>;
  getTransaction(input: { hash: `0x${string}` }): Promise<{ to: string | null; input: `0x${string}` }>;
}

export interface VerifiedX402Payment {
  ok: boolean;
  payer?: string;
  amountOs?: bigint;
  blockNumber?: number;
  logIndex?: number;
  reason?: string;
  retriable?: boolean;
}

function topicAddress(topic: string | undefined): string | undefined {
  if (!topic || !/^0x[0-9a-fA-F]{64}$/.test(topic)) return undefined;
  return `0x${topic.slice(-40)}`;
}

export function verifyX402Receipt(
  agreement: AgreementDocument,
  receipt: Pick<TransactionReceipt, "status" | "blockNumber" | "logs">,
): VerifiedX402Payment {
  const expected = x402AgreementTerms(agreement);
  if (receipt.status !== "success") return { ok: false, reason: "Base settlement transaction reverted" };
  const matching = receipt.logs.filter((log: Log) => {
    if (log.address.toLowerCase() !== BASE_SEPOLIA_USDC.toLowerCase()) return false;
    if (log.topics[0]?.toLowerCase() !== TRANSFER_TOPIC) return false;
    const from = topicAddress(log.topics[1]);
    const to = topicAddress(log.topics[2]);
    if (from?.toLowerCase() !== expected.payer.toLowerCase() || to?.toLowerCase() !== expected.payTo.toLowerCase()) return false;
    try { return BigInt(log.data) === BigInt(expected.amount); } catch { return false; }
  });
  if (matching.length !== 1) {
    return { ok: false, reason: "Base receipt does not contain exactly one agreed USDC transfer" };
  }
  const blockNumber = Number(receipt.blockNumber);
  if (!Number.isSafeInteger(blockNumber) || blockNumber < 0) return { ok: false, reason: "Base receipt block number is unsafe" };
  const logIndex = matching[0]?.logIndex;
  if (!Number.isSafeInteger(logIndex) || Number(logIndex) < 0) return { ok: false, reason: "Base USDC transfer log index is missing" };
  return { ok: true, payer: expected.payer, amountOs: BigInt(expected.amount), blockNumber, logIndex: Number(logIndex) };
}

const EIP3009_ABI = parseAbi([
  "function transferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce,uint8 v,bytes32 r,bytes32 s)",
]);

export async function verifyX402Authorization(
  agreement: AgreementDocument,
  transaction: { to: string | null; input: `0x${string}` },
): Promise<{ ok: boolean; reason?: string }> {
  const expected = x402AgreementTerms(agreement);
  if (transaction.to?.toLowerCase() !== BASE_SEPOLIA_USDC.toLowerCase()) {
    return { ok: false, reason: "x402 settlement did not call the agreed USDC contract" };
  }
  let args: readonly unknown[];
  try {
    const decoded = decodeFunctionData({ abi: EIP3009_ABI, data: transaction.input });
    if (decoded.functionName !== "transferWithAuthorization" || !decoded.args) throw new Error("wrong call");
    args = decoded.args;
  } catch {
    return { ok: false, reason: "x402 settlement is not a readable EIP-3009 authorization" };
  }
  const [from, to, value, , , nonce] = args;
  const expectedNonce = await dacsX402AuthorizationNonce({
    jobId: agreement.jobId,
    phaseIndex: expected.phaseIndex,
    payer: expected.payer,
    payee: expected.payTo,
    amount: expected.amount,
    asset: expected.asset,
    network: expected.network,
  });
  if (String(from).toLowerCase() !== expected.payer.toLowerCase()
    || String(to).toLowerCase() !== expected.payTo.toLowerCase()
    || BigInt(String(value)) !== BigInt(expected.amount)
    || String(nonce).toLowerCase() !== expectedNonce.toLowerCase()) {
    return { ok: false, reason: "x402 EIP-3009 authorization is not bound to the signed DACS job/phase" };
  }
  return { ok: true };
}

export class X402PaymentVerifier {
  private readonly reader: X402ReceiptReader;

  constructor(
    reader?: X402ReceiptReader,
    rpcUrl = process.env.BASE_SEPOLIA_RPC ?? "https://sepolia.base.org",
    private readonly timeoutMs = 12_000,
  ) {
    this.reader = reader ?? createPublicClient({ chain: baseSepolia, transport: http(rpcUrl) });
  }

  async verify(txHash: string, agreement: AgreementDocument): Promise<VerifiedX402Payment> {
    if (!TX_HASH.test(txHash)) return { ok: false, reason: "x402 settlement tx must be a 32-byte hash" };
    const hash = `0x${txHash.replace(/^0x/, "").toLowerCase()}` as `0x${string}`;
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const [receipt, transaction] = await Promise.race([
        Promise.all([
          this.reader.getTransactionReceipt({ hash }),
          this.reader.getTransaction({ hash }),
        ]),
        new Promise<never>((_resolve, reject) => {
          timer = setTimeout(() => reject(new Error("Base receipt lookup timed out")), this.timeoutMs);
        }),
      ]);
      const receiptVerdict = verifyX402Receipt(agreement, receipt);
      if (!receiptVerdict.ok) return receiptVerdict;
      const authorizationVerdict = await verifyX402Authorization(agreement, transaction);
      return authorizationVerdict.ok ? receiptVerdict : { ok: false, reason: authorizationVerdict.reason };
    } catch (error) {
      return { ok: false, reason: (error as Error).message, retriable: true };
    } finally {
      if (timer) clearTimeout(timer);
    }
  }
}
