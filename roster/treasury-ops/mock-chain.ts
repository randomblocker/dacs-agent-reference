/**
 * MockChain — in-memory multi-chain ChainPort adapter.
 *
 * One instance holds balances for ALL chains (keyed chain:address), so a
 * cross-chain rebalance "just works" in mock mode; register the same
 * instance under every chain id in the executor's ports map. A tiny flat
 * fee is charged on the source per transfer so balance math stays honest
 * (the policy's feeBufferPerTx must be >= this fee).
 *
 * txRefs are deterministic (hash of the intent id), and failure injection
 * is per-intent: `{ times, mode }` fails the first N attempts — mode "fail"
 * is a recorded per-intent failure (run continues), mode "crash" throws an
 * abortsRun error (simulated mid-run crash; resume retries it).
 *
 * BACKLOG note: real mode = Demos XM SDK adapters (one ChainPort per chain,
 * DEMOS_MNEMONIC / EVM keys + funded testnet accounts). Mock-only today.
 */
import { sha256Hex } from "../oracle-desk/attested-fetch.js";
import type { AbortsRun, AccountRef, ChainPort, TransferIntent } from "./types.js";

export interface FailureInjection {
  /** How many attempts to fail before letting the transfer succeed. */
  times: number;
  /** "fail" = per-intent failure (executor continues); "crash" = abort run. */
  mode: "fail" | "crash";
}

export interface MockChainOptions {
  /** Flat fee debited from the source on every successful transfer. */
  feePerTransfer?: number;
  /** intentId -> injection. Mutated as attempts consume `times`. */
  failures?: Record<string, FailureInjection>;
}

export class MockChainCrash extends Error implements AbortsRun {
  readonly abortsRun = true as const;
  constructor(message: string) {
    super(message);
    this.name = "MockChainCrash";
  }
}

export class MockChain implements ChainPort {
  private readonly balances = new Map<string, number>();
  private readonly failures: Record<string, FailureInjection>;
  readonly feePerTransfer: number;
  /** Total fees collected across all transfers (the mock "network"). */
  feesCollected = 0;

  constructor(initial: Record<string, Record<string, number>>, opts: MockChainOptions = {}) {
    for (const [chain, byAddress] of Object.entries(initial)) {
      for (const [address, balance] of Object.entries(byAddress)) {
        this.balances.set(this.key(chain, address), balance);
      }
    }
    this.feePerTransfer = opts.feePerTransfer ?? 1;
    this.failures = opts.failures ?? {};
  }

  private key(chain: string, address: string): string {
    return `${chain}:${address}`;
  }

  async getBalance(account: AccountRef): Promise<number> {
    return this.balances.get(this.key(account.chain, account.address)) ?? 0;
  }

  async transfer(intent: TransferIntent): Promise<{ txRef: string }> {
    const injection = this.failures[intent.intentId];
    if (injection && injection.times > 0) {
      injection.times -= 1;
      if (injection.mode === "crash") {
        throw new MockChainCrash(`injected crash on intent ${intent.intentId.slice(0, 16)}…`);
      }
      throw new Error(`injected failure on intent ${intent.intentId.slice(0, 16)}…`);
    }

    const fromKey = this.key(intent.from.chain, intent.from.address);
    const toKey = this.key(intent.to.chain, intent.to.address);
    const fromBalance = this.balances.get(fromKey) ?? 0;
    const totalDebit = intent.amount + this.feePerTransfer;
    if (fromBalance < totalDebit) {
      throw new Error(`insufficient funds: ${fromKey} has ${fromBalance}, needs ${totalDebit} (amount + fee)`);
    }

    this.balances.set(fromKey, fromBalance - totalDebit);
    this.balances.set(toKey, (this.balances.get(toKey) ?? 0) + intent.amount);
    this.feesCollected += this.feePerTransfer;

    return { txRef: `mocktx:${intent.from.chain}:${sha256Hex(`tx|${intent.intentId}`).slice(0, 24)}` };
  }
}

/** Register one MockChain instance under every chain id it holds. */
export function portsFor(chain: MockChain, chainIds: string[]): Record<string, ChainPort> {
  return Object.fromEntries(chainIds.map((id) => [id, chain]));
}
