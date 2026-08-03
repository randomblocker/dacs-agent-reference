/**
 * Real port construction — wires the live adapters each agent core needs. The
 * mock attestor remains available to offline-safe cores; live sec-audit content
 * evidence uses the gateway's persistent DACS identity.
 *
 * Tests bypass this and inject fakes directly into buildRegistry via a
 * hand-built GatewayPorts (see gateway.test.ts).
 */
import { join } from "node:path";
import { readFileSync, statSync } from "node:fs";
import { MockDahrAttestor, RealAttestedFetch } from "../oracle-desk/attested-fetch.js";
import { RealRegistry } from "../dep-upgrade/registry.js";
import { RealDns } from "../shared/attest-primitives.js";
import { RealProber } from "../site-auditor/prober.js";
import { MarketplaceStub } from "../procurement-butler/marketplace-stub.js";
import { RulingSigner } from "../evalbot/ruling.js";
import { TreasurySigner } from "../treasury-ops/proof.js";
import { RealComplianceFetch, realSources, type ListFetchContext } from "../compliance/sources.js";
import { PaymentGate, uniformFee, OS_PER_DEM, type Settlement, type TxReader } from "./settlement.js";
import { X402Gate } from "./x402.js";
import { ProcurementX402 } from "./procurement-x402.js";
import { loadX402RailDefinition, type X402RegistryTrustMode } from "../dacs/x402-production.js";
import type { AttestedFetchPort } from "../oracle-desk/types.js";
import type { DemosLike } from "../oracle-desk/live-dahr.js";
import type { GatewayPorts, OutputAnchor, OutputAnchorLifecycle } from "./types.js";
import { anthropicFromEnv } from "../llm/anthropic.js";
import type { ContentAttestor } from "../sec-audit/attest-files.js";

const DEFAULT_DEMOS_RPC = "https://demosnode.discus.sh/";

/** The subset of DemosAdapter the output anchor needs. */
interface AnchorCapable {
  getAddress(): string;
  anchorAddress(name: string): string;
  anchor(name: string, value: object): Promise<{ address: string; txRef?: string }>;
}

interface NonceReader {
  getAddressInfo(address: string): Promise<{ nonce?: number } | null>;
}

/**
 * Serialize ALL wallet operations (LiveDahr web2Requests AND StorageProgram
 * output anchors) through one FIFO — concurrent txs from a single wallet collide
 * on nonce (the SDK's serial-nonce note). Every on-chain op from the gateway's
 * wallet must go through `run`.
 */
export function makeWalletSerializer(readNonce: () => Promise<number>, timeoutMs = 90_000, pollMs = 2_000): {
  run<T>(fn: () => Promise<T>): Promise<T>;
  runEager<T>(fn: () => Promise<T>): Promise<T>;
  enqueue<T>(fn: () => Promise<T>, lifecycle: OutputAnchorLifecycle): void;
} {
  let tail: Promise<unknown> = Promise.resolve();
  const waitForAdvance = async (before: number): Promise<void> => {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if ((await readNonce()) > before) return;
      await new Promise((resolve) => setTimeout(resolve, pollMs));
    }
    throw new Error(`wallet nonce did not advance from ${before} within ${timeoutMs}ms`);
  };
  const enqueue = <T>(work: () => Promise<T>): Promise<T> => {
    const started = tail.then(work, work);
    tail = started.then(() => undefined, () => undefined);
    return started;
  };
  return {
    run<T>(fn: () => Promise<T>): Promise<T> {
      return enqueue(async () => {
        const before = await readNonce();
        const result = await fn();
        await waitForAdvance(before);
        return result;
      });
    },
    runEager<T>(fn: () => Promise<T>): Promise<T> {
      // DAHR has already signed, confirmed and broadcast its web2Request when
      // fn resolves. Return that attestation immediately, but keep the private
      // wallet queue occupied until the nonce advances so the NEXT write cannot
      // collide. A later confirmation delay is no longer user-facing latency.
      let resolve!: (value: T) => void;
      let reject!: (error: unknown) => void;
      const delivered = new Promise<T>((ok, fail) => { resolve = ok; reject = fail; });
      void enqueue(async () => {
        try {
          const before = await readNonce();
          const result = await fn();
          resolve(result);
          await waitForAdvance(before);
          return result;
        } catch (error) {
          reject(error);
          throw error;
        }
      });
      return delivered;
    },
    enqueue<T>(fn: () => Promise<T>, lifecycle: OutputAnchorLifecycle): void {
      // Scheduling is synchronous: HTTP handlers can return the completed agent
      // result even when earlier wallet work is still awaiting confirmation.
      // The queued task itself still owns the FIFO through nonce advancement.
      void enqueue(async () => {
        try {
          lifecycle.onStart();
          const before = await readNonce();
          const result = await fn();
          lifecycle.onBroadcast(result as { txRef?: string } | void);
          await waitForAdvance(before);
          lifecycle.onConfirmed(result as { txRef?: string } | void);
          return result;
        } catch (error) {
          lifecycle.onError(error);
          throw error;
        }
      }).catch(() => undefined);
    },
  };
}

type Serializer = ReturnType<typeof makeWalletSerializer>;

/** On-chain output anchor whose writes are serialized through the shared wallet FIFO. */
function makeOutputAnchor(adapter: AnchorCapable, serializer: Serializer): OutputAnchor {
  return {
    committerAddress: adapter.getAddress(),
    addressFor: (name) => adapter.anchorAddress(name),
    commit: (name, value) => serializer.run(() => adapter.anchor(name, value)),
    commitEager: (name, value) => serializer.runEager(() => adapter.anchor(name, value)),
    enqueue: (name, value, lifecycle) => serializer.enqueue(() => adapter.anchor(name, value), lifecycle),
  };
}

/**
 * Build the LIVE wallet features from ONE connected wallet: oracle-desk's DAHR
 * node-fetch + the shared on-chain output anchor (GATEWAY_LIVE_DAHR=1), and the
 * pay-dem settlement gate (GATEWAY_SETTLEMENT=1). Both need a funded
 * GATEWAY_DAHR_MNEMONIC. The Demos SDK is imported DYNAMICALLY so the default
 * (mock, unpaid) gateway carries no @kynesyslabs/dacs dependency at load time.
 * Any failure degrades LOUDLY to mock / no-settlement.
 */
async function maybeBuildLive(): Promise<{
  oracleAttestedFetch?: AttestedFetchPort;
  outputAnchor?: OutputAnchor;
  contentAttestor?: ContentAttestor;
  settlement?: Settlement;
}> {
  const wantDahr = process.env.GATEWAY_LIVE_DAHR === "1";
  const wantSettle = process.env.GATEWAY_SETTLEMENT === "1";
  if (!wantDahr && !wantSettle) return {};

  const rpc = process.env.DEMOS_RPC ?? DEFAULT_DEMOS_RPC;
  const mnemonic = process.env.GATEWAY_DAHR_MNEMONIC;
  if (!mnemonic) {
    console.error(
      "[gateway] GATEWAY_LIVE_DAHR/GATEWAY_SETTLEMENT set but GATEWAY_DAHR_MNEMONIC is unset — " +
        "falling back to MOCK attestation + no settlement.",
    );
    return {};
  }

  try {
    const { DemosAdapter } = await import("@kynesyslabs/dacs/substrate");
    const adapter = new DemosAdapter({ rpc, secret: mnemonic });
    await adapter.connect();
    const demos = adapter.raw as unknown as DemosLike & NonceReader;
    const walletAddr = adapter.getAddress();
    const out: {
      oracleAttestedFetch?: AttestedFetchPort;
      outputAnchor?: OutputAnchor;
      contentAttestor?: ContentAttestor;
      settlement?: Settlement;
    } = {};

    if (wantDahr) {
      const { LiveDahr, RealDahrProxy } = await import("../oracle-desk/live-dahr.js");
      // ONE serializer for every wallet WRITE — LiveDahr fetches AND output
      // anchors — so they never collide on the wallet's nonce.
      const serializer = makeWalletSerializer(async () => Number((await demos.getAddressInfo(walletAddr))?.nonce ?? 0));
      const liveDahr = new LiveDahr(new RealDahrProxy(demos));
      const { DacsSellerAttestor } = await import("../sec-audit/attest-files.js");
      out.oracleAttestedFetch = { attestFetch: (url) => serializer.runEager(() => liveDahr.attestFetch(url)) };
      out.outputAnchor = makeOutputAnchor(adapter as unknown as AnchorCapable, serializer);
      out.contentAttestor = new DacsSellerAttestor({
        primaryClaim: `did:demos:agent:${walletAddr.replace(/^0x/, "")}`,
        sign: (bytes) => adapter.sign(bytes),
      });
      console.error(
        `[gateway] LIVE attestation ACTIVE — wallet ${walletAddr} @ ${rpc} ` +
          "(oracle-desk: DAHR node-fetch; ALL agents: on-chain output anchor)",
      );
    }

    if (wantSettle) {
      const priceDem = Number(process.env.GATEWAY_PRICE_DEM ?? "1");
      const priceOs = BigInt(Math.round(priceDem * Number(OS_PER_DEM)));
      // Settlement only READS txs (getTxByHash) — no wallet writes, no serializer.
      const gate = new PaymentGate(demos as unknown as TxReader, walletAddr);
      out.settlement = { gate, fee: uniformFee(priceOs) };
      console.error(
        `[gateway] pay-dem SETTLEMENT ACTIVE — payTo ${walletAddr}, price ${priceDem} DEM/call ` +
          `(${priceOs} OS); present via X-Payment-Tx header`,
      );
    }

    return out;
  } catch (err) {
    console.error(
      `[gateway] LIVE init failed (${(err as Error).message}) — falling back to MOCK + no settlement.`,
    );
    return {};
  }
}

/** 24h — matches the compliance screener's list-body cache TTL. */
const COMPLIANCE_CACHE_TTL_MS = 24 * 60 * 60 * 1000;

export interface BuildPortsOptions {
  /** Directory for the compliance list-body cache (gitignored). */
  complianceCacheDir?: string;
}

/**
 * Build + initialize the x402 settlement gate (USDC on Base Sepolia). Needs the
 * agent names (registered as paid routes) so it's built in main.ts after the
 * registry. Enabled by GATEWAY_X402=1 + GATEWAY_X402_PAYTO (an EVM receive
 * address). Any failure disables x402 loudly — the gateway still runs.
 */
export async function buildX402(agents: readonly string[]): Promise<X402Gate | undefined> {
  if (process.env.GATEWAY_X402 !== "1") return undefined;
  const payTo = process.env.GATEWAY_X402_PAYTO;
  if (!payTo) {
    console.error("[gateway] GATEWAY_X402=1 but GATEWAY_X402_PAYTO (EVM receive address) is unset — x402 disabled.");
    return undefined;
  }
  const amount = process.env.X402_AMOUNT ?? "1000000";
  // x402 `asset` must be the token CONTRACT ADDRESS (the symbol goes in extra.name).
  // Default: USDC on Base Sepolia.
  const asset = process.env.X402_ASSET ?? "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
  const facilitatorUrl = process.env.X402_FACILITATOR ?? "https://x402.org/facilitator";
  try {
    const gate = new X402Gate(agents, {
      payTo,
      network: (process.env.X402_NETWORK ?? "eip155:84532") as `${string}:${string}`,
      asset,
      amount,
      facilitatorUrl,
    });
    await gate.init();
    console.error(
      `[gateway] x402 SETTLEMENT ACTIVE — payTo ${payTo}, ${amount} ${asset} raw/call @ ${facilitatorUrl}`,
    );
    return gate;
  } catch (err) {
    console.error(`[gateway] x402 init failed (${(err as Error).message}) — x402 disabled.`);
    return undefined;
  }
}

/** Build the full-procurement x402 buyer/resource pair. Disabled unless explicitly enabled. */
export async function buildProcurementX402(): Promise<ProcurementX402 | undefined> {
  if (process.env.DACS_X402_PROCUREMENT !== "1") return undefined;
  const keyPath = process.env.DACS_X402_BUYER_KEY_FILE
    ?? join(process.env.HOME ?? process.cwd(), ".config", "dacs", "procurement-buyer.evm.key");
  const mode = statSync(keyPath).mode & 0o777;
  if ((mode & 0o077) !== 0) throw new Error(`${keyPath} must have mode 0600`);
  const buyerPrivateKey = readFileSync(keyPath, "utf8").trim();
  if (!/^0x[0-9a-fA-F]{64}$/.test(buyerPrivateKey)) throw new Error("DACS x402 buyer key must be a 32-byte 0x private key");
  const publicResourceBase = process.env.DACS_X402_RESOURCE_BASE?.trim();
  if (!publicResourceBase) throw new Error("DACS_X402_RESOURCE_BASE is required when x402 procurement is enabled");
  const registryPath = process.env.DACS_X402_RAIL_REGISTRY_FILE?.trim();
  const stewardKey = process.env.DACS_X402_STEWARD_PUBLIC_KEY?.trim();
  if (!registryPath || !stewardKey) {
    throw new Error("DACS x402 procurement requires DACS_X402_RAIL_REGISTRY_FILE and DACS_X402_STEWARD_PUBLIC_KEY");
  }
  const trustMode = (process.env.DACS_X402_TRUST_MODE ?? "dacs-pa2-steward") as X402RegistryTrustMode;
  if (trustMode !== "dacs-pa2-steward" && trustMode !== "operator-provisional") {
    throw new Error("DACS_X402_TRUST_MODE must be dacs-pa2-steward or operator-provisional");
  }
  const railDefinition = loadX402RailDefinition(registryPath, stewardKey, trustMode);
  const port = Number(process.env.GATEWAY_PORT ?? "8402");
  const gate = new ProcurementX402({
    buyerPrivateKey,
    publicResourceBase,
    internalOrigin: process.env.DACS_X402_INTERNAL_ORIGIN ?? `http://127.0.0.1:${port}`,
    facilitatorUrl: process.env.X402_FACILITATOR ?? "https://x402.org/facilitator",
    statePath: process.env.DACS_X402_STATE_PATH ?? join(process.env.HOME ?? process.cwd(), ".local", "state", "dacs", "x402-settlements.json"),
    railDefinition,
  });
  await gate.init();
  console.error(`[gateway] DACS procurement x402 ACTIVE payer=${gate.buyerAddress} resource=${gate.resourceBase}`);
  return gate;
}

export async function buildRealPorts(opts: BuildPortsOptions = {}): Promise<GatewayPorts> {
  const attestor = new MockDahrAttestor();
  // compliance/out/ is gitignored; keep the megabyte list bodies out of git.
  const cacheDir = opts.complianceCacheDir ?? join(process.cwd(), "roster", "compliance", "out", "cache");

  // Optional LIVE attestation (oracle-desk DAHR node-fetch + on-chain output
  // anchor for every agent). Off by default → the gateway stays SDK-free and
  // mock-attested. Enabled only by GATEWAY_LIVE_DAHR=1 + a funded mnemonic. Any
  // failure degrades LOUDLY to mock — the gateway must never fail to start over it.
  const { oracleAttestedFetch, outputAnchor, contentAttestor, settlement } = await maybeBuildLive();
  const llm = anthropicFromEnv();
  console.error(`[gateway] Anthropic LLM ${llm ? `ACTIVE — model ${llm.model}` : "disabled — deterministic fallbacks active"}`);

  return {
    llm,
    attestor,
    attestedFetch: new RealAttestedFetch(attestor),
    oracleAttestedFetch,
    outputAnchor,
    contentAttestor,
    settlement,
    dns: new RealDns(),
    prober: new RealProber(),
    registry: new RealRegistry(),
    marketplace: new MarketplaceStub(),
    treasuryApprover: new TreasurySigner("approver"),
    rulingSigner: new RulingSigner(),
    complianceSources: () => {
      const ctx: ListFetchContext = {
        port: new RealComplianceFetch(attestor),
        cacheDir,
        ttlMs: COMPLIANCE_CACHE_TTL_MS,
        attestor,
      };
      return realSources(ctx);
    },
  };
}
