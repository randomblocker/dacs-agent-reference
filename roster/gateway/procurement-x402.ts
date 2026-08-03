/** Gateway-hosted x402 payment-intent resource for full DACS procurement. */
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { IncomingMessage } from "node:http";
import { settleFromRail } from "../../sdk/src/registry/dispatch.js";
import type { AgreementDocument } from "../dacs/standard-profile.js";
import { standardHash } from "../dacs/standard-profile.js";
import {
  x402AgreementTerms,
  x402IdentityBinding,
  x402IdentityMessage,
  x402IdentityMetadata,
  x402GovernanceDisclosure,
  x402SdkDescriptor,
  type X402RailDefinition,
} from "../dacs/x402-production.js";

interface Intent {
  agreementHash: string;
  agreement: AgreementDocument;
  expiresAt: number;
}

interface PersistedSettlement {
  agreementHash: string;
  jobId: string;
  txHash: string;
  payer: string;
  payee: string;
  network: string;
  amount: string;
  paymentReceiptHash: string;
  responseHeaders: Record<string, string>;
  settledAt: number;
}

interface State { settlements: Record<string, PersistedSettlement> }

export interface ProcurementX402Config {
  buyerPrivateKey: string;
  publicResourceBase: string;
  internalOrigin: string;
  facilitatorUrl?: string;
  statePath: string;
  railDefinition: X402RailDefinition;
}

export interface ProcurementX402Response {
  status: number;
  headers: Record<string, string>;
  body: unknown;
}

function adapterFor(req: IncomingMessage, url: URL): unknown {
  return {
    getHeader: (name: string) => req.headers[name.toLowerCase()] as string | undefined,
    getMethod: () => req.method ?? "GET",
    getPath: () => url.pathname,
    getUrl: () => url.toString(),
    getAcceptHeader: () => (req.headers.accept as string) ?? "application/json",
    getUserAgent: () => (req.headers["user-agent"] as string) ?? "",
    getQueryParams: () => Object.fromEntries(url.searchParams.entries()),
    getQueryParam: (name: string) => url.searchParams.get(name) ?? undefined,
  };
}

function receiptHeader(headers: Record<string, string>): string {
  return Object.entries(headers).find(([key]) => key.toLowerCase() === "payment-response")?.[1] ?? "";
}

function receiptHash(headers: Record<string, string>): string {
  const encoded = receiptHeader(headers);
  if (!encoded) throw new Error("facilitator settlement omitted PAYMENT-RESPONSE");
  return createHash("sha256").update(encoded, "utf8").digest("hex");
}

function jobIdFromPath(path: string, basePath: string): string | undefined {
  if (!path.startsWith(`${basePath}/`)) return undefined;
  const encoded = path.slice(basePath.length + 1);
  if (!encoded || encoded.includes("/")) return undefined;
  try { return decodeURIComponent(encoded); } catch { return undefined; }
}

export class ProcurementX402 {
  private readonly intents = new Map<string, Intent>();
  private readonly state: State;
  private readonly publicBase: URL;
  private readonly internalOrigin: URL;
  private buyerAddressValue = "";
  // The x402 package surface is loaded dynamically and kept behind this adapter.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private http: any;

  constructor(private readonly cfg: ProcurementX402Config) {
    this.publicBase = new URL(cfg.publicResourceBase.replace(/\/+$/, ""));
    this.internalOrigin = new URL(cfg.internalOrigin);
    if (this.publicBase.protocol !== "https:") throw new Error("DACS_X402_RESOURCE_BASE must use HTTPS");
    if (this.publicBase.search || this.publicBase.hash || this.publicBase.username || this.publicBase.password) {
      throw new Error("DACS_X402_RESOURCE_BASE must not contain credentials, query or fragment");
    }
    this.state = this.load();
  }

  get buyerAddress(): string {
    if (!this.buyerAddressValue) throw new Error("x402 procurement has not been initialized");
    return this.buyerAddressValue;
  }
  get resourceBase(): string { return this.publicBase.toString().replace(/\/$/, ""); }
  get governance(): ReturnType<typeof x402GovernanceDisclosure> {
    return x402GovernanceDisclosure(this.cfg.railDefinition);
  }
  matches(path: string): boolean {
    const basePath = this.publicBase.pathname.replace(/\/$/, "");
    return path === basePath || jobIdFromPath(path, basePath) !== undefined;
  }

  async init(): Promise<void> {
    const configuredResource = this.cfg.railDefinition.network.resourceBaseUrl.replace(/\/+$/, "");
    if (configuredResource !== this.resourceBase) {
      throw new Error("DACS_X402_RESOURCE_BASE does not match the authoritative x402 RailDefinition");
    }
    const { HTTPFacilitatorClient, x402HTTPResourceServer, x402ResourceServer } = await import(
      "../../sdk/node_modules/@x402/core/dist/esm/server/index.mjs"
    );
    const { ExactEvmScheme } = await import("../../sdk/node_modules/@x402/evm/dist/esm/exact/server/index.mjs");
    const facilitator = new HTTPFacilitatorClient({ url: this.cfg.facilitatorUrl ?? "https://x402.org/facilitator" });
    const core = new x402ResourceServer(facilitator).register("eip155:84532", new ExactEvmScheme());
    const lookup = (context: { path: string }): Intent => {
      const jobId = jobIdFromPath(context.path, this.publicBase.pathname.replace(/\/$/, ""));
      const intent = jobId ? this.intents.get(jobId) : undefined;
      if (!intent || intent.expiresAt <= Date.now()) throw new Error("x402 procurement intent is absent or expired");
      return intent;
    };
    this.http = new x402HTTPResourceServer(core, {
      [`GET ${this.publicBase.pathname.replace(/\/$/, "")}/*`]: {
        accepts: {
          scheme: "exact",
          network: "eip155:84532",
          payTo: (context: { path: string }) => x402AgreementTerms(lookup(context).agreement).payTo,
          price: (context: { path: string }) => {
            const terms = x402AgreementTerms(lookup(context).agreement);
            return { amount: terms.amount, asset: terms.asset };
          },
          maxTimeoutSeconds: 120,
          extra: { name: "USDC", version: "2" },
        },
        description: "DACS procurement settlement authorization",
        mimeType: "application/json",
        unpaidResponseBody: () => ({ contentType: "application/json", body: { error: "x402 payment required" } }),
      },
    });
    await this.http.initialize();
    const { privateKeyToAccount } = await import("viem/accounts");
    this.buyerAddressValue = privateKeyToAccount(this.cfg.buyerPrivateKey as `0x${string}`).address;
  }

  /** Produce a dual-controlled binding: DACS signs the bundle; Base signs this claim. */
  async identityMetadata(dacsIdentity: string): Promise<Record<string, unknown>> {
    const { privateKeyToAccount } = await import("viem/accounts");
    const account = privateKeyToAccount(this.cfg.buyerPrivateKey as `0x${string}`);
    const message = x402IdentityMessage(dacsIdentity, account.address);
    const signature = await account.signMessage({ message });
    return x402IdentityMetadata(x402IdentityBinding({ dacsIdentity, account: account.address, signature }));
  }

  register(agreement: AgreementDocument): void {
    const terms = x402AgreementTerms(agreement);
    if (!terms.resource.startsWith(`${this.resourceBase}/`)) throw new Error("agreement x402 resource is not served by this gateway");
    if (terms.payer.toLowerCase() !== this.buyerAddress.toLowerCase()) throw new Error("agreement x402 payer is not the configured buyer wallet");
    const agreementHash = standardHash(agreement);
    const incumbent = this.intents.get(agreement.jobId);
    if (incumbent && incumbent.agreementHash !== agreementHash) throw new Error("job id already has a different x402 payment intent");
    const persisted = this.state.settlements[agreement.jobId];
    if (persisted && persisted.agreementHash !== agreementHash) throw new Error("job id already has a different settled x402 agreement");
    this.intents.set(agreement.jobId, { agreementHash, agreement: structuredClone(agreement), expiresAt: agreement.terms.deadline });
  }

  async pay(agreement: AgreementDocument): Promise<Record<string, unknown>> {
    this.register(agreement);
    const cached = this.state.settlements[agreement.jobId];
    if (cached) return this.settlementRecord(cached);
    const terms = x402AgreementTerms(agreement);
    const internal = new URL(terms.resource);
    internal.protocol = this.internalOrigin.protocol;
    internal.host = this.internalOrigin.host;
    const settle = await settleFromRail(x402SdkDescriptor(this.cfg.railDefinition), {
      evmPrivateKey: this.cfg.buyerPrivateKey,
      paywall: {
        url: internal.toString(),
        network: terms.network,
        recipientEvm: terms.payTo,
        phaseIndex: terms.phaseIndex,
      },
    });
    const paid = await settle({
      rail: this.cfg.railDefinition.railId,
      amount: terms.amount,
      asset: this.cfg.railDefinition.asset.symbol,
      payee: terms.payTo,
      jobId: agreement.jobId,
    });
    if (!paid.ok) throw new Error("x402 facilitator did not return a verifiable settlement transaction");
    const settled = this.state.settlements[agreement.jobId];
    if (!settled || settled.txHash.replace(/^0x/, "").toLowerCase() !== paid.txHash.replace(/^0x/, "").toLowerCase()) {
      throw new Error("x402 resource and buyer rail returned different settlement receipts");
    }
    return this.settlementRecord(settled);
  }

  async handle(req: IncomingMessage): Promise<ProcurementX402Response> {
    const url = new URL(req.url ?? "/", this.publicBase.origin);
    const basePath = this.publicBase.pathname.replace(/\/$/, "");
    if (url.pathname === basePath) {
      if (req.method !== "GET") {
        return { status: 405, headers: { allow: "GET" }, body: { error: "method not allowed" } };
      }
      return {
        status: 200,
        headers: { "cache-control": "public, max-age=60" },
        body: {
          kind: "dacs-intent-scoped-x402-resource",
          resourceTemplate: `${this.resourceBase}/{jobId}`,
          createIntent: {
            method: "POST",
            href: new URL("/demo/procurement", this.publicBase.origin).toString(),
          },
          executionControl: {
            model: "server-orchestrated",
            interactiveConfirmation: false,
          },
          buyerControl: {
            model: "gateway-custodied-demo",
            acceptsExternalDacsIdentity: false,
            acceptsExternalPaymentSigner: false,
          },
          note: "A signed agreement creates the job-specific x402 resource; the base URL is discovery, not a reusable quote.",
        },
      };
    }
    const jobId = jobIdFromPath(url.pathname, basePath);
    const intent = jobId ? this.intents.get(jobId) : undefined;
    if (!jobId || !intent || intent.expiresAt <= Date.now()) return { status: 404, headers: {}, body: { error: "x402 procurement intent not found" } };
    if (req.method !== "GET") return { status: 405, headers: { allow: "GET" }, body: { error: "method not allowed" } };
    const paymentHeader = req.headers["payment-signature"] ?? req.headers["x-payment"];
    const cached = this.state.settlements[jobId];
    if (cached && paymentHeader) return { status: 200, headers: cached.responseHeaders, body: this.settlementRecord(cached) };
    const context = {
      adapter: adapterFor(req, url),
      path: url.pathname,
      method: "GET",
      paymentHeader: typeof paymentHeader === "string" ? paymentHeader : undefined,
    };
    const result = await this.http.processHTTPRequest(context);
    if (result.type === "payment-error") {
      return { status: result.response.status, headers: result.response.headers ?? {}, body: result.response.body ?? {} };
    }
    if (result.type !== "payment-verified") return { status: 500, headers: {}, body: { error: "x402 route unexpectedly unprotected" } };
    const settle = await this.http.processSettlement(
      result.paymentPayload,
      result.paymentRequirements,
      result.declaredExtensions,
      { request: context },
    );
    if (!settle.success) return { status: 502, headers: settle.headers ?? {}, body: { error: settle.errorReason } };
    const terms = x402AgreementTerms(intent.agreement);
    const txHash = String(settle.transaction ?? "");
    if (!/^(?:0x)?[0-9a-fA-F]{64}$/.test(txHash)) return { status: 502, headers: {}, body: { error: "facilitator omitted settlement transaction" } };
    const stored: PersistedSettlement = {
      agreementHash: intent.agreementHash,
      jobId,
      txHash,
      payer: String(settle.payer ?? terms.payer),
      payee: terms.payTo,
      network: String(settle.network ?? terms.network),
      amount: String(settle.amount ?? terms.amount),
      paymentReceiptHash: receiptHash(settle.headers),
      responseHeaders: settle.headers,
      settledAt: Date.now(),
    };
    if (stored.payer.toLowerCase() !== terms.payer.toLowerCase()
      || stored.payee.toLowerCase() !== terms.payTo.toLowerCase()
      || stored.network !== terms.network
      || BigInt(stored.amount) !== BigInt(terms.amount)) {
      return { status: 502, headers: {}, body: { error: "facilitator receipt differs from the signed agreement" } };
    }
    this.state.settlements[jobId] = stored;
    this.flush(); // durable before the buyer receives 200: crash-safe paid-job recovery
    return { status: 200, headers: settle.headers, body: this.settlementRecord(stored) };
  }

  private settlementRecord(value: PersistedSettlement): Record<string, unknown> {
    return {
      txHash: value.txHash,
      payer: value.payer,
      payee: value.payee,
      chainId: value.network,
      amountOs: value.amount,
      paymentReceiptHash: value.paymentReceiptHash,
      settledAt: value.settledAt,
    };
  }

  private load(): State {
    if (!existsSync(this.cfg.statePath)) return { settlements: {} };
    const value = JSON.parse(readFileSync(this.cfg.statePath, "utf8")) as State;
    if (!value || typeof value !== "object" || !value.settlements || typeof value.settlements !== "object") {
      throw new Error("x402 settlement state is unreadable; refusing to lose paid-job receipts");
    }
    return value;
  }

  private flush(): void {
    mkdirSync(dirname(this.cfg.statePath), { recursive: true, mode: 0o700 });
    const tmp = `${this.cfg.statePath}.tmp`;
    writeFileSync(tmp, JSON.stringify(this.state, null, 2) + "\n", { mode: 0o600 });
    renameSync(tmp, this.cfg.statePath);
    chmodSync(this.cfg.statePath, 0o600);
  }
}
