/** Production x402/Base-Sepolia terms shared by listings, agreements and settlement. */
import { readFileSync } from "node:fs";
import { signedBytes } from "@kynesyslabs/dacs";
import type { RailDescriptor } from "../../sdk/src/registry/types.js";
import { verify } from "../../src/identity.js";
import {
  standardHash,
  type AgreementDocument,
  type IdentityBundle,
  type PaymentRailRef,
  type PriceTerm,
} from "./standard-profile.js";

export const BASE_SEPOLIA_NETWORK = "eip155:84532" as const;
export const BASE_SEPOLIA_CHAIN_ID = 84_532;
export const BASE_SEPOLIA_USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e" as const;
export const X402_PROTOCOL_VERSION = "2" as const;
/** Canonical DACS-4 registry id (§9.4.2); per-deal coordinates live in the ref. */
export const X402_RAIL_ID = "x402:default" as const;
export const X402_RAIL_VERSION = 1 as const;
export const USDC_DECIMALS = 6;

/**
 * The seller's machine contact surface is hosted alongside its x402 resource.
 * Deriving the default from the configured live origin prevents an unrelated
 * or retired hostname from being signed into a fresh listing.
 */
export function x402PublicEndpoint(resourceBase: string, override?: string): string {
  const resource = new URL(resourceBase);
  if (resource.protocol !== "https:" || resource.username || resource.password) {
    throw new Error("x402 resourceBase must use clean HTTPS");
  }
  const endpoint = override === undefined
    ? new URL("/demo/procurement/options", resource.origin)
    : new URL(override);
  if (endpoint.protocol !== "https:" || endpoint.username || endpoint.password || endpoint.origin !== resource.origin) {
    throw new Error("publicEndpoint must use the live x402 gateway origin");
  }
  return endpoint.toString();
}

/**
 * The standard-wide PA-2 registry is the normative trust mode. The operator
 * mode exists solely to keep a live deployment usable while that registry is
 * not actually published/resolvable; it must always be disclosed to clients.
 */
export type X402RegistryTrustMode = "dacs-pa2-steward" | "operator-provisional";

const EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const HASH = /^[0-9a-f]{64}$/i;

export interface X402RailDefinition {
  railVersion: number;
  railId: typeof X402_RAIL_ID;
  railType: "x402";
  asset: { kind: "erc20"; chainId: typeof BASE_SEPOLIA_CHAIN_ID; contract: string; symbol: "USDC"; decimals: typeof USDC_DECIMALS };
  network: { kind: "x402-resource"; resourceBaseUrl: string };
  phaseHandler: "pay-x402";
  parameters: { scheme: "exact"; protocolVersion: typeof X402_PROTOCOL_VERSION };
  availability: "live" | "operator_gated" | "closed_data" | "bilateral" | "mocked" | "disabled" | "failed";
  governance: {
    proposedBy: string;
    acceptedAt: number;
    supersedes?: number;
    anchoring: "in-code" | "single-signer" | "multisig";
    /** Non-normative deployment extension. Required for provisional trust. */
    authorityScope?: X402RegistryTrustMode;
    /** Public explanation of why the non-standard authority is being used. */
    disclosure?: string;
  };
  signature: { algorithm: "ed25519"; signer: string; value: string };
}

export interface X402IdentityBinding {
  kind: "dacs-payment-account-binding";
  bindingVersion: "1";
  railId: typeof X402_RAIL_ID;
  network: typeof BASE_SEPOLIA_NETWORK;
  asset: typeof BASE_SEPOLIA_USDC;
  account: string;
  proof: { kind: "eip191-personal-sign"; message: string; signature: string };
}

export interface X402ListingTerms {
  network: typeof BASE_SEPOLIA_NETWORK;
  chainId: typeof BASE_SEPOLIA_CHAIN_ID;
  asset: string;
  decimals: number;
  payTo: string;
  resourceBase: string;
  scheme: "exact";
  protocolVersion: typeof X402_PROTOCOL_VERSION;
}

export interface X402AgreementTerms extends X402ListingTerms {
  payer: string;
  resource: string;
  amount: string;
  phaseIndex: number;
}

function decodeSignature(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "base64url"));
}

/**
 * Load and verify the authoritative PA-2 rail definition. Production x402 is
 * deliberately unavailable without a steward-signed definition and pinned
 * steward key (DACS-4 RD-1..RD-5, RAV-R5).
 */
export function loadX402RailDefinition(
  path: string,
  stewardPublicKeyHex: string,
  trustMode: X402RegistryTrustMode = "dacs-pa2-steward",
): X402RailDefinition {
  if (!/^[0-9a-f]{64}$/i.test(stewardPublicKeyHex)) {
    throw new Error("DACS x402 steward public key must be 32-byte hex");
  }
  const document = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
  if (document.registryId !== "dacs4:registry:v0.1" || !Array.isArray(document.entries)) {
    throw new Error("DACS x402 rail registry has an invalid index shape");
  }
  const candidates = document.entries.filter((entry): entry is X402RailDefinition => {
    const value = plainRecord(entry);
    return value?.railId === X402_RAIL_ID && value.railVersion === X402_RAIL_VERSION;
  });
  if (candidates.length !== 1) throw new Error(`rail registry must contain exactly one ${X402_RAIL_ID} v${X402_RAIL_VERSION}`);
  const rail = candidates[0]!;
  validateX402RailDefinition(rail);
  const declaredScope = rail.governance.authorityScope ?? "dacs-pa2-steward";
  if (declaredScope !== trustMode) {
    throw new Error(`x402 rail authority scope ${declaredScope} does not match configured trust mode ${trustMode}`);
  }
  if (trustMode === "operator-provisional") {
    let disclosure: URL;
    try { disclosure = new URL(rail.governance.disclosure ?? ""); }
    catch { throw new Error("operator-provisional x402 rail requires a public HTTPS disclosure URL"); }
    if (disclosure.protocol !== "https:") {
      throw new Error("operator-provisional x402 disclosure must use HTTPS");
    }
  }
  const signature = rail.signature;
  if (signature.signer !== rail.governance.proposedBy) throw new Error("x402 rail signer does not match its steward claim");
  const key = Uint8Array.from(Buffer.from(stewardPublicKeyHex, "hex"));
  const valid = verify(
    signedBytes("dacs-rail:v1:", standardHash(rail)),
    decodeSignature(signature.value),
    key,
  );
  if (!valid) throw new Error("x402 rail definition signature is invalid under the pinned steward key");
  return structuredClone(rail);
}

export function x402GovernanceDisclosure(rail: X402RailDefinition): {
  status: "normative-pa2" | "operator-provisional";
  conformantAuthority: boolean;
  signer: string;
  disclosure?: string;
} {
  const provisional = rail.governance.authorityScope === "operator-provisional";
  return {
    status: provisional ? "operator-provisional" : "normative-pa2",
    conformantAuthority: !provisional,
    signer: rail.governance.proposedBy,
    ...(rail.governance.disclosure ? { disclosure: rail.governance.disclosure } : {}),
  };
}

export function validateX402RailDefinition(rail: X402RailDefinition): void {
  if (rail.railId !== X402_RAIL_ID || rail.railVersion !== X402_RAIL_VERSION || rail.railType !== "x402") {
    throw new Error("x402 rail identity/version/type is not canonical");
  }
  if (rail.phaseHandler !== "pay-x402") throw new Error("x402 rail must dispatch pay-x402");
  if (rail.availability !== "live" && rail.availability !== "operator_gated") {
    throw new Error(`x402 rail is unavailable (${rail.availability})`);
  }
  if (rail.asset.kind !== "erc20" || rail.asset.chainId !== BASE_SEPOLIA_CHAIN_ID
    || rail.asset.contract.toLowerCase() !== BASE_SEPOLIA_USDC.toLowerCase()
    || rail.asset.symbol !== "USDC" || rail.asset.decimals !== USDC_DECIMALS) {
    throw new Error("x402 rail asset is not Base Sepolia USDC");
  }
  if (rail.network.kind !== "x402-resource") throw new Error("x402 rail network must be x402-resource");
  normalizedResourceBase(rail.network.resourceBaseUrl);
  if (rail.parameters.scheme !== "exact" || rail.parameters.protocolVersion !== X402_PROTOCOL_VERSION) {
    throw new Error("x402 rail scheme/protocol version is unsupported");
  }
  if (!Number.isSafeInteger(rail.governance.acceptedAt) || rail.governance.acceptedAt < 0
    || rail.governance.anchoring !== "single-signer") {
    throw new Error("production x402 requires a PA-2 single-signer governance record");
  }
  if (!rail.signature || rail.signature.algorithm !== "ed25519" || !rail.signature.signer || !rail.signature.value) {
    throw new Error("x402 rail has no valid steward signature envelope");
  }
}

/** Adapt a verified normative RailDefinition to the SDK's current dispatcher. */
export function x402SdkDescriptor(rail: X402RailDefinition): RailDescriptor {
  validateX402RailDefinition(rail);
  return {
    id: rail.railId,
    kind: rail.railType,
    availability: "live",
    params: {
      tokenAddress: rail.asset.contract,
      network: BASE_SEPOLIA_NETWORK,
      protocolVersion: rail.parameters.protocolVersion,
      railVersion: rail.railVersion,
    },
  };
}

function plainRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function normalizedAddress(value: unknown, label: string): string {
  const address = typeof value === "string" ? value.trim() : "";
  if (!EVM_ADDRESS.test(address)) throw new Error(`${label} must be a 20-byte 0x EVM address`);
  return address;
}

function normalizedResourceBase(value: unknown): string {
  const raw = typeof value === "string" ? value.trim().replace(/\/+$/, "") : "";
  let url: URL;
  try { url = new URL(raw); } catch { throw new Error("x402 resourceBase must be an absolute URL"); }
  const local = url.hostname === "127.0.0.1" || url.hostname === "localhost";
  if (url.protocol !== "https:" && !(local && url.protocol === "http:")) {
    throw new Error("x402 resourceBase must use HTTPS (HTTP is allowed only for localhost tests)");
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error("x402 resourceBase must not contain credentials, a query, or a fragment");
  }
  return raw;
}

/** Convert a canonical decimal display amount into integer token base units. */
export function decimalToBaseUnits(amount: string, decimals: number): string {
  if (!Number.isSafeInteger(decimals) || decimals < 0 || decimals > 36) {
    throw new Error("token decimals must be an integer between 0 and 36");
  }
  if (!/^(?:0|[1-9]\d*)(?:\.\d+)?$/.test(amount)) {
    throw new Error(`amount ${amount} is not canonical positive decimal text`);
  }
  const [whole, fraction = ""] = amount.split(".");
  if (fraction.length > decimals) throw new Error(`amount ${amount} exceeds ${decimals} token decimals`);
  const value = BigInt(whole!) * (10n ** BigInt(decimals))
    + BigInt((fraction + "0".repeat(decimals)).slice(0, decimals) || "0");
  if (value <= 0n) throw new Error("payment amount must be positive");
  return value.toString();
}

export function x402RailRef(input: { payTo: string; resourceBase: string }): PaymentRailRef {
  return {
    railId: X402_RAIL_ID,
    railVersion: X402_RAIL_VERSION,
    parameters: {
      scheme: "exact",
      payTo: normalizedAddress(input.payTo, "x402 payTo"),
      resourceBase: normalizedResourceBase(input.resourceBase),
      protocolVersion: X402_PROTOCOL_VERSION,
    },
  };
}

export function isX402Rail(rail: PaymentRailRef | undefined): boolean {
  return rail?.railId === X402_RAIL_ID;
}

export function x402ListingTerms(rail: PaymentRailRef | undefined): X402ListingTerms {
  if (!isX402Rail(rail)) throw new Error("agreement/listing did not select an x402 rail");
  const p = plainRecord(rail?.parameters);
  if (!p) throw new Error("x402 rail parameters are missing");
  if (rail?.railVersion !== X402_RAIL_VERSION) throw new Error("x402 rail version is not pinned to the supported definition");
  if (p.scheme !== "exact") throw new Error("x402 scheme must be exact");
  if (p.protocolVersion !== X402_PROTOCOL_VERSION) throw new Error("x402 protocolVersion must be 2");
  return {
    scheme: "exact",
    network: BASE_SEPOLIA_NETWORK,
    chainId: BASE_SEPOLIA_CHAIN_ID,
    asset: BASE_SEPOLIA_USDC,
    decimals: USDC_DECIMALS,
    payTo: normalizedAddress(p.payTo, "x402 payTo"),
    resourceBase: normalizedResourceBase(p.resourceBase),
    protocolVersion: X402_PROTOCOL_VERSION,
  };
}

export function x402IdentityMessage(dacsIdentity: string, account: string): string {
  if (!dacsIdentity.trim()) throw new Error("DACS identity is required for an x402 account binding");
  const address = normalizedAddress(account, "x402 identity account").toLowerCase();
  return [
    "DACS x402 payment-account binding",
    "version:1",
    `dacsIdentity:${dacsIdentity}`,
    `railId:${X402_RAIL_ID}`,
    `network:${BASE_SEPOLIA_NETWORK}`,
    `asset:${BASE_SEPOLIA_USDC.toLowerCase()}`,
    `account:${address}`,
  ].join("\n");
}

export function x402IdentityBinding(input: { dacsIdentity: string; account: string; signature: string }): X402IdentityBinding {
  const account = normalizedAddress(input.account, "x402 identity account");
  if (!/^0x[0-9a-fA-F]{130}$/.test(input.signature)) throw new Error("x402 identity proof must be a 65-byte EIP-191 signature");
  return {
    kind: "dacs-payment-account-binding",
    bindingVersion: "1",
    railId: X402_RAIL_ID,
    network: BASE_SEPOLIA_NETWORK,
    asset: BASE_SEPOLIA_USDC,
    account,
    proof: {
      kind: "eip191-personal-sign",
      message: x402IdentityMessage(input.dacsIdentity, account),
      signature: input.signature,
    },
  };
}

export function x402IdentityMetadata(binding: X402IdentityBinding): Record<string, unknown> {
  return { paymentAccounts: [binding] };
}

export async function verifyX402IdentityBinding(
  bundle: IdentityBundle,
  expectedAccount: string,
): Promise<X402IdentityBinding> {
  const primary = bundle.claims.find((claim) => claim.ref === bundle.presentedBy);
  const accounts = primary?.metadata?.paymentAccounts;
  if (!Array.isArray(accounts)) throw new Error("DACS identity has no linked payment account");
  const expected = normalizedAddress(expectedAccount, "expected x402 account");
  const raw = accounts.find((candidate) => plainRecord(candidate)?.railId === X402_RAIL_ID
    && String(plainRecord(candidate)?.account ?? "").toLowerCase() === expected.toLowerCase());
  if (!raw) throw new Error("DACS identity has no linked payment account matching the x402 payer/payee");
  const value = plainRecord(raw);
  const proof = plainRecord(value?.proof);
  if (!value || value.kind !== "dacs-payment-account-binding" || value.bindingVersion !== "1"
    || value.network !== BASE_SEPOLIA_NETWORK
    || String(value.asset).toLowerCase() !== BASE_SEPOLIA_USDC.toLowerCase()
    || proof?.kind !== "eip191-personal-sign" || typeof proof.message !== "string"
    || typeof proof.signature !== "string" || !HASH.test(standardHash(bundle, ["presentation"]))) {
    throw new Error("DACS x402 payment-account binding is malformed");
  }
  const message = x402IdentityMessage(bundle.presentedBy, expected);
  if (proof.message !== message) throw new Error("x402 payment-account proof is bound to a different DACS identity/account");
  const { verifyMessage } = await import("viem");
  const valid = await verifyMessage({
    address: expected as `0x${string}`,
    message,
    signature: proof.signature as `0x${string}`,
  });
  if (!valid) throw new Error("x402 payment-account proof is not signed by the linked Base account");
  return value as unknown as X402IdentityBinding;
}

export function x402ResourceForJob(resourceBase: string, jobId: string): string {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(jobId)) throw new Error("x402 job id is not URL-safe");
  return `${normalizedResourceBase(resourceBase)}/${encodeURIComponent(jobId)}`;
}

/** Terms that the two DACS-3 signatures bind for one x402 settlement. */
export function x402AgreementAdditionalTerms(
  rail: PaymentRailRef,
  payer: string,
  jobId: string,
  phaseIndex: number,
): { x402: { payer: string; resource: string; protocolVersion: "2"; phaseIndex: number } } {
  const terms = x402ListingTerms(rail);
  if (!Number.isSafeInteger(phaseIndex) || phaseIndex < 0) throw new Error("x402 phaseIndex must be a non-negative integer");
  return {
    x402: {
      payer: normalizedAddress(payer, "x402 payer"),
      resource: x402ResourceForJob(terms.resourceBase, jobId),
      protocolVersion: X402_PROTOCOL_VERSION,
      phaseIndex,
    },
  };
}

export function x402AgreementTerms(agreement: AgreementDocument): X402AgreementTerms {
  const listing = x402ListingTerms(agreement.terms.rail);
  const extra = plainRecord(agreement.terms.additionalTerms?.x402);
  if (!extra) throw new Error("agreement omitted its x402 payer/resource binding");
  if (extra.protocolVersion !== X402_PROTOCOL_VERSION) throw new Error("agreement x402 protocolVersion must be 2");
  if (!Number.isSafeInteger(extra.phaseIndex) || Number(extra.phaseIndex) < 0) throw new Error("agreement x402 phaseIndex is invalid");
  const resource = typeof extra.resource === "string" ? extra.resource : "";
  const expectedResource = x402ResourceForJob(listing.resourceBase, agreement.jobId);
  if (resource !== expectedResource) throw new Error("agreement x402 resource does not match its listing/job");
  if (agreement.terms.price.currency !== "USDC") throw new Error("x402 agreement currency must be USDC");
  return {
    ...listing,
    payer: normalizedAddress(extra.payer, "x402 payer"),
    resource,
    amount: decimalToBaseUnits(agreement.terms.price.amount, listing.decimals),
    phaseIndex: Number(extra.phaseIndex),
  };
}

export function paymentPhaseForAgreement(agreement: AgreementDocument): "pay-dem" | "pay-x402" {
  return isX402Rail(agreement.terms.rail) ? "pay-x402" : "pay-dem";
}

/** Produce a USDC display-price term; conversion to base units happens at settlement. */
export function usdcPrice(amount: string, unit: string): PriceTerm {
  decimalToBaseUnits(amount, USDC_DECIMALS);
  return { amount, currency: "USDC", unit };
}
