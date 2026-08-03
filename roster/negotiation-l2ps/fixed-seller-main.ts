/** Production entrypoint for independently keyed fixed-price Oracle/DD sellers. */
import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { DemosAdapter } from "@kynesyslabs/dacs/substrate";
import { LiveSubstrate } from "../../src/live/substrate.js";
import { PaymentGate, type TxReader } from "../gateway/settlement.js";
import { anthropicFromEnv } from "../llm/anthropic.js";
import { initIdentity, MessagingPeer, primaryClaimSigner } from "./demosdk.js";
import { SellerDaemon, SellerStateStore } from "./seller-daemon.js";
import { SellerAdapter, type StandardListingSpec, type WorkCallback } from "../dacs/seller-adapter.js";
import {
  oracleAutoAcceptListing,
  oracleAutoAcceptX402Listing,
  ddLiveFixedListing,
  ddLiveFixedX402Listing,
} from "../gateway/procurement-listings.js";
import { X402PaymentVerifier } from "../gateway/x402-verifier.js";
import {
  loadX402RailDefinition,
  x402IdentityBinding,
  x402IdentityMetadata,
} from "../dacs/x402-production.js";
import { makeOracleWork, normalizeOracleWorkParams, ORACLE_SERVICE_ID } from "../dacs/wire/oracle-desk.js";
import { resolveRequest } from "../oracle-desk/attest-any.js";
import { makeDdWork, DD_SERVICE_ID, subjectFromParams } from "../dacs/wire/dd-researcher.js";
import { DirectHttpsAttestor, RealAttestedFetch } from "../oracle-desk/attested-fetch.js";

type Profile = "oracle-auto-accept" | "dd-live-fixed";

const profile = process.env.DACS_FIXED_PROFILE as Profile | undefined;
if (profile !== "oracle-auto-accept" && profile !== "dd-live-fixed") {
  throw new Error("DACS_FIXED_PROFILE must be oracle-auto-accept or dd-live-fixed");
}

const serverUrl = process.env.SERVER_URL ?? "ws://demosnode.discus.sh:3005";
const rpc = process.env.DEMOS_RPC ?? "https://demosnode.discus.sh/";
const clientId = process.env.SELLER_CLIENT_ID ?? (profile === "oracle-auto-accept" ? "dacs-oracle-fixed" : "dacs-dd-fixed");
const keyPath = process.env.SELLER_KEY_PATH;
const statePath = process.env.SELLER_STATE_PATH;
if (!keyPath || !statePath) throw new Error("SELLER_KEY_PATH and SELLER_STATE_PATH are required");

function loadSecret(path: string): string {
  const mode = statSync(path).mode & 0o777;
  if ((mode & 0o077) !== 0) throw new Error(`${path} must have mode 0600`);
  const secret = readFileSync(path, "utf8").trim();
  if (!secret) throw new Error(`${path} is empty`);
  return secret;
}

function positiveIntegerEnv(name: string, fallback?: number): number {
  const raw = process.env[name];
  if (raw === undefined && fallback !== undefined) return fallback;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${name} must be a positive integer`);
  return value;
}

function oracleRequestGuard(request: Record<string, unknown>): void {
  const normalized = normalizeOracleWorkParams(request);
  if (normalized.product !== "crypto-price" && normalized.product !== "fx-rate" && normalized.product !== "chain-height") {
    throw new Error("Oracle product must be crypto-price, fx-rate, or chain-height");
  }
  // Catalog validation is closed over the selected product (required fields,
  // patterns, and unknown-field rejection) and performs no network request.
  resolveRequest(normalized);
}

function ddRequestGuard(request: Record<string, unknown>): void {
  subjectFromParams(request);
  const subject = String(request.subject ?? "");
  if (!subject || subject.length > 120 || !/^[A-Za-z0-9@._:/-]+$/.test(subject)) throw new Error("DD subject is not bounded or safe");
  const allowed = new Set(["kind", "subject"]);
  if (Object.keys(request).some((key) => !allowed.has(key))) throw new Error("DD request contains unsupported fields");
}

function listingSpec(now: number): StandardListingSpec {
  if (profile === "oracle-auto-accept") {
    const validUntil = positiveIntegerEnv("DACS_LISTING_VALID_UNTIL_MS");
    if (validUntil < now + 3_600_000) throw new Error("Oracle auto-accept commitment must remain valid for at least one hour");
    const listingVersion = positiveIntegerEnv("DACS_LISTING_VERSION", 3);
    if (listingVersion < 3) throw new Error("Oracle current listing requires DACS_LISTING_VERSION >= 3");
    return oracleAutoAcceptListing({
      listingVersion,
      notBefore: positiveIntegerEnv("DACS_LISTING_NOT_BEFORE_MS", now),
      validUntil,
      priceDem: process.env.DACS_FIXED_PRICE_DEM ?? "1",
      publicEndpoint: process.env.DACS_PUBLIC_ENDPOINT,
    });
  }
  const listingVersion = positiveIntegerEnv("DACS_LISTING_VERSION", 2);
  if (listingVersion < 2) throw new Error("DD current listing requires DACS_LISTING_VERSION >= 2");
  return ddLiveFixedListing({
    listingVersion,
    notBefore: positiveIntegerEnv("DACS_LISTING_NOT_BEFORE_MS", now),
    priceDem: process.env.DACS_FIXED_PRICE_DEM ?? "2",
    publicEndpoint: process.env.DACS_PUBLIC_ENDPOINT,
  });
}

async function main(): Promise<void> {
  const mnemonic = loadSecret(keyPath!);
  const adapter = new DemosAdapter({ rpc, secret: mnemonic });
  const raw = adapter.raw as unknown as TxReader & {
    connectWallet(secret: string): Promise<unknown>;
    getAddress(): string;
  };
  await raw.connectWallet(mnemonic);
  await adapter.connect();
  const payTo = raw.getAddress();
  const did = `did:demos:agent:${payTo.replace(/^0x/, "")}`;
  const seed = Buffer.concat([
    createHash("sha512").update(`dacs-${profile}-l2ps-v1\x00`).update(mnemonic).digest(),
    createHash("sha512").update(`dacs-${profile}-l2ps-v1\x01`).update(mnemonic).digest(),
  ]);
  const identity = await initIdentity(seed);
  const peer = new MessagingPeer({ serverUrl, clientId, publicKey: identity.mlkemPublicKey });
  await peer.connect();
  await peer.discoverPeers?.();

  const substrate = new LiveSubstrate(adapter);
  const sellerParty = { primaryClaim: did, sign: (bytes: Uint8Array) => adapter.sign(bytes) };
  // demosdk's DAHR proxy hides transaction/nonces and has hung beyond the
  // signed delivery deadline on the public node. Use the roster's established
  // bounded direct-HTTPS adapter; its complete source record is subsequently
  // signed by this stable seller and anchored in the DACS delivery.
  const attestedFetch = new RealAttestedFetch(new DirectHttpsAttestor(), 12_000, 512_000);
  const llm = profile === "dd-live-fixed" ? anthropicFromEnv() : undefined;
  const work: WorkCallback = profile === "oracle-auto-accept"
    ? makeOracleWork(attestedFetch)
    : makeDdWork(attestedFetch, {
      useLlm: Boolean(llm),
      ...(llm ? { llm: (prompt, timeoutMs) => llm.complete(prompt, { maxTokens: 700, timeoutMs }) } : {}),
    });
  const serviceId = profile === "oracle-auto-accept" ? ORACLE_SERVICE_ID : DD_SERVICE_ID;
  const seller = new SellerAdapter({ did, sign: sellerParty.sign }, substrate, serviceId, work);
  const spec = listingSpec(Date.now());
  const published = await seller.publishStandardListing(spec);
  const x402Enabled = process.env.DACS_X402_ENABLED === "1";
  const x402PayTo = process.env.DACS_X402_PAYTO?.trim() ?? "";
  const x402ResourceBase = process.env.DACS_X402_RESOURCE_BASE?.trim() ?? "";
  const x402PriceUsdc = process.env.DACS_X402_PRICE_USDC?.trim() ?? "";
  const x402IdentityProof = process.env.DACS_X402_IDENTITY_PROOF?.trim() ?? "";
  if (x402Enabled && (!x402PayTo || !x402ResourceBase || !x402PriceUsdc || !x402IdentityProof)) {
    throw new Error("DACS_X402_ENABLED=1 requires DACS_X402_PAYTO, DACS_X402_RESOURCE_BASE, DACS_X402_PRICE_USDC and DACS_X402_IDENTITY_PROOF");
  }
  if (x402Enabled) {
    const registryPath = process.env.DACS_X402_RAIL_REGISTRY_FILE?.trim() ?? "";
    const stewardKey = process.env.DACS_X402_STEWARD_PUBLIC_KEY?.trim() ?? "";
    if (!registryPath || !stewardKey) throw new Error("x402 seller requires the signed rail registry and pinned steward key");
    const trustMode = process.env.DACS_X402_TRUST_MODE ?? "dacs-pa2-steward";
    if (trustMode !== "dacs-pa2-steward" && trustMode !== "operator-provisional") {
      throw new Error("DACS_X402_TRUST_MODE must be dacs-pa2-steward or operator-provisional");
    }
    const rail = loadX402RailDefinition(registryPath, stewardKey, trustMode);
    if (rail.network.resourceBaseUrl.replace(/\/+$/, "") !== x402ResourceBase.replace(/\/+$/, "")) {
      throw new Error("seller x402 resource base differs from its authoritative RailDefinition");
    }
  }
  const x402Binding = x402Enabled
    ? x402IdentityBinding({ dacsIdentity: did, account: x402PayTo, signature: x402IdentityProof })
    : undefined;
  const x402Metadata = x402Binding ? x402IdentityMetadata(x402Binding) : undefined;
  const x402Spec = x402Enabled
    ? profile === "oracle-auto-accept"
      ? oracleAutoAcceptX402Listing({
          listingVersion: positiveIntegerEnv("DACS_X402_LISTING_VERSION", 3),
          validUntil: positiveIntegerEnv("DACS_LISTING_VALID_UNTIL_MS"),
          notBefore: positiveIntegerEnv("DACS_LISTING_NOT_BEFORE_MS", Date.now()),
          priceUsdc: x402PriceUsdc,
          payTo: x402PayTo,
          resourceBase: x402ResourceBase,
          identityMetadata: x402Metadata!,
        })
      : ddLiveFixedX402Listing({
          listingVersion: positiveIntegerEnv("DACS_X402_LISTING_VERSION", 2),
          notBefore: positiveIntegerEnv("DACS_LISTING_NOT_BEFORE_MS", Date.now()),
          priceUsdc: x402PriceUsdc,
          payTo: x402PayTo,
          resourceBase: x402ResourceBase,
          identityMetadata: x402Metadata!,
        })
    : undefined;
  const x402Published = x402Spec ? await seller.publishStandardListing(x402Spec) : undefined;
  const listings = new Map([
    [published.ref, published],
    ...(x402Published ? [[x402Published.ref, x402Published] as const] : []),
  ]);

  // The seller wallet owns DAHR, delivery, evidence, and bundle writes. Preserve
  // its single nonce domain across concurrent paid sessions.
  let writeTail: Promise<unknown> = Promise.resolve();
  const serialize = <T>(fn: () => Promise<T>): Promise<T> => {
    const current = writeTail.then(fn, fn);
    writeTail = current.then(() => undefined, () => undefined);
    return current;
  };
  const daemon = new SellerDaemon(
    peer,
    identity,
    payTo,
    new PaymentGate(raw, payTo),
    new SellerStateStore(statePath!),
    positiveIntegerEnv("DACS_MAX_SESSIONS", 4),
    console.error,
    undefined,
    (request) => serialize(async () => {
      if (!request.params) throw new Error("fixed-price delivery omitted its bound request");
      const workParams = profile === "oracle-auto-accept"
        ? normalizeOracleWorkParams(request.params)
        : request.params;
      const prepared = await seller.prepareDelivery(request.agreement.jobId, workParams, request.params);
      return {
        deliveryRef: prepared.attestationRef,
        attestation: prepared.anchoredAttestation,
        result: prepared.result,
        preparedAnchor: { name: prepared.anchorName, value: prepared.anchoredAttestation },
        deliverableContentHash: prepared.attestation.resultHash,
      };
    }),
    undefined,
    ["quick"],
    primaryClaimSigner(did, sellerParty.sign),
    {
      party: sellerParty,
      sub: substrate,
      ...(x402Metadata ? { identityMetadata: x402Metadata } : {}),
      async getListing(listingAnchorRef) {
        const selected = listingAnchorRef ? listings.get(listingAnchorRef) : published;
        if (!selected) throw new Error("buyer selected an unknown seller listing");
        return {
          listing: selected.listing,
          listingAnchorRef: selected.ref,
          ...(selected.autoAcceptCommitment ? { autoAcceptCommitment: selected.autoAcceptCommitment } : {}),
          ...(selected.autoAcceptCommitmentRef ? { autoAcceptCommitmentRef: selected.autoAcceptCommitmentRef } : {}),
        };
      },
    },
    profile === "oracle-auto-accept" ? oracleRequestGuard : ddRequestGuard,
    x402Enabled ? new X402PaymentVerifier() : undefined,
  );
  daemon.listen();
  console.error(`[${profile}] ready client=${clientId} did=${did} listing=${published.ref}`);
  if (published.autoAcceptCommitmentRef) console.error(`[${profile}] autoAccept=${published.autoAcceptCommitmentRef}`);
  if (x402Published) console.error(`[${profile}] x402 listing=${x402Published.ref} payTo=${x402PayTo}`);
  if (x402Published?.autoAcceptCommitmentRef) console.error(`[${profile}] x402 autoAccept=${x402Published.autoAcceptCommitmentRef}`);

  let stopping = false;
  const stop = (signal: string): void => {
    if (stopping) return;
    stopping = true;
    console.error(`[${profile}] ${signal} received; disconnecting`);
    peer.disconnect?.();
    setTimeout(() => process.exit(0), 100).unref();
  };
  process.on("SIGTERM", () => stop("SIGTERM"));
  process.on("SIGINT", () => stop("SIGINT"));
}

main().catch((error) => {
  console.error(`[${profile}] fatal:`, error);
  process.exitCode = 1;
});
