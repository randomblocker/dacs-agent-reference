/** Independent production entrypoint for the fixed-price Sponsored Post seller. */
import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { DemosAdapter } from "@kynesyslabs/dacs/substrate";
import { LiveSubstrate } from "../../src/live/substrate.js";
import { SellerAdapter } from "../dacs/seller-adapter.js";
import {
  loadX402RailDefinition,
  x402IdentityBinding,
  x402IdentityMetadata,
} from "../dacs/x402-production.js";
import { makeSponsoredPostWork, SPONSORED_POST_SERVICE_ID } from "../dacs/wire/sponsored-post.js";
import { PaymentGate, type TxReader } from "../gateway/settlement.js";
import {
  sponsoredPostLiveListing,
  sponsoredPostLiveX402Listing,
} from "../gateway/procurement-listings.js";
import { X402PaymentVerifier } from "../gateway/x402-verifier.js";
import { FileSponsoredPostIdempotencyStore } from "../sponsored-post/idempotency.js";
import { HttpSponsoredPostModerationPort } from "../sponsored-post/moderation.js";
import { parseSponsoredPostRequest } from "../sponsored-post/policy.js";
import type { XAccountBinding } from "../sponsored-post/types.js";
import { XApiSponsoredPostPort } from "../sponsored-post/x-api.js";
import { initIdentity, MessagingPeer, primaryClaimSigner } from "./demosdk.js";
import { SellerDaemon, SellerStateStore } from "./seller-daemon.js";

const serverUrl = process.env.SERVER_URL ?? "ws://demosnode.discus.sh:3005";
const rpc = process.env.DEMOS_RPC ?? "https://demosnode.discus.sh/";
const clientId = process.env.SELLER_CLIENT_ID ?? "dacs-sponsored-post";

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function readPrivate(path: string): string {
  const mode = statSync(path).mode & 0o777;
  if ((mode & 0o077) !== 0) throw new Error(`${path} must have mode 0600`);
  const value = readFileSync(path, "utf8").trim();
  if (!value) throw new Error(`${path} is empty`);
  return value;
}

function positiveInteger(name: string, fallback?: number): number {
  const raw = process.env[name];
  if (raw === undefined && fallback !== undefined) return fallback;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${name} must be a positive integer`);
  return value;
}

function loadAccountBinding(path: string): XAccountBinding {
  const parsed = JSON.parse(readFileSync(path, "utf8")) as XAccountBinding;
  // The listing builder is the shared runtime validator for this public shape.
  sponsoredPostLiveListing({ accountBinding: parsed });
  return parsed;
}

async function main(): Promise<void> {
  const keyPath = required("SELLER_KEY_PATH");
  const statePath = required("SELLER_STATE_PATH");
  const publicationState = required("SPONSORED_POST_STATE_DIR");
  const accountBinding = loadAccountBinding(required("SPONSORED_POST_ACCOUNT_BINDING_FILE"));
  const mnemonic = readPrivate(keyPath);
  const x = new XApiSponsoredPostPort({
    userAccessToken: readPrivate(required("X_USER_ACCESS_TOKEN_FILE")),
    handle: accountBinding.handle,
    timeoutMs: positiveInteger("X_API_TIMEOUT_MS", 12_000),
  });
  await x.verifyAccount(accountBinding.userId);
  const moderation = new HttpSponsoredPostModerationPort({
    endpoint: required("SPONSORED_POST_MODERATION_URL"),
    bearerToken: readPrivate(required("SPONSORED_POST_MODERATION_TOKEN_FILE")),
    timeoutMs: positiveInteger("SPONSORED_POST_MODERATION_TIMEOUT_MS", 5_000),
  });

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
    createHash("sha512").update("dacs-sponsored-post-l2ps-v1\x00").update(mnemonic).digest(),
    createHash("sha512").update("dacs-sponsored-post-l2ps-v1\x01").update(mnemonic).digest(),
  ]);
  const identity = await initIdentity(seed);
  const peer = new MessagingPeer({ serverUrl, clientId, publicKey: identity.mlkemPublicKey });
  await peer.connect();
  await peer.discoverPeers?.();

  const substrate = new LiveSubstrate(adapter);
  const party = { primaryClaim: did, sign: (bytes: Uint8Array) => adapter.sign(bytes) };
  const work = makeSponsoredPostWork(
    x,
    moderation,
    new FileSponsoredPostIdempotencyStore(publicationState),
  );
  const seller = new SellerAdapter({ did, sign: party.sign }, substrate, SPONSORED_POST_SERVICE_ID, work);
  const nativeSpec = sponsoredPostLiveListing({
    accountBinding,
    listingVersion: positiveInteger("DACS_LISTING_VERSION", 1),
    notBefore: positiveInteger("DACS_LISTING_NOT_BEFORE_MS", Date.now()),
    priceDem: process.env.DACS_FIXED_PRICE_DEM ?? "1",
    publicEndpoint: process.env.DACS_PUBLIC_ENDPOINT,
  });
  const published = await seller.publishStandardListing(nativeSpec);

  const x402Enabled = process.env.DACS_X402_ENABLED === "1";
  const x402PayTo = process.env.DACS_X402_PAYTO?.trim() ?? "";
  const x402ResourceBase = process.env.DACS_X402_RESOURCE_BASE?.trim() ?? "";
  const x402PriceUsdc = process.env.DACS_X402_PRICE_USDC?.trim() ?? "";
  const x402IdentityProof = process.env.DACS_X402_IDENTITY_PROOF?.trim() ?? "";
  if (x402Enabled && (!x402PayTo || !x402ResourceBase || !x402PriceUsdc || !x402IdentityProof)) {
    throw new Error("x402 requires payTo, resourceBase, price, and DACS identity proof");
  }
  if (x402Enabled) {
    const trustMode = process.env.DACS_X402_TRUST_MODE ?? "dacs-pa2-steward";
    if (trustMode !== "dacs-pa2-steward" && trustMode !== "operator-provisional") throw new Error("invalid x402 trust mode");
    const rail = loadX402RailDefinition(
      required("DACS_X402_RAIL_REGISTRY_FILE"),
      required("DACS_X402_STEWARD_PUBLIC_KEY"),
      trustMode,
    );
    if (rail.network.resourceBaseUrl.replace(/\/+$/, "") !== x402ResourceBase.replace(/\/+$/, "")) {
      throw new Error("seller x402 resource base differs from its authoritative RailDefinition");
    }
  }
  const paymentBinding = x402Enabled
    ? x402IdentityBinding({ dacsIdentity: did, account: x402PayTo, signature: x402IdentityProof })
    : undefined;
  const paymentMetadata = paymentBinding ? x402IdentityMetadata(paymentBinding) : undefined;
  const x402Spec = paymentMetadata
    ? sponsoredPostLiveX402Listing({
        accountBinding,
        payTo: x402PayTo,
        resourceBase: x402ResourceBase,
        identityMetadata: paymentMetadata,
        listingVersion: positiveInteger("DACS_X402_LISTING_VERSION", 2),
        notBefore: positiveInteger("DACS_LISTING_NOT_BEFORE_MS", Date.now()),
        priceUsdc: x402PriceUsdc,
      })
    : undefined;
  const x402Published = x402Spec ? await seller.publishStandardListing(x402Spec) : undefined;
  const listings = new Map([
    [published.ref, published],
    ...(x402Published ? [[x402Published.ref, x402Published] as const] : []),
  ]);

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
    new SellerStateStore(statePath),
    positiveInteger("DACS_MAX_SESSIONS", 2),
    console.error,
    undefined,
    (request) => serialize(async () => {
      if (!request.params) throw new Error("sponsored-post delivery omitted its bound request");
      const prepared = await seller.prepareDelivery(request.agreement.jobId, request.params, request.params);
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
    primaryClaimSigner(did, party.sign),
    {
      party,
      sub: substrate,
      identityMetadata: {
        linkedAccounts: [accountBinding],
        ...(paymentMetadata ?? {}),
      },
      async getListing(listingAnchorRef) {
        const selected = listingAnchorRef ? listings.get(listingAnchorRef) : published;
        if (!selected) throw new Error("buyer selected an unknown sponsored-post listing");
        return { listing: selected.listing, listingAnchorRef: selected.ref };
      },
    },
    (request) => { parseSponsoredPostRequest(request); },
    x402Enabled ? new X402PaymentVerifier() : undefined,
  );
  daemon.listen();
  console.error(`[sponsored-post] ready client=${clientId} did=${did} listing=${published.ref} x=@${accountBinding.handle}`);
  if (x402Published) console.error(`[sponsored-post] x402 listing=${x402Published.ref} payTo=${x402PayTo}`);

  let stopping = false;
  const stop = (signal: string): void => {
    if (stopping) return;
    stopping = true;
    console.error(`[sponsored-post] ${signal} received; disconnecting`);
    peer.disconnect?.();
    setTimeout(() => process.exit(0), 100).unref();
  };
  process.on("SIGTERM", () => stop("SIGTERM"));
  process.on("SIGINT", () => stop("SIGINT"));
}

main().catch((error) => {
  console.error("[sponsored-post] fatal:", error);
  process.exitCode = 1;
});
