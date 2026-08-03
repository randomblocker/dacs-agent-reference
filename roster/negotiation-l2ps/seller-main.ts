/** Production entrypoint for the persistent DACS audit-negotiation seller. */
import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { DemosAdapter } from "@kynesyslabs/dacs/substrate";
import { LiveSubstrate } from "../../src/live/substrate.js";
import { PaymentGate, type TxReader } from "../gateway/settlement.js";
import { ensureAuditorListing } from "./auditor-listing.js";
import { anthropicFromEnv } from "../llm/anthropic.js";
import { initIdentity, MessagingPeer, primaryClaimSigner } from "./demosdk.js";
import { SellerDaemon, SellerStateStore } from "./seller-daemon.js";
import { SellerAdapter } from "../dacs/seller-adapter.js";
import {
  AUDIT_NEGOTIATOR_SERVICE_ID,
  auditNegotiatorX402StandardListingSpec,
} from "../dacs/wire/audit-negotiator.js";
import { makeSecAuditWork } from "../dacs/wire/sec-audit.js";
import { DacsSellerAttestor } from "../sec-audit/attest-files.js";
import { auditTermsFromStandardAgreement, isStandardAgreement } from "./bind.js";
import { X402PaymentVerifier } from "../gateway/x402-verifier.js";
import { loadX402RailDefinition, x402IdentityBinding, x402IdentityMetadata } from "../dacs/x402-production.js";

const serverUrl = process.env.SERVER_URL ?? "ws://demosnode.discus.sh:3005";
const clientId = process.env.SELLER_CLIENT_ID ?? "dacs-auditor";
const keyPath = process.env.SELLER_KEY_PATH ?? "/home/auditor/.dacs/seller-key";
const statePath = process.env.SELLER_STATE_PATH ?? "/home/auditor/.dacs/seller-state.json";
const rpc = process.env.DEMOS_RPC ?? "https://demosnode.discus.sh/";

function loadSecret(path: string): string {
  const mode = statSync(path).mode & 0o777;
  if ((mode & 0o077) !== 0) throw new Error(`${path} must not be accessible by group/other (expected mode 0600)`);
  const secret = readFileSync(path, "utf8").trim();
  if (!secret) throw new Error(`${path} is empty`);
  return secret;
}

async function main(): Promise<void> {
  const mnemonic = loadSecret(keyPath);
  // Wallet derivation is local and must not make service availability depend on
  // the RPC's health. Chain connectivity is established lazily only when a
  // buyer presents a settlement transaction for verification.
  const adapter = new DemosAdapter({ rpc, secret: mnemonic });
  const raw = adapter.raw as unknown as TxReader & {
    connect(url: string): Promise<unknown>;
    connectWallet(secret: string): Promise<unknown>;
    getAddress(): string;
  };
  await raw.connectWallet(mnemonic);
  const payTo = raw.getAddress();
  const did = `did:demos:agent:${payTo.replace(/^0x/, "")}`;
  // ucrypto recommends a 128-byte master seed. Two independently domain-
  // separated SHA-512 blocks preserve deterministic identity without reusing
  // the wallet mnemonic directly as transport key material.
  const seed = Buffer.concat([
    createHash("sha512").update("dacs-auditor-l2ps-v1\x00").update(mnemonic).digest(),
    createHash("sha512").update("dacs-auditor-l2ps-v1\x01").update(mnemonic).digest(),
  ]);
  const identity = await initIdentity(seed);
  let peer: InstanceType<typeof MessagingPeer>;
  let retryMs = 5_000;
  for (;;) {
    peer = new MessagingPeer({ serverUrl, clientId, publicKey: identity.mlkemPublicKey });
    try {
      await peer.connect();
      await peer.discoverPeers?.();
      break;
    } catch (error) {
      peer.disconnect?.();
      console.error(`[auditor] messaging unavailable: ${(error as Error).message}; retrying in ${retryMs / 1000}s`);
      await new Promise((resolve) => setTimeout(resolve, retryMs));
      retryMs = Math.min(retryMs * 2, 60_000);
    }
  }

  let rpcConnected = false;
  let rpcConnecting: Promise<void> | undefined;
  const ensureRpcConnected = async (): Promise<void> => {
    if (rpcConnected) return;
    if (!rpcConnecting) {
      // Use the adapter's public connect path, not raw.connect(): DemosAdapter
      // maintains its own connected flag which guards signing and anchoring.
      rpcConnecting = adapter.connect()
        .then(() => { rpcConnected = true; })
        .finally(() => { rpcConnecting = undefined; });
    }
    await rpcConnecting;
  };
  const reader: TxReader = {
    async getTxByHash(hash) {
      await ensureRpcConnected();
      try {
        return await raw.getTxByHash(hash);
      } catch (error) {
        rpcConnected = false;
        throw error;
      }
    },
  };
  const substrate = new LiveSubstrate(adapter);
  const sellerParty = { primaryClaim: did, sign: (bytes: Uint8Array) => adapter.sign(bytes) };
  const deliveryAgent = new SellerAdapter(
    { did, sign: sellerParty.sign },
    substrate,
    AUDIT_NEGOTIATOR_SERVICE_ID,
    makeSecAuditWork(new DacsSellerAttestor(sellerParty)),
  );
  const researcherGithub = process.env.DACS_AUDITOR_RESEARCHER_GITHUB?.trim() ?? "";
  if (!researcherGithub) {
    throw new Error("DACS_AUDITOR_RESEARCHER_GITHUB is required for the Auditor's DACS-2 researcher Vet profile");
  }
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
  const x402Metadata = x402Enabled
    ? x402IdentityMetadata(x402IdentityBinding({ dacsIdentity: did, account: x402PayTo, signature: x402IdentityProof }))
    : undefined;
  // One Demos wallet cannot safely broadcast concurrent anchor writes with the
  // same nonce. Keep paid deliveries FIFO even though negotiation sessions may
  // run concurrently.
  let deliveryTail: Promise<unknown> = Promise.resolve();
  const deliver = <T>(work: () => Promise<T>): Promise<T> => {
    const started = deliveryTail.then(work, work);
    deliveryTail = started.then(() => undefined, () => undefined);
    return started;
  };
  const llm = anthropicFromEnv();
  let listingPromise: ReturnType<typeof ensureAuditorListing> | undefined;
  let x402ListingPromise: ReturnType<typeof deliveryAgent.publishStandardListing> | undefined;
  const getX402Listing = async () => {
    if (!x402Enabled) return undefined;
    if (!x402ListingPromise) {
      x402ListingPromise = ensureRpcConnected()
        .then(() => deliveryAgent.publishStandardListing(auditNegotiatorX402StandardListingSpec({
          payTo: x402PayTo,
          resourceBase: x402ResourceBase,
          priceUsdc: x402PriceUsdc,
          identityMetadata: x402Metadata!,
          researcherGithub,
          operatorClaim: did,
          listingVersion: Number(process.env.DACS_X402_LISTING_VERSION ?? "3"),
        })))
        .catch((error) => { x402ListingPromise = undefined; throw error; });
    }
    return x402ListingPromise;
  };
  const getListing = async () => {
    if (!listingPromise) {
      listingPromise = ensureRpcConnected()
        .then(() => ensureAuditorListing({ did, sign: sellerParty.sign }, substrate, researcherGithub))
        .catch((error) => { listingPromise = undefined; throw error; });
    }
    const result = await listingPromise;
    const listing = await substrate.read(result.ref);
    if (!listing) throw new Error("Auditor listing is not read-visible after publication");
    return { ...result, listing: listing as unknown as import("../dacs/standard-profile.js").Listing, listingAnchorRef: result.ref };
  };
  const getSelectedListing = async (listingAnchorRef?: string) => {
    const [native, x402] = await Promise.all([getListing(), getX402Listing()]);
    if (!listingAnchorRef || listingAnchorRef === native.listingAnchorRef) return native;
    if (x402 && listingAnchorRef === x402.ref) return { ...x402, listingAnchorRef: x402.ref };
    throw new Error("buyer selected an unknown Auditor listing");
  };
  const daemon = new SellerDaemon(
    peer,
    identity,
    payTo,
    new PaymentGate(reader, payTo),
    new SellerStateStore(statePath),
    8,
    console.error,
    llm ? (prompt, timeoutMs) => llm.complete(prompt, { maxTokens: 500, timeoutMs }) : undefined,
    (request) => deliver(async () => {
      if (!request.files?.length) throw new Error("paid audit carries no posted files to scan");
      await ensureRpcConnected();
      const standard = isStandardAgreement(request.agreement);
      const result = standard && substrate.anchorBatchWithReceipts
        ? await deliveryAgent.prepareDelivery(request.agreement.jobId, {
          files: request.files,
          negotiatedTerms: auditTermsFromStandardAgreement(request.agreement),
          repo: request.repo,
        })
        : await deliveryAgent.deliver(request.agreement.jobId, {
        files: request.files,
        negotiatedTerms: standard
          ? auditTermsFromStandardAgreement(request.agreement)
          : request.agreement.terms,
        repo: request.repo,
      });
      return {
        deliveryRef: result.attestationRef,
        attestation: (result.anchoredAttestation ?? result.attestation) as unknown as Record<string, unknown>,
        result: result.result,
        anchorReceipt: result.anchorReceipt,
        ...(standard && "anchorName" in result ? {
          preparedAnchor: { name: result.anchorName, value: result.anchoredAttestation },
        } : {}),
        deliverableContentHash: typeof result.attestation.meta?.reportHash === "string"
          ? result.attestation.meta.reportHash
          : result.attestation.resultHash,
      };
    }),
    (jobId, buyerDid) => deliver(async () => {
      await ensureRpcConnected();
      return deliveryAgent.fulfil(jobId, buyerDid);
    }),
    ["quick"],
    primaryClaimSigner(did, sellerParty.sign),
    { party: sellerParty, sub: substrate, getListing: getSelectedListing, ...(x402Metadata ? { identityMetadata: x402Metadata } : {}) },
    undefined,
    x402Enabled ? new X402PaymentVerifier() : undefined,
  );
  daemon.listen();
  console.error(`[auditor] ready client=${clientId} signer=${did} payTo=${payTo} server=${serverUrl}`);
  console.error(`[auditor] Anthropic negotiation ${llm ? `ACTIVE model=${llm.model}` : "disabled; deterministic policy active"}`);

  // L2PS registration only makes the transport reachable. The indexer discovers
  // agents from signed DACS-1 listings, so independently ensure this daemon's
  // own wallet has published its deterministic listing slot. Keep retrying on
  // transient RPC/node failures without taking negotiation transport offline.
  void (async () => {
    let retryMs = 5_000;
    for (;;) {
      try {
        await ensureRpcConnected();
        const listing = await getListing();
        console.error(`[auditor] listing ${listing.published ? "published" : "confirmed"} service=audit-negotiator did=${did} ref=${listing.ref}`);
        const x402Listing = await getX402Listing();
        if (x402Listing) console.error(`[auditor] x402 listing ${x402Listing.published ? "published" : "confirmed"} ref=${x402Listing.ref} payTo=${x402PayTo}`);
        break;
      } catch (error) {
        rpcConnected = false;
        console.error(`[auditor] listing unavailable: ${(error as Error).message}; retrying in ${retryMs / 1000}s`);
        await new Promise((resolve) => setTimeout(resolve, retryMs));
        retryMs = Math.min(retryMs * 2, 60_000);
      }
    }
  })();

  let stopping = false;
  const stop = (signal: string): void => {
    if (stopping) return;
    stopping = true;
    console.error(`[auditor] ${signal} received; disconnecting`);
    peer.disconnect?.();
    setTimeout(() => process.exit(0), 100).unref();
  };
  process.on("SIGTERM", () => stop("SIGTERM"));
  process.on("SIGINT", () => stop("SIGINT"));
}

main().catch((error) => {
  console.error(`[auditor] fatal: ${(error as Error).message}`);
  process.exit(1);
});
