/**
 * demosdk shim — centralises the three node-client gotchas for talking to the
 * live L2PS messaging surface (documented in the transport-probe memo):
 *
 *   1. `@kynesyslabs/demosdk` has no `./instant_messaging` export subpath, so we
 *      import the built file directly from the vendored SDK under `sdk/`.
 *   2. `MessagingPeer` is browser-targeted — Node 20 needs a `globalThis.WebSocket`.
 *   3. `MessagingPeerConfig.publicKey` must be the ML-KEM-AES identity key
 *      (1184 bytes), NOT ml-dsa — the registration proof signs it with ml-dsa but
 *      peers fetch it for ML-KEM encapsulation.
 *   4. demosdk 4.0.16 sends request/response frames before installing its
 *      waiter, and removes that waiter on the first unrelated frame. A fast
 *      public-key response can therefore be logged and still time out. The
 *      wrapper below installs durable, filtered waiters before sending and
 *      serialises encrypted sends until the upstream transport is fixed.
 *
 * It also exposes a `ucryptoSigner`: the ed25519 Signer the negotiation envelopes
 * are signed/verified with. Verification is over the public key embedded in the
 * signature (not the local identity), so a peer can verify its counterparty.
 */
// @ts-expect-error — vendored `ws` ships no type declarations at this path
import WS from "../../sdk/node_modules/ws/index.js";
// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).WebSocket = (globalThis as any).WebSocket ?? WS;

// `MessagingPeer` is a named export on the built module.
import { MessagingPeer as MessagingPeerImpl } from "../../sdk/node_modules/@kynesyslabs/demosdk/build/instant_messaging/index.js";
import { ucrypto } from "../../sdk/node_modules/@kynesyslabs/demosdk/build/encryption/index.js";
import { randomBytes } from "node:crypto";
import type { Signer, WireSig } from "./wire.js";
import type { Signer as DacsSigner } from "@kynesyslabs/dacs";
import { resolveFromDid, verify } from "../../src/identity.js";

export interface MessagingPeerInstance {
  connect(): Promise<unknown>;
  sendMessage(targetId: string, message: string): Promise<void>;
  onMessage(handler: (message: unknown, fromId: string) => void): void;
  discoverPeers?: () => Promise<string[]>;
  disconnect?: () => void;
}
export type MessagingPeerCtor = new (config: { serverUrl: string; clientId: string; publicKey: Uint8Array }) => MessagingPeerInstance;

interface ServerFrame {
  type?: unknown;
  payload?: unknown;
}

interface ResponseOptions {
  timeout?: number;
  errorHandler?: (error: unknown) => void;
  retryCount?: number;
  filterFn?: (message: ServerFrame) => boolean;
}

type MessageHandler = (message: unknown, fromId: string) => void;
type MessagingPeerInternals = MessagingPeerInstance & {
  awaitResponse(messageType: string, filterFn?: ResponseOptions["filterFn"], timeout?: number): Promise<unknown>;
  sendToServer(message: unknown): void;
  sendToServerAndWait(message: unknown, expectedResponseType: string, options?: ResponseOptions): Promise<unknown>;
  removeMessageHandler(handler: MessageHandler): void;
};

const MessagingPeerBase = MessagingPeerImpl as unknown as new (
  config: { serverUrl: string; clientId: string; publicKey: Uint8Array },
) => MessagingPeerInternals;

class ReliableMessagingPeer extends MessagingPeerBase {
  private outboundTail: Promise<void> = Promise.resolve();

  override awaitResponse(
    messageType: string,
    filterFn?: ResponseOptions["filterFn"],
    timeout = 10_000,
  ): Promise<unknown> {
    return new Promise((resolve, reject) => {
      let settled = false;
      const cleanup = (): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timeoutId);
        this.removeMessageHandler(handler);
      };
      const handler: MessageHandler = (message) => {
        const frame: ServerFrame = message && typeof message === "object" && "type" in message
          ? message as ServerFrame
          : { type: "message", payload: message };
        if (frame.type === messageType && (!filterFn || filterFn(frame))) {
          cleanup();
          resolve(frame.payload);
        } else if (frame.type === "error") {
          cleanup();
          const details = frame.payload && typeof frame.payload === "object" && "details" in frame.payload
            ? String((frame.payload as { details: unknown }).details)
            : "messaging server returned an error";
          reject(new Error(details));
        }
      };
      const timeoutId = setTimeout(() => {
        cleanup();
        reject(new Error(`Timeout waiting for response of type: ${messageType}`));
      }, timeout);
      this.onMessage(handler);
    });
  }

  override async sendToServerAndWait(
    message: unknown,
    expectedResponseType: string,
    options: ResponseOptions = {},
  ): Promise<unknown> {
    const { timeout = 10_000, errorHandler, retryCount = 0, filterFn } = options;
    try {
      // Install the response handler before a local or low-latency server can
      // answer the request. This ordering is the core demosdk 4.0.16 repair.
      const response = this.awaitResponse(expectedResponseType, filterFn, timeout);
      this.sendToServer(message);
      return await response;
    } catch (error) {
      errorHandler?.(error);
      if (retryCount > 0) {
        return await this.sendToServerAndWait(message, expectedResponseType, {
          ...options,
          retryCount: retryCount - 1,
        });
      }
      throw error;
    }
  }

  override async sendMessage(targetId: string, message: string): Promise<void> {
    // demosdk's response correlation is type/filter based rather than request-id
    // based. Keep public-key requests sequential so simultaneous encrypted sends
    // cannot consume each other's responses.
    const pending = this.outboundTail.then(
      () => super.sendMessage(targetId, message),
      () => super.sendMessage(targetId, message),
    );
    this.outboundTail = pending.catch(() => undefined);
    return await pending;
  }
}

export const MessagingPeer = ReliableMessagingPeer as unknown as MessagingPeerCtor;

const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
const unhex = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "hex"));

export interface PeerIdentity {
  /** ML-KEM-AES public key for MessagingPeer registration. */
  mlkemPublicKey: Uint8Array;
  /** ed25519 public key hex — the stable signer id used as the envelope sender. */
  signerId: string;
  signer: Signer;
}

/**
 * Bind DACS channel signatures to the wallet's primary CCI claim. Messaging
 * keeps its independent ML-KEM key, but CH-3 signatures must resolve from the
 * `sender` ClaimReference rather than from an unrelated transport identity.
 */
export function primaryClaimSigner(primaryClaim: string, sign: DacsSigner): Signer {
  const publicKey = resolveFromDid(primaryClaim);
  if (!publicKey) throw new Error(`primary claim ${primaryClaim} has no resolvable ed25519 key`);
  const publicKeyHex = hex(publicKey);
  return {
    id: primaryClaim,
    async sign(canonical: Uint8Array): Promise<WireSig> {
      return {
        signature: hex(await sign(canonical)),
        publicKey: publicKeyHex,
        scheme: "ed25519",
      };
    },
    async verify(canonical: Uint8Array, sig: WireSig, expectedSenderId: string): Promise<boolean> {
      if (sig.scheme !== "ed25519") return false;
      const expected = resolveFromDid(expectedSenderId);
      if (!expected || sig.publicKey.toLowerCase() !== hex(expected).toLowerCase()) return false;
      try {
        return verify(canonical, unhex(sig.signature), expected);
      } catch {
        return false;
      }
    },
  };
}

/**
 * Generate a fresh crypto identity for this process and return the MessagingPeer
 * registration key plus an ed25519 envelope signer. Each process gets its own
 * random seed (the singleton `ucrypto` holds one identity per process), which is
 * exactly why the two negotiating peers must run as separate processes.
 */
export async function initIdentity(seed?: Uint8Array): Promise<PeerIdentity> {
  const s = seed ?? new Uint8Array(randomBytes(128));
  await ucrypto.generateAllIdentities(s);
  const mlkem = await ucrypto.getIdentity("ml-kem-aes");
  const ed = await ucrypto.getIdentity("ed25519");
  const signerId = hex(ed.publicKey as Uint8Array);

  const signer: Signer = {
    id: signerId,
    async sign(canonical: Uint8Array): Promise<WireSig> {
      const signed = await ucrypto.sign("ed25519", canonical);
      return { signature: hex(signed.signature as Uint8Array), publicKey: hex(signed.publicKey as Uint8Array), scheme: "ed25519" };
    },
    async verify(canonical: Uint8Array, sig: WireSig, expectedSenderId: string): Promise<boolean> {
      if (sig.publicKey !== expectedSenderId) return false;
      try {
        const ok = await ucrypto.verify({
          algorithm: "ed25519",
          signature: Buffer.from(unhex(sig.signature)),
          publicKey: Buffer.from(unhex(sig.publicKey)),
          message: Buffer.from(canonical),
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } as any);
        return ok === true;
      } catch {
        return false;
      }
    },
  };

  return { mlkemPublicKey: mlkem.publicKey as Uint8Array, signerId, signer };
}
