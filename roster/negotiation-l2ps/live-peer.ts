/**
 * LivePeer — a negotiation peer over the live L2PS messaging server.
 *
 * Wraps a demosdk `MessagingPeer` with the two things the distributed session
 * needs beyond raw relay: (1) a HANDSHAKE so each side learns the other's
 * ed25519 signer id before any signed move (the lightweight stand-in for the
 * §8.3.2 CCI membership binding — Stage B replaces it with an anchored binding),
 * and (2) message ROUTING so hello frames and channel envelopes are dispatched
 * from the peer's single `onMessage` to the handshake waiter or the channel
 * mailbox respectively.
 */
import { MailboxChannel, type Channel } from "./channel.js";
import { MessagingPeer, type MessagingPeerInstance } from "./demosdk.js";
import type { ChannelEnvelope } from "./wire.js";

/**
 * Normalise a demosdk `onMessage` payload to a string. The peer decrypts inbound
 * messages and hands the handler the raw bytes as a Buffer (the JSON we sent);
 * server frames (register acks, etc.) arrive as objects, which we ignore.
 */
export function decodePayload(message: unknown): string | undefined {
  if (typeof message === "string") return message;
  if (message instanceof Uint8Array) return Buffer.from(message).toString("utf8");
  if (Buffer.isBuffer(message)) return message.toString("utf8");
  if (message && typeof message === "object") {
    const o = message as { data?: unknown; content?: unknown };
    if (typeof o.data === "string") return o.data;
    if (typeof o.content === "string") return o.content;
  }
  return undefined;
}

class LiveChannel extends MailboxChannel {
  constructor(
    private readonly peer: MessagingPeerInstance,
    private readonly peerClientId: string,
  ) {
    super();
  }
  override async send(env: ChannelEnvelope): Promise<void> {
    if (this.closed) throw new Error("channel closed");
    await this.peer.sendMessage(this.peerClientId, JSON.stringify(env));
  }
}

export class LivePeer {
  private readonly peer: MessagingPeerInstance;
  private helloWaiter: ((signerId: string) => void) | null = null;
  private active: LiveChannel | null = null;
  private channelId = "";

  constructor(serverUrl: string, myClientId: string, mlkemPub: Uint8Array) {
    this.peer = new MessagingPeer({ serverUrl, clientId: myClientId, publicKey: mlkemPub });
    this.peer.onMessage((message) => this.route(message));
  }

  private route(message: unknown): void {
    const raw = decodePayload(message);
    if (typeof raw !== "string") return;
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return;
    }
    const obj = parsed as { hello?: string; channelId?: string; body?: unknown; sequence?: number };
    if (typeof obj.hello === "string") {
      this.helloWaiter?.(obj.hello);
      return;
    }
    if (obj.channelId === this.channelId && obj.body && typeof obj.sequence === "number") {
      this.active?.deliver(parsed as ChannelEnvelope);
    }
  }

  async connect(): Promise<void> {
    await this.peer.connect();
    await this.peer.discoverPeers?.();
  }

  /** Exchange signer ids: resend hello until the peer's hello arrives (relay has no queue). */
  handshake(peerClientId: string, mySignerId: string, timeoutMs = 25_000): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      let done = false;
      this.helloWaiter = (sid) => {
        if (done) return;
        done = true;
        clearInterval(iv);
        clearTimeout(to);
        resolve(sid);
      };
      const send = () => void this.peer.sendMessage(peerClientId, JSON.stringify({ hello: mySignerId })).catch(() => {});
      send();
      const iv = setInterval(send, 1500);
      const to = setTimeout(() => {
        if (done) return;
        done = true;
        clearInterval(iv);
        reject(new Error(`handshake timed out after ${timeoutMs}ms`));
      }, timeoutMs);
    });
  }

  channel(peerClientId: string, channelId: string): Channel {
    this.channelId = channelId;
    this.active = new LiveChannel(this.peer, peerClientId);
    return this.active;
  }

  disconnect(): void {
    this.peer.disconnect?.();
  }
}
