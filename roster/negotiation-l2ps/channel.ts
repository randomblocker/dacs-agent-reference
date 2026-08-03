/**
 * The negotiation channel — the substrate the two peers exchange envelopes over.
 *
 * `Channel` is a tiny async mailbox: `send` an envelope, `receive` the next one
 * (with a timeout — a missed turn is a channel failure per DACS-3 RFQ-4). Two
 * implementations:
 *
 *   - `InProcessChannelPair` — two cross-wired mailboxes in one process, for the
 *     offline parity test (prove the distributed loop matches the in-process
 *     engine with zero network).
 *   - `L2psChannel` — over demosdk's `MessagingPeer`, the live SR-4 transport.
 *     Today it targets the legacy signaling server (E2E-encrypted relay,
 *     verified live on demosnode.discus.sh:3006's sibling 3005); swapping to the
 *     rollup-backed `L2PSMessagingPeer` (port 3006) is a constructor change once
 *     a node exposes it.
 */
import type { ChannelEnvelope } from "./wire.js";

export interface Channel {
  send(env: ChannelEnvelope): Promise<void>;
  /** Resolve the next inbound envelope, or reject after `timeoutMs`. */
  receive(timeoutMs?: number): Promise<ChannelEnvelope>;
  close(): Promise<void>;
}

const DEFAULT_RECV_TIMEOUT = 30_000;

/**
 * A queue-backed mailbox: inbound envelopes are `deliver`ed by the transport and
 * drained by `receive`. Shared by both channel implementations.
 */
export class MailboxChannel implements Channel {
  private readonly queue: ChannelEnvelope[] = [];
  private waiter: { resolve: (e: ChannelEnvelope) => void; reject: (err: Error) => void; timer: ReturnType<typeof setTimeout> } | null = null;
  protected closed = false;

  /** Called by the transport when an envelope arrives for this side. */
  deliver(env: ChannelEnvelope): void {
    if (this.waiter) {
      clearTimeout(this.waiter.timer);
      const w = this.waiter;
      this.waiter = null;
      w.resolve(env);
    } else {
      this.queue.push(env);
    }
  }

  async send(_env: ChannelEnvelope): Promise<void> {
    throw new Error("MailboxChannel.send is abstract — use a concrete channel");
  }

  receive(timeoutMs = DEFAULT_RECV_TIMEOUT): Promise<ChannelEnvelope> {
    const queued = this.queue.shift();
    if (queued) return Promise.resolve(queued);
    if (this.closed) return Promise.reject(new Error("channel closed"));
    return new Promise<ChannelEnvelope>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.waiter = null;
        reject(new Error(`receive timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      this.waiter = { resolve, reject, timer };
    });
  }

  async close(): Promise<void> {
    this.closed = true;
    if (this.waiter) {
      clearTimeout(this.waiter.timer);
      this.waiter.reject(new Error("channel closed"));
      this.waiter = null;
    }
  }
}

/**
 * Two cross-wired mailboxes: what A sends, B receives, and vice versa. For the
 * offline parity test — no network, deterministic.
 */
export function InProcessChannelPair(): [Channel, Channel] {
  const a = new (class extends MailboxChannel {
    override async send(env: ChannelEnvelope): Promise<void> {
      b.deliver(env);
    }
  })();
  const b = new (class extends MailboxChannel {
    override async send(env: ChannelEnvelope): Promise<void> {
      a.deliver(env);
    }
  })();
  return [a, b];
}

// ---------------------------------------------------------------------------
// Live L2PS transport (demosdk MessagingPeer)
// ---------------------------------------------------------------------------

/** Minimal surface of demosdk's MessagingPeer the channel depends on. */
export interface MessagingPeerLike {
  connect(): Promise<unknown>;
  sendMessage(targetId: string, message: string): Promise<void>;
  onMessage(handler: (message: unknown, fromId: string) => void): void;
  disconnect?: () => void;
}

/**
 * A `Channel` over a demosdk MessagingPeer. Envelopes are JSON-encoded and sent
 * to the fixed peer clientId; inbound messages carrying a matching channelId are
 * decoded and delivered. The peer's own E2E encryption protects the payload on
 * the wire (CH-2 confidentiality); the envelope signature protects authenticity.
 */
export class L2psChannel extends MailboxChannel {
  constructor(
    private readonly peer: MessagingPeerLike,
    private readonly peerClientId: string,
    private readonly channelId: string,
  ) {
    super();
    this.peer.onMessage((message) => this.onInbound(message));
  }

  private onInbound(message: unknown): void {
    let env: ChannelEnvelope | undefined;
    try {
      const raw = typeof message === "string" ? message : (message as { data?: string; content?: string }).data ?? (message as { content?: string }).content;
      if (typeof raw !== "string") return;
      const parsed = JSON.parse(raw) as ChannelEnvelope;
      if (parsed && parsed.channelId === this.channelId && parsed.body && typeof parsed.sequence === "number") env = parsed;
    } catch {
      return; // not our envelope — ignore
    }
    if (env) this.deliver(env);
  }

  override async send(env: ChannelEnvelope): Promise<void> {
    if (this.closed) throw new Error("channel closed");
    await this.peer.sendMessage(this.peerClientId, JSON.stringify(env));
  }

  override async close(): Promise<void> {
    await super.close();
    this.peer.disconnect?.();
  }
}
