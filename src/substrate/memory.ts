/**
 * A shared in-memory substrate for the ecosystem.
 *
 * It implements the anchor/read seam the DACS cores depend on (the same shape
 * `DemosAdapter` exposes over real Demos storage programs), plus a mock DAHR
 * proxy for the Vet stage and delivery attestation. All agents share ONE
 * instance, so anchoring by the buyer is immediately readable by the seller
 * and the verifier — exactly what a real shared substrate (the chain) gives
 * you, minus the network.
 *
 * The DAHR proxy routes by URL prefix to *mounted* handlers (here: the mock
 * GitHub). That mirrors what real DAHR is: an attested HTTP fetch of any
 * upstream — the responseHash is the attestation commitment over the body.
 *
 * Swapping this for the real thing is a one-liner: hand the agents a
 * `DemosAdapter` (from `@kynesyslabs/dacs/substrate`) instead of this — the
 * cores don't care which anchor implementation they're given.
 */
import { canonicalize, sha256Hex } from "@kynesyslabs/dacs";
import type { AnchorAcceptance, AnchorReceipt } from "../ports.js";

export interface ProxyHandler {
  (url: string): { status: number; body: unknown };
}

export class MemorySubstrate {
  /** address -> stored (signed) artifact. Public so the verifier/tests can peek. */
  readonly store = new Map<string, Record<string, unknown>>();

  /** URL prefix -> handler, for the mock DAHR proxy. */
  private readonly mounts = new Map<string, ProxyHandler>();
  private readonly receipts = new Map<string, AnchorReceipt>();

  private address(name: string): string {
    return `stor:${name}`;
  }

  /** Anchor a value under a deterministic name; returns its storage address. */
  async anchor(name: string, value: object): Promise<string> {
    const address = this.address(name);
    this.store.set(address, value as Record<string, unknown>);
    return address;
  }

  /** In-memory SR-2 receipt analogue used by Standard lifecycle tests. */
  async anchorWithReceipt(name: string, value: object): Promise<AnchorReceipt> {
    const address = await this.anchor(name, value);
    const anchoredAt = Date.now();
    const broadcastAt = anchoredAt;
    const confirmedAt = anchoredAt;
    const txRef = `memory:${name}:${anchoredAt}`;
    const receipt = { address, txRef, anchoredAt, broadcastAt, confirmedAt, inclusionLatencyMs: 0, contentHash: sha256Hex(canonicalize(value as Record<string, unknown>)) };
    this.receipts.set(txRef, receipt);
    return receipt;
  }

  async anchorAccepted(name: string, value: object): Promise<AnchorAcceptance> {
    const receipt = await this.anchorWithReceipt(name, value);
    return {
      address: receipt.address,
      txRef: receipt.txRef,
      contentHash: receipt.contentHash!,
      status: "accepted",
      acceptedAt: receipt.broadcastAt!,
    };
  }

  async confirmAcceptedAnchor(acceptance: AnchorAcceptance): Promise<AnchorReceipt> {
    return this.resolveAnchorReceipt(acceptance.txRef);
  }

  noteExternalNonce(_nonce: number): void {
    // The memory substrate has no wallet nonce, but implements the live port so
    // protocol tests exercise the same call path.
  }

  async verifyAnchorAcceptance(acceptance: AnchorAcceptance): Promise<void> {
    if (!this.receipts.has(acceptance.txRef)) throw new Error("unknown in-memory anchor acceptance");
  }

  async anchorBatchWithReceipts(entries: Array<{ name: string; value: object }>): Promise<AnchorReceipt[]> {
    return Promise.all(entries.map(({ name, value }) => this.anchorWithReceipt(name, value)));
  }

  async resolveAnchorReceipt(txRef: string): Promise<AnchorReceipt> {
    const receipt = this.receipts.get(txRef);
    if (!receipt) throw new Error("unknown in-memory anchor receipt");
    return receipt;
  }

  /** Deterministic storage address for a name (without writing) — for resume/resolve. */
  async anchorAddress(name: string): Promise<string> {
    return this.address(name);
  }

  /**
   * Address of ANOTHER owner's anchor. The in-memory store is one shared
   * namespace so the owner is irrelevant here — but on the real substrate
   * anchor addresses are owner-scoped (derived from the owner's wallet), so
   * cross-agent reads must go through this seam.
   */
  async anchorAddressFor(_owner: string, name: string): Promise<string> {
    return this.address(name);
  }

  /** Read the artifact anchored at an address (null if absent). */
  async read(ref: string): Promise<Record<string, unknown> | null> {
    return this.store.get(ref) ?? null;
  }

  /** Mount an upstream behind the DAHR proxy (e.g. https://api.github.com → mock GitHub). */
  mount(urlPrefix: string, handler: ProxyHandler): void {
    this.mounts.set(urlPrefix, handler);
  }

  /**
   * Mock DAHR consensus-backed proxy fetch. Routes to the mounted upstream;
   * unknown URLs 404. The responseHash is the attestation commitment over the
   * response body — the thing a real DAHR run gets network consensus on.
   */
  async proxyFetch(req: { url: string; method?: string }): Promise<{
    status: number;
    responseHash: string;
    body: unknown;
  }> {
    for (const [prefix, handler] of this.mounts) {
      if (req.url.startsWith(prefix)) {
        const res = handler(req.url);
        return {
          status: res.status,
          responseHash: sha256Hex(JSON.stringify(res.body ?? null)),
          body: res.body,
        };
      }
    }
    return { status: 404, responseHash: sha256Hex("null"), body: null };
  }
}
