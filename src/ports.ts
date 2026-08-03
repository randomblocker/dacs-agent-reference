/**
 * Structural ports the agents are written against. MemorySubstrate/MockGitHub/
 * CciDirectory implement them implicitly (mock mode), LiveSubstrate/LiveGitHub/
 * LiveCci implement them against the real testnet + real GitHub (live mode).
 * The agents cannot tell which world they're in — that's the point.
 */

export interface AnchorReceipt {
  address: string;
  txRef: string;
  /** Objective SR-2 inclusion-block timestamp (unix ms). */
  anchoredAt: number;
  blockNumber?: number;
  /** Canonical sha256 of the exact JSON value carried by the anchor tx. */
  contentHash?: string;
  /** Node estimate returned at broadcast time, when available. */
  expectedConfirmationBlock?: number;
  /** actual inclusion block minus the node estimate. */
  confirmationBlockDelta?: number;
  /** Local timestamp captured immediately after the broadcast RPC accepted the tx. */
  broadcastAt?: number;
  /** Local timestamp at which this process first observed confirmed inclusion. */
  confirmedAt?: number;
  /** Local confirmation observation minus local broadcast acceptance. */
  inclusionLatencyMs?: number;
  /** Sequential sender nonce carried by the transaction. */
  nonce?: number;
  /** Exact public transaction content whose sha256(JSON) is `txRef`. */
  transactionContent?: Record<string, unknown>;
  /** The StorageProgram value is replaced by null and must be reinserted before hashing. */
  transactionContentValueOmitted?: boolean;
}

/**
 * A non-value SR-2 write explicitly accepted by the substrate for processing.
 * This is stronger than a locally-created hash or an unacknowledged broadcast,
 * but deliberately carries no consensus timestamp/block claim.
 */
export interface AnchorAcceptance {
  address: string;
  txRef: string;
  contentHash: string;
  status: "accepted";
  acceptedAt: number;
  expectedConfirmationBlock?: number;
  nonce?: number;
  /** Exact public transaction content whose sha256(JSON) is `txRef`. */
  transactionContent?: Record<string, unknown>;
}

export interface AnchorResolveOptions {
  /** Node estimate captured when the transaction was admitted. */
  expectedConfirmationBlock?: number;
  /** Exact public transaction content whose sha256(JSON) is `txRef`. */
  transactionContent?: Record<string, unknown>;
  /** Artifact already carried by the protocol frame; used to rehydrate a compact proof. */
  anchorValue?: Record<string, unknown>;
  transactionContentValueOmitted?: boolean;
}

export interface SubstratePort {
  anchor(name: string, value: object): Promise<string>;
  /** Submit non-value evidence and return after explicit substrate admission. */
  anchorAccepted?(name: string, value: object): Promise<AnchorAcceptance>;
  /** Independently verify that an acceptance is known to the substrate queue. */
  verifyAnchorAcceptance?(acceptance: AnchorAcceptance): Promise<void>;
  /** Resolve a prior admission to its authoritative consensus receipt. */
  confirmAcceptedAnchor?(acceptance: AnchorAcceptance, owner?: string): Promise<AnchorReceipt>;
  /**
   * Tell the wallet-local allocator that an on-chain operation constructed
   * outside this substrate consumed `nonce`. This prevents the following
   * evidence anchor from reusing a payment nonce while the address projection
   * is still catching up.
   */
  noteExternalNonce?(nonce: number): void;
  /**
   * Typed SR-2 receipt used by Standard timing gates. Optional only so legacy
   * demos remain source-compatible; conformant commit flows require it.
   */
  anchorWithReceipt?(name: string, value: object): Promise<AnchorReceipt>;
  /**
   * Broadcast a known ordered group with distinct wallet nonces and await all
   * confirmations. The returned receipts preserve input order.
   */
  anchorBatchWithReceipts?(entries: Array<{ name: string; value: object }>): Promise<AnchorReceipt[]>;
  /** Independently resolve a previously returned SR-2 transaction receipt. */
  resolveAnchorReceipt?(txRef: string, owner?: string, options?: AnchorResolveOptions): Promise<AnchorReceipt>;
  /** Address of OUR OWN anchor of `name`. */
  anchorAddress(name: string): Promise<string>;
  /** Address of ANOTHER owner's anchor of `name` (owner-scoped on-chain). */
  anchorAddressFor(owner: string, name: string): Promise<string>;
  /**
   * Resolve and read an owner-scoped anchor while preserving authoritative
   * absence separately from an indeterminate name-index failure.
   */
  readAnchorFor?(owner: string, name: string): Promise<Record<string, unknown> | null>;
  read(ref: string): Promise<Record<string, unknown> | null>;
  proxyFetch(req: { url: string; method?: string }): Promise<{
    status: number;
    responseHash: string;
    body: unknown;
  }>;
}

export interface GitHubPort {
  getPull(repo: string, number: number): { number: number; title: string; diff: string } | null;
  postReview(
    login: string,
    repo: string,
    number: number,
    body: string,
  ): { id: number; user: { login: string }; body: string; submitted_at: string };
  listReviews(
    repo: string,
    number: number,
  ): Array<{ id: number; user: { login: string }; body: string; submitted_at: string }>;
  stateHash(url: string): string;
}

export interface CciPort {
  /** The GitHub login this DID has proven control of, or null. */
  githubLoginFor(didOrAddress: string): Promise<string | null>;
}
