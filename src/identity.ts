/**
 * Ecosystem identities. A DACS agent's identity is an ed25519 keypair; its
 * primary claim (CCI DID) embeds the raw public key hex, so anyone can resolve
 * the verifying key straight from the DID with no registry lookup — which is
 * how the verifier checks bundle signatures below.
 *
 * (Real deployments resolve keys via CCI on the Demos substrate; embedding the
 * key in the DID is the self-describing form the SDK's own tests use.)
 */
import {
  ed25519Sign,
  ed25519Verify,
  privateKeyFromSeed,
  publicKeyFromSeed,
  publicKeyFromRaw,
  rawPublicKey,
  type Signer,
} from "@kynesyslabs/dacs";

export interface Identity {
  label: string;
  /** CCI DID / primary claim (self-describing: embeds the ed25519 pubkey hex). */
  did: string;
  /** EVM address used as the settlement payer/payee coordinate. */
  evm: string;
  /** Signs raw bytes with this identity's ed25519 key. */
  sign: Signer;
}

/** Deterministically derive an identity from a byte-fill seed (demo only). */
export function makeIdentity(label: string, fill: number): Identity {
  const seed = Uint8Array.from(Buffer.alloc(32, fill));
  const priv = privateKeyFromSeed(seed);
  const pubHex = Buffer.from(rawPublicKey(publicKeyFromSeed(seed))).toString("hex");
  return {
    label,
    did: `did:demos:agent:${pubHex}`,
    evm: "0x" + fill.toString(16).padStart(2, "0").repeat(20),
    sign: (bytes) => ed25519Sign(bytes, priv),
  };
}

/** Resolve the ed25519 public key embedded in a self-describing DID (null if none). */
export function resolveFromDid(did: string): Uint8Array | null {
  const hex = did.match(/(?:^|:)(?:0x)?([0-9a-fA-F]{64})$/)?.[1];
  return hex ? Uint8Array.from(Buffer.from(hex, "hex")) : null;
}

/** Verifier for the bundle signature check (raw pubkey bytes -> key object). */
export const verify = (b: Uint8Array, s: Uint8Array, p: Uint8Array): boolean =>
  ed25519Verify(b, s, publicKeyFromRaw(p));

/**
 * Mock CCI directory — DID ↔ GitHub-login bindings.
 *
 * Shaped like the SDK's `SubstrateAdapter.resolveIdentity(ref) →
 * ResolvedIdentity { ref, boundTo?, raw }`, so when the SDK's CCI support
 * lands (in progress upstream) this class is replaced by
 * `adapter.resolveIdentity(did)` against the real Demos CCI — callers keep
 * their shape.
 *
 * The load-bearing property CCI provides for real: a binding exists ONLY if
 * the DID's owner proved control of the GitHub account (Web2 identity proof).
 * An impostor can *claim* any login in its listing; it cannot *bind* it.
 */
export interface ResolvedIdentityLike {
  ref: string;
  boundTo?: string;
  raw: unknown;
}

export class CciDirectory {
  private readonly bindings = new Map<string, string>();

  /** Record a proven DID → GitHub-login binding (the Web2 identity proof). */
  bind(did: string, githubLogin: string): void {
    this.bindings.set(did, githubLogin);
  }

  /** CCI lookup: which identity (if any) is bound to this DID? */
  async resolveIdentity(ref: string): Promise<ResolvedIdentityLike> {
    const login = this.bindings.get(ref);
    return {
      ref,
      boundTo: login ? `github:${login}` : undefined,
      raw: login ? { xm: { web2: { github: [{ username: login }] } } } : null,
    };
  }

  /** Convenience: the bound GitHub login, or null if the DID proved nothing. */
  async githubLoginFor(did: string): Promise<string | null> {
    return this.bindings.get(did) ?? null;
  }
}
