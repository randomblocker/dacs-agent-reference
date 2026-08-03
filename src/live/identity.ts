/**
 * Live identities — real Demos wallets behind the same Identity/CCI surface
 * the agents use.
 *
 * - An identity's DID embeds its wallet pubkey (`did:demos:agent:<hex>`), same
 *   convention as the mock — but here the key is a real funded wallet and
 *   `sign` goes through the wallet (DemosAdapter.sign).
 * - `LiveCci` is the real thing the mock `CciDirectory` was shaped after:
 *   `resolveIdentity` hits the on-chain GCR through the SDK and parses with
 *   `parseCciRecord` (dacs-sdk #13); `githubLoginFor` reads the subject's
 *   actual Web2 identity proofs. Nothing to `bind()` — bindings exist only if
 *   the DID's owner really proved control of the GitHub account.
 */
import { parseCciRecord } from "@kynesyslabs/dacs";
import type { Signer } from "@kynesyslabs/dacs";
import { DemosAdapter } from "@kynesyslabs/dacs/substrate";

export interface LiveIdentity {
  label: string;
  did: string;
  /** Demos address (0x + pubkey hex). */
  address: string;
  evm: string;
  sign: Signer;
  adapter: DemosAdapter;
}

/** Connect a wallet and derive its ecosystem identity. */
export async function connectIdentity(
  label: string,
  rpc: string,
  mnemonic: string,
  evm = "0x0000000000000000000000000000000000000000",
): Promise<LiveIdentity> {
  const adapter = new DemosAdapter({ rpc, secret: mnemonic });
  await adapter.connect();
  const address = await adapter.getAddress();
  const hex = address.replace(/^0x/, "");
  return {
    label,
    did: `did:demos:agent:${hex}`,
    address,
    evm,
    sign: (bytes) => adapter.sign(bytes),
    adapter,
  };
}

/** The real CCI — on-chain GCR lookups via any connected adapter. */
export class LiveCci {
  constructor(private readonly adapter: DemosAdapter) {}

  /** Which GitHub login (if any) did this DID prove control of? */
  async githubLoginFor(didOrAddress: string): Promise<string | null> {
    const hex = didOrAddress.match(/([0-9a-fA-F]{64})$/)?.[1];
    if (!hex) return null;
    const resolved = await this.adapter.resolveIdentity(hex);
    const record = parseCciRecord(didOrAddress, resolved.raw);
    const gh = record.web2.find((c) => c.platform === "github");
    return gh?.handle ?? null;
  }

  /** Reverse: which DIDs hold `web2:github:<login>`? */
  async subjectsForGithub(login: string): Promise<string[]> {
    return this.adapter.findSubjectsByClaim(`web2:github:${login}`);
  }
}
