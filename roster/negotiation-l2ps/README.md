# L2PS transport — negotiation across two live processes

Turns the in-process RFQ engine into a real **two-agent** negotiation: the seller
and buyer run as separate processes, exchanging **signed** DACS-3 §8.3.3
`ChannelMessage` envelopes over the live L2PS messaging server. This is the step
that makes the negotiated audit desk an actual on-network agent rather than a
demo that talks to itself.

    npm run roster:l2ps        # spawns a seller + buyer process, negotiates live

## What it proves

- **Faithful split.** The distributed loop reaches the *same* agreement the
  in-process `runNegotiation` engine does — proven offline by a parity test over
  an in-process channel (4 scenarios), so the transport is a split of the engine,
  not a drift-prone reimplementation.
- **Live, over a real server.** Two processes with distinct crypto identities
  handshake and negotiate to agreement over `demosnode.discus.sh:3005` (verified:
  seller 18.4 → buyer 11.96 → seller 14.88 → buyer accept, both converge on
  `deep/standard @ 14.88 DEM`).
- **Signed, authenticated moves.** Every move crosses the wire as a §8.3.3
  envelope (channelId, monotonic sequence, sender, type, body, signature); the
  receiver enforces channel, sequence, sender, and ed25519 signature. Tamper /
  out-of-sequence / wrong-sender envelopes are rejected (tested).

## NEGOTIATE → BIND → SETTLE (end to end, live)

The transport is now wired through to on-chain settlement:

    npx tsx roster/negotiation-l2ps/settle-live.ts               # DRY RUN
    SETTLE_CONFIRM=1 npx tsx roster/negotiation-l2ps/settle-live.ts   # broadcast

- **Bind** (`bind.ts`) turns the concluded negotiation into a `ChannelAgreement`
  (agreed terms + both parties' signer ids + `derivedFromChannel.lastMessageHash`
  + transcript hash). Both parties derive the SAME `agreementHash` from their own
  view — a mutual commitment neither can restate. Anchor-safe: it embeds only
  enums/numbers/ids/hashes, never raw LLM rationale, so its canonical form is pure
  ASCII (won't trip the storage-program non-ASCII hash-mismatch).
- **Settle** (`settle-live.ts`) conveys the bound terms and settles buyer → seller
  as a native DEM transfer on the live testnet, reusing the L1 run's wallet
  machinery. **Verified live**: `deep/standard @ 14.88` negotiated → bound → 0.01
  DEM settled buyer→seller, tx `9ebc4e68…` (buyer 136.00→134.99, seller +0.01).
  Money-safe: DRY RUN by default; `SETTLE_CONFIRM=1` to broadcast; the settled OS
  amount is a small token (the full price + agreementHash ride in the record).

## Files

| File | Purpose |
|------|---------|
| `wire.ts` | The §8.3.3 envelope, canonical bytes, and the injectable `Signer` (sign/verify + the four open-time invariants). |
| `channel.ts` | `Channel` mailbox interface; `InProcessChannelPair` (offline tests) and `L2psChannel` (over MessagingPeer). |
| `session.ts` | `runSide` — the distributed negotiation loop; faithful two-process form of `runNegotiation`; captures the signed envelope transcript. |
| `bind.ts` | `ChannelAgreement` + `agreementHash` + `lastMessageHash` + `sessionOpenParams` — binds the transcript to the outcome (§8.5/§8.6). |
| `demosdk.ts` | Shim for the vendored demosdk: WebSocket polyfill, `MessagingPeer`, and the ed25519 `ucrypto` signer. |
| `live-peer.ts` | `LivePeer` — connect, handshake signer ids, route hellos vs envelopes. |
| `peer-main.ts` | One peer as a process (role/brief from env). |
| `live-peers.ts` | Parent: spawns seller + buyer, asserts they agree. |
| `settle-live.ts` | Negotiate → bind → settle on live pay-dem (dry-run by default). |
| `session.test.ts` | 8 tests: engine parity (4 scenarios) + envelope enforcement (tamper/sequence/sender/canonical). |
| `bind.test.ts` | 5 tests: both parties derive the same agreementHash/lastMessageHash, session params, dual signatures, tamper detection, ASCII anchor-safety. |

## Transport notes

- **Server.** Targets the legacy signaling server (E2E-encrypted relay) on
  `discus:3005`, which is live today. The rollup-backed `L2PSMessagingPeer`
  (port 3006, DACS-3 §8.3.2 canonical) is opt-in node config; swapping to it is a
  constructor change in `demosdk.ts` + `live-peer.ts` once a node exposes it.
- **Payload shape.** `MessagingPeer.onMessage` hands handlers the **decrypted
  bytes as a Buffer** (not a string) — `decodePayload` normalises this. Peer
  identity for registration is the **ml-kem-aes** key (1184 bytes), not ml-dsa.
- **Two processes, by necessity.** demosdk's `ucrypto` holds one identity per
  process, so distinct signer identities require distinct processes — which is
  also the honest form of the split.

## Remaining follow-ons

1. **CCI-keyed signing.** Replace the messaging-identity ed25519 signer with
   `l2ps.channel.ChannelSession` (CCI primary-key signing) + the §8.3.2
   membership binding-proof anchored as a Storage Program. The envelope shape
   doesn't change — only the signer. (Done: bind + live pay-dem settle.)
2. **Commit-anchor.** Anchor `agreementHash` as a Storage Program (SR-2) at
   `dacs3:commit:{jobId}` before settling — the on-chain commit-agreement step.
   The agreement is already ASCII-safe for it.
3. **Full delivery.** Route `sessionOpenParams` through the steward's
   `dacs/wire/audit-negotiator.ts` so the settled deal also delivers the signed
   audit artifact (deep tier) — not just the value transfer.
4. **Buyer SDK ergonomics.** Wrap the `dacs-rfq/1` control frames in a buyer
   client helper; the seller protocol and persistent daemon are implemented.

## Persistent seller (`dacs-rfq/1`)

`npm run auditor:serve` runs a long-lived seller registered as `dacs-auditor`.
It accepts `dacs-rfq-open`, exchanges the normal signed channel envelopes,
returns a seller-signed `dacs-rfq-agreement`, and requires a buyer
`dacs-rfq-agreement-accept` signature before advertising payment. A final
`dacs-rfq-settle` carries the buyer's transaction hash; the daemon verifies a
confirmed native DEM transfer to its dedicated wallet for at least the agreed
price and returns `dacs-rfq-settled`.

The wallet secret is read from `SELLER_KEY_PATH` (default
`/home/auditor/.dacs/seller-key`, required mode 0600). The same secret produces
a stable, domain-separated L2PS identity without being transmitted. Offered,
accepted, and settled agreement/payment state is atomically persisted at
`SELLER_STATE_PATH`, preventing replay across service restarts.

`DACS_AUDITOR_RESEARCHER_GITHUB` is also required. It must name the GitHub
account that the seller DID has proved through Demos CCI. The value is signed
into DACS-1 listing v3; buyers independently resolve the CCI binding and record
it in the DACS-2 CompositeVerificationRecord. Missing or mismatched evidence
stops the session before negotiation or payment.
