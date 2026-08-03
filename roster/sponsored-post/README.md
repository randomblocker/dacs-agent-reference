# Sponsored Post Agent

An independent fixed-price DACS seller that publishes one policy-approved post
from a dedicated X account after settlement. It does not replace or share a
runtime with Oracle Desk.

## Safety and evidence model

- The signed agreement contains the exact post text. Inputs that would require
  trimming, Unicode normalization, or other hidden rewriting are rejected.
- V1 accepts a standalone text post of 1-240 characters. Links and mentions are
  rejected; media, replies, quotes, threads, deletion, and account selection are
  not exposed.
- A separate fail-closed moderation service must approve the text before the X
  request. Structural checks are defense in depth, not a claim of complete
  content-safety detection.
- Publication uses X API v2 `POST /2/tweets` with `paid_partnership: true`.
- The OAuth token is verified at startup with `GET /2/users/me` and must control
  the account named in the DACS identity metadata.
- Per-job publication state is written with mode 0600 before the X request. A
  timeout after send becomes `indeterminate` and cannot be retried until an
  operator reconciles the account; this prevents duplicate posts.
- Delivery contains the canonical public URL, post id, exact text bytes, and
  request/content hashes in the seller-signed DACS attestation. Text bytes are
  base64url encoded so Unicode posts do not trigger the Demos storage node's
  known non-ASCII transaction-hash disagreement.

## Activation gates

The `sponsored-post-live` procurement profile intentionally remains
`provisioning`. Do not mark it `live` until all of the following exist:

1. A dedicated X account and approved developer app, not a personal/team account.
2. A user-context OAuth access token with post-write access, stored in a 0600 file.
3. An independently keyed and funded Demos seller wallet.
4. A public X proof post binding the account to its `did:demos:agent:*` identity.
   `SPONSORED_POST_ACCOUNT_BINDING_FILE` records the DACS
   `cci-web2:twitter:<handle>` claim, X user id, proof post id/URL, and SHA-256
   hash of that proof text.
5. A production moderation endpoint with an operator-owned bearer credential.
6. Separate seller-session and publication-idempotency state directories with
   private permissions and backups.
7. Signed DEM and (if enabled) x402 listings published by this seller, with their
   refs and DID installed in the gateway configuration.
8. A paid end-to-end test proving Identify -> Vet -> Negotiate -> Settle ->
   Deliver -> Verify, including retry and indeterminate-publication drills.

## Runtime

`npm run sponsored-post:serve` starts the independent seller. Required settings:

- `SELLER_KEY_PATH`
- `SELLER_STATE_PATH`
- `SPONSORED_POST_STATE_DIR`
- `SPONSORED_POST_ACCOUNT_BINDING_FILE`
- `X_USER_ACCESS_TOKEN_FILE`
- `SPONSORED_POST_MODERATION_URL`
- `SPONSORED_POST_MODERATION_TOKEN_FILE`

Listing price/version, Demos/L2PS endpoints, and the existing DACS x402 settings
use the same environment names as the other production fixed-price sellers.
