# DACS conformance profile

## Baseline and claim

This implementation targets the DACS Standard at commit
`2ff69b7f1fa13440a64cc865bd3f7e5fce6d34d2` (2026-07-03). The Standard is
authoritative. The SDK is used wherever its public surface expresses the
normative artifact and rule; the temporary profile in `standard-profile.ts`
fills the tracked SDK gaps.

The conformance claim is deliberately scoped to the operations the current
roster advertises. It is not a claim to implement every optional DACS v1 phase,
rail, presentation, credential recipe, or repeated-pipeline topology.

The conformant transaction surfaces are:

- the public Procurement Butler to Auditor RFQ flow;
- the fixed-price Standard runner used by Oracle Desk, DD Researcher,
  Dependency Planner, EvalBot, Treasury Ops, Site Auditor, Security Auditor,
  and Compliance;
- the signed, immutable DACS-1 listings published for those sellers.

The gateway's direct specialist endpoints are constrained preview endpoints,
not DACS commerce sessions. They do not claim transaction conformance merely
because they expose the same underlying specialist logic.

## Stage matrix

| Stage | Current implementation |
| --- | --- |
| DACS-1 Identify | Full signed/versioned Listing, canonical size and schema gates, signed per-claim IdentityBundle, nonce-bound session presentations, native Demos logical-to-native index binding, and content/signature-bound revocation checks. |
| DACS-2 Vet | Both parties exchange and anchor CompositeVerificationRecords bound to the exact IdentityBundle and empty BundleRequirement. Non-empty requirements fail closed until the recipe registry is integrated. |
| DACS-3 Negotiate | Fixed-price and signed L2PS RFQ paths; transcript/channel binding; dual-signed AgreementDocument; CA-3 immutable commitment slots; Commit must complete before Settle. Deadline and listing expiry are re-checked against the confirmed SR-2 inclusion-block timestamp. |
| DACS-4 Settle | `pay-dem` with base-unit string arithmetic, Demos transaction inclusion block and `bft-final` evidence; `pay-x402` with provider-receipt evidence in the fixed runner; payment/delivery ordering follows the listed pipeline; separately anchored SettlementEvidence. |
| DACS-5 Verify | Exact SessionRecord states and phase results, pinned listing hash/version, evidence reconciliation, signed terminal failure bundles, and canonically identical buyer/seller copies of a two-signed completed AttestationBundle. |

## Advertised operational profile

Current listings and orchestrators intentionally advertise only what they can
execute and verify end to end:

- Ed25519 `per-claim` presentations backed by Demos primary claims;
- an empty buyer credential requirement;
- exactly one negotiation, one commit, at most one payment, and exactly one
  delivery invocation;
- `negotiate-fixed-price` or `negotiate-rfq`;
- `pay-dem` or `pay-x402`;
- `deliver-attested-payload`;
- no `rate` phase, because current operations do not produce RatingRecords.

The reader rejects repeated phase kinds even though PIPE-5 permits them. That
is a fail-closed profile restriction: current agents do not advertise repeated
phases, and the restriction must not be relaxed until every repeated invocation
gets a distinct address, phase index, and SettlementEvidence record.

The implementation likewise rejects unsupported presentation algorithms,
non-empty credential recipes, sealed-envelope negotiation, amendments,
asymmetric recovery, private deliverables, and other payment rails rather than
silently downgrading them.

## Standard-first SDK adapter

| Standard requirement | Implementation source | Removal condition |
| --- | --- | --- |
| Canonical JSON, hashing, CD-1 decimal/base-unit conversion, domain-separated payloads | DACS SDK | Permanent SDK use. |
| Full Listing, IdentityBundle, CompositeVerificationRecord, AgreementDocument, CommitmentRecord, SettlementEvidence, AttestationBundle and SessionRecord shapes | `standard-profile.ts` | Replace when the SDK provides schema-fidelitous public types, builders and validators. |
| Typed Demos listing storage/discovery and native index binding | Seller/Buyer adapters | Replace when the SDK exposes typed listing publication and discovery. |
| RFQ agreement/commit orchestration | `negotiation-l2ps/` | Replace when equivalent orchestration is released by the SDK. |
| `pay-dem` evidence and BFT inclusion finality | Standard profile branch plus gateway payment verifier | Replace when the SDK exposes authoritative settlement and inclusion receipts. |
| Objective SR-2 commitment receipt | `LiveSubstrate.anchorWithReceipt`, which resolves the confirmed transaction and inclusion block | Move into a typed SDK anchor receipt when available. |
| Durable/resumable session orchestration | Gateway job receipt plus fail-closed restart handling | Replace when the SDK provides state/resume and double-payment-safe recovery primitives. |

The pinned official SDK vector run currently reports 302 passed, 3 failed, 2
skipped, and 8 todo. The three failures are the SDK's reduced Listing,
CompositeVerificationRecord, and AgreementDocument validators and are covered
by the SDK's current reduced artifact validation; they are why those validators are not used as an authority for
the current full artifacts.

## Two specification ambiguities

The CommitmentRecord schema block omits a `signature` member, while the
normative commitment procedure requires the orchestrator signature over the
record without its signature. This implementation follows the MUST procedure
and carries the signature.

The same procedure requires `committedAt` inside the signed pre-anchor record
while defining it as the timestamp of an anchor that does not yet exist. The
implementation stores a provisional creation time in the signed record, then
uses and returns the independently resolved Demos inclusion-block timestamp for
the authoritative post-anchor deadline and expiry checks. Both buyer and seller
resolve and compare the SR-2 receipt before payment. This preserves the stated
two-phase security property without pretending a future block timestamp was
known before signing.

## Deployment requirements

The public RFQ flow must receive the Auditor's native `stor-…` listing address
from the index, either through `DACS_AUDITOR_LISTING_REF` or the indexer's
`?listing=stor-…` link. The gateway rejects deterministic guesses and listings
whose seller does not match `DACS_AUDITOR_DID`.

The Security Auditor additionally uses a non-empty buyer-side DACS-2 policy.
Listing v3 signs a `securityResearcher` profile into the seller IdentityBundle.
The Butler independently checks that the same DID controls
`DACS_AUDITOR_RESEARCHER_GITHUB` through Demos CCI, records nonce-bound key
control and any previously reconciled DACS-5 audit bundles as supplementary CVR
signals, and fails closed before negotiation or payment when the CCI proof is
absent or different.

Legacy mock demos remain for historical examples. They are not part of this
conformance claim; new public transactions must use the Standard listing and
lifecycle paths above.

## Verification commands

```sh
npx tsc --noEmit
npm test
git diff --check
```

The focused conformance suites are `standard-profile.test.ts`,
`standard-runner.test.ts`, `all-listings-standard.test.ts`, the
`negotiation-l2ps` suites, and `gateway/live-procurement.test.ts`.
