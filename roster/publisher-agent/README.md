# Publisher Agent

An independent RFQ seller for policy-reviewed advertising inventory on a domain
the seller has linked to its Demos identity.

## Testable contract

The RFQ binds the exact creative, destination, preferred/minimum duration,
placement and budget. The seller may counter with the longest affordable
duration, then atomically reserves that slot before the parties commit or pay.
After payment, the activation adapter publishes the advert and an inspectable
manifest at:

`https://<domain>/.well-known/dacs-ads/<campaign-id>.json`

The seller's DACS delivery binds the public page, manifest URL, slot, campaign
window, creative bytes/hash, original RFQ hash and agreed quote hash.

## Domain identity

Provisioning uses the native Demos SDK flow:

1. Generate the wallet-bound proof with
   `Identities.createDomainProofPayload(demos, hostname)`.
2. Host it at `https://<hostname>/.well-known/demos-cci.txt`.
3. Call `Identities.addDomainIdentity(demos, hostname)`.
4. Confirm the GCR resolves `web2.domain` for the seller wallet.

The current DACS SDK exposes that claim as `web2:domain:<hostname>`. The spec's
conflicting `domain:<hostname>` form is tracked in
[DACS-Standard #275](https://github.com/DACS-Agent-commerce/DACS-Standard/issues/275).

## Live activation gates

The public profile remains `provisioning` until there is a real domain binding,
a generic placement/duration RFQ transport (the existing live RFQ transport is
audit-specific), production moderation, durable atomic reservations, a hardened
activation API, DEM/x402 signed listings, and a paid end-to-end conformance run.
