# DACS Agent Reference

Copyable reference implementations for agents that use the DACS lifecycle:
Identify, Vet, Negotiate, Settle, Deliver and Verify. The repository includes
offline agent cores, live-adapter boundaries, native DEM and x402 examples,
and an experimental atomic Demos Work model.

This is a fresh, sanitized source export. It contains no production wallets,
identities, listing references, transaction records, domains, API credentials,
VPS configuration or deployment history.

## What is included

- Procurement Butler buyer orchestration and independently verifiable receipts.
- Oracle Desk, DD Researcher and Security Auditor seller examples.
- Fixed-price, fixed-price co-sign and RFQ negotiation profiles.
- DACS-1 listing, DACS-2 vet, DACS-3 agreement/commitment, DACS-4 settlement
  evidence and two-sided DACS-5 bundle construction.
- Native Demos DEM and Base Sepolia x402 rail bindings.
- Idempotent payment handling, nonce-safe writes and fail-closed recovery.
- Additional reference agents for evaluation, compliance, dependency planning,
  treasury planning, site auditing and sponsored content.
- An offline two-transaction atomic Demos Work proof of concept under
  [`src/demoswork`](./src/demoswork).

## Safety boundary

The default demonstrations are offline and do not spend funds. Live entrypoints
are examples only and fail closed unless the caller explicitly supplies wallet,
listing, identity and rail configuration. Never reuse production keys in a
development checkout.

The Demos Work POC is not a live node adapter or a claim of canonical support.
Its capability gate deliberately rejects live mode until the node and SDK expose
the required atomicity, authorization and receipt guarantees. See
[`docs/demoswork-atomic-poc.md`](./docs/demoswork-atomic-poc.md).

## Requirements

- Node.js 20.19+ or 22.12+
- npm
- Access to the currently private DACS SDK repository

The reference code imports `@kynesyslabs/dacs`. Until that SDK is publicly
released, contributors need read access to `DACS-Agent-commerce/dacs-sdk` or an
existing local SDK checkout. The setup script supports both:

```bash
# Existing SDK checkout
DACS_SDK_PATH=/absolute/path/to/dacs-sdk npm run setup

# Or clone the pinned SDK revision using your normal Git credentials
npm run setup
```

Automation may provide a narrowly scoped, read-only `DACS_SDK_GITHUB_TOKEN`.
Do not use a personal token with write or organization-administration access.

## Run the references

```bash
npm run setup
npm test
npm start

# Atomic Demos Work reference model (offline; spends nothing)
npm run demoswork:test
npm run demoswork:poc
```

Selected agent demonstrations are exposed as `roster:*` scripts in
[`package.json`](./package.json).

## Repository map

| Path | Purpose |
| --- | --- |
| `src/` | ReviewBot buyer/seller/verifier reference lifecycle and ports |
| `roster/` | Reusable specialist agents, DACS adapters and gateway examples |
| `src/demoswork/` | Atomic Purchase Work and Completion Work reference model |
| `docs/` | Architecture, limitations and promotion gates |
| `scripts/setup-sdk.sh` | Reproducible pinned-SDK setup |

## Conformance

The DACS Standard is normative. This repository uses the SDK where it exposes
the required behavior and keeps explicit, fail-closed adapters for documented
SDK gaps. See [`roster/dacs/CONFORMANCE.md`](./roster/dacs/CONFORMANCE.md).

Experimental code must not be described as canonical merely because its tests
pass. A live adapter must also pass the released Standard vectors and the
relevant network integration tests.

## Contributing and security

Run `npm run security:check`, `npm audit --audit-level=high`, typecheck and the
complete offline suite before opening a pull request. Report vulnerabilities
privately as described in [`SECURITY.md`](./SECURITY.md); never include keys,
private deliverables or exploit credentials in an issue.

Licensed under Apache-2.0. Third-party dependencies retain their own licenses.
