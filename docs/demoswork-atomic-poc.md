# Atomic DACS Demos Work proof of concept

This branch implements an offline reference model for the proposed two-Work DACS lifecycle. It is deliberately not connected to the production gateway.

## Model

The Purchase Work commits six critical operations as one state transition: agreement assertion, buyer Vet, seller Vet, commitment, native DEM payment, and payment evidence. The Completion Work commits five critical operations: purchase-receipt assertion, delivery, delivery evidence, buyer DACS-5 copy, and seller DACS-5 copy.

Every operation is content-hash-bound, dependency ordered, and signed by its required party. The stable `workId` excludes signatures and the eventual transaction hash. Payment evidence refers to the typed payment operation reference, avoiding a transaction self-reference cycle.

The memory executor provides the semantics the node would need to guarantee:

- isolated state overlay and all-or-nothing commit;
- rollback of a transfer when a later critical operation fails;
- create-only and compare-and-set storage;
- one payment slot per job and phase;
- idempotent replay by `workId`;
- conflicting-intent rejection;
- operation results and inclusion metadata bound into a deterministic reference receipt; and
- restart-safe replay from a durable snapshot.

Run the focused conformance suite and the Oracle proof:

```sh
npm run demoswork:test
npm run demoswork:poc
```

The CLI executes locally and does not spend DEM. Its timing measures only assembly, signing, and deterministic execution—not consensus latency.

## Live capability gate

The pinned SDK currently resolves Demos SDK 4.0.16. It can submit Demos Work and represent a native transaction, but it does not expose all load-bearing requirements for this profile: first-class StorageProgram steps, operation-level multi-party authorization, verified rollback of native state, a stable pre-submission Work identifier, an authoritative operation receipt, or Node 22-compatible Demos Work exports.

The reference receipt demonstrates the required shape and tamper checks, but it is not a substitute for a node-issued BFT proof. The capability gate therefore fails closed. `DACS_DEMOSWORK_ATOMIC_MODE` has three modeled rollout states: `disabled` keeps the normative multi-transaction path, `shadow` validates the atomic intent without moving payment off that path, and `live` is rejected until every required capability is proven. A live submission adapter must not be enabled until each capability is implemented and verified against the node.

## Promotion gate

Before a testnet canary, the node and SDK need to pass the conformance cases in `src/demoswork/dacs-atomic.test.ts`, then the Oracle profile needs at least 100 live lifecycles with zero duplicate payments and zero partial state after injected failures. Security Audit and DD should follow only after the Oracle canary meets those thresholds.
