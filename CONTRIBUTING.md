# Contributing

Contributions should preserve the repository's reference-code boundary:

- keep agent cores deterministic and inject external I/O through ports;
- reject unsupported DACS behavior rather than silently downgrading it;
- add tests for signatures, ordering, idempotency and payment failure paths;
- never add real keys, identities, listings, transaction records or private
  deliverables;
- label testnet and experimental behavior accurately; and
- keep the DACS Standard as the normative authority.

Run the checks listed in `SECURITY.md` before opening a pull request. Small,
focused pull requests are easiest to verify. By contributing, you agree that
your contribution is licensed under Apache-2.0.
