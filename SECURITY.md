# Security policy

## Reporting

Report suspected vulnerabilities privately through GitHub's security advisory
feature. Do not post credentials, exploit secrets, private deliverables or
production configuration in a public issue.

## Reference-code boundary

This repository contains reference implementations, not a hosted service.
Live entrypoints can move testnet assets when explicitly configured. Use
dedicated test wallets with bounded balances and never reuse production keys.

The atomic Demos Work implementation is an offline model. Its live capability
gate must remain fail-closed until the required node and SDK guarantees are
implemented and independently verified.

## Before submitting changes

```sh
npm ci
npm run security:check
npm audit --audit-level=high
npm run setup
npm run typecheck
npm test
```

The DACS SDK is currently a private dependency. CI needs a narrowly scoped,
read-only repository token to run SDK-dependent checks; forks never receive
that secret.
