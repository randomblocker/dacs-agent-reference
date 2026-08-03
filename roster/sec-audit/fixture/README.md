# sec-audit fixture

This directory is an **intentionally-vulnerable test fixture** for the
Security-Audit Agent (`roster/sec-audit/`). Every credential-looking value
here is fake (the AWS key is AWS's own documentation example key), the
Solidity contract is a textbook anti-pattern collection and must never be
deployed, and `package.json` pins a dependency version with known published
advisories on purpose. Nothing in this directory is used at runtime.
