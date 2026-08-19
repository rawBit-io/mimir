# Mimir

Mimir is an offline, public-data-only compiler for one fixed two-path Bitcoin
P2WSH recovery policy. It accepts account xpubs, key origins, and exact UTC
unlock dates; it never accepts private keys and never constructs, signs, or
broadcasts transactions.

This repository currently identifies itself as `mimir-v1-preview.1`. It is a
functional pre-mainnet implementation, not a production-ready Mimir v1 release.
The mainnet release gates in `mimir_spec.md`—including independent review,
complete Core differential/regtest coverage, reproducible release signing, and
recovery rehearsal—remain mandatory.

## What it produces

- Checksummed fixed and account-multipath descriptors
- Exact 87-byte witness script, P2WSH commitment, scriptPubKey, and address
- BIP 388 wallet-policy template and ordered key vector
- RFC 8785 canonical policy manifest and SHA256
- Pinned-draft BIP 138 recovery capsule, OP_RETURN data, and script
- A downloadable package containing all 24 public recovery artifacts
- Bitcoin Core verification, funding, monitoring, and recovery guidance

## Run locally

Node.js 22.13 or newer is required.

```bash
npm install
npm run dev
```

The application does not persist entered policy data. Its production content
security policy disables network connections, and all code, styles, icons, and
preview imagery are bundled locally.

## Validate

```bash
npm test
```

The test suite builds the deployable worker, renders the application shell,
checks public-only/offline constraints, exercises deterministic policy output
and fail-closed inputs, self-decrypts randomized capsules, and verifies pinned
BIP 380, Miniscript/Core, RFC 8785, and BIP 138 vectors.

