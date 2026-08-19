# MIMIR // POLICY TERMINAL

Mimir is a one-page, offline Bitcoin policy composer for public keys. Define an
owner group and an heir group, add up to 10 compressed secp256k1 public keys to
each, choose each group’s K-of-N threshold and common absolute timelock, then
compile the policy into inspectable P2WSH artifacts.

The composer accepts public data only. Every key must be a 33-byte compressed
public key encoded as 66 hexadecimal characters and beginning with `02` or
`03`. Private keys, seed phrases, fingerprints, derivation paths, and xpubs are
not inputs to the v2 interface.

## Current policy model

- One owner group with a configurable K-of-N threshold
- One heir group with a configurable K-of-N threshold
- 1–10 direct compressed public keys per group
- One shared absolute Unix/UTC timelock per group
- Click-first controls for adding, arranging, and compiling a policy on one page
- Native SegWit v0 P2WSH output for explicit verification
- No persistence, transaction construction, signing, or broadcasting

The original fixed owner/heir v1 compiler is retained in `lib/mimir.ts` for
compatibility and regression coverage. The web interface now defaults to the
v2 public-key policy composer.

The frozen v2 policy and validation rules are documented in
[`mimir_v2_spec.md`](mimir_v2_spec.md).

## Run locally

Node.js 22.13 or newer is required.

```bash
npm install
npm run dev
```

Open <http://localhost:3000>. If your system still uses Node 20, run the local
server through Node 22 instead:

```bash
npm exec --yes --package=node@22 -- npm run dev
```

All application code, styles, icons, and preview imagery are bundled locally.
The app does not persist entered policy data, and its production content
security policy disables network connections.

## Validate

```bash
npm test
```

The suite builds the deployable worker, renders the application shell, checks
public-only and offline constraints, and verifies deterministic policy output
and fail-closed inputs.

## Safety status

Mimir remains pre-mainnet software. Treat every generated policy as a preview,
independently reproduce its descriptor, script, address, thresholds, and
timelocks with trusted Bitcoin tooling, and complete a recovery rehearsal
before funding. Never paste a private key or seed phrase into this app.
