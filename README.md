# Mimir

Mimir is a one-page, offline Bitcoin recovery-script builder. Add direct
compressed public keys to one editable signer list, mark each row as an owner
or heir, and set a K-of-N threshold plus absolute UTC unlock time for each
group. The Miniscript and Bitcoin Script ASM update live as the policy changes.

There is no compile button, wizard, or drag-and-drop mode. Incomplete and
invalid input produces an actionable placeholder instead of policy output.

## Current policy model

- One owner K-of-N group and one heir K-of-N group
- 1–10 direct compressed secp256k1 public keys per group
- One shared absolute UTC/Unix timelock per group
- One unified signer list with an `OWNER` or `HEIR` marker on every row
- Live Miniscript and Bitcoin Script ASM preview
- Regtest and signet selection in the web interface
- Checksummed descriptor, witness script, scriptPubKey, address, invariants,
  warnings, and manifest hash under collapsed **Technical details**
- JSON manifest export whenever the live policy is valid
- No persistence, transaction construction, signing, or broadcasting

Every key must be a 33-byte compressed public key encoded as 66 hexadecimal
characters and beginning with `02` or `03`. Mimir does not accept private keys,
seed phrases, extended keys, fingerprints, or derivation paths.

The underlying v2 compiler retains its `bitcoin`, `signet`, and `regtest`
network support for deterministic compatibility, but the pre-mainnet web UI
intentionally exposes only regtest and signet. The immutable v1 compiler
remains in `lib/mimir.ts` for compatibility and regression coverage.

The frozen compiler semantics and live-interface rules are documented in
[`mimir_v2_spec.md`](mimir_v2_spec.md).

## Run locally

Node.js 22.13 or newer is required.

```bash
npm install
npm run dev
```

Open <http://localhost:3000>. If your system still uses Node 20, run through
Node 22 instead:

```bash
npm exec --yes --package=node@22 -- npm run dev
```

All application code, styles, icons, and preview imagery are local. Policy
state stays in volatile page memory, and the production content security policy
disables outbound network connections.

## Validate

```bash
npm test
```

The suite builds the deployable worker, renders the application shell, checks
public-only and offline constraints, and verifies deterministic policy output
and fail-closed validation.

## Safety status

Mimir remains pre-mainnet software. Reproduce every descriptor, script,
address, threshold, and timelock with trusted Bitcoin tooling, then complete a
recovery rehearsal before funding. Never paste a private key or seed phrase
into this app.
