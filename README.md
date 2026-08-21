# Mimir

Mimir is a one-page, offline, terminal-style builder for Bitcoin recovery
policies. Register up to five compressed public keys, then describe up to five
alternative spending paths by choosing signers, a `K-of-N` threshold, and an
optional absolute UTC date. The exact native P2WSH Miniscript, Bitcoin Script
ASM, address, and normalization result update live.

## Visual paths, read-once script

Users describe the policy naturally:

```text
PATH A OR PATH B OR ... OR PATH E
```

A public key may appear in several visual paths. On every tree change, Mimir
builds the complete Boolean policy and searches for an equivalent sane
Miniscript in which every public key check appears at most once. Common keys
are factored, redundant conditions are removed, and compatible threshold/date
ladders are collapsed automatically. If no verified read-once form is found,
the combination is rejected without producing an address.

For example:

```text
Owner
OR
after(T) AND 2-of-3(Owner, Recovery A, Recovery B)
```

normalizes to the equivalent policy:

```text
Owner
OR
after(T) AND 2-of-2(Recovery A, Recovery B)
```

The interface shows both the authored paths and the normalization result. It
does not ask the user to construct a Miniscript expression tree.

The compiler accepts only policies it can prove equivalent within its bounded
five-key/five-path model. It checks every signer subset at every authored and
emitted locktime boundary against the symbolic satisfactions of the generated
Miniscript, requires top-level and sublevel sanity, and verifies that each
emitted public key occurs once. This is a strong compiler guard, not a
substitute for independent Bitcoin tooling and a recovery rehearsal.

Key labels are descriptive only. The blocks, selected signers, threshold, and
date define spending. Dates are absolute calendar dates at `00:00:00 UTC`, not
relative durations from funding.

The current implementation provides:

- up to five valid compressed secp256k1 public keys;
- up to five alternative visual paths;
- a terminal policy canvas with a block palette and an implicit OR root;
- click, keyboard, touch, and native drag/drop placement for keys, multisig,
  timelock, AND, and OR controls;
- inline `K-of-N` and UTC-date configuration inside each branch;
- free reuse of a registered key across visual paths;
- fail-closed read-once normalization on every complete tree change;
- live exact Miniscript, Script ASM, P2WSH address, descriptor, script bytes,
  invariants, warnings, and canonical JSON export;
- Mainnet, Testnet, Signet, and Regtest selection beside the address artifact; and
- public demo keys that are visibly unsafe and blocked from address copying or
  JSON export.

Mimir accepts public data only—never private keys, seed phrases, extended keys,
fingerprints, or derivation paths. The concise current contract is
[`mimir_v6_spec.md`](mimir_v6_spec.md). Earlier implemented contracts remain in
the repository as historical specifications.

## Run locally

Node.js 22.13 or newer is required.

```bash
npm install
npm run dev
```

Open <http://localhost:3000>. If your system still uses Node 20:

```bash
npm exec --yes --package=node@22 -- npm run dev
```

All application code and assets are local. Policy state stays in volatile page
memory, and the production content security policy disables outbound network
connections.

## Validate

```bash
npm test
```

The suite builds the worker, renders the page, retains the v1–v5 compiler
tests, and verifies v6 normalization, canonical output, exact artifacts,
fail-closed rejection, and signer/time semantic equivalence.

## Safety status

Mimir emits native SegWit v0 P2WSH, not Taproot. The address is currently an
output artifact; Mimir does not yet build the planned Bitcoin Core funding
command, OP_RETURN payload, or dust transaction. It is preview software. Verify
the descriptor, script, address, threshold, timelocks, and recovery procedure
independently on Regtest or Signet before funding. Never paste a private key or
seed phrase into this app.
