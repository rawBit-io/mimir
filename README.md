# Mimir

Mimir is a one-page, offline builder for a deliberately small Bitcoin recovery
template. Add up to five compressed public keys, assign each signer to the
functional **Primary** or **Recovery** group, choose the immediate Primary
threshold, and set the staged Recovery dates. The exact P2WSH Miniscript,
Bitcoin Script ASM, and address update live.

## The 5×5 template

Every policy has one immediate Primary path and one Recovery path per Recovery
signer, for no more than five signers and five paths in total:

```text
Primary:  P of N primary signers can spend now
Recovery: M of M recovery signers can spend from date 1
          M-1 of M recovery signers can spend from date 2
          ...
          1 of M recovery signers can spend from date M
```

Recovery dates are absolute UTC calendar dates at `00:00:00`, must be strictly
increasing, and remain available after they become active. Primary and Recovery
are disjoint signer groups; the labels change real spending conditions.

For example, one Primary signer plus four Recovery signers produces five paths:
the Primary path now, then 4-of-4, 3-of-4, 2-of-4, and 1-of-4 Recovery paths at
four later dates. Thresholds in the recovery ladder are fixed by the template,
which removes the free-form rule-combination problem.

The interface provides:

- one editable signer list containing only labels and compressed public keys;
- functional Primary/Recovery assignment and a Primary P-of-N selector;
- a Recovery timeline with one UTC date per automatically derived threshold;
- optional public demo keys for an instant example, clearly marked unsafe and
  blocked from JSON export;
- live exact Miniscript, Bitcoin Script ASM, P2WSH address, descriptor, script
  bytes, invariants, warnings, and canonical JSON export; and
- Regtest and Signet selection.

Every key is trimmed and normalized to a 33-byte compressed secp256k1 public
key encoded as 66 lowercase hexadecimal characters and beginning with `02` or
`03`. Mimir accepts public data only—never private keys, seed phrases, extended
keys, fingerprints, or derivation paths.

The compiler canonicalizes keys and inputs deterministically, requires sane
Miniscript, and exhaustively compares the intended template with the generated
Miniscript's symbolic satisfactions for every signer subset and relevant time
boundary. With at most five signers and four Recovery locktimes, that check
covers at most 256 signer/time cases. It is a defense against compiler mistakes,
not a substitute for independent review or a recovery rehearsal.

The concise current contract is [`mimir_v4_spec.md`](mimir_v4_spec.md). Earlier
implemented contracts remain available as
[`mimir_v3_spec.md`](mimir_v3_spec.md),
[`mimir_v2_spec.md`](mimir_v2_spec.md), and
[`mimir_spec.md`](mimir_spec.md).

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

The suite builds the deployable worker, renders the application shell, verifies
deterministic v1–v4 compiler behavior and fail-closed validation, and checks the
5×5 template's exhaustive semantic equivalence invariant.

## Safety status

Mimir remains pre-mainnet software. Reproduce every descriptor, script,
address, threshold, timelock, and path with trusted Bitcoin tooling, then
complete a recovery rehearsal before funding. Never paste a private key or seed
phrase into this app.
