# Mimir

Mimir is a one-page, offline Bitcoin recovery-script builder. Add direct
compressed public keys to one unified list, visually mark each signer as
`OWNER` or `HEIR`, then construct one independent spending rule at a time. The
exact Miniscript and Bitcoin Script ASM update live as rules change.

There is no compile button or wizard. The **NEW RULE** area has a block palette
and rule canvas; blocks can be dragged into the canvas or clicked for keyboard
and touch use. Incomplete or invalid input produces an actionable placeholder
instead of policy output.

## Current policy model

Each rule is built independently:

1. Drag one or more key blocks into the rule canvas.
2. For multiple keys, add the single **Multisig** block and set K-of-N inside it.
3. Optionally add the single **Time delay** block and choose a future date. Delayed
   rules use `00:00:00 UTC` on that date; Bitcoin median time past can make
   actual eligibility later.
4. Select **ADD RULE**.

Multisig and Time delay can each appear only once in a draft rule. Removing a
block returns it to the palette.

`OWNER` and `HEIR` marks are visual labels only. They do not change spending
conditions; a key is delayed only when its rule enables **Time delay**.

The final policy is an OR across every saved rule:

```text
Rule 1 OR Rule 2 OR ... OR Rule N
```

Mimir supports up to 20 registered keys, 10 rules, and 10 keys in a rule. A key
may appear in at most one rule because duplicating keys across independent
branches can violate Miniscript sanity. Every multisig threshold must satisfy
`1 <= K <= N`.

The web interface provides:

- one editable signer list with owner/heir visual marks;
- a draggable **NEW RULE** block palette and canvas with optional multisig and
  calendar-date delay;
- a **YOUR RULES** list and live exact Miniscript/Bitcoin Script ASM;
- regtest and signet selection;
- collapsed **Technical details** containing the checksummed descriptor,
  witness script, scriptPubKey, address, invariants, warnings, and manifest
  hash; and
- JSON manifest export whenever the current policy is valid.

Every key must be a canonical 33-byte compressed secp256k1 public key encoded
as 66 hexadecimal characters and beginning with `02` or `03`. Mimir accepts
public data only—never private keys, seed phrases, extended keys, fingerprints,
or derivation paths.

The v3 compiler retains `bitcoin`, `signet`, and `regtest` network support for
deterministic compatibility, while the pre-mainnet web UI intentionally exposes
only regtest and signet. The immutable v1 and v2 compilers and specifications
remain available for compatibility and regression coverage.

The concise implemented contract is [`mimir_v3_spec.md`](mimir_v3_spec.md).
Legacy contracts remain in [`mimir_spec.md`](mimir_spec.md) and
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
public-only and offline constraints, and verifies deterministic v1, v2, and v3
policy output and fail-closed validation.

## Safety status

Mimir remains pre-mainnet software. Reproduce every descriptor, script,
address, threshold, timelock, and branch with trusted Bitcoin tooling, then
complete a recovery rehearsal before funding. Never paste a private key or seed
phrase into this app.
