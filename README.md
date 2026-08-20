# Mimir

Mimir is a one-page, offline visual builder for guarded Bitcoin recovery
policies. Add up to five compressed public keys, then build up to five spending
paths by dragging or clicking **Key**, **Multisig**, and **Time delay** blocks.
The exact P2WSH Miniscript, Bitcoin Script ASM, and address update live.

## Guarded paths

Every saved path says who can spend, how many signatures are required, and
optionally from which absolute UTC calendar date. Any one complete path can
unlock the Bitcoin:

```text
PATH A OR PATH B OR ... OR PATH E
```

Mimir keeps the visual workflow flexible while accepting only combinations it
can compile through a small deterministic model:

- paths whose signer sets are disjoint become independent OR branches;
- paths may reuse the **exact same signer set** when their thresholds strictly
  decrease as their dates strictly increase, forming one recovery ladder; and
- partially overlapping signer sets are rejected with a compatibility reason.

This supports, for example, one disjoint owner path plus three paths over the
same three recovery keys: 3-of-3 from the first date, 2-of-3 from the second,
and 1-of-3 from the third. Dates are entered as calendar dates, not relative
durations such as “one year after funding.”

Keys remain available after a path is saved so an exact signer set can be used
again. `OWNER` and `RECOVERY` marks are visual labels only; the blocks inside a
saved path define the policy.

The interface provides:

- a five-key public-key registry;
- a click-and-drag palette with Key, Multisig, and Time delay blocks;
- one compact canvas for constructing and adding one path at a time;
- inline compatibility feedback before an invalid combination reaches output;
- optional public demo keys, clearly marked unsafe and blocked from address
  copying or JSON export;
- live exact Miniscript, Bitcoin Script ASM, native P2WSH address, descriptor,
  script bytes, invariants, warnings, and canonical JSON export; and
- Regtest and Signet selection.

Every public key is normalized to a 33-byte compressed secp256k1 point encoded
as 66 lowercase hexadecimal characters beginning with `02` or `03`. Mimir
accepts public data only—never private keys, seed phrases, extended keys,
fingerprints, or derivation paths.

The compiler canonicalizes inputs deterministically, requires sane Miniscript,
and compares every authored path with the symbolic satisfactions of the exact
generated Miniscript across every signer subset and relevant locktime boundary.
That bounded exhaustive check is a defense against compiler mistakes, not a
substitute for independent review or a recovery rehearsal.

The concise current contract is [`mimir_v5_spec.md`](mimir_v5_spec.md). Earlier
implemented contracts remain available as
[`mimir_v4_spec.md`](mimir_v4_spec.md),
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

The suite builds the deployable worker, renders the application shell, retains
the v1–v4 compiler suites, and verifies the v5 guarded compiler's
canonicalization, fail-closed compatibility checks, and exhaustive semantic
equivalence invariant.

## Safety status

Mimir emits native SegWit v0 P2WSH, not Taproot. It remains pre-mainnet preview
software. Reproduce every descriptor, script, address, threshold, timelock, and
path with trusted Bitcoin tooling, then complete a recovery rehearsal before
funding. Never paste a private key or seed phrase into this app.
