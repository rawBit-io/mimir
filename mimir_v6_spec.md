# Mimir v6 — Read-once Policy Normalizer

Status: pre-mainnet preview  
Template: `mimir-read-once-normalizer-v1`

This document describes only the implemented v6 page and compiler. Mimir is a
bounded P2WSH policy builder, not a general Miniscript editor.

## 1. User policy

The user registers at most five public keys and authors at most five
alternative spending paths. Each path contains:

- one to five distinct registered keys;
- an integer threshold `K`, where `1 <= K <= N`; and
- either no lock or one absolute UTC calendar-date lock.

Any one satisfied path can spend:

```text
PATH 1 OR PATH 2 OR ... OR PATH 5
```

A registered key may be selected again in any other visual path. Labels are
descriptive and do not grant spending rights.

## 2. Read-once acceptance rule

Mimir does not compile the paths as a literal OR of repeated branches. It first
evaluates their complete spending semantics, then searches for an equivalent
read-once expression. The supported normalized expression is recursively made
from:

- a single threshold or a time-decaying threshold ladder over one key set;
- `AND` of two expressions using disjoint emitted key sets; or
- `OR` of two expressions using disjoint emitted key sets.

The search can remove redundant conditions and factor common keys. For example:

```text
A OR (after(T) AND 2-of-3(A,B,C))
```

is equivalent to:

```text
A OR (after(T) AND 2-of-2(B,C))
```

Likewise, `(A AND B) OR (after(T) AND A AND C)` can factor `A` into one
check. Exact-set threshold ladders such as 3-of-3, then 2-of-3, then 1-of-3
remain supported.

Key reuse plus a different date is not, by itself, an acceptance guarantee.
The entire policy must have an equivalent sane read-once form. If no supported
form exists, compilation fails and no address is produced.

## 3. Page workflow

The single terminal-style page has four working areas:

1. `01 KEYS` accepts labels and compressed public keys.
2. `02 POLICY` provides MULTISIG, TIMELOCK, and reusable key blocks. The user
   selects a spending path, then clicks a block or drags it into that path. An
   individual key creates a signing block; adding another key turns it into
   multisig. `K` and date controls live inside the resulting block. Users do
   not manipulate Boolean AND or OR controls.
3. `03 SPENDING PATHS` enumerates the alternatives derived from the visual
   tree. The root is always OR. Within one branch, its timelock and signing
   condition are joined by AND.
4. `LIVE BITCOIN SCRIPT` shows the authored policy, normalization counts and
   notes, exact Miniscript, Script ASM, address, descriptor, script hex,
   checks, warnings, and export. Network selection sits beside the address
   artifact rather than in the page header.

Click, touch, and keyboard interaction provide the complete workflow; native
drag-and-drop is an additional desktop interaction. A key stays reusable in
every branch. MULTISIG and TIMELOCK can each occur at most once per branch.
`ADD SPENDING PATH` adds another alternative, up to five. Internally, paths are
joined by OR and a timelock is joined to its path's signing condition by AND.
An incomplete or unsupported tree remains editable but emits no address. There
is no separate compile or save button.

The address dropdown exposes Mainnet, Testnet, Signet, and Regtest. The demo
deliberately reuses Owner across four visual paths and
shows that thirteen visual key uses normalize to four emitted key checks. Demo
address copying and export are blocked.

## 4. Inputs and dates

| Item | Implemented rule |
|---|---|
| Keys | 1–5 complete registry entries |
| Visual paths | 1–5 |
| Keys per path | 1–5 distinct registered keys |
| Threshold | Integer `K`, `1 <= K <= N` |
| Label | Non-empty, unique ignoring case, at most 80 characters |
| Public key | Valid 33-byte compressed secp256k1 point, normalized to lowercase hex |
| Date | Whole-day Unix timestamp at 00:00:00 UTC |
| CLTV operand | `500000000 <= T <= 2147483647` and divisible by 86400 |
| Witness script | At most 3,600 bytes |

Labels and IDs are trimmed and NFC-normalized. Public-key validation accepts
outer whitespace and uppercase hex, then stores lowercase canonical hex.
Private keys, seed phrases, WIF, x-only or uncompressed keys, extended keys,
fingerprints, and derivation paths are outside the input model.

The compiler accepts supported historical dates for reproducibility. The page
requires a future date for newly authored paths and caps the picker at
`2038-01-19`. If an open page crosses a saved unlock date, exact artifacts stay
visible for review, while address copying and export are blocked. Export
rechecks the current UTC date at click time.

## 5. Compiler request

`compileReadOncePolicy()` accepts:

```json
{
  "format": "mimir-read-once-policy-request",
  "version": 6,
  "network": "regtest",
  "template_id": "mimir-read-once-normalizer-v1",
  "keys": [
    {
      "id": "owner",
      "label": "Owner",
      "public_key": "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    }
  ],
  "paths": [
    {
      "key_ids": ["owner"],
      "threshold": 1,
      "unlock_unix": null
    }
  ]
}
```

Compiler networks are `bitcoin`, `testnet`, `signet`, and `regtest`. Caller key
IDs are references and do not survive
canonicalization. Complete unused keys are retained in the manifest and
reported in a warning.

## 6. Deterministic normalization

The compiler:

1. validates and canonically sorts keys and paths;
2. builds the authored truth table for every signer subset at every authored
   time stage;
3. removes keys that do not affect that truth table;
4. tries deterministic threshold-ladder, OR-partition, and AND-partition
   decompositions;
5. asks the Miniscript compiler to reject candidates that are not sane at the
   top level and sublevel;
6. selects the smallest accepted script, with lexical tie-breaking;
7. confirms that every emitted public key occurs at most once; and
8. compares symbolic satisfactions of the actual Miniscript with the authored
   policy at every signer subset and every authored or emitted lock boundary.

With at most five keys, the signer-space check is exhaustive. Sampling both
`T-1` and `T` catches an emitted timelock that activates early or late. The
symbolic witness check rejects unmodelled relative locks, witness secrets,
duplicate signatures, and unknown keys.

The result is deterministic for the same semantic request. Key and path input
order and caller key IDs do not change the script or canonical manifest.

## 7. Output

Successful compilation returns:

- normalized request and version-6 canonical manifest;
- authored paths and a normalization tree;
- authored key-use count, emitted key-check count, eliminated keys, and notes;
- exact Miniscript and Bitcoin Script ASM;
- checksummed `wsh(...)` descriptor;
- witness script, witness program, and scriptPubKey hex;
- network-specific native P2WSH address;
- SHA-256 of the exact canonical manifest bytes;
- invariants and operational warnings.

Address prefixes are `bc1q` for Mainnet, `tb1q` for Testnet and Signet, and
`bcrt1q` for Regtest. Network is recorded in the manifest and never changes the
witness script. Testnet and Signet deliberately produce the same address for
the same script because both use the `tb` human-readable prefix.
Labels and unused keys are manifest data, so they may change the manifest hash
without changing the script.

## 8. Safety boundary

Mimir emits native SegWit v0 P2WSH, not Taproot. A delayed spend requires
transaction `nLockTime` at least equal to the active timestamp and a non-final
`nSequence` on the input executing the Mimir witness script. Bitcoin evaluates
timestamp locks using median time past, so practical activation can occur
after the displayed UTC midnight.

The semantic comparison is a bounded compiler check, not Bitcoin Script
execution or a proof that unrelated dependencies are correct. The address is
an output artifact; the planned Bitcoin Core command, OP_RETURN encoding, and
dust transaction workflow are not implemented in v6. Mimir does not construct
transactions, sign, broadcast, monitor funds, derive child keys, or rotate
addresses. Independently reproduce and test the exact descriptor, script,
address, and recovery procedure before funding.
