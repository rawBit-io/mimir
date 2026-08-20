# Mimir v5 — Guarded Visual Composer

Status: pre-mainnet preview

Template: `mimir-guarded-rules-v1`

This document describes the implemented v5 application and compiler. Mimir is
not a general Miniscript editor: it presents a small visual vocabulary and
rejects rule combinations outside the guarded model.

## 1. Policy model

Mimir builds one native SegWit v0 P2WSH policy from no more than five public
keys and five authored spending paths:

```text
PATH A OR PATH B OR ... OR PATH E
```

Satisfying any one complete path is enough to spend. Each path contains:

- one key, or a `K-of-N` signer set selected with a Multisig block; and
- optionally, one absolute UTC calendar-date lock selected with a Time delay
  block.

Owner and Recovery marks organize the interface visually. They do not grant,
delay, or revoke spending rights. Only the blocks saved in a path enter the
compiler.

## 2. Compatibility guard

The compiler partitions authored paths by their complete signer set. It accepts
only these relationships:

1. **Disjoint signer sets.** Groups that share no keys compile as independent
   OR branches.
2. **Exact signer-set reuse.** Multiple paths over the identical key set compile
   as one staged ladder. In chronological order, dates must strictly increase
   and signature thresholds must strictly decrease.

Any partial overlap is rejected. For example, `{A,B,C}` and `{B,C}` cannot be
combined, while `{A,B,C}` may be reused by 3-of-3, 2-of-3, and 1-of-3 dated
paths. Duplicate paths, equal dates, unchanged or increasing thresholds, and a
later immediate path are also rejected.

This guard lets a key remain selectable after it appears in a saved path while
ensuring every accepted reuse has one deterministic Miniscript construction.
It is deliberately narrower than arbitrary Miniscript composition.

## 3. One-page workflow

1. Enter a label and compressed public key for each signer.
2. Drag or click the required Key blocks into **PATH CANVAS**.
3. For multiple keys, add the single Multisig block and choose `K`.
4. Optionally add the single Time delay block and choose a UTC date.
5. Add the path, then repeat for another spending alternative.
6. Review compatibility feedback, the natural-language path list, exact
   Miniscript, Bitcoin Script ASM, address, and technical details.

The page constructs one path at a time. Multisig and Time delay can each occur
at most once in the draft; removing one returns it to the palette. A key cannot
occur twice inside one path, but saved use never disables its palette block.
Changes compile live without a separate compile step.

The interface exposes Regtest and Signet. **Load demo** provides an instant
public example; demo-derived artifacts are visibly unsafe, and the resulting
address cannot be copied or the policy exported.

## 4. Inputs and limits

| Item | Implemented rule |
|---|---|
| Registered keys | 1–5 complete entries at compilation |
| Authored paths | 1–5 |
| Keys in one path | 1–5 distinct registered keys |
| Threshold | Integer `K`, `1 <= K <= N` |
| Signer-set relationship | Identical or disjoint; partial overlap rejected |
| Exact-set ladder | Thresholds strictly decrease as dates strictly increase |
| Label | Non-empty, unique ignoring case, at most 80 characters |
| Public key | Valid compressed secp256k1 point: `02` or `03` plus 64 hex characters |
| Delay | Whole-day Unix timestamp in the CLTV timestamp range |
| Witness script | At most 3,600 bytes |

Labels and IDs are trimmed and NFC-normalized. Public keys are normalized to
lowercase and validated as curve points. Private keys, seed phrases, WIF,
x-only or uncompressed keys, extended keys, fingerprints, and derivation paths
are not accepted.

The page sends every complete editor row to the live compiler. A complete
unused key does not change the script, but it is recorded in the manifest and
reported in a warning; an incomplete unused editor row is omitted.

Dates compile as absolute Unix timestamp locks at `00:00:00 UTC`. The compiler
accepts supported historical whole-day timestamps to reproduce an existing
policy; the interface requires a future date for a new path and caps its picker
at `2038-01-19`.

## 5. Compiler request

`compileGuardedRulePolicy()` accepts:

```json
{
  "format": "mimir-guarded-rule-request",
  "version": 5,
  "network": "regtest",
  "template_id": "mimir-guarded-rules-v1",
  "keys": [
    {
      "id": "owner",
      "label": "Owner",
      "public_key": "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    }
  ],
  "rules": [
    {
      "key_ids": ["owner"],
      "threshold": 1,
      "unlock_unix": null
    }
  ]
}
```

Supported compiler networks are `bitcoin`, `signet`, and `regtest`; generic
Bitcoin testnet is not supported. Mainnet exists for deterministic core
compatibility but is not exposed by the preview interface.

Key IDs are local references. The normalized v5 path schema contains no caller
path ID or other policy state. `unlock_unix` is exactly `null` for an immediate
path or a whole-day integer timestamp for a delayed path. Complete unused
registry keys are allowed and reported in a warning.

## 6. Deterministic construction

Keys inside each signer set are sorted by normalized public key. A group used
by one authored path compiles directly as:

```text
pk(KEY)                    for one key
multi(K,KEY_1,...,KEY_N)   for multiple keys
and_v(v:after(T),SIGNING)  when the path has a date
```

For an exact signer set reused by multiple paths, the compiler sorts its stages
chronologically. The earliest threshold is the base of a `thresh(...)`
expression. Every later locktime contributes the precise number of threshold
credits required by that stage's decrease; an earliest dated stage supplies an
outer `after(...)` guard. Consequently every public key appears only once in
the emitted Miniscript even when its signer set is authored several times.

Disjoint groups are sorted by their canonical signer-set keys and joined with a
fixed right-nested `or_i` expression. The descriptor body is `wsh(<exact
Miniscript>)`. This is P2WSH; v5 does not use Taproot or a Taproot script tree.

The compiler sorts registry keys, assigns canonical key, path, and group IDs,
and serializes a stable manifest. Caller IDs, input order, and authored path
order do not change the witness script or canonical result for the same
semantic policy.

Compilation fails closed if validation, the compatibility guard, Miniscript
top-level or sublevel sanity, internal artifact checks, the semantic check, or
the witness-script size limit fails.

## 7. Exhaustive semantic check

The compiler requests the symbolic satisfactions of the **actual generated
Miniscript**. It evaluates those witness shapes against the authored paths for:

- every subset of the policy's at most five signers; and
- immediately before and at every authored or emitted locktime boundary.

For every case, the authored policy and generated Miniscript must agree on
whether spending is possible. Sampling emitted boundaries also makes an
accidentally early or late generated lock fail closed. The compiled result
records the exhaustive policy-equivalence invariant and comparison count.

This bounded exhaustive comparison links the concrete authored policy to the
generated Miniscript's symbolic satisfaction model. It is not Bitcoin Script
execution, does not prove unrelated implementation code correct, and does not
replace verification with independent Bitcoin tooling.

## 8. Live output and export

For a valid policy, the page shows:

- all authored paths and their compatibility relationship;
- exact Miniscript and Bitcoin Script ASM;
- the network-specific native P2WSH address;
- the checksummed descriptor, witness script, scriptPubKey, manifest SHA-256,
  invariant results, warnings, and canonical JSON download.

The canonical manifest uses version `5` and template
`mimir-guarded-rules-v1`. It records normalized keys, authored paths, derived
compatibility groups, exact script artifacts, and network. Downloaded bytes are
the same canonical JSON bytes used for the displayed manifest hash.

Address prefixes are `bc1q` for mainnet, `tb1q` for Signet, and `bcrt1q` for
Regtest. Network selection changes the address and manifest, not the witness
script. Labels and unused complete keys are manifest data, so editing them can
change the manifest hash without changing the script. Invalid or incomplete
input used by a saved path removes valid artifacts rather than displaying stale
output.

If a saved Delay reaches the current UTC date while the page remains open, the
exact artifacts stay visible for review, but the status is downgraded and
address copy and JSON export are blocked until that path is rebuilt. Export
rechecks the current UTC date at click time.

## 9. Timelock, privacy, and safety boundary

A delayed spend requires transaction `nLockTime` at least equal to its active
date and a non-final `nSequence` on the input spending the Mimir output. Bitcoin
evaluates timestamp locks using median time past, so practical activation can
be later than displayed. Once active, a delayed path remains active.

Mimir handles public policy data only. It does not persist policy state, use
analytics, construct or sign transactions, broadcast, or monitor funds. The
production content security policy disables outbound runtime connections. Raw
public keys produce one fixed address; Mimir does not derive or rotate child
keys.

Mimir remains preview software. Reproduce the complete descriptor, script,
address, thresholds, dates, and paths with trusted Bitcoin tooling and rehearse
the exact policy on Regtest or Signet before funding.
