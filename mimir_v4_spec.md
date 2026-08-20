# Mimir v4 — Implemented 5×5 Recovery Template

Status: pre-mainnet preview

Template: `mimir-recovery-5x5-v1`

This document describes the focused Mimir application and compiler as
implemented. It is intentionally not a general policy editor.

## 1. Fixed policy shape

A policy contains two disjoint signer groups and no more than five signers:

- **Primary:** one immediate `P-of-N` spending path.
- **Recovery:** `M` dated paths over the same `M` Recovery signers, beginning
  with `M-of-M` and decreasing by one signature at every later date until
  `1-of-M`.

The complete policy is:

```text
Primary P-of-N now
OR Recovery M-of-M from T1
OR Recovery (M-1)-of-M from T2
...
OR Recovery 1-of-M from TM
```

There is at least one signer in each group. A signer belongs to exactly one
group. Because `N + M <= 5`, the policy has `1 + M <= 5` logical paths.
Recovery thresholds are derived by the template and cannot be edited
independently.

Recovery dates are absolute Unix timestamp locks at `00:00:00 UTC`, strictly
increase from `T1` through `TM`, and remain usable after activation. The Primary
path remains available at every date.

## 2. One-page workflow

1. Enter a unique label and compressed public key for each signer.
2. Assign every signer to Primary or Recovery.
3. Choose the number of Primary signatures `P`.
4. Choose one UTC calendar date for each automatically derived Recovery stage.
5. Review the live natural-language paths, exact Miniscript, Bitcoin Script
   ASM, P2WSH address, and technical details.

There is no free-form rule canvas, rule-order control, compile button, or
drag-and-drop composition. Changes compile live. The web interface exposes
Regtest and Signet. **Load demo keys** fills all five slots with publicly known
keys for an immediate example; the page marks that address unsafe and disables
JSON export until every demo key is replaced.

## 3. Inputs and limits

| Item | Implemented rule |
|---|---|
| Total signers | 2–5 |
| Primary signers | At least 1 |
| Recovery signers | At least 1, at most 4 |
| Primary threshold | Integer `P`, `1 <= P <= N` |
| Recovery paths | Exactly `M`, derived from `M-of-M` to `1-of-M` |
| Labels | Non-empty, unique ignoring case, at most 80 characters |
| Public keys | Unique valid compressed secp256k1 points: `02` or `03` plus 64 hex characters |
| Recovery dates | Exactly `M` strictly increasing whole UTC days |
| Witness script | At most 3,600 bytes |

Labels and IDs are trimmed and NFC-normalized. Public keys are normalized to
lowercase and validated as curve points. Private keys, seed phrases, WIF,
x-only or uncompressed keys, extended keys, fingerprints, and derivation paths
are not accepted.

The compiler accepts supported whole-day timestamps needed to reproduce an
existing policy. The interface requires future dates for newly created
policies and caps its date picker at `2038-01-19`.

## 4. Compiler request

`compileRecoveryTemplate()` accepts:

```json
{
  "format": "mimir-recovery-request",
  "version": 4,
  "network": "regtest",
  "template_id": "mimir-recovery-5x5-v1",
  "signers": [
    {
      "id": "owner",
      "label": "Owner",
      "public_key": "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      "group": "primary"
    },
    {
      "id": "recovery-1",
      "label": "Recovery 1",
      "public_key": "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
      "group": "recovery"
    }
  ],
  "primary_threshold": 1,
  "recovery_dates": [1818720000]
}
```

Supported compiler networks are `bitcoin`, `signet`, and `regtest`; generic
Bitcoin testnet is not supported. Mainnet exists for deterministic core
compatibility but is not exposed by the preview interface.

`recovery_dates` contains exactly one integer Unix timestamp for each Recovery
signer. Each timestamp is in the CLTV timestamp range and divisible by `86400`.

## 5. Deterministic script construction

Primary and Recovery keys are separately sorted by normalized public key. The
Primary fragment is:

```text
pk(KEY)                    when N = 1
multi(P,KEY_1,...,KEY_N)   when N > 1
```

For one Recovery signer, the Recovery fragment is:

```text
and_v(v:after(T1),pk(KEY))
```

For `M > 1`, the compact recovery ladder is:

```text
and_v(
  v:after(T1),
  thresh(M,
    pk(KEY_1),s:pk(KEY_2),...,s:pk(KEY_M),
    sln:after(T2),...,sln:after(TM)
  )
)
```

At `T1`, all `M` key checks are required. Each later timelock contributes one
threshold credit, so the required signatures decrease deterministically to one
at `TM`. The complete Miniscript is the fixed two-branch expression:

```text
or_i(PRIMARY_FRAGMENT,RECOVERY_FRAGMENT)
```

The descriptor body is `wsh(<exact Miniscript>)`. Compilation fails closed if
input validation, Miniscript top-level or sublevel sanity, internal artifact
checks, semantic equivalence, or the witness-script size limit fails.

Canonicalization sorts signers, assigns canonical signer IDs, and serializes a
stable manifest. Caller-selected IDs and signer input order do not change the
witness script or canonical result for the same semantic policy.

## 6. Exhaustive semantic check

The compiler obtains every symbolic witness satisfaction of the exact generated
Miniscript, then evaluates them against the authored policy:

1. the authored paths are Primary `P-of-N`, or any active Recovery `K-of-M`;
2. the symbolic satisfactions provide the signature set and `nLockTime`
   required by each witness shape of the emitted Miniscript.

It compares them for every subset of the policy's signers immediately before
and at every authored or symbolically emitted locktime. With at most five
signers and four correct Recovery locktimes, this is at most
`2^5 × 8 = 256` comparisons. Sampling emitted boundaries also makes an
accidentally early or late generated lock fail closed. The compiled result
records the `exhaustive-policy-equivalence` invariant and comparison count
alongside the manifest.

This exhaustively links the authored Boolean policy to the generated
Miniscript's symbolic satisfactions for the concrete input. It is not Bitcoin
Script execution, does not prove the absence of implementation defects outside
that model, and does not replace independent Bitcoin-tool verification.

## 7. Live output and export

For a valid policy the page shows:

- all logical paths in plain language;
- exact Miniscript and Bitcoin Script ASM;
- the network-specific native P2WSH address;
- the checksummed descriptor, witness script, scriptPubKey, manifest SHA-256,
  invariant results, warnings, and canonical JSON download.

The manifest format is `mimir-recovery-policy`, version `4`, using template
`mimir-recovery-5x5-v1`. It records normalized signers, Primary threshold,
derived Recovery paths and dates, exact script artifacts, and network. The
compiled result carries invariant results and warnings alongside that manifest.
The downloaded bytes are the same canonical JSON bytes used for the displayed
manifest hash.

Address prefixes are `bc1q` for mainnet, `tb1q` for Signet, and `bcrt1q` for
Regtest. Network selection changes the address and manifest, not the witness
script. Labels are also manifest data, so a label edit can change the manifest
hash without changing the script. Invalid or incomplete input removes valid
artifacts and displays an actionable state instead of stale output.

## 8. Timelock, privacy, and safety boundary

Recovery dates compile to absolute `OP_CHECKLOCKTIMEVERIFY` conditions. A
Recovery spend needs transaction `nLockTime` at least equal to the active date
and a non-final `nSequence` on the specific transaction input spending the
Mimir output. Bitcoin evaluates timestamp locks using median time past, so
practical activation can be later than displayed.

Mimir handles public policy data only. It does not persist policy state, use
analytics, construct or sign transactions, broadcast, or monitor funds. The
production content security policy disables outbound runtime connections.

Raw public keys produce one fixed address; Mimir does not derive or rotate
child keys. This remains preview software. Reproduce the complete policy with
trusted Bitcoin tooling and rehearse it on Regtest or Signet before funding.
