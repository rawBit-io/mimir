# Mimir v3 — Independent Rule Policy Specification

Status: pre-mainnet preview

Template ID: `mimir-rules-v3`

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY**
are normative.

## 1. Scope and compatibility

Mimir v3 builds one native SegWit v0 P2WSH policy from independent spending
rules. A rule selects one public key or a K-of-N public-key group and MAY add
one absolute calendar-date lock. The completed policy is:

```text
RULE_1 OR RULE_2 OR ... OR RULE_N
```

Each rule is a complete alternative spending path. A rule is not intrinsically
an owner or heir rule; owner/heir marks in the interface are visual organization
only. A key affects the compiled policy only when a rule references it.

This specification defines the `mimir-rules-v3` template. It MUST NOT change,
reinterpret, or silently migrate the immutable v1
`mimir-absolute-two-path-v1` or v2 `mimir-kofn-two-path-v2` contracts.

## 2. Request envelope

A v3 compiler request MUST have this shape:

```json
{
  "format": "mimir-rule-request",
  "version": 3,
  "network": "regtest",
  "template_id": "mimir-rules-v3",
  "keys": [
    {
      "id": "key-01",
      "label": "Owner desk key",
      "public_key": "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    },
    {
      "id": "key-02",
      "label": "Heir east",
      "public_key": "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    }
  ],
  "rules": [
    {
      "key_ids": ["key-01"],
      "threshold": 1,
      "unlock_unix": null
    },
    {
      "key_ids": ["key-02"],
      "threshold": 1,
      "unlock_unix": 1893456000
    }
  ]
}
```

`format`, `version`, and `template_id` MUST equal the values above. `network`
MUST be `bitcoin`, `signet`, or `regtest`; the compiler MUST reject any other
network. The pre-mainnet web interface MUST expose only `signet` and `regtest`.
Core `bitcoin` support is retained for compatibility, deterministic vectors,
and non-UI callers.

Input rules MUST NOT contain caller-selected rule IDs. Canonical rule identity
and order are compiler outputs derived from rule content.

## 3. Public-key registry

The registry MUST contain between 1 and 20 entries. Each entry MUST have:

- a non-empty NFC-normalized `id` of at most 64 characters;
- a non-empty NFC-normalized `label` of at most 80 characters; and
- a canonical compressed secp256k1 public key.

The public key MUST be exactly 33 bytes encoded as 66 hexadecimal characters,
begin with `02` or `03`, represent a valid curve point, and normalize to
lowercase. Private keys, WIF, seed phrases, x-only keys, uncompressed keys, and
extended keys MUST be rejected.

IDs, case-insensitive labels, and normalized public keys MUST each be unique.
For deterministic output, the compiler MUST sort registry entries
lexicographically by normalized public key. It MUST assign the resulting keys
canonical IDs `key-01`, `key-02`, and so on, then rewrite every rule reference
to the corresponding canonical ID. Caller ordering, caller-selected IDs, and
volatile interface row IDs MUST NOT affect output.

A registered key MAY be unused. It MUST then be absent from every script
fragment and reported in a warning.

## 4. Rule contract and limits

The request MUST contain between 1 and 10 rules. Each rule MUST contain:

```json
{
  "key_ids": ["key-01"],
  "threshold": 1,
  "unlock_unix": null
}
```

- `key_ids` MUST contain between 1 and 10 unique registry key IDs.
- Every referenced ID MUST resolve to a registry entry.
- `threshold` MUST be an integer `K` satisfying `1 <= K <= N`, where `N` is
  the number of keys in the rule.
- `unlock_unix` MUST be `null` for no time delay or a valid calendar-date Unix
  timestamp as defined in Section 5.

The same key MUST NOT appear in more than one rule. This restriction keeps each
alternative branch independent and prevents combinations that fail the frozen
Miniscript sanity requirements. A key MAY participate with other keys in one
multisig rule, but it is then unavailable to all other rules.

A one-key rule MUST have threshold 1. A rule with multiple keys represents a
K-of-N multisig path, including the valid 1-of-N case.

## 5. Calendar-date locks

A delayed rule MUST use an integer Unix timestamp in this inclusive range:

```text
500000000 <= unlock_unix <= 2147483647
```

It MUST also be exactly divisible by `86400`. This fixes the time to
`00:00:00 UTC` and prevents locale, time-zone, and time-of-day ambiguity. The
web interface MUST accept a calendar date, not a date-time input, and MUST map
`YYYY-MM-DD` to that date at midnight UTC.

An undelayed rule MUST use `null`; zero, missing sentinel values, and ambiguous
strings MUST NOT mean “no delay.” The upper bound is the Miniscript `after()`
limit and corresponds to `2038-01-19T03:14:07Z`; because v3 locks are midnight
UTC, the latest selectable delayed date is the last midnight not exceeding
that bound.

Delayed rules compile to absolute `OP_CHECKLOCKTIMEVERIFY` conditions. A spend
MUST set transaction `nLockTime` high enough and use a non-final input sequence.
Timestamp locks follow Bitcoin median-time-past semantics; the displayed date
does not guarantee block inclusion at wall-clock midnight.

## 6. Rule fragments

Within a rule, public keys MUST be sorted in ascending normalized byte/hex
order. Let `P(R)` be that ordered list and `K(R)` its threshold. The signing
fragment is:

```text
S(R) = pk(P0)                    when K = 1 and N = 1
S(R) = multi(K,P0,P1,...,PN-1)  otherwise
```

The complete rule fragment is:

```text
F(R) = S(R)                              when unlock_unix is null
F(R) = and_v(v:after(unlock_unix),S(R))  otherwise
```

`pk()` MUST be used only for the 1-of-1 special case. Every multi-key rule,
including 1-of-N, MUST use `multi()`.

## 7. Canonical rule ordering and OR construction

The compiler MUST derive each rule’s full `miniscript_fragment` before assigning
its canonical position. Rules MUST be sorted lexicographically by that exact
fragment, independent of request order. The manifest MUST then assign IDs
`rule-01`, `rule-02`, and so on in canonical order. Canonically equivalent
requests MUST therefore produce byte-identical normalized requests, manifests,
Miniscript, scripts, descriptors, addresses, and hashes.

For one rule, the complete Miniscript MUST be its fragment:

```text
F(R1)
```

For two or more rules, the compiler MUST combine the canonically sorted
fragments using a single frozen nesting direction and `or_i` only. Given the
ordered fragments `F1 ... Fn`, the construction is:

```text
OR(F1)          = F1
OR(F1,F2,...Fn) = or_i(F1,OR(F2,...Fn))
```

For three rules this is exactly:

```text
or_i(F1,or_i(F2,F3))
```

The compiler MUST NOT flatten, rebalance, commute, or substitute another OR
operator. The descriptor body MUST be `wsh(<exact-miniscript>)` and MUST receive
the standard descriptor checksum.

## 8. Compilation and artifacts

The compiler MUST require Miniscript sanity at both top and sublevels and MUST
reject a witness script larger than the 3,600-byte P2WSH standardness limit.

A successful compilation MUST produce:

- the normalized request with canonical keys and rules;
- each canonical rule and its exact Miniscript fragment;
- the complete nested Miniscript;
- the checksummed `wsh(...)` descriptor;
- compiled Bitcoin Script ASM;
- witness-script hex and byte length;
- `SHA256(witness_script)` as the 32-byte witness program;
- scriptPubKey hex `0020 || witness_program`;
- a network-specific SegWit v0 Bech32 address;
- a canonical v3 policy manifest and SHA-256 digest;
- internal invariant results; and
- operator warnings.

Address human-readable parts MUST be `bc` for mainnet, `tb` for signet, and
`bcrt` for regtest. Network selection MUST change only network-specific output,
not an otherwise identical witness script.

The manifest MUST use:

```text
format      = "mimir-rule-policy"
version     = 3
template_id = "mimir-rules-v3"
```

It MUST include normalized keys, canonical rules and fragments, full
Miniscript, descriptor body and checksum, script artifacts, address, and
network. JSON canonicalization MUST be deterministic. The policy manifest hash
MUST be `SHA256(UTF8(canonical_manifest))`.

## 9. Internal invariants and warnings

Before returning valid output, the compiler MUST verify at least:

- canonical registry-key order and canonical key references;
- deterministic canonical rule ordering;
- unique key use across rules;
- satisfiable thresholds and rule-size limits;
- date-only lock range and midnight divisibility;
- Miniscript top-level and sublevel sanity;
- descriptor checksum correctness;
- witness-program hash and scriptPubKey construction;
- address encoding for the selected network;
- witness-script standardness size; and
- reproducible canonical manifest hashing.

A failed invariant MUST stop output rather than downgrade to a warning.

Warnings MUST explain that raw public keys produce one fixed P2WSH address with
no child derivation or rotation and that users must independently verify the
policy. A policy containing untimed rules MUST warn that they are immediately
available. A policy containing timed rules MUST explain that those rules remain
available after their dates, use median time past, and need adequate
`nLockTime` plus a non-final input sequence. Unused registry keys MUST be named
in a warning. Mainnet compilation MUST carry an explicit preview-grade warning.

## 10. One-page live interface

The default v3 interface MUST keep the unified signer list, **NEW RULE** editor,
**YOUR RULES** list, validation feedback, and **LIVE BITCOIN SCRIPT** result on
one page.

The signer list MUST allow adding, editing, and removing up to 20 entries. Each
row MUST show an owner/heir visual mark. That mark MUST NOT silently add a key
to a compiled rule or change the compiler semantics in Sections 4–7.

The rule editor MUST let the user:

1. choose a single key;
2. optionally enable **Multisig**, select up to 10 currently unused keys, and
   choose a valid K-of-N threshold;
3. optionally enable **Time delay** and select a calendar date; and
4. use **ADD RULE** to append the completed rule.

For new policies, the web interface MUST require a delayed rule's date to be
later than the current UTC calendar date. The compiler MUST continue accepting
valid historical date locks so existing policies can be independently
reproduced and verified after their locks expire.

Used keys MUST be unavailable for subsequent rules. The interface MUST permit
removing a rule and returning its keys to the available set. It MUST show at
most 10 rules and MUST make the final `Rule 1 OR Rule 2 OR ...` relationship
clear.

Compilation MUST update dynamically after adding or removing a rule or changing
the network. There MUST be no explicit compile button. Valid current state MUST
show exact Miniscript and Bitcoin Script ASM. Advanced output MAY remain
collapsed under **Technical details**. JSON export MUST be enabled only for the
current valid `canonical_manifest` and MUST be removed or disabled immediately
when no valid current policy exists.

Incomplete or invalid input MUST show a placeholder or specific actionable
message. The interface MUST NOT present stale or partial artifacts as a valid
policy. All essential controls MUST be keyboard operable, have visible focus,
expose accessible names, and use touch-friendly targets. The layout SHOULD
remain usable at a 320 CSS-pixel viewport width.

## 11. Fail-closed validation

The compiler MUST stop without policy output for at least:

- malformed, non-canonical, private, extended, x-only, uncompressed, or
  off-curve key material;
- duplicate IDs, labels, or public keys;
- an empty registry, more than 20 registry keys, no rules, or more than 10
  rules;
- an empty rule, more than 10 keys in a rule, duplicate or unknown rule key
  references, or a key reused across rules;
- a non-integer, zero, negative, or greater-than-N threshold;
- a non-null lock that is non-integer, out of range, or not divisible by
  `86400`;
- caller-supplied or otherwise unsupported rule identity/state;
- unsupported networks, formats, versions, or template IDs;
- Miniscript compiler errors or failed internal invariants; and
- a witness script above the 3,600-byte limit.

Errors SHOULD identify the affected rule or field without exposing partial
output as valid.

## 12. Privacy and execution boundary

Mimir MUST accept public data only. It MUST NOT request, derive, store, or
transmit private keys, seed phrases, signatures, or wallet secrets. It MUST NOT
construct, sign, or broadcast transactions.

Policy state MUST remain in volatile page memory. The application MUST NOT use
browser storage, analytics, telemetry, or a backend for policy state. Runtime
network connections MUST be disabled by content security policy; compiler code,
styles, fonts, icons, and required assets MUST be local.

## 13. Deferred work and release gates

The following are outside v3 and MUST NOT be implied by valid output:

- arbitrary nested graphs beyond the frozen OR-of-rules construction;
- AND relationships between independently authored rules;
- relative timelocks, hashlocks, Taproot, Tapscript, MuSig, or FROST;
- time-of-day or non-UTC date locks;
- repeated keys across branches;
- child-key derivation or rotating address sets; and
- transaction construction, signing, broadcasting, or monitoring.

Before v3 may be described as production-ready, a release MUST include
independent security and Miniscript review, pinned Bitcoin Core differential
vectors, regtest spends for every fragment class and OR position, lock and
threshold boundary tests, deterministic export tests, fail-closed coverage,
reproducible signed builds, and documented funding and recovery rehearsals.

All mainnet output remains preview-grade. Users SHOULD independently reproduce
the exact rules, Miniscript, descriptor, script, address, thresholds, and locks
with trusted Bitcoin tooling and complete a multi-party recovery rehearsal
before funding.
