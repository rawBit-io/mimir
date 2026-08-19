# Mimir v2 — K-of-N Two-Path Policy Specification

Status: pre-mainnet preview

Template ID: `mimir-kofn-two-path-v2`

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY**
are normative.

## 1. Scope

Mimir v2 composes one native SegWit v0 P2WSH vault from two absolute-timelock
branches:

1. an owner K-of-N group, available at `T_OWNER`; and
2. an heir K-of-N group, available at `T_HEIR`.

The owner branch remains spendable after the heir branch unlocks. v2 is a
fixed template, not an arbitrary Bitcoin Script graph editor.

## 2. Input envelope

A compiler request MUST have this shape:

```json
{
  "format": "mimir-composer-request",
  "version": 2,
  "network": "regtest",
  "template_id": "mimir-kofn-two-path-v2",
  "keys": [
    {
      "id": "owner-01",
      "label": "Owner desk key",
      "public_key": "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    },
    {
      "id": "heir-01",
      "label": "Heir recovery key",
      "public_key": "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    }
  ],
  "owner": {
    "key_ids": ["owner-01"],
    "threshold": 1,
    "unlock_unix": 1893456000
  },
  "heirs": {
    "key_ids": ["heir-01"],
    "threshold": 1,
    "unlock_unix": 2051222400
  }
}
```

`network` MUST be exactly `bitcoin`, `signet`, or `regtest`. The compiler MUST
reject other formats, versions, template IDs, or networks.

## 3. Public-key registry

Each `keys` entry MUST contain:

```json
{
  "id": "owner-01",
  "label": "Owner desk key",
  "public_key": "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
}
```

- `public_key` MUST be a canonical 33-byte compressed secp256k1 point: exactly
  66 hexadecimal characters, beginning with `02` or `03`, and valid on the
  curve. It is normalized to lowercase.
- Private keys, WIF, seed phrases, x-only keys, uncompressed keys, xpubs, and
  other extended keys MUST be rejected as inputs.
- `id` and `label` MUST be non-empty NFC-normalized text without control
  characters. IDs MUST be no longer than 64 characters; labels MUST be no
  longer than 80 characters.
- IDs, case-insensitive labels, and public keys MUST each be unique across the
  registry.
- The registry MUST contain 1–20 keys. A registry key MAY remain unassigned;
  it MUST then be excluded from the policy and reported as a warning.

For deterministic export, registry entries MUST be ordered lexicographically
by normalized public key, with ID as the tie-breaker.

## 4. Group assignment and thresholds

The `owner` and `heirs` groups MUST each contain 1–10 unique registry key IDs.
Every ID MUST resolve to a registry entry. The same key ID MUST NOT appear in
both groups.

Each `threshold` MUST be an integer `K` satisfying `1 <= K <= N`, where `N` is
the number of keys assigned to that group.

The order in which keys are added, clicked, or dragged has no policy meaning.
Within each group, the compiler MUST sort normalized compressed public keys in
ascending lexicographic byte/hex order before constructing Miniscript. The
same registry and assignments MUST therefore compile identically despite UI or
JSON input ordering.

Examples include 1-of-1 owners plus 1-of-10 heirs, 2-of-3 owners plus 5-of-10
heirs, and the maximum 10-of-10 owners plus 10-of-10 heirs.

## 5. Absolute locks

`owner.unlock_unix` and `heirs.unlock_unix` MUST be integer Unix timestamps in
this inclusive range:

```text
500000000 <= T <= 2147483647
```

The upper bound is the Miniscript `after()` limit and corresponds to
2038-01-19T03:14:07Z. `T_OWNER` MUST be strictly less than `T_HEIR`. Each group
has exactly one common lock; v2 does not assign a different date to each key.

These values compile to absolute `OP_CHECKLOCKTIMEVERIFY` conditions. A spend
MUST set transaction `nLockTime` high enough and use a non-final input
sequence. Timestamp locks are subject to Bitcoin consensus median-time-past
semantics; a displayed UTC time is not a guarantee of inclusion at that wall
clock second.

## 6. Frozen policy construction

Let `P(G)` be the canonically sorted public keys of group `G`. Define:

```text
S(G) = pk(P0)                    when K = 1 and N = 1
S(G) = multi(K,P0,P1,...,PN-1)  otherwise
```

The exact v2 Miniscript, with no semantic variation, is:

```text
or_i(
  and_v(v:after(T_OWNER),S(OWNER)),
  and_v(v:after(T_HEIR),S(HEIRS))
)
```

Its serialized single-line form MUST be:

```text
or_i(and_v(v:after(T_OWNER),S(OWNER)),and_v(v:after(T_HEIR),S(HEIRS)))
```

For example, a 1-of-1 owner and 1-of-1 heir compile as:

```text
or_i(and_v(v:after(1893456000),pk(OWNER_KEY)),and_v(v:after(2051222400),pk(HEIR_KEY)))
```

A 2-of-3 owner group and 5-of-10 heir group use `multi(2,...)` and
`multi(5,...)` respectively. `pk()` MUST be used only for the 1-of-1 special
case; a 1-of-N group where `N > 1` MUST use `multi(1,...)`.

The descriptor body MUST be `wsh(<exact-miniscript>)` and MUST receive the
standard descriptor checksum. The compiler MUST require Miniscript sanity at
both top and sublevels and MUST reject a witness script larger than 3,600
bytes.

## 7. Compiled outputs

For a successful compile, Mimir MUST produce and display or export:

- exact Miniscript and checksummed `wsh(...)` descriptor;
- compiled script ASM and witness-script hex;
- witness-script byte length;
- `SHA256(witness_script)` as the 32-byte witness program;
- scriptPubKey hex `0020 || witness_program`;
- the network-specific SegWit v0 Bech32 address; and
- the canonical policy manifest and its SHA-256 digest.

Address human-readable parts MUST be `bc` for mainnet, `tb` for signet, and
`bcrt` for regtest. Network selection MUST affect the address, but MUST NOT
alter the witness script for otherwise identical inputs.

The manifest MUST use:

```text
format      = "mimir-composed-policy"
version     = 2
template_id = "mimir-kofn-two-path-v2"
```

It MUST include the normalized registry, both canonical groups and thresholds,
Unix and exact UTC locks, group Miniscript fragments, full Miniscript,
descriptor body and checksum, script artifacts, and address. JSON
canonicalization MUST be deterministic, and the reported policy hash MUST be
`SHA256(UTF8(canonical_manifest))`.

The one-page UI MUST offer a JSON download only for the latest successful
compile. The export MUST contain the complete v2 policy manifest; it MUST NOT
contain private material or transient drag/UI state.

## 8. One-page composer behavior

The default v2 UI MUST keep the registry, owner group, heir group, locks,
thresholds, compile action, validation feedback, and results on one page. A `+`
control MUST add a registry key. Users MAY assign or rearrange keys by drag and
drop, but drag and drop MUST NOT be the only path.

Click controls MUST be the authoritative accessible assignment path and MUST
provide the same semantics as dragging. All essential actions SHOULD be
keyboard operable, have visible focus, and expose accessible names. Reordering
MUST NOT change canonical output.

Compilation MUST occur only after an explicit user action. Invalid input MUST
produce a specific error and MUST NOT expose partial output as a valid policy.
Changing policy input after compilation SHOULD make it clear that the previous
result is stale until recompiled.

## 9. Fail-closed validation

The compiler MUST stop without policy output for at least:

- malformed, non-canonical, or off-curve public keys;
- duplicate registry IDs, labels, or public keys;
- empty groups, groups larger than 10, duplicate IDs within a group, unknown
  IDs, or owner/heir overlap;
- non-integer, zero, negative, or greater-than-N thresholds;
- non-integer or out-of-range locks, or `T_OWNER >= T_HEIR`;
- unsupported networks, request versions, or template IDs;
- Miniscript compiler errors or failed internal consistency invariants; and
- a witness script exceeding the 3,600-byte P2WSH standardness limit.

Internal checks MUST cover canonical key ordering, disjoint groups, satisfiable
thresholds, lock ordering, descriptor checksum, witness-program hash,
scriptPubKey construction, address encoding, script size, and reproducible
manifest hashing.

## 10. Privacy and execution boundary

The app MUST accept public data only. It MUST NOT request, derive, store, or
transmit private keys, seed phrases, signatures, or wallet secrets. It MUST NOT
construct, sign, or broadcast transactions.

Policy data MUST remain in volatile page memory. The app MUST NOT use browser
storage, analytics, telemetry, or a backend for policy state. Runtime network
connections MUST be disabled by content security policy; all compiler code,
styles, fonts, icons, and required assets MUST be local.

Raw public keys define one fixed P2WSH address. v2 has no child derivation or
address rotation, and the UI MUST warn users of that limitation.

## 11. Compatibility and deferred work

The existing `mimir-absolute-two-path-v1` implementation and its artifacts are
immutable. v2 MUST NOT reinterpret, silently migrate, or reuse the v1 template
ID for new semantics. The web UI defaults to v2; keeping the legacy compiler in
`lib/mimir.ts` is for compatibility and regression verification.

The following are explicitly deferred and MUST NOT be implied by a v2 output:

- arbitrary or nested branch graphs;
- different unlock dates for individual heirs;
- relative timelocks, hashlocks, and roles beyond owner/heir groups;
- Taproot, Tapscript, and MuSig/FROST aggregation;
- xpub derivation or rotating address sets; and
- a multi-recipient recovery-capsule v2 format.

## 12. Release gates

All mainnet output is preview-grade. Before describing v2 as production-ready,
a release MUST include:

1. independent security and Bitcoin Script/Miniscript review;
2. differential vectors reproduced with a pinned Bitcoin Core version for
   every supported network and representative 1-of-1, 1-of-10, 2-of-3,
   5-of-10, and 10-of-10 cases;
3. regtest spends of both branches, including threshold boundaries, premature
   lock failures, non-final sequence requirements, and invalid signatures;
4. deterministic manifest, descriptor, script, address, and JSON-export tests;
5. fail-closed tests for every validation class in Section 9;
6. reproducible builds and signed release artifacts; and
7. documented funding, monitoring, recovery, and multi-party rehearsal
   procedures.

Users SHOULD independently reproduce the exact descriptor, script, address,
thresholds, and timelocks with trusted Bitcoin Core tooling and complete a
recovery rehearsal before funding any output.
