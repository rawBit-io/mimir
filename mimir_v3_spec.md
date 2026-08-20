# Mimir v3 — Implemented Specification

Status: pre-mainnet preview

Template: `mimir-rules-v3`

This document describes the Mimir application and compiler as implemented.

## 1. Policy model

Mimir builds one native SegWit v0 P2WSH policy from public keys. A policy is a
list of independent spending rules:

```text
RULE A OR RULE B OR ... OR RULE N
```

Satisfying any one complete rule is enough to spend. Each rule contains:

- one key, or a K-of-N multisig group; and
- optionally, one absolute calendar-date lock.

`OWNER` and `HEIR` are visual labels in the interface. They are not part of the
compiled policy and do not grant, delay, or revoke spending rights. Only the
keys, threshold, and date saved in a rule affect the Bitcoin script.

Each public key may appear in only one rule. Saved rules are alternatives, not
steps in a sequence. A delayed rule remains available after its date and does
not disable an immediate or earlier rule.

## 2. User workflow

The application is a one-page builder:

1. Add signers and enter a label plus compressed public key for each one.
2. Mark signers as Owner or Heir for visual organization.
3. In **NEW RULE**, select one available key.
4. Optionally enable **Multisig**, select 2–10 keys, and choose K signatures.
5. Optionally enable **Time delay** and choose a calendar date.
6. Select **ADD RULE**, then repeat for other spending paths.
7. Review the live Miniscript, Bitcoin Script, address, and technical details.

The interface combines all saved rules with OR. It has no compile button and no
drag-and-drop workflow. Current output recalculates from saved rules, complete
key rows, and the network. Owner/Heir marks never enter the compiler.

A used key's public-key value cannot be edited or deleted until its rule is
removed; its label and visual role remain editable. The key is unavailable to
other rules. Saved rules are changed by removing and recreating them. Reset asks
for confirmation before clearing the page.

The web interface exposes Regtest and Signet only. Its date picker accepts a
future UTC calendar date from tomorrow through `2038-01-19`, interpreted as
`00:00:00 UTC`.

## 3. Inputs and limits

| Item | Implemented rule |
|---|---|
| Signers | 1–20 complete registry entries at compilation |
| Rules | 1–10 |
| Keys in one rule | 1–10 |
| Threshold | Integer K where `1 <= K <= N` |
| Key reuse | A public key may occur in only one rule |
| Label | Non-empty, at most 80 characters, unique ignoring case |
| Public key | Valid compressed secp256k1 key: `02` or `03` plus 64 hex characters |
| Delay | Integer `500000000 <= T <= 2147483647`, divisible by `86400` |
| Witness script | At most 3,600 bytes |

During compilation, labels are trimmed and NFC-normalized; public keys are
trimmed, normalized to lowercase, checked for a valid curve point, and required
to be unique. The visible fields retain the text as entered. Private keys, seed
phrases, WIF, x-only keys, uncompressed keys, and extended keys are not accepted.

The compiler accepts any valid whole-day lock in its supported range, including
past dates, so an existing policy remains reproducible. Requiring a future date
is an interface rule for newly created policies.

Incomplete or malformed unused signer rows do not enter compilation. A complete,
valid unused key is included in the manifest but excluded from the script, and
the output names it in a warning.

## 4. Compiler request

`compileRulePolicy()` accepts this request:

```json
{
  "format": "mimir-rule-request",
  "version": 3,
  "network": "regtest",
  "template_id": "mimir-rules-v3",
  "keys": [
    {
      "id": "input-owner",
      "label": "Owner",
      "public_key": "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    }
  ],
  "rules": [
    {
      "key_ids": ["input-owner"],
      "threshold": 1,
      "unlock_unix": null
    }
  ]
}
```

Core compiler networks are `bitcoin`, `signet`, and `regtest`. Generic Bitcoin
testnet is not supported. Mainnet support exists in the compiler but is not
available in the preview web interface.

Input key IDs are local references. Rules cannot provide their own IDs or any
additional rule state. `unlock_unix` is exactly `null` for an immediate rule or
an integer divisible by `86400` for a delayed rule.

Key IDs are trimmed and NFC-normalized, non-empty, control-character-free, at
most 64 characters, and unique. References within one rule must also be unique.

## 5. Script construction

Keys within a rule are sorted by normalized public key. The signing fragment is:

```text
pk(KEY)                    for one key
multi(K,KEY_1,...,KEY_N)   for multiple keys
```

A delayed rule wraps that fragment with absolute CLTV:

```text
and_v(v:after(UNLOCK_UNIX),SIGNING_FRAGMENT)
```

Complete rule fragments are sorted lexicographically, then joined with a fixed
right-nested `or_i` expression. For three fragments:

```text
or_i(F1,or_i(F2,F3))
```

The compiler sorts registry keys by public key, assigns `key-01`, `key-02`, and
so on, rewrites rule references, then assigns `rule-01`, `rule-02`, and so on in
canonical fragment order. Input key order, rule order, and caller-selected key
IDs therefore do not change the compiled policy.

The final descriptor body is:

```text
wsh(<exact Miniscript>)
```

Compilation stops if the request is invalid, Miniscript is not sane at top and
sublevels, an internal consistency check fails, or the witness script exceeds
the size limit.

## 6. Output and export

A valid policy is shown in the web app as:

- a natural-language OR summary;
- exact Miniscript and Bitcoin Script ASM; and
- the network-specific P2WSH address.

Collapsed technical details show:

- a checksummed `wsh(...)` descriptor;
- witness-script and scriptPubKey hex;
- the canonical-manifest SHA-256;
- the internal-check count and operator warnings; and
- canonical JSON download.

The compiler and downloaded manifest additionally carry normalized keys,
canonical rules, witness-script byte length, the witness-program hash, and the
remaining exact artifacts and invariant results.

Address prefixes are `bc1q` for mainnet, `tb1q` for Signet, and `bcrt1q` for
Regtest. Network selection changes the address and manifest, but not the witness
script for otherwise identical rules.

The manifest has format `mimir-rule-policy`, version `3`, and template
`mimir-rules-v3`. Each canonical rule records its key IDs, public keys,
threshold, optional Unix/UTC unlock date, and Miniscript fragment. It also
contains the full Miniscript, descriptor, script artifacts, address, network,
and complete normalized key registry.

The downloaded policy JSON is the exact canonical-manifest byte sequence used
to calculate the displayed SHA-256 hash. Labels and complete unused keys are
manifest data; changing them can change the manifest hash without changing the
witness script.

When the current policy is empty or invalid, Mimir removes valid artifacts and
shows an actionable waiting or error state instead of stale output.

## 7. Timelock behavior

The date lock compiles to `OP_CHECKLOCKTIMEVERIFY`. Spending through a delayed
rule requires:

- transaction `nLockTime` at least equal to the rule timestamp; and
- a non-final `nSequence` on the input spending the Mimir output.

Bitcoin evaluates timestamp locks using median time past. A rule can therefore
become usable later than the displayed midnight. Once usable, it remains
usable.

## 8. Privacy and safety boundary

Mimir is designed for public data only. Private keys, seed phrases, signatures,
and wallet secrets are never accepted as valid compiler input, persisted, or
transmitted; users must never paste them into the page. Mimir does not construct,
sign, broadcast, or monitor transactions.

Policy state exists only in page memory. The implementation does not persist it
to browser storage, send it to a policy backend, or use analytics or telemetry.
The production content security policy disables outbound runtime connections.

Raw public keys produce one fixed address; Mimir does not derive or rotate
child keys. The application remains preview software. Reproduce the descriptor,
script, address, thresholds, and dates with Bitcoin Core, and rehearse the exact
policy on Regtest or Signet before funding.
