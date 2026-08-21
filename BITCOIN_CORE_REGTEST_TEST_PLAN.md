# Mimir Bitcoin Core Regtest Test Plan

Status: planned; the Bitcoin Core execution harness is not implemented yet.

## 1. Objective

Execute Mimir's restricted Direct Script language against an independent
Bitcoin Core Regtest node. The test must fund real P2WSH outputs, construct real
witnesses and verify both accepted and rejected spends.

The language under test is:

```text
Policy = OR of 1–5 clauses
Clause = optional absolute CLTV AND one signature threshold
Signature threshold = K-of-N over 1–5 compressed secp256k1 public keys
```

The Core harness is the execution oracle. It must consume the witness-script
bytes emitted by Mimir; it must not reproduce Mimir's compiler logic and then
compare Mimir with itself.

## 2. Why Regtest

Exhaustive execution belongs on Regtest, not a public Testnet or Signet:

- block production and median time past are under test control;
- failed spends can be checked without consuming public resources;
- hundreds of P2WSH outputs can be funded and spent deterministically;
- the complete chain can be discarded after the run.

Public Testnet or Signet should be used only for a small end-to-end smoke test
after the Regtest suite passes.

Primary references:

- [Bitcoin Core: Testing Applications](https://developer.bitcoin.org/examples/testing.html)
- [BIP 65: OP_CHECKLOCKTIMEVERIFY](https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki)
- [BIP 113: Median time-past lock-time calculations](https://github.com/bitcoin/bips/blob/master/bip-0113.mediawiki)
- [BIP 141: P2WSH](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki)
- [BIP 147: NULLDUMMY](https://github.com/bitcoin/bips/blob/master/bip-0147.mediawiki)
- [Bitcoin Core: testmempoolaccept](https://github.com/bitcoin/bitcoin/blob/master/src/rpc/mempool.cpp)

## 3. Canonical key order

Use five deterministic test private keys and derive their compressed public
keys. Mimir orders selected public keys lexicographically by their 33-byte
compressed encoding.

Only this canonical order is emitted and tested. Labels, input key IDs,
registration order and the order in which keys were selected must not change
the witness script. Signatures in a CHECKMULTISIG witness must follow the same
canonical public-key order.

This removes representational permutations without removing any possible key
subset or threshold policy:

| Model | Single-clause representations |
| --- | ---: |
| Every key permutation treated as different | 2,610 |
| One canonical order for every selected subset | 160 |

Clause order remains authored order because it determines the explicit
OP_IF/OP_ELSE layout and the required branch-selector stack.

## 4. Exhaustive clause definitions

For a selected set of `m` keys there are `m` thresholds and two timing modes:
immediate or delayed.

```text
sum C(5,m) × m × 2, for m=1..5 = 160 clauses
```

| Selected keys | Key subsets | Thresholds | Timing modes | Cases |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 5 | 1 | 2 | 10 |
| 2 | 10 | 2 | 2 | 40 |
| 3 | 10 | 3 | 2 | 60 |
| 4 | 5 | 4 | 2 | 40 |
| 5 | 1 | 5 | 2 | 10 |
| **Total** |  |  |  | **160** |

Each of these 160 definitions must compile and its exact witness script must be
accepted by Bitcoin Core with a correct witness.

## 5. Successful spend matrix

For every selected key set and threshold, spend once with every exact valid set
of `K` signatures. A signer set containing more than `K` available private keys
does not create a new on-chain witness: it chooses one of its valid `K`-signature
subsets.

The number of exact valid signature sets per timing mode is:

```text
sum C(5,m) × (2^m - 1), for m=1..5 = 211
```

| Selected keys | Valid signature sets per timing mode | Immediate + delayed |
| ---: | ---: | ---: |
| 1 | 5 | 10 |
| 2 | 30 | 60 |
| 3 | 70 | 140 |
| 4 | 75 | 150 |
| 5 | 31 | 62 |
| **Total** | **211** | **422** |

Required result: **422 successful, confirmed spends**.

Each successful case records:

- Mimir request and canonical manifest hash;
- witness script hex and scriptPubKey hex;
- funding transaction ID and output index;
- spending transaction hex, txid and wtxid;
- exact witness stack from bottom to top;
- Bitcoin Core version, block hash and median time past.

## 6. Timelock execution

Use one shared future timestamp `T` for the exhaustive delayed matrix. For every
one of the 211 valid delayed witnesses:

1. Set transaction `nLockTime` to `T` and use a non-final `nSequence`.
2. Before activation, call `testmempoolaccept`; the transaction must be rejected.
3. Advance the Regtest chain until median time past reaches the required
   boundary.
4. Call `testmempoolaccept` again; the transaction must be accepted.
5. Broadcast, mine and confirm the spend.

Required result: **211 pre-lock rejections followed by 211 successful delayed
spends**.

Do not enumerate every calendar date. The execution rule is a scalar boundary,
so every delayed case is tested at `T-1` and `T`. Add separate serialization and
execution vectors for:

- the earliest permitted whole-day timestamp;
- a normal contemporary timestamp;
- Script-number sign-byte boundaries that intersect valid whole UTC days;
- `2106-02-07T00:00:00Z` (`4294944000`), Mimir's maximum date.

## 7. Multi-clause branch selection

Single-clause tests do not exercise OP_IF/OP_ELSE selectors. Build representative
policies containing one through five clauses and spend every branch position:

```text
1 + 2 + 3 + 4 + 5 = 15 successful branch-position spends
```

The fixtures must include:

- first, middle and final branches;
- immediate and delayed branches;
- CHECKSIG and CHECKMULTISIG bodies;
- repeated keys across branches;
- partially overlapping key sets;
- the maximum five-clause nesting depth.

For each branch, use the exact `branch_selector_bottom_to_top` items exported by
Mimir. Confirm that the selected branch succeeds and that the same signatures
with a selector for another unsatisfied branch fail.

## 8. Negative cases

Use `testmempoolaccept` for failures so rejected attempts do not consume their
funding outputs. Every rejection must include the expected Bitcoin Core reject
category in the test log.

### Signature failures

- no signature for a 1-of-N clause;
- `K-1` signatures for every threshold shape;
- a signature from a key outside the clause;
- a signature over a different transaction;
- modified DER signature bytes;
- reversed signature order for every threshold `K >= 2`;
- signatures that are individually valid but cannot match the selected public
  keys in increasing order.

### CHECKMULTISIG witness failures

- omit the historical dummy element;
- replace the empty dummy with a non-empty element;
- provide too few signatures;
- provide an extra stack item that prevents a clean true result.

### Timelock failures

- transaction `nLockTime = T-1`;
- final input sequence (`0xffffffff`);
- median time past below `T`;
- height-type `nLockTime` used against a timestamp CLTV operand;
- otherwise-valid delayed witness attached to an immediate transaction.

### Branch and P2WSH failures

- wrong minimal branch selector;
- missing selector;
- extra selector;
- non-minimal false/true selector;
- mutate one witness-script byte while retaining the original P2WSH output;
- use the correct witness script with a witness for a different clause.

### Compiler input failures

These remain local fail-closed tests and do not require funding:

- zero or more than five keys;
- zero or more than five clauses;
- invalid or duplicate compressed public keys;
- duplicate labels or IDs;
- unknown key references;
- duplicate keys inside one clause;
- threshold outside `1..N`;
- non-integer, height-type, non-midnight or out-of-range locktime.

## 9. Determinism cases

For every selected key subset:

- permute key registration order;
- replace input key IDs while preserving each label/public-key association;
- permute the selected-key input order;
- compile each representation for every supported network.

Expected result:

- witness script is identical for every equivalent key-order representation;
- changing labels changes manifest metadata but not the witness script;
- network changes address encoding and manifest network metadata, but not the
  witness script;
- canonical key IDs, manifest and address are reproducible for equivalent
  inputs;
- authored clause order remains visible and maps to documented selectors.

## 10. Public-network smoke tests

After the complete Regtest suite passes, perform only a small Testnet or Signet
smoke test:

1. immediate single signature;
2. immediate multisig;
3. delayed multisig;
4. first branch of a five-clause policy;
5. middle branch of the same policy;
6. final branch of the same policy.

Do not run the 422-spend exhaustive matrix on a public test network.

## 11. Acceptance criteria

The Core execution suite passes only when:

- all 160 canonical clause definitions execute as specified;
- all 422 exact valid witnesses are confirmed on Regtest;
- all 211 delayed witnesses fail before activation and succeed after activation;
- all 15 branch positions execute correctly;
- every mandatory negative fixture is rejected for the expected reason;
- every transaction uses the exact witness script emitted by Mimir;
- a repeat run produces the same scripts, manifests and transaction fixtures;
- the test report contains no skipped or unclassified case.

Passing this plan demonstrates exhaustive execution of the restricted grammar's
primitive clauses and complete coverage of the fixed branch-construction
mechanism. It does not claim enumeration of every complete five-clause policy:
there are `105,517,081,760` ordered policies even when delayed time is treated as
only one abstract mode. Testing the grammar compositionally avoids those
redundant billions of cases.
