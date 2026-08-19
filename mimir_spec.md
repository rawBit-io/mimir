# Mimir v1 — Architecture and Implementation Specification

**Status:** Draft specification for implementation
**Specification version:** 1.0-draft
**Date:** August 19, 2026
**Audience:** The AI or engineering team implementing Mimir, security reviewers, test engineers, and maintainers of the reference Bitcoin Core and Ledger workflows

---

## 1. Implementation directive

Implement **Mimir v1** according to this document.

Treat the component boundaries, security invariants, exported artifacts, policy semantics, and recovery requirements as normative. Do not expand the product into a general wallet, signer, transaction builder, hardware-wallet manager, or blockchain client.

Where this specification deliberately leaves implementation details open, choose the simplest design that:

1. Preserves interoperability.
2. Minimizes trusted code.
3. Produces deterministic policy outputs.
4. Can be independently checked with Bitcoin Core.
5. Does not introduce private-key handling into Mimir.
6. Fails closed when inputs or external compatibility are uncertain.

The implementation language, application framework, UI toolkit, and internal module organization are not prescribed.

---

## 2. Product definition

Mimir is a **public-data-only Bitcoin vault policy compiler and encrypted recovery-capsule generator**.

Mimir converts participant extended public keys and absolute unlock dates into:

- A fixed native-P2WSH vault descriptor.
- The exact witness script.
- The corresponding scriptPubKey and Bitcoin address.
- A BIP 388 wallet-policy representation suitable for compatible hardware signers.
- An optional BIP 138 encrypted recovery capsule.
- The raw data required to place that capsule into an OP_RETURN output.
- A complete public recovery bundle.
- Procedures for independently verifying the result with Bitcoin Core.

Mimir does **not**:

- Generate seeds or keys.
- Accept mnemonics, private keys, WIFs, xprvs, or passphrases.
- Query a blockchain.
- Discover UTXOs.
- Construct funding or recovery transactions.
- Parse or modify PSBTs.
- Estimate fees.
- Select coins.
- Create change.
- Sign transactions.
- Finalize transactions.
- Broadcast transactions.
- Hold Bitcoin Core RPC credentials.
- Communicate directly with a hardware wallet in the core application.

The reference system architecture is:

```text
Creation:
    Mimir Policy
    Mimir Capsule
    Bitcoin Core verification
    Bitcoin Core funding wallet

Monitoring:
    Bitcoin Core watch-only descriptor wallet

Recovery:
    Bitcoin Core watch-only coordinator
    Bitcoin Core offline descriptor signer

Optional hardware recovery:
    Bitcoin Core coordinator
    Separate Mimir-Ledger adapter
    Ledger signer
```

The funds must remain recoverable even if:

- Mimir disappears.
- The Mimir website disappears.
- GitHub disappears.
- The original browser no longer exists.
- The original Ledger no longer works.
- The original Mimir implementation cannot be executed.

The descriptor, witness script, participant key material, and Bitcoin consensus rules are the recovery foundation.

---

## 3. Design lineage

The original Mimir concept emphasized an encrypted on-chain recovery layer, deterministic operation, honest treatment of browser and operating-system limitations, and immutable release verification. This specification retains those principles but deliberately removes custom transaction signing and custom ECIES-like descriptor encryption from the Mimir core. Transaction work is delegated to Bitcoin Core, and the encrypted capsule uses a pinned BIP 138 profile.

This specification supersedes any earlier proposal in which Mimir:

- Generated seeds.
- Converted dice directly into signing keys.
- Accepted private keys.
- Constructed raw transactions.
- Parsed PSBTs.
- Implemented ECDSA signing.
- Implemented a custom public-key encryption format.
- Attempted browser-memory zeroization for spend secrets.

Those functions are outside Mimir v1.

---

## 4. Normative language

The terms **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** describe requirement levels in the usual RFC 2119 sense.

A requirement marked MUST or MUST NOT is part of the Mimir v1 compatibility contract.

A SHOULD requirement may be departed from only when the implementation documents the reason and preserves the relevant security property.

---

## 5. Standards basis

Mimir v1 builds on existing Bitcoin standards rather than defining a new spending or signing protocol.

### 5.1 Output descriptors

The canonical recovery representation is a checksummed BIP 380 output descriptor. Output descriptors are designed to describe the scripts controlled or monitored by a wallet, including key origins and derivations.

### 5.2 Native P2WSH

The vault output is native SegWit v0 P2WSH. In P2WSH, the output commits to the SHA256 of the exact witness script, and a future spend supplies that script as the final witness item.

Mimir v1 does not use:

- Legacy P2SH.
- Nested P2SH-P2WSH.
- Taproot.
- Bare scripts.

### 5.3 Absolute timelocks

The spending paths use `OP_CHECKLOCKTIMEVERIFY` through the Miniscript `after()` fragment.

A CLTV spend requires:

- A transaction `nLockTime` of the same type as the script lock.
- `nLockTime` at least equal to the script lock.
- A non-final input sequence.

Time-based finality is evaluated against median time past, based on the previous eleven block timestamps, rather than exact wall-clock time.

### 5.4 Wallet policies

The optional hardware-wallet representation follows BIP 388: a descriptor template with key placeholders plus a vector of extended public keys and origins. BIP 388 supports valid Miniscript templates inside `wsh(...)` and defines `/**` as the common receive/change derivation form.

### 5.5 Bitcoin Core

The reference transaction stack is Bitcoin Core.

The required capability set includes:

- Descriptor analysis and canonicalization.
- Address derivation.
- Watch-only descriptor import.
- Funded PSBT creation.
- OP_RETURN data outputs.
- PSBT decoding.
- Descriptor-based PSBT updating and signing.
- PSBT finalization.
- Mempool-policy testing.
- Broadcasting.

Bitcoin Core 31.0 documents these capabilities through RPCs including `getdescriptorinfo`, `deriveaddresses`, `importdescriptors`, `walletcreatefundedpsbt`, `decodepsbt`, `descriptorprocesspsbt`, `finalizepsbt`, `testmempoolaccept`, and `sendrawtransaction`.

Mimir MUST nevertheless publish an explicit minimum tested Bitcoin Core version rather than assuming every historical or future release behaves identically.

### 5.6 Encrypted capsule

The preferred encrypted capsule profile is BIP 138, “Compact Encryption Scheme for Non-seed Wallet Data.”

As of this specification date, the BIP 138 proposal remains an open pull request rather than a merged, final standard. Every Mimir release using it must therefore pin an exact specification commit and exact test-vector set.

The available Rust implementation includes CLI operation, arbitrary-data or descriptor encryption, device-assisted xpub retrieval, WASM targets, and committed test vectors. It should be treated as an important reference implementation, not as an automatically stable dependency.

### 5.7 Canonical manifests

Machine-readable manifests that are hashed MUST be serialized canonically. Mimir v1 uses RFC 8785 JSON Canonicalization Scheme for exported manifest hashes. RFC 8785 defines deterministic JSON serialization suitable for repeatable hashing.

---

## 6. Primary goals

### 6.1 Minimize the Mimir trusted computing base

Mimir-specific code should be restricted to:

- Public-key and origin validation.
- Fixed policy construction.
- Descriptor generation.
- Child public-key derivation.
- Witness-script generation.
- P2WSH scriptPubKey and address generation.
- Wallet-policy conversion.
- Recovery-capsule creation.
- Manifest generation.
- Human-readable review and export.

Generic transaction and signing complexity belongs to Bitcoin Core.

### 6.2 Ensure Mimir-independent recovery

The user must be able to recover with:

```text
Participant seed or private extended key
Exact origin path
Checksummed fixed descriptor
Exact witness script
Funding outpoint and amount
Bitcoin Core or another compatible descriptor implementation
```

Mimir must never be the only implementation capable of spending the vault.

### 6.3 Support enforced long-term self-lock and inheritance

The v1 policy provides:

- An owner path that becomes available at an absolute time.
- An heir path that becomes available at a later absolute time.

Before the owner date, nobody can spend.

Between the owner and heir dates, only the owner can spend.

After the heir date, either participant can spend.

### 6.4 Preserve interoperability

Mimir should emit standard artifacts wherever a suitable standard exists:

- BIP 32 extended keys.
- BIP 380 descriptors.
- P2WSH.
- Miniscript.
- BIP 388 wallet policies.
- BIP 138 encrypted metadata.
- BIP 174-compatible PSBT workflows through Bitcoin Core.

### 6.5 Make independent verification mandatory

Mimir must not ask the user to trust a Mimir-derived address by itself.

Before mainnet funding, the fixed descriptor and address must be independently reproduced by Bitcoin Core.

Where a compatible hardware signer is used, the address should also be displayed independently on that device.

### 6.6 Provide durable encrypted redundancy

The encrypted OP_RETURN capsule is a backup of the recovery package, not its sole copy.

Its purpose is to make the descriptor and essential recovery information durable and retrievable without publishing them in plaintext.

### 6.7 Support immutable releases

A released Mimir policy profile must never silently change.

A future correction or improvement becomes a new immutable version with a new release hash and, where necessary, a new template or capsule profile identifier.

---

## 7. Explicit non-goals

Mimir v1 is not intended to provide:

- A general Miniscript editor.
- Arbitrary Bitcoin Script construction.
- Multisig thresholds.
- More than two spending paths.
- Relative timelocks.
- Taproot privacy.
- Automatic death detection.
- Revocation of an heir after the heir date.
- Destination restrictions after a key becomes valid.
- Automatic vault rotation.
- An online hosted custody service.
- A blockchain explorer.
- A fee oracle.
- A transaction relay service.
- Seed-generation assurance.
- Secure deletion of secrets.
- Legal estate-planning advice.
- Universal hardware-wallet compatibility.
- Automatic compatibility with every Bitcoin Core version.
- Automatic compatibility with every future BIP 138 revision.
- Protection against a compromised participant seed.
- Protection against an heir spending after the heir path becomes valid.
- Guaranteed OP_RETURN relay through every node or miner policy.

---

## 8. Security model

### 8.1 Protected assets

The system protects:

1. The Bitcoin locked to the P2WSH output.
2. The correctness of the lock conditions.
3. The association between the descriptor, script, and address.
4. Recovery metadata confidentiality.
5. The long-term ability to reconstruct and spend the output.
6. The user’s ability to detect an incorrect or substituted policy before funding.

### 8.2 Trusted elements

At policy creation, the user ultimately trusts:

- The participant keys and their backups.
- At least one correct interpretation of Bitcoin consensus.
- The independent agreement between Mimir and Bitcoin Core.
- The computing environments used to run them.
- The user’s comparison of the resulting artifacts.

At spending time, the user trusts:

- The selected signer or private-key ceremony.
- Bitcoin Core’s transaction and signing implementation.
- Their review of the transaction destination, amounts, fees, and locktime.
- Optionally, a hardware signer’s trusted display.

### 8.3 Adversaries considered

The design should consider:

- A malicious Mimir artifact.
- A compromised Mimir distribution channel.
- A compromised online Bitcoin Core coordinator.
- A malicious or compromised funding wallet.
- A malicious PSBT.
- An incorrect descriptor or key origin.
- A substituted xpub.
- A wrong unlock timestamp.
- Loss of the witness script.
- Loss of the original hardware signer.
- Loss of the original software release.
- Public disclosure of an account xpub.
- Corruption or censorship of the OP_RETURN capsule.
- Long-term abandonment of the Mimir project.
- User confusion about absolute dates.
- Deposits made years after the policy was created.
- Compromise of an owner or heir key before it becomes usable.

### 8.4 Residual risks that Mimir cannot eliminate

Mimir must state these clearly:

- A compromised Mimir build can generate an attacker-controlled script. Independent verification is therefore mandatory.
- A compromised funding wallet can fund the wrong address unless the user verifies the final transaction.
- A compromised watch-only coordinator can construct a transaction paying an attacker. Offline review or hardware display is required.
- If a participant’s private key is compromised before its unlock time, the attacker may prepare a competing transaction and race the legitimate participant when the path becomes usable.
- The owner cannot move the funds before the owner date under the v1 policy.
- After the heir date, the heir can spend even when the owner is alive.
- Bitcoin cannot distinguish death from inactivity.
- On-chain data is permanent and public, even when encrypted.
- Anyone possessing an eligible account xpub may be able to decrypt the BIP 138 capsule.
- A valid xpub does not prove that the seed was securely generated or never exposed.
- Technical inheritance does not replace a will, executor instructions, or jurisdiction-specific estate planning.

---

## 9. Component architecture

```text
┌──────────────────────────────────────────────────────────────┐
│                         MIMIR V1                             │
│                                                              │
│  ┌──────────────────────┐    ┌────────────────────────────┐  │
│  │  Policy Compiler     │    │  Capsule Generator        │  │
│  │                      │    │                            │  │
│  │  deterministic       │    │  randomized per profile  │  │
│  │  public data only    │    │  public data only         │  │
│  └──────────┬───────────┘    └─────────────┬──────────────┘  │
│             │                              │                 │
│             └──────────────┬───────────────┘                 │
│                            ▼                                 │
│                  Public Vault Bundle                         │
└────────────────────────────┬─────────────────────────────────┘
                             │
          ┌──────────────────┼──────────────────────┐
          ▼                  ▼                      ▼
  Bitcoin Core       Physical backups      Optional Ledger
  verification       and recovery file      policy adapter
          │
          ▼
  Bitcoin Core funding wallet
          │
          ▼
       Bitcoin
          │
          ▼
  Watch-only Core coordinator
          │
          ├──────────► Offline Core signer
          │
          └──────────► Optional Ledger signer
```

### 9.1 Mimir Policy Compiler

The policy compiler:

- Accepts only public information.
- Implements exactly the approved v1 template.
- Produces deterministic output.
- Does not access the network.
- Does not invoke Bitcoin Core.
- Does not invoke a hardware wallet.
- Does not generate randomness.
- Does not contain transaction or PSBT code.
- Does not accept arbitrary descriptors as a substitute for structured inputs.

### 9.2 Mimir Capsule Generator

The capsule generator:

- Accepts only public metadata.
- Encrypts the recovery payload according to a pinned capsule profile.
- Uses secure randomness where required by that profile.
- Produces raw capsule bytes.
- Produces the data hex expected by a Bitcoin Core OP_RETURN `data` output.
- Produces the complete expected OP_RETURN scriptPubKey for verification.
- Does not handle spend secrets.
- Is internally separated from the deterministic policy compiler.

### 9.3 Bitcoin Core verification and funding wallet

Bitcoin Core independently:

- Canonicalizes and checks the descriptor.
- Derives the vault address.
- Constructs the funding transaction.
- Selects funding inputs.
- Adds change.
- Estimates fees.
- Adds the OP_RETURN output.
- Produces and signs the funding PSBT.
- Broadcasts the transaction.
- Verifies the confirmed outputs.

### 9.4 Bitcoin Core watch-only coordinator

The coordinator:

- Imports the fixed public descriptor.
- Monitors deposits and spends.
- Records UTXOs, amounts, and outpoints.
- Constructs a recovery PSBT.
- Selects the spending path.
- Sets the required locktime.
- Selects fees.
- Receives signed PSBTs.
- Finalizes and broadcasts.

It contains no participant private keys.

### 9.5 Bitcoin Core offline signer

The offline signer:

- Receives a PSBT and public recovery bundle.
- Independently decodes and reviews the PSBT.
- Receives one participant’s private descriptor or uses an isolated private descriptor wallet.
- Signs only the selected spending path.
- Returns the signed PSBT or finalized transaction.
- Does not require a synchronized blockchain when the PSBT contains all required previous-output data.

### 9.6 Optional Ledger adapter

The Ledger adapter is a separate, replaceable component.

It:

- Retrieves and displays account xpubs.
- Registers the BIP 388 wallet policy.
- Stores or exports the registration record.
- Requests on-device address display.
- Sends a Core-created PSBT for signing.
- Returns signatures to the coordinator.
- Never changes transaction outputs or policy data.
- Never becomes a mandatory recovery dependency.

---

## 10. Mimir v1 policy

### 10.1 Roles

The policy has exactly two roles:

```text
OWNER
HEIR
```

Role order is semantically significant:

```text
@0 = OWNER
@1 = HEIR
```

Keys must not be lexicographically reordered across roles.

### 10.2 Policy semantics

The canonical Miniscript policy is:

```text
wsh(
  or_i(
    and_v(v:after(T_OWNER),pk(KEY_OWNER)),
    and_v(v:after(T_HEIR),pk(KEY_HEIR))
  )
)
```

The exact canonical descriptor syntax emitted by the chosen descriptor implementation may remove whitespace, but it must preserve these semantics and branch ordering.

### 10.3 Timeline

The required relationship is:

```text
T_OWNER < T_HEIR
```

Behavior:

```text
Current consensus time < T_OWNER:
    No path is spendable.

T_OWNER <= current consensus time < T_HEIR:
    OWNER path is spendable.
    HEIR path is not spendable.

Current consensus time >= T_HEIR:
    OWNER path is spendable.
    HEIR path is spendable.
```

The owner path does not disappear when the heir path becomes valid.

### 10.4 Absolute timestamps

`T_OWNER` and `T_HEIR` are Unix timestamps.

They MUST:

- Be integers.
- Be at least `500000000`, ensuring timestamp rather than block-height semantics.
- Fit within Bitcoin transaction locktime limits.
- Satisfy `T_OWNER < T_HEIR`.
- Be rendered to users in both Unix and UTC forms.
- Be stored exactly as integers in the policy manifest.

The implementation may offer a convenience input such as “five years from now,” but the final security review must operate on exact UTC dates and exact integer timestamps.

The interface must warn that:

- The machine clock can be wrong.
- The lock is based on Bitcoin median time past, not the exact displayed wall-clock second.
- Confirmation may become possible later than the displayed UTC instant.
- A later deposit to the same address does not restart the clock.

### 10.5 Key model

Each role supplies:

```text
Master fingerprint
Account origin path
Canonical BIP32 extended public key
```

For example:

```text
[fingerprint/48'/0'/account'/2']xpub...
```

The specific account path is not consensus-critical and is not universally mandated by this specification.

The reference ceremony SHOULD use a dedicated native-P2WSH account, conventionally under a BIP48-style path, because it improves compatibility with BIP 388 and BIP 138 tooling.

Each participant SHOULD use a dedicated account xpub for one Mimir vault.

The implementation must clearly warn that:

- Reusing an ordinary wallet account xpub reduces capsule privacy.
- An xpub previously sent to a wallet server may allow that server to decrypt the capsule.
- A dedicated account does not protect against compromise of the underlying master seed.
- A new account xpub is not equivalent to a new independent seed.

### 10.6 Fixed vault derivation

Mimir v1 uses one fixed public child from each supplied account xpub:

```text
external branch: 0
address index:   0
child suffix:    /0/0
```

Therefore:

```text
KEY_OWNER = [OWNER_ORIGIN]OWNER_XPUB/0/0
KEY_HEIR  = [HEIR_ORIGIN]HEIR_XPUB/0/0
```

A single Mimir vault instance corresponds to this one fixed address.

Future Mimir versions may define other index behavior, but v1 must not silently use a different derivation.

The UI must tell users:

> This vault uses branch 0, index 0. Do not generate or fund additional addresses from the account policy.

### 10.7 Fixed descriptor

The fixed descriptor is the primary recovery artifact:

```text
wsh(
  or_i(
    and_v(
      v:after(T_OWNER),
      pk([OWNER_FINGERPRINT/OWNER_PATH]OWNER_XPUB/0/0)
    ),
    and_v(
      v:after(T_HEIR),
      pk([HEIR_FINGERPRINT/HEIR_PATH]HEIR_XPUB/0/0)
    )
  )
)#CHECKSUM
```

The actual export must be canonical, whitespace-free, and include the descriptor checksum.

### 10.8 BIP 388 account policy

For a compatible hardware signer, Mimir also outputs:

```text
Descriptor template:

wsh(
  or_i(
    and_v(v:after(T_OWNER),pk(@0/**)),
    and_v(v:after(T_HEIR),pk(@1/**))
  )
)
```

Key-information vector:

```text
[
  "[OWNER_FINGERPRINT/OWNER_PATH]OWNER_XPUB",
  "[HEIR_FINGERPRINT/HEIR_PATH]HEIR_XPUB"
]
```

The resulting multipath account descriptor replaces `/**` with:

```text
/<0;1>/*
```

Mimir must derive and export that account descriptor, but it is not the primary watch-only descriptor.

The fixed descriptor at branch 0, index 0 remains the canonical funded vault definition.

### 10.9 Address-use policy

The reference ceremony recommends:

- One vault instance.
- One fixed address.
- One principal funding event.
- One eventual sweep.
- No change back into the old vault.
- No reuse after spending.

Multiple UTXOs sent to the same fixed vault address may be recovered in a single transaction, but later deposits inherit the already-running absolute lock schedule.

The interface must warn prominently whenever a user attempts to reuse an existing policy.

---

## 11. Policy compiler inputs

The logical input contract is:

```json
{
  "format": "mimir-policy-request",
  "version": 1,
  "network": "bitcoin",
  "template_id": "mimir-absolute-two-path-v1",
  "vault_derivation": {
    "branch": 0,
    "index": 0
  },
  "participants": [
    {
      "role": "owner",
      "master_fingerprint": "8_hex_characters",
      "origin_path": "m/...",
      "xpub": "canonical_extended_public_key"
    },
    {
      "role": "heir",
      "master_fingerprint": "8_hex_characters",
      "origin_path": "m/...",
      "xpub": "canonical_extended_public_key"
    }
  ],
  "locks": {
    "owner_unix": 0,
    "heir_unix": 0
  }
}
```

The exact UI representation is not normative.

### 11.1 Supported networks

The initial implementation MUST support:

- Bitcoin mainnet.
- Regtest.

It SHOULD support:

- Signet.

Additional Bitcoin test networks MAY be supported when network identifiers and extended-key handling are unambiguous.

Every exported artifact must include the network explicitly.

### 11.2 Input validation

The policy compiler MUST reject:

- Missing participants.
- More or fewer than two participants.
- Repeated roles.
- Unknown roles.
- Private extended keys.
- WIFs.
- Mnemonics.
- Seed-like input.
- Malformed fingerprints.
- Malformed origin paths.
- Hardened derivation after an xpub.
- Invalid extended-key checksums.
- Extended keys for the wrong network.
- Invalid secp256k1 public points.
- Identical account public keys.
- Identical derived `/0/0` public keys.
- Timestamps with height semantics.
- `T_OWNER >= T_HEIR`.
- Unsupported templates.
- Arbitrary descriptor text supplied in place of structured policy input.
- Any extra spending branch not defined by the template.

The compiler SHOULD verify that the serialized xpub depth is consistent with the declared origin path depth.

It cannot prove that the supplied fingerprint and origin path genuinely belong to the xpub. That association must be verified using the source wallet or hardware device.

### 11.3 Mainnet guardrails

For mainnet, the UI MUST:

- Display the exact owner and heir dates in UTC.
- Display the exact timestamp integers.
- Explain the complete timeline.
- Warn that no emergency path exists.
- Warn that the owner cannot spend before `T_OWNER`.
- Warn that the heir can spend after `T_HEIR`.
- Warn against address reuse.
- Require export of the recovery bundle before presenting the vault as ready for verification.
- Mark the address as **unverified** until the Bitcoin Core verification procedure is completed.

The implementation may require an explicit user attestation before enabling mainnet output.

---

## 12. Deterministic policy output

Given the same:

- Mimir release.
- Network.
- Template.
- Participant key information.
- Derivation.
- Lock timestamps.

the policy compiler MUST produce byte-identical:

- Fixed descriptor.
- Account descriptor.
- BIP 388 policy template.
- Key-information vector.
- Derived child pubkeys.
- Witness script.
- P2WSH witness program.
- scriptPubKey.
- Address.
- Canonical policy manifest.
- Policy-manifest hash.

The policy compiler must not insert:

- Current time.
- Random identifiers.
- Random field ordering.
- Environment-specific paths.
- Locale-specific formatting.
- Browser-specific values.

Session timestamps and display labels may appear in a separate noncanonical session record, not in the deterministic policy manifest.

---

## 13. Policy manifest

Mimir exports a canonical UTF-8 JSON policy manifest.

The logical schema is:

```json
{
  "format": "mimir-policy",
  "version": 1,
  "network": "bitcoin",
  "template_id": "mimir-absolute-two-path-v1",
  "vault_derivation": {
    "branch": 0,
    "index": 0,
    "child_suffix": "/0/0"
  },
  "participants": [
    {
      "role": "owner",
      "master_fingerprint": "00000000",
      "origin_path": "m/...",
      "xpub": "xpub...",
      "derived_pubkey": "02..."
    },
    {
      "role": "heir",
      "master_fingerprint": "00000000",
      "origin_path": "m/...",
      "xpub": "xpub...",
      "derived_pubkey": "03..."
    }
  ],
  "locks": {
    "owner": {
      "unix": 0,
      "utc": "YYYY-MM-DDTHH:MM:SSZ"
    },
    "heir": {
      "unix": 0,
      "utc": "YYYY-MM-DDTHH:MM:SSZ"
    }
  },
  "descriptor": {
    "fixed": "wsh(...)#checksum",
    "account_multipath": "wsh(...)#checksum"
  },
  "wallet_policy": {
    "template": "wsh(...)",
    "keys": ["[fingerprint/path]xpub...", "[fingerprint/path]xpub..."],
    "funded_branch": 0,
    "funded_index": 0
  },
  "script": {
    "witness_script_hex": "...",
    "witness_program_sha256": "...",
    "script_pubkey_hex": "0020..."
  },
  "address": "bc1q..."
}
```

The exact field names above are normative for Mimir v1 unless a pre-mainnet schema review identifies a concrete interoperability defect.

The policy manifest:

- MUST contain no private key material.
- MUST reject duplicate JSON keys when parsed.
- MUST be canonicalized using RFC 8785 for hashing.
- MUST have its canonical bytes hashed with SHA256.
- MUST export the resulting `policy_manifest_sha256`.
- MUST be accepted only when every derived field is internally consistent.

The natural consensus identifier of the vault is:

```text
SHA256(witnessScript)
```

This value is also the 32-byte P2WSH witness program.

---

## 14. Internal consistency invariants

Before producing a valid policy bundle, Mimir MUST verify:

```text
derive(owner_xpub, /0/0) == exported owner derived pubkey

derive(heir_xpub, /0/0) == exported heir derived pubkey

compile(fixed_descriptor) == exported witnessScript

SHA256(witnessScript) == exported witness program

scriptPubKey == OP_0 PUSH32 witness_program

address(network, scriptPubKey) == exported address

fixed_descriptor == account_descriptor at branch 0, index 0

wallet_policy @0 == owner key information

wallet_policy @1 == heir key information

fixed descriptor contains T_OWNER exactly

fixed descriptor contains T_HEIR exactly

policy manifest contains no private extended key

policy manifest canonical hash is reproducible
```

Failure of any invariant must abort export.

---

## 15. Recovery capsule

### 15.1 Purpose

The capsule provides an encrypted, durable copy of the information needed to identify and reconstruct the vault.

It is a redundancy layer.

The capsule MUST NOT be presented as:

- The only descriptor backup.
- The only recovery method.
- A replacement for participant key backups.
- A replacement for a physical inheritance package.
- Guaranteed to be automatically discovered by ordinary wallets.

### 15.2 Capsule profile

A capsule profile defines:

```text
Encryption specification
Specification revision or commit
Reference implementation revision
Test-vector revision
Payload format
On-chain encoding
```

A Mimir release must bind to one exact profile identifier, for example:

```text
mimir-bip138-profile-1
```

That identifier must never change meaning after release.

The profile manifest MUST record:

```text
BIP number or proposal identifier
Exact specification commit
Exact implementation commit used for testing
Hash of test vectors
Encryption algorithm identifier
Binary format version
```

Mimir must not silently follow the latest branch of a draft specification.

### 15.3 BIP 138 eligibility

The fixed descriptor uses account xpub expressions with a trailing `/0/0` derivation.

This is intentional:

- It allows the BIP 138 profile to derive its recipient material from account xpub roots.
- The child public key revealed in a future spend is not the account-root public key used by the capsule profile.
- A literal bare pubkey is not used as the capsule recipient identity.

### 15.4 Capsule confidentiality model

The capsule is confidential against parties who do not possess an eligible participant account public key.

It does not prove possession of a private key.

Anyone who obtains an eligible account xpub may be able to decrypt the capsule.

Therefore:

- Dedicated vault account xpubs are strongly recommended.
- The xpubs should not be uploaded to third-party wallet services.
- The user’s own watch-only Core wallet is expected to possess the public descriptor and therefore already knows the plaintext.
- Capsule encryption protects the metadata from the general public blockchain, not from every computer intentionally given the xpub.

### 15.5 Capsule plaintext

The capsule plaintext MUST be a versioned Mimir recovery object containing at least:

```json
{
  "format": "mimir-recovery",
  "version": 1,
  "policy_manifest_sha256": "...",
  "network": "bitcoin",
  "template_id": "mimir-absolute-two-path-v1",
  "fixed_descriptor": "wsh(...)#checksum",
  "witness_script_hex": "...",
  "script_pubkey_hex": "0020...",
  "address": "bc1q...",
  "locks": {
    "owner_unix": 0,
    "owner_utc": "YYYY-MM-DDTHH:MM:SSZ",
    "heir_unix": 0,
    "heir_utc": "YYYY-MM-DDTHH:MM:SSZ"
  },
  "release_manifest_sha256": "...",
  "note": "optional encrypted human-readable text"
}
```

The plaintext MUST NOT contain:

- Mnemonics.
- Seed bytes.
- xprvs.
- WIFs.
- Private keys.
- BIP39 passphrases.
- Dice rolls.
- Ledger PINs.
- Core wallet passphrases.
- RPC credentials.

### 15.6 Capsule randomness

The capsule generator MUST follow the randomness requirements of its pinned encryption profile.

The deterministic-policy requirement does not apply to encryption nonces or privacy padding.

The capsule generator must not derive encryption randomness from:

- A participant private key.
- A mnemonic.
- A seed.
- The fixed witness script alone.
- A deterministic function that violates the pinned profile.

Capsule randomness protects metadata confidentiality. It is not used to generate or sign Bitcoin keys.

### 15.7 Capsule outputs

Mimir exports:

```text
Raw capsule bytes
Capsule byte length
Capsule SHA256
Capsule data hex
Expected OP_RETURN scriptPubKey hex
Capsule profile manifest
Human-readable inspection summary
```

The `data` value supplied to Bitcoin Core is the raw capsule bytes encoded as hex, without an already-prepended OP_RETURN opcode.

Mimir also outputs the complete expected OP_RETURN scriptPubKey so the confirmed transaction can be checked independently.

### 15.8 Publication modes

The reference workflow places the capsule in the same transaction that funds the vault.

A separate capsule publication transaction MAY be used when:

- Relay policy requires it.
- Privacy analysis favors it.
- The user wants to include the already-known funding outpoint in a later encrypted note.
- The funding wallet cannot create the required data output.

The recovery format must not depend on whether publication is in the same or a separate transaction.

### 15.9 Relay and fee handling

Mimir must display:

- Raw capsule byte size.
- OP_RETURN script size.
- A warning that on-chain data consumes block space and fees.
- A warning that node and miner relay policies may differ.
- A requirement to test the final signed transaction with the user’s intended Bitcoin Core node before broadcast.

Mimir must not claim universal relayability.

If the capsule cannot be relayed, the user may:

- Publish it separately.
- Retain it only off-chain.
- Use a later capsule profile.

Failure to publish the capsule must not make the vault unspendable.

---

## 16. Vault bundle

A complete Mimir vault bundle consists logically of:

```text
1. Canonical policy manifest
2. Policy-manifest SHA256
3. Fixed descriptor
4. Account multipath descriptor
5. Witness script
6. scriptPubKey
7. Vault address
8. BIP 388 wallet-policy template
9. BIP 388 key-information vector
10. Capsule raw bytes
11. Capsule data hex
12. Expected OP_RETURN scriptPubKey
13. Capsule SHA256
14. Capsule profile manifest
15. Mimir release manifest
16. Human-readable policy summary
17. Bitcoin Core verification procedure
18. Bitcoin Core funding procedure
19. Bitcoin Core monitoring procedure
20. Bitcoin Core software-recovery procedure
21. Optional Ledger recovery procedure
22. Empty verification-record template
23. Empty funding-record template
24. Physical-backup checklist
```

Packaging may be:

- A directory.
- An archive.
- A single downloadable package.
- Multiple individually downloadable files.

The packaging mechanism is not normative.

Every logical artifact must have:

- A stable type identifier.
- A SHA256 hash.
- An entry in the bundle manifest.

### 16.1 Bundle manifest

The bundle manifest is a canonical JSON index such as:

```json
{
  "format": "mimir-vault-bundle",
  "version": 1,
  "policy_manifest_sha256": "...",
  "compiler_release_manifest_sha256": "...",
  "capsule_profile_id": "mimir-bip138-profile-1",
  "artifacts": [
    {
      "type": "policy_manifest",
      "sha256": "..."
    },
    {
      "type": "fixed_descriptor",
      "sha256": "..."
    },
    {
      "type": "witness_script",
      "sha256": "..."
    },
    {
      "type": "capsule",
      "sha256": "..."
    }
  ]
}
```

The implementation may include file names, MIME types, or sizes, but those additions must be versioned and deterministic.

---

## 17. Human-readable policy summary

Mimir MUST produce a plain-language summary suitable for printing.

It must include:

```text
Network
Vault address
Vault witness-program hash
Owner master fingerprint and origin path
Heir master fingerprint and origin path
Owner exact unlock date and Unix timestamp
Heir exact unlock date and Unix timestamp
Branch 0, index 0 derivation
Policy-manifest hash
Capsule hash
Mimir release-manifest hash
```

It must explain:

```text
Before owner date:
    Nobody can spend.

After owner date but before heir date:
    Owner can spend.

After heir date:
    Owner or heir can spend.

The heir date does not depend on proof of death.

Later deposits do not restart the lock.

The address must not be reused after recovery.

The descriptor and witness script are essential recovery data.

The OP_RETURN capsule is only a backup.
```

The printed summary should contain the full descriptor or a clearly referenced accompanying descriptor file.

---

## 18. Creation workflow

### 18.1 Prepare participant keys

Each participant prepares:

```text
Seed or private-key backup, outside Mimir
Master fingerprint
Dedicated account path
Account xpub
```

Mimir sees only the public values.

Where a hardware wallet supplies the xpub, the xpub and fingerprint should be confirmed on the device display when supported.

### 18.2 Compile the policy

The user enters:

```text
Network
Owner public-key information
Heir public-key information
Owner exact unlock date
Heir exact unlock date
Optional encrypted note
```

Mimir:

1. Validates the inputs.
2. Derives both `/0/0` child pubkeys.
3. Constructs the fixed descriptor.
4. Constructs the BIP 388 account policy.
5. Produces the witness script.
6. Produces the P2WSH output.
7. Produces the address.
8. Builds the policy manifest.
9. Runs internal consistency checks.
10. Displays the policy timeline.

### 18.3 Create the capsule

Mimir:

1. Builds the recovery plaintext.
2. Encrypts it according to the pinned capsule profile.
3. Produces raw capsule bytes and hashes.
4. Produces the Bitcoin Core `data` hex.
5. Produces the expected OP_RETURN scriptPubKey.
6. Runs capsule self-tests.
7. Adds capsule information to the bundle.

### 18.4 Export before funding

The complete public bundle must be exported before the address is presented as ready to fund.

The user should create at least two off-chain copies on different media.

### 18.5 Independent Bitcoin Core verification

Before funding mainnet, the user must independently verify:

```text
Bitcoin Core canonical descriptor
==
Mimir fixed descriptor

Bitcoin Core derived address
==
Mimir address
```

The reference procedure uses Core’s descriptor-analysis and address-derivation capabilities. Core returns a canonical descriptor and checksum, and derives addresses from fixed or ranged descriptors.

The verification record must capture:

```text
Bitcoin Core version
Core canonical descriptor
Core descriptor checksum
Core-derived address
Mimir address
Match result
Verification date
Verifier identity or initials
```

Mimir MAY provide a screen where the user pastes Core output for exact comparison.

Mimir MUST NOT connect to Core RPC directly in v1.

### 18.6 Optional Ledger verification

Where Ledger support is used:

1. Register the BIP 388 policy.
2. Confirm the policy name, keys, and template on-device.
3. Request display of branch 0, index 0.
4. Compare the Ledger-displayed address with Mimir and Core.

Required equality:

```text
Mimir address
==
Bitcoin Core address
==
Ledger-displayed address
```

Ledger’s wallet-policy model requires the host to retain the policy and registration HMAC, while security-sensitive approval occurs on the device display. During signing, the host supplies a PSBT plus policy information and receives partial signatures.

### 18.7 Construct funding transaction in Bitcoin Core

The funding wallet receives:

```text
Vault address
Desired vault amount
Capsule data hex
```

Bitcoin Core is responsible for:

```text
Funding inputs
Multiple-input handling
Change
Fee estimation
RBF setting
PSBT creation
Funding signatures
Finalization
Broadcast
```

Core’s funded-PSBT RPC accepts ordinary address outputs and one hex-encoded `data` output that becomes OP_RETURN.

Mimir must not dictate funding UTXOs or funding-wallet key structure.

### 18.8 Review funding transaction

Before the funding wallet signs, the user must verify:

```text
Vault output address
Vault amount
Capsule output data
Change address
Fee
Network
Absence of unexpected outputs
```

The output index of the vault and capsule must not be assumed in advance because change placement may vary.

### 18.9 Preflight and broadcast

After signing:

1. Decode the final transaction.
2. Verify the vault scriptPubKey.
3. Verify the capsule OP_RETURN scriptPubKey.
4. Test mempool acceptance using the intended node.
5. Broadcast through Bitcoin Core.

### 18.10 Post-confirmation sealing

After the funding transaction has sufficient confirmations, create a funding record containing:

```json
{
  "format": "mimir-funding-record",
  "version": 1,
  "network": "bitcoin",
  "policy_manifest_sha256": "...",
  "funding_txid": "...",
  "raw_transaction_hex": "...",
  "vault_outputs": [
    {
      "vout": 0,
      "amount_sats": "0",
      "script_pubkey_hex": "0020..."
    }
  ],
  "capsule_output": {
    "vout": 0,
    "capsule_sha256": "...",
    "script_pubkey_hex": "6a..."
  },
  "confirmation": {
    "block_hash": "...",
    "block_height": 0,
    "confirmations_at_seal": 0
  }
}
```

The funding record should be created from Bitcoin Core output or independently decoded transaction data.

It is not produced by the Mimir policy compiler.

The final recovery package must include:

- Funding txid.
- Vault vout or vouts.
- Exact amount of each vault UTXO.
- Raw funding transaction.
- Capsule output index.
- Confirmation block information.

---

## 19. Monitoring workflow

### 19.1 Watch-only wallet

Create a Bitcoin Core descriptor wallet with private keys disabled.

Import the **fixed descriptor**, not the broader account descriptor, as the primary Mimir watch-only descriptor.

The import should use a timestamp appropriate to the funding transaction so Core can rescan efficiently.

Bitcoin Core descriptor wallets support private-key-disabled operation and descriptor import.

### 19.2 Monitoring responsibilities

The watch-only coordinator should monitor:

```text
Confirmed vault balance
Unconfirmed deposits
Additional deposits
Vault spends
Current chain median time past
Owner unlock proximity
Heir unlock proximity
Capsule transaction confirmation
```

### 19.3 Scheduled review

The owner should schedule reviews:

- Before the owner path becomes valid.
- Soon after the owner path becomes valid.
- Well before the heir path becomes valid.

The watch-only system should make the upcoming heir date prominent.

It must explain that rotation cannot occur before `T_OWNER` under the v1 policy.

### 19.4 Additional deposits

If the address receives a later deposit, the monitor must warn:

> This deposit uses the original absolute unlock dates. Its remaining lock duration is shorter than the original vault duration.

Monitoring software must not assume every UTXO was created at the original funding time.

---

## 20. Software recovery with Bitcoin Core

### 20.1 Coordinator role

The online Core coordinator:

1. Loads the fixed public descriptor.
2. Locates all unspent outputs belonging to the vault.
3. Selects one valid spending path.
4. Constructs a PSBT.
5. Sets a valid transaction locktime.
6. Sets non-final sequences.
7. Calculates the fee.
8. Sends all funds to a newly generated ordinary wallet address by default.
9. Supplies all information required by an offline signer.

### 20.2 Reference recovery transaction

The recommended v1 recovery transaction:

```text
Inputs:
    One or more UTXOs belonging to one Mimir fixed descriptor.

Outputs:
    Exactly one ordinary recovery destination.

Change:
    None back to the old Mimir address.

Sighash:
    SIGHASH_ALL.

Locktime:
    At least the selected branch timestamp.

Sequences:
    Non-final.
    RBF-compatible is recommended.
```

The system may support more complex Core-created transactions, but the certified Mimir recovery procedure should remain a complete sweep.

### 20.3 Multi-input behavior

Multiple inputs are supported when all Mimir inputs:

- Belong to the same fixed descriptor.
- Use the same selected spending path.
- Share compatible absolute-lock requirements.

Combining different Mimir policies in one recovery transaction is outside the certified v1 workflow.

### 20.4 PSBT contents

The coordinator must ensure the PSBT contains sufficient information for offline verification and signing, including:

```text
Previous outpoints
Previous-output amounts
Previous-output scriptPubKeys
Witness script
BIP32 derivation information
Unsigned transaction
Locktime
Sequences
Outputs
Sighash information
```

### 20.5 Offline review

Before exposing private material, the offline signer must decode and inspect the PSBT.

The review must verify:

```text
Every Mimir input belongs to the expected fixed descriptor
Every input amount is known
No unexpected input is present
Recovery destination is correct
Output amount is correct
Fee is correct and reasonable
There is no hidden change output
Locktime satisfies the selected path
All relevant sequences are non-final
Sighash is SIGHASH_ALL
Network and destination type are correct
```

Bitcoin Core can decode a PSBT into its unsigned transaction, key origins, scripts, and other fields.

A transaction must not be signed merely because Core reports that it is signable.

### 20.6 Private signing descriptor

The offline signing descriptor should contain private material for exactly one selected participant.

Owner recovery:

```text
OWNER account xpub is replaced by the corresponding xprv.
HEIR remains xpub-only.
```

Heir recovery:

```text
HEIR account xpub is replaced by the corresponding xprv.
OWNER remains xpub-only.
```

The private descriptor must otherwise describe the same fixed script.

Supplying only the intended branch’s private material:

- Reduces ambiguity.
- Reduces accidental signing with the wrong role.
- Limits secret exposure.
- Makes branch selection easier to audit.

### 20.7 Offline Core signing

The reference software-signing operation uses descriptor-based PSBT processing.

Bitcoin Core’s `descriptorprocesspsbt` can update SegWit inputs from descriptors, sign inputs for which private descriptor information is available, and finalize when a complete satisfaction is possible.

The exact command invocation is operational documentation rather than part of the Mimir compiler.

The compatibility test suite must prove that the selected Core release correctly signs both Mimir paths.

### 20.8 Private-material handling

The reference ceremony should prefer:

- A dedicated offline machine.
- An ephemeral Core data directory.
- No network connectivity.
- No shell history containing xprvs.
- No command-line arguments visible in process listings.
- No persistent logs containing private descriptors.
- Power-off after signing.

A persistent encrypted Core descriptor wallet MAY be used instead when operational simplicity is more important, provided the user understands that an encrypted wallet database remains.

Mimir itself must never accept the private descriptor.

### 20.9 Finalization and broadcast

The signed PSBT returns to the online coordinator.

The coordinator:

1. Combines signatures if necessary.
2. Finalizes the PSBT.
3. Extracts the final transaction.
4. Decodes the final transaction again.
5. Verifies that transaction semantics did not change.
6. Runs mempool-policy testing.
7. Broadcasts through Bitcoin Core.
8. Monitors confirmation.

PSBT finalization and transaction extraction are defined as distinct roles in BIP 174, and Bitcoin Core exposes finalization and broadcast operations.

---

## 21. Optional Ledger recovery

### 21.1 Architectural rule

Ledger support is optional and separate.

The funded vault must remain recoverable without:

- The original Ledger.
- The original Ledger firmware.
- The Ledger adapter.
- The registration HMAC.
- Ledger’s continued commercial existence.

### 21.2 Adapter interface

The logical adapter interface is:

```text
get_device_information()
get_master_fingerprint()
get_extended_public_key(path, display)
register_wallet_policy(name, template, keys)
get_wallet_address(policy, hmac, branch, index, display)
sign_psbt(policy, hmac, psbt)
```

Exact transport protocols and programming languages are not prescribed.

### 21.3 Registration

The adapter must register the exact BIP 388 policy generated by Mimir.

It must not independently reinterpret or rewrite:

- The lock timestamps.
- The key ordering.
- The role mapping.
- The derivation scheme.
- The Miniscript structure.

The registration record should contain:

```text
Device model
Device firmware version
Bitcoin application version
Adapter version
Policy name
Policy template
Key-information vector
Policy identifier
Registration HMAC
Displayed branch and index
Displayed vault address
Date of registration
```

The registration HMAC is not a private signing key, but it is signer-specific operational metadata and should be stored in the recovery package.

### 21.4 Address verification

The adapter must request on-device display of:

```text
branch 0
index 0
```

The user must compare the complete address against:

- Mimir.
- Bitcoin Core.
- The Ledger display.

### 21.5 Signing

The Core coordinator constructs the PSBT.

The adapter sends:

```text
Exact PSBT
Exact registered policy
Exact registration HMAC
```

The device returns partial signatures.

The adapter must:

- Verify that the unsigned transaction has not changed.
- Add only the returned signature fields.
- Return the resulting PSBT to Core.
- Never finalize or broadcast unless explicitly implemented as a separate, documented coordinator function.

Ledger’s documented model signs PSBT inputs whose BIP32 derivations match the device and leaves insertion, finalization, extraction, and broadcast to the host.

### 21.6 Compatibility matrix

Ledger support must be declared only for exact tested combinations:

```text
Device model
Device firmware
Bitcoin application version
Adapter version
Mimir template version
PSBT version
Core coordinator version
Test-vector hash
```

Unknown or untested versions must generate a warning and must not be silently treated as certified.

### 21.7 Required Ledger tests

A Ledger combination is certified only after it can:

1. Export and display the expected account xpub.
2. Register the exact Mimir policy.
3. Display the exact branch-0/index-0 address.
4. Reject a changed timestamp policy unless separately approved.
5. Reject a changed participant-key policy unless separately approved.
6. Sign the owner path after its lock.
7. Sign the heir path after its lock.
8. Refuse or clearly warn on an invalid locktime.
9. Refuse or clearly warn on unsupported sighash types.
10. Display the recovery destination, amount, and fee.
11. Produce signatures accepted by Bitcoin Core.
12. Complete a regtest or signet spend for both paths.

---

## 22. Rotation workflow

A new Mimir vault is not created by reusing the old descriptor.

Rotation requires:

```text
New exact timestamps
Preferably new dedicated account xpubs
New policy manifest
New address
New capsule
New bundle
New independent Core verification
New funding transaction
```

When the owner path becomes valid, the owner may sweep the old vault into a new Mimir vault.

The rotation transaction may contain:

```text
Inputs:
    Old Mimir vault UTXOs

Outputs:
    New Mimir vault address
    New capsule OP_RETURN
    Any coordinator-required fee handling
```

Bitcoin Core constructs and signs the transaction according to the same recovery principles.

Mimir only creates the new policy and new capsule.

The old descriptor must not be treated as renewed merely because new funds were sent to it.

---

## 23. Recovery without the on-chain capsule

The system must work when:

- No capsule was published.
- The capsule transaction was censored.
- The capsule bytes are corrupted.
- BIP 138 tooling is unavailable.
- The participant xpub used for decryption was lost.
- The capsule profile is no longer widely implemented.

The complete off-chain recovery path is:

```text
1. Obtain the fixed descriptor.
2. Verify its checksum.
3. Import it into a watch-only Core wallet.
4. Locate the vault UTXO.
5. Obtain one participant’s seed or account private key.
6. Reconstruct the corresponding private descriptor.
7. Construct and review the PSBT.
8. Sign with offline Core.
9. Finalize and broadcast.
```

This is the primary recovery path.

---

## 24. Recovery from the on-chain capsule

A participant recovering from the capsule should:

1. Obtain the capsule transaction ID from the physical recovery package or another locator.
2. Retrieve the raw confirmed transaction.
3. Extract the OP_RETURN data bytes.
4. Confirm the capsule magic and profile.
5. Derive or export the documented account xpub.
6. Decrypt the capsule using the archived reference decoder.
7. Verify the decrypted policy-manifest hash.
8. Verify the descriptor checksum.
9. Reproduce the P2WSH address in Bitcoin Core.
10. Compare it with the actual funded output.
11. Continue with the standard Core recovery workflow.

The recovery instructions must not tell the heir to import their mnemonic into an arbitrary online wallet merely to decrypt metadata.

Only the required account xpub should be exported for capsule decryption.

---

## 25. Bitcoin Core reference-profile requirements

Mimir does not implement Core integration, but each Mimir release must publish a tested Core reference profile.

The profile must record:

```text
Bitcoin Core version
Operating system used for tests
Descriptor support assumptions
Required RPC capability list
Funding procedure
Watch-only import procedure
Recovery-PSBT procedure
Offline-signing procedure
Finalization procedure
Broadcast procedure
Known limitations
Test-vector hashes
```

The implementation must not identify a Core release as compatible solely because the relevant RPC method names exist.

Compatibility requires complete end-to-end tests for:

- Descriptor canonicalization.
- Address derivation.
- Watch-only discovery.
- Funding with OP_RETURN.
- Owner-path signing.
- Heir-path signing.
- Multi-input recovery.
- Fee estimation.
- PSBT finalization.
- Mempool acceptance.

---

## 26. Mimir web application requirements

The reference application may be a local web application or single-file offline artifact.

### 26.1 Network behavior

The production artifact MUST:

- Work without an internet connection.
- Make no outbound network request.
- Load no external script.
- Load no external stylesheet.
- Load no external font.
- Load no remote image.
- Use no analytics.
- Use no telemetry.
- Use no remote error reporting.
- Use no CDN.
- Use no dynamic package loading.
- Use no service worker.

A strict content-security policy should disable network connections.

### 26.2 Persistence

The reference application MUST NOT store policy inputs or output automatically in:

- Local storage.
- IndexedDB.
- Cookies.
- Browser history.
- URL parameters.
- Remote storage.

The user explicitly exports the bundle.

Public inputs are not spend secrets, but silent persistence creates privacy and substitution risks.

### 26.3 Secret rejection

The application must detect and reject likely:

- xprvs.
- tprvs.
- WIF private keys.
- BIP39 word sequences.
- Raw 32-byte private keys.
- Seed phrases.
- Passphrases entered into fields intended for public data.

The UI should explain:

> Mimir never needs private keys. Do not enter them.

### 26.4 No live-page trust assumption

GitHub Pages or another website may distribute documentation and downloadable artifacts.

The final mainnet policy should be generated from an externally verified immutable artifact, not from an unverified mutable live page.

The release hash must be checked outside the artifact being verified.

### 26.5 Input and output review

The UI must display:

- Full fingerprints.
- Full origin paths.
- Full xpubs in an expandable review view.
- Derived child pubkeys.
- Both exact timestamps.
- Both UTC dates.
- Fixed descriptor.
- Address.
- Witness-program hash.
- Capsule hash and size.
- Release hash.
- Core-verification status.

It must not abbreviate critical values in the only review view.

A shortened display may be used only alongside access to the complete value.

---

## 27. Error handling

Mimir must fail closed.

### 27.1 Fatal errors

Fatal errors include:

- Invalid key material.
- Unsupported network.
- Unsupported policy template.
- Timestamp-order failure.
- Descriptor-construction failure.
- Descriptor-checksum failure.
- Child-derivation failure.
- Script-compilation failure.
- Internal consistency failure.
- Capsule-encryption failure.
- Capsule self-test failure.
- Manifest-canonicalization failure.
- Missing release-profile data.

Fatal errors must prevent presentation of a fundable address.

### 27.2 Warnings

Warnings may allow export but must remain visible for:

- Nonstandard origin paths.
- Reused account xpubs.
- Timestamps close to the current date.
- Missing optional encrypted note.
- Large capsule size.
- Unverified Core compatibility.
- Unverified hardware compatibility.
- Missing off-chain backup acknowledgment.
- Mainnet use without a completed signet or regtest rehearsal.
- BIP 138 profile based on a draft revision.

### 27.3 No silent normalization

Mimir must not silently:

- Swap owner and heir.
- Sort participant roles.
- Change account paths.
- Convert a private key into a public key.
- Change a network prefix.
- Adjust a timestamp.
- Round a date.
- Replace unsupported characters in a path.
- Drop unknown manifest fields when validating an imported bundle.
- Rewrite a capsule profile to a newer revision.

Any normalization must be shown and explicitly accepted.

---

## 28. Testing requirements

### 28.1 Policy test vectors

Publish exact vectors for:

- Mainnet.
- Regtest.
- At least one recommended origin path.
- At least one nonstandard but allowed origin path.
- Multiple timestamp values.
- Both owner and heir key orderings.
- Descriptor checksums.
- Derived child pubkeys.
- Witness scripts.
- scriptPubKeys.
- Addresses.
- Policy-manifest hashes.

### 28.2 Differential Bitcoin Core tests

For every vector:

```text
Mimir canonical descriptor == Core canonical descriptor

Mimir address == Core-derived address

Mimir script is solvable according to the tested Core profile
```

Differences must fail the release build.

### 28.3 Consensus-path tests

On regtest, test:

```text
Before T_OWNER:
    owner fails
    heir fails

At/after T_OWNER but before T_HEIR:
    owner succeeds
    heir fails

At/after T_HEIR:
    owner succeeds
    heir succeeds

Final nSequence:
    CLTV spend fails

Wrong locktime type:
    spend fails

nLockTime below selected branch:
    spend fails

Wrong key:
    spend fails

Modified witness script:
    spend fails
```

### 28.4 Funding tests

Test Core funding with:

- One funding input.
- Multiple funding inputs.
- Change.
- No change.
- Capsule in the funding transaction.
- Capsule in a separate transaction.
- RBF enabled.
- A large but supported capsule.
- Relay rejection.
- Mempool acceptance.
- Confirmed-transaction verification.

### 28.5 Monitoring tests

Verify that the watch-only wallet:

- Detects the initial funding.
- Detects multiple deposits.
- Reports exact amounts.
- Detects a spend.
- Does not require private keys.
- Can be recreated solely from the fixed descriptor and timestamp.

### 28.6 Software-recovery tests

Test:

- Owner-path single-input sweep.
- Owner-path multi-input sweep.
- Heir-path single-input sweep.
- Heir-path multi-input sweep.
- Only owner xprv supplied.
- Only heir xprv supplied.
- Wrong xprv.
- Wrong descriptor.
- Wrong input amount.
- Unexpected output.
- Excessive fee.
- Finalization.
- Mempool acceptance.
- Broadcast on regtest.

### 28.7 Capsule tests

For the pinned capsule profile:

- Pass all upstream test vectors.
- Encrypt and decrypt the Mimir recovery payload.
- Allow owner account xpub to decrypt.
- Allow heir account xpub to decrypt.
- Reject an unrelated xpub.
- Reject modified ciphertext.
- Reject modified authentication data.
- Reject wrong profile version.
- Reject truncated input.
- Enforce size bounds.
- Confirm the decrypted descriptor hash.
- Confirm the raw bytes survive OP_RETURN serialization and extraction unchanged.
- Scan plaintext for forbidden private-material fields.

### 28.8 Parser and fuzz tests

Fuzz:

- Extended-key parsing.
- Origin paths.
- Descriptor generation inputs.
- Timestamp parsing.
- Canonical JSON parsing.
- Duplicate JSON keys.
- Capsule decoding.
- Hex decoding.
- Unicode labels and notes.
- Oversized inputs.
- Malformed bundle manifests.

### 28.9 UI tests

Verify that the UI:

- Never accepts private material.
- Shows UTC and integer timestamps.
- Shows the correct timeline.
- Prevents export on fatal errors.
- Marks the vault unverified before Core comparison.
- Preserves complete values in exports.
- Works offline.
- Generates no network traffic.
- Produces identical policy output in supported browsers or environments.

### 28.10 Reproducible-build tests

At least two independent clean environments should produce byte-identical release artifacts from the same source and build profile.

---

## 29. Mainnet release gates

Mainnet mode must not be declared production-ready until:

1. The policy template is frozen.
2. The manifest schemas are frozen.
3. All policy vectors pass.
4. Bitcoin Core independently matches every descriptor and address.
5. Both spending paths succeed on regtest.
6. Both spending paths succeed in a small-value public test-network rehearsal.
7. A small-value mainnet round trip succeeds.
8. Multi-input recovery succeeds.
9. Capsule test vectors pass.
10. The exact BIP 138 profile is pinned.
11. The reference capsule decoder is archived.
12. The release artifact is reproducible.
13. The release manifest is signed.
14. The release artifact SHA256 is published through multiple channels.
15. The complete recovery process has been followed by a person who did not write the implementation.
16. An external security review has examined the policy compiler and artifact-generation path.
17. Known limitations are published prominently.

---

## 30. Release and immutability model

### 30.1 Release artifacts

A release should include:

```text
Source archive
Exact production artifact
Release manifest
Dependency manifest
Build instructions
Reproducible-build environment
Policy test vectors
Capsule test vectors
Bitcoin Core compatibility profile
Optional Ledger compatibility profile
Human recovery guide
Machine-readable schemas
SHA256SUMS
Maintainer signatures
```

### 30.2 Release manifest

The release manifest should bind:

```text
Mimir version
Source commit
Source archive SHA256
Production artifact SHA256
Policy template identifier
Policy schema version
Capsule profile identifier
Capsule specification commit
Dependency versions and hashes
Test-vector hashes
Build recipe hash
Core compatibility-profile hash
Ledger adapter compatibility-profile hash, if any
```

A source commit hash alone is not an adequate release commitment.

### 30.3 Immutable versions

The rule is:

```text
Mimir v1 remains immutable.
Mimir v2 is a separate artifact.
```

No release may silently change:

- Descriptor semantics.
- Key order.
- Child derivation.
- Timestamp interpretation.
- Manifest canonicalization.
- Capsule binary profile.
- Test-vector output.

### 30.4 No automatic updates

The production artifact must contain no automatic update mechanism.

Documentation may notify users that a newer immutable version exists, but a previously downloaded artifact must not replace itself.

### 30.5 On-chain release anchor

The project MAY publish:

```text
OP_RETURN:
    protocol marker
    SHA256(release manifest canonical bytes)
```

The release-manifest hash should also appear in the user’s recovery package and encrypted capsule.

An on-chain release anchor supplements signatures and independent mirrors; it does not replace them.

---

## 31. Privacy considerations

Mimir must explain:

- The fixed descriptor reveals all participant xpubs, roles, and lock dates to anyone who obtains it.
- A watch-only Core wallet necessarily possesses this public information.
- The on-chain capsule hides this information from the general public only while eligible xpubs remain private.
- Reusing an account xpub across services or vaults links those uses.
- The BIP 138 header may identify the OP_RETURN payload as encrypted wallet metadata.
- Placing the capsule in the funding transaction links the capsule to the vault output.
- A separate capsule transaction may improve or worsen privacy depending on its funding inputs and change.
- The P2WSH script becomes public when the vault is spent.
- Both participant child public keys and exact lock conditions become visible in the spending witness.

Mimir v1 does not promise indistinguishability or chain-analysis resistance.

---

## 32. Operational recovery package

The final physical or offline inheritance package should contain:

```text
Participant seed or private-key backup
Any BIP39 passphrase, stored according to the user’s plan
Master fingerprint
Exact account path
Account xpub
Fixed descriptor
Witness script
Vault address
Policy-manifest hash
Funding txid
Vault vout or vouts
Exact UTXO amounts
Raw funding transaction
Capsule transaction ID and output index
Capsule profile and decoder
Mimir release-manifest hash
Bitcoin Core recovery instructions
Optional Ledger registration record
Legal or executor instructions
```

The heir’s instructions must state:

```text
Do not type the seed into an arbitrary online wallet.

Export or derive only the documented account xpub to decrypt the capsule.

Use the descriptor to locate and reconstruct the vault.

Wait until the heir lock is valid according to Bitcoin consensus.

Sweep the full vault to a new ordinary wallet.

Verify the destination and fee before signing.

Do not reuse the old vault address.
```

---

## 33. Implementation freedom

The following choices are intentionally nonnormative:

- Programming language.
- Web framework.
- Whether the core is also exposed as a CLI or library.
- Internal class or module names.
- UI layout.
- Styling.
- Exact archive format.
- Exact Bitcoin Core command-line wrapper.
- PSBT transport medium.
- Whether public artifacts are displayed as QR codes.
- Operating system used for normal public-data compilation.
- Choice of well-reviewed descriptor or secp256k1 library.
- Choice of RFC 8785 implementation.
- Whether the capsule is placed in the funding transaction or a separate publication transaction.
- Whether the offline signer uses a temporary private descriptor directly or an encrypted descriptor wallet.
- How a future Ledger bridge communicates with Core.

These choices must not change the externally visible policy, artifact formats, or security boundaries.

---

## 34. Deferred features

The following must not delay a correct v1 and should be deferred:

- Taproot.
- Tapscript.
- MuSig2.
- More than two participants.
- Threshold heir groups.
- Multiple heir dates.
- Emergency guardian paths.
- Relative timelocks.
- Destination-constrained recovery.
- Vault covenants.
- Automatic rotation.
- Trezor signing.
- Generic HWI support.
- Mobile camera scanning.
- Seed generation.
- Dice conversion.
- BIP39 handling inside Mimir.
- Arbitrary policy import.
- BIP 139 payload support.
- Cloud synchronization.
- Hosted Core RPC integration.
- Automatic transaction building.
- Automatic blockchain discovery.
- Automatic legal-document generation.

A later version may add these only through a new immutable template or component profile.

---

## 35. Recommended implementation sequence

### Milestone 1: freeze policy semantics

Deliver:

- Exact template identifier.
- Exact fixed descriptor form.
- Exact branch and index.
- Input schema.
- Policy manifest schema.
- Initial test vectors.

Do not build the UI first.

### Milestone 2: pure policy compiler

Deliver a deterministic library or module that:

- Parses public inputs.
- Validates keys and dates.
- Derives child pubkeys.
- Produces descriptor, script, address, policy manifest, and hashes.
- Runs without UI or network.

### Milestone 3: Bitcoin Core differential harness

Deliver automated tests that:

- Start regtest Core.
- Compare descriptors and addresses.
- Fund the vault.
- Exercise both paths.
- Exercise invalid boundary conditions.

### Milestone 4: capsule profile

Deliver:

- Pinned BIP 138 revision.
- Archived implementation.
- Capsule payload schema.
- Encryption and decryption tests.
- OP_RETURN encoding.
- Size and policy tests.

### Milestone 5: bundle and human review

Deliver:

- Bundle manifest.
- Printable summary.
- Verification record.
- Funding record template.
- Recovery instructions.
- Mainnet guardrails.

### Milestone 6: reference Core workflows

Deliver tested procedures for:

- Creation verification.
- Funding.
- Watch-only monitoring.
- Owner recovery.
- Heir recovery.
- Multi-input sweep.
- Finalization and broadcast.

### Milestone 7: production web artifact

Deliver:

- Fully offline operation.
- No network dependencies.
- Reproducible build.
- Self-tests.
- Export workflow.
- Release manifest.

### Milestone 8: optional Ledger adapter

Implement only after the Core software-recovery path is complete and independently tested.

---

## 36. Definition of done

Mimir v1 is complete when:

- It accepts only public key information and exact dates.
- It implements exactly one frozen two-path P2WSH policy.
- It deterministically emits a checksummed fixed descriptor.
- Its descriptor and address match Bitcoin Core exactly.
- It emits an exact witness script and script commitment.
- It emits a BIP 388 account policy.
- It emits a pinned, interoperable encrypted capsule.
- It emits the OP_RETURN data and expected script.
- It exports a complete canonical public bundle.
- It never accepts or handles private keys.
- It never builds or signs transactions.
- It works entirely offline.
- Bitcoin Core can monitor the fixed descriptor.
- Bitcoin Core can sign the owner path from an owner private descriptor.
- Bitcoin Core can sign the heir path from an heir private descriptor.
- Bitcoin Core can recover multiple UTXOs from one vault.
- Recovery works without Mimir.
- Recovery works without the capsule.
- Recovery works without Ledger.
- Every release is reproducible and immutable.
- A person unfamiliar with the implementation can follow the archived documentation and complete a regtest recovery.

---

## 37. Final architectural statement

Mimir v1 is not a Bitcoin wallet.

It is a small, independently verifiable compiler for one carefully defined long-term vault policy, plus an encrypted recovery-capsule generator.

Its responsibility ends after producing and exporting:

```text
Policy
Descriptor
Witness script
Address
Hardware-wallet policy
Encrypted capsule
OP_RETURN data
Recovery bundle
Verification procedures
```

Bitcoin Core owns:

```text
Blockchain state
UTXO discovery
Coin selection
Transaction construction
Fees
Change
PSBT handling
Software signing
Finalization
Mempool testing
Broadcast
Monitoring
```

A separate Ledger adapter may provide hardware signing, but the descriptor and Bitcoin Core software-recovery path remain authoritative.

The core design rule is:

> Funds must depend on Bitcoin consensus, participant keys, and standard recovery artifacts—not on Mimir continuing to exist.
