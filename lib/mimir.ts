import { compileMiniscript } from "@bitcoinerlab/miniscript";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bech32 } from "@scure/base";
import { HDKey, type Versions } from "@scure/bip32";

export const TEMPLATE_ID = "mimir-absolute-two-path-v1" as const;
export const CAPSULE_PROFILE_ID = "mimir-bip138-profile-1-preview" as const;
export const BIP138_SPEC_COMMIT =
  "5af62cba9958a519218bcad8a0aae9e2090bb5bd" as const;
export const BIP138_REFERENCE_COMMIT =
  "8a0dd30dff9956913e60f0193461ccbf2fa7de7c" as const;
export const BIP138_VECTOR_SET_SHA256 =
  "24f395187ac4d5d57ebf06ebd6d1a1c362351d54634bdc5b78cfe0d9244669c2" as const;
export const RELEASE_ID = "mimir-v1-preview.1" as const;
// Miniscript after(n) is restricted to n < 2^31 even though raw CLTV can
// consume a wider uint32 value. Failing closed here preserves Core parity.
export const MAX_LOCKTIME = 0x7fffffff;
export const MIN_TIMESTAMP_LOCK = 500_000_000;

export type NetworkName = "bitcoin" | "regtest" | "signet";
export type Role = "owner" | "heir";

export type ParticipantInput = {
  role: Role;
  master_fingerprint: string;
  origin_path: string;
  xpub: string;
};

export type PolicyRequest = {
  format: "mimir-policy-request";
  version: 1;
  network: NetworkName;
  template_id: typeof TEMPLATE_ID;
  vault_derivation: { branch: 0; index: 0 };
  participants: [ParticipantInput, ParticipantInput];
  locks: { owner_unix: number; heir_unix: number };
};

export type PolicyManifest = {
  format: "mimir-policy";
  version: 1;
  network: NetworkName;
  template_id: typeof TEMPLATE_ID;
  vault_derivation: { branch: 0; index: 0; child_suffix: "/0/0" };
  participants: Array<
    ParticipantInput & {
      derived_pubkey: string;
    }
  >;
  locks: {
    owner: { unix: number; utc: string };
    heir: { unix: number; utc: string };
  };
  descriptor: {
    fixed: string;
    account_multipath: string;
  };
  wallet_policy: {
    template: string;
    keys: [string, string];
    funded_branch: 0;
    funded_index: 0;
  };
  script: {
    witness_script_hex: string;
    witness_program_sha256: string;
    script_pubkey_hex: string;
  };
  address: string;
};

export type InvariantResult = {
  id: string;
  label: string;
  ok: boolean;
};

export type CompiledPolicy = {
  request: PolicyRequest;
  manifest: PolicyManifest;
  canonical_manifest: string;
  policy_manifest_sha256: string;
  release_manifest: typeof RELEASE_MANIFEST;
  release_manifest_sha256: string;
  owner_root_xonly: Uint8Array;
  heir_root_xonly: Uint8Array;
  warnings: string[];
  invariants: InvariantResult[];
};

export type CapsuleResult = {
  profile: typeof CAPSULE_PROFILE_MANIFEST;
  recovery_plaintext: Record<string, unknown>;
  recovery_plaintext_canonical: string;
  raw_bytes: Uint8Array;
  raw_base64: string;
  data_hex: string;
  byte_length: number;
  capsule_sha256: string;
  op_return_script_pubkey_hex: string;
  op_return_script_byte_length: number;
  recipient_count: number;
  encoded_secret_count: number;
  self_test: {
    owner_can_decrypt: boolean;
    heir_can_decrypt: boolean;
    header_valid: boolean;
  };
};

export type BundleArtifact = {
  type: string;
  filename: string;
  media_type: string;
  encoding: "utf8" | "base64";
  content: string;
  byte_length: number;
  sha256: string;
};

export type VaultBundle = {
  format: "mimir-vault-bundle-package";
  version: 1;
  status: "pre-mainnet-preview";
  notice: string;
  bundle_manifest: {
    format: "mimir-vault-bundle";
    version: 1;
    policy_manifest_sha256: string;
    compiler_release_manifest_sha256: string;
    capsule_profile_id: typeof CAPSULE_PROFILE_ID;
    artifacts: Array<{
      type: string;
      filename: string;
      sha256: string;
      byte_length: number;
    }>;
  };
  artifacts: BundleArtifact[];
};

const MAINNET_VERSIONS: Versions = {
  public: 0x0488b21e,
  private: 0x0488ade4,
};

const TESTNET_VERSIONS: Versions = {
  public: 0x043587cf,
  private: 0x04358394,
};

const NETWORKS: Record<
  NetworkName,
  { label: string; hrp: string; versions: Versions; coinType: 0 | 1 }
> = {
  bitcoin: {
    label: "Bitcoin mainnet",
    hrp: "bc",
    versions: MAINNET_VERSIONS,
    coinType: 0,
  },
  regtest: {
    label: "Bitcoin regtest",
    hrp: "bcrt",
    versions: TESTNET_VERSIONS,
    coinType: 1,
  },
  signet: {
    label: "Bitcoin signet",
    hrp: "tb",
    versions: TESTNET_VERSIONS,
    coinType: 1,
  },
};

export const CAPSULE_PROFILE_MANIFEST = {
  format: "mimir-capsule-profile",
  version: 1,
  profile_id: CAPSULE_PROFILE_ID,
  status: "draft-pinned-preview",
  proposal: "BIP 138",
  specification_commit: BIP138_SPEC_COMMIT,
  reference_implementation_commit: BIP138_REFERENCE_COMMIT,
  tested_cipher_implementation: {
    package: "@noble/ciphers",
    version: "2.3.0",
    commit: "c9b7ed1017ffd342fbca186c108ae04053d7857b",
  },
  test_vector_set_sha256: BIP138_VECTOR_SET_SHA256,
  test_vector_set_hash_scheme:
    "SHA256(UTF8(sorted '<file_sha256>  <filename>\\n' lines))",
  encryption_algorithm: "CHACHA20_POLY1305",
  binary_format_version: 1,
  content_type: {
    type: "vendor-specific-opaque-tag",
    tag_utf8: "mimir/recovery-v1",
  },
  derivation_paths_in_header: false,
  individual_secret_bucket: 5,
  payload_padding: "none-static-recovery-object",
} as const;

export const RELEASE_MANIFEST = {
  format: "mimir-release",
  version: 1,
  mimir_version: RELEASE_ID,
  status: "pre-mainnet-preview",
  source_commit: "unreleased-workspace-preview",
  policy_template_id: TEMPLATE_ID,
  policy_schema_version: 1,
  vault_derivation: "/0/0",
  capsule_profile_id: CAPSULE_PROFILE_ID,
  capsule_specification_commit: BIP138_SPEC_COMMIT,
  capsule_reference_implementation_commit: BIP138_REFERENCE_COMMIT,
  capsule_test_vector_set_sha256: BIP138_VECTOR_SET_SHA256,
  dependencies: {
    bip32: {
      package: "@scure/bip32",
      version: "2.3.0",
      commit: "7ee63a35184ee9d5f184668526e06d3255bce586",
    },
    miniscript: {
      package: "@bitcoinerlab/miniscript",
      version: "2.0.0",
      commit: "1dae3936a9779e1b99fd8b024dd109ac675e6144",
    },
    cipher: CAPSULE_PROFILE_MANIFEST.tested_cipher_implementation,
  },
  core_reference_profile: {
    target_version: "31.0",
    status: "unverified-preview",
    end_to_end_certified: false,
  },
  mainnet_release_gates_complete: false,
  immutable_notice:
    "This preview profile is frozen for generated artifacts but is not a production-ready Mimir v1 release.",
} as const;

const TEXT_ENCODER = new TextEncoder();
const DESCRIPTOR_INPUT_CHARSET =
  "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
const DESCRIPTOR_CHECKSUM_CHARSET =
  "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const DESCRIPTOR_GENERATORS = [
  0xf5dee51989n,
  0xa9fdca3312n,
  0x1bab10e32dn,
  0x3706b1677an,
  0x644d626ffdn,
];
const BIP341_NUMS_X =
  "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const length = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

export function hexToBytes(hex: string): Uint8Array {
  if (!/^(?:[0-9a-fA-F]{2})*$/.test(hex)) {
    throw new Error("Invalid hexadecimal data.");
  }
  return Uint8Array.from(
    { length: hex.length / 2 },
    (_, index) => Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16),
  );
}

function xor32(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length !== 32 || b.length !== 32) {
    throw new Error("Internal error: BIP 138 XOR inputs must be 32 bytes.");
  }
  return Uint8Array.from(a, (value, index) => value ^ b[index]);
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  for (let index = 0; index < Math.min(a.length, b.length); index += 1) {
    if (a[index] !== b[index]) return a[index] - b[index];
  }
  return a.length - b.length;
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let index = 0; index < a.length; index += 1) {
    difference |= a[index] ^ b[index];
  }
  return difference === 0;
}

function randomBytes(length: number): Uint8Array {
  if (!globalThis.crypto?.getRandomValues) {
    throw new Error("Secure browser randomness is unavailable; capsule creation stopped.");
  }
  const output = new Uint8Array(length);
  globalThis.crypto.getRandomValues(output);
  return output;
}

function randomNonZeroNonce(): Uint8Array {
  for (;;) {
    const nonce = randomBytes(12);
    if (nonce.some((value) => value !== 0)) return nonce;
  }
}

function taggedHash(tag: string, message: Uint8Array): Uint8Array {
  const tagHash = sha256(TEXT_ENCODER.encode(tag));
  return sha256(concatBytes(tagHash, tagHash, message));
}

export function sha256Hex(value: string | Uint8Array): string {
  const bytes = typeof value === "string" ? TEXT_ENCODER.encode(value) : value;
  return bytesToHex(sha256(bytes));
}

export function canonicalizeJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("RFC 8785 canonical JSON cannot contain non-finite numbers.");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalizeJson(entry)).join(",")}]`;
  }
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const entries = Object.keys(record)
      .sort()
      .map((key) => {
        if (typeof record[key] === "undefined") {
          throw new Error("RFC 8785 canonical JSON cannot contain undefined values.");
        }
        return `${JSON.stringify(key)}:${canonicalizeJson(record[key])}`;
      });
    return `{${entries.join(",")}}`;
  }
  throw new Error(`Unsupported canonical JSON value: ${typeof value}.`);
}

function descriptorPolymod(symbols: number[]): bigint {
  let checksum = 1n;
  for (const symbol of symbols) {
    const top = checksum >> 35n;
    checksum = ((checksum & 0x7ffffffffn) << 5n) ^ BigInt(symbol);
    for (let bit = 0; bit < 5; bit += 1) {
      if (((top >> BigInt(bit)) & 1n) !== 0n) {
        checksum ^= DESCRIPTOR_GENERATORS[bit];
      }
    }
  }
  return checksum;
}

function descriptorExpand(descriptor: string): number[] {
  const symbols: number[] = [];
  const groups: number[] = [];
  for (const character of descriptor) {
    const position = DESCRIPTOR_INPUT_CHARSET.indexOf(character);
    if (position === -1) {
      throw new Error(`Descriptor contains unsupported character ${JSON.stringify(character)}.`);
    }
    symbols.push(position & 31);
    groups.push(position >> 5);
    if (groups.length === 3) {
      symbols.push(groups[0] * 9 + groups[1] * 3 + groups[2]);
      groups.length = 0;
    }
  }
  if (groups.length === 1) symbols.push(groups[0]);
  if (groups.length === 2) symbols.push(groups[0] * 3 + groups[1]);
  return symbols;
}

export function descriptorChecksum(descriptor: string): string {
  const symbols = descriptorExpand(descriptor).concat(new Array(8).fill(0));
  const checksum = descriptorPolymod(symbols) ^ 1n;
  return Array.from(
    { length: 8 },
    (_, index) =>
      DESCRIPTOR_CHECKSUM_CHARSET[
        Number((checksum >> BigInt(5 * (7 - index))) & 31n)
      ],
  ).join("");
}

export function addDescriptorChecksum(descriptor: string): string {
  return `${descriptor}#${descriptorChecksum(descriptor)}`;
}

function encodePushData(data: Uint8Array): Uint8Array {
  if (data.length <= 75) return concatBytes(Uint8Array.of(data.length), data);
  if (data.length <= 0xff) {
    return concatBytes(Uint8Array.of(0x4c, data.length), data);
  }
  if (data.length <= 0xffff) {
    return concatBytes(
      Uint8Array.of(0x4d, data.length & 0xff, (data.length >> 8) & 0xff),
      data,
    );
  }
  return concatBytes(
    Uint8Array.of(
      0x4e,
      data.length & 0xff,
      (data.length >> 8) & 0xff,
      (data.length >> 16) & 0xff,
      (data.length >> 24) & 0xff,
    ),
    data,
  );
}

const OPCODES: Record<string, number> = {
  OP_0: 0x00,
  OP_IF: 0x63,
  OP_ELSE: 0x67,
  OP_ENDIF: 0x68,
  OP_VERIFY: 0x69,
  OP_CHECKSIG: 0xac,
  OP_CHECKLOCKTIMEVERIFY: 0xb1,
};

function asmToScript(asm: string): Uint8Array {
  const chunks: Uint8Array[] = [];
  for (const token of asm.trim().split(/\s+/)) {
    if (token in OPCODES) {
      chunks.push(Uint8Array.of(OPCODES[token]));
      continue;
    }
    const pushed = token.match(/^<([0-9a-fA-F]*)>$/);
    if (!pushed) throw new Error(`Unsupported compiler token: ${token}.`);
    chunks.push(encodePushData(hexToBytes(pushed[1])));
  }
  return concatBytes(...chunks);
}

function compactSize(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error("CompactSize value is out of range.");
  }
  if (value < 0xfd) return Uint8Array.of(value);
  if (value <= 0xffff) {
    return Uint8Array.of(0xfd, value & 0xff, (value >> 8) & 0xff);
  }
  if (value <= 0xffffffff) {
    return Uint8Array.of(
      0xfe,
      value & 0xff,
      (value >>> 8) & 0xff,
      (value >>> 16) & 0xff,
      (value >>> 24) & 0xff,
    );
  }
  const big = BigInt(value);
  return Uint8Array.of(
    0xff,
    ...Array.from({ length: 8 }, (_, index) =>
      Number((big >> BigInt(index * 8)) & 0xffn),
    ),
  );
}

function readCompactSize(
  bytes: Uint8Array,
  offset: number,
): { value: number; next: number } {
  const first = bytes[offset];
  if (typeof first === "undefined") throw new Error("Truncated CompactSize.");
  if (first < 0xfd) return { value: first, next: offset + 1 };
  const size = first === 0xfd ? 2 : first === 0xfe ? 4 : 8;
  if (offset + 1 + size > bytes.length) throw new Error("Truncated CompactSize.");
  let value = 0n;
  for (let index = 0; index < size; index += 1) {
    value |= BigInt(bytes[offset + 1 + index]) << BigInt(index * 8);
  }
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error("CompactSize exceeds this implementation's safe limit.");
  }
  return { value: Number(value), next: offset + 1 + size };
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

export function utcFromUnix(unix: number): string {
  return new Date(unix * 1000).toISOString().replace(".000Z", "Z");
}

export function unixFromUtcInput(value: string): number {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)) {
    throw new Error("Use an exact UTC time in YYYY-MM-DDTHH:MM:SSZ form.");
  }
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) throw new Error("The UTC date is invalid.");
  const unix = milliseconds / 1000;
  if (!Number.isInteger(unix) || utcFromUnix(unix) !== value) {
    throw new Error("The UTC date does not represent an exact whole second.");
  }
  return unix;
}

export function networkLabel(network: NetworkName): string {
  return NETWORKS[network].label;
}

export function secretLikeReason(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (/\b(?:xprv|tprv|yprv|zprv|Yprv|Zprv|uprv|vprv|Uprv|Vprv)[1-9A-HJ-NP-Za-km-z]+\b/.test(trimmed)) {
    return "private extended key";
  }
  if (/\b(?:5[1-9A-HJ-NP-Za-km-z]{50}|[KL][1-9A-HJ-NP-Za-km-z]{51}|[9c][1-9A-HJ-NP-Za-km-z]{50,51})\b/.test(trimmed)) {
    return "WIF private key";
  }
  if (/^(?:0x)?[0-9a-fA-F]{64}$/.test(trimmed)) return "raw 32-byte value";
  const words = trimmed.toLowerCase().match(/\b[a-z]{3,10}\b/g) ?? [];
  if ([12, 15, 18, 21, 24].includes(words.length) && /^[a-z\s]+$/i.test(trimmed)) {
    return "mnemonic-like word sequence";
  }
  if (/\b(?:mnemonic|seed phrase|recovery phrase|bip39 passphrase|wallet passphrase|ledger pin|private key)\b/i.test(trimmed)) {
    return "secret-labelled text";
  }
  return null;
}

function validateOriginPath(path: string): { depth: number; indexes: number[] } {
  if (!/^m(?:\/(?:0|[1-9]\d*)(?:')?)+$/.test(path)) {
    throw new Error(
      "Origin paths must use canonical m/48'/… form with apostrophes for hardened steps.",
    );
  }
  const components = path.slice(2).split("/");
  const indexes = components.map((component) => {
    const hardened = component.endsWith("'");
    const numberText = hardened ? component.slice(0, -1) : component;
    const index = Number(numberText);
    if (!Number.isSafeInteger(index) || index < 0 || index >= 0x80000000) {
      throw new Error("Origin path child indexes must be between 0 and 2³¹−1.");
    }
    return hardened ? index + 0x80000000 : index;
  });
  if (components.length > 255) throw new Error("Origin path is too deep for BIP 32.");
  return { depth: components.length, indexes };
}

function originExpression(participant: ParticipantInput): string {
  return `[${participant.master_fingerprint}/${participant.origin_path.slice(2)}]${participant.xpub}`;
}

function parseParticipant(
  participant: ParticipantInput,
  network: NetworkName,
): {
  account: HDKey;
  derived: HDKey;
  derivedPubkey: Uint8Array;
  rootXonly: Uint8Array;
  keyInfo: string;
  warning?: string;
} {
  if (!/^[0-9a-f]{8}$/.test(participant.master_fingerprint)) {
    throw new Error(
      `${participant.role === "owner" ? "Owner" : "Heir"} fingerprint must be exactly 8 lowercase hex characters.`,
    );
  }
  const forbidden = secretLikeReason(participant.xpub);
  if (forbidden) {
    throw new Error(
      `${participant.role === "owner" ? "Owner" : "Heir"} field appears to contain a ${forbidden}. Mimir accepts public xpubs only.`,
    );
  }
  const path = validateOriginPath(participant.origin_path);
  const expectedPrefix = network === "bitcoin" ? "xpub" : "tpub";
  if (!participant.xpub.startsWith(expectedPrefix)) {
    throw new Error(
      `${participant.role === "owner" ? "Owner" : "Heir"} key must use the ${expectedPrefix} prefix for ${networkLabel(network)}.`,
    );
  }
  let account: HDKey;
  try {
    account = HDKey.fromExtendedKey(participant.xpub, NETWORKS[network].versions);
  } catch {
    throw new Error(
      `${participant.role === "owner" ? "Owner" : "Heir"} xpub is malformed, has a bad checksum, or belongs to another network.`,
    );
  }
  if (account.privateKey) throw new Error("Private extended keys are never accepted.");
  if (!account.publicKey || account.publicKey.length !== 33) {
    throw new Error("Extended key does not contain a valid compressed secp256k1 point.");
  }
  if (account.publicExtendedKey !== participant.xpub) {
    throw new Error("Extended public key is not in canonical BIP 32 serialization.");
  }
  if (account.depth !== path.depth) {
    throw new Error(
      `${participant.role === "owner" ? "Owner" : "Heir"} xpub depth (${account.depth}) does not match origin depth (${path.depth}).`,
    );
  }
  let derived: HDKey;
  try {
    derived = account.deriveChild(0).deriveChild(0);
  } catch {
    throw new Error("Could not derive the required public child /0/0.");
  }
  if (!derived.publicKey || derived.publicKey.length !== 33) {
    throw new Error("Derived /0/0 key is not a valid compressed public key.");
  }
  const recommended = new RegExp(
    `^m/48'/${NETWORKS[network].coinType}'/(?:0|[1-9]\\d*)'/2'$`,
  );
  return {
    account,
    derived,
    derivedPubkey: derived.publicKey,
    rootXonly: account.publicKey.slice(1),
    keyInfo: originExpression(participant),
    warning: recommended.test(participant.origin_path)
      ? undefined
      : `${participant.role === "owner" ? "Owner" : "Heir"} origin is allowed but not the recommended dedicated BIP48-style native-P2WSH account path.`,
  };
}

export function compilePolicy(request: PolicyRequest): CompiledPolicy {
  if (request.format !== "mimir-policy-request" || request.version !== 1) {
    throw new Error("Unsupported policy request format or version.");
  }
  if (!(request.network in NETWORKS)) throw new Error("Unsupported Bitcoin network.");
  if (request.template_id !== TEMPLATE_ID) throw new Error("Unsupported policy template.");
  if (
    request.vault_derivation.branch !== 0 ||
    request.vault_derivation.index !== 0
  ) {
    throw new Error("Mimir v1 is fixed to branch 0, index 0.");
  }
  if (request.participants.length !== 2) {
    throw new Error("Mimir v1 requires exactly two participants.");
  }
  const [ownerInput, heirInput] = request.participants;
  if (ownerInput.role !== "owner" || heirInput.role !== "heir") {
    throw new Error("Participant order is fixed: owner is @0 and heir is @1.");
  }
  for (const [label, timestamp] of [
    ["Owner", request.locks.owner_unix],
    ["Heir", request.locks.heir_unix],
  ] as const) {
    if (!Number.isInteger(timestamp)) throw new Error(`${label} timestamp must be an integer.`);
    if (timestamp < MIN_TIMESTAMP_LOCK) {
      throw new Error(`${label} lock has block-height semantics; use a Unix timestamp.`);
    }
    if (timestamp > MAX_LOCKTIME) {
      throw new Error(
        `${label} timestamp exceeds Miniscript after()'s 2038-01-19 limit.`,
      );
    }
  }
  if (request.locks.owner_unix >= request.locks.heir_unix) {
    throw new Error("Owner unlock must be strictly earlier than heir unlock.");
  }

  const owner = parseParticipant(ownerInput, request.network);
  const heir = parseParticipant(heirInput, request.network);
  if (equalBytes(owner.account.publicKey!, heir.account.publicKey!)) {
    throw new Error("Owner and heir account public keys must be different.");
  }
  if (equalBytes(owner.rootXonly, heir.rootXonly)) {
    throw new Error("Owner and heir BIP 138 root identities must be different.");
  }
  if (equalBytes(owner.derivedPubkey, heir.derivedPubkey)) {
    throw new Error("Owner and heir derived /0/0 keys must be different.");
  }

  const ownerKeyInfo = owner.keyInfo;
  const heirKeyInfo = heir.keyInfo;
  const miniscriptWithKeys = `or_i(and_v(v:after(${request.locks.owner_unix}),pk(${bytesToHex(owner.derivedPubkey)})),and_v(v:after(${request.locks.heir_unix}),pk(${bytesToHex(heir.derivedPubkey)})))`;
  const compiled = compileMiniscript(miniscriptWithKeys);
  if (compiled.error || !compiled.issane || !compiled.issanesublevel) {
    throw new Error(`Miniscript compiler rejected the frozen policy: ${compiled.error ?? "not sane"}.`);
  }
  const witnessScript = asmToScript(compiled.asm);
  const witnessProgram = sha256(witnessScript);
  const scriptPubkey = concatBytes(Uint8Array.of(0x00, 0x20), witnessProgram);
  const address = bech32.encode(
    NETWORKS[request.network].hrp,
    [0, ...bech32.toWords(witnessProgram)],
  );

  const fixedBody = `wsh(or_i(and_v(v:after(${request.locks.owner_unix}),pk(${ownerKeyInfo}/0/0)),and_v(v:after(${request.locks.heir_unix}),pk(${heirKeyInfo}/0/0))))`;
  const accountBody = `wsh(or_i(and_v(v:after(${request.locks.owner_unix}),pk(${ownerKeyInfo}/<0;1>/*)),and_v(v:after(${request.locks.heir_unix}),pk(${heirKeyInfo}/<0;1>/*))))`;
  const walletTemplate = `wsh(or_i(and_v(v:after(${request.locks.owner_unix}),pk(@0/**)),and_v(v:after(${request.locks.heir_unix}),pk(@1/**))))`;
  const fixedDescriptor = addDescriptorChecksum(fixedBody);
  const accountDescriptor = addDescriptorChecksum(accountBody);

  const manifest: PolicyManifest = {
    format: "mimir-policy",
    version: 1,
    network: request.network,
    template_id: TEMPLATE_ID,
    vault_derivation: { branch: 0, index: 0, child_suffix: "/0/0" },
    participants: [
      {
        ...ownerInput,
        derived_pubkey: bytesToHex(owner.derivedPubkey),
      },
      {
        ...heirInput,
        derived_pubkey: bytesToHex(heir.derivedPubkey),
      },
    ],
    locks: {
      owner: {
        unix: request.locks.owner_unix,
        utc: utcFromUnix(request.locks.owner_unix),
      },
      heir: {
        unix: request.locks.heir_unix,
        utc: utcFromUnix(request.locks.heir_unix),
      },
    },
    descriptor: {
      fixed: fixedDescriptor,
      account_multipath: accountDescriptor,
    },
    wallet_policy: {
      template: walletTemplate,
      keys: [ownerKeyInfo, heirKeyInfo],
      funded_branch: 0,
      funded_index: 0,
    },
    script: {
      witness_script_hex: bytesToHex(witnessScript),
      witness_program_sha256: bytesToHex(witnessProgram),
      script_pubkey_hex: bytesToHex(scriptPubkey),
    },
    address,
  };
  const canonicalManifest = canonicalizeJson(manifest);
  const releaseCanonical = canonicalizeJson(RELEASE_MANIFEST);
  const manifestContainsPrivateMaterial = secretLikeReason(canonicalManifest) !== null;

  const invariants: InvariantResult[] = [
    {
      id: "owner-child",
      label: "Owner xpub derives exported /0/0 pubkey",
      ok: manifest.participants[0].derived_pubkey === bytesToHex(owner.derivedPubkey),
    },
    {
      id: "heir-child",
      label: "Heir xpub derives exported /0/0 pubkey",
      ok: manifest.participants[1].derived_pubkey === bytesToHex(heir.derivedPubkey),
    },
    {
      id: "miniscript",
      label: "Frozen Miniscript compiles to exported witness script",
      ok: bytesToHex(asmToScript(compiled.asm)) === manifest.script.witness_script_hex,
    },
    {
      id: "witness-program",
      label: "SHA256(witness script) equals witness program",
      ok: sha256Hex(witnessScript) === manifest.script.witness_program_sha256,
    },
    {
      id: "script-pubkey",
      label: "scriptPubKey is OP_0 PUSH32 witness program",
      ok:
        manifest.script.script_pubkey_hex ===
        `0020${manifest.script.witness_program_sha256}`,
    },
    {
      id: "address",
      label: "Network P2WSH address encodes the exported script",
      ok:
        bech32.encode(
          NETWORKS[request.network].hrp,
          [0, ...bech32.toWords(witnessProgram)],
        ) === manifest.address,
    },
    {
      id: "account-fixed",
      label: "Account policy at branch 0, index 0 equals fixed descriptor body",
      ok: accountBody.replaceAll("/<0;1>/*", "/0/0") === fixedBody,
    },
    {
      id: "role-order",
      label: "Wallet policy maps @0 owner and @1 heir",
      ok:
        manifest.wallet_policy.keys[0] === ownerKeyInfo &&
        manifest.wallet_policy.keys[1] === heirKeyInfo,
    },
    {
      id: "timestamps",
      label: "Descriptor contains both exact lock timestamps",
      ok:
        fixedBody.includes(`after(${request.locks.owner_unix})`) &&
        fixedBody.includes(`after(${request.locks.heir_unix})`),
    },
    {
      id: "public-only",
      label: "Canonical manifest contains public material only",
      ok: !manifestContainsPrivateMaterial,
    },
    {
      id: "canonical-hash",
      label: "RFC 8785 canonical manifest hash is reproducible",
      ok:
        sha256Hex(canonicalManifest) ===
        sha256Hex(canonicalizeJson(JSON.parse(canonicalManifest))),
    },
  ];
  if (invariants.some((invariant) => !invariant.ok)) {
    throw new Error("An internal policy consistency invariant failed; export stopped.");
  }

  const warnings = [owner.warning, heir.warning].filter(
    (warning): warning is string => Boolean(warning),
  );
  if (request.network === "bitcoin") {
    warnings.push(
      "Mainnet release gates are not complete. Rehearse on regtest/signet and do not fund this preview output.",
    );
  }
  warnings.push(
    "The pinned BIP 138 capsule profile is based on a draft revision.",
    "The vault remains unverified until Bitcoin Core reproduces the complete descriptor and address.",
  );

  return {
    request,
    manifest,
    canonical_manifest: canonicalManifest,
    policy_manifest_sha256: sha256Hex(canonicalManifest),
    release_manifest: RELEASE_MANIFEST,
    release_manifest_sha256: sha256Hex(releaseCanonical),
    owner_root_xonly: owner.rootXonly,
    heir_root_xonly: heir.rootXonly,
    warnings,
    invariants,
  };
}

function buildBip138Payload(canonicalRecovery: string): Uint8Array {
  const typeTag = TEXT_ENCODER.encode("mimir/recovery-v1");
  const content = TEXT_ENCODER.encode(canonicalRecovery);
  return concatBytes(
    Uint8Array.of(0x02),
    compactSize(typeTag.length),
    typeTag,
    compactSize(content.length),
    content,
  );
}

function createIndividualSecrets(
  recipientRoots: Uint8Array[],
  encryptionSecret: Uint8Array,
): Uint8Array[] {
  const secrets = recipientRoots.map((root) =>
    xor32(
      encryptionSecret,
      taggedHash("BIP138_INDIVIDUAL_SECRET", root),
    ),
  );
  while (secrets.length < CAPSULE_PROFILE_MANIFEST.individual_secret_bucket) {
    const decoy = randomBytes(32);
    if (
      decoy.some((value) => value !== 0) &&
      !secrets.some((entry) => equalBytes(entry, decoy))
    ) {
      secrets.push(decoy);
    }
  }
  return secrets.sort(compareBytes);
}

function tryDecryptCapsule(
  raw: Uint8Array,
  recipientRoot: Uint8Array,
): Uint8Array | null {
  try {
    const magic = new TextDecoder().decode(raw.slice(0, 6));
    if (magic !== "BIP138" || raw[6] !== 0x01) return null;
    let offset = 7;
    const pathCount = raw[offset];
    offset += 1;
    for (let path = 0; path < pathCount; path += 1) {
      const childCount = raw[offset];
      offset += 1 + childCount * 4;
    }
    const secretCount = raw[offset];
    offset += 1;
    const entries: Uint8Array[] = [];
    for (let index = 0; index < secretCount; index += 1) {
      entries.push(raw.slice(offset, offset + 32));
      offset += 32;
    }
    if (raw[offset] !== 0x01) return null;
    offset += 1;
    const nonce = raw.slice(offset, offset + 12);
    if (nonce.length !== 12 || nonce.every((value) => value === 0)) return null;
    offset += 12;
    const length = readCompactSize(raw, offset);
    offset = length.next;
    const ciphertext = raw.slice(offset, offset + length.value);
    if (ciphertext.length !== length.value) return null;
    const individual = taggedHash("BIP138_INDIVIDUAL_SECRET", recipientRoot);
    for (const entry of entries) {
      try {
        const candidate = xor32(entry, individual);
        return chacha20poly1305(candidate, nonce).decrypt(ciphertext);
      } catch {
        // Decoys and other participants are expected to fail authentication.
      }
    }
    return null;
  } catch {
    return null;
  }
}

export function createCapsule(
  compiled: CompiledPolicy,
  note: string,
): CapsuleResult {
  const forbidden = secretLikeReason(note);
  if (forbidden) {
    throw new Error(`Encrypted note appears to contain a ${forbidden}; remove it.`);
  }
  if (TEXT_ENCODER.encode(note).length > 1000) {
    throw new Error("Encrypted note is limited to 1,000 UTF-8 bytes in this profile.");
  }
  const recoveryPlaintext = {
    format: "mimir-recovery",
    version: 1,
    policy_manifest_sha256: compiled.policy_manifest_sha256,
    network: compiled.manifest.network,
    template_id: TEMPLATE_ID,
    fixed_descriptor: compiled.manifest.descriptor.fixed,
    witness_script_hex: compiled.manifest.script.witness_script_hex,
    script_pubkey_hex: compiled.manifest.script.script_pubkey_hex,
    address: compiled.manifest.address,
    locks: {
      owner_unix: compiled.manifest.locks.owner.unix,
      owner_utc: compiled.manifest.locks.owner.utc,
      heir_unix: compiled.manifest.locks.heir.unix,
      heir_utc: compiled.manifest.locks.heir.utc,
    },
    release_manifest_sha256: compiled.release_manifest_sha256,
    note: note || "",
  };
  const canonicalRecovery = canonicalizeJson(recoveryPlaintext);
  if (secretLikeReason(canonicalRecovery)) {
    throw new Error("Recovery plaintext failed the public-material scan.");
  }
  const roots = [compiled.owner_root_xonly, compiled.heir_root_xonly]
    .filter((root) => bytesToHex(root) !== BIP341_NUMS_X)
    .sort(compareBytes);
  if (roots.length === 0) {
    throw new Error("No eligible BIP 138 recipient keys remain after exclusions.");
  }
  const encryptionSecret = taggedHash(
    "BIP138_DECRYPTION_SECRET",
    concatBytes(...roots),
  );
  const individualSecrets = createIndividualSecrets(roots, encryptionSecret);
  const nonce = randomNonZeroNonce();
  const payload = buildBip138Payload(canonicalRecovery);
  const ciphertext = chacha20poly1305(encryptionSecret, nonce).encrypt(payload);
  const raw = concatBytes(
    TEXT_ENCODER.encode("BIP138"),
    Uint8Array.of(0x01),
    Uint8Array.of(0x00),
    Uint8Array.of(individualSecrets.length),
    ...individualSecrets,
    Uint8Array.of(0x01),
    nonce,
    compactSize(ciphertext.length),
    ciphertext,
  );
  const ownerDecrypted = tryDecryptCapsule(raw, compiled.owner_root_xonly);
  const heirDecrypted = tryDecryptCapsule(raw, compiled.heir_root_xonly);
  const ownerCanDecrypt = ownerDecrypted
    ? equalBytes(ownerDecrypted, payload)
    : false;
  const heirCanDecrypt = heirDecrypted
    ? equalBytes(heirDecrypted, payload)
    : false;
  if (!ownerCanDecrypt || !heirCanDecrypt) {
    throw new Error("Capsule self-test failed; no capsule was exported.");
  }
  const opReturn = concatBytes(Uint8Array.of(0x6a), encodePushData(raw));
  return {
    profile: CAPSULE_PROFILE_MANIFEST,
    recovery_plaintext: recoveryPlaintext,
    recovery_plaintext_canonical: canonicalRecovery,
    raw_bytes: raw,
    raw_base64: toBase64(raw),
    data_hex: bytesToHex(raw),
    byte_length: raw.length,
    capsule_sha256: sha256Hex(raw),
    op_return_script_pubkey_hex: bytesToHex(opReturn),
    op_return_script_byte_length: opReturn.length,
    recipient_count: roots.length,
    encoded_secret_count: individualSecrets.length,
    self_test: {
      owner_can_decrypt: ownerCanDecrypt,
      heir_can_decrypt: heirCanDecrypt,
      header_valid:
        new TextDecoder().decode(raw.slice(0, 6)) === "BIP138" && raw[6] === 1,
    },
  };
}

function artifact(
  type: string,
  filename: string,
  mediaType: string,
  content: string,
  encoding: "utf8" | "base64" = "utf8",
  rawBytes?: Uint8Array,
): BundleArtifact {
  const bytes = rawBytes ?? TEXT_ENCODER.encode(content);
  return {
    type,
    filename,
    media_type: mediaType,
    encoding,
    content,
    byte_length: bytes.length,
    sha256: sha256Hex(bytes),
  };
}

function docsHeader(compiled: CompiledPolicy, title: string): string {
  return `# ${title}\n\nPREVIEW — NOT MAINNET READY\n\nPolicy manifest: ${compiled.policy_manifest_sha256}\nRelease manifest: ${compiled.release_manifest_sha256}\nCore profile: 31.0 target, end-to-end verification pending\n\nMimir never needs private keys. Never enter a seed, passphrase, xprv, WIF, or private descriptor into Mimir. Verify the release hash outside the live page.\n`;
}

function humanSummary(
  compiled: CompiledPolicy,
  capsule: CapsuleResult,
): string {
  const { manifest } = compiled;
  return `MIMIR V1 VAULT POLICY — PREVIEW / NOT MAINNET READY

Network: ${networkLabel(manifest.network)}
Vault address: ${manifest.address}
Witness-program SHA256: ${manifest.script.witness_program_sha256}
Owner: ${manifest.participants[0].master_fingerprint} ${manifest.participants[0].origin_path}
Heir: ${manifest.participants[1].master_fingerprint} ${manifest.participants[1].origin_path}
Owner unlock: ${manifest.locks.owner.utc} (${manifest.locks.owner.unix})
Heir unlock: ${manifest.locks.heir.utc} (${manifest.locks.heir.unix})
Vault derivation: branch 0, index 0 (/0/0)
Policy-manifest SHA256: ${compiled.policy_manifest_sha256}
Capsule SHA256: ${capsule.capsule_sha256}
Release-manifest SHA256: ${compiled.release_manifest_sha256}

TIMELINE
Before owner date: nobody can spend.
After owner date, before heir date: owner can spend.
After heir date: owner or heir can spend. The heir date does not depend on proof of death.

Later deposits do not restart either lock. Do not reuse the address after recovery.
The descriptor and witness script are essential recovery data. The OP_RETURN capsule is only a backup.

FIXED DESCRIPTOR
${manifest.descriptor.fixed}
`;
}

function coreVerificationDoc(compiled: CompiledPolicy): string {
  return `${docsHeader(compiled, "Bitcoin Core independent verification")}
Purpose: reproduce the fixed descriptor and vault address outside Mimir before any funding.

1. Use the documented Bitcoin Core version on the same network.
2. Analyze the full fixed descriptor and record Core's canonical descriptor and checksum.
3. Derive its one fixed address.
4. Compare the complete descriptor, address, network, and scriptPubKey byte-for-byte with the bundle.
5. Complete verification-record-template.json independently.

Any mismatch, parse error, unsupported descriptor, or untested Core version means: DO NOT FUND.
Mimir does not call Core RPC and cannot certify its own output. This preview names capabilities, not copy-paste production commands.
`;
}

function coreFundingDoc(compiled: CompiledPolicy, capsule: CapsuleResult): string {
  return `${docsHeader(compiled, "Bitcoin Core funding procedure")}
Prerequisites: exported bundle, two off-chain copies, independent verification PASS, correct network, intended amount, and optional capsule data.

Bitcoin Core owns inputs, coin selection, change, fees, RBF, PSBT creation, signing, finalization, mempool testing, and broadcast.

Before signing, review the exact vault address and amount, capsule data/script, change address, fee, network, and absence of unexpected outputs. Never assume either output index.

Preflight the final signed transaction: decode it; compare the vault scriptPubKey (${compiled.manifest.script.script_pubkey_hex}); compare the capsule OP_RETURN (${capsule.op_return_script_pubkey_hex}); run mempool acceptance on the intended node; then broadcast through Core.

After confirmation, create the funding record from Core or an independent decoder. Later deposits retain the original absolute dates. Never reuse this address after recovery.
`;
}

function coreMonitoringDoc(compiled: CompiledPolicy): string {
  return `${docsHeader(compiled, "Bitcoin Core watch-only monitoring")}
Create a descriptor wallet with private keys disabled. Import only the fixed descriptor, using an appropriate funding timestamp.

Monitor confirmed balance, unconfirmed and additional deposits, exact UTXOs, spends, capsule confirmation, chain median time past, and both unlock dates. Schedule reviews before owner unlock, soon after owner unlock, and well before heir unlock.

Rotation is impossible before the owner lock. Every later deposit uses the original absolute dates and therefore has a shorter remaining lock. Mimir does not connect to a node or persist monitoring data.
`;
}

function coreRecoveryDoc(compiled: CompiledPolicy): string {
  return `${docsHeader(compiled, "Bitcoin Core software recovery")}
The off-chain descriptor is the primary recovery route; the capsule is optional redundancy.

Online coordinator: load the fixed public descriptor, locate every UTXO, choose one branch, construct the PSBT, calculate the fee, and use one fresh ordinary-wallet sweep destination.

Certified transaction shape: inputs from this one fixed descriptor and one branch; exactly one sweep output; no change to the old vault; SIGHASH_ALL; nLockTime at least the selected timestamp; all input sequences non-final (RBF-compatible recommended).

Before exposing private material, the offline signer must verify every input and amount, the witness script and origins, destination, output amount, reasonable fee, absence of hidden change or unexpected inputs/outputs, locktime, non-final sequences, SIGHASH_ALL, and network.

Only outside Mimir, replace the selected participant's account xpub with the corresponding xprv; keep the other participant xpub-only and leave the descriptor otherwise unchanged. Prefer a dedicated offline machine, ephemeral Core directory, no network, and no secrets in history, process arguments, or logs.

Return the signed PSBT to the coordinator. Finalize, decode again, confirm unchanged semantics, test mempool acceptance, broadcast, and monitor. This preview does not certify signing commands until both paths and multi-input recovery pass a pinned Core profile.
`;
}

function ledgerDoc(compiled: CompiledPolicy): string {
  return `${docsHeader(compiled, "Optional Ledger recovery")}
OPTIONAL — NOT CERTIFIED IN THIS PREVIEW.

Recovery must remain possible without the device, firmware, adapter, registration HMAC, or Ledger itself. Register exactly the exported BIP 388 template and key vector. Never reinterpret timestamps, role order, derivation, or Miniscript.

Display branch 0, index 0 on-device and require exact equality among Mimir, Core, and device addresses. During recovery, the adapter may add returned signatures to the exact Core-created PSBT only after confirming the unsigned transaction is unchanged. Core retains finalization and broadcast.

Record the device, firmware, Bitcoin app, adapter, policy name/template/vector/identifier, HMAC, displayed branch/index/address, and registration date. Unknown combinations remain untested.
`;
}

function physicalChecklist(compiled: CompiledPolicy): string {
  return `${docsHeader(compiled, "Physical inheritance package checklist")}
Mimir exports public artifacts only. Assemble secret inheritance material outside Mimir.

[ ] Participant seed/private-key backup and separately planned BIP39 passphrase
[ ] Master fingerprint, exact account path, account xpub
[ ] Full fixed descriptor and witness script
[ ] Vault address and policy-manifest hash
[ ] Funding txid, every vault vout and exact amount, raw transaction
[ ] Capsule txid/output index, pinned profile, archived decoder
[ ] Externally verified Mimir release hash and Core recovery profile
[ ] Optional Ledger registration record
[ ] Legal/executor instructions
[ ] Two readable copies on separate media/locations with verified hashes

Never put seeds, passphrases, xprvs, private descriptors, PINs, or credentials inside the digital bundle.

HEIR NOTICE: Never type the seed into an arbitrary online wallet. Export only the documented account xpub for capsule decryption. Use the descriptor to reconstruct the vault. Wait until the heir lock is valid by Bitcoin consensus. Sweep everything to a new ordinary wallet, verify destination and fee before signing, and never reuse the old address.
`;
}

export function buildVaultBundle(
  compiled: CompiledPolicy,
  capsule: CapsuleResult,
): VaultBundle {
  const manifestPretty = `${JSON.stringify(compiled.manifest, null, 2)}\n`;
  const releasePretty = `${JSON.stringify(compiled.release_manifest, null, 2)}\n`;
  const capsuleProfilePretty = `${JSON.stringify(capsule.profile, null, 2)}\n`;
  const walletPolicy = `${JSON.stringify(
    {
      template: compiled.manifest.wallet_policy.template,
      keys: compiled.manifest.wallet_policy.keys,
      funded_branch: 0,
      funded_index: 0,
    },
    null,
    2,
  )}\n`;
  const verificationRecord = {
    format: "mimir-core-verification-record",
    version: 1,
    status: "UNVERIFIED",
    network: compiled.manifest.network,
    policy_manifest_sha256: compiled.policy_manifest_sha256,
    release_manifest_sha256: compiled.release_manifest_sha256,
    mimir_fixed_descriptor: compiled.manifest.descriptor.fixed,
    mimir_address: compiled.manifest.address,
    bitcoin_core_version: "",
    operating_system: "",
    compatibility_profile_sha256: "",
    core_canonical_descriptor: "",
    core_descriptor_checksum: "",
    core_derived_address: "",
    descriptor_exact_match: false,
    address_exact_match: false,
    network_and_script_match: false,
    verification_date: "",
    verifier: "",
    notes: "",
  };
  const fundingRecord = {
    format: "mimir-funding-record",
    version: 1,
    status: "UNSEALED",
    network: compiled.manifest.network,
    policy_manifest_sha256: compiled.policy_manifest_sha256,
    release_manifest_sha256: compiled.release_manifest_sha256,
    bitcoin_core_version: "",
    core_profile_sha256: "",
    funding_txid: "",
    raw_transaction_hex: "",
    vault_outputs: [],
    capsule_output: {
      publication_status: "not recorded",
      transaction_id: "",
      vout: null,
      capsule_sha256: capsule.capsule_sha256,
      script_pubkey_hex: capsule.op_return_script_pubkey_hex,
    },
    fee_sats: "",
    rbf: null,
    confirmation: {
      block_hash: "",
      block_height: null,
      confirmations_at_seal: null,
    },
    recorder: "",
    recorded_at: "",
    independent_decoder: "",
    independently_checked_at: "",
    notes: "",
  };

  const artifacts: BundleArtifact[] = [
    artifact("policy_manifest", "policy-manifest.json", "application/json", manifestPretty),
    artifact(
      "policy_manifest_sha256",
      "policy-manifest.sha256",
      "text/plain",
      `${compiled.policy_manifest_sha256}  policy-manifest.json\n`,
    ),
    artifact(
      "fixed_descriptor",
      "fixed-descriptor.txt",
      "text/plain",
      `${compiled.manifest.descriptor.fixed}\n`,
    ),
    artifact(
      "account_multipath_descriptor",
      "account-multipath-descriptor.txt",
      "text/plain",
      `${compiled.manifest.descriptor.account_multipath}\n`,
    ),
    artifact(
      "witness_script",
      "witness-script.hex",
      "text/plain",
      `${compiled.manifest.script.witness_script_hex}\n`,
    ),
    artifact(
      "script_pubkey",
      "script-pubkey.hex",
      "text/plain",
      `${compiled.manifest.script.script_pubkey_hex}\n`,
    ),
    artifact("vault_address", "vault-address.txt", "text/plain", `${compiled.manifest.address}\n`),
    artifact(
      "bip388_wallet_policy_template",
      "wallet-policy-template.txt",
      "text/plain",
      `${compiled.manifest.wallet_policy.template}\n`,
    ),
    artifact(
      "bip388_key_information_vector",
      "wallet-policy.json",
      "application/json",
      walletPolicy,
    ),
    artifact(
      "capsule",
      "recovery-capsule.bip138",
      "application/octet-stream",
      capsule.raw_base64,
      "base64",
      capsule.raw_bytes,
    ),
    artifact("capsule_data_hex", "capsule-data.hex", "text/plain", `${capsule.data_hex}\n`),
    artifact(
      "capsule_op_return_script_pubkey",
      "capsule-op-return-script.hex",
      "text/plain",
      `${capsule.op_return_script_pubkey_hex}\n`,
    ),
    artifact(
      "capsule_sha256",
      "recovery-capsule.sha256",
      "text/plain",
      `${capsule.capsule_sha256}  recovery-capsule.bip138\n`,
    ),
    artifact(
      "capsule_profile_manifest",
      "capsule-profile.json",
      "application/json",
      capsuleProfilePretty,
    ),
    artifact("mimir_release_manifest", "release-manifest.json", "application/json", releasePretty),
    artifact(
      "human_policy_summary",
      "policy-summary.txt",
      "text/plain",
      humanSummary(compiled, capsule),
    ),
    artifact(
      "core_verification_procedure",
      "bitcoin-core-verification.md",
      "text/markdown",
      coreVerificationDoc(compiled),
    ),
    artifact(
      "core_funding_procedure",
      "bitcoin-core-funding.md",
      "text/markdown",
      coreFundingDoc(compiled, capsule),
    ),
    artifact(
      "core_monitoring_procedure",
      "bitcoin-core-monitoring.md",
      "text/markdown",
      coreMonitoringDoc(compiled),
    ),
    artifact(
      "core_software_recovery_procedure",
      "bitcoin-core-software-recovery.md",
      "text/markdown",
      coreRecoveryDoc(compiled),
    ),
    artifact(
      "optional_ledger_recovery_procedure",
      "optional-ledger-recovery.md",
      "text/markdown",
      ledgerDoc(compiled),
    ),
    artifact(
      "core_verification_record_template",
      "verification-record-template.json",
      "application/json",
      `${JSON.stringify(verificationRecord, null, 2)}\n`,
    ),
    artifact(
      "funding_record_template",
      "funding-record-template.json",
      "application/json",
      `${JSON.stringify(fundingRecord, null, 2)}\n`,
    ),
    artifact(
      "physical_backup_checklist",
      "physical-backup-checklist.md",
      "text/markdown",
      physicalChecklist(compiled),
    ),
  ];

  return {
    format: "mimir-vault-bundle-package",
    version: 1,
    status: "pre-mainnet-preview",
    notice:
      "Public recovery artifacts only. This preview is not certified for mainnet funding.",
    bundle_manifest: {
      format: "mimir-vault-bundle",
      version: 1,
      policy_manifest_sha256: compiled.policy_manifest_sha256,
      compiler_release_manifest_sha256: compiled.release_manifest_sha256,
      capsule_profile_id: CAPSULE_PROFILE_ID,
      artifacts: artifacts.map((entry) => ({
        type: entry.type,
        filename: entry.filename,
        sha256: entry.sha256,
        byte_length: entry.byte_length,
      })),
    },
    artifacts,
  };
}

export function runStaticSelfTests(): Array<{
  id: string;
  label: string;
  ok: boolean;
}> {
  const descriptorVector = addDescriptorChecksum("raw(deadbeef)");
  const canonicalVector = canonicalizeJson({ b: 1, a: [true, "x"] });
  const coreOwner =
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
  const coreHeir =
    "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
  const coreMiniscript = `or_i(and_v(v:after(1800000000),pk(${coreOwner})),and_v(v:after(1900000000),pk(${coreHeir})))`;
  const coreCompile = compileMiniscript(coreMiniscript);
  const coreScript = asmToScript(coreCompile.asm);
  const coreDescriptor = addDescriptorChecksum(`wsh(${coreMiniscript})`);
  const vectorRoots = [
    hexToBytes("e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443"),
    hexToBytes("84526253c27c7aef56c7b71a5cd25bebb66dddda437826defc5b2568bde81f07"),
  ].sort(compareBytes);
  const vectorSecret = taggedHash(
    "BIP138_DECRYPTION_SECRET",
    concatBytes(...vectorRoots),
  );
  const chachaVector = chacha20poly1305(
    new Uint8Array(32),
    hexToBytes("000102030405060708090a0b"),
  ).encrypt(hexToBytes("48656c6c6f"));
  return [
    {
      id: "bip380-checksum",
      label: "BIP 380 descriptor checksum vector",
      ok: descriptorVector === "raw(deadbeef)#89f8spxm",
    },
    {
      id: "rfc8785-order",
      label: "RFC 8785 object-key ordering",
      ok: canonicalVector === '{"a":[true,"x"],"b":1}',
    },
    {
      id: "release-profile",
      label: "Pinned release and capsule profile data present",
      ok:
        RELEASE_MANIFEST.capsule_specification_commit === BIP138_SPEC_COMMIT &&
        CAPSULE_PROFILE_MANIFEST.test_vector_set_sha256.length === 64,
    },
    {
      id: "core-miniscript-vector",
      label: "Bitcoin Core 31.1 Miniscript/script/address vector",
      ok:
        coreCompile.issane &&
        coreDescriptor.endsWith("#y6l9v5nk") &&
        bytesToHex(coreScript) ===
          "630400d2496bb169210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac670400b33f71b1692102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5ac68" &&
        bech32.encode("bcrt", [0, ...bech32.toWords(sha256(coreScript))]) ===
          "bcrt1qzjmhqzvc38c26cntrvjhegv6fqpmaa9p54xgd4p8208ytdacq4gq550t2t",
    },
    {
      id: "bip138-secret-vector",
      label: "BIP 138 two-recipient decryption-secret vector",
      ok:
        bytesToHex(vectorSecret) ===
        "efa3c1e5a719874f5516818603cdad7ffc31c11a947c5b16b6b763ee09ea3539",
    },
    {
      id: "bip138-chacha-vector",
      label: "BIP 138 ChaCha20-Poly1305 encryption vector",
      ok:
        bytesToHex(chachaVector) ===
        "7df9cb9a0ac5851cc054b14d05f781127b2b0d31fa",
    },
  ];
}
