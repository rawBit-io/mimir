import { compileMiniscript } from "@bitcoinerlab/miniscript";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bech32 } from "@scure/base";
import {
  MAX_LOCKTIME,
  MIN_TIMESTAMP_LOCK,
  addDescriptorChecksum,
  bytesToHex,
  canonicalizeJson,
  hexToBytes,
  sha256Hex,
  unixFromUtcInput,
  utcFromUnix,
  type InvariantResult,
} from "./mimir";

export const TEMPLATE_ID_V2 = "mimir-kofn-two-path-v2" as const;

export type ComposerNetwork = "bitcoin" | "signet" | "regtest";

export type ComposerKey = {
  id: string;
  label: string;
  public_key: string;
};

export type ComposerRequest = {
  format: "mimir-composer-request";
  version: 2;
  network: ComposerNetwork;
  template_id: typeof TEMPLATE_ID_V2;
  keys: ComposerKey[];
  owner: {
    key_ids: string[];
    threshold: number;
    unlock_unix: number;
  };
  heirs: {
    key_ids: string[];
    threshold: number;
    unlock_unix: number;
  };
};

export type ComposerPolicyGroup = {
  key_ids: string[];
  public_keys: string[];
  threshold: number;
  unlock: {
    unix: number;
    utc: string;
  };
  miniscript_fragment: string;
};

export type ComposerPolicyManifest = {
  format: "mimir-composed-policy";
  version: 2;
  network: ComposerNetwork;
  template_id: typeof TEMPLATE_ID_V2;
  keys: ComposerKey[];
  owner: ComposerPolicyGroup;
  heirs: ComposerPolicyGroup;
  miniscript: string;
  descriptor: {
    body: string;
    checksummed: string;
  };
  script: {
    asm: string;
    witness_script_hex: string;
    witness_script_bytes: number;
    witness_program_sha256: string;
    script_pubkey_hex: string;
  };
  address: string;
};

export type CompiledComposerPolicy = {
  request: ComposerRequest;
  manifest: ComposerPolicyManifest;
  canonical_manifest: string;
  policy_manifest_sha256: string;
  miniscript: string;
  descriptor_body: string;
  descriptor: string;
  asm: string;
  witness_script_hex: string;
  witness_script_bytes: number;
  witness_program_sha256: string;
  script_pubkey_hex: string;
  address: string;
  invariants: InvariantResult[];
  warnings: string[];
};

const NETWORKS: Record<ComposerNetwork, { label: string; hrp: string }> = {
  bitcoin: { label: "Bitcoin mainnet", hrp: "bc" },
  signet: { label: "Bitcoin signet", hrp: "tb" },
  regtest: { label: "Bitcoin regtest", hrp: "bcrt" },
};

const MAX_REGISTRY_KEYS = 20;
const MAX_GROUP_KEYS = 10;
const MAX_STANDARD_P2WSH_SCRIPT_BYTES = 3_600;

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
  throw new Error("Compiler emitted an unexpectedly large pushed value.");
}

const OPCODES: Readonly<Record<string, number>> = {
  OP_0: 0x00,
  OP_FALSE: 0x00,
  OP_1NEGATE: 0x4f,
  OP_1: 0x51,
  OP_TRUE: 0x51,
  OP_2: 0x52,
  OP_3: 0x53,
  OP_4: 0x54,
  OP_5: 0x55,
  OP_6: 0x56,
  OP_7: 0x57,
  OP_8: 0x58,
  OP_9: 0x59,
  OP_10: 0x5a,
  OP_11: 0x5b,
  OP_12: 0x5c,
  OP_13: 0x5d,
  OP_14: 0x5e,
  OP_15: 0x5f,
  OP_16: 0x60,
  OP_IF: 0x63,
  OP_NOTIF: 0x64,
  OP_ELSE: 0x67,
  OP_ENDIF: 0x68,
  OP_VERIFY: 0x69,
  OP_DROP: 0x75,
  OP_DUP: 0x76,
  OP_BOOLAND: 0x9a,
  OP_BOOLOR: 0x9b,
  OP_CHECKSIG: 0xac,
  OP_CHECKSIGVERIFY: 0xad,
  OP_CHECKMULTISIG: 0xae,
  OP_CHECKMULTISIGVERIFY: 0xaf,
  OP_CHECKLOCKTIMEVERIFY: 0xb1,
};

function asmToScript(asm: string): Uint8Array {
  const chunks: Uint8Array[] = [];
  for (const token of asm.trim().split(/\s+/)) {
    const opcode = OPCODES[token];
    if (typeof opcode === "number") {
      chunks.push(Uint8Array.of(opcode));
      continue;
    }
    if (/^(?:0|[1-9]|1[0-6])$/.test(token)) {
      const value = Number(token);
      chunks.push(Uint8Array.of(value === 0 ? 0 : 0x50 + value));
      continue;
    }
    const pushed = token.match(/^<([0-9a-fA-F]*)>$/);
    if (pushed) {
      chunks.push(encodePushData(hexToBytes(pushed[1])));
      continue;
    }
    throw new Error(`Unsupported Miniscript compiler token: ${token}.`);
  }
  return concatBytes(...chunks);
}

function normalizeText(
  value: unknown,
  field: string,
  maximumLength: number,
): string {
  if (typeof value !== "string") throw new Error(`${field} must be text.`);
  const normalized = value.trim().normalize("NFC");
  if (!normalized) throw new Error(`${field} cannot be empty.`);
  if (normalized.length > maximumLength) {
    throw new Error(`${field} cannot exceed ${maximumLength} characters.`);
  }
  if (/\p{Cc}/u.test(normalized)) {
    throw new Error(`${field} cannot contain control characters.`);
  }
  return normalized;
}

export function validateCompressedPublicKey(value: unknown): string {
  if (typeof value !== "string") {
    throw new Error("Public key must be hexadecimal text.");
  }
  const normalized = value.trim().toLowerCase();
  if (!/^(?:02|03)[0-9a-f]{64}$/.test(normalized)) {
    throw new Error(
      "Public key must be a 33-byte compressed secp256k1 key (02/03 plus 32-byte x-coordinate); private, x-only, and uncompressed keys are rejected.",
    );
  }
  try {
    const point = secp256k1.Point.fromBytes(hexToBytes(normalized));
    if (bytesToHex(point.toBytes(true)) !== normalized) {
      throw new Error("non-canonical point encoding");
    }
  } catch {
    throw new Error("Public key is not a valid point on the secp256k1 curve.");
  }
  return normalized;
}

export function unixFromComposerUtc(value: string): number {
  const unix = unixFromUtcInput(value);
  validateTimestamp("Unlock", unix);
  return unix;
}

export function networkLabelV2(network: ComposerNetwork): string {
  if (!Object.prototype.hasOwnProperty.call(NETWORKS, network)) {
    throw new Error("Unsupported Bitcoin network.");
  }
  return NETWORKS[network].label;
}

function validateTimestamp(label: string, value: unknown): asserts value is number {
  if (!Number.isInteger(value)) {
    throw new Error(`${label} unlock timestamp must be an integer.`);
  }
  const timestamp = value as number;
  if (timestamp < MIN_TIMESTAMP_LOCK) {
    throw new Error(
      `${label} unlock must be a Unix timestamp of at least ${MIN_TIMESTAMP_LOCK}.`,
    );
  }
  if (timestamp > MAX_LOCKTIME) {
    throw new Error(
      `${label} unlock exceeds Miniscript after()'s 2038-01-19 limit.`,
    );
  }
}

function normalizeKeys(value: unknown): ComposerKey[] {
  if (!Array.isArray(value)) throw new Error("Key registry must be an array.");
  if (value.length === 0) throw new Error("Key registry cannot be empty.");
  if (value.length > MAX_REGISTRY_KEYS) {
    throw new Error(`Key registry supports at most ${MAX_REGISTRY_KEYS} keys.`);
  }

  const keys = value.map((entry, index) => {
    if (!entry || typeof entry !== "object") {
      throw new Error(`Key registry entry ${index + 1} is invalid.`);
    }
    const candidate = entry as Partial<ComposerKey>;
    return {
      id: normalizeText(candidate.id, `Key ${index + 1} ID`, 64),
      label: normalizeText(candidate.label, `Key ${index + 1} label`, 80),
      public_key: validateCompressedPublicKey(candidate.public_key),
    };
  });

  const uniqueFields = [
    ["ID", (key: ComposerKey) => key.id],
    ["label", (key: ComposerKey) => key.label.toLocaleLowerCase("en-US")],
    ["public key", (key: ComposerKey) => key.public_key],
  ] as const;
  for (const [field, select] of uniqueFields) {
    const seen = new Set<string>();
    for (const key of keys) {
      const selected = select(key);
      if (seen.has(selected)) {
        throw new Error(`Key registry contains a duplicate ${field}: ${selected}.`);
      }
      seen.add(selected);
    }
  }

  return keys.sort((left, right) =>
    left.public_key.localeCompare(right.public_key) || left.id.localeCompare(right.id),
  );
}

type GroupInput = ComposerRequest["owner"] | ComposerRequest["heirs"];

function normalizeGroup(
  role: "Owner" | "Heirs",
  value: unknown,
  keyById: Map<string, ComposerKey>,
): { input: GroupInput; keys: ComposerKey[] } {
  if (!value || typeof value !== "object") {
    throw new Error(`${role} policy group is required.`);
  }
  const candidate = value as Partial<GroupInput>;
  if (!Array.isArray(candidate.key_ids)) {
    throw new Error(`${role} key IDs must be an array.`);
  }
  if (candidate.key_ids.length < 1 || candidate.key_ids.length > MAX_GROUP_KEYS) {
    throw new Error(
      `${role} group must contain between 1 and ${MAX_GROUP_KEYS} keys.`,
    );
  }
  const selectedIds = candidate.key_ids.map((id, index) =>
    normalizeText(id, `${role} key ID ${index + 1}`, 64),
  );
  if (new Set(selectedIds).size !== selectedIds.length) {
    throw new Error(`${role} group contains a duplicate key ID.`);
  }
  const selectedKeys = selectedIds.map((id) => {
    const key = keyById.get(id);
    if (!key) throw new Error(`${role} group references unknown key ID: ${id}.`);
    return key;
  });
  if (!Number.isInteger(candidate.threshold)) {
    throw new Error(`${role} threshold must be an integer.`);
  }
  const threshold = candidate.threshold as number;
  if (threshold < 1 || threshold > selectedKeys.length) {
    throw new Error(
      `${role} threshold must be between 1 and its ${selectedKeys.length}-key group size.`,
    );
  }
  validateTimestamp(role, candidate.unlock_unix);

  selectedKeys.sort((left, right) =>
    left.public_key.localeCompare(right.public_key),
  );
  return {
    input: {
      key_ids: selectedKeys.map((key) => key.id),
      threshold,
      unlock_unix: candidate.unlock_unix as number,
    },
    keys: selectedKeys,
  };
}

function groupFragment(threshold: number, publicKeys: string[]): string {
  if (threshold === 1 && publicKeys.length === 1) {
    return `pk(${publicKeys[0]})`;
  }
  return `multi(${threshold},${publicKeys.join(",")})`;
}

function sameStrings(left: string[], right: string[]): boolean {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

export function compileComposedPolicy(
  request: ComposerRequest,
): CompiledComposerPolicy {
  if (!request || typeof request !== "object") {
    throw new Error("Policy request is required.");
  }
  if (request.format !== "mimir-composer-request" || request.version !== 2) {
    throw new Error("Unsupported composer request format or version.");
  }
  if (request.template_id !== TEMPLATE_ID_V2) {
    throw new Error("Unsupported composer policy template.");
  }
  if (!Object.prototype.hasOwnProperty.call(NETWORKS, request.network)) {
    throw new Error("Unsupported Bitcoin network.");
  }

  const keys = normalizeKeys(request.keys);
  const keyById = new Map(keys.map((key) => [key.id, key]));
  const owner = normalizeGroup("Owner", request.owner, keyById);
  const heirs = normalizeGroup("Heirs", request.heirs, keyById);
  const ownerIds = new Set(owner.input.key_ids);
  const overlap = heirs.input.key_ids.filter((id) => ownerIds.has(id));
  if (overlap.length > 0) {
    throw new Error(
      `A key cannot appear in both owner and heir groups: ${overlap.join(", ")}.`,
    );
  }
  if (owner.input.unlock_unix >= heirs.input.unlock_unix) {
    throw new Error("Owner unlock must be strictly earlier than heir unlock.");
  }

  const normalizedRequest: ComposerRequest = {
    format: "mimir-composer-request",
    version: 2,
    network: request.network,
    template_id: TEMPLATE_ID_V2,
    keys,
    owner: owner.input,
    heirs: heirs.input,
  };
  const ownerPublicKeys = owner.keys.map((key) => key.public_key);
  const heirPublicKeys = heirs.keys.map((key) => key.public_key);
  const ownerFragment = groupFragment(owner.input.threshold, ownerPublicKeys);
  const heirsFragment = groupFragment(heirs.input.threshold, heirPublicKeys);
  const miniscript =
    `or_i(and_v(v:after(${owner.input.unlock_unix}),${ownerFragment}),` +
    `and_v(v:after(${heirs.input.unlock_unix}),${heirsFragment}))`;

  const compiled = compileMiniscript(miniscript);
  if (compiled.error || !compiled.issane || !compiled.issanesublevel) {
    throw new Error(
      `Miniscript compiler rejected the composed policy: ${compiled.error ?? "not sane"}.`,
    );
  }
  const witnessScript = asmToScript(compiled.asm);
  if (witnessScript.length > MAX_STANDARD_P2WSH_SCRIPT_BYTES) {
    throw new Error(
      `Witness script is ${witnessScript.length} bytes; the P2WSH standardness limit is ${MAX_STANDARD_P2WSH_SCRIPT_BYTES} bytes.`,
    );
  }
  const witnessProgram = sha256(witnessScript);
  const scriptPubkey = concatBytes(Uint8Array.of(0x00, 0x20), witnessProgram);
  const address = bech32.encode(
    NETWORKS[request.network].hrp,
    [0, ...bech32.toWords(witnessProgram)],
  );
  const descriptorBody = `wsh(${miniscript})`;
  const descriptor = addDescriptorChecksum(descriptorBody);

  const manifest: ComposerPolicyManifest = {
    format: "mimir-composed-policy",
    version: 2,
    network: request.network,
    template_id: TEMPLATE_ID_V2,
    keys,
    owner: {
      key_ids: owner.input.key_ids,
      public_keys: ownerPublicKeys,
      threshold: owner.input.threshold,
      unlock: {
        unix: owner.input.unlock_unix,
        utc: utcFromUnix(owner.input.unlock_unix),
      },
      miniscript_fragment: ownerFragment,
    },
    heirs: {
      key_ids: heirs.input.key_ids,
      public_keys: heirPublicKeys,
      threshold: heirs.input.threshold,
      unlock: {
        unix: heirs.input.unlock_unix,
        utc: utcFromUnix(heirs.input.unlock_unix),
      },
      miniscript_fragment: heirsFragment,
    },
    miniscript,
    descriptor: {
      body: descriptorBody,
      checksummed: descriptor,
    },
    script: {
      asm: compiled.asm,
      witness_script_hex: bytesToHex(witnessScript),
      witness_script_bytes: witnessScript.length,
      witness_program_sha256: bytesToHex(witnessProgram),
      script_pubkey_hex: bytesToHex(scriptPubkey),
    },
    address,
  };
  const canonicalManifest = canonicalizeJson(manifest);
  const policyManifestSha256 = sha256Hex(canonicalManifest);

  const ownerSorted = [...ownerPublicKeys].sort();
  const heirsSorted = [...heirPublicKeys].sort();
  const invariants: InvariantResult[] = [
    {
      id: "miniscript-sane",
      label: "Composed Miniscript is sane at top level and sublevel",
      ok: compiled.issane && compiled.issanesublevel && !compiled.error,
    },
    {
      id: "canonical-owner-order",
      label: "Owner keys use lexicographic public-key order",
      ok: sameStrings(ownerPublicKeys, ownerSorted),
    },
    {
      id: "canonical-heir-order",
      label: "Heir keys use lexicographic public-key order",
      ok: sameStrings(heirPublicKeys, heirsSorted),
    },
    {
      id: "disjoint-groups",
      label: "Owner and heir key groups are disjoint",
      ok: overlap.length === 0,
    },
    {
      id: "thresholds",
      label: "Both signing thresholds are satisfiable",
      ok:
        owner.input.threshold >= 1 &&
        owner.input.threshold <= ownerPublicKeys.length &&
        heirs.input.threshold >= 1 &&
        heirs.input.threshold <= heirPublicKeys.length,
    },
    {
      id: "timelocks",
      label: "Owner unlock is strictly earlier than heir unlock",
      ok: owner.input.unlock_unix < heirs.input.unlock_unix,
    },
    {
      id: "descriptor-checksum",
      label: "Descriptor checksum covers the exact composed policy",
      ok: descriptor === addDescriptorChecksum(descriptorBody),
    },
    {
      id: "witness-program",
      label: "SHA256(witness script) equals the P2WSH witness program",
      ok: sha256Hex(witnessScript) === bytesToHex(witnessProgram),
    },
    {
      id: "script-pubkey",
      label: "scriptPubKey is OP_0 PUSH32 followed by the witness program",
      ok: bytesToHex(scriptPubkey) === `0020${bytesToHex(witnessProgram)}`,
    },
    {
      id: "address",
      label: "Network address encodes the exact P2WSH witness program",
      ok:
        bech32.encode(
          NETWORKS[request.network].hrp,
          [0, ...bech32.toWords(witnessProgram)],
        ) === address,
    },
    {
      id: "standard-script-size",
      label: "Witness script is within the 3,600-byte P2WSH standardness limit",
      ok: witnessScript.length <= MAX_STANDARD_P2WSH_SCRIPT_BYTES,
    },
    {
      id: "canonical-manifest-hash",
      label: "Canonical manifest hash is reproducible",
      ok:
        policyManifestSha256 ===
        sha256Hex(canonicalizeJson(JSON.parse(canonicalManifest))),
    },
  ];
  if (invariants.some((invariant) => !invariant.ok)) {
    throw new Error("An internal composer consistency invariant failed; output stopped.");
  }

  const assignedIds = new Set([
    ...owner.input.key_ids,
    ...heirs.input.key_ids,
  ]);
  const unassigned = keys.filter((key) => !assignedIds.has(key.id));
  const warnings: string[] = [];
  if (unassigned.length > 0) {
    warnings.push(
      `Unassigned registry keys are excluded from this policy: ${unassigned
        .map((key) => `${key.label} (${key.id})`)
        .join(", ")}.`,
    );
  }
  warnings.push(
    "Raw public keys define one fixed P2WSH address; there is no child-key derivation or address rotation.",
    "The owner branch remains spendable after the heir branch unlocks.",
    "Independently reproduce the descriptor, script, and address with Bitcoin Core before funding.",
  );
  if (request.network === "bitcoin") {
    warnings.push(
      "Mainnet output is preview-grade. Rehearse the exact policy on regtest or signet before use.",
    );
  }

  return {
    request: normalizedRequest,
    manifest,
    canonical_manifest: canonicalManifest,
    policy_manifest_sha256: policyManifestSha256,
    miniscript,
    descriptor_body: descriptorBody,
    descriptor,
    asm: compiled.asm,
    witness_script_hex: manifest.script.witness_script_hex,
    witness_script_bytes: manifest.script.witness_script_bytes,
    witness_program_sha256: manifest.script.witness_program_sha256,
    script_pubkey_hex: manifest.script.script_pubkey_hex,
    address,
    invariants,
    warnings,
  };
}
