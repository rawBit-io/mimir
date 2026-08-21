import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bech32 } from "@scure/base";

export const TEMPLATE_ID_DIRECT_SCRIPT = "mimir-direct-p2wsh-v1" as const;
export const MAX_DIRECT_SCRIPT_KEYS = 5;
export const MAX_DIRECT_SCRIPT_CLAUSES = 5;
export const MIN_TIMESTAMP_LOCK = 500_000_000;
export const MAX_TIMESTAMP_LOCK = 4_294_944_000;

const SECONDS_PER_DAY = 86_400;
const MAX_STANDARD_P2WSH_SCRIPT_BYTES = 3_600;
const MAX_SCRIPT_OPS = 201;

export type DirectScriptNetwork = "bitcoin" | "testnet" | "signet" | "regtest";

export type DirectScriptKey = {
  id: string;
  label: string;
  public_key: string;
};

export type DirectScriptClause = {
  key_ids: string[];
  threshold: number;
  unlock_unix: number | null;
};

export type DirectScriptPolicyRequest = {
  format: "mimir-direct-script-policy-request";
  version: 7;
  network: DirectScriptNetwork;
  template_id: typeof TEMPLATE_ID_DIRECT_SCRIPT;
  keys: DirectScriptKey[];
  clauses: DirectScriptClause[];
};

export type DirectScriptManifestClause = {
  id: string;
  key_ids: string[];
  public_keys: string[];
  threshold: number;
  unlock: { unix: number; utc: string } | null;
  summary: string;
  branch_selector_bottom_to_top: Array<0 | 1>;
  signature_order: string[];
  requires_checkmultisig_dummy: boolean;
  script_asm: string;
  script_hex: string;
};

export type DirectScriptPolicyManifest = {
  format: "mimir-direct-script-policy";
  version: 7;
  network: DirectScriptNetwork;
  template_id: typeof TEMPLATE_ID_DIRECT_SCRIPT;
  semantics: "OR of authored clauses; each clause is optional absolute CLTV AND one signature threshold";
  keys: DirectScriptKey[];
  clauses: DirectScriptManifestClause[];
  construction: {
    type: "right-nested-if-else" | "single-clause";
    authored_clauses: number;
    emitted_branches: number;
    authored_key_occurrences: number;
    emitted_key_occurrences: number;
    rewriting: false;
  };
  script: {
    asm: string;
    witness_script_hex: string;
    witness_script_bytes: number;
    opcode_count: number;
    sigop_count: number;
    witness_program_sha256: string;
    script_pubkey_hex: string;
  };
  address: string;
};

export type CompiledDirectScriptPolicy = {
  request: DirectScriptPolicyRequest;
  manifest: DirectScriptPolicyManifest;
  canonical_manifest: string;
  policy_manifest_sha256: string;
  asm: string;
  witness_script_hex: string;
  witness_script_bytes: number;
  opcode_count: number;
  sigop_count: number;
  witness_program_sha256: string;
  script_pubkey_hex: string;
  address: string;
};

type NormalizedClause = {
  key_ids: string[];
  public_keys: string[];
  threshold: number;
  unlock_unix: number | null;
};

type Instruction =
  | { kind: "opcode"; name: keyof typeof OPCODES }
  | { kind: "smallint"; value: number }
  | { kind: "push"; data: Uint8Array };

const NETWORKS: Readonly<Record<DirectScriptNetwork, { hrp: string }>> = {
  bitcoin: { hrp: "bc" },
  testnet: { hrp: "tb" },
  signet: { hrp: "tb" },
  regtest: { hrp: "bcrt" },
};

const OPCODES = {
  OP_0: 0x00,
  OP_1: 0x51,
  OP_2: 0x52,
  OP_3: 0x53,
  OP_4: 0x54,
  OP_5: 0x55,
  OP_IF: 0x63,
  OP_ELSE: 0x67,
  OP_ENDIF: 0x68,
  OP_DROP: 0x75,
  OP_CHECKSIG: 0xac,
  OP_CHECKMULTISIG: 0xae,
  OP_CHECKLOCKTIMEVERIFY: 0xb1,
} as const;

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function cloneJson<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function bytesToHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(value: string): Uint8Array {
  if (value.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(value)) {
    throw new Error("Hexadecimal data is malformed.");
  }
  return Uint8Array.from(value.match(/.{2}/g)?.map((byte) => Number.parseInt(byte, 16)) ?? []);
}

function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(chunks.reduce((total, chunk) => total + chunk.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
}

function sha256Hex(value: string | Uint8Array): string {
  return bytesToHex(sha256(typeof value === "string" ? new TextEncoder().encode(value) : value));
}

function canonicalizeValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalizeValue);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => compareText(left, right))
        .map(([key, child]) => [key, canonicalizeValue(child)]),
    );
  }
  return value;
}

function canonicalizeJson(value: unknown): string {
  return JSON.stringify(canonicalizeValue(value));
}

function normalizeText(value: unknown, field: string, maximumLength: number): string {
  if (typeof value !== "string") throw new Error(`${field} must be text.`);
  const normalized = value.trim().normalize("NFC");
  if (!normalized) throw new Error(`${field} cannot be empty.`);
  if (normalized.length > maximumLength) {
    throw new Error(`${field} cannot exceed ${maximumLength} characters.`);
  }
  if (/\p{Cc}/u.test(normalized)) throw new Error(`${field} cannot contain control characters.`);
  return normalized;
}

export function validateDirectScriptPublicKey(value: unknown): string {
  if (typeof value !== "string") throw new Error("Public key must be hexadecimal text.");
  const normalized = value.trim().toLowerCase();
  if (!/^(?:02|03)[0-9a-f]{64}$/.test(normalized)) {
    throw new Error(
      "Public key must be a 33-byte compressed secp256k1 key (02/03 plus a 32-byte x-coordinate).",
    );
  }
  try {
    const point = secp256k1.Point.fromBytes(hexToBytes(normalized));
    if (bytesToHex(point.toBytes(true)) !== normalized) throw new Error("non-canonical point");
  } catch {
    throw new Error("Public key is not a valid point on the secp256k1 curve.");
  }
  return normalized;
}

function validateTimestamp(value: unknown, field: string): asserts value is number {
  if (!Number.isInteger(value)) throw new Error(`${field} must be an integer Unix timestamp or null.`);
  const timestamp = value as number;
  if (timestamp < MIN_TIMESTAMP_LOCK) {
    throw new Error(`${field} must be at least ${MIN_TIMESTAMP_LOCK} so it is a timestamp lock.`);
  }
  if (timestamp > MAX_TIMESTAMP_LOCK) {
    throw new Error(`${field} exceeds the latest supported whole UTC day, 2106-02-07.`);
  }
  if (timestamp % SECONDS_PER_DAY !== 0) {
    throw new Error(`${field} must use whole-day granularity at 00:00:00 UTC.`);
  }
}

export function unixFromDirectScriptDate(value: string): number {
  const match = value.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!match) throw new Error("Unlock date must use YYYY-MM-DD.");
  const [, yearText, monthText, dayText] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const milliseconds = Date.UTC(year, month - 1, day);
  const date = new Date(milliseconds);
  if (
    !Number.isFinite(milliseconds) ||
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day
  ) {
    throw new Error("Unlock date must be a real calendar date.");
  }
  const unix = Math.floor(milliseconds / 1_000);
  validateTimestamp(unix, "Unlock date");
  return unix;
}

function utcFromUnix(value: number): string {
  return new Date(value * 1_000).toISOString().replace(".000Z", "Z");
}

function encodeScriptNumber(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error("Script number must be a non-negative integer.");
  if (value === 0) return new Uint8Array();
  const bytes: number[] = [];
  let remaining = value;
  while (remaining > 0) {
    bytes.push(remaining & 0xff);
    remaining = Math.floor(remaining / 256);
  }
  if ((bytes.at(-1) ?? 0) & 0x80) bytes.push(0);
  return Uint8Array.from(bytes);
}

function encodePushData(data: Uint8Array): Uint8Array {
  if (data.length <= 75) return concatBytes(Uint8Array.of(data.length), data);
  if (data.length <= 0xff) return concatBytes(Uint8Array.of(0x4c, data.length), data);
  if (data.length <= 0xffff) {
    return concatBytes(Uint8Array.of(0x4d, data.length & 0xff, (data.length >> 8) & 0xff), data);
  }
  throw new Error("A pushed value is unexpectedly large.");
}

function encodeInstruction(instruction: Instruction): Uint8Array {
  if (instruction.kind === "opcode") return Uint8Array.of(OPCODES[instruction.name]);
  if (instruction.kind === "smallint") {
    if (!Number.isInteger(instruction.value) || instruction.value < 0 || instruction.value > 16) {
      throw new Error("Small integer opcode is outside 0..16.");
    }
    return Uint8Array.of(instruction.value === 0 ? OPCODES.OP_0 : 0x50 + instruction.value);
  }
  return encodePushData(instruction.data);
}

function encodeInstructions(instructions: Instruction[]): Uint8Array {
  return concatBytes(...instructions.map(encodeInstruction));
}

function asmForInstruction(instruction: Instruction): string {
  if (instruction.kind === "opcode") return instruction.name;
  if (instruction.kind === "smallint") return String(instruction.value);
  return `<${bytesToHex(instruction.data)}>`;
}

function asmForInstructions(instructions: Instruction[]): string {
  return instructions.map(asmForInstruction).join(" ");
}

function op(name: keyof typeof OPCODES): Instruction {
  return { kind: "opcode", name };
}

function smallint(value: number): Instruction {
  return { kind: "smallint", value };
}

function pushHex(value: string): Instruction {
  return { kind: "push", data: hexToBytes(value) };
}

function instructionsForClause(clause: NormalizedClause): Instruction[] {
  const instructions: Instruction[] = [];
  if (clause.unlock_unix !== null) {
    instructions.push(
      { kind: "push", data: encodeScriptNumber(clause.unlock_unix) },
      op("OP_CHECKLOCKTIMEVERIFY"),
      op("OP_DROP"),
    );
  }
  if (clause.public_keys.length === 1) {
    instructions.push(pushHex(clause.public_keys[0]), op("OP_CHECKSIG"));
    return instructions;
  }
  instructions.push(smallint(clause.threshold));
  clause.public_keys.forEach((publicKey) => instructions.push(pushHex(publicKey)));
  instructions.push(smallint(clause.public_keys.length), op("OP_CHECKMULTISIG"));
  return instructions;
}

function instructionsForPolicy(clauses: NormalizedClause[], index = 0): Instruction[] {
  if (index === clauses.length - 1) return instructionsForClause(clauses[index]);
  return [
    op("OP_IF"),
    ...instructionsForClause(clauses[index]),
    op("OP_ELSE"),
    ...instructionsForPolicy(clauses, index + 1),
    op("OP_ENDIF"),
  ];
}

function branchSelector(index: number, clauseCount: number): Array<0 | 1> {
  if (clauseCount === 1) return [];
  if (index === clauseCount - 1) return Array.from({ length: index }, () => 0 as const);
  return [1, ...Array.from({ length: index }, () => 0 as const)];
}

function normalizeRequest(request: DirectScriptPolicyRequest): {
  request: DirectScriptPolicyRequest;
  clauses: NormalizedClause[];
} {
  if (!request || typeof request !== "object") throw new Error("Direct Script policy request is required.");
  if (request.format !== "mimir-direct-script-policy-request" || request.version !== 7) {
    throw new Error("Unsupported Direct Script policy request format or version.");
  }
  if (request.template_id !== TEMPLATE_ID_DIRECT_SCRIPT) {
    throw new Error("Unsupported Direct Script policy template.");
  }
  if (!Object.prototype.hasOwnProperty.call(NETWORKS, request.network)) {
    throw new Error("Unsupported Bitcoin network.");
  }
  if (!Array.isArray(request.keys) || request.keys.length < 1 || request.keys.length > MAX_DIRECT_SCRIPT_KEYS) {
    throw new Error(`Policy must register between 1 and ${MAX_DIRECT_SCRIPT_KEYS} keys.`);
  }
  if (!Array.isArray(request.clauses) || request.clauses.length < 1 || request.clauses.length > MAX_DIRECT_SCRIPT_CLAUSES) {
    throw new Error(`Policy must contain between 1 and ${MAX_DIRECT_SCRIPT_CLAUSES} clauses.`);
  }

  const inputKeys = request.keys.map((candidate, index) => ({
    input_id: normalizeText(candidate?.id, `Key ${index + 1} ID`, 64),
    label: normalizeText(candidate?.label, `Key ${index + 1} label`, 80),
    public_key: validateDirectScriptPublicKey(candidate?.public_key),
  }));
  if (new Set(inputKeys.map((key) => key.input_id)).size !== inputKeys.length) {
    throw new Error("Key IDs must be unique.");
  }
  if (new Set(inputKeys.map((key) => key.label.toLocaleLowerCase("en-US"))).size !== inputKeys.length) {
    throw new Error("Key labels must be unique ignoring case.");
  }
  if (new Set(inputKeys.map((key) => key.public_key)).size !== inputKeys.length) {
    throw new Error("Each public key may be registered only once.");
  }

  const sortedKeys = [...inputKeys].sort((left, right) =>
    compareText(left.public_key, right.public_key) || compareText(left.label, right.label));
  const canonicalKeys: DirectScriptKey[] = sortedKeys.map((key, index) => ({
    id: `key-${String(index + 1).padStart(2, "0")}`,
    label: key.label,
    public_key: key.public_key,
  }));
  const canonicalByInputId = new Map(sortedKeys.map((key, index) => [key.input_id, canonicalKeys[index]]));

  const clauses = request.clauses.map((candidate, clauseIndex): NormalizedClause => {
    if (!candidate || typeof candidate !== "object") {
      throw new Error(`Clause ${clauseIndex + 1} must be an object.`);
    }
    if (!Array.isArray(candidate.key_ids) || candidate.key_ids.length < 1 || candidate.key_ids.length > MAX_DIRECT_SCRIPT_KEYS) {
      throw new Error(`Clause ${clauseIndex + 1} must select between 1 and ${MAX_DIRECT_SCRIPT_KEYS} keys.`);
    }
    const inputIds = candidate.key_ids.map((value, keyIndex) =>
      normalizeText(value, `Clause ${clauseIndex + 1} key ${keyIndex + 1} ID`, 64));
    if (new Set(inputIds).size !== inputIds.length) {
      throw new Error(`Clause ${clauseIndex + 1} cannot select the same key twice.`);
    }
    const selected = inputIds.map((id) => {
      const key = canonicalByInputId.get(id);
      if (!key) throw new Error(`Clause ${clauseIndex + 1} references unknown key ID ${id}.`);
      return key;
    }).sort((left, right) => compareText(left.public_key, right.public_key));
    if (!Number.isInteger(candidate.threshold) || candidate.threshold < 1 || candidate.threshold > selected.length) {
      throw new Error(`Clause ${clauseIndex + 1} threshold must be an integer between 1 and ${selected.length}.`);
    }
    if (candidate.unlock_unix !== null) {
      validateTimestamp(candidate.unlock_unix, `Clause ${clauseIndex + 1} unlock`);
    }
    return {
      key_ids: selected.map((key) => key.id),
      public_keys: selected.map((key) => key.public_key),
      threshold: selected.length === 1 ? 1 : candidate.threshold,
      unlock_unix: candidate.unlock_unix,
    };
  });

  return {
    request: {
      format: "mimir-direct-script-policy-request",
      version: 7,
      network: request.network,
      template_id: TEMPLATE_ID_DIRECT_SCRIPT,
      keys: canonicalKeys,
      clauses: clauses.map((clause) => ({
        key_ids: [...clause.key_ids],
        threshold: clause.threshold,
        unlock_unix: clause.unlock_unix,
      })),
    },
    clauses,
  };
}

function clauseSummary(clause: NormalizedClause, keys: Map<string, DirectScriptKey>): string {
  const labels = clause.key_ids.map((id) => keys.get(id)?.label ?? id);
  const signer = labels.length === 1 ? labels[0] : `${clause.threshold}-of-${labels.length} · ${labels.join(", ")}`;
  return clause.unlock_unix === null
    ? `${signer} · immediately`
    : `${signer} · from ${utcFromUnix(clause.unlock_unix)}`;
}

export function compileDirectScriptPolicy(request: DirectScriptPolicyRequest): CompiledDirectScriptPolicy {
  const normalized = normalizeRequest(request);
  const policyInstructions = instructionsForPolicy(normalized.clauses);
  const witnessScript = encodeInstructions(policyInstructions);
  const asm = asmForInstructions(policyInstructions);
  const witnessProgram = sha256(witnessScript);
  const scriptPubkey = concatBytes(Uint8Array.of(0x00, 0x20), witnessProgram);
  const address = bech32.encode(NETWORKS[normalized.request.network].hrp, [0, ...bech32.toWords(witnessProgram)]);
  const opcodeCount = policyInstructions.filter((instruction) => instruction.kind === "opcode").length;
  if (witnessScript.length > MAX_STANDARD_P2WSH_SCRIPT_BYTES) {
    throw new Error(`Witness script exceeds the ${MAX_STANDARD_P2WSH_SCRIPT_BYTES}-byte P2WSH standardness limit.`);
  }
  if (opcodeCount > MAX_SCRIPT_OPS) {
    throw new Error(`Witness script exceeds Bitcoin Script's ${MAX_SCRIPT_OPS}-opcode limit.`);
  }
  const sigopCount = normalized.clauses.reduce(
    (total, clause) => total + (clause.public_keys.length === 1 ? 1 : clause.public_keys.length),
    0,
  );
  const keysById = new Map(normalized.request.keys.map((key) => [key.id, key]));
  const manifestClauses: DirectScriptManifestClause[] = normalized.clauses.map((clause, index) => {
    const instructions = instructionsForClause(clause);
    return {
      id: `clause-${String(index + 1).padStart(2, "0")}`,
      key_ids: [...clause.key_ids],
      public_keys: [...clause.public_keys],
      threshold: clause.threshold,
      unlock: clause.unlock_unix === null
        ? null
        : { unix: clause.unlock_unix, utc: utcFromUnix(clause.unlock_unix) },
      summary: clauseSummary(clause, keysById),
      branch_selector_bottom_to_top: branchSelector(index, normalized.clauses.length),
      signature_order: [...clause.key_ids],
      requires_checkmultisig_dummy: clause.public_keys.length > 1,
      script_asm: asmForInstructions(instructions),
      script_hex: bytesToHex(encodeInstructions(instructions)),
    };
  });
  const authoredKeyOccurrences = normalized.clauses.reduce((total, clause) => total + clause.key_ids.length, 0);

  const manifest: DirectScriptPolicyManifest = {
    format: "mimir-direct-script-policy",
    version: 7,
    network: normalized.request.network,
    template_id: TEMPLATE_ID_DIRECT_SCRIPT,
    semantics: "OR of authored clauses; each clause is optional absolute CLTV AND one signature threshold",
    keys: normalized.request.keys,
    clauses: manifestClauses,
    construction: {
      type: normalized.clauses.length === 1 ? "single-clause" : "right-nested-if-else",
      authored_clauses: normalized.clauses.length,
      emitted_branches: normalized.clauses.length,
      authored_key_occurrences: authoredKeyOccurrences,
      emitted_key_occurrences: authoredKeyOccurrences,
      rewriting: false,
    },
    script: {
      asm,
      witness_script_hex: bytesToHex(witnessScript),
      witness_script_bytes: witnessScript.length,
      opcode_count: opcodeCount,
      sigop_count: sigopCount,
      witness_program_sha256: bytesToHex(witnessProgram),
      script_pubkey_hex: bytesToHex(scriptPubkey),
    },
    address,
  };
  const canonicalManifest = canonicalizeJson(manifest);
  const policyManifestSha256 = sha256Hex(canonicalManifest);
  return {
    request: cloneJson(normalized.request),
    manifest: cloneJson(manifest),
    canonical_manifest: canonicalManifest,
    policy_manifest_sha256: policyManifestSha256,
    asm,
    witness_script_hex: manifest.script.witness_script_hex,
    witness_script_bytes: witnessScript.length,
    opcode_count: opcodeCount,
    sigop_count: sigopCount,
    witness_program_sha256: manifest.script.witness_program_sha256,
    script_pubkey_hex: manifest.script.script_pubkey_hex,
    address,
  };
}
