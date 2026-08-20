import { compileMiniscript } from "@bitcoinerlab/miniscript";
import { sha256 } from "@noble/hashes/sha2.js";
import { bech32 } from "@scure/base";
import { validateCompressedPublicKey } from "./composer";
import {
  MAX_LOCKTIME,
  MIN_TIMESTAMP_LOCK,
  addDescriptorChecksum,
  bytesToHex,
  canonicalizeJson,
  hexToBytes,
  sha256Hex,
  utcFromUnix,
  type InvariantResult,
} from "./mimir";

export const TEMPLATE_ID_V3 = "mimir-rules-v3" as const;

export type RuleNetwork = "bitcoin" | "signet" | "regtest";

export type RuleKey = {
  id: string;
  label: string;
  public_key: string;
};

export type RuleDefinition = {
  key_ids: string[];
  threshold: number;
  unlock_unix: number | null;
};

export type RuleComposerRequest = {
  format: "mimir-rule-request";
  version: 3;
  network: RuleNetwork;
  template_id: typeof TEMPLATE_ID_V3;
  keys: RuleKey[];
  rules: RuleDefinition[];
};

export type RulePolicyRule = {
  id: string;
  key_ids: string[];
  public_keys: string[];
  threshold: number;
  unlock: {
    unix: number;
    utc: string;
  } | null;
  miniscript_fragment: string;
};

export type RulePolicyManifest = {
  format: "mimir-rule-policy";
  version: 3;
  network: RuleNetwork;
  template_id: typeof TEMPLATE_ID_V3;
  keys: RuleKey[];
  rules: RulePolicyRule[];
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

export type CompiledRulePolicy = {
  request: RuleComposerRequest;
  manifest: RulePolicyManifest;
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

const NETWORKS: Record<RuleNetwork, { hrp: string }> = {
  bitcoin: { hrp: "bc" },
  signet: { hrp: "tb" },
  regtest: { hrp: "bcrt" },
};

const MAX_REGISTRY_KEYS = 20;
const MAX_RULES = 10;
const MAX_RULE_KEYS = 10;
const SECONDS_PER_DAY = 86_400;
const MAX_STANDARD_P2WSH_SCRIPT_BYTES = 3_600;

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

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

export function validateRulePublicKey(value: unknown): string {
  return validateCompressedPublicKey(value);
}

function validateRuleTimestamp(
  value: unknown,
  field = "Rule unlock",
): asserts value is number {
  if (!Number.isInteger(value)) {
    throw new Error(`${field} must be an integer Unix timestamp or null.`);
  }
  const timestamp = value as number;
  if (timestamp < MIN_TIMESTAMP_LOCK) {
    throw new Error(
      `${field} must be a Unix timestamp of at least ${MIN_TIMESTAMP_LOCK}.`,
    );
  }
  if (timestamp > MAX_LOCKTIME) {
    throw new Error(`${field} exceeds Miniscript after()'s 2038-01-19 limit.`);
  }
  if (timestamp % SECONDS_PER_DAY !== 0) {
    throw new Error(`${field} must use whole-day granularity at 00:00:00 UTC.`);
  }
}

export function unixFromRuleDate(value: string): number {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    throw new Error("Rule date must use the exact YYYY-MM-DD format.");
  }
  const [yearText, monthText, dayText] = value.split("-");
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
    throw new Error("Rule date is not a real calendar date.");
  }
  const unix = milliseconds / 1_000;
  validateRuleTimestamp(unix, "Rule date");
  return unix;
}

type NormalizedRegistry = {
  keys: RuleKey[];
  canonicalByInputId: Map<string, RuleKey>;
};

function normalizeKeys(value: unknown): NormalizedRegistry {
  if (!Array.isArray(value)) throw new Error("Key registry must be an array.");
  if (value.length === 0) throw new Error("Key registry cannot be empty.");
  if (value.length > MAX_REGISTRY_KEYS) {
    throw new Error(`Key registry supports at most ${MAX_REGISTRY_KEYS} keys.`);
  }

  const inputKeys = value.map((entry, index) => {
    if (!entry || typeof entry !== "object") {
      throw new Error(`Key registry entry ${index + 1} is invalid.`);
    }
    const candidate = entry as Partial<RuleKey>;
    return {
      id: normalizeText(candidate.id, `Key ${index + 1} ID`, 64),
      label: normalizeText(candidate.label, `Key ${index + 1} label`, 80),
      public_key: validateRulePublicKey(candidate.public_key),
    };
  });

  const uniqueFields = [
    ["ID", (key: RuleKey) => key.id],
    ["label", (key: RuleKey) => key.label.toLocaleLowerCase("en-US")],
    ["public key", (key: RuleKey) => key.public_key],
  ] as const;
  for (const [field, select] of uniqueFields) {
    const seen = new Set<string>();
    for (const key of inputKeys) {
      const selected = select(key);
      if (seen.has(selected)) {
        throw new Error(`Key registry contains a duplicate ${field}: ${selected}.`);
      }
      seen.add(selected);
    }
  }

  const sortedInputKeys = [...inputKeys].sort((left, right) =>
    compareText(left.public_key, right.public_key),
  );
  const keys = sortedInputKeys.map((key, index) => ({
    id: `key-${String(index + 1).padStart(2, "0")}`,
    label: key.label,
    public_key: key.public_key,
  }));
  const canonicalByInputId = new Map<string, RuleKey>();
  sortedInputKeys.forEach((key, index) => {
    canonicalByInputId.set(key.id, keys[index]);
  });
  return { keys, canonicalByInputId };
}

type NormalizedRule = {
  definition: RuleDefinition;
  keys: RuleKey[];
  miniscript_fragment: string;
};

function signingFragment(threshold: number, publicKeys: string[]): string {
  if (threshold === 1 && publicKeys.length === 1) {
    return `pk(${publicKeys[0]})`;
  }
  return `multi(${threshold},${publicKeys.join(",")})`;
}

function normalizeRules(
  value: unknown,
  canonicalByInputId: Map<string, RuleKey>,
): NormalizedRule[] {
  if (!Array.isArray(value)) throw new Error("Rules must be an array.");
  if (value.length < 1 || value.length > MAX_RULES) {
    throw new Error(`Policy must contain between 1 and ${MAX_RULES} rules.`);
  }

  const usedPublicKeys = new Map<string, number>();
  const rules = value.map((entry, ruleIndex) => {
    const ruleNumber = ruleIndex + 1;
    if (!entry || typeof entry !== "object") {
      throw new Error(`Rule ${ruleNumber} is invalid.`);
    }
    const candidate = entry as Partial<RuleDefinition>;
    const allowedFields = new Set(["key_ids", "threshold", "unlock_unix"]);
    const unsupportedFields = Object.keys(candidate).filter(
      (field) => !allowedFields.has(field),
    );
    if (unsupportedFields.length > 0) {
      throw new Error(
        `Rule ${ruleNumber} contains unsupported state: ${unsupportedFields.join(", ")}.`,
      );
    }
    if (!Array.isArray(candidate.key_ids)) {
      throw new Error(`Rule ${ruleNumber} key IDs must be an array.`);
    }
    if (
      candidate.key_ids.length < 1 ||
      candidate.key_ids.length > MAX_RULE_KEYS
    ) {
      throw new Error(
        `Rule ${ruleNumber} must contain between 1 and ${MAX_RULE_KEYS} keys.`,
      );
    }
    const inputIds = candidate.key_ids.map((id, keyIndex) =>
      normalizeText(id, `Rule ${ruleNumber} key ID ${keyIndex + 1}`, 64),
    );
    if (new Set(inputIds).size !== inputIds.length) {
      throw new Error(`Rule ${ruleNumber} contains a duplicate key ID.`);
    }
    const selectedKeys = inputIds.map((id) => {
      const key = canonicalByInputId.get(id);
      if (!key) {
        throw new Error(`Rule ${ruleNumber} references unknown key ID: ${id}.`);
      }
      return key;
    });
    for (const key of selectedKeys) {
      const previousRule = usedPublicKeys.get(key.public_key);
      if (previousRule !== undefined) {
        throw new Error(
          `Key ${key.label} appears in both rule ${previousRule} and rule ${ruleNumber}; each public key may appear in at most one rule.`,
        );
      }
      usedPublicKeys.set(key.public_key, ruleNumber);
    }
    if (!Number.isInteger(candidate.threshold)) {
      throw new Error(`Rule ${ruleNumber} threshold must be an integer.`);
    }
    const threshold = candidate.threshold as number;
    if (threshold < 1 || threshold > selectedKeys.length) {
      throw new Error(
        `Rule ${ruleNumber} threshold must be between 1 and its ${selectedKeys.length}-key group size.`,
      );
    }
    if (candidate.unlock_unix !== null) {
      validateRuleTimestamp(candidate.unlock_unix, `Rule ${ruleNumber} unlock`);
    }

    selectedKeys.sort((left, right) =>
      compareText(left.public_key, right.public_key),
    );
    const keyFragment = signingFragment(
      threshold,
      selectedKeys.map((key) => key.public_key),
    );
    const miniscriptFragment =
      candidate.unlock_unix === null
        ? keyFragment
        : `and_v(v:after(${candidate.unlock_unix}),${keyFragment})`;
    return {
      definition: {
        key_ids: selectedKeys.map((key) => key.id),
        threshold,
        unlock_unix: candidate.unlock_unix,
      },
      keys: selectedKeys,
      miniscript_fragment: miniscriptFragment,
    };
  });

  return rules.sort((left, right) =>
    compareText(left.miniscript_fragment, right.miniscript_fragment),
  );
}

function composeRuleFragments(fragments: string[]): string {
  if (fragments.length === 1) return fragments[0];
  return `or_i(${fragments[0]},${composeRuleFragments(fragments.slice(1))})`;
}

function sameStrings(left: string[], right: string[]): boolean {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

export function compileRulePolicy(
  request: RuleComposerRequest,
): CompiledRulePolicy {
  if (!request || typeof request !== "object") {
    throw new Error("Policy request is required.");
  }
  if (request.format !== "mimir-rule-request" || request.version !== 3) {
    throw new Error("Unsupported rule composer request format or version.");
  }
  if (request.template_id !== TEMPLATE_ID_V3) {
    throw new Error("Unsupported rule policy template.");
  }
  if (!Object.prototype.hasOwnProperty.call(NETWORKS, request.network)) {
    throw new Error("Unsupported Bitcoin network.");
  }

  const registry = normalizeKeys(request.keys);
  const rules = normalizeRules(request.rules, registry.canonicalByInputId);
  const normalizedRequest: RuleComposerRequest = {
    format: "mimir-rule-request",
    version: 3,
    network: request.network,
    template_id: TEMPLATE_ID_V3,
    keys: registry.keys,
    rules: rules.map((rule) => rule.definition),
  };
  const fragments = rules.map((rule) => rule.miniscript_fragment);
  const miniscript = composeRuleFragments(fragments);

  const compiled = compileMiniscript(miniscript);
  if (compiled.error || !compiled.issane || !compiled.issanesublevel) {
    throw new Error(
      `Miniscript compiler rejected the rule policy: ${compiled.error ?? "not sane"}.`,
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
  const network = NETWORKS[request.network];
  const address = bech32.encode(network.hrp, [
    0,
    ...bech32.toWords(witnessProgram),
  ]);
  const descriptorBody = `wsh(${miniscript})`;
  const descriptor = addDescriptorChecksum(descriptorBody);

  const manifestRules: RulePolicyRule[] = rules.map((rule, index) => ({
    id: `rule-${String(index + 1).padStart(2, "0")}`,
    key_ids: rule.definition.key_ids,
    public_keys: rule.keys.map((key) => key.public_key),
    threshold: rule.definition.threshold,
    unlock:
      rule.definition.unlock_unix === null
        ? null
        : {
            unix: rule.definition.unlock_unix,
            utc: utcFromUnix(rule.definition.unlock_unix),
          },
    miniscript_fragment: rule.miniscript_fragment,
  }));
  const manifest: RulePolicyManifest = {
    format: "mimir-rule-policy",
    version: 3,
    network: request.network,
    template_id: TEMPLATE_ID_V3,
    keys: registry.keys,
    rules: manifestRules,
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
  const sortedPublicKeys = registry.keys.map((key) => key.public_key).sort(compareText);
  const sortedFragments = [...fragments].sort(compareText);
  const flattenedRuleKeys = rules.flatMap((rule) =>
    rule.keys.map((key) => key.public_key),
  );
  const invariants: InvariantResult[] = [
    {
      id: "miniscript-sane",
      label: "Rule Miniscript is sane at top level and sublevel",
      ok: compiled.issane && compiled.issanesublevel && !compiled.error,
    },
    {
      id: "canonical-key-order",
      label: "Registry keys use lexicographic public-key order",
      ok: sameStrings(
        registry.keys.map((key) => key.public_key),
        sortedPublicKeys,
      ),
    },
    {
      id: "canonical-rule-order",
      label: "Rules use lexicographic Miniscript-fragment order",
      ok: sameStrings(fragments, sortedFragments),
    },
    {
      id: "disjoint-rules",
      label: "Every public key appears in at most one rule",
      ok: new Set(flattenedRuleKeys).size === flattenedRuleKeys.length,
    },
    {
      id: "thresholds",
      label: "Every signing threshold is satisfiable",
      ok: rules.every(
        (rule) =>
          rule.definition.threshold >= 1 &&
          rule.definition.threshold <= rule.keys.length,
      ),
    },
    {
      id: "day-timelocks",
      label: "Every absolute timelock uses 00:00:00 UTC day granularity",
      ok: rules.every(
        (rule) =>
          rule.definition.unlock_unix === null ||
          (rule.definition.unlock_unix >= MIN_TIMESTAMP_LOCK &&
            rule.definition.unlock_unix <= MAX_LOCKTIME &&
            rule.definition.unlock_unix % SECONDS_PER_DAY === 0),
      ),
    },
    {
      id: "descriptor-checksum",
      label: "Descriptor checksum covers the exact rule policy",
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
        bech32.encode(network.hrp, [0, ...bech32.toWords(witnessProgram)]) ===
        address,
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
    throw new Error(
      "An internal rule composer consistency invariant failed; output stopped.",
    );
  }

  const assignedIds = new Set(rules.flatMap((rule) => rule.definition.key_ids));
  const unassigned = registry.keys.filter((key) => !assignedIds.has(key.id));
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
  );
  if (rules.some((rule) => rule.definition.unlock_unix === null)) {
    warnings.push(
      "Untimed rules are immediately available as soon as this output is funded.",
    );
  }
  if (rules.some((rule) => rule.definition.unlock_unix !== null)) {
    warnings.push(
      "Timed rules remain available after their date; a later rule does not revoke an earlier rule.",
      "Calendar-date locks use Bitcoin median time past, so a timed rule may become usable after the displayed UTC midnight.",
      "Spending through a timed rule requires a transaction nLockTime at least equal to the rule timestamp and at least one non-final input sequence for CLTV.",
    );
  }
  warnings.push(
    "Independently reproduce and verify the descriptor, script, and address with Bitcoin Core before funding.",
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
