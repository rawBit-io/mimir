import { compileMiniscript, satisfier } from "@bitcoinerlab/miniscript";
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

export const TEMPLATE_ID_GUARDED = "mimir-guarded-rules-v1" as const;
export const MAX_GUARDED_KEYS = 5;
export const MAX_GUARDED_RULES = 5;

export type GuardedNetwork = "bitcoin" | "signet" | "regtest";

export type GuardedKey = {
  id: string;
  label: string;
  public_key: string;
};

export type GuardedRuleDefinition = {
  key_ids: string[];
  threshold: number;
  unlock_unix: number | null;
};

export type GuardedRuleComposerRequest = {
  format: "mimir-guarded-rule-request";
  version: 5;
  network: GuardedNetwork;
  template_id: typeof TEMPLATE_ID_GUARDED;
  keys: GuardedKey[];
  rules: GuardedRuleDefinition[];
};

export type GuardedPolicyRule = {
  id: string;
  group_id: string;
  key_ids: string[];
  public_keys: string[];
  threshold: number;
  unlock: { unix: number; utc: string } | null;
  summary: string;
};

export type GuardedPolicyGroup = {
  id: string;
  key_ids: string[];
  public_keys: string[];
  stages: GuardedPolicyRule[];
  miniscript_fragment: string;
};

export type GuardedRulePolicyManifest = {
  format: "mimir-guarded-rule-policy";
  version: 5;
  network: GuardedNetwork;
  template_id: typeof TEMPLATE_ID_GUARDED;
  keys: GuardedKey[];
  rules: GuardedPolicyRule[];
  groups: GuardedPolicyGroup[];
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

export type CompiledGuardedRulePolicy = {
  request: GuardedRuleComposerRequest;
  manifest: GuardedRulePolicyManifest;
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

const NETWORKS: Record<GuardedNetwork, { hrp: string }> = {
  bitcoin: { hrp: "bc" },
  signet: { hrp: "tb" },
  regtest: { hrp: "bcrt" },
};

const SECONDS_PER_DAY = 86_400;
const MAX_STANDARD_P2WSH_SCRIPT_BYTES = 3_600;

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function cloneJson<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
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
  OP_SWAP: 0x7c,
  OP_EQUAL: 0x87,
  OP_EQUALVERIFY: 0x88,
  OP_0NOTEQUAL: 0x92,
  OP_ADD: 0x93,
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

export function validateGuardedRulePublicKey(value: unknown): string {
  return validateCompressedPublicKey(value);
}

function validateGuardedTimestamp(
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

export function unixFromGuardedRuleDate(value: string): number {
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
  validateGuardedTimestamp(unix, "Rule date");
  return unix;
}

type NormalizedRegistry = {
  keys: GuardedKey[];
  canonicalByInputId: Map<string, GuardedKey>;
};

function normalizeKeys(value: unknown): NormalizedRegistry {
  if (!Array.isArray(value)) throw new Error("Key registry must be an array.");
  if (value.length === 0) throw new Error("Key registry cannot be empty.");
  if (value.length > MAX_GUARDED_KEYS) {
    throw new Error(`Key registry supports at most ${MAX_GUARDED_KEYS} keys.`);
  }

  const inputKeys = value.map((entry, index) => {
    if (!entry || typeof entry !== "object") {
      throw new Error(`Key registry entry ${index + 1} is invalid.`);
    }
    const candidate = entry as Partial<GuardedKey>;
    return {
      input_id: normalizeText(candidate.id, `Key ${index + 1} ID`, 64),
      label: normalizeText(candidate.label, `Key ${index + 1} label`, 80),
      public_key: validateGuardedRulePublicKey(candidate.public_key),
    };
  });

  const uniqueFields = [
    ["ID", (key: (typeof inputKeys)[number]) => key.input_id],
    [
      "label",
      (key: (typeof inputKeys)[number]) =>
        key.label.toLocaleLowerCase("en-US"),
    ],
    ["public key", (key: (typeof inputKeys)[number]) => key.public_key],
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

  inputKeys.sort((left, right) => compareText(left.public_key, right.public_key));
  const keys = inputKeys.map((key, index) => ({
    id: `key-${String(index + 1).padStart(2, "0")}`,
    label: key.label,
    public_key: key.public_key,
  }));
  const canonicalByInputId = new Map<string, GuardedKey>();
  inputKeys.forEach((key, index) => {
    canonicalByInputId.set(key.input_id, keys[index]);
  });
  return { keys, canonicalByInputId };
}

type NormalizedStage = {
  key_ids: string[];
  public_keys: string[];
  threshold: number;
  unlock_unix: number | null;
};

type NormalizedGroup = {
  sort_key: string;
  key_ids: string[];
  public_keys: string[];
  stages: NormalizedStage[];
  miniscript_fragment: string;
};

function signingFragment(threshold: number, publicKeys: string[]): string {
  if (threshold === 1 && publicKeys.length === 1) {
    return `pk(${publicKeys[0]})`;
  }
  return `multi(${threshold},${publicKeys.join(",")})`;
}

function ladderFragment(
  publicKeys: string[],
  stages: NormalizedStage[],
): string {
  const first = stages[0];
  if (stages.length === 1) {
    const signing = signingFragment(first.threshold, publicKeys);
    return first.unlock_unix === null
      ? signing
      : `and_v(v:after(${first.unlock_unix}),${signing})`;
  }

  const thresholdTerms = [
    `pk(${publicKeys[0]})`,
    ...publicKeys.slice(1).map((publicKey) => `s:pk(${publicKey})`),
  ];
  for (let index = 1; index < stages.length; index += 1) {
    const thresholdDrop = stages[index - 1].threshold - stages[index].threshold;
    for (let credit = 0; credit < thresholdDrop; credit += 1) {
      thresholdTerms.push(`sln:after(${stages[index].unlock_unix})`);
    }
  }
  const threshold = `thresh(${first.threshold},${thresholdTerms.join(",")})`;
  return first.unlock_unix === null
    ? threshold
    : `and_v(v:after(${first.unlock_unix}),${threshold})`;
}

function compareUnlock(
  left: number | null,
  right: number | null,
): number {
  if (left === right) return 0;
  if (left === null) return -1;
  if (right === null) return 1;
  return left - right;
}

function normalizeGroups(
  value: unknown,
  registry: NormalizedRegistry,
): NormalizedGroup[] {
  if (!Array.isArray(value)) throw new Error("Rules must be an array.");
  if (value.length === 0) throw new Error("Add at least one spending rule.");
  if (value.length > MAX_GUARDED_RULES) {
    throw new Error(`A policy supports at most ${MAX_GUARDED_RULES} rules.`);
  }

  const stages = value.map((entry, ruleIndex): NormalizedStage => {
    if (!entry || typeof entry !== "object") {
      throw new Error(`Rule ${ruleIndex + 1} is invalid.`);
    }
    const candidate = entry as Partial<GuardedRuleDefinition>;
    if (!Array.isArray(candidate.key_ids) || candidate.key_ids.length === 0) {
      throw new Error(`Rule ${ruleIndex + 1} must contain at least one key.`);
    }
    if (candidate.key_ids.length > MAX_GUARDED_KEYS) {
      throw new Error(`Rule ${ruleIndex + 1} contains too many keys.`);
    }
    const selectedKeys = candidate.key_ids.map((rawId, keyIndex) => {
      const inputId = normalizeText(
        rawId,
        `Rule ${ruleIndex + 1} key ${keyIndex + 1} ID`,
        64,
      );
      const key = registry.canonicalByInputId.get(inputId);
      if (!key) {
        throw new Error(
          `Rule ${ruleIndex + 1} references unknown key ID: ${inputId}.`,
        );
      }
      return key;
    });
    if (new Set(selectedKeys.map((key) => key.id)).size !== selectedKeys.length) {
      throw new Error(`Rule ${ruleIndex + 1} contains a duplicate key.`);
    }
    selectedKeys.sort((left, right) =>
      compareText(left.public_key, right.public_key),
    );
    if (!Number.isInteger(candidate.threshold)) {
      throw new Error(`Rule ${ruleIndex + 1} threshold must be an integer.`);
    }
    const threshold = candidate.threshold as number;
    if (threshold < 1 || threshold > selectedKeys.length) {
      throw new Error(
        `Rule ${ruleIndex + 1} threshold must be between 1 and ${selectedKeys.length}.`,
      );
    }
    if (candidate.unlock_unix !== null) {
      validateGuardedTimestamp(
        candidate.unlock_unix,
        `Rule ${ruleIndex + 1} unlock`,
      );
    }
    return {
      key_ids: selectedKeys.map((key) => key.id),
      public_keys: selectedKeys.map((key) => key.public_key),
      threshold,
      unlock_unix: candidate.unlock_unix,
    };
  });

  const byKeySet = new Map<string, NormalizedStage[]>();
  for (const stage of stages) {
    const setKey = stage.public_keys.join(",");
    const group = byKeySet.get(setKey) ?? [];
    group.push(stage);
    byKeySet.set(setKey, group);
  }

  const groups = [...byKeySet.entries()]
    .sort(([left], [right]) => compareText(left, right))
    .map(([sortKey, groupStages]): NormalizedGroup => {
      groupStages.sort((left, right) =>
        compareUnlock(left.unlock_unix, right.unlock_unix),
      );
      const immediateCount = groupStages.filter(
        (stage) => stage.unlock_unix === null,
      ).length;
      if (immediateCount > 1) {
        throw new Error(
          "The same key set can have at most one immediate rule stage.",
        );
      }
      for (let index = 1; index < groupStages.length; index += 1) {
        const previous = groupStages[index - 1];
        const current = groupStages[index];
        if (previous.unlock_unix === current.unlock_unix) {
          throw new Error(
            "Rules for the same key set must use distinct unlock dates.",
          );
        }
        if (current.threshold >= previous.threshold) {
          throw new Error(
            "For the same key set, signature thresholds must strictly decrease as time advances.",
          );
        }
      }
      const publicKeys = groupStages[0].public_keys;
      return {
        sort_key: sortKey,
        key_ids: groupStages[0].key_ids,
        public_keys: publicKeys,
        stages: groupStages,
        miniscript_fragment: ladderFragment(publicKeys, groupStages),
      };
    });

  for (let leftIndex = 0; leftIndex < groups.length; leftIndex += 1) {
    const leftKeys = new Set(groups[leftIndex].public_keys);
    for (let rightIndex = leftIndex + 1; rightIndex < groups.length; rightIndex += 1) {
      const overlap = groups[rightIndex].public_keys.filter((key) =>
        leftKeys.has(key),
      );
      if (overlap.length > 0) {
        throw new Error(
          "Different key-set groups must be completely disjoint; partial key overlap cannot be compiled by this guarded template.",
        );
      }
    }
  }
  return groups;
}

function rightNestedOr(fragments: string[]): string {
  if (fragments.length === 1) return fragments[0];
  return `or_i(${fragments[0]},${rightNestedOr(fragments.slice(1))})`;
}

function sameStrings(left: string[], right: string[]): boolean {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

function exhaustivePolicyEquivalence(
  keys: GuardedKey[],
  rules: GuardedRuleDefinition[],
  miniscript: string,
): { ok: boolean; cases: number; satisfactions: number } {
  const symbolic = satisfier(miniscript, { maxSolutions: null });
  const knownKeys = new Set(keys.map((key) => key.public_key));
  const canonicalById = new Map(keys.map((key) => [key.id, key]));
  const satisfactions = [
    ...symbolic.nonMalleableSats,
    ...symbolic.malleableSats,
  ].map((solution) => {
    const signatureMatches = [
      ...solution.asm.matchAll(/<sig\(([^)]+)\)>/g),
    ];
    const signatureKeys = signatureMatches.map((match) => match[1]);
    const remainingTokens = solution.asm
      .replace(/<sig\([^)]+\)>/g, "")
      .trim()
      .split(/\s+/)
      .filter(Boolean);
    const locktime = solution.nLockTime;
    return {
      keys: new Set(signatureKeys),
      nLockTime: typeof locktime === "number" ? locktime : null,
      invalidLocktime:
        locktime !== undefined && typeof locktime !== "number",
      hasRelativeLock: solution.nSequence !== undefined,
      hasDuplicateSignature:
        new Set(signatureKeys).size !== signatureKeys.length,
      hasUnmodeledWitness: remainingTokens.some(
        (token) => token !== "0" && token !== "1",
      ),
    };
  });
  const satisfactionsAreBoundToPolicy =
    satisfactions.length > 0 &&
    satisfactions.every(
      (solution) =>
        !solution.invalidLocktime &&
        !solution.hasRelativeLock &&
        !solution.hasDuplicateSignature &&
        !solution.hasUnmodeledWitness &&
        solution.keys.size > 0 &&
        [...solution.keys].every((key) => knownKeys.has(key)),
    );

  const boundaries = new Set<number>();
  for (const rule of rules) {
    if (rule.unlock_unix !== null) boundaries.add(rule.unlock_unix);
  }
  for (const solution of satisfactions) {
    if (solution.nLockTime !== null) boundaries.add(solution.nLockTime);
  }
  const orderedBoundaries = [...boundaries].sort((left, right) => left - right);
  const times =
    orderedBoundaries.length === 0
      ? [MIN_TIMESTAMP_LOCK - 1]
      : [
          ...new Set(
            orderedBoundaries.flatMap((boundary) => [boundary - 1, boundary]),
          ),
        ].sort((left, right) => left - right);

  let cases = 0;
  for (let mask = 0; mask < 2 ** keys.length; mask += 1) {
    const availableKeys = new Set<string>();
    keys.forEach((key, index) => {
      if ((mask & (1 << index)) !== 0) availableKeys.add(key.public_key);
    });
    for (const time of times) {
      cases += 1;
      const intendedSatisfied = rules.some((rule) => {
        const signatures = rule.key_ids.reduce((count, id) => {
          const key = canonicalById.get(id);
          return count + (key && availableKeys.has(key.public_key) ? 1 : 0);
        }, 0);
        return (
          signatures >= rule.threshold &&
          (rule.unlock_unix === null || time >= rule.unlock_unix)
        );
      });
      const miniscriptSatisfied = satisfactions.some(
        (solution) =>
          [...solution.keys].every((key) => availableKeys.has(key)) &&
          (solution.nLockTime === null || solution.nLockTime <= time),
      );
      if (intendedSatisfied !== miniscriptSatisfied) {
        return { ok: false, cases, satisfactions: satisfactions.length };
      }
    }
  }
  return {
    ok: satisfactionsAreBoundToPolicy,
    cases,
    satisfactions: satisfactions.length,
  };
}

export function compileGuardedRulePolicy(
  request: GuardedRuleComposerRequest,
): CompiledGuardedRulePolicy {
  if (!request || typeof request !== "object") {
    throw new Error("Guarded rule request is required.");
  }
  if (
    request.format !== "mimir-guarded-rule-request" ||
    request.version !== 5
  ) {
    throw new Error("Unsupported guarded rule request format or version.");
  }
  if (request.template_id !== TEMPLATE_ID_GUARDED) {
    throw new Error("Unsupported guarded rule policy template.");
  }
  if (!Object.prototype.hasOwnProperty.call(NETWORKS, request.network)) {
    throw new Error("Unsupported Bitcoin network.");
  }

  const registry = normalizeKeys(request.keys);
  const normalizedGroups = normalizeGroups(request.rules, registry);
  const miniscript = rightNestedOr(
    normalizedGroups.map((group) => group.miniscript_fragment),
  );
  const compiled = compileMiniscript(miniscript);
  if (compiled.error || !compiled.issane || !compiled.issanesublevel) {
    throw new Error(
      `Miniscript compiler rejected the guarded policy: ${compiled.error ?? "not sane"}.`,
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

  let ruleNumber = 0;
  const policyGroups: GuardedPolicyGroup[] = normalizedGroups.map(
    (group, groupIndex) => {
      const groupId = `group-${String(groupIndex + 1).padStart(2, "0")}`;
      const stages = group.stages.map((stage): GuardedPolicyRule => {
        ruleNumber += 1;
        const unlock =
          stage.unlock_unix === null
            ? null
            : {
                unix: stage.unlock_unix,
                utc: utcFromUnix(stage.unlock_unix),
              };
        return {
          id: `rule-${String(ruleNumber).padStart(2, "0")}`,
          group_id: groupId,
          key_ids: stage.key_ids,
          public_keys: stage.public_keys,
          threshold: stage.threshold,
          unlock,
          summary:
            unlock === null
              ? `${stage.threshold} of ${stage.key_ids.length} selected signers can spend immediately.`
              : `${stage.threshold} of ${stage.key_ids.length} selected signers can spend from ${unlock.utc}.`,
        };
      });
      return {
        id: groupId,
        key_ids: group.key_ids,
        public_keys: group.public_keys,
        stages,
        miniscript_fragment: group.miniscript_fragment,
      };
    },
  );
  const policyRules = policyGroups.flatMap((group) => group.stages);
  const normalizedRules: GuardedRuleDefinition[] = policyRules.map((rule) => ({
    key_ids: rule.key_ids,
    threshold: rule.threshold,
    unlock_unix: rule.unlock?.unix ?? null,
  }));
  const normalizedRequest: GuardedRuleComposerRequest = {
    format: "mimir-guarded-rule-request",
    version: 5,
    network: request.network,
    template_id: TEMPLATE_ID_GUARDED,
    keys: registry.keys,
    rules: normalizedRules,
  };
  const manifest: GuardedRulePolicyManifest = {
    format: "mimir-guarded-rule-policy",
    version: 5,
    network: request.network,
    template_id: TEMPLATE_ID_GUARDED,
    keys: registry.keys,
    rules: policyRules,
    groups: policyGroups,
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
  const equivalence = exhaustivePolicyEquivalence(
    registry.keys,
    normalizedRules,
    miniscript,
  );
  const usedPublicKeys = new Set(
    policyGroups.flatMap((group) => group.public_keys),
  );
  const invariants: InvariantResult[] = [
    {
      id: "miniscript-sane",
      label: "Guarded policy Miniscript is sane at top level and sublevel",
      ok: compiled.issane && compiled.issanesublevel && !compiled.error,
    },
    {
      id: "five-by-five-limits",
      label: "Policy contains at most 5 registered keys and 5 authored rules",
      ok:
        registry.keys.length <= MAX_GUARDED_KEYS &&
        normalizedRules.length <= MAX_GUARDED_RULES,
    },
    {
      id: "canonical-key-order",
      label: "Registered keys, groups, and group keys use canonical public-key order",
      ok:
        sameStrings(
          registry.keys.map((key) => key.public_key),
          registry.keys.map((key) => key.public_key).sort(compareText),
        ) &&
        sameStrings(
          normalizedGroups.map((group) => group.sort_key),
          normalizedGroups.map((group) => group.sort_key).sort(compareText),
        ) &&
        normalizedGroups.every((group) =>
          sameStrings(
            group.public_keys,
            [...group.public_keys].sort(compareText),
          ),
        ),
    },
    {
      id: "disjoint-rule-groups",
      label: "Different rule groups use completely disjoint key sets",
      ok:
        new Set(normalizedGroups.flatMap((group) => group.public_keys)).size ===
        normalizedGroups.reduce(
          (count, group) => count + group.public_keys.length,
          0,
        ),
    },
    {
      id: "descending-group-ladders",
      label: "Grouped stages strictly decrease threshold as absolute dates increase",
      ok: normalizedGroups.every((group) =>
        group.stages.every(
          (stage, index) =>
            index === 0 ||
            (compareUnlock(
              group.stages[index - 1].unlock_unix,
              stage.unlock_unix,
            ) < 0 &&
              stage.threshold < group.stages[index - 1].threshold),
        ),
      ),
    },
    {
      id: "day-timelocks",
      label: "Every delayed rule uses an absolute 00:00:00 UTC day lock",
      ok: normalizedRules.every(
        (rule) =>
          rule.unlock_unix === null ||
          (rule.unlock_unix >= MIN_TIMESTAMP_LOCK &&
            rule.unlock_unix <= MAX_LOCKTIME &&
            rule.unlock_unix % SECONDS_PER_DAY === 0),
      ),
    },
    {
      id: "single-key-emission",
      label: "Each used public key appears exactly once in emitted Miniscript",
      ok:
        [...usedPublicKeys].every(
          (key) => miniscript.split(key).length - 1 === 1,
        ) &&
        registry.keys
          .filter((key) => !usedPublicKeys.has(key.public_key))
          .every((key) => !miniscript.includes(key.public_key)),
    },
    {
      id: "exhaustive-policy-equivalence",
      label: `Generated Miniscript satisfactions match every authored rule in all ${equivalence.cases} signer/time boundary cases (${equivalence.satisfactions} symbolic witnesses)`,
      ok: equivalence.ok,
    },
    {
      id: "descriptor-checksum",
      label: "Descriptor checksum covers the exact guarded policy",
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
      "An internal guarded-rule consistency invariant failed; output stopped.",
    );
  }

  const unusedKeys = registry.keys.filter(
    (key) => !usedPublicKeys.has(key.public_key),
  );
  const warnings = [
    "Each displayed rule is an alternative spending path; satisfying any one complete rule can spend the output.",
    "Later stages for the same key set make that set easier to satisfy; they never revoke an earlier stage.",
    "Calendar-date locks use Bitcoin median time past, so a delayed rule may become usable after the displayed UTC midnight.",
    "A delayed spend requires transaction nLockTime at least equal to its timestamp and a non-final nSequence on the input executing this witness script.",
    "Raw public keys define one fixed P2WSH address; there is no child-key derivation or address rotation.",
    "Independently reproduce and verify the descriptor, script, and address with Bitcoin Core before funding.",
  ];
  if (unusedKeys.length > 0) {
    warnings.unshift(
      `${unusedKeys.length} registered ${unusedKeys.length === 1 ? "key is" : "keys are"} not used by any spending rule: ${unusedKeys.map((key) => key.label).join(", ")}.`,
    );
  }
  if (request.network === "bitcoin") {
    warnings.push(
      "Mainnet output is preview-grade. Rehearse the exact policy on regtest or signet before use.",
    );
  }

  return {
    // Return independent JSON snapshots so mutating one view cannot silently
    // alter another view while the canonical bytes and hash remain fixed.
    request: cloneJson(normalizedRequest),
    manifest: cloneJson(manifest),
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
