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

export const TEMPLATE_ID_READ_ONCE = "mimir-read-once-normalizer-v1" as const;
export const MAX_READ_ONCE_KEYS = 5;
export const MAX_READ_ONCE_PATHS = 5;

export type ReadOnceNetwork = "bitcoin" | "testnet" | "signet" | "regtest";

export type ReadOnceKey = {
  id: string;
  label: string;
  public_key: string;
};

export type ReadOnceVisualPath = {
  key_ids: string[];
  threshold: number;
  unlock_unix: number | null;
};

export type ReadOncePolicyRequest = {
  format: "mimir-read-once-policy-request";
  version: 6;
  network: ReadOnceNetwork;
  template_id: typeof TEMPLATE_ID_READ_ONCE;
  keys: ReadOnceKey[];
  paths: ReadOnceVisualPath[];
};

export type ReadOncePolicyPath = {
  id: string;
  key_ids: string[];
  public_keys: string[];
  threshold: number;
  unlock: { unix: number; utc: string } | null;
  summary: string;
};

export type ReadOnceStage = {
  threshold: number;
  unlock: { unix: number; utc: string } | null;
};

export type ReadOnceNormalizationNode =
  | {
      type: "threshold_ladder";
      key_ids: string[];
      public_keys: string[];
      stages: ReadOnceStage[];
      miniscript_fragment: string;
    }
  | {
      type: "and" | "or";
      key_ids: string[];
      children: [ReadOnceNormalizationNode, ReadOnceNormalizationNode];
      miniscript_fragment: string;
    };

export type ReadOncePolicyManifest = {
  format: "mimir-read-once-policy";
  version: 6;
  network: ReadOnceNetwork;
  template_id: typeof TEMPLATE_ID_READ_ONCE;
  keys: ReadOnceKey[];
  authored_paths: ReadOncePolicyPath[];
  normalization: {
    changed: boolean;
    authored_key_occurrences: number;
    emitted_key_checks: number;
    eliminated_key_ids: string[];
    notes: string[];
    tree: ReadOnceNormalizationNode;
  };
  miniscript: string;
  descriptor: { body: string; checksummed: string };
  script: {
    asm: string;
    witness_script_hex: string;
    witness_script_bytes: number;
    witness_program_sha256: string;
    script_pubkey_hex: string;
  };
  address: string;
};

export type CompiledReadOncePolicy = {
  request: ReadOncePolicyRequest;
  manifest: ReadOncePolicyManifest;
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

const NETWORKS: Record<ReadOnceNetwork, { hrp: string }> = {
  bitcoin: { hrp: "bc" },
  testnet: { hrp: "tb" },
  signet: { hrp: "tb" },
  regtest: { hrp: "bcrt" },
};

const SECONDS_PER_DAY = 86_400;
const MAX_STANDARD_P2WSH_SCRIPT_BYTES = 3_600;
const MAX_SYNTHESIS_CANDIDATES = 8;

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

function normalizeText(value: unknown, field: string, maximumLength: number): string {
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

export function validateReadOncePublicKey(value: unknown): string {
  return validateCompressedPublicKey(value);
}

function validateTimestamp(
  value: unknown,
  field = "Path unlock",
): asserts value is number {
  if (!Number.isInteger(value)) {
    throw new Error(`${field} must be an integer Unix timestamp or null.`);
  }
  const timestamp = value as number;
  if (timestamp < MIN_TIMESTAMP_LOCK) {
    throw new Error(`${field} must be at least ${MIN_TIMESTAMP_LOCK}.`);
  }
  if (timestamp > MAX_LOCKTIME) {
    throw new Error(`${field} exceeds Miniscript after()'s 2038-01-19 limit.`);
  }
  if (timestamp % SECONDS_PER_DAY !== 0) {
    throw new Error(`${field} must use whole-day granularity at 00:00:00 UTC.`);
  }
}

export function unixFromReadOnceDate(value: string): number {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    throw new Error("Path date must use the exact YYYY-MM-DD format.");
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
    throw new Error("Path date is not a real calendar date.");
  }
  const unix = milliseconds / 1_000;
  validateTimestamp(unix, "Path date");
  return unix;
}

type NormalizedRegistry = {
  keys: ReadOnceKey[];
  canonicalByInputId: Map<string, ReadOnceKey>;
  indexByCanonicalId: Map<string, number>;
};

function normalizeKeys(value: unknown): NormalizedRegistry {
  if (!Array.isArray(value)) throw new Error("Keyring must be an array.");
  if (value.length === 0) throw new Error("Keyring cannot be empty.");
  if (value.length > MAX_READ_ONCE_KEYS) {
    throw new Error(`Keyring supports at most ${MAX_READ_ONCE_KEYS} keys.`);
  }

  const inputKeys = value.map((entry, index) => {
    if (!entry || typeof entry !== "object") {
      throw new Error(`Keyring entry ${index + 1} is invalid.`);
    }
    const candidate = entry as Partial<ReadOnceKey>;
    return {
      input_id: normalizeText(candidate.id, `Key ${index + 1} ID`, 64),
      label: normalizeText(candidate.label, `Key ${index + 1} label`, 80),
      public_key: validateReadOncePublicKey(candidate.public_key),
    };
  });

  const identities = [
    ["ID", (key: (typeof inputKeys)[number]) => key.input_id],
    ["label", (key: (typeof inputKeys)[number]) => key.label.toLocaleLowerCase("en-US")],
    ["public key", (key: (typeof inputKeys)[number]) => key.public_key],
  ] as const;
  for (const [name, select] of identities) {
    const seen = new Set<string>();
    for (const key of inputKeys) {
      const selected = select(key);
      if (seen.has(selected)) throw new Error(`Keyring contains a duplicate ${name}: ${selected}.`);
      seen.add(selected);
    }
  }

  inputKeys.sort((left, right) => compareText(left.public_key, right.public_key));
  const keys = inputKeys.map((key, index) => ({
    id: `key-${String(index + 1).padStart(2, "0")}`,
    label: key.label,
    public_key: key.public_key,
  }));
  const canonicalByInputId = new Map<string, ReadOnceKey>();
  const indexByCanonicalId = new Map<string, number>();
  inputKeys.forEach((key, index) => {
    canonicalByInputId.set(key.input_id, keys[index]);
    indexByCanonicalId.set(keys[index].id, index);
  });
  return { keys, canonicalByInputId, indexByCanonicalId };
}

type NormalizedPath = {
  key_ids: string[];
  public_keys: string[];
  key_indexes: number[];
  threshold: number;
  unlock_unix: number | null;
};

function compareUnlock(left: number | null, right: number | null): number {
  if (left === right) return 0;
  if (left === null) return -1;
  if (right === null) return 1;
  return left - right;
}

function normalizePaths(value: unknown, registry: NormalizedRegistry): NormalizedPath[] {
  if (!Array.isArray(value)) throw new Error("Visual paths must be an array.");
  if (value.length === 0) throw new Error("Add at least one spending path.");
  if (value.length > MAX_READ_ONCE_PATHS) {
    throw new Error(`A policy supports at most ${MAX_READ_ONCE_PATHS} visual paths.`);
  }

  const paths = value.map((entry, pathIndex): NormalizedPath => {
    if (!entry || typeof entry !== "object") {
      throw new Error(`Path ${pathIndex + 1} is invalid.`);
    }
    const candidate = entry as Partial<ReadOnceVisualPath>;
    if (!Array.isArray(candidate.key_ids) || candidate.key_ids.length === 0) {
      throw new Error(`Path ${pathIndex + 1} must contain at least one key.`);
    }
    if (candidate.key_ids.length > MAX_READ_ONCE_KEYS) {
      throw new Error(`Path ${pathIndex + 1} contains too many keys.`);
    }
    const selected = candidate.key_ids.map((rawId, keyIndex) => {
      const inputId = normalizeText(rawId, `Path ${pathIndex + 1} key ${keyIndex + 1} ID`, 64);
      const key = registry.canonicalByInputId.get(inputId);
      if (!key) throw new Error(`Path ${pathIndex + 1} references unknown key ID: ${inputId}.`);
      return key;
    });
    if (new Set(selected.map((key) => key.id)).size !== selected.length) {
      throw new Error(`Path ${pathIndex + 1} contains a duplicate key.`);
    }
    selected.sort((left, right) => compareText(left.public_key, right.public_key));
    if (!Number.isInteger(candidate.threshold)) {
      throw new Error(`Path ${pathIndex + 1} threshold must be an integer.`);
    }
    const threshold = candidate.threshold as number;
    if (threshold < 1 || threshold > selected.length) {
      throw new Error(`Path ${pathIndex + 1} threshold must be between 1 and ${selected.length}.`);
    }
    if (candidate.unlock_unix !== null) {
      validateTimestamp(candidate.unlock_unix, `Path ${pathIndex + 1} unlock`);
    }
    return {
      key_ids: selected.map((key) => key.id),
      public_keys: selected.map((key) => key.public_key),
      key_indexes: selected.map((key) => registry.indexByCanonicalId.get(key.id) as number),
      threshold,
      unlock_unix: candidate.unlock_unix,
    };
  });

  paths.sort((left, right) =>
    compareUnlock(left.unlock_unix, right.unlock_unix) ||
    compareText(left.public_keys.join(","), right.public_keys.join(",")) ||
    left.threshold - right.threshold,
  );
  return paths;
}

type TruthTable = {
  key_indexes: number[];
  values: boolean[];
  time_count: number;
};

function tableOffset(timeIndex: number, mask: number, keyCount: number): number {
  return timeIndex * 2 ** keyCount + mask;
}

function tableValue(table: TruthTable, timeIndex: number, mask: number): boolean {
  return table.values[tableOffset(timeIndex, mask, table.key_indexes.length)];
}

function tableBits(table: TruthTable): string {
  let bits = 0n;
  table.values.forEach((value, index) => {
    if (value) bits |= 1n << BigInt(index);
  });
  return `${table.key_indexes.join(",")}|${table.time_count}|${bits.toString(16)}`;
}

function popcount(value: number): number {
  let count = 0;
  let remaining = value;
  while (remaining) {
    count += remaining & 1;
    remaining >>>= 1;
  }
  return count;
}

function buildAuthoredTable(
  paths: NormalizedPath[],
  usedIndexes: number[],
  boundaries: number[],
): TruthTable {
  const positionByGlobal = new Map(usedIndexes.map((index, position) => [index, position]));
  const values: boolean[] = [];
  const stageTimes = boundaries.length === 0
    ? [MIN_TIMESTAMP_LOCK - 1]
    : [boundaries[0] - 1, ...boundaries];
  for (const time of stageTimes) {
    for (let mask = 0; mask < 2 ** usedIndexes.length; mask += 1) {
      values.push(paths.some((path) => {
        let signatures = 0;
        for (const globalIndex of path.key_indexes) {
          const position = positionByGlobal.get(globalIndex);
          if (position !== undefined && (mask & (1 << position)) !== 0) signatures += 1;
        }
        return signatures >= path.threshold &&
          (path.unlock_unix === null || time >= path.unlock_unix);
      }));
    }
  }
  return { key_indexes: usedIndexes, values, time_count: stageTimes.length };
}

function localMaskToParentMask(
  localMask: number,
  positions: number[],
): number {
  let parentMask = 0;
  positions.forEach((position, localPosition) => {
    if ((localMask & (1 << localPosition)) !== 0) parentMask |= 1 << position;
  });
  return parentMask;
}

function projectTable(
  table: TruthTable,
  positions: number[],
): TruthTable {
  const values: boolean[] = [];
  for (let timeIndex = 0; timeIndex < table.time_count; timeIndex += 1) {
    for (let mask = 0; mask < 2 ** positions.length; mask += 1) {
      values.push(tableValue(table, timeIndex, localMaskToParentMask(mask, positions)));
    }
  }
  return {
    key_indexes: positions.map((position) => table.key_indexes[position]),
    values,
    time_count: table.time_count,
  };
}

function removeIrrelevantKeys(table: TruthTable): TruthTable {
  let current = table;
  let changed = true;
  while (changed && current.key_indexes.length > 1) {
    changed = false;
    for (let position = 0; position < current.key_indexes.length; position += 1) {
      let relevant = false;
      for (let timeIndex = 0; timeIndex < current.time_count && !relevant; timeIndex += 1) {
        for (let mask = 0; mask < 2 ** current.key_indexes.length; mask += 1) {
          if ((mask & (1 << position)) !== 0) continue;
          if (tableValue(current, timeIndex, mask) !== tableValue(current, timeIndex, mask | (1 << position))) {
            relevant = true;
            break;
          }
        }
      }
      if (!relevant) {
        current = projectTable(
          current,
          current.key_indexes.map((_, index) => index).filter((index) => index !== position),
        );
        changed = true;
        break;
      }
    }
  }
  return current;
}

function splitPositions(length: number, leftMask: number): [number[], number[]] {
  const left: number[] = [];
  const right: number[] = [];
  for (let position = 0; position < length; position += 1) {
    (leftMask & (1 << position) ? left : right).push(position);
  }
  return [left, right];
}

function mergePartitionMasks(
  leftMask: number,
  leftPositions: number[],
  rightMask: number,
  rightPositions: number[],
): number {
  return localMaskToParentMask(leftMask, leftPositions) |
    localMaskToParentMask(rightMask, rightPositions);
}

function deriveOrDecomposition(
  table: TruthTable,
  leftPositions: number[],
  rightPositions: number[],
): [TruthTable, TruthTable] | null {
  const left = projectTable(table, leftPositions);
  const right = projectTable(table, rightPositions);
  for (let timeIndex = 0; timeIndex < table.time_count; timeIndex += 1) {
    for (let leftMask = 0; leftMask < 2 ** leftPositions.length; leftMask += 1) {
      for (let rightMask = 0; rightMask < 2 ** rightPositions.length; rightMask += 1) {
        const expected = tableValue(left, timeIndex, leftMask) || tableValue(right, timeIndex, rightMask);
        const actual = tableValue(
          table,
          timeIndex,
          mergePartitionMasks(leftMask, leftPositions, rightMask, rightPositions),
        );
        if (actual !== expected) return null;
      }
    }
  }
  return [left, right];
}

function existentialProjection(
  table: TruthTable,
  ownPositions: number[],
  otherPositions: number[],
): TruthTable {
  const values: boolean[] = [];
  for (let timeIndex = 0; timeIndex < table.time_count; timeIndex += 1) {
    for (let ownMask = 0; ownMask < 2 ** ownPositions.length; ownMask += 1) {
      let possible = false;
      for (let otherMask = 0; otherMask < 2 ** otherPositions.length; otherMask += 1) {
        const parentMask = localMaskToParentMask(ownMask, ownPositions) |
          localMaskToParentMask(otherMask, otherPositions);
        if (tableValue(table, timeIndex, parentMask)) {
          possible = true;
          break;
        }
      }
      values.push(possible);
    }
  }
  return {
    key_indexes: ownPositions.map((position) => table.key_indexes[position]),
    values,
    time_count: table.time_count,
  };
}

function deriveAndDecomposition(
  table: TruthTable,
  leftPositions: number[],
  rightPositions: number[],
): [TruthTable, TruthTable] | null {
  const left = existentialProjection(table, leftPositions, rightPositions);
  const right = existentialProjection(table, rightPositions, leftPositions);
  for (let timeIndex = 0; timeIndex < table.time_count; timeIndex += 1) {
    for (let leftMask = 0; leftMask < 2 ** leftPositions.length; leftMask += 1) {
      for (let rightMask = 0; rightMask < 2 ** rightPositions.length; rightMask += 1) {
        const expected = tableValue(left, timeIndex, leftMask) && tableValue(right, timeIndex, rightMask);
        const actual = tableValue(
          table,
          timeIndex,
          mergePartitionMasks(leftMask, leftPositions, rightMask, rightPositions),
        );
        if (actual !== expected) return null;
      }
    }
  }
  return [left, right];
}

type LadderStage = { threshold: number; unlock_unix: number | null };

type SynthesisNode =
  | { type: "threshold_ladder"; key_indexes: number[]; stages: LadderStage[]; fragment: string }
  | { type: "and" | "or"; key_indexes: number[]; children: [SynthesisNode, SynthesisNode]; fragment: string };

type Candidate = {
  fragment: string;
  node: SynthesisNode;
  cost: number;
};

function signingFragment(threshold: number, publicKeys: string[]): string {
  if (threshold === 1 && publicKeys.length === 1) return `pk(${publicKeys[0]})`;
  return `multi(${threshold},${publicKeys.join(",")})`;
}

function ladderFragment(publicKeys: string[], stages: LadderStage[]): string {
  const first = stages[0];
  if (stages.length === 1) {
    const signing = signingFragment(first.threshold, publicKeys);
    return first.unlock_unix === null
      ? signing
      : `and_v(v:after(${first.unlock_unix}),${signing})`;
  }
  const terms = [
    `pk(${publicKeys[0]})`,
    ...publicKeys.slice(1).map((publicKey) => `s:pk(${publicKey})`),
  ];
  for (let index = 1; index < stages.length; index += 1) {
    const drop = stages[index - 1].threshold - stages[index].threshold;
    for (let credit = 0; credit < drop; credit += 1) {
      terms.push(`sln:after(${stages[index].unlock_unix})`);
    }
  }
  const threshold = `thresh(${first.threshold},${terms.join(",")})`;
  return first.unlock_unix === null
    ? threshold
    : `and_v(v:after(${first.unlock_unix}),${threshold})`;
}

function candidateForFragment(fragment: string, node: SynthesisNode): Candidate | null {
  const compiled = compileMiniscript(fragment);
  if (compiled.error || !compiled.issane || !compiled.issanesublevel) return null;
  try {
    return { fragment, node, cost: asmToScript(compiled.asm).length };
  } catch {
    return null;
  }
}

function addCandidate(candidates: Candidate[], candidate: Candidate | null): void {
  if (!candidate || candidates.some((entry) => entry.fragment === candidate.fragment)) return;
  candidates.push(candidate);
  candidates.sort((left, right) => left.cost - right.cost || compareText(left.fragment, right.fragment));
  if (candidates.length > MAX_SYNTHESIS_CANDIDATES) candidates.length = MAX_SYNTHESIS_CANDIDATES;
}

function thresholdCandidate(
  table: TruthTable,
  boundaries: number[],
  keys: ReadOnceKey[],
): Candidate | null {
  const keyCount = table.key_indexes.length;
  const thresholds: number[] = [];
  for (let timeIndex = 0; timeIndex < table.time_count; timeIndex += 1) {
    let matched: number | null = null;
    for (let threshold = 1; threshold <= keyCount + 1; threshold += 1) {
      let exact = true;
      for (let mask = 0; mask < 2 ** keyCount; mask += 1) {
        if (tableValue(table, timeIndex, mask) !== (popcount(mask) >= threshold)) {
          exact = false;
          break;
        }
      }
      if (exact) {
        matched = threshold;
        break;
      }
    }
    if (matched === null) return null;
    thresholds.push(matched);
  }
  if (thresholds.every((threshold) => threshold === keyCount + 1)) return null;
  if (thresholds.some((threshold, index) => index > 0 && threshold > thresholds[index - 1])) {
    return null;
  }

  const stages: LadderStage[] = [];
  thresholds.forEach((threshold, timeIndex) => {
    if (threshold > keyCount) return;
    if (timeIndex === 0 || threshold < thresholds[timeIndex - 1]) {
      stages.push({
        threshold,
        unlock_unix: timeIndex === 0 ? null : boundaries[timeIndex - 1],
      });
    }
  });
  if (stages.length === 0) return null;
  const publicKeys = table.key_indexes.map((index) => keys[index].public_key);
  const fragment = ladderFragment(publicKeys, stages);
  return candidateForFragment(fragment, {
    type: "threshold_ladder",
    key_indexes: table.key_indexes,
    stages,
    fragment,
  });
}

function synthesizeReadOnce(
  source: TruthTable,
  boundaries: number[],
  keys: ReadOnceKey[],
  memo = new Map<string, Candidate[]>(),
): Candidate[] {
  const table = removeIrrelevantKeys(source);
  const memoKey = tableBits(table);
  const existing = memo.get(memoKey);
  if (existing) return existing;
  const candidates: Candidate[] = [];
  memo.set(memoKey, candidates);
  addCandidate(candidates, thresholdCandidate(table, boundaries, keys));

  const keyCount = table.key_indexes.length;
  const fullMask = 2 ** keyCount - 1;
  for (let leftMask = 1; leftMask < fullMask; leftMask += 1) {
    if ((leftMask & 1) === 0) continue;
    const [leftPositions, rightPositions] = splitPositions(keyCount, leftMask);
    for (const [type, decomposition] of [
      ["or", deriveOrDecomposition(table, leftPositions, rightPositions)],
      ["and", deriveAndDecomposition(table, leftPositions, rightPositions)],
    ] as const) {
      if (!decomposition) continue;
      const leftCandidates = synthesizeReadOnce(decomposition[0], boundaries, keys, memo);
      const rightCandidates = synthesizeReadOnce(decomposition[1], boundaries, keys, memo);
      for (const left of leftCandidates) {
        for (const right of rightCandidates) {
          if (type === "or") {
            const ordered = [left, right].sort((a, b) => compareText(a.fragment, b.fragment));
            const fragment = `or_i(${ordered[0].fragment},${ordered[1].fragment})`;
            addCandidate(candidates, candidateForFragment(fragment, {
              type: "or",
              key_indexes: [...ordered[0].node.key_indexes, ...ordered[1].node.key_indexes].sort((a, b) => a - b),
              children: [ordered[0].node, ordered[1].node],
              fragment,
            }));
          } else {
            for (const [verifySide, otherSide] of [[left, right], [right, left]] as const) {
              const fragment = `and_v(v:${verifySide.fragment},${otherSide.fragment})`;
              addCandidate(candidates, candidateForFragment(fragment, {
                type: "and",
                key_indexes: [...verifySide.node.key_indexes, ...otherSide.node.key_indexes].sort((a, b) => a - b),
                children: [verifySide.node, otherSide.node],
                fragment,
              }));
            }
          }
        }
      }
    }
  }
  return candidates;
}

function toManifestNode(node: SynthesisNode, keys: ReadOnceKey[]): ReadOnceNormalizationNode {
  if (node.type === "threshold_ladder") {
    return {
      type: node.type,
      key_ids: node.key_indexes.map((index) => keys[index].id),
      public_keys: node.key_indexes.map((index) => keys[index].public_key),
      stages: node.stages.map((stage) => ({
        threshold: stage.threshold,
        unlock: stage.unlock_unix === null
          ? null
          : { unix: stage.unlock_unix, utc: utcFromUnix(stage.unlock_unix) },
      })),
      miniscript_fragment: node.fragment,
    };
  }
  return {
    type: node.type,
    key_ids: node.key_indexes.map((index) => keys[index].id),
    children: [toManifestNode(node.children[0], keys), toManifestNode(node.children[1], keys)],
    miniscript_fragment: node.fragment,
  };
}

function collectLadders(node: SynthesisNode): Extract<SynthesisNode, { type: "threshold_ladder" }>[] {
  if (node.type === "threshold_ladder") return [node];
  return [...collectLadders(node.children[0]), ...collectLadders(node.children[1])];
}

function nodeSatisfied(node: SynthesisNode, available: Set<number>, time: number): boolean {
  if (node.type === "threshold_ladder") {
    const signatures = node.key_indexes.filter((index) => available.has(index)).length;
    return node.stages.some((stage) =>
      signatures >= stage.threshold &&
      (stage.unlock_unix === null || time >= stage.unlock_unix),
    );
  }
  const left = nodeSatisfied(node.children[0], available, time);
  const right = nodeSatisfied(node.children[1], available, time);
  return node.type === "and" ? left && right : left || right;
}

function normalizationEquivalence(
  node: SynthesisNode,
  authored: TruthTable,
  boundaries: number[],
): { ok: boolean; cases: number } {
  const times = boundaries.length === 0
    ? [MIN_TIMESTAMP_LOCK - 1]
    : [boundaries[0] - 1, ...boundaries];
  let cases = 0;
  for (let timeIndex = 0; timeIndex < authored.time_count; timeIndex += 1) {
    for (let mask = 0; mask < 2 ** authored.key_indexes.length; mask += 1) {
      cases += 1;
      const available = new Set<number>();
      authored.key_indexes.forEach((keyIndex, position) => {
        if ((mask & (1 << position)) !== 0) available.add(keyIndex);
      });
      if (
        tableValue(authored, timeIndex, mask) !==
        nodeSatisfied(node, available, times[timeIndex])
      ) {
        return { ok: false, cases };
      }
    }
  }
  return { ok: true, cases };
}

function sameStrings(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function symbolicPolicyEquivalence(
  keys: ReadOnceKey[],
  paths: NormalizedPath[],
  miniscript: string,
): { ok: boolean; cases: number; satisfactions: number } {
  const symbolic = satisfier(miniscript, { maxSolutions: null });
  const knownKeys = new Set(keys.map((key) => key.public_key));
  const satisfactions = [...symbolic.nonMalleableSats, ...symbolic.malleableSats].map((solution) => {
    const signatureKeys = [...solution.asm.matchAll(/<sig\(([^)]+)\)>/g)].map((match) => match[1]);
    const remainingTokens = solution.asm
      .replace(/<sig\([^)]+\)>/g, "")
      .trim()
      .split(/\s+/)
      .filter(Boolean);
    return {
      keys: new Set(signatureKeys),
      nLockTime: typeof solution.nLockTime === "number" ? solution.nLockTime : null,
      invalidLocktime: solution.nLockTime !== undefined && typeof solution.nLockTime !== "number",
      hasRelativeLock: solution.nSequence !== undefined,
      hasDuplicateSignature: new Set(signatureKeys).size !== signatureKeys.length,
      hasUnmodeledWitness: remainingTokens.some((token) => token !== "0" && token !== "1"),
    };
  });
  const bound = satisfactions.length > 0 && satisfactions.every((solution) =>
    !solution.invalidLocktime &&
    !solution.hasRelativeLock &&
    !solution.hasDuplicateSignature &&
    !solution.hasUnmodeledWitness &&
    solution.keys.size > 0 &&
    [...solution.keys].every((key) => knownKeys.has(key)),
  );

  const boundaries = new Set<number>();
  paths.forEach((path) => {
    if (path.unlock_unix !== null) boundaries.add(path.unlock_unix);
  });
  satisfactions.forEach((solution) => {
    if (solution.nLockTime !== null) boundaries.add(solution.nLockTime);
  });
  const ordered = [...boundaries].sort((left, right) => left - right);
  const times = ordered.length === 0
    ? [MIN_TIMESTAMP_LOCK - 1]
    : [...new Set(ordered.flatMap((boundary) => [boundary - 1, boundary]))].sort((a, b) => a - b);
  let cases = 0;
  for (let mask = 0; mask < 2 ** keys.length; mask += 1) {
    const available = new Set<string>();
    keys.forEach((key, index) => {
      if ((mask & (1 << index)) !== 0) available.add(key.public_key);
    });
    for (const time of times) {
      cases += 1;
      const authored = paths.some((path) =>
        path.public_keys.filter((key) => available.has(key)).length >= path.threshold &&
        (path.unlock_unix === null || time >= path.unlock_unix),
      );
      const emitted = satisfactions.some((solution) =>
        [...solution.keys].every((key) => available.has(key)) &&
        (solution.nLockTime === null || solution.nLockTime <= time),
      );
      if (authored !== emitted) return { ok: false, cases, satisfactions: satisfactions.length };
    }
  }
  return { ok: bound, cases, satisfactions: satisfactions.length };
}

function authoredPath(path: NormalizedPath, index: number): ReadOncePolicyPath {
  const unlock = path.unlock_unix === null
    ? null
    : { unix: path.unlock_unix, utc: utcFromUnix(path.unlock_unix) };
  return {
    id: `path-${String(index + 1).padStart(2, "0")}`,
    key_ids: path.key_ids,
    public_keys: path.public_keys,
    threshold: path.threshold,
    unlock,
    summary: unlock === null
      ? `${path.threshold} of ${path.key_ids.length} selected signers can spend immediately.`
      : `${path.threshold} of ${path.key_ids.length} selected signers can spend from ${unlock.utc}.`,
  };
}

export function compileReadOncePolicy(request: ReadOncePolicyRequest): CompiledReadOncePolicy {
  if (!request || typeof request !== "object") throw new Error("Read-once policy request is required.");
  if (request.format !== "mimir-read-once-policy-request" || request.version !== 6) {
    throw new Error("Unsupported read-once policy request format or version.");
  }
  if (request.template_id !== TEMPLATE_ID_READ_ONCE) {
    throw new Error("Unsupported read-once policy template.");
  }
  if (!Object.prototype.hasOwnProperty.call(NETWORKS, request.network)) {
    throw new Error("Unsupported Bitcoin network.");
  }

  const registry = normalizeKeys(request.keys);
  const paths = normalizePaths(request.paths, registry);
  const boundaries = [...new Set(paths.flatMap((path) =>
    path.unlock_unix === null ? [] : [path.unlock_unix],
  ))].sort((left, right) => left - right);
  const usedIndexes = [...new Set(paths.flatMap((path) => path.key_indexes))].sort((a, b) => a - b);
  const authoredTable = buildAuthoredTable(paths, usedIndexes, boundaries);
  const reducedTable = removeIrrelevantKeys(authoredTable);
  const candidates = synthesizeReadOnce(reducedTable, boundaries, registry.keys);
  if (candidates.length === 0) {
    throw new Error(
      "These visual paths cannot be simplified into Mimir's sane read-once Miniscript grammar. Remove one overlapping path, change its signer set, or use a distinct public key.",
    );
  }
  const chosen = candidates[0];
  const miniscript = chosen.fragment;
  const compiled = compileMiniscript(miniscript);
  if (compiled.error || !compiled.issane || !compiled.issanesublevel) {
    throw new Error(`Miniscript rejected the normalized policy: ${compiled.error ?? "not sane"}.`);
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
  const address = bech32.encode(network.hrp, [0, ...bech32.toWords(witnessProgram)]);
  const descriptorBody = `wsh(${miniscript})`;
  const descriptor = addDescriptorChecksum(descriptorBody);
  const normalizedRequest: ReadOncePolicyRequest = {
    format: "mimir-read-once-policy-request",
    version: 6,
    network: request.network,
    template_id: TEMPLATE_ID_READ_ONCE,
    keys: registry.keys,
    paths: paths.map((path) => ({
      key_ids: path.key_ids,
      threshold: path.threshold,
      unlock_unix: path.unlock_unix,
    })),
  };
  const authoredPaths = paths.map(authoredPath);
  const authoredOccurrences = paths.reduce((count, path) => count + path.key_ids.length, 0);
  const emittedIndexes = [...new Set(chosen.node.key_indexes)].sort((a, b) => a - b);
  const emittedKeyChecks = registry.keys.reduce(
    (count, key) => count + (miniscript.split(key.public_key).length - 1),
    0,
  );
  const eliminatedKeyIds = usedIndexes
    .filter((index) => !emittedIndexes.includes(index))
    .map((index) => registry.keys[index].id);
  const repeatedLabels = registry.keys
    .filter((key) => paths.filter((path) => path.key_ids.includes(key.id)).length > 1)
    .map((key) => key.label);
  const ladders = collectLadders(chosen.node);
  const normalizedStageCount = ladders.reduce((count, ladder) => count + ladder.stages.length, 0);
  const changed = authoredOccurrences !== emittedKeyChecks ||
    eliminatedKeyIds.length > 0 ||
    repeatedLabels.length > 0 ||
    normalizedStageCount !== paths.length;
  const notes = changed
    ? [
        `Normalized ${paths.length} visual ${paths.length === 1 ? "path" : "paths"} into ${normalizedStageCount} read-once threshold ${normalizedStageCount === 1 ? "stage" : "stages"} across ${ladders.length} leaf ${ladders.length === 1 ? "group" : "groups"}.`,
        repeatedLabels.length > 0
          ? `Factored repeated visual key use for: ${repeatedLabels.join(", ")}.`
          : "Removed redundant visual conditions without repeating a public key.",
        "Every emitted public key check occurs at most once.",
      ]
    : ["The visual policy was already read-once; no key factoring was required."];

  const manifest: ReadOncePolicyManifest = {
    format: "mimir-read-once-policy",
    version: 6,
    network: request.network,
    template_id: TEMPLATE_ID_READ_ONCE,
    keys: registry.keys,
    authored_paths: authoredPaths,
    normalization: {
      changed,
      authored_key_occurrences: authoredOccurrences,
      emitted_key_checks: emittedKeyChecks,
      eliminated_key_ids: eliminatedKeyIds,
      notes,
      tree: toManifestNode(chosen.node, registry.keys),
    },
    miniscript,
    descriptor: { body: descriptorBody, checksummed: descriptor },
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
  const normalizedEquivalence = normalizationEquivalence(chosen.node, authoredTable, boundaries);
  const equivalence = symbolicPolicyEquivalence(registry.keys, paths, miniscript);
  const invariants: InvariantResult[] = [
    {
      id: "miniscript-sane",
      label: "Normalized Miniscript is sane at top level and sublevel",
      ok: !compiled.error && compiled.issane && compiled.issanesublevel,
    },
    {
      id: "read-once-public-keys",
      label: "Every public key occurs at most once in emitted Miniscript",
      ok: registry.keys.every((key) => miniscript.split(key.public_key).length - 1 <= 1) && emittedKeyChecks > 0,
    },
    {
      id: "normalization-equivalence",
      label: `Visual policy and normalized read-once tree agree in all ${normalizedEquivalence.cases} signer/time-stage cases`,
      ok: normalizedEquivalence.ok,
    },
    {
      id: "symbolic-policy-equivalence",
      label: `Actual Miniscript satisfactions match the visual policy in all ${equivalence.cases} signer/time-boundary cases (${equivalence.satisfactions} symbolic witnesses)`,
      ok: equivalence.ok,
    },
    {
      id: "five-by-five-limits",
      label: "Policy contains at most 5 registered keys and 5 visual paths",
      ok: registry.keys.length <= MAX_READ_ONCE_KEYS && paths.length <= MAX_READ_ONCE_PATHS,
    },
    {
      id: "canonical-key-order",
      label: "Registered keys use canonical public-key order",
      ok: sameStrings(
        registry.keys.map((key) => key.public_key),
        registry.keys.map((key) => key.public_key).sort(compareText),
      ),
    },
    {
      id: "day-timelocks",
      label: "Every delayed visual path uses an absolute 00:00:00 UTC day lock",
      ok: paths.every((path) => path.unlock_unix === null ||
        (path.unlock_unix >= MIN_TIMESTAMP_LOCK && path.unlock_unix <= MAX_LOCKTIME && path.unlock_unix % SECONDS_PER_DAY === 0)),
    },
    {
      id: "descriptor-checksum",
      label: "Descriptor checksum covers the exact normalized policy",
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
      ok: bech32.encode(network.hrp, [0, ...bech32.toWords(witnessProgram)]) === address,
    },
    {
      id: "standard-script-size",
      label: "Witness script is within the 3,600-byte P2WSH standardness limit",
      ok: witnessScript.length <= MAX_STANDARD_P2WSH_SCRIPT_BYTES,
    },
    {
      id: "canonical-manifest-hash",
      label: "Canonical manifest hash is reproducible",
      ok: policyManifestSha256 === sha256Hex(canonicalizeJson(JSON.parse(canonicalManifest))),
    },
  ];
  if (invariants.some((invariant) => !invariant.ok)) {
    throw new Error("An internal read-once normalization invariant failed; output stopped.");
  }

  const unusedKeys = registry.keys.filter((_, index) => !usedIndexes.includes(index));
  const warnings = [
    "Each visual path is an alternative way to spend; satisfying any one complete path can spend the output.",
    "Repeated visual keys are accepted only when normalization eliminates every repeated public-key check.",
    "Calendar-date locks use Bitcoin median time past, so a delayed path may become usable after the displayed UTC midnight.",
    "A delayed spend requires transaction nLockTime at least equal to its timestamp and a non-final nSequence on the input executing this witness script.",
    "Raw public keys define one fixed P2WSH address; there is no child-key derivation or address rotation.",
    "Independently reproduce and verify the descriptor, script, address, and normalization before funding.",
  ];
  if (eliminatedKeyIds.length > 0) {
    warnings.unshift(
      `Normalization removed semantically redundant key checks for: ${eliminatedKeyIds.map((id) => registry.keys.find((key) => key.id === id)?.label ?? id).join(", ")}.`,
    );
  }
  if (unusedKeys.length > 0) {
    warnings.unshift(
      `${unusedKeys.length} registered ${unusedKeys.length === 1 ? "key is" : "keys are"} unused by the visual policy: ${unusedKeys.map((key) => key.label).join(", ")}.`,
    );
  }
  if (request.network === "bitcoin") {
    warnings.push("Mainnet output is preview-grade. Rehearse the exact policy on Regtest or Signet before use.");
  }

  return {
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
