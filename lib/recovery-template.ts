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

export const TEMPLATE_ID_RECOVERY = "mimir-recovery-5x5-v1" as const;
export const MAX_RECOVERY_TEMPLATE_SIGNERS = 5;
export const MAX_RECOVERY_TEMPLATE_PATHS = 5;

export type RecoveryNetwork = "bitcoin" | "signet" | "regtest";
export type RecoverySignerGroup = "primary" | "recovery";

export type RecoverySigner = {
  id: string;
  label: string;
  public_key: string;
  group: RecoverySignerGroup;
};

export type RecoveryTemplateRequest = {
  format: "mimir-recovery-request";
  version: 4;
  network: RecoveryNetwork;
  template_id: typeof TEMPLATE_ID_RECOVERY;
  signers: RecoverySigner[];
  primary_threshold: number;
  recovery_dates: number[];
};

export type RecoveryPolicyPath = {
  id: string;
  kind: RecoverySignerGroup;
  key_ids: string[];
  public_keys: string[];
  threshold: number;
  unlock: { unix: number; utc: string } | null;
  summary: string;
};

export type RecoveryPolicyManifest = {
  format: "mimir-recovery-policy";
  version: 4;
  network: RecoveryNetwork;
  template_id: typeof TEMPLATE_ID_RECOVERY;
  signers: RecoverySigner[];
  primary: {
    key_ids: string[];
    public_keys: string[];
    threshold: number;
    miniscript_fragment: string;
  };
  recovery: {
    key_ids: string[];
    public_keys: string[];
    stages: Array<{
      id: string;
      threshold: number;
      unlock: { unix: number; utc: string };
    }>;
    miniscript_fragment: string;
  };
  logical_paths: RecoveryPolicyPath[];
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

export type CompiledRecoveryTemplate = {
  request: RecoveryTemplateRequest;
  manifest: RecoveryPolicyManifest;
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

const NETWORKS: Record<RecoveryNetwork, { hrp: string }> = {
  bitcoin: { hrp: "bc" },
  signet: { hrp: "tb" },
  regtest: { hrp: "bcrt" },
};

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

export function validateRecoveryPublicKey(value: unknown): string {
  return validateCompressedPublicKey(value);
}

function validateRecoveryTimestamp(
  value: unknown,
  field = "Recovery date",
): asserts value is number {
  if (!Number.isInteger(value)) {
    throw new Error(`${field} must be an integer Unix timestamp.`);
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

export function unixFromRecoveryDate(value: string): number {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    throw new Error("Recovery date must use the exact YYYY-MM-DD format.");
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
    throw new Error("Recovery date is not a real calendar date.");
  }
  const unix = milliseconds / 1_000;
  validateRecoveryTimestamp(unix);
  return unix;
}

type NormalizedSigners = {
  signers: RecoverySigner[];
  primary: RecoverySigner[];
  recovery: RecoverySigner[];
};

function normalizeSigners(value: unknown): NormalizedSigners {
  if (!Array.isArray(value)) throw new Error("Signers must be an array.");
  if (value.length < 2 || value.length > MAX_RECOVERY_TEMPLATE_SIGNERS) {
    throw new Error(
      `The 5×5 template requires between 2 and ${MAX_RECOVERY_TEMPLATE_SIGNERS} signers.`,
    );
  }

  const inputSigners = value.map((entry, index) => {
    if (!entry || typeof entry !== "object") {
      throw new Error(`Signer ${index + 1} is invalid.`);
    }
    const candidate = entry as Partial<RecoverySigner>;
    if (candidate.group !== "primary" && candidate.group !== "recovery") {
      throw new Error(`Signer ${index + 1} must belong to primary or recovery.`);
    }
    return {
      input_id: normalizeText(candidate.id, `Signer ${index + 1} ID`, 64),
      label: normalizeText(candidate.label, `Signer ${index + 1} label`, 80),
      public_key: validateRecoveryPublicKey(candidate.public_key),
      group: candidate.group,
    };
  });

  const uniqueFields = [
    ["ID", (signer: (typeof inputSigners)[number]) => signer.input_id],
    [
      "label",
      (signer: (typeof inputSigners)[number]) =>
        signer.label.toLocaleLowerCase("en-US"),
    ],
    [
      "public key",
      (signer: (typeof inputSigners)[number]) => signer.public_key,
    ],
  ] as const;
  for (const [field, select] of uniqueFields) {
    const seen = new Set<string>();
    for (const signer of inputSigners) {
      const selected = select(signer);
      if (seen.has(selected)) {
        throw new Error(`Signers contain a duplicate ${field}: ${selected}.`);
      }
      seen.add(selected);
    }
  }

  inputSigners.sort((left, right) =>
    compareText(left.public_key, right.public_key),
  );
  const signers: RecoverySigner[] = inputSigners.map((signer, index) => ({
    id: `key-${String(index + 1).padStart(2, "0")}`,
    label: signer.label,
    public_key: signer.public_key,
    group: signer.group,
  }));
  const primary = signers.filter((signer) => signer.group === "primary");
  const recovery = signers.filter((signer) => signer.group === "recovery");
  if (primary.length === 0 || recovery.length === 0) {
    throw new Error(
      "The 5×5 template requires at least one primary signer and one recovery signer.",
    );
  }
  return { signers, primary, recovery };
}

function normalizeRecoveryDates(value: unknown, recoveryCount: number): number[] {
  if (!Array.isArray(value)) {
    throw new Error("Recovery dates must be an array.");
  }
  if (value.length !== recoveryCount) {
    throw new Error(
      `The ${recoveryCount}-signer recovery group requires exactly ${recoveryCount} staged recovery dates.`,
    );
  }
  const dates = value.map((timestamp, index) => {
    validateRecoveryTimestamp(timestamp, `Recovery stage ${index + 1} date`);
    return timestamp;
  });
  for (let index = 1; index < dates.length; index += 1) {
    if (dates[index] <= dates[index - 1]) {
      throw new Error("Recovery dates must be strictly increasing.");
    }
  }
  return dates;
}

function signingFragment(threshold: number, publicKeys: string[]): string {
  if (threshold === 1 && publicKeys.length === 1) {
    return `pk(${publicKeys[0]})`;
  }
  return `multi(${threshold},${publicKeys.join(",")})`;
}

function recoveryFragment(publicKeys: string[], dates: number[]): string {
  if (publicKeys.length === 1) {
    return `and_v(v:after(${dates[0]}),pk(${publicKeys[0]}))`;
  }
  const thresholdTerms = [
    `pk(${publicKeys[0]})`,
    ...publicKeys.slice(1).map((publicKey) => `s:pk(${publicKey})`),
    ...dates.slice(1).map((timestamp) => `sln:after(${timestamp})`),
  ];
  return `and_v(v:after(${dates[0]}),thresh(${publicKeys.length},${thresholdTerms.join(",")}))`;
}

function sameStrings(left: string[], right: string[]): boolean {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

function exhaustivePolicyEquivalence(
  signers: RecoverySigner[],
  primaryThreshold: number,
  recoveryCount: number,
  recoveryDates: number[],
  miniscript: string,
): { ok: boolean; cases: number; satisfactions: number } {
  const symbolic = satisfier(miniscript, { maxSolutions: null });
  const satisfactions = [
    ...symbolic.nonMalleableSats,
    ...symbolic.malleableSats,
  ].map((solution) => {
    const signatureMatches = [
      ...solution.asm.matchAll(/<sig\(([^)]+)\)>/g),
    ];
    return {
      keys: new Set(signatureMatches.map((match) => match[1])),
      nLockTime: solution.nLockTime ?? null,
      hasRelativeLock: solution.nSequence !== undefined,
      hasDuplicateSignature:
        new Set(signatureMatches.map((match) => match[1])).size !==
        signatureMatches.length,
      hasUnmodeledWitness:
        /<[^>]+>/.test(solution.asm.replace(/<sig\([^)]+\)>/g, "")),
    };
  });
  const knownKeys = new Set(signers.map((signer) => signer.public_key));
  const satisfactionsAreBoundToTemplate =
    satisfactions.length > 0 &&
    satisfactions.every(
      (solution) =>
        !solution.hasRelativeLock &&
        !solution.hasDuplicateSignature &&
        !solution.hasUnmodeledWitness &&
        solution.keys.size > 0 &&
        [...solution.keys].every((key) => knownKeys.has(key)),
    );
  const boundaries = new Set(recoveryDates);
  for (const solution of satisfactions) {
    if (solution.nLockTime !== null) boundaries.add(solution.nLockTime);
  }
  const orderedBoundaries = [...boundaries].sort((left, right) => left - right);
  const times = [
    ...new Set(
      orderedBoundaries.flatMap((boundary) => [boundary - 1, boundary]),
    ),
  ].sort((left, right) => left - right);
  let cases = 0;
  for (let mask = 0; mask < 2 ** signers.length; mask += 1) {
    let primarySignatures = 0;
    let recoverySignatures = 0;
    const availableKeys = new Set<string>();
    signers.forEach((signer, index) => {
      if ((mask & (1 << index)) === 0) return;
      availableKeys.add(signer.public_key);
      if (signer.group === "primary") primarySignatures += 1;
      else recoverySignatures += 1;
    });

    for (const time of times) {
      cases += 1;
      const primarySatisfied = primarySignatures >= primaryThreshold;
      const intendedRecoverySatisfied = recoveryDates.some(
        (unlock, index) =>
          time >= unlock && recoverySignatures >= recoveryCount - index,
      );
      const intendedSatisfied =
        primarySatisfied || intendedRecoverySatisfied;
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
    ok: satisfactionsAreBoundToTemplate,
    cases,
    satisfactions: satisfactions.length,
  };
}

export function compileRecoveryTemplate(
  request: RecoveryTemplateRequest,
): CompiledRecoveryTemplate {
  if (!request || typeof request !== "object") {
    throw new Error("Recovery template request is required.");
  }
  if (request.format !== "mimir-recovery-request" || request.version !== 4) {
    throw new Error("Unsupported recovery template request format or version.");
  }
  if (request.template_id !== TEMPLATE_ID_RECOVERY) {
    throw new Error("Unsupported recovery policy template.");
  }
  if (!Object.prototype.hasOwnProperty.call(NETWORKS, request.network)) {
    throw new Error("Unsupported Bitcoin network.");
  }

  const registry = normalizeSigners(request.signers);
  if (!Number.isInteger(request.primary_threshold)) {
    throw new Error("Primary threshold must be an integer.");
  }
  if (
    request.primary_threshold < 1 ||
    request.primary_threshold > registry.primary.length
  ) {
    throw new Error(
      `Primary threshold must be between 1 and the ${registry.primary.length}-signer primary group size.`,
    );
  }
  const recoveryDates = normalizeRecoveryDates(
    request.recovery_dates,
    registry.recovery.length,
  );

  const primaryPublicKeys = registry.primary.map((signer) => signer.public_key);
  const recoveryPublicKeys = registry.recovery.map(
    (signer) => signer.public_key,
  );
  const primaryMiniscript = signingFragment(
    request.primary_threshold,
    primaryPublicKeys,
  );
  const recoveryMiniscript = recoveryFragment(
    recoveryPublicKeys,
    recoveryDates,
  );
  const miniscript = `or_i(${primaryMiniscript},${recoveryMiniscript})`;

  const compiled = compileMiniscript(miniscript);
  if (compiled.error || !compiled.issane || !compiled.issanesublevel) {
    throw new Error(
      `Miniscript compiler rejected the 5×5 recovery policy: ${compiled.error ?? "not sane"}.`,
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

  const normalizedRequest: RecoveryTemplateRequest = {
    format: "mimir-recovery-request",
    version: 4,
    network: request.network,
    template_id: TEMPLATE_ID_RECOVERY,
    signers: registry.signers,
    primary_threshold: request.primary_threshold,
    recovery_dates: recoveryDates,
  };
  const primaryPath: RecoveryPolicyPath = {
    id: "path-01",
    kind: "primary",
    key_ids: registry.primary.map((signer) => signer.id),
    public_keys: primaryPublicKeys,
    threshold: request.primary_threshold,
    unlock: null,
    summary: `${request.primary_threshold} of ${registry.primary.length} primary signers can spend immediately.`,
  };
  const recoveryStages = recoveryDates.map((unlock, index) => ({
    id: `stage-${String(index + 1).padStart(2, "0")}`,
    threshold: registry.recovery.length - index,
    unlock: { unix: unlock, utc: utcFromUnix(unlock) },
  }));
  const recoveryPaths: RecoveryPolicyPath[] = recoveryStages.map(
    (stage, index) => ({
      id: `path-${String(index + 2).padStart(2, "0")}`,
      kind: "recovery",
      key_ids: registry.recovery.map((signer) => signer.id),
      public_keys: recoveryPublicKeys,
      threshold: stage.threshold,
      unlock: stage.unlock,
      summary: `${stage.threshold} of ${registry.recovery.length} recovery signers can spend from ${stage.unlock.utc}.`,
    }),
  );
  const manifest: RecoveryPolicyManifest = {
    format: "mimir-recovery-policy",
    version: 4,
    network: request.network,
    template_id: TEMPLATE_ID_RECOVERY,
    signers: registry.signers,
    primary: {
      key_ids: registry.primary.map((signer) => signer.id),
      public_keys: primaryPublicKeys,
      threshold: request.primary_threshold,
      miniscript_fragment: primaryMiniscript,
    },
    recovery: {
      key_ids: registry.recovery.map((signer) => signer.id),
      public_keys: recoveryPublicKeys,
      stages: recoveryStages,
      miniscript_fragment: recoveryMiniscript,
    },
    logical_paths: [primaryPath, ...recoveryPaths],
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
    registry.signers,
    request.primary_threshold,
    registry.recovery.length,
    recoveryDates,
    miniscript,
  );
  const invariants: InvariantResult[] = [
    {
      id: "miniscript-sane",
      label: "Template Miniscript is sane at top level and sublevel",
      ok: compiled.issane && compiled.issanesublevel && !compiled.error,
    },
    {
      id: "five-by-five-limits",
      label: "Template contains at most 5 signers and 5 logical paths",
      ok:
        registry.signers.length <= MAX_RECOVERY_TEMPLATE_SIGNERS &&
        manifest.logical_paths.length <= MAX_RECOVERY_TEMPLATE_PATHS,
    },
    {
      id: "canonical-key-order",
      label: "Signers and both functional groups use lexicographic public-key order",
      ok:
        sameStrings(
          registry.signers.map((signer) => signer.public_key),
          registry.signers
            .map((signer) => signer.public_key)
            .sort(compareText),
        ) &&
        sameStrings(primaryPublicKeys, [...primaryPublicKeys].sort(compareText)) &&
        sameStrings(recoveryPublicKeys, [...recoveryPublicKeys].sort(compareText)),
    },
    {
      id: "disjoint-groups",
      label: "Every public key belongs to exactly one functional signer group",
      ok:
        registry.primary.length + registry.recovery.length ===
          registry.signers.length &&
        new Set([...primaryPublicKeys, ...recoveryPublicKeys]).size ===
          registry.signers.length,
    },
    {
      id: "derived-recovery-ladder",
      label: "Recovery thresholds descend exactly from M-of-M to 1-of-M",
      ok: recoveryStages.every(
        (stage, index) =>
          stage.threshold === registry.recovery.length - index,
      ),
    },
    {
      id: "day-timelocks",
      label: "Recovery dates strictly increase at 00:00:00 UTC day granularity",
      ok: recoveryDates.every(
        (timestamp, index) =>
          timestamp >= MIN_TIMESTAMP_LOCK &&
          timestamp <= MAX_LOCKTIME &&
          timestamp % SECONDS_PER_DAY === 0 &&
          (index === 0 || timestamp > recoveryDates[index - 1]),
      ),
    },
    {
      id: "exhaustive-policy-equivalence",
      label: `Generated Miniscript satisfactions match the authored policy in all ${equivalence.cases} signer/time cases (${equivalence.satisfactions} symbolic witnesses)`,
      ok: equivalence.ok,
    },
    {
      id: "descriptor-checksum",
      label: "Descriptor checksum covers the exact recovery policy",
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
      "An internal 5×5 template consistency invariant failed; output stopped.",
    );
  }

  const warnings = [
    "The primary path is available immediately as soon as this output is funded.",
    "Every recovery stage remains available after its date; a later stage does not revoke an earlier stage.",
    "Calendar-date locks use Bitcoin median time past, so a recovery stage may become usable after the displayed UTC midnight.",
    "Spending through a recovery stage requires a transaction nLockTime at least equal to its timestamp and a non-final nSequence on the input executing this witness script.",
    "Raw public keys define one fixed P2WSH address; there is no child-key derivation or address rotation.",
    "Independently reproduce and verify the descriptor, script, and address with Bitcoin Core before funding.",
  ];
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
