import assert from "node:assert/strict";
import test from "node:test";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import {
  MAX_DIRECT_SCRIPT_CLAUSES,
  MAX_DIRECT_SCRIPT_KEYS,
  TEMPLATE_ID_DIRECT_SCRIPT,
  compileDirectScriptPolicy,
  unixFromDirectScriptDate,
  validateDirectScriptPublicKey,
  type CompiledDirectScriptPolicy,
  type DirectScriptClause,
  type DirectScriptKey,
  type DirectScriptNetwork,
  type DirectScriptPolicyRequest,
} from "../lib/direct-script-policy";

function publicKey(index: number): string {
  const secret = new Uint8Array(32);
  secret[31] = index;
  return Buffer.from(secp256k1.getPublicKey(secret, true)).toString("hex");
}

function key(index: number): DirectScriptKey {
  return { id: `input-${index}`, label: `Signer ${index}`, public_key: publicKey(index) };
}

function requestWith(
  keys: DirectScriptKey[],
  clauses: DirectScriptClause[],
  network: DirectScriptNetwork = "regtest",
): DirectScriptPolicyRequest {
  return {
    format: "mimir-direct-script-policy-request",
    version: 7,
    network,
    template_id: TEMPLATE_ID_DIRECT_SCRIPT,
    keys: structuredClone(keys),
    clauses: structuredClone(clauses),
  };
}

const dates = [
  unixFromDirectScriptDate("2030-01-01"),
  unixFromDirectScriptDate("2031-01-01"),
  unixFromDirectScriptDate("2032-01-01"),
];

type Decoded = { opcode?: number; data?: Uint8Array };

function decodeScript(hex: string): Decoded[] {
  const bytes = Buffer.from(hex, "hex");
  const decoded: Decoded[] = [];
  for (let cursor = 0; cursor < bytes.length;) {
    const opcode = bytes[cursor++];
    if (opcode >= 1 && opcode <= 75) {
      const end = cursor + opcode;
      assert.ok(end <= bytes.length, "push must stay inside script");
      decoded.push({ data: bytes.subarray(cursor, end) });
      cursor = end;
    } else {
      decoded.push({ opcode });
    }
  }
  return decoded;
}

function scriptNumber(data: Uint8Array): number {
  if (data.length === 0) return 0;
  let result = 0;
  for (let index = 0; index < data.length; index += 1) result += data[index] * 256 ** index;
  const signMask = 0x80 * 256 ** (data.length - 1);
  return (result & signMask) !== 0 ? -(result & ~signMask) : result;
}

function evaluateSymbolically(
  compiled: CompiledDirectScriptPolicy,
  branchIndex: number,
  available: Set<string>,
  locktime: number,
): boolean {
  const selector = compiled.manifest.clauses[branchIndex].branch_selector_bottom_to_top;
  const stack: Array<number | string | boolean> = [...selector];
  const controls: Array<{ parent: boolean; condition: boolean }> = [];
  let active = true;

  for (const instruction of decodeScript(compiled.witness_script_hex)) {
    if (instruction.opcode === 0x63) {
      const branchCondition: boolean = active ? Boolean(stack.pop()) : false;
      controls.push({ parent: active, condition: branchCondition });
      active = active && branchCondition;
      continue;
    }
    if (instruction.opcode === 0x67) {
      const control = controls.at(-1);
      assert.ok(control, "ELSE needs IF");
      active = control.parent && !control.condition;
      continue;
    }
    if (instruction.opcode === 0x68) {
      const control = controls.pop();
      assert.ok(control, "ENDIF needs IF");
      active = control.parent;
      continue;
    }
    if (!active) continue;
    if (instruction.data) {
      stack.push(instruction.data.length === 33
        ? Buffer.from(instruction.data).toString("hex")
        : scriptNumber(instruction.data));
      continue;
    }
    const opcode = instruction.opcode as number;
    if (opcode === 0x00) stack.push(0);
    else if (opcode >= 0x51 && opcode <= 0x60) stack.push(opcode - 0x50);
    else if (opcode === 0xb1) {
      const required = stack.at(-1);
      if (typeof required !== "number" || locktime < required) return false;
    } else if (opcode === 0x75) {
      stack.pop();
    } else if (opcode === 0xac) {
      const pubkey = stack.pop();
      assert.equal(typeof pubkey, "string");
      stack.push(available.has(pubkey as string));
    } else if (opcode === 0xae) {
      const count = stack.pop();
      assert.equal(typeof count, "number");
      const pubkeys = Array.from({ length: count as number }, () => stack.pop() as string).reverse();
      const threshold = stack.pop();
      assert.equal(typeof threshold, "number");
      stack.push(pubkeys.filter((pubkey) => available.has(pubkey)).length >= (threshold as number));
    } else {
      assert.fail(`unexpected opcode ${opcode.toString(16)}`);
    }
  }
  assert.equal(controls.length, 0);
  return stack.length === 1 && stack[0] === true;
}

function assertSemanticEquivalence(compiled: CompiledDirectScriptPolicy): void {
  const publicKeys = compiled.request.keys.map((candidate) => candidate.public_key);
  const boundaries = compiled.request.clauses.flatMap((clause) => clause.unlock_unix === null ? [] : [clause.unlock_unix]);
  const times = boundaries.length === 0
    ? [499_999_999]
    : [...new Set(boundaries.flatMap((boundary) => [boundary - 1, boundary]))].sort((a, b) => a - b);
  for (let mask = 0; mask < 2 ** publicKeys.length; mask += 1) {
    const available = new Set(publicKeys.filter((_, index) => (mask & (1 << index)) !== 0));
    for (const time of times) {
      const expected = compiled.request.clauses.some((clause) =>
        clause.key_ids.filter((id) => {
          const candidate = compiled.request.keys.find((keyEntry) => keyEntry.id === id);
          return candidate ? available.has(candidate.public_key) : false;
        }).length >= clause.threshold && (clause.unlock_unix === null || time >= clause.unlock_unix));
      const actual = compiled.request.clauses.some((_, branchIndex) =>
        evaluateSymbolically(compiled, branchIndex, available, time));
      assert.equal(actual, expected, `mask=${mask} time=${time}`);
    }
  }
}

test("one immediate key compiles to the exact minimal P2WSH witness script", () => {
  const signer = key(1);
  const compiled = compileDirectScriptPolicy(requestWith([signer], [
    { key_ids: [signer.id], threshold: 1, unlock_unix: null },
  ]));
  assert.equal(compiled.asm, `<${signer.public_key}> OP_CHECKSIG`);
  assert.equal(compiled.witness_script_hex, `21${signer.public_key}ac`);
  assert.equal(compiled.witness_script_bytes, 35);
  assert.equal(compiled.witness_program_sha256, "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262");
  assert.equal(compiled.script_pubkey_hex, "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262");
  assert.equal(compiled.address, "bcrt1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qzf4jry");
  assert.equal("invariants" in compiled, false);
  assert.equal("warnings" in compiled, false);
  assert.equal(compiled.manifest.construction.type, "single-clause");
  assert.deepEqual(compiled.manifest.clauses[0].branch_selector_bottom_to_top, []);
  assertSemanticEquivalence(compiled);
});

test("the demo remains four literal branches and repeats every authored key occurrence", () => {
  const keys = [key(1), key(2), key(3), key(4)];
  const ids = keys.map((candidate) => candidate.id);
  const compiled = compileDirectScriptPolicy(requestWith(keys, [
    { key_ids: [ids[0]], threshold: 1, unlock_unix: null },
    { key_ids: ids, threshold: 3, unlock_unix: dates[0] },
    { key_ids: ids, threshold: 2, unlock_unix: dates[1] },
    { key_ids: ids, threshold: 1, unlock_unix: dates[2] },
  ]));

  assert.equal(compiled.manifest.construction.authored_clauses, 4);
  assert.equal(compiled.manifest.construction.emitted_branches, 4);
  assert.equal(compiled.manifest.construction.authored_key_occurrences, 13);
  assert.equal(compiled.manifest.construction.emitted_key_occurrences, 13);
  assert.equal(compiled.manifest.construction.rewriting, false);
  assert.deepEqual(
    compiled.manifest.clauses.map((clause) => clause.branch_selector_bottom_to_top),
    [[1], [1, 0], [1, 0, 0], [0, 0, 0]],
  );
  assert.equal(compiled.asm.split("OP_IF").length - 1, 3);
  assert.equal(compiled.asm.split("OP_ELSE").length - 1, 3);
  assert.equal(compiled.asm.split("OP_ENDIF").length - 1, 3);
  for (const [index, candidate] of keys.entries()) {
    assert.equal(compiled.asm.split(candidate.public_key).length - 1, index === 0 ? 4 : 3);
  }
  assert.doesNotMatch(compiled.asm, /OP_SWAP|OP_ADD|OP_0NOTEQUAL/);
  assertSemanticEquivalence(compiled);
});

test("arbitrary overlapping and repeated key sets compile without rewriting", () => {
  const keys = [key(1), key(2), key(3), key(4)];
  const compiled = compileDirectScriptPolicy(requestWith(keys, [
    { key_ids: [keys[0].id, keys[1].id], threshold: 2, unlock_unix: null },
    { key_ids: [keys[0].id, keys[3].id], threshold: 2, unlock_unix: dates[0] },
    { key_ids: [keys[1].id, keys[2].id], threshold: 1, unlock_unix: dates[1] },
  ]));
  assert.equal(compiled.manifest.construction.emitted_branches, 3);
  assert.equal(compiled.manifest.construction.emitted_key_occurrences, 6);
  assertSemanticEquivalence(compiled);
});

test("all 160 possible single-clause key-set, threshold, and timing shapes compile", () => {
  const keys = Array.from({ length: MAX_DIRECT_SCRIPT_KEYS }, (_, index) => key(index + 1));
  let shapes = 0;
  for (let selection = 1; selection < 2 ** keys.length; selection += 1) {
    const selected = keys.filter((_, index) => (selection & (1 << index)) !== 0);
    for (let threshold = 1; threshold <= selected.length; threshold += 1) {
      for (const unlock_unix of [null, dates[0]]) {
        shapes += 1;
        const compiled = compileDirectScriptPolicy(requestWith(keys, [{
          key_ids: selected.map((candidate) => candidate.id), threshold, unlock_unix,
        }]));
        assertSemanticEquivalence(compiled);
      }
    }
  }
  assert.equal(shapes, 160);
});

test("the maximum five-clause script stays small and every deep branch selects correctly", () => {
  const keys = Array.from({ length: MAX_DIRECT_SCRIPT_KEYS }, (_, index) => key(index + 1));
  const clauses: DirectScriptClause[] = [
    { key_ids: [keys[0].id], threshold: 1, unlock_unix: null },
    { key_ids: keys.map((candidate) => candidate.id), threshold: 5, unlock_unix: dates[0] },
    { key_ids: [keys[0].id, keys[2].id, keys[4].id], threshold: 2, unlock_unix: dates[1] },
    { key_ids: [keys[1].id, keys[2].id], threshold: 1, unlock_unix: dates[2] },
    { key_ids: [keys[0].id, keys[1].id, keys[3].id, keys[4].id], threshold: 3, unlock_unix: dates[2] },
  ];
  const compiled = compileDirectScriptPolicy(requestWith(keys, clauses));
  assert.equal(compiled.manifest.clauses.length, MAX_DIRECT_SCRIPT_CLAUSES);
  assert.deepEqual(compiled.manifest.clauses.at(-1)?.branch_selector_bottom_to_top, [0, 0, 0, 0]);
  assert.ok(compiled.witness_script_bytes < 1_000);
  assert.ok(compiled.opcode_count < 50);
  assertSemanticEquivalence(compiled);
});

test("key registration and clause key order cannot alter the script", () => {
  const keys = [key(1), key(2), key(3)];
  const first = compileDirectScriptPolicy(requestWith(keys, [{
    key_ids: keys.map((candidate) => candidate.id), threshold: 2, unlock_unix: dates[0],
  }]));
  const remapped = [...keys].reverse().map((candidate, index) => ({ ...candidate, id: `alias-${index}` }));
  const second = compileDirectScriptPolicy(requestWith(remapped, [{
    key_ids: remapped.map((candidate) => candidate.id), threshold: 2, unlock_unix: dates[0],
  }]));
  assert.equal(second.witness_script_hex, first.witness_script_hex);
  assert.equal(second.canonical_manifest, first.canonical_manifest);
});

test("network selection changes only the P2WSH address encoding", () => {
  const signer = key(1);
  const clause = [{ key_ids: [signer.id], threshold: 1, unlock_unix: null }];
  const bitcoin = compileDirectScriptPolicy(requestWith([signer], clause, "bitcoin"));
  const testnet = compileDirectScriptPolicy(requestWith([signer], clause, "testnet"));
  const signet = compileDirectScriptPolicy(requestWith([signer], clause, "signet"));
  const regtest = compileDirectScriptPolicy(requestWith([signer], clause, "regtest"));
  assert.match(bitcoin.address, /^bc1q/);
  assert.match(testnet.address, /^tb1q/);
  assert.equal(signet.address, testnet.address);
  assert.match(regtest.address, /^bcrt1q/);
  assert.equal(bitcoin.witness_script_hex, regtest.witness_script_hex);
});

test("dates use full CLTV range and exact whole UTC days", () => {
  assert.equal(unixFromDirectScriptDate("2106-02-07"), 4_294_944_000);
  assert.throws(() => unixFromDirectScriptDate("2106-02-08"), /2106-02-07/i);
  assert.throws(() => unixFromDirectScriptDate("2030-02-29"), /real calendar date/i);
});

test("invalid keys, limits, references, thresholds, and duplicate identities fail closed", () => {
  assert.equal(validateDirectScriptPublicKey(` ${publicKey(1).toUpperCase()} `), publicKey(1));
  assert.throws(() => validateDirectScriptPublicKey("02".padEnd(66, "0")), /valid point/i);
  const keys = [key(1), key(2)];
  assert.throws(() => compileDirectScriptPolicy(requestWith(
    [...keys, ...Array.from({ length: MAX_DIRECT_SCRIPT_KEYS - 1 }, (_, index) => key(index + 3))],
    [{ key_ids: [keys[0].id], threshold: 1, unlock_unix: null }],
  )), /between 1 and 5 keys/i);
  assert.throws(() => compileDirectScriptPolicy(requestWith(keys, Array.from(
    { length: MAX_DIRECT_SCRIPT_CLAUSES + 1 },
    () => ({ key_ids: [keys[0].id], threshold: 1, unlock_unix: null }),
  ))), /between 1 and 5 clauses/i);
  assert.throws(() => compileDirectScriptPolicy(requestWith(keys, [
    { key_ids: ["missing"], threshold: 1, unlock_unix: null },
  ])), /unknown key ID/i);
  assert.throws(() => compileDirectScriptPolicy(requestWith(keys, [
    { key_ids: keys.map((candidate) => candidate.id), threshold: 3, unlock_unix: null },
  ])), /threshold/i);
  assert.throws(() => compileDirectScriptPolicy(requestWith([keys[0], { ...keys[0], id: "other", label: "Other" }], [
    { key_ids: [keys[0].id], threshold: 1, unlock_unix: null },
  ])), /public key may be registered only once/i);
});
