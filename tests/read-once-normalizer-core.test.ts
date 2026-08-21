import assert from "node:assert/strict";
import test from "node:test";
import { compileMiniscript } from "@bitcoinerlab/miniscript";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import {
  MAX_READ_ONCE_KEYS,
  MAX_READ_ONCE_PATHS,
  TEMPLATE_ID_READ_ONCE,
  compileReadOncePolicy,
  unixFromReadOnceDate,
  validateReadOncePublicKey,
  type ReadOnceKey,
  type ReadOnceNetwork,
  type ReadOncePolicyRequest,
  type ReadOnceVisualPath,
} from "../lib/read-once-normalizer";

function publicKey(index: number): string {
  const secret = new Uint8Array(32);
  secret[30] = Math.floor(index / 256);
  secret[31] = index % 256;
  return Buffer.from(secp256k1.getPublicKey(secret, true)).toString("hex");
}

function key(index: number): ReadOnceKey {
  return {
    id: `input-${index}`,
    label: `Signer ${index}`,
    public_key: publicKey(index),
  };
}

const dates = [
  unixFromReadOnceDate("2030-01-01"),
  unixFromReadOnceDate("2031-01-01"),
  unixFromReadOnceDate("2032-01-01"),
  unixFromReadOnceDate("2033-01-01"),
  unixFromReadOnceDate("2034-01-01"),
];

function requestWith(
  keys: ReadOnceKey[],
  paths: ReadOnceVisualPath[],
  network: ReadOnceNetwork = "regtest",
): ReadOncePolicyRequest {
  return {
    format: "mimir-read-once-policy-request",
    version: 6,
    network,
    template_id: TEMPLATE_ID_READ_ONCE,
    keys: structuredClone(keys),
    paths: structuredClone(paths),
  };
}

test("repeated Owner is factored out of an immediate plus delayed recovery policy", () => {
  const keys = [key(1), key(2), key(3)];
  const compiled = compileReadOncePolicy(requestWith(keys, [
    { key_ids: [keys[0].id], threshold: 1, unlock_unix: null },
    { key_ids: keys.map((candidate) => candidate.id), threshold: 2, unlock_unix: dates[0] },
  ]));

  const [owner, heirA, heirB] = keys.map((candidate) => candidate.public_key);
  assert.equal(
    compiled.miniscript,
    `or_i(and_v(v:after(${dates[0]}),multi(2,${[heirA, heirB].sort().join(",")})),pk(${owner}))`,
  );
  assert.equal(compiled.manifest.normalization.authored_key_occurrences, 4);
  assert.equal(compiled.manifest.normalization.emitted_key_checks, 3);
  assert.match(compiled.manifest.normalization.notes.join(" "), /Factored repeated visual key use for: Signer 1/i);
  assert.equal(
    compiled.witness_script_hex,
    "630480d8db70b169522102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee52102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f952ae67210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac68",
  );
  assert.equal(
    compiled.script_pubkey_hex,
    "00208c4cabe522f863d1eca843201933bc7f6c7a8f36e4a6ce94c64eb57d8611f953",
  );
  assert.equal(
    compiled.address,
    "bcrt1q33x2hefzlp3arm9ggvspjvau0ak84rekujnva9xxf66hmps3l9fskmgcnk",
  );
  assert.equal(
    compiled.descriptor,
    `wsh(or_i(and_v(v:after(${dates[0]}),multi(2,${[heirA, heirB].sort().join(",")})),pk(${owner})))#6dpccwew`,
  );
  assert.ok(compiled.invariants.every((invariant) => invariant.ok));
  for (const candidate of keys) {
    assert.equal(compiled.miniscript.split(candidate.public_key).length - 1, 1);
  }
  const independent = compileMiniscript(compiled.miniscript);
  assert.equal(independent.error, null);
  assert.equal(independent.issane, true);
});

test("a later duplicate of an immediate key is removed as semantically redundant", () => {
  const signer = key(1);
  const compiled = compileReadOncePolicy(requestWith([signer], [
    { key_ids: [signer.id], threshold: 1, unlock_unix: null },
    { key_ids: [signer.id], threshold: 1, unlock_unix: dates[0] },
  ]));
  assert.equal(compiled.miniscript, `pk(${signer.public_key})`);
  assert.equal(compiled.manifest.normalization.authored_key_occurrences, 2);
  assert.equal(compiled.manifest.normalization.emitted_key_checks, 1);
  assert.ok(compiled.invariants.every((invariant) => invariant.ok));
});

test("an exact-set 3-of-3 to 2-of-3 to 1-of-3 ladder is normalized read-once", () => {
  const keys = [key(1), key(2), key(3)];
  const ids = keys.map((candidate) => candidate.id);
  const compiled = compileReadOncePolicy(requestWith(keys, [
    { key_ids: ids, threshold: 3, unlock_unix: dates[0] },
    { key_ids: [...ids].reverse(), threshold: 2, unlock_unix: dates[1] },
    { key_ids: ids, threshold: 1, unlock_unix: dates[2] },
  ]));
  assert.match(compiled.miniscript, /^and_v\(v:after\(/);
  assert.match(compiled.miniscript, /thresh\(3,/);
  assert.equal(compiled.manifest.normalization.tree.type, "threshold_ladder");
  assert.ok(compiled.invariants.every((invariant) => invariant.ok));
  for (const candidate of keys) {
    assert.equal(compiled.miniscript.split(candidate.public_key).length - 1, 1);
  }
});

test("the UI demo reuses Owner in every recovery stage and emits Owner only once", () => {
  const keys = [key(1), key(2), key(3), key(4)];
  const allIds = keys.map((candidate) => candidate.id);
  const compiled = compileReadOncePolicy(requestWith(keys, [
    { key_ids: [keys[0].id], threshold: 1, unlock_unix: null },
    { key_ids: allIds, threshold: 3, unlock_unix: dates[0] },
    { key_ids: allIds, threshold: 2, unlock_unix: dates[1] },
    { key_ids: allIds, threshold: 1, unlock_unix: dates[2] },
  ]));
  assert.equal(compiled.manifest.normalization.authored_key_occurrences, 13);
  assert.equal(compiled.manifest.normalization.emitted_key_checks, 4);
  assert.match(compiled.miniscript, /^or_i\(/);
  assert.match(compiled.miniscript, /thresh\(3,/);
  assert.ok(compiled.invariants.every((invariant) => invariant.ok));
  for (const candidate of keys) {
    assert.equal(compiled.miniscript.split(candidate.public_key).length - 1, 1);
  }
});

test("a common key across two differently timed 2-of-2 paths is factored", () => {
  const keys = [key(1), key(2), key(3)];
  const compiled = compileReadOncePolicy(requestWith(keys, [
    { key_ids: [keys[0].id, keys[1].id], threshold: 2, unlock_unix: null },
    { key_ids: [keys[0].id, keys[2].id], threshold: 2, unlock_unix: dates[0] },
  ]));
  assert.match(compiled.miniscript, /and_v/);
  assert.match(compiled.miniscript, /or_i/);
  assert.ok(compiled.invariants.every((invariant) => invariant.ok));
  for (const candidate of keys) {
    assert.equal(compiled.miniscript.split(candidate.public_key).length - 1, 1);
  }
});

test("an overlap graph that has no supported read-once equivalent fails closed", () => {
  const keys = [key(1), key(2), key(3), key(4)];
  const edges = [[0, 1], [0, 3], [1, 2]];
  assert.throws(
    () => compileReadOncePolicy(requestWith(keys, edges.map(([left, right]) => ({
      key_ids: [keys[left].id, keys[right].id],
      threshold: 2,
      unlock_unix: null,
    })))),
    /cannot be simplified.*read-once/i,
  );
});

test("canonical output is independent of caller key and path order", () => {
  const keys = [key(1), key(2), key(3)];
  const paths: ReadOnceVisualPath[] = [
    { key_ids: [keys[0].id], threshold: 1, unlock_unix: null },
    { key_ids: keys.map((candidate) => candidate.id), threshold: 2, unlock_unix: dates[0] },
  ];
  const first = compileReadOncePolicy(requestWith(keys, paths));
  const remapped = [...keys].reverse().map((candidate, index) => ({ ...candidate, id: `alias-${index}` }));
  const byPublicKey = new Map(remapped.map((candidate) => [candidate.public_key, candidate.id]));
  const secondPaths = [...paths].reverse().map((path) => ({
    ...path,
    key_ids: [...path.key_ids].reverse().map((id) => {
      const original = keys.find((candidate) => candidate.id === id);
      return byPublicKey.get(original?.public_key ?? "") as string;
    }),
  }));
  const second = compileReadOncePolicy(requestWith(remapped, secondPaths));
  assert.equal(second.canonical_manifest, first.canonical_manifest);
  assert.equal(second.policy_manifest_sha256, first.policy_manifest_sha256);
});

test("all 114 threshold-ladder shapes through five keys normalize read-once", () => {
  let shapes = 0;
  for (let keyCount = 1; keyCount <= 5; keyCount += 1) {
    const keys = Array.from({ length: keyCount }, (_, index) => key(index + 1));
    const ids = keys.map((candidate) => candidate.id);
    for (let selection = 1; selection < 2 ** keyCount; selection += 1) {
      const thresholds = Array.from({ length: keyCount }, (_, index) => keyCount - index)
        .filter((threshold) => (selection & (1 << (threshold - 1))) !== 0);
      for (const immediate of [true, false]) {
        shapes += 1;
        const paths = thresholds.map((threshold, stageIndex): ReadOnceVisualPath => ({
          key_ids: [...ids].reverse(),
          threshold,
          unlock_unix: immediate && stageIndex === 0
            ? null
            : dates[stageIndex - (immediate ? 1 : 0)],
        }));
        const compiled = compileReadOncePolicy(requestWith(keys, paths));
        assert.ok(compiled.invariants.every((invariant) => invariant.ok));
        for (const candidate of keys) {
          assert.equal(compiled.miniscript.split(candidate.public_key).length - 1, 1);
        }
      }
    }
  }
  assert.equal(shapes, 114);
});

test("input validation enforces the 5 by 5 surface and supported networks", () => {
  assert.equal(validateReadOncePublicKey(` ${publicKey(1).toUpperCase()} `), publicKey(1));
  assert.throws(() => unixFromReadOnceDate("2030-02-29"), /real calendar date/i);
  const sixKeys = Array.from({ length: MAX_READ_ONCE_KEYS + 1 }, (_, index) => key(index + 1));
  assert.throws(
    () => compileReadOncePolicy(requestWith(sixKeys, [
      { key_ids: [sixKeys[0].id], threshold: 1, unlock_unix: null },
    ])),
    /at most 5 keys/i,
  );
  const signer = key(1);
  const sixPaths = Array.from({ length: MAX_READ_ONCE_PATHS + 1 }, () => ({
    key_ids: [signer.id], threshold: 1, unlock_unix: null,
  }));
  assert.throws(
    () => compileReadOncePolicy(requestWith([signer], sixPaths)),
    /at most 5 visual paths/i,
  );
  const regtest = compileReadOncePolicy(requestWith([signer], [
    { key_ids: [signer.id], threshold: 1, unlock_unix: null },
  ], "regtest"));
  const signet = compileReadOncePolicy(requestWith([signer], [
    { key_ids: [signer.id], threshold: 1, unlock_unix: null },
  ], "signet"));
  const bitcoin = compileReadOncePolicy(requestWith([signer], [
    { key_ids: [signer.id], threshold: 1, unlock_unix: null },
  ], "bitcoin"));
  assert.match(regtest.address, /^bcrt1q/);
  assert.match(signet.address, /^tb1q/);
  assert.match(bitcoin.address, /^bc1q/);
});
