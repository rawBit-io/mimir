import assert from "node:assert/strict";
import test from "node:test";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import {
  TEMPLATE_ID_V2,
  compileComposedPolicy,
  unixFromComposerUtc,
  validateCompressedPublicKey,
  type ComposerKey,
  type ComposerNetwork,
  type ComposerRequest,
} from "../lib/composer";

function publicKey(index: number): string {
  const secret = new Uint8Array(32);
  secret[30] = Math.floor(index / 256);
  secret[31] = index % 256;
  return Buffer.from(secp256k1.getPublicKey(secret, true)).toString("hex");
}

const registry: ComposerKey[] = Array.from({ length: 20 }, (_, index) => ({
  id: `key-${String(index + 1).padStart(2, "0")}`,
  label: `Signer ${String(index + 1).padStart(2, "0")}`,
  public_key: publicKey(index + 1),
}));

function requestFor(
  ownerCount: number,
  ownerThreshold: number,
  heirCount: number,
  heirThreshold: number,
  network: ComposerNetwork = "regtest",
): ComposerRequest {
  return {
    format: "mimir-composer-request",
    version: 2,
    network,
    template_id: TEMPLATE_ID_V2,
    keys: structuredClone(registry.slice(0, ownerCount + heirCount)),
    owner: {
      key_ids: registry.slice(0, ownerCount).map((key) => key.id),
      threshold: ownerThreshold,
      unlock_unix: 1_893_456_000,
    },
    heirs: {
      key_ids: registry
        .slice(ownerCount, ownerCount + heirCount)
        .map((key) => key.id),
      threshold: heirThreshold,
      unlock_unix: 2_051_222_400,
    },
  };
}

test("1-of-1 groups retain the frozen two-path pk() shape", () => {
  const request = requestFor(1, 1, 1, 1);
  const compiled = compileComposedPolicy(request);
  const owner = request.keys[0].public_key;
  const heir = request.keys[1].public_key;

  assert.equal(
    compiled.miniscript,
    `or_i(and_v(v:after(1893456000),pk(${owner})),and_v(v:after(2051222400),pk(${heir})))`,
  );
  assert.equal(compiled.witness_script_bytes, 87);
  assert.match(compiled.descriptor, /^wsh\(.+\)#[a-z0-9]{8}$/);
  assert.match(compiled.address, /^bcrt1q/);
  assert.ok(compiled.invariants.every((invariant) => invariant.ok));
});

test("1-of-10 and 5-of-10 heirs compile as canonical multi() policies", () => {
  const anyHeir = compileComposedPolicy(requestFor(1, 1, 10, 1));
  const quorum = compileComposedPolicy(requestFor(1, 1, 10, 5));

  assert.match(anyHeir.manifest.heirs.miniscript_fragment, /^multi\(1,/);
  assert.match(quorum.manifest.heirs.miniscript_fragment, /^multi\(5,/);
  assert.equal(anyHeir.manifest.heirs.public_keys.length, 10);
  assert.equal(quorum.manifest.heirs.public_keys.length, 10);
  assert.match(anyHeir.asm, /1 .* 10 OP_CHECKMULTISIG/);
  assert.match(quorum.asm, /5 .* 10 OP_CHECKMULTISIG/);
  assert.notEqual(anyHeir.witness_script_hex, quorum.witness_script_hex);
  assert.ok(anyHeir.invariants.every((invariant) => invariant.ok));
  assert.ok(quorum.invariants.every((invariant) => invariant.ok));
});

test("2-of-3 owners and 5-of-10 heirs remain standard and internally consistent", () => {
  const compiled = compileComposedPolicy(requestFor(3, 2, 10, 5));

  assert.match(compiled.manifest.owner.miniscript_fragment, /^multi\(2,/);
  assert.match(compiled.manifest.heirs.miniscript_fragment, /^multi\(5,/);
  assert.equal(compiled.manifest.owner.public_keys.length, 3);
  assert.equal(compiled.manifest.heirs.public_keys.length, 10);
  assert.ok(compiled.witness_script_bytes < 3_600);
  assert.equal(compiled.script_pubkey_hex, `0020${compiled.witness_program_sha256}`);
  assert.ok(compiled.invariants.every((invariant) => invariant.ok));
});

test("registry and group ordering cannot change canonical output", () => {
  const firstRequest = requestFor(3, 2, 10, 5);
  const shuffledRequest = structuredClone(firstRequest);
  shuffledRequest.keys.reverse();
  shuffledRequest.owner.key_ids.reverse();
  shuffledRequest.heirs.key_ids.reverse();

  const first = compileComposedPolicy(firstRequest);
  const shuffled = compileComposedPolicy(shuffledRequest);

  assert.equal(first.miniscript, shuffled.miniscript);
  assert.equal(first.descriptor, shuffled.descriptor);
  assert.equal(first.witness_script_hex, shuffled.witness_script_hex);
  assert.equal(first.canonical_manifest, shuffled.canonical_manifest);
  assert.equal(first.policy_manifest_sha256, shuffled.policy_manifest_sha256);
  assert.deepEqual(first.request, shuffled.request);
});

test("P2WSH addresses use the correct network HRP", () => {
  const mainnet = compileComposedPolicy(requestFor(1, 1, 2, 1, "bitcoin"));
  const signet = compileComposedPolicy(requestFor(1, 1, 2, 1, "signet"));
  const regtest = compileComposedPolicy(requestFor(1, 1, 2, 1, "regtest"));

  assert.match(mainnet.address, /^bc1q/);
  assert.match(signet.address, /^tb1q/);
  assert.match(regtest.address, /^bcrt1q/);
  assert.equal(mainnet.witness_script_hex, signet.witness_script_hex);
  assert.equal(signet.witness_script_hex, regtest.witness_script_hex);
  assert.notEqual(mainnet.address, signet.address);
  assert.notEqual(signet.address, regtest.address);
});

test("public-key validation rejects private, x-only, uncompressed, and off-curve input", () => {
  assert.equal(validateCompressedPublicKey(publicKey(1).toUpperCase()), publicKey(1));
  assert.throws(() => validateCompressedPublicKey("11".repeat(32)), /compressed/i);
  assert.throws(() => validateCompressedPublicKey(`04${"11".repeat(64)}`), /compressed/i);
  assert.throws(() => validateCompressedPublicKey(`02${"ff".repeat(32)}`), /curve/i);
  assert.throws(() => validateCompressedPublicKey("xprv-not-public"), /compressed/i);
});

test("duplicate registry identities and cross-group reuse fail closed", () => {
  for (const field of ["id", "label", "public_key"] as const) {
    const request = requestFor(1, 1, 2, 1);
    request.keys[1][field] = request.keys[0][field];
    assert.throws(() => compileComposedPolicy(request), /duplicate/i);
  }

  const overlap = requestFor(1, 1, 2, 1);
  overlap.heirs.key_ids[0] = overlap.owner.key_ids[0];
  assert.throws(() => compileComposedPolicy(overlap), /both owner and heir/i);

  const repeated = requestFor(1, 1, 2, 1);
  repeated.heirs.key_ids = [repeated.heirs.key_ids[0], repeated.heirs.key_ids[0]];
  assert.throws(() => compileComposedPolicy(repeated), /duplicate key ID/i);
});

test("invalid thresholds, groups, references, and timestamps fail closed", () => {
  for (const threshold of [0, 3, 1.5]) {
    const request = requestFor(1, 1, 2, 1);
    request.heirs.threshold = threshold;
    assert.throws(() => compileComposedPolicy(request), /threshold/i);
  }

  const empty = requestFor(1, 1, 2, 1);
  empty.heirs.key_ids = [];
  assert.throws(() => compileComposedPolicy(empty), /between 1 and 10/i);

  const tooMany = requestFor(1, 1, 10, 5);
  tooMany.keys.push(structuredClone(registry[11]));
  tooMany.heirs.key_ids.push(registry[11].id);
  assert.throws(() => compileComposedPolicy(tooMany), /between 1 and 10/i);

  const unknown = requestFor(1, 1, 2, 1);
  unknown.heirs.key_ids[0] = "missing";
  assert.throws(() => compileComposedPolicy(unknown), /unknown key ID/i);

  const tooEarly = requestFor(1, 1, 2, 1);
  tooEarly.owner.unlock_unix = 499_999_999;
  assert.throws(() => compileComposedPolicy(tooEarly), /at least 500000000/i);

  const tooLate = requestFor(1, 1, 2, 1);
  tooLate.heirs.unlock_unix = 0x80000000;
  assert.throws(() => compileComposedPolicy(tooLate), /2038-01-19/i);

  const wrongOrder = requestFor(1, 1, 2, 1);
  wrongOrder.owner.unlock_unix = wrongOrder.heirs.unlock_unix;
  assert.throws(() => compileComposedPolicy(wrongOrder), /strictly earlier/i);

  assert.equal(unixFromComposerUtc("2030-01-01T00:00:00Z"), 1_893_456_000);
  assert.throws(() => unixFromComposerUtc("2040-01-01T00:00:00Z"), /2038-01-19/i);
});

test("the maximum 10-of-10 plus 10-of-10 policy stays below the script limit", () => {
  const compiled = compileComposedPolicy(requestFor(10, 10, 10, 10));

  assert.equal(compiled.request.keys.length, 20);
  assert.ok(compiled.witness_script_bytes > 600);
  assert.ok(compiled.witness_script_bytes <= 3_600);
  assert.ok(compiled.invariants.every((invariant) => invariant.ok));
  assert.equal(compiled.policy_manifest_sha256.length, 64);
});

test("unassigned registry keys are permitted but explicitly warned", () => {
  const request = requestFor(1, 1, 1, 1);
  request.keys.push(structuredClone(registry[2]));
  const compiled = compileComposedPolicy(request);

  assert.ok(compiled.warnings.some((warning) => /unassigned/i.test(warning)));
  assert.match(compiled.warnings[0], /Signer 03 \(key-03\)/);
});
