import assert from "node:assert/strict";
import test from "node:test";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import {
  TEMPLATE_ID_V3,
  compileRulePolicy,
  unixFromRuleDate,
  validateRulePublicKey,
  type RuleComposerRequest,
  type RuleKey,
  type RuleNetwork,
} from "../lib/rule-composer";

function publicKey(index: number): string {
  const secret = new Uint8Array(32);
  secret[30] = Math.floor(index / 256);
  secret[31] = index % 256;
  return Buffer.from(secp256k1.getPublicKey(secret, true)).toString("hex");
}

const registry: RuleKey[] = Array.from({ length: 20 }, (_, index) => ({
  id: `input-${String(index + 1).padStart(2, "0")}`,
  label: `Signer ${String(index + 1).padStart(2, "0")}`,
  public_key: publicKey(index + 1),
}));

function requestWith(
  rules: RuleComposerRequest["rules"],
  keyCount: number,
  network: RuleNetwork = "regtest",
): RuleComposerRequest {
  return {
    format: "mimir-rule-request",
    version: 3,
    network,
    template_id: TEMPLATE_ID_V3,
    keys: structuredClone(registry.slice(0, keyCount)),
    rules: structuredClone(rules),
  };
}

test("one-key immediate rule compiles directly as pk()", () => {
  const compiled = compileRulePolicy(
    requestWith(
      [{ key_ids: [registry[0].id], threshold: 1, unlock_unix: null }],
      1,
    ),
  );

  assert.equal(compiled.miniscript, `pk(${registry[0].public_key})`);
  assert.equal(compiled.manifest.rules.length, 1);
  assert.equal(compiled.manifest.rules[0].unlock, null);
  assert.equal(compiled.manifest.rules[0].id, "rule-01");
  assert.equal(compiled.request.keys[0].id, "key-01");
  assert.deepEqual(compiled.request.rules[0].key_ids, ["key-01"]);
  assert.match(compiled.descriptor, /^wsh\(.+\)#[a-z0-9]{8}$/);
  assert.match(compiled.address, /^bcrt1q/);
  assert.ok(compiled.invariants.every((invariant) => invariant.ok));
  assert.ok(compiled.warnings.some((warning) => /immediately available/i.test(warning)));
  assert.ok(!compiled.warnings.some((warning) => /median time past/i.test(warning)));
});

test("a timed 2-of-3 rule uses day-granular after() and multi()", () => {
  const unlock = unixFromRuleDate("2030-01-01");
  const compiled = compileRulePolicy(
    requestWith(
      [
        {
          key_ids: registry.slice(0, 3).map((key) => key.id).reverse(),
          threshold: 2,
          unlock_unix: unlock,
        },
      ],
      3,
    ),
  );
  const sortedKeys = registry
    .slice(0, 3)
    .map((key) => key.public_key)
    .sort();

  assert.equal(
    compiled.miniscript,
    `and_v(v:after(${unlock}),multi(2,${sortedKeys.join(",")}))`,
  );
  assert.deepEqual(compiled.manifest.rules[0].unlock, {
    unix: unlock,
    utc: "2030-01-01T00:00:00Z",
  });
  assert.match(compiled.asm, /2 .* 3 OP_CHECKMULTISIG/);
  assert.match(compiled.asm, /OP_CHECKLOCKTIMEVERIFY OP_VERIFY/);
  assert.ok(compiled.warnings.some((warning) => /nLockTime/i.test(warning)));
  assert.ok(compiled.warnings.some((warning) => /non-final input sequence/i.test(warning)));
  assert.ok(compiled.warnings.some((warning) => /median time past/i.test(warning)));
  assert.ok(!compiled.warnings.some((warning) => /immediately available/i.test(warning)));
});

test("multiple disjoint rules compile as a canonical right-nested OR", () => {
  const request = requestWith(
    [
      {
        key_ids: [registry[3].id],
        threshold: 1,
        unlock_unix: unixFromRuleDate("2032-01-01"),
      },
      { key_ids: [registry[0].id], threshold: 1, unlock_unix: null },
      {
        key_ids: [registry[1].id, registry[2].id],
        threshold: 1,
        unlock_unix: unixFromRuleDate("2030-01-01"),
      },
    ],
    4,
  );
  const compiled = compileRulePolicy(request);
  const fragments = compiled.manifest.rules.map(
    (rule) => rule.miniscript_fragment,
  );

  assert.deepEqual(fragments, [...fragments].sort());
  assert.equal(
    compiled.miniscript,
    `or_i(${fragments[0]},or_i(${fragments[1]},${fragments[2]}))`,
  );
  assert.match(compiled.asm, /OP_IF/);
  assert.ok(compiled.invariants.every((invariant) => invariant.ok));
});

test("key order, rule order, and arbitrary input IDs cannot change output", () => {
  const first = requestWith(
    [
      {
        key_ids: [registry[0].id, registry[1].id],
        threshold: 2,
        unlock_unix: null,
      },
      {
        key_ids: [registry[2].id, registry[3].id],
        threshold: 1,
        unlock_unix: unixFromRuleDate("2031-06-15"),
      },
    ],
    5,
  );
  const second = structuredClone(first);
  const replacementByOldId = new Map<string, string>();
  second.keys.forEach((key, index) => {
    const replacement = `arbitrary-${101 + index}`;
    replacementByOldId.set(key.id, replacement);
    key.id = replacement;
  });
  second.keys.reverse();
  second.rules = second.rules
    .reverse()
    .map((rule) => ({
      ...rule,
      key_ids: rule.key_ids
        .map((id) => replacementByOldId.get(id) as string)
        .reverse(),
    }));

  const compiledFirst = compileRulePolicy(first);
  const compiledSecond = compileRulePolicy(second);

  assert.deepEqual(compiledFirst.request, compiledSecond.request);
  assert.deepEqual(compiledFirst.manifest, compiledSecond.manifest);
  assert.equal(compiledFirst.miniscript, compiledSecond.miniscript);
  assert.equal(compiledFirst.descriptor, compiledSecond.descriptor);
  assert.equal(compiledFirst.witness_script_hex, compiledSecond.witness_script_hex);
  assert.equal(compiledFirst.canonical_manifest, compiledSecond.canonical_manifest);
  assert.equal(
    compiledFirst.policy_manifest_sha256,
    compiledSecond.policy_manifest_sha256,
  );
  assert.ok(compiledFirst.warnings.some((warning) => /unassigned/i.test(warning)));
});

test("date-only conversion is strict and bounded by Miniscript after()", () => {
  assert.equal(unixFromRuleDate("2030-01-01"), 1_893_456_000);
  assert.equal(unixFromRuleDate("2038-01-19"), 2_147_472_000);

  for (const invalid of [
    "2030-1-01",
    "2030-01-01T00:00:00Z",
    "2025-02-29",
    "2030-04-31",
    "1985-11-05",
    "2038-01-20",
    "",
  ]) {
    assert.throws(() => unixFromRuleDate(invalid), /date|timestamp|limit/i);
  }
});

test("duplicate registry identities and cross-rule key reuse fail closed", () => {
  for (const field of ["id", "label", "public_key"] as const) {
    const request = requestWith(
      [{ key_ids: [registry[0].id], threshold: 1, unlock_unix: null }],
      2,
    );
    request.keys[1][field] = request.keys[0][field];
    assert.throws(() => compileRulePolicy(request), /duplicate/i);
  }

  const overlap = requestWith(
    [
      { key_ids: [registry[0].id], threshold: 1, unlock_unix: null },
      {
        key_ids: [registry[0].id, registry[1].id],
        threshold: 1,
        unlock_unix: unixFromRuleDate("2030-01-01"),
      },
    ],
    2,
  );
  assert.throws(() => compileRulePolicy(overlap), /at most one rule/i);

  const repeated = requestWith(
    [
      {
        key_ids: [registry[0].id, registry[0].id],
        threshold: 1,
        unlock_unix: null,
      },
    ],
    1,
  );
  assert.throws(() => compileRulePolicy(repeated), /duplicate key ID/i);
});

test("invalid thresholds, groups, references, locks, and envelopes fail closed", () => {
  for (const threshold of [0, 3, 1.5]) {
    const request = requestWith(
      [
        {
          key_ids: [registry[0].id, registry[1].id],
          threshold,
          unlock_unix: null,
        },
      ],
      2,
    );
    assert.throws(() => compileRulePolicy(request), /threshold/i);
  }

  const emptyRule = requestWith(
    [{ key_ids: [], threshold: 1, unlock_unix: null }],
    1,
  );
  assert.throws(() => compileRulePolicy(emptyRule), /between 1 and 10 keys/i);

  const noRules = requestWith([], 1);
  assert.throws(() => compileRulePolicy(noRules), /between 1 and 10 rules/i);

  const tooManyRules = requestWith(
    registry.slice(0, 11).map((key) => ({
      key_ids: [key.id],
      threshold: 1,
      unlock_unix: null,
    })),
    11,
  );
  assert.throws(() => compileRulePolicy(tooManyRules), /between 1 and 10 rules/i);

  const tooManyKeys = requestWith(
    [
      {
        key_ids: registry.slice(0, 11).map((key) => key.id),
        threshold: 1,
        unlock_unix: null,
      },
    ],
    11,
  );
  assert.throws(() => compileRulePolicy(tooManyKeys), /between 1 and 10 keys/i);

  const tooLargeRegistry = requestWith(
    [{ key_ids: [registry[0].id], threshold: 1, unlock_unix: null }],
    20,
  );
  tooLargeRegistry.keys.push({
    id: "input-21",
    label: "Signer 21",
    public_key: publicKey(21),
  });
  assert.throws(() => compileRulePolicy(tooLargeRegistry), /at most 20 keys/i);

  const unknown = requestWith(
    [{ key_ids: ["missing"], threshold: 1, unlock_unix: null }],
    1,
  );
  assert.throws(() => compileRulePolicy(unknown), /unknown key ID/i);

  for (const unlock of [
    undefined,
    499_996_800,
    0x80000000,
    unixFromRuleDate("2030-01-01") + 1,
    1_893_456_000.5,
  ]) {
    const request = requestWith(
      [
        {
          key_ids: [registry[0].id],
          threshold: 1,
          unlock_unix: unlock as number | null,
        },
      ],
      1,
    );
    assert.throws(() => compileRulePolicy(request), /unlock|timestamp|granularity|limit/i);
  }

  const badEnvelope = requestWith(
    [{ key_ids: [registry[0].id], threshold: 1, unlock_unix: null }],
    1,
  ) as unknown as Omit<RuleComposerRequest, "version"> & { version: number };
  badEnvelope.version = 2;
  assert.throws(
    () => compileRulePolicy(badEnvelope as RuleComposerRequest),
    /format or version/i,
  );

  const callerRuleId = requestWith(
    [{ key_ids: [registry[0].id], threshold: 1, unlock_unix: null }],
    1,
  );
  Object.assign(callerRuleId.rules[0], { id: "caller-rule" });
  assert.throws(() => compileRulePolicy(callerRuleId), /unsupported state/i);
});

test("strict compressed-key validation remains available to rule UIs", () => {
  assert.equal(validateRulePublicKey(publicKey(1).toUpperCase()), publicKey(1));
  assert.throws(() => validateRulePublicKey("11".repeat(32)), /compressed/i);
  assert.throws(() => validateRulePublicKey(`04${"11".repeat(64)}`), /compressed/i);
  assert.throws(() => validateRulePublicKey(`02${"ff".repeat(32)}`), /curve/i);
});

test("P2WSH addresses use the selected network HRP", () => {
  const make = (network: RuleNetwork) =>
    compileRulePolicy(
      requestWith(
        [{ key_ids: [registry[0].id], threshold: 1, unlock_unix: null }],
        1,
        network,
      ),
    );
  const mainnet = make("bitcoin");
  const signet = make("signet");
  const regtest = make("regtest");

  assert.match(mainnet.address, /^bc1q/);
  assert.match(signet.address, /^tb1q/);
  assert.match(regtest.address, /^bcrt1q/);
  assert.equal(mainnet.witness_script_hex, signet.witness_script_hex);
  assert.equal(signet.witness_script_hex, regtest.witness_script_hex);
  assert.ok(mainnet.warnings.some((warning) => /mainnet/i.test(warning)));
  assert.ok(!signet.warnings.some((warning) => /mainnet output/i.test(warning)));
});

test("the maximum 20-key, 10-rule policy stays standard and reproducible", () => {
  const baseUnlock = unixFromRuleDate("2029-01-01");
  const rules = Array.from({ length: 10 }, (_, index) => ({
    key_ids: registry.slice(index * 2, index * 2 + 2).map((key) => key.id),
    threshold: index % 2 === 0 ? 1 : 2,
    unlock_unix: baseUnlock + index * 86_400,
  }));
  const compiled = compileRulePolicy(requestWith(rules, 20));

  assert.equal(compiled.request.keys.length, 20);
  assert.equal(compiled.request.rules.length, 10);
  assert.equal(compiled.manifest.rules.length, 10);
  assert.ok(compiled.witness_script_bytes > 700);
  assert.ok(compiled.witness_script_bytes <= 3_600);
  assert.equal(compiled.script_pubkey_hex, `0020${compiled.witness_program_sha256}`);
  assert.equal(compiled.policy_manifest_sha256.length, 64);
  assert.ok(compiled.invariants.every((invariant) => invariant.ok));
});
