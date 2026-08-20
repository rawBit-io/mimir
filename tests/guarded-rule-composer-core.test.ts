import assert from "node:assert/strict";
import test from "node:test";
import { compileMiniscript } from "@bitcoinerlab/miniscript";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import {
  MAX_GUARDED_KEYS,
  MAX_GUARDED_RULES,
  TEMPLATE_ID_GUARDED,
  compileGuardedRulePolicy,
  unixFromGuardedRuleDate,
  validateGuardedRulePublicKey,
  type GuardedKey,
  type GuardedNetwork,
  type GuardedRuleComposerRequest,
  type GuardedRuleDefinition,
} from "../lib/guarded-rule-composer";

function publicKey(index: number): string {
  const secret = new Uint8Array(32);
  secret[30] = Math.floor(index / 256);
  secret[31] = index % 256;
  return Buffer.from(secp256k1.getPublicKey(secret, true)).toString("hex");
}

function key(index: number): GuardedKey {
  return {
    id: `input-${index}`,
    label: `Signer ${index}`,
    public_key: publicKey(index),
  };
}

const dates = [
  unixFromGuardedRuleDate("2030-01-01"),
  unixFromGuardedRuleDate("2031-01-01"),
  unixFromGuardedRuleDate("2032-01-01"),
  unixFromGuardedRuleDate("2033-01-01"),
  unixFromGuardedRuleDate("2034-01-01"),
];

function requestWith(
  keys: GuardedKey[],
  rules: GuardedRuleDefinition[],
  network: GuardedNetwork = "regtest",
): GuardedRuleComposerRequest {
  return {
    format: "mimir-guarded-rule-request",
    version: 5,
    network,
    template_id: TEMPLATE_ID_GUARDED,
    keys: structuredClone(keys),
    rules: structuredClone(rules),
  };
}

test("Owner now plus one three-heir ladder compiles to the exact sane guarded Miniscript", () => {
  const keys = [key(1), key(2), key(3), key(4)];
  const rules: GuardedRuleDefinition[] = [
    { key_ids: [keys[0].id], threshold: 1, unlock_unix: null },
    {
      key_ids: keys.slice(1).map((candidate) => candidate.id),
      threshold: 3,
      unlock_unix: dates[0],
    },
    {
      key_ids: keys.slice(1).map((candidate) => candidate.id),
      threshold: 2,
      unlock_unix: dates[1],
    },
    {
      key_ids: keys.slice(1).map((candidate) => candidate.id),
      threshold: 1,
      unlock_unix: dates[2],
    },
  ];
  const compiled = compileGuardedRulePolicy(requestWith(keys, rules));
  const heirKeys = keys
    .slice(1)
    .map((candidate) => candidate.public_key)
    .sort();
  const recovery =
    `and_v(v:after(${dates[0]}),thresh(3,` +
    `pk(${heirKeys[0]}),s:pk(${heirKeys[1]}),s:pk(${heirKeys[2]}),` +
    `sln:after(${dates[1]}),sln:after(${dates[2]})))`;
  assert.equal(
    compiled.miniscript,
    `or_i(pk(${keys[0].public_key}),${recovery})`,
  );
  assert.equal(compiled.manifest.groups.length, 2);
  assert.equal(compiled.manifest.rules.length, 4);
  assert.notStrictEqual(compiled.request.keys, compiled.manifest.keys);
  assert.notStrictEqual(
    compiled.manifest.rules[0],
    compiled.manifest.groups[0].stages[0],
  );
  assert.deepEqual(
    compiled.manifest.groups[1].stages.map((stage) => stage.threshold),
    [3, 2, 1],
  );
  assert.deepEqual(
    compiled.manifest.groups[1].stages.map(
      (stage) => stage.unlock?.unix ?? null,
    ),
    dates.slice(0, 3),
  );
  assert.equal(compiled.manifest.groups[1].miniscript_fragment, recovery);
  // Independently reproduced from the exact ASM with bitcoinjs-lib 7.0.1.
  // Pinning the complete vector catches drift in Mimir's ASM serializer,
  // witness-program hashing, Bech32 encoding, or descriptor checksum.
  assert.equal(
    compiled.witness_script_hex,
    "63210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac670480d8db70b1692102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5ac7c2102e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13ac937c2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac937c63006704000cbd72b19268937c63006704803f9e74b1926893538768",
  );
  assert.equal(
    compiled.script_pubkey_hex,
    "00206dfb6b025f390e46d77457668b5c55eba4ebfa3ea818c949c554f4a5a207a55d",
  );
  assert.equal(
    compiled.address,
    "bcrt1qdhakkqjl8y8yd4m52angkhz4awjwh7374qvvjjw92n62tgs854wscg6sl3",
  );
  assert.equal(
    compiled.descriptor,
    `wsh(or_i(pk(${keys[0].public_key}),${recovery}))#rnqcwsnk`,
  );
  assert.match(compiled.asm, /OP_CHECKLOCKTIMEVERIFY/);
  assert.match(compiled.asm, /OP_ADD/);
  assert.match(compiled.address, /^bcrt1q/);
  assert.ok(compiled.witness_script_bytes < 3_600);
  assert.ok(compiled.invariants.every((invariant) => invariant.ok));
  assert.match(
    compiled.invariants.find(
      (invariant) => invariant.id === "exhaustive-policy-equivalence",
    )?.label ?? "",
    /96 signer\/time boundary cases \(11 symbolic witnesses\)/,
  );

  const independentlyCompiled = compileMiniscript(compiled.miniscript);
  assert.equal(independentlyCompiled.error, null);
  assert.equal(independentlyCompiled.issane, true);
  assert.equal(independentlyCompiled.issanesublevel, true);
  for (const candidate of keys) {
    assert.equal(compiled.miniscript.split(candidate.public_key).length - 1, 1);
  }
});

test("an immediate 3-of-3 to 2-of-3 ladder needs no outer timelock", () => {
  const keys = [key(1), key(2), key(3)];
  const ids = keys.map((candidate) => candidate.id);
  const compiled = compileGuardedRulePolicy(
    requestWith(keys, [
      { key_ids: ids, threshold: 3, unlock_unix: null },
      { key_ids: [...ids].reverse(), threshold: 2, unlock_unix: dates[0] },
    ]),
  );
  const sorted = keys.map((candidate) => candidate.public_key).sort();
  assert.equal(
    compiled.miniscript,
    `thresh(3,pk(${sorted[0]}),s:pk(${sorted[1]}),s:pk(${sorted[2]}),sln:after(${dates[0]}))`,
  );
  assert.doesNotMatch(compiled.miniscript, /^and_v/);
  assert.ok(compiled.invariants.every((invariant) => invariant.ok));
});

test("a threshold drop greater than one emits one identical time credit per dropped signature", () => {
  const keys = [key(1), key(2), key(3)];
  const ids = keys.map((candidate) => candidate.id);
  const compiled = compileGuardedRulePolicy(
    requestWith(keys, [
      { key_ids: ids, threshold: 3, unlock_unix: null },
      { key_ids: ids, threshold: 1, unlock_unix: dates[0] },
    ]),
  );
  const credit = `sln:after(${dates[0]})`;
  assert.equal(compiled.miniscript.split(credit).length - 1, 2);
  assert.deepEqual(
    compiled.manifest.groups[0].stages.map((stage) => stage.threshold),
    [3, 1],
  );
  assert.ok(compiled.invariants.every((invariant) => invariant.ok));
});

test("multiple completely disjoint groups compile as a canonical right-nested OR", () => {
  const keys = [key(1), key(2), key(3), key(4), key(5)];
  const compiled = compileGuardedRulePolicy(
    requestWith(keys, [
      { key_ids: [keys[4].id], threshold: 1, unlock_unix: dates[0] },
      {
        key_ids: [keys[1].id, keys[2].id],
        threshold: 2,
        unlock_unix: null,
      },
      { key_ids: [keys[0].id], threshold: 1, unlock_unix: null },
      {
        key_ids: [keys[1].id, keys[2].id],
        threshold: 1,
        unlock_unix: dates[1],
      },
    ]),
  );
  assert.equal(compiled.manifest.groups.length, 3);
  assert.match(compiled.miniscript, /^or_i\(.+,or_i\(.+,.+\)\)$/);
  assert.deepEqual(
    compiled.manifest.groups.map((group) => group.public_keys.join(",")),
    compiled.manifest.groups
      .map((group) => group.public_keys.join(","))
      .sort(),
  );
  assert.ok(compiled.invariants.every((invariant) => invariant.ok));
  assert.match(
    compiled.warnings.join(" "),
    /1 registered key is not used.*Signer 4/i,
  );
});

test("partially overlapping key sets fail closed", () => {
  const keys = [key(1), key(2), key(3)];
  assert.throws(
    () =>
      compileGuardedRulePolicy(
        requestWith(keys, [
          {
            key_ids: [keys[0].id, keys[1].id],
            threshold: 2,
            unlock_unix: null,
          },
          {
            key_ids: [keys[1].id, keys[2].id],
            threshold: 1,
            unlock_unix: dates[0],
          },
        ]),
      ),
    /completely disjoint|partial key overlap/i,
  );
  assert.throws(
    () =>
      compileGuardedRulePolicy(
        requestWith(keys, [
          {
            key_ids: [keys[0].id, keys[1].id, keys[2].id],
            threshold: 2,
            unlock_unix: null,
          },
          {
            key_ids: [keys[0].id, keys[1].id],
            threshold: 1,
            unlock_unix: dates[0],
          },
        ]),
      ),
    /completely disjoint|partial key overlap/i,
  );
});

test("same-set stages reject duplicate immediacy, dates, and equal or rising thresholds", () => {
  const keys = [key(1), key(2), key(3)];
  const ids = keys.map((candidate) => candidate.id);
  const rejects: Array<[GuardedRuleDefinition[], RegExp]> = [
    [
      [
        { key_ids: ids, threshold: 3, unlock_unix: null },
        { key_ids: ids, threshold: 2, unlock_unix: null },
      ],
      /at most one immediate/i,
    ],
    [
      [
        { key_ids: ids, threshold: 3, unlock_unix: dates[0] },
        { key_ids: ids, threshold: 2, unlock_unix: dates[0] },
      ],
      /distinct unlock dates/i,
    ],
    [
      [
        { key_ids: ids, threshold: 2, unlock_unix: dates[0] },
        { key_ids: ids, threshold: 2, unlock_unix: dates[1] },
      ],
      /strictly decrease/i,
    ],
    [
      [
        { key_ids: ids, threshold: 1, unlock_unix: dates[0] },
        { key_ids: ids, threshold: 2, unlock_unix: dates[1] },
      ],
      /strictly decrease/i,
    ],
  ];
  for (const [rules, error] of rejects) {
    assert.throws(
      () => compileGuardedRulePolicy(requestWith(keys, rules)),
      error,
    );
  }
});

test("bad timestamps, rule/key counts, references, and thresholds fail closed", () => {
  const keys = [key(1), key(2)];
  const base = {
    key_ids: [keys[0].id],
    threshold: 1,
    unlock_unix: null,
  } satisfies GuardedRuleDefinition;
  for (const unlock_unix of [
    499_996_800,
    2_147_558_400,
    dates[0] + 1,
    1.5,
  ]) {
    assert.throws(
      () =>
        compileGuardedRulePolicy(
          requestWith(keys, [{ ...base, unlock_unix }]),
        ),
      /timestamp|2038|whole-day|integer/i,
    );
  }
  assert.throws(
    () => compileGuardedRulePolicy(requestWith([], [base])),
    /cannot be empty/i,
  );
  assert.throws(
    () =>
      compileGuardedRulePolicy(
        requestWith(
          Array.from({ length: 6 }, (_, index) => key(index + 1)),
          [base],
        ),
      ),
    /at most 5 keys/i,
  );
  assert.throws(
    () => compileGuardedRulePolicy(requestWith(keys, [])),
    /at least one spending rule/i,
  );
  assert.throws(
    () =>
      compileGuardedRulePolicy(
        requestWith(keys, Array.from({ length: 6 }, () => ({ ...base }))),
      ),
    /at most 5 rules/i,
  );
  assert.throws(
    () =>
      compileGuardedRulePolicy(
        requestWith(keys, [
          { key_ids: ["missing"], threshold: 1, unlock_unix: null },
        ]),
      ),
    /unknown key ID/i,
  );
  assert.throws(
    () =>
      compileGuardedRulePolicy(
        requestWith(keys, [
          {
            key_ids: [keys[0].id, keys[0].id],
            threshold: 1,
            unlock_unix: null,
          },
        ]),
      ),
    /duplicate key/i,
  );
  assert.throws(
    () =>
      compileGuardedRulePolicy(
        requestWith(keys, [
          {
            key_ids: keys.map((candidate) => candidate.id),
            threshold: 3,
            unlock_unix: null,
          },
        ]),
      ),
    /between 1 and 2/i,
  );
  assert.equal(MAX_GUARDED_KEYS, 5);
  assert.equal(MAX_GUARDED_RULES, 5);
});

test("key order, rule order, selected-key order, and arbitrary input IDs cannot change artifacts", () => {
  const keys = [key(1), key(2), key(3), key(4), key(5)];
  const first = requestWith(keys, [
    { key_ids: [keys[0].id], threshold: 1, unlock_unix: null },
    {
      key_ids: [keys[1].id, keys[2].id, keys[3].id],
      threshold: 3,
      unlock_unix: dates[0],
    },
    {
      key_ids: [keys[1].id, keys[2].id, keys[3].id],
      threshold: 1,
      unlock_unix: dates[2],
    },
  ]);
  const idMap = new Map<string, string>();
  const secondKeys = structuredClone(first.keys).reverse();
  secondKeys.forEach((candidate, index) => {
    const original = candidate.id;
    candidate.id = `arbitrary-${index + 100}`;
    idMap.set(original, candidate.id);
  });
  const secondRules = structuredClone(first.rules)
    .reverse()
    .map((rule) => ({
      ...rule,
      key_ids: rule.key_ids
        .map((id) => idMap.get(id) as string)
        .reverse(),
    }));
  const second = requestWith(secondKeys, secondRules);

  const compiledFirst = compileGuardedRulePolicy(first);
  const compiledSecond = compileGuardedRulePolicy(second);
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
});

test("every single-group shape with up to five keys and five descending stages compiles", () => {
  let shapes = 0;
  for (let keyCount = 1; keyCount <= 5; keyCount += 1) {
    const keys = Array.from({ length: keyCount }, (_, index) => key(index + 1));
    const ids = keys.map((candidate) => candidate.id);
    for (let selection = 1; selection < 2 ** keyCount; selection += 1) {
      const thresholds = Array.from({ length: keyCount }, (_, index) =>
        keyCount - index,
      ).filter((threshold) => (selection & (1 << (threshold - 1))) !== 0);
      for (const immediate of [true, false]) {
        shapes += 1;
        const rules = thresholds.map(
          (threshold, stageIndex): GuardedRuleDefinition => ({
            key_ids: [...ids].reverse(),
            threshold,
            unlock_unix:
              immediate && stageIndex === 0
                ? null
                : dates[stageIndex - (immediate ? 1 : 0)],
          }),
        );
        const compiled = compileGuardedRulePolicy(requestWith(keys, rules));
        assert.ok(compiled.invariants.every((invariant) => invariant.ok));
        assert.equal(compiled.manifest.groups.length, 1);
        assert.deepEqual(
          compiled.manifest.rules.map((rule) => rule.threshold),
          thresholds,
        );
        for (const candidate of keys) {
          assert.equal(
            compiled.miniscript.split(candidate.public_key).length - 1,
            1,
          );
        }
      }
    }
  }
  assert.equal(shapes, 114);
});

test("P2WSH address HRPs follow the selected network", () => {
  const keys = [key(1)];
  const rules = [
    { key_ids: [keys[0].id], threshold: 1, unlock_unix: null },
  ];
  assert.match(
    compileGuardedRulePolicy(requestWith(keys, rules, "bitcoin")).address,
    /^bc1q/,
  );
  assert.match(
    compileGuardedRulePolicy(requestWith(keys, rules, "signet")).address,
    /^tb1q/,
  );
  assert.match(
    compileGuardedRulePolicy(requestWith(keys, rules, "regtest")).address,
    /^bcrt1q/,
  );
});

test("date and public-key helpers validate exact UI inputs", () => {
  assert.equal(unixFromGuardedRuleDate("2030-01-01"), 1_893_456_000);
  assert.equal(unixFromGuardedRuleDate("2038-01-19"), 2_147_472_000);
  for (const invalid of [
    "2030-1-01",
    "2030-01-01T00:00:00Z",
    "2025-02-29",
    "2030-04-31",
    "1985-11-05",
    "2038-01-20",
    "",
  ]) {
    assert.throws(
      () => unixFromGuardedRuleDate(invalid),
      /date|timestamp|limit/i,
    );
  }
  assert.equal(validateGuardedRulePublicKey(publicKey(1)), publicKey(1));
  for (const invalid of ["", "not-a-key", `04${"11".repeat(64)}`]) {
    assert.throws(
      () => validateGuardedRulePublicKey(invalid),
      /compressed.*public key|public key.*compressed/i,
    );
  }
});

test("request envelope and duplicate registry identities are validated", () => {
  const keys = [key(1), key(2)];
  const rules = [
    { key_ids: [keys[0].id], threshold: 1, unlock_unix: null },
  ];
  const wrongFormat = requestWith(keys, rules) as GuardedRuleComposerRequest & {
    format: string;
  };
  wrongFormat.format = "wrong";
  assert.throws(
    () => compileGuardedRulePolicy(wrongFormat),
    /format or version/i,
  );
  const wrongTemplate = requestWith(keys, rules) as GuardedRuleComposerRequest & {
    template_id: string;
  };
  wrongTemplate.template_id = "wrong";
  assert.throws(
    () => compileGuardedRulePolicy(wrongTemplate),
    /unsupported guarded rule policy template/i,
  );
  const wrongNetwork = requestWith(keys, rules) as GuardedRuleComposerRequest & {
    network: string;
  };
  wrongNetwork.network = "testnet";
  assert.throws(
    () => compileGuardedRulePolicy(wrongNetwork),
    /unsupported Bitcoin network/i,
  );

  const duplicateId = structuredClone(keys);
  duplicateId[1].id = duplicateId[0].id;
  assert.throws(
    () => compileGuardedRulePolicy(requestWith(duplicateId, rules)),
    /duplicate ID/i,
  );
  const duplicateLabel = structuredClone(keys);
  duplicateLabel[1].label = duplicateLabel[0].label.toUpperCase();
  assert.throws(
    () => compileGuardedRulePolicy(requestWith(duplicateLabel, rules)),
    /duplicate label/i,
  );
  const duplicatePublicKey = structuredClone(keys);
  duplicatePublicKey[1].public_key = duplicatePublicKey[0].public_key;
  assert.throws(
    () => compileGuardedRulePolicy(requestWith(duplicatePublicKey, rules)),
    /duplicate public key/i,
  );
});
