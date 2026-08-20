import assert from "node:assert/strict";
import test from "node:test";
import { compileMiniscript } from "@bitcoinerlab/miniscript";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import {
  MAX_RECOVERY_TEMPLATE_PATHS,
  MAX_RECOVERY_TEMPLATE_SIGNERS,
  TEMPLATE_ID_RECOVERY,
  compileRecoveryTemplate,
  unixFromRecoveryDate,
  validateRecoveryPublicKey,
  type RecoveryNetwork,
  type RecoverySigner,
  type RecoveryTemplateRequest,
} from "../lib/recovery-template";

function publicKey(index: number): string {
  const secret = new Uint8Array(32);
  secret[30] = Math.floor(index / 256);
  secret[31] = index % 256;
  return Buffer.from(secp256k1.getPublicKey(secret, true)).toString("hex");
}

function signer(
  index: number,
  group: RecoverySigner["group"],
): RecoverySigner {
  return {
    id: `input-${index}`,
    label: `${group === "primary" ? "Primary" : "Recovery"} ${index}`,
    public_key: publicKey(index),
    group,
  };
}

const dates = [
  unixFromRecoveryDate("2030-01-01"),
  unixFromRecoveryDate("2031-01-01"),
  unixFromRecoveryDate("2032-01-01"),
  unixFromRecoveryDate("2033-01-01"),
];

function requestWith(
  signers: RecoverySigner[],
  primaryThreshold = 1,
  recoveryDates = dates.slice(
    0,
    signers.filter((candidate) => candidate.group === "recovery").length,
  ),
  network: RecoveryNetwork = "regtest",
): RecoveryTemplateRequest {
  return {
    format: "mimir-recovery-request",
    version: 4,
    network,
    template_id: TEMPLATE_ID_RECOVERY,
    signers: structuredClone(signers),
    primary_threshold: primaryThreshold,
    recovery_dates: [...recoveryDates],
  };
}

test("the full 1 + 4 template compiles five logical paths into one sane P2WSH ladder", () => {
  const input = [
    signer(1, "primary"),
    signer(2, "recovery"),
    signer(3, "recovery"),
    signer(4, "recovery"),
    signer(5, "recovery"),
  ];
  const compiled = compileRecoveryTemplate(requestWith(input));
  const primaryKey = input[0].public_key;
  const recoveryKeys = input
    .slice(1)
    .map((candidate) => candidate.public_key)
    .sort();
  const expectedRecovery =
    `and_v(v:after(${dates[0]}),thresh(4,` +
    `pk(${recoveryKeys[0]}),` +
    recoveryKeys
      .slice(1)
      .map((key) => `s:pk(${key})`)
      .join(",") +
    `,sln:after(${dates[1]}),sln:after(${dates[2]}),sln:after(${dates[3]})))`;

  assert.equal(
    compiled.miniscript,
    `or_i(pk(${primaryKey}),${expectedRecovery})`,
  );
  assert.equal(compiled.manifest.logical_paths.length, 5);
  assert.deepEqual(
    compiled.manifest.logical_paths.map((path) => path.threshold),
    [1, 4, 3, 2, 1],
  );
  assert.deepEqual(
    compiled.manifest.recovery.stages.map((stage) => stage.unlock.unix),
    dates,
  );
  assert.equal(compiled.manifest.primary.miniscript_fragment, `pk(${primaryKey})`);
  assert.equal(compiled.manifest.recovery.miniscript_fragment, expectedRecovery);
  assert.match(compiled.descriptor, /^wsh\(.+\)#[a-z0-9]{8}$/);
  assert.match(compiled.asm, /OP_CHECKLOCKTIMEVERIFY/);
  assert.match(compiled.asm, /OP_ADD/);
  assert.match(compiled.address, /^bcrt1q/);
  assert.ok(compiled.witness_script_bytes < 3_600);
  assert.ok(compiled.invariants.every((invariant) => invariant.ok));
  assert.match(
    compiled.invariants.find(
      (invariant) => invariant.id === "exhaustive-policy-equivalence",
    )?.label ?? "",
    /256 signer\/time cases/,
  );

  const independentlyCompiled = compileMiniscript(compiled.miniscript);
  assert.equal(independentlyCompiled.error, null);
  assert.equal(independentlyCompiled.issane, true);
  assert.equal(independentlyCompiled.issanesublevel, true);
  for (const candidate of input) {
    assert.equal(compiled.miniscript.split(candidate.public_key).length - 1, 1);
  }
});

test("a primary multisig and a three-signer recovery group remain within 5×5", () => {
  const input = [
    signer(1, "primary"),
    signer(2, "primary"),
    signer(3, "recovery"),
    signer(4, "recovery"),
    signer(5, "recovery"),
  ];
  const compiled = compileRecoveryTemplate(requestWith(input, 2));

  assert.match(compiled.manifest.primary.miniscript_fragment, /^multi\(2,/);
  assert.deepEqual(
    compiled.manifest.logical_paths.map((path) => path.threshold),
    [2, 3, 2, 1],
  );
  assert.equal(compiled.manifest.logical_paths.length, 4);
  assert.equal(MAX_RECOVERY_TEMPLATE_SIGNERS, 5);
  assert.equal(MAX_RECOVERY_TEMPLATE_PATHS, 5);
  assert.match(
    compiled.invariants.find(
      (invariant) => invariant.id === "exhaustive-policy-equivalence",
    )?.label ?? "",
    /192 signer\/time cases/,
  );
  assert.ok(compiled.invariants.every((invariant) => invariant.ok));
});

test("all 20 supported signer-group and Primary-threshold shapes compile", () => {
  let configurations = 0;
  for (let signerCount = 2; signerCount <= 5; signerCount += 1) {
    for (
      let primaryCount = 1;
      primaryCount < signerCount;
      primaryCount += 1
    ) {
      const input = Array.from({ length: signerCount }, (_, index) =>
        signer(
          index + 1,
          index < primaryCount ? "primary" : "recovery",
        ),
      );
      for (let threshold = 1; threshold <= primaryCount; threshold += 1) {
        configurations += 1;
        const compiled = compileRecoveryTemplate(
          requestWith(input, threshold),
        );
        assert.equal(
          compiled.manifest.logical_paths.length,
          1 + signerCount - primaryCount,
        );
        assert.ok(compiled.invariants.every((invariant) => invariant.ok));
        assert.match(
          compiled.invariants.find(
            (invariant) => invariant.id === "exhaustive-policy-equivalence",
          )?.label ?? "",
          /Generated Miniscript satisfactions.*symbolic witnesses/,
        );
      }
    }
  }
  assert.equal(configurations, 20);
});

test("a one-signer recovery group uses the minimal timed pk branch", () => {
  const input = [signer(1, "primary"), signer(2, "recovery")];
  const compiled = compileRecoveryTemplate(requestWith(input));
  const primaryKey = input[0].public_key;
  const recoveryKey = input[1].public_key;

  assert.equal(
    compiled.miniscript,
    `or_i(pk(${primaryKey}),and_v(v:after(${dates[0]}),pk(${recoveryKey})))`,
  );
  assert.deepEqual(
    compiled.manifest.logical_paths.map((path) => path.threshold),
    [1, 1],
  );
  assert.ok(compiled.invariants.every((invariant) => invariant.ok));
});

test("signer order and arbitrary input IDs cannot change canonical artifacts", () => {
  const first = requestWith([
    signer(1, "primary"),
    signer(2, "recovery"),
    signer(3, "recovery"),
    signer(4, "recovery"),
    signer(5, "recovery"),
  ]);
  const second = structuredClone(first);
  second.signers.forEach((candidate, index) => {
    candidate.id = `arbitrary-${101 + index}`;
  });
  second.signers.reverse();

  const compiledFirst = compileRecoveryTemplate(first);
  const compiledSecond = compileRecoveryTemplate(second);

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
  assert.deepEqual(
    compiledFirst.request.signers.map((candidate) => candidate.public_key),
    compiledFirst.request.signers
      .map((candidate) => candidate.public_key)
      .sort(),
  );
});

test("date conversion is exact, whole-day UTC, and bounded by after()", () => {
  assert.equal(unixFromRecoveryDate("2030-01-01"), 1_893_456_000);
  assert.equal(unixFromRecoveryDate("2038-01-19"), 2_147_472_000);

  for (const invalid of [
    "2030-1-01",
    "2030-01-01T00:00:00Z",
    "2025-02-29",
    "2030-04-31",
    "1985-11-05",
    "2038-01-20",
    "",
  ]) {
    assert.throws(() => unixFromRecoveryDate(invalid), /date|timestamp|limit/i);
  }
});

test("invalid signer counts, groups, identities, and public keys fail closed", () => {
  assert.throws(
    () => compileRecoveryTemplate(requestWith([signer(1, "primary")], 1, [])),
    /between 2 and 5 signers/i,
  );
  assert.throws(
    () =>
      compileRecoveryTemplate(
        requestWith([
          signer(1, "primary"),
          signer(2, "recovery"),
          signer(3, "recovery"),
          signer(4, "recovery"),
          signer(5, "recovery"),
          signer(6, "recovery"),
        ]),
      ),
    /between 2 and 5 signers/i,
  );
  assert.throws(
    () =>
      compileRecoveryTemplate(
        requestWith([signer(1, "primary"), signer(2, "primary")], 1, []),
      ),
    /at least one primary signer and one recovery signer/i,
  );
  assert.throws(
    () =>
      compileRecoveryTemplate(
        requestWith(
          [signer(1, "recovery"), signer(2, "recovery")],
          1,
          dates.slice(0, 2),
        ),
      ),
    /at least one primary signer and one recovery signer/i,
  );

  for (const field of ["id", "label", "public_key"] as const) {
    const request = requestWith([
      signer(1, "primary"),
      signer(2, "recovery"),
    ]);
    request.signers[1][field] = request.signers[0][field];
    assert.throws(() => compileRecoveryTemplate(request), /duplicate/i);
  }
  const badKeyRequest = requestWith([
    signer(1, "primary"),
    signer(2, "recovery"),
  ]);
  badKeyRequest.signers[1].public_key = `04${"11".repeat(64)}`;
  assert.throws(() => compileRecoveryTemplate(badKeyRequest), /compressed/i);
  assert.throws(() => validateRecoveryPublicKey("02" + "00".repeat(32)));

  const badGroup = requestWith([
    signer(1, "primary"),
    signer(2, "recovery"),
  ]);
  badGroup.signers[1].group = "other" as RecoverySigner["group"];
  assert.throws(() => compileRecoveryTemplate(badGroup), /primary or recovery/i);
});

test("invalid primary thresholds and recovery schedules fail closed", () => {
  const baseSigners = [
    signer(1, "primary"),
    signer(2, "recovery"),
    signer(3, "recovery"),
  ];
  for (const threshold of [0, 2, 1.5]) {
    assert.throws(
      () => compileRecoveryTemplate(requestWith(baseSigners, threshold)),
      /primary threshold/i,
    );
  }
  assert.throws(
    () => compileRecoveryTemplate(requestWith(baseSigners, 1, [dates[0]])),
    /exactly 2 staged recovery dates/i,
  );
  assert.throws(
    () =>
      compileRecoveryTemplate(
        requestWith(baseSigners, 1, [dates[0], dates[0]]),
      ),
    /strictly increasing/i,
  );
  assert.throws(
    () =>
      compileRecoveryTemplate(
        requestWith(baseSigners, 1, [dates[1], dates[0]]),
      ),
    /strictly increasing/i,
  );
  assert.throws(
    () =>
      compileRecoveryTemplate(
        requestWith(baseSigners, 1, [dates[0] + 1, dates[1]]),
      ),
    /whole-day granularity/i,
  );
  assert.throws(
    () =>
      compileRecoveryTemplate(
        requestWith(baseSigners, 1, [dates[0] + 0.5, dates[1]]),
      ),
    /integer Unix timestamp/i,
  );
});

test("request envelopes and network-specific P2WSH addresses are checked", () => {
  const input = [
    signer(1, "primary"),
    signer(2, "recovery"),
    signer(3, "recovery"),
  ];
  const addresses = new Map<RecoveryNetwork, string>();
  for (const network of ["bitcoin", "signet", "regtest"] as const) {
    const compiled = compileRecoveryTemplate(requestWith(input, 1, undefined, network));
    addresses.set(network, compiled.address);
    assert.ok(compiled.invariants.every((invariant) => invariant.ok));
  }
  assert.match(addresses.get("bitcoin") ?? "", /^bc1q/);
  assert.match(addresses.get("signet") ?? "", /^tb1q/);
  assert.match(addresses.get("regtest") ?? "", /^bcrt1q/);

  const invalids = [
    { field: "format", value: "other" },
    { field: "version", value: 5 },
    { field: "template_id", value: "other" },
    { field: "network", value: "testnet" },
  ] as const;
  for (const invalid of invalids) {
    const request = requestWith(input) as unknown as Record<string, unknown>;
    request[invalid.field] = invalid.value;
    assert.throws(
      () => compileRecoveryTemplate(request as unknown as RecoveryTemplateRequest),
      /unsupported/i,
    );
  }
});
