import assert from "node:assert/strict";
import test from "node:test";
import {
  buildVaultBundle,
  compilePolicy,
  createCapsule,
  runStaticSelfTests,
  type PolicyRequest,
} from "../lib/mimir";

const request: PolicyRequest = {
  format: "mimir-policy-request",
  version: 1,
  network: "regtest",
  template_id: "mimir-absolute-two-path-v1",
  vault_derivation: { branch: 0, index: 0 },
  participants: [
    {
      role: "owner",
      master_fingerprint: "5a3469b6",
      origin_path: "m/48'/1'/0'/2'",
      xpub:
        "tpubDEhFJsryccF9b2PaR3mgUBVfoYbpVaXsmpK6sonC8cysYcpJzYsZfiwkR9JaoiNWCT9o1HN2bFccb2wMnAXGdKpW6nYQukZMZXfF32RnS6y",
    },
    {
      role: "heir",
      master_fingerprint: "1de75e0e",
      origin_path: "m/48'/1'/0'/2'",
      xpub:
        "tpubDEWZ8YQw72Yqbfmhw1g1Xnh6jt41X9vRk7UHmrKkRUWTye9P7R9ZdF894Yn1odHU7FgRPTYxL5dZHafRpbiHVNwyuxJt6pMA37SNWpvwYhX",
    },
  ],
  locks: { owner_unix: 1_893_456_000, heir_unix: 2_051_222_400 },
};

function clonedRequest(): PolicyRequest {
  return structuredClone(request);
}

test("pinned descriptor, Miniscript, canonicalization, and BIP 138 vectors pass", () => {
  const results = runStaticSelfTests();
  assert.ok(results.length >= 6);
  assert.deepEqual(
    results.filter((result) => !result.ok),
    [],
  );
});

test("policy output is deterministic and internally consistent", () => {
  const first = compilePolicy(clonedRequest());
  const second = compilePolicy(clonedRequest());

  assert.equal(first.canonical_manifest, second.canonical_manifest);
  assert.equal(first.policy_manifest_sha256, second.policy_manifest_sha256);
  assert.equal(first.manifest.descriptor.fixed, second.manifest.descriptor.fixed);
  assert.equal(first.manifest.script.witness_script_hex.length / 2, 87);
  assert.match(first.manifest.address, /^bcrt1q/);
  assert.equal(first.manifest.script.script_pubkey_hex, `0020${first.manifest.script.witness_program_sha256}`);
  assert.ok(first.invariants.every((invariant) => invariant.ok));
});

test("capsules are randomized, authenticated, and packaged with all 24 artifacts", () => {
  const compiled = compilePolicy(clonedRequest());
  const first = createCapsule(compiled, "Public executor contact instructions.");
  const second = createCapsule(compiled, "Public executor contact instructions.");
  const bundle = buildVaultBundle(compiled, first);

  assert.equal(new TextDecoder().decode(first.raw_bytes.slice(0, 6)), "BIP138");
  assert.equal(first.raw_bytes[6], 1);
  assert.equal(first.encoded_secret_count, 5);
  assert.deepEqual(first.self_test, {
    owner_can_decrypt: true,
    heir_can_decrypt: true,
    header_valid: true,
  });
  assert.notEqual(first.capsule_sha256, second.capsule_sha256);
  assert.match(first.op_return_script_pubkey_hex, /^6a4d/);
  assert.equal(bundle.artifacts.length, 24);
  assert.equal(bundle.bundle_manifest.artifacts.length, 24);
  assert.ok(bundle.artifacts.every((artifact) => /^[0-9a-f]{64}$/.test(artifact.sha256)));
});

test("private material and malformed public inputs fail closed", () => {
  const privateRequest = clonedRequest();
  privateRequest.participants[0].xpub = `xprv${"A".repeat(100)}`;
  assert.throws(() => compilePolicy(privateRequest), /private extended key/i);

  const depthRequest = clonedRequest();
  depthRequest.participants[0].origin_path = "m/48'/1'/0'";
  assert.throws(() => compilePolicy(depthRequest), /depth/i);

  const orderRequest = clonedRequest();
  orderRequest.locks.owner_unix = orderRequest.locks.heir_unix;
  assert.throws(() => compilePolicy(orderRequest), /strictly earlier/i);

  const limitRequest = clonedRequest();
  limitRequest.locks.heir_unix = 0x80000000;
  assert.throws(() => compilePolicy(limitRequest), /2038-01-19/i);
});
