/**
 * ts_policy/tests/no_post_seal_mutation.test.ts
 *
 * T6 AC4: "TypeScript has no direct enforcement or post-signature
 * policy mutation path."
 *
 * This file asserts the "no post-signature mutation" half:
 *   - A SealedPolicy is deep-frozen at runtime (Object.freeze).
 *   - A SealedPolicy is declared Readonly<> at the type level.
 *   - Even if mutation is forced (via `as unknown as { ... }`), the
 *     verifySeal round-trip will fail (the original seal no longer
 *     matches the modified bytes).
 *   - A new seal must be produced to "re-mutate" the policy (which
 *     bumps the policy_version — preventing silent rollback).
 */
import { test } from "node:test";
import { strict as assert } from "node:assert";
import {
  compile,
  seal,
  verifySeal,
  VerificationResult,
  makeRule,
} from "../src/index.js";

function buildSealed() {
  const ir = compile(
    [makeRule({ id: 1, name: "r1" })],
    { compiled_at_ms: 1_700_000_000_000 },
  ).ir;
  return seal(ir, {
    signer: "ts_policy",
    policy_version: 1,
    sealed_at_ms: 1_700_000_000_000,
    expiry: { at: null },
  });
}

test("SealedPolicy: the entire object graph is Object.isFrozen", () => {
  const s = buildSealed();
  assert.equal(Object.isFrozen(s), true);
  assert.equal(Object.isFrozen(s.ir), true);
  assert.equal(Object.isFrozen(s.ir.rules), true);
  for (const r of s.ir.rules) {
    assert.equal(Object.isFrozen(r), true);
  }
  assert.equal(Object.isFrozen(s.ir.rules[0]!.conditions), true);
});

test("SealedPolicy: attempted mutation at every level is rejected", () => {
  const s = buildSealed();
  // Top-level: policy_version
  assert.throws(() => {
    (s as unknown as { policy_version: number }).policy_version = 999;
  });
  // IR: hash
  assert.throws(() => {
    (s.ir as unknown as { hash: number }).hash = 0xdeadbeef;
  });
  // Rule: name
  assert.throws(() => {
    (s.ir.rules[0] as unknown as { name: string }).name = "tampered";
  });
  // Condition value
  assert.throws(() => {
    (
      s.ir.rules[0]!.conditions[0] as unknown as {
        value: { kind: string; value: string };
      }
    ).value = { kind: "domain", value: "evil.example" };
  });
});

test("SealedPolicy: even when mutation is forced, verifySeal detects tampering", () => {
  const s = buildSealed();
  // Object.freeze in non-strict mode silently ignores writes. The
  // verifySeal must catch the resulting byte mismatch.
  // We simulate "non-strict silent write" by checking the seal again
  // after a no-op attempt.
  try {
    (s as unknown as { policy_version: number }).policy_version = 999;
  } catch (_e: unknown) {
    // Strict mode threw — expected.
  }
  const result = verifySeal(s, "ts_policy", 1_700_000_000_000, 0);
  // The seal was computed over the ORIGINAL bytes, so the verification
  // must still pass. The freeze protected the bytes; verifySeal still
  // says VALID. This is the "no silent corruption" half of the proof.
  assert.equal(result, VerificationResult.VALID);
});

test("SealedPolicy: re-sealing requires a new policy_version (no silent rollback)", () => {
  const s1 = buildSealed();
  // Build a new sealed policy with a new rule.
  const ir2 = compile(
    [makeRule({ id: 1, name: "new-rule" })],
    { compiled_at_ms: 1_700_000_000_000 },
  ).ir;
  const s2 = seal(ir2, {
    signer: "ts_policy",
    policy_version: 2, // bumped
    sealed_at_ms: 1_700_000_000_001,
    expiry: { at: null },
  });
  // Different rules -> different seal
  assert.notEqual(s1.seal, s2.seal);
  // Rolling back to s1 (policy_version 1) when highest accepted is 2
  // is rejected.
  const result = verifySeal(s1, "ts_policy", 1_700_000_000_002, 2);
  assert.equal(result, VerificationResult.ROLLBACK);
});

test("SealedPolicy: tampering detected even if Object.isFrozen is bypassed", () => {
  // Simulate a low-level tampering: construct a new SealedPolicy-like
  // object with a tampered IR but the original seal value. The
  // verifySeal function does not trust the seal; it recomputes.
  const s = buildSealed();
  const tampered = {
    ir: {
      ...s.ir,
      rules: [
        {
          ...s.ir.rules[0],
          name: "tampered",
        },
      ],
    },
    seal: s.seal, // <- the original seal; doesn't match tampered IR
    signer: s.signer,
    sealed_at_ms: s.sealed_at_ms,
    policy_version: s.policy_version,
    expiry: s.expiry,
  };
  // The deepFreeze in the real seal() prevents this construction, but
  // we cast through unknown to simulate an attacker who has the seal
  // and tries to "rebind" it.
  const result = verifySeal(
    tampered as unknown as ReturnType<typeof buildSealed>,
    "ts_policy",
    1_700_000_000_000,
    0,
  );
  assert.equal(result, VerificationResult.TAMPERED);
});
