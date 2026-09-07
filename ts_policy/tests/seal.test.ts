/**
 * ts_policy/tests/seal.test.ts
 *
 * T6 AC: "TypeScript has no direct enforcement or post-signature
 * policy mutation path." This file tests the seal half of that
 * guarantee: the IR is frozen after sealing and verifySeal rejects
 * tampering.
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

function buildSealed(opts: { signer?: string; policy_version?: number; at?: number | null } = {}) {
  const ir = compile(
    [
      makeRule({ id: 1, name: "r1" }),
      makeRule({ id: 2, name: "r2" }),
    ],
    { compiled_at_ms: 1_700_000_000_000 },
  ).ir;
  return seal(ir, {
    signer: opts.signer ?? "ts_policy",
    policy_version: opts.policy_version ?? 1,
    sealed_at_ms: 1_700_000_000_000,
    expiry: { at: opts.at ?? null },
  });
}

test("seal: produces a SealedPolicy with non-zero seal", () => {
  const s = buildSealed();
  assert.notEqual(s.seal, 0);
  assert.equal(s.signer, "ts_policy\0\0\0\0\0\0\0");
  assert.equal(s.policy_version, 1);
  assert.equal(s.sealed_at_ms, 1_700_000_000_000);
});

test("seal: the IR is deep-frozen (no post-signature mutation)", () => {
  const s = buildSealed();
  assert.equal(Object.isFrozen(s), true);
  assert.equal(Object.isFrozen(s.ir), true);
  assert.equal(Object.isFrozen(s.ir.rules), true);
  assert.equal(Object.isFrozen(s.ir.rules[0]), true);
});

test("seal: attempts to mutate throw in strict mode (or silently fail)", () => {
  const s = buildSealed();
  // In non-strict mode, assignment silently fails. In strict mode, it
  // throws TypeError. Either way, the value is unchanged.
  const ir = s.ir;
  const beforeName = ir.rules[0]!.name;
  try {
    // Cast through unknown to bypass the Readonly<> type for the test.
    (ir.rules[0] as unknown as { name: string }).name = "tampered";
  } catch (_e: unknown) {
    // Expected in strict mode.
  }
  assert.equal(ir.rules[0]!.name, beforeName);
});

test("seal: signer must be 1..16 chars", () => {
  const ir = compile([makeRule({ id: 1 })], { compiled_at_ms: 1 }).ir;
  assert.throws(() =>
    seal(ir, { signer: "", policy_version: 1, expiry: { at: null } }),
  );
  assert.throws(() =>
    seal(ir, { signer: "x".repeat(17), policy_version: 1, expiry: { at: null } }),
  );
});

test("seal: signer is zero-padded to 16 chars", () => {
  const s = seal(
    compile([makeRule({ id: 1 })], { compiled_at_ms: 1 }).ir,
    { signer: "a", policy_version: 1, expiry: { at: null }, sealed_at_ms: 1 },
  );
  assert.equal(s.signer.length, 16);
  assert.equal(s.signer, "a\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
});

test("verifySeal: same signer + non-expired + non-rollback + untouched -> VALID", () => {
  const s = buildSealed();
  const result = verifySeal(s, "ts_policy", 1_700_000_000_000, 0);
  assert.equal(result, VerificationResult.VALID);
});

test("verifySeal: wrong signer -> INVALID_SIGNATURE", () => {
  const s = buildSealed({ signer: "alice" });
  const result = verifySeal(s, "bob", 1_700_000_000_000, 0);
  assert.equal(result, VerificationResult.INVALID_SIGNATURE);
});

test("verifySeal: expired policy -> EXPIRED", () => {
  const expiryMs = 1_700_000_000_000;
  const s = buildSealed({ at: expiryMs });
  const result = verifySeal(s, "ts_policy", expiryMs + 1, 0);
  assert.equal(result, VerificationResult.EXPIRED);
});

test("verifySeal: not yet expired -> VALID", () => {
  const expiryMs = 1_700_000_000_000;
  const s = buildSealed({ at: expiryMs });
  const result = verifySeal(s, "ts_policy", expiryMs - 1, 0);
  assert.equal(result, VerificationResult.VALID);
});

test("verifySeal: expiry at:null -> never expires", () => {
  const s = buildSealed({ at: null });
  const result = verifySeal(s, "ts_policy", 10_000_000_000_000, 0);
  assert.equal(result, VerificationResult.VALID);
});

test("verifySeal: rollback -> ROLLBACK", () => {
  const s = buildSealed({ policy_version: 5 });
  // Highest accepted is 10, this policy is version 5 -> rollback
  const result = verifySeal(s, "ts_policy", 1_700_000_000_000, 10);
  assert.equal(result, VerificationResult.ROLLBACK);
});

test("verifySeal: policy_version == highest -> VALID (equal is OK, only lower is rollback)", () => {
  const s = buildSealed({ policy_version: 5 });
  const result = verifySeal(s, "ts_policy", 1_700_000_000_000, 5);
  assert.equal(result, VerificationResult.VALID);
});

test("verifySeal: tampered IR -> TAMPERED", () => {
  const s = buildSealed();
  // The deep-frozen object means we can't mutate. Instead, build a
  // second SealedPolicy with a tampered IR (different rules) but
  // the original signer. The seal will not match the canonical bytes.
  const tampered = seal(
    compile([makeRule({ id: 1, name: "different" })], { compiled_at_ms: 1_700_000_000_000 }).ir,
    {
      signer: "ts_policy",
      policy_version: 1,
      sealed_at_ms: 1_700_000_000_000,
      expiry: { at: null },
    },
  );
  // Now copy the seal/signer from the original but keep the tampered IR.
  // The verifySeal will recompute and not match.
  // Use a manual construction to bypass the immutability for testing.
  const tamperedObj = {
    ir: tampered.ir,
    seal: s.seal, // <- original seal, won't match tampered IR
    signer: s.signer,
    sealed_at_ms: s.sealed_at_ms,
    policy_version: s.policy_version,
    expiry: s.expiry,
  };
  const result = verifySeal(
    tamperedObj as unknown as ReturnType<typeof buildSealed>,
    "ts_policy",
    1_700_000_000_000,
    0,
  );
  assert.equal(result, VerificationResult.TAMPERED);
});

test("seal: deterministic for the same input (no Date.now leak)", () => {
  const ir = compile(
    [makeRule({ id: 1, name: "r1" })],
    { compiled_at_ms: 1_700_000_000_000 },
  ).ir;
  const a = seal(ir, {
    signer: "ts_policy",
    policy_version: 1,
    sealed_at_ms: 1_700_000_000_000,
    expiry: { at: null },
  });
  const b = seal(ir, {
    signer: "ts_policy",
    policy_version: 1,
    sealed_at_ms: 1_700_000_000_000,
    expiry: { at: null },
  });
  assert.equal(a.seal, b.seal);
});
