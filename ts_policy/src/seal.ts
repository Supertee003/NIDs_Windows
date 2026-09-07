/**
 * ts_policy/src/seal.ts
 *
 * T6 TypeScript Sealing — wraps a compiled IR in a SHA-256 HMAC seal.
 *
 * After sealing, the IR is deep-frozen at runtime (Object.freeze) and
 * the TypeScript type is `Readonly<>` so the compiler rejects mutations.
 * This satisfies the T6 AC: "TypeScript has no direct enforcement or
 * post-signature policy mutation path."
 *
 * The seal is a SHA-256 HMAC over the canonicalized IR. This is NOT
 * Ed25519 (that's the next tier's signing primitive, performed in
 * Rust/Zig over the canonicalized wire bytes). The TS-side seal here
 * is the "frozen and handed off" boundary — analogous to how the Zig
 * `verifyPolicy` rejects rollback by tracking `g_highest_accepted_version`.
 *
 * Architecture note: the canonical IR bytes produced by
 * `canonicalRuleBytes` in `compiler.ts` is the SAME byte stream the
 * Zig `policy_signing.canonicalDigest` is supposed to consume in T7.
 * Both sides must agree on field order and value encoding.
 */
import { createHmac } from "node:crypto";
import { type PolicyIR, type SealedPolicy, type PolicyExpiry } from "./types.js";

// =====================================================================
// Canonical IR bytes for sealing
// =====================================================================

/**
 * Produce the canonical byte stream of the WHOLE IR (header + rules)
 * for sealing. Field order is fixed.
 *
 * Mirrors `core/policy_signing.zig::canonicalDigest` semantics:
 *   header(28 bytes LE) + rules...
 * The TS side serializes a JSON-canonical byte stream (not raw LE) for
 * two reasons:
 *   1. Cross-language safety: Zig `[]const u8` slices inside structs
 *      make `std.mem.asBytes` non-deterministic across processes.
 *   2. Test reproducibility: the JSON form is inspectable in CI logs
 *      and the Python validator.
 * The wire-format reconciliation is tracked as a follow-up (T7).
 */
function canonicalIRBytes(ir: PolicyIR): Buffer {
  const c: string[] = [];
  c.push(`magic=${ir.magic}`);
  c.push(`version=${ir.version}`);
  c.push(`rule_count=${ir.rule_count}`);
  c.push(`hash=${ir.hash}`);
  c.push(`compiled_at_ms=${ir.compiled_at_ms}`);
  c.push(`compiler_version=${ir.compiler_version}`);
  for (const r of ir.rules) {
    c.push(`rule:${r.id}|${r.name}|${r.priority}|${r.action}|${r.enabled ? 1 : 0}|${r.description}`);
    for (const cond of r.conditions) {
      c.push(
        `cond:${cond.field}|${cond.operator}|${cond.value.kind}=${cond.value.value ?? ""}`,
      );
      if (cond.value2 !== undefined) {
        c.push(
          `cond2:${cond.value2.kind}=${cond.value2.value ?? ""}`,
        );
      }
    }
  }
  return Buffer.from(c.join("\n"), "utf8");
}

// =====================================================================
// seal()
// =====================================================================

/**
 * Seal an IR. Returns a deep-frozen `SealedPolicy`.
 *
 * The `signer` argument is treated as a pre-shared identifier (16-char
 * zero-padded, mirroring `core/policy_signing.zig::SignerIdentity`).
 * In production, the signing key never appears in TypeScript — it
 * lives in the Rust signing service. The TS-side seal is a SHA-256
 * HMAC over the IR + signer name; it is NOT a replacement for
 * Ed25519 signing (next tier).
 */
export function seal(
  ir: PolicyIR,
  opts: {
    signer: string;
    sealed_at_ms?: number;
    policy_version: number;
    expiry: PolicyExpiry;
  },
): SealedPolicy {
  // Validate signer
  if (opts.signer.length === 0 || opts.signer.length > 16) {
    throw new Error(`signer must be 1..16 chars, got ${opts.signer.length}`);
  }
  if (!Number.isInteger(opts.policy_version) || opts.policy_version < 0) {
    throw new Error(`policy_version must be a non-negative integer`);
  }

  const signer = opts.signer.padEnd(16, "\0");
  const sealedAt = opts.sealed_at_ms ?? Date.now();

  // HMAC over the canonical IR bytes + signer
  const hmac = createHmac("sha256", signer);
  hmac.update(canonicalIRBytes(ir));
  const digest = hmac.digest();
  // First 8 bytes as u64 (little-endian)
  const sealU64 = Number(digest.readBigUInt64LE(0));

  // Build the SealedPolicy
  const sealed: SealedPolicy = {
    ir,
    seal: sealU64,
    signer,
    sealed_at_ms: sealedAt,
    policy_version: opts.policy_version,
    expiry: opts.expiry,
  };

  // Deep-freeze. This is the runtime half of the "no post-signature
  // mutation" guarantee. In strict mode, the Readonly<> type does
  // the compile-time half.
  deepFreeze(sealed);
  return sealed;
}

// =====================================================================
// verifySeal()
// =====================================================================

/**
 * Verify a sealed policy. Returns the verification status.
 *
 * Mirrors `core/policy_signing.zig::VerificationResult`:
 *   valid, tampered, invalid_signature, unknown_key, expired, rollback
 *
 * The TS side collapses `unknown_key` (no key registry in TS) into
 * `invalid_signature` if the signer doesn't match. Rollback is checked
 * by the caller (the caller owns the "highest accepted version" state).
 */
export enum VerificationResult {
  VALID = "valid",
  TAMPERED = "tampered",
  INVALID_SIGNATURE = "invalid_signature",
  EXPIRED = "expired",
  ROLLBACK = "rollback",
}

export function verifySeal(
  sealed: SealedPolicy,
  expectedSigner: string,
  nowMs: number,
  highestAcceptedVersion: number,
): VerificationResult {
  // 1. Signer must match
  if (sealed.signer !== expectedSigner.padEnd(16, "\0")) {
    return VerificationResult.INVALID_SIGNATURE;
  }
  // 2. Expiry
  if (sealed.expiry.at !== null && nowMs > sealed.expiry.at) {
    return VerificationResult.EXPIRED;
  }
  // 3. Rollback
  if (sealed.policy_version < highestAcceptedVersion) {
    return VerificationResult.ROLLBACK;
  }
  // 4. Recompute the seal
  const hmac = createHmac("sha256", sealed.signer);
  hmac.update(canonicalIRBytes(sealed.ir));
  const expected = Number(hmac.digest().readBigUInt64LE(0));
  if (expected !== sealed.seal) {
    return VerificationResult.TAMPERED;
  }
  return VerificationResult.VALID;
}

// =====================================================================
// deepFreeze
// =====================================================================

/**
 * Recursively freeze an object. Used to enforce the "no post-signature
 * mutation" invariant at runtime (the Readonly<> type is the
 * compile-time half).
 */
function deepFreeze<T>(obj: T): T {
  if (obj === null || typeof obj !== "object") return obj;
  if (Object.isFrozen(obj)) return obj;
  Object.freeze(obj);
  for (const key of Object.keys(obj)) {
    deepFreeze((obj as Record<string, unknown>)[key]);
  }
  return obj;
}
