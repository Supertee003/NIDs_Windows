/**
 * ts_policy/src/canonical_policy_bytes_v1.ts
 *
 * Versioned canonical policy byte encoder (S4). Pure and advisory only.
 * See shared/policy/policy_canonical_v1.md. This module is intentionally
 * additive: it does not change compiler.ts, seal.ts, or the Ed25519 sidecar.
 */
import { createHash } from "node:crypto";

export interface CanonicalConditionV1 {
  readonly field: number;
  readonly operator: number;
  readonly value: bigint;
  readonly value2: bigint;
}

export interface CanonicalRuleV1 {
  readonly id: number;
  readonly name: string;
  readonly priority: number;
  readonly action: number;
  readonly enabled: boolean;
  readonly description: string;
  readonly conditions: readonly CanonicalConditionV1[];
}

export interface CanonicalSignatureInputV1 {
  readonly irMagic: number;
  readonly irVersion: number;
  readonly irHash: bigint;
  readonly policyVersion: number;
  readonly expiryMs: bigint;
  readonly rules: readonly CanonicalRuleV1[];
}

const U32_MAX = 0xffffffffn;
const U64_MAX = 0xffffffffffffffffn;
const MAX_STRING_BYTES = 256;
const MAX_RULES = 64;
const MAX_CONDITIONS = 4;

function requireU32(value: number, field: string): number {
  if (!Number.isInteger(value) || value < 0 || BigInt(value) > U32_MAX) {
    throw new Error(`${field} must fit u32`);
  }
  return value;
}

function requireU16(value: number, field: string): number {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
    throw new Error(`${field} must fit u16`);
  }
  return value;
}

function requireU8(value: number, maximum: number, field: string): number {
  if (!Number.isInteger(value) || value < 0 || value > maximum) {
    throw new Error(`${field} must be in 0..${maximum}`);
  }
  return value;
}

function requireU64(value: bigint, field: string): bigint {
  if (typeof value !== "bigint" || value < 0n || value > U64_MAX) {
    throw new Error(`${field} must fit u64`);
  }
  return value;
}

function requireI64(value: bigint, field: string): bigint {
  if (typeof value !== "bigint") {
    throw new Error(`${field} must be a bigint`);
  }
  const min = -(1n << 63n);
  const max = (1n << 63n) - 1n;
  if (value < min || value > max) {
    throw new Error(`${field} must fit i64`);
  }
  return value;
}

function encodeString(value: string, field: string): Buffer {
  if (typeof value !== "string") {
    throw new Error(`${field} must be a string`);
  }
  const bytes = Buffer.from(value, "utf8");
  if (bytes.length > MAX_STRING_BYTES) {
    throw new Error(`${field} exceeds ${MAX_STRING_BYTES} UTF-8 bytes`);
  }
  return bytes;
}

/** Encode one representation-B rule into `PC01RULE` canonical bytes. */
export function canonicalRuleBytesV1(rule: CanonicalRuleV1): Buffer {
  if (rule === null || typeof rule !== "object") {
    throw new Error("rule must be an object");
  }
  const conditions = rule.conditions;
  if (!Array.isArray(conditions)) {
    throw new Error("conditions must be an array");
  }
  if (conditions.length > MAX_CONDITIONS) {
    throw new Error(`conditions exceed ${MAX_CONDITIONS}`);
  }
  const name = encodeString(rule.name, "name");
  const description = encodeString(rule.description, "description");
  const total =
    12 + 8 + 4 + name.length + 4 + description.length + conditions.length * 18;
  const buf = Buffer.alloc(total);
  let off = 0;
  buf.write("PC01RULE", off, "ascii");
  off += 8;
  buf.writeUInt16LE(1, off);
  off += 2;
  buf.writeUInt16LE(0, off);
  off += 2;
  buf.writeUInt32LE(requireU32(rule.id, "id"), off);
  off += 4;
  buf.writeUInt8(requireU8(rule.priority, 0xff, "priority"), off++);
  buf.writeUInt8(requireU8(rule.action, 5, "action"), off++);
  if (typeof rule.enabled !== "boolean") {
    throw new Error("enabled must be a boolean");
  }
  buf.writeUInt8(rule.enabled ? 1 : 0, off++);
  buf.writeUInt8(requireU8(conditions.length, MAX_CONDITIONS, "condition_count"), off++);
  buf.writeUInt32LE(name.length, off);
  off += 4;
  name.copy(buf, off);
  off += name.length;
  buf.writeUInt32LE(description.length, off);
  off += 4;
  description.copy(buf, off);
  off += description.length;
  for (let i = 0; i < conditions.length; i++) {
    const cond = conditions[i]!;
    buf.writeUInt8(requireU8(cond.field, 8, `conditions[${i}].field`), off++);
    buf.writeUInt8(requireU8(cond.operator, 5, `conditions[${i}].operator`), off++);
    buf.writeBigUInt64LE(requireU64(cond.value, `conditions[${i}].value`), off);
    off += 8;
    buf.writeBigUInt64LE(requireU64(cond.value2, `conditions[${i}].value2`), off);
    off += 8;
  }
  return buf;
}

function requireRules(rules: readonly CanonicalRuleV1[]): readonly CanonicalRuleV1[] {
  if (!Array.isArray(rules) || rules.length < 1 || rules.length > MAX_RULES) {
    throw new Error(`rule count must be 1..${MAX_RULES}`);
  }
  return rules;
}

/** Versioned rule-set digest pre-image. */
export function canonicalRuleSetBytesV1(rules: readonly CanonicalRuleV1[]): Buffer {
  const list = requireRules(rules);
  const ruleBytes = list.map(canonicalRuleBytesV1);
  const size = 16 + ruleBytes.reduce((sum, bytes) => sum + bytes.length, 0);
  const buf = Buffer.alloc(size);
  let off = 0;
  buf.write("PC01SETS", off, "ascii");
  off += 8;
  buf.writeUInt16LE(1, off);
  off += 2;
  buf.writeUInt16LE(0, off);
  off += 2;
  buf.writeUInt32LE(list.length, off);
  off += 4;
  for (const bytes of ruleBytes) {
    bytes.copy(buf, off);
    off += bytes.length;
  }
  return buf;
}

export function policyRuleSetDigestV1(rules: readonly CanonicalRuleV1[]): Buffer {
  return createHash("sha256").update(canonicalRuleSetBytesV1(rules)).digest();
}

/** Versioned signed-policy digest pre-image. */
export function canonicalSignatureBytesV1(input: CanonicalSignatureInputV1): Buffer {
  const rules = requireRules(input.rules);
  const ruleBytes = rules.map(canonicalRuleBytesV1);
  const size = 40 + ruleBytes.reduce((sum, bytes) => sum + bytes.length, 0);
  const buf = Buffer.alloc(size);
  let off = 0;
  buf.write("PC01SIGN", off, "ascii");
  off += 8;
  buf.writeUInt16LE(1, off);
  off += 2;
  buf.writeUInt16LE(0, off);
  off += 2;
  buf.writeUInt32LE(requireU32(input.irMagic, "irMagic"), off);
  off += 4;
  buf.writeUInt16LE(requireU16(input.irVersion, "irVersion"), off);
  off += 2;
  buf.writeUInt16LE(rules.length, off);
  off += 2;
  buf.writeBigUInt64LE(requireU64(input.irHash, "irHash"), off);
  off += 8;
  buf.writeUInt32LE(requireU32(input.policyVersion, "policyVersion"), off);
  off += 4;
  buf.writeBigInt64LE(requireI64(input.expiryMs, "expiryMs"), off);
  off += 8;
  for (const bytes of ruleBytes) {
    bytes.copy(buf, off);
    off += bytes.length;
  }
  return buf;
}

export function canonicalSignatureDigestV1(input: CanonicalSignatureInputV1): Buffer {
  return createHash("sha256").update(canonicalSignatureBytesV1(input)).digest();
}
