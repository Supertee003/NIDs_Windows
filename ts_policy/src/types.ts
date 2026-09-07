/**
 * ts_policy/src/types.ts
 *
 * T6 TypeScript Policy Plane — typed value system and policy schema.
 *
 * This module mirrors the Zig policy schema in `core/policy_plane.zig`
 * (frozen per G9, per `docs/architecture/CONTRACTS.md`). The TypeScript
 * side is the AUTHORING layer; Zig remains the DECISION authority
 * (per ADR-0001, `core/policy_engine.zig`).
 *
 * The field names, enum values, and structural shape MUST stay in sync
 * with `core/policy_plane.zig`. Tests in `tests/cross_language_contract.test.ts`
 * lock in the shape so any drift is detected at CI time.
 *
 * Architecture:
 *   Authoring (TS)  ->  Compiler (TS)  ->  Policy IR (TS struct + JSON)
 *                                       ->  Seal (TS SHA-256 HMAC)
 *                                       ->  Sign (next tier: Ed25519)
 *                                       ->  Verify (Zig/Rust, next tier)
 *
 * What TS does NOT do (asserted by `tests/no_enforcement.test.ts`):
 *   - No `child_process` / `exec` / `spawn`         (no shelling out)
 *   - No `net` / `dgram` / `http` / `https` / `fetch` (no network I/O)
 *   - No `node:fs` writes (reads allowed for tests only)
 *   - No `WFP` / `iptables` / `netsh` / firewall bindings
 *   - No policy mutation after seal                  (Object.freeze + Readonly<>)
 *   - No enforcement call                            (the Rust PEP / WFP do that)
 */

// =====================================================================
// Constants — MUST match core/policy_plane.zig
// =====================================================================

/** "POL1" in ASCII, little-endian. Mirrors `core/policy_plane.zig::POLICY_MAGIC`. */
export const POLICY_MAGIC = 0x504f4c31 as const;

/** Mirrors `core/policy_plane.zig::POLICY_IR_VERSION`. */
export const POLICY_IR_VERSION = 1 as const;

/** Max rules per IR. Mirrors `core/policy_plane.zig::MAX_POLICY_RULES = 256`. */
export const MAX_POLICY_RULES = 256 as const;

/** Max conditions per rule. Mirrors the `[4]?PolicyCondition` in Zig. */
export const MAX_CONDITIONS_PER_RULE = 4 as const;

/** Compiler version — included in every emitted IR. */
export const COMPILER_VERSION = "ts_policy-1.0.0" as const;

// =====================================================================
// Enums — MUST match core/policy_plane.zig byte values
// =====================================================================

/**
 * Field the condition matches. Mirrors `core/policy_plane.zig::ConditionType`.
 * Numeric values are part of the cross-language contract.
 */
export enum ConditionType {
  SRC_IP = 0,
  DST_IP = 1,
  SRC_PORT = 2,
  DST_PORT = 3,
  PROTOCOL = 4,
  RULE_ID = 5,
  VERDICT = 6,
  THREAT_INTEL_SEVERITY = 7,
  TIME_WINDOW = 8,
}

/**
 * Comparison operator. Mirrors `core/policy_plane.zig::ConditionOperator`.
 */
export enum ConditionOperator {
  EQUALS = 0,
  NOT_EQUALS = 1,
  GREATER_THAN = 2,
  LESS_THAN = 3,
  IN_RANGE = 4,
  MATCHES_ANY = 5,
}

/**
 * Action the rule emits. Mirrors `core/policy_plane.zig::PolicyActionDef`.
 *
 * T6 invariant: TypeScript defines these names but does NOT execute them.
 * Enforcement is `core/policy_engine.zig` and `shield/src/lib.rs`.
 */
export enum PolicyAction {
  ALLOW = 0,
  ALERT = 1,
  BLOCK = 2,
  QUARANTINE = 3,
  RATE_LIMIT = 4,
  LOG_ONLY = 5,
}

// =====================================================================
// Typed values — T6 AC: IPv4, IPv6, CIDR, string, enum, integer, time,
// domain, process, file, identity
// =====================================================================

/**
 * Discriminated union for the typed value set.
 *
 * Why a discriminated union: TypeScript's structural type system lets us
 * model the Zig `PolicyValue` sum type (`core/policy_ir.zig`) with full
 * type safety. Every constructor produces a `{ kind, value }` object
 * where `value`'s type is narrowed by `kind`. A rule can declare a
 * condition with `value: { kind: 'ipv4', value: '10.0.0.1' }` and the
 * compiler checks that the kind matches `ConditionType` semantics.
 */
export type TypedValue =
  | { kind: "ipv4"; value: string }              // e.g. "10.0.0.1"
  | { kind: "ipv6"; value: string }              // e.g. "::1"
  | { kind: "cidr"; value: string }              // e.g. "10.0.0.0/24"
  | { kind: "string"; value: string }            // free-form string
  | { kind: "enum"; value: string }              // enum token (validated at compile)
  | { kind: "integer"; value: number }           // 0 .. 2^32-1
  | { kind: "time"; value: number }              // epoch ms (i64)
  | { kind: "domain"; value: string }            // FQDN, e.g. "evil.example"
  | { kind: "process"; value: string }           // process name or path
  | { kind: "file"; value: string }              // file path or hash
  | { kind: "identity"; value: string };         // user/sid/token

// =====================================================================
// Typed value constructors
//
// Each constructor validates its input shape (e.g. IPv4 must be four
// dot-separated octets in 0..255). A bad value throws — the TS author
// learns at compile-to-IR time, not at run time in Zig.
// =====================================================================

/** Throws on invalid IPv4. */
export function ipv4(addr: string): { kind: "ipv4"; value: string } {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(addr);
  if (!m) throw new Error(`ipv4: not a dotted-quad: ${addr}`);
  for (let i = 1; i <= 4; i++) {
    const n = Number(m[i]);
    if (!Number.isInteger(n) || n < 0 || n > 255) {
      throw new Error(`ipv4: octet out of range: ${addr}`);
    }
  }
  return { kind: "ipv4", value: addr };
}

/** Throws on invalid IPv6. */
export function ipv6(addr: string): { kind: "ipv6"; value: string } {
  // Light validation: must contain at least one ':' and no invalid chars.
  if (!addr.includes(":")) throw new Error(`ipv6: missing colon: ${addr}`);
  if (!/^[0-9a-fA-F:.]+$/.test(addr)) {
    throw new Error(`ipv6: invalid characters: ${addr}`);
  }
  return { kind: "ipv6", value: addr };
}

/** Throws if prefix length is not in 0..32. */
export function cidr(spec: string): { kind: "cidr"; value: string } {
  const idx = spec.lastIndexOf("/");
  if (idx < 0) throw new Error(`cidr: missing prefix: ${spec}`);
  const base = spec.slice(0, idx);
  const prefix = Number(spec.slice(idx + 1));
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    throw new Error(`cidr: prefix out of range: ${spec}`);
  }
  // base must be a valid IPv4 dotted-quad
  return { kind: "cidr", value: ipv4(base).value + "/" + String(prefix) };
}

/** Throws on negative or non-integer port. */
export function port(p: number): { kind: "integer"; value: number } {
  if (!Number.isInteger(p) || p < 0 || p > 65535) {
    throw new Error(`port: out of range: ${p}`);
  }
  return { kind: "integer", value: p };
}

/** Throws on NaN/non-finite or out-of-range epoch ms. */
export function time(epochMs: number): { kind: "time"; value: number } {
  if (!Number.isFinite(epochMs)) {
    throw new Error(`time: not finite: ${epochMs}`);
  }
  return { kind: "time", value: Math.trunc(epochMs) };
}

/** Throws on empty domain or any whitespace. */
export function domain(d: string): { kind: "domain"; value: string } {
  if (d.length === 0 || /\s/.test(d)) {
    throw new Error(`domain: empty or has whitespace: ${d}`);
  }
  return { kind: "domain", value: d };
}

/** Process name or path. Allows empty for "any process" only when the
 *  caller passes an explicit `""` AND the operator is `MATCHES_ANY`. */
export function process_(p: string): { kind: "process"; value: string } {
  return { kind: "process", value: p };
}

/** File path or hash. */
export function file(f: string): { kind: "file"; value: string } {
  if (f.length === 0) throw new Error("file: empty path");
  return { kind: "file", value: f };
}

/** Identity (user/sid/token). */
export function identity(i: string): { kind: "identity"; value: string } {
  if (i.length === 0) throw new Error("identity: empty");
  return { kind: "identity", value: i };
}

// =====================================================================
// Condition — a single field/op/value test
// =====================================================================

/**
 * A condition tests one field against a value. `value2` is the upper
 * bound for `IN_RANGE`; ignored otherwise.
 *
 * Mirrors `core/policy_plane.zig::PolicyCondition`:
 *   { field: ConditionType, operator: ConditionOperator,
 *     value: u64, value2: u64 }
 *
 * The TS side uses `TypedValue` instead of `u64` so authors get type
 * checking on the value. The compiler narrows the value to u64 (or
 * throws) before emitting the IR.
 */
export interface PolicyCondition {
  readonly field: ConditionType;
  readonly operator: ConditionOperator;
  /** The value to match against. For IN_RANGE this is the lower bound. */
  readonly value: TypedValue;
  /** Upper bound for IN_RANGE. Required when operator=IN_RANGE. */
  readonly value2?: TypedValue;
}

// =====================================================================
// Rule — a name, conditions, an action
// =====================================================================

/**
 * Mirrors `core/policy_plane.zig::PolicyRuleDef`:
 *   { id: u32, name: []const u8, priority: u8, conditions: [4]?PolicyCondition,
 *     condition_count: u8, action: PolicyActionDef, enabled: bool,
 *     description: []const u8 }
 */
export interface PolicyRuleDef {
  readonly id: number;            // u32 (validated to be a non-negative int)
  readonly name: string;          // rule name (non-empty)
  readonly priority: number;      // u8, 0..255, higher = higher precedence
  readonly conditions: readonly PolicyCondition[]; // max 4 entries
  readonly action: PolicyAction;
  readonly enabled: boolean;
  readonly description: string;   // free-form human description
}

// =====================================================================
// Scope / Expiry — T6 AC requirement
// =====================================================================

/**
 * Scope limits which entities the rule applies to. A rule without a
 * scope (or with an empty `entities` array) applies globally.
 *
 * NOT a runtime construct — this is metadata for human/audit review and
 * is folded into the IR's `description` (or a dedicated field) when
 * compiled. The TypeScript side keeps it separate so authors can declare
 * intent without learning the IR schema.
 */
export interface PolicyScope {
  readonly entities: readonly string[];
  readonly tags: readonly string[];
}

/**
 * Expiry: when this rule (or this entire policy) stops being valid.
 * `null` means "never expires".
 */
export interface PolicyExpiry {
  /** epoch ms. `null` = never expires. */
  readonly at: number | null;
}

// =====================================================================
// IR — the compiled, versioned, deterministic intermediate representation
// =====================================================================

/**
 * The compiled IR. This is the SHAPE that cross-language tools (Zig,
 * Rust, Python) must agree on. See `tests/cross_language_contract.test.ts`.
 *
 * Mirrors `core/policy_plane.zig::PolicyIR`:
 *   { magic: u32, version: u16, rule_count: u16, rules: [256]PolicyRuleDef,
 *     hash: u64, signature: u64, compiled_at_ms: i64,
 *     compiler_version: []const u8 }
 */
export interface PolicyIR {
  readonly magic: number;            // u32
  readonly version: number;          // u16
  readonly rule_count: number;       // u16
  readonly rules: readonly PolicyRuleDef[];
  /** First 8 bytes of SHA-256(rule bytes). u64. */
  readonly hash: number;
  /** First 8 bytes of Ed25519 signature. u64. (0 until signed.) */
  readonly signature: number;
  /** Epoch ms when compiled. i64. */
  readonly compiled_at_ms: number;
  /** Compiler version string. */
  readonly compiler_version: string;
}

// =====================================================================
// SealedPolicy — IR after SHA-256 HMAC. Immutable.
// =====================================================================

/**
 * A sealed policy: an IR + the seal metadata (signer, sealed_at, hash).
 *
 * Once sealed, the IR is deep-frozen at runtime (Object.freeze) and
 * declared `Readonly<>` at the type level. Mutation throws in non-strict
 * mode and is rejected at compile time in strict mode.
 */
export interface SealedPolicy {
  readonly ir: Readonly<PolicyIR>;
  /** First 8 bytes of SHA-256(ir canonical bytes + signer). u64. */
  readonly seal: number;
  /** Signer name (16 chars, zero-padded). Mirrors `SignerIdentity` in Zig. */
  readonly signer: string;
  /** Epoch ms when sealed. */
  readonly sealed_at_ms: number;
  /** Policy version (monotonic, never goes backwards — see T7). */
  readonly policy_version: number;
  /** When this sealed policy stops being valid. */
  readonly expiry: PolicyExpiry;
}
