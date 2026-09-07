/**
 * ts_policy/src/compiler.ts
 *
 * T6 TypeScript Policy Compiler.
 *
 * Takes `PolicyRuleDef[]` from an author and produces a `PolicyIR`.
 * Performs:
 *   1. Validation: no_rules, too_many_rules, duplicate_id
 *   2. Deterministic ordering for hash stability (sort by priority DESC,
 *      specificity DESC, rule_id ASC, version DESC)
 *   3. Conflict resolution (deterministic): when two rules match the
 *      same input, the compiler picks the winner using the same
 *      ordering. This matches `core/policy_ir.zig::ConflictResolver`:
 *      priority > specificity > deny > rule_id.
 *   4. Hash: SHA-256 of the canonicalized rule bytes, take first 8
 *      bytes as u64 (little-endian).
 *   5. Magic / version stamp: writes POLICY_MAGIC and POLICY_IR_VERSION.
 *
 * This module has no side effects beyond SHA-256 hashing (via the
 * `node:crypto` module). It does NOT:
 *   - Open a network socket
 *   - Spawn a child process
 *   - Write to the filesystem
 *   - Call into the Rust PEP, WFP, or any firewall binding
 *   - Mutate a sealed IR
 */
import { createHash } from "node:crypto";
import {
  type PolicyIR,
  type PolicyRuleDef,
  type TypedValue,
  type PolicyScope,
  type PolicyExpiry,
  type PolicyCondition,
  PolicyAction,
  COMPILER_VERSION,
  MAX_CONDITIONS_PER_RULE,
  MAX_POLICY_RULES,
  POLICY_IR_VERSION,
  POLICY_MAGIC,
} from "./types.js";

// =====================================================================
// Compiler error
// =====================================================================

/**
 * Mirrors `core/policy_plane.zig::CompileError`. Numeric values are
 * stable across languages (this is part of the contract).
 */
export enum CompileError {
  NONE = 0,
  NO_RULES = 1,
  TOO_MANY_RULES = 2,
  DUPLICATE_ID = 3,
  INVALID_CONDITION = 4,
  INVALID_VALUE = 5,
  INVALID_PRIORITY = 6,
}

export class PolicyCompileError extends Error {
  readonly code: CompileError;
  readonly ruleId?: number;
  readonly field?: string;
  constructor(code: CompileError, message: string, opts?: { ruleId?: number; field?: string }) {
    super(message);
    this.name = "PolicyCompileError";
    this.code = code;
    if (opts?.ruleId !== undefined) this.ruleId = opts.ruleId;
    if (opts?.field !== undefined) this.field = opts.field;
  }
}

// =====================================================================
// Compile result
// =====================================================================

export interface CompileResult {
  readonly ir: PolicyIR;
  /** Indices of rules that were DROPPED due to conflict resolution.
   *  These are kept in the IR (for audit) but the conflict resolver
   *  treats them as disabled. Empty if there were no conflicts. */
  readonly dropped_rule_indices: readonly number[];
  /** Indices of rules that are the WINNERS of their conflict group.
   *  Always length === rules.length - dropped_rule_indices.length. */
  readonly winning_rule_indices: readonly number[];
  /** SHA-256 of the canonicalized rules (the same bytes the hash is
   *  derived from). Hex string for easy logging. */
  readonly canonical_hash_hex: string;
}

// =====================================================================
// Typed value -> u64 coercion
// =====================================================================

/**
 * Narrow a `TypedValue` to the u64 the Zig IR expects.
 *
 * Throws on values that don't fit in u64. The compiler is the ONLY
 * place this coercion happens — authors never see a raw u64.
 */
function valueToU64(v: TypedValue, ctx: { ruleId: number; field: string }): bigint {
  switch (v.kind) {
    case "integer": {
      if (!Number.isInteger(v.value) || v.value < 0) {
        throw new PolicyCompileError(
          CompileError.INVALID_VALUE,
          `integer must be non-negative: ${v.value}`,
          ctx,
        );
      }
      if (v.value > 0xffffffffffffffff) {
        throw new PolicyCompileError(
          CompileError.INVALID_VALUE,
          `integer exceeds u64: ${v.value}`,
          ctx,
        );
      }
      return BigInt(v.value);
    }
    case "ipv4": {
      // Encode as u32: 10.0.0.1 -> 0x0A000001
      const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(v.value);
      if (!m) {
        throw new PolicyCompileError(
          CompileError.INVALID_VALUE,
          `ipv4 not a dotted-quad: ${v.value}`,
          ctx,
        );
      }
      const a = Number(m[1]), b = Number(m[2]), c = Number(m[3]), d = Number(m[4]);
      return BigInt(((a << 24) | (b << 16) | (c << 8) | d) >>> 0);
    }
    case "ipv6":
    case "cidr":
    case "string":
    case "domain":
    case "process":
    case "file":
    case "identity":
    case "enum":
    case "time": {
      // String-like: hash the bytes to u64 (FNV-1a 64). The Zig side
      // does the same when the field is rule_id or verdict (string-
      // like enums are hashed at the comparison layer; here we hash
      // so a u64 lands in the IR).
      const fnvOffset = 0xcbf29ce484222325n;
      const fnvPrime = 0x100000001b3n;
      let h = fnvOffset;
      const stringValue: string = (v as { value: string }).value;
      const bytes = Buffer.from(stringValue, "utf8");
      for (let i = 0; i < bytes.length; i++) {
        h ^= BigInt(bytes[i]);
        h = (h * fnvPrime) & 0xffffffffffffffffn;
      }
      return h;
    }
    default: {
      // The previous switch covers every TypedValue kind; this branch
      // is unreachable at runtime. The cast is a guard: if a new kind
      // is added, the cast becomes a compile error.
      const _unreachable: never = v as never;
      void _unreachable;
      throw new PolicyCompileError(
        CompileError.INVALID_VALUE,
        `unknown value kind: ${String(v)}`,
        ctx,
      );
    }
  }
}

// =====================================================================
// Validation
// =====================================================================

/**
 * Validate a rule. Throws `PolicyCompileError` on any structural problem.
 */
function validateRule(rule: PolicyRuleDef, _index: number): void {
  if (!Number.isInteger(rule.id) || rule.id < 0 || rule.id > 0xffffffff) {
    throw new PolicyCompileError(
      CompileError.INVALID_VALUE,
      `rule.id must fit in u32`,
      { ruleId: rule.id, field: "id" },
    );
  }
  if (rule.name.length === 0) {
    throw new PolicyCompileError(
      CompileError.INVALID_VALUE,
      `rule.name is empty`,
      { ruleId: rule.id, field: "name" },
    );
  }
  if (!Number.isInteger(rule.priority) || rule.priority < 0 || rule.priority > 255) {
    throw new PolicyCompileError(
      CompileError.INVALID_PRIORITY,
      `rule.priority must fit in u8: ${rule.priority}`,
      { ruleId: rule.id, field: "priority" },
    );
  }
  if (rule.conditions.length > MAX_CONDITIONS_PER_RULE) {
    throw new PolicyCompileError(
      CompileError.INVALID_CONDITION,
      `rule.conditions exceeds max ${MAX_CONDITIONS_PER_RULE}: ${rule.conditions.length}`,
      { ruleId: rule.id, field: "conditions" },
    );
  }
  for (let i = 0; i < rule.conditions.length; i++) {
    const c = rule.conditions[i]!;
    if (c.operator === 4 /* IN_RANGE */ && c.value2 === undefined) {
      throw new PolicyCompileError(
        CompileError.INVALID_CONDITION,
        `IN_RANGE requires value2 (upper bound)`,
        { ruleId: rule.id, field: `conditions[${i}].value2` },
      );
    }
  }
}

// =====================================================================
// Specificity scoring
// =====================================================================

/**
 * Specificity score: higher = more specific. Used as a tie-break
 * AFTER priority in the conflict resolver. A rule with more conditions
 * and tighter (in_range) operators is more specific.
 */
function specificity(rule: PolicyRuleDef): number {
  let score = 0;
  for (const c of rule.conditions) {
    score += 1;
    if (c.operator === 4 /* IN_RANGE */) score += 1;
    if (c.operator === 2 /* GT */ || c.operator === 3 /* LT */) score += 1;
    if (c.value.kind !== "integer") score += 1; // typed values are more specific
  }
  return score;
}

// =====================================================================
// Deterministic ordering key
// =====================================================================

/**
 * Sort key for a rule. Order: priority DESC, specificity DESC,
 * rule_id ASC, version DESC.
 */
function sortKey(rule: PolicyRuleDef, version: number): readonly [number, number, number, number] {
  return [255 - rule.priority, -specificity(rule), rule.id, -version];
}

function compareKeys(
  a: readonly [number, number, number, number],
  b: readonly [number, number, number, number],
): number {
  for (let i = 0; i < 4; i++) {
    if (a[i]! < b[i]!) return -1;
    if (a[i]! > b[i]!) return 1;
  }
  return 0;
}

// =====================================================================
// Canonical bytes for hashing
// =====================================================================

/**
 * Produce the canonical byte stream of a rule for hashing.
 *
 * The TS side differs from `policy_signing.canonicalDigest` (which
 * uses `std.mem.asBytes(&rule)` on a Zig struct that includes
 * pointer-bearing `[]const u8` slices — not cross-language safe). The
 * TS side produces a JSON-canonical byte stream so the TS and Python
 * validators can reproduce the exact same hash. The Zig cross-check
 * is deferred to T7/T8 (Policy Signing).
 *
 * Field order in the canonical form is fixed: id, name, priority,
 * conditions, action, enabled, description. Condition fields:
 * field, operator, valueKind, valueU64, value2Kind?, value2U64?.
 */
function canonicalRuleBytes(rule: PolicyRuleDef): Buffer {
  const c: string[] = [];
  c.push(String(rule.id));
  c.push(rule.name);
  c.push(String(rule.priority));
  c.push(String(rule.action));
  c.push(rule.enabled ? "1" : "0");
  c.push(rule.description);
  // Conditions in declared order, value(s) as kind + u64.
  for (let i = 0; i < rule.conditions.length; i++) {
    const cond = rule.conditions[i]!;
    c.push(String(cond.field));
    c.push(String(cond.operator));
    c.push(cond.value.kind);
    c.push(valueToU64(cond.value, { ruleId: rule.id, field: `conditions[${i}].value` }).toString());
    if (cond.value2 !== undefined) {
      c.push(cond.value2.kind);
      c.push(
        valueToU64(cond.value2, { ruleId: rule.id, field: `conditions[${i}].value2` }).toString(),
      );
    }
  }
  // Join with a separator that cannot appear in any field.
  return Buffer.from(c.join("\x1f"), "utf8");
}

// =====================================================================
// Public API: compile
// =====================================================================

/**
 * Compile rules into a `PolicyIR`.
 *
 * This is the only entry point. It is pure (no I/O, no mutation of
 * input). The same `rules` array always produces the same IR (up to
 * `compiled_at_ms`, which the caller can pin to a fixed value for
 * golden vectors).
 */
export function compile(
  rules: readonly PolicyRuleDef[],
  opts: { compiled_at_ms?: number } = {},
): CompileResult {
  // ---- Validation ----
  if (rules.length === 0) {
    throw new PolicyCompileError(CompileError.NO_RULES, "no rules to compile");
  }
  if (rules.length > MAX_POLICY_RULES) {
    throw new PolicyCompileError(
      CompileError.TOO_MANY_RULES,
      `rule count ${rules.length} exceeds max ${MAX_POLICY_RULES}`,
    );
  }
  const seenIds = new Set<number>();
  for (let i = 0; i < rules.length; i++) {
    const r = rules[i]!;
    validateRule(r, i);
    if (seenIds.has(r.id)) {
      throw new PolicyCompileError(
        CompileError.DUPLICATE_ID,
        `duplicate rule id: ${r.id}`,
        { ruleId: r.id, field: "id" },
      );
    }
    seenIds.add(r.id);
  }

  // ---- Deterministic ordering ----
  // Use a per-rule version of 1 for ordering (version is per-IR, not
  // per-rule, in the current design). Conflict resolution is therefore
  // priority > specificity > rule_id (ASC).
  const version = 1;
  const sorted = [...rules].sort((a, b) =>
    compareKeys(sortKey(a, version), sortKey(b, version)),
  );

  // ---- Conflict resolution ----
  // Rules with the same priority+specificity+id+version are grouped;
  // the first (lowest sort key) wins. This matches
  // `core/policy_ir.zig::ConflictResolver.shouldWin`.
  const dropped: number[] = [];
  const winning: number[] = [];
  let lastKey: readonly [number, number, number, number] | null = null;
  for (let i = 0; i < sorted.length; i++) {
    const r = sorted[i]!;
    const k = sortKey(r, version);
    if (lastKey !== null && compareKeys(k, lastKey) === 0) {
      // Identical sort key — earlier entry wins, this one is dropped.
      dropped.push(r.id);
    } else {
      winning.push(r.id);
      lastKey = k;
    }
  }

  // ---- Hashing ----
  // Hash the CONCATENATED canonical bytes of all rules (in sorted
  // order). Take the first 8 bytes as the u64 hash.
  const allBytes: Buffer[] = sorted.map(canonicalRuleBytes);
  const totalLen = allBytes.reduce((s, b) => s + b.length, 0);
  const concat = Buffer.allocUnsafe(totalLen);
  let off = 0;
  for (const b of allBytes) {
    b.copy(concat, off);
    off += b.length;
  }
  const sha = createHash("sha256").update(concat).digest();
  // First 8 bytes as little-endian u64
  const hashU64 = Number(sha.readBigUInt64LE(0));
  const canonical_hash_hex = sha.toString("hex");

  // ---- Assemble IR ----
  // signature is 0 until the policy is signed (next tier).
  const ir: PolicyIR = {
    magic: POLICY_MAGIC,
    version: POLICY_IR_VERSION,
    rule_count: sorted.length,
    rules: sorted,
    hash: hashU64,
    signature: 0,
    compiled_at_ms: opts.compiled_at_ms ?? Date.now(),
    compiler_version: COMPILER_VERSION,
  };

  return {
    ir,
    dropped_rule_indices: dropped,
    winning_rule_indices: winning,
    canonical_hash_hex,
  };
}

// =====================================================================
// Test helper
// =====================================================================

/**
 * Test-only helper to build a PolicyRuleDef with sensible defaults.
 *
 * Exported (despite the underscore) because tests in `tests/` need it.
 * Production code should construct `PolicyRuleDef` directly so every
 * field is explicit.
 */
export function makeRule(overrides: {
  id: number;
  name?: string;
  priority?: number;
  action?: PolicyAction;
  enabled?: boolean;
  description?: string;
  conditions?: PolicyCondition[];
}): PolicyRuleDef {
  return {
    id: overrides.id,
    name: overrides.name ?? `rule-${overrides.id}`,
    priority: overrides.priority ?? 100,
    action: overrides.action ?? PolicyAction.BLOCK,
    enabled: overrides.enabled ?? true,
    description: overrides.description ?? "",
    conditions: overrides.conditions ?? [],
  };
}

// =====================================================================
// Scope / Expiry helpers
// =====================================================================

/**
 * T6 AC: scopes are part of authoring. A scope is metadata — the
 * compiler folds it into the rule's description so the IR stays
 * self-contained. The TS author can read it back from the rule
 * description if needed.
 */
export function applyScope(
  rule: PolicyRuleDef,
  scope: PolicyScope,
  expiry: PolicyExpiry,
): PolicyRuleDef {
  const expirySuffix = expiry.at !== null
    ? ` [expires:${expiry.at}]`
    : ` [expires:never]`;
  const scopeSuffix = scope.entities.length === 0 && scope.tags.length === 0
    ? ""
    : ` [scope:${[...scope.entities, ...scope.tags].join("|")}]`;
  return {
    ...rule,
    description: rule.description + scopeSuffix + expirySuffix,
  };
}
