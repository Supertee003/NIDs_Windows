/**
 * ts_policy/tests/compiler.test.ts
 *
 * T6 AC: "A policy can be authored in TypeScript and compiled to a
 * typed Policy IR" + "conflict resolution is deterministic
 * (priority/specificity/rule_id/version)".
 */
import { test } from "node:test";
import { strict as assert } from "node:assert";
import {
  compile,
  PolicyCompileError,
  CompileError,
  applyScope,
  makeRule,
  ipv4,
  port,
  domain,
  ConditionType,
  ConditionOperator,
  PolicyAction,
  COMPILER_VERSION,
  POLICY_MAGIC,
  POLICY_IR_VERSION,
  MAX_POLICY_RULES,
} from "../src/index.js";

// ---- Helpers ----

function makeCond(
  field: ConditionType,
  operator: ConditionOperator,
  value: ReturnType<typeof ipv4> | ReturnType<typeof port> | ReturnType<typeof domain>,
  value2?: ReturnType<typeof ipv4> | ReturnType<typeof port>,
) {
  const c: { field: ConditionType; operator: ConditionOperator; value: typeof value; value2?: typeof value2 } = {
    field,
    operator,
    value,
  };
  if (value2 !== undefined) c.value2 = value2;
  return c;
}

// ---- Tests ----

test("compile: empty list -> NO_RULES", () => {
  assert.throws(() => compile([]), (err: unknown) => {
    return err instanceof PolicyCompileError && err.code === CompileError.NO_RULES;
  });
});

test("compile: too many rules -> TOO_MANY_RULES", () => {
  const rules = Array.from({ length: MAX_POLICY_RULES + 1 }, (_, i) =>
    makeRule({ id: i, name: `r-${i}` }),
  );
  assert.throws(() => compile(rules), (err: unknown) => {
    return err instanceof PolicyCompileError && err.code === CompileError.TOO_MANY_RULES;
  });
});

test("compile: duplicate rule id -> DUPLICATE_ID", () => {
  const rules = [makeRule({ id: 1 }), makeRule({ id: 1 })];
  assert.throws(() => compile(rules), (err: unknown) => {
    return err instanceof PolicyCompileError && err.code === CompileError.DUPLICATE_ID;
  });
});

test("compile: invalid priority -> INVALID_PRIORITY", () => {
  const rules = [makeRule({ id: 1, priority: 256 })];
  assert.throws(() => compile(rules), (err: unknown) => {
    return err instanceof PolicyCompileError && err.code === CompileError.INVALID_PRIORITY;
  });
  const neg = [makeRule({ id: 1, priority: -1 })];
  assert.throws(() => compile(neg), (err: unknown) => {
    return err instanceof PolicyCompileError && err.code === CompileError.INVALID_PRIORITY;
  });
});

test("compile: IN_RANGE without value2 -> INVALID_CONDITION", () => {
  const rules = [
    makeRule({
      id: 1,
      conditions: [makeCond(ConditionType.SRC_PORT, ConditionOperator.IN_RANGE, port(0))],
    }),
  ];
  assert.throws(() => compile(rules), (err: unknown) => {
    return err instanceof PolicyCompileError && err.code === CompileError.INVALID_CONDITION;
  });
});

test("compile: too many conditions per rule -> INVALID_CONDITION", () => {
  const conditions = Array.from({ length: 5 }, () =>
    makeCond(ConditionType.SRC_PORT, ConditionOperator.EQUALS, port(80)),
  );
  const rules = [makeRule({ id: 1, conditions })];
  assert.throws(() => compile(rules), (err: unknown) => {
    return err instanceof PolicyCompileError && err.code === CompileError.INVALID_CONDITION;
  });
});

test("compile: valid single rule -> IR with magic and version", () => {
  const rules = [
    makeRule({
      id: 1,
      name: "block-loopback",
      priority: 200,
      action: PolicyAction.BLOCK,
      description: "block traffic from loopback",
      conditions: [makeCond(ConditionType.SRC_IP, ConditionOperator.EQUALS, ipv4("127.0.0.1"))],
    }),
  ];
  const result = compile(rules, { compiled_at_ms: 1_700_000_000_000 });
  assert.equal(result.ir.magic, POLICY_MAGIC);
  assert.equal(result.ir.version, POLICY_IR_VERSION);
  assert.equal(result.ir.rule_count, 1);
  assert.equal(result.ir.rules.length, 1);
  assert.equal(result.ir.rules[0]!.id, 1);
  assert.equal(result.ir.rules[0]!.name, "block-loopback");
  assert.equal(result.ir.compiler_version, COMPILER_VERSION);
  assert.equal(result.ir.compiled_at_ms, 1_700_000_000_000);
  assert.equal(result.ir.signature, 0); // unsigned
  assert.notEqual(result.ir.hash, 0); // hash is non-zero
  assert.equal(result.ir.rules[0]!.conditions.length, 1);
});

test("compile: hash is deterministic for the same input", () => {
  const rules = [
    makeRule({
      id: 1,
      conditions: [makeCond(ConditionType.SRC_IP, ConditionOperator.EQUALS, ipv4("10.0.0.1"))],
    }),
  ];
  const a = compile(rules, { compiled_at_ms: 1 });
  const b = compile(rules, { compiled_at_ms: 1 });
  assert.equal(a.ir.hash, b.ir.hash);
  assert.equal(a.canonical_hash_hex, b.canonical_hash_hex);
});

test("compile: different inputs produce different hashes", () => {
  const r1 = [makeRule({ id: 1, name: "a" })];
  const r2 = [makeRule({ id: 1, name: "b" })];
  const a = compile(r1, { compiled_at_ms: 1 });
  const b = compile(r2, { compiled_at_ms: 1 });
  assert.notEqual(a.ir.hash, b.ir.hash);
});

test("conflict resolution: higher priority wins (lower sort key)", () => {
  const r1 = makeRule({ id: 1, name: "low", priority: 50, action: PolicyAction.ALLOW });
  const r2 = makeRule({ id: 2, name: "high", priority: 200, action: PolicyAction.BLOCK });
  const result = compile([r1, r2], { compiled_at_ms: 1 });
  // Sort: highest priority first -> r2 first
  assert.equal(result.ir.rules[0]!.id, 2);
  assert.equal(result.ir.rules[1]!.id, 1);
  assert.equal(result.winning_rule_indices.length, 2);
  assert.equal(result.dropped_rule_indices.length, 0);
});

test("conflict resolution: ties broken by specificity (more conditions wins)", () => {
  const r1 = makeRule({ id: 1, name: "narrow", priority: 100, action: PolicyAction.BLOCK, conditions: [
    makeCond(ConditionType.SRC_IP, ConditionOperator.EQUALS, ipv4("10.0.0.1")),
    makeCond(ConditionType.DST_PORT, ConditionOperator.EQUALS, port(80)),
  ]});
  const r2 = makeRule({ id: 2, name: "broad", priority: 100, action: PolicyAction.ALLOW, conditions: [
    makeCond(ConditionType.SRC_IP, ConditionOperator.EQUALS, ipv4("10.0.0.1")),
  ]});
  const result = compile([r2, r1], { compiled_at_ms: 1 });
  // r1 has higher specificity -> comes first
  assert.equal(result.ir.rules[0]!.id, 1);
  assert.equal(result.ir.rules[1]!.id, 2);
});

test("conflict resolution: ties on priority + specificity broken by rule_id ASC", () => {
  const r_high_id = makeRule({ id: 99, name: "high-id", priority: 100, action: PolicyAction.BLOCK });
  const r_low_id = makeRule({ id: 1, name: "low-id", priority: 100, action: PolicyAction.ALLOW });
  const result = compile([r_high_id, r_low_id], { compiled_at_ms: 1 });
  // Same priority + same specificity -> rule_id ASC wins -> r_low_id first
  assert.equal(result.ir.rules[0]!.id, 1);
  assert.equal(result.ir.rules[1]!.id, 99);
});

test("conflict resolution: same priority+specificity, distinct rule_ids -> both kept (no conflict)", () => {
  // Conflict resolution only drops when the FULL sort key is identical.
  // With unique rule_ids, this is impossible (rule_id is part of the
  // sort key). So two rules that differ only in name/id never conflict
  // at this level — they coexist in the IR.
  const r_a = makeRule({ id: 1, name: "a", priority: 100 });
  const r_b = makeRule({ id: 2, name: "b", priority: 100 });
  const result = compile([r_a, r_b], { compiled_at_ms: 1 });
  assert.equal(result.ir.rules.length, 2);
  assert.equal(result.winning_rule_indices.length, 2);
  assert.equal(result.dropped_rule_indices.length, 0);
});

test("compile: deterministic across runs (same input -> same hash)", () => {
  const rules = [
    makeRule({ id: 3, name: "c", priority: 50 }),
    makeRule({ id: 1, name: "a", priority: 200 }),
    makeRule({ id: 2, name: "b", priority: 100 }),
  ];
  const a = compile(rules, { compiled_at_ms: 42 });
  const b = compile(rules, { compiled_at_ms: 42 });
  assert.equal(a.ir.hash, b.ir.hash);
  // Verify the ordering is by priority DESC
  assert.deepEqual(
    a.ir.rules.map((r: { id: number }) => r.id),
    [1, 2, 3],
  );
});

test("applyScope: appends scope + expiry to description", () => {
  const rule = makeRule({ id: 1, description: "test" });
  const scoped = applyScope(
    rule,
    { entities: ["10.0.0.0/24"], tags: ["internal"] },
    { at: 1_700_000_000_000 },
  );
  assert.ok(scoped.description.includes("[scope:"));
  assert.ok(scoped.description.includes("10.0.0.0/24"));
  assert.ok(scoped.description.includes("internal"));
  assert.ok(scoped.description.includes("[expires:1700000000000]"));
});

test("applyScope: expiry=null -> 'never' suffix", () => {
  const rule = makeRule({ id: 1, description: "test" });
  const scoped = applyScope(rule, { entities: [], tags: [] }, { at: null });
  assert.ok(scoped.description.includes("[expires:never]"));
});
