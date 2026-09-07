/**
 * ts_policy/tests/cross_language_contract.test.ts
 *
 * T6 AC: "A policy can be authored in TypeScript and compiled to a
 * typed Policy IR" + "IR supports the typed value set".
 *
 * This file locks in the IR JSON shape so cross-language tools (Zig
 * loader, Python validator, Rust PEP signer) can consume the same
 * artifact. The byte-level contract with Zig `policy_signing.canonicalDigest`
 * is a T7/T8 deliverable (the Zig `[]const u8` slices inside
 * `PolicyRuleDef` make `std.mem.asBytes` non-deterministic; the TS
 * side uses a JSON-canonical byte stream for cross-language safety).
 *
 * The shape asserted here MUST stay in sync with:
 *   - `core/policy_plane.zig::PolicyIR`
 *   - `core/policy_plane.zig::PolicyRuleDef`
 *   - `core/policy_plane.zig::PolicyCondition`
 *   - `core/policy_plane.zig::ConditionType`
 *   - `core/policy_plane.zig::ConditionOperator`
 *   - `core/policy_plane.zig::PolicyActionDef`
 */
import { test } from "node:test";
import { strict as assert } from "node:assert";
import {
  compile,
  PolicyAction,
  ConditionType,
  ConditionOperator,
  ipv4,
  port,
  domain,
  POLICY_MAGIC,
  POLICY_IR_VERSION,
  MAX_POLICY_RULES,
  COMPILER_VERSION,
} from "../src/index.js";

test("IR JSON shape: header fields are exactly magic, version, rule_count, hash, signature, compiled_at_ms, compiler_version", () => {
  const result = compile(
    [
      {
        id: 1,
        name: "r1",
        priority: 100,
        action: PolicyAction.BLOCK,
        enabled: true,
        description: "test",
        conditions: [],
      },
    ],
    { compiled_at_ms: 1_700_000_000_000 },
  );
  const ir = result.ir;
  // The keys present in the IR object:
  const expectedKeys = [
    "magic",
    "version",
    "rule_count",
    "rules",
    "hash",
    "signature",
    "compiled_at_ms",
    "compiler_version",
  ];
  assert.deepEqual(
    Object.keys(ir).sort(),
    expectedKeys.sort(),
  );
});

test("IR magic is 0x504F4C31 (POL1) — matches core/policy_plane.zig::POLICY_MAGIC", () => {
  const ir = compile(
    [{ id: 1, name: "r", priority: 100, action: PolicyAction.BLOCK, enabled: true, description: "", conditions: [] }],
    { compiled_at_ms: 1 },
  ).ir;
  assert.equal(ir.magic, POLICY_MAGIC);
  assert.equal(ir.magic, 0x504f4c31);
});

test("IR version is 1 — matches core/policy_plane.zig::POLICY_IR_VERSION", () => {
  const ir = compile(
    [{ id: 1, name: "r", priority: 100, action: PolicyAction.BLOCK, enabled: true, description: "", conditions: [] }],
    { compiled_at_ms: 1 },
  ).ir;
  assert.equal(ir.version, POLICY_IR_VERSION);
  assert.equal(ir.version, 1);
});

test("ConditionType enum values match the Zig byte values", () => {
  // These MUST stay in sync with core/policy_plane.zig::ConditionType
  assert.equal(ConditionType.SRC_IP, 0);
  assert.equal(ConditionType.DST_IP, 1);
  assert.equal(ConditionType.SRC_PORT, 2);
  assert.equal(ConditionType.DST_PORT, 3);
  assert.equal(ConditionType.PROTOCOL, 4);
  assert.equal(ConditionType.RULE_ID, 5);
  assert.equal(ConditionType.VERDICT, 6);
  assert.equal(ConditionType.THREAT_INTEL_SEVERITY, 7);
  assert.equal(ConditionType.TIME_WINDOW, 8);
});

test("ConditionOperator enum values match the Zig byte values", () => {
  assert.equal(ConditionOperator.EQUALS, 0);
  assert.equal(ConditionOperator.NOT_EQUALS, 1);
  assert.equal(ConditionOperator.GREATER_THAN, 2);
  assert.equal(ConditionOperator.LESS_THAN, 3);
  assert.equal(ConditionOperator.IN_RANGE, 4);
  assert.equal(ConditionOperator.MATCHES_ANY, 5);
});

test("PolicyAction enum values match the Zig byte values", () => {
  assert.equal(PolicyAction.ALLOW, 0);
  assert.equal(PolicyAction.ALERT, 1);
  assert.equal(PolicyAction.BLOCK, 2);
  assert.equal(PolicyAction.QUARANTINE, 3);
  assert.equal(PolicyAction.RATE_LIMIT, 4);
  assert.equal(PolicyAction.LOG_ONLY, 5);
});

test("compiler_version is the ts_policy-1.0.0 sentinel", () => {
  const ir = compile(
    [{ id: 1, name: "r", priority: 100, action: PolicyAction.BLOCK, enabled: true, description: "", conditions: [] }],
    { compiled_at_ms: 1 },
  ).ir;
  assert.equal(ir.compiler_version, COMPILER_VERSION);
  assert.equal(ir.compiler_version, "ts_policy-1.0.0");
});

test("MAX_POLICY_RULES is 256 — matches core/policy_plane.zig::MAX_POLICY_RULES", () => {
  assert.equal(MAX_POLICY_RULES, 256);
});

test("IR is JSON-serializable (round-trip via JSON.stringify / parse)", () => {
  const result = compile(
    [
      {
        id: 1,
        name: "block-loopback",
        priority: 200,
        action: PolicyAction.BLOCK,
        enabled: true,
        description: "block loopback",
        conditions: [
          {
            field: ConditionType.SRC_IP,
            operator: ConditionOperator.EQUALS,
            value: ipv4("127.0.0.1"),
          },
          {
            field: ConditionType.DST_PORT,
            operator: ConditionOperator.IN_RANGE,
            value: port(0),
            value2: port(1023),
          },
        ],
      },
      {
        id: 2,
        name: "alert-on-domain",
        priority: 100,
        action: PolicyAction.ALERT,
        enabled: true,
        description: "alert on evil.example",
        conditions: [
          {
            field: ConditionType.RULE_ID,
            operator: ConditionOperator.EQUALS,
            value: domain("evil.example"),
          },
        ],
      },
    ],
    { compiled_at_ms: 1_700_000_000_000 },
  );

  // Round-trip through JSON
  const json = JSON.stringify(result.ir);
  const parsed = JSON.parse(json);

  // Every field present after round-trip
  assert.equal(parsed.magic, result.ir.magic);
  assert.equal(parsed.version, result.ir.version);
  assert.equal(parsed.rule_count, result.ir.rule_count);
  assert.equal(parsed.hash, result.ir.hash);
  assert.equal(parsed.signature, result.ir.signature);
  assert.equal(parsed.compiled_at_ms, result.ir.compiled_at_ms);
  assert.equal(parsed.compiler_version, result.ir.compiler_version);
  assert.equal(parsed.rules.length, 2);

  // Rule[0] shape
  assert.equal(parsed.rules[0].id, 1);
  assert.equal(parsed.rules[0].name, "block-loopback");
  assert.equal(parsed.rules[0].priority, 200);
  assert.equal(parsed.rules[0].action, 2 /* BLOCK */);
  assert.equal(parsed.rules[0].enabled, true);
  assert.equal(parsed.rules[0].description, "block loopback");
  assert.equal(parsed.rules[0].conditions.length, 2);
  assert.equal(parsed.rules[0].conditions[0].field, 0 /* SRC_IP */);
  assert.equal(parsed.rules[0].conditions[0].operator, 0 /* EQUALS */);
  assert.equal(parsed.rules[0].conditions[0].value.kind, "ipv4");
  assert.equal(parsed.rules[0].conditions[0].value.value, "127.0.0.1");
  assert.equal(parsed.rules[0].conditions[1].field, 3 /* DST_PORT */);
  assert.equal(parsed.rules[0].conditions[1].operator, 4 /* IN_RANGE */);
  assert.equal(parsed.rules[0].conditions[1].value.kind, "integer");
  assert.equal(parsed.rules[0].conditions[1].value.value, 0);
  assert.equal(parsed.rules[0].conditions[1].value2.kind, "integer");
  assert.equal(parsed.rules[0].conditions[1].value2.value, 1023);
});

test("IR JSON is in a stable order (rules sorted by priority DESC at compile time)", () => {
  const result = compile(
    [
      { id: 1, name: "low", priority: 50, action: PolicyAction.ALLOW, enabled: true, description: "", conditions: [] },
      { id: 2, name: "high", priority: 200, action: PolicyAction.BLOCK, enabled: true, description: "", conditions: [] },
      { id: 3, name: "mid", priority: 100, action: PolicyAction.ALERT, enabled: true, description: "", conditions: [] },
    ],
    { compiled_at_ms: 1 },
  );
  assert.deepEqual(
    result.ir.rules.map((r: { id: number }) => r.id),
    [2, 3, 1],
  );
});
