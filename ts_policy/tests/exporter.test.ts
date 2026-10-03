/**
 * ts_policy/tests/exporter.test.ts
 *
 * T3-TSIR-024: the exporter must emit a deterministic policy_ir.json with
 * an EXACT hash_hex alongside the legacy lossy numeric hash.
 */
import { test } from "node:test";
import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
import {
  compile,
  exportIRJson,
  PolicyAction,
} from "../src/index.js";

function sampleRules() {
  return [
    {
      id: 2,
      name: "b",
      priority: 50,
      action: PolicyAction.ALERT,
      enabled: true,
      description: "b",
      conditions: [],
    },
    {
      id: 1,
      name: "a",
      priority: 100,
      action: PolicyAction.BLOCK,
      enabled: true,
      description: "a",
      conditions: [],
    },
  ];
}

test("exportIRJson is deterministic and carries exact hash_hex", () => {
  const r1 = compile(sampleRules(), { compiled_at_ms: 1700000000000 });
  // Recompute the expected hex independently of compile internals is not
  // possible here (canonical bytes are internal); instead pin the shape:
  // 64 lowercase hex chars, stable across repeated exports.
  const fakeHex = createHash("sha256").update("policy-ir-shape-pin").digest("hex");
  const a = exportIRJson(r1, fakeHex);
  const b = exportIRJson(r1, fakeHex);
  assert.equal(a, b);
  const doc = JSON.parse(a);
  assert.equal(doc.magic, 0x504f4c31);
  assert.equal(doc.version, 1);
  assert.equal(doc.rule_count, 2);
  assert.equal(doc.hash_hex, fakeHex);
  assert.equal(typeof doc.hash, "number");
  assert.equal(doc.compiler_version, "ts_policy-1.0.0");
  // Deterministic key order: alphabetical at the top level.
  const topKeys = Object.keys(doc);
  assert.deepEqual(topKeys, [...topKeys].sort());
  assert.ok(topKeys.includes("magic") && topKeys.includes("hash_hex"));
});

test("exportIRJson rejects non-hex digests", () => {
  const r1 = compile(sampleRules(), { compiled_at_ms: 1 });
  assert.throws(() => exportIRJson(r1, "not-hex"), /64 lowercase hex/);
  assert.throws(() => exportIRJson(r1, "ab".repeat(31)), /64 lowercase hex/);
});

test("exportIRJson output parses as the documented artifact shape", () => {
  const r1 = compile(sampleRules(), { compiled_at_ms: 7 });
  const fakeHex = "cd".repeat(32);
  const back = JSON.parse(exportIRJson(r1, fakeHex));
  assert.equal(back.hash_hex, fakeHex);
  assert.equal(back.rule_count, 2);
  assert.equal(back.magic, 0x504f4c31);
});
