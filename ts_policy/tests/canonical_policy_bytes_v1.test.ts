/** S4: TypeScript consumes the shared canonical policy byte vectors read-only. */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  canonicalRuleBytesV1,
  canonicalSignatureDigestV1,
  policyRuleSetDigestV1,
  type CanonicalConditionV1,
  type CanonicalRuleV1,
} from "../src/canonical_policy_bytes_v1.js";

interface RawCondition {
  field: number;
  operator: number;
  value: string;
  value2: string;
}

interface RawRule {
  id: number;
  name: string;
  priority: number;
  action: number;
  enabled: boolean;
  description: string;
  condition_count: number;
  conditions: RawCondition[];
}

interface RawCase {
  id: string;
  rules: RawRule[];
  ir_hash: string;
  policy_version: number;
  expiry_ms: number;
  ir_magic: number;
  ir_version: number;
  expected_rule_bytes_hex: string[];
  expected_rule_set_digest_hex: string;
  expected_signature_digest_hex: string;
}

interface RawManifest {
  format: string;
  cases: RawCase[];
}

const vectorUrl = new URL("../../shared/vectors/policy_canonical_v1.json", import.meta.url);
const manifest = JSON.parse(readFileSync(vectorUrl, "utf8")) as RawManifest;

function toRule(raw: RawRule): CanonicalRuleV1 {
  assert.equal(raw.condition_count, raw.conditions.length);
  const conditions: CanonicalConditionV1[] = raw.conditions.map((c) => ({
    field: c.field,
    operator: c.operator,
    value: BigInt(c.value),
    value2: BigInt(c.value2),
  }));
  return {
    id: raw.id,
    name: raw.name,
    priority: raw.priority,
    action: raw.action,
    enabled: raw.enabled,
    description: raw.description,
    conditions,
  };
}

test("shared policy canonical vector format is V1", () => {
  assert.equal(manifest.format, "POLICY_CANONICAL_BYTES_V1");
  assert.ok(manifest.cases.length >= 4);
});

for (const vector of manifest.cases) {
  test(`canonical policy bytes vector: ${vector.id}`, () => {
    const rules = vector.rules.map(toRule);
    const ruleHex = rules.map((rule) => canonicalRuleBytesV1(rule).toString("hex"));
    assert.deepEqual(ruleHex, vector.expected_rule_bytes_hex);
    assert.equal(
      policyRuleSetDigestV1(rules).toString("hex"),
      vector.expected_rule_set_digest_hex,
    );
    assert.equal(
      canonicalSignatureDigestV1({
        irMagic: vector.ir_magic,
        irVersion: vector.ir_version,
        irHash: BigInt(vector.ir_hash),
        policyVersion: vector.policy_version,
        expiryMs: BigInt(vector.expiry_ms),
        rules,
      }).toString("hex"),
      vector.expected_signature_digest_hex,
    );
  });
}

test("encoder rejects non-representable inputs instead of silently coercing", () => {
  const base: CanonicalRuleV1 = {
    id: 1,
    name: "r",
    priority: 1,
    action: 1,
    enabled: true,
    description: "",
    conditions: [],
  };
  assert.throws(() => canonicalRuleBytesV1({ ...base, name: "x".repeat(257) }), /256 UTF-8 bytes/);
  assert.throws(
    () =>
      canonicalRuleBytesV1({
        ...base,
        conditions: [{ field: 0, operator: 0, value: 1n << 64n, value2: 0n }],
      }),
    /fit u64/,
  );
  assert.throws(() => canonicalRuleBytesV1({ ...base, action: 6 }), /0\.\.5/);
});
