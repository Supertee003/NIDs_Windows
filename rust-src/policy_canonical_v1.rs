//! Versioned canonical policy byte encoder (S4). Pure evidence utility only.
//! See `shared/policy/policy_canonical_v1.md`. This module does not modify the
//! ADR-0005 exact-file signature contract or the legacy Zig/TS hash paths.

const RULE_MAGIC: &[u8; 8] = b"PC01RULE";
const SET_MAGIC: &[u8; 8] = b"PC01SETS";
const SIGN_MAGIC: &[u8; 8] = b"PC01SIGN";
const FORMAT_VERSION: u16 = 1;
const MAX_STRING_BYTES: usize = 256;
const MAX_RULES: usize = 64;
const MAX_CONDITIONS: usize = 4;

#[derive(Debug, Clone)]
pub struct ConditionV1 {
    pub field: u8,
    pub operator: u8,
    pub value: u64,
    pub value2: u64,
}

#[derive(Debug, Clone)]
pub struct RuleV1 {
    pub id: u32,
    pub name: String,
    pub priority: u8,
    pub action: u8,
    pub enabled: bool,
    pub description: String,
    pub conditions: Vec<ConditionV1>,
}

#[derive(Debug, Clone)]
pub struct SignatureInputV1 {
    pub ir_magic: u32,
    pub ir_version: u16,
    pub ir_hash: u64,
    pub policy_version: u32,
    pub expiry_ms: i64,
    pub rules: Vec<RuleV1>,
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_i64(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_string(out: &mut Vec<u8>, value: &str, field: &'static str) -> Result<(), &'static str> {
    let bytes = value.as_bytes();
    if bytes.len() > MAX_STRING_BYTES {
        return Err(match field {
            "name" => "name exceeds 256 UTF-8 bytes",
            _ => "description exceeds 256 UTF-8 bytes",
        });
    }
    push_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
    Ok(())
}

fn validate_rule(rule: &RuleV1) -> Result<(), &'static str> {
    if rule.action > 5 {
        return Err("action ordinal out of range");
    }
    if rule.conditions.len() > MAX_CONDITIONS {
        return Err("condition_count exceeds 4");
    }
    for cond in &rule.conditions {
        if cond.field > 8 {
            return Err("field ordinal out of range");
        }
        if cond.operator > 5 {
            return Err("operator ordinal out of range");
        }
    }
    Ok(())
}

fn validate_rules(rules: &[RuleV1]) -> Result<(), &'static str> {
    if rules.is_empty() || rules.len() > MAX_RULES {
        return Err("rule count must be 1..64");
    }
    for rule in rules {
        validate_rule(rule)?;
    }
    Ok(())
}

/// Encode one representation-B rule into `PC01RULE` canonical bytes.
pub fn canonical_rule_bytes_v1(rule: &RuleV1) -> Result<Vec<u8>, &'static str> {
    validate_rule(rule)?;
    let mut out = Vec::new();
    out.extend_from_slice(RULE_MAGIC);
    push_u16(&mut out, FORMAT_VERSION);
    push_u16(&mut out, 0);
    push_u32(&mut out, rule.id);
    out.push(rule.priority);
    out.push(rule.action);
    out.push(if rule.enabled { 1 } else { 0 });
    out.push(rule.conditions.len() as u8);
    push_string(&mut out, &rule.name, "name")?;
    push_string(&mut out, &rule.description, "description")?;
    for cond in &rule.conditions {
        out.push(cond.field);
        out.push(cond.operator);
        push_u64(&mut out, cond.value);
        push_u64(&mut out, cond.value2);
    }
    Ok(out)
}

/// Versioned rule-set digest pre-image (`PC01SETS`).
pub fn canonical_rule_set_bytes_v1(rules: &[RuleV1]) -> Result<Vec<u8>, &'static str> {
    validate_rules(rules)?;
    let mut out = Vec::new();
    out.extend_from_slice(SET_MAGIC);
    push_u16(&mut out, FORMAT_VERSION);
    push_u16(&mut out, 0);
    push_u32(&mut out, rules.len() as u32);
    for rule in rules {
        out.extend_from_slice(&canonical_rule_bytes_v1(rule)?);
    }
    Ok(out)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

pub fn policy_rule_set_digest_v1(rules: &[RuleV1]) -> Result<[u8; 32], &'static str> {
    Ok(sha256(&canonical_rule_set_bytes_v1(rules)?))
}

/// Versioned signed-policy digest pre-image (`PC01SIGN`).
pub fn canonical_signature_bytes_v1(
    input: &SignatureInputV1,
) -> Result<Vec<u8>, &'static str> {
    validate_rules(&input.rules)?;
    let mut out = Vec::new();
    out.extend_from_slice(SIGN_MAGIC);
    push_u16(&mut out, FORMAT_VERSION);
    push_u16(&mut out, 0);
    push_u32(&mut out, input.ir_magic);
    push_u16(&mut out, input.ir_version);
    push_u16(&mut out, input.rules.len() as u16);
    push_u64(&mut out, input.ir_hash);
    push_u32(&mut out, input.policy_version);
    push_i64(&mut out, input.expiry_ms);
    for rule in &input.rules {
        out.extend_from_slice(&canonical_rule_bytes_v1(rule)?);
    }
    Ok(out)
}

pub fn canonical_signature_digest_v1(
    input: &SignatureInputV1,
) -> Result<[u8; 32], &'static str> {
    Ok(sha256(&canonical_signature_bytes_v1(input)?))
}

// =====================================================================
// Shared-vector E2 tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const VECTOR_JSON: &str = include_str!("../shared/vectors/policy_canonical_v1.json");

    fn value_u64(text: &str) -> u64 {
        assert!(text.starts_with("0x"));
        u64::from_str_radix(&text[2..], 16).expect("valid u64 vector")
    }

    fn rule_from_value(value: &Value) -> RuleV1 {
        let conditions: Vec<ConditionV1> = value["conditions"]
            .as_array()
            .expect("conditions array")
            .iter()
            .map(|c| ConditionV1 {
                field: c["field"].as_u64().expect("field") as u8,
                operator: c["operator"].as_u64().expect("operator") as u8,
                value: value_u64(c["value"].as_str().expect("value hex")),
                value2: value_u64(c["value2"].as_str().expect("value2 hex")),
            })
            .collect();
        let condition_count = value["condition_count"].as_u64().expect("condition_count");
        assert_eq!(condition_count as usize, conditions.len());
        RuleV1 {
            id: value["id"].as_u64().expect("id") as u32,
            name: value["name"].as_str().expect("name").to_string(),
            priority: value["priority"].as_u64().expect("priority") as u8,
            action: value["action"].as_u64().expect("action") as u8,
            enabled: value["enabled"].as_bool().expect("enabled"),
            description: value["description"].as_str().expect("description").to_string(),
            conditions,
        }
    }

    fn hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    #[test]
    fn shared_vectors_match_rust_encoder() {
        let manifest: Value = serde_json::from_str(VECTOR_JSON).expect("vector JSON");
        assert_eq!(manifest["format"], "POLICY_CANONICAL_BYTES_V1");
        let cases = manifest["cases"].as_array().expect("cases array");
        assert!(cases.len() >= 4);

        for case in cases {
            let rules: Vec<RuleV1> = case["rules"]
                .as_array()
                .expect("rules array")
                .iter()
                .map(rule_from_value)
                .collect();
            let expected_rules = case["expected_rule_bytes_hex"]
                .as_array()
                .expect("expected rule bytes");
            assert_eq!(rules.len(), expected_rules.len());
            for (rule, expected) in rules.iter().zip(expected_rules.iter()) {
                assert_eq!(
                    hex(&canonical_rule_bytes_v1(rule).expect("rule bytes")),
                    expected.as_str().expect("hex")
                );
            }
            assert_eq!(
                hex(&policy_rule_set_digest_v1(&rules).expect("set digest")),
                case["expected_rule_set_digest_hex"]
                    .as_str()
                    .expect("set digest hex")
            );

            let input = SignatureInputV1 {
                ir_magic: case["ir_magic"].as_u64().expect("ir_magic") as u32,
                ir_version: case["ir_version"].as_u64().expect("ir_version") as u16,
                ir_hash: value_u64(case["ir_hash"].as_str().expect("ir_hash hex")),
                policy_version: case["policy_version"].as_u64().expect("policy_version") as u32,
                expiry_ms: case["expiry_ms"].as_i64().expect("expiry_ms"),
                rules,
            };
            assert_eq!(
                hex(&canonical_signature_digest_v1(&input).expect("signature digest")),
                case["expected_signature_digest_hex"]
                    .as_str()
                    .expect("signature digest hex")
            );
        }
    }

    #[test]
    fn encoder_rejects_non_representable_inputs() {
        let base = RuleV1 {
            id: 1,
            name: "r".into(),
            priority: 1,
            action: 1,
            enabled: true,
            description: String::new(),
            conditions: Vec::new(),
        };
        let mut long = base.clone();
        long.name = "x".repeat(257);
        assert!(canonical_rule_bytes_v1(&long).is_err());
        let mut bad_action = base;
        bad_action.action = 6;
        assert!(canonical_rule_bytes_v1(&bad_action).is_err());
    }
}
