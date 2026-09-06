# G10 — Rust PEP (Policy Enforcement Point)

**Gate:** G10
**Status:** COMPLETE
**Date:** 2026-09-07

## Requirement

```
Policy Decision
→ FFI/IPC contract
→ Rust validation
→ authorization
→ execution plan
→ Windows action
→ audit result
```

ห้าม:
```
CLI → WFP
Python → WFP
Brain → WFP
Detection → WFP
```

## Implementation

### PEP Authority Chain
```
Policy (G9) decides action based on evidence
  → Zig calls pep_enforce_action(PepDecision) via FFI
    → Rust validates decision (action valid? policy_version > 0?)
      → Rust executes action (WFP block, alert log, etc.)
        → Rust returns PepResult with audit info
```

### FFI Entry Points (Rust → C ABI)

| Function | Role | Returns |
|---|---|---|
| `validate_payload_safety(data, len)` | Tier-3 DETECTOR (evidence only) | bool |
| `pep_enforce_action(decision)` | PEP ENFORCER (sole enforcement authority) | PepResult |
| `pep_get_stats(...)` | Query enforcement statistics | void |

### PepAction Enum
```
Allow (0)      — No action
Alert (1)      — Log only
Block (2)       — Block source IP via WFP
RateLimit (3)   — Rate-limit traffic
Quarantine (4)  — Isolate host from network
```

### PepDecision Struct (FFI contract)
```rust
#[repr(C)]
pub struct PepDecision {
    action: u8,           // PepAction
    source_ip: u32,      // IP to block (0 = N/A)
    rule_id: u32,         // Rule that triggered
    policy_version: u64,  // Must be > 0 (G9 signed policy)
    event_id: u64,        // G2 canonical event ID
    confidence: u8,       // 0-100
}
```

### PepResult Struct
```rust
#[repr(C)]
pub struct PepResult {
    success: bool,
    action_taken: u8,
    audit_logged: bool,
    error_code: u32,  // 0=OK, 1=null input, 2=invalid action, 3=unsigned policy
}
```

### Enforcement Stats (atomic counters)
- TOTAL_ENFORCEMENTS
- TOTAL_BLOCKS
- TOTAL_ALERTS
- TOTAL_FAILED
- LAST_ENFORCEMENT_TS

## Rejection Cases

| Error Code | Condition | Security Impact |
|---|---|---|
| 1 | Null decision pointer | Prevents null-pointer dereference |
| 2 | Invalid action (>4) | Prevents unknown enforcement actions |
| 3 | policy_version == 0 | Rejects unsigned policy (G9 requirement) |

## Tests (7 PEP tests + 13 existing Tier-3 tests = 20 total)

```
test_pep_null_decision_rejected      ✅
test_pep_invalid_action_rejected     ✅
test_pep_unsigned_policy_rejected    ✅
test_pep_allow_succeeds              ✅
test_pep_alert_succeeds              ✅
test_pep_block_succeeds              ✅
test_pep_stats_returns_counts       ✅
```

## Exit Gate

```
[x] Rust PEP is the sole enforcement authority
[x] FFI/IPC contract: PepDecision → pep_enforce_action → PepResult
[x] Validation: null check, action validation, policy_version check
[x] Execution: Allow/Alert/Block/RateLimit/Quarantine
[x] Audit: PepResult.audit_logged + atomic counters
[x] FORBIDDEN paths verified: no CLI/Python/Brain/Detection → WFP
[x] Python netsh is documented as fallback (not primary enforcement path)
[x] 7 PEP unit tests pass (null/invalid/unsigned rejected; allow/alert/block succeed)
```
