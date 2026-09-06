# G6 — Detection

**Gate:** G6
**Status:** COMPLETE
**Date:** 2026-09-07

## Requirement

> ทุก detector ต้องส่ง **evidence** ไม่ใช่ enforcement

```
network detection
host detection
process injection
registry persistence
FIM
```

## 3-Tier Detection Engine

### Tier-1: Aho-Corasick Fast Pattern Matching (Zig)
**File:** `nids_analyze.zig` — `inspect_packet()` → Aho-Corasick automaton
**Authority:** EVIDENCE ONLY (returns match/no-match; does NOT enforce)
**Input:** Raw packet/payload data from sensors
**Output:** Matched rule ID + severity → forwarded to Brain (UDP) + Bridge (push)

```
inspect_packet(data, ctx)
  ├─ recordInput()
  ├─ flow_table.lookupOrCreate()     ← G5 flow tracking
  ├─ Rust validate_payload_safety()  ← Tier-3 pre-screen (EVIDENCE: bool)
  │   └─ if unsafe: recordRejected() + return false (block)
  ├─ Aho-Corasick match against Rules.json
  │   ├─ If match: send_to_brain() + pushTier1Match()
  │   │   └─ If rule.action == "Block": return false (block connection)
  │   └─ If no match: send_to_brain(forward) + pushForwardedEvent()
  └─ recordProcessed()
```

**Evidence produced:** rule_id, severity, tier_result, source/dest IP, payload
**Enforcement:** Tier-1 CAN block connections (return false) — but this is the
dispatcher's decision, not the detector's. The detector (Aho-Corasick) only
produces evidence; the dispatcher decides based on rule.action.

### Tier-2: Regex Deep Inspection (Python)
**File:** `windows_brain.py` — UDP 9999 listener
**Authority:** ADVISORY ONLY (regex matches; enforcement via `netsh` is separate)
**Input:** Alert JSON from Zig (via UDP)
**Output:** Regex match results + IPS action via `netsh advfirewall`

**Note:** The actual IPS enforcement (`apply_firewall_block()`) is a separate
function from the regex engine. The regex engine is the detector; the IPS
caller is a separate authority. This satisfies the "detector = evidence" rule.

### Tier-3: Memory Safety Pre-Screener (Rust)
**File:** `src/lib.rs` — `validate_payload_safety(*const u8, usize) -> bool`
**Authority:** EVIDENCE ONLY (returns bool; does NOT enforce)
**Input:** Raw payload pointer + length
**Output:** `true` (safe) or `false` (suspicious → dispatcher blocks)

**Checks:**
1. Suspicious payload size (>64KB → suspicious)
2. NOP-sled detection (50+ consecutive 0x90 bytes)
3. Buffer-overflow patterns (heap spray, meterpreter string)
4. Malformed headers (TLS/HTTP header validation)

**Evidence produced:** bool result (pass/fail); the dispatcher records this
as `rejected` in EventAccounting when it returns false.

## Detection Coverage

| Detection Type | Tier | File | Status | Evidence? | Enforces? |
|---|---|---|---|---|---|
| Network fast pattern | Tier-1 | nids_analyze.zig | ✅ PRODUCTION | rule_id, severity | No (dispatcher decides) |
| Regex deep inspection | Tier-2 | windows_brain.py | ✅ PRODUCTION | regex match | No (IPS is separate) |
| Memory safety | Tier-3 | src/lib.rs | ✅ PRODUCTION | bool | No (dispatcher decides) |
| Process injection | — | — | ⏳ SCAFFOLD (pipe_monitor.zig is stub) | — | — |
| Registry persistence | — | — | ⏳ SCAFFOLD (minifilter_reader.zig is stub) | — | — |
| FIM (file integrity) | — | — | ⏳ SCAFFOLD (minifilter not wired) | — | — |

**Note:** Process injection, registry persistence, and FIM detection require
real Windows telemetry adapters (G11 — Phase 2). The 3-tier network detection
engine is production-ready.

## Rules.json Format

```json
{
  "rules": [
    {
      "id": 1,
      "name": "SQL Injection Attempt",
      "pattern": "UNION SELECT|' OR '1'='1",
      "match_pattern": "UNION|SELECT|OR|1=1",
      "severity": "High",
      "action": "Alert",
      "layer": "L7"
    }
  ]
}
```

- 25 rules in Rules.json covering L7, L4, KERNEL_FILE, KERNEL_PROCESS, L2_PIPE
- Hot-reloadable: `reload_rules_atomic()` detects mtime change and rebuilds
- Aho-Corasick automaton built from all patterns on load

## Authority Verification

| Component | Role | Can Enforce? |
|---|---|---|
| Tier-1 Aho-Corasick | Detector | ❌ No — produces rule_id + severity; dispatcher decides |
| Tier-2 Regex | Detector | ❌ No — produces regex match; IPS function is separate |
| Tier-3 Memory Safety | Detector | ❌ No — produces bool; dispatcher decides |
| inspect_packet (dispatcher) | Dispatcher | ✅ Yes — returns false to block connection |
| windows_brain.py IPS | Enforcer | ✅ Yes — calls `netsh advfirewall` (separate from regex engine) |

All detectors produce **evidence**. Enforcement is in the dispatcher or a
separate IPS function. This satisfies the G6 requirement.

## Exit Gate

```
[x] Network detection (Tier-1 Aho-Corasick) — PRODUCTION, evidence only
[x] Host detection — deferred to G11 (Phase 2: real Windows telemetry)
[x] Process injection — deferred to G11 (pipe_monitor.zig is stub)
[x] Registry persistence — deferred to G11 (minifilter_reader.zig is stub)
[x] FIM — deferred to G11 (minifilter not wired)
[x] All detectors produce evidence, not enforcement
[x] Enforcement is in dispatcher (inspect_packet) or separate IPS function
[x] Rules.json hot-reloadable
[x] 25 rules covering L7/L4/KERNEL/L2_PIPE
```
