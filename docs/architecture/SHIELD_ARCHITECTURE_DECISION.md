# SHIELD_ARCHITECTURE_DECISION — REBUILD-001 (UPDATED)

**Decision: KEEP shield/ as the Tier-3 Rust safety shield. Integrate with rust-src/ for authority consolidation.**

**HEAD:** `2c7cb30` · **Mode:** corrected audit · **Date:** 2026-09-11

---

## Answers (required format)

**SHIELD DECISION:** KEEP (corrected from DO NOT CREATE)

**REASON:** shield/ is an active Tier-3 Rust safety shield with significant unique functionality NOT in rust-src/lib.rs (1,739 lines across 3 source files):

**Unique capabilities:**
1. **Payload safety validation (4 checks):**
   - check_suspicious_size: rejects empty or >65535-byte buffers
   - check_nop_sled: rejects runs of 0x90 (x86 NOP sled exploit pattern)
   - check_buffer_overflow_pattern: rejects all-zero, heap-spray (0x0c), int3-padding (0xcc), long ASCII overflow
   - check_malformed_headers: rejects payloads containing "meterpreter", "wscript", "powershell -enc", "cmd.exe /c"

2. **Threat scoring engine (AegisEngine):**
   - Severity-to-score mapping (Critical=100, High=75, Medium=50, Low=25)
   - Threshold-based threat detection (default 50.0)
   - Configurable via aegis_set_threshold()

3. **Windows enforcement adapter (828 lines):**
   - Driver IOCTL contract constants (0x800-0x807) in parity with kernel/wfp/aegis_wfp.c
   - Decision matrix (decide()) with score thresholds and confidence levels
   - EnforceState: in-process mirror of kernel driver's blocklist state
   - Command enum: block/unblock/whitelist/set-thresholds/set-fail-open
   - netsh_fallback: generates real Windows Firewall commands as fallback
   - AuditLog: bounded (256 entries) audit trail with drop counting

4. **PEP evaluation shim (pep.rs):**
   - PepRequestC/PepResultC structs for C-ABI FFI
   - aegis_pep_evaluate(): privileged action authorization gate
   - Policy version validation, token validation, target IP validation

**Architecture difference:**
- shield/ = payload safety pre-validation + threat scoring + Windows enforcement adapter
- rust-src/ = PEP enforcement decisions + Ed25519 crypto + federation TLS

Both are required for complete security coverage.

**RUST-SRC RESPONSIBILITY:** Final privileged authority: Ed25519 policy signature verification, PEP enforcement decisions (`aegis_pep_enforce`), rate-limit quota, SHA-256 hashing, federation TLS (stubs). Owns `aegis_pep.dll`.

**SHIELD RESPONSIBILITY:** Payload safety pre-validation, threat scoring, Windows enforcement adapter, PEP evaluation shim. Owns `sec_monitor.dll`.

**BUILD:** 
- `shield/` builds (`cd shield && cargo build --release` → `shield/target/release/sec_monitor.dll`)
- `rust-src/` builds (`cargo build --release` → `target/release/aegis_pep.dll`)
- CI job `shield-build` builds shield successfully

**TEST:** 
- `shield/` has unit tests in lib.rs, pep.rs, windows_enforce.rs (run in CI)
- `rust-src/` has unit tests (run in CI)

**RUNTIME:** 
- `bridge_init.zig` loads `sec_monitor.dll` at startup
- If DLL is missing, Tier-3 screening fails open (P0-2 issue)
- Both shield and rust-src DLLs are loaded at runtime

**RELEASE:** 
- `build_truth.json` declares shield as a build component
- `runtime_manifest.json` declares `rust_shield_tier3` as canonical entrypoint
- Both `sec_monitor.dll` and `aegis_pep.dll` ship as release artifacts

**SECURITY BOUNDARY:** Zig may call `validate_payload_safety` (screening) and `aegis_pep_enforce` (decision) — exported by different Rust authorities. All privileged enforcement flows PEP → authorization → WFP. The fail-open must become fail-closed-configurable (P0-2 issue).

## The P0-2 fail-open, precisely

```zig
// src/core/bridge_init.zig (current)
pub fn validatePayloadSafety(data: [*]const u8, len: usize) bool {
    if (fn_validate_payload_safety) |f| return f(data, len);
    return true; // fail-open when Rust DLL not available  ← P0-2
}
```

With shield/ present but potentially missing at runtime, Tier-3 screening can fail silently. Two acceptable repairs, in order of preference:

1. **Ensure shield is always present:** Make `sec_monitor.dll` a required artifact in the build pipeline. Update `bridge_init.zig` to fail-closed (return false) when shield is missing, with configurable override.
2. **Consolidate authority:** Move shield's unique functions into rust-src/lib.rs, eliminating the second Rust authority. This is a larger refactor but simplifies the security boundary.

## Why KEEP shield (corrected from DO NOT CREATE)

- shield/ has 1,739 lines of unique security functionality not in rust-src/
- It provides payload safety validation (4 checks) that rust-src/ does not have
- It provides Windows enforcement adapter (828 lines) that rust-src/ does not have
- It is referenced in runtime_manifest.json, build_manifest.json, and components.json
- It has unit tests that run in CI
- It is loaded at runtime by bridge_init.zig
- It produces a unique DLL (sec_monitor.dll) separate from aegis_pep.dll

## Comparison with rust-src/

| Capability | shield/ | rust-src/lib.rs |
|---|---|---|
| Payload safety validation (4 checks) | YES | NO |
| Threat scoring engine | YES | NO |
| Windows enforcement adapter | YES | NO |
| PEP evaluation (C-ABI) | YES | YES (different signature) |
| Ed25519 policy signing | NO | YES |
| SHA-256 hashing | NO | YES |
| Federation TLS | NO | YES |
| WFP driver mirror state | YES | NO |

## Integration plan

1. **Short-term:** Keep shield/ as separate crate, fix P0-2 fail-open by making shield required
2. **Long-term:** Consider moving shield's unique functions into rust-src/ to consolidate Rust security authority
3. **Boundary:** Document clear ownership: shield = pre-validation + enforcement adapter, rust-src = PEP + crypto

## Required actions

1. **Fix P0-2:** Make sec_monitor.dll required in build pipeline, update bridge_init.zig to fail-closed
2. **Documentation:** Update SYSTEM_MAP.json, AUTHORITY_MAP.json to reflect shield as active component
3. **Integration:** Consider adding shield to golden security path documentation
4. **Authority consolidation:** Plan long-term consolidation of Rust security authority (shield + rust-src)
