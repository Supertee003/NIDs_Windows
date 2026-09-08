# Step 28 — Real Windows Enforcement (WFP Callout Verification)

**Status:** PARTIAL (STEP 27 fixed; real WFP verification still requires STEP 55 verification chain)
**Files:** `src/windows/aegis_wfp.c`, `build.zig` (links `wpcap`, `Packet`, WDK optional), `drivers/wfp_callout/aegis_wfp.c` (kernel callout — optional), `core/windows_capture.zig` (Windows capture adapter)

---

## STEP 27 Verification

The dispatcher (`src/policy/action_dispatcher.zig`) was fixed to remove direct WFP calls:
- `.block`: Now routes through `pep.PepEnforcer.enforce()` instead of `WfpBackend.block()`
- `.rate_limit`: Now routes through `pep.PepEnforcer.enforce()` instead of `WfpBackend.rateLimit()`
- `.quarantine`: Block routed through PEP; escalation preserved via `FederationBackend.escalate()`
- `.escalate`: Federation escalation (STEP 36 dependency — framework present; production verification missing)
- `.allow`, `.drop`: Log + forensic (no enforcement needed)

---

## Production Enforcement Chain (Verified Structurally — STEP 28)

```
Policy (core/policy_engine.zig / src/policy/action_dispatcher.zig)
    v
Rust PEP Validation (shield/src/lib.rs + shield/src/pep.rs) — produces aegis_pep.dll (1,353,216 bytes at 85f4102 / 9594847 / b29a9c9)
    v
Rust Enforcement (shield/src/windows_enforce.rs)
    v
Windows Native Boundary (C ABI: wpcap.lib + Packet.lib)
    v
WFP Callout (drivers/wfp_callout/aegis_wfp.c — optional with BUILD_KERNEL_DRIVER=OFF)
```

---

## Artifacts Verified (STEP 4 / Build Truth)

- `zig build` → `zig-out/bin/aegis_nids.exe` (2,174,464 bytes at 9594847)
- `cargo build --release` → `target/release/aegis_pep.dll` (1,353,216 bytes)
- `cmake --build build --config Release` → `build/Release/aegis_wfp_user.dll`, `aegis_etw_helper.dll`, `aegis_fim_helper.dll`
- `build.zig` links: `wpcap`, `Packet`, `advapi32`, `tdh`, `ws2_32`, `kernel32`, `user32`, `ole32`, `secur32`, `ntdll`, `aegis_pep`
- `.gitignore`: `*.sys`, `*.inf` excluded; `core/` tracked (legacy); `drivers/` tracked

---

## Real WFP Enforcement Tests (STEP 55 — Still Pending)

Per `tests/wfp/test_t11_wfp_enforcement.py` (restored in Step 2 Round 2):
- `test_single_authoritative_wfp_enforcement_module_exists` — requires `core/wfp_ioctl.zig` (legacy) or `windows/windows_adapters.zig` (production)
- `test_rust_pep_path_exists` — requires `core/rust_pep.zig` (legacy) / `shield/src/lib.rs` (production DLL)
- `test_rust_pep_is_only_path_to_enforcement` — verifies no bypass exists (STEP 27 fixed; full audit requires STEP 60)
- `test_no_other_path_bypasses_rust_pep_path` — verifies dispatcher routes through PEP (STEP 27 fixed)

**STEP 55 (Real IPS) requires the full chain verified:**
- Real telemetry → detection → verdict → correlation → policy → PEP verification → Windows enforcement → forensics → audit → replay (STEP 59 — replayable security; STEP 57 — decision trace; STEP 58 — shadow decision; STEP 54 — IPS canary progression)

---

## Exit Gate (STEP 28 Partial — Framework Verified; Real Enforcement Unverified)

- [x] `build.zig` links `aegis_pep.dll` (production PEP DLL)
- [x] `shield/src/lib.rs` = production Rust enforcement crate
- [x] `shield/src/windows_enforce.rs` = Windows native enforcement boundary
- [x] `core/windows_adapters.zig` = production Windows adapter framework
- [x] `.gitignore`: `*.sys`, `*.inf` (driver binaries excluded); `core/` tracked separately
- [ ] `drivers/wfp_callout/aegis_wfp.c`: real kernel-mode WFP callout not fully verified (optional `BUILD_KERNEL_DRIVER`)
- [ ] Real block/quarantine/rate-limit/revoke/revoke rollback not fully tested (STEP 55 dependency)
- [x] Dispatcher (STEP 27): direct WFP path removed; routes through PEP
- [ ] Full enforcement chain audit (STEP 57-59) — requires decision trace, shadow comparison, replay verification, security authority review

---

## References

- `src/policy/action_dispatcher.zig` (STEP 27 fix applied — direct WFP removed; PEP routing added)
- `src/policy/pep_bindings.zig` (PEP FFI interface — `PepEnforcer.init/enforce/deinit`)
- `shield/Cargo.toml` (Rust crate: version 0.1.0; crate-type ["cdylib", "staticlib"])
- `build.zig` (line 65: `linkSystemLibrary("aegis_pep")` — links release DLL)
- `tests/wfp/test_t11_wfp_enforcement.py` (restored; framework exists; real WFP verification pending)
- `tests/pep/test_t8_rust_pep.py` (PEP framework verified; enforcement chain audit pending)
- `docs/ARCHITECTURE-TRUTH.md` (Windows Enforcement: framework REAL; real verification unverified — STEP 28)
- `docs/SHIELD-AUTHORITY.md` (STEP 8: ONE enforcement authority = `shield/src/lib.rs`)
