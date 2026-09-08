# Step 28 — Real Windows Enforcement (WFP Callout Verification — Production Chain)

**Status:** STUB (S4 framework verified structurally; full enforcement chain requires STEP 55 — Real IPS + STEP 57 — Security Decision Trace + STEP 61 — Final Regression + STEP 62 — Current-Head Golden Path + STEP 63 — Final Audit Evidence + STEP 64 — Release Candidate + STEP 65 — Final 100% Proof)
**Files Verified:** `windows/windows_adapters.zig` (production framework — 34,912 lines), `core/windows_capture.zig` (production — 8,299 lines; framework verified), `windows/etw_realtime.zig` (production — 36,192 lines; framework verified), `windows/fim.zig` (production — framework verified), `windows/registry_monitor.zig` (production — framework verified), `windows/injection_detector.zig` (production — framework verified), `windows/host_telemetry.zig` (production — 65,829 lines; framework verified)
**Enforcement Chain (STEP 27 Verified):**
```
Policy (core/policy_engine.zig / src/policy/action_dispatcher.zig — STEP 27 fixed: routes through PEP)
    ↓
Rust PEP Validation (shield/src/lib.rs + shield/src/pep.rs — framework verified; DLL produced)
    ↓
Rust Enforcement Execution (shield/src/windows_enforce.rs — framework verified)
    ↓
Windows Native Boundary (C ABI: build/Release/*.dll + drivers/wfp_callout/*.sys optional)
    ↓
WFP Callout (drivers/wfp_callout/aegis_wfp.c — optional; BUILD_KERNEL_DRIVER=OFF by default; real WFP verification requires full chain audit)
```

---

## Artifacts (Verified at HEAD 61f85f6 / b29a9c9 / c523a18 / 78b62be)

| Artifact | Path | Size | Source | Build Reference |
|----------|------|------|--------|-----------------|
| Core daemon | `zig-out/bin/aegis_nids.exe` | 2,174,464 bytes | `src/main.zig` | `build.zig` |
| Rust PEP DLL | `target/release/aegis_pep.dll` | 1,353,216 bytes | `shield/src/lib.rs` | `Cargo.toml` |
| WFP User DLL | `build/Release/aegis_wfp_user.dll` | 60 KB | `drivers/wfp_callout/aegis_wfp.c` | `CMakeLists.txt` |
| ETW Helper DLL | `build/Release/aegis_etw_helper.dll` | 13 KB | `src/windows/etw_native.c` | `CMakeLists.txt` |
| FIM Helper DLL | `build/Release/aegis_fim_helper.dll` | 13 KB | `src/windows/fim_native.c` | `CMakeLists.txt` |

---

## Exit Gate (STEP 28 — PARTIAL; Full Verification Requires Chain Audit)

- [x] `shield/src/lib.rs` = single Rust enforcement crate
- [x] `.gitignore`: `shield_rust/` excluded (stale duplicate removed)
- [x] `build.zig`: `linkSystemLibrary("aegis_pep")` links `target/release/aegis_pep.dll`
- [x] `action_dispatcher.zig`: direct WFP path removed; routes through PEP (STEP 27 verified)
- [x] `core/windows_adapters.zig` = production Windows adapter framework
- [x] `build.zig` links native helpers (`wpcap`, `Packet`, `tdh`, etc.)
- [ ] Real WFP callout verified (requires `BUILD_KERNEL_DRIVER=ON` + actual WFP filter installation + block/revoke/quarantine/revoke rollback verification — STEP 55 dependency)
- [ ] Full chain audit (requires STEP 55 Real IPS + STEP 57 Security Decision Trace + STEP 61 Final Regression + STEP 63 Final Audit Evidence + STEP 64 Release Candidate + STEP 65 Final 100% Proof)
- [ ] `.github/workflows/host-regression.yml` Phase K retargeted to `src/` per-file compiles (Phase T requires `tests/__init__.py` — still pending)

---

## References

- `docs/SHIELD-AUTHORITY.md` (STEP 8: ONE enforcement authority established)
- `docs/ARCHITECTURE-CONVERGENCE.md` (STEP 3: `core/` legacy; `src/` production; `build.zig` single runtime)
- `docs/BUILD-TRUTH.md` (STEP 4: all 6 builds verified; artifacts present)
- `docs/ARCHITECTURE-TRUTH.md` (STEP 6: subsystem status map; Windows framework REAL; verification unverified — STEP 28 dependency)
- `docs/GATE_REPORTS.md` (STEP 1 classification; 64-step taxonomy reference)
- `docs/Complete_Code_Implementation_Requirements_Report.md` (STEP 28 — WFP enforcement chain; STEP 55 — Real IPS; STEP 57 — Security Decision Trace; STEP 61 — Final Regression)
