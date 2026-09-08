# Shield Authority Resolution (Step 8)

**Status:** ACCEPTED — Single enforcement authority established
**Date:** 2026-09-08
**Baseline Commit:** 61f85f6 (after Step 2 Round 2 cleanup + core restore)

---

## Resolution: ONE Final Enforcement Authority

Per the Master Execution Roadmap (STEP 8 — Shield Authority) and ADR-RUNTIME-CONVERGENCE.md:

```
Policy Decision (core/policy_engine.zig / src/policy/action_dispatcher.zig — framework present; STEP 27 pending: direct WFP path must close)
    |
    v
Rust PEP Validation (shield/src/lib.rs + shield/src/pep.rs)
    |
    v
Rust Enforcement Execution (shield/src/windows_enforce.rs)
    |
    v
Windows Native Boundary (C ABI: build/Release/*.dll + WDK driver)
    |
    v
WFP Callout (drivers/wfp_callout/aegis_wfp.c — optional with BUILD_KERNEL_DRIVER=OFF)
```

---

## Shield Categories (Verified)

| Category | Component | File | Status | Evidence |
|---|---|---|---|---|
| Production Enforcement | Rust PEP (Shield) | `shield/src/lib.rs` | **REAL** (S4 framework) | Crate builds (`cargo build --release`); produces `aegis_pep.dll` |
| Production Enforcement | PEP Enforcement Module | `shield/src/pep.rs` | **REAL** (S4 framework) | Rust crate; linked by `build.zig` |
| Production Enforcement | Windows Enforcement | `shield/src/windows_enforce.rs` | **REAL** (S4 framework) | Native boundary; FFI to Zig |
| Legacy / Duplicate (REMOVED) | `shield_rust/` | (directory removed from git index per Step 2; kept on disk per reference) | **NOT IN BUILD** | `.gitignore`: `shield_rust/` |
| Legacy Enforcement References | `core/rust_pep.zig` (legacy reference only) | `core/rust_pep.zig` (tracked per user request) | **LEGACY / NOT BUILT** | Not imported by `src/main.zig`; `build.zig` uses `shield/` (Rust DLL) |

---

## Authority Invariants (Enforced by Architecture)

These are the authority violations from `docs/ARCHITECTURE_CANONICAL.md` Section 18 — all verified against current production path:

- [x] Sensor (`nose/` / Go) CANNOT enforce — only produces CanonicalEvent
- [x] Detector (`detection/`) CANNOT enforce — produces Evidence[] only
- [x] Brain (`brain/windows_brain.py` / `core/brain_engine.zig` — legacy reference) CANNOT enforce — advisory only; RAG must NOT return ALLOW/BLOCK (STEP 22 violation noted)
- [x] CLI (`tools/aegisctl.py`) CANNOT bypass PEP — uses named-pipe (`\.\pipe\aegis_control`); privileged authorization layered but audit/replay/recovery partial (STEP 42)
- [x] TypeScript Policy (`ts_policy/`) CANNOT enforce — compiles to Policy IR; PEP executes
- [x] Policy (`core/policy_engine.zig` — legacy framework; production: `src/policy/action_dispatcher.zig`) decides; PEP executes — **STILL PARTIAL (STEP 27)**: `action_dispatcher.zig` has direct WFP callback; must close
- [x] Rust PEP (`shield/` — production) is final authority — **STILL PENDING FULL VERIFICATION (STEP 60)**: audit dimensions and security authority review not fully verified
- [x] Windows Enforcement (`build.zig` links `aegis_pep.dll` + native `.dll` helpers) complies with PEP — **STILL PENDING REAL VERIFICATION (STEP 28, 55)**: real WFP block/quarantine/rate-limit/revoke not fully tested

---

## Cross-Language Boundary (Shield Layer)

Per `docs/ARCHITECTURE_CANONICAL.md` Section 3 (Cross-Language Contract) and `docs/ARCHITECTURE-TRUTH.md`:

```
Zig Policy (core/policy_engine.zig / src/policy/action_dispatcher.zig — STEP 27 pending)
    ↓
Rust FFI Call (pep_bindings.zig -> shield/src/lib.rs)
    ↓
Rust PEP Validation (shield/src/lib.rs + shield/src/pep.rs)
    ↓
Rust Enforcement (shield/src/windows_enforce.rs)
    ↓
C ABI (build.zig: linkSystemLibrary for wpcap, Packet, ntdll, advapi32)
    ↓
Windows SDK / WDK (cmake --build -> build/Release/*.dll + drivers/wfp_callout/*.sys optional)
```

---

## Exit Gate

- [x] `shield/src/lib.rs` = single Rust enforcement crate (no `shield_rust/` duplicate)
- [x] `build.zig` links `aegis_pep.dll` (not embedded source snapshot)
- [x] `.gitignore` excludes `shield_rust/` (stale duplicate)
- [x] `runtime_manifest.json` records `ABI_versions.rust_pep: v5.0.0`
- [x] `build_truth.json` verifies `target/release/aegis_pep.dll` exists
- [x] CI passes (Rust PEP Build ✅)
- [ ] Step 27: Direct enforcement removed from `src/policy/action_dispatcher.zig` (STILL PENDING — direct WFP path must close)
- [ ] Step 28: Real Windows enforcement verified (STILL PENDING — requires real IPS chain: detection -> verdict -> policy -> PEP -> WFP -> forensics)
- [ ] Step 60: Final Security Authority Review (STILL PENDING — requires audit of all 12 capability pairs from authority matrix)

---

## References

- `shield/Cargo.toml` — version 0.1.0, edition 2021, crate-type ["cdylib", "staticlib"]
- `build.zig` — `linkSystemLibrary("aegis_pep")` (line 65 in build.zig; conditional on `target/release/aegis_pep.dll.lib`)
- `docs/ARCHITECTURE-TRUTH.md` — Subsystem status: Rust PEP (REAL framework; production verification pending)
- `runtime_manifest.json` — `ABI_versions.rust_pep: v5.0.0`
- `docs/architecture/ADR-RUNTIME-CONVERGENCE.md` — `core/` (legacy) vs `src/` (production) distinction
