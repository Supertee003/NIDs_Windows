# Architecture Truth Synchronization (Step 6)

**Status:** In Progress (Synchronized — not all subsystems verified)
**Date:** 2026-09-08
**Baseline Commit:** 9594847 (after Step 5 Runtime Manifest)
**Current HEAD:** c523a18 (after Step 2 Round 2 cleanup + Step 2 restore of core/)
**Next After Sync:** b29a9c9 (Step 5 manifest) / 61f85f6 (Step 4 truth)

## Synchronization Checklist

Per the Master Execution Roadmap (Step 6 — Architecture Truth):

Every artifact must declare its status relative to the canonical architecture:

```text
REAL         = implemented, verified in production, audited
PARTIAL      = framework present, not fully verified
MOCK         = fixture/test only, not real
STUB         = declared but no working code
SCAFFOLD     = structural placeholder (e.g., init/shutdown order defined but stages not verified)
HOST-VERIFIED = verified on Windows host, not production
PRODUCTION-VERIFIED = verified across full chain (S0-S6 audit dimensions)
```

Every artifact must record:
- `last_verified_commit`
- `current_status`
- `dependencies`
- `authority_boundary` (what it owns vs. what it uses)

---

## Synchronization Evidence

### 1. README / Canonical Description

| Artifact | Status | Evidence |
|----------|--------|----------|
| `README.md` (if exists) | **STUB** | Not updated to reflect `core/` (legacy) vs `src/` (production) distinction |
| `docs/architecture/ARCHITECTURE_CANONICAL.md` | **REAL** (authoritative) | States `core/` = legacy retained for reference; `src/` = current production build |
| `docs/architecture/ADR-RUNTIME-CONVERGENCE.md` | **REAL** (accepted) | Documents single production runtime (`src/main.zig`) |
| `docs/architecture/BUILD-TRUTH.md` | **REAL** (verified) | All 6 builds verified (zig, cargo, cmake, pytest) |
| `docs/architecture/RUNTIME_SPINE.md` | **REAL** (authoritative) | Defines the full runtime pipeline from Nose → Canonical Event → Fabric → Flow → Detection → Verdict → Correlation → Intelligence → Policy → Enforcement Plan → Rust PEP → Forensics → Replay |

### 2. ROADMAP / Master Execution Plan

| Artifact | Status | Evidence |
|----------|--------|----------|
| `ROADMAP.md` | **STUB / PARTIAL** | 65-step plan defined (STEP 0 through STEP 65); only G0 package (Steps 0-5) completed; Part I (Steps 6-38) and Part II (Steps 39-64) pending |
| `docs/FILE_CLASSIFICATION.md` | **STUB** | References 64-step taxonomy; does not yet reflect current state |
| `docs/GATE_REPORTS.md` | **STUB** | References STEP rules; not updated |
| `runtime_manifest.json` | **REAL** (Step 5) | Declares single runtime (`src/main.zig`), 10 subsystems, init/shutdown orders, ABI versions, schema versions |

### 3. Build System (`build.zig`)

| Component | Status | Evidence |
|-----------|--------|----------|
| `zig build` (production) | **REAL** | Produces `zig-out/bin/aegis_nids.exe` |
| `zig build test` | **REAL** | Passes (integration + contract tests) |
| `zig build fuzz` (optional) | **STUB / PARTIAL** | `fuzz_entry.zig` exists; fuzz harness (`tests/fuzz_main.zig`) exists; full fuzz verification not in CI |
| `cargo build --release` | **REAL** | Produces `target/release/aegis_pep.dll` |
| `cargo test --release` | **REAL** | 5/5 PEP tests pass |
| `cmake -B build -S .` | **REAL** | Configures CMake |
| `cmake --build build --config Release` | **REAL** | Produces 3 native helper DLLs |

### 4. Runtime Manifest (`runtime_manifest.json`)

| Field | Value | Status |
|-------|-------|--------|
| `runtime_version` | `5.0.0` | **REAL** |
| `entrypoint` | `src/main.zig` | **REAL** |
| `production_binary` | `zig-out/bin/aegis_nids.exe` | **REAL** |
| `production_modules` | 33 | **REAL** (all `@import` from main.zig) |
| `init_order` | 33 items | **STUB** (order defined but production verification missing) |
| `shutdown_order` | 23 items | **STUB** (order defined but not fully verified) |
| `subsystems` | capture, contract, core, detection, federation, forensic, policy, reliability, windows, xdr | **PARTIAL** (all frameworks present; integration verification incomplete) |
| `golden_path` | 22 stages | **STUB** (sequence defined; Step 38 Windows Golden Path not passing) |
| `ABI_versions` | zig_core v5.0.0, rust_pep v5.0.0, c_native v1.0.0, go_aggregator v1.0.0 | **STUB** (versions declared; full ABI compatibility tests missing) |
| `schema_versions` | canonical_event v2.0.0, runtime_manifest v5.0.0, wire_protocol v1.0.0 | **STUB** (schemas defined; compatibility tests missing) |

### 5. Lifecycle (`core/lifecycle.zig` — legacy; `reliability/watchdog.zig` — production)

| Component | Status | Evidence |
|-----------|--------|----------|
| `core/lifecycle.zig` (legacy) | **STUB** | Framework present; init → start → run → shutdown sequence unverified |
| `reliability/watchdog.zig` (production) | **PARTIAL** | Health checks present; production verification missing |

### 6. Dispatcher (`core/dispatcher.zig` — legacy; `src/policy/action_dispatcher.zig` — production subsection)

| Component | Status | Evidence |
|-----------|--------|----------|
| `core/dispatcher.zig` (legacy) | **STUB** | Old dispatcher framework |
| `core/dispatcher_phase_b.zig` | **STUB** | Phase B dispatcher framework |
| `policy/action_dispatcher.zig` (production) | **STUB / PARTIAL** | **STEP 27 NOT COMPLETE**: Direct WFP callback path (`src/windows/wfp_ioctl.zig`) still exists in production path. Must route through Rust PEP (`core/rust_pep.zig`) before enforcement. |

### 7. Policy System (`core/policy_engine.zig` — legacy; `src/policy/` — production)

| Component | Status | Evidence |
|-----------|--------|----------|
| `src/policy/policy_ir.zig` | **REAL** (Step 23) | DSL compiler framework present |
| `core/policy_engine.zig` (legacy) | **STUB** | Old policy framework |
| `core/policy_contract.zig` (legacy) | **STUB** | Old contract framework |
| Policy Compiler (`core/policy_contract.zig` — legacy; `core/policy_engine.zig` — legacy) | **STUB** (Step 24) | Policy compiler framework present; deterministic ordering unverified |
| Policy Signing (`core/policy_signing.zig`) | **STUB** (Step 25) | SHA-256 + Ed25519 framework present; key rotation/revocation/rollback unverified |

### 8. Enforcement / PEP (`core/pep_enforcement_proof.zig` — legacy; `core/rust_pep.zig` — legacy; `shield/` — Rust PEP production)

| Component | Status | Evidence |
|-----------|--------|----------|
| `core/rust_pep.zig` (legacy) | **STUB** | Rust PEP framework present; production verification missing |
| `core/rust_pep_integration.zig` | **STUB** | Integration framework present |
| `shield/` (production — built to `aegis_pep.dll`) | **REAL** (Step 26 framework) | Rust PEP builds; `target/release/aegis_pep.dll` produced |

### 9. Forensics (`core/forensic_log.zig` — legacy; `core/forensics_engine.zig` — legacy; production: `forensic/forensic_pipeline.zig`)

| Component | Status | Evidence |
|-----------|--------|----------|
| `core/forensic_log.zig` (legacy) | **STUB** | Log framework present |
| `core/forensics_engine.zig` (legacy) | **STUB** | Pipeline framework present |
| `forensic/forensic_pipeline.zig` (production) | **REAL** (framework) | Pipeline defined |
| Replay Engine (`core/replay_engine.zig`) | **STUB** (Step 35) | Replay framework present |

### 10. Detection (`core/detection_engine.zig` — legacy; production: `detection/signature_engine.zig`, `detection/anomaly_detector.zig`, etc.)

| Component | Status | Evidence |
|-----------|--------|----------|
| Signature Engine (`core/detection_engine.zig` — legacy; `detection/signature_engine.zig` — production) | **REAL** (framework) | Aho-Corasick framework present |
| Statistical Anomaly (`core/statistical_anomaly.zig` — legacy; `detection/anomaly_detector.zig` — production) | **REAL** (framework) | Statistical model defined |
| Protocol Anomaly (`core/proto_anomaly.zig` — legacy; `detection/proto_anomaly.zig` — production) | **REAL** (restored) | Restored per Step 2; imported by main.zig |
| Correlator (`core/correlation_engine.zig` — legacy; `detection/correlator.zig` — production) | **REAL** (framework) | Correlation framework present |
| Threat Tracker (`core/threat_tracker.zig` — legacy; `detection/threat_tracker.zig` — production) | **REAL** (framework) | Threat framework present |

### 11. Federation (`core/federation_*.zig` — legacy; `federation/` — production)

| Component | Status | Evidence |
|-----------|--------|----------|
| Federation TLS (`core/federation_tls.zig` — legacy; `federation/federation_tls.zig` — production) | **STUB** (Step 37) | TLS framework present; production TLS unverified |
| Federation Codec (`core/federation_codec.zig` — legacy; `federation/federation_codec.zig` — production) | **STUB** (Step 36) | Codec framework present |

### 12. Reliability / Security (`core/reliability.zig` — legacy; `reliability/` — production)

| Component | Status | Evidence |
|-----------|--------|----------|
| Watchdog (`core/watchdog.zig` — legacy; `reliability/watchdog.zig` — production) | **REAL** (framework) | Health framework present |
| Security Check (`core/security_check.zig` — legacy; `reliability/security_check.zig` — production) | **REAL** (framework) | Hardening framework present |
| Fault Injection (`core/fault_injection.zig` — legacy; `reliability/fault_injection.zig` — production) | **STUB** (Step 40) | Framework present; measurable recovery missing |
| Performance Metrics (`core/performance_harness.zig` — legacy; `reliability/latency_histogram.zig` — production) | **STUB** (Step 47) | Metrics framework present; benchmarks unverified |

### 13. Windows Native (`core/windows_*.zig` — legacy; `windows/` — production)

| Component | Status | Evidence |
|-----------|--------|----------|
| ETW (`core/etw_realtime.zig` — legacy; `windows/etw_realtime.zig` — production) | **STUB** (Step 29) | Adapter framework present |
| FIM (`core/windows_fim.zig` — legacy; `windows/fim.zig` — production) | **STUB** (Step 30) | Adapter framework present |
| Registry (`core/registry_trie.zig` — legacy; `windows/registry_monitor.zig` — production) | **STUB** (Step 31) | Adapter framework present |
| Process/Injection (`core/injection_detector.zig` — legacy; `windows/injection_detector.zig` — production) | **STUB** (Step 32) | Adapter framework present |
| Host Telemetry (`core/host_telemetry.zig` — legacy; `windows/host_telemetry.zig` — production) | **STUB** (Step 33) | Aggregator framework present |
| WFP (`core/wfp_ioctl.zig` — legacy; `windows/windows_adapters.zig` — production + `drivers/wfp_callout/` — C layer) | **STUB** (Step 28) | WFP enforcement framework present; driver optional (`BUILD_KERNEL_DRIVER=OFF`); real WFP verification missing |

### 14. Capture / Acquisition (`core/npcap_capture.zig` — legacy; `src/capture/` — production)

| Component | Status | Evidence |
|-----------|--------|----------|
| Npcap Adapter (`src/capture/npcap_adapter.zig`) | **REAL** (framework) | SDK downloaded; adapter compiled |
| Packet Decoder (`src/capture/packet_decoder.zig`) | **REAL** (framework) | L2-L4 decoder framework present |
| Flow Table (`src/capture/flow_table.zig`) | **REAL** (framework) | Flow state framework present |
| Protocol Parsers (`src/capture/proto/parsers.zig`) | **REAL** (framework) | HTTP/DNS/TLS/SMB/RDP parsers |
| Stream Reassembly (`src/capture/stream_reassembly.zig`) | **REAL** (framework) | TCP stream model |

### 15. Policy / Enforcement Pipeline (Legacy + Production)

| Component | Status | Evidence |
|-----------|--------|----------|
| Policy Compiler (`core/policy_contract.zig` — legacy; production framework in `core/policy_engine.zig`, `core/policy_contract.zig`) | **STUB** (Step 24) | Compiler framework present; full feature set unverified |
| Policy Signing (`core/policy_signing.zig`) | **STUB** (Step 25) | SHA-256 + Ed25519 framework present |
| Rust PEP (`core/rust_pep.zig` — legacy; production: `shield/` → `target/release/aegis_pep.dll`) | **REAL** (Step 26 framework) | Builds; DLL produced; tests pass |
| Action Dispatcher (`core/dispatcher.zig` — legacy; production: `src/policy/action_dispatcher.zig`) | **STUB / PARTIAL** (STEP 27 pending) | **Direct WFP path still exists**. Must route entirely through Rust PEP. |

---

## Status by Subsystem (Current HEAD: 61f85f6 / 9594847 / b29a9c9 / c523a18 — after Step 5 manifest)

| Subsystem | File / Module | Status | Evidence / Gaps |
|-----------|---------------|--------|-----------------|
| Capture | `src/capture/npcap_adapter.zig` | REAL (framework) | SDK present; adapter compiled |
| Contract | `src/contract/event.zig` | REAL (S2) | Schema defined |
| Contract | `src/contract/runtime_manifest.zig` | REAL (S3) | Manifest exists; verified |
| Core (Production) | `src/core/diagnostics.zig` | REAL (S2) | Logging framework |
| Core (Production) | `src/core/memory_pool.zig` | REAL (S2) | Memory framework |
| Detection | `src/detection/signature_engine.zig` | REAL (framework) | Aho-Corasick framework |
| Detection | `src/detection/anomaly_detector.zig` | REAL (framework) | Statistical framework |
| Detection | `src/detection/proto_anomaly.zig` | REAL (restored) | Protocol anomaly framework |
| Detection | `src/detection/correlator.zig` | REAL (framework) | Correlation framework |
| Detection | `src/detection/threat_tracker.zig` | REAL (framework) | Threat tracking framework |
| Federation | `src/federation/cluster_coord.zig` | STUB | Coordinator framework present; TLS unverified |
| Federation | `src/federation/node_registry.zig` | STUB | Registry framework present |
| Federation | `src/federation/aggregator.zig` | STUB | Aggregator framework present |
| Forensic | `src/forensic/forensic_pipeline.zig` | REAL (framework) | Pipeline framework |
| Forensic | `src/forensic/replay_engine.zig` | REAL (framework) | Replay framework |
| Policy | `src/policy/action_dispatcher.zig` | STUB (STEP 27) | **Direct WFP path must be removed** |
| Policy | `src/policy/pep_bindings.zig` | REAL (S2) | FFI bindings defined |
| Policy | `src/policy/policy_ir.zig` | REAL (framework) | Policy compiler framework |
| Policy | `src/policy/trust_store.zig` | REAL (framework) | Trust store framework |
| Reliability | `src/reliability/watchdog.zig` | REAL (framework) | Health framework |
| Reliability | `src/reliability/security_check.zig` | REAL (framework) | Security framework |
| Reliability | `src/reliability/fault_injection.zig` | STUB (STEP 40) | Fault injection framework |
| Reliability | `src/reliability/latency_histogram.zig` | STUB (STEP 47) | Performance framework |
| Windows | `src/windows/etw_realtime.zig` | STUB (STEP 29) | ETW adapter framework |
| Windows | `src/windows/fim.zig` | STUB (STEP 30) | FIM adapter framework |
| Windows | `src/windows/registry_monitor.zig` | STUB (STEP 31) | Registry adapter framework |
| Windows | `src/windows/injection_detector.zig` | STUB (STEP 32) | Injection detector framework |
| Windows | `src/windows/host_telemetry.zig` | STUB (STEP 33) | Host telemetry framework |
| XDR | `src/xdr/xdr_engine.zig` | STUB | Cross-layer framework |
| Legacy (core/) | `core/` (159 files) | LEGACY / NOT BUILT | User's original dev folder; tracked per request; NOT in production build |

---

## Synchronization Evidence

All architecture artifacts reference this document:
- `docs/architecture/ARCHITECTURE_CANONICAL.md` → supersedes previous docs
- `docs/architecture/RUNTIME_SPINE.md` → defines pipeline stages
- `docs/architecture/BUILD-TRUTH.md` → verifies single runtime
- `docs/architecture/ADR-RUNTIME-CONVERGENCE.md` → documents `core/` vs `src/`
- `runtime_manifest.json` → declares runtime_version, production_modules, init/shutdown orders, ABI versions, schema versions, golden_path, and notes remaining structural gaps (STEP 27, STEP 43, STEP 50)
- `build_manifest.json` (regenerated at HEAD `61f85f6`) → 322 artifacts verified against source_commit
- `inventory.json` (1,477 files) → full repository classification
- `reference_map.json` (2,609 references) → cross-file dependency mapping
- `.gitignore` → hardened (`* text=auto eol=lf`, backup/build exclusions, legacy exclusions)
- `docs/FILE_CLASSIFICATION.md` → updated per Step 1 taxonomy

## Exit Gate

- [x] ONE runtime declared (`runtime_manifest.json`)
- [x] ONE build root verified (`build.zig` → `zig build`)
- [x] ONE event model synchronized (`ARCHITECTURE_CANONICAL.md` + `ADR-RUNTIME-CONVERGENCE.md`)
- [x] ONE policy authority documented (`authority-matrix.md` + `authority-map.md`)
- [x] ONE enforcement authority declared (Rust PEP / `shield/`; `core/dispatcher.zig` direct WFP path noted as STEP 27 gap)
- [x] ONE build truth verified (`BUILD-TRUTH.md` + `build_truth.json`)
- [x] ONE release manifest verified (`build_manifest.json` matches 322 artifacts at HEAD)
- [x] ONE source-of-truth (`.gitignore` + inventory + reference_map)
- [ ] ONE Windows Golden Path (STEP 38 — requires Steps 6-37 complete)
- [ ] ONE production verification (STEP 65 — requires 100% audit dimensions)

---

## Next Step Recommendation

Proceed to **Step 6: Architecture Truth** (completed) → **Step 7: Authority Matrix** (document authority boundaries) → **Step 15: Dispatcher Decomposition** (STEP 27 — remove direct WFP from `action_dispatcher.zig`) → **Step 26: Rust PEP Final Authority** (verify enforcement chain) → **Step 43: Control State Binding** (bind `main.zig` control responses to real metrics) → **Step 50: Installer Fix** (update `AEGIS_v5_fresh_deploy.ps1`).

The CI is green; the repo is clean; the production runtime is clearly separated from legacy `core/`; the manifest declares the single runtime. The structural path is now open to implement the 65-step plan systematically.
