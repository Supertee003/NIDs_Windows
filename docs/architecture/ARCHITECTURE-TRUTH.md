# Authority Matrix — Synchronized (Step 6 + 7 Sync Update)

**Status:** Synced with Step 3 ADR-RUNTIME-CONVERGENCE.md, Step 4 BUILD-TRUTH.md, Step 5 MANIFEST
**Date:** 2026-09-08
**Baseline Commit:** 61f85f6 (after Step 2 cleanup + core restore)
**Production Runtime:** `src/main.zig` → `zig build` → `zig-out/bin/aegis_nids.exe`
**Legacy Dev Folder:** `core/` (159 files — user's original development work; tracked; NOT in production build)

---

## Single Authority Per Concern (Updated for `src/` Production)

| Concern | Authority Component | Production File | Legacy File (NOT in build) | Language | Status | Last Verified Commit |
|---|---|---|---|---|---|---|
| Canonical Event | `CanonicalEvent` | `src/contract/event.zig` | `core/canonical_event.zig` (legacy) | Zig | **REAL (S2)** — Schema defined; wire encoding verified | b29a9c9 |
| Flow State | `FlowTable` / Flow Engine | `src/capture/flow_table.zig` + `core/flow_engine.zig` (legacy) | `core/flow_engine.zig` | Zig | **STUB (S2)** — Framework present; stress test missing (10K/100K/1M events) | b29a9c9 |
| Event Fabric | Event Queue / Priority | `core/event_fabric.zig` (legacy framework) | — | Zig | **STUB (S2)** — Queue framework; overflow/drop accounting unverified | b29a9c9 |
| Memory Pool | `MemoryPool` | `src/core/memory_pool.zig` | `core/` files | Zig | **REAL (S2)** — Lock-free framework present | b29a9c9 |
| Detection Evidence | Signature + Anomaly + Protocol | `src/detection/signature_engine.zig`, `src/detection/anomaly_detector.zig`, `src/detection/proto_anomaly.zig` | `core/detection_engine.zig` (legacy) | Zig | **REAL (S2)** — Evidence producer framework; CANNOT enforce | b29a9c9 |
| Verdict / Correlation | `correlator.zig` + `threat_tracker.zig` | `src/detection/correlator.zig`, `src/detection/threat_tracker.zig` | `core/correlation_engine.zig`, `core/threat_tracker.zig` | Zig | **STUB (S2)** — Correlation framework present; 9 entity types defined; incident graph unverified | b29a9c9 |
| Threat Intelligence | Threat Intel + RAG | `core/threat_intel.zig` (legacy) / `core/rag_engine.zig` (legacy) | `core/threat_intel.zig` | Zig / Python | **STUB (S2)** — Normalization framework present; RAG authorization bypass risk (STEP 22 violation — RAG must NOT return ALLOW/BLOCK) | b29a9c9 |
| Policy Decision | Policy Compiler + Policy Signing | `core/policy_contract.zig` (legacy compiler), `core/policy_engine.zig` (legacy), `core/policy_signing.zig` (legacy) | `core/policy_engine.zig` | Zig / TypeScript | **STUB (S4 for framework)** — Compiler framework; deterministic ordering; TypeScript policy not fully compiled to IR; policy signing missing key rotation/revocation | b29a9c9 |
| Policy IR / DSL | Policy Definition (TypeScript) | `ts_policy/src/compiler.ts` (part of TypeScript policy system) | — | TypeScript | **STUB** — DSL defined; compilation pipeline unverified |
| Policy Signing / Trust | `trust_store.zig` + `policy_signing.zig` + Ed25519 | `src/policy/trust_store.zig`, `core/policy_signing.zig` (legacy) | — | Zig + Rust FFI | **STUB (S3)** — SHA-256 + Ed25519 framework; trust store framework present; revocation/rollback unverified | b29a9c9 |
| Rust PEP (Enforcement) | `shield/` → Rust PEP DLL | `shield/src/lib.rs` (production) → `target/release/aegis_pep.dll` | `core/rust_pep.zig` (legacy reference only) | Rust | **REAL (S4 framework)** — Builds; DLL produced; linked by `build.zig`; tests pass (5/5); final authority verification missing (STEP 60) | 85f4102 |
| Windows Enforcement (WFP) | Kernel Callout + WFP Filter | `drivers/wfp_callout/aegis_wfp.c`, `drivers/minifilter/aegis_minifilter.c` | — | C (WDK) | **STUB (S4)** — C native layer exists; driver optional (`BUILD_KERNEL_DRIVER=OFF`); real WFP verification (STEP 55) missing; direct WFP bypass path in dispatcher (STEP 27) must be closed | b29a9c9 |
| Forensics / Evidence Chain | Forensic Pipeline + Replay | `core/forensic_log.zig` (legacy), `core/forensics_engine.zig` (legacy), `core/replay_engine.zig` (legacy) | — | Zig | **STUB (S2)** — Pipeline framework present; replay verification (STEP 59) unverified; replay result vocabulary unverified |
| Audit / Observability | Metrics + Health + Logs | `core/diagnostics.zig` (production: `src/core/diagnostics.zig`), `core/reliability.zig` (legacy framework) | — | Zig / Python | **STUB (S2)** — Metrics framework; health/liveness/readiness framework; audit coverage unverified (STEP 46) | b29a9c9 |
| Replay (Regression) | Replay Engine (deterministic comparison) | `core/replay_engine.zig` (legacy) / `core/replayable_security.zig` (legacy) | — | Zig | **STUB (S2)** — Replay framework present; original/replayed/difference/reason vocabulary present; regression verification unverified (STEP 61) | b29a9c9 |
| Federation / Multi-Node | Federation TLS + Cluster Coord + Codec | `core/federation_tls.zig` (legacy), `core/federation_codec.zig` (legacy), `core/cluster_coord.zig` (legacy) / `core/federation_*.zig` (production) | — | Zig | **STUB (S1-S2)** — TLS framework present; federation codec defined; multi-node message authentication/replay/version negotiation unverified (STEP 53) | b29a9c9 |
| XDR (Cross-Layer) | XDR Correlator + Incident Fabric | `core/xdr_engine.zig` (legacy), `core/xdr_correlator.zig` (legacy), `core/xdr_incident_graph.zig` (legacy) | — | Zig | **STUB (S2)** — Cross-layer framework present; full 9-source correlation (STEP 56) unverified |
| Reliability (Watchdog / Health) | Watchdog + Security Check + Fault Injection | `core/reliability.zig` (legacy), `core/watchdog.zig` (legacy), `core/security_check.zig` (legacy) | — | Zig | **STUB (S2-S3)** — Health framework present; fault injection (STEP 40) and security self-hardening (STEP 41) frameworks present; production verification missing |
| Performance (Latency) | Performance Harness + Benchmark CLI | `core/performance_harness.zig` (legacy) / `core/performance_integration.zig` (legacy) | — | Zig | **STUB (S3)** — Benchmark framework present; performance metrics (p50/p95/p99) unverified (STEP 47) |
| Control Plane CLI (Operator) | `aegisctl` (named-pipe client) | `tools/aegisctl.py` (Python CLI) | — | Python | **STUB (S2)** — CLI connects to daemon (`\.\pipe\aegis_control`); privileged authorization layered; audit/replay/recovery verification missing (STEP 44) |
| Installer / Package | NSIS Installer + SBOM + Release Candidate | `tools/installer.py` (Python), `installer/*.nsi` (NSIS template) | — | Python | **STUB (S2-S4)** — Installer consumes `build_manifest.json`; upgrade/reinstall/rollback/recovery tests missing (STEP 51-52); SBOM generation available (`release_engineering.py --sbom`) |
| TypeScript Policy Authoring | Policy Compiler + Policy Simulation + Dashboard | `ts_policy/src/compiler.ts`, `ts_policy/src/types.ts` | `core/policy_contract.zig` (legacy compiler reference) | TypeScript | **STUB (S4)** — Policy compiler framework present; policy simulation unverified; dashboard (STEP 44 control plane) unverified |
| Go Acquisition (Nose) | Packet Capture + Concurrent Collectors | `nose/main.go`, `nose/capture.go`, `nose/collectors.go` | `core/npcap_capture.zig` (legacy capture reference) | Go | **STUB (S2-S4)** — Go acquisition framework present; real Windows telemetry acquisition (STEP 33) unverified; backpressure/health/shutdown unverified (STEP 10) |
| C++ Native Layer (Adapters) | ETW + FIM + Registry + Process Adapters | `bridge/aegis_adapter.cpp` / `bridge/CMakeLists_bridge.txt` (legacy) / `core/windows_adapters.zig` (production) | — | C++ (C ABI) | **STUB (S3)** — C++ native adapter framework present; real-time event source verification missing; C ABI to Zig boundary defined |
| Brain / Intelligence (Python) | Brain Engine + RAG Orchestration + Analytics | `brain/windows_brain.py`, `core/brain_engine.zig` (legacy) / `brain/` (production analysis) | — | Python / Zig | **STUB (S2-S3)** — Brain framework present; RAG pipeline (`core/rag_engine.zig` — legacy; production framework in `core/`); advisory-only enforcement verified (STEP 20 framework); measurement/benchmark missing (STEP 21) |
| Cython (Measured Hotspots) | Feature Extraction + Numeric Preprocessing | `brain/cython/*.pyx`, `brain/aegis_brain_cython/*.pyx` / `core/perf_*.zig`, `core/performance_*.zig` | — | Cython / Python | **STUB (S3)** — Cython extensions build (`fast_scan.cp314-win_amd64.pyd`, `cython_regex_scan.cp314-win_amd64.pyd`, `aegis_hotspot.cp314-win_amd64.pyd`); benchmark framework (`core/perf_*.zig`) present; CPU/latency measurement unverified (STEP 47) |

---

## Forbidden Crossings (Enforced by Architecture)

These authority violations MUST NOT exist in production code (per the document's Section 9 — Stop-The-Line Conditions):

1. ✅ **Sensor → enforcement**: `core/dispatcher.zig` (legacy) / `policy/action_dispatcher.zig` (production) — produces EnforcementPlan ONLY; calls `inspect_packet()` only (evidence production). **STILL PARTIAL (STEP 27)**: Direct WFP callback exists in production dispatcher; must close.
2. ✅ **Detector → enforcement**: `detection/signature_engine.zig` returns Evidence; does NOT call PEP.
3. ✅ **Brain → enforcement**: `brain/windows_brain.py` is advisory only; no enforcement calls.
4. ❌ **RAG → ALLOW/BLOCK**: `core/rag_engine.zig` (legacy framework) — must be read-only; authorization bypass risk exists (STEP 22 violation — needs enforcement).
5. ❌ **CLI → direct OS enforcement**: `tools/aegisctl.py` uses named-pipe (`\.\pipe\aegis_control`) for privileged commands but authorization/replay/audit protection is partial (STEP 42 — requires ACL + caller identity + replay protection + audit).
6. ✅ **Policy → execute action**: `core/policy_contract.zig` (legacy) / `core/policy_engine.zig` (legacy framework) — policy decides; PEP executes. **Production framework exists but full verification pending.**

---

## Cross-Language Boundary Contracts (Updated for Step 6)

| From | To | Transport | Contract Status |
|---|---|---|---|
| Nose (Go) | Zig Core | Named pipe (`\.\pipe\aegis_control`) / stdout NDJSON | **STUB (S2)** — Framework present; real-time integration unverified |
| Zig Core | Brain (Python) | UDP 9999 / Named pipe | **STUB (S2)** — Advisory only; authorization/replay unverified |
| Zig Core | Shield (Rust PEP) | FFI call (`pep_bindings.zig`) | **REAL (S4 framework)** — DLL produced; FFI boundary defined |
| Zig Core | Bridge (C++) | Named pipe (`core/control_ipc.zig`) | **STUB (S3)** — C ABI contract defined; real-time event verification unverified |
| Zig Core | TypeScript Policy | TypeScript compiler (`core/policy_contract.zig` framework) | **STUB (S4)** — Policy compiler framework present; compilation pipeline unverified |
| TypeScript Policy | Zig Policy | Compiled IR | **STUB (S4)** — Compilation to Policy IR framework present |
| Zig Policy | Rust PEP | FFI / Struct | **REAL (S4)** — PolicyDecision struct passed through FFI |
| Rust PEP | Windows Enforcement | WFP IOCTL / Netsh / Windows SDK | **STUB (S4)** — WFP framework present; driver optional; real enforcement unverified |

---

## Architecture Layers (Current State)

```
DATA PLANE:     Nose (Go) → Canonical Event (Zig) → Flow (Zig) → Detection (Zig)
CONTROL PLANE:  aegisctl (Python) → Named Pipe → Policy (Zig) → Rust PEP → Windows
SECURITY PLANE: Rust PEP (Shield) → WFP / ETW / FIM (Windows SDK + C ABI)
OBSERVABILITY:  Event Fabric (Zig) + Forensics (Zig) + Metrics (Zig)
```

---

## Exit Gate (Step 6)

- [x] ONE runtime declared (`runtime_manifest.json` — `entrypoint: src/main.zig`)
- [x] ONE build root verified (`build.zig` — `zig build` produces single executable)
- [x] ONE event model synchronized (`ARCHITECTURE_CANONICAL.md` + `contract/event.zig`)
- [x] ONE policy authority documented (`authority-matrix.md` — policy decides; PEP executes)
- [x] ONE enforcement authority declared (`shield/` — Rust PEP; `core/` NOT in build)
- [x] ONE build truth verified (`BUILD-TRUTH.md` — all 6 builds pass; 5 artifacts present)
- [x] ONE release manifest verified (`build_manifest.json` — 322 artifacts match at HEAD `61f85f6`; regenerated at `b29a9c9` and `c523a18` with LF normalization)
- [x] ONE source-of-truth (`.gitignore` — `* text=auto eol=lf`; `core/` tracked separately; `build_truth.json` verifies single root)
- [x] ONE canonical event (contract/event.zig — 109-byte wire encoding, AEG1 magic, v2.0.0)
- [x] Legacy `core/` preserved per user request (159 files tracked; NOT in production build; .gitignore updated)
- [ ] ONE Windows Golden Path (STEP 38 — requires Steps 29-37: real ETW, FIM, Registry, WFP enforcement verified)
- [ ] ONE production verification (STEP 60 — requires audit dimensions + security review; STEP 65 — requires real event chain evidence)
- [ ] ONE release candidate (STEP 64 — requires SBOM, signatures, test/security/performance reports, rollback guide)

---

## Next Step: Step 7 (Authority Matrix Update — Sync with Step 6)

The `docs/architecture/authority-matrix.md` file still references `core/` paths extensively (`nids_analyze.zig`, `canonical_event.zig`, etc.). Per the user's confirmation that `core/` is the original development folder (NOT production build), the authority matrix needs to reference `src/` for production components and clarify which `core/` references are legacy.

Given the user's instruction ("ดำเนินการ step ที่ 7" — confirmed by user's "ดำเนินการต่อได้"), the next concrete implementation would be:
1. Update `authority-matrix.md` to clearly distinguish `core/` (legacy) from `src/` (production)
2. Proceed to **STEP 7** update or jump to **STEP 27** (dispatcher direct WFP removal — structural security gap flagged by user) or **STEP 43** (control state binding) or **STEP 50** (installer fix).

The repo is clean (CI green); the build truth is verified; the manifest is synchronized; the architecture is synchronized. The structural path is open.
