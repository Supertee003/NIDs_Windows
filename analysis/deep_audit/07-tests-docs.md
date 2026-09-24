# AEGIS Windows NIDS/IPS — Deep Audit: Tests, fixtures, manifests และ coverage claims

**ขอบเขต:** Tests, fixtures, manifests และ coverage claims ตามคำขอ | **HEAD ที่ตรวจ:** `46b93dcf9cca17b323ddff7a4c71e33e81c37fb5` | **วันที่รายงาน:** 2026-09-21

## บทสรุปผู้บริหาร

**ผลตัดสิน:** ขอบเขตนี้ยังไม่สามารถรองรับคำว่า production-accepted หรือ host-enforcement-verified ได้ หลักฐานส่วนใหญ่เป็น static contract, source-string scan, in-memory model หรือ unit test ที่ไม่ผูกกับ Windows host และ current HEAD เดียวกัน ขณะที่ `SYSTEM_MAP.json`, `FLOW_MAP.json` และ `EVIDENCE_INDEX.json` มี `head_sha` เก่า (`688ab566...`) ไม่ตรงกับ HEAD ที่ตรวจ (`46b93dcf...`) จึงทำให้ evidence chain ใช้ยืนยัน source ปัจจุบันไม่ได้ แม้ `runtime_manifest.json` จะระบุ golden path เป็น REAL/host-verified และรายงานบางฉบับใช้คำว่า PASS ก็ตาม

ข้อค้นพบที่หยุดการยอมรับมีสี่กลุ่มหลัก คือ (1) truth artifacts และ evidence index stale, (2) tests ที่ประกาศ REAL/host-verified แต่ตรวจเพียงข้อความหรือ manifest, (3) WFP/IPS tests ใช้ driver model แบบ in-memory และไม่มี `filter_id`, traffic postcondition หรือ cleanup จาก receipt, และ (4) cross-language policy signing ใช้ byte stream คนละแบบระหว่าง Zig กับ Python จึงยังไม่พิสูจน์ ABI/protocol compatibility

ไม่พบหลักฐานว่า audit นี้รัน controlled host block หรือแก้ระบบภายนอก การตรวจทำด้วย `git ls-files`, การอ่าน source จริง และ static consistency checks ที่ไม่ทำ mutation

## 1. ขอบเขตและไฟล์ที่มีอยู่จริง

รายการตาม `git ls-files` ที่เข้า pattern ของ scope มี **207 ไฟล์** ด้านล่าง รายการนี้รวม tests, fixtures, manifests, README/ROADMAP, runbooks และ phase/reports ที่ tracked อยู่จริง ไม่มีไฟล์ชื่อ manifest/doc ที่ผู้ใช้ระบุหายไปจากรายการ tracked; อย่างไรก็ดีมี **compatibility alias ใน manifests ที่ชี้ไปยัง `core/...` แต่ path เหล่านั้นไม่มีใน working tree** (ดู Critical finding C3)

### files_reviewed (relative path จาก repository root)

```text
.agents/skills/ask-matt/PHASE-BOUNDARIES.md
.agents/skills/improve-codebase-architecture/HTML-REPORT.md
EVIDENCE_INDEX.json
FLOW_MAP.json
README.md
ROADMAP.md
SYSTEM_MAP.json
brain/aegis_brain_cython/README.md
brain/aegis_brain_cython/test_fast_scan.py
build_manifest.json
ci_coverage.json
docs/GATE_REPORTS.md
docs/STEP06_completion_report.md
docs/ai-context/10-current-phase.md
docs/phases/phase-g-through-x-plan.md
docs/phases/phase-g-through-x-status.md
docs/runbooks/RB-001-block-ip-via-pep.md
docs/runbooks/RB-002-forensic-query.md
docs/runbooks/RB-003-audit-tamper-investigation.md
docs/runbooks/RB-004-restore-from-snapshot.md
docs/runbooks/RB-005-config-rollback.md
docs/runbooks/RB-006-subsystem-health-check.md
docs/runbooks/RB-007-performance-tuning.md
docs/runbooks/RB-008-siem-ingestion-debug.md
docs/runbooks/RB-009-hot-reload-config.md
docs/runbooks/RB-010-telemetry-export-setup.md
docs/runbooks/README.md
docs/runtime/LOCAL_RUNBOOK.md
docs/runtime/PHASE_NATIVE_READINESS.md
go/aggregator/README.md
inventory.json
reference_map.json
runtime_manifest.json
scripts/tests/test_e2e.py
src/core/compliance_reporter.zig
src/policy/dispatcher_phase_b.zig
src/tests/capture/flow_table.zig
src/tests/capture/npcap_adapter.zig
src/tests/capture/packet_decoder.zig
src/tests/capture/proto/parsers.zig
src/tests/capture/stream_reassembly.zig
src/tests/cli/cluster_cli.zig
src/tests/cli/etw_realtime_cli.zig
src/tests/cli/federation_bench_cli.zig
src/tests/cli/federation_cli.zig
src/tests/cli/federation_tcp_cli.zig
src/tests/cli/federation_tls_cli.zig
src/tests/cli/host_telemetry_cli.zig
src/tests/cli/host_telemetry_detectors_cli.zig
src/tests/cli/host_telemetry_mock_cli.zig
src/tests/cli/host_telemetry_scenarios_cli.zig
src/tests/cli/injection_detector_cli.zig
src/tests/cli/integration_test_cli.zig
src/tests/cli/ml_test_cli.zig
src/tests/cli/nose_pipe_e2e_cli.zig
src/tests/cli/perf_benchmark_cli.zig
src/tests/cli/registry_trie_cli.zig
src/tests/cli/windows_adapters_cli.zig
src/tests/cli_imports.zig
src/tests/contract/event.zig
src/tests/contract/runtime_manifest.zig
src/tests/core/bisect_a.zig
src/tests/core/bisect_b.zig
src/tests/core/core_configs.zig
src/tests/core/core_modules.zig
src/tests/core/diagnostics.zig
src/tests/core/memory_pool.zig
src/tests/detection/anomaly_detector.zig
src/tests/detection/correlator.zig
src/tests/detection/proto_anomaly.zig
src/tests/detection/signature_engine.zig
src/tests/detection/threat_tracker.zig
src/tests/federation/aggregator.zig
src/tests/federation/cluster_coord.zig
src/tests/federation/node_registry.zig
src/tests/forensic/abi_contract.zig
src/tests/forensic/decision_trace.zig
src/tests/forensic/evidence_record.zig
src/tests/forensic/forensic_pipeline.zig
src/tests/forensic/installer.zig
src/tests/forensic/integration_contract.zig
src/tests/forensic/policy_contract.zig
src/tests/forensic/provenance.zig
src/tests/forensic/python_contract.zig
src/tests/forensic/release_gate.zig
src/tests/forensic/release_manifest.zig
src/tests/forensic/replay_engine.zig
src/tests/forensic/replay_integrity.zig
src/tests/forensic/replay_verifier.zig
src/tests/forensic/test_fault.zig
src/tests/forensic/test_integration.zig
src/tests/forensic/test_release.zig
src/tests/forensic/test_unit.zig
src/tests/fuzz_main.zig
src/tests/integration/brain_integration.zig
src/tests/integration/concurrency_harden_integration.zig
src/tests/integration/correlation_integration.zig
src/tests/integration/detection_integration.zig
src/tests/integration/e2e_harness_integration.zig
src/tests/integration/fault_injection_integration.zig
src/tests/integration/flow_integration.zig
src/tests/integration/forensics_integration.zig
src/tests/integration/golden_path_e3.zig
src/tests/integration/golden_path_ffi.zig
src/tests/integration/hids_integration.zig
src/tests/integration/ips_canary_integration.zig
src/tests/integration/ips_simulation_integration.zig
src/tests/integration/nose_integration.zig
src/tests/integration/performance_integration.zig
src/tests/integration/policy_integration.zig
src/tests/integration/policy_plane_integration.zig
src/tests/integration/rag_integration.zig
src/tests/integration/release_engineering_integration.zig
src/tests/integration/replay_integration.zig
src/tests/integration/rust_pep_integration.zig
src/tests/integration/threat_intel_integration.zig
src/tests/integration/xdr_harden_integration.zig
src/tests/policy/action_dispatcher.zig
src/tests/policy/pep_bindings.zig
src/tests/policy/policy_ir.zig
src/tests/policy/trust_store.zig
src/tests/proofs/audit_trail_proof.zig
src/tests/proofs/brain_proof.zig
src/tests/proofs/compliance_proof.zig
src/tests/proofs/config_reload_proof.zig
src/tests/proofs/correlation_proof.zig
src/tests/proofs/detection_fabric_proof.zig
src/tests/proofs/documentation_proof.zig
src/tests/proofs/final_integration_proof.zig
src/tests/proofs/flow_state_proof.zig
src/tests/proofs/forensic_replay_proof.zig
src/tests/proofs/health_monitoring_proof.zig
src/tests/proofs/intelligence_proof.zig
src/tests/proofs/pep_enforcement_proof.zig
src/tests/proofs/performance_tuning_proof.zig
src/tests/proofs/policy_plane_proof.zig
src/tests/proofs/siem_integration_proof.zig
src/tests/proofs/telemetry_export_proof.zig
src/tests/reliability/fault_injection.zig
src/tests/reliability/latency_histogram.zig
src/tests/reliability/security_check.zig
src/tests/reliability/watchdog.zig
src/tests/stubs/etw_helper_stub.c
src/tests/stubs/fim_helper_stub.c
src/tests/windows/etw_realtime.zig
src/tests/windows/fim.zig
src/tests/windows/host_telemetry.zig
src/tests/windows/injection_detector.zig
src/tests/windows/registry_monitor.zig
src/tests/xdr/xdr_engine.zig
test_needs.py
tests/__init__.py
tests/adapters/test_t9_windows_adapters.py
tests/aegis_mouth_test.py
tests/aegis_nose_test.py
tests/contracts/event_vectors/event_vectors/README.md
tests/contracts/event_vectors/event_vectors/event_v1_001.bin
tests/contracts/event_vectors/event_vectors/event_v1_002.bin
tests/contracts/event_vectors/event_vectors/event_v1_003.bin
tests/contracts/event_vectors/event_vectors/event_v1_004.bin
tests/contracts/event_vectors/event_vectors/event_v1_005.bin
tests/contracts/event_vectors/event_vectors/golden_vectors.json
tests/contracts/event_vectors/event_vectors/vectors_metadata.json
tests/contracts/event_vectors/generate_test_vectors.py
tests/cython/PROFILE_REPORT.md
tests/cython/profile_brain_hotspot.py
tests/cython/test_cython_benchmark.py
tests/cython/test_cython_correctness.py
tests/cython/test_cython_no_policy_path.py
tests/cython/test_cython_profile.py
tests/e2e/test_t14_windows_golden_path.py
tests/federation/test_t13_federation_tls.py
tests/forensics/test_t12_forensics_replay.py
tests/host_telemetry/test_t10_single_source.py
tests/ips/test_t18_ips_canary_xdr.py
tests/pep/test_t8_rust_pep.py
tests/policy_signing/test_t7_signed_policy.py
tests/release/test_t17_perf_ci_installer.py
tests/reliability/test_t15_reliability_config.py
tests/runtime/README.md
tests/runtime/__init__.py
tests/runtime/conftest.py
tests/runtime/test_aegisctl.py
tests/runtime/test_component_matrix.py
tests/runtime/test_gate_d.py
tests/runtime/test_gate_e.py
tests/runtime/test_gate_f.py
tests/runtime/test_golden_path.py
tests/runtime/test_harness_integration.py
tests/runtime/test_harness_scaffold.py
tests/runtime/test_health.py
tests/runtime/test_restart.py
tests/runtime/test_states.py
tests/runtime/test_timeouts.py
tests/runtime/test_version.py
tests/runtime/test_wire.py
tests/security/test_t16_security_hardening.py
tests/security/test_t19_decision_trace_shadow_replay_review.py
tests/test_e2e.py
tests/test_golden_path.py
tests/tests/contracts/canonical_event.bin
tests/tests/contracts/test_vectors.json
tests/tests/contracts/wire_event.bin
tests/typescript/test_06_typescript_policy.py
tests/vectors/event_vectors.py
tests/wfp/test_t11_wfp_enforcement.py
tests/wfp/test_t11_windows_host.py
```

### รายการที่ไม่มีใน scope

ไม่พบ `ci_coverage.json`, `inventory.json`, `runtime_manifest.json`, `build_manifest.json`, `reference_map.json`, `SYSTEM_MAP.json`, `FLOW_MAP.json`, `EVIDENCE_INDEX.json`, `README.md` หรือ `ROADMAP.md` ที่หายจาก tracked tree. ไม่มี directory `runbooks/` หรือ `phase reports/` ที่ root; เอกสารที่ตรง scope อยู่ใต้ `docs/runbooks/` และ `docs/phases/` ตามรายการข้างต้น

## 2. Flow, data path และ privilege/language boundaries

เส้นทางที่ประกาศใน `FLOW_MAP.json` คือ Go/Npcap capture → CanonicalEvent 109 bytes → named pipe/C ABI → Zig fabric/flow/detection/correlation/threat tracking → policy → Rust PEP → WFP → audit/forensic/replay. ใน source/test จริง หลักฐานของช่วงต้นมีทั้ง unit/integration และ fixture แต่ช่วง PEP→WFP ยังเป็น structural proof หรือ deterministic in-memory model ไม่ใช่ Windows host effect

| Boundary | Input → output ที่ตรวจพบ | process/language/privilege | หลักฐานและข้อจำกัด |
|---|---|---|---|
| Acquisition | `nose/capture.go` raw packet → `nose/canonical.go` CanonicalEvent → `nose/pipe_writer.go` frame | Go process; capture/ingress ไม่ควรมี policy authority | `tests/aegis_nose_test.py`, `src/tests/integration/nose_integration.zig`, event fixtures; ยังต้องมี live Go→Zig current-head run |
| Ingress ABI | 4-byte little-endian length + 109-byte payload ตาม handoff/fixtures → `src/capture/nose_pipe_reader.zig` → event fabric | Go/Zig process boundary; named pipe; privilege boundary ยังไม่ใช่ enforcement | `tests/runtime/test_wire.py` ตรวจ envelope คนละ protocol กับ canonical binary; `golden_path_ffi.zig` มี conceptual/stub note |
| Runtime | CanonicalEvent → flow table → detector → correlator → threat tracker → policy decision | Zig runtime owner; worker lifecycle/readiness | `src/tests/integration/*`, `src/tests/proofs/*`; หลายไฟล์เป็น imported-module smoke tests หรือ in-memory integration |
| Intelligence | event/feature → Python `brain/windows_brain.py`/Cython → advice/threat score → Zig | Python/Cython process/language boundary; advisory only | `tests/cython/*`, `src/tests/integration/brain_integration.zig`; no enforcement should cross this boundary; live timeout/isolation evidence incomplete |
| Policy authoring/signing | TypeScript compiler/seal → PolicyIR/SignedPolicy → Zig signing/verification | Node/TS → Zig/PEP ABI; privileged authority remains Zig/Rust | `tests/typescript/test_06_typescript_policy.py`, `tests/policy_signing/test_t7_signed_policy.py`; canonical bytes are not proven identical (C4) |
| Enforcement | decision → `rust-src/lib.rs` PEP → native/WFP user bridge → driver | Zig/Rust FFI then user/kernel boundary; privileged mutation must be PEP-only | `tests/pep/test_t8_rust_pep.py`, `tests/wfp/test_t11_wfp_enforcement.py`; host test is opt-in/skippable and lacks receipt/postcondition |
| Evidence | event/decision/PEP/action → forensic ring/log → replay | Zig in-process ring/durable log boundary; replay must be observe-only | `src/tests/proofs/forensic_replay_proof.zig`, `tests/forensics/test_t12_forensics_replay.py`; no current-head durable Windows crash/recovery proof |
| Control plane | CLI/API JSON → authenticated named pipe → Zig control IPC → authorization → handler → audit | Python/TS client unprivileged request; Zig auth/runtime; Rust PEP for privileged action | `tests/runtime/test_aegisctl.py`, `test_health.py`, `tests/security/test_t16*`; many live tests skip if daemon unavailable |

### สถานะ authority ที่ต้องถือเป็นจริง

`DetectionResult`, `PolicyDecision`, PEP authorization, WFP result และ verified host postcondition เป็นคนละสถานะ ห้ามใช้ log, in-memory `isBlocked`, decision-only result หรือ bookkeeping เป็นหลักฐาน host block. ปัจจุบัน `runtime_manifest.json:478` ระบุ detection-only จนกว่าจะมี provider-owned receipt-producing adapter แต่ `runtime_manifest.json:334` และ T14/T18 claims บางส่วนยังใช้คำว่า REAL/host-verified

## 3. Mapping code areas → tests → evidence

| Code area | Tests/fixtures ที่ผูกไว้ | Evidence ที่อ้าง | ประเมินความครอบคลุม |
|---|---|---|---|
| Canonical event/wire | `src/tests/contract/*`, `src/tests/forensic/test_unit.zig`, `tests/runtime/test_wire.py`, `tests/contracts/event_vectors/*`, `tests/tests/contracts/*` | `EVIDENCE_INDEX` EVT-001/005 และ vector metadata | ขนาด/encoding บางส่วนมีหลักฐาน แต่มี fixture set ซ้ำสองชุดและไม่มี single cross-language execution gate |
| Capture/flow/parser | `src/tests/capture/*.zig`, `src/tests/integration/flow_integration.zig`, `src/tests/proofs/flow_state_proof.zig`, `tests/host_telemetry/*` | G2–G8, T10/T14 | `src/tests/capture/*.zig` หลายไฟล์มีเพียง “module imports cleanly”; parser/Npcap live path ไม่ได้พิสูจน์บน Windows ในชุดนี้ |
| Detection/correlation/threat | `src/tests/detection/*.zig`, `src/tests/integration/detection/correlation/threat_intel`, proofs | E3-003/004 และ G5–G8 | มี unit/in-memory coverage แต่ no measured production branch/coverage percentage; failure/backpressure edges ไม่ครบ |
| Policy/PEP | `src/tests/policy/*.zig`, `src/tests/integration/policy*`, `src/tests/proofs/pep_enforcement_proof.zig`, T7/T8 | G9/G10, T7/T8 | PEP proof moduleมี branch tests แต่หลาย acceptance tests ตรวจ source strings/manifest; actual DLL ABI/provider receipt ยังไม่ครบ |
| WFP/IPS | `src/core/real_ips_path.zig`, `src/windows/ips_canary_order.zig`, `src/tests/integration/ips_*`, T11/T18 | T11/T18, runtime manifest | Real IPS model ใช้ `DriverState` และ in-memory rule; ไม่ใช่ WFP filter; ไม่มี filter identity/traffic/rollback receipt |
| Windows adapters/HIDS | `src/tests/windows/*`, `src/tests/cli/windows_*`, `tests/adapters/test_t9*`, `tests/wfp/test_t11_windows_host.py` | T9/T11 | T9 ระบุเองว่า architectural, not host-verified; host test skip ได้ |
| Runtime lifecycle/health | `tests/runtime/conftest.py`, `test_health`, `test_states`, `test_restart`, `test_timeouts`, harness integration | runtime manifest 436 pass/23 skipped | contract tests เป็น static; live tests gated by OS/binaries/daemon and convert some dependency failures to SKIP |
| Reliability/fault/config | T15 + `src/tests/proofs/config_reload/health_monitoring`, `src/tests/integration/fault_injection` | G12/G13/T15 | deterministic Zig proofs; not host process crash, disk full, driver unload or durable recovery |
| Forensics/replay | T12, proof/integration files | E2/E3 claims | hash-chain/unit coverage exists; historical binary/policy/context/build identity and durable crash recovery not shown |
| Perf/release/manifests | T17, release integration/proofs, `ci_coverage.json`, `build_manifest.json` | runtime notes, CI matrix | T17 perf gate runs `python -c pass`; CI coverage is job-presence, not code coverage; release/rollback test can mutate local state |
| Docs/runbooks/reports | README/ROADMAP, `docs/GATE_REPORTS.md`, `docs/phases/*`, `docs/runbooks/*` | G2–G20 and phase claims | Older phase status and newer manifests conflict; RB-001 still instructs forbidden evidence path |

## 4. Critical findings

### C1 — Current-head evidence chain is broken (CRITICAL)

`git rev-parse HEAD` is `46b93dcf9cca17b323ddff7a4c71e33e81c37fb5`. `SYSTEM_MAP.json:2`, `FLOW_MAP.json:2` และ `EVIDENCE_INDEX.json:2` carry `688ab566d477105df5f868cee1571fbec77eedfd`. `EVIDENCE_INDEX.json:1177-1197` records a previous “resynced” state at `60c76fe`, which is also not current. `runtime_manifest.json:3` happens to carry the current full SHA, and `build_manifest.json:5` carries current abbreviated source commit, but this does not repair the stale maps/evidence index. `tools/truth.py:32-53,98-149` explicitly defines these artifacts as current-head gates. ผลคือ E1–E3 claims referring to stale maps cannot be evidence for current source, and `inventory.json`/`reference_map.json` have no SHA by design so their 2026-09-18 snapshots are not current-head attestations

**ผลกระทบ:** release/readiness claims can be attached to the wrong source revision; no evidence chain is production-grade until regenerated and independently re-run

### C2 — “REAL / host-verified Windows E2E” is asserted by structural tests, not executed evidence (CRITICAL)

`tests/e2e/test_t14_windows_golden_path.py:71-87,91-109,179-217` checks manifest labels, file presence and strings. It never starts the Windows pipeline, captures a packet, invokes the PEP DLL, observes WFP, or replays a receipt. `tests/ips/test_t18_ips_canary_xdr.py:92-109,116-178,184-227,233-261` likewise checks source text and manifest vocabulary. `tests/adapters/test_t9_windows_adapters.py:21-31` explicitly describes its proof as “architectural, not host-verified real calls”. Yet `runtime_manifest.json:334` says “golden path is REAL (host-verified Windows E2E)”. `tests/wfp/test_t11_windows_host.py:52-54` is skipped unless Windows and `AEGIS_RUN_WFP_HOST_TESTS=1`; the handoff says host block proof was NOT RUN. This is a false-positive gate

**ผลกระทบ:** CI can be green while the claimed Windows path has never run; downgrade all such claims to E1/E2 until live evidence is attached

### C3 — WFP/IPS “block” tests prove an in-memory rule, not host enforcement (CRITICAL)

`src/core/real_ips_path.zig:13-16,125-190,230-258` models WFP as `DriverState` and `rules[]`; `run()` returns `Outcome.blocked` after adding a local array entry. `RunResult` has no `filter_id`, request/trace linkage, provider receipt or independent traffic postcondition. `tests/wfp/test_t11_windows_host.py:74-103` only asserts a PEP decision byte and an unblock return code; it does not require a WFP receipt/filter identity, baseline/blocked/cleanup traffic, or cleanup by the original receipt. `tests/ips/test_t18_ips_canary_xdr.py` only scans source strings. This cannot support an enforcement claim under the audit rule

**ผลกระทบ:** an allow/decision or bookkeeping state can be mistaken for host effect; cleanup correctness and exact filter ownership remain untested

### C4 — Zig and Python policy-signature canonical byte streams are explicitly different (CRITICAL)

`src/policy/policy_signing.zig:74-95` hashes `std.mem.asBytes(&rule)`, including the in-memory Zig struct/slice representation. `tests/policy_signing/test_t7_signed_policy.py:48-59,72-80` admits that Python uses JSON-canonical rule bytes and says these are “two different byte streams”; the test signs and verifies wholly inside Python (`:209-223`) and does not consume a Zig-generated SignedPolicy or TS-generated artifact. A cross-language signature contract is therefore not proven and may fail at the Zig↔Python/TS boundary

**ผลกระทบ:** policy authenticity/ABI compatibility can fail closed or, worse, be interpreted inconsistently; the T7 title must not claim a TS/Zig/Python trio contract until one generated artifact is verified by all consumers

### C5 — Legacy `block_ip`/bookkeeping tests and runbook are invalid enforcement evidence (CRITICAL)

`tests/test_e2e.py:169-178` calls `bridge.block_ip()`/`unblock_ip()` and accepts any non-negative return (`rc >= 0`), without WFP receipt or traffic verification. The older `scripts/tests/test_e2e.py` is also in the tracked scope and is not a canonical current-head Windows proof. `docs/runbooks/RB-001-block-ip-via-pep.md:20-30,40-54` instructs `pep_enforcement.block_ip`, `wfp_ioctl.is_blocked`, and says block action is recorded even when kernel enforcement is inactive. These are explicitly disallowed evidence sources for this audit and can create a false operator gate

**ผลกระทบ:** operators and CI can report success from a legacy bridge/local list despite no host block. Mark these paths non-evidence and replace the runbook with receipt + traffic postcondition procedure

### C6 — Required runtime dependency and CI classification disagree for Shield (CRITICAL)

`tests/runtime/conftest.py:112-118,129` marks `shield` required. `ci_coverage.json:74-80` marks `shield` `required:false`, `classification:SUPPORT`, and documents it as quarantined/optional. `.github/workflows/ci.yml:93-104` runs the job, but `tools/ci_coverage.py:127-146` does not fail required matrix evaluation when an optional job is skipped. A runtime-required component can therefore be absent while the CI matrix remains green

**ผลกระทบ:** fail-closed dependency and CI acceptance semantics diverge; decide whether Shield is required for runtime, then make one source of truth and gate skipped/cancelled results accordingly

## 5. Important findings

### I1 — No code-coverage claim exists; `ci_coverage.json` is CI job coverage only

`ci_coverage.json:1-96` defines required jobs and support jobs, not statement/branch/function coverage. `tools/ci_coverage.py:63-104` only scans workflow job IDs and `:127-146` evaluates `needs` results. There is no measured Zig/Rust/C++/Go/Python/TS branch coverage or threshold in the scoped artifacts. “436 passed, 23 skipped” in `runtime_manifest.json:486` is a stale snapshot/count claim, not a coverage percentage

### I2 — Many Zig test aggregators are import-only smoke tests

`src/tests/capture/flow_table.zig`, `npcap_adapter.zig`, `packet_decoder.zig`, `proto/parsers.zig`, `stream_reassembly.zig`, `src/tests/policy/action_dispatcher.zig`, `pep_bindings.zig`, `policy_ir.zig`, `trust_store.zig`, and numerous `src/tests/forensic/*.zig` wrappers contain ~10-line “module imports cleanly” tests. They prove compilation/import only. The behavior is elsewhere, and no machine-readable map proves every production symbol has an executed behavioral test

### I3 — Live harness converts unavailable prerequisites into SKIP and has weak process cleanup

`tests/runtime/test_harness_integration.py:57-63,128-134,237-270` skips for non-Windows, missing binaries, failed bridge startup and absent processes. `tests/runtime/conftest.py:176-190` starts child processes and drain threads, but `_DRAIN_THREADS` and `_SPAWNED_OUTPUT` are process-global with no cleanup; teardown in harness only terminates the direct child and does not reap a process group/descendants. `tests/runtime/test_states.py:161-180` appends to `logs/runtime/audit.ndjson` without fixture isolation or cleanup. This creates leaked state and lets missing runtime coverage look green

### I4 — T17 performance gate is a false positive

`tests/release/test_t17_perf_ci_installer.py:74-87` runs `sys.executable -c pass` for every Zig benchmark module and calls this a green perf gate. It does not execute a benchmark, collect p50/p95/p99, CPU, memory, queue depth or drop rate. The source-string checks at `:55-71` only require names in code/docs

### I5 — T10 test can mutate a tracked manifest during testing

`tests/host_telemetry/test_t10_single_source.py:217-254` appends an invariant and writes `runtime_manifest.json` when the expected invariant is absent. Tests must not repair their own oracle. This can alter SHA/provenance and hide a failed gate; the branch must fail instead

### I6 — Static WFP scanner has material blind spots

`tests/wfp/test_t11_wfp_enforcement.py:69-101,105-133` scans only `src/**/*.zig`, ignores files whose path contains “test”, accepts comments/source-text heuristics, and checks only a narrow set of names. It does not inspect Rust FFI callsites, C/C++ bridge/driver call graphs, IOCTL access control, receipts or kernel state. Passing this negative scan is not “only PEP reaches WFP” proof

### I7 — Fixture sets are duplicated and validity semantics are incomplete

`tests/contracts/event_vectors/generate_test_vectors.py:20-30,221-277` owns five 109-byte vectors and metadata; the actual files match the listed SHA-256 values. Separately, `tests/tests/contracts/canonical_event.bin` and `wire_event.bin` are 109/125-byte fixtures with `tests/tests/contracts/test_vectors.json`, but there is no shared metadata/hash gate connecting the two sets. `tests/vectors/event_vectors.py:15-150` contains a separate Python fixture model with `struct_size: 100` (approximate) while the canonical generator says 109. Vector 004/005 include zero/max edge cases but no `expected_valid` contract is executed against a decoder. This is a compatibility and negative-path gap

### I8 — Documentation and manifests are internally contradictory and path-stale

`docs/phases/phase-g-through-x-status.md:7-27,73-120` is dated 2026-09-02 and reports multiple FAIL/NOT STARTED states, while newer manifests label many aliases REAL. `runtime_manifest.json:10-35,47-53,69-79` lists compatibility `core/...` paths that do not exist; the canonical paths are under `src/...`. `tests/e2e/test_t14_windows_golden_path.py:95-109` validates alias entries without requiring the alias file to exist. This undermines traceability from claim to executable file

### I9 — Rollback/release tests are not read-only by design

`tests/release/test_t17_perf_ci_installer.py:269-289` runs `upgrade_rollback.py snapshot` then `rollback`; this is a state-changing test and must not be executed in this audit environment. It needs an isolated disposable fixture root and explicit before/after hash checks. `tests/test_golden_path.py:131-157` writes a temporary config under `configs/` and removes it in `finally`, but an interrupted run can leave it behind

### I10 — Host adapter “REAL” status is not backed by host execution

`tests/adapters/test_t9_windows_adapters.py:122-163,166-208` accepts API names/comments/state strings and explicitly documents architectural proof. Linux stubs in `src/tests/stubs/etw_helper_stub.c` and `fim_helper_stub.c`, plus `src/tests/cli/windows_adapters_cli.zig:106-165`, are useful compile/negative fixtures but cannot prove ETW/FIM/Registry lifecycle, ACL or privilege behavior on Windows

### I11 — Forensics/replay proof is primarily deterministic in-memory/schema proof

`tests/forensics/test_t12_forensics_replay.py:68-175,189-245` scans modules and manifest; Zig proofs cover hashes and replay shape. It does not demonstrate historical policy/context/build binary pinning, durable fsync/crash recovery, or current-head Windows evidence. Claims must remain E2/E3 until an E4/E5 test records those inputs

## 6. False-positive gates and untested failure paths

| Gate/path | Why it can pass falsely | Failure path not covered |
|---|---|---|
| T14/T18/T9 | Source strings + manifest status | live process, real provider, actual Windows API, packet/traffic postcondition |
| T11 host | `skipif` on OS/env; asserts decision byte/return code | filter receipt, filter ownership, blocked TCP traffic, exact cleanup, driver hash |
| T17 perf | `python -c pass` | benchmark regression, tail latency, memory/queue/drop thresholds |
| Runtime harness | missing binary/dependency/startup failure becomes SKIP | required component unavailable must fail CI; descendant cleanup |
| T7 signing | Python self-sign/self-verify | Zig-produced bytes, TS-produced bytes, Rust verifier, malformed lengths/slice ABI |
| T10 authority | test writes missing invariant into manifest | oracle mutation, current-head digest change |
| Fixtures | metadata hashes only; duplicate fixture source | decoder cross-language semantic equivalence, invalid/edge acceptance rules |
| RB-001/e2e legacy | rc >= 0, local list/log | host effect, filter ID, traffic and cleanup |
| CI matrix | job presence and synthetic `needs` payload | actual workflow result on current HEAD; shield requiredness |

Failure paths not materially exercised include: named-pipe partial frame and reconnect across all language implementations; PEP DLL missing/ABI version mismatch; provider returns success without receipt; duplicate daemon/process ownership; WFP driver unload during active rule; filter table full with cleanup; crash between host mutation and audit; disk full/partial forensic write; malformed/expired/rollback policy crossing TS→Zig→Rust; replay with historical binary/context mismatch; and child-process descendant leak after timeout

## 7. Exact verification commands

คำสั่งต่อไปนี้เป็นลำดับที่ควรใช้ใน disposable checkout/Windows lab ตามความเหมาะสม ไม่ได้หมายความว่า audit นี้รัน controlled host block แล้ว

### 7.1 Current-head and truth gate (read-only)

```bash
git rev-parse HEAD
git status --short
git ls-files
python tools/truth.py verify --json
python tools/truth.py verify --strict
```

Expected immediately for the present tree: `truth.py verify` must report stale `SYSTEM_MAP.json`, `FLOW_MAP.json`, `EVIDENCE_INDEX.json` (and any other stale head-bearing artifact). Do not proceed to a release claim until it returns exit 0 after regeneration from the same HEAD

### 7.2 CI semantics and skip visibility

```bash
python tools/ci_coverage.py --json
python tools/ci_coverage.py --needs-json '{"zig-build-test":{"result":"success"},"rust-pep-build":{"result":"success"},"c-native-build":{"result":"success"},"python-tests":{"result":"success"},"go-nose-build-test":{"result":"success"},"ts-policy-build":{"result":"success"},"security-scan":{"result":"success"},"shield-build":{"result":"skipped"}}'
python -m pytest tests/ -v -rs --ignore=tests/test_e2e.py
```

The second command must fail if Shield is declared required. If the intended policy is optional, remove it from runtime-required fixtures and document detection-only behavior. Do not treat a green job-presence check as code coverage

### 7.3 Build and test matrix on Windows (after toolchain preflight)

```powershell
zig build
zig build test
cargo test --release --manifest-path Cargo.toml
cargo build --release --manifest-path Cargo.toml
cmake -B build -S .
cmake --build build --config Release
Push-Location nose; go test ./...; go build ./...; Pop-Location
Push-Location ts_policy; npm ci; npm run typecheck; npm run test:all; Pop-Location
python -m pytest tests/ -v -rs --ignore=tests/test_e2e.py
python tools/release_engineering.py --verify
```

Use the root Cargo manifest selected by `git ls-files '*Cargo.toml'`; do not use the nonexistent `rust-src\Cargo.toml` mentioned in the handoff. Record exit code, toolchain versions, current HEAD and skip list for each job

### 7.4 Fixture verification (do not overwrite the audited checkout)

```bash
python - <<'PY'
from pathlib import Path
import hashlib, json
root=Path("tests/contracts/event_vectors/event_vectors")
meta=json.loads((root/"vectors_metadata.json").read_text())
for v in meta["vectors"]:
    p=root/v["file"]; b=p.read_bytes()
    assert len(b)==v["size"] and hashlib.sha256(b).hexdigest()==v["sha256"], v["file"]
print("all metadata vectors match")
PY
```

The generator `python tests/contracts/event_vectors/generate_test_vectors.py` is a write operation. Run it only in a disposable worktree, then compare generated files with `git diff --exit-code`; add one decoder test that consumes every vector and asserts explicit valid/invalid expectations before accepting them

### 7.5 WFP host proof (not a release gate by itself)

```powershell
$env:AEGIS_RUN_WFP_HOST_TESTS="1"
python -m pytest tests/wfp/test_t11_windows_host.py -v -rs
```

This existing test is insufficient: it must be extended before use to require `request_id`, non-zero `filter_id`, receipt-to-request linkage, baseline TCP `192.168.126.20:8080` HTTP 200, blocked traffic during the bounded window, cleanup using the original receipt/filter identity, and post-cleanup HTTP 200. Run only on the disposable VMware Windows host named in the handoff; do not substitute `netsh`, Firewall API, legacy `block_ip`, or bookkeeping

## 8. Recommended actions, ordered by priority

1. **P0 — Re-establish truth:** regenerate `SYSTEM_MAP.json`, `FLOW_MAP.json`, `EVIDENCE_INDEX.json` and all head-bearing truth artifacts at one locked HEAD; run `python tools/truth.py verify --strict`; attach the exact CI run SHA. Mark all older evidence entries stale instead of overwriting history.
2. **P0 — Downgrade claims:** change T14/T18/T9 and manifest language from host-verified/REAL to E1/E2/E3 structural or deterministic model until a Windows execution artifact exists. Add `evidence_level`, `tested_head`, `command`, `environment`, and `artifact_digest` fields.
3. **P0 — Build real enforcement proof:** define a receipt schema containing non-zero `request_id`, `trace_id`, `filter_id`, policy digest, driver/provider identity, result and cleanup result. Execute only through Control Pipe → Zig → Rust PEP → WFP bridge → driver. Require independent TCP postcondition and exact filter-identity cleanup.
4. **P0 — Unify signing bytes:** replace raw Zig `asBytes` over slice-bearing structs with an explicit generated canonical byte encoder. Produce one TS artifact, verify it in Zig/Rust/Python, and add negative tests for field order, lengths, expiry, key rotation and ABI version.
5. **P0 — Fix CI authority:** choose one Shield requiredness policy; make `ci_coverage.json`, `tests/runtime/conftest.py`, runtime manifest and workflow agree. Required skipped/cancelled/absent jobs must fail the gate.
6. **P1 — Replace false gates:** remove `python -c pass` from T17; execute benchmark binaries and enforce p50/p95/p99, throughput, CPU, memory, queue and drop thresholds. Add a branch/function coverage policy per language rather than calling job presence “coverage”.
7. **P1 — Make tests hermetic:** change T10 to assert missing invariant rather than write the manifest; use `tmp_path`/fixture roots for audit/rollback/config tests; kill/reap process groups and join/drain threads; clear `_SPAWNED_OUTPUT` after each process.
8. **P1 — Make required live tests non-skippable in required jobs:** separate static Linux tests from Windows host jobs. Missing binaries, daemon, driver, PEP DLL or Npcap must fail the host job, not become a pass-by-absence. Always publish `pytest -rs` skip reports.
9. **P1 — Consolidate fixtures:** choose one canonical vector directory, add metadata hashes and expected validity for every binary, and run Zig/Go/C++/Rust/Python decoders against the same five files. Remove or explicitly classify the duplicate `tests/tests/contracts` set.
10. **P1 — Correct docs/runbooks:** remove `block_ip`/`is_blocked` as enforcement proof; state detection-only and no-host-effect conditions; update dated phase reports or label them historical; remove nonexistent `core/...` aliases or make alias generation/tested existence explicit.
11. **P2 — Add failure-path matrix:** cover pipe partial reads/reconnect, ABI mismatch, missing provider, driver unload, table full, crash-after-mutation, durable write failure, policy canonicalization mismatch, replay identity mismatch, concurrent start/stop and descendant cleanup.

## 9. Conclusion

ตามขอบเขต Tests/fixtures/manifests/evidence ระบบมี test inventory กว้าง แต่ **จำนวน test และคำว่า REAL ไม่เท่ากับ coverage หรือ enforcement proof**. จุดที่ต้องหยุดการยอมรับคือ stale current-head chain, structural false positives, offline WFP model, signing byte mismatch และ legacy evidence path. หลังปิด P0 แล้วจึงค่อยประเมิน E4/E5/E6/E7 ใหม่จาก logs/artifacts ที่ผูกกับ current HEAD และ disposable Windows host

## References

[1]: tools/truth.py "Current-head truth artifact verifier"  
[2]: ci_coverage.json "Canonical/support CI matrix semantics"  
[3]: runtime_manifest.json "Runtime modules, authority invariants and enforcement mode"  
[4]: SYSTEM_MAP.json "Machine-readable system map"  
[5]: FLOW_MAP.json "Machine-readable flow map"  
[6]: EVIDENCE_INDEX.json "Evidence registry and evidence levels"  
[7]: tests/wfp/test_t11_windows_host.py "Opt-in Windows PEP/WFP host test"  
[8]: src/core/real_ips_path.zig "Offline deterministic IPS model"  
[9]: src/policy/policy_signing.zig "Zig policy signature canonicalDigest implementation"  
[10]: tests/policy_signing/test_t7_signed_policy.py "Python cross-language signing test"  
[11]: README.md "Repository readiness and evidence-level policy"  
