# SRC_CORE_DISPOSITION — REBUILD-001 (Read-Only Audit)

**HEAD at audit:** `a480efb177e4fe71f556d095b438924793f7054b` (branch `main`, clean tree except `.freebuff/`)
**Mode:** READ-ONLY. No production source modified. No files deleted.

---

## 1. Executive finding (overturns the machine maps)

The maps (SYSTEM_MAP.json, README §18, AI_CONTEXT) say:

> `core/*.zig` — legacy proof modules, **NOT compiled** by build.zig; `core/nids_main.zig` superseded by `src/main.zig`.

Measured reality at HEAD `a480efb`:

1. `src/core/nids_main.zig` is **not a build root** — `build.zig` has exactly three roots: `aegis_nids` (`src/main.zig`), `zig build test` (`src/all_tests.zig`), fuzz (`src/fuzz_entry.zig`). The legacy entry point is never compiled, not even type-checked.
2. **But the production graph imports `src/core/` in both directions.** Canonical modules under `src/policy/`, `src/forensic/`, `src/windows/`, `src/reliability/`, `src/capture/` import `../core/*` (see §3). The canonical Event Fabric (`src/capture/nose_contract.zig`) depends on `src/core/priority_queue.zig`.
3. Only **two** `src/core` files are canonical today (`diagnostics.zig`, `memory_pool.zig` — imported by `src/main.zig`). The other 34 files are compiled by **no** build root, so their internal `test` blocks (e.g. all tests in `priority_queue.zig`) **never run in CI**.
4. Therefore: `src/core/` is not "legacy junk" and not "a second runtime that works". It is an **orphaned half of the production dependency graph**: half-connected, unbuilt, untested, but load-bearing for the modules that would make the full AEGIS flow (dispatcher/lifecycle/forensics/canary/pipe sensors) work again.

This matches the owner's report: the old runtime lived in `src/core/`, the spine moved to `src/`, the relationship mapping was never completed, and the system stopped working.

## 2. Security findings (P0)

| # | Finding | Evidence | Action required (later phases) |
|---|---------|----------|-------------------------------|
| P0-1 | **Zig→WFP enforcement bypass surface.** `src/core/rust_pep.zig` exposes `block_ip/read_events/wfpInit` and calls `src/policy/wfp_ioctl.zig` (`\\.\AegisWfpDevice`) **directly from Zig**, with no Rust PEP in the loop. Forbidden by AEGIS invariant §18 ("Zig → direct privileged enforcement"). | `src/core/rust_pep.zig` imports `../policy/wfp_ioctl.zig`; consumers: `windows_capture.zig`, `forensics_engine.zig`, `replay_engine.zig`, `ips_canary.zig`, `dispatcher.zig`, `lifecycle.zig` | When integrating: route `block_ip` through `src/policy/pep_bindings.zig` (aegis_pep.dll) only. `src/core/rust_pep.zig` must not be a second enforcement entry. |
| P0-2 | **Fail-open Tier-3.** `bridge_init.validatePayloadSafety()` returns `true` (fail-open) when `sec_monitor.dll` (shield) is absent. shield/ was deleted. | `src/core/bridge_init.zig` `initRustShield()`, search paths `target\release`, `shield\target\release` | Either recreate the payload-safety validator inside `rust-src` (recommended, see SHIELD decision) or make the fail-open explicit + audited. |
| P0-3 | **CI is red by construction.** `ci.yml` `go-build-test` runs `cd go/aggregator && go build ./...` — `go/aggregator` does not exist at HEAD. Meanwhile `nose/` (the real Go component) is never built or tested in CI. | `.github/workflows/ci.yml` lines ~147-161; `git ls-files` | Repoint the Go job at `nose/`; drop or restore `go/aggregator` per GO decision. |

## 3. Dependency facts (measured, not assumed)

### src/ → src/core/ edges (production modules importing "legacy" core)

```
src/capture/minifilter_reader.zig   → core/bridge_init.zig
src/capture/pipe_monitor.zig        → core/bridge_init.zig
src/capture/windows_capture.zig     → core/bridge_init.zig, core/nids_analyze.zig, core/rust_pep.zig
src/capture/nose_contract.zig       → core/priority_queue.zig          ← canonical Event Fabric!
src/forensic/forensics_engine.zig   → core/rust_pep.zig, core/brain_engine.zig
src/forensic/forensics_integration.zig → core/brain_engine.zig, core/rust_pep.zig
src/forensic/replay_engine.zig      → core/rust_pep.zig
src/forensic/replay_integration.zig → core/rust_pep.zig (EnforcementStatus, RejectionReason)
src/policy/dispatcher.zig           → core/brain_integration, core/brain_engine, core/rust_pep_integration, core/rust_pep, capture/nose_contract
src/policy/dispatcher_phase_b.zig   → core/brain_integration, core/brain_engine, core/rust_pep_integration, capture/nose_contract
src/policy/policy_contract.zig      → core/rust_pep.zig
src/policy/policy_engine.zig        → core/brain_engine.zig
src/policy/policy_integration.zig   → core/brain_engine.zig
src/reliability/lifecycle.zig       → core/brain_integration, core/rust_pep_integration, policy/dispatcher.zig
src/reliability/reliability.zig     → core/nids_analyze.zig (AegisIpcEvent == 76 bytes)
src/windows/ips_canary.zig          → core/rust_pep.zig
src/windows/ips_canary_integration.zig → core/rust_pep.zig
```

### src/core/ → src/ edges (legacy core importing canonical src)

```
core/priority_queue.zig → contract/canonical_event.zig, contract/event_queue.zig
core/brain_engine.zig   → contract/canonical_event, capture/flow_engine, detection/{detection_engine,verdict_aggregator,correlation_engine,threat_intel,rag_engine}
core/rust_pep.zig       → contract/canonical_event, policy/policy_engine, policy/wfp_ioctl
core/bridge_init.zig    → core/rust_pep (+ DynLib lookups: aegis_ipc.dll, sec_monitor.dll)
core/nids_main.zig      → core/{bridge_init,nids_analyze,nids_capture}, capture/{windows_capture,minifilter_reader,pipe_monitor}, forensic/forensic_log, capture/nose_contract
core/nids_capture.zig   → core/{bridge_init,nids_analyze}, windows/win32_io, capture/{nose_contract,nose_integration}
core/nids_analyze.zig   → core/bridge_init, forensic/forensic_log, capture/nose_contract, windows/win32_io
```

The tangle is **bidirectional**: canonical capture/policy/forensic modules call into core; core calls back into canonical contract/policy. This is the "relationship not mapped" break the owner described.

### Reachability classes (as compiled today)

| Class | Meaning | Files |
|---|---|---|
| R1 built+run | reachable from `src/main.zig` exe | core/diagnostics.zig, core/memory_pool.zig |
| R2 test-graph only | reachable from `src/all_tests.zig` | (none in core beyond R1 — tests/core/* only mirror diagnostics+memory_pool) |
| R3 orphaned production graph | imported by production modules that themselves are imported by no root (lifecycle.zig, dispatcher.zig, forensics_engine.zig, windows_capture.zig, minifilter_reader.zig, pipe_monitor.zig, ips_canary*.zig, dispatcher_phase_b.zig) | priority_queue, brain_engine, brain_integration, rust_pep, rust_pep_integration, bridge_init, nids_analyze, nids_capture |
| R4 dead entry | no root reaches it | nids_main.zig |
| R5 proof/bench/harness | proof modules, compiled only if their harness is reached | see matrix §4 |

## 4. File matrix (every `src/core/` file exactly once)

| File | Role | Owner | Existing equivalent | Reachability | Destination | Disposition | Risk |
|---|---|---|---|---|---|---|---|
| diagnostics.zig | Structured logging + metrics counters | Zig runtime | none (canonical) | R1 built+run | stays `src/core/` | INTEGRATE | low |
| memory_pool.zig | Slab allocator + lock-free ring | Zig runtime | none (canonical) | R1 built+run | stays `src/core/` | INTEGRATE | low |
| priority_queue.zig | 3-priority CanonicalEvent queue | Event Fabric | contract/event_queue.zig (component, not duplicate) | R3 (nose_contract depends on it) | stays, promoted to Event Fabric infra | INTEGRATE | low |
| brain_engine.zig | Heuristic threat advisor (advisor-only, cannot enforce) | Intelligence | brain/ (Python, different layer) | R3 | stays | INTEGRATE | low |
| brain_integration.zig | Zig↔Python/Cython bridge facade | Intelligence | brain/ windows_brain.py | R3 | stays | INTEGRATE | low |
| rust_pep.zig | WFP ring + block_ip bridge (imports policy/wfp_ioctl) | Security (must be) | policy/pep_bindings.zig, policy/wfp_production.zig | R3 | merge into src/policy behind PEP gate | MERGE | **P0-1 bypass** |
| rust_pep_integration.zig | Integration surface of rust_pep | Security | policy/pep_bindings.zig | R3 | merge with rust_pep.zig | MERGE | P0-1 |
| bridge_init.zig | Init/shutdown: WFP IOCTL, C++ IPC DLL, Rust shield DLL, UDP brain spool, g_shutdown | Runtime spine | none | R3 | move to src/reliability/ or src/runtime/; retarget shield lookup | MERGE | P0-2 fail-open |
| nids_analyze.zig | 3-tier analyzer: Aho-Corasick, rules loader (HMAC), pipe+TCP servers, rate limits | Detection | detection/signature_engine.zig (AC engine), policy loaders | R3 | extract ruleset loader + counters into src/detection; sensor loops optional | MERGE | medium |
| nids_capture.zig | Named-pipe sensor (admin-only SDDL, overlapped I/O) | Acquisition | capture/pipe_monitor.zig | R3 | move to src/capture | MERGE | low |
| nids_main.zig | Legacy 6-thread entry (analyze, pipe, WFP, minifilter, monitor, health pipe) | Legacy runtime | src/main.zig (canonical, richer) | R4 dead | keep as reference under core/ (no build root) | ARCHIVE | medium (drift, never type-checked) |
| real_ips_path.zig | Enforcement-chain model: telemetry→…→sig_verify→PEP→WFP, fail-closed, with tests | Security proof | docs/platform/p4-enforcement-contract.md | R5 | keep as executable spec | PROOF-ONLY | low |
| authority_review.zig | Authority conformance review harness | Proof | — | R5 | tests/proof | PROOF-ONLY | low |
| brain_proof.zig | Brain advisor behavior proof | Proof | — | R5 | tests/proof | PROOF-ONLY | low |
| canary_progression.zig | IPS canary progression checks | Proof | windows/ips_canary.zig (production) | R5 | tests/proof | TEST-ONLY | low |
| compliance_proof.zig | Compliance assertions | Proof | — | R5 | tests/proof | PROOF-ONLY | low |
| compliance_reporter.zig | Compliance report emitter | Proof | — | R5 | tests/proof | PROOF-ONLY | low |
| concurrency_harden.zig | Race/deadlock/shutdown scenario suite | Test | src/tests/ (mirrors) | R5 | tests/proof | TEST-ONLY | low |
| concurrency_harden_integration.zig | Integration wiring of the above | Test | — | R5 | tests/proof | TEST-ONLY | low |
| config_reload_proof.zig | Hot-reload correctness proof | Proof | main.zig reloadRules (production) | R5 | tests/proof | PROOF-ONLY | low |
| contract_freeze.zig | ABI/schema freeze assertions | Proof | shared/abi | R5 | tests/proof | PROOF-ONLY | low |
| documentation_proof.zig | Docs-vs-code consistency proof | Proof | — | R5 | tests/proof | PROOF-ONLY | low |
| e2e_harness.zig | End-to-end pipeline harness | Test | tests/runtime/* (python) | R5 | tests/proof | TEST-ONLY | low |
| e2e_harness_integration.zig | Harness wiring | Test | — | R5 | tests/proof | TEST-ONLY | low |
| fabric_accounting.zig | Fabric accounting proof (in=out+dropped+…) | Proof | nose_contract stats | R5 | tests/proof | PROOF-ONLY | low |
| final_integration_proof.zig | Final integration gate proof | Proof | — | R5 | tests/proof | PROOF-ONLY | low |
| integration_test.zig | Cross-subsystem integration test | Test | src/tests/forensic/test_integration.zig | R5 | tests/proof | TEST-ONLY | low |
| integration_test_cli.zig | CLI for integration test | Test | — | R5 | tests/proof | TEST-ONLY | low |
| legacy_removal.zig | Self-documenting deprecation map | Meta | docs/architecture/DEPRECATION_MAP.md | R5 | archive with docs | ARCHIVE | low |
| perf_benchmark.zig | Performance benchmarks | Bench | — | R5 | tests/bench | BENCHMARK-ONLY | low |
| perf_benchmark_cli.zig | Bench CLI | Bench | — | R5 | tests/bench | BENCHMARK-ONLY | low |
| performance_harness.zig | Perf harness | Bench | — | R5 | tests/bench | BENCHMARK-ONLY | low |
| performance_integration.zig | Perf integration wiring | Bench | — | R5 | tests/bench | BENCHMARK-ONLY | low |
| performance_tuning_proof.zig | Tuning proof | Proof | — | R5 | tests/proof | PROOF-ONLY | low |
| host_correlator_config.json | Config for integration test | Test config | configs/ | R5 | move with harness | TEST-ONLY | low |
| integration_test_config.json | Config for integration test | Test config | configs/ | R5 | move with harness | TEST-ONLY | low |
| perf_benchmark_config.json | Config for benchmarks | Bench config | configs/ | R5 | move with harness | BENCHMARK-ONLY | low |

**Total: 36 files (33 .zig + 3 .json). No DELETE dispositions** — per owner directive, nothing in `src/core/` may disappear.

## 5. Duplicate matrix (core vs canonical owners)

| Responsibility | core file | Canonical owner | Relationship |
|---|---|---|---|
| Aho-Corasick engine | nids_analyze.zig (own impl) | detection/signature_engine.zig | PARTIAL DUPLICATE (core version adds HMAC rules loader, rate limits, session tracking) |
| Pipe sensor | nids_capture.zig | capture/pipe_monitor.zig, capture/nose_pipe_reader.zig | PARTIAL DUPLICATE (core version is admin-only SDDL, richer) |
| Runtime entry | nids_main.zig | src/main.zig | LEGACY (canonical is strictly richer: service, control pipe, watchdog, ETW/FIM/registry) |
| WFP bridge | core/rust_pep.zig | policy/pep_bindings.zig → aegis_pep.dll; policy/wfp_ioctl.zig (transport) | WRAPPER + **BYPASS** (calls wfp_ioctl without PEP) |
| Queue | priority_queue.zig | contract/event_queue.zig | COMPOSITION (not duplicate: PQ = 3× EventQueue + priority logic) |
| Brain advisor | brain_engine.zig | brain/ (Python analytics) | COMPLEMENT (Zig heuristic advisor vs Python RAG — different tiers) |
| Aggregation | — | federation/aggregator.zig | go/aggregator was the Go twin; Zig owns it now |

## 6. What must happen to make `src/core/` usable again (patch order, no deletes)

1. **REBUILD-002 (test closure):** add `src/core` proof/test modules (R5) into `src/all_tests.zig` so the 30+ untested files get compiled and their tests run. Zero behavior change. This alone would have caught drift.
2. **REBUILD-003 (wire the production orphans):** import `reliability/lifecycle.zig` → `dispatcher.zig` → `forensics_engine.zig` chain into the canonical graph (or all_tests first), fixing compile drift as it surfaces. This is where "relationship not mapped" gets repaired.
3. **REBUILD-004 (P0-1):** re-route `core/rust_pep.zig` block_ip through `policy/pep_bindings.zig`; demote `core/rust_pep.zig` to transport-only or fold into `policy/wfp_production.zig`.
4. **REBUILD-005 (P0-2):** recreate the payload-safety validator inside `rust-src/lib.rs` (see SHIELD decision) and retarget `bridge_init` lookup; make fail-open configurable and audited.
5. **REBUILD-006 (P0-3):** fix CI Go job → `nose/` (see GO decision).
6. **REBUILD-007:** decide `nids_main.zig` fate (stay ARCHIVE as reference; optionally extract the health pipe server — it implements RUNTIME_CONTRACT §4 — into canonical runtime).
