# AEGIS Unwired-Module Inventory (living checklist)

**HEAD:** `aba9727` · **Updated:** 2026-10-04
**Rule:** every module is either ON the daemon path, TEST-ONLY (harness with
no production importer), QUARANTINED (naming/doc hazard, must stay
unlinked), or CONNECT-PLANNED (tracked slice). Anything else is a finding.

## ON PATH (golden — do not duplicate)
- `src/daemon.zig`, `src/main.zig`, `src/pipeline/*`, `src/capture/*`
  (flow_table, nose_pipe_reader, pipe_monitor), `src/detection/*`
  (signature_engine, anomaly_detector, correlator ← T1-CORR-010,
  threat_tracker, rag_engine[advisor]), `src/contract/*`,
  `src/policy/{pep_bindings,tier3_state,action_dispatcher,policy_ir,
  enforcement_receipt}`, `src/forensic/forensic_pipeline.zig`,
  `src/control/*`, `src/platform/*`, `src/windows/{etw_realtime,fim,
  registry_monitor,cpp_adapter}`, `src/reliability/{watchdog,
  security_check,fault_injection}`, `src/core/{diagnostics,memory_pool,
  bridge_init,rust_pep,runtime_paths,integration_test(main harness only)}`
- `rust-src/lib.rs` (PEP), `nose/{main,capture,canonical,pipe_writer,
  signature_classifier}`, `brain/windows_brain.py` (advisory),
  `tools/aegisctl*` (control plane), dashboards (readers)

## TEST-ONLY (harness, never wire into daemon)
- `src/federation/*` (7 files: codec, tcp, tls, cluster, registry,
  aggregator, bench) + `src/tests/cli/federation_*.zig`
- `src/xdr/*` (engine, correlator, graph, fabric, harden)
- `src/tests/cli/*` (17 demo harnesses), `src/tests/proofs/*`,
  `src/tests/integration/*`, `src/core/{integration_test (harness),
  perf_benchmark}`
- `src/forensic/{replay_engine,replay_verifier,replay_integrity,
  replayable_security,decision_trace(advisory),siem_forwarder(library)}`
- `src/policy/{dispatcher,dispatcher_phase_b}` + `src/reliability/
  lifecycle.zig` — quarantined orchestrators (headers + NEG pin)
- `src/windows/{host_telemetry_mock,host_telemetry_scenarios,
  windows_adapters,hids_process_monitor}`, `src/core/{brain_engine,
  real_ips_path,nids_analyze,nids_capture,nids_main(windows_capture)}`
- `src/detection/{detection_engine,ml_detector,verdict_aggregator,
  threat_intel,rag_intelligence,proto_anomaly(partial)}`
- `mouth/` (standalone TUI), `go/aggregator/` (SUPPORT sidecar),
  `aegis_dashboard/` (reader), `ts_policy/` (advisory compiler)

## QUARANTINED (must stay unlinked — pins enforce)
- `shield/src/{pep,windows_enforce}.rs` naming (screening only)
- `drivers/wfp_callout/quarantined/aegis_wfp_comm.c` (duplicate BlockFlow)
- `aegis_bridge block_ip/unblock_ip` externs (removed from Zig contracts)
- `scripts/{aegis_block,aegis_unblock}.py` (refuse mutations)
- `configs/aegis.conf [ips]` (no reader; must stay disabled)
- `installer.nsi` fossil, `tools/legacy/*`, `release/T20-final/*`
- TCP control transport (removed), web 0.0.0.0 bind (loopback only)
- `AEGIS_FAIL_OPEN` (removed), `mouth/enforced.json` (renamed)

## CONNECT-PLANNED (needs a design slice, NOT ad-hoc wiring)
- [ ] TS-IR exporter → `policy_ir.json` (magic/enum/bytes reconcile + vectors)
- [ ] Brain→daemon return contract (or declare one-way permanent)
- [ ] SIEM pipeline wiring (library ready; transport decision open)
- [ ] `forensics.replay` handler ← replay_verifier
- [ ] FED-XDR verdict: permanent test-only or Project 4+ cluster
- [ ] policy_signing onto enforcement path + trust_store CNG + two-person API
- [x] IPv6 full (contract v2) — wire v2 decode-ready T2-V6-022a (Go/Zig/
  C++/Python dispatch + 006 vector + bit2 preserved) + nose live emit
  T2-V6-022b (`eventFromPacket` sidecars, `Send` dispatches v2).
  REMAINING: detection/flow/forensic plumbing of full addresses
  (u32 identity + bit2 guard unchanged)
- [ ] duplicate `dispatcher` removal — BLOCKED 2026-10-04 (verified, 25 E2
  pins green): `tests/e2e/test_t14_windows_golden_path.py`
  (`test_incident_id_survives_dispatcher`,
  `test_dispatcher_is_sole_orchestrator`) reads `src/policy/dispatcher.zig`
  and pins it as SOLE orchestrator; `tests/forensics/
  test_t12_forensics_replay.py::test_dispatcher_writes_trace_for_every_decision`
  reads BOTH `dispatcher.zig` + `dispatcher_phase_b.zig`. Zero @import
  edges (only `reliability/lifecycle.zig` imports `dispatcher.zig`, itself
  unimported), but deletion breaks T14/T12. Needs architecture decision
  first: migrate T14/T12 pins to `pipeline/event_processor` +
  `policy/action_dispatcher` (aligns with T1-DISP-018 quarantine) or
  re-promote dispatcher — NOT silent removal.
- [ ] flow `is_ipv6` plumbing (normalize hardcodes false)

## COUPLING MAP (deep investigation 2026-10-04 — read before refactoring)

- Zig hubs (272 files): `contract/canonical_event.zig` 52 importers,
  `contract/event.zig` 27, `core/diagnostics.zig` 23. The spine is real;
  touch these only with cross-module evidence.
- Legacy fan-in: `core/rust_pep.zig` (shim, NOT the authority) is
  imported 15× across policy/forensic/windows/xdr/dispatcher; `daemon.zig`
  imports `core/{bridge_init,diagnostics,memory_pool,nids_capture,
  runtime_paths}` directly. Legacy-core never died — quarantine is by
  convention + NEG pins, not by graph.
- Test→tree writes (15 files): lab reruns restamp
  `analysis/PHASE8_*`, evidence-graph/pagination/policy-signing tests
  rewrite fixtures. Tests are NOT hermetic; a green run can dirty the
  tree and invalidate truth/release gates — verify `git status` after
  every matrix run and revert producer-owned stamps.
- Import-time effects (pinned): `brain/windows_brain.py` import runs
  sys.path edits + warning prints (banner/UDP/loop correctly gated
  behind `__main__`). Pin: `tests/brain/test_import_hygiene.py`.
- Full-suite teardown AV (RESOLVED 2026-10-04): combined `tests/` run
  segfaulted nondeterministically at/after teardown while all 546+ tests
  passed (summaries printed). cdb native stack: AV in `Py_Dealloc` during
  `Py_RunMain` teardown, pure python314.dll frames, no product DLL;
  reproduced on 3.11 and with/without `.pyd` files (Cython exonerated).
  Root-cause class: lingering pipe-drain threads blocked in readline()
  across interpreter teardown (bisect: every subset green, only the full
  set crashed). Fix: `tests/runtime/conftest.py::pytest_sessionfinish`
  reaps straggler procs and joins drain threads (T-HYG-002). Evidence:
  two consecutive full runs green after the fix (555 passed, exit 0).
  Remaining flake (separate, needs live daemon): pagination volume tests.

## KNOWN-OPEN robustness (filed, unscheduled)- flow pointer lock-escape (single-threaded today), forensic `append catch 0`,
  correlator/AC per-packet allocator, FIM non-ASCII/long-path caps,
  registry re-arm failure silent, ETW GUID mismatch/compound-literal UB,
  TLS parser bounds, nose frameLen stall, pipe_monitor prefix-only,
  nose TUI synthetic counters, C++ DNS port compare, IPC short framing,
  brain 4096 truncation/log growth/Rules hot-reload crash, TS u64 precision,
  SBOM salt, go.sum/Go split, CI truth/Trivy gates, web SSE backpressure,
  receipt validator reconciliation, disabled_rules end-to-end, canary IDs,
  siem_config dead transports, metrics u64→u32 truncation, watchdog toothless,
  fault-maybeCorrupt post-validation, quarantine federation best-effort,
  rust query unauthenticated, single g_ProofFilterId, WFP unload leak,
  query vs present tri-state callers, PepContext policy_version=0,
  signed_by never validated, flow identity dst-only, per-call DLL load,
  provider GUID split, ring stats partial, single-slot globals,
  `config/Rules.json` mirror drift, `blocked_ips.json` candidate confusion,
  `policy reload` unreachable via CLI parsers, Pro Console no live watch,
  graph readability at 100+ records, nose_dashboard.exe duality,
  `AEGISCTL_PATH` unused, brain UDP spoofable/127.0.0.1 attribution,
  `run_aegis.bat` 5-subsystem model + wmic, `D:\NIDs_Windows` hardcodes,
  Kali script default target, VMware auto-select fallback, ETW Linux stub
  reporting running, `last_event_ms` dual-clock, `struct_size` 128-vs-109
  confusion, legacy `serialize` memcpy path, wire CRC-no-HMAC,
  `getFrameSize` unchecked, event_queue 1500 truncation vs len claim,
  severity collapse, legacySource downgrade, `beat()` on drop,
  stream-reassembly stall/no-evict, DNS compression blind, HTTP unbounded
  headers, RDP/Kerberos single-magic FP, pipe_reader log flood/poll modes,
  `g_ac_mutex` copy-then-use, rule FNV collisions, golden-table drift,
  `RuleAction` enum vs Rules.json vocab, `threat_score`/`weight` fixed,
  incident cap fail-open, INCIDENT_TTL unenforced, IPv4-only evidence ring,
  `anomalies_emitted` never incremented, RAG wildcard overmatch,
  `successRate` pending-blind, spool replay automation, spill disk-full path
