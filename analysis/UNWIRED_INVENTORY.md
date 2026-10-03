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
- [ ] IPv6 full (contract v2) — v1 marks bit2, see T2-V6-016
- [ ] duplicate `dispatcher` removal (needs test-harness migration first)
- [ ] flow `is_ipv6` plumbing (normalize hardcodes false)

## KNOWN-OPEN robustness (filed, unscheduled)
- flow pointer lock-escape (single-threaded today), forensic `append catch 0`,
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
