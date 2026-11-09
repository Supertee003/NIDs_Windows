# COVERAGE-BOUNDARY-001 — what the repo contains vs what has evidence (survey, 2026-11-09)

- **TYPE:** read-only survey (E1 by construction; two measurements are E2/E3: see §7)
- **HEAD at survey:** `cca82e1` (build source `a1024f2`), worktree clean
- **CLAIM:** states the boundary between proven and never-surveyed areas. It
  closes nothing and adds no capability.

## 1. Method (reproducible)

Two scripts, both read-only, both under
`admin-evidence/coverage-boundary-20261109/` (gitignored host evidence):

```
python admin-evidence/coverage-boundary-20261109/coverage_map.py
#  -> coverage.json : per-module files/loc/evidence-mentions/test files, and
#     per-file count of evidence entries that name the file stem

python admin-evidence/coverage-boundary-20261109/reachability.py
#  -> reachability.json : @import graph over all 292 src/**.zig files from the
#     8 build roots in build.zig
```

**Method validation:** the reachability walk returns exactly **35** files that
no build root imports, and that set is byte-for-byte the `OUT_OF_UNIT` registry
in `tests/security/test_zig_test_scope.py` (integration 17, proof 11, plus
`flow_types.zig`, `npcap_test_live.zig`, `federation.zig`, `dispatcher*.zig`,
`reliability*.zig`). Two independent derivations agreeing means the boundary is
**declared**, not accidental.

Limits of the counting: evidence matching is lexical (file stem or module path
inside any entry field). Single-file components (`rust-src/lib.rs`,
`aegis_dashboard/src/main.rs`) are therefore under-counted, so §5 supplements
them with keyword counts.

## 2. The declared boundary (authoritative)

`SYSTEM_MAP.json::component_classification`:

| Class | Declared members |
|---|---|
| CANONICAL | `src/main.zig`, `rust-src/lib.rs`, `nose/main.go`, `src/windows/*.c`, `bridge/`, `brain/`, `ts_policy/` |
| SUPPORT | `shield/`, `go/aggregator/` |
| OPTIONAL | `mouth/`, `aegis_dashboard/` |
| LEGACY | `core/nids_main.zig`, `lib.rs (root)` |

Ten components are declared: `zig_core`, `rust_pep`, `go_nose`, `cpp_native`,
`cpp_bridge`, `brain`, `ts_policy`, `aggregator`, `shield`, `dashboard`.
Everything else in the tree is **undeclared** — and that is where most of the
never-surveyed mass sits.

## 3. Component matrix (measured)

| Component | files | LOC | evidence entries naming a file / keyword | latest evidence | E5 |
|---|---|---|---|---|---|
| zig_core | 145 | 75,628 | 54 files / 36 module mentions | 2026-11-09 | 41 |
| go_nose | 25 | 5,839 | 5 files / 70 | 2026-11-09 | 44 |
| cpp_native (`src/windows`+`drivers`) | 33 | 17,151 | 11 / 18 | 2026-11-09 | 14 |
| cpp_bridge | 12 | 3,044 | 1 / 27 keyword | 2026-11-09 | 11 |
| brain | 42 | 80,076 | 7 / 100 | 2026-11-09 | 5 |
| rust_pep | 1 | 2,937 | 9 keyword (`aegis_pep`) | 2026-11-09 | 3 |
| aggregator | 11 | 1,616 | 3 / 4 keyword | **2026-09-11** | 1 |
| shield | 2 | 93 | 8 keyword | **2026-09-11** | 2 |
| dashboard | 1 | 921 | 3 keyword | **2026-10-28** | **0** |
| ts_policy | 6 | 1,228 | 1 keyword | **—** | **0** |
| mouth (OPTIONAL) | 1 | 1,516 | 0 / 1 keyword | **2026-09-11** | 0 |

Two things stand out:

- **`ts_policy` is CANONICAL yet has no dated evidence and no E5** — one entry
  mentions it, undated. (Its role is advisory/authoring, but the map calls it
  canonical.)
- **`dashboard` has zero E5** and its last record is 2026-10-28; `shield` and
  `aggregator` have not been evidenced since **2026-09-11** — six weeks.

## 4. Undeclared mass (never inside any evidence contract)

| Area | files | LOC | evidence | note |
|---|---|---|---|---|
| `tools/` (aegisctl + helpers) | 67 | 15,597 | 82 mentions, 34 files named | operative CLI; partially covered |
| `scripts/` | 79 | 14,140 | 8 mentions, **5 files named** | 74/79 scripts never named by any entry |
| `src/tests/` | 119 | 23,299 | unit-test sources (reachable, run by `zig build test`) | — |
| `src/platform` | 2 | 444 | **0** | `win32_pipe.zig`, `win32_service.zig` — service/pipe plumbing with no record and no test |
| `src/operator`, `src/lab` | 2 | 67 | **0** | contract stubs |
| `analysis/` (root file) | 1 | 19 | 0 | |

## 5. The never-surveyed set (no evidence entry names the file)

Counted per module as `files_with_evidence / files`:

| module | never named | notable unnamed files |
|---|---|---|
| `src/detection` | **13 / 15** | `detection_engine`, `detection_interface`, `detection_result`, `signature_engine`, `anomaly_detector`, `ml_detector`, `correlation_engine`, `injection_detector`, `proto_anomaly`, `rag_engine`, `rag_intelligence`, `threat_intel`, `verdict_aggregator` |
| `src/windows` | **17 / 23** | `hids_engine`, `hids_process_monitor`, `host_telemetry*` (4), `registry_monitor`, `registry_trie`, `ips_canary*` (3), `ips_simulation`, `injection_detector`, `adapter_contract`, `cpp_adapter`, `win32_io`, `windows_adapters`, `fim_native.c` |
| `src/core` | **17 / 22** | `nids_main`, `nids_analyze`, `brain_engine`, `real_ips_path`, `priority_queue`, `memory_pool`, `perf_benchmark`, `performance_harness`, `e2e_harness`, `fabric_accounting`, `authority_review`, `canary_progression`, `concurrency_harden`, `contract_freeze`, `legacy_removal`, `integration_test`, `compliance_reporter` |
| `src/forensic` | **13 / 21** | `evidence_record`, `decision_trace`, `replay_engine`, `replay_verifier`, `replay_integrity`, `replayable_security`, `replay_contract`, `siem_forwarder`, `release_gate`, `release_manifest`, `forensics_engine`, `abi_contract`, `python_contract` |
| `src/policy` | **11 / 18** | `policy_engine`, `policy_signing`, `trust_store`, `tier3_state`, `enforcement_receipt`, `shadow_decision`, `shield_screen`, `rule_action`, `control_ipc`, `wfp_production`, `dispatcher_phase_b` |
| `src/capture` | 12 / 18 | `flow_engine`, `flow_table`, `flow_types`, `l7_classifier`, `nose_contract`, `npcap_capture`, `packet_decoder`, `pipe_monitor`, `stream_reassembly`, `proto/parsers`, `windows_capture`, `npcap_test_live` |
| `src/federation` | 7 / 9 | `federation`, `federation_tcp`, `federation_codec`, `cluster_coord`, `cluster_uplink`, `node_registry`, `federation_rust_tls` |
| `src/reliability` | 6 / 10 | `watchdog`, `fault_injection`, `fault_matrix`, `latency_histogram`, `release_provenance`, `security_check` |
| `src/xdr` | 4 / 7 | `xdr_engine`, `xdr_correlator`, `xdr_harden`, `xdr_incident_graph` |
| `src/contract` | 3 / 8 | `abi_manifest`, `event_fabric`, `wire_event` |
| `src/control` | 1 / 6 | `state_machine` |
| `src/pipeline` | 1 / 9 | `data_plane_contract` |
| `brain` | 35 / 42 | includes `acceptance_gates`, `core_routing`, `detection_scan`, Cython bridge files |
| `scripts` | 74 / 79 | `aegis_alerts`, `aegis_api`, `aegis_block`, `aegis_console*`, `add_web_evidence`, … |
| `tools` | 33 / 67 | `aegisctl/components`, `utils`, `audit_kernel_runtime`, `backup_recovery`, … |

These modules are **not dead**: 257/292 Zig files are reachable from the build
roots and 198 inline `test` blocks live in `src/detection` alone. The gap is
**traceability + host proof**, not code.

## 6. Out-of-unit suites (declared, and never run by `zig build test`)

35 files are excluded from the unit graph by the ratchet:

- 17 integration harnesses (`src/tests/integration/*`) — E3 scope
- 11 proof CLIs (`src/tests/proofs/*`) — proof scope
- 7 others (`flow_types`, `npcap_test_live`, `federation`, `dispatcher`,
  `dispatcher_phase_b`, `lifecycle`, `reliability`)

They are compiled by `zig build core-tools`, not executed by CI. Measured today
(because this had never been checked at this HEAD):

```
zig build core-tools                    -> exit 0
zig-out/bin/aegis_integration_test demo -> 6/6 scenarios PASS
   single-node-attack, cross-node-campaign, federation-failover,
   full-kill-chain, detector-aggregation, multi-source-correlation
```

So the E3 harness is **alive**, but no gate runs it: a break here would be
invisible to `zig build test`.

## 7. Junk / ambiguous artifacts (disposition needs an owner decision)

| Path | Why it is in this list |
|---|---|
| `fix_bridge_banner.py`, `fix_encoding.py`, `fix_head.py`, `test_needs.py` | one-shot patch scripts at repo root, 0 evidence, 0 tests, never imported |
| `tests/tests/contracts/{canonical_event.bin,wire_event.bin,test_vectors.json}` | duplicated fixture path (`tests/contracts/**` is the real one) |
| `.work/` (gitignored) | scratch evidence-append scripts from earlier rounds |
| `zig-out/bin/aegis_nids.old`, `aegis_nids_new.exe`, `*.obj` | local build leftovers (untracked, ignored) |

## 8. Boundary proposal

**Ring 1 — must carry evidence for every change (runtime spine):**
`src/contract`, `src/pipeline`, `src/capture`, `src/forensic`, `src/control`,
`src/policy`, `nose/`, `bridge/`, `drivers/`, `src/windows`, `rust-src`.
Rationale: these are the modules whose failure becomes silent data loss or a
false "all good" health projection.

**Ring 2 — support, evidence on change but no per-file record required:**
`brain/`, `go/aggregator`, `tools/aegisctl`, `shield/`, `dashboard`.
Rationale: advisory or operator-facing; a stale record is acceptable if the
health surface still tells the truth.

**Ring 3 — outside the evidence contract (declare it explicitly):**
`scripts/` (operator one-shots), `src/tests/**` (harnesses), `aegis_dashboard`
if it is being retired, `ts_policy` if it stays advisory-only, `mouth/` if it is
retired, root `fix_*.py`.

The gap this survey exposes is that **Rings 2 and 3 are not written down
anywhere**, so a reader cannot tell whether a module with no recent evidence is
"out of scope" or "forgotten". §3's 2026-09-11 rows are exactly that ambiguity.

## 9. Questions only the owner can answer

1. `mouth/` — OPTIONAL in the map, 1 file, last evidence 2026-09-11: keep or retire?
2. `aegis_dashboard/` — declared component, 0 E5, last record 2026-10-28: is it a shipped surface?
3. `ts_policy/` — CANONICAL but advisory-only and unevidenced: downgrade the class or evidence it?
4. Root `fix_*.py` + `tests/tests/**` — delete, or keep as historical?
5. `src/platform/win32_{pipe,service}.zig` — 444 LOC behind the service lifecycle with zero records: promote to Ring 1?

## 10. Reproduce

```
python admin-evidence/coverage-boundary-20261109/coverage_map.py
python admin-evidence/coverage-boundary-20261109/reachability.py
zig build core-tools && ./zig-out/bin/aegis_integration_test demo
```
