# AEGIS Language Ownership (STEP 0 — Baseline Freeze)

## Ownership Matrix

| Language | Role | Modules | Creates Events? | Modifies Events? | Makes Decisions? | Enforces? |
|----------|------|---------|-----------------|-------------------|-----------------|-----------|
| **Zig** | Core runtime + Event Fabric + Detection orchestration | 24 files (~9,460 lines) | ✅ (sensors) | ✅ (verdict, decision, action) | ✅ (PolicyEngine) | ✅ (PEP → wfp_ioctl) |
| **C++** | IPC bridge + DEFCON aggregation + transport | bridge/*.hpp, *.cpp (~795 lines) | ❌ | ❌ (reads only) | ❌ | ✅ (netsh advfirewall) |
| **Rust** | Shield (Tier-3 behavioral) + PEP boundary | shield/src/lib.rs (146 lines) | ❌ | ❌ (returns bool only) | ❌ | ❌ (validation only) |
| **Python** | Brain orchestration + RAG + analytics + CLI | brain/*.py, scripts/*.py (~2,000 lines) | ❌ | ❌ (receives via UDP) | ❌ (IPS via netsh) | ⚠️ (netsh directly, bypasses PEP) |
| **Cython** | Brain acceleration (hot paths) | brain/aegis_brain_cython/ (440 lines) | ❌ | ❌ | ❌ | ❌ |
| **Go** | Nose/acquisition + aggregator + REST API | go/aggregator/ (911 lines) | ❌ (reads NDJSON) | ❌ (dedup only) | ❌ | ❌ |

## Event Ownership (Who does what to events)

### Event Creators (Sensors)
| Sensor | File | Event Source | Event Types |
|--------|------|---------------|------------|
| Pipe Sensor | nids_capture.zig | .pipe_sensor | forward |
| WFP Sensor | windows_capture.zig | .wfp_sensor | forward |
| Minifilter | minifilter_reader.zig | .minifilter | forward |
| Pipe Monitor | pipe_monitor.zig | (not yet wired) | — |
| HIDS Process | hids_process_monitor.zig | .minifilter | session_start, session_end |
| Detection Engine | nids_analyze.zig | (legacy path) | block, match_ |
| Nose Contract | nose_contract.zig | (via createEvent) | all types |

### Event Modifiers
| Modifier | File | What it modifies |
|----------|------|-----------------|
| nose_contract | nose_contract.zig | validates magic+version before enqueue |
| DetectionManager | detection_interface.zig | sets verdict, rule_id, severity on result |
| PolicyEngine | policy_contract.zig | sets policy_action on CanonicalEvent |
| PEP | policy_contract.zig | sets enforcement_status (1=ok, 2=failed) |
| RAGEngine | rag_intelligence.zig | sets context_flags (threat_intel_match, etc.) |
| FlowTable | flow_engine.zig | updates packet_count, byte_count, risk_score |
| XDRCorrelator | xdr_correlator.zig | updates incident severity, event_count |

### Event Readers
| Reader | File | What it reads |
|--------|------|---------------|
| forensic_log | forensic_log.zig | logs all events to NDJSON |
| eventFabricDrain | nids_analyze.zig | pops from PriorityQueue |
| Go Aggregator | go/aggregator/collector.go | reads NDJSON file (fsnotify) |
| bridge_init | bridge_init.zig | pushes to C++ Bridge + UDP Brain |
| Python Brain | brain/windows_brain.py | receives via UDP, processes alerts |

## Decision Makers
| Decision Maker | File | What it decides |
|---------------|------|----------------|
| DetectionManager | detection_interface.zig | Verdict (no_match/match_alert/match_block) |
| PolicyEngine | policy_contract.zig | Decision (allow/alert/block/rate_limit/quarantine/log_only) |

## Enforcement Executors
| Executor | File | What it executes |
|-----------|------|-----------------|
| PEP (Zig) | policy_contract.zig | wfp_ioctl.block_ip() → WFP kernel filter |
| C++ Bridge | bridge/aegis_ipc.cpp | netsh advfirewall add/delete rule |
| Python Brain | brain/windows_brain.py | netsh advfirewall (bypasses PEP — known issue) |

## Known Issues (to fix in STEP 1+)

1. **Python Brain bypasses PEP** — calls netsh directly, not through PolicyDecision
2. **Legacy detection path** — inspect_packet() runs in parallel to Blueprint pipeline
3. **Modules initialized but not wired** — XDR/RAG/Flow are init'd in nids_main but not in the actual data path
4. **Rust Shield** — only returns bool (safe/unsafe), doesn't produce DetectionEvidence
5. **Go Aggregator** — reads NDJSON file, doesn't receive events via Wire format

## Acceptance Criteria

- [x] Each language has a single clear responsibility
- [x] No language makes decisions outside its scope
- [x] Event ownership (create/modify/read) is documented per module
- [ ] No bypass of PEP for enforcement (Python Brain needs fix)
- [ ] All modules are wired into the runtime data path (not just initialized)
