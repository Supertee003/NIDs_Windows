# AEGIS NIDS Windows — Phase 1: System Analysis
## Master Prompt v1.0 Compliance Report

**Date:** 2026-09-09
**Model:** Codebuff (MiMo 2.5 methodology applied)
**HEAD:** 1860ca18bb636f3a97451f2ed817564a6baae44a
**Branch:** main
**Prompt Version:** AEGIS-MASTER-v1.0

---

# A. REPOSITORY TRUTH

## A.1 Source of Truth
```
Git = Source of Truth
HEAD = 1860ca18bb636f3a97451f2ed817564a6baae44a
Branch = main
Dirty = CLEAN (0 uncommitted changes)
```

## A.2 Language Inventory

| Language | Directory | Files | Lines | Role | Status |
|---|---|---|---|---|---|
| **Zig** | src/ | 70 | ~6,500 | Runtime Core | ✅ Implemented |
| **Rust** | rust-src/ | 1 | 336 | PEP + TLS | ✅ Implemented |
| **Go** | nose/ + go/ | 15 | 3,343 | Capture + Aggregation | ✅ Implemented |
| **C++** | bridge/ | 6 | 1,640 | Native Adapter | ✅ Implemented |
| **Python** | brain/ + scripts/ | 32 | ~1,400 | Brain + RAG | ✅ Implemented |
| **Cython** | brain/ | 4 | 677 | Hot Loop | ✅ Implemented |
| **TypeScript** | ts_policy/ | 4 | 1,015 | Policy Authoring | ✅ Implemented |
| **C** | drivers/ | 6 | ~1,500 | Kernel Drivers | ⚠️ Source present, not compiled |
| **TOTAL** | | **~138** | **~16,000+** | | |

## A.3 Root File Classification

| Category | Files |
|---|---|
| **SOURCE** | build.zig, Cargo.toml, CMakeLists.txt |
| **CONFIG** | Rules.json, runtime_manifest.json, ci_coverage.json |
| **DOC** | README.md, AGENTS.md, DEEP_AUDIT_REPORT.md, RE_AUDIT_REPORT.md, DEVELOPMENT_ROADMAP.md |
| **EVIDENCE** | PATCH01-05_EVIDENCE.md |
| **GENERATED** | (none — clean) |
| **LEGACY** | (none at root) |

---

# B. BUILD TRUTH

## B.1 Build System Matrix

| Build | File | Target | Status |
|---|---|---|---|
| **Zig** | build.zig | src/main.zig → aegis_nids.exe | ✅ Defined |
| **Rust** | Cargo.toml | rust-src/lib.rs → aegis_pep.dll | ✅ Defined |
| **C++** | CMakeLists.txt | bridge/*.cpp → aegis_native.dll | ✅ Defined |
| **Go** | nose/go.mod | nose/*.go → aegis_nose.exe | ✅ Defined |
| **Go** | go/aggregator/ | go/aggregator/*.go → aegis_aggregator.exe | ✅ Defined |
| **Python** | brain/ | brain/windows_brain.py (interpreted) | ✅ Defined |
| **Cython** | brain/cython/setup.py | *.pyx → *.pyd | ✅ Defined |
| **TypeScript** | ts_policy/ | ts_policy/src/*.ts → Policy IR | ✅ Defined |
| **Driver** | drivers/ | *.c → .sys | ⚠️ Source only, no CI build |

## B.2 Build Graph

```
build.zig (PRIMARY)
├── src/main.zig (Zig runtime)
│   ├── imports: src/contract/*.zig (Canonical Event)
│   ├── imports: src/capture/*.zig (Npcap adapter, flow table)
│   ├── imports: src/detection/*.zig (AC, anomaly, correlator, tracker)
│   ├── imports: src/policy/*.zig (Policy IR, PEP, dispatcher)
│   ├── imports: src/forensic/*.zig (forensic ring)
│   ├── imports: src/reliability/*.zig (watchdog, security check, fault injection)
│   ├── imports: src/core/*.zig (diagnostics, memory pool)
│   └── FFI: aegis_pep.dll (Rust)

Cargo.toml (SECONDARY)
└── rust-src/lib.rs → aegis_pep.dll
    ├── ring (cryptography)
    ├── rustls (TLS)
    └── Ed25519 policy verification

CMakeLists.txt (SECONDARY)
├── bridge/aegis_adapter.cpp
├── bridge/aegis_ipc.cpp
└── bridge/aegis_packet_parser.cpp

go.mod (SECONDARY)
├── nose/*.go → aegis_nose.exe
└── go/aggregator/*.go → aegis_aggregator.exe
```

## B.3 ONE BUILD Status

| Criterion | Status |
|---|---|
| Zig builds runtime binary | ✅ Defined |
| Rust builds PEP DLL | ✅ Defined |
| C++ builds native adapter DLL | ✅ Defined |
| Go builds capture + aggregator | ✅ Defined |
| All produce same release | ⚠️ No unified release manifest |
| CI builds all | ⚠️ CI matrix skips some jobs |

---

# C. RUNTIME TRUTH

## C.1 Entry Point

```
src/main.zig::main()
    ↓
Windows: StartServiceCtrlDispatcherW → serviceMain → runDaemon
Console: runDaemon()
```

## C.2 Initialization Sequence (runDaemon)

```
1. Logger.setSink(StderrSink)
2. SecurityCheck.run() → report
3. manifest.probeCapabilities() → publish
4. ByteArena.init(16 MiB)
5. ForensicRing.initMemory(64 MiB)
6. ReliabilityWatchdog.init()
7. PerfTracker{}
8. FaultInjector.fromEnv()
9. AhoCorasick.init(100K)
10. Load Rules.json → AC.addPattern() × 18 → AC.build()
11. PolicySet.init() → Load configs/policies.json → PolicySet.add() × 6
12. AnomalyDetector.init()
13. FlowTable{}
14. ThreatTracker.init()
15. PepEnforcer.init() (loads aegis_pep.dll)
16. ActionDispatcher.init()
```

## C.3 Thread Model

| Thread | Function | Purpose |
|---|---|---|
| **Main** | serveWindowsPipe() | Named pipe control server |
| **Pipeline** | pipelineLoop() | Event queue → 7-stage processing |
| **Capture** | captureThread() | Npcap → packetCallback → pushEvent |

## C.4 Event Pipeline (7 Stages)

```
Npcap → packetCallback() → pushEvent(ev, payload)
                                    ↓
                            Pipeline Queue (4096 entries)
                                    ↓
                            pipelineLoop() popEvent()
                                    ↓
                    ┌────────────────┼────────────────┐
                    │                │                │
              1. Flow Table    2. AC Detection   3. Anomaly
              (lookupOrCreate)  (18 rules)       (EWMA)
                    │                │                │
                    └────────┬───────┘                │
                             │                        │
                    4. Threat Tracker            5. Policy Eval
                    (per-flow threat)           (6 policies)
                             │                        │
                             └──────────┬─────────────┘
                                        │
                               6. PEP Enforcement
                               (Rust aegis_pep.dll)
                                        │
                               6a. Action Dispatch
                               (WFP/Federation/Forensic)
                                        │
                               7. Forensic Recording
                               (64 MiB ring buffer)
```

## C.5 Control Plane

```
aegisctl.py → named pipe → handleControlRequest()
    ├── "status"            → real metrics
    ├── "metrics.snapshot"  → real diagnostics
    ├── "rules.list"        → rules_loaded count
    ├── "rules.reload"      → re-read Rules.json
    ├── "incidents.list"    → pipeline stats
    ├── "federation.status" → standalone mode
    ├── "health.check"      → capability probe
    └── "daemon.shutdown"   → graceful stop
```

---

# D. SYSTEM FLOW ANALYSIS

## D.1 FLOW-ID: PACKET-DETECTION (Primary Flow)

```
START:      Npcap captures raw packet
INPUT:      Ethernet/IP/TCP/UDP bytes
PROCESSING: packetCallback → IpcEvent + payload → pushEvent
STATE:      Queue slot allocated, head++
DECISION:   pipelineLoop pops, processes through 7 stages
OUTPUT:     Detection match (or no match)
SIDE EFFECT: forensic append, metrics increment, policy action
AUDIT:      forensic_ring.append()
RECOVERY:   Queue full → drop event (backpressure)
```

## D.2 FLOW-ID: CONTROL-STATUS

```
START:      aegisctl sends JSON command
INPUT:      {"command":"status"}
PROCESSING: parse JSON → lookup metrics → format response
STATE:      Read-only (metrics are atomic counters)
DECISION:   Format and return
OUTPUT:     {"ok":true,"data":{...}}
SIDE EFFECT: None (read-only)
AUDIT:      None currently (gap identified)
RECOVERY:   Parse error → send {"ok":false}
```

## D.3 FLOW-ID: RULES-RELOAD

```
START:      aegisctl sends {"command":"rules.reload"}
INPUT:      JSON command
PROCESSING: read Rules.json → parse → count rules
STATE:      Read-only (does NOT reinitialize AC)
DECISION:   Return current count
OUTPUT:     {"rules_loaded":18,"status":"ok"}
SIDE EFFECT: None (CRITICAL GAP: does not actually reload)
AUDIT:      None
RECOVERY:   N/A
```

**🔴 CRITICAL GAP: `rules.reload` does NOT actually reload rules into the Aho-Corasick automaton. It just returns the current count.**

## D.4 FLOW-ID: PEP-ENFORCEMENT

```
START:      Policy matches an event
INPUT:      IpcEvent + matched Policy
PROCESSING: PepEnforcer.enforce() → FFI to aegis_pep.dll
STATE:      PEP state (DLL loaded or not)
DECISION:   allow/block/rate_limit/quarantine/escalate/drop
OUTPUT:     PepDecision
SIDE EFFECT: ActionDispatcher routes enforcement
AUDIT:      forensic_backend.write()
RECOVERY:   PEP unavailable → fail-open (mapAction)
```

---

# E. DEPENDENCY CLOSURE

## E.1 For PACKET-DETECTION Flow

| Artifact | Classification |
|---|---|
| src/main.zig (packetCallback, pushEvent, processEvent, pipelineLoop) | IN-SCOPE |
| src/capture/npcap_adapter.zig | IN-SCOPE |
| src/capture/flow_table.zig | IN-SCOPE |
| src/detection/signature_engine.zig | IN-SCOPE |
| src/detection/anomaly_detector.zig | IN-SCOPE |
| src/detection/threat_tracker.zig | IN-SCOPE |
| src/policy/policy_ir.zig | IN-SCOPE |
| src/policy/pep_bindings.zig | IN-SCOPE |
| src/policy/action_dispatcher.zig | IN-SCOPE |
| src/forensic/forensic_pipeline.zig | IN-SCOPE |
| src/contract/event.zig | IN-SCOPE |
| src/core/diagnostics.zig | IN-SCOPE |
| rust-src/lib.rs (aegis_pep.dll) | IN-SCOPE (FFI) |
| Rules.json | IN-SCOPE (config) |
| configs/policies.json | IN-SCOPE (config) |
| nose/*.go | OUT-OF-SCOPE (separate capture) |
| bridge/*.cpp | OUT-OF-SCOPE (separate adapter) |
| ts_policy/src/*.ts | OUT-OF-SCOPE (policy authoring) |
| brain/*.py | OUT-OF-SCOPE (Brain) |
| drivers/*.c | OUT-OF-SCOPE (kernel driver) |
| core/*.zig | LEGACY (per ADR) |

---

# F. AUTHORITY GRAPH

## F.1 Security Authority Chain

```
Observer:         Npcap/packetCallback (Go→Zig boundary)
Transformer:      packetCallback (raw bytes → IpcEvent)
Detector:         AhoCorasick + AnomalyDetector
Decider:          PolicySet.evaluate()
Authorizer:       PepEnforcer.enforce() (Rust PEP)
Mutator:          ActionDispatcher.dispatch()
Enforcer:         WFP (via shield/) — STUB, not real yet
Auditor:          ForensicRing.append()
Rollback Owner:   WfpBackend.remove() — STUB
```

## F.2 Authority Violations Detected

| # | Type | Location | Description |
|---|---|---|---|
| 1 | ⚠️ DUPLICATE PEP | action_dispatcher.zig:111 | ActionDispatcher calls `pep_enforcer.enforce()` again INSIDE dispatch, AFTER pipeline already called PEP. This creates a DOUBLE PEP evaluation. |
| 2 | 🔴 NO REAL ENFORCEMENT | action_dispatcher.zig | WfpBackend has no `add_filter_fn` installed — all blocks are silently dropped. |
| 3 | ⚠️ FAIL-OPEN | pep_bindings.zig:81 | When PEP DLL unavailable, enforcement falls back to policy action directly — security degraded. |

---

# G. DATA FLOW (Provenance Chain)

```
CAPTURE ID:     Npcap packet handle
    ↓
EVENT ID:       diag.metrics.packets_captured.value (monotonic counter)
    ↓
FLOW ID:        FlowTable.FlowKey (5-tuple hash)
    ↓
DETECTION ID:   AhoCorasick.Match.rule_id (FNV-1a hash of rule_id string)
    ↓
INCIDENT ID:    (NOT IMPLEMENTED — no incident registry)
    ↓
POLICY ID:      PolicySet.Policy.id (from configs/policies.json)
    ↓
PEP REQUEST ID: ev.event_id (reused, not unique)
    ↓
ENFORCEMENT ID: (NOT IMPLEMENTED — no real WFP)
    ↓
AUDIT ID:       (NOT IMPLEMENTED — forensic ring has no unique ID)
    ↓
FORENSIC ID:    ForensicRing.append() offset (positional, not ID)
```

**🔴 PROVENANCE GAPS:**
- INCIDENT ID: No incident registry exists
- PEP REQUEST ID: Reuses event_id, not unique
- AUDIT ID: Forensic ring uses position, not unique ID
- ENFORCEMENT ID: No real enforcement to trace

---

# H. STATE MACHINE

## H.1 Pipeline State

```
PRECONDITION:  Queue has event
    ↓
REQUEST:       popEvent() returns QueuedEvent
    ↓
VALIDATION:    payload_len > 0 for AC match
    ↓
TRANSITION:    g_pipeline_events_processed++
    ↓
POSTCONDITION: Event processed through all 7 stages
    ↓
AUDIT:         forensic_ring.append()
```

## H.2 Failure State

```
FAILURE:       processEvent returns error
    ↓
STATE:         pipelineLoop catches error, logs warning
    ↓
RECOVERY:      Continue to next event (best-effort)
```

---

# I. CONTRACT GRAPH

| Contract | Producer | Consumer | Schema | Validated |
|---|---|---|---|---|
| Canonical Event | packetCallback | pipelineLoop | IpcEvent struct | ⚠️ Partial |
| Control Protocol | aegisctl.py | handleControlRequest | JSON | ⚠️ Informal |
| Policy IR | ts_policy compiler | PolicySet | JSON → Policy struct | ⚠️ Informal |
| PEP ABI | Zig pep_bindings | Rust aegis_pep | PepRequest/PepResponse | ✅ FFI |
| Metrics | diag.metrics | status/metrics.snapshot | Counter/Gauge | ⚠️ Informal |
| Forensic Record | processEvent | forensic_ring | Raw bytes | ⚠️ No schema |

---

# J. ERROR SEMANTICS

| Location | Current Behavior | Classification | Risk |
|---|---|---|---|
| pushEvent (queue full) | Returns false, event dropped | DROP_EVENT | ⚠️ Silent |
| processEvent error | Caught, logged, continue | DEGRADE | ⚠️ No metric |
| PEP unavailable | Fail-open (mapAction) | FAIL_OPEN | 🔴 Security risk |
| Rules.json missing | Warn, 0 rules, continue | DEGRADE | ⚠️ No detection |
| policies.json missing | Warn, empty PolicySet | DEGRADE | ⚠️ No policy |
| Control pipe parse error | Send {"ok":false} | RETRY | ✅ OK |
| AC match allocation | catch null → empty matches | DEGRADE | ⚠️ Silent |

---

# K. OBSERVABILITY

| Metric | Source | API Field | CLI Field | Accurate |
|---|---|---|---|---|
| packets_captured | diag.metrics | ✅ | ✅ | ✅ Real |
| flows_active | diag.metrics | ✅ | ✅ | ⚠️ Approximation |
| events_emitted | diag.metrics | ✅ | ✅ | ⚠️ Used as "incidents_open" |
| signatures_matched | diag.metrics | ✅ | ✅ | ✅ Real |
| anomalies_detected | diag.metrics | ✅ | ✅ | ✅ Real |
| blocks_issued | diag.metrics | ✅ | ✅ | ⚠️ Always 0 (no real WFP) |
| rules_loaded | g_rules_loaded | ✅ | ✅ | ✅ Real (18) |
| pipeline_processed | g_pipeline_events_processed | ✅ | ✅ | ✅ Real |
| pipeline_detections | g_pipeline_detections | ✅ | ✅ | ✅ Real |

---

# L. TEST COVERAGE

| Component | Unit Tests | Integration Tests | Windows Tests |
|---|---|---|---|
| Zig src/ | 34 test blocks | ⚠️ Limited | ❌ None |
| Rust PEP | ⚠️ Inline only | ❌ | ❌ |
| Go nose/ | ✅ canonical_test.go | ⚠️ | ❌ |
| Go aggregator/ | ✅ alert_test, correlator_test | ⚠️ | ❌ |
| C++ bridge/ | ✅ bridge_test.cpp | ⚠️ | ❌ |
| TypeScript | ✅ ts_policy/tests/ | ⚠️ | ❌ |
| Python brain/ | ⚠️ | ❌ | ❌ |
| Cython | ⚠️ | ❌ | ❌ |
| **Overall** | **E2 (Unit)** | **E0-E1** | **E0** |

---

# M. EVIDENCE GAP

| Evidence Level | Current | Required For |
|---|---|---|
| E0 | ❌ No evidence | — |
| E1 | ✅ Static inspection (zig ast-check) | Basic validation |
| E2 | ✅ Unit tests (34 blocks) | Component proof |
| E3 | ⚠️ Partial integration | Component integration |
| E4 | ❌ No system integration tests | System proof |
| E5 | ❌ No Windows host tests | Windows verification |
| E6 | ❌ No production simulation | Production proof |
| E7 | ❌ No release verification | Release proof |

---

# N. ROOT CAUSE ANALYSIS

## N.1 Why CI fails

**Root Cause:** The CI matrix (`ci.yml`) requires ALL 8 jobs to pass, but several jobs are configured to `continue-on-error: true` or have missing test infrastructure. The Zig build itself passes, but the Python tests and host regression tests have incomplete test environments.

**Evidence:** `zig ast-check` passes for all 70 Zig files. The `ci_coverage.json` was recreated but may not match actual CI expectations.

## N.2 Why Action Dispatcher double-evaluates PEP

**Root Cause:** The pipeline loop calls `pep_enforcer.enforce()` to get a decision, then passes that decision to `ActionDispatcher.dispatch()`. Inside dispatch, for `block`/`rate_limit`/`quarantine` cases, the dispatcher calls `pep_enforcer.enforce()` AGAIN. This is a duplicate PEP evaluation.

**Evidence:** src/main.zig line ~610 calls PEP, then passes decision to dispatcher. action_dispatcher.zig line ~111 calls PEP again inside the block/quarantine path.

## N.3 Why rules.reload does not reload

**Root Cause:** The `rules.reload` control command returns `g_rules_loaded` but does NOT re-read Rules.json or rebuild the Aho-Corasick automaton. This is a STUB implementation.

---

# O. INVARIANTS

| # | Invariant | Status |
|---|---|---|
| 1 | There is exactly one production runtime (Zig) | ✅ VERIFIED |
| 2 | There is exactly one Canonical Event (IpcEvent) | ✅ VERIFIED |
| 3 | There is exactly one event queue | ✅ VERIFIED |
| 4 | There is exactly one policy authority (PolicySet) | ✅ VERIFIED |
| 5 | There is exactly one PEP (Rust aegis_pep.dll) | ⚠️ DUPLICATE in ActionDispatcher |
| 6 | Every privileged action passes through Rust PEP | ⚠️ Fail-open when unavailable |
| 7 | ActionDispatcher does NOT directly enforce WFP | ✅ VERIFIED (WFP stub only) |
| 8 | Every security decision has an audit trace | 🔴 NOT IMPLEMENTED |
| 9 | Every control command has a verifiable postcondition | 🔴 STUB |
| 10 | Every metric maps to authoritative runtime state | ⚠️ Partial |
| 11 | No second runtime, no second event model | ✅ VERIFIED |
| 12 | No second enforcement authority | ✅ VERIFIED |

---

# P. PATCH SCOPE (for next patch)

## P.1 Identified Issues by Priority

| Priority | Issue | Flow-ID | Fix Complexity |
|---|---|---|---|
| **P0** | Double PEP evaluation in ActionDispatcher | PEP-ENFORCEMENT | Low |
| **P0** | rules.reload does not actually reload | RULES-RELOAD | Medium |
| **P0** | No incident registry (no INCIDENT ID) | INCIDENT-LIFECYCLE | High |
| **P1** | No audit trace for security decisions | AUDIT-TRACE | High |
| **P1** | PEP fail-open when DLL unavailable | PEP-FAIL-SAFE | Medium |
| **P1** | No real WFP enforcement | WFP-ENFORCEMENT | Very High |
| **P1** | Control commands lack postcondition verification | CONTROL-VERIFY | Medium |
| **P2** | Forensic ring has no unique record ID | FORENSIC-ID | Low |
| **P2** | PEP request_id reuses event_id | PEP-REQUEST-ID | Low |
| **P2** | No control command audit | CONTROL-AUDIT | Medium |
| **P2** | Queue drop event has no metric | QUEUE-DROP | Low |

---

# Q. RECOMMENDED NEXT PATCHES (System Flow Priority)

## Phase 1: Core Pipeline Hardening (P0)

| Patch | Flow-ID | Objective |
|---|---|---|
| PATCH-10 | PEP-ENFORCEMENT | Remove duplicate PEP call in ActionDispatcher |
| PATCH-11 | RULES-RELOAD | Implement real rules reload (rebuild AC) |
| PATCH-12 | INCIDENT-LIFECYCLE | Create incident registry + INCIDENT ID |
| PATCH-13 | AUDIT-TRACE | Add unique audit_id to every security decision |

## Phase 2: Control Plane Hardening (P1)

| Patch | Flow-ID | Objective |
|---|---|---|
| PATCH-14 | CONTROL-VERIFY | Add postcondition verification to all commands |
| PATCH-15 | CONTROL-AUDIT | Add audit logging to all control commands |
| PATCH-16 | PEP-FAIL-SAFE | Add PEP availability check + startup validation |

## Phase 3: Evidence & Observability (P1-P2)

| Patch | Flow-ID | Objective |
|---|---|---|
| PATCH-17 | FORENSIC-ID | Add unique forensic record ID |
| PATCH-18 | QUEUE-DROP | Add metric for dropped events |
| PATCH-19 | METRIC-ACCURACY | Align all metrics to real state |

---

**END OF PHASE 1 SYSTEM ANALYSIS**
