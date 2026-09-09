# AEGIS NIDS Windows — Phase 3: Data Plane Integration Evidence

**Date:** 2026-09-09
**Patches:** PATCH-20 (ETW/FIM/Registry adapter wiring)

---

## Summary

Phase 3 wires the existing Windows Data Plane adapters into the pipeline queue. Before this phase, all 5 adapters existed as standalone modules but were NOT connected to the event pipeline.

## What Was Done

### 1. Imported All Adapters
```
src/windows/etw_realtime.zig   → etw module
src/windows/fim.zig            → fim_mod module
src/windows/registry_monitor.zig → reg_mon module
src/windows/injection_detector.zig → inj_det module
```

### 2. Created Adapter Thread Functions
| Thread | Function | Purpose |
|---|---|---|
| ETW | `etwThread()` | Starts ETW session, sets callback, pushes events |
| FIM | `fimThread()` | Polls file changes, pushes to pipeline |
| Registry | `registryThread()` | Polls registry changes, pushes to pipeline |

### 3. ETW Callback → Pipeline
```
Windows Kernel → ETW → etwCallback() → IpcEvent → pushEvent() → Queue
```

### 4. FIM Poll → Pipeline
```
FileSystem → ReadDirectoryChangesW → FimWatcher.poll() → IpcEvent → pushEvent() → Queue
```

### 5. Registry Poll → Pipeline
```
Registry → RegNotifyChangeKeyValue → RegistryMonitor.drain() → IpcEvent → pushEvent() → Queue
```

## Thread Model (Updated)

```
Main thread:      Control pipe (named pipe server)
Pipeline thread:  Event processing (Flow→AC→Anomaly→Threat→Policy→PEP→Forensics)
Capture thread:   Npcap capture → packetCallback → pushEvent → queue
ETW thread:       ETW session → etwCallback → pushEvent → queue       ← NEW
FIM thread:       FIM poll → pushEvent → queue                         ← NEW
Registry thread:  Registry poll → pushEvent → queue                    ← NEW
```

**Total: 6 threads** (was 3)

## Data Flow (Updated)

```
┌─────────────────────────────────────────────────────────────────┐
│                    AEGIS Data Plane                              │
│                                                                  │
│  Npcap ──→ packetCallback ──→ pushEvent ──→ Queue (4096)       │
│  ETW   ──→ etwCallback    ──→ pushEvent ──→ Queue              │
│  FIM   ──→ fimThread      ──→ pushEvent ──→ Queue              │
│  Reg   ──→ registryThread ──→ pushEvent ──→ Queue              │
│                                              │                   │
│                                    pipelineLoop popEvent         │
│                                              │                   │
│                              Flow → AC → Anomaly → Threat       │
│                              Policy → PEP → Forensics           │
└─────────────────────────────────────────────────────────────────┘
```

## Invariant

Every Windows telemetry source (Npcap, ETW, FIM, Registry) feeds events into the same canonical pipeline queue. No source bypasses the pipeline.

## Verification

| Check | Result |
|---|---|
| `zig ast-check` all 70 src/*.zig | ✅ PASS |
| ETW adapter imported | ✅ 6 references |
| FIM adapter imported | ✅ 1 reference |
| Registry adapter imported | ✅ 1 reference |
| Injection adapter imported | ✅ 1 reference |
| ETW thread function | ✅ Present |
| FIM thread function | ✅ Present |
| Registry thread function | ✅ Present |
| Thread spawns | ✅ 3 new threads |

## State Changes

| Dimension | Before | After |
|---|---|---|
| **FLOW CHANGED** | Only Npcap feeds pipeline | 4 sources feed pipeline |
| **STATE CHANGED** | 3 threads | 6 threads |
| **CONTRACT CHANGED** | ETW/FIM/Registry not wired | All wired to pushEvent |
| **OBSERVABILITY CHANGED** | ETW/FIM/Registry silent | All produce pipeline events |

---

**Evidence Level:** E2 (unit proof — AST check + static analysis)
