# MULTI-PROCESS ARCHITECTURE

**HEAD:** `2c7cb30` · **Date:** 2026-09-11 · **Mode:** corrected audit

---

## Overview

AEGIS NIDS Windows is a **multi-process system** with 6 distinct components:

1. **Zig Core** (Tier-1 runtime spine)
2. **Go Nose** (packet acquisition)
3. **Go Aggregator** (alert sidecar - optional)
4. **Rust Shield** (Tier-3 payload safety - in-process)
5. **Rust PEP** (privileged action authorization - in-process)
6. **C++ Bridge** (Windows native adapters - in-process)

---

## Process Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        AEGIS NIDS Windows                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    Zig Core (aegis_nids.exe)             │  │
│  │                    Runtime Spine (Tier-1)                │  │
│  │                                                          │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │  │
│  │  │ Event Fabric│  │   Flow      │  │  Detection  │    │  │
│  │  │             │  │  Management │  │  Engine     │    │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘    │  │
│  │                                                          │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │  │
│  │  │  Policy     │  │  Forensics  │  │  Control    │    │  │
│  │  │  Engine     │  │  Pipeline   │  │  Pipe       │    │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘    │  │
│  │                                                          │  │
│  │  ┌────────────────────────────────────────────────────┐ │  │
│  │  │              Bridge Init (bridge_init.zig)         │ │  │
│  │  │  - Loads Rust Shield (sec_monitor.dll)             │ │  │
│  │  │  - Loads Rust PEP (aegis_pep.dll)                  │ │  │
│  │  │  - Loads C++ Bridge (aegis_ipc.dll)                │ │  │
│  │  └────────────────────────────────────────────────────┘ │  │
│  └──────────────────────────────────────────────────────────┘  │
│           │                    │                    │            │
│           │ Named Pipe         │ FFI                │ FFI        │
│           ▼                    ▼                    ▼            │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐│
│  │   Go Nose       │  │  Rust Shield    │  │  C++ Bridge     ││
│  │ (aegis-nose.exe)│  │ (sec_monitor.dll)│  │ (aegis_ipc.dll) ││
│  │                 │  │                 │  │                 ││
│  │ Packet          │  │ Tier-3 Payload  │  │ Windows Native  ││
│  │ Acquisition     │  │ Safety          │  │ Adapters        ││
│  │                 │  │                 │  │                 ││
│  │ - Npcap         │  │ - NOP sled      │  │ - ETW           ││
│  │ - Flow          │  │ - Buffer overflow│  │ - FIM           ││
│  │ - Canonical     │  │ - Malformed     │  │ - WFP           ││
│  │   Event         │  │   headers       │  │                 ││
│  └─────────────────┘  └─────────────────┘  └─────────────────┘│
│           │                    │                    │            │
│           │                    │ FFI                │            │
│           │                    ▼                    │            │
│           │           ┌─────────────────┐          │            │
│           │           │  Rust PEP       │          │            │
│           │           │ (aegis_pep.dll) │          │            │
│           │           │                 │          │            │
│           │           │ Privileged      │          │            │
│           │           │ Action          │          │            │
│           │           │ Authorization   │          │            │
│           │           └─────────────────┘          │            │
│           │                                        │            │
│           │ NDJSON                                  │            │
│           ▼                                        │            │
│  ┌─────────────────┐                               │            │
│  │ Go Aggregator   │                               │            │
│  │(aegis-aggregator│                               │            │
│  │     .exe)       │                               │            │
│  │                 │                               │            │
│  │ Alert Sidecar   │                               │            │
│  │ (Optional)      │                               │            │
│  │                 │                               │            │
│  │ - REST API      │                               │            │
│  │ - NDJSON tail   │                               │            │
│  │ - Dedup         │                               │            │
│  │ - Correlation   │                               │            │
│  └─────────────────┘                               │            │
│                                                     │            │
└─────────────────────────────────────────────────────────────────┘
```

---

## Component Responsibilities

### 1. Zig Core (aegis_nids.exe)
- **Language:** Zig
- **Role:** Runtime spine, event fabric, flow management, detection, correlation, policy, forensics, control
- **Build:** `zig build`
- **Artifact:** `zig-out/bin/aegis_nids.exe`
- **CI Job:** `zig-build-test`

### 2. Go Nose (aegis-nose.exe)
- **Language:** Go
- **Role:** Packet acquisition, flow collection, canonical event production
- **Build:** `cd nose && go build -o aegis-nose.exe .`
- **Artifact:** `nose/aegis-nose.exe`
- **CI Job:** `go-build-test`
- **Protocol:** Named pipe → Zig Core

### 3. Go Aggregator (aegis-aggregator.exe)
- **Language:** Go
- **Role:** Alert sidecar (REST API + NDJSON correlation)
- **Build:** `cd go/aggregator && go build -o aegis-aggregator.exe .`
- **Artifact:** `go/aggregator/aegis-aggregator.exe`
- **CI Job:** `go-build-test`
- **Protocol:** File-based (watches NDJSON logs via fsnotify)
- **Status:** Optional (required: false)

### 4. Rust Shield (sec_monitor.dll)
- **Language:** Rust
- **Role:** Tier-3 payload safety validation + threat scoring
- **Build:** `cd shield && cargo build --release`
- **Artifact:** `shield/target/release/sec_monitor.dll`
- **CI Job:** `shield-build`
- **Protocol:** FFI (loaded in-process by Zig Core)

### 5. Rust PEP (aegis_pep.dll)
- **Language:** Rust
- **Role:** Privileged action authorization (Policy Enforcement Point)
- **Build:** `cargo build --release`
- **Artifact:** `target/release/aegis_pep.dll`
- **CI Job:** `rust-pep-build`
- **Protocol:** FFI (loaded in-process by Zig Core)

### 6. C++ Bridge (aegis_ipc.dll)
- **Language:** C++
- **Role:** Windows native adapters (ETW, FIM, WFP)
- **Build:** `cd bridge && cmake -B build && cmake --build build`
- **Artifact:** `dist/aegis_ipc.dll`
- **CI Job:** (none in CI)
- **Protocol:** FFI (loaded in-process by Zig Core)

---

## Data Flow

### Primary Data Path (Acquisition → Detection → Enforcement)
```
Npcap → Go Nose → Named Pipe → Zig Core → Event Fabric → Flow → Detection → Policy → Rust PEP → WFP → Block/Allow
```

### Alert Aggregation Path (Optional Sidecar)
```
Zig Core → NDJSON Log → Go Aggregator (fsnotify) → REST API → Dashboard/CLI
```

### Payload Safety Screening (In-Process)
```
Zig Core → Rust Shield (validate_payload_safety) → Pass/Fail → Zig Core
```

---

## Authority Boundaries

| Component | Authority | Does NOT Own |
|---|---|---|
| Zig Core | Runtime orchestration, event fabric, detection, correlation | Privileged enforcement, crypto |
| Go Nose | Packet acquisition, canonical event production | Policy, enforcement, detection |
| Go Aggregator | Alert dedup, correlation, REST API | Runtime, enforcement, detection |
| Rust Shield | Payload safety screening, threat scoring | Final enforcement decisions |
| Rust PEP | Privileged action authorization, crypto | Payload screening, runtime |
| C++ Bridge | Windows native adapters (ETW, FIM, WFP) | Policy, enforcement, detection |

---

## Security Boundaries

1. **Go → Zig:** Named pipe (C ABI)
2. **Rust Shield → Zig:** FFI (in-process)
3. **Rust PEP → Zig:** FFI (in-process)
4. **C++ Bridge → Zig:** FFI (in-process)
5. **Go Aggregator:** File-based (NDJSON) - no direct IPC with Zig Core

---

## Build Matrix

| Component | Language | Build Command | Artifact | CI Job | Required |
|---|---|---|---|---|---|
| Zig Core | Zig | `zig build` | `aegis_nids.exe` | `zig-build-test` | Yes |
| Go Nose | Go | `cd nose && go build -o aegis-nose.exe .` | `aegis-nose.exe` | `go-build-test` | Yes |
| Go Aggregator | Go | `cd go/aggregator && go build -o aegis-aggregator.exe .` | `aegis-aggregator.exe` | `go-build-test` | No |
| Rust Shield | Rust | `cd shield && cargo build --release` | `sec_monitor.dll` | `shield-build` | Yes |
| Rust PEP | Rust | `cargo build --release` | `aegis_pep.dll` | `rust-pep-build` | Yes |
| C++ Bridge | C++ | `cd bridge && cmake -B build && cmake --build build` | `aegis_ipc.dll` | (none) | Yes |

---

## Runtime Dependencies

1. **Zig Core** depends on:
   - Rust Shield (sec_monitor.dll) - loaded at startup
   - Rust PEP (aegis_pep.dll) - loaded at startup
   - C++ Bridge (aegis_ipc.dll) - loaded at startup
   - Go Nose (aegis-nose.exe) - launched as separate process

2. **Go Aggregator** depends on:
   - Zig Core (produces NDJSON logs)
   - No direct IPC with Zig Core

3. **Go Nose** depends on:
   - Npcap driver (packet capture)
   - Zig Core (named pipe connection)

---

## Failure Modes

| Component | Failure | Impact | Recovery |
|---|---|---|---|
| Zig Core | Crash | System down | Restart service |
| Go Nose | Crash | No packet capture | Restart service |
| Go Aggregator | Crash | No REST API (optional) | Restart or ignore |
| Rust Shield | Missing | Tier-3 screening bypassed (fail-open) | Fix P0-2 |
| Rust PEP | Missing | No privileged action authorization | Critical failure |
| C++ Bridge | Missing | No Windows native adapters | Restart service |

---

## P0 Issues (from Audit)

1. **P0-1:** Zig→WFP enforcement bypass (rust_pep.zig calls wfp_ioctl directly)
2. **P0-2:** Fail-open Tier-3 (sec_monitor.dll missing → Tier-3 screening bypassed)
3. **P0-3:** CI red by construction (go-build-test broken)
4. **P0-4:** Machine maps stale (fixed in this commit)
5. **P0-5:** CLI canonical path conflict (fixed in this commit)
6. **P0-6:** go/aggregator tracked (resolved: kept as active sidecar)
7. **P0-7:** shield/ tracked (resolved: kept as active Tier-3)
