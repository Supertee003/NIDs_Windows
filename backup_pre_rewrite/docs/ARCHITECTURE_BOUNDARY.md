# AEGIS Architecture Boundary (Phase 23, AEGIS-001)

## Overview

This document defines the **frozen architecture boundaries** for AEGIS NIDS.
Each subsystem has a clear responsibility and MUST NOT cross these boundaries.

## Architecture Layers

```
┌─────────────────────────────────────────────────────┐
│ Layer 1: SENSORS (data collection only)              │
│   - Zig Core (nids_analyze.zig) — packet analysis   │
│   - WFP Sensor (windows_capture.zig) — kernel       │
│   - Pipe Sensor (nids_capture.zig) — IPC            │
│   - Minifilter (minifilter_reader.zig) — filesystem │
│   - Pipe Monitor (pipe_monitor.zig) — pipe scanner  │
│   Responsibility: Capture raw data → CanonicalEvent │
│   MUST NOT: Make policy decisions, block traffic     │
├─────────────────────────────────────────────────────┤
│ Layer 2: INGESTION (validation + normalization)     │
│   - Nose (Go aggregator) — event validation         │
│   Responsibility: Validate CanonicalEvent schema    │
│   MUST NOT: Run detection logic                     │
├─────────────────────────────────────────────────────┤
│ Layer 3: DETECTION (pattern matching + analysis)    │
│   - Tier-1: Aho-Corasick (nids_analyze.zig)         │
│   - Tier-2: Regex (windows_brain.py + Cython)       │
│   - Tier-3: Behavioral (Rust Shield)                │
│   Responsibility: Produce detection verdict         │
│   MUST NOT: Enforce policy (no blocking)            │
├─────────────────────────────────────────────────────┤
│ Layer 4: CORRELATION (cross-event analysis)         │
│   - Go Aggregator (session correlation)             │
│   - Python Brain (threat intelligence)              │
│   Responsibility: Correlate events, add context     │
│   MUST NOT: Make block/allow decisions              │
├─────────────────────────────────────────────────────┤
│ Layer 5: POLICY (decision making)                   │
│   - Policy Engine (future TypeScript Plane)         │
│   - DEFCON Aggregator (C++ Bridge)                  │
│   Responsibility: Decide ALLOW/ALERT/BLOCK          │
│   MUST NOT: Execute enforcement directly             │
├─────────────────────────────────────────────────────┤
│ Layer 6: ENFORCEMENT (action execution)             │
│   - Rust Shield (PEP - Policy Enforcement Point)    │
│   - WFP IOCTL (wfp_ioctl.zig) — kernel blocking     │
│   - Windows Firewall (netsh via C++ Bridge)         │
│   Responsibility: Execute policy decisions          │
│   MUST NOT: Make detection or policy decisions       │
├─────────────────────────────────────────────────────┤
│ Layer 7: FORENSICS (audit + replay)                │
│   - forensic_log.zig (NDJSON persistence)           │
│   - Go Aggregator (timeline reconstruction)         │
│   Responsibility: Record everything for IR         │
│   MUST NOT: Influence detection or policy           │
└─────────────────────────────────────────────────────┘
```

## Boundary Contracts

### 1. Sensor → Ingestion
- **Contract**: Sensors emit `CanonicalEvent` (defined in `core/canonical_event.zig`)
- **Direction**: One-way (sensor → ingestion)
- **Validation**: Ingestion validates `magic + version + struct_size`

### 2. Ingestion → Detection
- **Contract**: Validated `CanonicalEvent` with priority
- **Direction**: One-way via Priority Event Queue (AEGIS-005)
- **Validation**: Detection trusts ingestion's validation

### 3. Detection → Correlation
- **Contract**: `CanonicalEvent` with `event_type`, `severity`, `rule_id` filled
- **Direction**: One-way
- **Validation**: Correlation checks `rule_id` is non-zero for matches

### 4. Correlation → Policy
- **Contract**: `CanonicalEvent` with `context_flags` and `defcon_impact` filled
- **Direction**: One-way
- **Validation**: Policy checks `policy_action` is `allow` (default) before decision

### 5. Policy → Enforcement
- **Contract**: `CanonicalEvent` with final `policy_action` set
- **Direction**: One-way
- **Validation**: Enforcement checks `enforcement_status == 0` (pending) before executing

### 6. Enforcement → Forensics
- **Contract**: `CanonicalEvent` with `enforcement_status` updated
- **Direction**: One-way (write-only to audit log)
- **Validation**: Forensics records all fields, no filtering

## Language Ownership

| Language | Layer | Responsibility |
|----------|-------|----------------|
| **Zig** | 1, 3, 6 | Sensor + Detection + WFP Enforcement |
| **Go** | 2, 4, 7 | Ingestion + Correlation + Forensics API |
| **Python** | 3, 4 | Tier-2 Detection + Intelligence |
| **Cython** | 3 | Accelerated Tier-2 pattern matching |
| **C++** | 5, 6 | DEFCON Policy + Firewall Enforcement |
| **Rust** | 3, 6 | Behavioral Detection + PEP |
| **TypeScript** | 5 | (Future) Policy IR + Rule compiler |

## What NOT to Do

1. **Sensors MUST NOT block** — only detection + policy can decide to block
2. **Detection MUST NOT call WFP** — enforcement is a separate layer
3. **Policy MUST NOT execute** — it only sets `policy_action` field
4. **Enforcement MUST NOT decide** — it only executes what policy decided
5. **Forensics MUST NOT filter** — it records everything, unconditionally
6. **No layer reads from another layer's internal state** — only via CanonicalEvent

## Canonical Event Model (AEGIS-002)

Defined in `core/canonical_event.zig`:

- **Magic**: `0x41454731` ("AEG1")
- **Version**: 1
- **Size**: `@sizeOf(CanonicalEvent)` bytes
- **Fields**: See `canonical_event.zig` for full schema
- **Validation**: `canonical_event.validate()` checks magic + version + size

All languages must implement the same layout:
- Zig: `extern struct`
- C++: `#pragma pack(push, 1) struct`
- Rust: `#[repr(C, packed)]`
- Go: struct with same field order
- Python: dataclass with same field names

## Sprint 1 (AEGIS-001 through AEGIS-008)

This document freezes the architecture boundary for Sprint 1.
Subsequent sprints may add layers but MUST NOT change existing boundaries.
