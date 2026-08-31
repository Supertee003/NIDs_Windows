<div align="center">

# AEGIS NIDS

### Multi-Tier Network Intrusion Detection System for Windows

[![Build Status](https://github.com/Supertee003/NIDs_Windows/actions/workflows/ci.yml/badge.svg)](https://github.com/Supertee003/NIDs_Windows/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Zig 0.13](https://img.shields.io/badge/Zig-0.13-orange.svg)](https://ziglang.org/)
[![Rust](https://img.shields.io/badge/Rust-stable-red.svg)](https://www.rust-lang.org/)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8.svg)](https://go.dev/)
[![Tests](https://img.shields.io/badge/Tests-84%20targets%20%7C%20~770%20cases-brightgreen.svg)](#testing)

**Observation -> Canonical Semantics -> Stateful Context -> Evidence -> Decision -> Controlled Enforcement -> Immutable Trace -> Replay**

</div>

---

## Overview

AEGIS is a production-grade Network Intrusion Detection System built for Windows environments. It combines five programming languages -- each with a clearly bounded responsibility -- to implement a full detection-to-enforcement pipeline with 21 verified proof modules, immutable forensic logging, and compliance mapping to SOC 2, ISO 27001, and NIST CSF.

The system processes network traffic through an 8-stage pipeline: from sensor ingestion through detection, verdict aggregation, policy decision making, Rust-enforced PEP execution, and finally forensic recording with hash-chained audit trails. Every enforcement action is traceable, replayable, and attributable.

### Key Features

- **8-stage event pipeline** with single runtime spine (no competing paths)
- **21 proof modules** (G1-G21) verifying architecture contracts end-to-end
- **84 test targets** with approximately 770 individual test cases
- **Fail-soft architecture** -- system continues when Brain or PEP is unavailable
- **Immutable forensic logging** with hash chain integrity verification
- **Hash-chained audit trail** for tamper-evident operator action tracking
- **Hot config reload** via mtime watchdog (5-second detection, no restart)
- **Snapshot/restore** with RPO 5min, RTO 30sec bounds
- **Multi-format telemetry export**: OpenTelemetry, Prometheus, SIEM CEF
- **SIEM ingestion**: CEF, LEEF, KEY-VALUE format normalization
- **DEFCON rollup** (5 levels) from subsystem health and queue metrics
- **10 operational runbooks** covering incident response, recovery, troubleshooting
- **Compliance mapping** to SOC 2, ISO 27001, NIST CSF control objectives

---

## Table of Contents

- [Architecture](#architecture)
- [Pipeline Stages](#pipeline-stages)
- [Proof Modules](#proof-modules-g1g21)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Testing](#testing)
- [Configuration](#configuration)
- [Runbooks](#runbooks)
- [Compliance](#compliance)
- [Contributing](#contributing)
- [License](#license)

---

## Architecture

AEGIS follows a **5-tier architecture** with strict separation of concerns. Each tier has a designated programming language and a clearly bounded responsibility scope. Tiers communicate through explicit wire protocols with fixed-width, bounded-length, versioned, and checksummed messages.

```
+-----------+    +-----------+    +-----------+    +-----------+    +-----------+
|   Nose    |    |   Core    |    |   Brain   |    |  Shield   |    |  Mouth   |
|  (Go/C)   |--->|  (Zig)    |--->| (Python)  |--->|  (Rust)   |--->|  (Rust)  |
+-----------+    +-----------+    +-----------+    +-----------+    +-----------+
   Sensor          Pipeline         Advisory         Enforcement       DEFCON TUI
   Ingest         (8 stages)       (fail-soft)       (PEP)            (Operator)
```

### Tier Responsibilities

| Tier | Language | Role | Key Constraint |
|------|----------|------|----------------|
| **Nose** | Go + C | Sensor ingestion (WFP, minifilter, pipe) | No policy authority |
| **Core** | Zig | 8-stage pipeline, event fabric, flow, forensics | No direct enforcement |
| **Brain** | Python | Advisory: threat score, confidence, RAG | Cannot enforce (advisory only) |
| **Shield** | Rust | PEP: validate, execute, deferred queue | Final enforcement authority |
| **Mouth** | Rust | DEFCON TUI, operator interaction | Display only |

### Single Runtime Spine

All events flow through exactly **one** runtime path -- no competing implementations. The dispatcher (`core/dispatcher.zig`) orchestrates the pipeline, with lifecycle managed by `core/lifecycle.zig`. The `main()` function only bootstraps the runtime.

---

## Pipeline Stages

The Core pipeline processes each event through **8 stages** in strict order:

| # | Stage | Module | Proof | Responsibility |
|---|-------|--------|-------|----------------|
| 1 | Nose | `nose/`, `drivers/` | G3 | Sensor ingestion (WFP, minifilter, pipe) |
| 2 | Event Fabric | `core/event_fabric.zig` | G2 | Priority queue + backpressure (4 levels) |
| 3 | Flow | `core/flow_engine.zig` | G4 | Flow tracking (atomic upsert, eviction) |
| 4 | Detection | `core/detection_engine.zig` | G5 | Rule matching (evidence producer, NOT enforcer) |
| 5 | Verdict | `core/verdict_aggregator.zig` | G8 | Brain advisory (fail-soft, 6-state verdict) |
| 6 | Policy | `core/policy_engine.zig` | G9 | Decision (block/alert/allow, NOT execute) |
| 7 | PEP | `core/rust_pep.zig` -> `shield/` | G10 | Enforcement (validate -> execute -> deferred) |
| 8 | Forensic | `core/forensics_engine.zig` | G11 | Immutable log + hash chain + query + redact |

### Fail-Soft Behavior

| Subsystem Down | Impact | System Continues? |
|----------------|--------|:-:|
| Brain | Verdict defaults to conservative | Yes |
| PEP | No enforcement (forensic still records) | Yes |
| Detection | No evidence (verdict stays unknown) | Yes |
| RAG | No context enrichment | Yes |
| Forensic | No recording (critical data loss) | No |
| Audit | No operator trail (compliance impact) | No |

---

## Proof Modules (G1-G21)

21 self-contained proof modules verify architecture contracts end-to-end. Each module contains 15-30 unit tests.

| Gate | Module | Verified Property |
|------|--------|-------------------|
| **G1** | `contract_freeze.zig` | Contract freeze (no breaking changes) |
| **G2** | `fabric_accounting.zig` | Fabric accounting (input = processed + dropped + rejected) |
| **G3** | `runtime_spine.zig` | Runtime spine (single path, golden path trace) |
| **G4** | `flow_state_proof.zig` | Flow state (atomic upsert, eviction, 10K stress) |
| **G5** | `detection_fabric_proof.zig` | Detection fabric (non-invasive detectors, evidence) |
| **G6** | `correlation_proof.zig` | Correlation (entity schema lock, incident graph) |
| **G7** | `intelligence_proof.zig` | Intelligence (Threat Intel + RAG separation, fail-soft) |
| **G8** | `brain_proof.zig` | Brain advisory (advisory-only, fail-soft) |
| **G9** | `policy_plane_proof.zig` | Policy plane (IR stability, signing, conflict resolution) |
| **G10** | `pep_enforcement_proof.zig` | PEP enforcement (validate, execute, deferred queue) |
| **G11** | `forensic_replay_proof.zig` | Forensic replay (immutable, query, redact, replay) |
| **G12** | `config_reload_proof.zig` | Config reload (hot reload, atomic swap, validation) |
| **G13** | `health_monitoring_proof.zig` | Health monitoring (liveness, readiness, DEFCON) |
| **G14** | `audit_trail_proof.zig` | Audit trail (chain of custody, tamper-evident) |
| **G15** | `telemetry_export_proof.zig` | Telemetry export (OTLP, Prometheus, SIEM CEF) |
| **G16** | `siem_integration_proof.zig` | SIEM integration (CEF, LEEF, KEY-VALUE) |
| **G17** | `backup_recovery_proof.zig` | Backup and recovery (snapshot, restore, RPO/RTO) |
| **G18** | `performance_tuning_proof.zig` | Performance (thread pool, queue sizing, batching) |
| **G19** | `compliance_proof.zig` | Compliance (SOC 2, ISO 27001, NIST CSF mapping) |
| **G20** | `documentation_proof.zig` | Documentation (API ref, runbooks, architecture) |
| **G21** | `final_integration_proof.zig` | Final integration (end-to-end, resilience, compliance) |

---

## Project Structure

```
NIDs_Windows/
+-- build.zig                      # Zig build system (84 test targets)
+-- aegis.manifest.json            # Build manifest (versions + provenance)
+-- config/
|   +-- Rules.json                # Detection rules (hot-reloadable)
|   +-- aegis.conf                 # System configuration
+-- core/                          # Zig core pipeline (89 .zig files)
|   +-- canonical_event.zig        # Immutable event schema (frozen)
|   +-- dispatcher.zig            # 8-stage pipeline orchestrator
|   +-- detection_engine.zig      # Rule matching + evidence production
|   +-- flow_engine.zig           # Flow tracking (atomic upsert)
|   +-- policy_engine.zig         # Decision making (NOT execution)
|   +-- rust_pep.zig              # PEP interface -> Rust shield
|   +-- forensics_engine.zig      # Immutable log + hash chain
|   +-- *_proof.zig               # 21 proof modules (G1-G21)
|   +-- ...                        # 60+ runtime + sensor modules
+-- brain/                         # Python advisory layer (fail-soft)
+-- nose/                          # Go sensor ingestion
+-- shield/                        # Rust enforcement (PEP)
+-- mouth/                         # Rust DEFCON TUI
+-- bridge/                        # C++ IPC bridge
+-- drivers/                       # C kernel drivers (WFP + minifilter)
+-- docs/
|   +-- architecture/              # 7 canonical architecture docs
|   +-- ai-context/               # 11 AI development context files
|   +-- runbooks/                 # 10 operational runbooks
+-- .github/workflows/ci.yml       # Cross-language CI (11 stages)
```

---

## Getting Started

### Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| [Zig](https://ziglang.org/download/) | 0.13.0 | Core pipeline |
| [Rust](https://rustup.rs/) | stable | Shield (PEP) + Mouth (TUI) |
| [Go](https://go.dev/dl/) | 1.21+ | Nose (sensor) |
| [Python](https://python.org/) | 3.10+ | Brain (advisory) |
| Visual Studio Build Tools | 2022 | C++ bridge + kernel drivers |

### Build

```bash
# Clone the repository
git clone https://github.com/Supertee003/NIDs_Windows.git
cd NIDs_Windows

# Build the core (produces zig-out/bin/aegis-nids.exe)
zig build

# Run the NIDS
zig build run
```

### Quick Test

```bash
# Run all 84 test targets
zig build test

# Run a specific proof module
zig test core/final_integration_proof.zig
```

---

## Testing

### Test Coverage

| Category | Modules | Tests |
|----------|:-------:|:----:|
| Base modules (events, queue, fabric) | 12 | ~80 |
| Runtime modules (Phase 5-27) | 24 | ~180 |
| G1-G21 proof modules | 21 | ~450 |
| Sensor/platform modules | 8 | ~60 |
| **Total** | **84** | **~770** |

### CI Pipeline (11 stages)

| Stage | Purpose | Gate |
|-------|---------|:----:|
| 1. Repository hygiene | No backup files, no cache | Hard |
| 2. Zig build/test | Core runtime (84 targets) | Hard |
| 3. C/C++ build | Bridge, drivers | Hard |
| 4. Rust build/test | Shield (PEP), Mouth (TUI) | Hard |
| 5. Go build/test | Nose, aggregator | Hard |
| 6. Python tests | Brain, RAG | Hard |
| 7. Contract vectors | Wire, ABI, schema | Hard |
| 8. Static analysis | `zig fmt --check` | Hard |
| 9. Security checks | Policy bypass, PEP integrity | Hard |
| 10. Integration tests | End-to-end pipeline | Hard |
| 11. Build manifest | Version provenance | Hard |

---

## Configuration

### Detection Rules (`config/Rules.json`)

3-tier rule matching with hot-reload (5-second detection via mtime watchdog):

| Tier | Engine | Match Type |
|------|--------|------------|
| 1 | Zig AC automaton | `fast_pattern` |
| 2 | Python regex | `regex_pattern` |
| 3 | Rust memory shield | Behavior validation |

```json
{
  "nids_rules": [{
    "rule_id": "R0056",
    "name": "SQL Injection (Auth Bypass)",
    "severity": "Critical",
    "action": "Drop",
    "fast_pattern": "SQLI_BYPASS"
  }]
}
```

### System Config (`config/aegis.conf`)

```ini
[brain]
hot_reload = true
rules_file = config/Rules.json

[nose]
refresh_interval_s = 2

[ips]
enabled = true
method = netsh
```

---

## Runbooks

10 operational runbooks covering incident response, recovery, troubleshooting, and deployment:

| ID | Type | Title |
|----|------|-------|
| RB-001 | Incident Response | Block IP via PEP |
| RB-002 | Incident Response | Forensic query for incident reconstruction |
| RB-003 | Incident Response | Audit trail tamper investigation |
| RB-004 | Recovery | Restore from snapshot |
| RB-005 | Recovery | Config rollback |
| RB-006 | Troubleshooting | Subsystem health check |
| RB-007 | Troubleshooting | Performance tuning |
| RB-008 | Troubleshooting | SIEM ingestion debugging |
| RB-009 | Deployment | Hot reload config |
| RB-010 | Deployment | Telemetry export setup |

See `docs/runbooks/` for detailed procedures.

**RPO:** 5 minutes (max data loss) | **RTO:** 30 seconds (max recovery time)

---

## Compliance

AEGIS **maps** selected product controls and evidence mechanisms to SOC 2, ISO 27001, and NIST CSF control objectives. This is an engineering control mapping, **not** a formal compliance certification.

| Framework | Controls Mapped | Key Modules |
|-----------|:--------------:|-------------|
| **SOC 2** | 9 | PEP, Audit, Brain, SIEM, Health, Backup, Policy, Forensic |
| **ISO 27001** | 8 | Config, Forensic, Health, PEP, Policy, SIEM, Backup |
| **NIST CSF** | 8 | Config, PEP, Policy, Brain, SIEM, Backup, Telemetry |

**Cross-cutting:** PEP enforcement and Backup recovery satisfy controls in all 3 frameworks.

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Read `docs/ai-context/` files for shared architecture context
4. Run tests: `zig build test`
5. Commit using Conventional Commits: `feat(G14): add audit trail tamper detection`
6. Open a Pull Request

### AI Development

See `docs/architecture/AI_DEVELOPMENT.md` for the AI role model (A0-A3) and context block format.

---

## License

This project is licensed under the **MIT License** -- see [LICENSE](LICENSE) for details.

---

<div align="center">

**Built with Zig | Rust | Go | Python | C++**

AEGIS NIDS (c) 2026 Supertee003

</div>
