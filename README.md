# AEGIS NIDS

**AEGIS** is a multi-tier Network Intrusion Detection System (NIDS) for Windows, built with a Zig core, C++ bridge, Rust shield, Go nose, and Python brain. It implements a full detection-to-enforcement pipeline with 21 verified proof modules (G1-G21) covering contracts, forensics, compliance, and operational resilience.

[![Build Status](https://github.com/Supertee003/NIDs_Windows/actions/workflows/ci.yml/badge.svg)](https://github.com/Supertee003/NIDs_Windows/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Zig](https://img.shields.io/badge/Zig-0.13-orange.svg)](https://ziglang.org/)

---

## Table of Contents

- [Architecture](#architecture)
- [Pipeline Stages](#pipeline-stages)
- [Proof Modules (G1-G21)](#proof-modules-g1g21)
- [Project Structure](#project-structure)
- [Building](#building)
- [Testing](#testing)
- [Configuration](#configuration)
- [Runbooks](#runbooks)
- [Compliance](#compliance)
- [Contributing](#contributing)
- [License](#license)

---

## Architecture

AEGIS follows a **5-tier architecture** with strict separation of concerns:

```
+-----------+    +-----------+    +-----------+    +-----------+    +-----------+
|   Nose    | -> |   Core    | -> |   Brain   | -> |  Shield   | -> |  Mouth   |
| (Go/C)    |    | (Zig)     |    | (Python)  |    | (Rust)    |    | (Rust)    |
+-----------+    +-----------+    +-----------+    +-----------+    +-----------+
   Sensor         Pipeline         Advisory         Enforcement       DEFCON TUI
   Ingest         (8 stages)       (fail-soft)      (PEP)            (Operator)
```

**Tier Roles:**
- **Nose** -- Sensor ingestion (WFP callout, minifilter, pipe monitor)
- **Core** -- Zig pipeline (canonical events, detection, verdict, policy, PEP, forensic, audit)
- **Brain** -- Python advisory layer (fail-soft, never enforces directly)
- **Shield** -- Rust enforcement layer (validate -> execute -> deferred queue)
- **Mouth** -- Rust DEFCON TUI for operator interaction

---

## Pipeline Stages

The Core pipeline processes each event through **8 stages** in strict order:

```
Event -> [Nose] -> [Flow] -> [Detection] -> [Verdict] -> [Policy] -> [PEP] -> [Forensic] -> [Audit]
                    |          |              |           |          |          |           |
                    v          v              v           v          v          v           v
               FlowState   Evidence      Verdict      Decision   Enforcement  Record      Trail
                             (G5)        (Brain)     (Policy)    (G10)       (G11)       (G14)
```

| Stage | Module | Proof | Responsibility |
|-------|--------|-------|----------------|
| 1. Nose | `nose/`, `core/wfp_ioctl.zig` | G3 | Sensor ingestion (WFP, minifilter, pipe) |
| 2. Flow | `core/flow_engine.zig` | G4 | Flow tracking (atomic upsert, eviction) |
| 3. Detection | `core/detection_engine.zig` | G5 | Rule matching (non-invasive detectors) |
| 4. Verdict | `core/verdict_aggregator.zig` | G8 | Brain advisory (fail-soft) |
| 5. Policy | `core/policy_engine.zig` | G9 | Decision (block/alert/allow) |
| 6. PEP | `core/rust_pep.zig` | G10 | Enforcement (validate -> execute -> deferred) |
| 7. Forensic | `core/forensics_engine.zig` | G11 | Immutable log + query + redaction |
| 8. Audit | `core/audit_trail_proof.zig` | G14 | Operator trail (hash-chained, tamper-evident) |

---

## Proof Modules (G1-G21)

The rewrite introduced **21 proof modules** that verify the architecture's contracts end-to-end. Each module is self-contained and tested.

| Gate | Module | Section | Verified Property |
|------|--------|---------|-------------------|
| **G1** | `contract_freeze.zig` | Sec.1-4 | Contract freeze (no breaking changes after release) |
| **G2** | `fabric_accounting.zig` | Sec.5-7 | Fabric accounting (input = processed + dropped + rejected) |
| **G3** | `runtime_spine.zig` | Sec.8-10 | Runtime spine (production vs tooling separation) |
| **G4** | `flow_state_proof.zig` | Sec.11-13 | Flow state (atomic upsert, eviction, stress test) |
| **G5** | `detection_fabric_proof.zig` | Sec.14-16 | Detection fabric (non-invasive detectors, evidence) |
| **G6** | `correlation_proof.zig` | Sec.17-19 | Correlation (entity schema lock, incident graph) |
| **G7** | `intelligence_proof.zig` | Sec.20-22 | Intelligence (Threat Intel + RAG separation, fail-soft) |
| **G8** | `brain_proof.zig` | Sec.23-25 | Brain advisory (advisory-only, fail-soft when down) |
| **G9** | `policy_plane_proof.zig` | Sec.26-28 | Policy plane (IR stability, signing, conflict resolution) |
| **G10** | `pep_enforcement_proof.zig` | Sec.29-31 | PEP enforcement (validate, execute, deferred queue) |
| **G11** | `forensic_replay_proof.zig` | Sec.32-34 | Forensic replay (immutable, query, redact, replay) |
| **G12** | `config_reload_proof.zig` | Sec.35-37 | Config reload (hot reload, atomic swap, validation) |
| **G13** | `health_monitoring_proof.zig` | Sec.38-40 | Health monitoring (liveness, readiness, DEFCON rollup) |
| **G14** | `audit_trail_proof.zig` | Sec.41-43 | Audit trail (chain of custody, tamper-evident) |
| **G15** | `telemetry_export_proof.zig` | Sec.44-46 | Telemetry export (OpenTelemetry, Prometheus, SIEM CEF) |
| **G16** | `siem_integration_proof.zig` | Sec.47-49 | SIEM integration (CEF, LEEF, KEY-VALUE ingestion) |
| **G17** | `backup_recovery_proof.zig` | Sec.50-52 | Backup & recovery (snapshot, restore, RPO/RTO) |
| **G18** | `performance_tuning_proof.zig` | Sec.53-55 | Performance tuning (thread pool, queue sizing, batching) |
| **G19** | `compliance_proof.zig` | Sec.56-58 | Compliance (SOC 2, ISO 27001, NIST CSF) |
| **G20** | `documentation_proof.zig` | Sec.59-61 | Documentation (API reference, runbooks, architecture) |
| **G21** | `final_integration_proof.zig` | Sec.62-64 | Final integration (end-to-end, resilience, compliance) |

---

## Project Structure

```
NIDs_Windows/
+-- build.zig                    # Zig build system (84 test targets)
+-- config/
|   +-- Rules.json              # Detection rules (rule_id, severity, action)
|   +-- aegis.conf              # System configuration (brain, nose, mouth, ips)
+-- core/                       # Zig core pipeline (88 .zig files)
|   +-- canonical_event.zig     # Canonical event schema (frozen)
|   +-- dispatcher.zig          # 8-stage pipeline dispatcher
|   +-- lifecycle.zig           # Init/shutdown lifecycle
|   +-- detection_engine.zig   # Rule matching
|   +-- verdict_aggregator.zig # Verdict aggregation
|   +-- policy_engine.zig      # Decision making
|   +-- rust_pep.zig           # Enforcement (PEP)
|   +-- forensics_engine.zig   # Forensic recording
|   +-- forensic_log.zig       # NDJSON append-only logger
|   +-- audit_trail_proof.zig  # G14: hash-chained audit
|   +-- final_integration_proof.zig  # G21: capstone
|   +-- ... (75 more modules)
+-- brain/                      # Python advisory layer (fail-soft)
+-- nose/                       # Go sensor ingestion
+-- shield/                     # Rust enforcement (PEP)
+-- mouth/                      # Rust DEFCON TUI
+-- bridge/                     # C++ IPC bridge
+-- drivers/                    # C kernel drivers (WFP + minifilter)
+-- docs/                       # Architecture docs, runbooks, status
+-- scripts/                    # Deploy + management scripts
+-- .github/workflows/ci.yml   # CI/CD (zig build test)
```

---

## Building

### Prerequisites

- **Zig 0.13.0** -- [ziglang.org](https://ziglang.org/download/)
- **Rust (stable)** -- for shield/mouth components
- **Go 1.21+** -- for nose component
- **Python 3.10+** -- for brain component
- **Visual Studio Build Tools** -- for C++ bridge and kernel drivers

### Build the Core

```bash
zig build
```

This produces `zig-out/bin/aegis-nids.exe` and installs `config/Rules.json`.

---

## Testing

Run all **84 test targets**:

```bash
zig build test
```

Run a specific proof module:

```bash
zig test core/final_integration_proof.zig
```

### Test Coverage

| Category | Modules | Tests |
|----------|---------|-------|
| Base modules | 12 | ~80 |
| Runtime (Phase 5-27) | 24 | ~180 |
| G1-G21 proofs | 21 | ~450 |
| Sensor/platform | 8 | ~60 |
| **Total** | **84** | **~770** |

---

## Configuration

### `config/Rules.json`

Detection rules with 3-tier matching:
- **Tier 1**: Zig AC automaton (fast_pattern)
- **Tier 2**: Python regex (regex_pattern)
- **Tier 3**: Rust memory shield (behavior validation)

```json
{
  "nids_rules": [
    {
      "rule_id": "R0056",
      "name": "SQL Injection (Auth Bypass)",
      "severity": "Critical",
      "action": "Drop",
      "fast_pattern": "SQLI_BYPASS",
      "match_pattern": "' OR 1=1"
    }
  ]
}
```

### `config/aegis.conf`

System configuration:

```ini
[bridge]
pipe_name = \\.\pipe\aegis_bridge
event_queue_capacity = 8192

[core]
brain_udp_port = 9999
brain_udp_host = 127.0.0.1

[brain]
hot_reload = true
rules_file = config/Rules.json

[nose]
refresh_interval_s = 2

[mouth]
refresh_interval_ms = 1000
log_file = logs/anomalous.json

[ips]
enabled = true
method = netsh
```

**Hot reload**: Rules.json changes are detected within 5 seconds (mtime watchdog). No process restart needed.

---

## Runbooks

| ID | Type | Title | Module |
|----|------|-------|--------|
| RB-001 | Incident Response | Block IP via PEP | pep_enforcement_proof |
| RB-002 | Incident Response | Forensic query for incident reconstruction | forensic_replay_proof |
| RB-003 | Incident Response | Audit trail tamper investigation | audit_trail_proof |
| RB-004 | Recovery | Restore from snapshot | backup_recovery_proof |
| RB-005 | Recovery | Config rollback | config_reload_proof |
| RB-006 | Troubleshooting | Subsystem health check | health_monitoring_proof |
| RB-007 | Troubleshooting | Performance tuning (queue depth + batching) | performance_tuning_proof |
| RB-008 | Troubleshooting | SIEM ingestion debugging | siem_integration_proof |
| RB-009 | Deployment | Hot reload config (no restart) | config_reload_proof |
| RB-010 | Deployment | Telemetry export setup | telemetry_export_proof |

See `docs/runbooks/` for detailed step-by-step procedures.

---

## Compliance

AEGIS satisfies three compliance frameworks with a single feature set:

| Framework | Controls | Satisfied By |
|-----------|----------|--------------|
| **SOC 2** | CC6.1, CC6.6, CC7.1, CC7.2, A1.1-A1.3, C1.1-C1.2 | PEP, Audit, Brain, SIEM, Health, Backup, Policy, Forensic |
| **ISO 27001** | A.5.9, A.5.24, A.5.30, A.8.12, A.8.15, A.8.16, A.8.23, A.8.24 | Config, Forensic, Health, PEP, Policy, SIEM, Backup |
| **NIST CSF** | ID.AM, PR.AC, PR.DS, DE.CM, RS.AN, RS.MI, RC.RP, RC.CO | Config, PEP, Policy, Brain, SIEM, Backup, Telemetry |

**Cross-cutting**: PEP enforcement and Backup recovery satisfy controls in all 3 frameworks.

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Run tests (`zig build test`)
4. Commit with conventional commits (`feat:`, `fix:`, `docs:`, `test:`)
5. Open a Pull Request

### Commit Hygiene

- Use **granular commits** (one logical change per commit)
- Follow **Conventional Commits** specification
- Reference the proof gate (e.g., `feat(G14): add audit trail tamper detection`)

---

## License

This project is licensed under the **MIT License** -- see [LICENSE](LICENSE) for details.

---

## Acknowledgments

- AEGIS architecture based on v5.0 blueprint (64 sections)
- 21 proof modules (G1-G21) verify contracts end-to-end
- Multi-language design: Zig (core), C++ (bridge), Rust (shield/mouth), Go (nose), Python (brain)
- 84 test targets with ~770 tests

**Status**: G1-G21 rewrite complete. Production-ready pending P2 items (PEP quarantine implementation).
