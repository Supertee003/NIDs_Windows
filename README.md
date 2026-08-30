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

AEGIS follows a **single runtime spine** with strict separation of concerns:

```
SOURCE
  |
SENSOR (Nose - Go/C)
  |
CANONICAL EVENT (Zig - immutable)
  |
VALIDATION (Zig)
  |
EVENT FABRIC (Zig - priority queue)
  |
STATE / FLOW (Zig - atomic upsert, bounded)
  |
DETECTION (Zig - evidence producer, NOT enforcer)
  |
EVIDENCE (Zig - aggregated)
  |
VERDICT (Zig + Brain advisory - fail-soft)
  |
CORRELATION (Zig - entity graph, 9 types)
  |
INTELLIGENCE (Zig - Threat Intel + RAG, separate)
  |
POLICY (Zig - decides, NOT executes)
  |
ENFORCEMENT PLAN (Zig -> Rust)
  |
RUST PEP (Rust - validate, execute, defer)
  |
ACTION (Rust - block/alert/rate-limit)
  |
FORENSICS (Zig - immutable, hash-chained)
  |
REPLAY (Zig - deterministic regression)
```

**Canonical Architecture Document**: `docs/architecture/ARCHITECTURE_CANONICAL.md`

---

## Pipeline Stages

The Core pipeline processes each event through **12 stages** in strict order:

| Stage | Module | Proof | Responsibility |
|-------|--------|-------|----------------|
| 1. Nose | `nose/`, `drivers/` | G3 | Sensor ingestion (WFP, minifilter, pipe) |
| 2. Canonical Event | `core/canonical_event.zig` | G1 | Immutable event schema |
| 3. Event Fabric | `core/event_fabric.zig` | G2 | Priority queue + backpressure |
| 4. Flow | `core/flow_engine.zig` | G4 | Flow tracking (atomic upsert, eviction) |
| 5. Detection | `core/detection_engine.zig` | G5 | Rule matching (non-invasive detectors) |
| 6. Verdict | `core/verdict_aggregator.zig` | G8 | Brain advisory (fail-soft) |
| 7. Correlation | `core/correlation_engine.zig` | G6 | Entity graph (9 types, 8 relationships) |
| 8. Intelligence | `core/threat_intel.zig` | G7 | Threat Intel + RAG (separate) |
| 9. Policy | `core/policy_engine.zig` | G9 | Decision (block/alert/allow) |
| 10. PEP | `core/rust_pep.zig` -> `shield/` | G10 | Enforcement (validate -> execute -> deferred) |
| 11. Forensic | `core/forensics_engine.zig` | G11 | Immutable log + query + redaction |
| 12. Audit | `core/audit_trail_proof.zig` | G14 | Operator trail (hash-chained, tamper-evident) |

---

## Proof Modules (G1-G21)

The rewrite introduced **21 proof modules** that verify the architecture's contracts end-to-end. Each module is self-contained and tested.

| Gate | Module | Section | Verified Property |
|------|--------|---------|-------------------|
| **G1** | `contract_freeze.zig` | Sec.1-4 | Contract freeze (no breaking changes after release) |
| **G2** | `fabric_accounting.zig` | Sec.5-7 | Fabric accounting (input = processed + dropped + rejected) |
| **G3** | `runtime_spine.zig` | Sec.8-10 | Runtime spine (single path, golden path trace) |
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
| **G19** | `compliance_proof.zig` | Sec.56-58 | Compliance (SOC 2, ISO 27001, NIST CSF control mapping) |
| **G20** | `documentation_proof.zig` | Sec.59-61 | Documentation (API reference, runbooks, architecture) |
| **G21** | `final_integration_proof.zig` | Sec.62-64 | Final integration (end-to-end, resilience, compliance) |

---

## Project Structure

```
NIDs_Windows/
+-- build.zig                    # Zig build system (84 test targets)
+-- aegis.manifest.json          # Build manifest (versions + provenance)
+-- config/
|   +-- Rules.json              # Detection rules (hot-reloadable)
|   +-- aegis.conf               # System configuration
+-- core/                        # Zig core pipeline (88 .zig files)
+-- brain/                       # Python advisory layer (fail-soft)
+-- nose/                        # Go sensor ingestion
+-- shield/                      # Rust enforcement (PEP)
+-- mouth/                       # Rust DEFCON TUI
+-- bridge/                      # C++ IPC bridge
+-- drivers/                     # C kernel drivers (WFP + minifilter)
+-- docs/
|   +-- architecture/            # Canonical architecture docs
|   +-- ai-context/             # AI development context (11 files)
|   +-- runbooks/               # Operational runbooks (RB-001 to RB-010)
+-- scripts/                     # Deploy + management scripts
+-- .github/workflows/ci.yml     # Cross-language CI matrix (11 stages)
```

---

## Building

### Prerequisites

- **Zig 0.13.0** - [ziglang.org](https://ziglang.org/download/)
- **Rust (stable)** - for shield/mouth components
- **Go 1.21+** - for nose component
- **Python 3.10+** - for brain component
- **Visual Studio Build Tools** - for C++ bridge and kernel drivers

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

### CI Matrix (11 stages)

The CI pipeline runs on every push/PR:

| Stage | Purpose |
|-------|---------|
| 1. Repository hygiene | No backup files, no tracked cache |
| 2. Zig build/test | Core runtime (84 targets) |
| 3. C/C++ build/test | Bridge, drivers |
| 4. Rust build/test | Shield, mouth |
| 5. Go build/test | Nose, aggregator |
| 6. Python/Cython tests | Brain, RAG |
| 7. Cross-language contract vectors | ABI, wire types |
| 8. Static analysis | Lint, format (HARD gate) |
| 9. Security checks | Policy bypass, PEP integrity |
| 10. Integration tests | End-to-end pipeline |
| 11. Build manifest | Version provenance |

---

## Configuration

### `config/Rules.json`

Detection rules with 3-tier matching:
- **Tier 1**: Zig AC automaton (fast_pattern)
- **Tier 2**: Python regex (regex_pattern)
- **Tier 3**: Rust memory shield (behavior validation)

**Hot reload**: Rules.json changes are detected within 5 seconds (mtime watchdog). No process restart needed.

### `config/aegis.conf`

System configuration with sections: `[bridge]`, `[core]`, `[brain]`, `[nose]`, `[mouth]`, `[ips]`.

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

---

## Compliance

AEGIS **maps** selected product controls and evidence mechanisms to SOC 2, ISO 27001, and NIST CSF control objectives.

**Important**: AEGIS is **NOT** "SOC 2 compliant" or "ISO 27001 certified" unless a formal third-party assessment has been performed. The compliance proof module (G19) maps features to control objectives for engineering reference only.

| Framework | Controls Mapped | Satisfied By |
|-----------|-----------------|--------------|
| **SOC 2** | CC6.1, CC6.6, CC7.1, CC7.2, A1.1-A1.3, C1.1-C1.2 | PEP, Audit, Brain, SIEM, Health, Backup, Policy, Forensic |
| **ISO 27001** | A.5.9, A.5.24, A.5.30, A.8.12, A.8.15, A.8.16, A.8.23, A.8.24 | Config, Forensic, Health, PEP, Policy, SIEM, Backup |
| **NIST CSF** | ID.AM, PR.AC, PR.DS, DE.CM, RS.AN, RS.MI, RC.RP, RC.CO | Config, PEP, Policy, Brain, SIEM, Backup, Telemetry |

See `docs/architecture/ARCHITECTURE_CANONICAL.md` Section 10 for compliance wording rules.

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Read `docs/ai-context/` files for shared context
4. Run tests (`zig build test`)
5. Commit with conventional commits (`feat:`, `fix:`, `docs:`, `test:`)
6. Open a Pull Request

### Commit Hygiene

- Use **granular commits** (one logical change per commit)
- Follow **Conventional Commits** specification
- Reference the proof gate (e.g., `feat(G14): add audit trail tamper detection`)

### AI Development

See `docs/architecture/AI_DEVELOPMENT.md` for the AI role model (A0-A3) and context block format.

---

## License

This project is licensed under the **MIT License** - see [LICENSE](LICENSE) for details.

---

## Acknowledgments

- AEGIS architecture based on v5.0 blueprint (64 sections)
- 21 proof modules (G1-G21) verify contracts end-to-end
- Multi-language design: Zig (core), C++ (bridge), Rust (shield/mouth), Go (nose), Python (brain)
- 84 test targets with ~770 tests
- Cross-language CI matrix (11 stages)

**Status**: G1-G23 complete. Consolidation phase finalized.
