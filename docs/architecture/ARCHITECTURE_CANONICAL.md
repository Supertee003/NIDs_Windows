# AEGIS NIDS - Canonical Architecture

**Status**: AUTHORITATIVE
**Date**: 2026-08-31
**Supersedes**: All previous architecture documents (see DEPRECATION_MAP.md)

---

## Purpose

This document is the **single source of truth** for AEGIS NIDS architecture.
All other architecture documents are DEPRECATED and point to this file.

If any conflict arises between this document and another file, **this file wins**.

---

## 1. System Identity

AEGIS is a multi-tier Windows Network Intrusion Detection System (NIDS) built on the principle:

> Observation -> Canonical Semantics -> Stateful Context -> Evidence -> Decision -> Controlled Enforcement -> Immutable Trace -> Replay

The system must be able to answer:
- What happened?
- Why did we believe it?
- Which evidence supported it?
- Which policy decided?
- Which version was used?
- What action was attempted?
- Did enforcement actually happen?
- Can we replay the decision?

---

## 2. Runtime Spine (Single Path)

There is exactly **one** runtime spine. No competing paths are allowed.

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

**Authority**: `core/dispatcher.zig` orchestrates this spine.
**Lifecycle**: `core/lifecycle.zig` controls init/shutdown.
**Main**: `nids_main.zig` only bootstraps runtime.

---

## 3. Language Ownership

| Language | Owns | Forbidden |
|----------|------|-----------|
| **Zig** | Runtime, event fabric, flow, detection orchestration, correlation, lifecycle, Windows coordination | Independent policy authority, direct enforcement |
| **C** | Stable ABI, wire types, fixed-width primitives, native headers | Business logic |
| **C++** | Native adapters, Windows interop, legacy bridge compatibility, transport adapter | Becoming thinner over time |
| **Go** | Nose, collectors, event ingestion, I/O-heavy concurrency, external aggregation | Independent policy authority |
| **Rust** | Security boundary, policy verification, PEP, enforcement, privileged state, rollback | Final enforcement authority |
| **Python** | Brain orchestration, RAG, analytics, experiments, model lifecycle | Direct enforcement |
| **Cython** | Feature extraction, hot loops, numeric preprocessing, performance-sensitive Brain ops | Policy decisions |

---

## 4. Semantic Positions

Every source file belongs to exactly **one** semantic position:

| Position | Responsibility |
|----------|---------------|
| OBSERVE | Collect data from Windows/network/host |
| NORMALIZE | Validate and convert source info to Canonical Events |
| TRANSPORT | Move data between processes/components |
| SCHEDULE | Queue, priority, backpressure, dispatch |
| STATE | Flow/session/entity state |
| DETECT | Generate evidence |
| CORRELATE | Combine events/entities into context or incidents |
| INTELLIGENCE | Threat intel, Brain, RAG, contextual enrichment |
| DECIDE | Policy and decision planning |
| ENFORCE | PEP and privileged actions |
| REMEMBER | Forensics, audit, replay |
| OPERATE | Lifecycle, health, metrics, deployment, config |
| PROVE | Tests, proof modules, fault injection, benchmarks |

---

## 5. File Classification

Every file has exactly **one** primary classification:

| Class | Description |
|-------|-------------|
| RUNTIME | Required for product execution |
| ADAPTER | Connects runtime boundaries |
| PROOF | Verifies an invariant |
| TEST | Tests behavior |
| HARNESS | Drives tests/scenarios |
| BENCHMARK | Measures performance |
| MIGRATION | Temporary compatibility logic |
| LEGACY | Old implementation awaiting removal |

---

## 6. Contract Authority

Each contract has exactly **one** authoritative definition:

| Contract | Authority File | Notes |
|----------|---------------|-------|
| CanonicalEvent | `core/canonical_event.zig` | Immutable after observation |
| Wire/ABI | `core/wire_event.zig` | Fixed width, explicit endian, no pointers |
| Evidence | `core/detection_engine.zig` | Produced by detectors |
| Verdict | `core/verdict_aggregator.zig` | 6 states: benign/observe/suspicious/malicious/unknown/error |
| PolicyDecision | `core/policy_engine.zig` | Decides, does NOT execute |
| EnforcementPlan | `core/policy_engine.zig` -> Rust | Validated before execution |
| EnforcementResult | `core/rust_pep.zig` | 7 statuses: executed/failed/denied/deferred/not_applicable/unsupported/timeout |
| ForensicRecord | `core/forensics_engine.zig` | Complete decision trace |

**Rule**: Do not add decision state directly into the original event.
Use new objects for: DetectionEvidence, DetectionVerdict, CorrelationResult, ThreatContext, BrainAdvice, PolicyDecision, EnforcementPlan, EnforcementResult, ForensicRecord.

---

## 7. Security Boundary

**Rust PEP** is the final enforcement authority.

Rust validates before execution:
- policy
- version
- signature
- target
- action
- authorization
- expiry

PEP returns explicit results (never a single `success` flag):
- EXECUTED
- FAILED
- DENIED
- DEFERRED
- NOT_APPLICABLE
- UNSUPPORTED
- TIMEOUT

**No bypass**: Detection cannot call PEP. Brain cannot enforce. Policy cannot execute directly.

---

## 8. Fail-Soft Model

When a subsystem is unavailable, the system continues with reduced capability:

| Subsystem Down | Impact | System Continues? |
|----------------|--------|-------------------|
| Brain | Verdict defaults to "suspicious" (no advisory) | YES |
| PEP | No enforcement (forensic still records) | YES |
| Detection | No evidence (verdict stays "unknown") | YES |
| Forensic | No recording (CRITICAL - data loss) | NO |
| Audit | No operator trail (compliance impact) | NO |

---

## 9. Version Freeze

These versions are frozen separately and recorded per release:

- Event Schema (canonical_event.zig)
- Wire Protocol (wire_event.zig)
- Policy IR (policy_plane.zig)
- Detection Rule Set (config/Rules.json)
- Policy Set (signed IR)

A code release records which versions it used (see `aegis.manifest.json`).

---

## 10. Compliance Wording (IMPORTANT)

AEGIS **maps** selected product controls to SOC 2, ISO 27001, and NIST CSF control objectives.

AEGIS is **NOT** "SOC 2 compliant" or "ISO 27001 certified" unless a formal third-party assessment has been performed.

Correct wording:
> "AEGIS maps selected product controls and evidence mechanisms to SOC 2, ISO 27001, and NIST CSF control objectives."

Incorrect wording:
> "AEGIS is SOC 2 / ISO 27001 / NIST CSF compliant"

---

## 11. Target Repository Structure

```
NIDs_Windows/
|
+-- core/                    # Zig runtime (production)
|   +-- event/               # Canonical events, wire types
|   +-- runtime/             # Dispatcher, lifecycle
|   +-- state/               # Flow, session, entity
|   +-- detection/           # Detectors, evidence
|   +-- correlation/         # Entity graph, incidents
|   +-- intelligence/        # Threat intel, brain integration
|   +-- policy/              # Policy IR, decisions
|   +-- enforcement/         # PEP integration
|   +-- forensics/           # Recording, audit
|   +-- telemetry/           # Export, SIEM
|
+-- sensors/                 # Sensor ingestion
|   +-- nose/                # Go nose
|   +-- wfp/                 # WFP callout driver
|   +-- hids/                # HIDS collector
|
+-- bridge/                  # C++ IPC bridge
+-- brain/                   # Python advisory layer
+-- shield/                  # Rust enforcement (PEP)
+-- mouth/                   # Rust DEFCON TUI
+-- shared/                  # Cross-language schemas
|   +-- schema/
|   +-- protocol/
+-- tests/                   # Behavioral tests
+-- proof/                   # Proof modules (G1-G21)
+-- benchmarks/              # Performance benchmarks
+-- tools/                   # Utility scripts
+-- docs/                    # Documentation
+-- config/                  # Configuration files
+-- scripts/                 # Deploy/management scripts
```

**Note**: This is a target state. Migration is incremental.

---

## 12. Build Manifest

Every release produces `aegis.manifest.json` containing:

```json
{
  "git_commit": "...",
  "core_version": "...",
  "event_schema_version": 1,
  "wire_version": 1,
  "ruleset_version": 1,
  "policy_version": 1,
  "brain_version": "...",
  "shield_version": "...",
  "nose_version": "...",
  "driver_version": "...",
  "compiler_versions": {
    "zig": "0.13.0",
    "rust": "...",
    "go": "...",
    "python": "..."
  },
  "build_time": "..."
}
```

This becomes part of forensics and release provenance.

---

## References

- `docs/architecture/RUNTIME_SPINE.md` - Detailed spine documentation
- `docs/architecture/LANGUAGE_OWNERSHIP.md` - Language ownership table
- `docs/architecture/CONTRACTS.md` - Contract definitions
- `docs/architecture/FAILURE_MODEL.md` - Failure modes and fail-soft
- `docs/architecture/FILE_REGISTRY.csv` - File inventory with semantic positions
- `docs/architecture/DEPRECATION_MAP.md` - Deprecated documents
- `docs/ai-context/` - AI development context files

---

**End of Canonical Architecture**
