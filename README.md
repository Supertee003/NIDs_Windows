# AEGIS NIDS Windows

> **AI DEVELOPMENT NOTE**
> This repository is a security operations machine.
> Do not patch files in isolation.
> Identify the system flow, dependency closure, authority, contract, state transition, and evidence
> before changing code.
> See `AGENTS.md` and `AI_CONTEXT.md`.

---

## 1. AEGIS Mission

AEGIS is a Windows-native Network Intrusion Detection System built as a **seven-language security operations machine**. It captures network traffic, detects threats, enforces policy, records forensic evidence, and provides operator control through a unified pipeline.

## 2. System Overview

AEGIS operates across five planes:

| Plane | Role |
|---|---|
| **Data Plane** | Capture → Canonical Event → Event Fabric → Flow |
| **Decision Plane** | Detection → Correlation → Threat → Intelligence → Policy |
| **Enforcement Plane** | Policy → Rust PEP → Authorization → Windows Enforcement |
| **Control Plane** | CLI/TUI/Web → Control API → Authorization → Runtime Mutation |
| **Evidence Plane** | Event → Decision → Action → Audit → Forensics → Replay → Observability |

## 3. Architecture

> **Maturity vocabulary.** A component matures through distinct, non-interchangeable
> stages: `DESIGNED` → `IMPLEMENTED` → `INTEGRATED` → `UNIT VERIFIED` →
> `SYSTEM VERIFIED` → `WINDOWS VERIFIED` → `PRODUCTION VERIFIED` → `RELEASE VERIFIED`.
> "IMPLEMENTED" below means *code exists and is wired*, **not** production-proven.
> Actual per-component proof lives in §13 (`Verification Status`) and
> `EVIDENCE_INDEX.json`.

| Layer | Components | Implementation | Evidence |
|---|---|---|---|
| Capture | Npcap adapter, packet decoder, flow table, L7 parsers, stream reassembly | IMPLEMENTED | E2 |
| Detection | Aho-Corasick signatures, EWMA anomaly, protocol anomaly, multi-event correlation, atomic threat tracker | IMPLEMENTED | E2 |
| Policy | Policy IR (DSL compiler), Trust Store + Key Lifecycle, Rust PEP, action dispatcher | IMPLEMENTED | E2 |
| Forensic | 64 MiB ring buffer with embedded hash chain, decision trace, evidence records, replay engine, replay verifier | IMPLEMENTED | E2 |
| Host (Win) | ETW real-time, FIM, registry monitor, injection detector (T1055), WFP, host telemetry | IMPLEMENTED | E1-E2 (not Windows-verified) |
| Reliability | Watchdog, security self-hardening, latency histogram, fault injection | IMPLEMENTED | E2 |
| Federation | Cluster coordinator, node registry, aggregator | IMPLEMENTED | E2 (single-node; mTLS not host-verified) |
| XDR | Cross-layer correlation engine | IMPLEMENTED | E2 |
| Operations | aegisctl CLI, NSIS installer, backup/recovery, CI/CD, release engineering | PARTIAL — command set exists, several commands still report without proving a state transition | E1-E2 |

## 4. Data Plane

```
Raw Packets (Npcap)
  → Go Nose (packet capture + canonical event production)
  → IPC (named pipe)
  → Zig Flow Table (bidirectional 5-tuple)
  → Zig Packet Decoder (Ethernet/IPv4/IPv6/TCP/UDP)
  → Zig L7 Parsers (DNS, HTTP, TLS, SMB, RDP, Kerberos)
  → Zig Stream Reassembly (TCP)
```

## 5. Decision Plane

```
Canonical Event
  → Signature Engine (Aho-Corasick, up to 100K patterns)
  → Anomaly Detector (EWMA + z-score)
  → Protocol Anomaly Detector
  → Correlator (multi-event temporal + spatial)
  → Threat Tracker (atomic scoring, incident escalation)
```

## 6. Enforcement Plane

```
Incident
  → Policy IR (DSL → AST)
  → Rust PEP (Ed25519 signature verification + authorization)
  → Action Dispatcher (block, quarantine, rate-limit, alert)
  → Windows Enforcement (WFP filtering, process control)
```

**Final enforcement authority: Rust PEP.** No other component may claim enforcement.

## 7. Control Plane

```
Operator
  → aegisctl.py (CLI)
  → Named Pipe IPC
  → Zig Control Server
  → Authorization
  → State Mutation
  → Postcondition Verification
  → Audit
  → Result
```

## 8. Evidence Plane

```
Pipeline Event
  → Security Decision Trace (128-byte struct)
  → Forensic Record (4KB slot with embedded hash chain)
  → Forensic Ring Buffer (64 MiB circular)
  → Replay Engine (PCAP replay with deterministic timing)
  → Replay Verifier (export → verify → replay → compare)
  → Evidence Record (hash chain + tamper detection)
  → Provenance (build chain + release chain)
```

## 9. Seven-Language Ownership

| Language | Owns |
|---|---|
| **Zig** | Runtime fabric, event, flow, dispatcher, detection, correlation, forensics |
| **Go** | Packet acquisition (Nose), collectors, I/O-heavy ingestion |
| **C++** | Windows native adapters (ETW, FIM, Registry, WFP) |
| **Python** | Brain (Tier-2), analytics, RAG |
| **Rust** | Crypto, trust, PEP, authorization, WFP/security enforcement |
| **TypeScript** | Policy authoring, simulation, compiler |
| **Cython** | Measured Python hot loops only (after profiling) |

## 10. Operator Interfaces

| Interface | Status |
|---|---|
| CLI (`tools/aegisctl.py`) — the single canonical client | IMPLEMENTED (E2) |
| Named Pipe Control (`\\.\pipe\aegis_control`) | IMPLEMENTED (E2) |
| DEFCON monitor (`mouth/`, optional) | IMPLEMENTED (E1) |
| Web Dashboard (`aegis_dashboard/`, optional) | DESIGNED / OPTIONAL — not on the release path |
| NSIS Installer | IMPLEMENTED (E1) |

## 11. Runtime Lifecycle

```
main()
  → init subsystems
  → start pipeline
  → start watchdog
  → start control pipe (named pipe server)
  → start capture (Npcap / Go Nose)
  → run loop (event processing + detection + policy + enforcement + forensics)
  → shutdown (graceful cleanup)
```

## 12. Security Boundaries

| Boundary | Owner | Verification |
|---|---|---|
| Policy signature verification | Rust PEP (Ed25519) | P0: must be real crypto |
| PEP authorization | Rust PEP | Every privileged action passes PEP |
| WFP enforcement | C++ / Windows kernel | P1: requires Windows host test |
| Forensic integrity | Zig (hash chain + CRC) | E2: unit tests pass |
| Replay safety | Zig (observe-only default) | E2: unit tests pass |

## 13. Current Status

**HEAD:** `48eb2a72265a15c1b780a6bfa76d4f4dae2fc7f2`
**Branch:** `main`
**Phase:** Modular aegisctl rewrite + truth rebuild

> Earlier revisions of this README pinned HEAD `97dbfef`. That is HISTORICAL.
> Any document whose HEAD differs from `git rev-parse HEAD` is stale per `AGENTS.md`.

| Component | Implementation Status | Verification Status | Host Status |
|---|---|---|---|
| Zig Core | IMPLEMENTED | E2 (unit tests) | NOT_VERIFIED |
| Rust PEP | IMPLEMENTED | E2 (Ed25519 + SHA-256 verified) | NOT_VERIFIED |
| Go Nose | IMPLEMENTED | E1 (AST) | NOT_VERIFIED |
| C++ Native | IMPLEMENTED | E1 (selftest passes) | NOT_VERIFIED |
| C++ Bridge | IMPLEMENTED | E1 (selftest passes) | NOT_VERIFIED |
| Python Brain | IMPLEMENTED | E0 | NOT_VERIFIED |
| TypeScript Policy | IMPLEMENTED | E1 (typecheck) | NOT_VERIFIED |
| Forensic Pipeline | IMPLEMENTED | E2 (unit tests) | NOT_VERIFIED |
| Replay Verifier | IMPLEMENTED | E2 (unit tests) | NOT_VERIFIED |
| Decision Trace | IMPLEMENTED | E2 (unit tests) | NOT_VERIFIED |
| WFP Enforcement | INTEGRATED | E2 (API test) | NOT_VERIFIED |

## 14. Verification Levels

| Level | Description |
|---|---|
| E0 | No evidence |
| E1 | Static inspection / AST analysis |
| E2 | Unit test proof |
| E3 | Component integration test |
| E4 | System integration test |
| E5 | Windows host verification |
| E6 | Production simulation |
| E7 | Release verification |

## 15. Build

### Prerequisites

- Zig 0.13.0+
- Rust 1.78+ (cargo)
- CMake 3.20+ and Visual Studio 2022 (MSVC)
- Npcap SDK (`NPCAP_DIR` env var or `C:\Npcap`)
- Go 1.22+
- Node.js 18+ (for TypeScript policy)

### Build Commands

```powershell
# Zig core
zig build

# Rust PEP
cargo build --release

# C++ native adapters
cmake -B build -S .
cmake --build build --config Release

# Go Nose
cd nose && go build -o aegis-nose.exe .

# TypeScript policy (advisory only - no build output)
cd ts_policy && npm run typecheck && npm run test:all
```

## 16. Test

```powershell
# Zig tests (50+ modules)
zig build test

# Rust tests
cargo test --release

# TypeScript tests
cd ts_policy && npm run test

# Python tests (control-plane + contract tests)
python -m pytest tests/ -v --ignore=tests/test_e2e.py
```

## 17. Run

```powershell
# Run directly
.\zig-out\bin\aegis_nids.exe

# Install as Windows service
.\aegis_setup.exe

# Control plane
python tools\aegisctl.py status
python tools\aegisctl.py rules list
python tools\aegisctl.py incidents list --severity alert
```

## 18. Repository Map

```
D:\NIDs_Windows/
├── src/                    # Canonical Zig source (Tier-1)
│   ├── main.zig           # Runtime spine
│   ├── contract/          # Canonical event schema
│   ├── core/              # Diagnostics, memory pool
│   ├── capture/           # Packet capture subsystem
│   ├── detection/         # Detection engines
│   ├── policy/            # Policy IR, trust store, PEP bindings
│   ├── forensic/          # Forensic pipeline, replay, provenance
│   ├── reliability/       # Watchdog, security checks, perf
│   ├── federation/        # Cluster federation
│   ├── windows/           # Windows adapters (Zig + C native)
│   ├── xdr/               # Cross-layer detection
│   └── tests/             # Unit tests (50+ modules)
├── rust-src/               # Rust PEP (Tier-3) — the ONLY enforcement authority
├── nose/                   # Go packet acquisition (CANONICAL)
├── bridge/                 # C++ IPC bridge
├── src/windows/            # C native adapters (ETW, FIM, WFP)
├── brain/                  # Python brain (Tier-2)
├── ts_policy/              # TypeScript policy compiler
├── go/aggregator/          # Go alert sidecar (SUPPORT, optional, REST :9200)
├── shield/                 # Rust payload-screening DLL (SUPPORT — NOT an enforcement authority)
├── mouth/                  # Rust DEFCON monitor GUI (OPTIONAL)
├── aegis_dashboard/        # Rust dashboard (OPTIONAL)
├── drivers/                # Windows kernel drivers
├── tools/                  # Canonical operator tooling (aegisctl.py, release engineering)
├── scripts/                # Operational helper scripts (NOT the CLI)├── configs/                # Runtime configuration
├── docs/                   # Architecture, ADRs, runbooks
├── AI_CONTEXT.md           # Machine-readable AI context
├── SYSTEM_MAP.json         # Component inventory
├── FLOW_MAP.json           # Data/decision flows
├── AUTHORITY_MAP.json      # Language ownership
├── CONTRACT_MAP.json       # Cross-language contracts
├── EVIDENCE_INDEX.json     # Evidence artifacts
├── build_truth.json        # Build commands → artifacts
├── runtime_manifest.json   # Canonical entrypoints
├── inventory.json          # File inventory (620 files, 0 unclassified)
└── reference_map.json      # File → role mapping
```

## 19. Development Workflow

See `AGENTS.md` for the full workflow rules.

**Control Loop:**
```
CURRENT HEAD → TRUTH SNAPSHOT → SYSTEM MAP → ONE FLOW CONTRACT
→ ONE PATCH TRANSACTION → REAL VERIFICATION → EVIDENCE
→ COMMIT → REBASE SYSTEM MAP
```

**Vertical Slices:**
- Phase 6: FOR-001, FOR-002, FOR-003
- Phase 7: FFI-001, FFI-002, FFI-003, FFI-004
- Phase 8: VER-001, VER-002, VER-003, VER-004
- Phase 9: REL-001, REL-002, REL-003, REL-004

## 20. Release Criteria

- [ ] All P0 security gaps closed
- [ ] Rust PEP crypto verified with real Ed25519
- [ ] WFP enforcement proven on Windows host
- [ ] Forensic integrity verified under concurrency
- [ ] All unit tests pass (E2)
- [ ] Component integration tests pass (E3)
- [ ] Release manifest generated
- [ ] Installer validated
- [ ] No stale evidence artifacts
