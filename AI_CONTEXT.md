# AI_CONTEXT.md — AEGIS NIDS Windows
## Machine-Generated Current-HEAD Context Layer

**HEAD:** `48eb2a72265a15c1b780a6bfa76d4f4dae2fc7f2`
**BRANCH:** `main`
**GENERATED:** 2026-09-12T00:00:00.000000+00:00
**GENERATOR:** opencode agent (TRUTH-REBUILD current-HEAD resync)
**ARCHITECTURE:** Hub-and-Spoke with Plane Separation

> HISTORICAL NOTE: earlier revisions of this file referenced HEAD `2c7cb30…`
> (2026-09-10). Those revisions are HISTORICAL evidence only; `2c7cb30` is no
> longer current truth.

---

## 1. WHAT AEGIS IS

AEGIS is a **Security Operations Machine** — a Windows-native Network Intrusion Detection System with seven-language architecture. It is NOT a single-file project. It is a runtime with capture, detection, policy, enforcement, forensics, and control planes.

**Architecture:** Hub-and-Spoke with Plane Separation
- **Zig** = Runtime Spine (the hub)
- **Go/C++** = Acquisition (sensors, adapters)
- **Python/Cython** = Intelligence (Brain, RAG, analytics)
- **Rust** = Security (PEP, crypto, WFP enforcement)
- **TypeScript** = Control (policy authoring, CLI, UI)

**Cython is a Python-to-native performance bridge, NOT the system integration bus.**

## 2. ARCHITECTURE (Plane Separation)

```
                         ┌───────────────┐
                         │ CLI / TUI /   │
                         │ WEB / TS      │
                         └───────┬───────┘
                                 │
                           Control Protocol
                                 │
                                 ▼
                     ┌────────────────────┐
                     │       ZIG          │
                     │   RUNTIME SPINE    │
                     │                    │
                     │ Canonical Event    │
                     │ Event Fabric       │
                     │ Flow               │
                     │ Detection          │
                     │ Correlation        │
                     │ Runtime State      │
                     └──────┬──────┬──────┘
                            │      │
               ┌────────────┘      └────────────┐
               │                                │
               ▼                                ▼
          GO / C / C++                       PYTHON
          Sensors                            Brain/RAG
               │                                │
               └───────────┐      ┌────────────┘
                           ▼      ▼
                           CYTHON
                              │
                              ▼
                        Native Compute

                              │
                              ▼
                           POLICY
                              │
                              ▼
                         RUST PEP
                              │
                      Authorization
                              │
                              ▼
                    Windows Enforcement
                              │
                             WFP
                              │
                              ▼
                     Audit / Forensics
                              │
                              ▼
                       Observability
```

## 3. PLANES

| Plane | Language | Role | Boundary |
|---|---|---|---|
| A: Acquisition | Go, C/C++ | Sensors, Windows adapters | C ABI → Zig |
| B: Runtime | Zig | Spine, Event Fabric, Flow, Detection, Correlation | Hub |
| C: Intelligence | Python, Cython | Brain, RAG, Analytics | Analytics Contract → Zig |
| D: Security | Rust | PEP, Crypto, WFP enforcement | PEP ABI → Zig |
| E: Control | TypeScript | Policy authoring, CLI, UI | Control Protocol → Zig |

## 4. ONE RUNTIME

```
zig build                                   → aegis_nids.exe       (Tier-1: runtime spine)
cargo build --release                       → aegis_pep.dll        (Tier-3: Rust PEP)
cmake -B build && cmake --build build       → 3 C DLLs             (native adapters)
cd nose && go build -o aegis-nose.exe .     → aegis-nose.exe       (Go: packet acquisition)
python brain/windows_brain.py               → (interpreted)        (Tier-2: analytics)
cd ts_policy && npm run typecheck && npm run test:all   → (advisory only, no output)   (policy authoring, advisory)
```

**ONE production runtime. No duplicates.**

## 5. CONTRACTS (5 Core Contracts)

| Contract | ID | Description | Boundary |
|---|---|---|---|
| CONTRACT-01 | CANONICAL_EVENT | 109-byte event schema | All sensors → Zig |
| CONTRACT-02 | PEP_ABI | PEP request/response (64/16 bytes) | Zig ↔ Rust |
| CONTRACT-03 | RUNTIME_ABI | Module lifecycle + worker stages | Zig ↔ all |
| CONTRACT-04 | CONTROL_PROTOCOL | JSON over named pipe | TS/CLI → Zig |
| CONTRACT-05 | POLICY_IR | Policy AST (Action, Condition, Policy) | TS → Rust PEP |

## 6. LANGUAGE OWNERSHIP

| Language | Owns | Does NOT Own |
|---|---|---|
| Zig | Runtime fabric, event, flow, dispatcher, detection, correlation, forensics | Privileged enforcement, crypto |
| Go | Packet acquisition (Nose), collectors, I/O | Policy, enforcement |
| C++ | Windows native adapters (ETW, FIM, Registry, WFP) | Policy decision, enforcement |
| Python | Brain (Tier-2), analytics, RAG | Privileged OS calls, enforcement |
| Rust | Crypto, trust, PEP, authorization, WFP/security enforcement | Detection logic |
| TypeScript | Policy authoring, simulation, compiler | Enforcement, runtime |
| Cython | Python-to-native performance bridge | New logic, system integration |

## 7. AUTHORITY BOUNDARIES

- **Final enforcement authority:** Rust PEP (`rust-src/lib.rs`)
- **Runtime orchestration:** Zig core (`src/main.zig`)
- **Packet acquisition:** Go Nose (`nose/`)
- **Policy authoring:** TypeScript (`ts_policy/`)
- **Brain analytics:** Python (`brain/`)
- **Native adapters:** C++ (`bridge/`, `src/windows/`)

**Never bypass Rust PEP. Never create a second runtime. Never create a second enforcement authority.**

## 8. LANGUAGE INTEGRATION (Correct Paths)

| Path | Boundary | Status |
|---|---|---|
| Go → C ABI → Zig | Acquisition | ✅ Correct |
| C++ → C ABI → Zig | Native adapters | ✅ Correct |
| Python ↔ Cython ↔ C/C++ | Performance bridge | ✅ Correct |
| Zig ↔ Rust FFI | PEP enforcement | ✅ Correct |
| TypeScript → Control Protocol → Zig | Policy/UI | ✅ Correct |

## 9. LANGUAGE INTEGRATION (Wrong Paths - NEVER DO)

| Path | Why Wrong |
|---|---|
| Go → Rust PEP | Wrong authority boundary |
| Python → WFP | Wrong security boundary |
| TypeScript → native WFP | Wrong security boundary |
| C++ → Rust → Zig → C++ | Cyclic architecture |
| All languages → all languages | Architectural mesh |

## 10. CURRENT PHASE

**ARCHITECTURE STABILIZATION** (Hub-and-Spoke + Plane Separation)

Previous phases:
- Phase 6 (Forensics): IMPLEMENTED, verification E2
- Phase 7 (FFI): IMPLEMENTED, verification E2
- Phase 8 (Testing): IMPLEMENTED, verification E2
- Phase 9 (Release): IMPLEMENTED, verification E2
- Truth Stabilization: COMPLETED

## 11. ACTIVE BLOCKERS

P0 risks as of HEAD `48eb2a72` (2026-09-12):

- P0-1: Zig bypasses the Rust PEP for WFP enforcement
  (`src/core/rust_pep.zig` / `src/policy/wfp_production.zig` reach the WFP
  IOCTL directly). `rust-src/lib.rs` is declared the ONLY final enforcement
  authority. OPEN.
- P0-2: Tier-3 fail-closed state is not surfaced truthfully. When
  `sec_monitor.dll` is absent the runtime logs "fail-closed" yet continues;
  `health.check` never reports the Tier-3 state. OPEN.
- P0-3: CI is red by construction. `python-tests` runs the full pytest suite
  (currently 3 failures) and `go-build-test` mixes the canonical Go sensor
  with the optional aggregator sidecar. OPEN (see CI-001..CI-004).
- P0-4: Machine maps stale (HEAD mismatch) — **FIXED** (all maps and
  `AGENTS.md` now carry `48eb2a72`).
- P0-5: CLI canonical path conflict (`scripts/aegisctl.py` vs
  `tools/aegisctl.py`) — **FIXED**: `scripts/aegisctl.py` does not exist;
  `tools/aegisctl.py` is the single canonical client.
- P0-6: `go/aggregator/` ownership — **RESOLVED**: classified SUPPORT
  (optional operator sidecar, REST :9200). It is NOT part of the acquisition
  authority and NOT part of the runtime path.
- P0-7: `shield/` ownership — **CLASSIFIED + QUARANTINED, REMOVAL OPEN**: the
  crate is SUPPORT (Tier-3 payload screening DLL loaded in-process by
  `src/core/bridge_init.zig`). `shield/src/pep.rs`,
  `shield/src/windows_enforce.rs` and the `aegis_pep_evaluate` /
  `aegis_pep_status_count` / `aegis_pep_version` exports in `shield/src/lib.rs`
  are a duplicate PEP + WFP enforcement surface and are now marked QUARANTINED
  in code and in `AUTHORITY_MAP.json` (`quarantined_duplicates[SHIELD_PEP]`).
  They cannot be deleted in isolation because three things still bind to them:
  the dormant `extern "sec_monitor" fn aegis_pep_evaluate` in
  `src/forensic/policy_contract.zig` (declared, never called), the
  `tests/pep/test_t8_rust_pep.py` expectations, and the shield C-ABI shim.
  Removal is slice **PEP-001** (tracked as GAP-007).
- P0-8: `health.check` payload does not conform to `RUNTIME_CONTRACT.md` §4.1
  (missing `pid`, `last_event_ms`, `counters`) and reports capability flags
  (`etw`/`fim`/`wfp` = "available") instead of live subsystem state. OPEN.
- P0-9: Stale pytest dumps (`test_failures_full.txt`, `test_failed_lines.txt`,
  `test_failures_output.txt`) were tracked at repo root and described failures
  that no longer exist. **FIXED** (removed; test state is now reported by CI).

## 12. CURRENT BUILD COMMANDS

```powershell
zig build                                   # Zig core (aegis_nids.exe)
zig build test                              # Zig tests
cargo build --release                       # Rust PEP (aegis_pep.dll)
cd shield && cargo build --release          # Rust Shield (sec_monitor.dll)
cmake -B build && cmake --build build       # C++ native helpers
cd bridge && cmake -B build && cmake --build build  # C++ bridge
cd nose && go build -o aegis-nose.exe .     # Go Nose (packet acquisition)
cd go/aggregator && go build -o aegis-aggregator.exe .  # Go Aggregator (REST API sidecar)
cd ts_policy && npm run typecheck && npm run test:all   # TypeScript policy compiler
```

## 12b. COMPONENT CLASSIFICATION (TRUTH-002)

| Path | Class | Owner of | Not an owner of |
|---|---|---|---|
| `src/main.zig` | CANONICAL | Runtime spine (event fabric, flow, detection, correlation, dispatch, forensics, control pipe) | privileged enforcement, crypto |
| `rust-src/lib.rs` | CANONICAL | Final enforcement authority: PEP, Ed25519, TLS, authorization | detection logic |
| `nose/main.go` | CANONICAL | Packet acquisition, flow collection, IPC reader, canonical event production | policy, enforcement |
| `src/windows/*.c`, `bridge/` | CANONICAL | Windows native adapters (ETW, FIM, Registry, WFP user-mode) | policy decision, enforcement |
| `brain/` | CANONICAL | Tier-2 analytics, RAG, rules scanning | privileged OS calls, enforcement |
| `ts_policy/` | CANONICAL | Policy authoring + compilation to Policy IR (advisory, no artifact) | enforcement, runtime |
| `shield/` | SUPPORT | Tier-3 payload screening symbol (`validate_payload_safety`) exported to Zig | **any enforcement decision or WFP action** |
| `go/aggregator/` | SUPPORT | Optional operator alert sidecar (NDJSON → REST :9200) | acquisition, policy, enforcement |
| `mouth/` | OPTIONAL | Standalone DEFCON monitor GUI | runtime, enforcement |
| `aegis_dashboard/` | OPTIONAL | Operator web UI backend | runtime, enforcement |
| `core/` (directory) | DOES NOT EXIST | — | — |
| `core/*.zig` (manifest keys) | ALIAS | Manifest module IDs that resolve through `real_path` to `src/**` | — |
| `core/nids_main.zig` | LEGACY | Superseded by `src/main.zig` + `src/daemon.zig` | — |

Rule: a component is **CANONICAL** only if it is built by the CI matrix AND
executed by the production runtime. SUPPORT builds in CI but is not on the
golden path. OPTIONAL is operator-only.

## 13. CURRENT RUNTIME ENTRYPOINTS

**Multi-process architecture:**

1. **Zig Core** (`src/main.zig` → `aegis_nids.exe`) — Runtime spine
   - Startup: main → init subsystems → start pipeline → start watchdog → start control pipe → start capture → run loop

2. **Go Nose** (`nose/main.go` → `aegis-nose.exe`) — Packet acquisition
   - Launches as separate process, connects to Zig via named pipe

3. **Go Aggregator** (`go/aggregator/main.go` → `aegis-aggregator.exe`) — SUPPORT: alert sidecar (optional)
   - REST API on port 9200, watches NDJSON logs via fsnotify. NOT on the golden path.

4. **Rust Shield** (`shield/src/lib.rs` → `sec_monitor.dll`) — SUPPORT: loaded in-process by Zig core
   - Tier-3 payload safety validation (`validate_payload_safety`).
   - NOT an enforcement authority. `shield/src/pep.rs` and
     `shield/src/windows_enforce.rs` are a duplicate PEP/WFP implementation and
     are tracked as OPEN STOP-THE-LINE (P0-7).

5. **Rust PEP** (`rust-src/lib.rs` → `aegis_pep.dll`) — Loaded in-process by Zig core
   - Privileged action authorization

6. **C++ Bridge** (`bridge/aegis_ipc.cpp` → `aegis_ipc.dll`) — Loaded in-process by Zig core
   - Windows native adapters (ETW, FIM, WFP)

## 14. WHERE MACHINE-READABLE TRUTH IS STORED

| Artifact | Path | Role |
|---|---|---|
| AI Context | `AI_CONTEXT.md` | First document an agent reads |
| System map | `SYSTEM_MAP.json` | Component inventory + roles |
| Flow map | `FLOW_MAP.json` | Data/decision/enforcement flows |
| Authority map | `AUTHORITY_MAP.json` | Language ownership + security authority |
| Contract map | `CONTRACT_MAP.json` | Cross-language contracts + schemas |
| Evidence index | `EVIDENCE_INDEX.json` | All evidence artifacts |
| Build truth | `build_truth.json` | Build commands → artifacts |
| Runtime manifest | `runtime_manifest.json` | Canonical entrypoints |
| Inventory | `inventory.json` | File inventory + classifications |
| Reference map | `reference_map.json` | File → role mapping |

## 15. WHAT THE AI MUST NEVER DO

1. Do not patch files in isolation — identify the system flow first
2. Do not create a second runtime
3. Do not create a second Canonical Event
4. Do not create a second Policy Authority
5. Do not create a second Enforcement Authority
6. Do not bypass Rust PEP
7. Do not promote mocks/stubs/scaffolds to production
8. Do not use old reports as current truth (check HEAD SHA)
9. Do not trust README claims as implementation proof
10. Do not work around STOP-THE-LINE conditions silently
11. Do not change unrelated files
12. Do not use compilation as runtime proof
13. Do not use unit tests as Windows-host proof
14. Do not use Cython as the system integration bus
15. Do not create language-to-language mesh (use hub-and-spoke)
