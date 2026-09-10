# AI_CONTEXT.md — AEGIS NIDS Windows
## Machine-Generated Current-HEAD Context Layer

**HEAD:** `61c80ca3fa68bf4d1c589e953428c453d90774cf`
**BRANCH:** `main`
**GENERATED:** 2026-09-10
**GENERATOR:** OpenCode MiMo 2.5 Free
**ARCHITECTURE:** Hub-and-Spoke with Plane Separation

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

None. All gaps closed. Exit Gate 13/13 PASS.

## 12. CURRENT BUILD COMMANDS

```powershell
zig build                                   # Zig core
zig build test                              # Zig tests
cargo build --release                       # Rust PEP
cmake -B build && cmake --build build       # C++ native
cd nose && go build -o aegis-nose.exe .     # Go Nose
cd ts_policy && npm run test                # TypeScript tests
```

## 13. CURRENT RUNTIME ENTRYPOINT

`src/main.zig` — `main()` function

Startup sequence:
```
main → init subsystems → start pipeline → start watchdog → start control pipe → start capture → run loop
```

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
