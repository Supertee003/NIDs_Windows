# AI_CONTEXT.md — AEGIS NIDS Windows
## Machine-Generated Current-HEAD Context Layer

**HEAD:** `b187948bb2875c4f0d4009097313012a03ce410f`
**BRANCH:** `main`
**GENERATED:** 2026-09-09
**GENERATOR:** OpenCode MiMo 2.5 Free

---

## 1. WHAT AEGIS IS

AEGIS is a **Security Operations Machine** — a Windows-native Network Intrusion Detection System with seven-language architecture. It is NOT a single-file project. It is a runtime with capture, detection, policy, enforcement, forensics, and control planes.

## 2. ONE RUNTIME

```
zig build                                   → aegis_nids.exe       (Tier-1: runtime spine)
cargo build --release                       → aegis_pep.dll        (Tier-3: Rust PEP)
cmake -B build && cmake --build build       → 3 C DLLs             (native adapters)
cd nose && go build -o aegis-nose.exe .     → aegis-nose.exe       (Go: packet acquisition)
python brain/windows_brain.py               → (interpreted)        (Tier-2: analytics)
cd ts_policy && npm run build               → ts_policy/dist/      (policy authoring, advisory)
```

**ONE production runtime. No duplicates.**

## 3. LANGUAGE OWNERSHIP

| Language | Owns | Does NOT Own |
|---|---|---|
| Zig | Runtime fabric, event, flow, dispatcher, detection, correlation, forensics | Privileged enforcement, crypto |
| Go | Packet acquisition (Nose), collectors, I/O | Policy, enforcement |
| C++ | Windows native adapters (ETW, FIM, Registry, WFP) | Policy decision, enforcement |
| Python | Brain (Tier-2), analytics, RAG | Privileged OS calls, enforcement |
| Rust | Crypto, trust, PEP, authorization, WFP/security enforcement | Detection logic |
| TypeScript | Policy authoring, simulation, compiler | Enforcement, runtime |
| Cython | Measured Python hot loops only (after profiling) | New logic |

## 4. AUTHORITY BOUNDARIES

- **Final enforcement authority:** Rust PEP (`rust-src/lib.rs`)
- **Runtime orchestration:** Zig core (`src/main.zig`)
- **Packet acquisition:** Go Nose (`nose/`)
- **Policy authoring:** TypeScript (`ts_policy/`)
- **Brain analytics:** Python (`brain/`)
- **Native adapters:** C++ (`bridge/`, `src/windows/`)

**Never bypass Rust PEP. Never create a second runtime. Never create a second enforcement authority.**

## 5. CURRENT PHASE

**Phase 6 — Evidence & Forensics** (vertical slices completed)
- FOR-001 Forensic Record Integrity ✅
- FOR-002 Forensic Verification ✅
- FOR-003 Replay Integrity ✅

**Phase 7 — Multi-Language Integration** (patches 36-39 completed)
**Phase 8 — Testing & Verification** (patches 40-43 completed)
**Phase 9 — Release Engineering** (patches 44-46 completed)

## 6. ACTIVE BLOCKERS

None currently. Previous blockers (aegis_fim_helper.dll linker error, stub crypto) are documented in EVIDENCE_INDEX.json.

## 7. CURRENT BUILD COMMANDS

```powershell
zig build                                   # Zig core
zig build test                              # Zig tests
cargo build --release                       # Rust PEP
cmake -B build && cmake --build build       # C++ native
cd nose && go build -o aegis-nose.exe .     # Go Nose
cd ts_policy && npm run test                # TypeScript tests
```

## 8. CURRENT RUNTIME ENTRYPOINT

`src/main.zig` — `main()` function

Startup sequence:
```
main → init subsystems → start pipeline → start watchdog → start control pipe → start capture → run loop
```

## 9. WHERE MACHINE-READABLE TRUTH IS STORED

| Artifact | Path | Role |
|---|---|---|
| System map | `SYSTEM_MAP.json` | Component inventory + roles |
| Flow map | `FLOW_MAP.json` | Data/decision/enforcement flows |
| Authority map | `AUTHORITY_MAP.json` | Language ownership + security authority |
| Contract map | `CONTRACT_MAP.json` | Cross-language contracts + schemas |
| Evidence index | `EVIDENCE_INDEX.json` | All evidence artifacts |
| Build truth | `build_truth.json` | Build commands → artifacts |
| Runtime manifest | `runtime_manifest.json` | Canonical entrypoints |
| Inventory | `inventory.json` | File inventory + classifications |
| Reference map | `reference_map.json` | File → role mapping |

## 10. WHAT THE AI MUST NEVER DO

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
