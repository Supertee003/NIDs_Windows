# AGENTS.md â€” AEGIS NIDS Windows

**Status:** STEP 01 â€” Repository + Runtime Truth
**Applies to:** All human + AI agents contributing to AEGIS NIDS Windows

---

## AI Command (Recite Before Any Code Change)

```
Use the existing AEGIS repository as the source of truth.

Do not invent a new architecture.

Implement only the assigned step.

Do not create a second runtime.

Do not create a second Canonical Event.

Do not create a second Policy Authority.

Do not create a second Enforcement Authority.

Do not bypass the Rust PEP.

Do not promote mock, stub, scaffold, or placeholder code to production.

Do not change unrelated files.

Run the existing implementation before rewriting.

Add tests and evidence for the change.

If the requested change requires modifying an architecture boundary,
contract, runtime order, authority, or language ownership,
STOP and report the conflict before coding.
```

---

## Source of Truth

| Artifact | Path | Role |
|---|---|---|
| Architecture decisions | `docs/adr/` | Formal ADRs |
| File inventory | `inventory.json` | Tracked files + classifications |
| Runtime declaration | `runtime_manifest.json` | Canonical entrypoints + artifacts |
| Build truth | `build_truth.json` | Build commands â†’ artifact paths |
| Reference map | `reference_map.json` | File â†’ role mapping |
| This file | `AGENTS.md` | Workflow rules |

---

## Canonical Runtime (per ADR-RUNTIME-CONVERGENCE)

Build order (build each component separately):

```
zig build                                   (Zig Tier-1: aegis_nids.exe)
cargo build --release                       (Rust Tier-3: aegis_pep.dll)
cmake -B build && cmake --build build       (C++: native helpers)
cd nose && go build -o aegis-nose.exe .     (Go Nose: packet acquisition)
python brain/windows_brain.py               (Python Tier-2: brain/analytics)
```

**ONE production runtime.**

---

## Language Ownership

| Language | Owns | Does NOT own |
|---|---|---|
| Zig | runtime fabric, event, flow, dispatcher, detection orchestration, correlation, forensics | privileged enforcement, crypto |
| Go | packet acquisition (Nose), collectors, I/O, external feeds | policy, enforcement |
| C++ | Windows native (ETW, FIM, Registry, process adapters) | policy decision, enforcement |
| Python | Brain (Tier-2), analytics, RAG | privileged OS calls, enforcement |
| Rust | crypto, trust, PEP, authorization, WFP, rollback security | detection logic |
| TypeScript | policy authoring, simulation, dashboard | enforcement, runtime |
| Cython | measured hot loops only (after profiling) | new logic |

---

## STOP-THE-LINE Triggers

Halt all coding immediately and file an issue when any of these is detected:

- ABI mismatch
- Memory corruption / use-after-free
- Race condition or deadlock
- Event loss (silent)
- Policy bypass
- PEP bypass
- Unauthorized enforcement
- Crypto verification bypass
- Privileged IPC exposure
- Driver contract mismatch
- Duplicate runtime
- Duplicate policy authority
- Duplicate enforcement authority
- Forensic inconsistency
- Production mock
- Build/runtime mismatch
- Stale evidence

---

## Pre-Commit Checks

```powershell
git ls-files | Select-String -Pattern '\.(exe|dll|pdb|obj|o|so|ilk|exp|lib)$'   # empty
git ls-files | Select-String -Pattern '^(\.zig-cache|target|__pycache__|zig-out|shield/target|build/|dist/)/'  # empty
git ls-files | Select-String -Pattern '^logs/'   # empty
git ls-files lib.rs   # empty
Test-Path docs/adr/ADR-RUNTIME-CONVERGENCE.md   # True
Test-Path inventory.json   # True
Test-Path runtime_manifest.json   # True
Test-Path build_truth.json   # True
```

---

## STEP Completion Report Template

```
STEP:        NN
TASK:        <one-line summary>
LANGUAGE:    <primary language(s)>
CURRENT COMMIT: <SHA>

FILES CHANGED:        <list>
FILES NOT CHANGED:    <list>

CURRENT STATE:        <before>
TARGET STATE:         <after>

IMPLEMENTATION:       <what was done>
INTEGRATION:          <how it connects>

AUTHORITY:            <runtime | policy | pep | forensic | federation | xdr>

REAL / MOCK / STUB:   <which parts are real>

TESTS:                <what tests pass>
FAILURE TESTS:        <negative/fault tests>

WINDOWS STATUS:       <builds? runs?>

SECURITY IMPACT:      <changed security-wise>
PERFORMANCE IMPACT:   <changed perf-wise>
REGRESSION:           <any broken test>

REMAINING GAPS:        <what this step did NOT solve>
EXIT GATE:             <PASS / FAIL>
NEXT STEP:             <NN+1>
```

---

## Execution Order

```
01 Repository inventory + runtime truth      â† CURRENT
02 Repository cleanup
03 Runtime convergence
04 Build truth
...
60 Final 100%
```

**No step may begin until the previous step's Exit Gate = PASS.**