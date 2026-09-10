# AGENTS.md — AEGIS NIDS Windows
## Version 2.0 — Current-HEAD Vertical Slice Workflow

**HEAD:** `97dbfef`
**Applies to:** All human + AI agents contributing to AEGIS NIDS Windows

---

## PRIME DIRECTIVE

Do not patch files in isolation.

First understand the system behavior.

The unit of reasoning is: **SYSTEM FLOW**
The unit of implementation is: **VERTICAL SLICE**
The unit of modification is: **PATCH TRANSACTION**
The unit of proof is: **EVIDENCE**

---

## CONTROL LOOP

```
CURRENT HEAD
  ↓
TRUTH SNAPSHOT
  ↓
SYSTEM MAP
  ↓
ONE FLOW CONTRACT
  ↓
ONE PATCH TRANSACTION
  ↓
REAL VERIFICATION
  ↓
EVIDENCE
  ↓
COMMIT
  ↓
REBASE SYSTEM MAP
```

After every patch, rebuild the machine maps. Never use a pre-patch architecture map as current truth.

---

## SOURCE OF TRUTH HIERARCHY

When sources disagree, use this order:

1. Actual runtime behavior
2. Current source code at current HEAD
3. Current build configuration
4. Current-head machine-readable manifests
5. AGENTS.md and ADRs
6. Current-head evidence
7. Reports tied to current HEAD
8. README
9. AI assumptions

Never treat an old report as current truth. If a report contains a different HEAD SHA, mark it HISTORICAL.

---

## MACHINE-READABLE TRUTH

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

Every machine map includes: `head_sha`, `created_at`, `generator_version`.

If a map has a different HEAD than the current source, it is STALE. Do not use it as current truth.

---

## CANONICAL RUNTIME

```
zig build                                   → aegis_nids.exe       (Tier-1: runtime spine)
cargo build --release                       → aegis_pep.dll        (Tier-3: Rust PEP)
cmake -B build && cmake --build build       → 3 C DLLs             (native adapters)
cd nose && go build -o aegis-nose.exe .     → aegis-nose.exe       (Go: packet acquisition)
python brain/windows_brain.py               → (interpreted)        (Tier-2: analytics)
cd ts_policy && npm run build               → ts_policy/dist/      (policy authoring, advisory)
```

**ONE production runtime. No duplicates.**

---

## LANGUAGE OWNERSHIP

| Language | Owns | Does NOT Own |
|---|---|---|
| Zig | Runtime fabric, event, flow, dispatcher, detection, correlation, forensics | Privileged enforcement, crypto |
| Go | Packet acquisition (Nose), collectors, I/O | Policy, enforcement |
| C++ | Windows native adapters (ETW, FIM, Registry, WFP) | Policy decision, enforcement |
| Python | Brain (Tier-2), analytics, RAG | Privileged OS calls, enforcement |
| Rust | Crypto, trust, PEP, authorization, WFP/security enforcement | Detection logic |
| TypeScript | Policy authoring, simulation, compiler | Enforcement, runtime |
| Cython | Measured Python hot loops only (after profiling) | New logic |

---

## STOP-THE-LINE TRIGGERS

Halt all coding immediately and file an issue when any of these is detected:

- ABI mismatch
- Memory corruption / use-after-free
- Race condition or deadlock
- Silent event loss
- Policy bypass
- PEP bypass
- Unauthorized enforcement
- Crypto verification bypass
- Privileged IPC exposure
- Driver contract mismatch
- Duplicate runtime
- Duplicate authority
- Forensic inconsistency
- Production mock
- Build/runtime mismatch
- Stale evidence
- Contradictory source-of-truth documents

Do not work around these silently.

---

## CURRENT HEAD SNAPSHOT

Before changing code, execute and record:

```powershell
git rev-parse HEAD
git branch --show-current
git status --short
git log -1 --oneline
git ls-files
```

Read: `AI_CONTEXT.md`, `SYSTEM_MAP.json`, `FLOW_MAP.json`, `AUTHORITY_MAP.json`, `CONTRACT_MAP.json`, `EVIDENCE_INDEX.json`

If any machine map has a different HEAD: MARK STALE. Do not use it as current truth.

---

## VERTICAL SLICE REQUIREMENT

The slice must cross all relevant layers.

Example FOR-001:
```
Event → forensic record → sequence → hash → CRC → persistence → read → verify → replay → audit → CLI → evidence
```

A vertical slice is not complete when only the storage struct changes.

---

## PATCH REQUIREMENTS

Each patch must declare:

```
PATCH-ID
FLOW-ID
TARGET HEAD
TARGET FILES
TARGET SYMBOLS
IN-SCOPE / OUT-OF-SCOPE
CONTRACT IMPACT
ABI IMPACT
AUTHORITY IMPACT
STATE IMPACT
TEST IMPACT
EVIDENCE IMPACT
```

Each patch must produce:

```
PATCH-ID
FLOW-ID
TARGET HEAD
FINAL HEAD
FILES CHANGED
OLD FLOW → NEW FLOW
INVARIANT
BUILD RESULT
TEST RESULT
WINDOWS RESULT (if applicable)
EVIDENCE LEVEL
EVIDENCE ARTIFACTS
ROLLBACK
REMAINING RISK
OPEN BLOCKERS
COMPLETION GATE
```

---

## POST-PATCH REBASELINE

After every successful patch:

1. Record final HEAD
2. Rebuild affected machine maps
3. Update evidence index
4. Update current phase status
5. Identify newly closed gaps
6. Identify remaining blockers

Do not continue using the pre-patch architecture map as if it were current.

---

## TEST MATRIX

| Level | Description |
|---|---|
| E0 | No evidence |
| E1 | Static inspection |
| E2 | Unit test proof |
| E3 | Component integration |
| E4 | System integration |
| E5 | Windows host verification |
| E6 | Production simulation |
| E7 | Release verification |

Do not claim a higher level from a lower-level test.

---

## PRE-COMMIT CHECKS

```powershell
# No build artifacts tracked
git ls-files | Select-String -Pattern '\.(exe|dll|pdb|obj|o|so|ilk|exp|lib)$'   # empty

# No cache dirs tracked
git ls-files | Select-String -Pattern '^(\.zig-cache|target|__pycache__|zig-out|shield/target|build/|dist/)/'  # empty

# No runtime state tracked
git ls-files | Select-String -Pattern '^logs/'   # empty

# No legacy root lib.rs
git ls-files lib.rs   # empty

# Required truth artifacts exist
Test-Path AI_CONTEXT.md   # True
Test-Path SYSTEM_MAP.json   # True
Test-Path FLOW_MAP.json   # True
Test-Path AUTHORITY_MAP.json   # True
Test-Path CONTRACT_MAP.json   # True
Test-Path EVIDENCE_INDEX.json   # True
```

---

## EXECUTION ORDER

```
Phase 6: Forensic Integrity          (FOR-001, FOR-002, FOR-003)
Phase 7: Multi-Language Integration  (FFI-001, FFI-002, FFI-003, FFI-004)
Phase 8: Testing & Verification      (VER-001, VER-002, VER-003, VER-004)
Phase 9: Release Engineering         (REL-001, REL-002, REL-003, REL-004)
```

No slice may begin until the previous slice's Completion Gate = PASS.
