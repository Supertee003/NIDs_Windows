# Language Ownership

**Status**: AUTHORITATIVE
**Source**: `docs/architecture/ARCHITECTURE_CANONICAL.md` Section 3

---

## Zig - System Core

**Owns**:
- Runtime orchestration (dispatcher, lifecycle)
- Event fabric (priority queue, backpressure)
- Flow state (atomic upsert, eviction)
- Detection orchestration (evidence producer)
- Correlation orchestration (entity graph)
- Windows-native coordination
- Forensics (immutable log, audit trail)
- Telemetry export (OTLP, Prometheus, CEF)

**Forbidden**:
- Independent policy authority
- Direct enforcement (must go through Rust PEP)
- Brain/RAG logic (Python owns this)

**Authority files**: `core/dispatcher.zig`, `core/lifecycle.zig`, `core/canonical_event.zig`

---

## C - Stable ABI

**Owns**:
- Stable ABI definitions
- Wire types (fixed-width, explicit endian)
- Native headers
- Kernel driver scaffolding

**Forbidden**:
- Business logic
- Runtime orchestration

**Authority files**: `drivers/`, `shared/protocol/`

---

## C++ - Native Adapters

**Owns**:
- Native adapters (Windows interop)
- Legacy bridge compatibility
- Transport adapter (IPC)
- Windows API wrappers

**Forbidden**:
- Becoming thicker over time (should thin out)
- Policy decisions
- Enforcement

**Authority files**: `bridge/`

**Direction**: C++ should become thinner over time as Zig absorbs more Windows coordination.

---

## Go - Nose / Collectors

**Owns**:
- Nose (sensor ingestion)
- Collectors (event sources)
- Event ingestion (I/O-heavy)
- External aggregation
- High-concurrency I/O

**Forbidden**:
- Independent policy authority
- Enforcement decisions
- Brain/RAG logic

**Authority files**: `nose/`, `go/aggregator/`

**Rule**: Go must not be an independent policy authority.

---

## Rust - Security Boundary (PEP)

**Owns**:
- Security boundary (policy verification)
- PEP (Policy Enforcement Point)
- Enforcement execution
- Privileged state management
- Rollback (deferred queue, retry)

**Forbidden**:
- Policy decisions (Zig decides, Rust executes)
- Detection logic
- Brain/RAG logic

**Authority files**: `shield/`, `mouth/`

**Rule**: Rust is the **final enforcement authority**. No bypass allowed.

**PEP validation** (before execution):
- policy
- version
- signature
- target
- action
- authorization
- expiry

**PEP results** (7 statuses, never single success flag):
- EXECUTED
- FAILED
- DENIED
- DEFERRED
- NOT_APPLICABLE
- UNSUPPORTED
- TIMEOUT

---

## Python - Brain / RAG

**Owns**:
- Brain orchestration (advisory layer)
- RAG (Retrieval Augmented Generation)
- Analytics
- Experiments
- Model lifecycle

**Forbidden**:
- Direct enforcement (block, quarantine, kill-process)
- Policy decisions
- Runtime orchestration

**Authority files**: `brain/`

**Brain output** (advisory only):
- score
- confidence
- features
- context
- recommendation

**Brain must NOT execute**:
- block
- quarantine
- kill-process

**Rule**: Python remains the orchestration layer. Brain is advisory + fail-soft.

---

## Cython - Brain Accelerator

**Owns**:
- Feature extraction
- Hot loops
- Numeric preprocessing
- Performance-sensitive Brain operations

**Forbidden**:
- Policy decisions
- Enforcement
- Runtime orchestration

**Authority files**: `brain/` (Cython modules)

**Rule**: Cython remains the accelerator for Python Brain, not an independent authority.

---

## Cross-Language Rules

1. **Wire/ABI**: Must remain explicit (fixed width, explicit endian, bounded length, version, checksum, no pointers, no raw memory dump)

2. **Cross-language vectors**: Treated as contract tests (validated in CI)

3. **No language can bypass Rust PEP** for enforcement

4. **No language can modify CanonicalEvent** after observation

5. **Each language has exactly one authority domain** (see table above)

---

## Build System Ownership

| Build System | Owns | Coordinates |
|--------------|------|-------------|
| CMake | C/C++ native components | `CMakeLists.txt` |
| Zig build | Core runtime | `build.zig` |
| Cargo | Rust components (shield, mouth) | `shield/Cargo.toml`, `mouth/Cargo.toml` |
| Go | Nose/Aggregator | `nose/go.mod`, `go/aggregator/go.mod` |
| Python/Cython | Brain | `brain/requirements.txt`, `brain/setup.py` |

**Top-level orchestration**: A Windows script coordinates these build systems. Avoid having several build systems independently decide what the product contains.
