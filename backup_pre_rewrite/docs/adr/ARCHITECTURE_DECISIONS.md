# AEGIS NIDS — Architecture Decision Records (v3.0)

## Table of Contents

| ADR | Title | Status |
|-----|-------|--------|
| [ADR-001](#adr-001-zig-013-as-core-language) | Zig 0.13 as Core Language | Accepted |
| [ADR-002](#adr-002-explicit-wire-encoding-no-memcpy) | Explicit Wire Encoding (No memcpy) | Accepted |
| [ADR-003](#adr-003-pressure-aware-sampling-at-source) | Pressure-Aware Sampling at Source | Accepted |
| [ADR-004](#adr-004-flow-context-as-value-type) | Flow Context as Value Type | Accepted |
| [ADR-005](#adr-005-single-combined-pipeline-entry-point) | Single Combined Pipeline Entry Point | Accepted |
| [ADR-006](#adr-006-stub-implementations-for-test-mode) | Stub Implementations for Test Mode | Accepted |
| [ADR-007](#adr-007-6-language-architecture) | 6-Language Multi-Runtime Architecture | Accepted |
| [ADR-008](#adr-008-forensics-ring-buffer-4096-entries) | Forensics Ring Buffer (4096 entries) | Accepted |
| [ADR-009](#adr-009-defcon-escalation-model) | DEFCON Escalation Model | Accepted |
| [ADR-010](#adr-010-prometheus-metrics-naming-convention) | Prometheus Metrics Naming Convention | Accepted |

---

## ADR-001: Zig 0.13 as Core Language

**Date:** 2026-08-28
**Status:** Accepted

### Context
AEGIS NIDS needs a systems language for the core detection engine that:
- Compiles to native code (no runtime overhead)
- Has no garbage collection (deterministic memory management)
- Supports extern FFI for C/C++/Rust interop
- Has built-in testing framework
- Can target Windows x86_64

### Decision
Use **Zig 0.13.0** as the core language for:
- Main detection pipeline (nids_analyze.zig)
- Event Fabric runtime (event_fabric.zig)
- All integration layers (STEP 3-26)
- WFP IOCTL bridge (wfp_ioctl.zig)

### Consequences
**Positive:**
- Zero-overhead abstractions (comptime)
- Built-in `std.testing` (no external test framework)
- Direct C ABI interop (no wrapper layers needed)
- Cross-compilation support

**Negative:**
- Zig 0.13 API still evolving (breaking changes between versions)
- Smaller ecosystem than Rust/Go
- Debug builds can be slow (ReleaseFast needed for production)

---

## ADR-002: Explicit Wire Encoding (No memcpy)

**Date:** 2026-08-28
**Status:** Accepted

### Context
Canonical events cross language boundaries (Zig → C++ → Python → Go). Using `memcpy(struct)` or `@ptrCast` would:
- Break across compilers (different padding rules)
- Break across languages (Rust enum tags, Zig extern alignment)
- Be non-portable (endianness, alignment)

### Decision
All wire encoding uses **explicit field-by-field** encoding:
- `std.mem.writeInt(u32, buf[offset..], value, .little)` for each field
- `std.mem.readInt(u32, bytes[offset..], .little)` for decoding
- No `@ptrCast`, no `@alignCast`, no struct memcpy
- Fixed offsets documented in `shared/protocol/wire_v1.md`

### Consequences
**Positive:**
- Byte-identical output across all languages
- No padding/alignment dependency
- Self-documenting wire format
- Forward compatible (struct_size field)

**Negative:**
- More code than memcpy (but trivial)
- Must update spec when fields change

---

## ADR-003: Pressure-Aware Sampling at Source

**Date:** 2026-08-28
**Status:** Accepted

### Context
Under high load, the event fabric queue fills up. If sensors keep pushing, events get dropped at the queue — wasting the enqueue/dequeue cost. Better to drop at the source.

### Decision
Implement **SamplingPolicy** in `nose_integration.zig`:
- `low` pressure: submit everything
- `medium` (50%+): drop 50% of LOW-priority at source
- `high` (80%+): drop ALL LOW-priority at source
- `saturated` (100%): drop LOW+NORMAL at source; HIGH retries once after backoff

### Consequences
**Positive:**
- Critical events (HIGH priority) always get queue slots
- Low-priority events dropped before wasting queue bandwidth
- Sensors can query `currentPressure()` before expensive operations

**Negative:**
- Some events lost under high load (acceptable — better than blocking)
- PRNG adds minor overhead (xorshift64, ~2ns/op)

---

## ADR-004: Flow Context as Value Type

**Date:** 2026-08-28
**Status:** Accepted

### Context
Flow context (packet_count, byte_count, risk_score) is accessed by the detection layer after `flow_int.processEvent()`. If returned as a pointer, the caller could hold it across yields while another thread mutates the flow state.

### Decision
`FlowContext` is a **value type** (struct, not pointer):
- `processEvent()` returns `FlowContext` by value (snapshot)
- Caller can keep it across yields without race conditions
- `updateRiskScore()` mutates the underlying FlowTable entry

### Consequences
**Positive:**
- Race-free: snapshot is immutable
- No lock contention for reading flow state
- Simple ownership (no need to free pointer)

**Negative:**
- 64-byte struct copied per call (negligible vs pipeline overhead)
- Caller must call `updateRiskScore()` separately to persist changes

---

## ADR-005: Single Combined Pipeline Entry Point

**Date:** 2026-08-28
**Status:** Accepted

### Context
The Golden Path has 6 stages (RAG → Flow → Detection → Correlation → Policy → Forensics). If each stage is called separately, callers must remember the correct order and pass intermediate results correctly.

### Decision
`policy_int.processEventFullPipeline(event, det_mgr, payload)` is the **single entry point**:
- Runs all 6 stages in correct order
- Returns `FullPipelineResult` with all intermediate results
- Caller doesn't need to know stage ordering

### Consequences
**Positive:**
- Impossible to call stages in wrong order
- Single function call per event (simple API)
- All intermediate results available for forensics

**Negative:**
- Less flexible for partial pipeline (but `processEventFlowOnly()` exists)
- Function signature is longer (but only called from eventFabricDrain)

---

## ADR-006: Stub Implementations for Test Mode

**Date:** 2026-08-28
**Status:** Accepted

### Context
Multi-language integration (C++/Rust/Go/Python/Cython) requires external DLLs/services that aren't available during test runs. Using `extern fn` directly causes linker errors.

### Decision
Each integration module provides **stub implementations**:
- Stub functions mimic the real FFI logic in pure Zig
- Aliased to the same names as extern declarations
- Example: `const aegis_bridge_push_event = stub_bridge_push_event;`
- In production: replace stubs with `std.DynLib` loading

### Consequences
**Positive:**
- Tests run without external dependencies
- Stub logic mirrors real implementation (meaningful test coverage)
- No linker errors in test mode

**Negative:**
- Production requires manual switch to DynLib loading (future work)
- Stubs must be kept in sync with real implementations

---

## ADR-007: 6-Language Multi-Runtime Architecture

**Date:** 2026-08-28
**Status:** Accepted

### Context
AEGIS NIDS needs to leverage strengths of multiple languages:
- Zig: fast core pipeline
- C++: zero-copy packet parsing
- Rust: behavioral analysis (Tier-3)
- Go: alert aggregation + REST API
- Python: regex deep inspection (Tier-2)
- Cython: pattern matching acceleration

### Decision
Each language runs as a **separate process/service** with Zig as the orchestrator:
- Zig pipeline calls detectors via FFI (Rust/Cython) or IPC (C++/Python/Go)
- Go aggregator watches NDJSON log + exposes REST API
- Python brain receives payloads via UDP
- C++ bridge provides zero-copy packet parsing via shared memory

### Consequences
**Positive:**
- Each language used where it's strongest
- Fault isolation (crash in one language doesn't kill pipeline)
- Independent scaling (Go aggregator can run on separate host)

**Negative:**
- More complex deployment (6 runtimes)
- IPC overhead between languages (mitigated by zero-copy where possible)
- Testing requires stubs for all external dependencies

---

## ADR-008: Forensics Ring Buffer (4096 entries)

**Date:** 2026-08-28
**Status:** Accepted

### Context
Forensics replay queries need fast access to recent events. Disk I/O (NDJSON) is too slow for real-time incident investigation.

### Decision
Use an **in-memory ring buffer** (4096 entries):
- O(1) write (ring index + mutex)
- O(N) query scan (acceptable for 4096 entries)
- FIFO eviction (oldest entries dropped when full)
- `seq` field for getRecord() lookup (handles eviction)

### Consequences
**Positive:**
- Sub-microsecond write latency
- No allocator needed (fixed array)
- Query works without disk I/O

**Negative:**
- Only 4096 recent events queryable (older → disk NDJSON)
- O(N) scan per query (acceptable: 4096 * ~10ns = ~40µs)

---

## ADR-009: DEFCON Escalation Model

**Date:** 2026-08-28
**Status:** Accepted

### Context
The Python brain computes a DEFCON level (1-5) from event counts. This level needs to influence policy decisions (DEFCON 1 = block everything).

### Decision
DEFCON levels computed from counts:
- `critical >= 1` → DEFCON 1 (block all matches)
- `blocked >= 3` → DEFCON 2
- `matched >= 10` → DEFCON 3
- `matched >= 1` → DEFCON 4
- else → DEFCON 5 (normal)

**DEFCON 1 override:** All matches escalate to BLOCK (even benign events).

### Consequences
**Positive:**
- Automatic escalation under attack
- Clear 5-level model (intuitive for SOC analysts)
- Override prevents false negatives during critical attacks

**Negative:**
- DEFCON 1 may cause false positives (benign traffic blocked)
- Acceptable trade-off: better safe than sorry during critical threat

---

## ADR-010: Prometheus Metrics Naming Convention

**Date:** 2026-08-28
**Status:** Accepted

### Context
Metrics from 14+ pipeline modules need consistent naming for Prometheus/Grafana dashboards.

### Decision
All metrics use `aegis_` prefix + module name + metric name:
- `aegis_fabric_accepted_total` (counter)
- `aegis_flow_active_flows` (gauge)
- `aegis_policy_blocks_total` (counter)
- `aegis_forensics_ring_used` (gauge)
- `aegis_version_major` (gauge)

**Convention:**
- Counters: `_total` suffix (Prometheus standard)
- Gauges: no suffix
- Unit suffix: `_ms`, `_ns`, `_bytes` where applicable

### Consequences
**Positive:**
- Easy to filter in Grafana (`aegis_*`)
- Follows Prometheus naming best practices
- Self-documenting (module name in metric)

**Negative:**
- Longer metric names (but Prometheus handles this efficiently)
