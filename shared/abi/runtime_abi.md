# CONTRACT-03: Runtime ABI (Lifecycle)

**Contract ID:** RUNTIME_ABI
**Version:** 1.0
**Status:** FROZEN
**Languages:** Zig (spine), all others (consumers)

## Purpose

Defines how subsystems attach to the Zig Runtime Spine.
Every language boundary (Go, C++, Python, Rust) enters through this ABI.
Zig is the hub; languages are spokes.

## Module Lifecycle

```
init(subsystem_config) → initialized
    │
    ▼
start() → running
    │
    ├── heartbeat() → alive (periodic)
    │
    ▼
stop() → stopped
    │
    ▼
deinit() → resources freed
```

## Module Categories

| Category | Description | Init Order |
|----------|-------------|------------|
| production | Core runtime modules | 1-12 |
| acquisition | Sensors (Go, C++) | 13-16 |
| intelligence | Python Brain, RAG | 17-20 |
| security | Rust PEP, WFP | 21-24 |
| control | TypeScript, CLI | 25-28 |
| tooling | Benchmarks, tests | 29-32 |
| proof | Verification modules | 33-36 |

## Worker Stages (Pipeline)

```
sensors → event_fabric → dispatcher → analysis_workers → correlation → policy → pep → forensics
```

Each stage:
- Receives CanonicalEvent from previous stage
- Processes (detection, correlation, policy eval)
- Forwards to next stage
- Records to forensic ring (if enabled)

## Golden Path Tracer

Traces event through 12 stages:
1. source → 2. fabric → 3. dispatcher → 4. flow → 5. detection → 6. verdict
7. correlation → 8. threat_intel → 9. brain → 10. policy → 11. pep → 12. forensics

## Interface Contract

### For Go/C++ (Sensors)
```c
// Sensor initialization
int aegis_sensor_init(const AegisSensorConfig* config);

// Event submission (C ABI)
int aegis_ingest(const AegisCanonicalEvent* event);

// Sensor shutdown
void aegis_sensor_shutdown(void);
```

### For Python (Brain)
```python
# Brain initialization
def aegis_brain_init(config: dict) -> int:

# Analysis request
def aegis_analyze(event: bytes) -> dict:

# Brain shutdown
def aegis_brain_shutdown() -> None:
```

### For Rust (PEP)
```rust
// PEP initialization
pub extern "C" fn aegis_pep_init() -> c_int;

// PEP enforcement
pub extern "C" fn aegis_pep_enforce(
    req: *const AegisPepRequest,
    resp: *mut AegisPepResponse,
) -> c_int;

// PEP shutdown
pub extern "C" fn aegis_pep_shutdown();
```

## Invariants

- Zig is the ONLY runtime spine
- No second runtime may exist
- All subsystems attach through C ABI or language-specific FFI
- Module init order is deterministic (no race conditions)
- Golden path tracer must trace every event through all 12 stages
- No module may skip the pipeline (no side channels)

## References

- `src/contract/runtime_spine.zig` - Zig implementation
- `src/contract/runtime_manifest.zig` - Capability flags
- `shared/runtime/components.json` - Component registry
- `CONTRACT_MAP.json` - Contract registry
