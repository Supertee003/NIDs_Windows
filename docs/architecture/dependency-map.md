# AEGIS NIDS — Dependency Map (Rewrite v3.0)

## Module Dependencies (Zig core)

```
                    nids_main.zig
                         │
                    ┌────┴────┐
                    │         │
            bridge_init  forensic_log
                    │
            ┌───────┼───────┐
            │       │       │
      nids_capture  │  nids_analyze
            │       │       │
      windows_capture│  detection_interface
            │       │       │
      wfp_ioctl     │  policy_contract
                    │       │
              nose_contract  │
                    │  ┌────┘
              event_fabric  │
                    │  │
              priority_queue│
                    │  │
              event_queue  │
                    │  │
              canonical_event
                    │
              wire_event
```

## Runtime Dependency (Rewrite Target)

```
                    nids_main.zig
                         │
                    runtime/
                    ├── dispatcher.zig
                    ├── pipeline.zig
                    ├── lifecycle.zig
                    ├── worker.zig
                    └── shutdown.zig
                         │
              ┌──────────┼──────────┐
              │          │          │
        event_fabric  nose_contract  analyze/
              │          │          ├── detectors/
        priority_queue   │          └── evidence/
              │          │
        event_queue  canonical_event
              │          │
                    wire_event
```

## Cross-Language Dependencies

```
Zig Core (coordinator)
  ↓ FFI
C++ Bridge (adapter)
  ↓ shared memory
Python Brain (advisor)
  ↓ Cython
Cython (accelerator)

Zig Core
  ↓ FFI
Rust Shield (security authority)
  ↓ validate + execute
WFP/HOST action

Zig Core
  ↓ NDJSON log
Go Aggregator (acquisition + REST API)

Zig Core
  ↓ wire protocol
C ABI boundary (shared/protocol/wire_v1.h)
```

## Dependency Rules

1. **Zig → C**: only via `extern fn` (no C++ in core path)
2. **Zig → C++**: only via C++ Bridge (adapter pattern)
3. **Zig → Rust**: only via FFI (Rust exports `#[no_mangle] extern "C"`)
4. **Zig → Go**: only via NDJSON log (file-based IPC)
5. **Zig → Python**: only via UDP (:9999) or NDJSON log
6. **Zig → Cython**: only via Python bridge (indirect)
7. **C → all languages**: shared wire protocol header (`shared/protocol/wire_v1.h`)

## Forbidden Dependencies

- ❌ Python → WFP IOCTL (Brain must not enforce)
- ❌ Python → direct firewall block (Brain must not enforce)
- ❌ Rust → arbitrary JavaScript (Rust validates only)
- ❌ C++ → detection logic (C++ is adapter, not detector)
- ❌ Go → policy decisions (Go is acquisition, not decision maker)
- ❌ Kernel → Python/RAG/LLM (heavy processing in user mode only)
