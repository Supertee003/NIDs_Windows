# G3 — Runtime Spine

**Gate:** G3
**Status:** COMPLETE
**Date:** 2026-09-07

## Definition

```
runtime_spine = describe + verify
dispatcher = execute
```

The runtime spine describes the system's init order, worker ownership, and lifecycle.
The dispatcher (`inspect_packet`) executes event analysis.

## Init Order

```
Step 1: nids_main.zig:main()
  ├─ Create logs/ directory
  ├─ Spawn Thread: nids_analyze.analyze_packets(allocator)
  │   ├─ Step 1a: loadBridgeDll()     — Load C++ IPC Bridge DLL (aegis_ipc.dll)
  │   ├─ Step 1b: loadRustDll()       — Load Rust Memory Safety DLL (sec_monitor.dll)
  │   ├─ Step 1c: bridgeInit()        — Initialize C++ Bridge (ring buffer + DEFCON)
  │   ├─ Step 1d: Create UDP socket    — 127.0.0.1:9999 → Python Brain
  │   ├─ Step 1e: reload_rules_atomic() — Load Rules.json + build Aho-Corasick
  │   ├─ Step 1f: Spawn bridgeStatusReporter thread (30s interval)
  │   ├─ Step 1g: Spawn pipe_listener thread
  │   └─ Step 1h: Spawn tcp_listener thread
  ├─ Sleep 500ms (wait for analyzer ready)
  ├─ Spawn Thread: nids_capture.capture_packets(allocator, "127.0.0.1")
  └─ Spawn Thread: windows_capture.capture_packets(allocator, "127.0.0.1")
```

## Worker Ownership

| Thread | Owner | Responsibility | Lifecycle |
|---|---|---|---|
| main | nids_main.zig | Spawn + join all threads | Runs forever |
| analyze_packets | nids_analyze.zig | Init bridge/rules + spawn listeners | Runs forever |
| bridgeStatusReporter | nids_analyze.zig | Print Bridge stats + event accounting every 30s | Detached (runs forever) |
| pipe_listener | nids_analyze.zig | Listen on `\\.\pipe\aegis_sensor_pipe` | Joined by analyze_packets |
| tcp_listener | nids_analyze.zig | Listen on 0.0.0.0:12345 | Joined by analyze_packets |
| capture_packets (pipe) | nids_capture.zig | Read from named pipe, call inspect_packet | Joined by main |
| capture_packets (WFP) | windows_capture.zig | Read from `\\.\AegisWfpDevice`, call inspect_packet | Joined by main |

## Dispatcher: inspect_packet

`inspect_packet` is the canonical dispatcher entry point. All sensors call it.

```
inspect_packet(data, ctx)
  ├─ recordInput()           — G3 accounting
  ├─ Rust Memory Safety      — Tier-3 pre-screen
  │   └─ if unsafe: recordRejected() + return false
  ├─ Load active ruleset     — if null: recordDropped("no ruleset") + return false
  ├─ Tier-1: Aho-Corasick    — Fast pattern match
  │   ├─ If match: send_to_brain() + pushTier1Match()
  │   │   └─ If Block action: recordProcessed() + return false
  │   │   └─ Else: recordProcessed() + return true
  │   └─ If no match: send_to_brain(forward) + pushForwardedEvent()
  │       └─ recordProcessed() + return true
```

## Event Accounting (G3/G4)

```
input = processed + dropped + rejected + expired + failed
```

| Counter | When Incremented |
|---|---|
| total_input | Every call to `inspect_packet` |
| total_processed | Event successfully analyzed (matched or forwarded) |
| total_dropped | Event dropped (e.g., no ruleset loaded) |
| total_rejected | Event rejected by Rust memory safety check |
| total_expired | (placeholder for future timeout logic) |
| total_failed | Event caused an error (not currently used; future error handling) |

Accounting is printed every 30 seconds by `bridgeStatusReporter`.

## Golden Path

```
Sensor (pipe/WFP/TCP)
  → inspect_packet(data, ctx)
    → Rust validate_payload_safety(data) → bool
    → Aho-Corasick match against Rules.json
      → If match: UDP to Brain:9999 + push to C++ Bridge
      → If no match: UDP forward to Brain + push forwarded event
    → Return true (allow) or false (block)
```

## Production/Tool Classification

| Component | Classification | Status |
|---|---|---|
| nids_main.zig | PRODUCTION | Runtime entrypoint |
| nids_analyze.zig | PRODUCTION | Dispatcher + Tier-1 engine |
| nids_capture.zig | PRODUCTION | Pipe sensor |
| windows_capture.zig | PRODUCTION | WFP sensor |
| bridge/aegis_ipc.* | PRODUCTION | C++ IPC Bridge |
| src/lib.rs | PRODUCTION | Rust Tier-3 memory safety |
| windows_brain.py | PRODUCTION | Python Tier-2 regex engine |
| windows_perf.go | TOOL | Performance dashboard (Nose) |
| aegis_daemon.py | TOOL | Daemon manager |
| aegis_console.py | TOOL | Interactive menu |
| pipe_monitor.zig | SCAFFOLD | Stub (no Win32 API binding) |
| minifilter_reader.zig | SCAFFOLD | Stub (no fltlib binding) |
| drivers/* | SCAFFOLD | Kernel driver source (not built in CI) |

## Exit Gate

```
[x] init order documented
[x] worker ownership documented
[x] lifecycle documented
[x] production/tool classification documented
[x] golden path documented
[x] event accounting implemented (input = processed + dropped + rejected + expired + failed)
[x] accounting printed every 30s via bridgeStatusReporter
```
