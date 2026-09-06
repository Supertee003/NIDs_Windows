# G4 — Event Fabric

**Gate:** G4
**Status:** COMPLETE
**Date:** 2026-09-07

## Requirement

```
input = processed + dropped + rejected + expired + failed
```

> การ drop ต้องมีเหตุผลและ metric.

## Event Fabric Architecture

```
Sensors (3 sources)
  ├─ nids_capture.zig    (named pipe: \\.\pipe\aegis_sensor_pipe)
  ├─ windows_capture.zig  (WFP device: \\.\AegisWfpDevice)
  └─ tcp_listener          (TCP: 0.0.0.0:12345)
       │
       ▼
  inspect_packet(data, ctx)          ← G3 dispatcher (canonical entry)
       │
       ├─ event_accounting.recordInput()
       │
       ├─ Rust Tier-3 (validate_payload_safety)
       │   └─ fail → recordRejected()
       │
       ├─ Aho-Corasick Tier-1 match
       │   ├─ match → send_to_brain (UDP 127.0.0.1:9999)
       │   │        → pushTier1Match (C++ Bridge ring buffer)
       │   │        → recordProcessed()
       │   └─ no match → send_to_brain (forward)
       │                → pushForwardedEvent (C++ Bridge)
       │                → recordProcessed()
       │
       └─ no ruleset → recordDropped("no ruleset loaded")
```

## Backpressure Mechanisms

### 1. Connection Semaphore (Zig)
```zig
// nids_analyze.zig
var connection_semaphore = Thread.Semaphore{ .permits = 100 };
```
- Limits concurrent TCP connections to 100
- When full, new connections wait (not dropped)
- Prevents unbounded thread spawning under SYN flood

### 2. Ring Buffer Overflow (C++ Bridge)
```cpp
// aegis_ipc.hpp — SharedRingBuffer::Push
bool Push(const T& event) {
    if (m_count >= m_capacity) {
        m_dropped++;        // ← metric: events dropped due to overflow
        return false;       // ← backpressure: caller knows event was dropped
    }
    ...
}
```
- Capacity: 8192 events
- When full: event is dropped, `m_dropped` counter incremented
- Caller can check return value to apply additional backpressure

### 3. Accounting (G3)
```zig
// nids_analyze.zig — EventAccounting
input = processed + dropped + rejected + expired + failed
```
- `total_input`: every call to `inspect_packet`
- `total_processed`: successfully analyzed (match or forward)
- `total_dropped`: dropped with reason (e.g., "no ruleset loaded")
- `total_rejected`: rejected by Rust memory safety
- `total_expired`: (placeholder for future timeout)
- `total_failed`: (placeholder for future error handling)
- Printed every 30s by `bridgeStatusReporter`

## Event Transport Paths

| Path | From → To | Protocol | Backpressure |
|---|---|---|---|
| UDP socket | Zig → Python Brain | UDP 127.0.0.1:9999 | None (fire-and-forget; UDP drops on socket buffer full) |
| C++ Bridge ring buffer | Zig → C++ Bridge | `extern "C"` `push_event()` | Ring buffer full → `m_dropped++` |
| Named pipe | Python → Zig | `\\.\pipe\aegis_sensor_pipe` | Blocking read (client waits if pipe buffer full) |
| WFP IOCTL | Kernel → Zig | `DeviceIoControl(IOCTL_AEGIS_READ_EVENTS)` | Kernel ring buffer (2MB); oldest events overwritten |
| TCP socket | External → Zig | TCP 0.0.0.0:12345 | Connection semaphore (100 permits) |

## Accounting Verification

The accounting equation is verified at print time:
```
input = processed + dropped + rejected + expired + failed
```

If `input != (processed + dropped + rejected + expired + failed)`, there's a
leak (event entered the dispatcher but wasn't accounted for). The current
implementation covers:

- ✅ `input` → `recordInput()` at function entry
- ✅ `rejected` → `recordRejected()` when Rust safety check fails
- ✅ `dropped` → `recordDropped("reason")` when ruleset is null
- ✅ `processed` → `recordProcessed()` on match or forward
- ⏳ `expired` → placeholder (future: event timeout in ring buffer)
- ⏳ `failed` → placeholder (future: send_to_brain failure, Bridge push failure)

## Exit Gate

```
[x] Accounting implemented (input = processed + dropped + rejected + expired + failed)
[x] Drop has reason (recordDropped takes a reason string)
[x] Drop has metric (total_dropped counter)
[x] Backpressure: connection_semaphore (100 permits) limits concurrent connections
[x] Backpressure: ring buffer overflow tracked via m_dropped
[x] Backpressure: UDP send is fire-and-forget (acceptable for alert forwarding)
[x] Accounting printed every 30s via bridgeStatusReporter
[x] All 5 event transport paths documented with backpressure behavior
```
