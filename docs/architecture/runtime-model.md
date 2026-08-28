# AEGIS NIDS — Runtime Model (Rewrite v3.0)

## Thread Architecture (Rewrite Target)

```
main()
  ↓
Runtime (lifecycle.zig)
  ├── Start Sensors (Sensor Pool)
  ├── Start Event Fabric
  ├── Start Analysis Workers (pool)
  ├── Start Correlation Worker
  ├── Start Policy Worker
  ├── Start Enforcement Worker
  ├── Health Monitor
  └── Shutdown Handler
```

### Current (v2.0/v3.0) — 6 Hardcoded Threads
```
T1: Analyze (nids_analyze.analyze_packets)
T2: Pipe Sensor (nids_capture.capture_packets)
T3: WFP Sensor (windows_capture.capture_events)
T4: Minifilter Reader (minifilter_reader.read_events)
T5: Pipe Monitor (pipe_monitor.monitor_pipes)
T6: HIDS Process Monitor (hids_process_monitor)
```

### Rewrite Target — Runtime Scheduler
```
Sensor Pool (N threads, configurable)
  ↓ submit events
Event Fabric (single queue, thread-safe)
  ↓ pop events
Analysis Workers (M threads, configurable)
  ├── Flow update
  ├── Detection (evidence production)
  └── Telemetry
  ↓ evidence[]
Correlation Worker (1 thread)
  ↓ verdict + incident
Policy Worker (1 thread)
  ↓ EnforcementPlan
Enforcement Worker (1 thread, Rust PEP)
  ↓ EnforcementResult
Forensics (inline, no separate thread)
```

### Thread Ownership Rules
- Thread ownership ต้องมาจาก runtime scheduler
- ไม่ใช่ feature-by-feature
- ทุก feature ไม่สร้าง thread เอง
- Shutdown จาก runtime เท่านั้น (ไม่ใช่จาก thread ตัวเอง)

## Lifecycle States

```
INIT → STARTING → RUNNING → DRAINING → STOPPED
                       ↓
                    DEGRADED (fault injection / resource exhaustion)
                       ↓
                    RECOVERING → RUNNING
```

### State Transitions
| From | To | Trigger |
|------|-----|---------|
| INIT | STARTING | `runtime.start()` |
| STARTING | RUNNING | All subsystems initialized |
| RUNNING | DRAINING | `runtime.shutdown()` or CTRL+C |
| RUNNING | DEGRADED | Fault (WFP down, Brain down, etc.) |
| DEGRADED | RECOVERING | Fault resolved |
| RECOVERING | RUNNING | All subsystems healthy |
| DRAINING | STOPPED | All events processed |
| any | STOPPED | Fatal error or force kill |

## Init/Shutdown Order

### Init (must follow this order)
```
1. Forensic logger (needs to log everything from start)
2. Event Fabric (queue must be ready before sensors)
3. Nose Contract (validation must be ready before events)
4. Flow Engine (must be ready before detection)
5. Detection Manager (must be ready before pipeline)
6. Correlation (must be ready before verdict)
7. Threat Intelligence (must be ready before brain)
8. Brain (must be ready before policy)
9. Policy Engine + IR (must be ready before PEP)
10. Rust PEP (must be ready before enforcement)
11. Sensors (start capturing only when pipeline is ready)
12. Runtime workers (start processing)
```

### Shutdown (reverse order)
```
1. Stop sensors (no new events)
2. Drain event fabric queue
3. Stop workers
4. Flush forensics
5. Shutdown PEP
6. Shutdown policy
7. Shutdown brain
8. Shutdown threat intel
9. Shutdown correlation
10. Shutdown detection
11. Shutdown flow
12. Shutdown fabric
13. Shutdown nose
14. Close forensic logger
```
