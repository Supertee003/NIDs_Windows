# AEGIS NIDS — System Architecture (Rewrite v3.0)

## Status: FROZEN — Changes require ADR

## Overview

AEGIS NIDS is a Windows-native Security Event Fabric + Detection + Correlation + Intelligence + Policy Enforcement Platform.

```
                              AEGIS
                                │
                ┌───────────────┴───────────────┐
                │                               │
             NETWORK                          HOST
                │                               │
              WFP                          Minifilter
                │                               │
                └───────────────┬───────────────┘
                                ▼
                              NOSE
                                │
                        Canonical Event
                                │
                           Validation
                                │
                       Event Fabric Queue
                                │
                      Runtime Dispatcher
                                │
            ┌───────────────────┼───────────────────┐
            │                   │                   │
           FLOW             DETECTION          TELEMETRY
            │                   │
            └───────────────────┘
                     │
                 EVIDENCE
                     │
                CORRELATION
                     │
              ENTITY / INCIDENT
                     │
          ┌──────────┴──────────┐
          │                     │
    Threat Intelligence      Brain
          │                     │
          └──────────┬──────────┘
                     │
                    RAG
                     │
                  VERDICT
                     │
                   POLICY
                     │
                 POLICY IR
                     │
                  RUST
                     │
                    PEP
                     │
                 WFP/HOST
                     │
                   ACTION
                     │
                FORENSICS
                     │
                  REPLAY
```

## Design Principles

1. **ไม่ Big Bang** — Extract → Redirect → Verify → Deprecate → Remove
2. **ห้ามสอง source of truth** — แต่ละ responsibility มี owner เดียว
3. **แม่นก่อนเร็ว** — correctness > performance
4. **Nose ไม่ฉลาด** — แม่นก่อนเร็ว, event ที่ผิดตั้งแต่ต้นแก้ไม่ได้
5. **Detection = evidence producer** — ไม่ใช่ decision maker
6. **Brain = advisor** — ไม่ใช่ enforcer
7. **Policy = plan** — ไม่ใช่ action ตรงๆ
8. **Rust = security authority** — validate + execute, ไม่รับ arbitrary input

## Module Inventory

### Core Runtime (Zig)
| Module | Responsibility |
|--------|---------------|
| `core/canonical_event.zig` | Single event schema (source of truth) |
| `core/wire_event.zig` | Explicit wire format (field-by-field, no memcpy) |
| `core/event_queue.zig` | Thread-safe ring buffer |
| `core/priority_queue.zig` | 3-priority event routing |
| `core/nose_contract.zig` | Sensor → Fabric interface |
| `core/event_fabric.zig` | Runtime subsystem (pressure, backpressure, metrics) |
| `core/runtime/dispatcher.zig` | (NEW) Pipeline dispatcher |
| `core/runtime/pipeline.zig` | (NEW) Pipeline stages |
| `core/runtime/lifecycle.zig` | (NEW) Init/shutdown lifecycle |
| `core/runtime/worker.zig` | (NEW) Worker threads |
| `core/runtime/shutdown.zig` | (NEW) Graceful shutdown |

### Detection (Zig)
| Module | Responsibility |
|--------|---------------|
| `core/detection_interface.zig` | Detector trait + DetectionManager |
| `core/analyze/detectors/` | (NEW) Detector implementations |
| `core/analyze/evidence/` | (NEW) Evidence model + aggregator |

### Flow (Zig)
| Module | Responsibility |
|--------|---------------|
| `core/flow_engine.zig` | FlowKey + FlowState + FlowTable (will be rewritten to hash-based) |

### Policy (Zig + Rust)
| Module | Responsibility |
|--------|---------------|
| `core/policy_contract.zig` | PolicyDecision + PolicyRule + PolicyEngine + PEP |
| `core/policy_ir.zig` | PolicyIR + PolicyIRBuilder |

### Windows Integration
| Module | Responsibility |
|--------|---------------|
| `core/wfp_ioctl.zig` | WFP kernel driver IOCTL bridge |
| `core/nids_capture.zig` | Named pipe IPC sensor |
| `core/windows_capture.zig` | WFP event reader |
| `core/pipe_monitor.zig` | Named pipe interceptor |
| `core/minifilter_reader.zig` | Minifilter event reader |
| `core/hids_process_monitor.zig` | HIDS process events |
| `core/forensic_log.zig` | NDJSON persistent logger |
| `core/win32_io.zig` | Win32 I/O helpers |
| `core/bridge_init.zig` | C++ bridge initialization |

## Answer Key: Who Does What?

| Question | Answer |
|----------|--------|
| ใครสร้าง event? | Sensors (WFP, Minifilter, Pipe, HIDS) |
| ใคร validate? | Nose Contract (magic + version + struct_size) |
| ใคร enqueue? | Event Fabric (via nose.submit) |
| ใครอ่าน? | Runtime Dispatcher (pops from Fabric) |
| ใครสร้าง evidence? | Detectors (via DetectionManager) |
| ใครสร้าง verdict? | Verdict Aggregator (from evidence[]) |
| ใครตัดสิน policy? | PolicyEngine (from verdict + context) |
| ใคร enforce? | Rust PEP (validate → execute) |
| ใครเก็บ forensic? | Forensics Integration (ring + NDJSON) |
