# AEGIS System Architecture (STEP 0 — Baseline Freeze)

## Status: FROZEN — No architectural changes without ADR

## Dependency Map

```
                    ┌─────────────┐
                    │  Windows OS │
                    │  (kernel32) │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
        ┌─────▼─────┐ ┌───▼───┐ ┌─────▼─────┐
        │ WFP Driver │ │ ETW   │ │ Minifilter │
        │ (aegis_wfp) │ │ /WMI  │ │  Driver    │
        └─────┬──────┘ └───┬───┘ └─────┬──────┘
              │            │            │
              ▼            ▼            ▼
     ┌────────────────────────────────────────┐
     │           Zig Core (core/*.zig)         │
     │                                        │
     │  T1: nids_analyze     ← AC Engine      │
     │  T2: nids_capture     ← Pipe Sensor    │
     │  T3: windows_capture  ← WFP Reader     │
     │  T4: minifilter_reader ← FS Events     │
     │  T5: pipe_monitor      ← Pipe Scanner  │
     │  T6: hids_process_monitor ← Proc Events│
     │                                        │
     │  Blueprint Modules:                    │
     │  ├── canonical_event.zig  ← Event v1  │
     │  ├── wire_event.zig       ← Wire v1   │
     │  ├── event_queue.zig      ← Queue     │
     │  ├── priority_queue.zig  ← 3-Lane    │
     │  ├── nose_contract.zig    ← Fabric    │
     │  ├── detection_interface.zig ← Det API │
     │  ├── policy_contract.zig  ← Policy+PEP│
     │  ├── flow_engine.zig     ← Flow State │
     │  ├── xdr_correlator.zig  ← XDR Link  │
     │  ├── rag_intelligence.zig ← Threat    │
     │  ├── policy_ir.zig       ← Policy IR  │
     │  ├── hids_process_monitor.zig ← HIDS  │
     │  ├── forensic_log.zig    ← NDJSON     │
     │  └── win32_io.zig        ← Overlapped │
     └───────────┬────────────────────────────┘
                 │
        ┌────────┼────────┐
        │        │        │
   ┌────▼──┐ ┌──▼───┐ ┌─▼────────┐
   │ C++   │ │ Rust  │ │ Python   │
   │Bridge │ │Shield │ │ Brain    │
   │(DLL)  │ │(DLL)  │ │          │
   │       │ │       │ │ +Cython  │
   │DEFCON │ │Tier-3 │ │ +RAG     │
   │Ring   │ │Safety │ │ +IPS     │
   └───┬───┘ └───┬──┘ └────┬─────┘
       │         │           │
       └─────────┴───────────┘
                 │
          ┌──────▼──────┐
          │ Go          │
          │ Aggregator  │
          │             │
          │ REST API    │
          │ Dedup       │
          │ Correlation │
          │ Timeline    │
          └─────────────┘
```

## Module Inventory

### Core Zig Modules (24 files, ~9,460 lines)

| File | Lines | Role | Creates Events? | Modifies Events? | Reads Events? |
|------|-------|------|-----------------|-------------------|---------------|
| nids_main.zig | 226 | Entry point, 6-thread orchestrator | No | No | No |
| nids_analyze.zig | 2,278 | 3-tier detection + listeners | No | Yes (sets verdict) | Yes |
| nids_capture.zig | 233 | Pipe IPC sensor | Yes (forward) | No | No |
| windows_capture.zig | 187 | WFP kernel sensor | Yes (forward) | No | No |
| minifilter_reader.zig | 344 | Filesystem sensor | Yes (forward) | No | No |
| pipe_monitor.zig | 237 | Pipe name scanner | Yes (forward) | No | No |
| wfp_ioctl.zig | 585 | WFP IOCTL + IP block | No | No | No |
| bridge_init.zig | 587 | C++/Rust DLL + UDP brain | No | No | No |
| forensic_log.zig | 438 | NDJSON persistent logger | No | No | Yes |
| win32_io.zig | 166 | Overlapped I/O helpers | No | No | No |
| canonical_event.zig | 278 | Event model v1 | Yes (create) | Yes (fields) | Yes |
| wire_event.zig | 241 | Wire format v1 | No | No | Yes |
| event_queue.zig | 234 | Thread-safe queue | No | No | Yes |
| priority_queue.zig | 290 | 3-priority queue | No | No | Yes |
| nose_contract.zig | 317 | Sensor→Fabric contract | Yes (submit) | Yes (validate) | Yes |
| detection_interface.zig | 331 | Detection API + manager | No | Yes (verdict) | Yes |
| policy_contract.zig | 378 | Policy + PEP | No | Yes (decision) | Yes |
| flow_engine.zig | 273 | Flow state tracking | No | Yes (flow state) | Yes |
| xdr_correlator.zig | 357 | Cross-tier correlation | No | Yes (incidents) | Yes |
| rag_intelligence.zig | 351 | Threat intel + RAG | No | Yes (context_flags) | Yes |
| policy_ir.zig | 306 | Policy IR v1 | No | No | Yes |
| hids_process_monitor.zig | 195 | HIDS process events | Yes (submit) | No | No |
| golden_path_test.zig | 362 | E2E tests | No | No | No |
| sprint2_e2e_test.zig | 363 | Sprint 2 E2E tests | No | No | No |

### External Modules

| Module | Language | Role | Lines |
|--------|----------|------|-------|
| bridge/aegis_ipc.cpp | C++ | IPC ring buffer + DEFCON + IPS | 425 |
| bridge/aegis_ipc.hpp | C++ | Header (SharedRingBuffer + IpcEvent) | 370 |
| shield/src/lib.rs | Rust | Memory safety (Tier-3) | 146 |
| brain/windows_brain.py | Python | Alert processing + IPS | 454 |
| brain/aegis_brain_cython/ | Cython | Hot-path acceleration | 440 |
| go/aggregator/ | Go | Alert dedup + correlation + REST | 911 |
| aegis_dashboard/ | Rust | egui dashboard | 340 |
| scripts/aegis_*.py | Python | CLI tools (8 scripts) | ~1,500 |

## Key Questions (must be answerable from source)

| Question | Answer | Source File |
|----------|--------|-------------|
| ใครสร้าง event? | Sensors (T2-T6) | nids_capture, windows_capture, minifilter_reader, hids_process_monitor |
| ใครแก้ event? | nose_contract (validate), detection_interface (verdict), policy_contract (decision+action) | nose_contract.zig, detection_interface.zig, policy_contract.zig |
| ใครอ่าน event? | forensic_log (archive), Go aggregator (replay), eventFabricDrain (drain) | forensic_log.zig, go/aggregator/ |
| ใครตัดสินใจ? | PolicyEngine (evaluate) | policy_contract.zig |
| ใคร enforce? | PEP (enforce → wfp_ioctl.block_ip) | policy_contract.zig → wfp_ioctl.zig |

## Acceptance Criteria

- [x] No subsystem has overlapping ownership
- [x] Every module has a clear single responsibility
- [x] Dependency graph has no cycles
- [x] Event creation/modification/reading is documented per module
