# Authority Matrix

**Gate:** G1 | **Date:** 2026-09-07

## Single Authority Per Concern

| Concern | Authority | Component | Language | Status |
|---|---|---|---|---|
| Canonical Event | `IpcEvent` struct | `bridge/aegis_ipc.hpp` | C++ (source of truth) | S3 |
| Flow State | `FlowTable` | `nids_analyze.zig` | Zig | S3 |
| Detection Evidence | `inspect_packet()` | `nids_analyze.zig` / `windows_brain.py` / `src/lib.rs` | Zig/Python/Rust | S4 |
| Correlation | `AtomicThreatTracker` | `nids_analyze.zig` | Zig | S3 |
| Verdict | `AtomicThreatTracker.getState()` | `nids_analyze.zig` | Zig | S3 |
| Policy | `PolicyIR` + Ed25519 | `nids_analyze.zig` (G9) | Zig | S2 |
| Enforcement | `pep_enforce_action()` | `src/lib.rs` | Rust | S3 |
| Forensics | `ForensicRecord` + JSONL | `nids_analyze.zig` (G11) | Zig | S2 |
| Control | `aegisctl` (G26) | future | — | S0 |
| Federation | `ClusterCoord` (G17) | future | Zig | S1 |

## Architecture Layers

```
DATA PLANE:     Sensors → inspect_packet → Canonical Event → Flow → Detection
CONTROL PLANE:  aegisctl → Control Request → Policy → Rust PEP → Windows
SECURITY PLANE: Detection → Correlation → Policy → Ed25519 → Rust PEP
OBSERVABILITY:  EventAccounting + FlowTable + PEP stats + DEFCON + JSONL logs
```

## Shield Authority Resolution

- `src/lib.rs` = PRODUCTION (Rust PEP + Tier-3 detector)
- `shield/` = EMPTY (removed)
- `windows_sec_monitor.rs` = TOOL (DEFCON display only)

## Forbidden Crossings

- Sensor → enforcement: FORBIDDEN (calls inspect_packet only)
- Detector → enforcement: FORBIDDEN (returns evidence)
- Brain → enforcement: FORBIDDEN (IPS is separate function)
- RAG → ALLOW/BLOCK: FORBIDDEN (context only)
- CLI → direct OS enforcement: FORBIDDEN (goes through PEP)
- Policy → execute action: FORBIDDEN (decides; PEP executes)
