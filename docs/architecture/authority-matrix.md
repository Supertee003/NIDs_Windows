# Authority Matrix

**Gate:** G1 | **Date:** 2026-09-07

## Single Authority Per Concern

| Concern | Authority | Component | Language | Status |
|---|---|---|---|---|
| Canonical Event | `CanonicalEvent` | `src/contract/event.zig` (production) / `core/canonical_event.zig` (legacy) | Zig (source of truth, per ADR-0003) | S3 |
| Flow State | `FlowTable` | `src/capture/flow_table.zig` (production) / `core/flow_engine.zig` (legacy) | Zig | S3 |
| Detection Evidence | `inspect_packet()` | `nids_analyze.zig` / `windows_brain.py` / `src/lib.rs` | Zig/Python/Rust | S4 |
| Correlation | `AtomicThreatTracker` | `nids_analyze.zig` | Zig | S3 |
| Verdict | `AtomicThreatTracker.getState()` | `nids_analyze.zig` | Zig | S3 |
| Policy | `PolicyIR` + Ed25519 | `nids_analyze.zig` (G9) | Zig | S2 |
| Enforcement | `pep_enforce_action()` | `src/lib.rs` | Rust | S3 |
| Forensics | `ForensicRecord` + JSONL | `nids_analyze.zig` (G11) | Zig | S2 |
| Control | `aegisctl` | `tools/aegisctl.py` (production CLI; authorization/replay/audit partial per Step 42) | â€” | S0 |
| Federation | `ClusterCoord` / `FederationCodec` | `core/federation_*.zig` / `core/federation_tls.zig` (production framework; multi-node verification unverified per Step 53) | Zig | S1 |

## Legacy Authorities (superseded, do not extend)

- `bridge/aegis_ipc.hpp` `IpcEvent` = LEGACY (72-byte, schema_version 2). Was the C++ "source of truth" pre-ADR-0003; event authority moved to Zig `core/canonical_event.zig` (109-byte wire, "AEG1" magic, v1). Keep for compat only; new code MUST emit the canonical wire.
- `src/contract/event.zig` `IpcEvent` = LEGACY (80-byte, magic 0xAE615011, v5).
- `core/npcap_capture.zig` = LEGACY packet capture. Packet capture moved to Go Nose (`nose/capture.go` via gopacket/npcap) per ADR-0003; keep npcap_capture.zig for reference only.

## Captured-Source Ownership (ADR-0003)

- Windows networking + Go Nose = network capture owner (gopacket/npcap), acquisition-only.
- C++ adapters (`bridge/aegis_adapter.hpp/.cpp`) = ETW / FIM / Registry / Process owner, via start/stop/poll/callback/health/error over C ABI to Zig.

## Architecture Layers

```
DATA PLANE:     Sensors â†’ inspect_packet â†’ Canonical Event â†’ Flow â†’ Detection
CONTROL PLANE:  aegisctl â†’ Control Request â†’ Policy â†’ Rust PEP â†’ Windows
SECURITY PLANE: Detection â†’ Correlation â†’ Policy â†’ Ed25519 â†’ Rust PEP
OBSERVABILITY:  EventAccounting + FlowTable + PEP stats + DEFCON + JSONL logs
```

## Shield Authority Resolution

- `src/lib.rs` = PRODUCTION (Rust PEP + Tier-3 detector)
- `shield/` = EMPTY (removed)
- `windows_sec_monitor.rs` = TOOL (DEFCON display only)

## Forbidden Crossings

- Sensor â†’ enforcement: FORBIDDEN (calls inspect_packet only)
- Detector â†’ enforcement: FORBIDDEN (returns evidence)
- Brain â†’ enforcement: FORBIDDEN (IPS is separate function)
- RAG â†’ ALLOW/BLOCK: FORBIDDEN (context only)
- CLI â†’ direct OS enforcement: FORBIDDEN (goes through PEP)
- Policy â†’ execute action: FORBIDDEN (decides; PEP executes)
