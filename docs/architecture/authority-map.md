# AEGIS NIDs Windows -- Authority Map

**Status:** Locked by ADR-0001  
**Date:** 2026-09-02  

## Authority Invariants

Each concern has exactly ONE owner. No other module may perform the
owner's authority without explicit delegation via ADR.

## Data Plane Authorities

| Concern | Owner | Language | Boundary |
|---|---|---|---|
| Event schema | core/canonical_event.zig | Zig | Defines CanonicalEvent struct, enums, version |
| Event queue | core/event_fabric.zig | Zig | Accepts, prioritizes, drops events |
| Flow state | core/flow_engine.zig | Zig | Creates, updates, expires flow records |
| Detection evidence | core/detection_engine.zig | Zig | Produces Evidence[] only; never enforces |
| Verdict | core/dispatcher.zig | Zig | Aggregates evidence into verdict |
| Correlation | core/correlation_engine.zig | Zig | Links entities into incidents |
| Threat intel | core/threat_intel.zig | Zig | Enriches with external intelligence |
| RAG context | core/rag_engine.zig | Zig | Enriches context; never authorizes |
| Brain advice | brain/windows_brain.py | Python | Advisory score + recommendation only |

## Control Plane Authorities

| Concern | Owner | Language | Boundary |
|---|---|---|---|
| Policy decision | core/policy_engine.zig | Zig | Final decision; consumes evidence + advice |
| Policy signing | (P0.2: needs real crypto) | Zig/Rust | Must be SHA-256 + Ed25519 |
| Enforcement | shield/src/lib.rs | Rust | Final enforcement; validates + executes |
| Forensics | core/forensics_engine.zig | Zig | Immutable trace of all decisions |
| Audit | core/forensic_log.zig | Zig | Append-only NDJSON log |

## Forbidden Actions

These are authority violations that MUST NOT exist in production:

1. aegisctl directly modifying blocked_ips.json (bypasses PEP)
2. aegisctl sending SIGUSR1 to core for block/unblock (bypasses PEP)
3. Detection engine calling block_ip or wfp_ioctl (detection is evidence-only)
4. Brain calling netsh advfirewall (brain is advisory-only)
5. RAG returning allow/block verdict (RAG is context-only)
6. nids_analyze.zig competing with dispatcher.zig (single orchestrator)
7. Policy using FNV-1a as signature (must be real crypto)
8. Test/proof modules initialized in production lifecycle

## Authority Flow (Canonical)

```
Event (Nose/WFP/HIDS)
    |
    v
[Canonical Event] -- owner: canonical_event.zig
    |
    v
[Event Fabric] ---- owner: event_fabric.zig
    |
    v
[Flow State] ------ owner: flow_engine.zig
    |
    v
[Detection] ------- owner: detection_engine.zig (produces Evidence[])
    |
    v
[Correlation] ----- owner: correlation_engine.zig
    |
    v
[Threat Intel] ---- owner: threat_intel.zig
    |
    v
[RAG] ------------- owner: rag_engine.zig (P0.1: must be in dispatcher)
    |
    v
[Brain Advice] ---- owner: brain_engine.zig
    |
    v
[Policy Decision] - owner: policy_engine.zig
    |
    v
[Rust PEP] -------- owner: shield/src/lib.rs (validates + enforces)
    |
    v
[Windows Enforcement] (WFP IOCTL, netsh, etc.)
    |
    v
[Forensics] ------- owner: forensics_engine.zig (immutable trace)
    |
    v
[Replay] ----------- owner: replay_engine.zig (read-only)
```

## Cross-Language Boundary Contracts

| From | To | Transport | Contract |
|---|---|---|---|
| Nose (Go) | Core (Zig) | named pipe / stdout JSON | CanonicalEvent JSON |
| Core (Zig) | Brain (Python) | UDP 9999 | Alert JSON |
| Core (Zig) | Shield (Rust) | FFI call | PolicyDecision struct |
| Core (Zig) | Bridge (C++) | named pipe | IpcEvent struct |
| Core (Zig) | Aggregator (Go) | NDJSON file | Forensic log lines |
| aegisctl (Python) | Core (Zig) | PID file + signal | Control request |
| aegisctl (Python) | Aggregator (Go) | HTTP :9200 | REST API |
| aegisctl (Python) | Brain (Python) | UDP 9999 | HEALTH JSON |
