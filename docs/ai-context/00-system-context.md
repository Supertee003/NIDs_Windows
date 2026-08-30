# 00 - System Context

## System
AEGIS Windows security platform - multi-tier NIDS (Network Intrusion Detection System).

## Identity
Observation -> Canonical Semantics -> Stateful Context -> Evidence -> Decision -> Controlled Enforcement -> Immutable Trace -> Replay

## Architecture
- Zig core (runtime, event fabric, flow, detection, correlation, forensics)
- C/C++ bridge (IPC, Windows interop)
- Go nose (sensor ingestion, I/O concurrency)
- Rust shield (PEP, enforcement boundary)
- Python brain (advisory, RAG, analytics)
- Rust mouth (DEFCON TUI)

## Principles
1. ONE runtime spine (no competing paths)
2. ONE canonical event model (immutable after observation)
3. ONE state authority (flow engine)
4. ONE evidence model (detection produces, verdict aggregates)
5. ONE decision authority (policy decides, NOT executes)
6. ONE enforcement authority (Rust PEP, no bypass)
7. ONE forensic trace (immutable, hash-chained)
8. ONE replay path (deterministic regression)

## Current Phase
G1-G21 rewrite complete. G22 final polish complete. G23 consolidation phase (this document).

## References
- Canonical architecture: docs/architecture/ARCHITECTURE_CANONICAL.md
- Runtime spine: docs/architecture/RUNTIME_SPINE.md
- File registry: docs/architecture/FILE_REGISTRY.csv
