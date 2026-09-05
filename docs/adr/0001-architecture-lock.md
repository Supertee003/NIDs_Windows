# ADR-0001: Architecture Lock

**Status:** Accepted  
**Date:** 2026-09-02  

## Context

AEGIS NIDs Windows has grown organically through 110+ commits across 7 languages.
The repository contains 89 .zig files in core/, multiple proof modules, test
harnesses, and production code mixed together. Without a locked architecture,
further development risks competing pipelines, authority violations, security
bypasses, and unverifiable runtime behavior.

## Decision

Lock the architecture as defined in the AEGIS Machine diagram. No ownership
changes are permitted without a new ADR.

### Ownership Invariants (Immutable)

| Position | Owner Module | Language | Authority |
|---|---|---|---|
| Canonical Event | core/canonical_event.zig | Zig | One schema authority |
| Event Fabric | core/event_fabric.zig | Zig | One queue authority |
| Flow State | core/flow_engine.zig | Zig | One mutable flow-state authority |
| Detection | core/detection_engine.zig | Zig | Evidence producer only |
| Verdict | core/dispatcher.zig | Zig | Evidence to verdict aggregation |
| Correlation | core/correlation_engine.zig | Zig | Context/incident association |
| Threat Intel | core/threat_intel_engine.zig | Zig | External intelligence enrichment |
| RAG | core/rag_engine.zig | Zig | Context enrichment only |
| Brain | brain/windows_brain.py | Python | Advisory only |
| Policy | core/policy_engine.zig | Zig | Final decision authority |
| Rust PEP | shield/src/lib.rs | Rust | Final enforcement authority |
| Forensics | core/forensics_engine.zig | Zig | Immutable trace |
| aegisctl | scripts/aegisctl.py | Python | Requests only, never bypasses PEP |

### Pipeline Order (Canonical)

OBSERVE -> CANONICAL EVENT -> STATE -> EVIDENCE -> INTELLIGENCE
-> ADVISORY -> POLICY -> RUST AUTHORIZATION -> WINDOWS ENFORCEMENT
-> IMMUTABLE TRACE -> REPLAY

### Dispatcher as Sole Orchestrator

core/dispatcher.zig is the ONLY production runtime orchestrator.
core/nids_analyze.zig is legacy and must not compete.

### Production vs Test Separation

Production lifecycle initializes ONLY: Forensics, Event Fabric, Nose, Flow,
Detection, Verdict, Correlation, Threat Intel, RAG, Brain, Policy, PEP,
Telemetry/Health. Test/proof modules must be in separate test profiles.

## Consequences

1. Any change to ownership requires a new ADR
2. aegisctl must NOT directly modify enforcement state
3. Policy signing must use real crypto, not FNV-1a
4. RAG must appear in dispatcher runtime trace
5. Production executable must not initialize test harnesses
6. Legacy nids_analyze.zig must be audited and migrated or removed

## References

- docs/architecture/component-inventory.md
- docs/architecture/authority-map.md
- docs/architecture/runtime-path.md
- docs/architecture/legacy-map.md
