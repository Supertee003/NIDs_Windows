# 04 - Contracts

Each contract has ONE authoritative definition.

## Contracts (12)

1. CanonicalEvent - core/canonical_event.zig (immutable after observation)
2. Wire/ABI - core/wire_event.zig (fixed width, explicit endian, no pointers)
3. DetectionEvidence - core/detection_engine.zig (evidence producer only)
4. AggregatedVerdict - core/verdict_aggregator.zig (6 states: benign/observe/suspicious/malicious/unknown/error)
5. CorrelationResult - core/correlation_engine.zig (9 entity types, 8 relationships, LOCKED schema)
6. ThreatContext - core/threat_intel.zig (operational: IOC IP/domain/hash/reputation)
7. BrainAdvice - core/brain_engine.zig (advisory only, fail-soft, cannot enforce)
8. PolicyDecision - core/policy_engine.zig (decides, NOT executes)
9. EnforcementPlan - core/policy_engine.zig -> Rust (validated before execution)
10. EnforcementResult - core/rust_pep.zig (7 statuses, never single success flag)
11. ForensicRecord - core/forensics_engine.zig (complete decision trace, immutable)
12. AuditRecord - core/audit_trail_proof.zig (hash-chained, tamper-evident)

## Rule
Do NOT add decision state to CanonicalEvent. Use new objects for each stage's output.

## Version Freeze
- Event Schema: Frozen (G1)
- Wire Protocol: Frozen (G1)
- Policy IR: Frozen (G9)
- Detection Rules: Hot-reloadable (G12)
- Policy Set: Frozen + signed (G9)
