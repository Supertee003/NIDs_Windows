# 05 - Data Lifecycle

## Event Flow

```
Source -> Nose -> CanonicalEvent -> Validation -> EventFabric -> Flow -> Detection -> Evidence -> Verdict -> Correlation -> Intelligence -> Policy -> EnforcementPlan -> Rust PEP -> Action -> Forensics -> Replay
```

## State Transitions (Event Fabric)

| State | Description |
|-------|-------------|
| accepted | Event entered fabric |
| processed | Event completed pipeline |
| source_dropped | Nose dropped (intentional sampling) |
| queue_dropped | Fabric dropped (congestion) |
| rejected | Validation failed |
| expired | Timeout |

## Sampling vs Queue Overflow

- NOSE = intentional sampling (controlled)
- FABRIC = congestion handling (backpressure)

These are conceptually separate.

## Flow Lifecycle

```
FlowKey -> hash -> bucket -> FlowState (atomic upsert)
  -> timeout -> eviction (bounded capacity)
  -> snapshot API (no mutable pointer after lock release)
```

## Forensic Recording

Records entire decision trace:
- source, event, flow, evidence, verdict, correlation
- threat_intel, brain, policy, decision, pep, action, result

With versions:
- schema_version, ruleset_version, detector_version
- brain_version, intel_version, policy_version

## Replay

```
historical event + ruleset v1 + policy v1
  -> compare with same event + ruleset v2 + policy v2
  -> deterministic result
```

## Immutability Rules

- CanonicalEvent: immutable after observation
- ForensicRecord: immutable, hash-chained, append-only
- AuditRecord: immutable, hash-chained, tamper-evident
- Snapshot: immutable, content-addressed
