# 01 - Semantic Map

Every source file belongs to exactly ONE semantic position.

## Positions

| Position | Responsibility | Examples |
|----------|---------------|----------|
| OBSERVE | Collect data from Windows/network/host | nose/, drivers/ |
| NORMALIZE | Validate and convert source info to Canonical Events | core/canonical_event.zig |
| TRANSPORT | Move data between processes/components | core/wire_event.zig, bridge/ |
| SCHEDULE | Queue, priority, backpressure, dispatch | core/event_fabric.zig |
| STATE | Flow/session/entity state | core/flow_engine.zig |
| DETECT | Generate evidence | core/detection_engine.zig |
| CORRELATE | Combine events/entities into context or incidents | core/correlation_engine.zig |
| INTELLIGENCE | Threat intel, Brain, RAG, contextual enrichment | core/threat_intel.zig, brain/ |
| DECIDE | Policy and decision planning | core/policy_engine.zig |
| ENFORCE | PEP and privileged actions | shield/ (Rust) |
| REMEMBER | Forensics, audit, replay | core/forensics_engine.zig |
| OPERATE | Lifecycle, health, metrics, deployment, config | core/lifecycle.zig, core/dispatcher.zig |
| PROVE | Tests, proof modules, fault injection, benchmarks | core/*_proof.zig, tests/ |

## Rule
A file must have exactly one primary classification. If a file spans multiple positions, split it.
