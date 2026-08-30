# 02 - Runtime Spine

Single runtime path. No competing paths allowed.

## Stages (12)

```
1. Nose (OBSERVE) - Go/C - sensor ingestion
2. Canonical Event (NORMALIZE) - Zig - immutable
3. Validation (NORMALIZE) - Zig
4. Event Fabric (SCHEDULE) - Zig - priority queue
5. Flow/State (STATE) - Zig - atomic upsert
6. Detection (DETECT) - Zig - evidence producer
7. Verdict (DETECT) - Zig + Brain advisory - 6-state
8. Correlation (CORRELATE) - Zig - entity graph (9 types)
9. Intelligence (INTELLIGENCE) - Zig + Python - TI + RAG
10. Policy (DECIDE) - Zig - decides, NOT executes
11. Rust PEP (ENFORCE) - Rust - validate + execute + defer
12. Forensics (REMEMBER) - Zig - immutable, hash-chained
13. Replay (REMEMBER) - Zig - deterministic
```

## Authority
- Orchestrator: core/dispatcher.zig
- Lifecycle: core/lifecycle.zig
- Main: nids_main.zig (bootstrap only)

## Rule
Dispatcher = orchestrator, NOT a second monolith. If processEvent() is too large, split into processFlow(), processDetection(), etc.
