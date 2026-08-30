# 03 - Language Ownership

| Language | Owns | Forbidden |
|----------|------|-----------|
| Zig | Runtime, event fabric, flow, detection, correlation, lifecycle, Windows coord | Policy authority, direct enforcement |
| C | Stable ABI, wire types, fixed-width primitives, native headers | Business logic |
| C++ | Native adapters, Windows interop, legacy bridge, transport adapter | Becoming thinner |
| Go | Nose, collectors, event ingestion, I/O concurrency, aggregation | Policy authority |
| Rust | Security boundary, policy verification, PEP, enforcement, privileged state, rollback | Policy decisions, detection |
| Python | Brain orchestration, RAG, analytics, experiments, model lifecycle | Direct enforcement |
| Cython | Feature extraction, hot loops, numeric preprocessing, Brain perf | Policy decisions |

## Rule
Each language has exactly ONE authority domain. No language can bypass Rust PEP for enforcement.

## Build Systems
- CMake: C/C++ native
- Zig build: Core
- Cargo: Rust (shield, mouth)
- Go: Nose/Aggregator
- Python/Cython: Brain
