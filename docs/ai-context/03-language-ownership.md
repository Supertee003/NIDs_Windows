# 03 - Language Ownership

| Language | Owns | Forbidden |
|----------|------|-----------|
| Zig | Runtime, event fabric, flow, detection, correlation, lifecycle, Windows coord | Policy authority, direct enforcement |
| C | Stable ABI, wire types, fixed-width primitives, native headers | Business logic |
| C++ | Native adapters, Windows interop, legacy bridge, transport adapter | Becoming thinner |
| Go | Nose, collectors, event ingestion, I/O concurrency, aggregation | Policy authority |
| Rust | Crypto/trust (Ed25519, TLS), detection-only PEP evaluation, authorization evidence, federation TLS | Policy decisions, detection logic, host effects |
| Python | Brain orchestration, RAG, analytics, experiments, model lifecycle | Direct enforcement |
| Cython | Feature extraction, hot loops, numeric preprocessing, Brain perf | Policy decisions |

## Rule
Each language has exactly ONE authority domain. No language can create a host-effect authority; Rust PEP is detection-only and no host action is authorized.

## Build Systems
- CMake: C/C++ native
- Zig build: Core
- Cargo: Rust (shield, mouth)
- Go: Nose/Aggregator
- Python/Cython: Brain
