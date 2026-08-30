# 08 - Testing Policy

## Test Layers

| Layer | Purpose | Gate |
|-------|---------|------|
| Unit | Test individual functions | Per-function |
| Integration | Test subsystem boundaries | Per-subsystem |
| Proof | Verify invariants (G1-G21) | Per-gate |
| Behavioral | Test end-to-end behavior | Per-feature |
| Cross-language | Test ABI/contract vectors | Per-contract |
| Benchmark | Measure performance | Per-regression |
| Stress | High-load verification | Per-release |

## CI Matrix (11 stages)

| Stage | Purpose | Hard Gate? |
|-------|---------|------------|
| 1. Repository hygiene | No backup files, no cache | YES |
| 2. Zig build/test | Core runtime | YES |
| 3. C/C++ build/test | Bridge, drivers | YES |
| 4. Rust build/test | Shield, mouth | YES |
| 5. Go build/test | Nose, aggregator | YES |
| 6. Python/Cython tests | Brain, RAG | YES |
| 7. Cross-language contract vectors | ABI, wire types | YES |
| 8. Static analysis | Lint, format | YES (hard) |
| 9. Security checks | Policy bypass, PEP integrity | YES |
| 10. Integration tests | End-to-end pipeline | YES |
| 11. Artifact/package validation | Build manifest | YES |

## Formatting

Formatting is a HARD gate (no `continue-on-error: true`).

```
zig fmt --check core/*.zig build.zig
```

## Proof Modules (G1-G21)

21 proof modules verify architecture contracts:

- G1-G3: Foundation (contract freeze, fabric accounting, runtime spine)
- G4-G10: Core pipeline (flow, detection, correlation, intelligence, brain, policy, PEP)
- G11-G18: Operations (forensic, config, health, audit, telemetry, SIEM, backup, performance)
- G19-G21: Compliance + docs + integration

Each proof module has 15-30 tests. All must pass.

## Definition of Done (Testing)

A task is complete only when:
- Unit tests pass
- Integration tests pass (if boundary changed)
- Proof module passes (if invariant touched)
- CI passes all 11 stages
