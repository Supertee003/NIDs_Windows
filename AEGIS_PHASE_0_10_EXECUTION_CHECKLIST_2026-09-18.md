# AEGIS Phase 0–10 Execution Checklist

## Frozen authority boundaries

`CanonicalEvent` and `event_id` originate at the verified ingress/Core boundary. Cython and Python produce only `DetectionResult` metadata. Tier routing selects `POLICY`, `COMPLETE`, `TIER3`, or `FAIL_CLOSED`; it does not select a host effect. Rust Shield/PEP is the sole policy authority. WFP/provider attests host effect. `EnforcementReceipt` is the authoritative result evidence, and Mouth consumes validated receipt/evidence rather than raw policy text or logs.

## Frozen status semantics

`MATCH` means a detector found an explainable match. `NO_MATCH` means the scanner completed without a match. `UNKNOWN` means the scanner cannot conclude. `ERROR` means the scanner failed. `UNAVAILABLE` means a required scanner/dependency is unavailable. Only `ENFORCED` with `host_effect_confirmed=true` and provider evidence may represent a host effect.

## Execution order

| Phase | Work | Gate |
|---|---|---|
| 0 | Freeze contracts and baseline | Schema and authority review |
| 1 | Connect Cython/Python scanner to DetectionResult | Python/Cython parity |
| 2 | Connect Tier routing to Core | Event conservation and deterministic route |
| 3 | Define Tier-3 request/result and unavailable path | No silent drop; fail-closed fallback |
| 4 | Connect policy route to Rust Shield/PEP | PEP remains sole policy authority |
| 5 | Persist receipt/evidence through ForensicRing | Identity and hash-chain verification |
| 6 | Make Mouth consume receipt/evidence | No false BLOCKED |
| 7 | Full integration scenarios | Observe, match, unknown, unavailable, WFP unavailable |
| 8 | Lifecycle/recovery acceptance | Restart recovery and forensic preservation |
| 9 | Tier-3 runtime readiness | Artifact, dependencies, provider, timeout |
| 10 | WFP host-effect gated proof | Provider and host postcondition only |

## Current truth

Native Zig and Go results were reported as exit code 0. Python contract suite has passed 25 tests. Observe-only runtime proof passed with Rust Shield READY, WFP unavailable, Tier-3 stopped, forensic chain verified, zero blocks, and zero errors. Phase 9 and Phase 10 remain gated and must not be inferred from those results.
