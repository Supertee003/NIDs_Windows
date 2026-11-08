# FIM-PROBE-IDENTITY-COMMENT-001

PATCH-ID: FIM-PROBE-IDENTITY-COMMENT-001
FLOW-ID: QLOSS-HEALTH-001 (FIM ingress -> candidate duplicate measurement -> queue admission)
TARGET HEAD: 1f14d7eb27c1d91e374cf456974f0cdbed1dd100
FINAL SOURCE HEAD: 795246d7b4794b11c9b45e0b17a43c6cb219602a
FILES CHANGED: `src/pipeline/fim_dedup.zig`, `src/capture/minifilter_reader.zig`
TARGET SYMBOLS: `fim_dedup.Entry.ts`, timestamp probe test, minifilter measurement loop

## Scope and contract

- IN-SCOPE: Correct comments/test naming so timestamp equality is described as a candidate measurement key, not proof that two observations share a callback identity.
- OUT-OF-SCOPE: Any event suppression/coalescing, driver ABI or record layout changes, throughput policy, ring/queue behavior, and live VM deployment.
- CONTRACT IMPACT: None; the probe key and counters are unchanged.
- ABI IMPACT: None.
- AUTHORITY IMPACT: None; no detection or enforcement authority changed.
- STATE IMPACT: None; all rows continue to be submitted to the pipeline.
- TEST IMPACT: Targeted standalone FIM probe tests.
- EVIDENCE IMPACT: Add E2 source/test evidence and preserve #29 stop-line as open.

## Result

OLD FLOW: repeated `(path, kind, pid, timestamp)` key was described as an identical callback, despite the producer identity contract not proving that claim.
NEW FLOW: same key is counted as a repeated measurement key only; every row still reaches `submitRecord` and no suppression is performed.

INVARIANT: A measurement collision can never suppress or discard a minifilter observation.
BUILD RESULT: `zig build` PASS.
TEST RESULT: `zig test src/pipeline/fim_dedup.zig` PASS (7/7).
DIFF CHECK: `git diff --check` PASS.
WINDOWS RESULT: Not applicable; no live host change or deployment.
EVIDENCE LEVEL: E2 for probe contract tests; no higher-level claim.
EVIDENCE ARTIFACTS: `analysis/current-head/FIM-PROBE-IDENTITY-COMMENT-001-20261109.md`.

## Closure and remaining work

ROLLBACK: Revert source commit `795246d`; behavior is unchanged by this documentation/test-label correction.
REMAINING RISK: Timestamp equality still does not establish event identity. #29 telemetry loss and any safe coalescing approach remain unresolved.
OPEN BLOCKERS: Driver-provided stable identity or a different lossless throughput/admission solution; corrected E5 evidence is still required before considering suppression.
COMPLETION GATE: PASS for this comment/probe-contract clarification only; issue #29 remains OPEN.
