# Phase 4–6 Structure Implementation Report

**วันที่:** 17 กันยายน 2026  
**Target HEAD:** `46b93dcf9cca17b323ddff7a4c71e33e81c37fb5`  
**Scope:** Structural implementation only; group error/build sweep deferred by agreement

## Phase 4 — Acquisition and data plane

Added `src/pipeline/data_plane_contract.zig` with shared structural types for:

- acquisition source identity
- epoch/sequence event identity
- ingress counters
- submitted/processed/dropped conservation gap
- duplicate and non-monotonic identity counters

The contract intentionally does not replace the existing queue implementation yet. It provides the boundary that Go Nose, ETW, FIM, Registry, replay and the Zig queue will converge on.

Added fixture:

- `contracts/fixtures/data_plane/ingress_counters.json`

## Phase 5 — Detection and correlation

Added `src/detection/detection_result.zig` with a deterministic result structure containing:

- event identity
- detector kind
- detector version
- match status
- rule ID
- incident ID
- severity
- human-readable reason

Added fixture:

- `contracts/fixtures/detection/signature_match.json`

The existing event processor remains intact during this structure pass. The new result contract is the migration boundary for signature, anomaly, correlation and threat tracker output.

## Phase 6 — Rules and policy

Extended the existing `src/policy/policy_contract.zig` with `PolicyMetadata` and `PolicyMetadataStatus`:

- policy ID
- revision
- digest
- signer
- issued/expiry timestamps
- lifecycle status
- identity validation
- lifetime validation

This is additive and keeps the existing `PolicyEngine` and PEP contract source-compatible.

Added fixture:

- `contracts/fixtures/policy/active_policy.json`

## Test graph integration

The new modules are imported by `src/all_tests.zig`:

```text
pipeline/data_plane_contract.zig
detection/detection_result.zig
policy/policy_contract.zig
```

## Verification completed

Passed:

- Python tooling compilation.
- JSON parsing for all seven contract fixtures currently present.
- Targeted file existence and non-empty checks.
- `git diff --check` for Phase 4–6 changes.

Deferred by agreement:

- Zig formatter/build/test.
- Windows acquisition integration.
- Real producer-to-queue counter wiring.
- Detection processor migration to `DetectionResult`.
- Policy loader signature verification and atomic policy swap integration.
- Full Phase 4–6 error/build sweep.

## Status

```text
Phase 4 structure: implemented as data-plane boundary
Phase 5 structure: implemented as detection-result boundary
Phase 6 structure: implemented as policy metadata boundary
Group error sweep: deferred until Phase 4–6 structure is complete
Production readiness: not claimed
```

## Next structural work

Before the group sweep, connect the new boundaries to the active paths:

1. map queue/Nose counters to `IngressCounters`;
2. map processor signature/anomaly/correlation results to `DetectionResult`;
3. carry `PolicyMetadata` through loader, reload, evaluation and audit;
4. add negative fixtures for duplicate IDs, expired policy and malformed detection output;
5. then run the agreed single error/build/integration sweep for Phase 4–6.
