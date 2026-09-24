# Phase 1–3 Structure Implementation Report

**วันที่:** 17 กันยายน 2026  
**Target HEAD:** `46b93dcf9cca17b323ddff7a4c71e33e81c37fb5`  
**Scope:** Structural implementation only; group error sweep deferred by agreement

## Phase 1 — Runtime foundation

Implemented structural lifecycle metadata in `src/control/state_machine.zig`:

- Added explicit `FAILED` system state.
- Added `SystemState.canTransition(next)` legal-transition graph.
- Preserved the legacy `transition()` call shape so existing call sites are not rewritten during the structure pass.
- Added unit coverage for the intended lifecycle sequence:

```text
STOPPED → STARTING → READY → RUNNING → STOPPING → STOPPED
```

The checked transition graph is not yet the complete runtime transaction. Worker join, queue drain, forensic flush, SCM stop and Windows postconditions remain deferred to the later group verification.

## Phase 2 — Control-plane structure

Extended `src/control/protocol.zig` with versioned envelope metadata:

- `CONTROL_PROTOCOL_VERSION = 2`
- `CONTROL_NONCE_BYTES = 16`
- `protocol_version`
- `issued_at_ms`
- `nonce`

The existing command enum and dispatch path remain compatible during this structure pass. Wire parsing, nonce validation, caller authentication, SDDL and postcondition enforcement are intentionally not claimed complete yet.

## Phase 3 — Contract and ABI structure

Added `src/contract/abi_manifest.zig` and imported it into `src/all_tests.zig`.

The manifest explicitly distinguishes:

```text
canonical_event_v1      109 bytes  explicit little-endian wire fields
ipc_event_v5_internal     96 bytes  Zig extern internal event ABI
```

This prevents the two representations from being treated as interchangeable. Added tests assert both sizes and versions.

Added shared JSON fixtures:

- `contracts/fixtures/control/runtime_health_request.json`
- `contracts/fixtures/control/runtime_health_response.json`
- `contracts/fixtures/abi/event_boundaries.json`
- `contracts/fixtures/health/degraded_core.json`

## Verification completed

Passed:

- Python compilation of `tools/rebuild_truth.py` and `tools/create_manifest.py`.
- JSON parsing for all four new fixtures.
- Targeted artifact existence and non-empty checks.
- `git diff --check` for the changed Phase 1–3 files.

Deferred by agreement:

- Zig formatter/build/test.
- Windows SCM and named-pipe integration.
- Full control request parser migration.
- ABI cross-language compile/run vectors.
- Full Phase 0–3 error sweep.
- Current-head truth closure.

## Structural files changed/added

- `src/control/state_machine.zig`
- `src/control/protocol.zig`
- `src/contract/abi_manifest.zig`
- `src/all_tests.zig`
- `contracts/fixtures/control/runtime_health_request.json`
- `contracts/fixtures/control/runtime_health_response.json`
- `contracts/fixtures/abi/event_boundaries.json`
- `contracts/fixtures/health/degraded_core.json`

## Status

```text
Phase 1 structure: implemented, not runtime-verified
Phase 2 structure: implemented, not wire/security-verified
Phase 3 structure: implemented, static fixture checks passed
Group error sweep: deferred until Phase 0–3 structure is complete
Production readiness: not claimed
```

## Next structural work

Continue completing Phase 1–3 structure before group verification:

1. connect `canTransition` to the authoritative runtime mutation path;
2. make control envelope fields parse and serialize on the active named-pipe path;
3. add negative control/ABI fixtures;
4. add cross-language fixture readers;
5. then run the agreed single error/build/integration sweep for Phase 0–3.
