# Phase 7–9 Structure Implementation Report

**วันที่:** 17 กันยายน 2026  
**Target HEAD:** `46b93dcf9cca17b323ddff7a4c71e33e81c37fb5`  
**Scope:** Structural implementation only; group error/build sweep deferred by agreement

## Phase 7 — PEP/WFP enforcement

Added `src/policy/enforcement_receipt.zig` with an explicit separation between:

```text
decision
→ provider action
→ host effect confirmation
→ enforcement receipt
```

The contract distinguishes:

- pending
- enforced
- failed
- unavailable
- rolled back
- simulated

A receipt is successful only when the status is `enforced` **and** the host effect is confirmed. This prevents a PEP decision or WFP request from being reported as a completed block before the host result is known.

Added fixture:

- `contracts/fixtures/enforcement/wfp_receipt.json`

The existing Rust PEP and C WFP implementation remain unchanged during this structure pass. The new receipt is the migration boundary for their integration.

## Phase 8 — Windows adapters and deployment boundary

Added `src/windows/adapter_contract.zig` with:

- adapter kind
- adapter readiness state
- provider version
- capability mask
- error/degraded code
- heartbeat timestamps
- adapter profile required/available capability checks

The real adapter modules discovered in the repository are:

```text
src/windows/aegis_wfp.c
src/windows/wfp_ioctl.c
src/windows/windows_adapters.zig
src/windows/etw_realtime.zig
src/windows/fim.zig
src/capture/nose_pipe_reader.zig
src/windows/cpp_adapter.zig
```

No duplicate `wfp_filter.zig` was created because it does not exist in the current source tree.

Added fixture:

- `contracts/fixtures/adapters/degraded_etw.json`

## Phase 9 — Forensic and replay

Added `src/forensic/replay_contract.zig` with an explicit observe-only safety boundary:

- replay ID
- source digest
- replay mode
- host mutation prohibition
- enforcement-attempt counter
- safe outcome predicate

A replay request is safe only when host mutation is disabled and the source is identified. A replay outcome is observe-only only when no enforcement attempt occurred.

The existing forensic hash-chain and replay comparison implementations remain intact during this structure pass.

Added fixture:

- `contracts/fixtures/replay/observe_only.json`

## Test graph integration

The new modules are imported by `src/all_tests.zig`:

```text
policy/enforcement_receipt.zig
windows/adapter_contract.zig
forensic/replay_contract.zig
```

## Verification completed

Passed:

- Python tooling compilation.
- JSON parsing for all ten contract fixtures currently present.
- Targeted file existence and non-empty checks.
- `git diff --check` for Phase 7–9 changes.

Deferred by agreement:

- Zig formatter/build/test.
- Rust PEP and C WFP runtime integration.
- Windows driver/filter host-effect verification.
- Adapter startup/heartbeat integration.
- Replay execution proving zero enforcement calls.
- Full Phase 7–9 error/build/integration sweep.

## Status

```text
Phase 7 structure: enforcement receipt boundary implemented
Phase 8 structure: adapter readiness/profile boundary implemented
Phase 9 structure: replay observe-only boundary implemented
Group error sweep: deferred until Phase 7–9 structure is complete
Production readiness: not claimed
```

## Next structural work

Before the group sweep, connect the new boundaries to active paths:

1. carry `EnforcementReceipt` from Rust PEP/WFP result to audit/forensic output;
2. map Windows adapter startup and heartbeat data into `AdapterStatus`;
3. enforce `ReplayRequest.isSafe()` before invoking replay execution;
4. add negative fixtures for unavailable WFP, adapter dependency failure and replay mutation attempts;
5. then run the agreed single error/build/integration sweep for Phase 7–9.
