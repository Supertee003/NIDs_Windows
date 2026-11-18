# RETIRE-HOST-EFFECT-001 — Detection-only host-effect retirement (issue #25)

**Patch ID:** RETIRE-HOST-EFFECT-001
**Flow ID:** IDS-WFP-001 / IDS-PEP-001
**Target source:** `bb5d780` (post-patch source commit is recorded by the truth maps)
**Evidence level:** E2 (unit/build proof; Windows E5 NOT_PROVEN)

## Decision

AEGIS is a detection-only IDS. The confirmed product decision is that no
production path may request, install, or confirm a host effect. This patch
removes the last reachable production path to a WFP filter instead of leaving
it "gated but present".

## Old flow -> new flow

**Old:** Zig policy -> Rust PEP `aegis_pep_enforce` -> `adapter_cache` ->
`adapter.block_flow` -> bridge -> `IOCTL_AEGIS_BLOCK_FLOW` ->
`AegisWfpBlockFlow` -> `FwpmFilterAdd0(FWP_ACTION_BLOCK)` -> `filter_id`
receipt.

**New:** Zig policy -> Rust PEP `aegis_pep_enforce` classifies BLOCK/QUARANTINE
as `DECISION_ESCALATE` reason `8` with `filter_id = 0`; the adapter is never
probed or called. The driver dispatch rejects `IOCTL_AEGIS_BLOCK_FLOW` with
`STATUS_NOT_SUPPORTED`, so even a legacy/foreign caller cannot reach
`AegisWfpBlockFlow`. Capture callouts remain `FWP_ACTION_PERMIT` only.
`IOCTL_AEGIS_UNBLOCK_FLOW` (and the PEP unblock exports) stay for ABI stability
and cleanup-only use.

## Files changed

| File | Change |
|---|---|
| `drivers/wfp_callout/aegis_wfp.c` | Block IOCTL dispatch hard-fails as `STATUS_NOT_SUPPORTED`; legacy handler retained but unreachable |
| `rust-src/lib.rs` | `aegis_pep_enforce` never calls `adapter.block_flow`/`with_adapter`; BLOCK/QUARANTINE -> ESCALATE reason 8, `filter_id = 0`; legacy `Adapter`/`block_flow` marked `#[allow(dead_code)]` |
| `tests/wfp/test_t11_wfp_enforcement.py` | Rewritten as the detection-only contract: driver hard-fail, no adapter call, permit-only callouts, no Zig transport, manifest invariants |
| `tests/wfp/test_t11_windows_host.py` | Host tests now require ESCALATE reason 8 and `filter_id = 0` for BLOCK/QUARANTINE |
| `scripts/run_g2_dupfilter_proof.ps1` | Retired the duplicate-filter host proof; now proves detection-only output markers |
| `tools/create_manifest.py` | Authority invariants state the retired host effect and the hard-fail IOCTL |
| `tools/golden_path_evidence.py`, `tools/release_candidate.py` | Wording matches the detection-only runtime |
| `runtime_manifest.json` | Regenerated from the above |
| ADR-0001/0002/0009, `docs/ai-context/00,06`, `docs/architecture/*`, `docs/ARCHITECTURE.md`, `docs/FILE_CLASSIFICATION.md`, `docs/WFP_IOCTL_STATUS.md`, `docs/USER_OPERATIONS_GUIDE.md`, `docs/PORTABLE_DEPLOYMENT_AND_WSL2_TESTING.md` | Authority wording updated; historical notes preserved |
| `tests/pep/test_t8_rust_pep.py`, `tests/security/test_t16_security_hardening.py`, `tests/contracts/test_pep_abi_layout.py`, `tests/docs/test_stale_doc_sweep.py` | Docstrings/comments updated to the detection-only boundary |

## Invariant

1. `aegis_pep_enforce` contains no `block_flow` or `with_adapter` reference.
2. Driver dispatch contains no `status = AegisWfpBlockFlow(Irp);`.
3. `IOCTL_AEGIS_BLOCK_FLOW` dispatch returns `STATUS_NOT_SUPPORTED`.
4. Capture callout classify actions are exactly `{FWP_ACTION_PERMIT}`.
5. `runtime_manifest.json` authority invariants say the Rust PEP is
   detection-only and the block IOCTL is unsupported.
6. No Zig module calls `wfp_ioctl.block_ip`/`unblock_ip`.

## Build / test result

- `scripts/wdk_build_production.ps1` — PASS. Output
  `build/x64/wfp/aegis_wfp.sys`, 41,472 bytes,
  SHA-256 `2ECE7D52DEBFD45DC15FF381B659CE7391C4A4DF89B65746D8F4B5103988C71C`
  (only the pre-existing `ExAllocatePoolWithTag` C4996 warnings).
- `cargo build --release` — PASS, no warnings.
- `cargo test` — 51 passed / 1 ignored + 3 passed, RC 0.
- `zig build` — PASS.
- `zig build test` — PASS (RC 0).
- `python -m pytest -q` — 1018 passed, 4 skipped, 27 subtests passed.
- Focused `tests/wfp tests/pep tests/security/test_t16_security_hardening.py
  tests/contracts/test_pep_abi_layout.py tests/docs/test_stale_doc_sweep.py`
  — 91 passed, 3 skipped.

## Windows / host result

NONE. The new driver is compiled but not deployed or loaded, the services
`AegisWfp`/`AegisMinifilter` remain stopped, and no elevated run was performed
in this patch. Windows E5 remains NOT_PROVEN. Tests that would need the host
are skipped unless `AEGIS_RUN_WFP_HOST_TESTS=1`.

## Rollback

Revert the patch and rebuild `build/x64/wfp/aegis_wfp.sys` plus
`target/release/aegis_pep.dll`; re-run `python tools/rebuild_truth.py`. No data
migration or on-host state is involved because no filter is ever created.

## Remaining risk / open items

- ABI compatibility is preserved intentionally: the block symbol and IOCTL
  still exist and are documented as unsupported, so a stale caller receives
  `STATUS_NOT_SUPPORTED` rather than an ABI break.
- `aegis_pep_unblock_filter` still calls the adapter for cleanup of legacy
  filters; it can never create one.
- E5/E7, production driver signing, #28, #29, #30 remain open and out of scope
  for this patch.
