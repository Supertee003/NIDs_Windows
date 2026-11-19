# CLOSURE-CI-RECONCILE-20261120 — Patch Record (E1/E2)

## Declaration

| Field | Value |
|---|---|
| PATCH-ID | CLOSURE-CI-RECONCILE-20261120 |
| FLOW-ID | RELEASE-GATES, CI-GATES, CAPTURE-ARBITRATION |
| TARGET HEAD | `dac8cd3` |
| FINAL HEAD | this commit |
| TARGET FILES | `build_manifest.json`, `tests/release/test_ci_gates.py`, `tests/release/test_historical_closures.py`, `EVIDENCE_INDEX.json`, this record |
| TARGET SYMBOLS | records/tests only; no product symbol changed |
| IN-SCOPE | reconcile three red release-gate pins against the current tree; refresh the 674-artifact digest snapshot to build source `a53eda8` |
| OUT-OF-SCOPE | `src/`, `drivers/`, `release/T20-final/b597e71`, installer, services, host, topology, load injection, soak window |
| CONTRACT IMPACT | none — no wire/ABI/schema change |
| ABI IMPACT | none |
| AUTHORITY IMPACT | none; detection-only, no host effect, PEP remains the sole WFP device reader |
| STATE IMPACT | none at runtime |
| TEST IMPACT | two stale test pins updated; release suite 201/201; full suite 1434 passed / 2 failed (E4 host-state only) |
| EVIDENCE IMPACT | +1 E1 entry (records + local build-staging); no E-level promotion |

## Why this patch exists

After the v1.1 slices were committed at build source `a53eda8`, three release
pins were red. Two were caused by the slices; one was pre-existing on the
main line:

| Pin | Disposition | Evidence |
|---|---|---|
| `test_ac3_verify_mode_detects_drift` + all three `fresh_deploy` plan tests | **slice-caused** — the slices changed 19 tracked `src/*`/`tools/*` files but the 674-artifact digest snapshot still held their `f4cde3c` digests | passes on pre-slice `f0baadf`, failed on `a53eda8`; `release_engineering.py --refresh-digests` re-recorded them, header stays `a53eda8` |
| `test_the_pep_is_still_the_only_importer_of_the_bridge` | **slice-caused** — RULE-COVERAGE-001 made `src/capture/wfp_telemetry.zig` import `wfp_ioctl.zig` for the pure `wfpTcpFlags` / `WFP_TCP_FLAGS_PRESENT` wire helpers | passes on pre-slice `f0baadf`; the device transport (`init`/`shutdown`/`isConnected`/`read_events`/`get_stats`) is still called only by `src/core/rust_pep.zig`, and EVT-039 still pins zero writable IOCTLs + a GENERIC_READ-only device open |
| `test_drivers_job_is_manual_only_until_a_run_is_verified` | **pre-existing main-line drift** — CI-GREY-GATES deliberately removed `if: workflow_dispatch` and the legacy `build_drivers.bat` and moved to `windows-2022` + authoritative WDK scripts; the pin still asserted the retired design | fails identically on pre-slice `f0baadf`; see `analysis/current-head/CI-GREY-GATES-CLOSEOUT-20261119.md` |

## Old flow → New flow

`release_engineering.py --verify` = FAIL (19 stale digests) → `fresh_deploy`
preflight aborts → 6 red release pins; WFP closure pin asserts a literal import
list that the capture layer legitimately grew; CI pin asserts a WDK job design
that CI-GREY-GATES retired
→
`--verify` = OK 674/674 at `source_commit=a53eda8`; `fresh_deploy --plan` runs;
WFP pin asserts the pure-helper allow-list **and** the stronger device-owner
invariant; CI pin asserts the current `windows-2022` / fail-closed WDK design.

## Invariant

Detection-only. No host effect, no WFP enforcement, one production runtime,
build source unchanged at `a53eda8`. The Rust PEP remains the only caller of
the WFP device transport. The terminal **SOAK_FAIL** verdict is untouched.

## Build result

No source change. Local-only build staging (untracked, gitignored, no host
effect) to give the runtime/installer tests a true signal:

- `cmake -B build -G Ninja && cmake --build build --config Release` → 3 C
  helper DLLs; `python tools/stage_helpers.py --stage` → staged into
  `zig-out/bin`.
- `cd bridge && cmake -B build && cmake --build build --config Release` →
  `dist/aegis_ipc.dll`, copied into `zig-out/bin`.
- Before staging, `aegis_nids.exe` failed to load with `0xC0000135`
  (missing `aegis_fim_helper.dll` / `aegis_etw_helper.dll`); after staging the
  runtime harness passes.

## Test result

| Command | Result |
|---|---|
| `python tools/release_engineering.py --verify` | OK — 674/674, `source_commit=a53eda8` |
| `python -m pytest tests/release -q` | 201 passed |
| `python -m pytest tests/runtime/test_harness_integration.py -q` | 3 passed, 2 skipped |
| `python tools/truth.py verify` | TRUTH_VALID — build source `a53eda8` |
| `python -m pytest -q` | 1434 passed, 29 skipped, 1 xfailed, 1 xpassed, **2 failed** |

The 2 remaining failures are `tests/integration/test_e4_live_pipeline.py::
test_every_surface_agrees_about_health` and
`::test_readiness_publishes_the_state_machine_and_never_degrades_anonymously`.
They probe the **installed** daemon, which is DEGRADED with
`failure_reasons=["degraded_without_named_component","state_degraded"]` on the
old candidate. They are host-state evidence, not a source regression; they are
not skipped or softened. `python scripts/check_summary.py` cannot resolve
`admin-evidence/*` pointers in this worktree (raw host artifacts live in the
main tree `D:\NIds_Windows`).

## Evidence level

E1 (records/CI pin reconciliation) + E2 (local native build staging). No E5.

## Rollback

Revert this commit and re-run `release_engineering.py --refresh-digests` if the
digest snapshot must match the prior tree. Build outputs are gitignored.

## Remaining risk / blockers

- The 2 E4 live-daemon failures stay red until a new signed candidate is
  installed in an owner-named fresh soak window.
- WDK driver rebuild and Windows E5 for slices 1-8 remain outstanding.
- `soak_24h` is still FAIL / NOT closed; release stays **NOT SHIPPABLE**.

## Completion gate

Release pins green, truth valid, no source or host change — **PASS (E1/E2)**.
