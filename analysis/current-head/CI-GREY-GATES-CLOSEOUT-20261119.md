# CI grey-gate closeout — 2026-11-19

**Target HEAD:** `3470da9` (release tip, also merged as `233b724` on `main`)
**Build source:** `f4cde3c503fd8b696183751a608b999768caa769` (unchanged)
**Signed candidate:** `release/T20-final/b597e71` (unchanged, not rebuilt, not re-signed)

## Problem

Both `codex/v1.1-release` and `main` were green except two permanently grey
(skipped) checks in `AEGIS CI`:

| Check | Old gate | Why grey |
|---|---|---|
| `Kernel Drivers Build (WDK, manual)` | `if: github.event_name == 'workflow_dispatch'` | `windows-latest` (win25-vs2026) intentionally has no standalone WDK headers/libs (`actions/runner-images#14263`). All three historical dispatch runs failed with `WDK Include\km not found`. |
| `Package Release` | `if: startsWith(github.ref,'refs/tags/v') && success()` | Tag-only; branch pushes skip it. Its last step is `softprops/action-gh-release@v2`, which creates a real GitHub Release and uploads the installer. |

Grey is not neutral here: it is an unverified gate. This patch makes both run
for real on every push without publishing anything before the soak, and without
faking a pass.

## Changes (all records/CI only)

### 1. Canonical WDK build, un-gated, fail-closed

- `runs-on: windows-2022` — the only hosted image that still ships the
  standalone WDK headers and `km` libraries (WDK `10.1.26100.4202`, SDK
  `10.0.26100.0`, verified against the runner-image manifest).
- Calls the authoritative build scripts from `build_truth.json`:
  `scripts/wdk_build_production.ps1` and `scripts/wdk_build_minifilter.ps1`.
  Both use `$ErrorActionPreference = 'Stop'` and `exit 1` on a failed
  compile/link, unlike legacy `scripts/build_drivers.bat`, which prints an
  error but exits 0 and writes to `build\Release` instead of the canonical
  `build\x64\...` paths.
- Explicit verification step requires both canonical outputs
  (`build/x64/wfp/aegis_wfp.sys`, `build/x64/minifilter/aegis_minifilter.sys`)
  to exist and be non-empty, then uploads them as `kernel_drivers`.
- `if: workflow_dispatch` removed. Job name is now `Kernel Drivers Build (WDK)`.

### 2. Package Release: build every push, publish only on tag

- Job-level `if` changed to `success()`; the job now always runs on push/PR.
- `needs` gains `drivers-wdk-build`.
- Artifacts are shared across jobs (new uploads: `runtime_exe`, `nose_exe`;
  `native_helpers` extended with `aegis_wfp_user.dll` and the `bridge/dist`
  outputs; `kernel_drivers` from the WDK job). A staging step reconstructs the
  canonical layout (`zig-out/bin`, `target/release`, `nose`, `dist`,
  `build/Release`, `build/x64/{wfp,minifilter}`) with hard `Need` assertions.
- `python tools/installer.py --package --output aegis_setup.exe` and
  `python tools/release_engineering.py --sbom` now run on every push; the
  installer file is explicitly verified as present and non-empty.
- `softprops/action-gh-release@v2` keeps its own
  `if: startsWith(github.ref,'refs/tags/v')`, so **no branch push can create a
  Release or publish an installer**.

## Invariants

- No source, build script, driver source, signed candidate or installer changed.
  `tools/truth.py verify` continues to report the build source as `f4cde3c`.
- `build_manifest.json` digest for `.github/workflows/ci.yml` is refreshed in a
  separate commit after the CI change, per the tool's committed-state rule.
- `softprops/action-gh-release` remains tag-gated; soak and the `v1.1` tag stay
  on hold.

## Verification performed

- `yaml.safe_load(.github/workflows/ci.yml)` — valid, 16 jobs.
- `python tools/ci_coverage.py` — every required project has a CI job; PASS.
- `python tools/release_engineering.py --verify` — 674/674 after digest refresh.
- `python tools/truth.py verify` — TRUTH_VALID, build source `f4cde3c`.
- CI on both tips (`codex/v1.1-release` and `main`) must show 0 failure and
  0 skipped check-runs; watcher logs:
  `admin-evidence/e5-clean-host-20261119-final/ci-grey-closeout-*.log`.

## Known limitation

This is E1/E3 evidence for the CI gates themselves, not a Windows-host driver
load proof. Driver install/signature verification remains E5 evidence from
RB-024 (`admin-evidence/e5-clean-host-20261119-final/RB-024-result.json`),
which is unchanged by this patch.

## Correction after first CI run (`44395854509`)

The first run proved the WDK job green on `windows-2022`, but exposed a
cross-job artifact-layout regression: adding `dist/*` files to `native_helpers`
moved upload-artifact's least-common-ancestor from `build/Release` to the repo
root, so the Zig job downloaded the import libraries as
`target/helpers/build/Release/aegis_fim_helper.lib` instead of the path
`build.zig` requires (`target/helpers/aegis_fim_helper.lib`). That reddened
`Zig Build & Test`, which then reddened `ci-matrix` and skipped
`Package Release`.

Fix (records/CI only):

- `native_helpers` now uploads only files under `build/Release` (the four
  original helper files plus `aegis_wfp_user.dll/.lib`), restoring the flat
  layout the canonical Zig link expects.
- The native bridge is built inside `package-release` itself
  (`cd bridge && cmake -B build && cmake --build build --config Release`),
  which produces `dist/aegis_ipc.dll` at the repo root; staging asserts it
  there and copies it to `zig-out/bin`.
- Staging paths changed from `native_helpers/build/Release/...` and
  `native_helpers/dist/aegis_ipc.dll` to `native_helpers/aegis_*.dll` and
  `dist/aegis_ipc.dll`.

All other invariants unchanged: no source/build/signed-candidate change,
publish remains tag-only, soak and tag remain on hold.
