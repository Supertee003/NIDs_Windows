# Test Results — what is recorded, and what it proves

> These are **repository evidence records**, not a fresh run performed while writing this page.
> Each number carries the source artifact and the scope of what it actually proves. Do not merge
> counts from different commits into one "current run".

---

## 1. Historical full Python suite at `a53eda8` (two-phase, zero skips)

From
[`analysis/current-head/CAPTURE-LOOPBACK-002-FULLPATH-20261122.md`](../../analysis/current-head/CAPTURE-LOOPBACK-002-FULLPATH-20261122.md):

| Phase | Command / condition | Result |
|---|---|---|
| Phase 1 | daemon stopped (no host effects) | included in combined total |
| Phase 2 | `pytest -q --deselect tests/runtime/test_harness_integration.py::TestCoreLifecycle::test_core_reaches_running_within_startup_timeout` | **1470 passed, 1 deselected, 27 subtests passed** in 246.71 s |
| **Combined** | Phase 1 + Phase 2 | **1471 passed, 0 skipped, 0 xfail, 0 xpass, 27 subtests passed** |

This is the source of the "1,471 passed / 0 skipped" claim in the resume and README. It was a
**real full-suite run on the then-current source**, with one test deselected in phase 2 because it
requires the daemon lifecycle state that phase intentionally excludes. It is HISTORICAL at the
current build source `aa3b7b0`; the current-source local gate run is
`pytest -q -m "not host_live"` → **1520 passed, 1 skipped, 18 deselected, 27 subtests passed**,
recorded in `analysis/current-head/TEST-MATRIX-AA3B7B0-20261126.md`. No test was skipped or
xfailed to hide a failure: the two `host_live` tests require the installed current-source host and
passed only in the elevated owner run.

## 2. Zig suites — different recorded snapshots, not one merged number

`EVIDENCE_INDEX.json` records several distinct runs:

| Evidence entry | Zig result |
|---|---|
| Entry at line 44 | `zig build test --summary all` → **2116 passed / 11 skipped / 0 failed** (2127 total) |
| Entry at line 112 | `zig all_tests` → **2114 passed / 11 skipped / 0 failed** (2125 total) |
| Entry at line 172 | `zig unit suite` → **2109 passed / 11 skipped / 0 failed**; out-of-unit suite → **1234 passed** |
| Historical (`572ff13`) | 2034 passed / 10 skipped / 0 failed |

The 10–11 skips are pre-existing opt-in host/hardware cases
(`analysis/current-head/INGRESS-KIND-ATTRIBUTION-001-20261109.md`). State the count together with
its evidence entry; do not claim "zero skips" for Zig.

## 3. Release and soak (E7 / release record)

From
[`analysis/current-head/V1.1-RELEASE-CLOSEOUT-20261122.md`](../../analysis/current-head/V1.1-RELEASE-CLOSEOUT-20261122.md)
and [`SOAK-PASS-466A226-20261122.md`](../../analysis/current-head/SOAK-PASS-466A226-20261122.md).
**HISTORICAL at release identity `a53eda8`** relative to current build source `aa3b7b0`, whose board is **5/6 PASS, `soak_24h` OPEN, NOT SHIPPABLE**; `release/release-status.json` now separates the immutable release board from `current_head_board`.

| Item | Recorded result |
|---|---|
| Release gates | **SHIPPABLE — 6/6 PASS (0 open)**; single status source: `release/release-status.json` |
| Published tag | annotated `v1.1` → tag object `0b9287b`, commit `dd8647d` |
| Signed candidate | `466a226`; build source `a53eda8` |
| Manifest verification | **674/674 artifacts** |
| `SHA256SUMS` digest | `A053C048C8B373CF93E766D9C54F54D191B33D273627075A6121516591E4996C` |
| Download-back verification | all four public release assets byte-compared against locally verified originals |
| Soak verdict | **PASS**, `elapsed/required = 36.52 / 24.0 h`, `problems=[]`, `scm_restarts=[]` |
| Soak counters | `queue_dropped_total`, `nose_frames_rejected/dropped/pipe_errors`, `minifilter_ring_dropped`, `minifilter_pipeline_dropped`, `shed_overload` — all **0 during that window** |
| Services | AegisNids, AegisAggregator, AegisWfp, AegisMinifilter all RUNNING; daemon `RUNNING`, not DEGRADED |

**Scope limit:** the zero-loss statement applies to that specific soak window. The current lab host
shows nonzero counters in a different window — see [Observed performance](../portfolio/OBSERVED_PERFORMANCE.md).

## 4. Detection evidence

| Test | Result |
|---|---|
| Rule catalog / evaluable coverage | **23/23** (E2 pins) / **23/23** (code paths) — see [Detection catalog](../portfolio/DETECTION_CATALOG.md) |
| Host-positive proof | **L4 family only**; R9006 has E5 + E6 proof with a 118,632-row zero-false-positive control |
| Demo window | bounded 40-SYN burst → `VERDICT: PASS (exit 0)`, 1 attributed row, 1 × R9006, drop/shed/quota deltas 0 |
| Negative controls | 10-port negative control → zero hits; R3003 E5 ambient negative observation |
| R2003 | **no host-positive proof in the original FN-1 census** (ProcessStart v0–v4 had no `CommandLine`); at `aa3b7b0` a narrow E5 re-measurement has one positive row and two negative controls — see `analysis/current-head/R2003-CMDLINE-HOST-PROOF-E5-AA3B7B0-20261126.md`; full matrix not re-measured |
| Control-plane fail-closed probe | invalid requests rejected without an enforcement receipt (`scripts/run_control_receipt_probe.py`) |
| Import hygiene | `tests/brain/test_import_hygiene.py` — no import-time host effects |

**Do not claim** all 23 rules are live-proven, and **do not** treat synthetic fixtures as sensor proof.

## 5. Controlled component benchmarks (T17 — historical gate record)

From [`docs/gates/T17_benchmark_results.md`](../gates/T17_benchmark_results.md), measured with
`perf_benchmark_cli quick` (`-O ReleaseFast`), 100 iterations. Thresholds passed.

| Suite | ops/sec | µs/op | Threshold |
|---|---:|---:|---:|
| ProcessTracker (100 creates) | 20,200 | 49.51 | 1,000 PASS |
| FileIntegrityStore (50 baselines) | 145,582 | 6.87 | 500 PASS |
| RegistryWatchQueue (100 enqueues) | 100,857 | 9.92 | 5,000 PASS |
| Federation codec (10 encode+decode) | 1,049,318 | 0.95 | 10,000 PASS |
| CrossNodeAggregator (50 reports) | 191,058 | 5.23 | 1,000 PASS |
| Full pipeline (4 events) | 33,573 | 29.79 | 500 PASS |

p50/p95/p99 for the same suites are recorded in the T17 file (full pipeline **29.7 / 30.0 / 31.7 µs**).
These are **component benchmarks**, not proof of a maximum sustainable events/sec for the whole
product, and they were not re-run while writing this page.

## 6. Test pyramid — status by level

| Level | What exists | What is missing / open |
|---|---|---|
| Unit | Zig suites, Python contract/security tests, Go golden-path codec tests, FNV-1a pin | Rust codec is TBD; no authoritative MITRE mapping |
| Integration | Go→Zig pipe, canonical codec parity, event→detection, detection→forensics, CLI→daemon | Active control IPC has no nonce/replay enforcement |
| System | E5 Windows host observe proof, loopback full-path self-test, install/boot preflight gates | No clean-install/uninstall campaign in this dataset |
| Negative | malformed IPC, invalid rule, missing sensor, forensic tamper checks, control fail-closed probe | No exhaustive fuzz campaign published here |
| Performance | T17 component benchmarks, live snapshot stage latencies | No fixed-rate offered-load ceiling; see [Observed performance](../portfolio/OBSERVED_PERFORMANCE.md) |

## 7. Limitations to say out loud

1. The current lab host reports `minifilter_ring_dropped=1,341,156` and `alert_file.failed=7,028`
   at the 2026-11-23 snapshot — see observed performance. Do not claim zero loss on this host.
2. `zig build test --summary all` still records 11 skips in current evidence; only the combined
   **Python** run reached zero skips.
3. `forensics.replay` is integrity-only and does not re-execute detection (see
   [Security boundaries](../architecture/SECURITY_BOUNDARIES.md)).
4. WFP source scope changes have E1 code-level analysis only; no WDK build, E5, or soak for that
   newer source.
5. No build, test, soak, release download, or truth verification was re-run by the author of this
   summary page.

---

*See also: [Detection catalog](../portfolio/DETECTION_CATALOG.md) ·
[Observed performance](../portfolio/OBSERVED_PERFORMANCE.md) ·
[Failure matrix](../OPERATIONAL_FAILURE_MATRIX.md)*
