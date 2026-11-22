# CAPTURE-LOOPBACK-002 — full-path loopback capture with 5-tuple attribution

**Date:** 2026-11-22
**Branch:** `codex/loopback-capture-v2.1.0` (from `a9f8664`)
**Build source commit:** `a53eda8344a20f86ad4f4e4001e9b3d648067671` (unchanged — records/test-only slice)
**Result:** PASS, E5 (live host, attributable), **no source, wire, rule, or authority change**

## Claim

With the canonical Go Nose sensor pinned to `\\Device\\NPF_Loopback`, a local
SYN burst reaches the full detection path and produces an R9006 forensic row
that names the exact test-owned source IP and ephemeral source port. A
below-threshold control produces no such row. This closes the *full-path*
portion that CAPTURE-LOOPBACK-001 explicitly left as a runbook choice; the
raw-capability portion was already closed at E5 on 2026-11-17.

## Runtime setup (operator, Admin PowerShell)

The single-owner control pipe required stopping the old service/orphan first:

1. `python tools\aegisctl.py stop` (service `AegisNids` stopped; orphan nose PID 7476 removed by owner)
2. Core from the worktree, with `AEGIS_DAEMON_IFACE` **unset** (direct Zig Npcap disabled):
   `.\zig-out\bin\aegis_nids.exe` — new PID 31340, `RUNNING`
3. Nose pinned full capture (not `-capture-probe`):
   `nose\aegis-nose.exe -capture -iface '\Device\NPF_Loopback' -require-iface`

Nose device enumeration confirmed `#10 name=\Device\NPF_Loopback description="Adapter for loopback traffic capture"`.

## Stimulus and proof

`admin-evidence/loopback-fullpath-20261122/loopback_proof.py` (raw transcript:
`proof-run.txt`) ran against the live CLI and core log:

| Step | Measurement | Result |
|---|---|---|
| Positive burst: 40 SYNs `127.0.0.2 → 127.0.0.1:24000..24039` | 40 sockets bound, all 40 destination ports emitted | PASS |
| Canonical ingress `queue.stats → capture_npcap.pushed` | **+101** frames submitted to Zig | PASS |
| Core NDJSON new rows read from byte offset | 7 rows | — |
| R9006 (`rule="1745456278"`) row with `src_ip="127.0.0.2"` and `src_port` in the test-owned socket set | **1 hit**, e.g. `src_port=62158`, `session_id=1304`, `event_id=1382` | PASS |
| Hit enforcement fields | `enforcement_status="observed"`, `host_effect_confirmed=false` | detection-only invariant holds |
| Negative control: 10 SYNs `127.0.0.3 → 127.0.0.1:24100..24109` (below threshold 20) | **0** attributable R9006 rows | PASS |

The attribution is exact: the row must carry the dedicated source IP *and* an
ephemeral port that the test's own sockets bound. Ambient host traffic cannot
satisfy it (the 2026-11-14 window measured +52 ambient anomalies).

## Test changes (records-only)

- `tests/integration/loopback_attribution.py` (new): shared, stdlib-only helpers
  for source-pinned SYN bursts, byte-offset core-log reads, exact 5-tuple R9006
  matching, and the `capture_npcap.pushed` ingress counter.
- `tests/integration/test_e6_l4_scan_detection.py`: removed the `xfail(strict=False)`
  marker; the test now asserts the attributable hit, ingress advance, the
  below-threshold negative control, and `host_effect_confirmed is False`.
- `tests/integration/test_e6_attack_burst.py`: removed the xfail marker from
  `test_a_localhost_port_scan_is_captured_and_scored`; it now requires the same
  attributable hit plus ingress/forensic/anomaly counter movement and the
  negative control. The host-effect invariant test remains independent.
- `scripts/kali_attacks/` (operator-generated, gitignored): 23 scripts regenerated
  from the repo's own `release/T20-final/7234d7a/scripts/gen_kali_22.py` generator.
  `tests/lab/test_kali_script_coverage.py`: 3 passed.

No `SOURCE_PATHS` file changed. `python tools/truth.py verify` → `TRUTH_VALID`,
build source still `a53eda8`. No rebuild, no re-sign, no re-soak, no version bump,
no tag/push/publish.

## Verification

| Check | Result |
|---|---|
| Manual proof script | `PROOF PASS` (exit 0) |
| `pytest tests/integration/test_e6_l4_scan_detection.py tests/integration/test_e6_attack_burst.py` | 4 passed in 60.39 s |
| `pytest tests/lab/test_kali_script_coverage.py` | 3 passed |
| Full `pytest -q -rA` (before skip closure) | 1467 passed, 4 skipped, 27 subtests passed (0 xfail, 0 xpass) in 345 s |
| WFP host tests (`tests/wfp/conftest.py` auto-enables when real DLL + driver exist) | **4 passed** — `DETECTION_ONLY_*` on the real PEP, ABIs pinned, no host effect |
| Phase 1 — no daemon: `pytest tests/runtime/test_harness_integration.py::TestCoreLifecycle::test_core_reaches_running_within_startup_timeout` | **1 passed in 5.26 s** (core started by the test itself, reached RUNNING within timeout) |
| Phase 2 — daemon running (core from `zig-out`, nose pinned to NPF_Loopback): `pytest -q --deselect 'tests/runtime/test_harness_integration.py::TestCoreLifecycle::test_core_reaches_running_within_startup_timeout'` | **1470 passed, 1 deselected, 27 subtests passed** in 246.71 s (0 skipped, 0 failed, 0 xfail, 0 xpass) |
| **Combined (Phase 1 + Phase 2)** | **1471 passed, 0 skipped, 0 xfail, 0 xpass, 27 subtests passed** |
| `python tools/truth.py verify` | `TRUTH_VALID` |

All four prior skips are now closed without weakening an assertion:

- **3 × WFP host skips** — `tests/wfp/conftest.py` enables
  `AEGIS_RUN_WFP_HOST_TESTS=1` only when `target/release/aegis_pep.dll` and
  `%SystemRoot%\System32\drivers\aegis_wfp.sys` are real files on Windows. CI on
  non-Windows or without the artifacts still skips. The tests still load the
  actual DLL and prove detection-only (`ESCALATE` reason 8, `filter_id == 0`, no
  WFP filter). Measured hashes: PEP `BFAAAA22…`, driver `B26AC754…`.
- **1 × control-pipe skip** — the runtime is genuinely single-owner, so one pytest
  process cannot both start its own core and use the operator's running core. It is
  proven in two honest phases: Phase 1 with no daemon (the test starts its own core
  and passes), Phase 2 with the daemon the loopback tests require (the test is
  deselected, never skipped or marked passed). The two runs cover every collected
  test exactly once. The deselect is recorded in the command, not hidden behind a
  marker edit.

## Limits

- One host, one interface (`\\Device\\NPF_Loopback`), one rule (R9006), one stimulus
  class (TCP SYN burst). No L7 payload claim, no remote Kali claim, no enforcement
  claim.
- Loopback remains a **self-test binding**, not the production default; production
  keeps the real link. This slice did not change selection policy.
- The raw probe evidence (CAPTURE-LOOPBACK-001-E5-20261117) was recorded at `d74ca100`,
  a historical build source; this record re-proves the full path at `a53eda8` identity.
