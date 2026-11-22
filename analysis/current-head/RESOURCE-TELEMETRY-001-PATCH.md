# RESOURCE-TELEMETRY-001 — Patch Record (E2)

## Declaration

| Field | Value |
|---|---|
| PATCH-ID | RESOURCE-TELEMETRY-001 |
| FLOW-ID | OBS-001 (control-plane health projection) |
| TARGET HEAD | `aff6f86` |
| FINAL HEAD | `f3a5200` |
| TARGET FILES | `src/windows/resource_telemetry.zig` (new), `src/control/state_machine.zig`, `src/all_tests.zig`, `tools/aegisctl/api/control_api.py`, `tools/aegisctl/web_dashboard/app.py`, `tests/runtime/test_health.py`, `tests/tools/test_web_dashboard.py`, `analysis/current-head/OWNER-DECISIONS-EXTENDED-20261119.md` |
| TARGET SYMBOLS | `current`, `cpuPercent`, `json`, `healthJson`, `_daemon_resources`, `renderOverview` |
| IN-SCOPE | sampled process CPU%/memory, control-query-only read, additive health field, loopback KPI display |
| OUT-OF-SCOPE | event hot path, DEFCON/data-loss coupling, enforcement, host effects, build.zig/CMake changes, E5 host attribution |
| CONTRACT IMPACT | additive `health.resources` object; old readers ignore it |
| ABI IMPACT | none (no CanonicalEvent wire change) |
| AUTHORITY IMPACT | observe-only; no enforcement/PEP/path authority moved |
| STATE IMPACT | module-local cached sample (500 ms min interval), no pipeline state |
| TEST IMPACT | 7 pure Zig tests; 5 health projection tests; 1 dashboard DOM test |
| EVIDENCE IMPACT | E2 only; EVIDENCE_INDEX entry `RESOURCE-TELEMETRY-001-E2-20261119` |

## Old flow → New flow

`control health (no resource data) → dashboard shows no CPU/RAM`
→
`control query → healthJson → resource_telemetry.current() (Win32 pulled, cached) → additive health.resources → typed Python projection → loopback dashboard KPI (unknown shown as —)`

## Invariant

No per-event Win32 call. First sample `cpu_percent=null, seeded=false`; NaN/Inf/non-monotonic ticks map to null; 1 core = 100%; missing/malformed block stays empty (never fabricated zero). Gauges never gate detection, DEFCON, or enforcement.

## Verification

- `zig fmt` PASS; `zig build` PASS; `zig build test --summary all` PASS (2123/2134 at commit time, later 2128/2139)
- `python -m pytest tests/runtime/test_health.py -q` 40 passed; `tests/tools/test_web_dashboard.py` 22 passed
- Full pytest after the following slices: 1417 passed (4 unrelated ratchet/doc failures fixed in records)

## Evidence level

E2. No E5 claim: no CPU sample is attributed to the installed soak candidate.

## Rollback

Revert `f3a5200`; remove `src/windows/resource_telemetry.zig` and the additive health/CLI/dashboard blocks.

## Remaining risk / blockers

- Windows host attribution (`E5`) requires the owner-installed signed candidate and a fresh soak window.
- Multi-core normalization is deliberately per-core; operators must not read >100% as a fault.

## Completion gate

Zig + Python targeted suites PASS, no wire change, no hot-path sampling, no enforcement coupling — **PASS (E2)**.
