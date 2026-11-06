# ADR-0011 - Build optimization mode is a runtime property, not a developer preference

**Status:** Accepted
**Date:** 2026-11-07
**Supersedes:** -
**Superseded by:** -
**Owner:** AEGIS Core Team
**Related:** FLOW QLOSS-HEALTH-001, ADR-0010, evidence
`QLOSS-CONSUMER-001-E5-20261107`, `QLOSS-LIMIT-001-E5-20261107`

---

## Context

`zig build` defaulted to `.Debug` (`build.zig`, `b.option(...) orelse .Debug`).
Nothing in the build truth, the installer, or the acceptance checks looked at the
optimization mode, so every shipped daemon and every measurement taken from it
ran an unoptimized binary - for the whole admission investigation.

The cost only became visible after `action_to_forensic` was split into
`forensic_append` / `forensic_hash` / `receipt_issue` (`2729583`), which showed
append at **217 us mean / 27.5 ms max** while hash and receipt were 20 ns and
30 ns. A scratch benchmark then isolated the variable: appending a 4 KiB record
costs **34 us in Debug and 12 us in ReleaseSafe**, flat across 4-64 MiB rings and
32-1400 B payloads.

## Decision

`zig build` now defaults to **`.ReleaseSafe`**. Runtime safety checks stay
compiled in, so this is not a trade of correctness for speed; a debug session
passes `-Doptimize=Debug` explicitly. The shipped artifact hash changed with the
switch, and the install checks pin the expected binary, so a build-mode
regression would fail the deploy rather than silently ship.

## Consequences

Measured on the same host and the same synthetic churn:

| Load | Debug build | ReleaseSafe build |
|---|---|---|
| 20,000 files | 94,345 rows dropped | **0** dropped, depth_peak 4,075 |
| 60,000 files | not reached | 2,930 rows/s, 439 dropped (0.12%) |
| 120,000 files | not reached | **3,427 rows/s, 283 dropped (0.02%)**, ring 0, depth drained to 92 |

- **Forensic append is still the dominant per-event cost** (38 us of the ~48 us
  `capture_to_decode` mean), so the next lever is inside that stage - the 4 KiB
  zero/SHA-256/CRC32 passes - not worker parallelism.
- **Two earlier conclusions were revised** (recorded in ADR-0010): 1,325 rows/s
  was a saturated drain rate, not capacity, and the 10:1 producer/consumer ratio
  used to reject buffering was inflated by the Debug build.
- **The lesson is process-level, not cryptographic:** no amount of algorithmic
  tuning in the consumer would have helped while the compile mode was wrong, and
  nothing in the pipeline would have reported it. Instrumentation found it only
  because the stage was split finely enough to compare parts.

## Guards

1. `build.zig` documents why the default is `.ReleaseSafe`; a change back to
   `.Debug` must justify itself in review.
2. Installs verify the expected runtime hash, so a different build mode reaches
   the operator as a failed check, not as slow throughput.
3. Throughput claims must state the build mode. Every number in ADR-0010 taken
   before `61ef9b2` is Debug-build data.
