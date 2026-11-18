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

## Follow-up measurement: which pass inside the append actually costs

ADR-0010 left "38 us of the ~48 us `capture_to_decode` mean sits in
`forensic_append`" unresolved, with three candidate passes over the 4 KiB slot.
Measured individually at ReleaseSafe (4,000 records, 4,092 B CRC coverage,
`.work/bench_passes.zig`):

| Pass | Per record | Share |
|---|---|---|
| `@memset(slot, 0)` | 0.04 us | <1% |
| SHA-256 over 4,060 B | 2.53 us | 23% |
| **CRC32 over 4,092 B** | **7.60 us** | **69%** |
| composite | 11.05 us | - |

The assumed hotspot (SHA-256) was not the hotspot. `std.hash.Crc32` is a
byte-at-a-time table walk (~537 MB/s), so the cheapest integrity pass dominated
the most expensive one by 3x.

Resolution: `src/forensic/crc32_slicing.zig` computes the same ISO-HDLC function
eight bytes at a time (**7.62 us -> 1.85 us, 4.1x**). This is a speed
substitution, not a contract change - same polynomial, same refin/refout, same
init/xorout - so every record stays byte-identical, the hash chain is untouched,
and no stored vector had to be regenerated. Six tests in that module pin equality
against `std.hash.Crc32` as an oracle across every length up to 64 B, unaligned
windows, a full 4 KiB record, streamed splits, empty input, and the ISO-HDLC
check value `0xCBF43926`.

Rejected: the SSE4.2 `crc32` instruction (2-10x faster still) because it computes
**CRC-32C (Castagnoli)**, a different polynomial; using it would change every
stored CRC and therefore the forensic format. Hardcoding that shift was not worth
a format break to win ~1.4 us.

**Correction (ADR-0012).** The host figures below were read from a clock that
only advances every ~571 us, so they are tick-straddle statistics, not
durations - the direction of the change is real, the microseconds are not. The
quantified saving is the isolated E2 benchmark (`QLOSS-CONSUMER-002-E2`, measured
with `std.time.Timer`): 11.05 us -> 5.2 us per append. Re-measured with a
monotonic clock, the append now reports p50 16.4 us / mean 24.6 us
(`QLOSS-CLOCK-001-E5-20261108`).

Host observation from the coarse clock (E5, `QLOSS-CONSUMER-002-E5-20261107`):
installing the sliced build moved the reported `forensic_append` from **28.65 us
to 18.08 us mean (-36.9%, p99 524 us -> 262 us, max 19.9 ms -> 5.5 ms)** and
`capture_to_decode` from 36.03 to 28.17 us, with `dropped_total` 0 and readiness
`degraded=false / ready=true / overall_gate=true`.

Remaining: after the swap, append is ~18 us on the host with SHA-256 the largest
identified part (2.53 us isolated). Zig 0.13's `Sha256` has no SHA-NI dispatch, so
the next step would be a format-preserving hardware hash path, measured before
adopted. The gap between 18 us measured and ~11 us of accounted passes is
unnamed overhead (ring-wrap `@memset` of the tail region, mutex handoff, cache
misses) and is the real next target.
