# ADR-0012 - Runtime latency is measured with a monotonic clock, never the calendar clock

**Status:** Accepted
**Date:** 2026-11-08
**Supersedes:** -
**Superseded by:** -
**Owner:** AEGIS Core Team
**Related:** FLOW QLOSS-HEALTH-001, ADR-0011, evidence
`QLOSS-CLOCK-001-E5-20261108`, `QLOSS-CONSUMER-002-E5-20261107`

---

## Context

`aegisctl queue` reports per-stage latency, and every claim about the admission
path since ADR-0010 rests on those numbers. They were measured with
`std.time.nanoTimestamp()`.

That function is a calendar clock. Measured on the lab host:

| Probe | Result |
|---|---|
| 200,000 consecutive `nanoTimestamp()` reads | 199,997 returned the same value |
| Smallest non-zero step between two reads | 571,000 ns |
| SHA-256 over 4,060 B, 64 samples | 0 ns on every sample |

So any stage shorter than ~571 us measured as **0 ns**, and a stage that did take
time measured as 0 or as one tick, depending on whether an event happened to
straddle a tick boundary. The reported `mean` was therefore the tick size
weighted by the probability of straddling it, not a duration:

- `forensic_append` read p50 = 1 ns and p95 = 1 ns while the same code provably
  hashes and CRCs 4 KiB per event.
- The mean moved 28.65 us -> 18.08 us across the CRC32 change, which is a real
  direction but not a measurement of the append.
- ADR-0011's "217 us mean / 27.5 ms max" and the QLOSS-CONSUMER evidence built on
  the same broken instrument.

`src/core/perf_benchmark.zig` already documented the limitation for benchmark
code ("std.time.nanoTimestamp has only ~ms resolution on Windows and yields 0ns
elapsed for fast loops"). The runtime telemetry path never got the same
treatment. Two sources of truth about the same clock disagreed, and the shipped
one was wrong.

## Decision

Runtime **duration** marks read a monotonic high-resolution clock
(`src/reliability/monotonic_clock.zig`, `std.time.Timer` -> QueryPerformanceCounter
on Windows). Absolute **calendar** timestamps keep `std.time.nanoTimestamp()`,
because their meaning is wall-clock time and stored values must stay comparable
with records already on disk. The distinction is written in both files.

A guard test pins it: `src/tests/reliability/monotonic_clock.zig` fails if the
duration clock is not high resolution, or if it is coarser than the calendar
clock.

## Consequences

- Latency is now a duration. After the swap, `forensic_append` reports
  p50 16.4 us, p95/p99 32.8 us, mean 24.6 us over 396,555 events, with
  `dropped_total` 0 - a unimodal distribution, not a tick statistic.
- Every pre-2026-11-08 latency number in this repository is **approximate at
  best and must not be quoted as microseconds**. QLOSS-CONSUMER-002's E5 entry
  is annotated; the isolated E2 benchmark (which used `std.time.Timer`) stands.
- Watchdog and health thresholds that were tuned against inflated latencies
  should be re-read against the new numbers before they are tightened.
- The remaining overhead in the append is now measurable: 24.6 us measured
  against ~11 us of accounted passes, so ~13 us is still unnamed.
