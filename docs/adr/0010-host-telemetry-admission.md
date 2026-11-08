# ADR-0010 — Host telemetry admission under storm: isolate, protect, never guess

**Status:** Accepted
**Date:** 2026-11-06
**Supersedes:** —
**Superseded by:** —
**Owner:** AEGIS Core Team
**Related:** FLOW QLOSS-HEALTH-001, evidence `E5-DEPLOY-05EBBA0-RING4M`,
`QLOSS-QUEUE-BURST-20261106`, `QLOSS-FIM-STORM-20261106`,
`QLOSS-FAIRSHARE-001-E5-20261107`, `QLOSS-CRITICAL-001-E5-20261107`

---

## Context

The Windows host runtime pulls file/process telemetry from the minifilter ring
(4 MiB, `AEGIS_RING_SIZE`) into a 16,384-slot pipeline queue, and the pipeline
consumes it. On this host the consumer sustains **~1,325 drained rows/s**
(measured over 204.7 s of churn), while a 20,000-file churn demands on the order
of **14,000 events/s**. Producer-to-consumer is therefore about **10:1** during
a storm.

Four measured facts drove this ADR, in order:

1. **Per-event allow-row auditing was the original backpressure.** Removing it
   (`940714b`) took queue loss to zero over 143 s / 120 samples.
2. **The kernel ring burst-overflowed** (8,627 records / 157 s) while the reader
   drained ~1,250/s; a 1 MiB → 4 MiB ring removed it (`05ebba0`, `ring_dropped`
   0 ever since).
3. **Queue capacity is not the lever.** After instrumenting `depth_peak`
   (`86024fb`), a churn burst refused ~157,000 events; absorbing it would need
   roughly **36× the queue (~950 MB of static state)**.
4. **One source could silence another.** FIM alone shed 131,065 rows while ETW
   was refused behind it, so the host looked quiet rather than overloaded.

## Decision

Admission is layered, each layer answering one question, and every refusal is
attributed to a named counter:

| Layer | Constant | Question it answers |
|---|---|---|
| Network reserve | `RESERVED_NETWORK_SLOTS` = 1,024 | Can host telemetry starve the IDS network tail? (No) |
| Fair share | `SOURCE_OCCUPANCY_CAP` = working host tail / 2 = 7,168 | Can one host sensor blind another? (No) |
| Critical class | `CRITICAL_SLOTS` = 1,024, `WORKING_HOST_TAIL` = 14,336 | Can churn displace a write into a protected system tree? (No) |

Refusals are counted as `reserved_tail_shed`, `source_quota_shed`, or plain
`dropped_total`/full-queue, never silently. `queue.stats` reports `depth_peak`,
`source_occupancy_cap`, `critical_slots`, `critical_pushed_total`, and
per-source `active`.

**QLOSS-ISOLATION-002 (2026-11-07).** The fair share must be half of
`WORKING_HOST_TAIL` (14,336), not half of the whole host tail (15,360). The
earlier formula produced 7,680 per source, so two sources could claim 15,360
slots while the shared tail check refuses at 14,336: the second source was
stopped at 6,656 by the shared boundary before it ever reached its own 7,680
share — the same starvation the 80/20 split was rejected for, only smaller.
With 7,168 the two shares sum to exactly the working tail, so a second host
sensor always reaches its cap. This is pairwise isolation only; with three or
more host sources the sum of half-shares still exceeds the tail, so a dynamic
fair-share remains an open decision.

**E5 confirmation (2026-11-08).** The corrected cap is deployed (daemon
`C5991397...`, source `12093dd`) and measured, not just reasoned about: live
`queue.stats` reports `source_occupancy_cap=7168`, and a 90 s synthetic churn
(6 workers × 900 files, 56 samples) produced `fim_active_max 7168`,
`etw_active_max 7168`, `depth_peak 13,575`, `reserved_tail_shed 0`, and
`source_quota_shed 206,999` (FIM dropped 206,276 vs ETW 723, ring 0). Both
sources reached their full share and the shared boundary refused nothing, which
is exactly what the 7,680 formula made impossible (second source capped at
6,656). Total loss is unchanged in kind: every refusal is the storming source's
own excess, so this remains isolation, not loss reduction.

## Alternatives considered and rejected

**WAL / disk spill buffer.** Rejected as the primary answer. The measured
deficit is 10:1 and sustained, not a short spike: 180k spilled events would need
~2.3 minutes at 1,325 rows/s just to replay, so the backlog grows during the
storm and would need a byte cap anyway — which is loss with extra disk I/O. This
host already produced a 41 GB diagnostic log before `FileSink` rotation existed;
a second unbounded sink is a proven risk, not a hypothetical one. A capped WAL
remains a plausible *last* layer for short spikes only.

**More queue slots (16,384 → 32,768).** Rejected. It costs +26 MB of static
state and only moves the boundary: the same measurement showed a need for ~36×
the queue.

**80/20 per-source split.** Implemented, deployed, and rejected on its own
numbers (`QLOSS-FAIRSHARE-001-E5-20261107`): FIM drove total occupancy to the
shared boundary, where the boundary check refuses ETW **before** the per-source
cap is consulted, and ETW still lost 25,666 rows. 50/50 was chosen because it
keeps a real guarantee: another host sensor always has half the tail reachable.

**Dynamic work-conserving quota without preemption.** Rejected as unsound. With
a shared FIFO, borrowing idle space and a hard guarantee are mutually exclusive:
once the borrower fills the tail there is nothing to give back without evicting
queued events. Making it work requires either preemption (dropping the
borrower's queued rows, which changes forensic ordering) or separate queues per
class. Both are larger structural changes than this ADR authorises; they are
recorded as the open decision, not silently approximated.

## Consequences

- **Isolation, not zero loss.** The storming source still sheds its own excess
  (119k–181k rows in the synthetic churn), and total loss does not fall; what
  changes is *which* stream pays. A single-source host workload also gives up
  headroom it used to hold, because half the tail is reserved for others.
- **Protected writes are guaranteed slot access, not immunity from all loss.**
  Critical rows bypass the share and may use the 1,024-slot reserve; they are
  still bounded by the host tail and the absolute queue size.
- **The protection was not exercised adversarially.** Forcing a System32 storm
  would mean writing into protected system trees on this host, so the guarantee
  is proven at unit level (E2) and visible through `critical_pushed_total`
  (264 rows from natural activity), not by a live protected storm.
- **Operators read the cause, not just the count.** RB-006 documents the three
  refusal counters and warns that `depth` is a sample while `depth_peak` is the
  high-water mark, because drained bursts are invisible in the former.

## Correction (2026-11-07, after ReleaseSafe)

`zig build` defaulted to `.Debug`, so every binary that produced the numbers above
was unoptimized. Once the default became `.ReleaseSafe` (`61ef9b2`), the
forensic append mean fell from **217 us to 38 us** and a 60,000-file churn
sustained **2,930 rows/s with 439 drops (0.12%)**, ring 0, depth drained to 0
(`QLOSS-CONSUMER-001-E5-20261107`).

Two statements in this ADR are therefore revised, not deleted:

- The **1,325 rows/s** figure was a *saturated drain rate*, not the consumer's
  capacity. Capacity is at least 2,930 rows/s on this host.
- The **"10:1 producer/consumer gap"** used above to reject buffering was
  substantially an artifact of the Debug build. The conclusion that a sustained
  deficit cannot be buffered away still holds in principle, but the ratio that
  justified it was inflated, so WAL should be re-evaluated against a measured
  ReleaseSafe deficit rather than the old number.

What does not change: forensic append still dominates per-event cost (38 us of
the ~48 us `capture_to_decode` mean), so the next lever is inside that stage —
the 4 KiB zero/hash/CRC passes — not worker parallelism.

## Open work (explicitly out of scope here)

1. Reduce ingress volume at the sensor: FIM/ETW aggregation or debouncing for
   repeated file operations — the only lever that lowers the total. **ADR-0012
   (Proposed) now records the design, the measurement gate, and the alternatives
   rejected; it changes no runtime behaviour until that gate is measured.**
2. Raise consumer throughput (batching, worker pool, async offload) to narrow
   the 10:1 gap; the pipeline audit path is the suspected cost.
3. If work-conserving quota is still wanted, choose preemption or per-class
   queues first; do not approximate it with borrowing.
4. Production driver signing (the 4 MiB ring ships test-signed).

## Verification

- `zig build test --summary all`: 2,041 passed / 10 skipped / 0 failed.
- E5 deploys: `05ebba0` (27/27), `33be54a` (80/20 rejected), `fadc216` (27/27),
  `ad9733c` (28/28) — all with hash-verified rollback and unchanged
  detection-only posture (`prevention_gate=closed`, `tier3_enforcing=false`).
- Truth gates after each slice: `truth.py verify` TRUTH_VALID,
  `release_engineering.py --verify` 651/651, `pytest tests/docs tests/release`
  104 passed.
