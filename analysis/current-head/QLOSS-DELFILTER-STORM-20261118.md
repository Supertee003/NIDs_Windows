# QLOSS delete filter — ETW-lane storm measurement

**Created:** 2026-11-18
**Records HEAD:** `f751592` (build source `b600a25`)
**Measured on:** installed daemon `e32ba355…` (sha256 of `C:\Program Files\AEGIS NIDS\runtime\aegis_nids.exe` = `zig-out/bin/aegis_nids.exe`), service RUNNING, PIDs unchanged
**Level:** E5 (live host, no restart, detection-only)
**Gap:** `GAP-QLOSS-ISOLATION-002` / ADR-0014 option A, delete half

---

## Purpose

The existing option-A evidence (`QLOSS-DELFILTER-001-E5-20261118`) proved that a
noise delete is filtered and a rule-visible delete passes, but it did not run a
storm and it predates the delete-aggregate patch (`9c9f22f`). This measurement
answers the two open questions for the ETW half:

1. does the filter hold under a 20,000-file delete burst without queue or ring
   loss, and
2. does a mass delete still leave one visible aggregate record and does `R1002`
   still fire?

## Method

* Scratch root `D:\tmp\aegis-storm-20261118` (never a watched system path).
* 20,000 one-byte files (`*.tmp`), 6 writer/deleter workers, created then
  deleted; timings 1.9 s create / 0.9 s delete.
* `aegisctl queue --json` sampled every 2 s for the window.
* Canary `D:\tmp\aegis-canary-20261118\del.locked` created and deleted before the
  storm; a second canary was run after the storm.
* Ring searched with `forensic search --field payload_contains --value
  delete-aggregate` and `--field rule --value R1002`.

## Counters (cumulative; delta = after − before)

| counter | before | after | delta |
|---|---|---|---|
| `etw.file_name_delete` | 24,361 | 33,164 | **+8,803** |
| `etw.name_delete_filtered` | 23,930 | 32,731 | **+8,801** |
| `etw.delete_aggregate_events` | 186 | 188 | **+2** |
| `dropped_total` | 0 | 0 | **0** |
| `shed_overload` | 0 | 0 | **0** |
| `source_quota_shed` | 0 | 0 | **0** |
| `reserved_tail_shed` | 0 | 0 | **0** |
| `minifilter.dropped` | 0 | 0 | **0** |
| `minifilter_pipeline_dropped` | 0 | 0 | **0** |
| `depth_peak` | 1,358 | 1,805 | +447 |
| `pushed_total` | 974,351 | 1,018,042 | +43,691 |

`depth_peak` and `pushed_total` include ambient registry/network traffic during
the same window, not only the churn.

## Detection evidence

* Aggregate: 1 record whose payload contains `delete-aggregate`
  (`host_telemetry`, 222 B). The window counter is also visible in
  `queue.stats` (`delete_aggregate_events`).
* `R1002` before the storm: 2 records (the existing canary row plus the new
  `del.locked` delete).
* `R1002` after the storm: a fresh `post.locked` canary produced 2 new records
  (sequence 1,047,868 and 1,047,869, `file_sensor`, 66 B each). The earlier
  post-storm search returned 0 only because the ring retention is minutes long;
  the fresh canary is the actual check.

## What this proves

1. Under this delete burst the ETW delete filter keeps 8,801 rows out of the
   pipeline, the aggregate path emits, and **no queue, quota, tail or ring loss
   is recorded**.
2. A rule-visible delete still reaches the kernel-file automaton before and
   after the storm (`R1002`).
3. The reduction is visible (counter + aggregate row), not silent.

## What this does not prove (why the gap stays OPEN)

1. **Only the ETW half of the stimulus.** The QLOSS baseline
   (`QLOSS-CRITICAL-001-E5-20261107`) also produced ~309k FIM rows because the
   service was deployed with the storm root as its FIM proof root. FIM currently
   watches `C:\Windows\System32` and `SysWOW64`; a `D:\tmp` churn is not seen by
   that lane. Reproducing the baseline needs `AEGIS_FIM_PROOF_ROOT` plus a
   service restart — an elevated maintenance window this session does not have.
2. **The provider saw 8,803 of 20,000 deletes.** 22k deletes/s is faster than
   this ETW provider delivered; provider-side misses have no product counter and
   are not claimed as filtered. A paced re-run (or a provider statistics source)
   is needed before any "all deletes accounted for" statement.
3. **No 24 h soak.** Acceptance criterion 4 is still pending, and the soak must
   run alone on the new build.
4. No source change was made in this measurement; the daemon is the installed
   `e32ba355…` image.

## Next

* Elevated maintenance window: set the FIM proof root, repeat the same 20,000
  churn, compare total drops and `shed_overload` to
  `QLOSS-CRITICAL-001` (FIM 271,887 dropped / ETW 42,456 dropped / quota_shed
  87,096 / tail_shed 227,254 in that baseline).
* If that passes, the only remaining gate is the 24 h soak with
  `--loss-budget 3500 --shed-budget 20000`.
