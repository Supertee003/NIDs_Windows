# QLOSS delete filter — FIM-half storm measurement (elevated window)

**Created:** 2026-11-18
**Records HEAD:** `ca378ba` (build source `b600a25`)
**Measured on:** installed daemon `e32ba355…` (`C:\Program Files\AEGIS NIDS\runtime\aegis_nids.exe`), restarted into the proof-root configuration and then restored; PIDs `29084` → `23300`
**Level:** E5 (live host, detection-only, one elevated maintenance window)
**Gap:** `GAP-QLOSS-ISOLATION-002` / ADR-0014 option A, FIM half

---

## Purpose

The 2026-11-18 ETW-lane storm (`QLOSS-DELFILTER-002-E5-20261118`) covered only the
ETW `NameDelete` half of the `QLOSS-CRITICAL-001` stimulus. The baseline's other
half was FIM: 309,723 pushed / 271,887 dropped, plus 87,096 `source_quota_shed`
and 227,254 `reserved_tail_shed`. This run reproduces that half on the current
build: same 20,000-file churn, but the service is restarted with
`AEGIS_FIM_PROOF_ROOT` pointing at the storm directory so the
`ReadDirectoryChangesW` watcher and the minifilter both see the burst.

## Method

1. `[Environment]::SetEnvironmentVariable("AEGIS_FIM_PROOF_ROOT",
   "D:\tmp\aegis-fim-storm-20261118", "Machine")`, then stop/start `AegisNids`.
   The variable was absent before the run and is absent again after it.
2. Control batch: 100 zero-byte `*.tmp` files created, then deleted, with a
   queue snapshot between phases. This gives the per-operation notification
   yield for both lanes.
3. Storm: 20,004 files (6 workers), create then delete, with a 1 s
   `aegisctl queue --json` sampler running throughout.
4. Canary `fim-canary-20261118.locked` created and deleted after the storm.
5. Queue snapshots before/after each phase; settle loop until `depth` stayed 0
   for two consecutive seconds (settled in 2 s).
6. Restore: machine variable cleared, service stopped/started, new PID recorded,
   proof directory removed.

Script: `tools/_tmp_fim_storm_proof.ps1` (temporary, removed after the run).
Raw result: `D:\tmp\aegis-fim-result.json`.

## Counters (deltas)

Control batch (100 files):

| counter | create | delete |
|---|---|---|
| `fim_probe.native_poll.records` | +100 | +100 |
| `fim_probe.minifilter.records` | +159 | +168 |
| `fim_probe.batch_records` | +259 | +268 |
| `capture_fim.dropped` | 0 | 0 |
| `batch_overflow` | 0 | 0 |

The native watcher delivered exactly one notification per file operation in the
control batch. That is the expected yield used below.

Storm (20,004 files, create 2.39 s / delete 1.92 s):

| counter | before | after | delta |
|---|---|---|---|
| `capture_fim.pushed` | 777 | 42,297 | **+41,520** |
| `fim_probe.native_poll.records` | 200 | 1,367 | **+1,167** |
| `fim_probe.minifilter.records` | 577 | 40,930 | **+40,353** |
| `fim_probe.batch_records` | 777 | 42,297 | **+41,520** |
| `fim_probe.batch_duplicates` | 173 | 260 | +87 |
| `fim_probe.batch_overflow` | 0 | 0 | **0** |
| `dropped_total` | 0 | 0 | **0** |
| `shed_overload` | 0 | 0 | **0** |
| `source_quota_shed` | 0 | 0 | **0** |
| `reserved_tail_shed` | 0 | 0 | **0** |
| `minifilter.dropped` / `minifilter_pipeline_dropped` | 0 | 0 | **0** |
| `depth_peak` | 1,945 | 2,146 | +201 |
| `etw.file_name_delete` | 54,749 | 91,882 | **+37,133** |
| `etw.name_delete_filtered` | 54,732 | 91,840 | **+37,108** |
| `etw.delete_aggregate_events` | 250 | 251 | **+1** |

`batch_records` is exactly `native_poll.records + minifilter.records`
(1,167 + 40,353 = 41,520), so no FIM row was lost between the lanes and the
pipeline in this window.

## Detection evidence

`R1002` search after the canary returned 4 records: three `file_sensor`
canonical rows carrying rule id `3830763994` (79 B, 79 B, 58 B) and one
`host_telemetry` row at 459 B. The payload search for the canary name returned
the same 4 records plus one 459 B `host_telemetry` record with `rule_id = 0`,
which is consistent with the delete aggregate.

## Findings

1. **FIM half passes on this stimulus.** 41,520 FIM rows entered the pipeline
   with zero `dropped_total`, zero `shed_overload`, zero `source_quota_shed`,
   zero `reserved_tail_shed` and zero minifilter ring drops. Against the
   `QLOSS-CRITICAL-001` baseline (FIM 271,887 dropped, quota 87,096, tail
   227,254) that is the required strictly-below result.
2. **The ETW delete filter is active in the same window.** 37,108 deletes were
   filtered and one aggregate event was emitted; the canary still raised
   `R1002`.
3. **Stop-the-line finding — the native FIM helper truncated its own batch and
   counted nothing.** Based on the control yield, 20,004 creates + 20,004
   deletes should produce ~40,008 `native_poll` records. The storm produced
   **1,167 — 38,841 missing (97.1%)** — with `batch_overflow = 0` and no drop
   counter anywhere. The mechanism is in `src/windows/fim_native.c`: when the
   64 KiB `ReadDirectoryChangesW` buffer overflows, `GetOverlappedResult`
   succeeds with `bytes_returned == 0`, and the worker does `continue` without
   reading `ERROR_NOTIFY_ENUM_DIR` or incrementing anything
   (`src/windows/fim_native.c:112-132`). The minifilter lane covered the same
   operations (40,353 records ≈ 40,008 + ambient), so host FIM coverage held in
   this run, but the fallback watcher loses bursts silently and cannot be
   relied on at this rate.

## What this does not prove

1. Only one storm run; create/delete timings differ from the 180 s baseline
   window (2.39 s / 1.92 s here), so this is the same file count and shape, not
   the same wall-clock window.
2. The FIM yielded 41,520 rows here versus ~581,610 attempted in the
   2026-11-07 baseline (309,723 pushed + 271,887 dropped). The installed build
   dedups at batch level and the baseline ran on a different build; the
   comparison that matters for the gap is drops, not total rows.
3. `predecode_dropped` and ETW provider-side misses are unchanged and still
   uncounted by the product.
4. No 24 h soak; acceptance criterion 4 is still open.

## Next

* Only the 24 h soak remains for `GAP-QLOSS-ISOLATION-002` (owner scheduled it
  last).
* `GAP-FIM-NATIVE-OVERFLOW-003` (new, stop-the-line): count
  `ERROR_NOTIFY_ENUM_DIR` / zero-byte completions in the helper and surface a
  `fim_native_overflow` counter in `queue.stats`; then bound the rate or drain
  faster. Not fixed in this window.
