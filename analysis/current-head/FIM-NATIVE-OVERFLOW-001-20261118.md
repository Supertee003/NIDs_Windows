# FIM native watcher — overflow counter and re-measurement

**Created:** 2026-11-18
**Source HEAD:** `aa42fca` (truth maps `d52c618`)
**Deployed:** `aegis_nids.exe` `a02fc7fb…`, `aegis_fim_helper.dll` `5a047ce6…` (backup of `e32ba355…` / `5275ed8b…` in `D:\tmp\aegis-fim-fix-backup-20261118`)
**Level:** E5 (live host, detection-only, one elevated window)
**Gap:** `GAP-FIM-NATIVE-OVERFLOW-003`

---

## Why

`QLOSS-FIMSTORM-003-E5-20261118` showed the native `ReadDirectoryChangesW`
watcher delivering 1,167 notifications for ~40,008 file operations while every
loss counter read zero. The mechanism was `src/windows/fim_native.c`: a
directory buffer overflow completes with `bytes_returned == 0` (or
`ERROR_NOTIFY_ENUM_DIR`), and both paths did `continue` as if no data existed.

## Change

* `src/windows/fim_native.c` — a per-session `overflow_batches` (LONG64) is
  incremented on both overflow paths; exported as
  `aegis_fim_overflow_count()`.
* `src/windows/fim.zig` — `FimWatcher.takeOverflow()` sums the live sessions and
  returns only the new batches.
* `src/pipeline/telemetry_threads.zig` — the FIM thread publishes that delta to
  `state.g_fim_native_overflow`.
* `src/pipeline/runtime_state.zig` — new atomic, documented as distinct from the
  duplicate probe's `g_fim_batch_overflow`.
* `src/control/handler_registry.zig` — `fim_probe.native_overflow` in
  `queue.stats`, with the schema assertion extended.
* `src/pipeline/event_processor.zig` — stale comment corrected (Npcap **and** the
  Go Nose v3 lane carry full Ethernet payloads; both map to `.capture_npcap`).

Build/test: `zig build` green; `zig build test --summary all` = 3,335 passed /
10 skipped / 0 failed.

## Method

Elevated script (temporary) with a hash-verified backup of both installed
binaries, stop service, install the new build, set
`AEGIS_FIM_PROOF_ROOT=D:\tmp\aegis-fim-storm-20261118b`, start, run a 100-file
control batch, then the same 20,004-file storm, canary, sampler, restore the
machine env and restart. The new build stays installed; rollback is the hashed
backup above.

## Results

Control batch (100 files): `native_poll.records` +100 (create) and +100
(delete); `native_overflow` **0** in both phases; pipeline drops 0.

Storm (20,004 files, create 1.72 s / delete 1.61 s):

| counter | delta |
|---|---|
| `capture_fim.pushed` | **+40,328** |
| `fim_probe.minifilter.records` | **+40,320** |
| `fim_probe.native_poll.records` | **+8** |
| `fim_probe.native_overflow` | **+7** |
| `fim_probe.batch_records` | +40,328 |
| `dropped_total` / `shed_overload` | 0 / 0 |
| `source_quota_shed` / `reserved_tail_shed` | 0 / 0 |
| `minifilter.dropped` / `minifilter_pipeline_dropped` | 0 / 0 |
| `depth_peak` | +1,131 |

Canary `fimfix-canary-20261118.locked`: payload search returned the canary name
in 4 `file_sensor` rows with rule id `3830763994` plus one 559 B
`host_telemetry` row; the `R1002` search returned those 4 `file_sensor` rows.

## What this proves

1. The silent path is gone: a storm that previously reported zero losses now
   reports **7 discarded batches** in `queue.stats`, while the control batch
   reports zero. A reader can distinguish "idle" from "lost a batch".
2. Host FIM coverage still held: the minifilter lane delivered 40,320 records
   for the same operations, the pipeline recorded no drops, and `R1002` fired.
3. The corrected comment matches the Nose v3 payload path.

## Honest limits and decision

* The counter counts **batches**, not records. Windows discards the whole
  buffer on overflow, so the number of notifications inside a lost batch is not
  recoverable; seven batches over a ~3.3 s burst is consistent with one
  discarded request per ~500 ms poll tick. This is why the lane cannot claim a
  record-level loss budget.
* The 500 ms poll cadence is the actual throughput bound: one 64 KiB batch per
  tick, regardless of the counter. That is a separate throughput change, not
  part of this slice.
* **Decision:** the native watcher stays as a *counted fallback*, not the
  primary FIM lane. Production coverage relies on the minifilter (proven here
  and in the earlier storm), and the native overflow is now a visible counter.
  Retiring or re-tuning the lane is left to a future change with its own soak.
* The installed daemon is a local unsigned build; a release cut must rebuild
  and re-sign (the existing v1.1 distribution item).
