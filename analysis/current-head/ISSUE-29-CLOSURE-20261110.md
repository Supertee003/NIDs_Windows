# ISSUE-29 CLOSURE — held 4,000 op-sets/s with zero drops (E5)

**Record ID:** ISSUE-29-CLOSURE-20261110
**Flow ID:** QLOSS (host telemetry ingress admission)
**Source commit:** `c79c5a1` (deployed build `ED74E56F…`)
**Evidence level:** E5 (Windows host, current source, hash-asserted deploy)
**Window:** `admin-evidence/host-window-005-20261110/`

## Acceptance criterion

The owner's #29 criterion: **zero drops at sustained 4,000 FIM file-ops/s**,
where one op-set is a complete open + write + close + unlink.

## Result

| Run | Held rate | Op-sets | New drops | State |
|---|---|---|---|---|
| 90 s acceptance | **3,999.9/s** | 359,996 | **0** | RUNNING (not degraded) |
| 300 s sustained | **4,000.0/s** | 1,199,998 | **0** | RUNNING (not degraded) |

Every counter that can represent loss stayed at zero through both runs:

```
queue_dropped_total          0
minifilter_pipeline_dropped  0
minifilter_ring_dropped      0
nose_frames_dropped          0
nose_frames_rejected         0
nose_pipe_errors             0
source_quota_shed            0
reserved_tail_shed           0
```

Queue occupancy never approached the limits: `depth_peak = 5,754` of
`16,384`, and the per-source share (`source_occupancy_cap = 7,168`) was never
reached — `pace_waits = 0`.

## What actually fixed it

1. **ETW-FILE-DEDUPE-001 (the fix).** The minifilter already emits one
   `capture_fim` row per `IRP_MJ_CREATE`; the ETW Kernel-File `NameCreate` copy
   was pure duplicate work and was the lane that died. Suppressing it while the
   minifilter is `ok` removed ~1.55 M queue pushes in the 5-minute window:
   `etw.name_create_deduped = 1,549,792`, `etw.file_name_create = 0`.
   Writes and deletes — which the minifilter does **not** emit — were untouched
   (`file_write = 1,631,789`, `file_name_delete = 1,500,699`).
2. **PACE-MF-001 (the safety net, not the fix).** The minifilter reader can now
   pause instead of overflowing its own share. Measured `pace_waits = 0`, so it
   never had to engage in these windows; it exists so a future burst degrades
   into latency instead of loss.

## Why the earlier window failed (and what it taught)

The 90 s run at 3,887.5/s on 2026-11-10 lost 20,430 rows (`capture_fim 19,700`)
with `source_quota_shed = 100,700` and `depth_peak 13,621`. That daemon had just
absorbed a 6,383 op-sets/s burst (2.7 M events) from the un-throttled generator,
so the ingress ring still carried that backlog when the next window started.
From a clean counter set, the same rate and then 4,000/s absorb without reaching
the share cap. The conclusion is therefore stated precisely:

- **4,000 op-sets/s from a clean start: PASS.**
- **A 6,383 op-sets/s burst still sheds** — the zero-loss ceiling of this build
  is now between 4,000 and 6,383 op-sets/s, not "unbounded".
- The earlier "4,008.6/s zero drops" claim remains retracted: that measurement
  never held the rate and could not attribute drops (SOAK-GATE-002).

## Evidence artifacts (local, git-ignored)

| File | Content |
|---|---|
| `admin-evidence/host-window-005-20261110/deploy-window-005-result.json` | deploy with per-file hash assertion (`ED74E56F…`, match `true`) |
| `.../rate-4000-held.json` | 90 s held-rate window, zero drops |
| `.../rate-4000-held-5min.json` | 300 s sustained window, 1,199,998 op-sets, zero drops |
| `.../queue-after-rate.txt`, `health-after-rate.json` | per-source and integrity counters at settle |
| `.../soak-window-start.json` | clean soak start (rate_exit 0) |

## Limitations (do not over-read this record)

- Acceptance is at 4,000 op-sets/s. Above that the build still sheds.
- The 24 h soak (R-08) is a **separate** gate and has only just started from
  this clean counter set; #30 remains open until it completes crash-free.
- E7 signed release is untouched by this record.

## Status

**#29 acceptance criterion met at E5 on this host.** The issue can be closed
with the residual ceiling stated above; the follow-on work (higher sustained
rates) is a new slice, not a reopening of this measurement.
