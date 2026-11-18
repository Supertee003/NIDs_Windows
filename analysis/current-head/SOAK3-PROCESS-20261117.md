# SOAK3-PROCESS-20261117 - a 24.62 h process-start window, PASS

> **CLOSED - PASS, with the baseline disclosed.** This is the replacement for
> `SOAK2`, which is VOID (`analysis/current-head/SOAK2-VOID-20261117.md`). The
> window is the life of the running process (PID 23072), not a window that began
> with a fresh `--baseline auto` snapshot. The baseline is a reconstruction from
> a code invariant, not a sample; §3 states the invariant, its code anchors, and
> what would falsify it. The gate itself read the live absolute counters and
> agreed with the reconstruction.

**Created:** 2026-11-17T02:24+07:00
**Window:** process start `2026-11-16T01:45:40.79` -> `2026-11-17T01:45:40.79`
(24 h); gate evaluated at `2026-11-17T02:22:44`, 24.62 h after start
**Build under test:** `aegis_nids.exe` sha256
`7955A6E3C9BB8AC4E5872114B33316AADA74F09E39F48C0513BA6FFA58D71A18`,
build source `7c604d5` (verified by hash, not filename; the same image is
installed at `C:\Program Files\AEGIS NIDS\runtime\aegis_nids.exe`)
**Gate artifact:** `admin-evidence/e5-clean-host-20261117-process-soak/soak-24h-process-start.json`
**Baseline:** `admin-evidence/e5-clean-host-20261117-process-soak/soak-24h-process-start.baseline.json`

## 1. Gate command and verdict

```powershell
python tools/host_soak_check.py `
  --start auto `
  --baseline admin-evidence\e5-clean-host-20261117-process-soak\soak-24h-process-start.baseline.json `
  --hours 24 --loss-budget 3500 --shed-budget 20000 `
  --json admin-evidence\e5-clean-host-20261117-process-soak\soak-24h-process-start.json
```

| Fact | Value |
|---|---|
| Verdict | **`PASS`** |
| `soak_start` (derived from uptime) | `2026-11-16T01:45:41.226629` |
| Process start (Win32_Process, PID 23072) | `2026-11-16T01:45:40.7902870+07:00` |
| Host boot time | `2026-11-16T01:45:04.5000000+07:00` |
| `checked_at` | `2026-11-17T02:22:44` |
| `elapsed_hours` | **24.62** (required 24.0) |
| `daemon_uptime_hours` | **24.62** |
| Services | `AegisNids`, `AegisAggregator`, `AegisWfp`, `AegisMinifilter` all `RUNNING` |
| `daemon_state` / `daemon_health_state` | `RUNNING` / `RUNNING` |
| `scm_restarts` | `[]` |
| `problems` | `[]` |
| Exit code | 0 |

The uptime and the elapsed window are equal to two decimals, which is the
property the SOAK2 gate failed on: no process restart occurred between the
window start and the check. `scm_restarts` is empty *and* the uptime test
passed, so this is not an SCM-restart-shaped blind spot.

## 2. Loss and shed, attributed

Gate values at `2026-11-17T02:22:44` (absolute = delta, because the window starts
at process start; see §3):

| Counter | Value | Budget | Attribution |
|---|---:|---:|---|
| `queue_dropped_total` | 1,377 | 3,500 | **all** `capture_etw` / `reg_change`; `source_quota_shed` = 1,377 |
| `shed_overload` | 984 | 20,000 | ETW Kernel-File storm shed (see below) |
| `nose_frames_rejected` | 0 | 3,500 | - |
| `nose_frames_dropped` | 0 | 3,500 | - |
| `nose_pipe_errors` | 0 | 3,500 | - |
| `minifilter_ring_dropped` | 0 | 3,500 | - |
| `minifilter_pipeline_dropped` | 0 | 3,500 | - |

`queue.stats` at `2026-11-17T02:23:31` (`python tools/aegisctl.py queue --json`):

- pushed 36,628,734 rows in 24.62 h (~413/s): `capture_npcap` 5,731,513,
  `capture_etw` 29,544,026, `capture_fim` 1,279,114, `capture_registry` 10,069,
  `capture_host_net` 6,640, `capture_wfp` 57,372.
- Every source except ETW shows `dropped=0`. The one ETW bucket that dropped is
  `reg_change`: 1,377 dropped of 11,524,334 pushed. The per-source occupancy cap
  (`source_occupancy_cap=7168`, `source_quota_shed=1377`) refused those rows:
  that is the bounded fair-share behaviour, and it is counted, not silent.
- `reserved_tail_shed=0`, so no network row was refused at the reserved tail;
  `depth_peak=7169` against a 16,384-slot queue and a 14,336-slot working host
  tail. The peak is one slot above the per-source cap because one protected
  System32 row was admitted beside it (`critical_pushed_total=20,439`).
- `shed_overload=984` can only come from `isStormSheddable` -
  `Microsoft-Windows-Kernel-File` event `0x10`/`0x0B` under ETW share pressure
  (`src/pipeline/telemetry_threads.zig:135-138, 365-371`). These are host file
  telemetry rows discarded by policy during a write/name-delete storm; no
  network frame and no detection row is involved.
- The ETW pre-decode gate skipped 2,529,577,415 native records
  (`etw.predecode_dropped`) - provider/event pairs the classifier does not map,
  skipped before decode by design (`src/windows/etw_realtime.zig:1054-1063`).
  `etw.dropped_unmapped=0` means the gate and the classifier did not drift, so
  that number is not hidden loss. It is reported here because it is large and a
  reader should not have to find it themselves.

Interpretation, stated narrowly: **no network loss, no minifilter loss, no queue
overflow, and host-telemetry admission stayed inside the owner budgets.** The
1,377 quota sheds and 984 storm sheds are the designed bounded-loss behaviour of
the host telemetry lanes.

## 3. The baseline is a reconstruction, and this is why it is sound

The gate needs a "before" value to compute a delta. There is no sampled "before"
file for this process: it started at `01:45:40.79` on 2026-11-16, and nobody
snapshotted the counters in the first seconds. Recording a fake sample now and
back-dating it would be fabrication. Instead the baseline file is honest about
what it is:

```json
"sampled": false,
"origin": "constructed_from_process_start_invariant",
"recorded_at": "2026-11-16T01:45:40.79+07:00"
```

The reconstruction rests on four source facts, all checked at `7c604d5`:

1. every loss counter is a process-lifetime atomic initialized to zero -
   `g_queue_drops` (`src/pipeline/runtime_state.zig:280`), `g_ingress_dropped`
   (`src/pipeline/event_queue.zig:138`), `g_shed_overload`
   (`src/pipeline/telemetry_threads.zig:44`), and the nose/minifilter counters in
   `runtime_state.zig:266-333`;
2. the only mutation is `fetchAdd` (`event_queue.zig:231-275`,
   `telemetry_threads.zig:369`); no path stores a lower value or resets a
   counter;
3. therefore the counters were exactly 0 at process start;
4. the window start is the process start (the gate derives it from uptime, and
   the derived start is within 0.44 s of the `Win32_Process` creation time), so
   "delta since baseline" and "absolute value" are the same number.

What would falsify it: a counter reset path, a process restart inside the
window, or a baseline recorded with a different start. The gate checks the
second directly (`daemon_uptime_hours` vs `elapsed_hours`) and it passed. The
first is a static property of the cited lines; if a future patch adds a store,
this baseline pattern must not be reused.

## 4. What the window covers, and what it does not

**Covered.** A full 24 h of the installed production process on the real host:
all four services RUNNING the whole time, 7/7 subsystems RUNNING, detection
pipeline live (5.7 M packets captured, 36.6 M rows pushed), no crash, no SCM
restart, no reboot, admission within budget.

**Not covered, stated plainly.**

1. The window is a **process-start** window, not an install-start window. The
   install was on 2026-11-15; the host rebooted at `2026-11-16T01:44:53` and
   this process began 47 s later. The 24 h therefore describes the post-reboot
   process only.
2. It includes ordinary desktop use of the machine. No AEGIS gate, scan, or
   operator stimulus is recorded inside it: `DETECT-L4-001` ran at
   `2026-11-16T00:07` local, 1.6 h **before** this process started, and every
   command in this closeout ran after the 24 h mark. The host was not
   artificially idle, and this record does not claim it was.
3. It says nothing about a driver reload, an upgrade, or a signer change. Those
   are separate lifecycle events with their own windows.
4. It is one host and one build. A second host or a re-signed build needs its
   own window; this artifact cannot be transplanted.
5. The budgets (3,500 loss / 20,000 shed) are owner policy, not physics. A
   different workload can exceed them and the gate would then fail, correctly.
6. The drivers remain **test-signed**; this is release-engineering scope, not a
   soak property, and it is recorded in `KNOWN_LIMITATIONS.md`.

## 5. Relationship to previous windows

| Window | Result | Why |
|---|---|---|
| `SOAK-SHED-001` (2026-11-14) | FAIL | 15,163 shed against a 4,000 budget, produced by live gates inside the window |
| `SOAK2` (2026-11-15 -> 11-16) | **VOID** | host rebooted 8.9 h in; daemon uptime 24.42 h < 33.34 h elapsed at the gate |
| `SOAK3` (this record) | **PASS** | process-start window, no restart, budgets honoured, no gate inside |

`SOAK-SHED-001`'s own next step was "restart the soak from a new baseline after
the patches, and either run live gates before the window or size the shed budget
for them". Both halves happened here: the window started after the reboot on the
current build, every live gate ran outside it, and the shed budget was raised to
20,000 by policy before the measurement. The gap is closed by this record.

## 6. Release consequence

With this artifact, `python tools/final_audit.py --release-check` reports
**SHIPPABLE, 0/6 gates open** at records HEAD `54d66b0` / build source `7c604d5`:

```
PASS truth_artifacts   TRUTH_VALID (build source 7c604d5)
PASS component_audit   modules 66/66, prod failures 0, part_ii 5/5
PASS release_signature signatures.json signs SHA256SUMS (9F87BF36D28149F5...)
PASS clean_host_e5     admin-evidence/e5-clean-host-20261114-222014/preflight-...json
PASS soak_24h          soak-24h-process-start.json is PASS at 24.62/24.0 h
PASS evidence_debt     unnamed product files 0 <= baseline 0
```

`soak_24h` cites this artifact because the gate selects the newest soak artifact
by `checked_at`; the SOAK2 FAIL artifact remains on disk as history and is not
erased. The release tree `release/T20-final/9ebee9b` is unchanged: its runtime is
`7c604d5`, the same build this window measured.
