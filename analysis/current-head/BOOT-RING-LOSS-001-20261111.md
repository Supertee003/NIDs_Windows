# BOOT-RING-LOSS-001 — 448 minifilter rows lost while the daemon was initialising

**Created:** 2026-11-11
**Measured on:** deployed `ED74E56F…` (source `c79c5a1`), boot 2026-11-11 01:30:26
**Level:** E1 (host reads; no product change)
**Status:** open finding. It is **not** the ETW loss and **not** a failure of
`4c4ed3a` — that build was never deployed (see §5).

---

## 1. What the host reported

The first soak after the reboot failed at 0.06 h:

```
daemon                          RUNNING / DEGRADED
queue_dropped_total             0
shed_overload                   0
minifilter_ring_dropped         448
minifilter_pipeline_dropped     0
```

`queue.stats` on the same process:

```
minifilter: state=ok reads=5700 rows=92562 dropped=448
            ring_written=113754 pipeline_dropped=0 pace_waits=10
queue: depth=0 peak=11955  pushed=223,035  dropped=0
```

So the loss is entirely **kernel-ring overflow**, not queue admission. The
ring is 4 MiB (`AEGIS_RING_SIZE`), which holds roughly 113 k 36-byte records;
113,754 records were written before the reader caught up, and 448 did not fit.

## 2. Mechanism

The boot task starts `AegisWfp` and `AegisMinifilter`, then restarts
`AegisNids` because the drivers were down at boot. The daemon process started
about 2 min 25 s after boot (health uptime at the 01:36 check implies 01:32:51;
the boot was 01:30:26). During the whole initialisation window the minifilter
was already emitting into the ring with **no reader attached**, so the ring
filled and the last 448 records were dropped by the driver.

The driver's `DroppedEvents` is a gauge, not a per-process counter:

- restarting the daemon alone does **not** reset it;
- only a driver reload (`AegisRingInitialize` on load) zeroes it.

That is why a soak started from the boot state can never pass at
`--loss-budget 0` even after the daemon is healthy again.

## 3. Why this is a real finding, not noise

| Question | Answer |
|---|---|
| Is it silent? | No — `minifilter_ring_dropped=448` is in health, and the daemon goes DEGRADED because of it. |
| Is it big? | 448 / 113,754 = **0.39 %** of the boot window. |
| What is lost? | File events during service initialisation; a persistence write in that window is not evaluated. |
| Does it recur? | On every boot that reloads the minifilter, because the ring is sized for ~2 min of boot traffic and the daemon takes ~2.4 min to attach. |
| Is it related to ETW? | No. ETW drops were `capture_etw/fim_change` at queue admission; this is `capture_fim` at the kernel ring. |

## 4. Options

| Option | Work | Effect |
|---|---|---|
| **A. 8 MiB ring** (`AEGIS_RING_SIZE` 4 → 8 MiB) | driver edit, WDK build, test-sign, elevated driver swap, E5 re-measure | roughly doubles the buffered boot window (~4.8 min); the 2.45 min gap fits with margin. A driver change, so a separate patch and candidate. |
| **B. Attach earlier** | source: re-evaluate bridge readiness / let the reader thread attach before the daemon reports running | removes the gap instead of buffering it; larger change, needs E5. |
| **C. Bounded startup limitation** | record + disclose per boot | no code change; 0.39 % of boot events remain a stated blind spot. |

Recommendation: **A** as the next driver candidate (small, measurable), with
**C** as the interim disclosure. Do not silently reset the counter and call the
window clean.

## 5. The 01:29 window did not deploy

`admin-evidence/host-window-006-20261111/deploy-window-006.log` stops after:

```
01:29:00  recorded rollback copy from the live install
01:29:00  staged=C40DEA47… live=ED74E56F… rollback=ED74E56F…
```

There is no `stopping AegisNids` line and no result JSON. The reboot was
requested at 01:29:00 with a 60 s delay, and the installed image is still
`ED74E56F…`. The deploy did not stop, copy, or start anything. The exact
termination is not recorded (the script had no catch-all trap); the likely
cause is a non-elevated `sc.exe stop` plus the reboot killing the 90 s wait
before it could report. The script now refuses to start unless elevated, traps
terminating errors into a result file, and fails on an `sc.exe` stop error.

**Consequence:** the 448-row boot loss was measured on the old build. It is
still the expected shape on `4c4ed3a` (that patch changes the ETW admission
policy, not the minifilter ring), but the new build's numbers do not exist yet.

## 6. Immediate operation

`host-window-006-20261111/steady-soak.ps1` reloads the minifilter (zeroing the
driver gauge), restarts the daemon, refuses to arm unless
`ring/drops/shed = 0`, and then starts the 24 h window. The boot transient is
recorded here and in the post-boot probe; it is excluded from the steady-state
window on the record, not erased.
