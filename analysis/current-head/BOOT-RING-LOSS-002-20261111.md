# BOOT-RING-LOSS-002 — the reader must already be waiting when the ring is born

**Created:** 2026-11-11
**Build source before this patch:** `4c4ed3a`
**Finding:** after the demand-start change, the 01:49 boot still dropped 4,012
minifilter rows. The ring, not the start mode, was the remaining limit.
**Level:** E2 (unit/build). Host proof is the next window.

---

## 1. What the 01:49 boot measured

The demand-start change worked mechanically — the task ran at 01:49:52, the
drivers were `STOPPED -> RUNNING` by 01:49:59, and the daemon was `RUNNING` at
01:49:59. But `queue.stats` on the new build reported:

```
minifilter: state=ok reads=7322 rows=190191 dropped=4012
            ring_written=188653 pipeline_dropped=0
health:     minifilter_ring_dropped=4012, state=DEGRADED
```

The daemon attached in the same second the drivers started, so the gap was not
the problem. The problem is the **boot write rate**: the daemon log shows
4,096 records drained in under a second, 12,288 by the first second and 49,152
by the eleventh — while the 4 MiB ring holds roughly 116 k 36-byte records.
The boot storm outran the drain for long enough to overflow by 4,012 rows.

## 2. Why starting the drivers first cannot win

Any order that starts the minifilter before the daemon creates a backlog equal
to `rate x daemon-init-time`. Measured init is ~7 s and the measured burst is
>16 k records/s, so the backlog is >112 k — right at the 4 MiB ring's capacity,
which is why the loss moved from 448 to 4,012 instead of disappearing.

Starting the **daemon first** is the only order that starts the ring empty. The
minifilter reader is a retry loop, so it can already be waiting on the port
before the driver exists. The remaining question is how quickly it notices the
driver.

## 3. The retry interval was 10 s

`src/capture/minifilter_reader.zig` retried `FilterConnectCommunicationPort`
every **10,000 ms**. If the boot task starts the daemon first and the
minifilter one second later, the reader can sleep through that one second and
attach up to 9 s later — long enough for ~144 k boot records to pile up, which
is again beyond the ring.

Change: `CONNECT_RETRY_MS` 10,000 -> **1,000 ms**. One cheap local port probe
per second bounds the post-driver backlog to roughly one second of boot writes,
well inside the ring's headroom. The first-failure log cadence is unchanged
(every 6th retry, now every 6 s while the driver is absent).

## 4. Boot order (host side, not in this commit)

`admin-evidence/host-window-003-20261110/boot-sequence.ps1` now does:

1. start `AegisWfp` (the daemon attests it once at startup) and let it settle;
2. start `AegisNids` (now `DEMAND_START`) and wait for `RUNNING`;
3. start `AegisMinifilter` — the reader is already retrying, so it connects
   within one second of the ring existing.

The loader's `State()` was also fixed (it had the same `sc.exe` array-match
defect as the deploy script, so it saw `UNKNOWN` and wasted its retry budget).

## 5. Verification

```
zig build test --summary all   -> 2,085 passed / 10 skipped / 0 failed
zig build                      -> exit 0, daemon 21A875CF8F103E3B...
```

No wire, ABI, contract or queue-policy change; this is a retry constant plus a
comment that records why it is 1 s.

## 6. What is still open

- **E5:** the new build (`21A875CF…`) must be deployed and the host rebooted.
  The probe must show `minifilter_ring_dropped = 0`; until then this is a
  hypothesis backed by the measured rate, not a proof.
- **Packaging:** the boot order lives in a local evidence script. The installer
  still needs a tracked boot script, the task registration, and the matching
  start mode (BOOT-RING-LOSS-001 §7).
- **Tradeoff:** a 1 s retry is more port probes when the driver is absent. It
  does not affect the steady-state pull loop (`IDLE_SLEEP_MS = 50`).
