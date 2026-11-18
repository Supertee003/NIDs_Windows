# SOAK-21H-BUDGET — 21.77 h at 3,500/4,000: PASS at the 21 h criterion

**Created:** 2026-11-14
**Measured on:** installed `B8EFE0B85F1754D51180F4B6D7AEEC8DB56B00FEE1EDB321A1A2C8EE46167E11`
(source `cc3518d`), daemon pid 24396 -> restarted 2026-11-13 16:55:21
**Window:** 2026-11-13 16:55:21 -> 2026-11-14 14:41:42 (**21.77 h**)
**Record:** `admin-evidence/host-window-006-20261111/soak-21h-budget.json`
**Verdict:** **PASS at `--hours 21`**, with a declared **deviation from the 24 h
gate** (21.77 h instead of 24 h on this exact build).

---

## 1. Result

| Check | Value |
|---|---|
| elapsed | 21.77 h |
| required for this record | 21 h |
| services | all four `RUNNING` |
| daemon uptime | 21.77 h (no restart) |
| SCM 7031/7034 | none |
| health state | **RUNNING**, `degraded=false` |
| `loss_budget` | **3500** (read from the service environment) |
| `queue_dropped_total` | **2,898** (budget 3,500) |
| `shed_overload` | **3,396** (budget 4,000) |
| `minifilter_ring_dropped` | **0** |
| `minifilter_pipeline_dropped` | **0** |
| nose dropped / rejected / pipe errors | **0 / 0 / 0** |
| rows pushed | 18,062,077 |

## 2. The point this proves

The daemon carried **2,898 lost rows** and still reported:

```
state = RUNNING
degraded = false
loss_budget = 3500
```

That is the budget-aware behaviour working end to end: the same counters on
build `33223B2C` (no budget) produced `DEGRADED` and readiness exit 1. The
accepted envelope is now operational, not just a note in a record.

The 21 h PASS also satisfies the crash-free part of R-08 on this build:
no restart, no crash, all four services running for the whole window.

## 3. The 24 h deviation, stated plainly

The project's gate is 24 h. This window is **21.77 h**, so:

- the formal 24 h gate on build `B8EFE0B8` is **not met**;
- the previous build `33223B2C` ran **25.33 h** with the same loss path and
  passed the crash-free part (`SOAK-25H`);
- the delta between `33223B2C` and `B8EFE0B8` is the loss-budget health logic
  plus a rebuild; it does not touch the capture, queue, ring or forensic path;
- the owner accepted closing on the 21.77 h window rather than waiting the
  remaining 2 h 14 min (2026-11-14 16:55).

This record does not call the 21.77 h window a 24 h PASS. It is a PASS at the
21 h criterion plus a declared deviation, and the duration evidence is the
combination of 25.33 h (previous build) + 21.77 h (this build).

## 4. What remains unchanged

- The accepted loss envelope is **3,500 queue + 4,000 shed per 24 h**; the
  window used 2,898 + 3,396.
- `shed_overload` is not in health; the soak tool's `--shed-budget` is the gate.
- The write filter coverage decision (generic ETW writes not ingested) stands.
- One lab host; no fleet or kernel qualification claim.

## 5. 22.11 h re-check (same process)

At 2026-11-14 15:02:04 the owner re-ran the same command with `--hours 24`:

```
verdict = IN_PROGRESS   (22.11 h < 24 h)
problems = []
state = RUNNING, degraded = false
queue_dropped_total = 2,898  (unchanged from 21.77 h)
shed_overload = 3,396        (unchanged from 21.77 h)
ring = 0, scm_restarts = []
```

`IN_PROGRESS` with an empty `problems` list is the expected pre-24 h answer,
not a failure: the counters did not move in the 20 minutes since the 21.77 h
check, and no problem appeared. The closure remains the 21.77 h PASS plus the
declared deviation; a later 24 h run would be the formal completion of the same
window if the service is left running.
