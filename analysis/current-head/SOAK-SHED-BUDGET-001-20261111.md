# SOAK-SHED-BUDGET-001 — a soak may not pass on policy shed it does not count

**Created:** 2026-11-11
**Build source:** `4c4ed3a` (unchanged; this patch touches `tools/` and `tests/` only)
**Depends on:** QLOSS-ETW-PRIORITY-001
**Evidence level:** E2 (unit) + E1 (live reading)

---

## Why

QLOSS-ETW-PRIORITY-001 moves low-value ETW file writes/deletes from
`source_quota_shed` (overflow, counted in `data_integrity.queue_dropped_total`)
to `shed_overload` (deliberate policy shed, exposed only on `queue.stats`).

`host_soak_check.py` read only the health payload. On a build carrying that
change, the same discarded rows could move out of the counter the soak reads
and a "zero loss" 24 h window could be reported while the queue was still
shedding. That is the S1-05 class of defect (a gate that reports a green it did
not earn), reintroduced by a policy repair.

## What changed

`tools/host_soak_check.py`:

- new `--shed-budget` (default 0) and a `queue.stats` read;
- `evaluate()` takes the queue payload and fails when `shed_overload` exceeds
  the budget, and fails closed when `queue.stats` is unavailable;
- the report carries `shed_overload` and `shed_budget` beside the existing
  `loss_budget`.

`tests/security/test_soak_verdict.py`: three new cases — 145,915 shed fails at
budget 0, 150 shed passes at budget 200, and an unavailable queue surface is a
problem, not a zero.

## Verification

```
python -m pytest -q tests/security/test_soak_verdict.py   -> 11 passed
python tools/host_soak_check.py --start auto --hours 24 --loss-budget 0
  -> FAIL (3): DEGRADED + queue_dropped_total=148217, shed_overload=0
```

The live run is unchanged because the deployed daemon (source `c79c5a1`) does
not yet carry the shed reprioritisation; the tool now covers the build that
does.

## Limitation

The default budget is 0, which keeps the R-08 criterion strict. An owner who
accepts a bounded policy-shed rate must pass `--shed-budget N` explicitly; the
number then appears in the soak report and cannot be inferred from a PASS.
