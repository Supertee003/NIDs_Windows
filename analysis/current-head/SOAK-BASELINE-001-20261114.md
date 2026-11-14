# SOAK-BASELINE-001 — the soak gate charged a window with its own deploy burst

**Created:** 2026-11-14
**Build source:** `68a6caa` (this patch touches `tools/` and `tests/` only)
**Level:** E2 (pure-function verdict tests + one live run on the host)
**Found while:** closing the 24 h duration deviation left by `RC-FINAL`

---

## 1. What the host actually showed

`RC-FINAL` closed the release candidate at 21.77 h against a budget of 3,500
queue drops + 4,000 policy sheds per 24 h. The installed candidate was replaced
at 17:11 on 2026-11-14 by the write-intent minifilter (`deploy-driver-007`), so
the soak clock restarted. Two hours later:

| Counter | Value (since 17:11) | 24 h budget |
|---|---:|---:|
| `queue_dropped_total` | 0 | 3,500 |
| `shed_overload` | **5,310** | 4,000 |

Re-running the gate against that process failed immediately, and it was right to:

```
shed_overload=5310 exceeds the policy-shed budget 0
```

Sampling `queue.stats` twice, 60 s apart, at 18:55:

```
pushed_total    1,576,121 -> 1,592,468   (+16,347)
shed_overload       5,310 ->     5,310   (0)
dropped_total           0 ->         0   (0)
```

So the 5,310 sheds did not happen during the two quiet hours — they happened in
the first minutes after the restart, while the minifilter ring was draining and
the FIM/HKCU canaries ran (`fim-write.json`, `fim-dll-drop.json`,
`canary-hkcu-e5.json`, all 17:11-17:12). The daemon then lost nothing.

## 2. The defect in the gate, not in the daemon

`host_soak_check.evaluate` compared the *cumulative* counters against the budget:

```python
value = integrity.get(key)
if isinstance(value, (int, float)) and value > loss_budget:
    problems.append(f"{key}={int(value)} exceeds the loss budget {loss_budget}")
```

The counters live for the life of the process. A window that starts at process
start therefore includes the deploy's own burst, and a 24 h budget can be spent
in the first twenty minutes — after which no window on that process can ever
pass, no matter how clean it is. The mirror-image risk is worse: a caller who
wants a passing verdict is pushed toward "restart and measure immediately",
which is precisely when a system is least representative.

The gate was not wrong to fail; it was answering a different question than the
one the soak asks. "Was anything lost during these 24 hours?" is a delta.

## 3. Fix

`--baseline auto|<path>` anchors the window at a recorded counter snapshot:

- `auto` snapshots `data_integrity` + `shed_overload` now, writes the snapshot
  next to the report (`<json>.baseline.json`), and starts the window at that
  moment;
- a path replays an earlier anchor, so a verdict can be re-derived later;
- the gate scores **growth since the anchor**, and still fails on:
  - growth above the budget, per counter;
  - a counter that went *backwards* (the process restarted inside the window,
    so the delta is meaningless);
  - a counter missing from the payload or from the baseline (fail closed — an
    unread counter is not evidence of zero loss);
- every report carries `counters_absolute` **and** `counters_delta`, so the
  pre-window burst stays visible in the artifact instead of being forgotten.

Without `--baseline` the previous absolute comparison applies unchanged, so the
historical `PASS` artifacts (`soak-21h-budget`, `soak-24h-budget`) remain
reproducible exactly.

### Second, smaller hardening

A missing loss counter used to be skipped (`isinstance(value, (int, float))`).
It is now a problem in both modes. The daemon always emits all six keys, so this
only fires on a truncated payload — which is exactly the case where a silent
pass would be wrong.

## 4. Verification

| Check | Result |
|---|---|
| `pytest tests/security/test_soak_verdict.py` | 15 passed (6 new) |
| `pytest tests/security tests/tools tests/docs` | 439 passed |
| live `--baseline auto` run on the host | `IN_PROGRESS`, `counters_delta` all 0, `counters_absolute.shed_overload=5310`, `problems []` |

New pins:

- a window whose only loss is the pre-window burst passes, and the burst is
  still reported (`counters_absolute`);
- growth of 3,501 queue rows / 4,001 sheds inside the window fails;
- a counter below its baseline fails as a restart;
- a baseline missing a counter fails closed.

## 5. Consequence for the release record

This does **not** retroactively make the 21.77 h window a 24 h one. It makes a
*new* 24 h observation possible on the current build without pretending the
deploy burst did not happen. Window started 2026-11-14 ~19:05 from a recorded
baseline; the artifact is
`admin-evidence/host-window-006-20261111/soak-24h-delta-20261114.json` plus its
`.baseline.json`.

The envelope itself is unchanged and still the owner's decision: 3,500 queue +
4,000 shed per 24 h, 0.035 % of pushed rows.

## 6. Residual

- The baseline is a counter snapshot, not a timestamped series: if the daemon
  restarts between the anchor and the check, the backwards-counter rule catches
  it, but the window is then void rather than resumed.
- `--baseline auto` trusts the caller to start it when the host is settled. A
  lab script could anchor during a storm and measure only what follows; the
  absolute values in the same artifact are the guard against that being hidden.
- The 24 h window must be re-evaluated by a second run of the tool; this patch
  only starts it.
