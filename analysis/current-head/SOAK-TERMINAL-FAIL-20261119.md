# Terminal soak FAIL — old signed candidate `f4cde3c` (2026-11-19)

## What happened

The background waiter `admin-evidence/e5-clean-host-20261119-final/soak-wait-terminal.ps1`
reached a terminal verdict at **2026-11-19T22:40:04+07:00**:

```
SOAK_TERMINAL status=SOAK_FAIL verdict=FAIL problems=2
artifact=D:\NIds_Windows\admin-evidence\e5-clean-host-20261119-final\soak-24h-f4cde3c-delta-20261119-2240.json
```

## Measured facts (from the artifact, not inferred)

| Field | Value |
|---|---|
| soak_start | 2026-11-19T04:38:09 |
| checked_at | 2026-11-19T22:40:03 |
| elapsed / required | 18.03 h / 24.0 h (terminal early on fail conditions) |
| services | AegisNids, AegisAggregator, AegisWfp, AegisMinifilter all RUNNING |
| daemon_state / health | RUNNING / **DEGRADED** |
| scm_restarts | none |
| queue_dropped_total | baseline 0 → 5177 (delta +5177) |
| loss_budget | 3500 (exceeded) |
| other ingress counters | 0 (nose rejected/dropped/pipe errors, minifilter ring/pipeline drops) |
| shed_overload | 0 |

Problems recorded by the waiter:

1. daemon reports DEGRADED (`state=DEGRADED`, `runtime_state=RUNNING`);
2. `queue_dropped_total` grew by 5177 inside the window, exceeding the owner-approved loss budget 3500.

## Scope and limitations

- This window covers **only** the old signed candidate `b597e71` / build source `f4cde3c`.
  The four capability slices on the current worktree source (`f3a5200`, `183e095`,
  `683ff20`, and POLICY-MUTATE-001) are outside its coverage and were never
  claimed to be soaked.
- The verdict is **negative E5 evidence** about that candidate. It does not
  prove any capability, and it does not close `soak_24h`.
- No host install, restart, service change, topology switch or load injection
  was performed as a result of this finding. The artifact lives in the owner's
  main tree (`D:\NIds_Windows`), not the isolated worktree.

## Live test consequence (honest, not a code regression)

The full pytest run after this finding has **2 E4 live-daemon failures** in
`tests/integration/test_e4_live_pipeline.py` (`test_every_surface_agrees_about_health`
and `test_readiness_publishes_the_state_machine_and_never_degrades_anonymously`).
The live `readiness` payload reports:

```
state=DEGRADED, state_machine_state=RUNNING, degraded_components=[],
failure_reasons=[degraded_without_named_component, state_degraded]
```

That is the same DEGRADED-vs-RUNNING contradiction recorded by the soak artifact.
These tests exercise the **installed old binary**, not the worktree source, and
they fail because the host is degraded — no source change caused them. They were
not softened or skipped: fabricating a pass would violate the no-fake-pass rule.
They will keep failing until the owner repairs the host and installs a new signed
candidate (which is also required for a fresh soak).

## Consequence

- `soak_24h` is **FAIL / NOT closed**. The release board rows in
  `docs/gates/T20_100pct_audit.{md,json}` were updated from IN_PROGRESS to the
  terminal FAIL verdict so no document claims an in-flight window that has ended.
- Release remains **NOT SHIPPABLE**. No tag, push, GitHub Release or publish.
- A fresh soak requires a **new signed candidate** containing the current source
  and an **owner-named baseline window**. Until then, all new slices stay E2.

## Source-of-truth note

Per AGENTS.md the artifact is the authority for this verdict; the board files
are records snapshots of it. `scripts/check_summary.py` cannot be run in this
worktree because `admin-evidence/` is intentionally absent here — the main tree
remains the place where the artifact can be opened and re-verified.
