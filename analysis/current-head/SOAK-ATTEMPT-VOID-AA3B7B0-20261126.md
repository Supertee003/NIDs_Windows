# Voided 24 h soak attempt — `aa3b7b0` — 2026-11-26 16:29:31

**RECORD-ID:** `SOAK-ATTEMPT-VOID-AA3B7B0-20261126-162907`
**STATUS:** `VOIDED` — no PASS, no evidence credit, not used by any gate.
**BUILD SOURCE:** `aa3b7b0161e425e54155d5767737bffcde7939b5`

A genuine 24 h window was started with the current-source runtime installed and a clean counter baseline: `minifilter_ring_dropped 68,740,045 → 0` after a pre-window driver recycle, `loss_budget` still 3500, `nose_connected=true`, `health.state=RUNNING`. The detached finalizer was running.

During that window the agent performed other work — release-tree assembly, a WDK driver build, pytest and doc checks — which generated substantial file-system I/O on the same host. The daemon correctly recorded loss and stopped calling itself healthy:

| Counter at abort | Value |
|---|---:|
| `minifilter_ring_dropped` | 37,361 |
| `minifilter_pipeline_dropped` | 468 |
| `queue_dropped_total` | 1,562 |
| `health.state` | `DEGRADED` |

Those deltas are attributable to the agent's own work, not to an idle soak. The attempt was therefore **voided before its scheduled end**, the sleeping finalizer was stopped, and the exact pre-soak baseline was restored (`restore.verified=true`, service `Running`, env and machine interface pin equal to baseline). Nothing was relabelled as a pass and no loss budget was raised.

Verbatim artifacts: `analysis/current-head/raw-aa3b7b0-20261126/soak-void/` (`start.json` shows `status=VOIDED`, `abort.json`, `health-at-abort.json`, `soak.baseline.json`, `soak-initial.json`, transcripts).

**Lesson applied:** all non-soak work is finished before the next window starts, and no file-heavy command is run while it is active. The next soak must come from a fresh baseline and end with its own evaluated artifact.
