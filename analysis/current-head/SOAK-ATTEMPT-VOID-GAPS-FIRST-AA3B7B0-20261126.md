# Voided soak attempt before remaining gap closure — `aa3b7b0` — 2026-11-26

**RECORD-ID:** `SOAK-ATTEMPT-VOID-GAPS-FIRST-AA3B7B0-20261126`
**RUN-ID:** `20261126-214622`
**STATUS:** `VOIDED_DEFERRED_GAPS_FIRST` — no PASS, no evidence credit, not used by any gate.
**BUILD SOURCE:** `aa3b7b0161e425e54155d5767737bffcde7939b5`

A 24 h window was armed at **21:46:50** after the current-head documentation closeout was committed (`e49c106`). It started clean: current-source daemon/Nose/PEP installed, minifilter lifetime gauge recycled `0 → 0`, `loss_budget` unchanged at 3500, `nose_connected=true`, `health.state=RUNNING`, Nose PID `20524`. Unlike the previous attempt, the finalizer was a **SYSTEM Scheduled Task** (`AegisNidsSoakFinalize_20261126-214622`) independent of the agent shell; it began heartbeats at 21:48 and remained alive.

The owner then directed that the remaining evidence gaps be closed **before** the final soak. The window was therefore intentionally voided at **22:28:41**, before 24 h. Health at void was `DEGRADED` with `minifilter_ring_dropped=1,592,603`, `minifilter_pipeline_dropped=14,826` and `queue_dropped_total=88,485`; these values are recorded as observed and are **not** reinterpreted as a PASS or as a budget change.

An elevated owner-run void script:

- stopped the finalizer process (none remained outside the task) and **deleted the Scheduled Task** — `finalizer_task_deleted=true`;
- restored the exact pre-soak baseline — `restore.verified=true`;
- restored daemon `FBD9BDB3…`, Nose `AEAB9B63…`, PEP `870CB962…`;
- restored service env `AEGIS_LOSS_BUDGET=3500` and machine interface pin `\\Device\\NPF_{5FD31C6E-DE48-44CB-838E-14667A04DA4B}`;
- left service `Running`, `errors=[]`.

No loss budget was raised, no PASS was relabelled, and the attempt contributes nothing to `soak_24h`. Verbatim artifacts: `analysis/current-head/raw-aa3b7b0-20261126/soak-void-gaps-first/`.

**What worked:** the Scheduled Task finalizer survived the harness and produced heartbeats independently. The void was a deliberate owner-directed deferral, not an infrastructure failure. A fresh window must still be started only after the remaining gap work is committed.
