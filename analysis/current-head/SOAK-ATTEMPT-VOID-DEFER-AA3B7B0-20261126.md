# Voided soak attempt after server restart and owner-directed deferral — `aa3b7b0` — 2026-11-26

**RECORD-ID:** `SOAK-ATTEMPT-VOID-DEFER-AA3B7B0-20261126`
**RUN-ID:** `20261126-172958`
**STATUS:** `VOIDED_DEFERRED` — no PASS, no evidence credit, not used by any gate.
**BUILD SOURCE:** `aa3b7b0161e425e54155d5767737bffcde7939b5`

A second 24 h window was armed at **17:30:26** with a clean baseline: current-source daemon/Nose/PEP installed, minifilter lifetime gauge recycled `166,653 → 0` with `loss_budget` still 3500, `nose_connected=true`, `health.state=RUNNING`. The detached finalizer wrote heartbeats every five minutes through **20:35:28**.

The OpenCode server then restarted. The harness shell waiting on the finalizer was cancelled, and the detached finalizer stopped writing heartbeats; no live finalizer process remained (the apparent PID from a CIM query was the query process itself). No `result.json` and no `soak-final.json` were produced. The installed binaries remained at the swapped current-source hashes with no process left to restore them at 24 h.

The owner then directed that the remaining documentation closeout be completed first and the soak redone last. An elevated owner-run script recorded the void and restored the exact pre-soak baseline:

- `restore.verified=true`
- daemon `FBD9BDB3…`, Nose `AEAB9B63…`, PEP `870CB962…`
- service env `AEGIS_LOSS_BUDGET=3500`, machine interface pin restored to `\\Device\\NPF_{5FD31C6E-DE48-44CB-838E-14667A04DA4B}`
- service `Running`, `errors=[]`
- health at void: `RUNNING`, all seven loss counters and `shed_overload` **0**

No budget was raised, no PASS was relabelled, and the attempt contributes nothing to `soak_24h`. Verbatim artifacts: `analysis/current-head/raw-aa3b7b0-20261126/soak-void-defer/`.

**Lesson applied:** a detached finalizer owned by the harness command tree does not survive a harness server restart. The final window must be started only after all records work is committed, and its finalizer must be observed independently of the agent shell.
