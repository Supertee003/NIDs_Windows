# Issue #29 addendum — ADR-0012 measurement status conflict

**Date:** 2026-11-08
**Current source baseline:** `adb1b73`
**Affected decision:** `docs/adr/0012-fim-ingress-volume.md`

## Stop-line finding

ADR-0012's header says the duplicate-ratio E5 gate PASSED, while its measurement-gate section says “not yet measured,” says nothing was deployed, and still lists the measurement as open. This is a contradictory source-of-truth record under the project stop-line rules. No FIM coalescing code should be added while this conflict remains unresolved.

## Evidence inspected

The ignored operator archive `admin-evidence/adr0012-dup-ratio-20261108/` contains deployed-build results tied to source commit `dfececbd708ee5a49f017038568c807aee9b8d72` (an ancestor of current HEAD), including `elevated-deploy-v6-result.json`, three phase summaries, 66 NDJSON samples, and final queue stats. The measurement used six workers and 20,000 files. Per-PID duplicate ratios were 48.177% for create-once, 49.391% for rewrite, and 56.992% for recreate; all three summaries report zero probe overflow. This exceeds the ~10% FIM-only deficit in the ADR's baseline.

The final queue snapshot separately reports 575,935 minifilter same-timestamp duplicates. This supports investigating duplicate callback delivery, but it does not by itself prove queue-drop reduction from coalescing. No coalescer or `fim_coalesced_total` was deployed in this measurement.

`elevated-revert-result.json` shows the proof-root environment was removed but the installed executable hash remained the probe build hash. Treat the host as still running that measurement build until its installed hash is checked; do not describe this as binary rollback.

## Resolution

The ADR and evidence index were reconciled to say that the measurement gate passed and the coalescing slice is accepted for implementation, while the loss-reduction implementation/E5 gate remains open. This is a records correction only; no runtime code changed in this addendum.
