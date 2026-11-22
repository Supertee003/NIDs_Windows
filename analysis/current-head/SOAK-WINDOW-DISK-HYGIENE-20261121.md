# SOAK-WINDOW-DISK-HYGIENE-20261121 — disclosed in-window host hygiene action

**Status: DISCLOSURE only. Not a gate result. Not a PASS. No counter was reset, no AEGIS service restarted, no topology or load change.**

## Context

The fresh 466a226 24 h soak started at `2026-11-21T03:34:12.757760` (+07:00)
from a verified zero-loss baseline (`process_generation_ms=1795206470719`).
At `2026-11-21T23:18` (19.85 h elapsed) a read-only check showed:

- `state=RUNNING`, `degraded=false`, generation unchanged
- all seven loss/shed counters still exactly `0`

## Observation

The agent harness could not write one of its own output files:
`failed to write output file: There is not enough space on the disk (os error 112)`.
`Get-Volume C:` / `Get-PSDrive C:` reported `SizeRemaining=0` on a
287,446,134,784-byte volume. No CBS `RebootPending`, no WU `RebootRequired`,
no `pending.xml`, no running `TiWorker`/`TrustedInstaller`/`wuauclt` were found.

## Action taken (owner-approved)

The owner explicitly approved removing **one stale temp file**:

`C:\Users\User\AppData\Local\Temp\b33e1c86-0109-4111-aa9f-41a672ce6a1b.tmp`
(11,647,068 bytes, last written 2026-11-18 16:07:55, GUID-named `.tmp`).

It was removed with `Remove-Item -Force`. The owner had already been told that
one file-delete event is negligible against the 3,500-row loss budget.

After the deletion:

- a 4,096-byte write probe to `C:\Users\User\AppData\Local\Temp` succeeded and
  the probe file was removed;
- a re-check at 19.93 h returned `RUNNING`, `degraded=false`, generation
  `1795206470719` unchanged, and **all seven counters still 0**.

`Get-Volume` continued to report `SizeRemaining=0` after the deletion even
though writes succeeded — this is a reporting discrepancy, not a claim that
the freed space is unavailable. It should be re-checked before `-Mode final`,
because that command must write `soak-24h-delta-final.json` on C:.

## Why this does not void the window

The AEGIS services were not restarted, the installed bundle and drivers were
not changed, the process generation is identical, no counter was reset, and no
load was injected. The action removed one orphaned temp file outside the
product tree. The counters stayed at zero after it.

## Follow-up

Before/after `-Mode final`, confirm the final artifact exists and parses with
`verdict=PASS`, `elapsed_hours >= 24`, `problems=[]`, and the same generation.
If C: is still full at that point, free more space with owner approval first —
never rewrite the checker, the budgets, or the artifact.
