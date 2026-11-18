# RB-004: Restore from Snapshot

## Objective

Recover system state from a previously captured snapshot using the
upgrade/rollback tool. Destructive by nature: read fully before running.

## Prerequisites

- Admin shell (service restart is part of recovery).
- A snapshot id from a previous capture.

## Steps

1. **List and pick**
   ```bat
   python tools/upgrade_rollback.py report
   ```
   - Choose by incident timeline (latest known-good, not latest).
   - Record the snapshot id and why it is trusted.

2. **Capture the current (broken) state first**
   ```bat
   python tools/upgrade_rollback.py snapshot
   ```
   - Never roll back without a return ticket.

3. **Verify, then roll back**
   ```bat
   python tools/upgrade_rollback.py rollback --snapshot <id>
   ```
   - The tool verifies integrity before applying; a failed verify
     aborts (do not force it).

4. **Restart and confirm**
   ```bat
   sc.exe stop AegisNids
   sc.exe start AegisNids
   python scripts\aegis_open.py status
   ```
   - In PowerShell, `sc.exe` with the extension -- bare `sc` is the
     Set-Content alias and writes junk files (see EVT-163). If SCM
     stop hangs, use `aegisctl stop --all` (GAP-017).
   - Expect 4 OK rows; daemon pid must be new.

5. **Confirm the restore**
   - `status` green, DEFCON as expected, events flowing
     (`events count` advances), `forensic verify` true.

6. **Record**: snapshot id, reason, before/after pids, verify output.

## Verification

- Status green on the new pid; ring verifies; flow resumes.
- RTO is measured wall-clock by the tool (`report`).

## Rollback of the rollback

- The step-2 snapshot is the way back; earlier snapshots next.
- If everything fails: reinstall from release media, then restore.

## Notes

- RPO/RTO are measured by the tool, not promised by this doc.
- Keeper task: disable during the window, re-enable after
  (`schtasks /change /tn AegisKeeper /disable|/enable`), or it may
  start the service mid-procedure.

## References

- `tools/upgrade_rollback.py --help`, `tools/fresh_deploy.py --plan`
- RB-005 (config-only rollback, lighter), GAP-017 (stop paths)
