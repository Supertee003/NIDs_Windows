# RB-003: Audit Trail Tamper Investigation

## Objective

Respond to a suspected-tampered record store. Do not fix anything by
hand -- the chain is tamper-evident by design, and hand edits destroy
the evidence you are investigating.

## Prerequisites

- A reason for suspicion (verify failure, gap, anomaly). No elevation.

## Steps

1. **Run hash-chain verification**
   ```bat
   python tools\aegisctl.py forensic verify
   ```
   - `verified: true` ends the investigation (record the all-clear).
   - Anything else (or a timeout under load -- re-run quiet first,
     see EVT-148) starts it.

2. **Export the current state BEFORE touching anything**
   ```bat
   python tools\aegisctl.py forensic export
   ```
   - Keep the export offline. This is your evidence copy.

3. **Scope with record queries**
   ```bat
   python tools\aegisctl.py forensics list
   python tools\aegisctl.py forensic show --id <first-suspect>
   ```
   - Chain breaks cascade forward: the earliest anomaly bounds the
     scope; everything after it is suspect until proven otherwise.

4. **Classify (record for the report, do not repair)**
   - Content changed under a stored hash, link break (insert/delete/
     reorder), or field edit -- note which, with ids.

5. **Escalate, then restore**
   - Escalate suspected compromise per local incident process.
   - Restore integrity only via RB-004 (known-good snapshot), never
     by editing records.

## Verification

- `verify` true after restore, on the restored store.
- Export + written scope note exist before any restore ran.

## Rollback

- Do NOT "fix" records. Rollback here means RB-004 restore.

## Notes

- Genesis-seeded chain; any field edit breaks verification loudly.
- A verify timeout under display/test load is contention, not
  tampering -- re-run quiet (EVT-147/148).

## References

- RB-002 (query), RB-004 (restore), EVT-156 deploy proofs
