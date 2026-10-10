# RB-002: Forensic Query for Incident Reconstruction

## Objective

Reconstruct an incident from the forensic record store. Everything here
is read-only; the log is append-only and immutable.

## Prerequisites

- System running (any state). No elevation needed.

## Steps

1. **Scope the incident**: fix one of event_id, source IP, time window,
   or minimum severity before querying.

2. **Query by event id (most precise)**
   ```bat
   python tools\aegisctl.py forensic show --id <event_id>
   ```

3. **Query by source IP (host investigation)**
   ```bat
   python tools\aegisctl.py forensic search --field src_ip --value <ip>
   ```

4. **Query by time window / severity (sweep)**
   ```bat
   python tools\aegisctl.py events tail --count 50
   python tools\aegisctl.py events stats
   python tools\aegisctl.py forensics list
   ```
   - `stats`/`count` bound the sweep before you page through it.

5. **Verify integrity first when it matters**
   ```bat
   python tools\aegisctl.py forensic verify
   ```
   - `verified: true` (~5s) or stop and say why: no conclusion from an
     unverified ring.

6. **Share carefully (no redact command exists)**
   - Mask the last IP octet and drop ports/payloads BY HAND before any
     external sharing. There is no automated redactor on this host;
     anyone promising one is selling the old design doc.

7. **Replay (lab/CI only)**
   - Deterministic replay is proven in `zig build test`, not by hand
     on prod. Do not inject synthetic events into the production ring.

## Verification

- Returned records carry identifiers (event/rule/trace/audit ids).
- `verify` true for any integrity claim.
- Shared material hand-masked.

## Rollback

None -- queries are read-only.

## Notes

- The log is append-only; empty filters return broad results, so scope
  first (step 1).
- Retention is bounded (ring overwrites oldest); export promptly
  (`forensic export`) when an incident matters.

## References

- RB-003 (tamper response when verify fails)
- `zig build test` (replay determinism proofs)
