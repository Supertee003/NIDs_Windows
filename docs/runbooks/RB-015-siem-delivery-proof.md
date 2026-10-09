# RB-015: SIEM Delivery Proof (Lab)

> Lab only for the enabled-forwarder run (it opens egress to the lab
> SIEM/sink). The failure-path proof (refused endpoint -> spool) is safe
> anywhere but proves the most on the same VM that will later deliver.

## Objective

Prove the opt-in forwarder delivers: disabled default -> file-sink
delivery with metrics -> refused-endpoint spool with metrics ->
replay drains the spool. Each phase is asserted through
`metrics.snapshot → siem:{...}`, never by vibes.

## Prerequisites

- Lab VM with the service installed. A sink: either a file path (no
  network needed) or a lab TCP/HTTP listener (netcat, logstash, splunk
  HEC, elastic `_bulk` — see presets in `configs/siem_config.json`).
- `configs/siem_config.json` present (fields: enabled, format
  ndjson|cef|syslog, transport file|http|https|tcp|udp, destination,
  batch_size, flush_interval_ms, retry_count/delay, include_fields).
- Fixture generator ready (`scripts/aegis_event_gen.py --pipe`).

## Steps

1. **Disabled baseline** (default, no env):
   ```
   python tools/aegisctl.py metrics
   ```
   Require `siem.enabled:false` (or the siem block absent/zeroed).
   The forwarder must not exist until opted in.

2. **File-sink delivery**:
   - Set `AEGIS_SIEM=1`, `AEGIS_SIEM_TRANSPORT=file`,
     `AEGIS_SIEM_DEST=<lab path, e.g. C:\Temp\siem_out.json>`
     in the service environment; restart the service.
   - Generate traffic: a few `--fixture xss` pipe events plus normal
     background (detections forward; rule-0 traffic does not).
   - Require: `siem.enabled:true`, `forwarded>0`, `batches>0`,
     `spooled==0`, `failed==0`; the destination file holds one JSON
     object per line with the configured `include_fields`.
   - Cross-check line count against `forwarded` (equal, not
     approximately).

3. **Failure-path spool** (proves no-loss, the point of the spool):
   - Point the transport at a REFUSED endpoint (closed port on
     127.0.0.1, e.g. TCP to a port with no listener); restart.
   - Generate traffic; require `failed>0`, `spooled>0`,
     `retries>0`, and a `<destination>.spool` file with the
     undelivered lines.
   - Expect the service to keep detecting (spool never blocks the
     pipeline; failure is counted, not fatal).

4. **Replay drains the spool**:
   - Restore a working destination; the forwarder replays on its
     flush cadence. Require `spooled==0` again, `forwarded`
     increased by exactly the spooled count, and the `.spool` file
     REMOVED (replay deletes only on full drain — a leftover spool
     with `spooled==0` is a bug, file it with the metrics output).

5. **Disable again**: unset `AEGIS_SIEM`, restart, confirm the
   step-1 baseline returns (no forwarder, no egress attempts).

## Verification

- Metrics transitions: disabled -> delivering -> spooling -> drained
  -> disabled, each asserted from `metrics.snapshot`.
- File contents: destination lines parse as JSON with required fields;
  counts reconcile with `forwarded` at every phase.
- No detection impact: rules still match during spool phases
  (spot-check `alerts`).

## Rollback

Step 5 IS the rollback (env unset + restart). Delete lab sink files.
The spool file must not survive a drained state — if it does, keep it
as evidence and file the bug instead of deleting.

## Notes

- SIEM forwarding is the ONLY network egress the daemon initiates
  (brain channel excepted when enabled); keep it lab-scoped and say
  so in the test record.
- Batching means `forwarded` moves in steps of `batch_size` — assert
  divisibility-tolerant equality (>= and congruent), not exact
  per-event increments.
- RB-008 covers ingestion-side debugging (SIEM reading our output);
  this runbook covers our delivery to the SIEM.

## References

- Config + forwarder: `configs/siem_config.json`,
  `src/forensic/siem_forwarder.zig` (semantics, presets, spool/replay),
  `src/daemon.zig` (initSiemFromEnv).
- Metrics surface: `handler_registry.zig` (metrics.snapshot siem block).
- Spool/replay pins: forwarder tests (refused-TCP spool + replay).
- Debug companion: RB-008.
