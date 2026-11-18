# RB-008: SIEM Ingestion Debugging

## Objective

Know exactly what this host can and cannot do with SIEM formats today,
so debugging starts from truth instead of the old design doc.

## Status first (read this, it changes the procedure)

- There is NO live ingestion listener on this host (no CEF/LEEF/KV
  port, no `siem_endpoint` in `configs/runtime.json`).
- What EXISTS and is proven: the CEF parser/encoder units
  (`src/forensic/siem_forwarder.zig`, `src/xdr/xdr_harden.zig` --
  wired into `zig build test`, 24/24 green) and CEF export strings.
- So: format bugs are triaged in unit tests + lab, never by poking a
  production port that is not there.

## Format reference (stable, keep for eyeball checks)

- CEF: `CEF:0|AEGIS|NIDS|1.0|<rule_id>|<name>|<severity>|<extensions>`
  (pipe-delimited header, space-separated `key=value` extensions).
- LEEF: `LEEF:1.0|...` (pipe header, TAB-separated extensions).
- KEY-VALUE: space-separated `key=value` (empty input rejected).
- Severity: digit 0-9 or low=3/medium=5/high=7/critical=9.
- Max 16 extensions; rest dropped. Slices borrow the input.

## Steps (executable)

1. **Prove the parsers**
   ```bat
   zig build test
   ```
   - siem_forwarder suite must stay 24/24. A format regression shows
     up here first, not on the wire.

2. **Eyeball a suspect line against the shapes above**
   - Missing `CEF:`/`LEEF:` prefix, space-instead-of-tab in LEEF,
     non-numeric severity, >16 extensions: reject causes in that
     order.

3. **Export-side check (what leaves the host)**
   - CEF export strings exist in `src/xdr/xdr_harden.zig` (unit-pinned
     prefix `CEF:0|AEGIS|NIDS|`). Delivery proof is a lab exercise:
     RB-015.

4. **Record**: sample line + verdict (shape-ok / which rule broke).

## Verification

- `zig build test` green (parser units).
- Suspect line classified against the reference, not guessed.

## Rollback

None -- parsing is stateless and read-only from here.

## Notes

- The old revision described a live ingestion port with
  `parseCef/parseLeef/parseKeyVal` handlers. That port does not exist
  on this host; do not go looking for it.
- RB-015 covers delivery; RB-010 covers the export surfaces that do
  exist (Prometheus file below).

## References

- `src/forensic/siem_forwarder.zig` (units + CEF format)
- RB-010, RB-015
