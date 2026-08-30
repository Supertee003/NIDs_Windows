# RB-008: SIEM Ingestion Debugging

## Objective
Debug SIEM ingestion issues when external events (CEF, LEEF, KEY-VALUE format) are not being properly ingested by AEGIS NIDS. This runbook covers diagnosing and fixing ingestion problems.

## Prerequisites
- AEGIS NIDS running with SIEM integration enabled
- Access to SIEM ingestion logs
- Sample SIEM events for testing (CEF, LEEF, KEY-VALUE formats)

## Steps

1. **Verify SIEM source is sending events**
   - Check network connectivity to the SIEM ingestion port
   - Verify the external SIEM (Cisco ASA, IBM QRadar, etc.) is configured to send events
   - Capture a sample event from the wire (tcpdump/Wireshark)

2. **Identify the SIEM format**
   - CEF: starts with `CEF:version|vendor|product|...`
   - LEEF: starts with `LEEF:version|vendor|product|...`
   - KEY-VALUE: space-separated `key=value` pairs (no prefix)

3. **Test CEF ingestion**
   ```
   input = "CEF:0|AEGIS|NIDS|1.0|100|SQL Injection|9|src=10.0.0.1 act=block"
   event = parseCef(input)
   ```
   - Verify event is non-null
   - Check: vendor="AEGIS", product="NIDS", sig_id="100", severity=9
   - Check: 2 extensions (src=10.0.0.1, act=block)
   - If null: input doesn't start with "CEF:" or malformed

4. **Test LEEF ingestion**
   ```
   input = "LEEF:1.0|AEGIS|NIDS|1.0|src=10.0.0.1\tact=block\tsev=9"
   event = parseLeef(input)
   ```
   - Verify event is non-null
   - Check: vendor="AEGIS", product="NIDS", dev_version="1.0"
   - Check: 3 extensions (tab-separated)
   - Check: severity=9 (from "sev" extension)
   - If null: input doesn't start with "LEEF:" or malformed

5. **Test KEY-VALUE ingestion**
   ```
   input = "src=10.0.0.1 act=block sev=9 rule=100"
   event = parseKeyVal(input)
   ```
   - Verify event is non-null
   - Check: 4 extensions (space-separated)
   - Check: severity=9 (from "sev" key)
   - If null: no key=value pairs found (empty input rejected)

6. **Check extension parsing**
   - Extensions should be stored in inline array (MAX_EXTENSIONS=16)
   - Verify `event.extension_count` matches expected
   - Check `event.extensions[i].key` and `event.extensions[i].value`
   - If count > 16: only first 16 stored (rest silently dropped)

7. **Verify normalization**
   - All 3 formats should produce `NormalizedEvent`
   - Check `event.source_format` is correct (.cef, .leef, or .keyval)
   - Same logical event in 3 formats should produce same severity

8. **Check for common issues**
   - **Missing prefix**: CEF requires "CEF:", LEEF requires "LEEF:"
   - **Wrong delimiter**: LEEF uses tabs (0x09) for extensions, not spaces
   - **Malformed severity**: must be digit 0-9 or named (low/medium/high/critical)
   - **Too many extensions**: max 16, rest dropped
   - **Empty input**: KEY-VALUE returns null for empty string

9. **Record the debugging session**
   - Audit trail records: action=subsystem_status_change (SIEM)
   - Include the issue and resolution in the detail field

## Verification
- `parseCef(valid_cef_input)` returns non-null NormalizedEvent
- `parseLeef(valid_leef_input)` returns non-null NormalizedEvent
- `parseKeyVal(valid_keyval_input)` returns non-null NormalizedEvent
- `parseKeyVal("")` returns null (empty input rejected)
- All formats produce same severity for same logical event
- Extensions accessible (inline array, no dangling slice)

## Rollback
No rollback needed - SIEM parsing is stateless. If a fix is applied (e.g., correcting the SIEM source configuration), verify with a test event.

## Notes
- CEF: 8 pipe-delimited header fields + space-separated key=value extensions
- LEEF: 5 pipe-delimited header fields + tab-separated key=value extensions
- KEY-VALUE: space-separated key=value pairs (generic format)
- Max extensions: 16 (inline array, no heap allocation)
- Severity mapping: digit (0-9) or named (low=3, medium=5, high=7, critical=9)
- All parsed slices point INTO the input (caller-owned, no dangling pointers)

## References
- G16: `core/siem_integration_proof.zig` - SIEM integration proof
- G15: `core/telemetry_export_proof.zig` - Telemetry export (CEF output)
- `docs/runbooks/RB-010-telemetry-export-setup.md` - Telemetry export setup
