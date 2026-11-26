# R2003 CommandLine re-measurement on the host — `aa3b7b0` — 2026-11-26

**RECORD-ID:** `R2003-CMDLINE-HOST-PROOF-E5-AA3B7B0-20261126`
**BUILD SOURCE:** `aa3b7b0161e425e54155d5767737bffcde7939b5`
**EVIDENCE LEVEL:** **E5 narrow** (one elevated owner probe on this host with current-source binaries). This is **not** a full 23-rule matrix, a soak, a driver-lifecycle proof, an install campaign or E7.

## What was proven

S1 (`493648f`) added a read-only producer that recovers `ProcessCommandLineInformation`
for Kernel-Process `ProcessStart` events and appends it as AEGT TLV kind 2. That
producer was previously proven only at E2. This record re-measures it on a real
Windows host at the current build source.

The elevated run swapped four current-source binaries into the install tree:

| Binary | SHA-256 |
|---|---|
| `aegis_nids.exe` | `6F548AF7641C1C476FB591D165ED734027ED18D93F980AFEA755C20A716BBB98` |
| `aegis-nose.exe` | `8C05FE485D2548DF50C83F5BEA792F4228FEAE387306668A439912A39A7D24D4` |
| `aegis_pep.dll` | `6E05AAE1BAE000C8D2C1A841EFF9B65035E5131066FFB43800AD414659564926` |
| `aegis_etw_helper.dll` | `B594EC775B69D1BF799DCCD7FCC2DFAA6C6DB9DF1EB4BC967EB3D4C6BA19EECE` |

The Nose capturer used the loopback selector `\Device\NPF_Loopback`; no loss
budget was changed. Results (`v2`, the controlled run):

```text
baseline R2003 rows: 0 (ring_records=8725, verified=true)
POSITIVE  powershell.exe -NoProfile -Command "# AEGIS_R2003_V2_POS_20261126_IEX; Start-Sleep -Seconds 30"
          marker_matched=1, verified R2003 row=1
          record_seq=8919, rule_id=2485705370, source=10 (host_telemetry), verified=true
NEG CMDLINE  benign marker, no IEX in command line: marker_matched=0
NEG WIRE     IEX marker only inside a script file: marker_matched=0
verdict=PASS_E5_NARROW, errors=[]
restore_verified=true, service_status=Running
```

The negative command-line case's `r2003_total` remained `1` because the verified
positive row legitimately stays in the forensic ring; the independent marker for
that case matched `0`, so no new row was attributed to it. The `r2003_delta=1`
field in the raw JSON is relative to the original baseline, not to the positive
case, and must not be read as a second detection.

## Honest record of the discarded run

An earlier probe (`v1`) produced a real positive row but reused one marker across
all three cases, so its negative controls were contaminated. It is recorded as
`NOT_PROVEN` and contributes no evidence credit. Its raw transcript is retained
beside the controlled run. No test, verdict or counter was edited to obtain the
v2 result.

## Boundary

- This closes the **current-source host re-measurement gap for R2003 only**. It
  does not re-measure the 22 other rules; the recorded `22/23` host-evaluable
  census remains a historical snapshot, not a new matrix result.
- No real-Ethernet tagged frame, IPv6 extension-header or non-loopback sensor
  stimulus was generated.
- No full Windows E5 / kernel IDS qualification, soak, E6 simulation or E7 claim.
- All binaries were restored hash-identically; the host was left `Running`.

## Artifacts

Raw artifacts: `analysis/current-head/raw-aa3b7b0-20261126/r2003-e5/`
(`v2-result.json`, `v2-transcript.txt`, `v2-positive_marker.raw.txt`,
`v2-negative_cmd_marker.raw.txt`, `v2-negative_wire_marker.raw.txt`,
`v2-baseline_r2003.raw.txt`, plus the discarded `v1-*` set). The `*.raw.txt`
captures were transcoded from their original UTF-16LE bytes under
`D:\aegis-tmp\r2003-aa3b7b0-20261126-v2\` (and `...-20261126\` for v1) to UTF-8/LF
to satisfy the repository encoding guard; the original captures remain outside
the tree and no value, verdict or evidence level changed.
