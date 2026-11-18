# PROCESS-CMDLINE-001 — command line is not in either process lane

**Created:** 2026-11-18
**Records HEAD at measurement:** `e04d192`
**Measured on:** installed daemon + installed `aegis_etw_helper.dll`
**Level:** E5 for the live measurement, E1 for the provider-manifest check
**Status:** accepted limitation (gap closed)

---

## Question

`R2003` (`IEX|DownloadString|DownloadFile|PS_CRADLE|Net.WebClient`) is a
`KERNEL_PROCESS` rule. It has never fired on a real process launch. The earlier
diagnosis (`PROJECT-SCAN-20261118.md`) proved the layer routing is now correct
and left one question: does the process-create payload carry the command line?

## What was tried first

`src/windows/etw_native.c` enabled `Microsoft-Windows-Kernel-Process` with
`MatchAnyKeyword = AEGIS_WINEVENT_KEYWORD_PROCESS (0x10)`, on the theory that the
provider hides `ProcessStart.CommandLine` unless its Process keyword is on.
The helper was built, installed as `C:\Program Files\AEGIS NIDS\runtime\aegis_etw_helper.dll`
(sha256 `c6a910e4dbf873ee668f44076410b47410cc9ea88bd66783c349965eced49dbc`,
identical to `build-helper/Release/aegis_etw_helper.dll`), and the service was
started after the file was written (service PID 29084, creation
2026-11-18 16:54:45; DLL mtime 16:54:21). The running helper therefore contains
the change.

## Measurements

### 1. Process events are flowing

`aegisctl queue --json` → `etw.process_start` advanced
2412 → 2755 → 3929 → 3944 across the test window with `dropped_total = 0` and
`capture_etw.dropped = 0`. The lane is alive; this is not a lost-sensor result.

### 2. The same process row exists, without its arguments

Launched (marker in the command line):

```
powershell -NoProfile -Command "Start-Sleep -Milliseconds 2500" -AegisMarker CMDPROBE9173
```

(PowerShell rejected `-AegisMarker`, but the text is still part of the created
process's command line.) Within one second:

| query (`forensic search --field payload_contains`) | result |
|---|---|
| `CMDPROBE9173` | **0 records** |
| `powershell.exe` | 2 records: `file_sensor` 61 B, `host_telemetry` 306 B |

The ETW process row for that exact launch is in the ring (306 bytes) and the
argument is not in it.

Earlier the same day, `IEX 'Write-Output aegis-cmdline-probe-20261118'` added no
`R2003` row: `aegis_core.ndjson` still held 2 matches, both from before the run
and outside ring retention. `R2003` remains inert.

### 3. The provider does not publish it at all

`Get-WinEvent -ListProvider Microsoft-Windows-Kernel-Process` on this host lists
`ProcessStart` (Id 1) versions 0 through 4. Their templates are:

| version | fields |
|---|---|
| 0 | ProcessID, CreateTime, ParentProcessID, SessionID, ImageName |
| 1 | … + Flags |
| 2 | … + ImageChecksum, TimeDateStamp, PackageFullName, PackageRelativeAppId |
| 3 | … + ProcessSequenceNumber, ParentProcessSequenceNumber, ProcessTokenElevationType, ProcessTokenIsElevated, MandatoryLabel |
| 4 | same set as v3 |

**No version has a `CommandLine` field.** `wevtutil gp` confirms
`WINEVENT_KEYWORD_PROCESS = 0x10`, so the keyword was correct but cannot reveal a
field the event does not define.

### 4. The other lane carries only the image path

`src/capture/minifilter_reader.zig::submitRecord()` sets
`ce.payload_length = path_utf8.len` and pushes `path_utf8`; the process-create
rows measured here are the 61-byte image paths (`file_sensor` source). This is
the second process lane and it has no command line either.

## Conclusion

Command-line visibility is structurally unavailable from both current process
lanes:

* `Microsoft-Windows-Kernel-Process/ProcessStart` (Id 1, v0–v4) has no
  `CommandLine` field, regardless of keyword mask.
* The minifilter process record carries the image path only.
* Therefore `R2003` cannot match a host process row. `R2001`/`R2002`/`R2005`
  still work because they match image names; `R2004` was proven live earlier.

This is recorded as a limitation, not a failed fix. The keyword change is kept
because it narrows the provider to the only events the pipeline consumes
(`ProcessStart`), and it is now the installed helper's behaviour; its comment was
corrected so it no longer claims to add command-line visibility.

## What a real fix would require (v1.1+, not done here)

1. **NT Kernel Logger** session with `EVENT_TRACE_FLAG_PROCESS`. It is a
   singleton, requires an elevated session, and its records are MOF-style rather
   than the manifest/TDH path this helper uses. New parser, new lifecycle, new
   soak.
2. **Driver-side enrichment**: the minifilter or a small kernel component reads
   the new process command line and adds it to the record. Driver rebuild, signing
   and a race policy for short-lived processes.

Either option is a new feature with its own ABI/authority review. Retargeting
`R2003` to image-name matching was rejected: `powershell.exe` alone fires on
normal administration and would be a false-positive generator, not a replacement
for content detection.

## What is not claimed

* No claim that `R2003` works, or that the detection gap is gone.
* No change to detection rules, the wire schema, the PEP/WFP boundary or the
  installed daemon binary.
* E5 here means "measured on this installed host"; the absence of the field is
  also fixed by the provider manifest, so it is not host-specific.
