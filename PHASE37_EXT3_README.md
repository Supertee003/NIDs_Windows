# AEGIS NIDS - Phase 37 Extension 3: Enhanced Detection Rules

**Risk**: MEDIUM | **Phase 37 Extension** | **Status: HOST-VERIFIED + 33 tests**

Extends Phase 37's detection capabilities with three new detectors that
close gaps surfaced by the Ext 2 scenario library. The base Phase 37 only
flagged office-apps-spawning-shells; Ext 3 adds web/service/SQL/mail
server detection, command-line anomaly detection, and process injection
heuristics.

## Why This Extension

Phase 37 core detection (parent_child_anomaly) only caught the T1566.001
pattern (Office apps spawning shells). Ext 2 scenarios revealed gaps:

| Scenario | What Should Trigger | What Actually Triggered |
|---|---|---|
| T1190 webshell | w3wp → cmd anomaly | (nothing - w3wp not in parents list) |
| T1078 valid-accounts | svchost → cmd anomaly | (nothing - svchost not in parents list) |
| T1059 command-exec | powershell -enc pattern | (nothing - no cmdline anomaly detector) |
| T1003 credential-dump | process injection pattern | (nothing - no injection detector) |

Ext 3 closes all four gaps with three new detectors.

## Design Principles

Same as Ext 1+2:

- **Pure Zig, host-testable on Linux** — no Win32 API; uses HostEvent
  fields already present in Phase 37 core
- **Additive only** — does NOT modify Phase 37 core (`host_telemetry.zig`);
  instead exposes detector functions that callers compose into the
  pipeline
- **Kill switch OFF by default** — `DetectorConfig{ .enabled = true }` opts in
- **Extended enum maps back** — `ExtendedSuspicionReason.toBaseReason()`
  maps new reasons to existing `ht.SuspicionReason` values so incidents
  flow through the same `CorrelationEngine`

## Files

| File | Purpose |
|---|---|
| `core/host_telemetry_detectors.zig` | 3 detectors + aggregator + extended enum, **33 tests** |
| `core/host_telemetry_detectors_cli.zig` | CLI demo (9 scenarios + PASS/FAIL summary) |
| `core/host_telemetry_detectors_config.json` | Reference config (parent patterns, cmdline tokens, injection indicators) |
| `PHASE37_EXT3_README.md` | This document |

## Architecture

```
                 Phase 37 core (frozen)
                 +-----------------------------+
                 | HostTelemetry.ingestEvent()  |
                 | -> ProcessTracker            |
                 |    (parent_child_anomaly for |
                 |     office apps only)         |
                 +-----------------------------+
                              ^
                              | (additive layer)
                              |
                 +-----------------------------+
                 | Phase 37 Ext 3 (this)        |
                 | +--------------------------+ |
                 | | ExtendedParentDetector   | |  w3wp/apache/nginx/svchost/
                 | |                          | |  sqlservr/etc -> shell
                 | +--------------------------+ |
                 | | CmdlineAnomalyDetector   | |  -enc/-EncodedCommand,
                 | |                          | |  IEX/Net.WebClient,
                 | |                          | |  http:// in cmdline
                 | +--------------------------+ |
                 | | ProcessInjectionDetector | |  temp folder execution,
                 | |                          | |  unsigned elevated in temp
                 | +--------------------------+ |
                 | | EnhancedDetectorAggregator| | runs all 3 + returns
                 | |                          | | up to 3 reasons per event
                 | +--------------------------+ |
                 +-----------------------------+
                              |
                              v
                 ExtendedSuspicionReason (10 new + 10 mirror)
                              |
                              v
                 toBaseReason() -> ht.SuspicionReason
                              |
                              v
                 Phase 37 CorrelationEngine (unchanged)
```

## Three New Detectors

### 1. ExtendedParentDetector

Catches parent-child anomalies beyond office apps. Adds four parent
categories:

| Category | Processes | MITRE |
|---|---|---|
| Web servers | w3wp.exe, apache.exe, nginx.exe, httpd.exe, iisexpress.exe | T1190 |
| Service hosts | svchost.exe, services.exe, csrss.exe, lsass.exe | T1078 |
| SQL servers | sqlservr.exe, mysqld.exe, postgres.exe, oracle.exe | T1190 |
| Mail servers | exim.exe, postfix.exe, dovecot.exe, sendmail.exe | T1190 |

When any of these spawn a shell (cmd/powershell/wscript/cscript/mshta/
rundll32/regsvr32), the detector returns the matching reason
(`web_server_spawning_shell`, `service_host_spawning_shell`, etc.).

### 2. CmdlineAnomalyDetector

Catches suspicious command-line tokens. Three pattern categories:

| Pattern | Tokens | MITRE | Reason |
|---|---|---|---|
| Encoded commands | `-enc`, `-EncodedCommand` + base64 payload | T1059.001 | `encoded_command_payload` |
| Download cradles | `IEX`, `Invoke-Expression`, `Net.WebClient`, `DownloadString`, `Invoke-WebRequest`, `iwr`, `curl http://` | T1059 | `download_cradle` |
| URLs in cmdline | `http://`, `https://` | T1059 | `suspicious_url_in_cmdline` |

The encoded-command check also verifies a base64-looking payload (long
string of `[A-Za-z0-9+/=]` characters) follows the `-enc` flag, to avoid
false positives on legitimate short `-enc` usage.

### 3. ProcessInjectionDetector

Approximates T1055 (Process Injection) detection via image-path
heuristics. Two patterns:

| Pattern | Condition | Reason |
|---|---|---|
| Temp-folder execution | `isInTempFolder(img) AND ppid != 0` | `process_injection_virtual_alloc` |
| Unsigned elevated in temp | `integrity.isElevated() AND isInTempFolder(img) AND !is_signed` | `process_injection_write_memory` |

Temp folder patterns checked: `\temp\`, `\users\public\`,
`\appdata\local\temp\`, `\windows\temp\`.

**Note**: This is a heuristic approximation. Full T1055 detection would
require ETW Thread/VM hooks (`CreateRemoteThread`, `VirtualAllocEx`,
`WriteProcessMemory`) — future Ext 4+ candidate.

## EnhancedDetectorAggregator

Runs all 3 detectors on a `process_create` event. Returns up to 3
reasons (one per detector):

```zig
var agg = det.EnhancedDetectorAggregator.init(.{ .enabled = true });
const result = agg.check(ev, parent_img);
// result.reasons[0..result.count] contains the matched reasons
```

Counts per-detector hits for observability:

- `total_extended_detections` — sum of all detector hits
- `total_parent_detections` — extended parent detector hits
- `total_cmdline_detections` — cmdline anomaly detector hits
- `total_injection_detections` — process injection detector hits

## ExtendedSuspicionReason Enum

Mirrors the base `ht.SuspicionReason` (10 values) and adds 10 new
values. The `toBaseReason()` method maps new reasons back to base
equivalents so incidents flow through the unchanged `CorrelationEngine`:

| New Reason | Maps To |
|---|---|
| `web_server_spawning_shell` | `parent_child_anomaly` |
| `service_host_spawning_shell` | `parent_child_anomaly` |
| `sql_server_spawning_shell` | `parent_child_anomaly` |
| `mail_server_spawning_shell` | `parent_child_anomaly` |
| `encoded_command_payload` | `suspicious_cmdline` |
| `download_cradle` | `suspicious_cmdline` |
| `suspicious_url_in_cmdline` | `suspicious_cmdline` |
| `process_injection_remote_thread` | `suspicious_cmdline` |
| `process_injection_virtual_alloc` | `suspicious_cmdline` |
| `process_injection_write_memory` | `suspicious_cmdline` |

Critical-type reasons (file_integrity_*, registry_*, network_host_*,
process_injection_*) auto-bump incident severity to CRITICAL.

## Quick Start

```bash
# 1. Run unit tests
zig test core/host_telemetry_detectors.zig -lc

# 2. Build CLI demo
zig build-exe core/host_telemetry_detectors_cli.zig -lc

# 3. Run all 9 scenarios + summary (exit 0 iff all pass)
./host_telemetry_detectors_cli demo

# 4. Run a single scenario
./host_telemetry_detectors_cli scenario aggregator-multi
```

Expected demo output (excerpt):
```
AEGIS NIDS - Phase 37 Ext 3: Enhanced Detection CLI

  -> kill switch off; detection count=0
  -> w3wp -> cmd; reason[0]=WEB_SERVER_SPAWNING_SHELL, count=1
  -> httpd -> powershell; reason[0]=WEB_SERVER_SPAWNING_SHELL
  -> svchost -> cmd; reason[0]=SERVICE_HOST_SPAWNING_SHELL
  -> sqlservr -> cmd; reason[0]=SQL_SERVER_SPAWNING_SHELL
  -> powershell -enc; encoded_payload_detected=true, count=1
  -> IEX Net.WebClient; download_cradle_detected=true, count=1
  -> unsigned in temp; injection_detected=true, count=1
  -> multi-detection; reasons=[WEB_SERVER_SPAWNING_SHELL, ENCODED_COMMAND_PAYLOAD], count=2
  [PASS] kill-switch-off
  [PASS] web-server-shell
  [PASS] apache-shell
  [PASS] svchost-shell
  [PASS] sql-server-shell
  [PASS] encoded-command
  [PASS] download-cradle
  [PASS] injection-temp
  [PASS] aggregator-multi

9/9 scenarios passed
```

## Integration Sketch

```zig
const det = @import("host_telemetry_detectors.zig");
const ht = @import("host_telemetry.zig");

// On startup, after HostTelemetry.init():
var agg = det.EnhancedDetectorAggregator.init(.{ .enabled = true });

// In your process_create handler (e.g. ETW callback):
// 1. Let Phase 37 core process the event first
const base_reason = host.ingestEvent(ev);

// 2. Run extended detectors on the same event
const parent_img = host.tracker.getProcess(ev.ppid).?.imagePath();
const result = agg.check(ev, parent_img);

// 3. Forward each extended reason to the correlation engine
// (via toBaseReason() so it flows through the same pipeline)
for (result.reasons[0..result.count]) |ext_reason| {
    std.log.info("extended detection: {s} -> {s}",
        .{ ext_reason.toString(), ext_reason.toBaseReason().toString() });
    // Optionally create an incident with ext_reason instead of base
    // if you want the more specific label in the audit log
}
```

## Verification Checklist

Run on host (Linux or Windows) before promoting to production:

```
[ ] zig test core/host_telemetry_detectors.zig -lc             -> "All 69 tests passed"
                                                                 (33 detectors + 33 host_telemetry
                                                                  + 3 misc transitively)
[ ] zig build-exe core/host_telemetry_detectors_cli.zig -lc    -> clean compile
[ ] ./host_telemetry_detectors_cli demo                       -> "9/9 scenarios passed" (exit 0)
[ ] ./host_telemetry_detectors_cli scenario aggregator-multi   -> [PASS]
[ ] Inspect core/host_telemetry_detectors_config.json         -> valid JSON, kill_switch.enabled=false
```

## Risk & Rollback

- **Risk**: MEDIUM — additive detection layer; no enforcement changes
- **Rollback**: set `DetectorConfig.enabled = false` (kill switch) —
  module becomes a no-op. To fully remove: stop calling
  `EnhancedDetectorAggregator.check()` and unlink the import.
- **Failure mode**: extended detectors are heuristics; expect some false
  positives on legitimate admin activity (e.g. DBA running cmd from
  sqlservr context, dev running powershell -enc for legitimate scripts).
  Tunable via `DetectorConfig` per-detector enables.
- **Future enhancement**: full T1055 process injection detection would
  require ETW Thread/VM hooks (`CreateRemoteThread`, `VirtualAllocEx`,
  `WriteProcessMemory`) — Ext 4+ candidate (Windows-only).

## Phase 37 Extension Progress

| Extension | Status | Tests | Notes |
|---|---|---|---|
| Ext 1 — Mock Telemetry Source | COMPLETE | 26 | MockTelemetrySource + EventPump + 4 scenarios |
| Ext 2 — Scenario Library | COMPLETE | 18 | 5 new MITRE scenarios + 1 combined |
| **Ext 3 — Enhanced Detection** | **COMPLETE (this)** | **33** | **3 new detectors + aggregator** |
| Ext 4 — Real ETW Adapter | PENDING | — | Windows-only; needs Win32 API |
| Ext 5 — Real FIM Adapter | PENDING | — | Windows-only; ReadDirectoryChangesW |
| Ext 6 — Real RegNotify Adapter | PENDING | — | Windows-only; RegNotifyChangeKeyValue |
| Ext 7 — Full T1055 Detection | PENDING | — | ETW Thread/VM hooks (Windows-only) |

Combined Ext 1 + Ext 2 + Ext 3: 10 MITRE scenarios with 3 enhanced
detectors covering T1190, T1078, T1059, T1055 patterns.
