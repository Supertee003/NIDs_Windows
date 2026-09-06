# AEGIS NIDS - Phase 37 Extension 2: Scenario Library

**Risk**: MEDIUM | **Phase 37 Extension** | **Status: HOST-VERIFIED + 18 tests**

Adds 5 new scripted attack scenarios matching additional MITRE ATT&CK
techniques to the mock telemetry library from Phase 37 Ext 1. Each
scenario is a function that appends scripted `(HostEvent, delay_ns)`
tuples to a `MockTelemetrySource`, designed to trigger specific suspicion
reasons in the Phase 37 detection pipeline.

## Why This Extension

Phase 37 Ext 1 (Mock Source) shipped with 4 basic scenarios (macro-dropper,
persistence, unsigned-system, lateral-movement). For broader security
testing coverage and to validate the detection pipeline against more
attack patterns, Ext 2 adds:

1. **T1003 — Credential Dumping**: LSASS dump file creation + exfil socket
2. **T1059 — Command Execution**: cmd → powershell -enc → curl download chain
3. **T1486 — Ransomware**: Mass file encryption + ransom note
4. **T1078 — Valid Accounts**: Suspicious admin logon + lateral SMB
5. **T1190 — Webshell**: Webshell drop in inetpub + reverse shell

Plus 1 combined attack chain:
- **T1190+T1486 — Full Kill Chain**: Webshell drops ransomware, mass encryption follows

## Design Principles

Same as Ext 1:

- **Pure Zig, host-testable on Linux** — no Win32 API; reuses `MockTelemetrySource`
  from Ext 1
- **Additive only** — test scaffolding, not production code
- **Kill switch OFF by default** — scenarios respect `MockConfig.enabled`
- **Each scenario self-contained** — can be composed via `MultiSourcePump`
- **MITRE ATT&CK mapped** — each scenario tagged with technique ID for
  traceability

## Files

| File | Purpose |
|---|---|
| `core/host_telemetry_scenarios.zig` | 5 new scenario builders + 1 combined chain + helper functions, **18 tests** |
| `core/host_telemetry_scenarios_cli.zig` | CLI demo (7 scenarios + PASS/FAIL summary, exit 0 iff all match) |
| `core/host_telemetry_scenarios_config.json` | Scenario catalog with MITRE mappings + detection coverage matrix |
| `PHASE37_EXT2_README.md` | This document |

## Architecture

```
                 Phase 37 Ext 1 (foundation)
                 +-----------------------------+
                 | MockTelemetrySource          |
                 | + EventPump + MultiSourcePump |
                 +-----------------------------+
                              ^
                              | (extends with new scenarios)
                              |
                 +-----------------------------+
                 | Phase 37 Ext 2 (this)       |
                 | +--------------------------+ |
                 | | buildCredentialDump     | |  T1003
                 | | buildCommandExecution   | |  T1059
                 | | buildRansomware          | |  T1486
                 | | buildValidAccounts        | |  T1078
                 | | buildWebshell             | |  T1190
                 | | buildFullKillChain        | |  T1190+T1486
                 | +--------------------------+ |
                 +-----------------------------+
                              |
                              v
                 +-----------------------------+
                 | EventPump -> HostTelemetry  |  (Phase 37 core)
                 | -> CorrelatedIncident       |
                 +-----------------------------+
```

## Scenario Catalog

### T1003 — Credential Dumping (LSASS)

**Pattern**: Attacker process opens LSASS memory, dumps to file in temp
folder, exfiltrates via TCP socket to non-standard port.

```
t=0ms   : taskhost.exe spawns (unsigned, HIGH integrity, in C:\Users\Public)
t=5ms   : lsass.dmp created in C:\Users\Public\ (50MB, classic LSASS dump size)
t=10ms  : TCP socket to 203.0.113.99:8888 (non-standard exfil port)
```

**Detection**: `unsigned_elevated` suspicion from process_create; FIM
file_create in user-writable path; socket tracked for potential ML verdict
correlation.

### T1059 — Command and Scripting Interpreter

**Pattern**: User-initiated cmd.exe spawns powershell.exe with `-enc` flag
(encoded base64 command), which spawns curl.exe to download next-stage
payload via HTTP.

```
t=0ms   : cmd.exe spawned by explorer.exe (PID 100)
t=5ms   : powershell.exe spawned by cmd.exe with -enc <base64>
t=10ms  : curl.exe spawned by powershell.exe
t=15ms  : TCP socket to 198.51.100.50:80 (HTTP download)
```

**Detection**: 3 processes tracked (cmd/ps/curl); outbound socket from
curl PID tracked for ML verdict correlation.

### T1486 — Data Encrypted for Impact (Ransomware)

**Pattern**: Unsigned ransomware binary spawns, mass-modifies 5 user
Documents files (1MB each), creates ransom note.

```
t=0ms   : sysupdate.exe spawns (unsigned, HIGH integrity, in C:\Users\Public)
t=1-5ms : 5 file_modify events on Documents/*.docx/xlsx/zip/pptx/accdb
t=6ms   : README_LOCKED.txt created in Documents folder
```

**Detection**: `unsigned_elevated` suspicion from process_create; 6 FIM
file_create observations (no baselines set, so all return `.created`).

### T1078 — Valid Accounts (Suspicious Logon)

**Pattern**: Process spawns with admin SID (RID 500), opens socket to
internal SMB port (445), then escalates to SYSTEM via cmd.exe.

```
t=0ms   : svchost.exe spawns with SID S-1-5-21-...-500 (Administrator)
t=5ms   : TCP socket to 10.0.0.50:445 (SMB - lateral movement target)
t=10ms  : cmd.exe spawned by svchost (anomaly: svchost spawning shell)
```

**Detection**: 2 processes tracked; lateral movement socket tracked;
cmd.exe spawned by svchost would be flagged if svchost were in the
suspicious-parents list (future enhancement).

### T1190 — Exploit Public-Facing Application (Webshell)

**Pattern**: Webshell file dropped in `C:\inetpub\wwwroot\uploads\`,
executed by w3wp.exe (web server), which spawns cmd.exe as reverse shell.

```
t=0ms   : config.php created in inetpub\wwwroot\uploads\ (webshell)
t=1ms   : w3wp.exe registered as parent (PID 5000, SYSTEM integrity)
t=5ms   : cmd.exe spawned by w3wp.exe (anomaly: web server spawning shell)
t=10ms  : TCP socket to 198.51.100.200:4444 (reverse shell)
```

**Detection**: 2 processes tracked; reverse shell socket tracked for ML
verdict correlation; w3wp.exe -> cmd.exe would be flagged if w3wp were in
the suspicious-parents list (future enhancement).

### T1190+T1486 — Full Kill Chain

**Pattern**: Combines webshell drop + ransomware execution in a single
scenario. Webshell spawns cmd.exe, which spawns unsigned ransomware
binary, which mass-encrypts files.

```
Phase 1 (T1190): 4 webshell events (file_create + w3wp + cmd + reverse_shell)
Phase 2 (T1486): rw_proc spawns + 3 file_modify events
Total: 8 events across 2 attack phases
```

**Detection**: 3 processes tracked (w3wp + cmd + rw_proc); 1 reverse
shell socket; 4 FIM file_create observations.

## Detection Coverage Matrix

| Suspicion Reason | T1003 | T1059 | T1486 | T1078 | T1190 | T1190+T1486 |
|---|---|---|---|---|---|---|
| `parent_child_anomaly` | — | — | — | — | — | — |
| `unsigned_elevated` | ✓ | — | ✓ | — | — | ✓ |
| `unsigned_system_path` | — | — | — | — | — | — |
| `file_integrity_mismatch` | — | — | — | — | — | — |
| `file_integrity_deleted` | — | — | — | — | — | — |
| `registry_persistence_key` | — | — | — | — | — | — |
| `registry_critical_key` | — | — | — | — | — | — |
| `network_host_correlation` | (if ML verdict) | (if ML verdict) | (if ML verdict) | (if ML verdict) | (if ML verdict) | (if ML verdict) |

**Note**: `parent_child_anomaly` is currently only triggered for
office-spawning-shell patterns (T1566.001). Future enhancement: extend
the suspicious-parents list to include web servers (w3wp.exe, apache.exe,
nginx.exe) and svchost.exe to catch T1190 and T1078 anomalies.

## Quick Start

```bash
# 1. Run unit tests (host: Linux or Windows)
zig test core/host_telemetry_scenarios.zig -lc

# 2. Build CLI demo
zig build-exe core/host_telemetry_scenarios_cli.zig -lc

# 3. Run all 7 scenarios + summary (exit 0 iff all pass)
./host_telemetry_scenarios_cli demo

# 4. Run a single scenario
./host_telemetry_scenarios_cli scenario ransomware
```

Expected demo output (excerpt):
```
AEGIS NIDS - Phase 37 Ext 2: Scenario Library CLI

  -> pumped 3 events; suspicion=1; exfil_socket_tracked=true
  -> pumped 4 events; processes_tracked=3; download_socket=true
  -> pumped 7 events; suspicion=1; FIM_creates=6
  -> pumped 3 events; processes_tracked=2; lateral_socket=true
  -> pumped 4 events; processes_tracked=2; reverse_shell=true
  -> pumped 8 events; processes_tracked=3; reverse_shell=true
  -> pumped 21 events across 5 scenarios round-robin
  [PASS] credential-dump
  [PASS] command-execution
  [PASS] ransomware
  [PASS] valid-accounts
  [PASS] webshell
  [PASS] full-kill-chain
  [PASS] multi-technique

7/7 scenarios passed
```

## Integration Sketch

```zig
const scn = @import("host_telemetry_scenarios.zig");
const mock = @import("host_telemetry_mock.zig");
const ht = @import("host_telemetry.zig");

var host = try ht.HostTelemetry.init(allocator, .{ .enabled = true });
defer host.shutdown();

// Replay a single scenario
var src = mock.MockTelemetrySource.init("ransomware-test", .{ .enabled = true });
try scn.buildRansomwareScenario(&src);

var pump = mock.EventPump.init(src.asSource(), &host);
_ = pump.pumpAll(0, 100);

// Check detection results
std.log.info("suspicion emitted: {d}", .{pump.total_suspicion_emitted});
std.log.info("FIM observations: {d}", .{host.fim.total_created});

// Run multiple scenarios concurrently (MultiSourcePump)
var s1 = mock.MockTelemetrySource.init("cred", .{ .enabled = true });
try scn.buildCredentialDumpScenario(&s1);
var s2 = mock.MockTelemetrySource.init("cmd", .{ .enabled = true });
try scn.buildCommandExecutionScenario(&s2);

var sources = [_]mock.HostTelemetrySource{ s1.asSource(), s2.asSource() };
var mp = mock.MultiSourcePump.init(&sources, &host);
while (true) {
    const r = mp.pumpOnce(std.time.nanoTimestamp());
    if (r == .all_exhausted) break;
}
```

## Verification Checklist

Run on host (Linux or Windows) before promoting to production:

```
[ ] zig test core/host_telemetry_scenarios.zig -lc             -> "All 81 tests passed"
                                                                 (18 scenarios + 26 mock
                                                                  + 33 host_telemetry
                                                                  + 4 misc transitively)
[ ] zig build-exe core/host_telemetry_scenarios_cli.zig -lc   -> clean compile
[ ] ./host_telemetry_scenarios_cli demo                       -> "7/7 scenarios passed" (exit 0)
[ ] ./host_telemetry_scenarios_cli scenario ransomware        -> [PASS]
[ ] ./host_telemetry_scenarios_cli scenario full-kill-chain   -> [PASS]
[ ] Inspect core/host_telemetry_scenarios_config.json        -> valid JSON, kill_switch.enabled=false
```

## Risk & Rollback

- **Risk**: MEDIUM — additive test scenarios; no enforcement changes
- **Rollback**: set `MockConfig.enabled = false` (kill switch) — scenarios
  become no-ops. To fully remove: stop calling `buildXxxScenario()` and
  unlink the import.
- **Failure mode**: this module is test scaffolding — should NOT be
  enabled in production. Production should swap `MockTelemetrySource`
  for real adapters (ETW/FIM/RegNotify) when those land.
- **Composability**: scenarios can be combined via `MultiSourcePump` to
  simulate concurrent attack patterns (verified in `multi-technique`
  scenario with 5 sources producing 21 events total).

## Phase 37 Extension Progress

| Extension | Status | Notes |
|---|---|---|
| Ext 1 — Mock Telemetry Source | COMPLETE | HostTelemetrySource interface + MockTelemetrySource + 4 scenarios + EventPump (26 tests) |
| **Ext 2 — Scenario Library** | **COMPLETE (this extension)** | 5 new MITRE scenarios + 1 combined chain (18 tests) |
| Ext 3 — Real ETW Adapter | PENDING | Windows-only; needs Win32 API |
| Ext 4 — Real FIM Adapter | PENDING | Windows-only; ReadDirectoryChangesW |
| Ext 5 — Real RegNotify Adapter | PENDING | Windows-only; RegNotifyChangeKeyValue |

Combined Phase 37 Ext 1 + Ext 2 provides 10 MITRE ATT&CK scenarios
covering 10 distinct techniques for end-to-end detection testing.
