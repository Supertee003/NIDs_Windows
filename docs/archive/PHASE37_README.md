# AEGIS NIDS - Phase 37: HIDS/XDR Endpoint Correlation

**Risk**: MEDIUM | **Tier 4 - Advanced Detection** | **Status: HOST-VERIFIED + 33 tests**

Host Intrusion Detection + Extended Detection & Response endpoint layer.
Joins host telemetry (process / file / registry / socket) with network
flow verdicts (from Phase 36 ML detector) to attribute malicious traffic
to a responsible process, and surfaces persistence / injection / integrity
anomalies that network-only detection cannot see.

## Why Phase 37 (Host Layer)

Phases 32 (Npcap) + 36 (ML flow detector) see *the wire* — what's flowing.
They cannot answer: **which process opened the malicious socket?** A flow
verdict like `192.168.1.41:51000 -> 198.51.100.7:4444 [MALICIOUS 0.93]`
names the addresses, not the binary. Phase 37 closes that gap by:

1. Tracking process creates/exits with parent-chain walking (4 generations)
2. Maintaining a per-PID socket table (TCP/UDP 4-tuples -> owning PID)
3. Hashing system files at baseline and detecting tampering (SHA-256)
4. Watching the registry persistence + critical-key locations
5. **Correlating**: when the ML detector emits a high-score flow verdict,
   the engine walks the socket table to find the owning PID, then walks the
   process tracker to compose image / cmdline / parent chain / signer, then
   emits a `CorrelatedIncident` with full attribution.

The result: an analyst gets `dropper.exe (unsigned, HIGH integrity, parent
explorer.exe) -> TCP 192.168.1.41:51000 -> 198.51.100.7:4444 [MALICIOUS]`
instead of just the IP tuple.

## Design Principles

Mirrors Phase 32 (Npcap) + Phase 36 (ML detector):

- **Pure Zig, host-testable on Linux** — no Windows API calls in the core
  module. All 33 tests run on Linux (no kernel hooks needed). ETW /
  RegNotifyChangeKeyValue / ReadDirectoryChangesW adapters live outside
  this module and feed `HostEvent` records via `ingestEvent()`.
- **Additive only** — enforcement stays in the WFP kernel driver. Phase 37
  emits `CorrelatedIncident` records; it does NOT block, kill, or quarantine.
- **Kill switch OFF by default** — `HostConfig{ .enabled = true }` must be
  set explicitly. Until then `ingestEvent()` is a no-op and `pushFlowVerdict`
  returns null.
- **Singleton facade** — `HostTelemetry.instance()` (project style: matches
  NpcapSensor / MlDetector singletons).
- **Bounded memory** — fixed caps: 4096 processes, 256 incidents, 32 sockets
  per PID, 64-entry registry ring buffer, 6 reasons per incident.

## Files

| File | Purpose |
|---|---|
| `core/host_telemetry.zig` | Core module (HostEvent taxonomy, ProcessTracker, FileIntegrityStore, RegistryWatchQueue, SocketTable, CorrelationEngine), **33 tests** |
| `core/host_telemetry_cli.zig` | CLI demo (7 scenarios + PASS/FAIL summary, exit 0 iff all match) |
| `core/host_correlator_config.json` | Reference config (kill switch, suspicious parents, baseline paths, persistence keys) |
| `PHASE37_README.md` | This document |

## Architecture

```
+-----------------+   +----------------+   +---------------------+
|  ETW Process    |   |  FIM Adapter   |   | RegNotify Adapter   |
|  (Kernel prov)  |   |  (ReadDirectory|   | (RegNotifyChange-   |
|  -> HostEvent   |   |   ChangesW)    |   |  KeyValue)          |
+-----------------+   +----------------+   +---------------------+
        |                    |                     |
        v                    v                     v
   +---------------------------------------------+
   |   HostTelemetry.ingestEvent(HostEvent)      |
   |   ----------------------------------       |
   |   ProcessTracker   FileIntegrityStore      |
   |       |                  |                 |
   |       v                  v                 |
   |   SocketTable      RegistryWatchQueue      |
   |       |                  |                 |
   |       v                  v                 |
   |   CorrelationEngine  (suspicion reasons)   |
   +---------------------------------------------+
                          ^
                          |
+-----------------+      |     +-----------------------+
|  Phase 36 ML    |------+---->|  CorrelatedIncident   |
|  (flow verdict) |  pushFlowVerdict()  (network+host  |
+-----------------+            attribution)          |
                               +-----------------------+
                                          |
                                          v
                                  Phase 19 XdrEngine
                                  (CEF -> SIEM)
```

## Host Event Taxonomy

11 event types — every host telemetry source reduces to one of these:

| Event | Source | Critical? | Notes |
|---|---|---|---|
| `PROCESS_CREATE` | ETW Kernel-Process | no | pid, ppid, image, cmdline, integrity, signer |
| `PROCESS_EXIT` | ETW Kernel-Process | no | removes from ProcessTracker |
| `IMAGE_LOAD` | ETW Image-Load | no | (future) signature validation |
| `FILE_CREATE` | FIM adapter | no | new path not in baseline |
| `FILE_MODIFY` | FIM adapter | yes | SHA-256 mismatch with baseline |
| `FILE_DELETE` | FIM adapter | yes | baseline path removed |
| `REG_SET_VALUE` | RegNotify | yes | persistence/critical key match |
| `REG_CREATE_KEY` | RegNotify | yes | persistence/critical key match |
| `REG_DELETE_KEY` | RegNotify | yes | persistence/critical key match |
| `SOCKET_OPEN` | ETW Winsock-APM / WFP | no | 4-tuple -> PID entry |
| `SOCKET_CLOSE` | ETW Winsock-APM / WFP | no | removes from SocketTable |

## Suspicion Reasons (11)

| Reason | Severity | Trigger |
|---|---|---|
| `none` | info | clean event |
| `parent_child_anomaly` | high | Office app spawning shell (T1566.001) |
| `integrity_escalation` | critical | child integrity > parent (UAC bypass T1548.002) |
| `unsigned_elevated` | high | HIGH/SYSTEM integrity, is_signed=false |
| `unsigned_system_path` | critical | unsigned binary in System32/SysWOW64/Windows |
| `suspicious_cmdline` | high | (future) encoded powershell, suspicious tokens |
| `file_integrity_mismatch` | critical | SHA-256 != baseline (T1571 / T1547) |
| `file_integrity_deleted` | critical | baseline path removed |
| `registry_persistence_key` | critical | HKLM/HKCU Run / Services / Winlogon changed (T1547 / T1060) |
| `registry_critical_key` | critical | SAM / SECURITY / Lsa / Policies\System changed (T1003 / T1112) |
| `network_host_correlation` | critical | ML flow verdict score >= threshold, attributed to PID |

## Quick Start

```bash
# 1. Run unit tests (host: Linux or Windows, no Npcap/ETW needed)
zig test core/host_telemetry.zig -lc

# 2. Build CLI demo
zig build-exe core/host_telemetry_cli.zig -lc

# 3. Run all 7 scenarios + summary (exit 0 iff all pass)
./host_telemetry_cli demo

# 4. Run a single scenario
./host_telemetry_cli scenario network-correlation
```

Expected demo output (excerpt):
```
AEGIS NIDS - Phase 37 HIDS/XDR Endpoint Correlation CLI

  -> child spawned by WINWORD; reason=PARENT_CHILD_ANOMALY
  -> unsigned SYSTEM binary; reason=UNSIGNED_SYSTEM_PATH
  -> svchost.exe tampered; reason=FILE_INTEGRITY_MISMATCH, mismatch_count=1
  -> HKLM Run\Backdoor set; reason=REGISTRY_PERSISTENCE_KEY, persistence_hits=1
  -> proc-reason=UNSIGNED_ELEVATED, PID=999, image=C:\Users\Public\dropper.exe
  -> incident.severity=CRITICAL, reason_count=3, flow_score=0.93
  -> flow: 192.168.1.41:51000 -> 198.51.100.7:4444 (TCP)
  [PASS] kill-switch-off
  [PASS] normal-proc
  [PASS] parent-child-anomaly
  [PASS] unsigned-system-path
  [PASS] fim-mismatch
  [PASS] registry-persistence
  [PASS] network-correlation

7/7 scenarios passed
```

## Correlation Policy

A `CorrelatedIncident` is emitted when **all** of the following hold:

1. `HostConfig.enabled == true` (kill switch off)
2. `enable_socket_correlation == true`
3. Network flow verdict score >= `incident_score_threshold` (default 0.70)
4. Socket table has an entry matching the flow's 4-tuple
   (proto + local_ip + local_port + remote_ip + remote_port)
5. Incident ring buffer has capacity (max 256; oldest dropped on overflow)

The incident then collects:
- Network side: 4-tuple, proto, score, label (from ML detector)
- Host side: PID, image_path, cmdline, signer flag, integrity level
- Parent chain depth (up to 4 generations)
- All suspicion reasons discovered along the way (deduplicated)
- Severity: starts HIGH for score >= 0.70, CRITICAL for score >= 0.90;
  bumped to CRITICAL by any critical-type reason (FIM mismatch, registry
  persistence, unsigned system path, integrity escalation)

## Configuration

See `core/host_correlator_config.json` for the reference config. Key fields:

```json
{
  "kill_switch": { "enabled": false },
  "correlation": {
    "window_ms": 5000,
    "incident_score_threshold": 0.70,
    "max_incidents": 256
  },
  "file_integrity": {
    "baseline_paths": [
      "C:\\Windows\\System32\\svchost.exe",
      "C:\\Windows\\System32\\lsass.exe",
      "C:\\Windows\\System32\\drivers\\etc\\hosts",
      ...
    ]
  },
  "registry_watch": {
    "persistence_keys": [
      "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
      ...
    ],
    "critical_keys": [
      "HKLM\\SAM\\SAM",
      "HKLM\\SECURITY",
      ...
    ]
  }
}
```

Note: the JSON is the **reference config** — runtime loading is not yet
wired in. `HostConfig` struct fields are initialized to safe defaults; the
JSON serves as the canonical list of paths/keys for the future adapter
that will populate `FileIntegrityStore` baselines and `RegistryWatchQueue`
subscriptions.

## Integration Sketch

```zig
const ht = @import("host_telemetry.zig");
const ml = @import("ml_detector.zig"); // Phase 36

// On startup:
var host = try ht.HostTelemetry.init(allocator, .{
    .enabled = true,                 // kill switch on
    .incident_score_threshold = 0.70,
});
defer host.shutdown();

// From each host telemetry adapter (ETW / FIM / RegNotify / Winsock):
host.ingestEvent(process_create_ev);
host.ingestEvent(file_modify_ev);
host.ingestEvent(registry_set_value_ev);
host.ingestEvent(socket_open_ev);

// When Phase 36 ML detector emits a verdict:
if (ml_verdict.score >= 0.70) {
    if (host.pushFlowVerdict(.{
        .timestamp_ns = ml_verdict.timestamp_ns,
        .proto = .tcp,
        .local_ip = ml_verdict.local_ip,
        .local_port = ml_verdict.local_port,
        .remote_ip = ml_verdict.remote_ip,
        .remote_port = ml_verdict.remote_port,
        .score = ml_verdict.score,
        .label_len = ml_verdict.label_len,
        .label = ml_verdict.label,
    })) |idx| {
        const inc = host.correlator.getIncident(idx).?;
        // Forward to Phase 19 XdrEngine for CEF/SIEM export
        xdr.processAttributedIncident(inc);
    }
}
```

## Verification Checklist

Run on host (Linux or Windows) before promoting to production:

```
[ ] zig test core/host_telemetry.zig -lc        -> "All 33 tests passed"
[ ] zig build-exe core/host_telemetry_cli.zig -lc   -> clean compile
[ ] ./host_telemetry_cli demo                    -> "7/7 scenarios passed" (exit 0)
[ ] ./host_telemetry_cli scenario network-correlation  -> [PASS]
[ ] ./host_telemetry_cli help                    -> usage screen
[ ] Inspect core/host_correlator_config.json    -> valid JSON, kill_switch.enabled=false
```

## DevSecOps Tier Progress

| Tier | Phase | Status |
|---|---|---|
| 1 - Safety Foundation | Phase 35 (kill switches) | COMPLETE |
| 1 - Safety Foundation | Phase 40 (rollback) | COMPLETE |
| 2 - Additive Integrations | Phase 33 (WFP bridge) | COMPLETE |
| 2 - Additive Integrations | Phase 34 (forensic replay) | COMPLETE |
| 3 - Core Expansion | Phase 32 (Npcap) | COMPLETE (v3 ARP-visibility) |
| 3 - Core Expansion | Phase 38 (sensor ingest) | COMPLETE |
| 4 - Advanced Detection | Phase 36 (ML/AI flow) | COMPLETE |
| 4 - Advanced Detection | **Phase 37 (HIDS/XDR endpoint)** | **COMPLETE (this phase)** |
| 5 - Complex | Phase 39 (cluster) | PENDING |

**Gate-4 tag**: `v5.4-advanced-detection` is now ready — Tier 4 is complete
with both Phase 36 (ML flow detection) and Phase 37 (host endpoint
correlation) landed.

## Risk & Rollback

- **Risk**: MEDIUM — additive detection layer; no enforcement changes
- **Rollback**: set `HostConfig.enabled = false` (kill switch) — module
  becomes a no-op without code removal. To fully remove: stop calling
  `HostTelemetry.init()` and unlink the import in `build.zig`.
- **Failure mode**: ETW / FIM / RegNotify adapters not yet wired in —
  module compiles and tests pass, but produces no incidents at runtime
  until adapters feed `HostEvent` records. This is intentional: keeps
  the core testable and the adapter contracts clean.
