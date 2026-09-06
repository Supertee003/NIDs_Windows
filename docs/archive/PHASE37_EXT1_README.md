# AEGIS NIDS - Phase 37 Extension 1: Mock Telemetry Source

**Risk**: MEDIUM | **Phase 37 Extension** | **Status: HOST-VERIFIED + 26 tests**

Defines the `HostTelemetrySource` interface + provides a `MockTelemetrySource`
that replays scripted `HostEvent` sequences. Closes the gap between Phase
37's logical model (the `HostTelemetry` facade with ProcessTracker/FIM/
RegistryWatch/SocketTable) and the absence of real Windows adapters (ETW/
FIM/RegNotify) on the Linux host test environment.

## Why This Extension

Phase 37 (HIDS/XDR) shipped with a complete logical model — but no real
host telemetry sources were wired in. The module compiled and 33 tests
passed, but produced no incidents at runtime because no `HostEvent`
records were being fed into `HostTelemetry.ingestEvent()`.

Real Windows adapters (ETW Process/Thread, ReadDirectoryChangesW FIM,
RegNotifyChangeKeyValue, ETW Winsock-APM) require Win32 API calls that
won't compile or run on the Linux host. To unblock end-to-end testing
and define the contract that future adapters must follow, Phase 37 Ext 1
ships:

1. **HostTelemetrySource** interface (vtable pattern, like Phase 39 Ext 1's
   `Transport`)
2. **MockTelemetrySource** — replays scripted `(HostEvent, delay_ns)`
   tuples in order, supports reset/replay for repeatable tests
3. **Scripted scenarios** — 4 predefined attack patterns (macro-dropper,
   persistence, unsigned-system, lateral-movement) as ready-to-use
   `MockTelemetrySource` factories
4. **EventPump** — pulls events from a source and feeds them to
   `HostTelemetry.ingestEvent()`; handles kill switch + delay timing
5. **MultiSourcePump** — round-robins between multiple sources

## Design Principles

Mirrors Phase 32 (Npcap) + Phase 36 (ML) + Phase 37 (HIDS) + Phase 39
(cluster):

- **Pure Zig, host-testable on Linux** — no Win32 API calls. Real
  adapters will subclass `HostTelemetrySource` with Windows-specific
  implementations behind `builtin.os.tag == .windows` guards.
- **Additive only** — enforcement stays in WFP kernel driver per node.
- **Kill switch OFF by default** — `MockConfig{ .enabled = true }` opts in.
- **Bounded memory** — 256-event scenario buffer, capped source name.
- **Deterministic** — `jitter_ns=0` default makes tests reproducible.

## Files

| File | Purpose |
|---|---|
| `core/host_telemetry_mock.zig` | HostTelemetrySource interface + MockTelemetrySource + 4 scripted scenarios + EventPump + MultiSourcePump, **26 tests** |
| `core/host_telemetry_mock_cli.zig` | CLI demo (7 scenarios + PASS/FAIL summary, exit 0 iff all match) |
| `core/host_telemetry_mock_config.json` | Reference config (kill switch, scenario library, adapter contract) |
| `PHASE37_EXT1_README.md` | This document |

## Architecture

```
                 Real Adapters (future, Windows-only)
                 +-----------+ +-----------+ +-----------+ +-----------+
                 | ETW Proc  | | FIM       | | RegNotify | | ETW Win   |
                 | Source    | | Source    | | Source    | | sock Src  |
                 +-----+-----+ +-----+-----+ +-----+-----+ +-----+-----+
                       |             |             |             |
                       v             v             v             v
                 +---------------------------------------------------+
                 |   HostTelemetrySource vtable                      |
                 |   { nextEvent, name, isExhausted, reset }         |
                 +---------------------------------------------------+
                                       ^
                                       | (also implements vtable)
                 +---------------------+---------------------+
                 |   MockTelemetrySource (this module)       |
                 |   - 4 scripted scenarios                  |
                 |   - delay_ns timing                       |
                 |   - loop_on_exhausted option              |
                 +---------------------+---------------------+
                                       |
                                       v
                 +---------------------+---------------------+
                 |   EventPump / MultiSourcePump              |
                 |   (polls source, calls ingestEvent)       |
                 +---------------------+---------------------+
                                       |
                                       v
                 +---------------------+---------------------+
                 |   HostTelemetry facade (Phase 37)          |
                 |   - ProcessTracker / FileIntegrityStore   |
                 |   - RegistryWatchQueue / SocketTable      |
                 |   - CorrelationEngine (joins ML verdicts) |
                 +---------------------+---------------------+
                                       |
                                       v
                              CorrelatedIncident
                              (network + host attribution)
```

## HostTelemetrySource Interface

```zig
pub const HostTelemetrySource = struct {
    ctx: *anyopaque,
    nextEventFn: *const fn (ctx: *anyopaque, now_ns: i64) SourceError!?ht.HostEvent,
    nameFn: *const fn (ctx: *anyopaque) []const u8,
    isExhaustedFn: *const fn (ctx: *anyopaque) bool,
    resetFn: *const fn (ctx: *anyopaque) void,

    pub fn nextEvent(self: HostTelemetrySource, now_ns: i64) SourceError!?ht.HostEvent;
    pub fn name(self: HostTelemetrySource) []const u8;
    pub fn isExhausted(self: HostTelemetrySource) bool;
    pub fn reset(self: HostTelemetrySource) void;
};
```

`SourceError` covers `SourceExhausted`, `SourceDisabled`, `InvalidState`.

Real adapters (ETW, FIM, RegNotify, Winsock-APM) MUST implement this
interface so they can be pumped via `EventPump` or `MultiSourcePump`.
`MockTelemetrySource` is the reference implementation and the test bed.

## Scripted Scenarios

4 predefined attack patterns matching MITRE ATT&CK techniques:

| Scenario | Events | MITRE | Timeline |
|---|---|---|---|
| `macro-dropper` | 4 | T1566.001 | WINWORD → cmd → dropper → C2 socket (5ms apart) |
| `persistence` | 2 | T1547.001 + T1571 | svchost.exe hash tamper + HKLM Run\\Backdoor set |
| `unsigned-system` | 1 | T1027 | Unsigned SYSTEM-integrity binary in System32 spawns |
| `lateral-movement` | 5 | T1021 | TCP sockets to ports 445/3389/22/135/139 on internal hosts |

Each scenario is a function `buildXxxScenario(out: *MockTelemetrySource) !void`
that appends events with appropriate delays. Callers can compose them,
extend them, or build their own from scratch.

## EventPump

```zig
const pump = mock.EventPump.init(source.asSource(), &host);
const result = pump.pumpOnce(now_ns);
switch (result) {
    .emitted => |reason| { /* event ingested, reason is SuspicionReason */ },
    .skipped => {},        // source had no event ready (delay not elapsed)
    .exhausted => {},     // source has no more events
    .disabled => {},      // host kill switch off
}
```

`pumpAll(now_ns, max_iterations)` drains the source in one call (advancing
time by `correlation_window_ms` per event). Returns count of events pumped.

## MultiSourcePump

Round-robins between multiple sources in a single poll loop. Useful for
simulating concurrent telemetry streams (e.g. ETW Process + ETW Winsock
events arriving in interleaved order):

```zig
var sources = [_]HostTelemetrySource{ src1.asSource(), src2.asSource() };
var pump = mock.MultiSourcePump.init(&sources, &host);
const r = pump.pumpOnce(now_ns);
switch (r) {
    .emitted => |reason| {},
    .skipped => {},
    .all_exhausted => break,  // every source is exhausted
    .disabled => {},
}
```

## Quick Start

```bash
# 1. Run unit tests (host: Linux or Windows, no Win32 API needed)
zig test core/host_telemetry_mock.zig -lc

# 2. Build CLI demo
zig build-exe core/host_telemetry_mock_cli.zig -lc

# 3. Run all 7 scenarios + summary (exit 0 iff all pass)
./host_telemetry_mock_cli demo

# 4. Run a single scenario
./host_telemetry_mock_cli scenario full-attack-chain
```

Expected demo output (excerpt):
```
AEGIS NIDS - Phase 37 Ext 1: Mock Telemetry Source CLI

  -> kill switch off; pump returned disabled (expected); total_pumped=0
  -> pumped 4 events; suspicion_emitted=2; parent_anomalies=1
  -> pumped 2 events; FIM mismatches=1; persistence_hits=1
  -> pumped 1 events; suspicious_processes=1
  -> pumped 5 events; sockets_for_pid_4321=5
  -> attributed to PID=300, image='C:\Users\Public\dropper.exe', severity=CRITICAL, reasons=3
  -> pumped 4 events round-robin; processes_tracked=2; sockets_pid_200=2
  [PASS] kill-switch-off
  [PASS] macro-dropper
  [PASS] persistence
  [PASS] unsigned-system
  [PASS] lateral-movement
  [PASS] full-attack-chain
  [PASS] multi-source

7/7 scenarios passed
```

## Integration Sketch

```zig
const mock = @import("host_telemetry_mock.zig");
const ht = @import("host_telemetry.zig");

// On startup (production will swap MockTelemetrySource for real adapters):
var host = try ht.HostTelemetry.init(allocator, .{ .enabled = true });
defer host.shutdown();

var src = mock.MockTelemetrySource.init("etw-proc-mock", .{ .enabled = true });
try mock.buildMacroDropperScenario(&src);

var pump = mock.EventPump.init(src.asSource(), &host);
// Drive the pump in your event loop:
while (!pump.source.isExhausted()) {
    const r = pump.pumpOnce(std.time.nanoTimestamp());
    switch (r) {
        .emitted => |reason| {
            if (reason != .none) {
                std.log.info("suspicion: {s}", .{reason.toString()});
            }
        },
        .skipped => std.time.sleep(1_000_000), // 1ms
        .exhausted => break,
        .disabled => break,
    }
}

// Check for correlated incidents (from Phase 36 ML detector pushes):
if (host.correlator.incidentCount() > 0) {
    const inc = host.correlator.getIncident(0).?;
    std.log.warn("CRITICAL: {s} attributed to PID {d} ({s})",
        .{ inc.severity.toString(), inc.attributed_pid, inc.attributedImage() });
}
```

## Verification Checklist

Run on host (Linux or Windows) before promoting to production:

```
[ ] zig test core/host_telemetry_mock.zig -lc            -> "All 64 tests passed"
                                                          (26 mock + 33 host_telemetry
                                                           + 5 misc transitively)
[ ] zig build-exe core/host_telemetry_mock_cli.zig -lc   -> clean compile
[ ] ./host_telemetry_mock_cli demo                       -> "7/7 scenarios passed" (exit 0)
[ ] ./host_telemetry_mock_cli scenario full-attack-chain -> [PASS]
[ ] ./host_telemetry_mock_cli scenario multi-source      -> [PASS]
[ ] Inspect core/host_telemetry_mock_config.json         -> valid JSON, kill_switch.enabled=false
```

## Risk & Rollback

- **Risk**: MEDIUM — additive test/source layer; no enforcement changes
- **Rollback**: set `MockConfig.enabled = false` (kill switch) — module
  becomes a no-op. To fully remove: stop calling `MockTelemetrySource.init()`
  + `EventPump.init()` and unlink the import.
- **Failure mode**: this module is test scaffolding — it should NOT be
  enabled in production. Production code should swap `MockTelemetrySource`
  for real adapters (ETW/FIM/RegNotify) when those land.
- **Future contract**: real adapters MUST implement `HostTelemetrySource`
  so they can be pumped via `EventPump` / `MultiSourcePump`. The mock is
  the reference implementation.
