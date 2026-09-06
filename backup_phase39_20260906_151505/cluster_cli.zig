// cluster_cli.zig - AEGIS Phase 39 Distributed Cluster Coordination CLI demo.
// Builds with `zig build-exe cluster_cli.zig -lc`.
//
// Modes:
//   help                              - this screen
//   demo                              - 6 scenarios + PASS/FAIL summary (exit 0
//                                      iff all expected verdicts match)
//   scenario <name>                   - run a single named scenario
//
// Scenarios (matches README + test suite):
//   kill-switch-off                   - cluster disabled -> no aggregation
//   single-node                       - one node reports -> no escalation
//   cross-node-escalation             - 2 nodes report same source -> HIGH
//   critical-escalation               - 3 nodes report same source -> CRITICAL
//   heartbeat-timeout                 - peer misses 3 beats -> DEAD
//   threat-intel-broadcast            - peer shares IoC -> local check matches
//   leader-election                   - highest active NodeId wins

const std = @import("std");
const cc = @import("cluster_coord.zig");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    std.debug.print("AEGIS NIDS - Phase 39 Distributed Cluster Coordination CLI\n", .{});
    std.debug.print("===========================================================\n\n", .{});

    const mode: []const u8 = if (args.len >= 2) args[1] else "help";

    if (std.mem.eql(u8, mode, "help")) {
        printHelp();
        return;
    }

    if (std.mem.eql(u8, mode, "demo")) {
        const results = [_]struct { name: []const u8, ok: bool }{
            .{ .name = "kill-switch-off", .ok = scenarioKillSwitchOff(alloc) },
            .{ .name = "single-node", .ok = scenarioSingleNode(alloc) },
            .{ .name = "cross-node-escalation", .ok = scenarioCrossNodeEscalation(alloc) },
            .{ .name = "critical-escalation", .ok = scenarioCriticalEscalation(alloc) },
            .{ .name = "heartbeat-timeout", .ok = scenarioHeartbeatTimeout(alloc) },
            .{ .name = "threat-intel-broadcast", .ok = scenarioThreatIntelBroadcast(alloc) },
            .{ .name = "leader-election", .ok = scenarioLeaderElection(alloc) },
        };
        var passed: usize = 0;
        for (results) |r| {
            const tag = if (r.ok) "PASS" else "FAIL";
            std.debug.print("  [{s}] {s}\n", .{ tag, r.name });
            if (r.ok) passed += 1;
        }
        std.debug.print("\n{d}/{d} scenarios passed\n", .{ passed, results.len });
        if (passed != results.len) std.process.exit(1);
        return;
    }

    if (std.mem.eql(u8, mode, "scenario")) {
        if (args.len < 3) {
            std.debug.print("Usage: cluster_cli scenario <name>\n", .{});
            std.debug.print("Names: kill-switch-off | single-node | cross-node-escalation |\n", .{});
            std.debug.print("       critical-escalation | heartbeat-timeout | threat-intel-broadcast |\n", .{});
            std.debug.print("       leader-election\n", .{});
            return;
        }
        const name = args[2];
        const ok = runScenarioByName(alloc, name);
        const tag = if (ok) "PASS" else "FAIL";
        std.debug.print("\n  [{s}] {s}\n", .{ tag, name });
        if (!ok) std.process.exit(1);
        return;
    }

    std.debug.print("Unknown mode: {s}\n", .{mode});
    printHelp();
}

fn printHelp() void {
    std.debug.print("Usage:\n", .{});
    std.debug.print("  cluster_cli help                          - this screen\n", .{});
    std.debug.print("  cluster_cli demo                          - all 7 scenarios + summary\n", .{});
    std.debug.print("  cluster_cli scenario <name>               - one scenario\n", .{});
    std.debug.print("\nScenario names:\n", .{});
    std.debug.print("  kill-switch-off          - cluster disabled -> no aggregation\n", .{});
    std.debug.print("  single-node              - one node reports -> no escalation\n", .{});
    std.debug.print("  cross-node-escalation    - 2 nodes report same source -> HIGH\n", .{});
    std.debug.print("  critical-escalation      - 3 nodes report same source -> CRITICAL\n", .{});
    std.debug.print("  heartbeat-timeout        - peer misses 3 beats -> DEAD\n", .{});
    std.debug.print("  threat-intel-broadcast   - peer shares IoC -> local check matches\n", .{});
    std.debug.print("  leader-election          - highest active NodeId wins\n", .{});
}

fn runScenarioByName(alloc: std.mem.Allocator, name: []const u8) bool {
    if (std.mem.eql(u8, name, "kill-switch-off")) return scenarioKillSwitchOff(alloc);
    if (std.mem.eql(u8, name, "single-node")) return scenarioSingleNode(alloc);
    if (std.mem.eql(u8, name, "cross-node-escalation")) return scenarioCrossNodeEscalation(alloc);
    if (std.mem.eql(u8, name, "critical-escalation")) return scenarioCriticalEscalation(alloc);
    if (std.mem.eql(u8, name, "heartbeat-timeout")) return scenarioHeartbeatTimeout(alloc);
    if (std.mem.eql(u8, name, "threat-intel-broadcast")) return scenarioThreatIntelBroadcast(alloc);
    if (std.mem.eql(u8, name, "leader-election")) return scenarioLeaderElection(alloc);
    std.debug.print("[ERR] unknown scenario: {s}\n", .{name});
    return false;
}

// --------------------------------------------------------------
// Scenario implementations
// --------------------------------------------------------------

fn scenarioKillSwitchOff(alloc: std.mem.Allocator) bool {
    var cluster = cc.ClusterCoord.init(alloc, .{ .enabled = false, .node_id = 1 }) catch return false;
    defer cluster.shutdown();

    cluster.ingest(.{
        .msg_type = .incident_report,
        .from_node_id = 1,
        .timestamp_ns = 1_000_000_000,
        .incident_source_ip = .{ 198, 51, 100, 5 },
        .incident_remote_port = 4444,
        .incident_proto = 6,
        .incident_severity = .high,
        .incident_score = 0.85,
    });
    // Kill switch off -> no incidents aggregated
    const ok = cluster.aggregator.incidentCount() == 0;
    std.debug.print("  -> kill switch off; incidents_aggregated={d}\n", .{
        cluster.aggregator.incidentCount(),
    });
    return ok;
}

fn scenarioSingleNode(alloc: std.mem.Allocator) bool {
    var cluster = cc.ClusterCoord.init(alloc, .{ .enabled = true, .node_id = 1 }) catch return false;
    defer cluster.shutdown();

    cluster.ingest(.{
        .msg_type = .incident_report,
        .from_node_id = 1,
        .timestamp_ns = 1_000_000_000,
        .incident_source_ip = .{ 198, 51, 100, 5 },
        .incident_remote_port = 4444,
        .incident_proto = 6,
        .incident_severity = .medium,
        .incident_score = 0.75,
        .incident_label_len = 9,
        .incident_label = blk: {
            var b = [_]u8{0} ** cc.MAX_INCIDENT_LABEL;
            @memcpy(b[0..9], "malicious");
            break :blk b;
        },
    });

    const inc = cluster.aggregator.getIncident(.{ 198, 51, 100, 5 }, 4444, 6).?;
    // Single node: no escalation - severity stays at original
    const ok = inc.reporting_count == 1 and inc.severity == .medium;
    std.debug.print("  -> single node; reporting_count={d}, severity={s}\n", .{
        inc.reporting_count, inc.severity.toString(),
    });
    return ok;
}

fn scenarioCrossNodeEscalation(alloc: std.mem.Allocator) bool {
    var cluster = cc.ClusterCoord.init(alloc, .{ .enabled = true, .node_id = 1 }) catch return false;
    defer cluster.shutdown();

    // Two nodes report same source IP within 30s window
    cluster.ingest(.{
        .msg_type = .incident_report,
        .from_node_id = 1,
        .timestamp_ns = 1_000_000_000,
        .incident_source_ip = .{ 198, 51, 100, 5 },
        .incident_remote_port = 4444,
        .incident_proto = 6,
        .incident_severity = .medium,
        .incident_score = 0.75,
        .incident_label_len = 9,
        .incident_label = blk: {
            var b = [_]u8{0} ** cc.MAX_INCIDENT_LABEL;
            @memcpy(b[0..9], "malicious");
            break :blk b;
        },
    });
    cluster.ingest(.{
        .msg_type = .incident_report,
        .from_node_id = 2,
        .timestamp_ns = 1_100_000_000,
        .incident_source_ip = .{ 198, 51, 100, 5 },
        .incident_remote_port = 4444,
        .incident_proto = 6,
        .incident_severity = .medium,
        .incident_score = 0.80,
        .incident_label_len = 9,
        .incident_label = blk: {
            var b = [_]u8{0} ** cc.MAX_INCIDENT_LABEL;
            @memcpy(b[0..9], "malicious");
            break :blk b;
        },
    });

    const inc = cluster.aggregator.getIncident(.{ 198, 51, 100, 5 }, 4444, 6).?;
    const ok = inc.reporting_count == 2 and inc.severity == .high;
    std.debug.print("  -> 2 nodes reported; reporting_count={d}, severity={s} (escalated), score={d:.2}\n", .{
        inc.reporting_count, inc.severity.toString(), inc.score,
    });
    return ok;
}

fn scenarioCriticalEscalation(alloc: std.mem.Allocator) bool {
    var cluster = cc.ClusterCoord.init(alloc, .{ .enabled = true, .node_id = 1 }) catch return false;
    defer cluster.shutdown();

    // Three nodes report the same C2 source within 30s window
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
            .incident_label_len = 2,
            .incident_label = blk: {
                var b = [_]u8{0} ** cc.MAX_INCIDENT_LABEL;
                @memcpy(b[0..2], "c2");
                break :blk b;
            },
        });
    }

    const inc = cluster.aggregator.getIncident(.{ 198, 51, 100, 42 }, 4444, 6).?;
    const ok = inc.reporting_count == 3 and inc.severity == .critical;
    std.debug.print("  -> 3 nodes reported; reporting_count={d}, severity={s} (CRITICAL), critical_count={d}\n", .{
        inc.reporting_count, inc.severity.toString(), cluster.aggregator.total_critical,
    });
    return ok;
}

fn scenarioHeartbeatTimeout(alloc: std.mem.Allocator) bool {
    var cluster = cc.ClusterCoord.init(alloc, .{
        .enabled = true,
        .node_id = 1,
        .heartbeat_timeout_ms = 1_000, // 1s
        .heartbeat_dead_threshold = 3,
    }) catch return false;
    defer cluster.shutdown();

    // Register peer with heartbeat at t=0
    cluster.ingest(.{
        .msg_type = .heartbeat,
        .from_node_id = 5,
        .timestamp_ns = 0,
    });
    const peer_initial = cluster.registry.get(5).?;
    std.debug.print("  -> peer 5 joined; health={s}\n", .{peer_initial.health.toString()});

    // 3 ticks, each 1.5s apart (>1s timeout = 1 miss each), should reach DEAD
    cluster.tick(1_500_000_000); // 1st miss -> DEGRADED
    cluster.tick(3_000_000_000); // 2nd miss -> UNHEALTHY
    cluster.tick(4_500_000_000); // 3rd miss -> DEAD
    const peer_after = cluster.registry.get(5).?;
    const ok = peer_after.health == .dead;
    std.debug.print("  -> after 3 missed beats; health={s}, misses={d}\n", .{
        peer_after.health.toString(), peer_after.heartbeat_misses,
    });
    return ok;
}

fn scenarioThreatIntelBroadcast(alloc: std.mem.Allocator) bool {
    var cluster = cc.ClusterCoord.init(alloc, .{ .enabled = true, .node_id = 1 }) catch return false;
    defer cluster.shutdown();

    // Peer shares a C2 IP IoC
    cluster.ingest(.{
        .msg_type = .threat_intel_share,
        .from_node_id = 2,
        .timestamp_ns = 1_000_000_000,
        .threat_intel = .{
            .kind = .c2_server,
            .ip = .{ 198, 51, 100, 7 },
            .source_node_id = 2,
            .confidence = 95,
        },
    });

    // Local check: is this IP in the threat intel list?
    const m = cluster.checkThreatIp(.{ 198, 51, 100, 7 });
    const ok = m != null and m.?.kind == .c2_server and m.?.confidence == 95;
    std.debug.print("  -> IoC shared by peer 2; entries={d}, match_kind={s}, confidence={d}\n", .{
        cluster.threat_intel.entryCount(),
        if (m) |e| e.kind.toString() else "none",
        if (m) |e| e.confidence else 0,
    });
    return ok;
}

fn scenarioLeaderElection(alloc: std.mem.Allocator) bool {
    var cluster = cc.ClusterCoord.init(alloc, .{ .enabled = true, .node_id = 1 }) catch return false;
    defer cluster.shutdown();

    // Register peers with higher IDs
    cluster.ingest(.{
        .msg_type = .heartbeat,
        .from_node_id = 5,
        .timestamp_ns = 1_000_000_000,
    });
    cluster.ingest(.{
        .msg_type = .heartbeat,
        .from_node_id = 10,
        .timestamp_ns = 1_000_000_000,
    });

    // Run election
    const r = cluster.election.elect(&cluster.registry, 1_000_000_000);
    const ok = r.leader == 10 and r.changed and cluster.currentLeader() == 10;
    std.debug.print("  -> election: leader={d}, changed={}, self_is_leader={}\n", .{
        r.leader, r.changed, cluster.isLeader(),
    });
    return ok;
}
