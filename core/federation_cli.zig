// federation_cli.zig - AEGIS Phase 39 Ext 1: Federation Codec CLI demo.
// Builds with `zig build-exe federation_cli.zig -lc`.
//
// Modes:
//   help                              - this screen
//   demo                              - 6 scenarios + PASS/FAIL summary (exit 0
//                                      iff all expected verdicts match)
//   scenario <name>                   - run a single named scenario
//
// Scenarios:
//   kill-switch-off          - federation disabled -> no sends
//   roundtrip-heartbeat      - encode -> decode preserves fields
//   roundtrip-incident       - encode -> decode preserves 4-tuple + score
//   crc-detects-bitflip      - flipped byte fails decode (CrcMismatch)
//   retry-backoff            - send failure triggers exponential backoff
//   two-node-loopback        - node A -> node B heartbeat via loopback
//   queue-overflow-drops     - overflow drops oldest when configured

const std = @import("std");
const cc = @import("cluster_coord.zig");
const fc = @import("federation_codec.zig");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    std.debug.print("AEGIS NIDS - Phase 39 Ext 1: Federation Codec CLI\n", .{});
    std.debug.print("=================================================\n\n", .{});

    const mode: []const u8 = if (args.len >= 2) args[1] else "help";

    if (std.mem.eql(u8, mode, "help")) {
        printHelp();
        return;
    }

    if (std.mem.eql(u8, mode, "demo")) {
        const results = [_]struct { name: []const u8, ok: bool }{
            .{ .name = "kill-switch-off", .ok = scenarioKillSwitchOff(alloc) },
            .{ .name = "roundtrip-heartbeat", .ok = scenarioRoundtripHeartbeat(alloc) },
            .{ .name = "roundtrip-incident", .ok = scenarioRoundtripIncident(alloc) },
            .{ .name = "crc-detects-bitflip", .ok = scenarioCrcDetectsBitflip(alloc) },
            .{ .name = "retry-backoff", .ok = scenarioRetryBackoff(alloc) },
            .{ .name = "two-node-loopback", .ok = scenarioTwoNodeLoopback(alloc) },
            .{ .name = "queue-overflow-drops", .ok = scenarioQueueOverflowDrops(alloc) },
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
            std.debug.print("Usage: federation_cli scenario <name>\n", .{});
            std.debug.print("Names: kill-switch-off | roundtrip-heartbeat | roundtrip-incident |\n", .{});
            std.debug.print("       crc-detects-bitflip | retry-backoff | two-node-loopback |\n", .{});
            std.debug.print("       queue-overflow-drops\n", .{});
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
    std.debug.print("  federation_cli help                          - this screen\n", .{});
    std.debug.print("  federation_cli demo                          - all 7 scenarios + summary\n", .{});
    std.debug.print("  federation_cli scenario <name>               - one scenario\n", .{});
    std.debug.print("\nScenario names:\n", .{});
    std.debug.print("  kill-switch-off         - federation disabled -> no sends\n", .{});
    std.debug.print("  roundtrip-heartbeat      - encode -> decode preserves fields\n", .{});
    std.debug.print("  roundtrip-incident        - encode -> decode preserves 4-tuple + score\n", .{});
    std.debug.print("  crc-detects-bitflip       - flipped byte fails decode (CrcMismatch)\n", .{});
    std.debug.print("  retry-backoff            - send failure triggers exponential backoff\n", .{});
    std.debug.print("  two-node-loopback        - node A -> node B heartbeat via loopback\n", .{});
    std.debug.print("  queue-overflow-drops      - overflow drops oldest when configured\n", .{});
}

fn runScenarioByName(alloc: std.mem.Allocator, name: []const u8) bool {
    if (std.mem.eql(u8, name, "kill-switch-off")) return scenarioKillSwitchOff(alloc);
    if (std.mem.eql(u8, name, "roundtrip-heartbeat")) return scenarioRoundtripHeartbeat(alloc);
    if (std.mem.eql(u8, name, "roundtrip-incident")) return scenarioRoundtripIncident(alloc);
    if (std.mem.eql(u8, name, "crc-detects-bitflip")) return scenarioCrcDetectsBitflip(alloc);
    if (std.mem.eql(u8, name, "retry-backoff")) return scenarioRetryBackoff(alloc);
    if (std.mem.eql(u8, name, "two-node-loopback")) return scenarioTwoNodeLoopback(alloc);
    if (std.mem.eql(u8, name, "queue-overflow-drops")) return scenarioQueueOverflowDrops(alloc);
    std.debug.print("[ERR] unknown scenario: {s}\n", .{name});
    return false;
}

// --------------------------------------------------------------
// Scenario implementations
// --------------------------------------------------------------

fn scenarioKillSwitchOff(alloc: std.mem.Allocator) bool {
    var f = fc.FederationFacade.init(alloc, .{ .enabled = false, .node_id = 1 }) catch return false;
    defer f.shutdown();

    const ok = f.send(.{
        .msg_type = .heartbeat,
        .from_node_id = 1,
        .timestamp_ns = 1_000_000_000,
    }, 1_000_000_000);
    const queue_empty = f.outbound.queueCount() == 0;
    std.debug.print("  -> send returned {}, queue_count={d}\n", .{ ok, f.outbound.queueCount() });
    return !ok and queue_empty;
}

fn scenarioRoundtripHeartbeat(alloc: std.mem.Allocator) bool {
    var f = fc.FederationFacade.init(alloc, .{ .enabled = true, .node_id = 1 }) catch return false;
    defer f.shutdown();

    const msg = cc.ClusterMessage{
        .msg_type = .heartbeat,
        .from_node_id = 5,
        .to_node_id = 0,
        .timestamp_ns = 1_000_000_000,
    };
    var buf: [fc.MAX_FRAME_SIZE]u8 = undefined;
    const n = fc.encode(msg, &buf) catch return false;
    const decoded = fc.decode(buf[0..n]) catch return false;

    const ok = decoded.msg_type == .heartbeat and
        decoded.from_node_id == 5 and
        decoded.timestamp_ns == 1_000_000_000;
    std.debug.print("  -> encoded {d} bytes; decoded msg_type={s}, from={d}, ts={d}\n", .{
        n, decoded.msg_type.toString(), decoded.from_node_id, decoded.timestamp_ns,
    });
    return ok;
}

fn scenarioRoundtripIncident(alloc: std.mem.Allocator) bool {
    _ = alloc;

    var msg = cc.ClusterMessage{
        .msg_type = .incident_report,
        .from_node_id = 1,
        .timestamp_ns = 1_000_000_000,
        .incident_source_ip = .{ 198, 51, 100, 5 },
        .incident_remote_port = 4444,
        .incident_proto = 6,
        .incident_severity = .high,
        .incident_score = 0.85,
    };
    const label = "malicious";
    @memcpy(msg.incident_label[0..label.len], label);
    msg.incident_label_len = label.len;

    var buf: [fc.MAX_FRAME_SIZE]u8 = undefined;
    const n = fc.encode(msg, &buf) catch return false;
    const decoded = fc.decode(buf[0..n]) catch return false;

    const ok = decoded.msg_type == .incident_report and
        decoded.incident_remote_port == 4444 and
        decoded.incident_severity == .high and
        decoded.incident_score == 0.85 and
        std.mem.eql(u8, &decoded.incident_source_ip, &[_]u8{ 198, 51, 100, 5 });
    std.debug.print("  -> encoded {d} bytes; severity={s}, score={d:.2}, src={d}.{d}.{d}.{d}:{d}\n", .{
        n, decoded.incident_severity.toString(), decoded.incident_score,
        decoded.incident_source_ip[0], decoded.incident_source_ip[1],
        decoded.incident_source_ip[2], decoded.incident_source_ip[3],
        decoded.incident_remote_port,
    });
    return ok;
}

fn scenarioCrcDetectsBitflip(alloc: std.mem.Allocator) bool {
    _ = alloc;
    const msg = cc.ClusterMessage{
        .msg_type = .heartbeat,
        .from_node_id = 5,
        .timestamp_ns = 1_000_000_000,
    };
    var buf: [fc.MAX_FRAME_SIZE]u8 = undefined;
    const n = fc.encode(msg, &buf) catch return false;

    // Flip a bit in payload
    buf[fc.HEADER_LEN] ^= 0x01;
    const err = fc.decode(buf[0..n]);
    const ok = if (err) |_| false else |e| e == error.CrcMismatch;
    std.debug.print("  -> bit-flip in payload; decode returned {s}\n", .{
        if (ok) "CrcMismatch (expected)" else "unexpected-success",
    });
    return ok;
}

fn scenarioRetryBackoff(alloc: std.mem.Allocator) bool {
    _ = alloc;
    var cm = fc.ConnectionManager.init(.{
        .initial_backoff_ms = 1,
        .max_backoff_ms = 100,
        .backoff_multiplier = 2.0,
    });
    cm.markConnected(1_000_000_000);

    // Series of failures: 1ms, 2ms, 4ms, 8ms...
    cm.markSendFailure(2_000_000_000);
    const b1 = cm.computeBackoff();
    cm.markSendFailure(3_000_000_000);
    const b2 = cm.computeBackoff();
    cm.markSendFailure(4_000_000_000);
    const b3 = cm.computeBackoff();

    const ok = cm.state == .degraded and
        b1 == 2 and b2 == 4 and b3 == 8;
    std.debug.print("  -> after 3 failures: state={s}, backoffs={d}ms/{d}ms/{d}ms\n", .{
        cm.state.toString(), b1, b2, b3,
    });
    return ok;
}

fn scenarioTwoNodeLoopback(alloc: std.mem.Allocator) bool {
    // Two facades simulate two cluster nodes in-process
    var f1 = fc.FederationFacade.init(alloc, .{ .enabled = true, .node_id = 1 }) catch return false;
    defer f1.shutdown();
    var f2 = fc.FederationFacade.init(alloc, .{ .enabled = true, .node_id = 2 }) catch return false;
    defer f2.shutdown();

    var t1 = fc.LoopbackTransport.init(alloc);
    defer t1.deinit();
    t1.connect();
    var t2 = fc.LoopbackTransport.init(alloc);
    defer t2.deinit();
    t2.connect();

    // Node 1 queues + sends a heartbeat
    _ = f1.send(.{
        .msg_type = .heartbeat,
        .from_node_id = 1,
        .timestamp_ns = 1_000_000_000,
    }, 1_000_000_000);
    f1.flushTo(t1.asTransport(), 1_000_000_000) catch return false;

    // Network delivery: t1 -> t2
    t1.deliverTo(&t2) catch return false;

    // Node 2 receives + decodes
    const msg = f2.receive(t2.asTransport()) catch return false;
    const ok = msg.msg_type == .heartbeat and
        msg.from_node_id == 1 and
        msg.timestamp_ns == 1_000_000_000;
    std.debug.print("  -> node 1 sent heartbeat; node 2 received msg_type={s}, from={d}\n", .{
        msg.msg_type.toString(), msg.from_node_id,
    });
    return ok;
}

fn scenarioQueueOverflowDrops(alloc: std.mem.Allocator) bool {
    _ = alloc;
    var q = fc.OutboundQueue.init(true); // drop oldest on overflow
    var i: u32 = 0;
    while (i < fc.MAX_OUTBOUND_QUEUE + 5) : (i += 1) {
        _ = q.enqueue(.{
            .msg_type = .heartbeat,
            .from_node_id = i,
        }, 0);
    }
    const ok = q.queueCount() == fc.MAX_OUTBOUND_QUEUE and
        q.total_dropped == 5;
    std.debug.print("  -> queued {d} items; queue_count={d}, dropped={d}\n", .{
        fc.MAX_OUTBOUND_QUEUE + 5, q.queueCount(), q.total_dropped,
    });
    return ok;
}
