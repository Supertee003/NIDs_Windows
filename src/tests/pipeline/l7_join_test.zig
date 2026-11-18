//! L7-JOIN-001: the join between acquisition and the matcher was untested.
//!
//! `Event_queue`'s v3 gate test proves payload bytes survive the wire decode,
//! and `signature_engine`'s tests prove the automaton matches, but nothing
//! loaded a real `Rules.json` pattern and asked whether a frame that arrived
//! through the v3 envelope actually produces that rule id. That join is the only
//! interesting part, so it is pinned here: rules document -> Aho-Corasick ->
//! v3 frame -> queue -> match, plus a benign control.

const std = @import("std");
const canonical = @import("../../contract/canonical_event.zig");
const sig = @import("../../detection/signature_engine.zig");
const rule_loader = @import("../../pipeline/rule_loader.zig");
const event_queue = @import("../../pipeline/event_queue.zig");

const RULES = 
    \\ {"nids_rules": [
    \\   {"rule_id": "R0056", "name": "SQL Injection (Auth Bypass)",
    \\    "category": "Injection", "layer": "L7",
    \\    "fast_pattern": "SQLI_BYPASS", "match_pattern": "' OR 1=1",
    \\    "severity": "Critical", "action": "Drop",
    \\    "target_ports": [80, 443], "target_protocols": ["TCP"]}
    \\ ]}
;

/// Boundaries where the produced rule id is not compared: the join is.
fn queueThroughV3(payload: []const u8) !canonical.DecodedFrame {
    var ce = canonical.create(.npcap_sensor);
    ce.event_id = 6100;
    ce.timestamp_ms = 1700000610000;
    ce.monotonic_ns = 6100000000;
    ce.event_type = .forward;
    ce.source_port = 49152;
    ce.dest_port = 80;
    ce.protocol = 6;
    ce.payload_length = @intCast(payload.len);

    // An IPv4 event carries no 16-byte lane; serializeV3 rejects one that is
    // supplied, which is the contract this path has to honour.
    const env = canonical.V3Envelope{
        .flags = canonical.V3PayloadFlags.PAYLOAD_PRESENT | canonical.V3PayloadFlags.PROVENANCE_VALID,
        .completeness = .complete,
        .payload_len = @intCast(payload.len),
        .original_len = @intCast(payload.len),
        .payload_crc32 = std.hash.Crc32.hash(payload),
        .capture_sequence = 6100,
        .producer_epoch = 0x5F5E1000,
        .producer_generation = 1,
        .interface_id = 3,
    };
    var wire: [canonical.WIRE_V3_MAX_SIZE]u8 = undefined;
    const n = try canonical.serializeV3(&ce, null, null, env, payload, &wire);
    const frame = canonical.deserializeDispatch(wire[0..n]).?;
    try std.testing.expect(event_queue.pushDecodedFrame(&frame, frame.payload));
    return frame;
}

test "L7 rule from Rules.json matches payload that arrived in a v3 frame" {
    const alloc = std.testing.allocator;
    var ac = try sig.AhoCorasick.init(alloc, 100_000);
    defer ac.deinit();
    const report = rule_loader.loadRulesInto(&ac, RULES, "l7_join://Rules.json");
    try std.testing.expectEqual(@as(u32, 1), report.loaded);

    // Drain anything a previous test left behind so the pop below is ours.
    while (event_queue.popEvent()) |_| {}

    const body = "GET /login?user=admin' OR 1=1-- HTTP/1.1\r\nHost: target\r\n\r\n";
    _ = try queueThroughV3(body);
    const queued = event_queue.popEvent().?;

    const hit = ac.matchFirst(queued.payload[0..queued.payload_len]);
    try std.testing.expect(hit != null);
    try std.testing.expectEqual(rule_loader.hashRuleId("R0056"), hit.?.rule_id);
}

test "a benign payload through the same path matches nothing" {
    const alloc = std.testing.allocator;
    var ac = try sig.AhoCorasick.init(alloc, 100_000);
    defer ac.deinit();
    const report = rule_loader.loadRulesInto(&ac, RULES, "l7_join://Rules.json");
    try std.testing.expectEqual(@as(u32, 1), report.loaded);

    while (event_queue.popEvent()) |_| {}

    const body = "GET /index.html HTTP/1.1\r\nHost: target\r\n\r\n";
    _ = try queueThroughV3(body);
    const queued = event_queue.popEvent().?;

    try std.testing.expect(ac.matchFirst(queued.payload[0..queued.payload_len]) == null);
}
