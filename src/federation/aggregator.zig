// II14 - Federation Aggregator
// AEGIS NIDS v5.0+ â€” Cross-node event aggregation & correlation
//
// Subscribes to remote-node events, de-duplicates by event_id, and feeds
// them into a "federated correlator" that detects cluster-wide patterns
// (e.g., port scan from same src across multiple sensors).

const std = @import("std");
const event = @import("../contract/event.zig");
const diag = @import("../core/diagnostics.zig");

pub const FederatedEvent = struct {
    ev: event.IpcEvent,
    origin_node_id: u32,
    received_ns: i128 = 0,
};

pub const Aggregator = struct {
    seen: std.AutoHashMap(u64, void), // event_id dedup
    events: std.ArrayList(FederatedEvent),
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    duplicates_dropped: u64 = 0,

    pub fn init(allocator: std.mem.Allocator) Aggregator {
        return .{
            .seen = std.AutoHashMap(u64, void).init(allocator),
            .events = std.ArrayList(FederatedEvent).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Aggregator) void {
        self.seen.deinit();
        self.events.deinit();
    }

    pub fn ingest(self: *Aggregator, ev: *const event.IpcEvent, origin_node_id: u32) !bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!ev.validate()) {
            diag.warn("aggregator: rejected invalid event from node {d}", .{origin_node_id});
            return false;
        }
        const gop = try self.seen.getOrPut(ev.event_id);
        if (gop.found_existing) {
            self.duplicates_dropped += 1;
            return false;
        }
        try self.events.append(.{
            .ev = ev.*,
            .origin_node_id = origin_node_id,
            .received_ns = std.time.nanoTimestamp(),
        });
        return true;
    }

    pub fn pending(self: *Aggregator) usize {
        return self.events.items.len;
    }

    pub fn drain(self: *Aggregator) []FederatedEvent {
        self.mutex.lock();
        defer self.mutex.unlock();
        const items = self.events.items;
        self.events = std.ArrayList(FederatedEvent).init(self.allocator);
        return items;
    }

    // Cross-node correlation: count distinct nodes that saw an event from src_ip
    pub fn countNodesForSource(self: *Aggregator, src_ip: u32) u32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        var seen_nodes = std.AutoHashMap(u32, void).init(self.allocator);
        defer seen_nodes.deinit();
        for (self.events.items) |fe| {
            if (fe.ev.src_ip == src_ip) {
                seen_nodes.put(fe.origin_node_id, {}) catch break;
            }
        }
        return @intCast(seen_nodes.count());
    }
};

// ============================================================================
// Tests
// ============================================================================
test "Aggregator dedup by event_id" {
    var ag = Aggregator.init(std.testing.allocator);
    defer ag.deinit();
    var ev = event.IpcEvent.init(.signature_match);
    ev.event_id = 100;
    try std.testing.expect(try ag.ingest(&ev, 1));
    try std.testing.expect(!try ag.ingest(&ev, 2)); // dup
    try std.testing.expectEqual(@as(u64, 1), ag.duplicates_dropped);
    try std.testing.expectEqual(@as(usize, 1), ag.pending());
}

test "Aggregator rejects invalid event" {
    var ag = Aggregator.init(std.testing.allocator);
    defer ag.deinit();
    var ev = event.IpcEvent.init(.signature_match);
    ev.magic = 0; // invalidate
    try std.testing.expect(!try ag.ingest(&ev, 1));
}

test "Aggregator countNodesForSource" {
    var ag = Aggregator.init(std.testing.allocator);
    defer ag.deinit();
    var ev1 = event.IpcEvent.init(.signature_match);
    ev1.event_id = 1;
    ev1.src_ip = 0x0A000001;
    var ev2 = event.IpcEvent.init(.signature_match);
    ev2.event_id = 2;
    ev2.src_ip = 0x0A000001;
    var ev3 = event.IpcEvent.init(.signature_match);
    ev3.event_id = 3;
    ev3.src_ip = 0x0A000002;
    _ = try ag.ingest(&ev1, 1);
    _ = try ag.ingest(&ev2, 2);
    _ = try ag.ingest(&ev3, 3);
    try std.testing.expectEqual(@as(u32, 2), ag.countNodesForSource(0x0A000001));
    try std.testing.expectEqual(@as(u32, 1), ag.countNodesForSource(0x0A000002));
}
