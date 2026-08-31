//! flow_engine.zig - AEGIS Flow Engine (Rewrite Phase 6)
//!
//! Connection tracking: groups CanonicalEvents into Flows keyed by 5-tuple.
//! This is the FIRST stage of the detection pipeline (after nose/fabric).
//!
//! Architecture:
//!   Event Fabric -> Dispatcher -> Flow Engine -> (future) Detection
//!
//! Types (FlowKey, Flow, FlowUpdate, etc.) live in flow_types.zig.
//! This file contains only the FlowEngine implementation.

const std = @import("std");
const canonical = @import("canonical_event.zig");
const flow_types = @import("flow_types.zig");

// Re-export types for backward compatibility
pub const FlowKey = flow_types.FlowKey;
pub const FlowState = flow_types.FlowState;
pub const Flow = flow_types.Flow;
pub const FlowUpdateKind = flow_types.FlowUpdateKind;
pub const FlowUpdate = flow_types.FlowUpdate;
pub const FLOW_IDLE_TIMEOUT_NS = flow_types.FLOW_IDLE_TIMEOUT_NS;
pub const EVICT_BATCH_SIZE = flow_types.EVICT_BATCH_SIZE;

// ============================================================
// Flow Engine
// ============================================================

pub const FlowEngine = struct {
    allocator: std.mem.Allocator,
    map: flow_types.FlowMap,
    idle_timeout_ns: i128,
    max_flows: usize,
    /// Total flows created (lifetime counter).
    total_created: u64,
    /// Total flows evicted by idle timeout.
    total_expired: u64,
    /// Total flows ended normally.
    total_ended: u64,
    /// Total packets processed.
    total_packets: u64,
    /// Total bytes processed.
    total_bytes: u64,

    pub fn init(allocator: std.mem.Allocator) FlowEngine {
        return .{
            .allocator = allocator,
            .map = flow_types.FlowMap.init(allocator),
            .idle_timeout_ns = FLOW_IDLE_TIMEOUT_NS,
            .max_flows = 65536,
            .total_created = 0,
            .total_expired = 0,
            .total_ended = 0,
            .total_packets = 0,
            .total_bytes = 0,
        };
    }

    pub fn deinit(self: *FlowEngine) void {
        self.map.deinit();
    }

    /// Configure idle timeout and max size. Must be called before processing events.
    pub fn configure(self: *FlowEngine, idle_timeout_ns: i128, max_flows: usize) void {
        self.idle_timeout_ns = idle_timeout_ns;
        self.max_flows = max_flows;
    }

    /// Process a CanonicalEvent and return a FlowUpdate.
    /// This is the main entry point — dispatcher calls this for every event.
    pub fn processEvent(self: *FlowEngine, event: canonical.CanonicalEvent) FlowUpdate {
        const key = FlowKey.fromEvent(event);
        const now_ns = event.monotonic_ns;

        // Check if flow already exists
        if (self.map.getPtr(key)) |flow_entry| {
            // Update existing flow
            const old_state = flow_entry.state;
            updateFlowState(flow_entry, event, now_ns);

            self.total_packets += 1;
            self.total_bytes += event.payload_length;

            return .{
                .kind = if (flow_entry.state != old_state) .flow_state_changed else .flow_updated,
                .key = key,
                .flow = flow_entry.*,
                .triggering_event_id = event.event_id,
            };
        }

        // New flow — first check if table is full, evict if needed.
        if (self.map.count() >= self.max_flows) {
            const evict_count = @min(EVICT_BATCH_SIZE, @max(@as(usize, 1), self.max_flows / 100));
            self.evictOldest(evict_count);
        }

        // Create new flow
        const new_flow = Flow{
            .key = key,
            .state = initStateFromEvent(event),
            .start_ns = now_ns,
            .last_seen_ns = now_ns,
            .packet_count = 1,
            .byte_count = event.payload_length,
            .session_id_set = 1,
            .last_session_id = event.session_id,
            .initial_direction = event.direction,
            .max_severity = event.severity,
            .rule_matched = event.rule_id != 0,
            .last_rule_id = event.rule_id,
        };

        self.map.put(key, new_flow) catch {
            return .{
                .kind = .flow_updated,
                .key = key,
                .flow = new_flow,
                .triggering_event_id = event.event_id,
            };
        };

        self.total_created += 1;
        self.total_packets += 1;
        self.total_bytes += event.payload_length;

        return .{
            .kind = .flow_created,
            .key = key,
            .flow = new_flow,
            .triggering_event_id = event.event_id,
        };
    }

    /// Evict flows that have been idle longer than idle_timeout_ns.
    /// Returns the number of flows evicted.
    pub fn sweepExpired(self: *FlowEngine, now_ns: i128) usize {
        var to_remove = std.ArrayList(FlowKey).init(self.allocator);
        defer to_remove.deinit();

        var it = self.map.iterator();
        while (it.next()) |entry| {
            if (now_ns - entry.value_ptr.last_seen_ns > self.idle_timeout_ns) {
                to_remove.append(entry.value_ptr.key) catch break;
            }
        }

        const n = to_remove.items.len;
        for (to_remove.items) |k| {
            _ = self.map.remove(k);
        }
        self.total_expired += n;
        return n;
    }

    /// Force-remove the N oldest flows (by last_seen_ns).
    fn evictOldest(self: *FlowEngine, n: usize) void {
        if (self.map.count() == 0) return;

        const Candidate = struct { key: FlowKey, ts: i128 };
        var candidates = std.ArrayList(Candidate).init(self.allocator);
        defer candidates.deinit();
        candidates.ensureTotalCapacity(@min(n, self.map.count())) catch return;

        var it = self.map.iterator();
        while (it.next()) |entry| {
            candidates.append(.{
                .key = entry.value_ptr.key,
                .ts = entry.value_ptr.last_seen_ns,
            }) catch break;
        }

        const lessThan = struct {
            fn lt(_: void, a: Candidate, b: Candidate) bool {
                return a.ts < b.ts;
            }
        }.lt;
        std.mem.sort(Candidate, candidates.items, {}, lessThan);

        const to_evict = @min(n, candidates.items.len);
        for (candidates.items[0..to_evict]) |c| {
            _ = self.map.remove(c.key);
        }
        self.total_expired += to_evict;
    }

    /// Get a flow by key (read-only). Returns null if not present.
    pub fn getFlow(self: *const FlowEngine, key: FlowKey) ?Flow {
        return self.map.get(key);
    }

    /// Current number of tracked flows.
    pub fn count(self: *const FlowEngine) usize {
        return self.map.count();
    }
};

// ============================================================
// Internal helpers
// ============================================================

fn initStateFromEvent(event: canonical.CanonicalEvent) FlowState {
    if (event.event_type == .session_start) return .established;
    if (event.event_type == .session_end) return .closed;
    if (event.protocol == 6) {
        return .new;
    }
    return .established;
}

fn updateFlowState(flow_entry: *Flow, event: canonical.CanonicalEvent, now_ns: i128) void {
    flow_entry.last_seen_ns = now_ns;
    flow_entry.packet_count += 1;
    flow_entry.byte_count += event.payload_length;

    if (event.session_id != flow_entry.last_session_id) {
        flow_entry.session_id_set +%= 1;
        flow_entry.last_session_id = event.session_id;
    }

    if (event.severity > flow_entry.max_severity) {
        flow_entry.max_severity = event.severity;
    }

    if (event.rule_id != 0) {
        flow_entry.rule_matched = true;
        flow_entry.last_rule_id = event.rule_id;
    }

    switch (flow_entry.state) {
        .new => {
            if (event.event_type == .session_start or event.protocol != 6) {
                flow_entry.state = .established;
            }
        },
        .established => {
            if (event.event_type == .session_end) {
                flow_entry.state = .closing;
            }
        },
        .closing => {
            if (event.event_type == .session_end) {
                flow_entry.state = .closed;
            }
        },
        .closed => {},
    }
}

// ============================================================
// Tests
// ============================================================

test "FlowKey.fromEvent canonicalizes bidirectional flows" {
    var e1 = canonical.create(.wfp_sensor);
    e1.source_ip = 0x0A000001;
    e1.source_port = 12345;
    e1.dest_ip = 0x0A000002;
    e1.dest_port = 80;
    e1.protocol = 6;

    var e2 = canonical.create(.wfp_sensor);
    e2.source_ip = 0x0A000002;
    e2.source_port = 80;
    e2.dest_ip = 0x0A000001;
    e2.dest_port = 12345;
    e2.protocol = 6;

    const k1 = FlowKey.fromEvent(e1);
    const k2 = FlowKey.fromEvent(e2);

    try std.testing.expect(FlowKey.eql(k1, k2));
    try std.testing.expect(k1.ip_a == 0x0A000001);
    try std.testing.expect(k1.port_a == 12345);
    try std.testing.expect(k1.ip_b == 0x0A000002);
    try std.testing.expect(k1.port_b == 80);
}

test "FlowKey.fromEvent handles same-IP flows (port breaks tie)" {
    var e1 = canonical.create(.wfp_sensor);
    e1.source_ip = 0x0A000001;
    e1.source_port = 5000;
    e1.dest_ip = 0x0A000001;
    e1.dest_port = 80;
    e1.protocol = 6;

    var e2 = canonical.create(.wfp_sensor);
    e2.source_ip = 0x0A000001;
    e2.source_port = 80;
    e2.dest_ip = 0x0A000001;
    e2.dest_port = 5000;
    e2.protocol = 6;

    const k1 = FlowKey.fromEvent(e1);
    const k2 = FlowKey.fromEvent(e2);
    try std.testing.expect(FlowKey.eql(k1, k2));
    try std.testing.expect(k1.port_a == 80);
}

test "FlowKey.fromEvent uses session_id for non-IP events" {
    var e = canonical.create(.pipe_sensor);
    e.is_pipe = 1;
    e.source_ip = 0;
    e.session_id = 0xDEADBEEFCAFE;
    e.protocol = 0;

    const k = FlowKey.fromEvent(e);
    try std.testing.expect(k.ip_a == 0xBEEFCAFE);
    try std.testing.expect(k.port_a == 0xDEAD);
    try std.testing.expect(k.ip_b == 0);
    try std.testing.expect(k.port_b == 0);
}

test "FlowEngine: first packet creates new flow" {
    var engine = FlowEngine.init(std.testing.allocator);
    defer engine.deinit();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001;
    event.source_port = 12345;
    event.dest_ip = 0x0A000002;
    event.dest_port = 80;
    event.protocol = 6;
    event.payload_length = 100;

    const update = engine.processEvent(event);

    try std.testing.expect(update.kind == .flow_created);
    try std.testing.expect(engine.count() == 1);
    try std.testing.expect(engine.total_created == 1);
    try std.testing.expect(engine.total_packets == 1);
    try std.testing.expect(engine.total_bytes == 100);
}

test "FlowEngine: second packet updates existing flow" {
    var engine = FlowEngine.init(std.testing.allocator);
    defer engine.deinit();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001;
    event.source_port = 12345;
    event.dest_ip = 0x0A000002;
    event.dest_port = 80;
    event.protocol = 6;
    event.payload_length = 100;
    event.session_id = 1;

    _ = engine.processEvent(event);

    event.source_ip = 0x0A000002;
    event.source_port = 80;
    event.dest_ip = 0x0A000001;
    event.dest_port = 12345;
    event.payload_length = 200;
    event.session_id = 2;

    const update = engine.processEvent(event);

    try std.testing.expect(update.kind == .flow_updated);
    try std.testing.expect(engine.count() == 1);
    try std.testing.expect(update.flow.packet_count == 2);
    try std.testing.expect(update.flow.byte_count == 300);
    try std.testing.expect(update.flow.last_session_id == 2);
    try std.testing.expect(update.flow.session_id_set == 2);
}

test "FlowEngine: session_start transitions new -> established" {
    var engine = FlowEngine.init(std.testing.allocator);
    defer engine.deinit();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001;
    event.source_port = 12345;
    event.dest_ip = 0x0A000002;
    event.dest_port = 80;
    event.protocol = 6;

    const upd1 = engine.processEvent(event);
    try std.testing.expect(upd1.kind == .flow_created);
    try std.testing.expect(upd1.flow.state == .new);

    event.event_type = .session_start;
    const upd2 = engine.processEvent(event);
    try std.testing.expect(upd2.kind == .flow_state_changed);
    try std.testing.expect(upd2.flow.state == .established);

    event.event_type = .forward;
    const upd3 = engine.processEvent(event);
    try std.testing.expect(upd3.kind == .flow_updated);
    try std.testing.expect(upd3.flow.state == .established);
}

test "FlowEngine: session_end transitions established -> closing -> closed" {
    var engine = FlowEngine.init(std.testing.allocator);
    defer engine.deinit();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001;
    event.source_port = 12345;
    event.dest_ip = 0x0A000002;
    event.dest_port = 80;
    event.protocol = 6;
    event.event_type = .session_start;

    _ = engine.processEvent(event);

    event.event_type = .session_end;
    const upd1 = engine.processEvent(event);
    try std.testing.expect(upd1.flow.state == .closing);

    const upd2 = engine.processEvent(event);
    try std.testing.expect(upd2.flow.state == .closed);
}

test "FlowEngine: UDP flow starts established" {
    var engine = FlowEngine.init(std.testing.allocator);
    defer engine.deinit();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001;
    event.source_port = 5353;
    event.dest_ip = 0xE00000FB;
    event.dest_port = 5353;
    event.protocol = 17;

    const update = engine.processEvent(event);
    try std.testing.expect(update.flow.state == .established);
}

test "FlowEngine: tracks max severity and rule matches" {
    var engine = FlowEngine.init(std.testing.allocator);
    defer engine.deinit();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001;
    event.source_port = 12345;
    event.dest_ip = 0x0A000002;
    event.dest_port = 80;
    event.protocol = 6;
    event.severity = 1;
    event.rule_id = 0;

    _ = engine.processEvent(event);

    event.severity = 3;
    event.rule_id = 0xDEADBEEF;
    const update = engine.processEvent(event);

    try std.testing.expect(update.flow.max_severity == 3);
    try std.testing.expect(update.flow.rule_matched == true);
    try std.testing.expect(update.flow.last_rule_id == 0xDEADBEEF);
}

test "FlowEngine: sweepExpired evicts idle flows" {
    var engine = FlowEngine.init(std.testing.allocator);
    defer engine.deinit();
    engine.configure(100 * std.time.ns_per_ms, 1000);

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001;
    event.source_port = 12345;
    event.dest_ip = 0x0A000002;
    event.dest_port = 80;
    event.protocol = 6;
    event.monotonic_ns = 0;
    event.payload_length = 100;

    _ = engine.processEvent(event);
    try std.testing.expect(engine.count() == 1);

    var n = engine.sweepExpired(50 * std.time.ns_per_ms);
    try std.testing.expect(n == 0);
    try std.testing.expect(engine.count() == 1);

    n = engine.sweepExpired(200 * std.time.ns_per_ms);
    try std.testing.expect(n == 1);
    try std.testing.expect(engine.count() == 0);
    try std.testing.expect(engine.total_expired == 1);
}

test "FlowEngine: evicts oldest when table is full" {
    var engine = FlowEngine.init(std.testing.allocator);
    defer engine.deinit();
    engine.configure(std.time.ns_per_s, 4);

    var i: u32 = 0;
    while (i < 4) : (i += 1) {
        var event = canonical.create(.wfp_sensor);
        event.source_ip = 0x0A000000 + i;
        event.source_port = @intCast(1000 + i);
        event.dest_ip = 0x0A0000FF;
        event.dest_port = 80;
        event.protocol = 6;
        event.monotonic_ns = @intCast(i);
        _ = engine.processEvent(event);
    }
    try std.testing.expect(engine.count() == 4);

    var event5 = canonical.create(.wfp_sensor);
    event5.source_ip = 0x0A00000A;
    event5.source_port = 9999;
    event5.dest_ip = 0x0A0000FF;
    event5.dest_port = 80;
    event5.protocol = 6;
    event5.monotonic_ns = 100;

    _ = engine.processEvent(event5);
    try std.testing.expect(engine.count() == 4);
    try std.testing.expect(engine.total_expired == 1);

    const old_key = FlowKey{
        .ip_a = 0x0A000000,
        .port_a = 1000,
        .ip_b = 0x0A0000FF,
        .port_b = 80,
        .protocol = 6,
    };
    try std.testing.expect(engine.getFlow(old_key) == null);
}

test "FlowEngine: configure() changes timeout and max" {
    var engine = FlowEngine.init(std.testing.allocator);
    defer engine.deinit();
    engine.configure(5 * std.time.ns_per_s, 100);
    try std.testing.expect(engine.idle_timeout_ns == 5 * std.time.ns_per_s);
    try std.testing.expect(engine.max_flows == 100);
}

test "FlowEngine: lifetime stats accumulate correctly" {
    var engine = FlowEngine.init(std.testing.allocator);
    defer engine.deinit();

    var i: u32 = 0;
    while (i < 3) : (i += 1) {
        var j: u32 = 0;
        while (j < 5) : (j += 1) {
            var event = canonical.create(.wfp_sensor);
            event.source_ip = 0x0A000000 + i;
            event.source_port = @intCast(1000 + i);
            event.dest_ip = 0x0A0000FF;
            event.dest_port = 80;
            event.protocol = 6;
            event.payload_length = 50;
            _ = engine.processEvent(event);
        }
    }

    try std.testing.expect(engine.total_created == 3);
    try std.testing.expect(engine.total_packets == 15);
    try std.testing.expect(engine.total_bytes == 15 * 50);
}
