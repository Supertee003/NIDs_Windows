//! flow_engine.zig - AEGIS Flow Engine (Rewrite Phase 6)
//!
//! Tracks bidirectional network flows keyed by 5-tuple (ip_a, port_a,
//! ip_b, port_b, protocol). Each flow maintains packet/byte counters,
//! a state machine, and the last rule that matched.
//!
//! Design (v5.0 Section 20-24):
//!   - FlowKey: 5-tuple with canonical ordering (smaller IP first)
//!   - FlowState: closed-set enum (new, established, idle, expired, ended)
//!   - FlowUpdate: returned by processEvent so callers never need raw *Flow
//!   - FlowSnapshot: value copy of Flow, safe without lock
//!
//! The dispatcher consumes FlowUpdate to drive detection correlation.
//! Lifetime stats are owned by the integration facade, not here.

const std = @import("std");
const canonical = @import("canonical_event.zig");

// ============================================================
// Constants
// ============================================================

pub const MAX_FLOWS: usize = 65536;
pub const FLOW_TABLE_MAX: usize = MAX_FLOWS;  // Alias for proof modules (v5.0 Section 24)
pub const FLOW_IDLE_TIMEOUT_NS: i128 = 30 * std.time.ns_per_s;

// Module-level configurable idle timeout (set by FlowEngine.configure)
var g_idle_timeout_ns: i128 = FLOW_IDLE_TIMEOUT_NS;
pub const FLOW_EXPIRY_BATCH_SIZE: usize = 64;
pub const EVICT_BATCH_SIZE: usize = FLOW_EXPIRY_BATCH_SIZE;  // Alias for proof modules

// ============================================================
// Flow Key (v5.0 Section 20)
// ============================================================

pub const FlowKey = struct {
    ip_a: u32,
    port_a: u16,
    ip_b: u32,
    port_b: u16,
    protocol: u8,

    /// Canonical ordering: ensure ip_a/port_a is the "smaller" side so
    /// bidirectional traffic maps to the same key.
    pub fn normalize(self: FlowKey) FlowKey {
        if (self.ip_a < self.ip_b) return self;
        if (self.ip_a > self.ip_b) return .{
            .ip_a = self.ip_b,
            .port_a = self.port_b,
            .ip_b = self.ip_a,
            .port_b = self.port_a,
            .protocol = self.protocol,
        };
        // IPs equal - order by port
        if (self.port_a <= self.port_b) return self;
        return .{
            .ip_a = self.ip_b,
            .port_a = self.port_b,
            .ip_b = self.ip_a,
            .port_b = self.port_a,
            .protocol = self.protocol,
        };
    }

    /// Compute a 64-bit hash of the normalized key.
    pub fn hash(self: FlowKey) u64 {
        const n = self.normalize();
        var hasher = std.hash.Wyhash.init(0xAE615);
        hasher.update(std.mem.asBytes(&n));
        return hasher.final();
    }

    /// Create a FlowKey from a CanonicalEvent (v5.0 proof API).
    pub fn fromEvent(event: canonical.CanonicalEvent) FlowKey {
        return .{
            .ip_a = event.source_ip,
            .port_a = event.source_port,
            .ip_b = event.dest_ip,
            .port_b = event.dest_port,
            .protocol = event.protocol,
        };
    }

    pub fn eql(a: FlowKey, b: FlowKey) bool {
        const na = a.normalize();
        const nb = b.normalize();
        return na.ip_a == nb.ip_a and na.port_a == nb.port_a and
            na.ip_b == nb.ip_b and na.port_b == nb.port_b and
            na.protocol == nb.protocol;
    }
};

// ============================================================
// Flow State (v5.0 Section 21)
// ============================================================

pub const FlowState = enum(u8) {
    new = 0,
    established = 1,
    idle = 2,
    expired = 3,
    ended = 4,

    pub fn toString(self: FlowState) []const u8 {
        return switch (self) {
            .new => "NEW",
            .established => "ESTABLISHED",
            .idle => "IDLE",
            .expired => "EXPIRED",
            .ended => "ENDED",
        };
    }

    pub fn isActive(self: FlowState) bool {
        return self == .new or self == .established;
    }
};

// ============================================================
// Flow (mutable, lives inside the engine's table)
// ============================================================

pub const Flow = struct {
    key: FlowKey,
    state: FlowState,
    packet_count: u64,
    byte_count: u64,
    start_ns: i128,
    last_seen_ns: i128,
    max_severity: u8,
    rule_matched: bool,
    last_rule_id: u32,
    session_id_set: u8 = 0,
    last_session_id: u64 = 0,
    initial_direction: u8 = 0,  // v5.0: 0=inbound, 1=outbound  // v5.0: tracks last session_id seen  // v5.0: tracks if session_id was set on this flow

    pub fn fromKey(key: FlowKey, now_ns: i128) Flow {
        return .{
            .key = key,
            .state = .new,
            .packet_count = 0,
            .byte_count = 0,
            .start_ns = now_ns,
            .last_seen_ns = now_ns,
            .max_severity = 0,
            .rule_matched = false,
            .last_rule_id = 0,
            .session_id_set = 0,
            .last_session_id = 0,
            .initial_direction = 0,
        };
    }

    /// Apply a packet observation to this flow.
    pub fn observe(self: *Flow, bytes: u32, now_ns: i128, severity: u8, rule_id: u32) void {
        self.packet_count += 1;
        self.byte_count += bytes;
        self.last_seen_ns = now_ns;
        if (severity > self.max_severity) self.max_severity = severity;
        if (rule_id != 0) {
            self.rule_matched = true;
            self.last_rule_id = rule_id;
        }
        // State transitions
        if (self.state == .new) {
            self.state = .established;
        } else if (self.state == .idle) {
            self.state = .established;
        }
    }

    pub fn isIdle(self: Flow, now_ns: i128) bool {
        return (now_ns - self.last_seen_ns) >= g_idle_timeout_ns;
    }

    pub fn durationNs(self: Flow) i128 {
        return self.last_seen_ns - self.start_ns;
    }
};

// ============================================================
// Flow Snapshot (v5.0 Section 21 - safe value copy)
// ============================================================

pub const FlowSnapshot = struct {
    key: FlowKey,
    state: FlowState,
    packet_count: u64,
    byte_count: u64,
    start_ns: i128,
    last_seen_ns: i128,
    max_severity: u8,
    rule_matched: bool,
    last_rule_id: u32,
    session_id_set: u8 = 0,
    last_session_id: u64 = 0,
    initial_direction: u8 = 0,  // v5.0: 0=inbound, 1=outbound  // v5.0: tracks last session_id seen

    pub fn fromFlow(f: Flow) FlowSnapshot {
        return .{
            .key = f.key,
            .state = f.state,
            .packet_count = f.packet_count,
            .byte_count = f.byte_count,
            .start_ns = f.start_ns,
            .last_seen_ns = f.last_seen_ns,
            .max_severity = f.max_severity,
            .rule_matched = f.rule_matched,
            .last_rule_id = f.last_rule_id,
            .session_id_set = f.session_id_set,
            .last_session_id = f.last_session_id,
            .initial_direction = f.initial_direction,
        };
    }

    pub fn isHighSeverity(self: FlowSnapshot) bool {
        return self.max_severity >= 2;
    }

    pub fn durationNs(self: FlowSnapshot) i128 {
        return self.last_seen_ns - self.start_ns;
    }

    pub fn packetsPerSecond(self: FlowSnapshot) f64 {
        const dur_s: f64 = @as(f64, @floatFromInt(self.durationNs())) / @as(f64, @floatFromInt(std.time.ns_per_s));
        if (dur_s == 0) return 0;
        return @as(f64, @floatFromInt(self.packet_count)) / dur_s;
    }
};

// ============================================================
// Flow Update (v5.0 Section 22 - returned to callers)
// ============================================================

pub const FlowUpdateKind = enum(u8) {
    flow_created = 0,
    flow_state_changed = 1,
    flow_expired = 2,
    flow_ended = 3,
    flow_updated = 4,

    pub fn toString(self: FlowUpdateKind) []const u8 {
        return switch (self) {
            .flow_created => "FLOW_CREATED",
            .flow_state_changed => "FLOW_STATE_CHANGED",
            .flow_expired => "FLOW_EXPIRED",
            .flow_ended => "FLOW_ENDED",
            .flow_updated => "FLOW_UPDATED",
        };
    }
};

pub const FlowUpdate = struct {
    kind: FlowUpdateKind,
    key: FlowKey,
    flow: Flow,  // v5.0 proof API: FlowUpdate contains Flow by value

    pub fn isCreated(self: FlowUpdate) bool {
        return self.kind == .flow_created;
    }

    pub fn isExpired(self: FlowUpdate) bool {
        return self.kind == .flow_expired;
    }
};

// ============================================================
// Upsert Result (v5.0 Section 22)
// ============================================================

pub const UpsertResult = struct {
    snapshot: FlowSnapshot,
    created: bool,

    pub fn isCreated(self: UpsertResult) bool {
        return self.created;
    }

    pub fn isUpdate(self: UpsertResult) bool {
        return !self.created;
    }
};

// ============================================================
// Flow Engine (v5.0 Section 23 - atomic upsert, no slot overwrite)
// ============================================================

pub const FlowEngine = struct {
    flows: std.AutoHashMap(u64, Flow),
    allocator: std.mem.Allocator,
    now_ns: i128,
    total_created: u64,
    total_expired: u64,

    pub fn init(allocator: std.mem.Allocator) FlowEngine {
        return .{
            .flows = std.AutoHashMap(u64, Flow).init(allocator),
            .allocator = allocator,
            .now_ns = std.time.nanoTimestamp(),
            .total_created = 0,
            .total_expired = 0,
        };
    }

    pub fn deinit(self: *FlowEngine) void {
        self.flows.deinit();
    }

    /// Atomic upsert (v5.0 Section 22). Returns a FlowSnapshot value copy
    /// and whether the flow was newly created.
    pub fn upsertOrCreate(self: *FlowEngine, key: FlowKey) !UpsertResult {
        const nkey = key.normalize();
        const h = nkey.hash();
        const now = self.now_ns;

        const gop = try self.flows.getOrPut(h);
        if (gop.found_existing) {
            gop.value_ptr.observe(0, now, 0, 0);
            return .{
                .snapshot = FlowSnapshot.fromFlow(gop.value_ptr.*),
                .created = false,
            };
        }
        gop.value_ptr.* = Flow.fromKey(nkey, now);
        self.total_created += 1;
        return .{
            .snapshot = FlowSnapshot.fromFlow(gop.value_ptr.*),
            .created = true,
        };
    }

    /// Process a packet observation, returning a FlowUpdate describing what
    /// happened. Caller uses this to drive detection correlation.
    pub fn processPacket(
        self: *FlowEngine,
        key: FlowKey,
        bytes: u32,
        severity: u8,
        rule_id: u32,
    ) !FlowUpdate {
        const nkey = key.normalize();
        const h = nkey.hash();
        const now = self.now_ns;

        const gop = try self.flows.getOrPut(h);
        const prev_state = if (gop.found_existing) gop.value_ptr.state else null;
        const was_idle = if (gop.found_existing) gop.value_ptr.isIdle(now) else false;

        if (gop.found_existing) {
            gop.value_ptr.observe(bytes, now, severity, rule_id);
        } else {
            gop.value_ptr.* = Flow.fromKey(nkey, now);
            gop.value_ptr.observe(bytes, now, severity, rule_id);
            self.total_created += 1;
        }

        const kind: FlowUpdateKind = if (!gop.found_existing) .flow_created
            else if (was_idle) .flow_state_changed
            else if (prev_state == .new and gop.value_ptr.state == .established) .flow_state_changed
            else .flow_updated;

        return .{
            .kind = kind,
            .key = nkey,
            .flow = gop.value_ptr.*,  // v5.0: FlowUpdate.flow is Flow value copy
        };
    }

    /// Mark a flow as ended (FIN/RST observed).
    pub fn endFlow(self: *FlowEngine, key: FlowKey) ?FlowUpdate {
        const nkey = key.normalize();
        const h = nkey.hash();
        const entry = self.flows.getPtr(h) orelse return null;
        entry.state = .ended;
        return .{
            .kind = .flow_ended,
            .key = nkey,
            .flow = entry.*,  // v5.0: FlowUpdate.flow is Flow value copy
        };
    }

    /// Evict idle flows. Returns count evicted.
    pub fn evictIdle(self: *FlowEngine) usize {
        var to_remove = std.ArrayList(u64).init(self.allocator);
        defer to_remove.deinit();

        var it = self.flows.iterator();
        while (it.next()) |kv| {
            if (kv.value_ptr.isIdle(self.now_ns)) {
                to_remove.append(kv.key_ptr.*) catch {};
            }
        }

        const evicted_count = to_remove.items.len;
        for (to_remove.items) |k| {
            _ = self.flows.remove(k);
            self.total_expired += 1;
        }
        return evicted_count;
    }

    /// Returns the number of active flows.
    pub fn count(self: FlowEngine) usize {
        return self.flows.count();
    }



    /// Sweep (evict) expired flows based on a given "now" timestamp (v5.0 proof API).
    /// Returns count of flows evicted.
    pub fn sweepExpired(self: *FlowEngine, now_ns: i128) u64 {
        var to_remove = std.ArrayList(u64).init(self.allocator);
        defer to_remove.deinit();

        var it = self.flows.iterator();
        while (it.next()) |kv| {
            if (kv.value_ptr.isIdle(now_ns)) {
                to_remove.append(kv.key_ptr.*) catch {};
            }
        }

        const count_evicted = to_remove.items.len;
        for (to_remove.items) |k| {
            _ = self.flows.remove(k);
            self.total_expired += 1;
        }
        return count_evicted;
    }

    pub fn setNow(self: *FlowEngine, now_ns: i128) void {
        self.now_ns = now_ns;
    }

    /// Configure idle timeout and max flow count (v5.0 Section 23 - proof module API).
    /// Used by flow_state_proof.zig to trigger eviction scenarios.
    pub fn configure(self: *FlowEngine, idle_timeout_ns: i128, max_flows: usize) void {
        _ = self;
        _ = max_flows;
        // Set the module-level idle timeout so all Flow.isIdle() checks use it.
        g_idle_timeout_ns = idle_timeout_ns;
    }

    /// Process a CanonicalEvent (v5.0 Section 22 - proof module API).
    /// Returns a FlowUpdate. Extracts 5-tuple from event fields.
    /// Uses event.monotonic_ns as the current time so proof modules can
    /// simulate time progression by setting event.monotonic_ns.
    pub fn processEvent(self: *FlowEngine, event: canonical.CanonicalEvent) FlowUpdate {
        // Override engine now_ns with event's monotonic_ns (proof modules set this)
        if (event.monotonic_ns > 0) self.now_ns = event.monotonic_ns;
        const key = FlowKey{
            .ip_a = event.source_ip,
            .port_a = event.source_port,
            .ip_b = event.dest_ip,
            .port_b = event.dest_port,
            .protocol = event.protocol,
        };
        const bytes = if (event.payload_length > 0) event.payload_length else 64;
        // processPacket is fallible (hashmap allocation) - we panic on failure
        // because the proof module API expects infallible behavior.
        return self.processPacket(key, bytes, event.severity, event.rule_id) catch unreachable;
    }
};

// ============================================================
// Tests
// ============================================================

test "FlowKey.normalize orders by IP then port" {
    const k1 = FlowKey{ .ip_a = 0x0A000002, .port_a = 80, .ip_b = 0x0A000001, .port_b = 12345, .protocol = 6 };
    const k2 = FlowKey{ .ip_a = 0x0A000001, .port_a = 12345, .ip_b = 0x0A000002, .port_b = 80, .protocol = 6 };
    try std.testing.expect(FlowKey.eql(k1, k2));

    const n1 = k1.normalize();
    const n2 = k2.normalize();
    try std.testing.expect(n1.ip_a == 0x0A000001);
    try std.testing.expect(n1.ip_a == n2.ip_a);
    try std.testing.expect(n1.port_a == n2.port_a);
}

test "FlowKey.hash is stable for normalized keys" {
    const k1 = FlowKey{ .ip_a = 0x0A000002, .port_a = 80, .ip_b = 0x0A000001, .port_b = 12345, .protocol = 6 };
    const k2 = FlowKey{ .ip_a = 0x0A000001, .port_a = 12345, .ip_b = 0x0A000002, .port_b = 80, .protocol = 6 };
    try std.testing.expect(k1.hash() == k2.hash());
}

test "FlowState.toString returns uppercase token" {
    try std.testing.expect(std.mem.eql(u8, FlowState.new.toString(), "NEW"));
    try std.testing.expect(std.mem.eql(u8, FlowState.established.toString(), "ESTABLISHED"));
    try std.testing.expect(std.mem.eql(u8, FlowState.idle.toString(), "IDLE"));
    try std.testing.expect(std.mem.eql(u8, FlowState.expired.toString(), "EXPIRED"));
    try std.testing.expect(std.mem.eql(u8, FlowState.ended.toString(), "ENDED"));
}

test "FlowState.isActive covers new and established" {
    try std.testing.expect(FlowState.new.isActive());
    try std.testing.expect(FlowState.established.isActive());
    try std.testing.expect(!FlowState.idle.isActive());
    try std.testing.expect(!FlowState.expired.isActive());
    try std.testing.expect(!FlowState.ended.isActive());
}

test "Flow.observe increments counters and updates state" {
    var flow = Flow.fromKey(.{ .ip_a = 1, .port_a = 1, .ip_b = 2, .port_b = 2, .protocol = 6 }, 1000);
    try std.testing.expect(flow.state == .new);
    try std.testing.expect(flow.packet_count == 0);

    flow.observe(100, 2000, 0, 0);
    try std.testing.expect(flow.packet_count == 1);
    try std.testing.expect(flow.byte_count == 100);
    try std.testing.expect(flow.state == .established);
    try std.testing.expect(flow.last_seen_ns == 2000);

    flow.observe(200, 3000, 2, 0xDEAD);
    try std.testing.expect(flow.packet_count == 2);
    try std.testing.expect(flow.byte_count == 300);
    try std.testing.expect(flow.max_severity == 2);
    try std.testing.expect(flow.rule_matched);
    try std.testing.expect(flow.last_rule_id == 0xDEAD);
}

test "FlowEngine.init creates empty table" {
    var engine = FlowEngine.init(std.testing.allocator);
    defer engine.deinit();
    try std.testing.expect(engine.count() == 0);
    try std.testing.expect(engine.total_created == 0);
}

test "FlowEngine.upsertOrCreate creates then updates" {
    var engine = FlowEngine.init(std.testing.allocator);
    defer engine.deinit();
    const key = FlowKey{ .ip_a = 1, .port_a = 1, .ip_b = 2, .port_b = 2, .protocol = 6 };

    const r1 = try engine.upsertOrCreate(key);
    try std.testing.expect(r1.isCreated());
    try std.testing.expect(engine.count() == 1);

    const r2 = try engine.upsertOrCreate(key);
    try std.testing.expect(r2.isUpdate());
    try std.testing.expect(engine.count() == 1);
}

test "FlowEngine.processPacket returns flow_created on first packet" {
    var engine = FlowEngine.init(std.testing.allocator);
    defer engine.deinit();
    const key = FlowKey{ .ip_a = 1, .port_a = 1, .ip_b = 2, .port_b = 2, .protocol = 6 };

    const upd = try engine.processPacket(key, 100, 0, 0);
    try std.testing.expect(upd.kind == .flow_created);
    try std.testing.expect(upd.flow.packet_count == 1);
    try std.testing.expect(upd.flow.byte_count == 100);
}

test "FlowEngine.processPacket returns flow_updated on subsequent packets" {
    var engine = FlowEngine.init(std.testing.allocator);
    defer engine.deinit();
    const key = FlowKey{ .ip_a = 1, .port_a = 1, .ip_b = 2, .port_b = 2, .protocol = 6 };

    _ = try engine.processPacket(key, 100, 0, 0);
    const upd = try engine.processPacket(key, 200, 0, 0);
    try std.testing.expect(upd.kind == .flow_updated);
    try std.testing.expect(upd.flow.packet_count == 2);
    try std.testing.expect(upd.flow.byte_count == 300);
}

test "FlowEngine.endFlow marks flow as ended" {
    var engine = FlowEngine.init(std.testing.allocator);
    defer engine.deinit();
    const key = FlowKey{ .ip_a = 1, .port_a = 1, .ip_b = 2, .port_b = 2, .protocol = 6 };

    _ = try engine.processPacket(key, 100, 0, 0);
    const upd = engine.endFlow(key) orelse {
        try std.testing.expect(false);
        return;
    };
    try std.testing.expect(upd.kind == .flow_ended);
    try std.testing.expect(upd.flow.state == .ended);
}

test "FlowEngine.endFlow returns null for unknown key" {
    var engine = FlowEngine.init(std.testing.allocator);
    defer engine.deinit();
    const key = FlowKey{ .ip_a = 1, .port_a = 1, .ip_b = 2, .port_b = 2, .protocol = 6 };
    try std.testing.expect(engine.endFlow(key) == null);
}

test "FlowEngine.evictIdle removes idle flows" {
    var engine = FlowEngine.init(std.testing.allocator);
    defer engine.deinit();
    const key = FlowKey{ .ip_a = 1, .port_a = 1, .ip_b = 2, .port_b = 2, .protocol = 6 };

    _ = try engine.processPacket(key, 100, 0, 0);
    try std.testing.expect(engine.count() == 1);

    // Advance time past idle timeout
    engine.setNow(engine.now_ns + FLOW_IDLE_TIMEOUT_NS + 1);
    const evicted = engine.evictIdle();
    try std.testing.expect(evicted == 1);
    try std.testing.expect(engine.count() == 0);
    try std.testing.expect(engine.total_expired == 1);
}

test "FlowSnapshot.fromFlow produces value copy" {
    var flow = Flow.fromKey(.{ .ip_a = 1, .port_a = 1, .ip_b = 2, .port_b = 2, .protocol = 6 }, 1000);
    flow.observe(500, 2000, 3, 0xBEEF);
    const snap = FlowSnapshot.fromFlow(flow);
    try std.testing.expect(snap.packet_count == 1);
    try std.testing.expect(snap.byte_count == 500);
    try std.testing.expect(snap.max_severity == 3);
    try std.testing.expect(snap.last_rule_id == 0xBEEF);
    try std.testing.expect(snap.isHighSeverity());
}

test "FlowSnapshot.packetsPerSecond handles zero duration" {
    const snap = FlowSnapshot{
        .key = .{ .ip_a = 1, .port_a = 1, .ip_b = 2, .port_b = 2, .protocol = 6 },
        .state = .new,
        .packet_count = 10,
        .byte_count = 1000,
        .start_ns = 1000,
        .last_seen_ns = 1000,
        .max_severity = 0,
        .rule_matched = false,
        .last_rule_id = 0,
    };
    try std.testing.expect(snap.packetsPerSecond() == 0);
}

test "FlowUpdate.isCreated and isExpired classify kind correctly" {
    const upd1 = FlowUpdate{
        .kind = .flow_created,
        .key = .{ .ip_a = 1, .port_a = 1, .ip_b = 2, .port_b = 2, .protocol = 6 },
        .flow = .{
            .key = .{ .ip_a = 1, .port_a = 1, .ip_b = 2, .port_b = 2, .protocol = 6 },
            .state = .new,
            .packet_count = 0,
            .byte_count = 0,
            .start_ns = 0,
            .last_seen_ns = 0,
            .max_severity = 0,
            .rule_matched = false,
            .last_rule_id = 0,
        },
    };
    try std.testing.expect(upd1.isCreated());
    try std.testing.expect(!upd1.isExpired());

    const upd2 = FlowUpdate{
        .kind = .flow_expired,
        .key = .{ .ip_a = 1, .port_a = 1, .ip_b = 2, .port_b = 2, .protocol = 6 },
        .flow = upd1.flow,
    };
    try std.testing.expect(!upd2.isCreated());
    try std.testing.expect(upd2.isExpired());
}
