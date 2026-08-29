//! flow_engine.zig - AEGIS Flow Engine (Rewrite Phase 6)
//!
//! Connection tracking: groups CanonicalEvents into Flows keyed by 5-tuple.
//! This is the FIRST stage of the detection pipeline (after nose/fabric).
//!
//! Architecture:
//!   Event Fabric -> Dispatcher -> Flow Engine -> (future) Detection
//!
//! Flow Key (5-tuple, canonical direction):
//!   - For TCP/UDP: {min(src,dst)_ip, min(src,dst)_port, max_ip, max_port, protocol}
//!     Canonicalized so both directions of a bidirectional flow map to same key.
//!   - For non-IP events (is_pipe=1, host events): use session_id as fallback key.
//!
//! Flow State Machine:
//!   new -> established -> closing -> closed
//!   (Idle timeout moves any state -> closed after FLOW_IDLE_TIMEOUT_NS)
//!
//! Output (Evidence Producer pattern, NOT event mutation):
//!   - FlowUpdate struct returned by value from processEvent()
//!   - Dispatcher decides what to do with it (log, pass to detection, etc.)
//!   - Original event is NOT modified.

const std = @import("std");
const canonical = @import("canonical_event.zig");

// ============================================================
// Constants
// ============================================================

/// Default idle timeout: 60 seconds of no packets -> flow is evicted.
pub const FLOW_IDLE_TIMEOUT_NS: i128 = 60 * std.time.ns_per_s;

/// Default max flow table size. Beyond this, oldest flows are evicted.
pub const FLOW_TABLE_MAX: usize = 65536;

/// Eviction batch size when table is full.
pub const EVICT_BATCH_SIZE: usize = 64;

// ============================================================
// Flow Key (canonical 5-tuple)
// ============================================================

/// Canonical 5-tuple flow key. Both directions of a bidirectional flow
/// map to the same key via min/max canonicalization.
pub const FlowKey = struct {
    /// Lower of {src_ip, dst_ip} - ensures direction-independent key
    ip_a: u32,
    /// Lower of {src_port, dst_port} (when ip_a == ip_b, ports break the tie)
    port_a: u16,
    /// Higher of {src_ip, dst_ip}
    ip_b: u32,
    /// Higher of {src_port, dst_port}
    port_b: u16,
    /// IP protocol (TCP=6, UDP=17, etc.)
    protocol: u8,

    /// Compute the canonical key from a CanonicalEvent.
    /// For non-IP events (is_pipe=1), uses session_id packed into ip_a/port_a.
    pub fn fromEvent(event: canonical.CanonicalEvent) FlowKey {
        // Non-IP / host events: use session_id as the discriminator.
        if (event.is_pipe != 0 or event.source_ip == 0) {
            return .{
                .ip_a = @truncate(event.session_id),
                .port_a = @truncate(event.session_id >> 32),
                .ip_b = 0,
                .port_b = 0,
                .protocol = event.protocol,
            };
        }

        // IP events: canonicalize by (ip, port) tuple ordering.
        if (event.source_ip < event.dest_ip or
            (event.source_ip == event.dest_ip and event.source_port <= event.dest_port))
        {
            return .{
                .ip_a = event.source_ip,
                .port_a = event.source_port,
                .ip_b = event.dest_ip,
                .port_b = event.dest_port,
                .protocol = event.protocol,
            };
        } else {
            return .{
                .ip_a = event.dest_ip,
                .port_a = event.dest_port,
                .ip_b = event.source_ip,
                .port_b = event.source_port,
                .protocol = event.protocol,
            };
        }
    }

    /// Stable hash for hashmap use.
    pub fn hash(self: FlowKey) u64 {
        // FNV-1a inspired mix; good enough for in-memory table.
        var h: u64 = 0xcbf29ce484222325;
        const fields = [_]u64{
            self.ip_a,
            self.port_a,
            self.ip_b,
            self.port_b,
            self.protocol,
        };
        for (fields) |f| {
            h ^= f;
            h *%= 0x100000001b3;
        }
        return h;
    }

    pub fn eql(a: FlowKey, b: FlowKey) bool {
        return a.ip_a == b.ip_a and a.port_a == b.port_a and
            a.ip_b == b.ip_b and a.port_b == b.port_b and a.protocol == b.protocol;
    }
};

// ============================================================
// Flow State
// ============================================================

pub const FlowState = enum(u8) {
    /// Just saw first packet, no SYN seen yet (or non-TCP).
    new = 0,
    /// TCP SYN+SYN-ACK seen, or first packet for UDP/ICMP.
    established = 1,
    /// TCP FIN seen, waiting for final ACK.
    closing = 2,
    /// Fully closed (FIN+ACK both directions) or evicted by timeout.
    closed = 3,

    pub fn toString(self: FlowState) []const u8 {
        return switch (self) {
            .new => "NEW",
            .established => "ESTABLISHED",
            .closing => "CLOSING",
            .closed => "CLOSED",
        };
    }
};

/// Tracked flow record.
pub const Flow = struct {
    key: FlowKey,
    state: FlowState,
    /// First packet timestamp (monotonic ns).
    start_ns: i128,
    /// Last packet timestamp (monotonic ns).
    last_seen_ns: i128,
    /// Total packets observed (both directions).
    packet_count: u64,
    /// Total bytes observed (sum of payload_length).
    byte_count: u64,
    /// Distinct session_ids seen on this flow (for correlation).
    session_id_set: u8,
    /// Last session_id seen (for correlation continuity).
    last_session_id: u64,
    /// Direction of the first packet seen (0=inbound, 1=outbound).
    initial_direction: u8,
    /// Highest severity event seen on this flow (0=Low..3=Critical).
    max_severity: u8,
    /// True if any rule has matched on this flow.
    rule_matched: bool,
    /// Last rule_id that matched (0 if none).
    last_rule_id: u32,
};

// ============================================================
// Flow Update (evidence producer output)
// ============================================================

/// What kind of flow update this is.
pub const FlowUpdateKind = enum(u8) {
    /// First packet seen on a new flow.
    flow_created = 0,
    /// Subsequent packet on existing flow.
    flow_updated = 1,
    /// Flow transitioned to a new state (e.g., new -> established).
    flow_state_changed = 2,
    /// Flow was evicted due to idle timeout.
    flow_expired = 3,
    /// Flow completed (FIN+ACK both directions, or session_end event).
    flow_ended = 4,
};

/// Output struct returned by processEvent(). Passed by value (cheap: ~96 bytes).
/// Dispatcher decides what to do with it.
pub const FlowUpdate = struct {
    kind: FlowUpdateKind,
    key: FlowKey,
    flow: Flow,
    /// The event_id that triggered this update (for correlation).
    triggering_event_id: u64,
};

// ============================================================
// Flow Engine
// ============================================================

const FlowMap = std.HashMap(FlowKey, Flow, FlowKeyContext, std.hash_map.default_max_load_percentage);

const FlowKeyContext = struct {
    pub fn hash(_: @This(), k: FlowKey) u64 {
        return k.hash();
    }
    pub fn eql(_: @This(), a: FlowKey, b: FlowKey) bool {
        return FlowKey.eql(a, b);
    }
};

pub const FlowEngine = struct {
    allocator: std.mem.Allocator,
    map: FlowMap,
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
            .map = FlowMap.init(allocator),
            .idle_timeout_ns = FLOW_IDLE_TIMEOUT_NS,
            .max_flows = FLOW_TABLE_MAX,
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
        if (self.map.getPtr(key)) |flow| {
            // Update existing flow
            const old_state = flow.state;
            updateFlowState(flow, event, now_ns);

            self.total_packets += 1;
            self.total_bytes += event.payload_length;

            return .{
                .kind = if (flow.state != old_state) .flow_state_changed else .flow_updated,
                .key = key,
                .flow = flow.*,
                .triggering_event_id = event.event_id,
            };
        }

        // New flow — first check if table is full, evict if needed.
        // Scale eviction count with table size: 1% of max, min 1, max EVICT_BATCH_SIZE.
        // (Old bug: always passed EVICT_BATCH_SIZE=64 which evicted ALL flows
        // when max_flows was small, e.g. in tests with max_flows=4.)
        if (self.map.count() >= self.max_flows) {
            const evict_count = @min(EVICT_BATCH_SIZE, @max(@as(usize, 1), self.max_flows / 100));
            self.evictOldest(evict_count);
        }

        // Create new flow
        const flow = Flow{
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

        self.map.put(key, flow) catch {
            // Allocation failure — degrade gracefully by returning flow_updated
            // without storing. (Production: log + metric.)
            return .{
                .kind = .flow_updated,
                .key = key,
                .flow = flow,
                .triggering_event_id = event.event_id,
            };
        };

        self.total_created += 1;
        self.total_packets += 1;
        self.total_bytes += event.payload_length;

        return .{
            .kind = .flow_created,
            .key = key,
            .flow = flow,
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
    /// Used when table is full and a new flow must be inserted.
    fn evictOldest(self: *FlowEngine, n: usize) void {
        if (self.map.count() == 0) return;

        // Collect candidates with their last_seen_ns
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

        // Sort by last_seen_ns ascending (oldest first) using std.mem.sort
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

/// Determine initial flow state from the first packet.
fn initStateFromEvent(event: canonical.CanonicalEvent) FlowState {
    // TCP session_start event -> established immediately (or new if just SYN).
    // For UDP/ICMP and other protocols, treat as established on first packet.
    if (event.event_type == .session_start) return .established;
    if (event.event_type == .session_end) return .closed;
    if (event.protocol == 6) {
        // TCP without session_start — assume mid-stream capture, mark new.
        return .new;
    }
    // UDP/ICMP/other — established on first packet.
    return .established;
}

/// Update flow state machine based on new event.
fn updateFlowState(flow: *Flow, event: canonical.CanonicalEvent, now_ns: i128) void {
    flow.last_seen_ns = now_ns;
    flow.packet_count += 1;
    flow.byte_count += event.payload_length;

    // Track distinct session_ids (rough hash-set approximation: count bit changes)
    if (event.session_id != flow.last_session_id) {
        flow.session_id_set +%= 1;
        flow.last_session_id = event.session_id;
    }

    // Track max severity
    if (event.severity > flow.max_severity) {
        flow.max_severity = event.severity;
    }

    // Track rule matches
    if (event.rule_id != 0) {
        flow.rule_matched = true;
        flow.last_rule_id = event.rule_id;
    }

    // State transitions
    switch (flow.state) {
        .new => {
            if (event.event_type == .session_start or event.protocol != 6) {
                flow.state = .established;
            }
        },
        .established => {
            if (event.event_type == .session_end) {
                flow.state = .closing;
            }
        },
        .closing => {
            if (event.event_type == .session_end) {
                flow.state = .closed;
            }
        },
        .closed => {
            // Closed flows stay closed (until evicted by sweep).
        },
    }
}

// ============================================================
// Tests
// ============================================================

test "FlowKey.fromEvent canonicalizes bidirectional flows" {
    var e1 = canonical.create(.wfp_sensor);
    e1.source_ip = 0x0A000001; // 10.0.0.1
    e1.source_port = 12345;
    e1.dest_ip = 0x0A000002; // 10.0.0.2
    e1.dest_port = 80;
    e1.protocol = 6;

    var e2 = canonical.create(.wfp_sensor);
    e2.source_ip = 0x0A000002; // 10.0.0.2 (reversed)
    e2.source_port = 80;
    e2.dest_ip = 0x0A000001;
    e2.dest_port = 12345;
    e2.protocol = 6;

    const k1 = FlowKey.fromEvent(e1);
    const k2 = FlowKey.fromEvent(e2);

    try std.testing.expect(FlowKey.eql(k1, k2));
    try std.testing.expect(k1.ip_a == 0x0A000001);
    try std.testing.expect(k1.port_a == 12345); // port paired with ip_a (source_port when source_ip is lower)
    try std.testing.expect(k1.ip_b == 0x0A000002);
    try std.testing.expect(k1.port_b == 80); // port paired with ip_b
}

test "FlowKey.fromEvent handles same-IP flows (port breaks tie)" {
    var e1 = canonical.create(.wfp_sensor);
    e1.source_ip = 0x0A000001;
    e1.source_port = 5000;
    e1.dest_ip = 0x0A000001; // same IP
    e1.dest_port = 80;
    e1.protocol = 6;

    var e2 = canonical.create(.wfp_sensor);
    e2.source_ip = 0x0A000001;
    e2.source_port = 80; // reversed
    e2.dest_ip = 0x0A000001;
    e2.dest_port = 5000;
    e2.protocol = 6;

    const k1 = FlowKey.fromEvent(e1);
    const k2 = FlowKey.fromEvent(e2);
    try std.testing.expect(FlowKey.eql(k1, k2));
    try std.testing.expect(k1.port_a == 80); // lower port first
}

test "FlowKey.fromEvent uses session_id for non-IP events" {
    var e = canonical.create(.pipe_sensor);
    e.is_pipe = 1;
    e.source_ip = 0;
    e.session_id = 0xDEADBEEFCAFE;
    e.protocol = 0;

    const k = FlowKey.fromEvent(e);
    // session_id = 0xDEADBEEFCAFE as u64 = 0x0000DEADBEEFCAFE
    // Lower 32 bits (@truncate to u32) = 0xBEEFCAFE
    // Upper 32 bits (session_id >> 32) = 0x0000DEAD, @truncate to u16 = 0xDEAD
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

    // Second packet: reverse direction (should map to same flow)
    event.source_ip = 0x0A000002;
    event.source_port = 80;
    event.dest_ip = 0x0A000001;
    event.dest_port = 12345;
    event.payload_length = 200;
    event.session_id = 2;

    const update = engine.processEvent(event);

    try std.testing.expect(update.kind == .flow_updated);
    try std.testing.expect(engine.count() == 1); // still one flow
    try std.testing.expect(update.flow.packet_count == 2);
    try std.testing.expect(update.flow.byte_count == 300);
    try std.testing.expect(update.flow.last_session_id == 2);
    try std.testing.expect(update.flow.session_id_set == 2); // 2 distinct sessions
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

    // First packet: new flow, TCP, no session_start -> state = .new
    const upd1 = engine.processEvent(event);
    try std.testing.expect(upd1.kind == .flow_created);
    try std.testing.expect(upd1.flow.state == .new);

    // Second packet: session_start -> transitions to .established
    event.event_type = .session_start;
    const upd2 = engine.processEvent(event);
    try std.testing.expect(upd2.kind == .flow_state_changed);
    try std.testing.expect(upd2.flow.state == .established);

    // Third packet: no transition (stays established)
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

    _ = engine.processEvent(event); // -> established

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
    event.dest_ip = 0xE00000FB; // 224.0.0.251 (mDNS)
    event.dest_port = 5353;
    event.protocol = 17; // UDP

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
    engine.configure(100 * std.time.ns_per_ms, 1000); // 100ms timeout

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

    // Sweep at t=50ms -> flow not yet expired
    var n = engine.sweepExpired(50 * std.time.ns_per_ms);
    try std.testing.expect(n == 0);
    try std.testing.expect(engine.count() == 1);

    // Sweep at t=200ms -> flow expired (idle > 100ms)
    n = engine.sweepExpired(200 * std.time.ns_per_ms);
    try std.testing.expect(n == 1);
    try std.testing.expect(engine.count() == 0);
    try std.testing.expect(engine.total_expired == 1);
}

test "FlowEngine: evicts oldest when table is full" {
    var engine = FlowEngine.init(std.testing.allocator);
    defer engine.deinit();
    engine.configure(std.time.ns_per_s, 4); // very small table

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

    // Insert 5th flow — should evict the oldest (i=0)
    var event5 = canonical.create(.wfp_sensor);
    event5.source_ip = 0x0A00000A;
    event5.source_port = 9999;
    event5.dest_ip = 0x0A0000FF;
    event5.dest_port = 80;
    event5.protocol = 6;
    event5.monotonic_ns = 100;

    _ = engine.processEvent(event5);
    try std.testing.expect(engine.count() == 4); // still 4 (evicted 1, added 1)
    try std.testing.expect(engine.total_expired == 1);

    // Verify the oldest flow (i=0) is gone.
    // i=0: source_ip=0x0A000000, source_port=1000, dest_ip=0x0A0000FF, dest_port=80
    // source_ip < dest_ip, so ip_a=source_ip, port_a=source_port=1000, port_b=dest_port=80
    const old_key = FlowKey{
        .ip_a = 0x0A000000,
        .port_a = 1000, // source_port (paired with ip_a which is the lower IP)
        .ip_b = 0x0A0000FF,
        .port_b = 80, // dest_port (paired with ip_b)
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

    // Create 3 distinct flows, 5 packets each
    var i: u32 = 0;
    while (i < 3) : (i += 1) {
        var j: u32 = 0;
        while (j < 5) : (j += 1) {
            var event = canonical.create(.wfp_sensor);
            event.source_ip = 0x0A000000 + i;
            event.source_port = @intCast(1000 + i); // varies per flow i, not per packet j
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
