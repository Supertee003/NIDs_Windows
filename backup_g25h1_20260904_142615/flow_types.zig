//! flow_types.zig - AEGIS Flow Type Definitions
//!
//! Extracted from flow_engine.zig (G37 refactor) to allow modules to use
//! flow-related types without importing the full FlowEngine implementation.
//!
//! Contains: FlowKey, FlowState, Flow, FlowUpdateKind, FlowUpdate, constants.

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
// Flow Map (hashmap type alias, used by FlowEngine)
// ============================================================

pub const FlowMap = std.HashMap(FlowKey, Flow, FlowKeyContext, std.hash_map.default_max_load_percentage);

pub const FlowKeyContext = struct {
    pub fn hash(_: @This(), k: FlowKey) u64 {
        return k.hash();
    }
    pub fn eql(_: @This(), a: FlowKey, b: FlowKey) bool {
        return FlowKey.eql(a, b);
    }
};
