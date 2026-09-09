// I15 - Atomic Threat Tracker & Incident Model
// AEGIS NIDS v5.0+ â€” Per-flow / per-host threat aggregation with incident model
//
// Atomic = lock-free updates via atomic primitives for hot fields (score, count).
// Incident = the final aggregated record kept until eviction or quarantine.
//
// One ThreatTracker holds:
//   - FlowThreat keyed by flow_id
//   - HostThreat keyed by src_ip (or [16]u8 for IPv6)
//   - Open incidents list

const std = @import("std");
const event = @import("../contract/event.zig");
const manifest = @import("../contract/runtime_manifest.zig");

pub const MAX_INCIDENTS: usize = 4096;
pub const INCIDENT_TTL_NS: i128 = 3600 * std.time.ns_per_s; // 1 hour

// ============================================================================
// Evidence â€” single piece of evidence attached to an incident
// ============================================================================
pub const Evidence = struct {
    event_id: u64,
    timestamp_ns: i128,
    rule_id: u32,
    severity: event.EventSeverity,
    kind: event.EventKind,
    weight: u16,
};

// ============================================================================
// FlowThreat â€” per-flow threat metadata (lock-free hot fields)
// ============================================================================
pub const FlowThreat = struct {
    flow_id: u64,
    src_ip: [16]u8 = [_]u8{0} ** 16,
    dst_ip: [16]u8 = [_]u8{0} ** 16,
    score: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    evidence_count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    incident_id: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    first_seen_ns: i128,
    last_seen_ns: std.atomic.Value(i64) = std.atomic.Value(i64).init(0),
    blocked: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    // Small ring buffer of evidence (size 4)
    evidence_ring: [4]Evidence = [_]Evidence{.{ .event_id = 0, .timestamp_ns = 0, .rule_id = 0, .severity = .info, .kind = .packet_captured, .weight = 0 }} ** 4,
    evidence_head: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    pub fn addEvidence(self: *FlowThreat, ev: *const event.IpcEvent, weight: u16) void {
        const h = self.evidence_head.fetchAdd(1, .monotonic);
        const slot = h % self.evidence_ring.len;
        self.evidence_ring[slot] = .{
            .event_id = ev.event_id,
            .timestamp_ns = ev.timestamp_ns,
            .rule_id = ev.rule_id,
            .severity = ev.severity,
            .kind = ev.kind,
            .weight = weight,
        };
        _ = self.score.fetchAdd(weight, .monotonic);
        _ = self.evidence_count.fetchAdd(1, .monotonic);
        self.last_seen_ns.store(@intCast(ev.timestamp_ns), .release);
    }

    pub fn currentScore(self: *const FlowThreat) u32 {
        return self.score.load(.monotonic);
    }
};

// ============================================================================
// Incident â€” multi-evidence aggregate
// ============================================================================
pub const Incident = struct {
    id: u64,
    flow_id: u64,
    src_ip: [16]u8,
    severity: event.EventSeverity,
    score: u32,
    first_seen_ns: i128,
    last_seen_ns: i128,
    evidence_count: u32,
    classification: [32]u8 = [_]u8{0} ** 32,
    state: IncidentState = .open,
};

pub const IncidentState = enum(u8) {
    open = 0,
    escalated = 1,
    blocked = 2,
    resolved = 3,
    false_positive = 4,
};

// ============================================================================
// ThreatTracker â€” top-level state
// ============================================================================
pub const ThreatTracker = struct {
    flow_threats: std.AutoHashMap(u64, FlowThreat),
    incidents: [MAX_INCIDENTS]Incident = [_]Incident{.{
        .id = 0,
        .flow_id = 0,
        .src_ip = [_]u8{0} ** 16,
        .severity = .info,
        .score = 0,
        .first_seen_ns = 0,
        .last_seen_ns = 0,
        .evidence_count = 0,
    }} ** MAX_INCIDENTS,
    incident_count: u32 = 0,
    next_incident_id: u64 = 1,
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator) ThreatTracker {
        return .{
            .flow_threats = std.AutoHashMap(u64, FlowThreat).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ThreatTracker) void {
        self.flow_threats.deinit();
    }

    pub fn observeFlowThreat(self: *ThreatTracker, ev: *const event.IpcEvent, weight: u16) !?*Incident {
        const gop = try self.flow_threats.getOrPut(ev.flow_id);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{
                .flow_id = ev.flow_id,
                .first_seen_ns = ev.timestamp_ns,
            };
            @memcpy(gop.value_ptr.src_ip[0..4], std.mem.asBytes(&ev.src_ip));
            @memcpy(gop.value_ptr.dst_ip[0..4], std.mem.asBytes(&ev.dst_ip));
        }
        gop.value_ptr.addEvidence(ev, weight);
        // If score crosses threshold, escalate to incident
        const score = gop.value_ptr.currentScore();
        if (score >= 100 and gop.value_ptr.incident_id.load(.monotonic) == 0) {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.incident_count >= MAX_INCIDENTS) return null;
            const id = self.next_incident_id;
            self.next_incident_id += 1;
            const idx = self.incident_count;
            self.incident_count += 1;
            self.incidents[idx] = .{
                .id = id,
                .flow_id = ev.flow_id,
                .src_ip = gop.value_ptr.src_ip,
                .severity = if (score >= 500) .emergency else if (score >= 250) .alert else .warning,
                .score = score,
                .first_seen_ns = gop.value_ptr.first_seen_ns,
                .last_seen_ns = ev.timestamp_ns,
                .evidence_count = gop.value_ptr.evidence_count.load(.monotonic),
            };
            gop.value_ptr.incident_id.store(id, .release);
            return &self.incidents[idx];
        }
        return null;
    }

    pub fn openIncidents(self: *ThreatTracker) []const Incident {
        return self.incidents[0..self.incident_count];
    }
};

// ============================================================================
// Tests
// ============================================================================
test "FlowThreat add evidence" {
    var ft = FlowThreat{ .flow_id = 42, .first_seen_ns = 1000 };
    var ev = event.IpcEvent.init(.signature_match);
    ev.timestamp_ns = 2000;
    ev.event_id = 1;
    ev.rule_id = 100;
    ft.addEvidence(&ev, 30);
    try std.testing.expectEqual(@as(u32, 30), ft.currentScore());
    try std.testing.expectEqual(@as(u32, 1), ft.evidence_count.load(.monotonic));
    // Add 5 more â€” ring should wrap at 4
    var i: u32 = 0;
    while (i < 5) : (i += 1) {
        var e = event.IpcEvent.init(.signature_match);
        e.event_id = i + 2;
        e.timestamp_ns = 3000 + i;
        ft.addEvidence(&e, 20);
    }
    try std.testing.expectEqual(@as(u32, 130), ft.currentScore());
    try std.testing.expectEqual(@as(u32, 6), ft.evidence_count.load(.monotonic));
}

test "ThreatTracker escalates to incident" {
    var tt = ThreatTracker.init(std.testing.allocator);
    defer tt.deinit();
    var ev = event.IpcEvent.init(.signature_match);
    ev.flow_id = 1;
    ev.timestamp_ns = 1000;
    ev.event_id = 1;
    ev.src_ip = 0x0A000001;
    ev.rule_id = 1;
    // Add weight 100 in one shot
    const inc = try tt.observeFlowThreat(&ev, 100);
    try std.testing.expect(inc != null);
    try std.testing.expectEqual(@as(u32, 1), tt.incident_count);
}

test "ThreatTracker no incident below threshold" {
    var tt = ThreatTracker.init(std.testing.allocator);
    defer tt.deinit();
    var ev = event.IpcEvent.init(.signature_match);
    ev.flow_id = 2;
    ev.timestamp_ns = 1000;
    ev.event_id = 2;
    ev.src_ip = 0x0A000002;
    ev.rule_id = 2;
    const inc = try tt.observeFlowThreat(&ev, 30);
    try std.testing.expect(inc == null);
    try std.testing.expectEqual(@as(u32, 0), tt.incident_count);
}

test "ThreatTracker multiple flows tracked independently" {
    var tt = ThreatTracker.init(std.testing.allocator);
    defer tt.deinit();
    // Flow A: high severity
    var ev_a = event.IpcEvent.init(.signature_match);
    ev_a.flow_id = 10;
    ev_a.timestamp_ns = 1000;
    ev_a.event_id = 1;
    ev_a.src_ip = 0x0A000001;
    ev_a.rule_id = 1;
    _ = try tt.observeFlowThreat(&ev_a, 100);
    // Flow B: low severity
    var ev_b = event.IpcEvent.init(.signature_match);
    ev_b.flow_id = 20;
    ev_b.timestamp_ns = 2000;
    ev_b.event_id = 2;
    ev_b.src_ip = 0x0A000002;
    ev_b.rule_id = 2;
    const inc_b = try tt.observeFlowThreat(&ev_b, 20);
    try std.testing.expect(inc_b == null);
    // Flow A should still have incident
    try std.testing.expectEqual(@as(u32, 1), tt.incident_count);
}

test "ThreatTracker escalate from low to critical" {
    var tt = ThreatTracker.init(std.testing.allocator);
    defer tt.deinit();
    var ev = event.IpcEvent.init(.signature_match);
    ev.flow_id = 30;
    ev.src_ip = 0x0A000003;
    ev.rule_id = 3;
    // First observation: low severity
    ev.timestamp_ns = 1000;
    ev.event_id = 1;
    const r1 = try tt.observeFlowThreat(&ev, 50);
    try std.testing.expect(r1 == null);
    // Second observation: crosses threshold
    ev.timestamp_ns = 2000;
    ev.event_id = 2;
    const r2 = try tt.observeFlowThreat(&ev, 60);
    try std.testing.expect(r2 != null);
    try std.testing.expectEqual(@as(u32, 1), tt.incident_count);
}

test "ThreatTracker incident count increments" {
    var tt = ThreatTracker.init(std.testing.allocator);
    defer tt.deinit();
    try std.testing.expectEqual(@as(u32, 0), tt.incident_count);
    var ev = event.IpcEvent.init(.signature_match);
    ev.flow_id = 40;
    ev.src_ip = 0x0A000004;
    ev.rule_id = 4;
    ev.timestamp_ns = 1000;
    ev.event_id = 1;
    _ = try tt.observeFlowThreat(&ev, 100);
    try std.testing.expectEqual(@as(u32, 1), tt.incident_count);
    var ev2 = event.IpcEvent.init(.signature_match);
    ev2.flow_id = 50;
    ev2.src_ip = 0x0A000005;
    ev2.rule_id = 5;
    ev2.timestamp_ns = 2000;
    ev2.event_id = 2;
    _ = try tt.observeFlowThreat(&ev2, 100);
    try std.testing.expectEqual(@as(u32, 2), tt.incident_count);
}
