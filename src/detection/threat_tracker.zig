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
const diag = @import("../core/diagnostics.zig");

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
        // GAP-016: hostile timestamps must not int3 the pipeline. Nose
        // monotonic_ns is copied verbatim and canonical validation never
        // bounds it, so clamp to i64 range (saturating, fail-open) instead
        // of trapping on values past 292 years in nanoseconds.
        self.last_seen_ns.store(@intCast(@min(ev.timestamp_ns, @as(u64, @intCast(std.math.maxInt(i64))))), .release);
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
    /// Incidents refused because the table was full (INCIDENT-CAP-063).
    /// Counted under the incident mutex; surfaced once via diag.warn so a
    /// long-running daemon that stops creating incidents is diagnosable
    /// instead of silently blind. No eviction here — expiry/compaction
    /// policy is a follow-up design slice, not an ad-hoc drop.
    dropped_at_cap: u64 = 0,
    cap_warned: bool = false,

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
            if (self.incident_count >= MAX_INCIDENTS) {
                // INCIDENT-CAP-063: full table refuses silently no more.
                // Count every refusal; warn once so a sustained storm does
                // not flood the log with its own symptom.
                self.dropped_at_cap += 1;
                if (!self.cap_warned) {
                    self.cap_warned = true;
                    diag.warn("threat tracker incident table full ({d}); new incidents refused until restart", .{MAX_INCIDENTS});
                }
                return null;
            }
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

    /// Evict idle state past INCIDENT_TTL_NS (A1: eviction-policy verdict).
    ///
    /// Verdict (documented, not guessed):
    ///  - Only `.open` incidents expire. Terminal states (escalated,
    ///    blocked, resolved, false_positive) are operator-owned and persist.
    ///    Today nothing transitions states, so every incident is .open —
    ///    the rule still matters for the day something does.
    ///  - Expired slots are swap-removed (order is not a contract;
    ///    event_processor copies incidents by value, FlowThreat keys by
    ///    id, so no dangling references exist).
    ///  - Idle FlowThreat entries (last_seen past TTL) are dropped with
    ///    their incidents: an idle flow's scoreboard disappears entirely,
    ///    which also bounds the map. A re-offending flow starts fresh and
    ///    can escalate again.
    ///  - `now_ns` MUST be event-clock (ev.timestamp_ns), the same clock
    ///    as first_seen/last_seen — never wall-clock. Out-of-order events
    ///    (now < last_seen) never expire: fail direction is keep, not drop.
    /// Returns the number of incidents expired (the caller owns the open
    /// counter decrement — single pipeline thread, no race).
    pub fn pruneExpired(self: *ThreatTracker, now_ns: u64) u32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        const ttl: u64 = @intCast(INCIDENT_TTL_NS);
        var expired: u32 = 0;

        // 1. Drop idle flow state first so re-offense starts fresh.
        // Collect-then-remove: mutating the map under its own iterator
        // can skip entries; a skipped idle flow is merely pruned on a
        // later pass (safe direction), but collect-then-remove is exact.
        var idle_flows = std.ArrayList(u64).init(self.allocator);
        defer idle_flows.deinit();
        var flow_it = self.flow_threats.iterator();
        while (flow_it.next()) |entry| {
            const last: u64 = @intCast(entry.value_ptr.last_seen_ns.load(.monotonic));
            if (now_ns > last and now_ns - last > ttl) {
                idle_flows.append(entry.key_ptr.*) catch continue;
            }
        }
        for (idle_flows.items) |flow_id| {
            if (self.flow_threats.getPtr(flow_id)) |ft| {
                ft.incident_id.store(0, .release);
            }
            _ = self.flow_threats.remove(flow_id);
        }

        // 2. Resolve + swap-remove expired .open incidents.
        var i: usize = 0;
        while (i < self.incident_count) {
            const inc = &self.incidents[i];
            const is_open = inc.state == .open;
            const last: u64 = if (inc.last_seen_ns < 0) 0 else @intCast(inc.last_seen_ns);
            const idle = now_ns > last and now_ns - last > ttl;
            if (is_open and idle) {
                inc.state = .resolved;
                expired += 1;
                const last_idx = self.incident_count - 1;
                if (i != last_idx) {
                    self.incidents[i] = self.incidents[last_idx];
                }
                self.incident_count -= 1;
                // Do not advance: the swapped-in entry is unexamined.
            } else {
                i += 1;
            }
        }
        return expired;
    }
};

// ============================================================================
// EVT-210: control-plane incident snapshot
// ============================================================================

/// Flat, pointer-free incident row safe to hand to another thread. `Incident`
/// itself embeds no pointers, but a reader outside the mutex could still see a
/// slot mid-swap (pruneExpired moves the last entry over an expired one), so
/// the control plane only ever consumes these copies.
pub const SnapshotRow = struct {
    id: u64,
    flow_id: u64,
    /// BE network-order IPv4, the canonical rendering convention (EVT-201).
    src_ip: u32,
    /// EventSeverity ordinal (event.EventSeverity).
    severity: u8,
    /// IncidentState ordinal.
    state: u8,
    score: u32,
    evidence_count: u32,
};

/// How many rows the control plane copies per request. The true open count is
/// always reported alongside, so a full table still shows its size honestly.
pub const SNAPSHOT_CAP: usize = 64;

/// The daemon publishes its live tracker here before spawning any worker.
/// Null means "no tracker in this process" (unit tests, tooling): the reader
/// gets an empty, labeled snapshot rather than a crash or a stale pointer.
pub var g_live: ?*ThreatTracker = null;

/// EVT-210: thread-safe read of the open incidents for the control plane.
///
/// Copies up to `buf.len` incidents, HIGHEST score first (ties by id), into
/// pointer-free SnapshotRow values while holding the same mutex every mutation
/// of `incidents`/`incident_count` takes (observeFlowThreat creation +
/// pruneExpired). A handler thread can therefore never observe a torn row or a
/// half-swapped slot. `total_out` receives the true open count, which may
/// exceed the copied rows: the view is bounded, the total is not. Returns the
/// number of rows written. With no live tracker the snapshot is empty and
/// `total_out` is 0 -- labeled absence, never a stale read.
pub fn snapshotOpenIncidents(buf: []SnapshotRow, total_out: *u64) usize {
    const self = g_live orelse {
        total_out.* = 0;
        return 0;
    };
    self.mutex.lock();
    defer self.mutex.unlock();
    const n: usize = self.incident_count;
    total_out.* = n;
    const k = @min(buf.len, n);
    var out: usize = 0;
    var have_floor = false;
    var floor_score: u32 = 0;
    var floor_id: u64 = 0;
    while (out < k) {
        var best: ?usize = null;
        var i: usize = 0;
        while (i < n) : (i += 1) {
            const inc = &self.incidents[i];
            // Select strictly below the previous pick so a key can never be
            // emitted twice (ids are unique; score ties break by id).
            if (have_floor) {
                const below = inc.score < floor_score or
                    (inc.score == floor_score and inc.id < floor_id);
                if (!below) continue;
            }
            if (best == null) {
                best = i;
                continue;
            }
            const b = &self.incidents[best.?];
            if (inc.score > b.score or
                (inc.score == b.score and inc.id > b.id))
            {
                best = i;
            }
        }
        const sel = best orelse break;
        const inc = &self.incidents[sel];
        buf[out] = .{
            .id = inc.id,
            .flow_id = inc.flow_id,
            .src_ip = std.mem.readInt(u32, inc.src_ip[0..4], .little),
            .severity = @intFromEnum(inc.severity),
            .state = @intFromEnum(inc.state),
            .score = inc.score,
            .evidence_count = inc.evidence_count,
        };
        out += 1;
        have_floor = true;
        floor_score = inc.score;
        floor_id = inc.id;
    }
    return out;
}

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

test "FlowThreat clamps hostile timestamps instead of trapping (GAP-016)" {
    var ft = FlowThreat{ .flow_id = 43, .first_seen_ns = 1000 };
    var ev = event.IpcEvent.init(.signature_match);
    ev.timestamp_ns = std.math.maxInt(u64);
    ev.event_id = 1;
    ev.rule_id = 100;
    ft.addEvidence(&ev, 30);
    try std.testing.expectEqual(std.math.maxInt(i64), ft.last_seen_ns.load(.monotonic));
    // Sane values still land verbatim.
    ev.timestamp_ns = 2000;
    ft.addEvidence(&ev, 1);
    try std.testing.expectEqual(@as(i64, 2000), ft.last_seen_ns.load(.monotonic));
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

test "ThreatTracker full table refuses loudly, not silently" {
    // INCIDENT-CAP-063: at MAX_INCIDENTS the next incident used to vanish
    // into a bare null. Refusals are now counted (and warned once) so a
    // long-running daemon that stops creating incidents is diagnosable.
    var tt = ThreatTracker.init(std.testing.allocator);
    defer tt.deinit();
    var flow: u64 = 1;
    while (flow <= MAX_INCIDENTS + 1) : (flow += 1) {
        var ev = event.IpcEvent.init(.signature_match);
        ev.flow_id = flow;
        ev.timestamp_ns = 1000;
        ev.event_id = flow;
        _ = try tt.observeFlowThreat(&ev, 100);
    }
    try std.testing.expectEqual(@as(u32, MAX_INCIDENTS), tt.incident_count);
    try std.testing.expectEqual(@as(u64, 1), tt.dropped_at_cap);
}

test "A1: idle open incident expires past TTL and frees its slot" {
    var tt = ThreatTracker.init(std.testing.allocator);
    defer tt.deinit();
    var ev = event.IpcEvent.init(.signature_match);
    ev.flow_id = 1;
    ev.timestamp_ns = 1000;
    ev.event_id = 1;
    const inc = try tt.observeFlowThreat(&ev, 100);
    try std.testing.expect(inc != null);
    try std.testing.expectEqual(@as(u32, 1), tt.incident_count);
    // Before TTL: nothing expires.
    try std.testing.expectEqual(@as(u32, 0), tt.pruneExpired(1000 + @as(u64, @intCast(INCIDENT_TTL_NS))));
    try std.testing.expectEqual(@as(u32, 1), tt.incident_count);
    // Past TTL: resolved, compacted, slot reusable.
    try std.testing.expectEqual(@as(u32, 1), tt.pruneExpired(1000 + @as(u64, @intCast(INCIDENT_TTL_NS)) + 1));
    try std.testing.expectEqual(@as(u32, 0), tt.incident_count);
    try std.testing.expectEqual(@as(usize, 0), tt.openIncidents().len);
    // Re-offense starts fresh (flow state was dropped with the incident).
    var ev2 = event.IpcEvent.init(.signature_match);
    ev2.flow_id = 1;
    ev2.timestamp_ns = 2000 + @as(u64, @intCast(INCIDENT_TTL_NS)) + 1;
    ev2.event_id = 2;
    const inc2 = try tt.observeFlowThreat(&ev2, 100);
    try std.testing.expect(inc2 != null);
    try std.testing.expectEqual(@as(u32, 1), tt.incident_count);
}

test "A1: terminal states persist past TTL, out-of-order never expires" {
    var tt = ThreatTracker.init(std.testing.allocator);
    defer tt.deinit();
    var ev = event.IpcEvent.init(.signature_match);
    ev.flow_id = 1;
    ev.timestamp_ns = 1000;
    ev.event_id = 1;
    const inc = try tt.observeFlowThreat(&ev, 100);
    try std.testing.expect(inc != null);
    // Operator-owned terminal state survives TTL expiry passes.
    inc.?.state = .blocked;
    const far_future = 1000 + @as(u64, @intCast(INCIDENT_TTL_NS)) + 1;
    try std.testing.expectEqual(@as(u32, 0), tt.pruneExpired(far_future));
    try std.testing.expectEqual(@as(u32, 1), tt.incident_count);
    // Out-of-order event clock (now < last_seen) expires nothing —
    // fail direction is keep, never drop.
    inc.?.state = .open;
    try std.testing.expectEqual(@as(u32, 0), tt.pruneExpired(500));
    try std.testing.expectEqual(@as(u32, 1), tt.incident_count);
}

test "A1: expiry reclaims a full table (cap-063 follow-up)" {
    var tt = ThreatTracker.init(std.testing.allocator);
    defer tt.deinit();
    var flow: u64 = 1;
    while (flow <= MAX_INCIDENTS) : (flow += 1) {
        var ev = event.IpcEvent.init(.signature_match);
        ev.flow_id = flow;
        ev.timestamp_ns = 1000;
        ev.event_id = flow;
        _ = try tt.observeFlowThreat(&ev, 100);
    }
    try std.testing.expectEqual(@as(u32, MAX_INCIDENTS), tt.incident_count);
    // All idle past TTL: the whole table compacts, and the refused
    // newcomer from cap-063 now fits.
    const expired = tt.pruneExpired(1000 + @as(u64, @intCast(INCIDENT_TTL_NS)) + 1);
    try std.testing.expectEqual(@as(u32, MAX_INCIDENTS), expired);
    try std.testing.expectEqual(@as(u32, 0), tt.incident_count);
    var ev_new = event.IpcEvent.init(.signature_match);
    ev_new.flow_id = MAX_INCIDENTS + 1;
    ev_new.timestamp_ns = 2000 + @as(u64, @intCast(INCIDENT_TTL_NS)) + 1;
    ev_new.event_id = MAX_INCIDENTS + 1;
    const inc = try tt.observeFlowThreat(&ev_new, 100);
    try std.testing.expect(inc != null);
    try std.testing.expectEqual(@as(u32, 1), tt.incident_count);
}

test "EVT-210 snapshotOpenIncidents copies highest-score-first under the mutex" {
    var tt = ThreatTracker.init(std.testing.allocator);
    defer tt.deinit();
    g_live = &tt;
    defer g_live = null;

    var lo = event.IpcEvent.init(.signature_match);
    lo.flow_id = 1;
    lo.timestamp_ns = 1000;
    lo.event_id = 1;
    lo.src_ip = 0xC0A87E0A;
    lo.rule_id = 1;
    _ = try tt.observeFlowThreat(&lo, 100); // score 100 -> warning

    var hi = event.IpcEvent.init(.signature_match);
    hi.flow_id = 2;
    hi.timestamp_ns = 2000;
    hi.event_id = 2;
    hi.src_ip = 0xC0A87E14;
    hi.rule_id = 1;
    _ = try tt.observeFlowThreat(&hi, 300); // score 300 -> alert

    var buf: [SNAPSHOT_CAP]SnapshotRow = undefined;
    var total: u64 = 0;
    const n = snapshotOpenIncidents(&buf, &total);
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expectEqual(@as(u64, 2), total);
    try std.testing.expectEqual(@as(u32, 300), buf[0].score);
    try std.testing.expectEqual(@as(u32, 100), buf[1].score);
    // BE integer survives the asBytes/readInt round trip (EVT-201).
    try std.testing.expectEqual(@as(u32, 0xC0A87E14), buf[0].src_ip);
    try std.testing.expectEqual(@as(u8, @intFromEnum(event.EventSeverity.alert)), buf[0].severity);
    try std.testing.expectEqual(@as(u8, @intFromEnum(IncidentState.open)), buf[0].state);
}

test "EVT-210 snapshotOpenIncidents is empty and honest without a live tracker" {
    g_live = null;
    var buf: [SNAPSHOT_CAP]SnapshotRow = undefined;
    var total: u64 = 99;
    try std.testing.expectEqual(@as(usize, 0), snapshotOpenIncidents(&buf, &total));
    try std.testing.expectEqual(@as(u64, 0), total);
}

test "EVT-210 snapshotOpenIncidents bounds rows but reports the true total" {
    var tt = ThreatTracker.init(std.testing.allocator);
    defer tt.deinit();
    g_live = &tt;
    defer g_live = null;
    var flow: u64 = 1;
    while (flow <= 5) : (flow += 1) {
        var ev = event.IpcEvent.init(.signature_match);
        ev.flow_id = flow;
        ev.timestamp_ns = 1000;
        ev.event_id = flow;
        _ = try tt.observeFlowThreat(&ev, @intCast(100 + flow));
    }
    var buf: [2]SnapshotRow = undefined;
    var total: u64 = 0;
    const n = snapshotOpenIncidents(&buf, &total);
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expectEqual(@as(u64, 5), total); // bounded view, true total
    try std.testing.expectEqual(@as(u32, 105), buf[0].score);
    try std.testing.expectEqual(@as(u32, 104), buf[1].score);
}