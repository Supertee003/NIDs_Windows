//! xdr_runtime.zig - Advisory XDR evidence fabric wired into the runtime
//! pipeline (XDR-WIRE-001).
//!
//! Owner decision (2026-11-02): XDR enters the production daemon as
//! **advisory, read-only evidence** only. This module feeds classified
//! detection-identity events into the selected correlation fabric
//! (`xdr_incident_fabric.zig`), keeps a bounded in-memory incident table,
//! and exposes it through the control plane (`xdr.list`).
//!
//! Hard boundary (pinned by src/contract/runtime_spine.zig and
//! tests/security/test_xdr_wire_advisory.py):
//!   - Nothing here computes a threat score, touches DEFCON, policy, PEP,
//!     ActionDispatcher, or any host effect. The Decision stays a plain
//!     evidence summary (severity/confidence/source count) with no action
//!     field by construction.
//!   - This module is NOT in the runtime manifest and the runtime spine
//!     pin must keep rejecting it there.
//!   - Only events with detection identity (rule_id != 0) are fed; plain
//!     packets never enter the fabric.
//!   - XDR-RECEIPT-002: when an advisory decision freezes, this module
//!     hands the caller the retained evidence batch through ObserveOutcome
//!     and exposes receipt persisted/failed/skipped counters. It does NOT
//!     touch the forensic ring itself: the recording-only persistence
//!     lives in pipeline/event_processor.recordXdrAdvisoryReceipt, which
//!     issues an IDS Evidence Receipt via xdr_evidence_flow.recordAssessment.
//!
//! Fail-soft: fixed capacity, dropped observations are counted, never
//! fatal. Without startLive() both observex and the handler answer
//! honestly empty (same contract as threat_tracker.g_live).

const std = @import("std");
const event = @import("../contract/event.zig");
const fab = @import("xdr_incident_fabric.zig");

pub const SourceCategory = fab.SourceCategory;
pub const Evidence = fab.Evidence;

/// Bounded detail view returned by the control handler; the real counts
/// are authoritative fields of their own (same contract as incidents.list).
pub const SNAPSHOT_CAP: usize = 32;

pub const SNAPSHOT_TAG = "advisory_read_only";

/// XDR-RECEIPT-002: what the caller receives from one observation. It is
/// filled only when the advisory decision crossed multi-source and froze;
/// the retained evidence rows are the receipt batch (replay-deterministic
/// from the fabric incident).
pub const ObserveOutcome = struct {
    frozen: bool = false,
    entity_len: usize = 0,
    entity: [fab.MAX_KEY_LEN]u8 = undefined,
    rows: [fab.MAX_EVIDENCE]Evidence = undefined,
    row_count: usize = 0,
    decision: fab.Decision = .{},
};

var g_mutex: std.Thread.Mutex = .{};
var g_fabric: fab.Fabric = .{};
var g_started: bool = false;
var g_evidence_total: u64 = 0;
var g_observation_dropped: u64 = 0;
var g_advisories_total: u64 = 0;
// XDR-RECEIPT-002: receipt persistence counters (read-only evidence
// counters like everything else here; never health or decision inputs).
var g_receipts_recorded: u64 = 0;
var g_receipts_failed: u64 = 0;
var g_receipts_skipped: u64 = 0;

/// Map a canonical event source to its XDR evidence category. Detection
/// results (detection_*/policy/system) stay unmapped: their underlying
/// capture events are the evidence rows.
pub fn categoryForSource(src: event.EventSource) ?SourceCategory {
    return switch (src) {
        .capture_npcap, .capture_wfp => .network,
        .capture_etw, .capture_host_net => .host,
        .capture_fim => .file,
        .capture_registry => .registry,
        .federation => .federation,
        else => null,
    };
}

/// Daemon startup: publish the advisory fabric before any worker spawns.
/// Idempotent: re-start replaces the bounded table (process-lifetime
/// advisory counters keep running; they are evidence counters, never
/// health inputs).
// XDR-005-A: host socket evidence arrives as a state observation (no
// detection identity). It is held until network evidence for the same
// entity arrives inside the TTL, then joins that incident as the second
// source. Host-only observations never open an incident by themselves.
pub const HOST_TTL_MS: i64 = 120_000;
pub const RECENT_TTL_MS: i64 = 120_000;
const RECENT_CAP: usize = 64;
const PENDING_CAP: usize = 32;

const RecentNetwork = struct {
    entity: [fab.MAX_KEY_LEN]u8 = undefined,
    entity_len: usize = 0,
    last_seen_ms: i64 = 0,
};

const PendingHost = struct {
    entity: [fab.MAX_KEY_LEN]u8 = undefined,
    entity_len: usize = 0,
    row: Evidence = .{},
    added_ms: i64 = 0,
};

pub const HostCounters = struct {
    offered: u64 = 0,
    pending: u64 = 0,
    joined: u64 = 0,
    expired: u64 = 0,
    evicted: u64 = 0,
    deferred: u64 = 0,
    recent_evicted: u64 = 0,
    /// Host observations whose recent-window entity no longer had a live
    /// network incident (fabric eviction). They are dropped, never promoted
    /// into a host-only incident.
    orphaned: u64 = 0,
};

var g_recent: [RECENT_CAP]RecentNetwork = undefined;
var g_recent_count: usize = 0;
var g_pending: [PENDING_CAP]PendingHost = undefined;
var g_pending_count: usize = 0;
// TTL clock: fabric-relative elapsed milliseconds from a monotonic Instant
// captured by startLive(). Never derived from event timestamps (those are
// wall-clock and jump on NTP adjustment). If Instant is unavailable the
// module degrades honestly to wall-clock and reports clock:"wall".
var g_clock_origin: ?std.time.Instant = null;
var g_clock_wall: bool = false;
var g_host_offered: u64 = 0;
var g_host_joined: u64 = 0;
var g_host_expired: u64 = 0;
var g_host_evicted: u64 = 0;
var g_host_deferred: u64 = 0;
var g_recent_evicted: u64 = 0;
var g_host_orphaned: u64 = 0;

fn findIncidentLocked(inc_id: u64) ?usize {
    for (g_fabric.incidents[0..g_fabric.incident_count], 0..) |*inc, i| {
        if (inc.incident_id == inc_id) return i;
    }
    return null;
}

fn findIncidentByEntityLocked(entity: []const u8) ?usize {
    for (g_fabric.incidents[0..g_fabric.incident_count], 0..) |*inc, i| {
        if (inc.entity_len == entity.len and std.mem.eql(u8, inc.entity[0..inc.entity_len], entity)) return i;
    }
    return null;
}

fn findRecentLocked(entity: []const u8) ?usize {
    for (g_recent[0..g_recent_count], 0..) |*r, i| {
        if (r.entity_len == entity.len and std.mem.eql(u8, r.entity[0..r.entity_len], entity)) return i;
    }
    return null;
}

fn sweepRecentLocked(now_ms: i64) void {
    var i: usize = 0;
    while (i < g_recent_count) {
        if (now_ms - g_recent[i].last_seen_ms > RECENT_TTL_MS) {
            g_recent[i] = g_recent[g_recent_count - 1];
            g_recent_count -= 1;
        } else {
            i += 1;
        }
    }
}

fn updateRecentLocked(entity: []const u8, now_ms: i64) void {
    sweepRecentLocked(now_ms);
    if (findRecentLocked(entity)) |i| {
        g_recent[i].last_seen_ms = now_ms;
        return;
    }
    var idx = g_recent_count;
    if (idx >= RECENT_CAP) {
        var oldest: usize = 0;
        for (g_recent[1..RECENT_CAP], 1..) |r, i| {
            if (r.last_seen_ms < g_recent[oldest].last_seen_ms) oldest = i;
        }
        idx = oldest;
        g_recent_evicted += 1;
    } else {
        g_recent_count += 1;
    }
    g_recent[idx] = .{
        .entity = undefined,
        .entity_len = entity.len,
        .last_seen_ms = now_ms,
    };
    @memcpy(g_recent[idx].entity[0..entity.len], entity);
}

fn takePendingLocked(entity: []const u8) ?PendingHost {
    for (g_pending[0..g_pending_count], 0..) |*p, i| {
        if (p.entity_len == entity.len and std.mem.eql(u8, p.entity[0..p.entity_len], entity)) {
            const row = p.*;
            g_pending[i] = g_pending[g_pending_count - 1];
            g_pending_count -= 1;
            return row;
        }
    }
    return null;
}

fn sweepPendingLocked(now_ms: i64) void {
    var i: usize = 0;
    while (i < g_pending_count) {
        if (now_ms - g_pending[i].added_ms > HOST_TTL_MS) {
            g_host_expired += 1;
            g_pending[i] = g_pending[g_pending_count - 1];
            g_pending_count -= 1;
        } else {
            i += 1;
        }
    }
}

fn storePendingLocked(entity: []const u8, row: Evidence, now_ms: i64) void {
    for (g_pending[0..g_pending_count]) |*p| {
        if (p.entity_len == entity.len and std.mem.eql(u8, p.entity[0..p.entity_len], entity)) {
            p.row = row;
            p.added_ms = now_ms;
            return;
        }
    }
    var idx = g_pending_count;
    if (idx >= PENDING_CAP) {
        var oldest: usize = 0;
        for (g_pending[1..PENDING_CAP], 1..) |p, i| {
            if (p.added_ms < g_pending[oldest].added_ms) oldest = i;
        }
        idx = oldest;
        g_host_evicted += 1;
    } else {
        g_pending_count += 1;
    }
    g_pending[idx] = .{
        .entity = undefined,
        .entity_len = entity.len,
        .row = row,
        .added_ms = now_ms,
    };
    @memcpy(g_pending[idx].entity[0..entity.len], entity);
}

fn freezeLocked(out: *ObserveOutcome, idx: usize, ts_ms: i64) void {
    // Advisory auto-assessment: the first crossing into multi-source
    // territory freezes the Decision (severity/confidence/source count).
    // It is never a host action and nothing downstream may treat it as one.
    if (g_fabric.distinctSources(idx) < 2) return;
    const inc = &g_fabric.incidents[idx];
    if (inc.decision != null) return;
    _ = g_fabric.decide(idx, ts_ms);
    g_advisories_total += 1;
    out.* = .{ .frozen = true };
    out.entity_len = inc.entity_len;
    @memcpy(out.entity[0..inc.entity_len], inc.entity[0..inc.entity_len]);
    if (inc.decision) |d| out.decision = d;
    const rows = inc.evidenceRows();
    out.row_count = rows.len;
    @memcpy(out.rows[0..rows.len], rows);
}

/// Caller must hold g_mutex (origin is only replaced under the same lock).
pub fn fabricNowMsLocked() i64 {
    if (g_clock_origin) |origin| {
        const now = std.time.Instant.now() catch {
            g_clock_wall = true;
            return std.time.milliTimestamp();
        };
        if (now.order(origin) == .lt) {
            g_clock_wall = true;
            return std.time.milliTimestamp();
        }
        return std.math.cast(i64, now.since(origin) / std.time.ns_per_ms) orelse std.math.maxInt(i64);
    }
    g_clock_wall = true;
    return std.time.milliTimestamp();
}

pub fn startLive() void {
    g_mutex.lock();
    defer g_mutex.unlock();
    g_fabric = .{};
    g_recent_count = 0;
    g_pending_count = 0;
    g_clock_origin = std.time.Instant.now() catch null;
    g_clock_wall = g_clock_origin == null;
    g_started = true;
}

/// Advisory evidence ingest. entity must be non-empty; event_id must be
/// nonzero (a frozen observation, not a live packet wheel). Returns the
/// incident id, or 0 when the observation was refused (not started,
/// oversized entity, or table overflow — dropped counter distinguishes
/// the last two).
pub fn observe(
    category: SourceCategory,
    entity: []const u8,
    event_id: u64,
    ts_ms: i64,
    severity: u8,
) u64 {
    var src = event.IpcEvent.init(.signature_match);
    src.event_id = event_id;
    src.timestamp_ns = if (ts_ms <= 0)
        0
    else
        @as(u64, @intCast(@min(ts_ms, std.math.maxInt(i64) / std.time.ns_per_ms))) * std.time.ns_per_ms;
    var local_out = ObserveOutcome{};
    return observeEvent(&local_out, category, entity, severity, &src);
}

/// Advisory evidence ingest with the full source-event context. Same
/// refusal/fail-soft contract as observe(); additionally hands the caller
/// the frozen advisory batch (ObserveOutcome.frozen) so the recording-only
/// receipt step can persist it without this module touching the ring.
pub fn observeEvent(
    out: *ObserveOutcome,
    category: SourceCategory,
    entity: []const u8,
    severity: u8,
    source_event: *const event.IpcEvent,
) u64 {
    g_mutex.lock();
    defer g_mutex.unlock();
    return observeEventLocked(out, category, entity, severity, source_event, fabricNowMsLocked());
}

/// Deterministic-clock seam for TTL tests. Production callers use
/// observeEvent(), which supplies fabricNowMsLocked().
pub fn observeEventAt(
    out: *ObserveOutcome,
    category: SourceCategory,
    entity: []const u8,
    severity: u8,
    source_event: *const event.IpcEvent,
    now_ms: i64,
) u64 {
    g_mutex.lock();
    defer g_mutex.unlock();
    return observeEventLocked(out, category, entity, severity, source_event, now_ms);
}

fn observeEventLocked(
    out: *ObserveOutcome,
    category: SourceCategory,
    entity: []const u8,
    severity: u8,
    source_event: *const event.IpcEvent,
    now_ms: i64,
) u64 {
    // Clear any previous frozen batch before this observation. A caller that
    // reuses one outcome must never mistake stale rows for a new freeze.
    out.* = .{};
    if (!g_started) return 0;
    const event_id = source_event.event_id;
    const ts_ms = std.math.cast(i64, source_event.timestamp_ns / std.time.ns_per_ms) orelse 0;
    if (event_id == 0 or entity.len == 0 or entity.len > fab.MAX_KEY_LEN) {
        g_observation_dropped += 1;
        return 0;
    }
    g_evidence_total += 1;

    var ev = Evidence{
        .source = category,
        .event_id = event_id,
        .ts_ms = ts_ms,
        .severity = severity,
    };
    @memcpy(ev.entity[0..entity.len], entity);
    ev.entity_len = entity.len;

    // Ingest is the single fold point: existing entity folds in place,
    // new entity creates the incident and folds this observation once.
    const inc_id = g_fabric.ingest(ev);
    if (inc_id == 0) {
        g_observation_dropped += 1; // fabric table overflow (fail-soft)
        return 0;
    }
    var idx = findIncidentLocked(inc_id) orelse {
        g_observation_dropped += 1;
        return 0;
    };

    if (category == .network) {
        // Expired pending host rows must never be joined by a late network
        // event; sweep by the same clock before matching.
        sweepPendingLocked(now_ms);
        updateRecentLocked(entity, now_ms);
    }

    // XDR-005-A: a host socket observation that arrived first was held
    // pending. Join it before the freeze check so the incident crosses in
    // one decision instead of requiring a second network observation.
    if (takePendingLocked(entity)) |pending| {
        if (g_fabric.ingest(pending.row) == 0) {
            // Incident table overflow: the host row is gone from the pending
            // table and must be counted as a drop, never silently lost.
            g_observation_dropped += 1;
        } else {
            g_evidence_total += 1;
            g_host_joined += 1;
            idx = findIncidentLocked(inc_id) orelse idx;
        }
    }

    freezeLocked(out, idx, ts_ms);
    return inc_id;
}

/// XDR-005-A host socket admission. Host telemetry has no detection
/// identity (rule_id = 0), so it never opens an incident. It either joins a
/// recent network incident for the same entity (the second source) or waits
/// in a bounded pending table until network evidence arrives inside TTL.
pub fn observeHostObservation(
    out: *ObserveOutcome,
    entity: []const u8,
    severity: u8,
    source_event: *const event.IpcEvent,
) u64 {
    g_mutex.lock();
    defer g_mutex.unlock();
    return observeHostObservationLocked(out, entity, severity, source_event, fabricNowMsLocked());
}

/// Deterministic-clock seam for TTL tests.
pub fn observeHostObservationAt(
    out: *ObserveOutcome,
    entity: []const u8,
    severity: u8,
    source_event: *const event.IpcEvent,
    now_ms: i64,
) u64 {
    g_mutex.lock();
    defer g_mutex.unlock();
    return observeHostObservationLocked(out, entity, severity, source_event, now_ms);
}

fn observeHostObservationLocked(
    out: *ObserveOutcome,
    entity: []const u8,
    severity: u8,
    source_event: *const event.IpcEvent,
    now_ms: i64,
) u64 {
    out.* = .{};
    if (!g_started) return 0;
    const event_id = source_event.event_id;
    const ts_ms = std.math.cast(i64, source_event.timestamp_ns / std.time.ns_per_ms) orelse 0;
    g_host_offered += 1;
    if (event_id == 0 or entity.len == 0 or entity.len > fab.MAX_KEY_LEN) {
        g_observation_dropped += 1;
        return 0;
    }

    sweepPendingLocked(now_ms);
    sweepRecentLocked(now_ms);

    var ev = Evidence{
        .source = .host,
        .event_id = event_id,
        .ts_ms = ts_ms,
        .severity = severity,
    };
    @memcpy(ev.entity[0..entity.len], entity);
    ev.entity_len = entity.len;

    if (findRecentLocked(entity) != null) {
        // Fresh network evidence exists, but the fabric incident table is
        // bounded: if the entity's incident was evicted, folding here would
        // open a brand-new host-only incident without detection identity.
        // That is forbidden, so the observation is dropped with an honest
        // counter instead.
        const idx = findIncidentByEntityLocked(entity) orelse {
            g_host_orphaned += 1;
            g_observation_dropped += 1;
            return 0;
        };
        const inc_id = g_fabric.incidents[idx].incident_id;
        g_evidence_total += 1;
        if (g_fabric.ingest(ev) == 0) {
            g_observation_dropped += 1;
            return 0;
        }
        g_host_joined += 1;
        freezeLocked(out, idx, ts_ms);
        return inc_id;
    }

    // No network evidence inside the recent window: hold, never open.
    storePendingLocked(entity, ev, now_ms);
    g_host_deferred += 1;
    return 0;
}

/// Current bounded-table state plus cumulative counters. Read-only.
pub fn hostCounters() HostCounters {
    g_mutex.lock();
    defer g_mutex.unlock();
    return .{
        .offered = g_host_offered,
        .pending = @intCast(g_pending_count),
        .joined = g_host_joined,
        .expired = g_host_expired,
        .evicted = g_host_evicted,
        .deferred = g_host_deferred,
        .recent_evicted = g_recent_evicted,
        .orphaned = g_host_orphaned,
    };
}

pub fn hostClockName() []const u8 {
    g_mutex.lock();
    defer g_mutex.unlock();
    return if (g_clock_wall or g_clock_origin == null) "wall" else "monotonic";
}

/// Process-lifetime advisory counters (read-only; never health inputs).
pub fn advisoryCount() u64 {
    g_mutex.lock();
    defer g_mutex.unlock();
    return g_advisories_total;
}

/// XDR-RECEIPT-002 receipt-persistence counters. The mutators are called
/// only from the recording-only helper in pipeline/event_processor; they
/// change nothing but evidence numbers.
pub fn noteReceiptRecorded() void {
    g_mutex.lock();
    defer g_mutex.unlock();
    g_receipts_recorded += 1;
}

pub fn noteReceiptFailed() void {
    g_mutex.lock();
    defer g_mutex.unlock();
    g_receipts_failed += 1;
}

pub fn noteReceiptSkipped() void {
    g_mutex.lock();
    defer g_mutex.unlock();
    g_receipts_skipped += 1;
}

pub fn receiptsRecorded() u64 {
    g_mutex.lock();
    defer g_mutex.unlock();
    return g_receipts_recorded;
}

pub fn receiptsFailed() u64 {
    g_mutex.lock();
    defer g_mutex.unlock();
    return g_receipts_failed;
}

pub fn receiptsSkipped() u64 {
    g_mutex.lock();
    defer g_mutex.unlock();
    return g_receipts_skipped;
}

pub fn evidenceTotal() u64 {
    g_mutex.lock();
    defer g_mutex.unlock();
    return g_evidence_total;
}

pub fn observationsDropped() u64 {
    g_mutex.lock();
    defer g_mutex.unlock();
    return g_observation_dropped;
}

/// Bounded JSON view for the control plane. Honest-empty when the fabric
/// was never started (same honesty contract as incidents.list without a
/// tracker). Fabrication for dashboards is out of scope.
pub fn listJson(a: std.mem.Allocator) ?[]const u8 {
    g_mutex.lock();
    const live = g_started;
    const evidence_total = g_evidence_total;
    const dropped = g_observation_dropped;
    const advisories = g_advisories_total;
    const receipts_recorded = g_receipts_recorded;
    const receipts_failed = g_receipts_failed;
    const receipts_skipped = g_receipts_skipped;
    const host = HostCounters{
        .offered = g_host_offered,
        .pending = @intCast(g_pending_count),
        .joined = g_host_joined,
        .expired = g_host_expired,
        .evicted = g_host_evicted,
        .deferred = g_host_deferred,
        .recent_evicted = g_recent_evicted,
        .orphaned = g_host_orphaned,
    };
    const clock_name: []const u8 = if (g_clock_wall or g_clock_origin == null) "wall" else "monotonic";

    var out = std.ArrayList(u8).init(a);
    defer out.deinit();
    const writer = out.writer();
    writer.print("{{\"xdr_scope\":\"{s}\",\"started\":{},\"evidence_total\":{d},\"observations_dropped\":{d},\"advisories_total\":{d},\"receipts_recorded\":{d},\"receipts_failed\":{d},\"receipts_skipped\":{d},\"host_net\":{{\"clock\":\"{s}\",\"offered\":{d},\"pending\":{d},\"joined\":{d},\"expired\":{d},\"evicted\":{d},\"deferred\":{d},\"recent_evicted\":{d},\"orphaned\":{d}}},\"incidents\":[", .{
        SNAPSHOT_TAG,
        live,
        evidence_total,
        dropped,
        advisories,
        receipts_recorded,
        receipts_failed,
        receipts_skipped,
        clock_name,
        host.offered,
        host.pending,
        host.joined,
        host.expired,
        host.evicted,
        host.deferred,
        host.recent_evicted,
        host.orphaned,
    }) catch {
        g_mutex.unlock();
        return null;
    };

    if (live) {
        var shown: usize = 0;
        for (g_fabric.incidents[0..g_fabric.incident_count]) |*inc| {
            if (shown >= SNAPSHOT_CAP) break;
            if (shown != 0) writer.writeByte(',') catch break;
            var sev: u8 = 0;
            var conf: u8 = 0;
            var srcs_used: u8 = 0;
            var made_ms: i64 = 0;
            if (inc.decision) |d| {
                sev = d.severity;
                conf = d.confidence;
                srcs_used = d.source_categories_used;
                made_ms = d.made_ms;
            }
            writer.print("{{\"id\":{d},\"entity\":\"{s}\",\"severity\":{d},\"confidence\":{d},\"source_categories_used\":{d},\"decision_made_ms\":{d},\"distinct_sources\":{d},\"evidence\":{d},\"source_categories\":[", .{
                inc.incident_id,
                inc.entitySlice(),
                sev,
                conf,
                srcs_used,
                made_ms,
                inc.distinctSources(),
                inc.evidence_count,
            }) catch break;
            var first_cat = true;
            for (fab.SOURCE_CATEGORIES) |cat| {
                if (!inc.hasSource(cat)) continue;
                if (!first_cat) writer.writeByte(',') catch break;
                writer.print("\"{s}\"", .{cat.label()}) catch break;
                first_cat = false;
            }
            writer.writeAll("]}") catch break;
            shown += 1;
        }
    }
    writer.writeAll("]}") catch {
        g_mutex.unlock();
        return null;
    };
    g_mutex.unlock();
    return out.toOwnedSlice() catch null;
}

// ============================================================
// Tests
// ============================================================

test "xdr_runtime refusals: not started, zero event id, oversized entity" {
    startLive();
    // Honest-empty JSON when the observations are all refused.
    const before_dropped = observationsDropped();

    try std.testing.expectEqual(@as(u64, 0), observe(.network, "10.0.0.4", 0, 1, 2)); // zero id
    try std.testing.expectEqual(@as(u64, 0), observe(.network, "", 5, 1, 2)); // empty entity
    var too_long: [fab.MAX_KEY_LEN + 1]u8 = undefined;
    @memset(too_long[0..], 'x');
    try std.testing.expectEqual(@as(u64, 0), observe(.network, &too_long, 6, 1, 2));
    try std.testing.expect(before_dropped + 3 <= observationsDropped());
}

test "xdr_runtime single source stays a folder, no advisory decision" {
    startLive();
    const id = observe(.network, "198.51.100.6", 1, 1000, 3);
    try std.testing.expectEqual(@as(u64, 1), id);
    try std.testing.expectEqual(@as(u64, 0), advisoryCount());
    const json = listJson(std.testing.allocator) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(json);
    // No decision fields materialized, scope tag pinned.
    try std.testing.expect(std.mem.indexOf(u8, json, "\"advisories_total\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, SNAPSHOT_TAG) != null);
}

test "xdr_runtime multi-source crossing freezes an advisory decision" {
    startLive();
    _ = observe(.network, "203.0.113.9", 101, 1000, 3);
    const id = observe(.host, "203.0.113.9", 102, 1100, 3);
    try std.testing.expectEqual(@as(u64, 1), id);
    try std.testing.expectEqual(@as(u64, 1), advisoryCount());
    const json2 = listJson(std.testing.allocator) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(json2);
    // Advisory summary carries evidence classification only: the JSON
    // must not contain action/enforce/quarantine keys at all.
    try std.testing.expect(std.mem.indexOf(u8, json2, "\"source_categories_used\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, json2, "action") == null);
    try std.testing.expect(std.mem.indexOf(u8, json2, "enforce") == null);
}

test "xdr_runtime frozen outcome carries the replay batch and clears stale state" {
    startLive();
    var net = event.IpcEvent.init(.signature_match);
    net.event_id = 201;
    net.timestamp_ns = 1_700_000_000_000_000_000;
    net.source = .capture_npcap;
    net.rule_id = 9001;

    var out = ObserveOutcome{};
    _ = observeEvent(&out, .network, "203.0.113.77", 4, &net);
    try std.testing.expect(!out.frozen);

    var host = event.IpcEvent.init(.signature_match);
    host.event_id = 202;
    host.timestamp_ns = net.timestamp_ns + 100 * std.time.ns_per_ms;
    host.source = .capture_etw;
    host.rule_id = 9002;
    _ = observeEvent(&out, .host, "203.0.113.77", 3, &host);

    try std.testing.expect(out.frozen);
    try std.testing.expectEqual(@as(usize, 2), out.row_count);
    try std.testing.expectEqual(@as(u64, 201), out.rows[0].event_id);
    try std.testing.expectEqual(@as(u64, 202), out.rows[1].event_id);
    try std.testing.expectEqual(SourceCategory.network, out.rows[0].source);
    try std.testing.expectEqual(SourceCategory.host, out.rows[1].source);
    try std.testing.expectEqual(@as(u8, 2), out.decision.source_categories_used);
    try std.testing.expect(std.mem.eql(u8, out.entity[0..out.entity_len], "203.0.113.77"));

    var later = event.IpcEvent.init(.signature_match);
    later.event_id = 203;
    later.timestamp_ns = host.timestamp_ns + std.time.ns_per_ms;
    later.source = .capture_npcap;
    _ = observeEvent(&out, .network, "198.51.100.9", 2, &later);
    try std.testing.expect(!out.frozen);
    try std.testing.expectEqual(@as(usize, 0), out.row_count);
}

test "xdr_runtime categoryForSource is closed and honest" {
    try std.testing.expectEqual(SourceCategory.network, categoryForSource(.capture_npcap).?);
    try std.testing.expectEqual(SourceCategory.network, categoryForSource(.capture_wfp).?);
    try std.testing.expectEqual(SourceCategory.host, categoryForSource(.capture_etw).?);
    try std.testing.expectEqual(SourceCategory.host, categoryForSource(.capture_host_net).?);
    try std.testing.expectEqual(SourceCategory.file, categoryForSource(.capture_fim).?);
    try std.testing.expectEqual(SourceCategory.registry, categoryForSource(.capture_registry).?);
    try std.testing.expectEqual(SourceCategory.federation, categoryForSource(.federation).?);
    try std.testing.expectEqual(@as(?SourceCategory, null), categoryForSource(.capture_pipe_monitor));
    try std.testing.expectEqual(@as(?SourceCategory, null), categoryForSource(.detection_corr));
    try std.testing.expectEqual(@as(?SourceCategory, null), categoryForSource(.policy));
    try std.testing.expectEqual(@as(?SourceCategory, null), categoryForSource(.system));
}

fn hostFixture(event_id: u64) event.IpcEvent {
    var host = event.IpcEvent.init(.host_socket_observed);
    host.source = .capture_host_net;
    host.event_id = event_id;
    host.timestamp_ns = 1_700_000_000_000_000_000 + event_id * std.time.ns_per_ms;
    return host;
}

fn networkFixture(event_id: u64) event.IpcEvent {
    var net = event.IpcEvent.init(.signature_match);
    net.source = .capture_npcap;
    net.rule_id = 9001;
    net.event_id = event_id;
    net.timestamp_ns = 1_700_000_000_000_000_000 + event_id * std.time.ns_per_ms;
    return net;
}

test "xdr_runtime host-only observation stays pending and opens no incident" {
    startLive();
    const before = hostCounters();
    var host = hostFixture(401);
    var out = ObserveOutcome{};

    try std.testing.expectEqual(@as(u64, 0), observeHostObservationAt(&out, "198.51.100.30", 2, &host, 1000));
    try std.testing.expect(!out.frozen);
    try std.testing.expectEqual(@as(usize, 0), out.row_count);

    const after = hostCounters();
    try std.testing.expectEqual(before.offered + 1, after.offered);
    try std.testing.expectEqual(before.deferred + 1, after.deferred);
    try std.testing.expectEqual(before.joined, after.joined);
    try std.testing.expectEqual(@as(u64, 1), after.pending);

    const json = listJson(std.testing.allocator) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(json);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"host_net\":{\"clock\":\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"pending\":1") != null);
    // No incident opened: the entity never appears in the incident table.
    try std.testing.expect(std.mem.indexOf(u8, json, "198.51.100.30") == null);
}

test "xdr_runtime network then host freezes with two sources" {
    startLive();
    var net = networkFixture(402);
    var host = hostFixture(403);
    var out = ObserveOutcome{};

    const net_id = observeEventAt(&out, .network, "203.0.113.40", 3, &net, 1000);
    try std.testing.expect(net_id != 0);
    try std.testing.expect(!out.frozen);

    const before = hostCounters();
    const host_id = observeHostObservationAt(&out, "203.0.113.40", 2, &host, 1500);
    try std.testing.expectEqual(net_id, host_id);
    try std.testing.expect(out.frozen);
    try std.testing.expectEqual(@as(usize, 2), out.row_count);
    try std.testing.expectEqual(@as(u64, 402), out.rows[0].event_id);
    try std.testing.expectEqual(@as(u64, 403), out.rows[1].event_id);
    try std.testing.expectEqual(SourceCategory.network, out.rows[0].source);
    try std.testing.expectEqual(SourceCategory.host, out.rows[1].source);
    try std.testing.expectEqual(@as(u8, 2), out.decision.source_categories_used);
    try std.testing.expectEqual(before.joined + 1, hostCounters().joined);
    try std.testing.expectEqual(@as(u64, 0), hostCounters().pending);

    const json = listJson(std.testing.allocator) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(json);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"source_categories\":[\"network\",\"host\"]") != null);
}

test "xdr_runtime host then network joins the pending row before freezing" {
    startLive();
    var host = hostFixture(404);
    var net = networkFixture(405);
    var out = ObserveOutcome{};

    try std.testing.expectEqual(@as(u64, 0), observeHostObservationAt(&out, "203.0.113.41", 2, &host, 1000));
    try std.testing.expectEqual(@as(u64, 1), hostCounters().pending);

    const before = hostCounters();
    const net_id = observeEventAt(&out, .network, "203.0.113.41", 3, &net, 1500);
    try std.testing.expect(net_id != 0);
    try std.testing.expect(out.frozen);
    try std.testing.expectEqual(@as(usize, 2), out.row_count);
    try std.testing.expectEqual(@as(u64, 405), out.rows[0].event_id);
    try std.testing.expectEqual(@as(u64, 404), out.rows[1].event_id);
    try std.testing.expectEqual(before.joined + 1, hostCounters().joined);
    try std.testing.expectEqual(@as(u64, 0), hostCounters().pending);
}

test "xdr_runtime pending host expires after TTL with no incident" {
    startLive();
    const before = hostCounters();
    var host = hostFixture(406);
    var out = ObserveOutcome{};
    try std.testing.expectEqual(@as(u64, 0), observeHostObservationAt(&out, "203.0.113.42", 2, &host, 1000));

    var host2 = hostFixture(407);
    try std.testing.expectEqual(@as(u64, 0), observeHostObservationAt(&out, "203.0.113.42", 2, &host2, 1000 + HOST_TTL_MS + 1));
    const after = hostCounters();
    try std.testing.expectEqual(before.expired + 1, after.expired);
    try std.testing.expectEqual(@as(u64, 1), after.pending); // the second offer is pending
    try std.testing.expectEqual(before.joined, after.joined);

    const json = listJson(std.testing.allocator) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(json);
    try std.testing.expect(std.mem.indexOf(u8, json, "203.0.113.42") == null);
}

test "xdr_runtime recent network window expires and refuses a late host row" {
    startLive();
    var net = networkFixture(408);
    var host = hostFixture(409);
    var out = ObserveOutcome{};
    _ = observeEventAt(&out, .network, "203.0.113.43", 3, &net, 1000);
    try std.testing.expect(!out.frozen);

    const before = hostCounters();
    try std.testing.expectEqual(@as(u64, 0), observeHostObservationAt(&out, "203.0.113.43", 2, &host, 1000 + RECENT_TTL_MS + 1));
    try std.testing.expect(!out.frozen);
    try std.testing.expectEqual(before.joined, hostCounters().joined);
    try std.testing.expectEqual(before.deferred + 1, hostCounters().deferred);
    try std.testing.expectEqual(@as(u64, 1), hostCounters().pending);
}

test "xdr_runtime pending host table is bounded and evicts oldest" {
    startLive();
    const before = hostCounters();
    var out = ObserveOutcome{};
    var entity_buf: [32]u8 = undefined;

    var i: usize = 0;
    while (i < 33) : (i += 1) {
        const entity = try std.fmt.bufPrint(&entity_buf, "203.0.113.{d}", .{i + 50});
        var host = hostFixture(@intCast(500 + i));
        _ = observeHostObservationAt(&out, entity, 2, &host, @intCast(1000 + i));
    }
    const after = hostCounters();
    try std.testing.expectEqual(@as(u64, 32), after.pending);
    try std.testing.expectEqual(before.evicted + 1, after.evicted);
    try std.testing.expectEqual(before.offered + 33, after.offered);
    try std.testing.expectEqual(before.deferred + 33, after.deferred);
}

test "xdr_runtime host observation cannot open a host-only incident after eviction" {
    startLive();
    // Simulate a still-fresh recent-window entity whose fabric incident was
    // evicted: the observation must be dropped, never promoted to a new
    // incident without detection identity.
    g_mutex.lock();
    g_recent[0] = .{ .entity = undefined, .entity_len = 12, .last_seen_ms = 1000 };
    @memcpy(g_recent[0].entity[0..12], "203.0.113.90");
    g_recent_count = 1;
    g_mutex.unlock();

    const before = hostCounters();
    var host = hostFixture(410);
    var out = ObserveOutcome{};
    try std.testing.expectEqual(@as(u64, 0), observeHostObservationAt(&out, "203.0.113.90", 2, &host, 1500));
    try std.testing.expect(!out.frozen);
    const after = hostCounters();
    try std.testing.expectEqual(before.orphaned + 1, after.orphaned);
    try std.testing.expectEqual(before.joined, after.joined);
    // It is not hidden in the pending table either: the recent window says
    // the network incident existed, so a later retry cannot fix that.
    try std.testing.expectEqual(@as(u64, 0), after.pending);
    try std.testing.expectEqual(@as(usize, 0), g_fabric.incident_count);
}
