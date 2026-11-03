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
        .capture_etw => .host,
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
pub fn startLive() void {
    g_mutex.lock();
    defer g_mutex.unlock();
    g_fabric = .{};
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
    // Clear any previous frozen batch before this observation. A caller that
    // reuses one outcome must never mistake stale rows for a new freeze.
    out.* = .{};
    if (!g_started) return 0;
    const event_id = source_event.event_id;
    const ts_ms = std.math.cast(i64, source_event.timestamp_ns / std.time.ns_per_ms) orelse 0;
    if (event_id == 0 or entity.len == 0 or entity.len > fab.MAX_KEY_LEN) {
        g_mutex.lock();
        g_observation_dropped += 1;
        g_mutex.unlock();
        return 0;
    }
    g_mutex.lock();
    defer g_mutex.unlock();
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
    var idx: ?usize = null;
    for (g_fabric.incidents[0..g_fabric.incident_count], 0..) |*inc, i| {
        if (inc.incident_id == inc_id) {
            idx = i;
            break;
        }
    }
    const at = idx orelse {
        g_observation_dropped += 1;
        return 0;
    };
    // Advisory auto-assessment: the first crossing into multi-source
    // territory freezes the Decision (severity/confidence/source count).
    // It is never a host action and nothing downstream may treat it as one.
    if (g_fabric.distinctSources(at) >= 2 and g_fabric.incidents[at].decision == null) {
        _ = g_fabric.decide(at, ts_ms);
        g_advisories_total += 1;
        const inc = &g_fabric.incidents[at];
        out.* = .{ .frozen = true };
        out.entity_len = inc.entity_len;
        @memcpy(out.entity[0..inc.entity_len], inc.entity[0..inc.entity_len]);
        if (inc.decision) |d| out.decision = d;
        const rows = inc.evidenceRows();
        out.row_count = rows.len;
        @memcpy(out.rows[0..rows.len], rows);
    }
    return inc_id;
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

    var out = std.ArrayList(u8).init(a);
    defer out.deinit();
    const writer = out.writer();
    writer.print("{{\"xdr_scope\":\"{s}\",\"started\":{},\"evidence_total\":{d},\"observations_dropped\":{d},\"advisories_total\":{d},\"receipts_recorded\":{d},\"receipts_failed\":{d},\"receipts_skipped\":{d},\"incidents\":[", .{
        SNAPSHOT_TAG,
        live,
        evidence_total,
        dropped,
        advisories,
        receipts_recorded,
        receipts_failed,
        receipts_skipped,
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
            writer.print("{{\"id\":{d},\"entity\":\"{s}\",\"severity\":{d},\"confidence\":{d},\"source_categories_used\":{d},\"decision_made_ms\":{d},\"distinct_sources\":{d},\"evidence\":{d}}}", .{
                inc.incident_id,
                inc.entitySlice(),
                sev,
                conf,
                srcs_used,
                made_ms,
                inc.distinctSources(),
                inc.evidence_count,
            }) catch break;
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
    try std.testing.expectEqual(SourceCategory.file, categoryForSource(.capture_fim).?);
    try std.testing.expectEqual(SourceCategory.registry, categoryForSource(.capture_registry).?);
    try std.testing.expectEqual(SourceCategory.federation, categoryForSource(.federation).?);
    try std.testing.expectEqual(@as(?SourceCategory, null), categoryForSource(.capture_pipe_monitor));
    try std.testing.expectEqual(@as(?SourceCategory, null), categoryForSource(.detection_corr));
    try std.testing.expectEqual(@as(?SourceCategory, null), categoryForSource(.policy));
    try std.testing.expectEqual(@as(?SourceCategory, null), categoryForSource(.system));
}
