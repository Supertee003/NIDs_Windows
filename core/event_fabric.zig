//! event_fabric.zig - AEGIS Event Fabric (Rewrite Phase 5)
//!
//! Thin facade over nose_contract.zig that exposes the submit/pop API
//! consumed by the dispatcher and lifecycle. The Event Fabric is the
//! single ingress point into the pipeline: sensors MUST submit through
//! this facade so that priority routing, validation, and backpressure
//! are applied uniformly.
//!
//! Contract:
//!   1. submitEvent(event) -> bool  (true if accepted, false if dropped)
//!   2. popEvent() -> ?CanonicalEvent  (null if queue empty)
//!   3. isInitialized() -> bool  (true after initFabric, false after shutdownFabric)
//!
//! The actual queue and validation logic live in nose_contract.zig.
//! This file exists so dispatcher.zig can `@import("event_fabric.zig")`
//! without coupling directly to nose_contract.zig internals.

const std = @import("std");
const canonical = @import("canonical_event.zig");
const nose = @import("nose_contract.zig");
const fab_acct = @import("fabric_accounting.zig");

// ============================================================
// Initialization state (mirrors nose_contract.g_fabric_initialized)
// ============================================================

var g_init_count: u64 = 0;
var g_submit_count: u64 = 0;
var g_pop_count: u64 = 0;
var g_drop_count: u64 = 0;

// G4: per-reason accounting (drop must have a reason + metric)
var g_acc_rejected: u64 = 0; // validation failure (magic/version/size)
var g_acc_dropped_fabric: u64 = 0; // queue full / priority overflow
var g_acc_not_initialized: u64 = 0; // submit before initFabric

// T3: backpressure + drop-reason accounting
var g_acc_reason: [DROP_REASON_COUNT]u64 = [_]u64{0} ** DROP_REASON_COUNT;
var g_backpressure: fab_acct.BackpressureTracker = fab_acct.BackpressureTracker.init(0);

pub const DROP_REASON_COUNT: usize = @intFromEnum(DropReason.not_initialized) + 1;

/// G4 accounting snapshot. Identity (must always hold):
///   submitted == accepted + rejected + dropped_by_fabric + not_initialized
pub const Accounting = struct {
    submitted: u64,
    accepted: u64,
    rejected: u64,
    dropped_by_fabric: u64,
    not_initialized: u64,

    pub fn identityHolds(self: Accounting) bool {
        return self.submitted ==
            self.accepted + self.rejected + self.dropped_by_fabric + self.not_initialized;
    }
};

/// T3: why an event was dropped at the ingress point. Every loss carries a
/// machine-readable reason so monitoring can distinguish capacity pressure
/// (queue_full / priority_saturation) from schema errors (validation_failed)
/// from lifecycle races (not_initialized).
pub const DropReason = enum(u8) {
    queue_full = 0, // physical overflow of a priority sub-queue
    priority_saturation = 1, // dropped due to backpressure (sampling/saturation)
    validation_failed = 2, // failed magic/version/schema validation
    not_initialized = 3, // fabric not up yet

    pub fn toString(self: DropReason) []const u8 {
        return switch (self) {
            .queue_full => "QUEUE_FULL",
            .priority_saturation => "PRIORITY_SATURATION",
            .validation_failed => "VALIDATION_FAILED",
            .not_initialized => "NOT_INITIALIZED",
        };
    }
};

/// T3: G4 per-reason fabric accounting for monitoring/metrics export.
pub fn getAccounting() Accounting {
    return .{
        .submitted = g_submit_count,
        .accepted = g_submit_count - g_drop_count,
        .rejected = g_acc_rejected,
        .dropped_by_fabric = g_acc_dropped_fabric,
        .not_initialized = g_acc_not_initialized,
    };
}

/// T3: number of events dropped with the given reason since process start.
pub fn dropReasonCount(reason: DropReason) u64 {
    return g_acc_reason[@intFromEnum(reason)];
}

/// T3: current backpressure level, derived from live queue depth.
/// (NORMAL -> ELEVATED -> HIGH -> SATURATED as the fabric fills.)
pub fn currentBackpressure() fab_acct.BackpressureLevel {
    return g_backpressure.getLevel();
}

/// T3: sync the backpressure tracker with the fabric's live queue depth.
/// Re-sizes the tracker whenever the fabric is (re)initialized with a
/// different capacity so per-run backpressure is always calibrated.
fn updateBackpressure() void {
    if (!isInitialized()) {
        _ = g_backpressure.updateDepth(0);
        return;
    }
    const cfg = nose.getConfig();
    const capacity = cfg.capacity_per_priority * nose.PRIORITY_COUNT;
    if (g_backpressure.capacity != capacity) {
        g_backpressure = fab_acct.BackpressureTracker.init(capacity);
    }
    const depth = nose.pendingCount();
    _ = g_backpressure.updateDepth(depth);
}

/// Returns the number of dropped events with a reason that implies capacity
/// pressure (queue_full or priority_saturation). Used to separate "we were
/// overwhelmed" from "the event was invalid".
pub fn overflowDropCount() u64 {
    return g_acc_reason[@intFromEnum(DropReason.queue_full)] +
        g_acc_reason[@intFromEnum(DropReason.priority_saturation)];
}

/// Returns true if the Event Fabric is currently initialized.
pub fn isInitialized() bool {
    return nose.isFabricInitialized();
}

/// Submit a CanonicalEvent into the fabric.
/// Returns true if accepted, false if rejected/dropped.
pub fn submitEvent(event: canonical.CanonicalEvent) bool {
    g_submit_count += 1;
    const result = nose.submitEvent(event);
    if (result != .accepted) {
        g_drop_count += 1;
        const reason = classifyDrop(result);
        g_acc_reason[@intFromEnum(reason)] += 1;
        switch (result) {
            .rejected => g_acc_rejected += 1,
            .dropped_at_source, .dropped_by_fabric => g_acc_dropped_fabric += 1,
            .not_initialized => g_acc_not_initialized += 1,
            .accepted => unreachable,
        }
        updateBackpressure();
        return false;
    }
    updateBackpressure();
    return true;
}

/// Map a fabric SubmitResult to a DropReason so every loss is attributable.
fn classifyDrop(result: nose.SubmitResult) DropReason {
    return switch (result) {
        .rejected => .validation_failed,
        .not_initialized => .not_initialized,
        .dropped_at_source => .priority_saturation, // sampling discarded under pressure
        .dropped_by_fabric => if (g_backpressure.getLevel().isCritical()) .priority_saturation else .queue_full,
        .accepted => unreachable,
    };
}

/// Pop the next highest-priority event from the fabric.
/// Returns null if the queue is empty or the fabric is not initialized.
pub fn popEvent() ?canonical.CanonicalEvent {
    if (!isInitialized()) return null;
    const ev = nose.popEvent() orelse return null;
    g_pop_count += 1;
    updateBackpressure();
    return ev;
}

/// Returns the count of submit calls since process start.
pub fn submitCount() u64 {
    return g_submit_count;
}

/// Returns the count of pop calls since process start.
pub fn popCount() u64 {
    return g_pop_count;
}

/// Returns the count of dropped events since process start.
pub fn dropCount() u64 {
    return g_drop_count;
}

// ============================================================
// Tests
// ============================================================

test "event_fabric.isInitialized returns false before init" {
    if (isInitialized()) {
        nose.shutdownFabric(std.testing.allocator);
    }
    try std.testing.expect(!isInitialized());
}

test "event_fabric.submitEvent rejects events when not initialized" {
    if (isInitialized()) {
        nose.shutdownFabric(std.testing.allocator);
    }
    var event = canonical.create(.zig_core);
    event.event_type = .block;
    try std.testing.expect(!submitEvent(event));
}

test "event_fabric.popEvent returns null when not initialized" {
    if (isInitialized()) {
        nose.shutdownFabric(std.testing.allocator);
    }
    try std.testing.expect(popEvent() == null);
}

test "event_fabric.submitEvent accepts after init" {
    nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 8 }) catch {};
    defer nose.shutdownFabric(std.testing.allocator);

    var event = canonical.create(.zig_core);
    event.event_type = .block;
    try std.testing.expect(submitEvent(event));
    try std.testing.expect(submitCount() >= 1);
}

test "event_fabric.popEvent returns events in FIFO order within priority" {
    nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 8 }) catch {};
    defer nose.shutdownFabric(std.testing.allocator);

    var i: u64 = 0;
    while (i < 3) : (i += 1) {
        var event = canonical.create(.zig_core);
        event.event_id = 100 + i;
        event.event_type = .block;
        _ = submitEvent(event);
    }

    i = 0;
    while (i < 3) : (i += 1) {
        const ev = popEvent() orelse {
            try std.testing.expect(false);
            return;
        };
        try std.testing.expect(ev.event_id == 100 + i);
    }
    try std.testing.expect(popEvent() == null);
}

test "G4: accounting identity holds across accept/reject/uninitialized" {
    if (isInitialized()) {
        nose.shutdownFabric(std.testing.allocator);
    }

    // not_initialized path
    var event = canonical.create(.zig_core);
    event.event_type = .block;
    try std.testing.expect(!submitEvent(event));

    // initialized: accepted + rejected paths
    nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 4 }) catch {};
    defer nose.shutdownFabric(std.testing.allocator);

    try std.testing.expect(submitEvent(event)); // accepted

    var bad = canonical.create(.zig_core);
    bad.magic = 0xDEAD; // invalid -> rejected
    try std.testing.expect(!submitEvent(bad));

    const acc = getAccounting();
    try std.testing.expect(acc.identityHolds());
    try std.testing.expect(acc.rejected >= 1);
    try std.testing.expect(acc.not_initialized >= 1);
    try std.testing.expect(acc.accepted >= 1);
}

test "T3: DropReason toString and mapping" {
    try std.testing.expect(std.mem.eql(u8, DropReason.queue_full.toString(), "QUEUE_FULL"));
    try std.testing.expect(std.mem.eql(u8, DropReason.priority_saturation.toString(), "PRIORITY_SATURATION"));
    try std.testing.expect(std.mem.eql(u8, DropReason.validation_failed.toString(), "VALIDATION_FAILED"));
    try std.testing.expect(std.mem.eql(u8, DropReason.not_initialized.toString(), "NOT_INITIALIZED"));
}

test "T3: drop reason = validation_failed for rejections" {
    if (isInitialized()) {
        nose.shutdownFabric(std.testing.allocator);
    }
    nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 }) catch {};
    defer nose.shutdownFabric(std.testing.allocator);

    var bad = canonical.create(.zig_core);
    bad.magic = 0xDEAD;
    try std.testing.expect(!submitEvent(bad));
    try std.testing.expect(dropReasonCount(.validation_failed) >= 1);
    try std.testing.expect(overflowDropCount() == dropReasonCount(.queue_full) + dropReasonCount(.priority_saturation));
}

test "T3: drop reason = not_initialized before fabric init" {
    if (isInitialized()) {
        nose.shutdownFabric(std.testing.allocator);
    }
    var event = canonical.create(.zig_core);
    event.event_type = .block;
    try std.testing.expect(!submitEvent(event));
    try std.testing.expect(dropReasonCount(.not_initialized) >= 1);
}

test "T3: overflow drops are attributed queue_full" {
    if (isInitialized()) {
        nose.shutdownFabric(std.testing.allocator);
    }
    nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 2 }) catch {};
    defer nose.shutdownFabric(std.testing.allocator);

    var event = canonical.create(.zig_core);
    event.event_type = .block; // high priority -> fills the high sub-queue

    try std.testing.expect(submitEvent(event));
    try std.testing.expect(submitEvent(event));
    try std.testing.expect(!submitEvent(event)); // high sub-queue full

    try std.testing.expect(dropReasonCount(.queue_full) >= 1);
    try std.testing.expect(g_acc_dropped_fabric >= 1);
    try std.testing.expect(getAccounting().identityHolds());
}

test "T3: backpressure tracks queue depth NORMAL -> SATURATED -> NORMAL" {
    if (isInitialized()) {
        nose.shutdownFabric(std.testing.allocator);
    }
    // capacity 2 per priority => total fabric capacity 6
    nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 2 }) catch {};
    defer nose.shutdownFabric(std.testing.allocator);

    try std.testing.expect(currentBackpressure() == .normal);

    // fill high (2 block), normal (2 match), low (2 forward) => depth 6/6 = 100%
    var i: usize = 0;
    while (i < 2) : (i += 1) {
        var block_e = canonical.create(.zig_core);
        block_e.event_type = .block;
        try std.testing.expect(submitEvent(block_e));

        var match_e = canonical.create(.zig_core);
        match_e.event_type = .match_;
        try std.testing.expect(submitEvent(match_e));

        var forward_e = canonical.create(.zig_core);
        forward_e.event_type = .forward;
        try std.testing.expect(submitEvent(forward_e));
    }
    try std.testing.expect(currentBackpressure() == .saturated);

    // A low-priority submit under saturation is refused with the saturation reason
    var extra = canonical.create(.zig_core);
    extra.event_type = .forward;
    try std.testing.expect(!submitEvent(extra));
    try std.testing.expect(dropReasonCount(.priority_saturation) >= 1);

    // Pop drains back to normal
    var drained: usize = 0;
    while (drained < 6) : (drained += 1) {
        try std.testing.expect(popEvent() != null);
    }
    try std.testing.expect(popEvent() == null);
    try std.testing.expect(currentBackpressure() == .normal);
}

test "T3: fabric input invariant holds under mixed accepted/rejected/dropped" {
    if (isInitialized()) {
        nose.shutdownFabric(std.testing.allocator);
    }
    nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 1 }) catch {};
    defer nose.shutdownFabric(std.testing.allocator);

    // one accepted, one invalid (rejected), one overflow (dropped)
    var ok = canonical.create(.zig_core);
    ok.event_type = .block;
    try std.testing.expect(submitEvent(ok));

    var bad = canonical.create(.zig_core);
    bad.magic = 0xBAD1;
    try std.testing.expect(!submitEvent(bad));

    var overflow = canonical.create(.zig_core);
    overflow.event_type = .block;
    try std.testing.expect(!submitEvent(overflow));

    const acc = getAccounting();
    // invariant: submitted == accepted + rejected + dropped_by_fabric + not_initialized
    try std.testing.expect(acc.identityHolds());
    try std.testing.expect(acc.submitted == acc.accepted + acc.rejected + acc.dropped_by_fabric + acc.not_initialized);
    try std.testing.expect(dropReasonCount(.validation_failed) >= 1);
}
