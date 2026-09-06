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

/// G4: per-reason fabric accounting for monitoring/metrics export.
pub fn getAccounting() Accounting {
    return .{
        .submitted = g_submit_count,
        .accepted = g_submit_count - g_drop_count,
        .rejected = g_acc_rejected,
        .dropped_by_fabric = g_acc_dropped_fabric,
        .not_initialized = g_acc_not_initialized,
    };
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
        switch (result) {
            .rejected => g_acc_rejected += 1,
            .dropped_at_source, .dropped_by_fabric => g_acc_dropped_fabric += 1,
            .not_initialized => g_acc_not_initialized += 1,
            .accepted => unreachable,
        }
        return false;
    }
    return true;
}

/// Pop the next highest-priority event from the fabric.
/// Returns null if the queue is empty or the fabric is not initialized.
pub fn popEvent() ?canonical.CanonicalEvent {
    if (!isInitialized()) return null;
    const ev = nose.popEvent() orelse return null;
    g_pop_count += 1;
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
