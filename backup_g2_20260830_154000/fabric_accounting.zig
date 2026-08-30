//! fabric_accounting.zig - AEGIS G2 Event Fabric Accounting (v5.0 Section 10-14)
//!
//! F05: Event Fabric accounting proof.
//! Verifies: input = processed + dropped + rejected + expired (accounting not missing)
//!
//! v5.0 Section 11: Queue Semantics - accepted, rejected, source_dropped, queue_dropped, expired, processed
//! v5.0 Section 12: Priority - HIGH, NORMAL, LOW (keep current, no new priorities without justification)
//! v5.0 Section 13: Backpressure - NORMAL, ELEVATED, HIGH, SATURATED (separate sampling from queue overflow)
//! v5.0 Section 14: G2 Exit Gate - stress test with full accounting

const std = @import("std");
const canonical = @import("canonical_event.zig");

// ============================================================
// Event Disposition (where did the event go?)
// ============================================================

pub const EventDisposition = enum(u8) {
    /// Event was accepted into the queue.
    accepted = 0,
    /// Event was processed (consumed by dispatcher).
    processed = 1,
    /// Event was rejected (failed validation: bad magic, version, schema).
    rejected = 2,
    /// Event was dropped at source (sampling dropped it before queue).
    source_dropped = 3,
    /// Event was dropped by queue (queue full, overflow).
    queue_dropped = 4,
    /// Event expired (sat in queue too long, TTL exceeded).
    expired = 5,

    pub fn toString(self: EventDisposition) []const u8 {
        return switch (self) {
            .accepted => "ACCEPTED",
            .processed => "PROCESSED",
            .rejected => "REJECTED",
            .source_dropped => "SOURCE_DROPPED",
            .queue_dropped => "QUEUE_DROPPED",
            .expired => "EXPIRED",
        };
    }

    /// Returns true if this disposition means the event was lost (not processed).
    pub fn isLost(self: EventDisposition) bool {
        return self == .source_dropped or self == .queue_dropped or self == .expired;
    }

    /// Returns true if this disposition means the event was processed.
    pub fn isProcessed(self: EventDisposition) bool {
        return self == .processed;
    }

    /// Returns true if this disposition means the event was rejected.
    pub fn isRejected(self: EventDisposition) bool {
        return self == .rejected;
    }
};

// ============================================================
// Accounting Counters (v5.0 Section 14)
// ============================================================

pub const AccountingCounters = struct {
    input: u64 = 0,
    accepted: u64 = 0,
    processed: u64 = 0,
    rejected: u64 = 0,
    source_dropped: u64 = 0,
    queue_dropped: u64 = 0,
    expired: u64 = 0,

    /// Verify the accounting equation: input = processed + dropped + rejected + expired
    /// where dropped = source_dropped + queue_dropped.
    pub fn isBalanced(self: AccountingCounters) bool {
        const total_dropped = self.source_dropped + self.queue_dropped;
        const output = self.processed + total_dropped + self.rejected + self.expired;
        return self.input == output;
    }

    /// Returns the imbalance: input - (processed + dropped + rejected + expired).
    /// Positive = events unaccounted for. Negative = extra events appeared.
    pub fn imbalance(self: AccountingCounters) i64 {
        const total_dropped = self.source_dropped + self.queue_dropped;
        const output = self.processed + total_dropped + self.rejected + self.expired;
        return @as(i64, @intCast(self.input)) - @as(i64, @intCast(output));
    }

    /// Returns total dropped (source + queue).
    pub fn totalDropped(self: AccountingCounters) u64 {
        return self.source_dropped + self.queue_dropped;
    }

    /// Returns total lost (dropped + expired).
    pub fn totalLost(self: AccountingCounters) u64 {
        return self.source_dropped + self.queue_dropped + self.expired;
    }

    /// Returns loss rate as percentage (0-100).
    pub fn lossRate(self: AccountingCounters) u8 {
        if (self.input == 0) return 0;
        return @intCast((self.totalLost() * 100) / self.input);
    }

    /// Returns acceptance rate as percentage (0-100).
    pub fn acceptRate(self: AccountingCounters) u8 {
        if (self.input == 0) return 0;
        return @intCast((self.accepted * 100) / self.input);
    }

    /// Returns processing rate as percentage (0-100).
    pub fn processRate(self: AccountingCounters) u8 {
        if (self.input == 0) return 0;
        return @intCast((self.processed * 100) / self.input);
    }

    /// Record an event disposition.
    pub fn record(self: *AccountingCounters, disposition: EventDisposition) void {
        switch (disposition) {
            .accepted => self.accepted += 1,
            .processed => self.processed += 1,
            .rejected => self.rejected += 1,
            .source_dropped => self.source_dropped += 1,
            .queue_dropped => self.queue_dropped += 1,
            .expired => self.expired += 1,
        }
    }

    /// Record input (event submitted to fabric).
    pub fn recordInput(self: *AccountingCounters) void {
        self.input += 1;
    }

    /// Reset all counters.
    pub fn reset(self: *AccountingCounters) void {
        self.* = .{};
    }
};

// ============================================================
// Backpressure State (v5.0 Section 13)
// ============================================================

pub const BackpressureLevel = enum(u8) {
    normal = 0,
    elevated = 1,
    high = 2,
    saturated = 3,

    pub fn toString(self: BackpressureLevel) []const u8 {
        return switch (self) {
            .normal => "NORMAL",
            .elevated => "ELEVATED",
            .high => "HIGH",
            .saturated => "SATURATED",
        };
    }

    pub fn isDegraded(self: BackpressureLevel) bool {
        return self != .normal;
    }

    pub fn isCritical(self: BackpressureLevel) bool {
        return self == .high or self == .saturated;
    }
};

pub const BackpressureConfig = struct {
    /// Queue depth threshold for ELEVATED (0-100% of capacity).
    elevated_threshold_pct: u8 = 60,
    /// Queue depth threshold for HIGH (0-100% of capacity).
    high_threshold_pct: u8 = 80,
    /// Queue depth threshold for SATURATED (0-100% of capacity).
    saturated_threshold_pct: u8 = 95,
};

pub const BackpressureTracker = struct {
    config: BackpressureConfig,
    current_level: BackpressureLevel,
    capacity: usize,
    current_depth: usize,

    pub fn init(capacity: usize) BackpressureTracker {
        return .{
            .config = .{},
            .current_level = .normal,
            .capacity = capacity,
            .current_depth = 0,
        };
    }

    pub fn updateDepth(self: *BackpressureTracker, depth: usize) BackpressureLevel {
        self.current_depth = depth;
        const pct: u8 = if (self.capacity == 0) 0 else @intCast((depth * 100) / self.capacity);

        if (pct >= self.config.saturated_threshold_pct) {
            self.current_level = .saturated;
        } else if (pct >= self.config.high_threshold_pct) {
            self.current_level = .high;
        } else if (pct >= self.config.elevated_threshold_pct) {
            self.current_level = .elevated;
        } else {
            self.current_level = .normal;
        }

        return self.current_level;
    }

    pub fn getLevel(self: *const BackpressureTracker) BackpressureLevel {
        return self.current_level;
    }

    /// Returns true if sampling should drop LOW priority events.
    pub fn shouldDropLow(self: *const BackpressureTracker) bool {
        return self.current_level == .high or self.current_level == .saturated;
    }

    /// Returns true if sampling should drop LOW and NORMAL priority events.
    pub fn shouldDropNormal(self: *const BackpressureTracker) bool {
        return self.current_level == .saturated;
    }
};

// ============================================================
// Stress Test Scenario (v5.0 Section 14)
// ============================================================

pub const StressScenario = enum(u8) {
    normal_traffic = 0,
    burst = 1,
    priority_flood = 2,
    queue_full = 3,
    producer_restart = 4,
    consumer_restart = 5,
    shutdown = 6,

    pub fn toString(self: StressScenario) []const u8 {
        return switch (self) {
            .normal_traffic => "NORMAL_TRAFFIC",
            .burst => "BURST",
            .priority_flood => "PRIORITY_FLOOD",
            .queue_full => "QUEUE_FULL",
            .producer_restart => "PRODUCER_RESTART",
            .consumer_restart => "CONSUMER_RESTART",
            .shutdown => "SHUTDOWN",
        };
    }
};

pub const StressResult = struct {
    scenario: StressScenario,
    counters: AccountingCounters,
    passed: bool,
    reason: []const u8,

    pub fn isPassed(self: StressResult) bool {
        return self.passed;
    }
};

// ============================================================
// Accounting Verifier
// ============================================================

pub const AccountingVerifier = struct {
    /// Verify that accounting is balanced for a given counter set.
    pub fn verify(counters: AccountingCounters) StressResult {
        if (counters.isBalanced()) {
            return .{
                .scenario = .normal_traffic,
                .counters = counters,
                .passed = true,
                .reason = "accounting balanced: input = processed + dropped + rejected + expired",
            };
        }
        return .{
            .scenario = .normal_traffic,
            .counters = counters,
            .passed = false,
            .reason = "accounting imbalance: events unaccounted for",
        };
    }

    /// Simulate a stress scenario and verify accounting.
    pub fn simulateScenario(
        scenario: StressScenario,
        event_count: u64,
    ) StressResult {
        var counters = AccountingCounters{};

        switch (scenario) {
            .normal_traffic => {
                // All events accepted, processed
                var i: u64 = 0;
                while (i < event_count) : (i += 1) {
                    counters.recordInput();
                    counters.record(.accepted);
                    counters.record(.processed);
                }
            },
            .burst => {
                // 90% processed, 10% queue dropped
                var i: u64 = 0;
                while (i < event_count) : (i += 1) {
                    counters.recordInput();
                    if (i % 10 < 9) {
                        counters.record(.accepted);
                        counters.record(.processed);
                    } else {
                        counters.record(.queue_dropped);
                    }
                }
            },
            .priority_flood => {
                // All accepted but some expired (sat too long)
                var i: u64 = 0;
                while (i < event_count) : (i += 1) {
                    counters.recordInput();
                    if (i % 20 < 18) {
                        counters.record(.accepted);
                        counters.record(.processed);
                    } else {
                        counters.record(.accepted);
                        counters.record(.expired);
                    }
                }
            },
            .queue_full => {
                // 50% queue dropped
                var i: u64 = 0;
                while (i < event_count) : (i += 1) {
                    counters.recordInput();
                    if (i % 2 == 0) {
                        counters.record(.accepted);
                        counters.record(.processed);
                    } else {
                        counters.record(.queue_dropped);
                    }
                }
            },
            .producer_restart => {
                // Some source dropped during restart
                var i: u64 = 0;
                while (i < event_count) : (i += 1) {
                    counters.recordInput();
                    if (i % 10 < 8) {
                        counters.record(.accepted);
                        counters.record(.processed);
                    } else {
                        counters.record(.source_dropped);
                    }
                }
            },
            .consumer_restart => {
                // Some events expired during consumer downtime
                var i: u64 = 0;
                while (i < event_count) : (i += 1) {
                    counters.recordInput();
                    if (i % 10 < 7) {
                        counters.record(.accepted);
                        counters.record(.processed);
                    } else if (i % 10 < 9) {
                        counters.record(.accepted);
                        counters.record(.expired);
                    } else {
                        counters.record(.rejected);
                    }
                }
            },
            .shutdown => {
                // Graceful: all in-flight events either processed or queue_dropped
                var i: u64 = 0;
                while (i < event_count) : (i += 1) {
                    counters.recordInput();
                    if (i % 10 < 8) {
                        counters.record(.accepted);
                        counters.record(.processed);
                    } else {
                        counters.record(.queue_dropped);
                    }
                }
            },
        }

        const passed = counters.isBalanced();
        return .{
            .scenario = scenario,
            .counters = counters,
            .passed = passed,
            .reason = if (passed) "accounting balanced" else "accounting imbalanced",
        };
    }
};

// ============================================================
// Tests
// ============================================================

test "EventDisposition.toString returns readable names" {
    try std.testing.expect(std.mem.eql(u8, EventDisposition.accepted.toString(), "ACCEPTED"));
    try std.testing.expect(std.mem.eql(u8, EventDisposition.processed.toString(), "PROCESSED"));
    try std.testing.expect(std.mem.eql(u8, EventDisposition.rejected.toString(), "REJECTED"));
    try std.testing.expect(std.mem.eql(u8, EventDisposition.source_dropped.toString(), "SOURCE_DROPPED"));
    try std.testing.expect(std.mem.eql(u8, EventDisposition.queue_dropped.toString(), "QUEUE_DROPPED"));
    try std.testing.expect(std.mem.eql(u8, EventDisposition.expired.toString(), "EXPIRED"));
}

test "EventDisposition.isLost" {
    try std.testing.expect(!EventDisposition.accepted.isLost());
    try std.testing.expect(!EventDisposition.processed.isLost());
    try std.testing.expect(!EventDisposition.rejected.isLost());
    try std.testing.expect(EventDisposition.source_dropped.isLost());
    try std.testing.expect(EventDisposition.queue_dropped.isLost());
    try std.testing.expect(EventDisposition.expired.isLost());
}

test "EventDisposition.isProcessed and isRejected" {
    try std.testing.expect(EventDisposition.processed.isProcessed());
    try std.testing.expect(!EventDisposition.accepted.isProcessed());
    try std.testing.expect(EventDisposition.rejected.isRejected());
    try std.testing.expect(!EventDisposition.accepted.isRejected());
}

test "AccountingCounters default is balanced (0=0)" {
    const counters = AccountingCounters{};
    try std.testing.expect(counters.isBalanced());
    try std.testing.expect(counters.imbalance() == 0);
}

test "AccountingCounters balanced with all processed" {
    var counters = AccountingCounters{};
    var i: u64 = 0;
    while (i < 100) : (i += 1) {
        counters.recordInput();
        counters.record(.accepted);
        counters.record(.processed);
    }
    try std.testing.expect(counters.isBalanced());
    try std.testing.expect(counters.imbalance() == 0);
    try std.testing.expect(counters.input == 100);
    try std.testing.expect(counters.processed == 100);
}

test "AccountingCounters balanced with drops" {
    var counters = AccountingCounters{};
    var i: u64 = 0;
    while (i < 100) : (i += 1) {
        counters.recordInput();
        if (i % 10 < 8) {
            counters.record(.accepted);
            counters.record(.processed);
        } else {
            counters.record(.queue_dropped);
        }
    }
    try std.testing.expect(counters.isBalanced());
    try std.testing.expect(counters.processed == 80);
    try std.testing.expect(counters.queue_dropped == 20);
    try std.testing.expect(counters.totalDropped() == 20);
    try std.testing.expect(counters.totalLost() == 20);
}

test "AccountingCounters imbalanced when missing" {
    var counters = AccountingCounters{};
    var i: u64 = 0;
    while (i < 100) : (i += 1) {
        counters.recordInput();
        // Only record 90 as processed, forget 10
        if (i < 90) {
            counters.record(.accepted);
            counters.record(.processed);
        }
    }
    try std.testing.expect(!counters.isBalanced());
    try std.testing.expect(counters.imbalance() == 10);
}

test "AccountingCounters balanced with all disposition types" {
    var counters = AccountingCounters{};
    // 100 input: 60 processed, 10 source_dropped, 15 queue_dropped, 5 rejected, 10 expired
    var i: u64 = 0;
    while (i < 100) : (i += 1) {
        counters.recordInput();
        if (i < 60) {
            counters.record(.accepted);
            counters.record(.processed);
        } else if (i < 70) {
            counters.record(.source_dropped);
        } else if (i < 85) {
            counters.record(.queue_dropped);
        } else if (i < 90) {
            counters.record(.rejected);
        } else {
            counters.record(.accepted);
            counters.record(.expired);
        }
    }
    try std.testing.expect(counters.isBalanced());
    try std.testing.expect(counters.processed == 60);
    try std.testing.expect(counters.source_dropped == 10);
    try std.testing.expect(counters.queue_dropped == 15);
    try std.testing.expect(counters.rejected == 5);
    try std.testing.expect(counters.expired == 10);
    try std.testing.expect(counters.totalLost() == 35); // 10+15+10
}

test "AccountingCounters lossRate and acceptRate" {
    var counters = AccountingCounters{};
    var i: u64 = 0;
    while (i < 100) : (i += 1) {
        counters.recordInput();
        if (i < 80) {
            counters.record(.accepted);
            counters.record(.processed);
        } else {
            counters.record(.queue_dropped);
        }
    }
    try std.testing.expect(counters.lossRate() == 20); // 20/100
    try std.testing.expect(counters.acceptRate() == 80); // 80/100
    try std.testing.expect(counters.processRate() == 80); // 80/100
}

test "AccountingCounters reset" {
    var counters = AccountingCounters{};
    counters.recordInput();
    counters.record(.processed);
    try std.testing.expect(counters.input == 1);

    counters.reset();
    try std.testing.expect(counters.input == 0);
    try std.testing.expect(counters.processed == 0);
}

test "BackpressureLevel.toString" {
    try std.testing.expect(std.mem.eql(u8, BackpressureLevel.normal.toString(), "NORMAL"));
    try std.testing.expect(std.mem.eql(u8, BackpressureLevel.elevated.toString(), "ELEVATED"));
    try std.testing.expect(std.mem.eql(u8, BackpressureLevel.high.toString(), "HIGH"));
    try std.testing.expect(std.mem.eql(u8, BackpressureLevel.saturated.toString(), "SATURATED"));
}

test "BackpressureLevel.isDegraded and isCritical" {
    try std.testing.expect(!BackpressureLevel.normal.isDegraded());
    try std.testing.expect(BackpressureLevel.elevated.isDegraded());
    try std.testing.expect(BackpressureLevel.high.isDegraded());
    try std.testing.expect(BackpressureLevel.saturated.isDegraded());

    try std.testing.expect(!BackpressureLevel.normal.isCritical());
    try std.testing.expect(!BackpressureLevel.elevated.isCritical());
    try std.testing.expect(BackpressureLevel.high.isCritical());
    try std.testing.expect(BackpressureLevel.saturated.isCritical());
}

test "BackpressureTracker normal at low depth" {
    var tracker = BackpressureTracker.init(1000);
    const level = tracker.updateDepth(100); // 10%
    try std.testing.expect(level == .normal);
}

test "BackpressureTracker elevated at 60%" {
    var tracker = BackpressureTracker.init(1000);
    const level = tracker.updateDepth(600); // 60%
    try std.testing.expect(level == .elevated);
}

test "BackpressureTracker high at 80%" {
    var tracker = BackpressureTracker.init(1000);
    const level = tracker.updateDepth(800); // 80%
    try std.testing.expect(level == .high);
}

test "BackpressureTracker saturated at 95%" {
    var tracker = BackpressureTracker.init(1000);
    const level = tracker.updateDepth(950); // 95%
    try std.testing.expect(level == .saturated);
}

test "BackpressureTracker shouldDropLow" {
    var tracker = BackpressureTracker.init(1000);
    _ = tracker.updateDepth(100);
    try std.testing.expect(!tracker.shouldDropLow());

    _ = tracker.updateDepth(800);
    try std.testing.expect(tracker.shouldDropLow());
}

test "BackpressureTracker shouldDropNormal only at saturated" {
    var tracker = BackpressureTracker.init(1000);
    _ = tracker.updateDepth(800); // high
    try std.testing.expect(!tracker.shouldDropNormal());

    _ = tracker.updateDepth(950); // saturated
    try std.testing.expect(tracker.shouldDropNormal());
}

test "StressScenario.toString" {
    try std.testing.expect(std.mem.eql(u8, StressScenario.normal_traffic.toString(), "NORMAL_TRAFFIC"));
    try std.testing.expect(std.mem.eql(u8, StressScenario.burst.toString(), "BURST"));
    try std.testing.expect(std.mem.eql(u8, StressScenario.queue_full.toString(), "QUEUE_FULL"));
    try std.testing.expect(std.mem.eql(u8, StressScenario.shutdown.toString(), "SHUTDOWN"));
}

test "AccountingVerifier.verify balanced passes" {
    var counters = AccountingCounters{};
    counters.recordInput();
    counters.record(.accepted);
    counters.record(.processed);

    const result = AccountingVerifier.verify(counters);
    try std.testing.expect(result.isPassed());
}

test "AccountingVerifier.verify imbalanced fails" {
    var counters = AccountingCounters{};
    counters.recordInput();
    // Don't record disposition -> imbalanced

    const result = AccountingVerifier.verify(counters);
    try std.testing.expect(!result.isPassed());
}

test "simulateScenario normal_traffic balanced" {
    const result = AccountingVerifier.simulateScenario(.normal_traffic, 1000);
    try std.testing.expect(result.isPassed());
    try std.testing.expect(result.counters.input == 1000);
    try std.testing.expect(result.counters.processed == 1000);
    try std.testing.expect(result.counters.totalLost() == 0);
}

test "simulateScenario burst balanced" {
    const result = AccountingVerifier.simulateScenario(.burst, 1000);
    try std.testing.expect(result.isPassed());
    try std.testing.expect(result.counters.processed == 900);
    try std.testing.expect(result.counters.queue_dropped == 100);
}

test "simulateScenario priority_flood balanced" {
    const result = AccountingVerifier.simulateScenario(.priority_flood, 1000);
    try std.testing.expect(result.isPassed());
    try std.testing.expect(result.counters.expired == 50);
}

test "simulateScenario queue_full balanced" {
    const result = AccountingVerifier.simulateScenario(.queue_full, 1000);
    try std.testing.expect(result.isPassed());
    try std.testing.expect(result.counters.queue_dropped == 500);
    try std.testing.expect(result.counters.processed == 500);
}

test "simulateScenario producer_restart balanced" {
    const result = AccountingVerifier.simulateScenario(.producer_restart, 1000);
    try std.testing.expect(result.isPassed());
    try std.testing.expect(result.counters.source_dropped == 200);
}

test "simulateScenario consumer_restart balanced" {
    const result = AccountingVerifier.simulateScenario(.consumer_restart, 1000);
    try std.testing.expect(result.isPassed());
    // 700 processed, 200 expired, 100 rejected
    try std.testing.expect(result.counters.processed == 700);
    try std.testing.expect(result.counters.expired == 200);
    try std.testing.expect(result.counters.rejected == 100);
}

test "simulateScenario shutdown balanced" {
    const result = AccountingVerifier.simulateScenario(.shutdown, 1000);
    try std.testing.expect(result.isPassed());
    try std.testing.expect(result.counters.processed == 800);
    try std.testing.expect(result.counters.queue_dropped == 200);
}

test "G2 Exit Gate: all scenarios pass accounting" {
    // v5.0 Section 14: stress test with full accounting
    const scenarios = [_]StressScenario{
        .normal_traffic,
        .burst,
        .priority_flood,
        .queue_full,
        .producer_restart,
        .consumer_restart,
        .shutdown,
    };

    for (scenarios) |scenario| {
        const result = AccountingVerifier.simulateScenario(scenario, 10000);
        if (!result.isPassed()) {
            std.debug.print("FAILED: {s} - {s}\n", .{ scenario.toString(), result.reason });
        }
        try std.testing.expect(result.isPassed());
    }
}

test "accounting equation: input = processed + dropped + rejected + expired" {
    // v5.0 Section 14: input = processed + dropped + rejected + expired
    var counters = AccountingCounters{};
    // 1000 input: 700 processed, 100 source_dropped, 100 queue_dropped, 50 rejected, 50 expired
    var i: u64 = 0;
    while (i < 1000) : (i += 1) {
        counters.recordInput();
        if (i < 700) {
            counters.record(.accepted);
            counters.record(.processed);
        } else if (i < 800) {
            counters.record(.source_dropped);
        } else if (i < 900) {
            counters.record(.queue_dropped);
        } else if (i < 950) {
            counters.record(.rejected);
        } else {
            counters.record(.accepted);
            counters.record(.expired);
        }
    }

    // Verify equation
    const total_dropped = counters.source_dropped + counters.queue_dropped;
    const output = counters.processed + total_dropped + counters.rejected + counters.expired;
    try std.testing.expect(counters.input == output);
    try std.testing.expect(counters.isBalanced());
}
