//! fault_injection.zig - AEGIS Fault Injection (Rewrite Phase 25 / Manual Phase 23)
//!
//! Simulates subsystem failures to verify defined failure behavior.
//! Every fault has a defined response (fail-soft, fail-open, fail-closed).
//!
//! Architecture (Manual Section 31):
//!   Simulate: WFP unavailable, driver unavailable, queue full, Brain unavailable,
//!   RAG unavailable, policy malformed, IPC failure, PEP unavailable, disk full,
//!   forensic failure
//!
//! Exit Gate: Every failure has defined behavior.

const std = @import("std");

// ============================================================
// Constants
// ============================================================

pub const MAX_FAULTS: usize = 32;

// ============================================================
// Fault Type
// ============================================================

pub const FaultType = enum(u8) {
    wfp_unavailable = 0,
    driver_unavailable = 1,
    queue_full = 2,
    brain_unavailable = 3,
    rag_unavailable = 4,
    policy_malformed = 5,
    ipc_failure = 6,
    pep_unavailable = 7,
    disk_full = 8,
    forensic_failure = 9,

    pub fn toString(self: FaultType) []const u8 {
        return switch (self) {
            .wfp_unavailable => "WFP_UNAVAILABLE",
            .driver_unavailable => "DRIVER_UNAVAILABLE",
            .queue_full => "QUEUE_FULL",
            .brain_unavailable => "BRAIN_UNAVAILABLE",
            .rag_unavailable => "RAG_UNAVAILABLE",
            .policy_malformed => "POLICY_MALFORMED",
            .ipc_failure => "IPC_FAILURE",
            .pep_unavailable => "PEP_UNAVAILABLE",
            .disk_full => "DISK_FULL",
            .forensic_failure => "FORENSIC_FAILURE",
        };
    }

    /// Returns the expected failure behavior for this fault type.
    pub fn expectedBehavior(self: FaultType) FaultBehavior {
        return switch (self) {
            .wfp_unavailable => .fail_soft, // Continue without WFP, use other sensors
            .driver_unavailable => .fail_soft, // Continue without kernel driver
            .queue_full => .drop_low_priority, // Drop LOW priority, keep HIGH/NORMAL
            .brain_unavailable => .fail_soft, // System works without Brain (deterministic mode)
            .rag_unavailable => .fail_soft, // RAG is fail-soft by design
            .policy_malformed => .fail_closed, // If policy is broken, BLOCK unknown traffic
            .ipc_failure => .fail_soft, // Continue with degraded IPC
            .pep_unavailable => .fail_open, // If PEP is down, allow traffic (availability > security)
            .disk_full => .fail_soft, // Stop forensic logging, keep processing
            .forensic_failure => .fail_soft, // Continue without forensic recording
        };
    }

    /// Returns true if this fault is critical (affects enforcement).
    pub fn isCritical(self: FaultType) bool {
        return self == .policy_malformed or self == .pep_unavailable;
    }
};

// ============================================================
// Fault Behavior (expected response)
// ============================================================

pub const FaultBehavior = enum(u8) {
    /// System continues with degraded functionality.
    fail_soft = 0,
    /// System allows traffic through (availability > security).
    fail_open = 1,
    /// System blocks unknown traffic (security > availability).
    fail_closed = 2,
    /// Drop low-priority events, keep high-priority.
    drop_low_priority = 3,

    pub fn toString(self: FaultBehavior) []const u8 {
        return switch (self) {
            .fail_soft => "FAIL_SOFT",
            .fail_open => "FAIL_OPEN",
            .fail_closed => "FAIL_CLOSED",
            .drop_low_priority => "DROP_LOW_PRIORITY",
        };
    }

    pub fn isDegraded(self: FaultBehavior) bool {
        return self == .fail_soft or self == .drop_low_priority;
    }

    pub fn isPermissive(self: FaultBehavior) bool {
        return self == .fail_open;
    }

    pub fn isRestrictive(self: FaultBehavior) bool {
        return self == .fail_closed;
    }
};

// ============================================================
// Fault Status
// ============================================================

pub const FaultStatus = enum(u8) {
    /// Fault not active.
    inactive = 0,
    /// Fault injected, system responded correctly.
    handled = 1,
    /// Fault injected, system responded incorrectly.
    mishandled = 2,
    /// Fault injected, system crashed or hung.
    crashed = 3,
    /// Fault injected, system behavior undefined.
    undefined = 4,

    pub fn toString(self: FaultStatus) []const u8 {
        return switch (self) {
            .inactive => "INACTIVE",
            .handled => "HANDLED",
            .mishandled => "MISHANDLED",
            .crashed => "CRASHED",
            .undefined => "UNDEFINED",
        };
    }

    pub fn isHandled(self: FaultStatus) bool {
        return self == .handled;
    }

    pub fn isFailure(self: FaultStatus) bool {
        return self == .mishandled or self == .crashed or self == .undefined;
    }
};

// ============================================================
// Fault Result
// ============================================================

pub const FaultResult = struct {
    fault_type: FaultType,
    status: FaultStatus,
    expected_behavior: FaultBehavior,
    actual_behavior: FaultBehavior,
    description: []const u8,
    duration_ns: u64,

    pub fn isHandled(self: FaultResult) bool {
        return self.status == .handled and self.expected_behavior == self.actual_behavior;
    }

    pub fn isFailure(self: FaultResult) bool {
        return self.status.isFailure() or self.expected_behavior != self.actual_behavior;
    }
};

// ============================================================
// Active Fault (injected state)
// ============================================================

pub const ActiveFault = struct {
    fault_type: FaultType,
    injected_at_ns: u64,
    description: []const u8,
};

// ============================================================
// Fault Engine
// ============================================================

pub const FaultEngine = struct {
    active_faults: [MAX_FAULTS]ActiveFault,
    active_count: usize,
    /// Total faults injected (lifetime).
    total_injected: u64,
    /// Total faults handled correctly.
    total_handled: u64,
    /// Total faults mishandled.
    total_mishandled: u64,
    /// Total critical faults.
    total_critical: u64,

    pub fn init() FaultEngine {
        return .{
            .active_faults = undefined,
            .active_count = 0,
            .total_injected = 0,
            .total_handled = 0,
            .total_mishandled = 0,
            .total_critical = 0,
        };
    }

    /// Inject a fault. Returns true if injected successfully.
    pub fn injectFault(self: *FaultEngine, fault_type: FaultType, timestamp_ns: u64) bool {
        if (self.active_count >= MAX_FAULTS) return false;

        // Check if already active
        for (0..self.active_count) |i| {
            if (self.active_faults[i].fault_type == fault_type) return true;
        }

        self.active_faults[self.active_count] = .{
            .fault_type = fault_type,
            .injected_at_ns = timestamp_ns,
            .description = fault_type.toString(),
        };
        self.active_count += 1;
        self.total_injected += 1;
        if (fault_type.isCritical()) {
            self.total_critical += 1;
        }
        return true;
    }

    /// Resolve a fault (mark as handled).
    pub fn resolveFault(self: *FaultEngine, fault_type: FaultType, handled: bool) FaultResult {
        const expected = fault_type.expectedBehavior();

        var status: FaultStatus = .handled;
        if (!handled) {
            status = .mishandled;
        }

        // Remove from active faults
        var found = false;
        for (0..self.active_count) |i| {
            if (self.active_faults[i].fault_type == fault_type) {
                // Shift remaining
                var j = i;
                while (j < self.active_count - 1) : (j += 1) {
                    self.active_faults[j] = self.active_faults[j + 1];
                }
                self.active_count -= 1;
                found = true;
                break;
            }
        }

        if (found) {
            if (handled) {
                self.total_handled += 1;
            } else {
                self.total_mishandled += 1;
            }
        }

        return .{
            .fault_type = fault_type,
            .status = status,
            .expected_behavior = expected,
            .actual_behavior = if (handled) expected else .fail_open, // simplification
            .description = fault_type.toString(),
            .duration_ns = 0,
        };
    }

    /// Check if a specific fault is currently active.
    pub fn isFaultActive(self: *const FaultEngine, fault_type: FaultType) bool {
        for (0..self.active_count) |i| {
            if (self.active_faults[i].fault_type == fault_type) return true;
        }
        return false;
    }

    /// Count of currently active faults.
    pub fn activeCount(self: *const FaultEngine) usize {
        return self.active_count;
    }

    /// Get pass rate (0-100).
    pub fn passRate(self: *const FaultEngine) u8 {
        const total = self.total_handled + self.total_mishandled;
        if (total == 0) return 0;
        return @intCast((self.total_handled * 100) / total);
    }

    /// Clear all faults.
    pub fn clear(self: *FaultEngine) void {
        self.active_count = 0;
    }

    /// Reset all stats.
    pub fn reset(self: *FaultEngine) void {
        self.* = init();
    }
};

// ============================================================
// All Fault Types (for iteration)
// ============================================================

pub const ALL_FAULT_TYPES = [_]FaultType{
    .wfp_unavailable,
    .driver_unavailable,
    .queue_full,
    .brain_unavailable,
    .rag_unavailable,
    .policy_malformed,
    .ipc_failure,
    .pep_unavailable,
    .disk_full,
    .forensic_failure,
};

// ============================================================
// Tests
// ============================================================

test "FaultType.toString returns readable names" {
    try std.testing.expect(std.mem.eql(u8, FaultType.wfp_unavailable.toString(), "WFP_UNAVAILABLE"));
    try std.testing.expect(std.mem.eql(u8, FaultType.queue_full.toString(), "QUEUE_FULL"));
    try std.testing.expect(std.mem.eql(u8, FaultType.brain_unavailable.toString(), "BRAIN_UNAVAILABLE"));
    try std.testing.expect(std.mem.eql(u8, FaultType.rag_unavailable.toString(), "RAG_UNAVAILABLE"));
    try std.testing.expect(std.mem.eql(u8, FaultType.policy_malformed.toString(), "POLICY_MALFORMED"));
    try std.testing.expect(std.mem.eql(u8, FaultType.pep_unavailable.toString(), "PEP_UNAVAILABLE"));
    try std.testing.expect(std.mem.eql(u8, FaultType.disk_full.toString(), "DISK_FULL"));
    try std.testing.expect(std.mem.eql(u8, FaultType.forensic_failure.toString(), "FORENSIC_FAILURE"));
}

test "FaultType.isCritical" {
    try std.testing.expect(!FaultType.wfp_unavailable.isCritical());
    try std.testing.expect(!FaultType.queue_full.isCritical());
    try std.testing.expect(FaultType.policy_malformed.isCritical());
    try std.testing.expect(FaultType.pep_unavailable.isCritical());
}

test "FaultType.expectedBehavior returns correct behavior" {
    try std.testing.expect(FaultType.wfp_unavailable.expectedBehavior() == .fail_soft);
    try std.testing.expect(FaultType.queue_full.expectedBehavior() == .drop_low_priority);
    try std.testing.expect(FaultType.brain_unavailable.expectedBehavior() == .fail_soft);
    try std.testing.expect(FaultType.rag_unavailable.expectedBehavior() == .fail_soft);
    try std.testing.expect(FaultType.policy_malformed.expectedBehavior() == .fail_closed);
    try std.testing.expect(FaultType.pep_unavailable.expectedBehavior() == .fail_open);
    try std.testing.expect(FaultType.disk_full.expectedBehavior() == .fail_soft);
    try std.testing.expect(FaultType.forensic_failure.expectedBehavior() == .fail_soft);
}

test "FaultBehavior.toString returns readable names" {
    try std.testing.expect(std.mem.eql(u8, FaultBehavior.fail_soft.toString(), "FAIL_SOFT"));
    try std.testing.expect(std.mem.eql(u8, FaultBehavior.fail_open.toString(), "FAIL_OPEN"));
    try std.testing.expect(std.mem.eql(u8, FaultBehavior.fail_closed.toString(), "FAIL_CLOSED"));
    try std.testing.expect(std.mem.eql(u8, FaultBehavior.drop_low_priority.toString(), "DROP_LOW_PRIORITY"));
}

test "FaultBehavior.isDegraded, isPermissive, isRestrictive" {
    try std.testing.expect(FaultBehavior.fail_soft.isDegraded());
    try std.testing.expect(FaultBehavior.drop_low_priority.isDegraded());
    try std.testing.expect(!FaultBehavior.fail_open.isDegraded());

    try std.testing.expect(FaultBehavior.fail_open.isPermissive());
    try std.testing.expect(!FaultBehavior.fail_closed.isPermissive());

    try std.testing.expect(FaultBehavior.fail_closed.isRestrictive());
    try std.testing.expect(!FaultBehavior.fail_open.isRestrictive());
}

test "FaultStatus.toString returns readable names" {
    try std.testing.expect(std.mem.eql(u8, FaultStatus.inactive.toString(), "INACTIVE"));
    try std.testing.expect(std.mem.eql(u8, FaultStatus.handled.toString(), "HANDLED"));
    try std.testing.expect(std.mem.eql(u8, FaultStatus.mishandled.toString(), "MISHANDLED"));
    try std.testing.expect(std.mem.eql(u8, FaultStatus.crashed.toString(), "CRASHED"));
}

test "FaultStatus.isHandled and isFailure" {
    try std.testing.expect(FaultStatus.handled.isHandled());
    try std.testing.expect(!FaultStatus.mishandled.isHandled());

    try std.testing.expect(FaultStatus.mishandled.isFailure());
    try std.testing.expect(FaultStatus.crashed.isFailure());
    try std.testing.expect(!FaultStatus.handled.isFailure());
}

test "FaultResult.isHandled and isFailure" {
    const handled = FaultResult{
        .fault_type = .wfp_unavailable,
        .status = .handled,
        .expected_behavior = .fail_soft,
        .actual_behavior = .fail_soft,
        .description = "test",
        .duration_ns = 1000,
    };
    try std.testing.expect(handled.isHandled());
    try std.testing.expect(!handled.isFailure());

    const failed = FaultResult{
        .fault_type = .wfp_unavailable,
        .status = .mishandled,
        .expected_behavior = .fail_soft,
        .actual_behavior = .fail_open,
        .description = "test",
        .duration_ns = 1000,
    };
    try std.testing.expect(!failed.isHandled());
    try std.testing.expect(failed.isFailure());
}

test "FaultEngine init has zero stats" {
    const engine = FaultEngine.init();
    try std.testing.expect(engine.active_count == 0);
    try std.testing.expect(engine.total_injected == 0);
}

test "FaultEngine injectFault adds fault" {
    var engine = FaultEngine.init();
    try std.testing.expect(engine.injectFault(.wfp_unavailable, 1000));
    try std.testing.expect(engine.activeCount() == 1);
    try std.testing.expect(engine.isFaultActive(.wfp_unavailable));
    try std.testing.expect(engine.total_injected == 1);
}

test "FaultEngine injectFault is idempotent for same type" {
    var engine = FaultEngine.init();
    try std.testing.expect(engine.injectFault(.queue_full, 1000));
    try std.testing.expect(engine.injectFault(.queue_full, 2000)); // already active
    try std.testing.expect(engine.activeCount() == 1); // still 1
    try std.testing.expect(engine.total_injected == 1);
}

test "FaultEngine injectFault tracks critical" {
    var engine = FaultEngine.init();
    _ = engine.injectFault(.wfp_unavailable, 1000);
    _ = engine.injectFault(.policy_malformed, 2000);
    try std.testing.expect(engine.total_critical == 1); // only policy_malformed
}

test "FaultEngine resolveFault removes fault" {
    var engine = FaultEngine.init();
    _ = engine.injectFault(.wfp_unavailable, 1000);
    try std.testing.expect(engine.activeCount() == 1);

    const result = engine.resolveFault(.wfp_unavailable, true);
    try std.testing.expect(result.isHandled());
    try std.testing.expect(engine.activeCount() == 0);
    try std.testing.expect(!engine.isFaultActive(.wfp_unavailable));
    try std.testing.expect(engine.total_handled == 1);
}

test "FaultEngine resolveFault tracks mishandled" {
    var engine = FaultEngine.init();
    _ = engine.injectFault(.pep_unavailable, 1000);

    const result = engine.resolveFault(.pep_unavailable, false);
    try std.testing.expect(!result.isHandled());
    try std.testing.expect(engine.total_mishandled == 1);
}

test "FaultEngine isFaultActive" {
    var engine = FaultEngine.init();
    try std.testing.expect(!engine.isFaultActive(.queue_full));

    _ = engine.injectFault(.queue_full, 1000);
    try std.testing.expect(engine.isFaultActive(.queue_full));
    try std.testing.expect(!engine.isFaultActive(.wfp_unavailable));
}

test "FaultEngine multiple faults" {
    var engine = FaultEngine.init();
    _ = engine.injectFault(.wfp_unavailable, 1000);
    _ = engine.injectFault(.queue_full, 2000);
    _ = engine.injectFault(.brain_unavailable, 3000);
    try std.testing.expect(engine.activeCount() == 3);

    _ = engine.resolveFault(.queue_full, true);
    try std.testing.expect(engine.activeCount() == 2);
    try std.testing.expect(engine.isFaultActive(.wfp_unavailable));
    try std.testing.expect(!engine.isFaultActive(.queue_full));
    try std.testing.expect(engine.isFaultActive(.brain_unavailable));
}

test "FaultEngine passRate" {
    var engine = FaultEngine.init();
    engine.total_handled = 8;
    engine.total_mishandled = 2;
    try std.testing.expect(engine.passRate() == 80); // 8/10 = 80%
}

test "FaultEngine clear removes active faults" {
    var engine = FaultEngine.init();
    _ = engine.injectFault(.wfp_unavailable, 1000);
    _ = engine.injectFault(.queue_full, 2000);
    try std.testing.expect(engine.activeCount() == 2);

    engine.clear();
    try std.testing.expect(engine.activeCount() == 0);
    try std.testing.expect(engine.total_injected == 2); // lifetime not reset
}

test "FaultEngine reset zeroes everything" {
    var engine = FaultEngine.init();
    _ = engine.injectFault(.wfp_unavailable, 1000);
    _ = engine.resolveFault(.wfp_unavailable, true);
    try std.testing.expect(engine.total_injected == 1);

    engine.reset();
    try std.testing.expect(engine.total_injected == 0);
    try std.testing.expect(engine.total_handled == 0);
}

test "ALL_FAULT_TYPES has 10 types" {
    try std.testing.expect(ALL_FAULT_TYPES.len == 10);
}

test "ALL_FAULT_TYPES covers all enum values" {
    var seen = [_]bool{false} ** 10;
    for (ALL_FAULT_TYPES) |ft| {
        seen[@intFromEnum(ft)] = true;
    }
    for (seen) |s| {
        try std.testing.expect(s);
    }
}

test "every fault type has defined behavior" {
    for (ALL_FAULT_TYPES) |ft| {
        const behavior = ft.expectedBehavior();
        // Every behavior should be one of the 4 defined values
        _ = behavior.toString(); // should not crash
    }
}
