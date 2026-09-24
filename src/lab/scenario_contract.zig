//! Phase 11 controlled-lab contract: bounded scenarios with cleanup proof.
const std = @import("std");

pub const ScenarioKind = enum(u8) { sql_marker, command_marker, xss_marker, traversal_marker, bounded_recon, file_canary, process_canary };
pub const ScenarioStatus = enum(u8) { planned, running, detected, blocked, completed, failed, cleaned };

pub const Scenario = struct {
    scenario_id: []const u8,
    kind: ScenarioKind,
    marker: []const u8,
    max_events: u32,
    requires_cleanup: bool = true,
};

pub const ScenarioResult = struct {
    scenario_id: []const u8,
    status: ScenarioStatus,
    matched_rule_id: u32 = 0,
    event_id: u64 = 0,
    enforcement_receipt_id: u64 = 0,
    cleanup_confirmed: bool = false,

    pub fn isComplete(self: ScenarioResult) bool {
        return (self.status == .completed or self.status == .cleaned) and self.cleanup_confirmed;
    }
};

test "lab scenario completion requires cleanup" {
    const result = ScenarioResult{ .scenario_id = "sql-001", .status = .completed, .event_id = 1 };
    try std.testing.expect(!result.isComplete());
    const cleaned = ScenarioResult{ .scenario_id = "sql-001", .status = .cleaned, .event_id = 1, .cleanup_confirmed = true };
    try std.testing.expect(cleaned.isComplete());
}
