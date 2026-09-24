//! Phase 10 operator contract: explicit recovery intent and postconditions.
const std = @import("std");

pub const Operation = enum(u8) { preflight, status, health, start, stop, restart, snapshot, rollback, export_snapshot };
pub const Outcome = enum(u8) { requested, accepted, completed, failed, unavailable, rolled_back };

pub const RecoveryRequest = struct {
    request_id: u64,
    operation: Operation,
    target: []const u8,
    reason: []const u8 = "",
    expected_state: []const u8 = "",
    dry_run: bool = false,
};

pub const RecoveryResult = struct {
    request_id: u64,
    operation: Operation,
    outcome: Outcome,
    resulting_state: []const u8,
    postcondition_proven: bool = false,
    message: []const u8 = "",

    pub fn isSuccessful(self: RecoveryResult) bool {
        return self.outcome == .completed and self.postcondition_proven;
    }
};

test "operator result requires a proven postcondition" {
    const pending = RecoveryResult{ .request_id = 1, .operation = .restart, .outcome = .accepted, .resulting_state = "STARTING" };
    try std.testing.expect(!pending.isSuccessful());
    const done = RecoveryResult{ .request_id = 1, .operation = .restart, .outcome = .completed, .resulting_state = "RUNNING", .postcondition_proven = true };
    try std.testing.expect(done.isSuccessful());
}
