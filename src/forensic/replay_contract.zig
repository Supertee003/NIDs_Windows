//! Phase 9 replay contract: historical analysis must never enforce on host.
const std = @import("std");

pub const ReplayMode = enum(u8) { observe_only = 0, compare = 1, export_snapshot = 2 };

pub const ReplayRequest = struct {
    replay_id: u64,
    source_digest: []const u8,
    mode: ReplayMode,
    allow_host_mutation: bool = false,

    pub fn isSafe(self: ReplayRequest) bool {
        return !self.allow_host_mutation and self.source_digest.len > 0 and self.replay_id != 0;
    }
};

pub const ReplayOutcome = struct {
    replay_id: u64,
    processed: u64,
    matches: u64,
    diffs: u64,
    enforcement_attempts: u64 = 0,
    safe: bool = true,

    pub fn isObserveOnly(self: ReplayOutcome) bool {
        return self.safe and self.enforcement_attempts == 0;
    }
};

test "replay request rejects host mutation" {
    try std.testing.expect((ReplayRequest{ .replay_id = 1, .source_digest = "sha256:fixture", .mode = .observe_only }).isSafe());
    try std.testing.expect(!(ReplayRequest{ .replay_id = 1, .source_digest = "sha256:fixture", .mode = .observe_only, .allow_host_mutation = true }).isSafe());
}

test "replay outcome is observe-only when no enforcement occurred" {
    const outcome = ReplayOutcome{ .replay_id = 1, .processed = 10, .matches = 8, .diffs = 2 };
    try std.testing.expect(outcome.isObserveOnly());
}
