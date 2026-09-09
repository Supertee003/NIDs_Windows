// Aggregator test: runs unit tests from src/forensic/evidence_record.zig
const std = @import("std");

comptime {
    _ = @import("../../forensic/evidence_record.zig");
}

test "evidence_record module imports cleanly" {
    try std.testing.expect(true);
}
