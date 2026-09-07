// Aggregator test: runs unit tests from src/capture/npcap_adapter.zig
const std = @import("std");

comptime {
    _ = @import("../../capture/npcap_adapter.zig");
}

test "npcap_adapter module imports cleanly" {
    try std.testing.expect(true);
}
