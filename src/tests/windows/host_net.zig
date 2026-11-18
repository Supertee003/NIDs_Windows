// Aggregator test: runs unit tests from src/windows/host_net.zig and pins the
// observe-only boundary at the test-graph level (XDR-005-A).
const std = @import("std");
const host_net = @import("../../windows/host_net.zig");
const event = @import("../../contract/event.zig");

comptime {
    _ = @import("../../windows/host_net.zig");
}

test "host_net module imports cleanly" {
    try std.testing.expect(true);
}

test "host_net event projection stays an observation, not a detection" {
    var observed = host_net.Observed{ .family = .v4 };
    observed.local_addr = .{ 10, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    observed.local_port = 445;
    observed.remote_addr = .{ 10, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    observed.remote_port = 50000;
    observed.owning_pid = 4242;

    const ev = host_net.toIpcEvent(&observed);
    try std.testing.expectEqual(event.EventKind.host_socket_observed, ev.kind);
    try std.testing.expectEqual(event.EventSource.capture_host_net, ev.source);
    try std.testing.expectEqual(@as(u32, 0), ev.rule_id);
    try std.testing.expectEqual(@as(u32, 0), ev.flow_id);
    try std.testing.expectEqual(@as(u32, 0), ev.policy_id);
    try std.testing.expectEqual(event.EventSeverity.info, ev.severity);
}
