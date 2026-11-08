//! Pins the clock that every runtime duration mark depends on.
//!
//! `aegisctl queue` reports per-stage latency, and every consumer of that data
//! (QLOSS evidence, watchdog thresholds, throughput claims) is only as good as
//! the clock behind it. This file holds the guard so a future edit cannot quietly
//! switch the duration marks back to the coarse calendar clock.

const std = @import("std");
const clock = @import("../../reliability/monotonic_clock.zig");

test "duration marks are read from the high-resolution clock" {
    try std.testing.expect(clock.isHighResolution());
}

test "the calendar clock's tick is coarse enough to hide a pipeline sample" {
    // Documents the defect monotonically_clock.zig replaces, without asserting
    // a specific tick: on hosts where nanoTimestamp is already fine this simply
    // passes with a tiny step.
    var smallest: i128 = std.math.maxInt(i128);
    var i: usize = 0;
    while (i < 20_000) : (i += 1) {
        const a = std.time.nanoTimestamp();
        const b = std.time.nanoTimestamp();
        if (b > a and b - a < smallest) smallest = b - a;
    }
    try std.testing.expect(smallest > 0);

    // nowNs must be at least as fine: measure the same consecutive-read step.
    var smallest_hr: i128 = std.math.maxInt(i128);
    i = 0;
    while (i < 20_000) : (i += 1) {
        const a = clock.nowNs();
        const b = clock.nowNs();
        if (b > a and b - a < smallest_hr) smallest_hr = b - a;
    }
    try std.testing.expect(smallest_hr > 0);
    try std.testing.expect(smallest_hr <= smallest);
}
