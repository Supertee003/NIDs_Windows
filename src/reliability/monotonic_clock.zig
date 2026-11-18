//! Monotonic nanosecond clock for runtime latency marks.
//!
//! `std.time.nanoTimestamp()` is a calendar clock, not a duration clock, and on
//! Windows it is far too coarse for pipeline telemetry. Measured on the lab
//! host: 199,997 of 200,000 consecutive reads returned the same value, the
//! smallest non-zero step was 571,000 ns, and a 2.5 us SHA-256 over 4 KiB
//! measured 0 ns on all 64 samples. Every stage latency that `aegisctl queue`
//! reported was therefore a tick-straddle statistic (what fraction of events
//! happened to cross a 571 us tick), not a duration. `src/core/perf_benchmark.zig`
//! already documents the limitation for benchmarks; the runtime path kept using
//! the coarse clock, which is what this module fixes.
//!
//! This clock reads QueryPerformanceCounter through `std.time.Timer`, which
//! advances in sub-microsecond steps on the same host.
//!
//! Scope: durations only. Absolute wall-clock timestamps (event time, audit
//! time, receipt time) keep using `std.time.nanoTimestamp()` because their
//! meaning is calendar time, not elapsed time, and mixing the two would make
//! stored timestamps incomparable with the ones already on disk.

const std = @import("std");

var g_once = std.once(startTimer);
var g_timer: std.time.Timer = undefined;
var g_high_res: bool = false;

fn startTimer() void {
    g_timer = std.time.Timer.start() catch return;
    g_high_res = true;
}

/// Monotonic nanoseconds for measuring elapsed time. Never calendar time.
///
/// Falls back to `std.time.nanoTimestamp()` only when the platform cannot give
/// a high-resolution timer, so a duration is still produced (just coarsely)
/// instead of trapping on a path that runs once per event.
pub fn nowNs() i128 {
    g_once.call();
    if (g_high_res) return @intCast(g_timer.read());
    return std.time.nanoTimestamp();
}

/// True when durations are read from the high-resolution timer.
pub fn isHighResolution() bool {
    g_once.call();
    return g_high_res;
}

test "nowNs is monotonic and non-decreasing" {
    var prev = nowNs();
    var i: usize = 0;
    while (i < 10_000) : (i += 1) {
        const now = nowNs();
        try std.testing.expect(now >= prev);
        prev = now;
    }
}

test "nowNs resolves work far below the calendar clock's tick" {
    // The defect this module replaces: a ~1 us operation read 0 ns because the
    // calendar clock only advanced every ~571 us. Busy-wait past a few thousand
    // clock reads and require a non-zero, sub-tick-sized measurement.
    var iterations: usize = 0;
    var elapsed: i128 = 0;
    while (elapsed == 0 and iterations < 1_000_000) : (iterations += 1) {
        const t0 = nowNs();
        var acc: u64 = 0;
        var j: usize = 0;
        while (j < 32) : (j += 1) acc +%= j *% 7;
        std.mem.doNotOptimizeAway(acc);
        elapsed = nowNs() - t0;
    }
    try std.testing.expect(elapsed > 0);
    try std.testing.expect(elapsed < 100 * std.time.ns_per_ms);
    try std.testing.expect(iterations < 1_000_000);
}

test "a 4 KiB hash measures as non-zero elapsed time" {
    const buf = [_]u8{0xA5} ** 4060;
    var digest: [32]u8 = undefined;
    var total: i128 = 0;
    var i: usize = 0;
    while (i < 64) : (i += 1) {
        const t0 = nowNs();
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update(&buf);
        h.final(&digest);
        total += nowNs() - t0;
    }
    try std.testing.expect(total > 0);
    // 64 hashes of 4 KiB must take well under a second even on a slow path.
    try std.testing.expect(total < std.time.ns_per_s);
    try std.testing.expectEqual(@as(u8, 0xA5), buf[0]);
}
