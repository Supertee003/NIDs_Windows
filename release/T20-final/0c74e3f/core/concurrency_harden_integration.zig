//! concurrency_harden_integration.zig - AEGIS Concurrency Hardening Integration (Phase 24)

const std = @import("std");
const conc = @import("concurrency_harden.zig");

var g_engine: ?conc.ConcurrencyEngine = null;
var g_initialized: bool = false;

var g_total_tests: u64 = 0;
var g_total_critical: u64 = 0;

pub fn init() void {
    if (g_initialized) return;
    g_engine = conc.ConcurrencyEngine.init();
    g_initialized = true;
    g_total_tests = 0;
    g_total_critical = 0;
    std.log.info("[CONCURRENCY] Concurrency hardening initialized", .{});
}

pub fn isInitialized() bool {
    return g_initialized;
}

pub fn resetStats() void {
    g_total_tests = 0;
    g_total_critical = 0;
    if (g_engine) |*engine| {
        engine.reset();
    }
}

pub fn simulateConcurrentSubmit(config: conc.StressConfig) u64 {
    if (g_engine) |*engine| {
        return engine.simulateConcurrentSubmit(config);
    }
    return 0;
}

pub fn verifyCounts(test_name: []const u8, config: conc.StressConfig, duration_ns: u64) conc.ConcurrencyResult {
    if (g_engine) |*engine| {
        const result = engine.verifyCounts(test_name, config, duration_ns);
        g_total_tests += 1;
        if (result.isCritical()) {
            g_total_critical += 1;
        }
        return result;
    }
    return .{
        .test_name = test_name,
        .status = .failed,
        .events_sent = 0,
        .events_received = 0,
        .events_lost = 0,
        .duplicates = 0,
        .duration_ns = 0,
        .threads_used = 0,
        .failure_reason = "engine not initialized",
    };
}

pub const ConcurrencyStats = struct {
    total_tests: u64,
    total_passed: u64,
    total_failed: u64,
    total_critical: u64,
    pass_rate: u8,
};

pub fn getStats() ConcurrencyStats {
    if (g_engine) |*engine| {
        return .{
            .total_tests = engine.total_tests,
            .total_passed = engine.total_passed,
            .total_failed = engine.total_failed,
            .total_critical = engine.total_critical,
            .pass_rate = engine.passRate(),
        };
    }
    return .{
        .total_tests = 0,
        .total_passed = 0,
        .total_failed = 0,
        .total_critical = 0,
        .pass_rate = 0,
    };
}

pub fn shutdown() void {
    if (!g_initialized) return;
    g_engine = null;
    g_initialized = false;
    std.log.info("[CONCURRENCY] Concurrency hardening shutdown", .{});
}

test "concurrency integration: full lifecycle" {
    if (g_initialized) shutdown();

    try std.testing.expect(!isInitialized());
    init();
    try std.testing.expect(isInitialized());

    const config = conc.StressConfig.default();
    _ = simulateConcurrentSubmit(config);
    const result = verifyCounts("integration_test", config, 1000000);
    try std.testing.expect(result.isPassed());

    const stats = getStats();
    try std.testing.expect(stats.total_tests >= 1);

    resetStats();
    const reset_stats = getStats();
    try std.testing.expect(reset_stats.total_tests == 0);

    init();
    try std.testing.expect(isInitialized());
    shutdown();
    shutdown();
    try std.testing.expect(!isInitialized());
}
