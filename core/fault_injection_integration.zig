//! fault_injection_integration.zig - AEGIS Fault Injection Integration (Phase 25)

const std = @import("std");
const fault = @import("fault_injection.zig");

var g_engine: ?fault.FaultEngine = null;
var g_initialized: bool = false;

var g_total_injected: u64 = 0;
var g_total_handled: u64 = 0;
var g_total_mishandled: u64 = 0;

pub fn init() void {
    if (g_initialized) return;
    g_engine = fault.FaultEngine.init();
    g_initialized = true;
    g_total_injected = 0;
    g_total_handled = 0;
    g_total_mishandled = 0;
    std.log.info("[FAULT] Fault injection initialized (10 fault types)", .{});
}

pub fn isInitialized() bool {
    return g_initialized;
}

pub fn resetStats() void {
    g_total_injected = 0;
    g_total_handled = 0;
    g_total_mishandled = 0;
    if (g_engine) |*engine| {
        engine.reset();
    }
}

pub fn injectFault(fault_type: fault.FaultType, timestamp_ns: u64) bool {
    if (!g_initialized) return false;
    if (g_engine) |*engine| {
        const result = engine.injectFault(fault_type, timestamp_ns);
        if (result) g_total_injected += 1;
        return result;
    }
    return false;
}

pub fn resolveFault(fault_type: fault.FaultType, handled: bool) fault.FaultResult {
    if (g_engine) |*engine| {
        const result = engine.resolveFault(fault_type, handled);
        if (result.isHandled()) {
            g_total_handled += 1;
        } else if (result.isFailure()) {
            g_total_mishandled += 1;
        }
        return result;
    }
    return .{
        .fault_type = fault_type,
        .status = .inactive,
        .expected_behavior = fault_type.expectedBehavior(),
        .actual_behavior = fault_type.expectedBehavior(),
        .description = "engine not initialized",
        .duration_ns = 0,
    };
}

pub fn isFaultActive(fault_type: fault.FaultType) bool {
    if (g_engine) |*engine| {
        return engine.isFaultActive(fault_type);
    }
    return false;
}

pub fn activeCount() usize {
    if (g_engine) |*engine| {
        return engine.activeCount();
    }
    return 0;
}

pub const FaultStats = struct {
    total_injected: u64,
    total_handled: u64,
    total_mishandled: u64,
    active_faults: usize,
    pass_rate: u8,
};

pub fn getStats() FaultStats {
    if (g_engine) |*engine| {
        return .{
            .total_injected = g_total_injected,
            .total_handled = g_total_handled,
            .total_mishandled = g_total_mishandled,
            .active_faults = engine.activeCount(),
            .pass_rate = engine.passRate(),
        };
    }
    return .{
        .total_injected = 0,
        .total_handled = 0,
        .total_mishandled = 0,
        .active_faults = 0,
        .pass_rate = 0,
    };
}

pub fn shutdown() void {
    if (!g_initialized) return;
    g_engine = null;
    g_initialized = false;
    std.log.info("[FAULT] Fault injection shutdown", .{});
}

test "fault injection integration: full lifecycle" {
    if (g_initialized) shutdown();

    try std.testing.expect(!isInitialized());
    init();
    try std.testing.expect(isInitialized());

    // Inject WFP fault
    try std.testing.expect(injectFault(.wfp_unavailable, 1000));
    try std.testing.expect(isFaultActive(.wfp_unavailable));
    try std.testing.expect(activeCount() == 1);

    // Resolve as handled
    const result = resolveFault(.wfp_unavailable, true);
    try std.testing.expect(result.isHandled());
    try std.testing.expect(!isFaultActive(.wfp_unavailable));

    // Inject critical fault
    try std.testing.expect(injectFault(.policy_malformed, 2000));
    const critical_result = resolveFault(.policy_malformed, false);
    try std.testing.expect(critical_result.isFailure());

    const stats = getStats();
    try std.testing.expect(stats.total_injected >= 2);
    try std.testing.expect(stats.total_handled >= 1);
    try std.testing.expect(stats.total_mishandled >= 1);

    resetStats();
    const reset_stats = getStats();
    try std.testing.expect(reset_stats.total_injected == 0);

    init();
    try std.testing.expect(isInitialized());
    shutdown();
    shutdown();
    try std.testing.expect(!isInitialized());
}
