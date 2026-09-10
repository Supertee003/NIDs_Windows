//! policy_plane_integration.zig - AEGIS Policy Plane Integration (Phase 27)

const std = @import("std");
const plane = @import("policy_plane.zig");

var g_compiler: ?plane.PolicyCompiler = null;
var g_current_ir: ?plane.PolicyIR = null;
var g_initialized: bool = false;

var g_total_compiles: u64 = 0;
var g_total_simulations: u64 = 0;

pub fn init() void {
    if (g_initialized) return;
    g_compiler = plane.PolicyCompiler.init();
    g_initialized = true;
    g_total_compiles = 0;
    g_total_simulations = 0;
    std.log.info("[POLICY-PLANE] Policy plane initialized (IR v{d})", .{plane.POLICY_IR_VERSION});
}

pub fn isInitialized() bool {
    return g_initialized;
}

pub fn resetStats() void {
    g_total_compiles = 0;
    g_total_simulations = 0;
    if (g_compiler) |*c| {
        c.resetStats();
    }
    g_current_ir = null;
}

pub fn compilePolicy(rules: []const plane.PolicyRuleDef) plane.CompileError {
    if (g_compiler) |*c| {
        const result = c.compile(rules);
        if (result.error_ == .none) {
            g_current_ir = result.ir;
            g_total_compiles += 1;
        }
        return result.error_;
    }
    return .no_rules;
}

pub fn simulatePolicy(values: []const u64) ?plane.SimulationResult {
    if (g_current_ir) |ir| {
        g_total_simulations += 1;
        return plane.PolicySimulator.simulate(ir, values);
    }
    return null;
}

pub fn hasCompiledPolicy() bool {
    if (g_current_ir) |ir| {
        return ir.isValid() and ir.ruleCount() > 0;
    }
    return false;
}

pub fn getRuleCount() usize {
    if (g_current_ir) |ir| {
        return ir.ruleCount();
    }
    return 0;
}

pub const PolicyPlaneStats = struct {
    total_compiles: u64,
    total_simulations: u64,
    current_rule_count: usize,
    has_policy: bool,
};

pub fn getStats() PolicyPlaneStats {
    return .{
        .total_compiles = g_total_compiles,
        .total_simulations = g_total_simulations,
        .current_rule_count = getRuleCount(),
        .has_policy = hasCompiledPolicy(),
    };
}

pub fn shutdown() void {
    if (!g_initialized) return;
    g_compiler = null;
    g_current_ir = null;
    g_initialized = false;
    std.log.info("[POLICY-PLANE] Policy plane shutdown", .{});
}

test "policy plane integration: full lifecycle" {
    if (g_initialized) shutdown();

    try std.testing.expect(!isInitialized());
    init();
    try std.testing.expect(isInitialized());

    // No policy compiled yet
    try std.testing.expect(!hasCompiledPolicy());
    try std.testing.expect(simulatePolicy(&[_]u64{0} ** 9) == null);

    // Compile a simple policy
    const rules = [_]plane.PolicyRuleDef{
        .{
            .id = 1,
            .name = "tcp_alert",
            .priority = 10,
            .conditions = blk: {
                var c: [4]?plane.PolicyCondition = .{ null, null, null, null };
                c[0] = .{ .field = .protocol, .operator = .equals, .value = 6, .value2 = 0 };
                break :blk c;
            },
            .condition_count = 1,
            .action = .alert,
            .enabled = true,
            .description = "alert on TCP",
        },
    };

    const err = compilePolicy(&rules);
    try std.testing.expect(err == .none);
    try std.testing.expect(hasCompiledPolicy());
    try std.testing.expect(getRuleCount() == 1);

    // Simulate
    var tcp_values = [_]u64{0} ** 9;
    tcp_values[@intFromEnum(plane.ConditionType.protocol)] = 6;
    const sim = simulatePolicy(&tcp_values);
    try std.testing.expect(sim != null);
    try std.testing.expect(sim.?.isMatched());
    try std.testing.expect(sim.?.action == .alert);

    const stats = getStats();
    try std.testing.expect(stats.total_compiles == 1);
    try std.testing.expect(stats.total_simulations == 1);

    // Reset
    resetStats();
    try std.testing.expect(!hasCompiledPolicy());

    // Double-init/double-shutdown
    init();
    try std.testing.expect(isInitialized());
    shutdown();
    shutdown();
    try std.testing.expect(!isInitialized());
}
