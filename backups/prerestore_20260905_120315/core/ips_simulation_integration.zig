//! ips_simulation_integration.zig - AEGIS IPS Simulation Integration (Phase 26)

const std = @import("std");
const ips_sim = @import("ips_simulation.zig");

var g_engine: ?ips_sim.IpsSimEngine = null;
var g_initialized: bool = false;

var g_total_processed: u64 = 0;
var g_total_blocks: u64 = 0;
var g_total_rollbacks: u64 = 0;

pub fn init() void {
    if (g_initialized) return;
    g_engine = ips_sim.IpsSimEngine.init();
    g_initialized = true;
    g_total_processed = 0;
    g_total_blocks = 0;
    g_total_rollbacks = 0;
    std.log.info("[IPS-SIM] IPS simulation initialized (mode=AUDIT)", .{});
}

pub fn isInitialized() bool {
    return g_initialized;
}

pub fn resetStats() void {
    g_total_processed = 0;
    g_total_blocks = 0;
    g_total_rollbacks = 0;
    if (g_engine) |*engine| {
        engine.reset();
    }
}

pub fn getMode() ips_sim.IpsMode {
    if (g_engine) |*engine| {
        return engine.getMode();
    }
    return .audit;
}

pub fn advance() bool {
    if (g_engine) |*engine| {
        return engine.advance();
    }
    return false;
}

pub fn rollbackMode() bool {
    if (g_engine) |*engine| {
        return engine.rollbackMode();
    }
    return false;
}

pub fn setMode(mode: ips_sim.IpsMode) bool {
    if (g_engine) |*engine| {
        return engine.setMode(mode);
    }
    return false;
}

pub fn processDecision(
    event_id: u64,
    would_block: bool,
    is_canary_event: bool,
    blocked_ip: u32,
    timestamp_ns: u64,
) ips_sim.SimulationResult {
    if (g_engine) |*engine| {
        const result = engine.processDecision(event_id, would_block, is_canary_event, blocked_ip, timestamp_ns);
        g_total_processed += 1;
        if (result.actually_blocked) {
            g_total_blocks += 1;
        }
        return result;
    }
    return .{
        .mode = .audit,
        .action = .logged_only,
        .event_id = event_id,
        .would_block = would_block,
        .actually_blocked = false,
        .rollback_available = false,
        .description = "engine not initialized",
    };
}

pub fn rollbackBlock(event_id: u64, timestamp_ns: u64) bool {
    if (g_engine) |*engine| {
        const result = engine.rollbackBlock(event_id, timestamp_ns);
        if (result) g_total_rollbacks += 1;
        return result;
    }
    return false;
}

pub fn pendingBlocks() usize {
    if (g_engine) |*engine| {
        return engine.pendingBlocks();
    }
    return 0;
}

pub const IpsSimStats = struct {
    total_processed: u64,
    total_blocks: u64,
    total_rollbacks: u64,
    current_mode: ips_sim.IpsMode,
    pending_blocks: usize,
};

pub fn getStats() IpsSimStats {
    if (g_engine) |*engine| {
        return .{
            .total_processed = g_total_processed,
            .total_blocks = g_total_blocks,
            .total_rollbacks = g_total_rollbacks,
            .current_mode = engine.getMode(),
            .pending_blocks = engine.pendingBlocks(),
        };
    }
    return .{
        .total_processed = 0,
        .total_blocks = 0,
        .total_rollbacks = 0,
        .current_mode = .audit,
        .pending_blocks = 0,
    };
}

pub fn shutdown() void {
    if (!g_initialized) return;
    g_engine = null;
    g_initialized = false;
    std.log.info("[IPS-SIM] IPS simulation shutdown", .{});
}

test "ips simulation integration: full lifecycle" {
    if (g_initialized) shutdown();

    try std.testing.expect(!isInitialized());
    init();
    try std.testing.expect(isInitialized());
    try std.testing.expect(getMode() == .audit);

    // Process in AUDIT
    const audit_result = processDecision(1, true, false, 0x08080808, 1000);
    try std.testing.expect(audit_result.action == .logged_only);

    // Advance to SIMULATE
    try std.testing.expect(advance());
    const sim_result = processDecision(2, true, false, 0x08080808, 2000);
    try std.testing.expect(sim_result.action == .simulated);

    // Advance to CANARY
    try std.testing.expect(advance());
    const canary_result = processDecision(3, true, true, 0x08080808, 3000);
    try std.testing.expect(canary_result.action == .canary_executed);

    // Advance to ENFORCE
    try std.testing.expect(advance());
    const enforce_result = processDecision(4, true, false, 0x08080808, 4000);
    try std.testing.expect(enforce_result.action == .enforced);

    // Rollback
    try std.testing.expect(rollbackBlock(4, 5000));

    const stats = getStats();
    try std.testing.expect(stats.total_processed >= 4);
    try std.testing.expect(stats.total_blocks >= 2);
    try std.testing.expect(stats.total_rollbacks >= 1);

    // Reset
    resetStats();
    const reset_stats = getStats();
    try std.testing.expect(reset_stats.total_processed == 0);

    // Double-init/double-shutdown
    init();
    try std.testing.expect(isInitialized());
    shutdown();
    shutdown();
    try std.testing.expect(!isInitialized());
}
