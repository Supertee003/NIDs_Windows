//! rust_pep_integration.zig - AEGIS Rust PEP Integration (Rewrite Phase 13)
//!
//! Thin facade over rust_pep.zig that owns a singleton PepExecutor.
//! Mirrors the pattern of policy_integration.zig and brain_integration.zig.
//!
//! Lifecycle (owned by runtime/lifecycle.zig):
//!   init()     -> create PepExecutor
//!   execute(event, decision) -> EnforcementResult
//!   shutdown() -> reset executor state

const std = @import("std");
const canonical = @import("canonical_event.zig");
const policy = @import("policy_engine.zig");
const rust_pep = @import("rust_pep.zig");

// ============================================================
// Singleton state
// ============================================================

var g_executor: ?rust_pep.PepExecutor = null;
var g_initialized: bool = false;

// Lifetime stats
var g_total_executions: u64 = 0;
var g_total_executed: u64 = 0;
var g_total_rejected: u64 = 0;
var g_total_deferred: u64 = 0;
var g_total_no_ops: u64 = 0;
var g_total_failures: u64 = 0;

// ============================================================
// Initialization
// ============================================================

pub fn init() void {
    if (g_initialized) return;
    g_executor = rust_pep.PepExecutor.init();
    g_initialized = true;
    g_total_executions = 0;
    g_total_executed = 0;
    g_total_rejected = 0;
    g_total_deferred = 0;
    g_total_no_ops = 0;
    g_total_failures = 0;
    std.log.info("[RUST-PEP] PEP integration initialized (security authority)", .{});
}

pub fn isInitialized() bool {
    return g_initialized;
}

/// Reset all stats (for tests).
pub fn resetStats() void {
    g_total_executions = 0;
    g_total_executed = 0;
    g_total_rejected = 0;
    g_total_deferred = 0;
    g_total_no_ops = 0;
    g_total_failures = 0;
    if (g_executor) |*executor| {
        executor.* = rust_pep.PepExecutor.init();
    }
}

// ============================================================
// Execution
// ============================================================

/// Execute an enforcement decision. Returns EnforcementResult.
/// Returns no_op result if not initialized (fail-open).
pub fn execute(
    event: canonical.CanonicalEvent,
    decision: policy.EnforcementDecision,
) rust_pep.EnforcementResult {
    if (!g_initialized) {
        return .{
            .status = .no_op,
            .reason = .none,
            .requested_action = decision.action,
            .actual_action = .allow, // fail-open
            .event_id = event.event_id,
            .blocked_ip = 0,
            .message = "PEP not initialized, fail-open",
        };
    }
    if (g_executor) |*executor| {
        const result = executor.execute(event, decision);
        g_total_executions += 1;
        switch (result.status) {
            .executed => g_total_executed += 1,
            .rejected => g_total_rejected += 1,
            .deferred => g_total_deferred += 1,
            .no_op => g_total_no_ops += 1,
            .failed => g_total_failures += 1,
        }
        return result;
    }
    return .{
        .status = .no_op,
        .reason = .none,
        .requested_action = decision.action,
        .actual_action = .allow,
        .event_id = event.event_id,
        .blocked_ip = 0,
        .message = "PEP executor not available",
    };
}

/// Check if an IP is currently blocked.
pub fn isIpBlocked(ip: u32) bool {
    if (g_executor) |*executor| {
        return executor.isIpBlocked(ip);
    }
    return false;
}

/// Manually unblock an IP.
pub fn unblockIp(ip: u32) bool {
    if (g_executor) |*executor| {
        return executor.unblockIp(ip);
    }
    return false;
}

/// Current blocklist size.
pub fn blocklistSize() usize {
    if (g_executor) |*executor| {
        return executor.blocklistSize();
    }
    return 0;
}

/// Clear all blocked IPs.
pub fn clearBlocklist() void {
    if (g_executor) |*executor| {
        executor.clearBlocklist();
    }
}

// ============================================================
// Stats
// ============================================================

pub const PepStats = struct {
    total_executions: u64,
    total_executed: u64,
    total_rejected: u64,
    total_deferred: u64,
    total_no_ops: u64,
    total_failures: u64,
    blocklist_count: usize,
};

pub fn getStats() PepStats {
    if (g_executor) |*executor| {
        return .{
            .total_executions = g_total_executions,
            .total_executed = g_total_executed,
            .total_rejected = g_total_rejected,
            .total_deferred = g_total_deferred,
            .total_no_ops = g_total_no_ops,
            .total_failures = g_total_failures,
            .blocklist_count = executor.blocklistSize(),
        };
    }
    return .{
        .total_executions = 0,
        .total_executed = 0,
        .total_rejected = 0,
        .total_deferred = 0,
        .total_no_ops = 0,
        .total_failures = 0,
        .blocklist_count = 0,
    };
}

// ============================================================
// Shutdown
// ============================================================

pub fn shutdown() void {
    if (!g_initialized) return;
    g_executor = null;
    g_initialized = false;
    std.log.info("[RUST-PEP] PEP integration shutdown", .{});
}

// ============================================================
// Tests (single serial test - parallelism-safe)
// ============================================================

test "rust pep integration: full lifecycle (init, execute, stats, shutdown)" {
    // Clean slate
    if (g_initialized) shutdown();

    // --- Phase A: execute returns no_op when not initialized ---
    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x08080808;

    const decision = policy.EnforcementDecision{
        .action = .block,
        .rule = .verdict_malicious,
        .confidence = 90,
        .reason = "test",
        .event_id = event.event_id,
        .brain_recommended_verdict = .malicious,
        .original_verdict = .malicious,
        .threat_score = 80,
    };

    const empty_result = execute(event, decision);
    try std.testing.expect(empty_result.status == .no_op);

    // --- Phase B: init ---
    try std.testing.expect(!isInitialized());
    init();
    try std.testing.expect(isInitialized());

    const stats_init = getStats();
    try std.testing.expect(stats_init.total_executions == 0);
    try std.testing.expect(stats_init.blocklist_count == 0);

    // --- Phase C: execute allow -> no_op ---
    var event_allow = canonical.create(.wfp_sensor);
    event_allow.source_ip = 0x0A000001;
    const dec_allow = policy.EnforcementDecision{
        .action = .allow,
        .rule = .default_allow,
        .confidence = 50,
        .reason = "test",
        .event_id = 1,
        .brain_recommended_verdict = .benign,
        .original_verdict = .benign,
        .threat_score = 10,
    };
    const result_allow = execute(event_allow, dec_allow);
    try std.testing.expect(result_allow.status == .no_op);

    // --- Phase D: execute block on public IP -> executed ---
    const result_block = execute(event, decision);
    try std.testing.expect(result_block.status == .executed);
    try std.testing.expect(result_block.blocked_ip == 0x08080808);
    try std.testing.expect(isIpBlocked(0x08080808));

    // --- Phase E: execute block on localhost -> rejected ---
    var event_localhost = canonical.create(.wfp_sensor);
    event_localhost.source_ip = 0x7F000001;
    const dec_localhost = policy.EnforcementDecision{
        .action = .block,
        .rule = .verdict_malicious,
        .confidence = 100,
        .reason = "test",
        .event_id = 2,
        .brain_recommended_verdict = .malicious,
        .original_verdict = .malicious,
        .threat_score = 90,
    };
    const result_rejected = execute(event_localhost, dec_localhost);
    try std.testing.expect(result_rejected.status == .rejected);
    try std.testing.expect(result_rejected.reason == .localhost_protected);

    const stats_after = getStats();
    try std.testing.expect(stats_after.total_executions == 3);
    try std.testing.expect(stats_after.total_no_ops == 1);
    try std.testing.expect(stats_after.total_executed == 1);
    try std.testing.expect(stats_after.total_rejected == 1);
    try std.testing.expect(stats_after.blocklist_count == 1);

    // --- Phase F: unblockIp removes from blocklist ---
    try std.testing.expect(unblockIp(0x08080808));
    try std.testing.expect(!isIpBlocked(0x08080808));
    try std.testing.expect(blocklistSize() == 0);

    // --- Phase G: resetStats zeroes counters ---
    resetStats();
    const stats_reset = getStats();
    try std.testing.expect(stats_reset.total_executions == 0);
    try std.testing.expect(stats_reset.blocklist_count == 0);

    // --- Phase H: double-init is no-op, double-shutdown is no-op ---
    init(); // no-op
    try std.testing.expect(isInitialized());
    shutdown();
    shutdown(); // no-op
    try std.testing.expect(!isInitialized());

    // --- Phase I: after shutdown, execute returns no_op ---
    const empty_result2 = execute(event, decision);
    try std.testing.expect(empty_result2.status == .no_op);
}
