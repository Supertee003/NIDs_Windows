//! rust_pep_integration.zig - AEGIS Rust PEP Integration (Phase 13)
//!
//! Thin facade over rust_pep.zig that owns a singleton RustPep.

const std = @import("std");
const canonical = @import("canonical_event.zig");
const policy = @import("policy_engine.zig");
const rust_pep = @import("rust_pep.zig");

var g_pep: ?rust_pep.RustPep = null;
var g_initialized: bool = false;
var g_allocator: std.mem.Allocator = std.heap.page_allocator;
var g_total_executions: u64 = 0;
var g_total_blocks: u64 = 0;

pub fn init() void {
    if (g_initialized) return;
    g_pep = rust_pep.RustPep.init(g_allocator);
    g_initialized = true;
    g_total_executions = 0;
    g_total_blocks = 0;
    std.log.info("[RUST-PEP] PEP integration initialized (security authority)", .{});
}

pub fn isInitialized() bool { return g_initialized; }

pub fn shutdown() void {
    if (!g_initialized) return;
    if (g_pep) |*pep| pep.deinit();
    g_pep = null;
    g_initialized = false;
    std.log.info("[RUST-PEP] PEP integration shutdown", .{});
}

pub fn execute(event: canonical.CanonicalEvent, decision: policy.EnforcementDecision) rust_pep.EnforcementResult {
    g_total_executions += 1;
    if (!g_initialized) {
        return .{
            .status = .no_op,
            .reason = .none,
            .requested_action = decision.action,
            .actual_action = .allow,
            .event_id = decision.event_id,
            .blocked_ip = 0,
            .message = "PEP not initialized",
        };
    }
    if (g_pep) |*pep| {
        const result = pep.execute(event, decision);
        if (result.status == .executed and result.actual_action.isBlocking()) {
            g_total_blocks += 1;
        }
        return result;
    }
    return .{
        .status = .no_op,
        .reason = .none,
        .requested_action = decision.action,
        .actual_action = .allow,
        .event_id = decision.event_id,
        .blocked_ip = 0,
        .message = "PEP missing",
    };
}

pub fn isBlocked(ip: u32) bool {
    if (g_pep) |*pep| return pep.isBlocked(ip);
    return false;
}

pub fn getStats() struct { total_executions: u64, total_blocks: u64 } {
    return .{ .total_executions = g_total_executions, .total_blocks = g_total_blocks };
}

pub fn resetStats() void {
    g_total_executions = 0;
    g_total_blocks = 0;
    if (g_pep) |*pep| pep.resetStats();
}

test "rust_pep_integration: full lifecycle" {
    if (isInitialized()) shutdown();
    try std.testing.expect(!isInitialized());

    init();
    defer shutdown();
    try std.testing.expect(isInitialized());

    var event = canonical.create(.zig_core);
    event.source_ip = 0xCBCBCBCB;
    event.dest_ip = 0x0A000002;
    const decision = policy.EnforcementDecision{
        .action = .block,
        .rule = .verdict_malicious,
        .confidence = 90,
        .reason = "test",
        .event_id = 1,
        .brain_recommended_verdict = .malicious,
        .original_verdict = .malicious,
        .threat_score = 80,
    };

    const result = execute(event, decision);
    try std.testing.expect(result.status == .executed);
    try std.testing.expect(isBlocked(0xCBCBCBCB));

    const stats = getStats();
    try std.testing.expect(stats.total_executions == 1);
    try std.testing.expect(stats.total_blocks == 1);
}

test "rust_pep_integration: returns no_op when not initialized" {
    if (isInitialized()) shutdown();
    const event = canonical.create(.zig_core);
    const decision = policy.EnforcementDecision{
        .action = .block,
        .rule = .verdict_malicious,
        .confidence = 90,
        .reason = "test",
        .event_id = 1,
        .brain_recommended_verdict = .malicious,
        .original_verdict = .malicious,
        .threat_score = 80,
    };
    const result = execute(event, decision);
    try std.testing.expect(result.status == .no_op);
}
