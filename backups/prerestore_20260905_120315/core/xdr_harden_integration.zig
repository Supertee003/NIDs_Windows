//! xdr_harden_integration.zig - AEGIS XDR Integration (Rewrite Phase 19)
//!
//! Thin facade over xdr_harden.zig that owns a singleton XdrEngine.
//! Provides SIEM export and incident management API.

const std = @import("std");
const forensics = @import("forensics_engine.zig");
const xdr = @import("xdr_harden.zig");

var g_engine: ?xdr.XdrEngine = null;
var g_initialized: bool = false;

var g_total_incidents: u64 = 0;
var g_total_exports: u64 = 0;

pub fn init() void {
    if (g_initialized) return;
    g_engine = xdr.XdrEngine.init();
    g_initialized = true;
    g_total_incidents = 0;
    g_total_exports = 0;
    std.log.info("[XDR] XDR hardening initialized (SIEM CEF export)", .{});
}

pub fn isInitialized() bool {
    return g_initialized;
}

pub fn resetStats() void {
    g_total_incidents = 0;
    g_total_exports = 0;
    if (g_engine) |*engine| {
        engine.reset();
    }
}

pub fn processRecord(record: forensics.PipelineResult) u64 {
    if (!g_initialized) return 0;
    if (g_engine) |*engine| {
        const id = engine.processRecord(record);
        g_total_incidents += 1;
        return id;
    }
    return 0;
}

pub fn exportCef(incident_idx: usize, buf: []u8) usize {
    if (!g_initialized) return 0;
    if (g_engine) |*engine| {
        const len = engine.exportCef(incident_idx, buf);
        if (len > 0) g_total_exports += 1;
        return len;
    }
    return 0;
}

pub fn incidentCount() usize {
    if (g_engine) |*engine| {
        return engine.count();
    }
    return 0;
}

pub const XdrStats = struct {
    total_incidents: u64,
    total_exports: u64,
    current_incidents: usize,
};

pub fn getStats() XdrStats {
    if (g_engine) |*engine| {
        return .{
            .total_incidents = g_total_incidents,
            .total_exports = g_total_exports,
            .current_incidents = engine.count(),
        };
    }
    return .{ .total_incidents = 0, .total_exports = 0, .current_incidents = 0 };
}

pub fn shutdown() void {
    if (!g_initialized) return;
    g_engine = null;
    g_initialized = false;
    std.log.info("[XDR] XDR hardening shutdown", .{});
}

test "xdr integration: full lifecycle (init, process, export, shutdown)" {
    if (g_initialized) shutdown();

    // Not initialized -> processRecord returns 0
    const detection_engine = @import("detection_engine.zig");
    const policy_engine = @import("policy_engine.zig");
    const rust_pep = @import("rust_pep.zig");

    const empty_id = processRecord(.{
        .event_id = 1,
        .timestamp_ns = 1000,
        .source_ip = 0x0A000001,
        .dest_ip = 0x0A000002,
        .source_port = 12345,
        .dest_port = 80,
        .protocol = 6,
        .aggregated_verdict = detection_engine.Verdict.benign,
        .aggregated_confidence = 50,
        .escalated = false,
        .original_verdict = detection_engine.Verdict.benign,
        .correlation_alert_count = 0,
        .correlation_rules = .{ 0, 0, 0 },
        .threat_intel_matched = false,
        .threat_intel_max_severity = 0,
        .brain_advice_kind = 0,
        .brain_threat_score = 0,
        .brain_recommended_verdict = detection_engine.Verdict.benign,
        .policy_action = policy_engine.EnforcementAction.allow,
        .policy_rule = policy_engine.PolicyRule.default_allow,
        .policy_confidence = 50,
        .pep_status = rust_pep.EnforcementStatus.no_op,
        .pep_rejection_reason = rust_pep.RejectionReason.none,
        .pep_blocked_ip = 0,
    });
    try std.testing.expect(empty_id == 0);

    // Init
    try std.testing.expect(!isInitialized());
    init();
    try std.testing.expect(isInitialized());

    // Process record -> creates incident
    const id = processRecord(.{
        .event_id = 1,
        .timestamp_ns = 1000,
        .source_ip = 0x08080808,
        .dest_ip = 0x0A000002,
        .source_port = 12345,
        .dest_port = 80,
        .protocol = 6,
        .aggregated_verdict = detection_engine.Verdict.malicious,
        .aggregated_confidence = 90,
        .escalated = false,
        .original_verdict = detection_engine.Verdict.malicious,
        .correlation_alert_count = 0,
        .correlation_rules = .{ 0, 0, 0 },
        .threat_intel_matched = false,
        .threat_intel_max_severity = 0,
        .brain_advice_kind = 0,
        .brain_threat_score = 80,
        .brain_recommended_verdict = detection_engine.Verdict.malicious,
        .policy_action = policy_engine.EnforcementAction.block,
        .policy_rule = policy_engine.PolicyRule.verdict_malicious,
        .policy_confidence = 90,
        .pep_status = rust_pep.EnforcementStatus.executed,
        .pep_rejection_reason = rust_pep.RejectionReason.none,
        .pep_blocked_ip = 0x08080808,
    });
    try std.testing.expect(id > 0);
    try std.testing.expect(incidentCount() == 1);

    // Export CEF
    var buf: [512]u8 = undefined;
    const len = exportCef(0, &buf);
    try std.testing.expect(len > 0);
    try std.testing.expect(std.mem.startsWith(u8, buf[0..len], "CEF:0|AEGIS|NIDS|"));

    // Stats
    const stats = getStats();
    try std.testing.expect(stats.total_incidents == 1);
    try std.testing.expect(stats.total_exports == 1);

    // Reset
    resetStats();
    const stats_reset = getStats();
    try std.testing.expect(stats_reset.total_incidents == 0);

    // Double-init/double-shutdown
    init();
    try std.testing.expect(isInitialized());
    shutdown();
    shutdown();
    try std.testing.expect(!isInitialized());

    // After shutdown -> returns 0
    const empty_id2 = processRecord(.{
        .event_id = 1,
        .timestamp_ns = 1000,
        .source_ip = 0x0A000001,
        .dest_ip = 0x0A000002,
        .source_port = 12345,
        .dest_port = 80,
        .protocol = 6,
        .aggregated_verdict = detection_engine.Verdict.benign,
        .aggregated_confidence = 50,
        .escalated = false,
        .original_verdict = detection_engine.Verdict.benign,
        .correlation_alert_count = 0,
        .correlation_rules = .{ 0, 0, 0 },
        .threat_intel_matched = false,
        .threat_intel_max_severity = 0,
        .brain_advice_kind = 0,
        .brain_threat_score = 0,
        .brain_recommended_verdict = detection_engine.Verdict.benign,
        .policy_action = policy_engine.EnforcementAction.allow,
        .policy_rule = policy_engine.PolicyRule.default_allow,
        .policy_confidence = 50,
        .pep_status = rust_pep.EnforcementStatus.no_op,
        .pep_rejection_reason = rust_pep.RejectionReason.none,
        .pep_blocked_ip = 0,
    });
    try std.testing.expect(empty_id2 == 0);
}
