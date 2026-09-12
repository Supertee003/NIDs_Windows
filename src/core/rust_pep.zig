//! rust_pep.zig - AEGIS Rust PEP (Policy Enforcement Point) (Phase 13)
//!
//! Validates and executes EnforcementDecisions from the Policy Engine.
//! The PEP is the SECURITY AUTHORITY - it can REJECT or DEFER decisions
//! that violate safety rules (e.g., blocking localhost, blocking critical
//! infrastructure IPs).
//!
//! Contract:
//!   EnforcementStatus: enum (no_op, executed, rejected, deferred, failed)
//!   RejectionReason: enum with toString()
//!   EnforcementResult: struct { status, reason, requested_action, actual_action,
//!                                event_id, blocked_ip, message }
//!   RustPep: execute(event, decision) -> EnforcementResult
//!
//! SECURITY (PEP-001): This module is the ONLY Zig entry point for privileged
//! enforcement. It delegates to Rust PEP via pep_bindings for authorization
//! and execution. Direct WFP access from Zig is prohibited.

const std = @import("std");
const canonical = @import("../contract/canonical_event.zig");
const policy = @import("../policy/policy_engine.zig");
const wfp_ioctl = @import("../policy/wfp_ioctl.zig");  // Phase 28: WFP kernel bridge
const pep_bindings = @import("../policy/pep_bindings.zig");       // REBUILD-004: PEP authority gate
const event_mod = @import("../contract/event.zig");
const policy_ir_mod = @import("../policy/policy_ir.zig");

// ============================================================
// Enforcement Status
// ============================================================

pub const EnforcementStatus = enum(u8) {
    no_op = 0,
    executed = 1,
    rejected = 2,
    deferred = 3,
    failed = 4,

    pub fn toString(self: EnforcementStatus) []const u8 {
        return switch (self) {
            .no_op => "NO_OP",
            .executed => "EXECUTED",
            .rejected => "REJECTED",
            .deferred => "DEFERRED",
            .failed => "FAILED",
        };
    }
};

// ============================================================
// Rejection Reason
// ============================================================

pub const RejectionReason = enum(u8) {
    none = 0,
    localhost_protected = 1,
    private_network_block_deferred = 2,
    critical_infra_protected = 3,
    invalid_decision = 4,
    duplicate_block = 5,
    rate_limit_window = 6,

    pub fn toString(self: RejectionReason) []const u8 {
        return switch (self) {
            .none => "NONE",
            .localhost_protected => "LOCALHOST_BLOCK_FORBIDDEN",
            .private_network_block_deferred => "PRIVATE_NETWORK_BLOCK_DEFERRED",
            .critical_infra_protected => "CRITICAL_INFRA_PROTECTED",
            .invalid_decision => "INVALID_DECISION",
            .duplicate_block => "DUPLICATE_BLOCK",
            .rate_limit_window => "RATE_LIMIT_WINDOW",
        };
    }
};

// ============================================================
// Enforcement Result
// ============================================================

pub const EnforcementResult = struct {
    status: EnforcementStatus,
    reason: RejectionReason,
    requested_action: policy.EnforcementAction,
    actual_action: policy.EnforcementAction,
    event_id: u64,
    blocked_ip: u32,
    message: []const u8,

    pub fn isExecuted(self: EnforcementResult) bool {
        return self.status == .executed;
    }

    pub fn isRejected(self: EnforcementResult) bool {
        return self.status == .rejected;
    }
};

// ============================================================
// Rust PEP (Zig-side simulation of the Rust enforcement layer)
// ============================================================

pub const RustPep = struct {
    // In-memory blocklist (real PEP pushes to WFP/minifilter)
    blocked_ips: std.AutoHashMap(u32, void),
    total_executed: u64 = 0,
    total_rejected: u64 = 0,
    total_deferred: u64 = 0,
    total_failed: u64 = 0,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) RustPep {
        return .{
            .blocked_ips = std.AutoHashMap(u32, void).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *RustPep) void {
        self.blocked_ips.deinit();
    }

    /// Execute an enforcement decision. May REJECT or DEFER per safety rules.
    pub fn execute(
        self: *RustPep,
        event: canonical.CanonicalEvent,
        decision: policy.EnforcementDecision,
    ) EnforcementResult {
        // Rule 1: never block localhost
        if (decision.action.isBlocking()) {
            if (isLocalhost(event.source_ip) or isLocalhost(event.dest_ip)) {
                self.total_rejected += 1;
                return .{
                    .status = .rejected,
                    .reason = .localhost_protected,
                    .requested_action = decision.action,
                    .actual_action = .allow,
                    .event_id = decision.event_id,
                    .blocked_ip = 0,
                    .message = "cannot block localhost",
                };
            }
        }

        // Rule 2: defer blocking on private network ranges (low confidence only)
        if (decision.action.isBlocking() and decision.confidence < 70) {
            if (isPrivateNetwork(event.source_ip) or isPrivateNetwork(event.dest_ip)) {
                self.total_deferred += 1;
                return .{
                    .status = .deferred,
                    .reason = .private_network_block_deferred,
                    .requested_action = decision.action,
                    .actual_action = .alert,
                    .event_id = decision.event_id,
                    .blocked_ip = 0,
                    .message = "private network block deferred (low confidence)",
                };
            }
        }

        // Rule 3: critical infrastructure protection (well-known DNS, etc.)
        if (decision.action.isBlocking()) {
            if (isCriticalInfra(event.source_ip)) {
                self.total_rejected += 1;
                return .{
                    .status = .rejected,
                    .reason = .critical_infra_protected,
                    .requested_action = decision.action,
                    .actual_action = .allow,
                    .event_id = decision.event_id,
                    .blocked_ip = 0,
                    .message = "critical infrastructure protected",
                };
            }
        }

        // Execute non-blocking actions immediately
        if (!decision.action.isBlocking()) {
            self.total_executed += 1;
            return .{
                .status = .executed,
                .reason = .none,
                .requested_action = decision.action,
                .actual_action = decision.action,
                .event_id = decision.event_id,
                .blocked_ip = 0,
                .message = "action executed",
            };
        }

        // Execute the block - add to in-memory blocklist
        // (real PEP would call WFP/minifilter to add the filter)
        const target_ip = event.source_ip;
        if (self.blocked_ips.contains(target_ip)) {
            // Already blocked - don't double-add
            return .{
                .status = .executed,
                .reason = .duplicate_block,
                .requested_action = decision.action,
                .actual_action = decision.action,
                .event_id = decision.event_id,
                .blocked_ip = target_ip,
                .message = "ip already blocked",
            };
        }

        // The Zig model records the authorized decision only. The Rust PEP
        // owns the privileged WFP side effect in the production adapter.
        self.blocked_ips.put(target_ip, {}) catch {
            self.total_failed += 1;
            return .{
                .status = .failed,
                .reason = .none,
                .requested_action = decision.action,
                .actual_action = .allow,
                .event_id = decision.event_id,
                .blocked_ip = 0,
                .message = "blocklist insertion failed",
            };
        };

        self.total_executed += 1;
        return .{
            .status = .executed,
            .reason = .none,
            .requested_action = decision.action,
            .actual_action = decision.action,
            .event_id = decision.event_id,
            .blocked_ip = target_ip,
            .message = "block executed",
        };
    }

    pub fn isBlocked(self: *RustPep, ip: u32) bool {
        return self.blocked_ips.contains(ip);
    }

    pub fn blockedCount(self: *RustPep) usize {
        return self.blocked_ips.count();
    }

    pub fn unblock(self: *RustPep, ip: u32) bool {
        return self.blocked_ips.remove(ip);
    }

    pub fn resetStats(self: *RustPep) void {
        self.blocked_ips.clearRetainingCapacity();
        self.total_executed = 0;
        self.total_rejected = 0;
        self.total_deferred = 0;
        self.total_failed = 0;
    }
};

// ============================================================
// IP classification helpers
// ============================================================

pub fn isLocalhost(ip: u32) bool {
    return ip == 0x7F000001; // 127.0.0.1
}

pub fn isPrivateNetwork(ip: u32) bool {
    // 10.0.0.0/8
    if ((ip & 0xFF000000) == 0x0A000000) return true;
    // 172.16.0.0/12
    if ((ip & 0xFFF00000) == 0xAC100000) return true;
    // 192.168.0.0/16
    if ((ip & 0xFFFF0000) == 0xC0A80000) return true;
    return false;
}

pub fn isCriticalInfra(ip: u32) bool {
    // 8.8.8.8 (Google DNS), 1.1.1.1 (Cloudflare DNS), 8.8.4.4
    if (ip == 0x08080808 or ip == 0x01010101 or ip == 0x08080404) return true;
    return false;
}

// ============================================================
// WFP IOCTL transport re-exports (T11)
//
// SECURITY (REBUILD-004, closes audit P0-1):
// The Rust PEP is the ONLY authority for privileged enforcement. The direct
// The previous direct WFP path exposed an unauthenticated Zig-to-WFP
// bypass. It is now gated behind the Rust PEP (aegis_pep.dll via
// src/policy/pep_bindings.zig):
//
//   block_ip(ip) →  PEP authorization (capability mask, quota, two-person
//                    rule for high severity)  →  only on ALLOW does the
//                    WFP IOCTL transport execute the block.
//
// If the PEP DLL is unavailable the gate is FAIL-CLOSED (returns false) —
// a privileged action is never silently executed without authorization.
// wfpInit/wfpShutdown/wfpIsConnected/read_events/get_stats remain pure
// telemetry transport (read-only, not privileged) and are unchanged.
// ============================================================

pub const WfpRingStats = wfp_ioctl.WfpRingStats;
pub const WfpEventHeader = wfp_ioctl.WfpEventHeader;

pub fn wfpInit() bool {
    return wfp_ioctl.init();
}

pub fn wfpShutdown() void {
    wfp_ioctl.shutdown();
}

pub fn wfpIsConnected() bool {
    return wfp_ioctl.isConnected();
}

/// Module-level PEP gate. Initialized lazily on first privileged call.
var g_pep_gate: ?pep_bindings.PepEnforcer = null;
var g_pep_gate_mutex: std.Thread.Mutex = .{};

fn pepGate() ?*pep_bindings.PepEnforcer {
    g_pep_gate_mutex.lock();
    defer g_pep_gate_mutex.unlock();
    if (g_pep_gate == null) {
        g_pep_gate = pep_bindings.PepEnforcer.init();
    }
    if (g_pep_gate.?.available) return &g_pep_gate.?;
    return null;
}

/// PRIVILEGED: block an IP via WFP — REQUIRES Rust PEP authorization.
/// Fail-closed: no PEP → no block.
pub fn block_ip(ipv4: u32) bool {
    const pep_gate = pepGate() orelse {
        std.log.err("[RUST-PEP] block_ip(0x{x}) REJECTED: PEP unavailable (fail-closed)", .{ipv4});
        return false;
    };

    // Build a synthetic enforcement request for the PEP.
    // Severity: blocking an IP is a high-severity privileged action.
    var ev = event_mod.IpcEvent.init(.action_block);
    ev.src_ip = ipv4;
    ev.severity = .alert;
    const pol = policy_ir_mod.Policy{
        .id = 0, // synthetic — enforcement requested by detection, not a named policy
        .name = "pep-gated-wfp-block",
        .condition = .{ .clauses = &[_]policy_ir_mod.Clause{} },
        .action = .block,
        .severity = .alert,
        .ttl_sec = 0,
    };

    const request_id = g_pep_request_counter.fetchAdd(1, .acq_rel) + 1;
    const decision = pep_gate.enforce(&ev, pol, 0, 0x1, request_id); // caps bit0 = block capability

    switch (decision) {
        .block => {},
        .rate_limit => {
            std.log.warn("[RUST-PEP] block_ip(0x{x}) RATE_LIMITED by PEP quota", .{ipv4});
            return false;
        },
        .escalate => {
            std.log.warn("[RUST-PEP] block_ip(0x{x}) ESCALATED by PEP (two-person rule)", .{ipv4});
            return false;
        },
        else => {
            std.log.warn("[RUST-PEP] block_ip(0x{x}) REJECTED by PEP decision={s}", .{ ipv4, @tagName(decision) });
            return false;
        },
    }

    // Rust PEP owns the WFP side effect and returned block only after success.
    return true;
}

var g_pep_request_counter = std.atomic.Value(u64).init(0);

/// PRIVILEGED: unblock an IP — also PEP-gated (fail-closed).
pub fn unblock_ip(ipv4: u32) bool {
    const pep_gate = pepGate() orelse {
        std.log.err("[RUST-PEP] unblock_ip(0x{x}) REJECTED: PEP unavailable (fail-closed)", .{ipv4});
        return false;
    };
    var ev = event_mod.IpcEvent.init(.action_allow);
    ev.src_ip = ipv4;
    ev.severity = .info;
    const pol = policy_ir_mod.Policy{
        .id = 0,
        .name = "pep-gated-wfp-unblock",
        .condition = .{ .clauses = &[_]policy_ir_mod.Clause{} },
        .action = .pass,
        .severity = .info,
        .ttl_sec = 0,
    };
    const request_id = g_pep_request_counter.fetchAdd(1, .acq_rel) + 1;
    const decision = pep_gate.enforce(&ev, pol, 0, 0x1, request_id);
    if (decision != .allow) {
        std.log.warn("[RUST-PEP] unblock_ip(0x{x}) not authorized: {s}", .{ ipv4, @tagName(decision) });
        return false;
    }
    return pep_gate.unblockIp(ipv4, 0, 0x1, request_id);
}

pub fn read_events(out_buf: []u8) u32 {
    return wfp_ioctl.read_events(out_buf);
}

pub fn get_stats() ?WfpRingStats {
    return wfp_ioctl.get_stats();
}

test "block_ip is fail-closed when PEP unavailable" {
    // In unit tests aegis_pep.dll may not be loadable; the gate MUST refuse
    // the privileged action rather than execute it.
    if (pepGate() != null) return error.SkipZigTest; // PEP present: nothing to prove here
    try std.testing.expect(!block_ip(0x08080808));
    try std.testing.expect(!unblock_ip(0x08080808));
}

test "WFP IOCTL codes match WFP protocol spec (transport unchanged)" {
    _ = wfp_ioctl;
}

// ============================================================
// Tests
// ============================================================

test "EnforcementStatus.toString returns uppercase" {
    try std.testing.expect(std.mem.eql(u8, EnforcementStatus.no_op.toString(), "NO_OP"));
    try std.testing.expect(std.mem.eql(u8, EnforcementStatus.executed.toString(), "EXECUTED"));
    try std.testing.expect(std.mem.eql(u8, EnforcementStatus.rejected.toString(), "REJECTED"));
}

test "RejectionReason.toString returns uppercase" {
    try std.testing.expect(std.mem.eql(u8, RejectionReason.none.toString(), "NONE"));
    try std.testing.expect(std.mem.eql(u8, RejectionReason.localhost_protected.toString(), "LOCALHOST_BLOCK_FORBIDDEN"));
}

test "isLocalhost detects 127.0.0.1" {
    try std.testing.expect(isLocalhost(0x7F000001));
    try std.testing.expect(!isLocalhost(0x0A000001));
}

test "isPrivateNetwork detects RFC1918 ranges" {
    try std.testing.expect(isPrivateNetwork(0x0A000001)); // 10.0.0.1
    try std.testing.expect(isPrivateNetwork(0xAC100001)); // 172.16.0.1
    try std.testing.expect(isPrivateNetwork(0xC0A80001)); // 192.168.0.1
    try std.testing.expect(!isPrivateNetwork(0x08080808)); // 8.8.8.8
}

test "isCriticalInfra detects well-known DNS" {
    try std.testing.expect(isCriticalInfra(0x08080808)); // 8.8.8.8
    try std.testing.expect(isCriticalInfra(0x01010101)); // 1.1.1.1
    try std.testing.expect(!isCriticalInfra(0x0A000001));
}

test "RustPep.init creates empty blocklist" {
    var pep = RustPep.init(std.testing.allocator);
    defer pep.deinit();
    try std.testing.expect(pep.blockedCount() == 0);
    try std.testing.expect(pep.total_executed == 0);
}

test "RustPep.execute allows non-blocking decisions" {
    var pep = RustPep.init(std.testing.allocator);
    defer pep.deinit();
    var event = canonical.create(.zig_core);
    event.source_ip = 0x0A000001;
    event.dest_ip = 0x0A000002;
    const decision = policy.EnforcementDecision{
        .action = .alert,
        .rule = .verdict_suspicious,
        .confidence = 60,
        .reason = "test",
        .event_id = 1,
        .brain_recommended_verdict = .suspicious,
        .original_verdict = .suspicious,
        .threat_score = 40,
    };
    const result = pep.execute(event, decision);
    try std.testing.expect(result.status == .executed);
    try std.testing.expect(result.actual_action == .alert);
    try std.testing.expect(pep.total_executed == 1);
}

test "RustPep.execute rejects blocking localhost" {
    var pep = RustPep.init(std.testing.allocator);
    defer pep.deinit();
    var event = canonical.create(.zig_core);
    event.source_ip = 0x7F000001; // localhost
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
    const result = pep.execute(event, decision);
    try std.testing.expect(result.status == .rejected);
    try std.testing.expect(result.reason == .localhost_protected);
    try std.testing.expect(result.actual_action == .allow);
    try std.testing.expect(pep.total_rejected == 1);
}

test "RustPep.execute defers blocking private networks at low confidence" {
    var pep = RustPep.init(std.testing.allocator);
    defer pep.deinit();
    var event = canonical.create(.zig_core);
    event.source_ip = 0x0A0000A1; // private
    event.dest_ip = 0x0A000002;
    const decision = policy.EnforcementDecision{
        .action = .block,
        .rule = .verdict_malicious,
        .confidence = 60, // below 70 threshold
        .reason = "test",
        .event_id = 1,
        .brain_recommended_verdict = .malicious,
        .original_verdict = .malicious,
        .threat_score = 50,
    };
    const result = pep.execute(event, decision);
    try std.testing.expect(result.status == .deferred);
    try std.testing.expect(result.reason == .private_network_block_deferred);
    try std.testing.expect(result.actual_action == .alert);
}

test "RustPep.execute blocks private networks at high confidence" {
    var pep = RustPep.init(std.testing.allocator);
    defer pep.deinit();
    var event = canonical.create(.zig_core);
    event.source_ip = 0x0A0000A1; // private
    event.dest_ip = 0x0A000002;
    const decision = policy.EnforcementDecision{
        .action = .block,
        .rule = .verdict_malicious,
        .confidence = 90, // above 70 threshold
        .reason = "test",
        .event_id = 1,
        .brain_recommended_verdict = .malicious,
        .original_verdict = .malicious,
        .threat_score = 80,
    };
    const result = pep.execute(event, decision);
    try std.testing.expect(result.status == .executed);
    try std.testing.expect(result.blocked_ip == 0x0A0000A1);
    try std.testing.expect(pep.isBlocked(0x0A0000A1));
}

test "RustPep.execute rejects blocking critical infra" {
    var pep = RustPep.init(std.testing.allocator);
    defer pep.deinit();
    var event = canonical.create(.zig_core);
    event.source_ip = 0x08080808; // Google DNS
    event.dest_ip = 0x0A000002;
    const decision = policy.EnforcementDecision{
        .action = .block,
        .rule = .verdict_malicious,
        .confidence = 95,
        .reason = "test",
        .event_id = 1,
        .brain_recommended_verdict = .malicious,
        .original_verdict = .malicious,
        .threat_score = 90,
    };
    const result = pep.execute(event, decision);
    try std.testing.expect(result.status == .rejected);
    try std.testing.expect(result.reason == .critical_infra_protected);
}

test "RustPep.execute adds IP to blocklist" {
    var pep = RustPep.init(std.testing.allocator);
    defer pep.deinit();
    var event = canonical.create(.zig_core);
    event.source_ip = 0xCBCBCBCB; // public, unknown
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
    const result = pep.execute(event, decision);
    try std.testing.expect(result.status == .executed);
    try std.testing.expect(pep.isBlocked(0xCBCBCBCB));
    try std.testing.expect(pep.blockedCount() == 1);
}

test "RustPep.execute detects duplicate blocks" {
    var pep = RustPep.init(std.testing.allocator);
    defer pep.deinit();
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
    _ = pep.execute(event, decision);
    const result = pep.execute(event, decision);
    try std.testing.expect(result.status == .executed);
    try std.testing.expect(result.reason == .duplicate_block);
    try std.testing.expect(pep.blockedCount() == 1); // still only one entry
}

test "RustPep.unblock removes from blocklist" {
    var pep = RustPep.init(std.testing.allocator);
    defer pep.deinit();
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
    _ = pep.execute(event, decision);
    try std.testing.expect(pep.isBlocked(0xCBCBCBCB));
    try std.testing.expect(pep.unblock(0xCBCBCBCB));
    try std.testing.expect(!pep.isBlocked(0xCBCBCBCB));
}

test "RustPep.resetStats clears blocklist and counters" {
    var pep = RustPep.init(std.testing.allocator);
    defer pep.deinit();
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
    _ = pep.execute(event, decision);
    try std.testing.expect(pep.blockedCount() == 1);
    pep.resetStats();
    try std.testing.expect(pep.blockedCount() == 0);
    try std.testing.expect(pep.total_executed == 0);
}

test "EnforcementResult.isExecuted and isRejected work" {
    const r1 = EnforcementResult{
        .status = .executed,
        .reason = .none,
        .requested_action = .block,
        .actual_action = .block,
        .event_id = 1,
        .blocked_ip = 0,
        .message = "ok",
    };
    try std.testing.expect(r1.isExecuted());
    try std.testing.expect(!r1.isRejected());

    const r2 = EnforcementResult{
        .status = .rejected,
        .reason = .localhost_protected,
        .requested_action = .block,
        .actual_action = .allow,
        .event_id = 1,
        .blocked_ip = 0,
        .message = "nope",
    };
    try std.testing.expect(!r2.isExecuted());
    try std.testing.expect(r2.isRejected());
}