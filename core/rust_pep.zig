//! rust_pep.zig - AEGIS Rust PEP (Policy Enforcement Point) (Rewrite Phase 13)
//!
//! Security authority: VALIDATES then EXECUTES EnforcementDecision from Policy Engine.
//! Pattern: validate -> execute (Master Plan: Rust = security authority).
//!
//! Architecture:
//!   Policy Engine (12) -> Rust PEP (13) -> [future Forensics (14)]
//!   PEP receives EnforcementDecision, validates it's safe, then executes.
//!
//! Phase 13 (this file): Zig-side PEP executor.
//! Future: actual Rust FFI calls to rust_shield for WFP blockIp() etc.
//! For now, simulates enforcement with in-memory blocklist + logging.
//!
//! Security validation rules (PEP must NOT execute invalid decisions):
//!   1. Block decisions for localhost (127.0.0.1, ::1) are REJECTED
//!   2. Block decisions for private networks (10.0.0.0/8, 192.168.0.0/16) require elevated confidence
//!   3. Quarantine decisions require confidence >= 80
//!   4. Rate limit decisions require explicit rule match
//!   5. Allow decisions are always safe (no validation needed)

const std = @import("std");
const canonical = @import("canonical_event.zig");
const policy = @import("policy_engine.zig");
const detection = @import("detection_engine.zig");

// ============================================================
// Enforcement Result
// ============================================================

pub const EnforcementStatus = enum(u8) {
    /// Decision was executed successfully.
    executed = 0,
    /// Decision was rejected by PEP validation (unsafe).
    rejected = 1,
    /// Decision was deferred (e.g., waiting for elevated confidence).
    deferred = 2,
    /// Execution failed (e.g., WFP call failed).
    failed = 3,
    /// No action needed (allow decisions are no-ops).
    no_op = 4,

    pub fn toString(self: EnforcementStatus) []const u8 {
        return switch (self) {
            .executed => "EXECUTED",
            .rejected => "REJECTED",
            .deferred => "DEFERRED",
            .failed => "FAILED",
            .no_op => "NO_OP",
        };
    }

    pub fn isSuccess(self: EnforcementStatus) bool {
        return self == .executed or self == .no_op;
    }

    pub fn isFailure(self: EnforcementStatus) bool {
        return self == .rejected or self == .failed;
    }
};

pub const RejectionReason = enum(u8) {
    none = 0,
    /// Attempted to block localhost.
    localhost_protected = 1,
    /// Attempted to block private network without sufficient confidence.
    private_network_low_confidence = 2,
    /// Quarantine requires confidence >= 80.
    quarantine_low_confidence = 3,
    /// Rate limit requires explicit rule match.
    rate_limit_no_rule = 4,
    /// Invalid decision (nil event_id, etc.).
    invalid_decision = 5,

    pub fn toString(self: RejectionReason) []const u8 {
        return switch (self) {
            .none => "NONE",
            .localhost_protected => "LOCALHOST_PROTECTED",
            .private_network_low_confidence => "PRIVATE_NETWORK_LOW_CONFIDENCE",
            .quarantine_low_confidence => "QUARANTINE_LOW_CONFIDENCE",
            .rate_limit_no_rule => "RATE_LIMIT_NO_RULE",
            .invalid_decision => "INVALID_DECISION",
        };
    }
};

pub const EnforcementResult = struct {
    status: EnforcementStatus,
    reason: RejectionReason,
    /// The action that was requested.
    requested_action: policy.EnforcementAction,
    /// The action that was actually taken (may differ if deferred/rejected).
    actual_action: policy.EnforcementAction,
    /// Event ID that was processed.
    event_id: u64,
    /// IP that was blocked (if action was block and executed).
    blocked_ip: u32,
    /// Human-readable message.
    message: []const u8,

    pub fn isExecuted(self: EnforcementResult) bool {
        return self.status == .executed;
    }

    pub fn isRejected(self: EnforcementResult) bool {
        return self.status == .rejected;
    }
};

// ============================================================
// Blocklist (in-memory, simulates WFP blockIp)
// ============================================================

const BlocklistEntry = struct {
    ip: u32,
    blocked_at_ns: i128,
    reason: []const u8,
    rule: policy.PolicyRule,
};

const MAX_BLOCKLIST_ENTRIES: usize = 1024;

pub const Blocklist = struct {
    entries: [MAX_BLOCKLIST_ENTRIES]?BlocklistEntry,
    count: usize,

    pub fn init() Blocklist {
        return .{
            .entries = [_]?BlocklistEntry{null} ** MAX_BLOCKLIST_ENTRIES,
            .count = 0,
        };
    }

    /// Add an IP to the blocklist. Returns false if full.
    pub fn add(self: *Blocklist, ip: u32, blocked_at_ns: i128, reason: []const u8, rule: policy.PolicyRule) bool {
        // Check if already blocked
        for (0..self.count) |i| {
            if (self.entries[i]) |entry| {
                if (entry.ip == ip) return true; // already blocked
            }
        }
        if (self.count >= MAX_BLOCKLIST_ENTRIES) return false;
        self.entries[self.count] = .{
            .ip = ip,
            .blocked_at_ns = blocked_at_ns,
            .reason = reason,
            .rule = rule,
        };
        self.count += 1;
        return true;
    }

    /// Check if an IP is blocked.
    pub fn isBlocked(self: *const Blocklist, ip: u32) bool {
        for (0..self.count) |i| {
            if (self.entries[i]) |entry| {
                if (entry.ip == ip) return true;
            }
        }
        return false;
    }

    /// Remove an IP from the blocklist. Returns true if removed.
    pub fn remove(self: *Blocklist, ip: u32) bool {
        for (0..self.count) |i| {
            if (self.entries[i]) |entry| {
                if (entry.ip == ip) {
                    // Shift remaining entries down
                    var j: usize = i;
                    while (j < self.count - 1) : (j += 1) {
                        self.entries[j] = self.entries[j + 1];
                    }
                    self.entries[self.count - 1] = null;
                    self.count -= 1;
                    return true;
                }
            }
        }
        return false;
    }

    /// Clear all entries.
    pub fn clear(self: *Blocklist) void {
        for (0..self.count) |i| {
            self.entries[i] = null;
        }
        self.count = 0;
    }
};

// ============================================================
// PEP Executor (security authority)
// ============================================================

pub const PepExecutor = struct {
    blocklist: Blocklist,
    /// Total decisions received.
    total_decisions: u64,
    /// Total executed (block/quarantine actually applied).
    total_executed: u64,
    /// Total rejected (validation failed).
    total_rejected: u64,
    /// Total deferred (waiting for elevated confidence).
    total_deferred: u64,
    /// Total no-ops (allow decisions).
    total_no_ops: u64,
    /// Total failures (execution error).
    total_failures: u64,

    pub fn init() PepExecutor {
        return .{
            .blocklist = Blocklist.init(),
            .total_decisions = 0,
            .total_executed = 0,
            .total_rejected = 0,
            .total_deferred = 0,
            .total_no_ops = 0,
            .total_failures = 0,
        };
    }

    /// Validate and execute an enforcement decision.
    /// This is the main entry point - dispatcher calls this after Policy Engine.
    pub fn execute(
        self: *PepExecutor,
        event: canonical.CanonicalEvent,
        decision: policy.EnforcementDecision,
    ) EnforcementResult {
        self.total_decisions += 1;

        // --- Validation phase ---
        const validation = self.validate(event, decision);
        if (validation.status == .rejected) {
            self.total_rejected += 1;
            return validation;
        }
        if (validation.status == .deferred) {
            self.total_deferred += 1;
            return validation;
        }

        // --- Execution phase ---
        switch (decision.action) {
            .allow, .log_only => {
                self.total_no_ops += 1;
                return .{
                    .status = .no_op,
                    .reason = .none,
                    .requested_action = decision.action,
                    .actual_action = decision.action,
                    .event_id = event.event_id,
                    .blocked_ip = 0,
                    .message = "allow/log_only: no enforcement needed",
                };
            },
            .alert => {
                // Alert is logged but not enforced (no blocklist change).
                self.total_no_ops += 1;
                return .{
                    .status = .no_op,
                    .reason = .none,
                    .requested_action = .alert,
                    .actual_action = .alert,
                    .event_id = event.event_id,
                    .blocked_ip = 0,
                    .message = "alert: logged only, no enforcement",
                };
            },
            .block, .quarantine => {
                // Execute block: add source IP to blocklist
                const ip_to_block = event.source_ip;
                if (ip_to_block == 0) {
                    self.total_failures += 1;
                    return .{
                        .status = .failed,
                        .reason = .invalid_decision,
                        .requested_action = decision.action,
                        .actual_action = .allow, // fail-open
                        .event_id = event.event_id,
                        .blocked_ip = 0,
                        .message = "cannot block: source IP is zero",
                    };
                }
                const added = self.blocklist.add(ip_to_block, event.monotonic_ns, decision.reason, decision.rule);
                if (!added) {
                    self.total_failures += 1;
                    return .{
                        .status = .failed,
                        .reason = .none,
                        .requested_action = decision.action,
                        .actual_action = .allow, // fail-open
                        .event_id = event.event_id,
                        .blocked_ip = 0,
                        .message = "blocklist full, cannot add IP",
                    };
                }
                self.total_executed += 1;
                return .{
                    .status = .executed,
                    .reason = .none,
                    .requested_action = decision.action,
                    .actual_action = decision.action,
                    .event_id = event.event_id,
                    .blocked_ip = ip_to_block,
                    .message = "IP blocked successfully",
                };
            },
            .rate_limit => {
                // Rate limit: in Phase 13, logged but not enforced (future: WFP callout)
                self.total_no_ops += 1;
                return .{
                    .status = .no_op,
                    .reason = .none,
                    .requested_action = .rate_limit,
                    .actual_action = .rate_limit,
                    .event_id = event.event_id,
                    .blocked_ip = 0,
                    .message = "rate_limit: logged (future: WFP callout)",
                };
            },
        }
    }

    /// Validate that the decision is safe to execute.
    /// Returns rejected/deferred status if validation fails.
    fn validate(
        self: *const PepExecutor,
        event: canonical.CanonicalEvent,
        decision: policy.EnforcementDecision,
    ) EnforcementResult {
        _ = self;

        // Allow/log_only/alert: always safe, no validation needed
        if (decision.action == .allow or decision.action == .log_only or decision.action == .alert) {
            return .{
                .status = .executed, // pass validation
                .reason = .none,
                .requested_action = decision.action,
                .actual_action = decision.action,
                .event_id = event.event_id,
                .blocked_ip = 0,
                .message = "validation passed (non-blocking action)",
            };
        }

        // Block/quarantine: validate target IP
        const target_ip = event.source_ip;

        // Rule 1: Cannot block localhost (127.0.0.1)
        if (isLocalhost(target_ip)) {
            return .{
                .status = .rejected,
                .reason = .localhost_protected,
                .requested_action = decision.action,
                .actual_action = .allow, // fail-open: allow instead of block
                .event_id = event.event_id,
                .blocked_ip = 0,
                .message = "rejected: cannot block localhost",
            };
        }

        // Rule 2: Block on private networks requires confidence >= 80
        if (isPrivateNetwork(target_ip) and decision.confidence < 80) {
            return .{
                .status = .deferred,
                .reason = .private_network_low_confidence,
                .requested_action = decision.action,
                .actual_action = .allow, // defer: allow for now
                .event_id = event.event_id,
                .blocked_ip = 0,
                .message = "deferred: private network block requires higher confidence",
            };
        }

        // Rule 3: Quarantine requires confidence >= 80
        if (decision.action == .quarantine and decision.confidence < 80) {
            return .{
                .status = .deferred,
                .reason = .quarantine_low_confidence,
                .requested_action = .quarantine,
                .actual_action = .allow, // defer
                .event_id = event.event_id,
                .blocked_ip = 0,
                .message = "deferred: quarantine requires confidence >= 80",
            };
        }

        // Rule 4: Rate limit requires explicit rule match (not default_allow)
        if (decision.action == .rate_limit and decision.rule == .default_allow) {
            return .{
                .status = .rejected,
                .reason = .rate_limit_no_rule,
                .requested_action = .rate_limit,
                .actual_action = .allow,
                .event_id = event.event_id,
                .blocked_ip = 0,
                .message = "rejected: rate_limit requires explicit rule match",
            };
        }

        // All validation passed
        return .{
            .status = .executed, // pass validation
            .reason = .none,
            .requested_action = decision.action,
            .actual_action = decision.action,
            .event_id = event.event_id,
            .blocked_ip = 0,
            .message = "validation passed",
        };
    }

    /// Check if an IP is currently blocked.
    pub fn isIpBlocked(self: *const PepExecutor, ip: u32) bool {
        return self.blocklist.isBlocked(ip);
    }

    /// Unblock an IP manually.
    pub fn unblockIp(self: *PepExecutor, ip: u32) bool {
        return self.blocklist.remove(ip);
    }

    /// Current blocklist size.
    pub fn blocklistSize(self: *const PepExecutor) usize {
        return self.blocklist.count;
    }

    /// Clear all blocked IPs.
    pub fn clearBlocklist(self: *PepExecutor) void {
        self.blocklist.clear();
    }
};

// ============================================================
// IP classification helpers
// ============================================================

/// Check if IP is localhost (127.0.0.0/8).
fn isLocalhost(ip: u32) bool {
    return (ip & 0xFF000000) == 0x7F000000; // 127.0.0.0/8
}

/// Check if IP is in a private network range.
/// 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
fn isPrivateNetwork(ip: u32) bool {
    // 10.0.0.0/8
    if ((ip & 0xFF000000) == 0x0A000000) return true;
    // 172.16.0.0/12
    if ((ip & 0xFFF00000) == 0xAC100000) return true;
    // 192.168.0.0/16
    if ((ip & 0xFFFF0000) == 0xC0A80000) return true;
    return false;
}

// ============================================================
// Tests (all use local executor instances - parallelism-safe)
// ============================================================

test "EnforcementStatus.toString returns readable names" {
    try std.testing.expect(std.mem.eql(u8, EnforcementStatus.executed.toString(), "EXECUTED"));
    try std.testing.expect(std.mem.eql(u8, EnforcementStatus.rejected.toString(), "REJECTED"));
    try std.testing.expect(std.mem.eql(u8, EnforcementStatus.deferred.toString(), "DEFERRED"));
    try std.testing.expect(std.mem.eql(u8, EnforcementStatus.failed.toString(), "FAILED"));
    try std.testing.expect(std.mem.eql(u8, EnforcementStatus.no_op.toString(), "NO_OP"));
}

test "EnforcementStatus.isSuccess and isFailure" {
    try std.testing.expect(EnforcementStatus.executed.isSuccess());
    try std.testing.expect(EnforcementStatus.no_op.isSuccess());
    try std.testing.expect(!EnforcementStatus.rejected.isSuccess());
    try std.testing.expect(EnforcementStatus.rejected.isFailure());
    try std.testing.expect(EnforcementStatus.failed.isFailure());
    try std.testing.expect(!EnforcementStatus.executed.isFailure());
}

test "RejectionReason.toString returns readable names" {
    try std.testing.expect(std.mem.eql(u8, RejectionReason.none.toString(), "NONE"));
    try std.testing.expect(std.mem.eql(u8, RejectionReason.localhost_protected.toString(), "LOCALHOST_PROTECTED"));
    try std.testing.expect(std.mem.eql(u8, RejectionReason.private_network_low_confidence.toString(), "PRIVATE_NETWORK_LOW_CONFIDENCE"));
    try std.testing.expect(std.mem.eql(u8, RejectionReason.quarantine_low_confidence.toString(), "QUARANTINE_LOW_CONFIDENCE"));
}

test "isLocalhost detects 127.0.0.0/8" {
    try std.testing.expect(isLocalhost(0x7F000001)); // 127.0.0.1
    try std.testing.expect(isLocalhost(0x7F0000FF)); // 127.0.0.255
    try std.testing.expect(isLocalhost(0x7FFFFFFF)); // 127.255.255.255
    try std.testing.expect(!isLocalhost(0x0A000001)); // 10.0.0.1
    try std.testing.expect(!isLocalhost(0xC0A80001)); // 192.168.0.1
}

test "isPrivateNetwork detects private ranges" {
    try std.testing.expect(isPrivateNetwork(0x0A000001)); // 10.0.0.1
    try std.testing.expect(isPrivateNetwork(0x0AFFFFFF)); // 10.255.255.255
    try std.testing.expect(isPrivateNetwork(0xC0A80001)); // 192.168.0.1
    try std.testing.expect(isPrivateNetwork(0xAC100001)); // 172.16.0.1
    try std.testing.expect(!isPrivateNetwork(0x08080808)); // 8.8.8.8 (public)
    try std.testing.expect(!isPrivateNetwork(0x7F000001)); // 127.0.0.1 (localhost, not private)
}

test "isPrivateNetwork correctly identifies 192.168.1.1" {
    try std.testing.expect(isPrivateNetwork(0xC0A80101)); // 192.168.1.1
}

test "Blocklist init, add, isBlocked" {
    var bl = Blocklist.init();
    try std.testing.expect(bl.count == 0);
    try std.testing.expect(!bl.isBlocked(0x0A000001));

    try std.testing.expect(bl.add(0x0A000001, 1000, "test", .verdict_malicious));
    try std.testing.expect(bl.count == 1);
    try std.testing.expect(bl.isBlocked(0x0A000001));
    try std.testing.expect(!bl.isBlocked(0x0A000002));
}

test "Blocklist add duplicate returns true (idempotent)" {
    var bl = Blocklist.init();
    try std.testing.expect(bl.add(0x0A000001, 1000, "test", .verdict_malicious));
    try std.testing.expect(bl.count == 1);
    try std.testing.expect(bl.add(0x0A000001, 2000, "test2", .verdict_malicious));
    try std.testing.expect(bl.count == 1); // still 1 (idempotent)
}

test "Blocklist remove" {
    var bl = Blocklist.init();
    _ = bl.add(0x0A000001, 1000, "test", .verdict_malicious);
    _ = bl.add(0x0A000002, 2000, "test", .verdict_malicious);
    try std.testing.expect(bl.count == 2);

    try std.testing.expect(bl.remove(0x0A000001));
    try std.testing.expect(bl.count == 1);
    try std.testing.expect(!bl.isBlocked(0x0A000001));
    try std.testing.expect(bl.isBlocked(0x0A000002));

    // Remove non-existent returns false
    try std.testing.expect(!bl.remove(0x0A000099));
}

test "Blocklist clear" {
    var bl = Blocklist.init();
    _ = bl.add(0x0A000001, 1000, "test", .verdict_malicious);
    _ = bl.add(0x0A000002, 2000, "test", .verdict_malicious);
    try std.testing.expect(bl.count == 2);

    bl.clear();
    try std.testing.expect(bl.count == 0);
    try std.testing.expect(!bl.isBlocked(0x0A000001));
}

test "PepExecutor init has zero stats" {
    const executor = PepExecutor.init();
    try std.testing.expect(executor.total_decisions == 0);
    try std.testing.expect(executor.total_executed == 0);
    try std.testing.expect(executor.total_rejected == 0);
    try std.testing.expect(executor.blocklistSize() == 0);
}

test "execute: allow decision is no_op" {
    var executor = PepExecutor.init();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001;

    const decision = policy.EnforcementDecision{
        .action = .allow,
        .rule = .default_allow,
        .confidence = 50,
        .reason = "test",
        .event_id = event.event_id,
        .brain_recommended_verdict = .benign,
        .original_verdict = .benign,
        .threat_score = 10,
    };

    const result = executor.execute(event, decision);
    try std.testing.expect(result.status == .no_op);
    try std.testing.expect(executor.total_no_ops == 1);
    try std.testing.expect(executor.blocklistSize() == 0);
}

test "execute: alert decision is no_op (logged only)" {
    var executor = PepExecutor.init();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001;

    const decision = policy.EnforcementDecision{
        .action = .alert,
        .rule = .verdict_suspicious,
        .confidence = 70,
        .reason = "test",
        .event_id = event.event_id,
        .brain_recommended_verdict = .suspicious,
        .original_verdict = .suspicious,
        .threat_score = 50,
    };

    const result = executor.execute(event, decision);
    try std.testing.expect(result.status == .no_op);
    try std.testing.expect(executor.blocklistSize() == 0);
}

test "execute: block on public IP executes successfully" {
    var executor = PepExecutor.init();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x08080808; // 8.8.8.8 (public)

    const decision = policy.EnforcementDecision{
        .action = .block,
        .rule = .verdict_malicious,
        .confidence = 90,
        .reason = "test block",
        .event_id = event.event_id,
        .brain_recommended_verdict = .malicious,
        .original_verdict = .malicious,
        .threat_score = 80,
    };

    const result = executor.execute(event, decision);
    try std.testing.expect(result.status == .executed);
    try std.testing.expect(result.blocked_ip == 0x08080808);
    try std.testing.expect(executor.total_executed == 1);
    try std.testing.expect(executor.blocklistSize() == 1);
    try std.testing.expect(executor.isIpBlocked(0x08080808));
}

test "execute: block on localhost is REJECTED" {
    var executor = PepExecutor.init();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x7F000001; // 127.0.0.1

    const decision = policy.EnforcementDecision{
        .action = .block,
        .rule = .verdict_malicious,
        .confidence = 100,
        .reason = "test block localhost",
        .event_id = event.event_id,
        .brain_recommended_verdict = .malicious,
        .original_verdict = .malicious,
        .threat_score = 90,
    };

    const result = executor.execute(event, decision);
    try std.testing.expect(result.status == .rejected);
    try std.testing.expect(result.reason == .localhost_protected);
    try std.testing.expect(result.actual_action == .allow); // fail-open
    try std.testing.expect(executor.total_rejected == 1);
    try std.testing.expect(executor.blocklistSize() == 0); // not blocked
}

test "execute: block on private network with low confidence is DEFERRED" {
    var executor = PepExecutor.init();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001; // 10.0.0.1 (private)

    const decision = policy.EnforcementDecision{
        .action = .block,
        .rule = .verdict_malicious,
        .confidence = 60, // < 80
        .reason = "test private block",
        .event_id = event.event_id,
        .brain_recommended_verdict = .malicious,
        .original_verdict = .malicious,
        .threat_score = 70,
    };

    const result = executor.execute(event, decision);
    try std.testing.expect(result.status == .deferred);
    try std.testing.expect(result.reason == .private_network_low_confidence);
    try std.testing.expect(result.actual_action == .allow); // defer
    try std.testing.expect(executor.total_deferred == 1);
    try std.testing.expect(executor.blocklistSize() == 0); // not blocked
}

test "execute: block on private network with high confidence executes" {
    var executor = PepExecutor.init();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001; // 10.0.0.1 (private)

    const decision = policy.EnforcementDecision{
        .action = .block,
        .rule = .verdict_malicious,
        .confidence = 90, // >= 80
        .reason = "test private block high confidence",
        .event_id = event.event_id,
        .brain_recommended_verdict = .malicious,
        .original_verdict = .malicious,
        .threat_score = 85,
    };

    const result = executor.execute(event, decision);
    try std.testing.expect(result.status == .executed);
    try std.testing.expect(executor.blocklistSize() == 1);
}

test "execute: quarantine with low confidence is DEFERRED" {
    var executor = PepExecutor.init();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x08080808; // public

    const decision = policy.EnforcementDecision{
        .action = .quarantine,
        .rule = .verdict_malicious,
        .confidence = 70, // < 80
        .reason = "test quarantine",
        .event_id = event.event_id,
        .brain_recommended_verdict = .malicious,
        .original_verdict = .malicious,
        .threat_score = 75,
    };

    const result = executor.execute(event, decision);
    try std.testing.expect(result.status == .deferred);
    try std.testing.expect(result.reason == .quarantine_low_confidence);
    try std.testing.expect(executor.total_deferred == 1);
}

test "execute: quarantine with high confidence executes" {
    var executor = PepExecutor.init();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x08080808; // public

    const decision = policy.EnforcementDecision{
        .action = .quarantine,
        .rule = .verdict_malicious,
        .confidence = 85, // >= 80
        .reason = "test quarantine",
        .event_id = event.event_id,
        .brain_recommended_verdict = .malicious,
        .original_verdict = .malicious,
        .threat_score = 80,
    };

    const result = executor.execute(event, decision);
    try std.testing.expect(result.status == .executed);
    try std.testing.expect(executor.total_executed == 1);
}

test "execute: rate_limit with default_allow rule is REJECTED" {
    var executor = PepExecutor.init();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x08080808;

    const decision = policy.EnforcementDecision{
        .action = .rate_limit,
        .rule = .default_allow, // no explicit rule
        .confidence = 60,
        .reason = "test rate_limit",
        .event_id = event.event_id,
        .brain_recommended_verdict = .observe,
        .original_verdict = .observe,
        .threat_score = 40,
    };

    const result = executor.execute(event, decision);
    try std.testing.expect(result.status == .rejected);
    try std.testing.expect(result.reason == .rate_limit_no_rule);
}

test "execute: block with zero source IP FAILS" {
    var executor = PepExecutor.init();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0; // invalid

    const decision = policy.EnforcementDecision{
        .action = .block,
        .rule = .verdict_malicious,
        .confidence = 90,
        .reason = "test block zero IP",
        .event_id = event.event_id,
        .brain_recommended_verdict = .malicious,
        .original_verdict = .malicious,
        .threat_score = 80,
    };

    const result = executor.execute(event, decision);
    try std.testing.expect(result.status == .failed);
    try std.testing.expect(result.reason == .invalid_decision);
    try std.testing.expect(executor.total_failures == 1);
}

test "execute: stats accumulate correctly" {
    var executor = PepExecutor.init();

    // Run 1: ALLOW (no_op)
    var event1 = canonical.create(.wfp_sensor);
    event1.source_ip = 0x0A000001;
    const dec1 = policy.EnforcementDecision{
        .action = .allow,
        .rule = .default_allow,
        .confidence = 50,
        .reason = "test",
        .event_id = 1,
        .brain_recommended_verdict = .benign,
        .original_verdict = .benign,
        .threat_score = 10,
    };
    _ = executor.execute(event1, dec1);

    // Run 2: BLOCK public IP (executed)
    var event2 = canonical.create(.wfp_sensor);
    event2.source_ip = 0x08080808;
    const dec2 = policy.EnforcementDecision{
        .action = .block,
        .rule = .verdict_malicious,
        .confidence = 90,
        .reason = "test",
        .event_id = 2,
        .brain_recommended_verdict = .malicious,
        .original_verdict = .malicious,
        .threat_score = 80,
    };
    _ = executor.execute(event2, dec2);

    // Run 3: BLOCK localhost (rejected)
    var event3 = canonical.create(.wfp_sensor);
    event3.source_ip = 0x7F000001;
    const dec3 = policy.EnforcementDecision{
        .action = .block,
        .rule = .verdict_malicious,
        .confidence = 100,
        .reason = "test",
        .event_id = 3,
        .brain_recommended_verdict = .malicious,
        .original_verdict = .malicious,
        .threat_score = 90,
    };
    _ = executor.execute(event3, dec3);

    try std.testing.expect(executor.total_decisions == 3);
    try std.testing.expect(executor.total_no_ops == 1);
    try std.testing.expect(executor.total_executed == 1);
    try std.testing.expect(executor.total_rejected == 1);
    try std.testing.expect(executor.blocklistSize() == 1);
}

test "unblockIp removes IP from blocklist" {
    var executor = PepExecutor.init();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x08080808;
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
    _ = executor.execute(event, decision);
    try std.testing.expect(executor.isIpBlocked(0x08080808));

    try std.testing.expect(executor.unblockIp(0x08080808));
    try std.testing.expect(!executor.isIpBlocked(0x08080808));
    try std.testing.expect(executor.blocklistSize() == 0);
}

test "clearBlocklist removes all entries" {
    var executor = PepExecutor.init();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x08080808;
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
    _ = executor.execute(event, decision);
    try std.testing.expect(executor.blocklistSize() == 1);

    executor.clearBlocklist();
    try std.testing.expect(executor.blocklistSize() == 0);
}
