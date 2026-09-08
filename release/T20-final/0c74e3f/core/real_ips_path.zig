//! real_ips_path.zig - AEGIS Real IPS Chain (T18 / Step 54)
//!
//! The real IPS path, modelled as an ordered chain:
//!
//!   Real Telemetry -> Detection -> Verdict -> Policy -> Signature
//!   Verification -> Rust PEP -> WFP -> Real Block
//!
//! The enforced-action lifecycle is exercised across the full matrix:
//! allow, block, quarantine, rate-limit, expiry, revoke, rollback, and
//! driver-unavailable. When the WFP driver is gone the path is
//! FAIL-CLOSED: a blocking decision is never silently upgraded to allow.
//!
//! Self-contained: imports std only. WFP is modelled as a DriverState so
//! the whole matrix is deterministic and testable offline (no driver in
//! CI). The Rust PEP and WFP links are reached AFTER signature
//! verification succeeds; a failed signature check rejects before PEP.

const std = @import("std");

pub const CHAIN_LENGTH: usize = 7;

pub const ChainLink = enum(u8) {
    telemetry = 0,
    detection = 1,
    verdict = 2,
    policy = 3,
    signature_verification = 4,
    rust_pep = 5,
    wfp = 6,

    pub fn label(self: ChainLink) []const u8 {
        return switch (self) {
            .telemetry => "telemetry",
            .detection => "detection",
            .verdict => "verdict",
            .policy => "policy",
            .signature_verification => "signature_verification",
            .rust_pep => "rust_pep",
            .wfp => "wfp",
        };
    }
};

pub const CHAIN_ORDER = [CHAIN_LENGTH]ChainLink{
    .telemetry,
    .detection,
    .verdict,
    .policy,
    .signature_verification,
    .rust_pep,
    .wfp,
};

pub const Action = enum(u8) {
    allow = 0,
    block = 1,
    quarantine = 2,
    rate_limit = 3,

    pub fn label(self: Action) []const u8 {
        return switch (self) {
            .allow => "allow",
            .block => "block",
            .quarantine => "quarantine",
            .rate_limit => "rate_limit",
        };
    }
};

pub const Outcome = enum(u8) {
    allowed,
    blocked,
    quarantined,
    rate_limited,
    expired,
    revoked,
    rolled_back,
    fail_closed,
};

pub const DriverState = enum(u8) {
    available,
    unavailable,
};

pub const MAX_RULES: usize = 64;
pub const AUDIT_CAP: usize = 64;

pub const RuleSource = enum(u8) {
    live = 0,
    expired = 1,
    revoked = 2,
    rolled_back = 3,
};

pub const Rule = struct {
    ip: u32 = 0,
    action: Action = .allow,
    created_ms: u64 = 0,
    expiry_ms: u64 = 0,
    active: bool = false,
    source: RuleSource = .live,

    pub fn isExpired(self: *const Rule, now_ms: u64) bool {
        return self.expiry_ms != 0 and now_ms >= self.expiry_ms;
    }
};

pub const RunResult = struct {
    outcome: Outcome = .fail_closed,
    action: Action = .allow,
    reached_pep: bool = false,
    reached_wfp: bool = false,
    applied_rule: ?usize = null,
    driver_unavailable: bool = false,
};

pub const AuditEntry = struct {
    ts_ms: u64,
    ip: u32,
    action: Action,
    outcome: Outcome,
};

pub const RealIPSPath = struct {
    driver: DriverState = .available,
    rules: [MAX_RULES]Rule = undefined,
    rule_count: usize = 0,
    audit: [AUDIT_CAP]AuditEntry = undefined,
    audit_len: usize = 0,

    pub fn setDriver(self: *RealIPSPath, d: DriverState) void {
        self.driver = d;
    }

    pub fn run(
        self: *RealIPSPath,
        ip: u32,
        severity: u8,
        enforce: ?Action,
        sig_verified: bool,
        now_ms: u64,
        expiry_ms: u64,
    ) RunResult {
        // Signature verification is the last admission gate before the
        // Rust PEP + WFP terminal links.
        if (!sig_verified) {
            const res = RunResult{ .outcome = .fail_closed };
            self.appendAudit(now_ms, ip, .allow, .fail_closed);
            return res;
        }
        const eff = enforce orelse .allow;
        if (eff == .allow or severity <= 1) {
            const res = RunResult{
                .outcome = .allowed,
                .action = .allow,
                .reached_pep = true,
                .reached_wfp = true,
            };
            self.appendAudit(now_ms, ip, .allow, .allowed);
            return res;
        }
        // enforcement decision already reached the PEP; WFP must be live.
        if (self.driver == .unavailable) {
            const res = RunResult{
                .outcome = .fail_closed,
                .action = eff,
                .reached_pep = true,
                .reached_wfp = false,
                .driver_unavailable = true,
            };
            self.appendAudit(now_ms, ip, eff, .fail_closed);
            return res;
        }
        const idx = self.applyRule(ip, eff, now_ms, expiry_ms) catch return RunResult{ .outcome = .fail_closed, .action = eff, .reached_pep = true, .reached_wfp = true };
        const outcome: Outcome = switch (eff) {
            .block => .blocked,
            .quarantine => .quarantined,
            .rate_limit => .rate_limited,
            .allow => .allowed,
        };
        const res = RunResult{
            .outcome = outcome,
            .action = eff,
            .reached_pep = true,
            .reached_wfp = true,
            .applied_rule = idx,
        };
        self.appendAudit(now_ms, ip, eff, outcome);
        return res;
    }

    pub fn expire(self: *RealIPSPath, now_ms: u64) usize {
        var n: usize = 0;
        for (self.rules[0..self.rule_count]) |*r| {
            if (r.active and r.isExpired(now_ms)) {
                r.active = false;
                r.source = .expired;
                self.appendAudit(now_ms, r.ip, r.action, .expired);
                n += 1;
            }
        }
        return n;
    }

    pub fn revoke(self: *RealIPSPath, ip: u32, now_ms: u64) bool {
        for (self.rules[0..self.rule_count]) |*r| {
            if (r.active and r.ip == ip) {
                r.active = false;
                r.source = .revoked;
                self.appendAudit(now_ms, ip, r.action, .revoked);
                return true;
            }
        }
        return false;
    }

    pub fn rollback(self: *RealIPSPath, ip: u32, now_ms: u64) bool {
        for (self.rules[0..self.rule_count]) |*r| {
            if (r.active and r.ip == ip) {
                r.active = false;
                r.source = .rolled_back;
                self.appendAudit(now_ms, ip, r.action, .rolled_back);
                return true;
            }
        }
        return false;
    }

    pub fn isBlocked(self: *const RealIPSPath, ip: u32) bool {
        for (self.rules[0..self.rule_count]) |r| {
            if (r.active and r.ip == ip and (r.action == .block or r.action == .quarantine)) {
                return true;
            }
        }
        return false;
    }

    pub fn activeRuleCount(self: *const RealIPSPath) usize {
        var n: usize = 0;
        for (self.rules[0..self.rule_count]) |r| {
            if (r.active) n += 1;
        }
        return n;
    }

    fn applyRule(self: *RealIPSPath, ip: u32, action: Action, now_ms: u64, expiry_ms: u64) !usize {
        if (self.rule_count >= MAX_RULES) return error.TableFull;
        const idx = self.rule_count;
        self.rules[idx] = .{
            .ip = ip,
            .action = action,
            .created_ms = now_ms,
            .expiry_ms = expiry_ms,
            .active = true,
            .source = .live,
        };
        self.rule_count += 1;
        return idx;
    }

    fn appendAudit(self: *RealIPSPath, ts_ms: u64, ip: u32, action: Action, outcome: Outcome) void {
        if (self.audit_len < AUDIT_CAP) {
            self.audit[self.audit_len] = .{ .ts_ms = ts_ms, .ip = ip, .action = action, .outcome = outcome };
            self.audit_len += 1;
        }
    }
};

// ============================================================
// Tests
// ============================================================

fn unsignedIp(a: u8, b: u8, c: u8, d: u8) u32 {
    return (@as(u32, a) << 24) | (@as(u32, b) << 16) | (@as(u32, c) << 8) | @as(u32, d);
}

const ipA = unsignedIp(198, 51, 100, 12);
const ipB = unsignedIp(198, 51, 100, 34);

test "CHAIN_ORDER is the real IPS path in mandated order" {
    const want = [7][]const u8{
        "telemetry",
        "detection",
        "verdict",
        "policy",
        "signature_verification",
        "rust_pep",
        "wfp",
    };
    for (CHAIN_ORDER, want) |link, label| {
        try std.testing.expectEqualStrings(label, link.label());
    }
}

test "run with no signature verification is fail-closed before PEP" {
    var path = RealIPSPath{};
    const r = path.run(ipA, 4, .block, false, 1000, 0);
    try std.testing.expectEqual(Outcome.fail_closed, r.outcome);
    try std.testing.expectEqual(false, r.reached_pep);
    try std.testing.expectEqual(false, r.reached_wfp);
    try std.testing.expectEqual(false, path.isBlocked(ipA));
}

test "allow does not install a rule" {
    var path = RealIPSPath{};
    const r = path.run(ipA, 0, .allow, true, 1000, 0);
    try std.testing.expectEqual(Outcome.allowed, r.outcome);
    try std.testing.expectEqual(true, r.reached_pep);
    try std.testing.expectEqual(true, r.reached_wfp);
    try std.testing.expectEqual(@as(usize, 0), path.activeRuleCount());
}

test "block applies a real block rule" {
    var path = RealIPSPath{};
    const r = path.run(ipA, 4, .block, true, 1000, 0);
    try std.testing.expectEqual(Outcome.blocked, r.outcome);
    try std.testing.expectEqual(true, r.reached_pep);
    try std.testing.expectEqual(true, r.reached_wfp);
    try std.testing.expectEqual(true, path.isBlocked(ipA));
}

test "quarantine applies a quarantine rule" {
    var path = RealIPSPath{};
    const r = path.run(ipA, 3, .quarantine, true, 1000, 0);
    try std.testing.expectEqual(Outcome.quarantined, r.outcome);
    try std.testing.expectEqual(true, path.isBlocked(ipA));
    try std.testing.expectEqual(Action.quarantine, r.action);
}

test "rate-limit applies a throttle rule" {
    var path = RealIPSPath{};
    const r = path.run(ipA, 2, .rate_limit, true, 1000, 0);
    try std.testing.expectEqual(Outcome.rate_limited, r.outcome);
    try std.testing.expectEqual(Action.rate_limit, r.action);
    try std.testing.expectEqual(false, path.isBlocked(ipA));
    try std.testing.expectEqual(@as(usize, 1), path.activeRuleCount());
}

test "expiry deactivates a time-bounded rule" {
    var path = RealIPSPath{};
    _ = path.run(ipA, 4, .block, true, 1000, 2_000);
    try std.testing.expectEqual(true, path.isBlocked(ipA));
    const n = path.expire(2_000);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(false, path.isBlocked(ipA));
}

test "revoke removes a live rule" {
    var path = RealIPSPath{};
    _ = path.run(ipA, 4, .block, true, 1000, 0);
    try std.testing.expectEqual(true, path.revoke(ipA, 1100));
    try std.testing.expectEqual(false, path.isBlocked(ipA));
    try std.testing.expectEqual(Outcome.revoked, path.audit[path.audit_len - 1].outcome);
}

test "rollback removes a live rule and records rollback" {
    var path = RealIPSPath{};
    _ = path.run(ipA, 4, .block, true, 1000, 0);
    try std.testing.expectEqual(true, path.rollback(ipA, 1100));
    try std.testing.expectEqual(false, path.isBlocked(ipA));
    try std.testing.expectEqual(Outcome.rolled_back, path.audit[path.audit_len - 1].outcome);
}

test "driver-unavailable is fail-closed (blocking never becomes allow)" {
    var path = RealIPSPath{};
    path.setDriver(.unavailable);
    const r = path.run(ipA, 4, .block, true, 1000, 0);
    try std.testing.expectEqual(Outcome.fail_closed, r.outcome);
    try std.testing.expectEqual(true, r.driver_unavailable);
    try std.testing.expectEqual(true, r.reached_pep);
    try std.testing.expectEqual(false, r.reached_wfp);
    try std.testing.expectEqual(false, path.isBlocked(ipA));
}

test "driver-unavailable cannot block even for critical severity" {
    var path = RealIPSPath{};
    path.setDriver(.unavailable);
    const r = path.run(ipA, 4, .block, true, 1000, 0);
    try std.testing.expectEqual(Outcome.fail_closed, r.outcome);
    try std.testing.expectEqual(Action.block, r.action);
    try std.testing.expectEqual(@as(usize, 0), path.activeRuleCount());
}

test "driver restore resumes enforcement" {
    var path = RealIPSPath{};
    path.setDriver(.unavailable);
    _ = path.run(ipA, 4, .block, true, 1000, 0);
    path.setDriver(.available);
    const r = path.run(ipB, 4, .block, true, 1100, 0);
    try std.testing.expectEqual(Outcome.blocked, r.outcome);
    try std.testing.expectEqual(true, path.isBlocked(ipB));
}

test "per-ip rules are isolated" {
    var path = RealIPSPath{};
    _ = path.run(ipA, 4, .block, true, 1000, 0);
    try std.testing.expectEqual(false, path.isBlocked(ipB));
    try std.testing.expectEqual(true, path.isBlocked(ipA));
}

test "audit trail is bounded and never overflows" {
    var path = RealIPSPath{};
    var i: usize = 0;
    while (i < AUDIT_CAP * 2) : (i += 1) {
        _ = path.run(ipA, 4, .block, true, 1000, 0);
    }
    try std.testing.expectEqual(AUDIT_CAP, path.audit_len);
}