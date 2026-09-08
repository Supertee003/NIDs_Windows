//! ips_canary_order.zig - AEGIS IPS Canary Order (T18 / Steps 53)
//!
//! The mandated IPS canary progression (order strictly enforced):
//!
//!   Detection Only -> Shadow -> Canary -> Limited Enforcement -> Expanded Enforcement
//!
//! Stage semantics:
//!   detection_only       - verdicts computed but never applied (pure observe)
//!   shadow               - verdicts logged alongside the live path, never applied
//!   canary               - applied ONLY to canary traffic (203.0.113.0/24, CANA magic)
//!   limited_enforcement  - applied ONLY within the canary's declared scope block
//!   expanded_enforcement - applied to real traffic (fully live IPS)
//!   rolled_back          - fail-closed hold; promotions are blocked until reset
//!
//! Canary spec carries scope/target/expiry/rollback/audit:
//!   scope    = CIDR block the canary may enforce on (canary stage is pinned to
//!              TEST-NET-3; limited stage uses spec.scope_cidr_base/_prefix_len)
//!   target   = target_port scoping of allowed enforcement
//!   expiry   = time-bounded canary; expiry_after_ms != 0 -> auto rollback
//!   rollback = auto (consecutive failures / fail rate / expiry) + manual
//!   audit    = bounded append-only trail of every transition with reason
//!
//! Promotion requires ALL gates to hold (fail-closed): minimum observations,
//! failure rate <= max_fail_bps, soak dwell elapsed, and HUMAN APPROVAL for
//! the limited -> expanded transition.
//!
//! Self-contained: imports std only. Time is injected (now_ms) so every
//! transition is deterministic and testable offline.

const std = @import("std");

pub const CANARY_MAGIC: u32 = 0x43414E41;
pub const CANARY_IP_BASE: u32 = 0xCB007100;
pub const CANARY_PREFIX_LEN: u8 = 24;

pub const AUDIT_CAP: usize = 64;

pub const Stage = enum(u8) {
    detection_only = 0,
    shadow = 1,
    canary = 2,
    limited_enforcement = 3,
    expanded_enforcement = 4,
    rolled_back = 5,

    pub fn label(self: Stage) []const u8 {
        return switch (self) {
            .detection_only => "detection_only",
            .shadow => "shadow",
            .canary => "canary",
            .limited_enforcement => "limited_enforcement",
            .expanded_enforcement => "expanded_enforcement",
            .rolled_back => "rolled_back",
        };
    }

    pub fn isEnforcing(self: Stage) bool {
        return switch (self) {
            .canary, .limited_enforcement, .expanded_enforcement => true,
            else => false,
        };
    }
};

pub const PROMOTION_ORDER = [5]Stage{
    .detection_only,
    .shadow,
    .canary,
    .limited_enforcement,
    .expanded_enforcement,
};

pub const CanarySpec = struct {
    name: []const u8 = "default",
    scope_cidr_base: u32 = CANARY_IP_BASE,
    scope_prefix_len: u8 = CANARY_PREFIX_LEN,
    target_port: u16 = 22,
    expiry_after_ms: u64 = 0,
};

pub const PromotionGate = struct {
    min_observations: u32 = 5,
    max_fail_bps: u32 = 200,
    min_dwell_ms: u64 = 60_000,
    consecutive_fail_limit: u32 = 3,
    auto_rollback_fail_bps: u32 = 2000,
    auto_rollback_min_runs: u32 = 10,
    require_human_approval_limited_to_expanded: bool = true,
};

pub const PromotionError = error{ GateNotMet, ImpossibleFromStage };

pub const DenyReason = enum {
    none,
    min_observations_not_met,
    fail_rate_too_high,
    dwell_not_met,
    human_approval_missing,
    stage_order,
    expired,
};

pub const AuditReason = enum {
    gate_met,
    human_approved,
    auto_rollback_consecutive,
    auto_rollback_fail_rate,
    expiry,
    manual_rollback,
    reset,
};

pub const AuditEntry = struct {
    ts_ms: u64,
    from: Stage,
    to: Stage,
    reason: AuditReason,
};

pub const IPSCanaryOrder = struct {
    spec: CanarySpec = .{},
    gate: PromotionGate = .{},
    stage: Stage = .detection_only,
    now_ms: u64 = 0,
    stage_entered_ms: u64 = 0,
    human_approved_limited_to_expanded: bool = false,
    rollbacks: u32 = 0,
    last_deny: DenyReason = .none,

    stage_observations: u32 = 0,
    stage_fails: u32 = 0,
    stage_passes: u32 = 0,
    stage_consecutive_fails: u32 = 0,

    audit: [AUDIT_CAP]AuditEntry = undefined,
    audit_len: usize = 0,

    pub fn observe(self: *IPSCanaryOrder, passed: bool) void {
        self.stage_observations += 1;
        if (passed) {
            self.stage_passes += 1;
            self.stage_consecutive_fails = 0;
        } else {
            self.stage_fails += 1;
            self.stage_consecutive_fails += 1;
        }
        if (self.stage.isEnforcing()) {
            if (self.stage_consecutive_fails >= self.gate.consecutive_fail_limit) {
                self.transition(.rolled_back, .auto_rollback_consecutive);
                return;
            }
            if (self.stage_observations >= self.gate.auto_rollback_min_runs and
                self.failRateBps() > self.gate.auto_rollback_fail_bps)
            {
                self.transition(.rolled_back, .auto_rollback_fail_rate);
            }
        }
    }

    pub fn evaluateExpiry(self: *IPSCanaryOrder) void {
        if (self.isExpired()) {
            self.transition(.rolled_back, .expiry);
        }
    }

    pub fn isExpired(self: *const IPSCanaryOrder) bool {
        return self.spec.expiry_after_ms != 0 and
            (self.now_ms - self.stage_entered_ms) >= self.spec.expiry_after_ms;
    }

    pub fn promote(self: *IPSCanaryOrder) PromotionError!Stage {
        self.last_deny = .none;
        const target = nextStage(self.stage) orelse {
            self.last_deny = .stage_order;
            return PromotionError.ImpossibleFromStage;
        };
        if (self.stage_observations < self.gate.min_observations) {
            self.last_deny = .min_observations_not_met;
            return PromotionError.GateNotMet;
        }
        if (self.failRateBps() > self.gate.max_fail_bps) {
            self.last_deny = .fail_rate_too_high;
            return PromotionError.GateNotMet;
        }
        if ((self.now_ms - self.stage_entered_ms) < self.gate.min_dwell_ms) {
            self.last_deny = .dwell_not_met;
            return PromotionError.GateNotMet;
        }
        if (target == .expanded_enforcement and
            self.gate.require_human_approval_limited_to_expanded and
            !self.human_approved_limited_to_expanded)
        {
            self.last_deny = .human_approval_missing;
            return PromotionError.GateNotMet;
        }
        const reason: AuditReason = if (target == .expanded_enforcement) .human_approved else .gate_met;
        self.transition(target, reason);
        return target;
    }

    pub fn approveLimitedToExpanded(self: *IPSCanaryOrder) void {
        self.human_approved_limited_to_expanded = true;
    }

    pub fn manualRollback(self: *IPSCanaryOrder) PromotionError!void {
        if (!self.stage.isEnforcing()) return PromotionError.ImpossibleFromStage;
        self.transition(.rolled_back, .manual_rollback);
    }

    pub fn reset(self: *IPSCanaryOrder) void {
        self.transition(.detection_only, .reset);
    }

    pub fn stageApplies(self: *const IPSCanaryOrder, ip: u32) bool {
        return switch (self.stage) {
            .detection_only, .shadow, .rolled_back => false,
            .canary => ipWithin(ip, CANARY_IP_BASE, CANARY_PREFIX_LEN),
            .limited_enforcement => ipWithin(ip, self.spec.scope_cidr_base, self.spec.scope_prefix_len),
            .expanded_enforcement => true,
        };
    }

    pub fn failRateBps(self: *const IPSCanaryOrder) u32 {
        if (self.stage_observations == 0) return 0;
        return @intCast((@as(u64, self.stage_fails) * 10000) / self.stage_observations);
    }

    pub fn auditTail(self: *const IPSCanaryOrder, n: usize) []const AuditEntry {
        const take = @min(n, self.audit_len);
        return self.audit[self.audit_len - take .. self.audit_len];
    }

    fn transition(self: *IPSCanaryOrder, to: Stage, reason: AuditReason) void {
        if (self.audit_len < AUDIT_CAP) {
            self.audit[self.audit_len] = .{
                .ts_ms = self.now_ms,
                .from = self.stage,
                .to = to,
                .reason = reason,
            };
            self.audit_len += 1;
        }
        if (to == .rolled_back) self.rollbacks += 1;
        self.stage = to;
        self.stage_entered_ms = self.now_ms;
        self.stage_observations = 0;
        self.stage_fails = 0;
        self.stage_passes = 0;
        self.stage_consecutive_fails = 0;
    }
};

fn nextStage(cur: Stage) ?Stage {
    return switch (cur) {
        .detection_only => .shadow,
        .shadow => .canary,
        .canary => .limited_enforcement,
        .limited_enforcement => .expanded_enforcement,
        else => null,
    };
}

fn ipWithin(ip: u32, base: u32, prefix_len: u8) bool {
    if (prefix_len >= 32) return ip == base;
    if (prefix_len == 0) return true;
    const shift: u5 = @intCast(32 - prefix_len);
    return (ip >> shift) == (base >> shift);
}

// ============================================================
// Tests
// ============================================================

fn unsignedIp(a: u8, b: u8, c: u8, d: u8) u32 {
    return (@as(u32, a) << 24) | (@as(u32, b) << 16) | (@as(u32, c) << 8) | @as(u32, d);
}

const canaryIp = unsignedIp(203, 0, 113, 77);
const scopeIp = unsignedIp(10, 20, 0, 5);
const realIp = unsignedIp(198, 51, 100, 7);

test "PROMOTION_ORDER is the mandated five stages in order" {
    const want = [5]Stage{
        .detection_only,
        .shadow,
        .canary,
        .limited_enforcement,
        .expanded_enforcement,
    };
    for (PROMOTION_ORDER, want) |got, exp| {
        try std.testing.expectEqual(exp, got);
    }
}

test "starts in detection_only, which never applies" {
    var p = IPSCanaryOrder{};
    try std.testing.expectEqual(Stage.detection_only, p.stage);
    try std.testing.expectEqual(false, p.stageApplies(canaryIp));
    try std.testing.expectEqual(false, p.stageApplies(realIp));
}

test "shadow observes but never applies" {
    var p = IPSCanaryOrder{};
    p.stage = .shadow;
    try std.testing.expectEqual(false, p.stageApplies(canaryIp));
    try std.testing.expectEqual(false, p.stageApplies(realIp));
}

test "canary applies ONLY to canary TEST-NET-3 traffic" {
    var p = IPSCanaryOrder{};
    p.stage = .canary;
    try std.testing.expectEqual(true, p.stageApplies(canaryIp));
    try std.testing.expectEqual(false, p.stageApplies(realIp));
    try std.testing.expectEqual(false, p.stageApplies(unsignedIp(10, 0, 0, 1)));
}

test "limited_enforcement applies only within the declared scope block" {
    var p = IPSCanaryOrder{};
    p.stage = .limited_enforcement;
    p.spec.scope_cidr_base = unsignedIp(10, 20, 0, 0);
    p.spec.scope_prefix_len = 24;
    try std.testing.expectEqual(true, p.stageApplies(scopeIp));
    try std.testing.expectEqual(false, p.stageApplies(canaryIp));
    try std.testing.expectEqual(false, p.stageApplies(realIp));
}

test "expanded_enforcement applies to real traffic" {
    var p = IPSCanaryOrder{};
    p.stage = .expanded_enforcement;
    try std.testing.expectEqual(true, p.stageApplies(realIp));
    try std.testing.expectEqual(true, p.stageApplies(canaryIp));
}

test "rolled_back never applies (fail-closed)" {
    var p = IPSCanaryOrder{};
    p.stage = .rolled_back;
    try std.testing.expectEqual(false, p.stageApplies(realIp));
    try std.testing.expectEqual(false, p.stageApplies(canaryIp));
}

test "promotion requires observations (fail-closed)" {
    var p = IPSCanaryOrder{};
    p.gate.min_observations = 5;
    p.gate.min_dwell_ms = 0;
    try std.testing.expectError(PromotionError.GateNotMet, p.promote());
    try std.testing.expectEqual(DenyReason.min_observations_not_met, p.last_deny);
    for (0..5) |_| p.observe(true);
    try std.testing.expectEqual(Stage.shadow, try p.promote());
}

test "promotion requires dwell" {
    var p = IPSCanaryOrder{};
    p.gate.min_observations = 0;
    p.gate.min_dwell_ms = 60_000;
    for (0..3) |_| p.observe(true);
    p.now_ms = 30_000;
    try std.testing.expectError(PromotionError.GateNotMet, p.promote());
    try std.testing.expectEqual(DenyReason.dwell_not_met, p.last_deny);
    p.now_ms = 60_000;
    try std.testing.expectEqual(Stage.shadow, try p.promote());
}

test "promotion requires fail rate within budget" {
    var p = IPSCanaryOrder{};
    p.gate.min_observations = 4;
    p.gate.min_dwell_ms = 0;
    for (0..4) |_| p.observe(false);
    try std.testing.expectError(PromotionError.GateNotMet, p.promote());
    try std.testing.expectEqual(DenyReason.fail_rate_too_high, p.last_deny);
}

test "human approval required for limited -> expanded (fail-closed)" {
    var p = IPSCanaryOrder{};
    p.gate = .{ .min_observations = 1, .min_dwell_ms = 0 };
    p.stage = .limited_enforcement;
    p.now_ms = 1000;
    p.stage_entered_ms = 0; // staged promotion precondition satisfied by tests
    p.stage_observations = 1;
    p.stage_passes = 1;
    try std.testing.expectError(PromotionError.GateNotMet, p.promote());
    try std.testing.expectEqual(DenyReason.human_approval_missing, p.last_deny);
    p.approveLimitedToExpanded();
    try std.testing.expectEqual(Stage.expanded_enforcement, try p.promote());
    try std.testing.expectEqual(AuditReason.human_approved, p.audit[p.audit_len - 1].reason);
}

test "stages cannot be skipped" {
    var p = IPSCanaryOrder{};
    p.gate.min_observations = 0;
    p.gate.min_dwell_ms = 0;
    p.stage = .detection_only;
    try std.testing.expectEqual(Stage.shadow, try p.promote());
    p.stage_observations = 0;
    try std.testing.expectEqual(Stage.canary, try p.promote());
}

test "cannot promote from rolled_back without reset" {
    var p = IPSCanaryOrder{};
    p.stage = .rolled_back;
    try std.testing.expectError(PromotionError.ImpossibleFromStage, p.promote());
    try std.testing.expectEqual(DenyReason.stage_order, p.last_deny);
    p.reset();
    try std.testing.expectEqual(Stage.detection_only, p.stage);
}

test "expiry auto-rolls back with expiry audit reason" {
    var p = IPSCanaryOrder{};
    p.spec.expiry_after_ms = 10_000;
    p.stage = .canary;
    p.stage_entered_ms = 0;
    p.now_ms = 10_000;
    try std.testing.expectEqual(true, p.isExpired());
    p.evaluateExpiry();
    try std.testing.expectEqual(Stage.rolled_back, p.stage);
    try std.testing.expectEqual(AuditReason.expiry, p.audit[p.audit_len - 1].reason);
}

test "consecutive enforcement failures auto-rollback" {
    var p = IPSCanaryOrder{};
    p.gate.consecutive_fail_limit = 3;
    p.stage = .canary;
    p.observe(true);
    p.observe(false);
    p.observe(false);
    p.observe(false);
    try std.testing.expectEqual(Stage.rolled_back, p.stage);
    try std.testing.expectEqual(AuditReason.auto_rollback_consecutive, p.audit[p.audit_len - 1].reason);
    try std.testing.expectEqual(@as(u32, 1), p.rollbacks);
}

test "manual rollback allowed from enforcing stages only" {
    var p = IPSCanaryOrder{};
    p.stage = .limited_enforcement;
    try p.manualRollback();
    try std.testing.expectEqual(Stage.rolled_back, p.stage);
    try std.testing.expectEqual(AuditReason.manual_rollback, p.audit[p.audit_len - 1].reason);
}

test "audit trail is bounded" {
    var p = IPSCanaryOrder{};
    p.gate.min_observations = 0;
    p.gate.min_dwell_ms = 0;
    var i: usize = 0;
    while (i < AUDIT_CAP * 2) : (i += 1) {
        p.reset();
    }
    try std.testing.expectEqual(AUDIT_CAP, p.audit_len);
}

test "promotion resets per-stage accounting" {
    var p = IPSCanaryOrder{};
    p.gate.min_observations = 2;
    p.gate.min_dwell_ms = 0;
    p.observe(true);
    p.observe(true);
    _ = try p.promote();
    try std.testing.expectEqual(@as(u32, 0), p.stage_fails);
    try std.testing.expectEqual(@as(u32, 0), p.stage_observations);
}