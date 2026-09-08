//! canary_progression.zig - AEGIS IPS Enforcement Progression (P4 / Phase T)
//!
//! Governs how enforcement decisions earn the right to touch real
//! traffic, moving through strictly ordered stages:
//!
//!   simulation -> shadow -> canary -> enforce
//!                                    enforce -> rolled_back (auto/manual)
//!   rolled_back -> simulation (full reset, cycle restarts)
//!
//! Stage semantics:
//!   simulation - decisions computed but discarded, pipeline observes
//!   shadow     - decisions logged alongside the live path, not applied
//!   canary     - decisions applied ONLY to canary traffic
//!                (203.0.113.0/24 TEST-NET-3, CANA magic 0x43414E41)
//!   enforce    - decisions applied to real traffic; failure bursts
//!                roll back automatically
//!
//! Promotion gates (all must hold, fail-closed):
//!   - minimum canary runs observed in the current stage
//!   - canary failure rate <= max_fail_rate_bps (basis points)
//!   - minimum observation window elapsed in the current stage
//!   - human approval for the canary -> enforce transition
//!
//! Self-contained: imports std only. Time is injected (advanceClock)
//! so every transition is deterministic and testable offline.

const std = @import("std");

// ============================================================
// Constants (compatible with ips_canary.zig, Phase 18)
// ============================================================

/// Magic number identifying canary events ("CANA").
pub const CANARY_MAGIC: u32 = 0x43414E41;

/// Canary traffic lives in TEST-NET-3 (203.0.113.0/24).
pub const CANARY_IP_BASE: u32 = 0xCB007100;

/// Number of canary probes the Phase 18 harness defines.
pub const CANARY_TEST_COUNT: usize = 4;

// ============================================================
// Stages and gates
// ============================================================

pub const Stage = enum(u8) {
    simulation = 0,
    shadow = 1,
    canary = 2,
    enforce = 3,
    rolled_back = 4,

    pub fn label(self: Stage) []const u8 {
        return switch (self) {
            .simulation => "simulation",
            .shadow => "shadow",
            .canary => "canary",
            .enforce => "enforce",
            .rolled_back => "rolled_back",
        };
    }
};

pub const GateConfig = struct {
    /// Canary runs required in the current stage before promotion.
    min_canary_runs: u32 = 10,
    /// Maximum tolerated canary failure rate, in basis points (2%).
    max_fail_rate_bps: u32 = 200,
    /// Minimum observation window per stage, milliseconds (5 min).
    min_observe_ms: u64 = 300_000,
    /// Consecutive enforcement failures that trigger auto-rollback.
    consecutive_rollback_fails: u32 = 3,
    /// Human approval required for canary -> enforce (fail-closed).
    require_human_approval: bool = true,
    /// In enforce stage, a canary fail rate above this (after enough
    /// runs) also triggers rollback. Basis points.
    enforce_fail_rate_bps: u32 = 2000,
    /// Runs that must complete in enforce before the rate trigger arms.
    enforce_rate_min_runs: u32 = 10,
};

pub const PromotionError = error{
    GateNotMet,
    ImpossibleFromStage,
};

pub const DenyReason = enum {
    none,
    wrong_stage,
    runs_not_met,
    fail_rate_too_high,
    observe_window_not_met,
    human_approval_missing,
};

pub const AuditReason = enum {
    gate_met,
    human_approved,
    auto_rollback_consecutive,
    auto_rollback_rate,
    manual_rollback,
    reset_after_rollback,
};

pub const AuditEntry = struct {
    ts_ms: u64,
    from: Stage,
    to: Stage,
    reason: AuditReason,
};

// ============================================================
// Progression controller
// ============================================================

pub const Progression = struct {
    gate: GateConfig,
    stage: Stage = .simulation,
    stage_entered_ms: u64 = 0,
    now_ms: u64 = 0,

    // Per-stage canary accounting (reset on every transition).
    stage_runs: u32 = 0,
    stage_passed: u32 = 0,

    // Lifetime accounting (never reset except full reset).
    total_runs: u32 = 0,
    total_passed: u32 = 0,

    // Enforce-stage failure tracking.
    consecutive_fails: u32 = 0,
    human_approved: bool = false,
    rollbacks: u32 = 0,

    audit: [AUDIT_CAP]AuditEntry = undefined,
    audit_len: usize = 0,

    pub const AUDIT_CAP: usize = 64;

    pub fn init(gate: GateConfig, start_ms: u64) Progression {
        return .{
            .gate = gate,
            .stage = .simulation,
            .stage_entered_ms = start_ms,
            .now_ms = start_ms,
        };
    }

    /// Deterministic time injection (no wall clock anywhere).
    pub fn advanceClock(self: *Progression, delta_ms: u64) void {
        self.now_ms += delta_ms;
    }

    fn failRateBps(runs: u32, passed: u32) u32 {
        if (runs == 0) return 0;
        const failed: u64 = @as(u64, runs) - passed;
        return @intCast((failed * 10_000) / @as(u64, runs));
    }

    /// Current stage canary failure rate in basis points.
    pub fn stageFailRateBps(self: *const Progression) u32 {
        return failRateBps(self.stage_runs, self.stage_passed);
    }

    /// Evaluate promotion gates WITHOUT mutating state (pure check).
    pub fn checkPromotion(self: *const Progression) DenyReason {
        const g = self.gate;
        if (self.stage_runs < g.min_canary_runs) return .runs_not_met;
        if (failRateBps(self.stage_runs, self.stage_passed) > g.max_fail_rate_bps) {
            return .fail_rate_too_high;
        }
        if (self.now_ms - self.stage_entered_ms < g.min_observe_ms) {
            return .observe_window_not_met;
        }
        if (self.stage == .canary and g.require_human_approval and !self.human_approved) {
            return .human_approval_missing;
        }
        return .none;
    }

    /// Promote one stage forward. Fail-closed: any unmet gate denies.
    pub fn promote(self: *Progression) PromotionError!Stage {
        const from = self.stage;
        const to: Stage = switch (from) {
            .simulation => .shadow,
            .shadow => .canary,
            .canary => .enforce,
            .enforce, .rolled_back => return PromotionError.ImpossibleFromStage,
        };
        const deny = self.checkPromotion();
        if (deny != .none) return PromotionError.GateNotMet;

        const reason: AuditReason = if (from == .canary) .human_approved else .gate_met;
        self.transition(to, reason);
        return to;
    }

    /// Record one canary probe outcome against the current stage.
    /// While enforcing, failure bursts and fail rates trigger
    /// automatic rollback (fail-closed on real traffic).
    pub fn recordCanary(self: *Progression, passed: bool) void {
        self.stage_runs += 1;
        self.total_runs += 1;
        if (passed) {
            self.stage_passed += 1;
            self.total_passed += 1;
            self.consecutive_fails = 0;
            return;
        }
        if (self.stage == .enforce) {
            self.consecutive_fails += 1;
            if (self.consecutive_fails >= self.gate.consecutive_rollback_fails) {
                self.transition(.rolled_back, .auto_rollback_consecutive);
                return;
            }
            if (self.stage_runs >= self.gate.enforce_rate_min_runs and
                self.stageFailRateBps() > self.gate.enforce_fail_rate_bps)
            {
                self.transition(.rolled_back, .auto_rollback_rate);
                return;
            }
        }
    }

    /// Human approval for canary -> enforce. Ignored elsewhere so an
    /// approval can never leak across stages (fail-closed).
    pub fn approveCanaryToEnforce(self: *Progression) void {
        if (self.stage == .canary) self.human_approved = true;
    }

    /// Operator-initiated rollback. Allowed from shadow, canary and
    /// enforce; simulation has nothing to roll back.
    pub fn manualRollback(self: *Progression) PromotionError!void {
        switch (self.stage) {
            .shadow, .canary, .enforce => {
                self.transition(.rolled_back, .manual_rollback);
            },
            .simulation, .rolled_back => return PromotionError.ImpossibleFromStage,
        }
    }

    /// Restart the full cycle after a rollback (back to simulation).
    pub fn resetAfterRollback(self: *Progression, start_ms: u64) PromotionError!void {
        if (self.stage != .rolled_back) return PromotionError.ImpossibleFromStage;
        self.stage = .simulation;
        self.stage_entered_ms = start_ms;
        self.now_ms = start_ms;
        self.stage_runs = 0;
        self.stage_passed = 0;
        self.consecutive_fails = 0;
        self.human_approved = false;
        self.appendAudit(.{
            .ts_ms = start_ms,
            .from = .rolled_back,
            .to = .simulation,
            .reason = .reset_after_rollback,
        });
    }

    fn transition(self: *Progression, to: Stage, reason: AuditReason) void {
        const from = self.stage;
        self.stage = to;
        self.stage_entered_ms = self.now_ms;
        self.stage_runs = 0;
        self.stage_passed = 0;
        self.consecutive_fails = 0;
        self.human_approved = false;
        if (to == .enforce) {
            // The approval that opened this stage is consumed.
            self.human_approved = false;
        }
        if (to == .rolled_back) self.rollbacks += 1;
        self.appendAudit(.{ .ts_ms = self.now_ms, .from = from, .to = to, .reason = reason });
    }

    fn appendAudit(self: *Progression, entry: AuditEntry) void {
        if (self.audit_len < AUDIT_CAP) {
            self.audit[self.audit_len] = entry;
            self.audit_len += 1;
        }
        // Bounded: beyond capacity entries are dropped (fail-soft),
        // the stage machine itself never lies.
    }
};

// ============================================================
// Tests
// ============================================================

const testing = std.testing;

const FAST = GateConfig{
    .min_canary_runs = 3,
    .max_fail_rate_bps = 2000, // tolerate 1/3 failures for fast tests
    .min_observe_ms = 100,
    .consecutive_rollback_fails = 3,
    .require_human_approval = true,
    .enforce_fail_rate_bps = 3000,
    .enforce_rate_min_runs = 5,
};

test "stage order and defaults" {
    try testing.expectEqual(@as(u8, 0), @intFromEnum(Stage.simulation));
    try testing.expectEqual(@as(u8, 1), @intFromEnum(Stage.shadow));
    try testing.expectEqual(@as(u8, 2), @intFromEnum(Stage.canary));
    try testing.expectEqual(@as(u8, 3), @intFromEnum(Stage.enforce));
    try testing.expectEqual(@as(u8, 4), @intFromEnum(Stage.rolled_back));

    const p = Progression.init(FAST, 1000);
    try testing.expectEqual(Stage.simulation, p.stage);
    try testing.expectEqual(@as(u32, 0), p.stage_runs);
    try testing.expectEqual(@as(u32, 0), p.rollbacks);
    try testing.expectEqualStrings("canary", Stage.canary.label());
}

test "promotion denied before minimum canary runs" {
    var p = Progression.init(FAST, 0);
    p.advanceClock(FAST.min_observe_ms + 1);
    p.recordCanary(true);
    p.recordCanary(true);
    try testing.expectEqual(DenyReason.runs_not_met, p.checkPromotion());
    try testing.expectError(PromotionError.GateNotMet, p.promote());
    try testing.expectEqual(Stage.simulation, p.stage);
}

test "promotion denied inside observation window" {
    var p = Progression.init(FAST, 0);
    // Enough runs, but the clock barely moved.
    p.recordCanary(true);
    p.recordCanary(true);
    p.recordCanary(true);
    try testing.expectEqual(DenyReason.observe_window_not_met, p.checkPromotion());
    try testing.expectError(PromotionError.GateNotMet, p.promote());
}

test "promotion denied when fail rate too high" {
    var p = Progression.init(FAST, 0);
    p.advanceClock(FAST.min_observe_ms + 1);
    // 1/3 failed = 3333 bps > 2000 bps gate.
    p.recordCanary(false);
    p.recordCanary(true);
    p.recordCanary(true);
    try testing.expectEqual(@as(u32, 3333), p.stageFailRateBps());
    try testing.expectEqual(DenyReason.fail_rate_too_high, p.checkPromotion());
}

test "simulation -> shadow promotes when all gates met" {
    var p = Progression.init(FAST, 0);
    p.advanceClock(FAST.min_observe_ms + 1);
    p.recordCanary(true);
    p.recordCanary(true);
    p.recordCanary(true);
    const to = try p.promote();
    try testing.expectEqual(Stage.shadow, to);
    try testing.expectEqual(@as(u32, 0), p.stage_runs); // per-stage reset
    try testing.expectEqual(@as(u32, 3), p.total_runs); // lifetime kept
    try testing.expectEqual(@as(usize, 1), p.audit_len);
    try testing.expectEqual(AuditReason.gate_met, p.audit[0].reason);
    try testing.expectEqual(Stage.simulation, p.audit[0].from);
    try testing.expectEqual(Stage.shadow, p.audit[0].to);
}

test "shadow -> canary promotes; human approval cannot leak between stages" {
    var p = Progression.init(FAST, 0);
    p.advanceClock(FAST.min_observe_ms + 1);
    p.recordCanary(true);
    p.recordCanary(true);
    p.recordCanary(true);
    _ = try p.promote(); // sim -> shadow

    // Approval while in shadow must be ignored.
    p.advanceClock(FAST.min_observe_ms + 1);
    p.recordCanary(true);
    p.recordCanary(true);
    p.recordCanary(true);
    p.approveCanaryToEnforce();
    const to = try p.promote(); // shadow -> canary
    try testing.expectEqual(Stage.canary, to);
    try testing.expect(!p.human_approved);
}

test "canary -> enforce requires human approval" {
    var p = Progression.init(FAST, 0);
    p.advanceClock(FAST.min_observe_ms + 1);
    p.recordCanary(true);
    p.recordCanary(true);
    p.recordCanary(true);
    _ = try p.promote(); // sim -> shadow
    p.advanceClock(FAST.min_observe_ms + 1);
    p.recordCanary(true);
    p.recordCanary(true);
    p.recordCanary(true);
    _ = try p.promote(); // shadow -> canary

    p.advanceClock(FAST.min_observe_ms + 1);
    p.recordCanary(true);
    p.recordCanary(true);
    p.recordCanary(true);
    // Gates met but no approval.
    try testing.expectEqual(DenyReason.human_approval_missing, p.checkPromotion());
    try testing.expectError(PromotionError.GateNotMet, p.promote());

    p.approveCanaryToEnforce();
    const to = try p.promote();
    try testing.expectEqual(Stage.enforce, to);
    // Approval consumed on entry.
    try testing.expect(!p.human_approved);
}

test "promote is impossible from terminal stages" {
    var p = Progression.init(FAST, 0);
    p.stage = .enforce;
    try testing.expectError(PromotionError.ImpossibleFromStage, p.promote());
    p.stage = .rolled_back;
    try testing.expectError(PromotionError.ImpossibleFromStage, p.promote());
    try testing.expectError(PromotionError.ImpossibleFromStage, p.manualRollback());
    // Reset is only legal FROM rolled_back.
    p.stage = .simulation;
    try testing.expectError(PromotionError.ImpossibleFromStage, p.resetAfterRollback(0));
}

test "enforce successes reset the consecutive failure counter" {
    var p = Progression.init(FAST, 0);
    p.stage = .enforce;
    p.recordCanary(false);
    p.recordCanary(false);
    try testing.expectEqual(@as(u32, 2), p.consecutive_fails);
    p.recordCanary(true);
    try testing.expectEqual(@as(u32, 0), p.consecutive_fails);
    try testing.expectEqual(Stage.enforce, p.stage);
}

test "three consecutive enforcement failures auto-rollback" {
    var p = Progression.init(FAST, 0);
    p.stage = .enforce;
    p.recordCanary(false);
    p.recordCanary(false);
    try testing.expectEqual(Stage.enforce, p.stage);
    p.recordCanary(false);
    try testing.expectEqual(Stage.rolled_back, p.stage);
    try testing.expectEqual(@as(u32, 1), p.rollbacks);
    try testing.expectEqual(AuditReason.auto_rollback_consecutive, p.audit[p.audit_len - 1].reason);
}

test "enforce fail-rate trigger rolls back after enough runs" {
    var gate = FAST;
    gate.consecutive_rollback_fails = 99; // disable consecutive trigger
    gate.enforce_rate_min_runs = 5;
    gate.enforce_fail_rate_bps = 2000; // 20%
    var p = Progression.init(gate, 0);
    p.stage = .enforce;
    // 4 fails / 5 runs = 80% >> 20% but trigger needs >= 5 runs;
    // failures do not hit the consecutive counter (99).
    p.recordCanary(false);
    p.recordCanary(false);
    p.recordCanary(false);
    p.recordCanary(false);
    try testing.expectEqual(Stage.enforce, p.stage);
    p.recordCanary(false); // 5/5 = 100% -> rate trigger fires
    try testing.expectEqual(Stage.rolled_back, p.stage);
    try testing.expectEqual(AuditReason.auto_rollback_rate, p.audit[p.audit_len - 1].reason);
}

test "manual rollback from canary and full reset restart the cycle" {
    var p = Progression.init(FAST, 0);
    p.advanceClock(FAST.min_observe_ms + 1);
    p.recordCanary(true);
    p.recordCanary(true);
    p.recordCanary(true);
    _ = try p.promote(); // sim -> shadow
    try p.manualRollback();
    try testing.expectEqual(Stage.rolled_back, p.stage);
    try testing.expectEqual(AuditReason.manual_rollback, p.audit[p.audit_len - 1].reason);

    try p.resetAfterRollback(5000);
    try testing.expectEqual(Stage.simulation, p.stage);
    try testing.expectEqual(@as(u64, 5000), p.now_ms);
    try testing.expectEqual(@as(u32, 0), p.stage_runs);
    try testing.expectEqual(@as(u32, 1), p.rollbacks); // history kept
}

test "audit trail is bounded and never overflows" {
    var p = Progression.init(FAST, 0);
    // Cycle promote/rollback far beyond AUDIT_CAP.
    var cycle: usize = 0;
    while (cycle < 100) : (cycle += 1) {
        p.advanceClock(FAST.min_observe_ms + 1);
        p.stage = .canary; // fast-path for the audit stress test
        p.human_approved = true;
        p.stage_runs = p.gate.min_canary_runs;
        p.stage_passed = p.gate.min_canary_runs;
        _ = p.promote() catch unreachable; // -> enforce (audit entry)
        _ = p.manualRollback() catch unreachable; // -> rolled_back
        p.resetAfterRollback(p.now_ms) catch unreachable; // -> simulation
    }
    try testing.expectEqual(Progression.AUDIT_CAP, p.audit_len);
}

test "canary constants stay compatible with Phase 18 harness" {
    try testing.expectEqual(@as(u32, 0x43414E41), CANARY_MAGIC);
    try testing.expectEqual(@as(u32, 0xCB007100), CANARY_IP_BASE); // 203.0.113.0
    try testing.expectEqual(@as(usize, 4), CANARY_TEST_COUNT);
}

test "end-to-end happy path: simulation to enforce under strict gates" {
    const strict = GateConfig{
        .min_canary_runs = 10,
        .max_fail_rate_bps = 200, // 2%
        .min_observe_ms = 60_000,
        .consecutive_rollback_fails = 3,
        .require_human_approval = true,
        .enforce_fail_rate_bps = 1000,
        .enforce_rate_min_runs = 20,
    };
    var p = Progression.init(strict, 0);

    var stage: usize = 0;
    while (stage < 3) : (stage += 1) { // sim->shadow->canary->enforce
        var i: usize = 0;
        while (i < 10) : (i += 1) p.recordCanary(true);
        p.advanceClock(60_001);
        if (p.stage == .canary) p.approveCanaryToEnforce();
        _ = try p.promote();
    }
    try testing.expectEqual(Stage.enforce, p.stage);
    // A single canary failure while enforcing does NOT roll back.
    p.recordCanary(false);
    try testing.expectEqual(Stage.enforce, p.stage);
    try testing.expectEqual(@as(u32, 0), p.rollbacks);
}
