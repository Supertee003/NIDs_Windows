//! tier3_state.zig - Tier-3 Security Authority State Machine
//!
//! SECURITY (P0.2): Defines the operational state of the Tier-3 subsystem
//! (PEP + payload screening). All enforcement decisions are gated by this state.
//!
//! State Machine:
//!   ABSENT  → Tier-3 not loaded. No enforcement allowed. Health = DEGRADED.
//!   LOADING → Tier-3 initialization in progress. No enforcement allowed.
//!   READY   → Tier-3 fully operational. Normal enforcement.
//!   FAILED  → Tier-3 loaded but failed. Privileged enforcement restricted.
//!   DEGRADED→ Tier-3 partially operational. Reduced enforcement.
//!
//! Policy:
//!   READY     → normal operation
//!   FAILED    → security degraded, privileged enforcement restricted, operator-visible, audit
//!   ABSENT    → NOT healthy, no enforcement, operator alert
//!   LOADING   → transitional, no enforcement until READY
//!   DEGRADED  → reduced enforcement, operator alert

const std = @import("std");

// ============================================================
// Tier-3 State Enum
// ============================================================

pub const Tier3State = enum(u8) {
    /// Tier-3 subsystem not loaded (DLL missing or not attempted).
    /// Policy: NOT healthy, no enforcement allowed.
    absent = 0,

    /// Tier-3 initialization in progress.
    /// Policy: transitional, no enforcement until READY.
    loading = 1,

    /// Tier-3 fully operational.
    /// Policy: normal operation, all enforcement allowed.
    ready = 2,

    /// Tier-3 loaded but failed initialization.
    /// Policy: security degraded, privileged enforcement restricted.
    failed = 3,

    /// Tier-3 partially operational (some functions work, others don't).
    /// Policy: reduced enforcement, operator alert.
    degraded = 4,

    pub fn toString(self: Tier3State) []const u8 {
        return switch (self) {
            .absent => "ABSENT",
            .loading => "LOADING",
            .ready => "READY",
            .failed => "FAILED",
            .degraded => "DEGRADED",
        };
    }

    /// Whether the system is healthy (only READY is healthy).
    pub fn isHealthy(self: Tier3State) bool {
        return self == .ready;
    }

    /// Whether enforcement actions are allowed (only READY allows enforcement).
    pub fn isEnforcementAllowed(self: Tier3State) bool {
        return self == .ready;
    }

    /// Whether privileged enforcement (block/unblock WFP) is allowed.
    pub fn isPrivilegedEnforcementAllowed(self: Tier3State) bool {
        return self == .ready;
    }
};

// ============================================================
// Tier-3 Subsystem State
// ============================================================

pub const Tier3Subsystem = struct {
    state: Tier3State = .absent,
    pep_loaded: bool = false,
    payload_screening: bool = false,
    error_message: ?[]const u8 = null,
    init_attempted: bool = false,

    /// Check if enforcement actions are allowed.
    /// P0.2: Honors AEGIS_FAIL_OPEN=1 env var (operator override).
    pub fn canEnforce(self: *const Tier3Subsystem) bool {
        if (self.state.isEnforcementAllowed()) return true;
        // P0.2: AEGIS_FAIL_OPEN=1 override — operator can force fail-open
        if (isFailOpenOverride()) {
            // Audit log: override detected, security degraded
            std.log.warn("[TIER3] AEGIS_FAIL_OPEN=1 override active — enforcement enabled despite Tier-3 state={s}", .{self.state.toString()});
            return true;
        }
        return false;
    }

    /// Check if privileged enforcement (WFP block/unblock) is allowed.
    pub fn canEnforcePrivileged(self: *const Tier3Subsystem) bool {
        return self.state.isPrivilegedEnforcementAllowed();
    }

    /// Check if the system is healthy.
    pub fn isHealthy(self: *const Tier3Subsystem) bool {
        return self.state.isHealthy();
    }

    /// Get health status string for reporting.
    pub fn healthStatus(self: *const Tier3Subsystem) []const u8 {
        return switch (self.state) {
            .absent => "missing-fail-closed",
            .loading => "initializing",
            .ready => "ok",
            .failed => "failed-degraded",
            .degraded => "partial-degraded",
        };
    }

    /// Transition to loading state.
    pub fn beginInit(self: *Tier3Subsystem) void {
        self.state = .loading;
        self.init_attempted = true;
        self.error_message = null;
    }

    /// Mark as ready (initialization succeeded).
    pub fn markReady(self: *Tier3Subsystem) void {
        self.state = .ready;
        self.pep_loaded = true;
        self.payload_screening = true;
        self.error_message = null;
    }

    /// Mark as failed (initialization failed).
    pub fn markFailed(self: *Tier3Subsystem, msg: []const u8) void {
        self.state = .failed;
        self.error_message = msg;
    }

    /// Mark as absent (DLL not found).
    pub fn markAbsent(self: *Tier3Subsystem, msg: []const u8) void {
        self.state = .absent;
        self.error_message = msg;
    }

    /// Mark as degraded (partial functionality).
    pub fn markDegraded(self: *Tier3Subsystem, msg: []const u8) void {
        self.state = .degraded;
        self.error_message = msg;
    }
};

// ============================================================
// Global Tier-3 State
// ============================================================

/// Global Tier-3 subsystem state. Initialized at daemon startup.
pub var g_tier3 = Tier3Subsystem{};

/// P0.2: Check if AEGIS_FAIL_OPEN=1 env var is set.
/// When set, the system overrides Tier-3 state to allow enforcement.
/// WARNING: This is a security override — all state transitions are audit-logged.
fn isFailOpenOverride() bool {
    if (std.process.getEnvVarOwned(std.heap.page_allocator, "AEGIS_FAIL_OPEN")) |val| {
        defer std.heap.page_allocator.free(val);
        return std.mem.eql(u8, val, "1");
    } else |_| {
        return false;
    }
}

/// Audit log for Tier-3 state transitions.
pub fn auditTransition(old: Tier3State, new: Tier3State, reason: []const u8) void {
    if (old == new) return;
    const diag = @import("../core/diagnostics.zig");
    diag.critical("TIER3 STATE: {s} -> {s} ({s})", .{ old.toString(), new.toString(), reason });
    std.log.err("[TIER3] State transition: {s} -> {s} ({s})", .{ old.toString(), new.toString(), reason });
}

// ============================================================
// Tests
// ============================================================

test "Tier3State: only READY is healthy" {
    try std.testing.expect(Tier3State.ready.isHealthy());
    try std.testing.expect(!Tier3State.absent.isHealthy());
    try std.testing.expect(!Tier3State.loading.isHealthy());
    try std.testing.expect(!Tier3State.failed.isHealthy());
    try std.testing.expect(!Tier3State.degraded.isHealthy());
}

test "Tier3State: only READY allows enforcement" {
    try std.testing.expect(Tier3State.ready.isEnforcementAllowed());
    try std.testing.expect(!Tier3State.absent.isEnforcementAllowed());
    try std.testing.expect(!Tier3State.loading.isEnforcementAllowed());
    try std.testing.expect(!Tier3State.failed.isEnforcementAllowed());
    try std.testing.expect(!Tier3State.degraded.isEnforcementAllowed());
}

test "Tier3Subsystem: state transitions" {
    var sub = Tier3Subsystem{};

    // Initial state is absent
    try std.testing.expectEqual(Tier3State.absent, sub.state);
    try std.testing.expect(!sub.canEnforce());
    try std.testing.expect(!sub.isHealthy());

    // Begin init
    sub.beginInit();
    try std.testing.expectEqual(Tier3State.loading, sub.state);
    try std.testing.expect(!sub.canEnforce());

    // Mark ready
    sub.markReady();
    try std.testing.expectEqual(Tier3State.ready, sub.state);
    try std.testing.expect(sub.canEnforce());
    try std.testing.expect(sub.isHealthy());

    // Mark degraded
    sub.markDegraded("partial failure");
    try std.testing.expectEqual(Tier3State.degraded, sub.state);
    try std.testing.expect(!sub.canEnforce());
    try std.testing.expect(!sub.isHealthy());
}

test "Tier3Subsystem: health status strings" {
    var sub = Tier3Subsystem{};
    try std.testing.expectEqualStrings("missing-fail-closed", sub.healthStatus());

    sub.markReady();
    try std.testing.expectEqualStrings("ok", sub.healthStatus());

    sub.markFailed("DLL load error");
    try std.testing.expectEqualStrings("failed-degraded", sub.healthStatus());
}
