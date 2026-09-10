//! ips_simulation.zig - AEGIS IPS Simulation (Rewrite Phase 26 / Manual Phase 24)
//!
//! IPS enforcement progression: AUDIT -> SIMULATE -> CANARY -> ENFORCE
//! Each mode controls how aggressive enforcement is, with rollback capability.
//!
//! Architecture (Manual Section 32):
//!   Start: AUDIT (observe only)
//!   Then:  SIMULATE (compute actions, don't execute)
//!   Then:  CANARY (execute on controlled test events only)
//!   Finally: ENFORCE (full production enforcement)
//!
//! Exit Gate: Can rollback at any stage.

const std = @import("std");

// ============================================================
// IPS Mode (enforcement progression)
// ============================================================

pub const IpsMode = enum(u8) {
    /// Observe only. Log what WOULD happen. No enforcement at all.
    audit = 0,
    /// Compute enforcement actions but don't execute. Log simulated results.
    simulate = 1,
    /// Execute enforcement on canary/test events only. Real traffic unaffected.
    canary = 2,
    /// Full production enforcement. All actions executed.
    enforce = 3,

    pub fn toString(self: IpsMode) []const u8 {
        return switch (self) {
            .audit => "AUDIT",
            .simulate => "SIMULATE",
            .canary => "CANARY",
            .enforce => "ENFORCE",
        };
    }

    /// Returns true if this mode executes enforcement actions.
    pub fn executesActions(self: IpsMode) bool {
        return self == .canary or self == .enforce;
    }

    /// Returns true if this mode is production-ready.
    pub fn isProduction(self: IpsMode) bool {
        return self == .enforce;
    }

    /// Returns the next mode in progression, or null if already at max.
    pub fn nextMode(self: IpsMode) ?IpsMode {
        return switch (self) {
            .audit => .simulate,
            .simulate => .canary,
            .canary => .enforce,
            .enforce => null,
        };
    }

    /// Returns the previous mode (for rollback), or null if at minimum.
    pub fn previousMode(self: IpsMode) ?IpsMode {
        return switch (self) {
            .audit => null,
            .simulate => .audit,
            .canary => .simulate,
            .enforce => .canary,
        };
    }
};

// ============================================================
// Simulation Result
// ============================================================

pub const SimulationAction = enum(u8) {
    /// No action taken (audit mode).
    logged_only = 0,
    /// Action computed but not executed (simulate mode).
    simulated = 1,
    /// Action executed on canary event only.
    canary_executed = 2,
    /// Action fully executed in production.
    enforced = 3,
    /// Action rolled back.
    rolled_back = 4,

    pub fn toString(self: SimulationAction) []const u8 {
        return switch (self) {
            .logged_only => "LOGGED_ONLY",
            .simulated => "SIMULATED",
            .canary_executed => "CANARY_EXECUTED",
            .enforced => "ENFORCED",
            .rolled_back => "ROLLED_BACK",
        };
    }

    pub fn isExecuted(self: SimulationAction) bool {
        return self == .canary_executed or self == .enforced;
    }
};

pub const SimulationResult = struct {
    mode: IpsMode,
    action: SimulationAction,
    event_id: u64,
    would_block: bool,
    actually_blocked: bool,
    rollback_available: bool,
    description: []const u8,

    pub fn isExecuted(self: SimulationResult) bool {
        return self.action.isExecuted();
    }
};

// ============================================================
// Rollback Record
// ============================================================

pub const RollbackRecord = struct {
    event_id: u64,
    blocked_ip: u32,
    timestamp_ns: u64,
    reason: []const u8,
    rolled_back: bool,
    rollback_timestamp_ns: u64,

    pub fn isRolledBack(self: RollbackRecord) bool {
        return self.rolled_back;
    }
};

// ============================================================
// IPS Simulation Engine
// ============================================================

pub const MAX_ROLLBACK_RECORDS: usize = 256;

pub const IpsSimEngine = struct {
    current_mode: IpsMode,
    /// Total events processed per mode.
    audit_count: u64,
    simulate_count: u64,
    canary_count: u64,
    enforce_count: u64,
    /// Total blocks executed (canary + enforce).
    total_blocks_executed: u64,
    /// Total rollbacks performed.
    total_rollbacks: u64,
    /// Rollback records for undo.
    rollback_records: [MAX_ROLLBACK_RECORDS]RollbackRecord,
    rollback_count: usize,

    pub fn init() IpsSimEngine {
        return .{
            .current_mode = .audit, // Start in AUDIT mode
            .audit_count = 0,
            .simulate_count = 0,
            .canary_count = 0,
            .enforce_count = 0,
            .total_blocks_executed = 0,
            .total_rollbacks = 0,
            .rollback_records = undefined,
            .rollback_count = 0,
        };
    }

    /// Set the IPS mode. Returns true if allowed (forward progression or rollback).
    pub fn setMode(self: *IpsSimEngine, mode: IpsMode) bool {
        self.current_mode = mode;
        return true;
    }

    /// Advance to next mode. Returns false if already at ENFORCE.
    pub fn advance(self: *IpsSimEngine) bool {
        if (self.current_mode.nextMode()) |next| {
            self.current_mode = next;
            return true;
        }
        return false;
    }

    /// Rollback to previous mode. Returns false if already at AUDIT.
    pub fn rollbackMode(self: *IpsSimEngine) bool {
        if (self.current_mode.previousMode()) |prev| {
            self.current_mode = prev;
            return true;
        }
        return false;
    }

    /// Process an enforcement decision based on current mode.
    pub fn processDecision(
        self: *IpsSimEngine,
        event_id: u64,
        would_block: bool,
        is_canary_event: bool,
        blocked_ip: u32,
        timestamp_ns: u64,
    ) SimulationResult {
        switch (self.current_mode) {
            .audit => {
                self.audit_count += 1;
                return .{
                    .mode = .audit,
                    .action = .logged_only,
                    .event_id = event_id,
                    .would_block = would_block,
                    .actually_blocked = false,
                    .rollback_available = false,
                    .description = "audit: logged only, no action",
                };
            },
            .simulate => {
                self.simulate_count += 1;
                return .{
                    .mode = .simulate,
                    .action = .simulated,
                    .event_id = event_id,
                    .would_block = would_block,
                    .actually_blocked = false,
                    .rollback_available = false,
                    .description = "simulate: computed action, not executed",
                };
            },
            .canary => {
                self.canary_count += 1;
                if (would_block and is_canary_event) {
                    // Execute on canary events only
                    self.total_blocks_executed += 1;
                    self.recordRollback(event_id, blocked_ip, timestamp_ns, "canary block");
                    return .{
                        .mode = .canary,
                        .action = .canary_executed,
                        .event_id = event_id,
                        .would_block = would_block,
                        .actually_blocked = true,
                        .rollback_available = true,
                        .description = "canary: executed on test event",
                    };
                }
                return .{
                    .mode = .canary,
                    .action = .logged_only,
                    .event_id = event_id,
                    .would_block = would_block,
                    .actually_blocked = false,
                    .rollback_available = false,
                    .description = "canary: non-canary event, logged only",
                };
            },
            .enforce => {
                self.enforce_count += 1;
                if (would_block) {
                    self.total_blocks_executed += 1;
                    self.recordRollback(event_id, blocked_ip, timestamp_ns, "enforce block");
                    return .{
                        .mode = .enforce,
                        .action = .enforced,
                        .event_id = event_id,
                        .would_block = would_block,
                        .actually_blocked = true,
                        .rollback_available = true,
                        .description = "enforce: action executed in production",
                    };
                }
                return .{
                    .mode = .enforce,
                    .action = .logged_only,
                    .event_id = event_id,
                    .would_block = would_block,
                    .actually_blocked = false,
                    .rollback_available = false,
                    .description = "enforce: no block needed",
                };
            },
        }
    }

    /// Record a block for potential rollback.
    fn recordRollback(self: *IpsSimEngine, event_id: u64, blocked_ip: u32, timestamp_ns: u64, reason: []const u8) void {
        if (self.rollback_count < MAX_ROLLBACK_RECORDS) {
            self.rollback_records[self.rollback_count] = .{
                .event_id = event_id,
                .blocked_ip = blocked_ip,
                .timestamp_ns = timestamp_ns,
                .reason = reason,
                .rolled_back = false,
                .rollback_timestamp_ns = 0,
            };
            self.rollback_count += 1;
        }
    }

    /// Rollback a specific block by event_id. Returns true if rolled back.
    pub fn rollbackBlock(self: *IpsSimEngine, event_id: u64, timestamp_ns: u64) bool {
        for (0..self.rollback_count) |i| {
            if (self.rollback_records[i].event_id == event_id and !self.rollback_records[i].rolled_back) {
                self.rollback_records[i].rolled_back = true;
                self.rollback_records[i].rollback_timestamp_ns = timestamp_ns;
                self.total_rollbacks += 1;
                return true;
            }
        }
        return false;
    }

    /// Get current mode.
    pub fn getMode(self: *const IpsSimEngine) IpsMode {
        return self.current_mode;
    }

    /// Count of pending (non-rolled-back) blocks.
    pub fn pendingBlocks(self: *const IpsSimEngine) usize {
        var count: usize = 0;
        for (0..self.rollback_count) |i| {
            if (!self.rollback_records[i].rolled_back) count += 1;
        }
        return count;
    }

    /// Reset all stats (for tests).
    pub fn reset(self: *IpsSimEngine) void {
        self.* = init();
    }
};

// ============================================================
// Tests
// ============================================================

test "IpsMode.toString returns readable names" {
    try std.testing.expect(std.mem.eql(u8, IpsMode.audit.toString(), "AUDIT"));
    try std.testing.expect(std.mem.eql(u8, IpsMode.simulate.toString(), "SIMULATE"));
    try std.testing.expect(std.mem.eql(u8, IpsMode.canary.toString(), "CANARY"));
    try std.testing.expect(std.mem.eql(u8, IpsMode.enforce.toString(), "ENFORCE"));
}

test "IpsMode.executesActions" {
    try std.testing.expect(!IpsMode.audit.executesActions());
    try std.testing.expect(!IpsMode.simulate.executesActions());
    try std.testing.expect(IpsMode.canary.executesActions());
    try std.testing.expect(IpsMode.enforce.executesActions());
}

test "IpsMode.isProduction" {
    try std.testing.expect(!IpsMode.audit.isProduction());
    try std.testing.expect(!IpsMode.canary.isProduction());
    try std.testing.expect(IpsMode.enforce.isProduction());
}

test "IpsMode.nextMode progression" {
    try std.testing.expect(IpsMode.audit.nextMode() == .simulate);
    try std.testing.expect(IpsMode.simulate.nextMode() == .canary);
    try std.testing.expect(IpsMode.canary.nextMode() == .enforce);
    try std.testing.expect(IpsMode.enforce.nextMode() == null);
}

test "IpsMode.previousMode rollback" {
    try std.testing.expect(IpsMode.audit.previousMode() == null);
    try std.testing.expect(IpsMode.simulate.previousMode() == .audit);
    try std.testing.expect(IpsMode.canary.previousMode() == .simulate);
    try std.testing.expect(IpsMode.enforce.previousMode() == .canary);
}

test "SimulationAction.toString returns readable names" {
    try std.testing.expect(std.mem.eql(u8, SimulationAction.logged_only.toString(), "LOGGED_ONLY"));
    try std.testing.expect(std.mem.eql(u8, SimulationAction.simulated.toString(), "SIMULATED"));
    try std.testing.expect(std.mem.eql(u8, SimulationAction.canary_executed.toString(), "CANARY_EXECUTED"));
    try std.testing.expect(std.mem.eql(u8, SimulationAction.enforced.toString(), "ENFORCED"));
    try std.testing.expect(std.mem.eql(u8, SimulationAction.rolled_back.toString(), "ROLLED_BACK"));
}

test "SimulationAction.isExecuted" {
    try std.testing.expect(!SimulationAction.logged_only.isExecuted());
    try std.testing.expect(!SimulationAction.simulated.isExecuted());
    try std.testing.expect(SimulationAction.canary_executed.isExecuted());
    try std.testing.expect(SimulationAction.enforced.isExecuted());
}

test "IpsSimEngine init starts in AUDIT mode" {
    const engine = IpsSimEngine.init();
    try std.testing.expect(engine.current_mode == .audit);
    try std.testing.expect(engine.audit_count == 0);
}

test "IpsSimEngine advance progresses through modes" {
    var engine = IpsSimEngine.init();
    try std.testing.expect(engine.getMode() == .audit);

    try std.testing.expect(engine.advance());
    try std.testing.expect(engine.getMode() == .simulate);

    try std.testing.expect(engine.advance());
    try std.testing.expect(engine.getMode() == .canary);

    try std.testing.expect(engine.advance());
    try std.testing.expect(engine.getMode() == .enforce);

    // Can't advance past ENFORCE
    try std.testing.expect(!engine.advance());
}

test "IpsSimEngine rollbackMode goes back" {
    var engine = IpsSimEngine.init();
    _ = engine.advance(); // audit -> simulate
    _ = engine.advance(); // simulate -> canary

    try std.testing.expect(engine.rollbackMode());
    try std.testing.expect(engine.getMode() == .simulate);

    try std.testing.expect(engine.rollbackMode());
    try std.testing.expect(engine.getMode() == .audit);

    // Can't rollback past AUDIT
    try std.testing.expect(!engine.rollbackMode());
}

test "IpsSimEngine processDecision in AUDIT mode" {
    var engine = IpsSimEngine.init();
    const result = engine.processDecision(1, true, false, 0x08080808, 1000);

    try std.testing.expect(result.mode == .audit);
    try std.testing.expect(result.action == .logged_only);
    try std.testing.expect(result.would_block == true);
    try std.testing.expect(result.actually_blocked == false);
    try std.testing.expect(!result.isExecuted());
    try std.testing.expect(engine.audit_count == 1);
}

test "IpsSimEngine processDecision in SIMULATE mode" {
    var engine = IpsSimEngine.init();
    _ = engine.advance(); // audit -> simulate

    const result = engine.processDecision(1, true, false, 0x08080808, 1000);

    try std.testing.expect(result.mode == .simulate);
    try std.testing.expect(result.action == .simulated);
    try std.testing.expect(result.would_block == true);
    try std.testing.expect(result.actually_blocked == false);
    try std.testing.expect(!result.isExecuted());
    try std.testing.expect(engine.simulate_count == 1);
}

test "IpsSimEngine processDecision in CANARY mode with canary event" {
    var engine = IpsSimEngine.init();
    _ = engine.advance(); // audit -> simulate
    _ = engine.advance(); // simulate -> canary

    const result = engine.processDecision(1, true, true, 0x08080808, 1000);

    try std.testing.expect(result.mode == .canary);
    try std.testing.expect(result.action == .canary_executed);
    try std.testing.expect(result.actually_blocked == true);
    try std.testing.expect(result.rollback_available == true);
    try std.testing.expect(engine.total_blocks_executed == 1);
    try std.testing.expect(engine.canary_count == 1);
}

test "IpsSimEngine processDecision in CANARY mode with non-canary event" {
    var engine = IpsSimEngine.init();
    _ = engine.advance();
    _ = engine.advance(); // canary

    const result = engine.processDecision(1, true, false, 0x08080808, 1000);

    try std.testing.expect(result.action == .logged_only);
    try std.testing.expect(!result.actually_blocked);
}

test "IpsSimEngine processDecision in ENFORCE mode" {
    var engine = IpsSimEngine.init();
    _ = engine.advance(); // simulate
    _ = engine.advance(); // canary
    _ = engine.advance(); // enforce

    const result = engine.processDecision(1, true, false, 0x08080808, 1000);

    try std.testing.expect(result.mode == .enforce);
    try std.testing.expect(result.action == .enforced);
    try std.testing.expect(result.actually_blocked == true);
    try std.testing.expect(result.rollback_available == true);
    try std.testing.expect(engine.enforce_count == 1);
    try std.testing.expect(engine.total_blocks_executed == 1);
}

test "IpsSimEngine processDecision in ENFORCE mode no block needed" {
    var engine = IpsSimEngine.init();
    _ = engine.advance();
    _ = engine.advance();
    _ = engine.advance(); // enforce

    const result = engine.processDecision(1, false, false, 0, 1000);

    try std.testing.expect(result.action == .logged_only);
    try std.testing.expect(!result.actually_blocked);
}

test "IpsSimEngine rollbackBlock undoes a block" {
    var engine = IpsSimEngine.init();
    _ = engine.advance();
    _ = engine.advance();
    _ = engine.advance(); // enforce

    _ = engine.processDecision(1, true, false, 0x08080808, 1000);
    try std.testing.expect(engine.pendingBlocks() == 1);

    try std.testing.expect(engine.rollbackBlock(1, 2000));
    try std.testing.expect(engine.total_rollbacks == 1);
    try std.testing.expect(engine.pendingBlocks() == 0);
}

test "IpsSimEngine rollbackBlock fails for non-existent event" {
    var engine = IpsSimEngine.init();
    _ = engine.advance();
    _ = engine.advance();
    _ = engine.advance(); // enforce

    _ = engine.processDecision(1, true, false, 0x08080808, 1000);

    try std.testing.expect(!engine.rollbackBlock(999, 2000)); // not found
}

test "IpsSimEngine rollbackBlock fails for already rolled back" {
    var engine = IpsSimEngine.init();
    _ = engine.advance();
    _ = engine.advance();
    _ = engine.advance(); // enforce

    _ = engine.processDecision(1, true, false, 0x08080808, 1000);
    try std.testing.expect(engine.rollbackBlock(1, 2000));
    try std.testing.expect(!engine.rollbackBlock(1, 3000)); // already rolled back
}

test "IpsSimEngine setMode directly" {
    var engine = IpsSimEngine.init();
    try std.testing.expect(engine.setMode(.enforce));
    try std.testing.expect(engine.getMode() == .enforce);

    try std.testing.expect(engine.setMode(.audit));
    try std.testing.expect(engine.getMode() == .audit);
}

test "IpsSimEngine pendingBlocks counts non-rolled-back" {
    var engine = IpsSimEngine.init();
    _ = engine.advance();
    _ = engine.advance();
    _ = engine.advance(); // enforce

    _ = engine.processDecision(1, true, false, 0x08080808, 1000);
    _ = engine.processDecision(2, true, false, 0x08080809, 2000);
    _ = engine.processDecision(3, true, false, 0x0808080A, 3000);

    try std.testing.expect(engine.pendingBlocks() == 3);

    _ = engine.rollbackBlock(2, 4000);
    try std.testing.expect(engine.pendingBlocks() == 2);
}

test "IpsSimEngine reset zeroes everything" {
    var engine = IpsSimEngine.init();
    _ = engine.advance();
    _ = engine.advance();
    _ = engine.advance(); // enforce
    _ = engine.processDecision(1, true, false, 0x08080808, 1000);

    engine.reset();
    try std.testing.expect(engine.getMode() == .audit);
    try std.testing.expect(engine.total_blocks_executed == 0);
    try std.testing.expect(engine.rollback_count == 0);
}

test "RollbackRecord.isRolledBack" {
    const not_rolled_back = RollbackRecord{
        .event_id = 1,
        .blocked_ip = 0x08080808,
        .timestamp_ns = 1000,
        .reason = "test",
        .rolled_back = false,
        .rollback_timestamp_ns = 0,
    };
    try std.testing.expect(!not_rolled_back.isRolledBack());

    const rolled_back = RollbackRecord{
        .event_id = 1,
        .blocked_ip = 0x08080808,
        .timestamp_ns = 1000,
        .reason = "test",
        .rolled_back = true,
        .rollback_timestamp_ns = 2000,
    };
    try std.testing.expect(rolled_back.isRolledBack());
}

test "SimulationResult.isExecuted" {
    const executed = SimulationResult{
        .mode = .enforce,
        .action = .enforced,
        .event_id = 1,
        .would_block = true,
        .actually_blocked = true,
        .rollback_available = true,
        .description = "test",
    };
    try std.testing.expect(executed.isExecuted());

    const not_executed = SimulationResult{
        .mode = .audit,
        .action = .logged_only,
        .event_id = 1,
        .would_block = true,
        .actually_blocked = false,
        .rollback_available = false,
        .description = "test",
    };
    try std.testing.expect(!not_executed.isExecuted());
}

test "full progression: audit -> simulate -> canary -> enforce" {
    var engine = IpsSimEngine.init();

    // AUDIT: log only
    const audit_result = engine.processDecision(1, true, false, 0x08080808, 1000);
    try std.testing.expect(audit_result.action == .logged_only);

    // SIMULATE: compute but don't execute
    _ = engine.advance();
    const sim_result = engine.processDecision(2, true, false, 0x08080808, 2000);
    try std.testing.expect(sim_result.action == .simulated);

    // CANARY: execute on canary event only
    _ = engine.advance();
    const canary_result = engine.processDecision(3, true, true, 0x08080808, 3000);
    try std.testing.expect(canary_result.action == .canary_executed);

    // ENFORCE: full execution
    _ = engine.advance();
    const enforce_result = engine.processDecision(4, true, false, 0x08080808, 4000);
    try std.testing.expect(enforce_result.action == .enforced);

    // Verify counts
    try std.testing.expect(engine.audit_count == 1);
    try std.testing.expect(engine.simulate_count == 1);
    try std.testing.expect(engine.canary_count == 1);
    try std.testing.expect(engine.enforce_count == 1);
    try std.testing.expect(engine.total_blocks_executed == 2); // canary + enforce

    // Rollback enforce block
    try std.testing.expect(engine.rollbackBlock(4, 5000));
    try std.testing.expect(engine.pendingBlocks() == 1); // canary block still active
}
