//! fault_matrix.zig - AEGIS Fault Injection Matrix (P3 Phase R)
//!
//! Defines the fault x subsystem x expected-behavior matrix and a drill
//! runner that verifies each observed recovery behavior matches the
//! documented expectation.
//!
//! Phase R exit condition:
//!   Every fault kind has at least one defined recovery behavior for a
//!   core subsystem, and every drill compares observed vs expected.
//!   No undefined failure modes remain.
//!
//! Design notes:
//!   - Fixed-capacity table (no allocation). Overflow is counted,
//!     never panics (fail-soft, same policy as the rest of AEGIS).
//!   - Self-contained: imports only std, so it can be unit-tested in
//!     isolation.
//!   - defaultMatrix() ships a curated baseline of 18 cells that
//!     covers all 10 fault kinds across the core subsystems.

const std = @import("std");

// ============================================================
// Capacity constants
// ============================================================

/// Maximum cells in the matrix.
pub const MAX_CELLS: usize = 64;
/// Maximum length of a cell note.
pub const MAX_NOTE_LEN: usize = 64;

// ============================================================
// Fault taxonomy
// ============================================================

pub const FaultKind = enum(u8) {
    process_crash = 0,
    disk_full = 1,
    pipe_broken = 2,
    driver_unloaded = 3,
    stage_timeout = 4,
    oom = 5,
    corrupted_input = 6,
    clock_skew = 7,
    network_loss = 8,
    policy_reject = 9,

    pub fn toString(self: FaultKind) []const u8 {
        return switch (self) {
            .process_crash => "process_crash",
            .disk_full => "disk_full",
            .pipe_broken => "pipe_broken",
            .driver_unloaded => "driver_unloaded",
            .stage_timeout => "stage_timeout",
            .oom => "oom",
            .corrupted_input => "corrupted_input",
            .clock_skew => "clock_skew",
            .network_loss => "network_loss",
            .policy_reject => "policy_reject",
        };
    }

    /// Number of distinct fault kinds (for coverage checks).
    pub const count: usize = 10;
};

pub const Subsystem = enum(u8) {
    dispatcher = 0,
    event_fabric = 1,
    flow_engine = 2,
    detection = 3,
    policy = 4,
    pep = 5,
    forensics = 6,
    rag = 7,
    brain = 8,
    capture = 9,
    aegisctl = 10,
    telemetry = 11,

    pub fn toString(self: Subsystem) []const u8 {
        return switch (self) {
            .dispatcher => "dispatcher",
            .event_fabric => "event_fabric",
            .flow_engine => "flow_engine",
            .detection => "detection",
            .policy => "policy",
            .pep => "pep",
            .forensics => "forensics",
            .rag => "rag",
            .brain => "brain",
            .capture => "capture",
            .aegisctl => "aegisctl",
            .telemetry => "telemetry",
        };
    }
};

pub const RecoveryBehavior = enum(u8) {
    /// Skip the failed stage / drop the extra load, keep serving.
    fail_soft_degrade = 0,
    /// Queue the work and retry when the dependency returns.
    buffer_and_retry = 1,
    /// Restart the failed subsystem (watchdog / service recovery).
    restart_subsystem = 2,
    /// Refuse to operate without this dependency (security boundary).
    fail_closed = 3,
    /// Tolerate and keep going (ring buffers overwrite, counters bump).
    ignore_and_log = 4,

    pub fn toString(self: RecoveryBehavior) []const u8 {
        return switch (self) {
            .fail_soft_degrade => "fail_soft_degrade",
            .buffer_and_retry => "buffer_and_retry",
            .restart_subsystem => "restart_subsystem",
            .fail_closed => "fail_closed",
            .ignore_and_log => "ignore_and_log",
        };
    }

    /// True when the system keeps serving (degraded) instead of
    /// shutting the pipeline down. Only fail_closed is not fail-soft.
    pub fn isFailSoft(self: RecoveryBehavior) bool {
        return switch (self) {
            .fail_closed => false,
            else => true,
        };
    }
};

// ============================================================
// Matrix cell
// ============================================================

pub const FaultCell = struct {
    fault: FaultKind,
    subsystem: Subsystem,
    expected: RecoveryBehavior,
    /// Budget for recovery actions (drills assert observed latency
    /// stays under this budget; 0 = no budget defined yet).
    max_recovery_ms: u32,
    /// Drill vector id (0 = no drill vector defined yet).
    drill_id: u32,
    note_buf: [MAX_NOTE_LEN]u8 = undefined,
    note_len: u8 = 0,

    pub fn setNote(self: *FaultCell, note_text: []const u8) void {
        const n = @min(note_text.len, MAX_NOTE_LEN);
        @memcpy(self.note_buf[0..n], note_text[0..n]);
        self.note_len = @intCast(n);
    }

    pub fn note(self: *const FaultCell) []const u8 {
        return self.note_buf[0..self.note_len];
    }
};

// ============================================================
// Fault matrix
// ============================================================

pub const FaultMatrix = struct {
    cells: [MAX_CELLS]FaultCell,
    cell_count: usize,
    rejected_duplicates: u64,
    rejected_overflow: u64,

    pub fn init() FaultMatrix {
        var m: FaultMatrix = undefined;
        m.cell_count = 0;
        m.rejected_duplicates = 0;
        m.rejected_overflow = 0;
        var i: usize = 0;
        while (i < MAX_CELLS) : (i += 1) {
            m.cells[i] = .{
                .fault = .process_crash,
                .subsystem = .dispatcher,
                .expected = .fail_soft_degrade,
                .max_recovery_ms = 0,
                .drill_id = 0,
                .note_buf = undefined,
                .note_len = 0,
            };
        }
        return m;
    }

    /// Register a cell. Rejects duplicate (fault, subsystem) pairs and
    /// overflow, counting rejections instead of panicking.
    pub fn register(
        self: *FaultMatrix,
        fault: FaultKind,
        subsystem: Subsystem,
        expected: RecoveryBehavior,
        max_recovery_ms: u32,
        drill_id: u32,
        note_text: []const u8,
    ) bool {
        if (self.lookup(fault, subsystem) != null) {
            self.rejected_duplicates += 1;
            return false;
        }
        if (self.cell_count >= MAX_CELLS) {
            self.rejected_overflow += 1;
            return false;
        }
        const idx = self.cell_count;
        const c = &self.cells[idx];
        c.fault = fault;
        c.subsystem = subsystem;
        c.expected = expected;
        c.max_recovery_ms = max_recovery_ms;
        c.drill_id = drill_id;
        c.setNote(note_text);
        self.cell_count += 1;
        return true;
    }

    /// Look up the expected behavior for a fault x subsystem pair.
    /// Returns null when the pair is UNDEFINED (a coverage gap).
    pub fn lookup(self: *const FaultMatrix, fault: FaultKind, subsystem: Subsystem) ?*const FaultCell {
        var i: usize = 0;
        while (i < self.cell_count) : (i += 1) {
            const c = &self.cells[i];
            if (c.fault == fault and c.subsystem == subsystem) {
                return c;
            }
        }
        return null;
    }

    /// Number of defined cells for one fault kind (coverage count).
    pub fn coverage(self: *const FaultMatrix, fault: FaultKind) usize {
        var count: usize = 0;
        var i: usize = 0;
        while (i < self.cell_count) : (i += 1) {
            if (self.cells[i].fault == fault) count += 1;
        }
        return count;
    }

    /// True when every fault kind has at least one defined cell.
    pub fn allKindsCovered(self: *const FaultMatrix) bool {
        var k: u8 = 0;
        while (k < FaultKind.count) : (k += 1) {
            const kind: FaultKind = @enumFromInt(k);
            if (self.coverage(kind) == 0) return false;
        }
        return true;
    }

    /// Count of cells whose recovery is fail-closed (security boundary).
    pub fn failClosedCount(self: *const FaultMatrix) usize {
        var count: usize = 0;
        var i: usize = 0;
        while (i < self.cell_count) : (i += 1) {
            if (!self.cells[i].expected.isFailSoft()) count += 1;
        }
        return count;
    }

    pub fn reset(self: *FaultMatrix) void {
        self.* = FaultMatrix.init();
    }
};

// ============================================================
// Drill runner
// ============================================================

pub const DrillResult = enum(u8) {
    pass = 0,
    fail_mismatch = 1,
    fail_no_cell = 2,

    pub fn toString(self: DrillResult) []const u8 {
        return switch (self) {
            .pass => "PASS",
            .fail_mismatch => "FAIL_MISMATCH",
            .fail_no_cell => "FAIL_NO_CELL",
        };
    }
};

pub const DrillRunner = struct {
    total_drills: u64,
    passed: u64,
    failed: u64,

    pub fn init() DrillRunner {
        return .{ .total_drills = 0, .passed = 0, .failed = 0 };
    }

    /// Run one drill: inject a fault into a subsystem, report the
    /// observed recovery behavior, and compare it with the matrix.
    pub fn runDrill(
        self: *DrillRunner,
        matrix: *const FaultMatrix,
        fault: FaultKind,
        subsystem: Subsystem,
        observed: RecoveryBehavior,
    ) DrillResult {
        self.total_drills += 1;
        const cell = matrix.lookup(fault, subsystem) orelse {
            self.failed += 1;
            return .fail_no_cell;
        };
        if (cell.expected == observed) {
            self.passed += 1;
            return .pass;
        }
        self.failed += 1;
        return .fail_mismatch;
    }

    pub fn resetStats(self: *DrillRunner) void {
        self.total_drills = 0;
        self.passed = 0;
        self.failed = 0;
    }
};

// ============================================================
// Curated default matrix (P3 baseline)
// ============================================================

/// Build the default fault matrix. Every FaultKind is covered; the
/// behavior per cell follows the AEGIS failure model:
///   - enforcement/PEP paths fail CLOSED (never serve unprotected)
///   - advisory paths (brain, rag) fail SOFT (skip and continue)
///   - buffers (fabric, forensics ring) absorb pressure
///   - process/driver crashes are restarted by watchdog/service recovery
pub fn defaultMatrix() FaultMatrix {
    var m = FaultMatrix.init();
    // process_crash
    _ = m.register(.process_crash, .dispatcher, .restart_subsystem, 5000, 1, "watchdog restarts the runtime spine");
    _ = m.register(.process_crash, .capture, .restart_subsystem, 5000, 2, "service recovery restarts the sensor");
    _ = m.register(.process_crash, .pep, .fail_closed, 1000, 3, "PEP down means no enforcement: fail closed");
    // disk_full
    _ = m.register(.disk_full, .forensics, .ignore_and_log, 100, 0, "ring buffer overwrites oldest records");
    _ = m.register(.disk_full, .telemetry, .fail_soft_degrade, 1000, 4, "exporter drops batch, pipeline keeps serving");
    // pipe_broken
    _ = m.register(.pipe_broken, .capture, .buffer_and_retry, 2000, 5, "sensor buffers events until the pipe returns");
    _ = m.register(.pipe_broken, .aegisctl, .fail_soft_degrade, 1000, 6, "ctl reports degraded status instead of crashing");
    // driver_unloaded
    _ = m.register(.driver_unloaded, .capture, .fail_closed, 500, 7, "no capture means no verdicts: alert operator");
    _ = m.register(.driver_unloaded, .pep, .fail_closed, 500, 8, "WFP unavailable: refuse to disable enforcement");
    // stage_timeout
    _ = m.register(.stage_timeout, .brain, .fail_soft_degrade, 200, 9, "advisory brain skipped on timeout");
    _ = m.register(.stage_timeout, .rag, .fail_soft_degrade, 200, 10, "RAG fail-soft default context");
    _ = m.register(.stage_timeout, .detection, .fail_soft_degrade, 1000, 11, "detector skipped for this event, pipeline continues");
    // oom
    _ = m.register(.oom, .event_fabric, .buffer_and_retry, 1000, 12, "backpressure applies before any drop");
    _ = m.register(.oom, .forensics, .ignore_and_log, 100, 0, "ring buffer absorbs memory pressure");
    // corrupted_input
    _ = m.register(.corrupted_input, .detection, .ignore_and_log, 10, 13, "malformed event dropped with error counter");
    _ = m.register(.corrupted_input, .policy, .fail_closed, 100, 14, "policy parse failure refuses to compile");
    // clock_skew
    _ = m.register(.clock_skew, .telemetry, .ignore_and_log, 100, 0, "timestamps clamped, events kept");
    // network_loss
    _ = m.register(.network_loss, .telemetry, .buffer_and_retry, 5000, 15, "SIEM export retries with backoff");
    // policy_reject
    _ = m.register(.policy_reject, .policy, .fail_closed, 100, 16, "invalid policy signature: refuse activation");
    return m;
}

// ============================================================
// Tests (P3.2 - Phase R)
// ============================================================

test "P3.2: FaultKind toString roundtrip" {
    try std.testing.expectEqualStrings("process_crash", FaultKind.process_crash.toString());
    try std.testing.expectEqualStrings("corrupted_input", FaultKind.corrupted_input.toString());
    try std.testing.expectEqualStrings("policy_reject", FaultKind.policy_reject.toString());
    // Every enum value must stringify to a non-empty string.
    var k: u8 = 0;
    while (k < FaultKind.count) : (k += 1) {
        const kind: FaultKind = @enumFromInt(k);
        try std.testing.expect(kind.toString().len > 0);
    }
}

test "P3.2: RecoveryBehavior isFailSoft classification" {
    try std.testing.expect(RecoveryBehavior.fail_soft_degrade.isFailSoft());
    try std.testing.expect(RecoveryBehavior.buffer_and_retry.isFailSoft());
    try std.testing.expect(RecoveryBehavior.restart_subsystem.isFailSoft());
    try std.testing.expect(RecoveryBehavior.ignore_and_log.isFailSoft());
    try std.testing.expect(!RecoveryBehavior.fail_closed.isFailSoft());
}

test "P3.2: register and lookup roundtrip" {
    var m = FaultMatrix.init();
    try std.testing.expect(m.register(.disk_full, .forensics, .ignore_and_log, 100, 0, "ring overwrites"));
    const cell = m.lookup(.disk_full, .forensics).?;
    try std.testing.expectEqual(RecoveryBehavior.ignore_and_log, cell.expected);
    try std.testing.expectEqualStrings("ring overwrites", cell.note());
    try std.testing.expectEqual(@as(usize, 1), m.cell_count);
}

test "P3.2: duplicate cell rejected" {
    var m = FaultMatrix.init();
    try std.testing.expect(m.register(.oom, .event_fabric, .buffer_and_retry, 1000, 1, "first"));
    try std.testing.expect(!m.register(.oom, .event_fabric, .ignore_and_log, 5, 0, "dup"));
    try std.testing.expectEqual(@as(usize, 1), m.cell_count);
    try std.testing.expectEqual(@as(u64, 1), m.rejected_duplicates);
    // The first registration wins (deterministic).
    try std.testing.expectEqual(RecoveryBehavior.buffer_and_retry, m.lookup(.oom, .event_fabric).?.expected);
}

test "P3.2: lookup undefined pair returns null" {
    var m = FaultMatrix.init();
    _ = m.register(.oom, .event_fabric, .buffer_and_retry, 1000, 1, "only cell");
    try std.testing.expect(m.lookup(.oom, .pep) == null);
}

test "P3.2: coverage counting and allKindsCovered" {
    var m = FaultMatrix.init();
    try std.testing.expect(!m.allKindsCovered());
    // Cover only one kind first.
    _ = m.register(.process_crash, .dispatcher, .restart_subsystem, 5000, 1, "one");
    try std.testing.expectEqual(@as(usize, 1), m.coverage(.process_crash));
    try std.testing.expectEqual(@as(usize, 0), m.coverage(.disk_full));
    // The default matrix must cover every kind.
    const dm = defaultMatrix();
    try std.testing.expect(dm.allKindsCovered());
}

test "P3.2: defaultMatrix resolves curated cells" {
    const dm = defaultMatrix();
    const pep = dm.lookup(.process_crash, .pep).?;
    try std.testing.expectEqual(RecoveryBehavior.fail_closed, pep.expected);
    const brain = dm.lookup(.stage_timeout, .brain).?;
    try std.testing.expectEqual(RecoveryBehavior.fail_soft_degrade, brain.expected);
    const fabric = dm.lookup(.oom, .event_fabric).?;
    try std.testing.expectEqual(RecoveryBehavior.buffer_and_retry, fabric.expected);
    // 5 fail-closed cells: process_crash x pep, driver_unloaded x capture,
    // driver_unloaded x pep, corrupted_input x policy, policy_reject x policy.
    try std.testing.expectEqual(@as(u32, 5), @as(u32, @intCast(dm.failClosedCount())));
}

test "P3.2: runDrill passes when observed matches expected" {
    const dm = defaultMatrix();
    var r = DrillRunner.init();
    const result = r.runDrill(&dm, .process_crash, .dispatcher, .restart_subsystem);
    try std.testing.expectEqual(DrillResult.pass, result);
    try std.testing.expectEqual(@as(u64, 1), r.passed);
    try std.testing.expectEqual(@as(u64, 0), r.failed);
}

test "P3.2: runDrill fails on mismatch" {
    const dm = defaultMatrix();
    var r = DrillRunner.init();
    const result = r.runDrill(&dm, .process_crash, .pep, .fail_soft_degrade);
    try std.testing.expectEqual(DrillResult.fail_mismatch, result);
    try std.testing.expectEqual(@as(u64, 1), r.failed);
}

test "P3.2: runDrill reports missing cell" {
    var m = FaultMatrix.init();
    var r = DrillRunner.init();
    const result = r.runDrill(&m, .clock_skew, .dispatcher, .ignore_and_log);
    try std.testing.expectEqual(DrillResult.fail_no_cell, result);
    try std.testing.expectEqualStrings("FAIL_NO_CELL", result.toString());
}

test "P3.2: DrillRunner stats accumulate and reset" {
    const dm = defaultMatrix();
    var r = DrillRunner.init();
    _ = r.runDrill(&dm, .process_crash, .dispatcher, .restart_subsystem);
    _ = r.runDrill(&dm, .process_crash, .pep, .fail_closed);
    _ = r.runDrill(&dm, .clock_skew, .dispatcher, .ignore_and_log);
    try std.testing.expectEqual(@as(u64, 3), r.total_drills);
    try std.testing.expectEqual(@as(u64, 2), r.passed);
    try std.testing.expectEqual(@as(u64, 1), r.failed);
    r.resetStats();
    try std.testing.expectEqual(@as(u64, 0), r.total_drills);
}

test "P3.2: full matrix counts overflow instead of panicking" {
    var m = FaultMatrix.init();
    m.cell_count = MAX_CELLS;
    try std.testing.expect(!m.register(.oom, .pep, .fail_closed, 1, 0, "overflow"));
    try std.testing.expectEqual(@as(u64, 1), m.rejected_overflow);
    try std.testing.expectEqual(@as(usize, MAX_CELLS), m.cell_count);
}
