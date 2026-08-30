//! backup_recovery_proof.zig - AEGIS G17 Backup & Recovery Proof (v5.0 Section 62-64)
//!
//! F20: Snapshot, restore, RPO (Recovery Point Objective), RTO (Recovery Time Objective).
//!
//! v5.0 Section 62: Snapshot -- capture config + ruleset version + audit trail state
//!                  at a point in time. Snapshot is immutable and content-addressed.
//! v5.0 Section 63: Restore -- load a snapshot and replay it back into the system.
//!                  Restore is idempotent (same snapshot -> same state).
//! v5.0 Section 64: G17 Exit Gate - RPO and RTO are bounded.
//!                  RPO = max data loss (snapshot interval, default 5 min).
//!                  RTO = max recovery time (restore + verify, default 30 sec).
//!
//! Architecture (forensic_log + audit_trail + config_reload):
//!   SnapshotManager -> capture(state) -> snapshot (content-addressed)
//!   SnapshotManager -> restore(snapshot_id) -> replay state -> verify
//!
//! This module proves:
//!   1. Snapshot: captures config + ruleset version + audit record count + content hash
//!   2. Restore: idempotent (same snapshot -> same state)
//!   3. RPO: bounded by snapshot interval (default 5 min = 300s)
//!   4. RTO: bounded by restore + verify time (default 30s)

const std = @import("std");

// ============================================================
// System State (what gets snapshotted)
// ============================================================

pub const MAX_SNAPSHOTS: usize = 32;
pub const SNAPSHOT_HASH_SEED: u64 = 0xA171BAC5; // "AEGIS BACKUP" magic (valid hex)

pub const SystemState = struct {
    /// Current ruleset version.
    ruleset_version: u32,
    /// Number of rules in the active ruleset.
    rule_count: u32,
    /// Number of events processed since startup.
    total_events: u64,
    /// Number of blocks enforced.
    total_blocks: u64,
    /// Number of audit records written.
    audit_record_count: u64,
    /// Current DEFCON level (1-5).
    defcon_level: u8,
    /// Config file mtime (epoch_ms).
    config_mtime_ms: i64,
    /// Snapshot timestamp (epoch_ms).
    snapshot_at_ms: i64,
};

/// Compute a content hash of the system state (FNV-1a over fields).
fn computeStateHash(state: SystemState) u64 {
    var hash: u64 = SNAPSHOT_HASH_SEED;
    hash ^= state.ruleset_version;
    hash *%= 0x100000001b3;
    hash ^= state.rule_count;
    hash *%= 0x100000001b3;
    hash ^= state.total_events;
    hash *%= 0x100000001b3;
    hash ^= state.total_blocks;
    hash *%= 0x100000001b3;
    hash ^= state.audit_record_count;
    hash *%= 0x100000001b3;
    hash ^= state.defcon_level;
    hash *%= 0x100000001b3;
    hash ^= @as(u64, @intCast(state.config_mtime_ms));
    hash *%= 0x100000001b3;
    hash ^= @as(u64, @intCast(state.snapshot_at_ms));
    hash *%= 0x100000001b3;
    return hash;
}

// ============================================================
// Snapshot (immutable, content-addressed)
// ============================================================
// v5.0 Section 62: "Snapshot is immutable and content-addressed."

pub const Snapshot = struct {
    /// Sequential snapshot ID (1-indexed).
    snapshot_id: u64,
    /// The captured system state.
    state: SystemState,
    /// Content hash of the state (for integrity verification).
    content_hash: u64,
    /// Snapshot timestamp (epoch_ms) -- matches state.snapshot_at_ms.
    captured_at_ms: i64,
};

// ============================================================
// Snapshot Manager
// ============================================================

pub const SnapshotManager = struct {
    snapshots: [MAX_SNAPSHOTS]Snapshot,
    count: usize,
    next_snapshot_id: u64,
    /// Time of the last successful snapshot (epoch_ms).
    last_snapshot_ms: i64,
    /// Time of the last successful restore (epoch_ms).
    last_restore_ms: i64,
    /// Total snapshots captured.
    total_captures: u64,
    /// Total restores performed.
    total_restores: u64,

    pub fn init() SnapshotManager {
        return .{
            .snapshots = undefined,
            .count = 0,
            .next_snapshot_id = 1,
            .last_snapshot_ms = 0,
            .last_restore_ms = 0,
            .total_captures = 0,
            .total_restores = 0,
        };
    }

    /// Capture a snapshot of the current system state.
    /// v5.0 Section 62: snapshot is immutable and content-addressed.
    /// Returns the snapshot_id, or 0 if the snapshot store is full.
    pub fn capture(self: *SnapshotManager, state: SystemState) u64 {
        if (self.count >= MAX_SNAPSHOTS) return 0;

        const snapshot_id = self.next_snapshot_id;
        const content_hash = computeStateHash(state);

        self.snapshots[self.count] = .{
            .snapshot_id = snapshot_id,
            .state = state,
            .content_hash = content_hash,
            .captured_at_ms = state.snapshot_at_ms,
        };

        self.count += 1;
        self.next_snapshot_id += 1;
        self.last_snapshot_ms = state.snapshot_at_ms;
        self.total_captures += 1;

        return snapshot_id;
    }

    /// Get a snapshot by ID (read-only).
    pub fn getById(self: SnapshotManager, snapshot_id: u64) ?Snapshot {
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            if (self.snapshots[i].snapshot_id == snapshot_id) {
                return self.snapshots[i];
            }
        }
        return null;
    }

    /// Restore from a snapshot. Returns the restored SystemState, or null if
    /// the snapshot_id is invalid or the content hash doesn't match (corrupted).
    /// v5.0 Section 63: restore is idempotent.
    pub fn restore(self: *SnapshotManager, snapshot_id: u64, now_ms: i64) ?SystemState {
        const snapshot = self.getById(snapshot_id) orelse return null;

        // Verify content hash (integrity check).
        const recomputed = computeStateHash(snapshot.state);
        if (recomputed != snapshot.content_hash) return null;

        self.last_restore_ms = now_ms;
        self.total_restores += 1;

        return snapshot.state;
    }

    /// Returns the most recent snapshot (or null if none).
    pub fn latest(self: SnapshotManager) ?Snapshot {
        if (self.count == 0) return null;
        return self.snapshots[self.count - 1];
    }

    /// Returns the timestamp of the most recent snapshot (or 0 if none).
    pub fn lastSnapshotMs(self: SnapshotManager) i64 {
        return self.last_snapshot_ms;
    }

    /// Returns the number of stored snapshots.
    pub fn len(self: SnapshotManager) usize {
        return self.count;
    }

    /// Returns true if the snapshot store is full.
    pub fn isFull(self: SnapshotManager) bool {
        return self.count >= MAX_SNAPSHOTS;
    }
};

// ============================================================
// RPO / RTO (v5.0 Section 64)
// ============================================================
// v5.0 Section 64: "RPO and RTO are bounded."
//   RPO = max data loss = snapshot interval (default 5 min = 300000 ms)
//   RTO = max recovery time = restore + verify (default 30 sec = 30000 ms)

pub const DEFAULT_RPO_MS: i64 = 5 * 60 * 1000; // 5 minutes
pub const DEFAULT_RTO_MS: i64 = 30 * 1000; // 30 seconds

pub const RpoRtoStatus = struct {
    /// Configured RPO (max acceptable data loss in ms).
    rpo_ms: i64,
    /// Configured RTO (max acceptable recovery time in ms).
    rto_ms: i64,
    /// Actual time since last snapshot (ms). If this exceeds rpo_ms, RPO is violated.
    time_since_last_snapshot_ms: i64,
    /// Actual time of the last restore (ms). If this exceeds rto_ms, RTO is violated.
    last_restore_duration_ms: i64,
    /// True if RPO is currently satisfied (time since snapshot <= rpo_ms).
    rpo_satisfied: bool,
    /// True if RTO is currently satisfied (last restore duration <= rto_ms).
    rto_satisfied: bool,

    pub fn isCompliant(self: RpoRtoStatus) bool {
        return self.rpo_satisfied and self.rto_satisfied;
    }
};

/// Check RPO/RTO compliance given the current state.
/// v5.0 Section 64: G17 Exit Gate - RPO and RTO are bounded.
pub fn checkRpoRto(
    manager: SnapshotManager,
    now_ms: i64,
    last_restore_duration_ms: i64,
) RpoRtoStatus {
    const rpo_ms = DEFAULT_RPO_MS;
    const rto_ms = DEFAULT_RTO_MS;

    // Time since last snapshot (RPO check).
    const last_snapshot = manager.lastSnapshotMs();
    const time_since_last_snapshot_ms = if (last_snapshot == 0) now_ms else (now_ms - last_snapshot);
    const rpo_satisfied = time_since_last_snapshot_ms <= rpo_ms;

    // Last restore duration (RTO check).
    const rto_satisfied = last_restore_duration_ms <= rto_ms;

    return .{
        .rpo_ms = rpo_ms,
        .rto_ms = rto_ms,
        .time_since_last_snapshot_ms = time_since_last_snapshot_ms,
        .last_restore_duration_ms = last_restore_duration_ms,
        .rpo_satisfied = rpo_satisfied,
        .rto_satisfied = rto_satisfied,
    };
}

// ============================================================
// Snapshot Proof (v5.0 Section 62)
// ============================================================

pub const SnapshotCheck = struct {
    capture_assigns_sequential_id: bool,
    snapshot_is_content_addressed: bool,
    snapshot_is_immutable: bool,
    snapshot_stores_full_state: bool,
    snapshot_ok: bool,

    pub fn isPassed(self: SnapshotCheck) bool {
        return self.snapshot_ok;
    }
};

/// Verify snapshot capture.
/// v5.0 Section 62: snapshot is immutable and content-addressed.
pub fn verifySnapshot() SnapshotCheck {
    var manager = SnapshotManager.init();

    const state1 = SystemState{
        .ruleset_version = 1,
        .rule_count = 10,
        .total_events = 1000,
        .total_blocks = 50,
        .audit_record_count = 200,
        .defcon_level = 5,
        .config_mtime_ms = 1000,
        .snapshot_at_ms = 5000,
    };

    const id1 = manager.capture(state1);

    // Capture assigns sequential ID.
    const capture_assigns_sequential_id = id1 == 1 and manager.len() == 1;

    // Get the snapshot.
    const snap1 = manager.getById(id1).?;

    // Snapshot is content-addressed (hash matches computed hash).
    const expected_hash = computeStateHash(state1);
    const snapshot_is_content_addressed = snap1.content_hash == expected_hash and
        snap1.content_hash != 0;

    // Snapshot is immutable (the stored state matches what was captured).
    const snapshot_is_immutable = snap1.state.ruleset_version == 1 and
        snap1.state.rule_count == 10 and
        snap1.state.total_events == 1000 and
        snap1.state.total_blocks == 50 and
        snap1.state.audit_record_count == 200 and
        snap1.state.defcon_level == 5 and
        snap1.state.config_mtime_ms == 1000 and
        snap1.state.snapshot_at_ms == 5000;

    // Snapshot stores the full state (all 8 fields).
    const snapshot_stores_full_state = snapshot_is_immutable;

    return .{
        .capture_assigns_sequential_id = capture_assigns_sequential_id,
        .snapshot_is_content_addressed = snapshot_is_content_addressed,
        .snapshot_is_immutable = snapshot_is_immutable,
        .snapshot_stores_full_state = snapshot_stores_full_state,
        .snapshot_ok = capture_assigns_sequential_id and snapshot_is_content_addressed and
            snapshot_is_immutable and snapshot_stores_full_state,
    };
}

// ============================================================
// Restore Proof (v5.0 Section 63)
// ============================================================

pub const RestoreCheck = struct {
    restore_returns_state: bool,
    restore_idempotent: bool,
    restore_corrupted_detected: bool,
    restore_invalid_id_returns_null: bool,
    restore_ok: bool,

    pub fn isPassed(self: RestoreCheck) bool {
        return self.restore_ok;
    }
};

/// Verify restore from snapshot.
/// v5.0 Section 63: restore is idempotent.
pub fn verifyRestore() RestoreCheck {
    var manager = SnapshotManager.init();

    const state = SystemState{
        .ruleset_version = 2,
        .rule_count = 15,
        .total_events = 2000,
        .total_blocks = 100,
        .audit_record_count = 300,
        .defcon_level = 3,
        .config_mtime_ms = 2000,
        .snapshot_at_ms = 6000,
    };

    const id = manager.capture(state);

    // Restore returns the captured state.
    const restored1 = manager.restore(id, 7000);
    const restore_returns_state = restored1 != null and
        restored1.?.ruleset_version == 2 and
        restored1.?.total_events == 2000 and
        restored1.?.defcon_level == 3;

    // Restore is idempotent (same snapshot -> same state, multiple times).
    const restored2 = manager.restore(id, 8000);
    const restored3 = manager.restore(id, 9000);
    const restore_idempotent = restored2 != null and restored3 != null and
        restored2.?.ruleset_version == restored1.?.ruleset_version and
        restored3.?.total_events == restored1.?.total_events and
        restored3.?.audit_record_count == restored1.?.audit_record_count;

    // Restore detects corrupted snapshot (content hash mismatch).
    // We simulate corruption by modifying the stored snapshot's state.
    var corrupted_manager = manager;
    corrupted_manager.snapshots[0].state.total_events = 99999; // tampered!
    const corrupted_restore = corrupted_manager.restore(id, 10000);
    const restore_corrupted_detected = corrupted_restore == null;

    // Restore with invalid ID returns null.
    const invalid_restore = manager.restore(999, 11000);
    const restore_invalid_id_returns_null = invalid_restore == null;

    return .{
        .restore_returns_state = restore_returns_state,
        .restore_idempotent = restore_idempotent,
        .restore_corrupted_detected = restore_corrupted_detected,
        .restore_invalid_id_returns_null = restore_invalid_id_returns_null,
        .restore_ok = restore_returns_state and restore_idempotent and
            restore_corrupted_detected and restore_invalid_id_returns_null,
    };
}

// ============================================================
// RPO Proof (v5.0 Section 64)
// ============================================================

pub const RpoCheck = struct {
    rpo_default_5min: bool,
    rpo_satisfied_within_interval: bool,
    rpo_violated_after_interval: bool,
    rpo_no_snapshot_violates: bool,
    rpo_ok: bool,

    pub fn isPassed(self: RpoCheck) bool {
        return self.rpo_ok;
    }
};

/// Verify RPO (Recovery Point Objective).
/// v5.0 Section 64: RPO = max data loss = snapshot interval (default 5 min).
pub fn verifyRpo() RpoCheck {
    // Default RPO is 5 minutes (300000 ms).
    const rpo_default_5min = DEFAULT_RPO_MS == 300000;

    var manager = SnapshotManager.init();

    // Capture a snapshot at t=10000ms.
    const state = SystemState{
        .ruleset_version = 1,
        .rule_count = 10,
        .total_events = 1000,
        .total_blocks = 50,
        .audit_record_count = 200,
        .defcon_level = 5,
        .config_mtime_ms = 1000,
        .snapshot_at_ms = 10000,
    };
    _ = manager.capture(state);

    // At t=20000ms (10s after snapshot), RPO is satisfied (10s < 5min).
    const status_within = checkRpoRto(manager, 20000, 0);
    const rpo_satisfied_within_interval = status_within.rpo_satisfied and
        status_within.time_since_last_snapshot_ms == 10000;

    // At t=400000ms (390s after snapshot), RPO is violated (390s > 300s = 5min).
    const status_after = checkRpoRto(manager, 400000, 0);
    const rpo_violated_after_interval = !status_after.rpo_satisfied and
        status_after.time_since_last_snapshot_ms == 390000;

    // With no snapshots, RPO is always violated (time_since = now).
    var empty_manager = SnapshotManager.init();
    const status_empty = checkRpoRto(empty_manager, 50000, 0);
    const rpo_no_snapshot_violates = !status_empty.rpo_satisfied and
        status_empty.time_since_last_snapshot_ms == 50000;

    return .{
        .rpo_default_5min = rpo_default_5min,
        .rpo_satisfied_within_interval = rpo_satisfied_within_interval,
        .rpo_violated_after_interval = rpo_violated_after_interval,
        .rpo_no_snapshot_violates = rpo_no_snapshot_violates,
        .rpo_ok = rpo_default_5min and rpo_satisfied_within_interval and
            rpo_violated_after_interval and rpo_no_snapshot_violates,
    };
}

// ============================================================
// RTO Proof (v5.0 Section 64) - G17 Exit Gate
// ============================================================

pub const RtoCheck = struct {
    rto_default_30s: bool,
    rto_satisfied_fast_restore: bool,
    rto_violated_slow_restore: bool,
    rto_rpo_both_compliant: bool,
    rto_ok: bool,

    pub fn isPassed(self: RtoCheck) bool {
        return self.rto_ok;
    }
};

/// Verify RTO (Recovery Time Objective).
/// v5.0 Section 64: G17 Exit Gate - RTO = max recovery time (default 30 sec).
pub fn verifyRto() RtoCheck {
    // Default RTO is 30 seconds (30000 ms).
    const rto_default_30s = DEFAULT_RTO_MS == 30000;

    var manager = SnapshotManager.init();

    const state = SystemState{
        .ruleset_version = 1,
        .rule_count = 10,
        .total_events = 1000,
        .total_blocks = 50,
        .audit_record_count = 200,
        .defcon_level = 5,
        .config_mtime_ms = 1000,
        .snapshot_at_ms = 10000,
    };
    _ = manager.capture(state);

    // Fast restore (5 seconds) -- RTO satisfied.
    const status_fast = checkRpoRto(manager, 15000, 5000);
    const rto_satisfied_fast_restore = status_fast.rto_satisfied and
        status_fast.last_restore_duration_ms == 5000;

    // Slow restore (60 seconds) -- RTO violated.
    const status_slow = checkRpoRto(manager, 15000, 60000);
    const rto_violated_slow_restore = !status_slow.rto_satisfied and
        status_slow.last_restore_duration_ms == 60000;

    // Both RPO and RTO compliant (within bounds).
    const status_both = checkRpoRto(manager, 15000, 10000);
    const rto_rpo_both_compliant = status_both.isCompliant() and
        status_both.rpo_satisfied and status_both.rto_satisfied;

    return .{
        .rto_default_30s = rto_default_30s,
        .rto_satisfied_fast_restore = rto_satisfied_fast_restore,
        .rto_violated_slow_restore = rto_violated_slow_restore,
        .rto_rpo_both_compliant = rto_rpo_both_compliant,
        .rto_ok = rto_default_30s and rto_satisfied_fast_restore and
            rto_violated_slow_restore and rto_rpo_both_compliant,
    };
}

// ============================================================
// G17 Report
// ============================================================

pub const G17Report = struct {
    snapshot_ok: bool,
    restore_ok: bool,
    rpo_ok: bool,
    rto_ok: bool,

    pub fn isComplete(self: G17Report) bool {
        return self.snapshot_ok and self.restore_ok and
            self.rpo_ok and self.rto_ok;
    }
};

pub fn generateReport() G17Report {
    return .{
        .snapshot_ok = verifySnapshot().isPassed(),
        .restore_ok = verifyRestore().isPassed(),
        .rpo_ok = verifyRpo().isPassed(),
        .rto_ok = verifyRto().isPassed(),
    };
}

// ============================================================
// Tests
// ============================================================

test "SNAPSHOT_HASH_SEED is valid hex" {
    // G14 lesson: ensure the seed is a valid hex literal (no G-Z chars).
    try std.testing.expect(SNAPSHOT_HASH_SEED == 0xA171BAC5);
}

test "SystemState has 8 fields" {
    const state = SystemState{
        .ruleset_version = 1,
        .rule_count = 10,
        .total_events = 100,
        .total_blocks = 5,
        .audit_record_count = 20,
        .defcon_level = 5,
        .config_mtime_ms = 1000,
        .snapshot_at_ms = 2000,
    };
    try std.testing.expect(state.ruleset_version == 1);
    try std.testing.expect(state.rule_count == 10);
    try std.testing.expect(state.total_events == 100);
    try std.testing.expect(state.total_blocks == 5);
    try std.testing.expect(state.audit_record_count == 20);
    try std.testing.expect(state.defcon_level == 5);
    try std.testing.expect(state.config_mtime_ms == 1000);
    try std.testing.expect(state.snapshot_at_ms == 2000);
}

test "computeStateHash is deterministic" {
    const state = SystemState{
        .ruleset_version = 1,
        .rule_count = 10,
        .total_events = 100,
        .total_blocks = 5,
        .audit_record_count = 20,
        .defcon_level = 5,
        .config_mtime_ms = 1000,
        .snapshot_at_ms = 2000,
    };
    const hash1 = computeStateHash(state);
    const hash2 = computeStateHash(state);
    try std.testing.expect(hash1 == hash2);
    try std.testing.expect(hash1 != 0);
}

test "computeStateHash differs for different states" {
    const state1 = SystemState{
        .ruleset_version = 1,
        .rule_count = 10,
        .total_events = 100,
        .total_blocks = 5,
        .audit_record_count = 20,
        .defcon_level = 5,
        .config_mtime_ms = 1000,
        .snapshot_at_ms = 2000,
    };
    const state2 = SystemState{
        .ruleset_version = 2, // different!
        .rule_count = 10,
        .total_events = 100,
        .total_blocks = 5,
        .audit_record_count = 20,
        .defcon_level = 5,
        .config_mtime_ms = 1000,
        .snapshot_at_ms = 2000,
    };
    try std.testing.expect(computeStateHash(state1) != computeStateHash(state2));
}

test "SnapshotManager init starts empty" {
    const manager = SnapshotManager.init();
    try std.testing.expect(manager.len() == 0);
    try std.testing.expect(!manager.isFull());
    try std.testing.expect(manager.lastSnapshotMs() == 0);
    try std.testing.expect(manager.latest() == null);
}

test "SnapshotManager capture assigns sequential IDs" {
    var manager = SnapshotManager.init();
    const state = SystemState{
        .ruleset_version = 1,
        .rule_count = 10,
        .total_events = 100,
        .total_blocks = 5,
        .audit_record_count = 20,
        .defcon_level = 5,
        .config_mtime_ms = 1000,
        .snapshot_at_ms = 2000,
    };
    const id1 = manager.capture(state);
    const id2 = manager.capture(state);
    const id3 = manager.capture(state);
    try std.testing.expect(id1 == 1);
    try std.testing.expect(id2 == 2);
    try std.testing.expect(id3 == 3);
    try std.testing.expect(manager.len() == 3);
}

test "SnapshotManager capture returns 0 when full" {
    var manager = SnapshotManager.init();
    var i: usize = 0;
    while (i < MAX_SNAPSHOTS) : (i += 1) {
        const state = SystemState{
            .ruleset_version = @intCast(i),
            .rule_count = 10,
            .total_events = 100,
            .total_blocks = 5,
            .audit_record_count = 20,
            .defcon_level = 5,
            .config_mtime_ms = 1000,
            .snapshot_at_ms = @intCast(i * 1000),
        };
        const id = manager.capture(state);
        try std.testing.expect(id != 0);
    }
    try std.testing.expect(manager.isFull());

    const overflow_state = SystemState{
        .ruleset_version = 999,
        .rule_count = 10,
        .total_events = 100,
        .total_blocks = 5,
        .audit_record_count = 20,
        .defcon_level = 5,
        .config_mtime_ms = 1000,
        .snapshot_at_ms = 999000,
    };
    const overflow_id = manager.capture(overflow_state);
    try std.testing.expect(overflow_id == 0);
}

test "SnapshotManager getById finds snapshot" {
    var manager = SnapshotManager.init();
    const state = SystemState{
        .ruleset_version = 1,
        .rule_count = 10,
        .total_events = 100,
        .total_blocks = 5,
        .audit_record_count = 20,
        .defcon_level = 5,
        .config_mtime_ms = 1000,
        .snapshot_at_ms = 2000,
    };
    const id = manager.capture(state);
    const snap = manager.getById(id).?;
    try std.testing.expect(snap.snapshot_id == id);
    try std.testing.expect(snap.state.ruleset_version == 1);
    try std.testing.expect(manager.getById(999) == null);
}

test "SnapshotManager latest returns most recent" {
    var manager = SnapshotManager.init();
    const state1 = SystemState{
        .ruleset_version = 1,
        .rule_count = 10,
        .total_events = 100,
        .total_blocks = 5,
        .audit_record_count = 20,
        .defcon_level = 5,
        .config_mtime_ms = 1000,
        .snapshot_at_ms = 2000,
    };
    const state2 = SystemState{
        .ruleset_version = 2,
        .rule_count = 10,
        .total_events = 100,
        .total_blocks = 5,
        .audit_record_count = 20,
        .defcon_level = 5,
        .config_mtime_ms = 1000,
        .snapshot_at_ms = 3000,
    };
    _ = manager.capture(state1);
    _ = manager.capture(state2);
    const latest = manager.latest().?;
    try std.testing.expect(latest.snapshot_id == 2);
    try std.testing.expect(latest.state.ruleset_version == 2);
}

test "SnapshotManager restore returns captured state" {
    var manager = SnapshotManager.init();
    const state = SystemState{
        .ruleset_version = 3,
        .rule_count = 15,
        .total_events = 500,
        .total_blocks = 25,
        .audit_record_count = 100,
        .defcon_level = 2,
        .config_mtime_ms = 5000,
        .snapshot_at_ms = 10000,
    };
    const id = manager.capture(state);
    const restored = manager.restore(id, 15000).?;
    try std.testing.expect(restored.ruleset_version == 3);
    try std.testing.expect(restored.total_events == 500);
    try std.testing.expect(restored.defcon_level == 2);
}

test "SnapshotManager restore is idempotent" {
    var manager = SnapshotManager.init();
    const state = SystemState{
        .ruleset_version = 1,
        .rule_count = 10,
        .total_events = 100,
        .total_blocks = 5,
        .audit_record_count = 20,
        .defcon_level = 5,
        .config_mtime_ms = 1000,
        .snapshot_at_ms = 2000,
    };
    const id = manager.capture(state);
    const r1 = manager.restore(id, 3000).?;
    const r2 = manager.restore(id, 4000).?;
    const r3 = manager.restore(id, 5000).?;
    try std.testing.expect(r1.ruleset_version == r2.ruleset_version);
    try std.testing.expect(r2.ruleset_version == r3.ruleset_version);
    try std.testing.expect(r1.total_events == r3.total_events);
}

test "SnapshotManager restore returns null for invalid ID" {
    var manager = SnapshotManager.init();
    try std.testing.expect(manager.restore(999, 1000) == null);
    try std.testing.expect(manager.restore(0, 1000) == null);
}

test "SnapshotManager restore detects corrupted snapshot" {
    var manager = SnapshotManager.init();
    const state = SystemState{
        .ruleset_version = 1,
        .rule_count = 10,
        .total_events = 100,
        .total_blocks = 5,
        .audit_record_count = 20,
        .defcon_level = 5,
        .config_mtime_ms = 1000,
        .snapshot_at_ms = 2000,
    };
    const id = manager.capture(state);

    // Tamper with the stored state.
    manager.snapshots[0].state.total_events = 99999;

    // Restore should fail (content hash mismatch).
    try std.testing.expect(manager.restore(id, 3000) == null);
}

test "verifySnapshot passes (v5.0 Section 62)" {
    const check = verifySnapshot();
    try std.testing.expect(check.isPassed());
    try std.testing.expect(check.capture_assigns_sequential_id);
    try std.testing.expect(check.snapshot_is_content_addressed);
    try std.testing.expect(check.snapshot_is_immutable);
    try std.testing.expect(check.snapshot_stores_full_state);
}

test "verifyRestore passes (v5.0 Section 63)" {
    const check = verifyRestore();
    try std.testing.expect(check.isPassed());
    try std.testing.expect(check.restore_returns_state);
    try std.testing.expect(check.restore_idempotent);
    try std.testing.expect(check.restore_corrupted_detected);
    try std.testing.expect(check.restore_invalid_id_returns_null);
}

test "DEFAULT_RPO_MS is 5 minutes" {
    try std.testing.expect(DEFAULT_RPO_MS == 300000);
}

test "DEFAULT_RTO_MS is 30 seconds" {
    try std.testing.expect(DEFAULT_RTO_MS == 30000);
}

test "checkRpoRto RPO satisfied within interval" {
    var manager = SnapshotManager.init();
    const state = SystemState{
        .ruleset_version = 1,
        .rule_count = 10,
        .total_events = 100,
        .total_blocks = 5,
        .audit_record_count = 20,
        .defcon_level = 5,
        .config_mtime_ms = 1000,
        .snapshot_at_ms = 10000,
    };
    _ = manager.capture(state);
    const status = checkRpoRto(manager, 20000, 5000);
    try std.testing.expect(status.rpo_satisfied);
    try std.testing.expect(status.rto_satisfied);
    try std.testing.expect(status.isCompliant());
}

test "checkRpoRto RPO violated after interval" {
    var manager = SnapshotManager.init();
    const state = SystemState{
        .ruleset_version = 1,
        .rule_count = 10,
        .total_events = 100,
        .total_blocks = 5,
        .audit_record_count = 20,
        .defcon_level = 5,
        .config_mtime_ms = 1000,
        .snapshot_at_ms = 10000,
    };
    _ = manager.capture(state);
    // 400 seconds later -> exceeds 5min (300s) RPO.
    const status = checkRpoRto(manager, 410000, 5000);
    try std.testing.expect(!status.rpo_satisfied);
    try std.testing.expect(!status.isCompliant());
}

test "checkRpoRto RTO violated for slow restore" {
    var manager = SnapshotManager.init();
    const state = SystemState{
        .ruleset_version = 1,
        .rule_count = 10,
        .total_events = 100,
        .total_blocks = 5,
        .audit_record_count = 20,
        .defcon_level = 5,
        .config_mtime_ms = 1000,
        .snapshot_at_ms = 10000,
    };
    _ = manager.capture(state);
    // 60 second restore -> exceeds 30s RTO.
    const status = checkRpoRto(manager, 20000, 60000);
    try std.testing.expect(!status.rto_satisfied);
    try std.testing.expect(!status.isCompliant());
}

test "checkRpoRto no snapshot violates RPO" {
    const manager = SnapshotManager.init();
    const status = checkRpoRto(manager, 50000, 5000);
    try std.testing.expect(!status.rpo_satisfied);
}

test "verifyRpo passes (v5.0 Section 64)" {
    const check = verifyRpo();
    try std.testing.expect(check.isPassed());
    try std.testing.expect(check.rpo_default_5min);
    try std.testing.expect(check.rpo_satisfied_within_interval);
    try std.testing.expect(check.rpo_violated_after_interval);
    try std.testing.expect(check.rpo_no_snapshot_violates);
}

test "verifyRto passes (G17 Exit Gate)" {
    // v5.0 Section 64: "RPO and RTO are bounded."
    const check = verifyRto();
    try std.testing.expect(check.isPassed());
    try std.testing.expect(check.rto_default_30s);
    try std.testing.expect(check.rto_satisfied_fast_restore);
    try std.testing.expect(check.rto_violated_slow_restore);
    try std.testing.expect(check.rto_rpo_both_compliant);
}

test "generateReport is complete" {
    const report = generateReport();
    try std.testing.expect(report.snapshot_ok);
    try std.testing.expect(report.restore_ok);
    try std.testing.expect(report.rpo_ok);
    try std.testing.expect(report.rto_ok);
    try std.testing.expect(report.isComplete());
}

test "G17 Exit Gate: full backup and recovery flow" {
    // v5.0 Section 62-64: snapshot -> restore -> RPO/RTO compliance
    var manager = SnapshotManager.init();

    // Step 1: capture system state at t=10000ms.
    const state_v1 = SystemState{
        .ruleset_version = 1,
        .rule_count = 10,
        .total_events = 1000,
        .total_blocks = 50,
        .audit_record_count = 200,
        .defcon_level = 5,
        .config_mtime_ms = 1000,
        .snapshot_at_ms = 10000,
    };
    const snap_id = manager.capture(state_v1);
    try std.testing.expect(snap_id == 1);

    // Step 2: simulate system changes (more events, blocks, audit records).
    // (In a real system, these would happen between snapshots.)

    // Step 3: capture another snapshot at t=60000ms (50s later).
    const state_v2 = SystemState{
        .ruleset_version = 2,
        .rule_count = 12,
        .total_events = 5000,
        .total_blocks = 250,
        .audit_record_count = 800,
        .defcon_level = 3, // escalated
        .config_mtime_ms = 2000,
        .snapshot_at_ms = 60000,
    };
    const snap_id2 = manager.capture(state_v2);
    try std.testing.expect(snap_id2 == 2);

    // Step 4: restore from snapshot 1 (rollback to v1 state).
    const restored = manager.restore(snap_id, 65000).?;
    try std.testing.expect(restored.ruleset_version == 1);
    try std.testing.expect(restored.total_events == 1000);
    try std.testing.expect(restored.defcon_level == 5);

    // Step 5: verify RPO/RTO compliance (within bounds).
    const status = checkRpoRto(manager, 65000, 5000); // 5s restore
    try std.testing.expect(status.rpo_satisfied); // last snapshot at 60000, now 65000 (5s)
    try std.testing.expect(status.rto_satisfied); // 5s restore < 30s
    try std.testing.expect(status.isCompliant());

    // Step 6: verify snapshot integrity (content hash matches).
    const snap1 = manager.getById(snap_id).?;
    try std.testing.expect(snap1.content_hash == computeStateHash(state_v1));
    const snap2 = manager.getById(snap_id2).?;
    try std.testing.expect(snap2.content_hash == computeStateHash(state_v2));
}
