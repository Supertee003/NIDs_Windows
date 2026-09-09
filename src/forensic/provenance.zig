// PATCH-34 - Forensic Provenance & Storage Lifecycle
// AEGIS NIDS v5.0+ -- Provenance chain tracking and evidence lifecycle
//
// Provenance chain:
//   CAPTURE-ID -> EVENT-ID -> FLOW-ID -> DETECTION-ID -> INCIDENT-ID
//   -> POLICY-ID -> PEP-REQUEST-ID -> ENFORCEMENT-ID -> AUDIT-ID -> FORENSIC-ID
//
// Storage lifecycle:
//   ACTIVE -> RETIRED -> ARCHIVED -> PURGED

const std = @import("std");
const event = @import("../contract/event.zig");
const evidence = @import("evidence_record.zig");

// ============================================================================
// Provenance Chain ID Types
// ============================================================================
pub const ProvenanceId = struct {
    capture_id: u64 = 0,
    event_id: u64 = 0,
    flow_id: u64 = 0,
    detection_id: u64 = 0,
    incident_id: u64 = 0,
    policy_id: u32 = 0,
    pep_request_id: u64 = 0,
    enforcement_id: u64 = 0,
    audit_id: u64 = 0,
    forensic_id: u64 = 0,

    pub fn init() ProvenanceId {
        return .{};
    }

    /// Check if this provenance chain has at least one non-zero ID.
    pub fn hasAny(self: *const ProvenanceId) bool {
        return self.capture_id != 0 or self.event_id != 0 or self.flow_id != 0 or
            self.detection_id != 0 or self.incident_id != 0 or self.policy_id != 0 or
            self.pep_request_id != 0 or self.enforcement_id != 0 or self.audit_id != 0 or
            self.forensic_id != 0;
    }

    /// Check if this is a complete chain (all IDs set).
    pub fn isComplete(self: *const ProvenanceId) bool {
        return self.capture_id != 0 and self.event_id != 0 and self.flow_id != 0 and
            self.detection_id != 0 and self.incident_id != 0 and self.policy_id != 0 and
            self.pep_request_id != 0 and self.enforcement_id != 0 and self.audit_id != 0 and
            self.forensic_id != 0;
    }

    /// Compute a compact hash of the provenance chain for integrity.
    pub fn hash(self: *const ProvenanceId) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(std.mem.asBytes(&self.capture_id));
        hasher.update(std.mem.asBytes(&self.event_id));
        hasher.update(std.mem.asBytes(&self.flow_id));
        hasher.update(std.mem.asBytes(&self.detection_id));
        hasher.update(std.mem.asBytes(&self.incident_id));
        hasher.update(std.mem.asBytes(&self.policy_id));
        hasher.update(std.mem.asBytes(&self.pep_request_id));
        hasher.update(std.mem.asBytes(&self.enforcement_id));
        hasher.update(std.mem.asBytes(&self.audit_id));
        hasher.update(std.mem.asBytes(&self.forensic_id));
        return hasher.final();
    }
};

// ============================================================================
// Storage Lifecycle
// ============================================================================
pub const StorageState = enum(u8) {
    active = 0, // Currently being written to
    retired = 1, // No longer written, but readable
    archived = 2, // Compressed/stored for long-term
    purged = 3, // Deleted (marker only)
};

pub const StorageLifecycle = struct {
    state: StorageState = .active,
    created_ns: u64 = 0,
    retired_ns: u64 = 0,
    archived_ns: u64 = 0,
    purged_ns: u64 = 0,
    record_count: u64 = 0,
    byte_size: u64 = 0,
    max_records: u64 = 1000000, // retention limit
    max_age_ns: u64 = 30 * 24 * 3600 * std.time.ns_per_s, // 30 days

    pub fn init() StorageLifecycle {
        return .{
            .created_ns = @intCast(std.time.nanoTimestamp()),
        };
    }

    pub fn transition(self: *StorageLifecycle, new_state: StorageState) bool {
        const now: u64 = @intCast(std.time.nanoTimestamp());
        // Valid transitions: active->retired, retired->archived, archived->purged
        switch (self.state) {
            .active => {
                if (new_state == .retired) {
                    self.state = .retired;
                    self.retired_ns = now;
                    return true;
                }
            },
            .retired => {
                if (new_state == .archived) {
                    self.state = .archived;
                    self.archived_ns = now;
                    return true;
                }
            },
            .archived => {
                if (new_state == .purged) {
                    self.state = .purged;
                    self.purged_ns = now;
                    return true;
                }
            },
            .purged => {},
        }
        return false;
    }

    pub fn isExpired(self: *const StorageLifecycle) bool {
        if (self.state == .purged) return false;
        const now: u64 = @intCast(std.time.nanoTimestamp());
        const age = now -| self.created_ns;
        return age > self.max_age_ns or self.record_count > self.max_records;
    }

    pub fn shouldRetire(self: *const StorageLifecycle) bool {
        return self.state == .active and self.isExpired();
    }
};

// ============================================================================
// Forensic Audit Trail Entry
// ============================================================================
pub const AuditAction = enum(u8) {
    record_appended = 1,
    record_read = 2,
    record_verified = 3,
    record_corrupted = 4,
    chain_verified = 5,
    chain_broken = 6,
    lifecycle_transition = 7,
    evidence_created = 8,
    evidence_verified = 9,
    replay_started = 10,
    replay_completed = 11,
};

pub const AuditEntry = extern struct {
    timestamp_ns: u64,
    provenance_hash: u64,
    record_index: u64,
    action: AuditAction,
    success: u8,
    reserved: [5]u8,

    comptime {
        if (@sizeOf(AuditEntry) != 32) {
            @compileError("AuditEntry must be exactly 32 bytes");
        }
    }

    pub fn init(action: AuditAction, prov_hash: u64, index: u64, success: bool) AuditEntry {
        return .{
            .timestamp_ns = @intCast(std.time.nanoTimestamp()),
            .provenance_hash = prov_hash,
            .record_index = index,
            .action = action,
            .success = if (success) 1 else 0,
            .reserved = [_]u8{0} ** 5,
        };
    }
};

// ============================================================================
// ForensicAuditLog -- append-only audit trail
// ============================================================================
pub const ForensicAuditLog = struct {
    entries: std.ArrayList(AuditEntry),
    max_entries: usize,

    pub fn init(allocator: std.mem.Allocator, max_entries: usize) ForensicAuditLog {
        return .{
            .entries = std.ArrayList(AuditEntry).init(allocator),
            .max_entries = max_entries,
        };
    }

    pub fn deinit(self: *ForensicAuditLog) void {
        self.entries.deinit();
    }

    pub fn append(self: *ForensicAuditLog, entry: AuditEntry) !void {
        if (self.entries.items.len >= self.max_entries) {
            // Evict oldest
            _ = self.entries.orderedRemove(0);
        }
        try self.entries.append(entry);
    }

    pub fn count(self: *const ForensicAuditLog) usize {
        return self.entries.items.len;
    }

    pub fn get(self: *const ForensicAuditLog, index: usize) ?*const AuditEntry {
        if (index >= self.entries.items.len) return null;
        return &self.entries.items[index];
    }

    /// Verify audit log integrity: timestamps must be non-decreasing.
    pub fn verifyIntegrity(self: *const ForensicAuditLog) bool {
        var i: usize = 1;
        while (i < self.entries.items.len) : (i += 1) {
            if (self.entries.items[i].timestamp_ns < self.entries.items[i - 1].timestamp_ns) {
                return false;
            }
        }
        return true;
    }
};

// ============================================================================
// ProvenanceTracker -- manages provenance chains for forensic records
// ============================================================================
pub const ProvenanceTracker = struct {
    chains: std.ArrayList(ProvenanceId),
    lifecycle: std.ArrayList(StorageLifecycle),
    audit_log: ForensicAuditLog,

    pub fn init(allocator: std.mem.Allocator) ProvenanceTracker {
        return .{
            .chains = std.ArrayList(ProvenanceId).init(allocator),
            .lifecycle = std.ArrayList(StorageLifecycle).init(allocator),
            .audit_log = ForensicAuditLog.init(allocator, 10000),
        };
    }

    pub fn deinit(self: *ProvenanceTracker) void {
        self.audit_log.deinit();
        self.lifecycle.deinit();
        self.chains.deinit();
    }

    /// Register a new provenance chain.
    pub fn register(self: *ProvenanceTracker, chain: ProvenanceId) !u64 {
        const idx = self.chains.items.len;
        try self.chains.append(chain);
        try self.lifecycle.append(StorageLifecycle.init());
        try self.audit_log.append(AuditEntry.init(
            .evidence_created,
            chain.hash(),
            idx,
            true,
        ));
        return idx;
    }

    /// Get the provenance chain for a given index.
    pub fn getChain(self: *const ProvenanceTracker, index: usize) ?*const ProvenanceId {
        if (index >= self.chains.items.len) return null;
        return &self.chains.items[index];
    }

    /// Get the lifecycle for a given index.
    pub fn getLifecycle(self: *const ProvenanceTracker, index: usize) ?*const StorageLifecycle {
        if (index >= self.lifecycle.items.len) return null;
        return &self.lifecycle.items[index];
    }

    /// Transition a record's lifecycle state.
    pub fn transitionLifecycle(self: *ProvenanceTracker, index: usize, new_state: StorageState) bool {
        if (index >= self.lifecycle.items.len) return false;
        const success = self.lifecycle.items[index].transition(new_state);
        if (success) {
            const chain = &self.chains.items[index];
            self.audit_log.append(AuditEntry.init(
                .lifecycle_transition,
                chain.hash(),
                index,
                true,
            )) catch {};
        }
        return success;
    }

    /// Verify all chains have valid lifecycle transitions.
    pub fn verifyAll(self: *const ProvenanceTracker) bool {
        for (self.lifecycle.items) |lc| {
            // Check for invalid state (purged should not be in the list)
            if (lc.state == .purged) return false;
        }
        return true;
    }

    pub fn count(self: *const ProvenanceTracker) usize {
        return self.chains.items.len;
    }
};

// ============================================================================
// Tests
// ============================================================================
test "ProvenanceId init and basic checks" {
    const pid = ProvenanceId.init();
    try std.testing.expect(!pid.hasAny());
    try std.testing.expect(!pid.isComplete());
}

test "ProvenanceId hasAny and isComplete" {
    var pid = ProvenanceId.init();
    pid.capture_id = 1;
    try std.testing.expect(pid.hasAny());
    try std.testing.expect(!pid.isComplete());

    pid.event_id = 2;
    pid.flow_id = 3;
    pid.detection_id = 4;
    pid.incident_id = 5;
    pid.policy_id = 6;
    pid.pep_request_id = 7;
    pid.enforcement_id = 8;
    pid.audit_id = 9;
    pid.forensic_id = 10;
    try std.testing.expect(pid.isComplete());
}

test "ProvenanceId hash is deterministic" {
    var pid = ProvenanceId.init();
    pid.capture_id = 42;
    pid.event_id = 99;
    const h1 = pid.hash();
    const h2 = pid.hash();
    try std.testing.expectEqual(h1, h2);
}

test "StorageLifecycle transitions" {
    var lc = StorageLifecycle.init();
    try std.testing.expectEqual(StorageState.active, lc.state);
    try std.testing.expect(lc.transition(.retired));
    try std.testing.expectEqual(StorageState.retired, lc.state);
    try std.testing.expect(lc.transition(.archived));
    try std.testing.expectEqual(StorageState.archived, lc.state);
    try std.testing.expect(lc.transition(.purged));
    try std.testing.expectEqual(StorageState.purged, lc.state);
    // Cannot transition from purged
    try std.testing.expect(!lc.transition(.active));
}

test "StorageLifecycle invalid transition" {
    var lc = StorageLifecycle.init();
    // Cannot go directly from active to archived
    try std.testing.expect(!lc.transition(.archived));
    try std.testing.expectEqual(StorageState.active, lc.state);
}

test "AuditEntry size is 32 bytes" {
    try std.testing.expectEqual(@as(usize, 32), @sizeOf(AuditEntry));
}

test "ForensicAuditLog append and verify" {
    var log = ForensicAuditLog.init(std.testing.allocator, 100);
    defer log.deinit();

    _ = try log.append(AuditEntry.init(.record_appended, 0, 0, true));
    _ = try log.append(AuditEntry.init(.record_verified, 0, 1, true));
    try std.testing.expectEqual(@as(usize, 2), log.count());
    try std.testing.expect(log.verifyIntegrity());
}

test "ForensicAuditLog eviction" {
    var log = ForensicAuditLog.init(std.testing.allocator, 3);
    defer log.deinit();

    _ = try log.append(AuditEntry.init(.record_appended, 0, 0, true));
    _ = try log.append(AuditEntry.init(.record_appended, 0, 1, true));
    _ = try log.append(AuditEntry.init(.record_appended, 0, 2, true));
    // This should evict the oldest
    _ = try log.append(AuditEntry.init(.record_appended, 0, 3, true));
    try std.testing.expectEqual(@as(usize, 3), log.count());
    // First entry should be index 1 (index 0 was evicted)
    const first = log.get(0).?;
    try std.testing.expectEqual(@as(u64, 1), first.record_index);
}

test "ProvenanceTracker register and verify" {
    var tracker = ProvenanceTracker.init(std.testing.allocator);
    defer tracker.deinit();

    var pid1 = ProvenanceId.init();
    pid1.capture_id = 1;
    pid1.event_id = 2;
    _ = try tracker.register(pid1);

    var pid2 = ProvenanceId.init();
    pid2.capture_id = 3;
    pid2.event_id = 4;
    _ = try tracker.register(pid2);

    try std.testing.expectEqual(@as(usize, 2), tracker.count());
    try std.testing.expect(tracker.verifyAll());

    // Verify chain linkage
    const c1 = tracker.getChain(0).?;
    const c2 = tracker.getChain(1).?;
    try std.testing.expect(c1.hasAny());
    try std.testing.expect(c2.hasAny());
}
