// PATCH-35 — Replay & Evidence Verification
// AEGIS NIDS v5.0+ -- Verify forensic evidence through controlled replay
//
// Provides:
//   - ReplayDecision: structured record of a replay verification
//   - ReplayVerifier: orchestrates export → verify → replay → compare
//   - Safety: replay never executes live enforcement by default
//
// Flow:
//   1. Export forensic records from the ring
//   2. Verify record integrity (CRC + hash chain)
//   3. Replay events through the pipeline in observation-only mode
//   4. Compare replay decisions against original decisions
//   5. Produce ReplayDecision with pass/fail + evidence

const std = @import("std");
const event = @import("../contract/event.zig");
const forensic = @import("forensic_pipeline.zig");
const trace_mod = @import("decision_trace.zig");
const integrity = @import("replay_integrity.zig");

/// Replay mode — controls enforcement behavior during replay
pub const ReplayMode = enum(u8) {
    observe_only = 0, // no enforcement (default, safe)
    simulate = 1, // record what WOULD have happened
    enforce = 2, // actually enforce (DANGEROUS — never use in production replay)
};

/// Result of comparing original vs replay for a single event
pub const EventReplayResult = struct {
    original_audit_id: u64,
    original_decision: u8, // PepDecision enum value
    replay_decision: u8, // PepDecision enum value
    match: bool,
    rule_id: u32,
    policy_id: u32,
};

/// ReplayDecision — complete record of a replay verification run
pub const ReplayDecision = extern struct {
    magic: u32,
    version: u16,
    _pad0: [2]u8,

    // Run identity
    replay_id: u64, // unique replay run ID
    timestamp_ns: u64, // when the replay was executed

    // Source
    source_start: u64, // first forensic record index
    source_end: u64, // last forensic record index (exclusive)
    source_count: u64, // number of records exported

    // Integrity
    integrity_verified: bool, // true if all records passed CRC + hash check
    integrity_errors: u32, // number of records that failed integrity
    _pad1: [2]u8,

    // Replay
    replay_mode: u8, // ReplayMode enum
    _pad2: [3]u8,
    events_replayed: u64, // number of events fed through pipeline
    events_matched: u64, // number where replay decision == original
    events_mismatched: u64, // number where replay decision != original

    // Hash
    original_hash: [32]u8, // SHA-256 of original record hashes
    replay_hash: [32]u8, // SHA-256 of replay record hashes

    // Outcome
    pass: bool, // true if replay is deterministic
    _pad3: [7]u8,

    pub fn init(replay_id: u64) ReplayDecision {
        return .{
            .magic = 0x7265706C, // "repl"
            .version = 1,
            ._pad0 = .{ 0, 0 },
            .replay_id = replay_id,
            .timestamp_ns = @intCast(@as(u64, @intCast(std.time.nanoTimestamp()))),
            .source_start = 0,
            .source_end = 0,
            .source_count = 0,
            .integrity_verified = false,
            .integrity_errors = 0,
            ._pad1 = .{ 0, 0 },
            .replay_mode = @intFromEnum(ReplayMode.observe_only),
            ._pad2 = .{ 0, 0, 0 },
            .events_replayed = 0,
            .events_matched = 0,
            .events_mismatched = 0,
            .original_hash = [_]u8{0} ** 32,
            .replay_hash = [_]u8{0} ** 32,
            .pass = false,
            ._pad3 = .{ 0, 0, 0, 0, 0, 0, 0 },
        };
    }

    pub fn validate(self: *const ReplayDecision) bool {
        return self.magic == 0x7265706C and self.version == 1;
    }

    pub fn asBytes(self: *const ReplayDecision) []const u8 {
        return std.mem.asBytes(self);
    }
};

/// Exported forensic record with its metadata
pub const ExportedRecord = struct {
    slot: []const u8, // raw record bytes (caller owns after export)
    index: u64, // original index in the ring
    valid_crc: bool, // CRC check result
    valid_hash: bool, // hash chain check result
};

/// ReplayVerifier — orchestrates the full replay verification flow
pub const ReplayVerifier = struct {
    allocator: std.mem.Allocator,
    ring: *forensic.ForensicRing,
    decision: ReplayDecision,
    exported_records: std.ArrayList(ExportedRecord),
    event_results: std.ArrayList(EventReplayResult),

    pub fn init(allocator: std.mem.Allocator, ring: *forensic.ForensicRing, replay_id: u64) ReplayVerifier {
        return .{
            .allocator = allocator,
            .ring = ring,
            .decision = ReplayDecision.init(replay_id),
            .exported_records = std.ArrayList(ExportedRecord).init(allocator),
            .event_results = std.ArrayList(EventReplayResult).init(allocator),
        };
    }

    pub fn deinit(self: *ReplayVerifier) void {
        for (self.exported_records.items) |rec| {
            self.allocator.free(rec.slot);
        }
        self.exported_records.deinit();
        self.event_results.deinit();
    }

    /// Step 1: Export forensic records from the ring.
    /// Exports all retained records (from oldest to newest).
    pub fn exportRecords(self: *ReplayVerifier) !void {
        const count = self.ring.recordCount();
        const num_slots = self.ring.capacity() / forensic.RECORD_BYTES;
        const oldest: u64 = if (count > num_slots) count - num_slots else 0;

        self.decision.source_start = oldest;
        self.decision.source_end = count;
        self.decision.source_count = count - oldest;

        var i = oldest;
        while (i < count) : (i += 1) {
            const slot = self.ring.readRecord(i, self.allocator) orelse continue;
            const valid_crc = forensic.ForensicRing.verifyRecord(slot);
            const valid_hash = forensic.ForensicRing.verifyRecordHash(slot);
            try self.exported_records.append(.{
                .slot = slot,
                .index = i,
                .valid_crc = valid_crc,
                .valid_hash = valid_hash,
            });
        }
    }

    /// Step 2: Verify integrity of all exported records.
    pub fn verifyIntegrity(self: *ReplayVerifier) bool {
        var errors: u32 = 0;
        for (self.exported_records.items) |rec| {
            if (!rec.valid_crc or !rec.valid_hash) {
                errors += 1;
            }
        }
        self.decision.integrity_errors = errors;
        self.decision.integrity_verified = (errors == 0);
        return self.decision.integrity_verified;
    }

    /// Step 3: Compute original hash (SHA-256 of all exported record hashes).
    pub fn computeOriginalHash(self: *ReplayVerifier) void {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        for (self.exported_records.items) |rec| {
            if (rec.slot.len >= @sizeOf(forensic.RecordHeader)) {
                const hdr = std.mem.bytesAsValue(forensic.RecordHeader, rec.slot[0..@sizeOf(forensic.RecordHeader)]);
                hasher.update(&hdr.current_hash);
            }
        }
        hasher.final(&self.decision.original_hash);
    }

    /// Step 4: Record a replay comparison result.
    pub fn recordReplayResult(
        self: *ReplayVerifier,
        original_audit_id: u64,
        original_decision: u8,
        replay_decision: u8,
        rule_id: u32,
        policy_id: u32,
    ) !void {
        const match = original_decision == replay_decision;
        try self.event_results.append(.{
            .original_audit_id = original_audit_id,
            .original_decision = original_decision,
            .replay_decision = replay_decision,
            .match = match,
            .rule_id = rule_id,
            .policy_id = policy_id,
        });
        self.decision.events_replayed += 1;
        if (match) {
            self.decision.events_matched += 1;
        } else {
            self.decision.events_mismatched += 1;
        }
    }

    /// Step 5: Compute replay hash from event results.
    pub fn computeReplayHash(self: *ReplayVerifier) void {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        for (self.event_results.items) |res| {
            hasher.update(std.mem.asBytes(&res.original_audit_id));
            hasher.update(&.{res.original_decision, res.replay_decision});
        }
        hasher.final(&self.decision.replay_hash);
    }

    /// Step 6: Finalize — determine pass/fail.
    pub fn finalize(self: *ReplayVerifier) void {
        self.decision.pass = self.decision.integrity_verified and
            self.decision.events_mismatched == 0 and
            self.decision.events_replayed > 0;
    }

    /// Run the full verification flow (export → verify → hash).
    /// The caller must then feed events through the pipeline and call
    /// recordReplayResult for each, then computeReplayHash + finalize.
    pub fn runVerification(self: *ReplayVerifier) !bool {
        try self.exportRecords();
        _ = self.verifyIntegrity();
        self.computeOriginalHash();
        return self.decision.integrity_verified;
    }
};

// ============================================================================
// Tests
// ============================================================================
test "ReplayDecision init and validate" {
    var rd = ReplayDecision.init(42);
    try std.testing.expect(rd.validate());
    try std.testing.expectEqual(@as(u64, 42), rd.replay_id);
    try std.testing.expect(!rd.pass); // not yet finalized
}

test "ReplayDecision asBytes" {
    var rd = ReplayDecision.init(1);
    const bytes = rd.asBytes();
    try std.testing.expect(bytes.len > 0);
    try std.testing.expect(bytes.len >= 64); // at least 64 bytes for the struct
}

test "ReplayMode defaults to observe_only" {
    const rd = ReplayDecision.init(1);
    try std.testing.expectEqual(@intFromEnum(ReplayMode.observe_only), rd.replay_mode);
}

test "EventReplayResult match" {
    const res = EventReplayResult{
        .original_audit_id = 1,
        .original_decision = 1, // block
        .replay_decision = 1, // block
        .match = true,
        .rule_id = 5,
        .policy_id = 3,
    };
    try std.testing.expect(res.match);
}

test "EventReplayResult mismatch" {
    const res = EventReplayResult{
        .original_audit_id = 2,
        .original_decision = 1, // block
        .replay_decision = 0, // allow
        .match = false,
        .rule_id = 5,
        .policy_id = 3,
    };
    try std.testing.expect(!res.match);
}

test "ReplayVerifier export and verify" {
    var ring = try forensic.ForensicRing.initMemory(std.testing.allocator, 8 * forensic.RECORD_BYTES);
    defer ring.deinit(std.testing.allocator);

    var ev = event.IpcEvent.init(.signature_match);
    ev.now();
    _ = try ring.append(&ev, "payload1", 10, 5, 1, 3);
    _ = try ring.append(&ev, "payload2", 11, 6, 0, 4);

    var verifier = ReplayVerifier.init(std.testing.allocator, &ring, 1);
    defer verifier.deinit();

    const ok = try verifier.runVerification();
    try std.testing.expect(ok);
    try std.testing.expectEqual(@as(u64, 2), verifier.decision.source_count);
    try std.testing.expect(verifier.decision.integrity_verified);
    try std.testing.expectEqual(@as(u32, 0), verifier.decision.integrity_errors);
}

test "ReplayVerifier records replay results" {
    var ring = try forensic.ForensicRing.initMemory(std.testing.allocator, 8 * forensic.RECORD_BYTES);
    defer ring.deinit(std.testing.allocator);

    var ev = event.IpcEvent.init(.signature_match);
    ev.now();
    _ = try ring.append(&ev, "data", 0, 0, 0, 0);

    var verifier = ReplayVerifier.init(std.testing.allocator, &ring, 1);
    defer verifier.deinit();

    _ = try verifier.runVerification();

    // Simulate replay results
    try verifier.recordReplayResult(0, 1, 1, 5, 3); // match (block→block)
    try verifier.recordReplayResult(1, 0, 0, 0, 0); // match (allow→allow)

    verifier.computeReplayHash();
    verifier.finalize();

    try std.testing.expect(verifier.decision.pass);
    try std.testing.expectEqual(@as(u64, 2), verifier.decision.events_replayed);
    try std.testing.expectEqual(@as(u64, 2), verifier.decision.events_matched);
    try std.testing.expectEqual(@as(u64, 0), verifier.decision.events_mismatched);
}

test "ReplayVerifier detects mismatch" {
    var ring = try forensic.ForensicRing.initMemory(std.testing.allocator, 8 * forensic.RECORD_BYTES);
    defer ring.deinit(std.testing.allocator);

    var ev = event.IpcEvent.init(.signature_match);
    ev.now();
    _ = try ring.append(&ev, "data", 0, 0, 0, 0);

    var verifier = ReplayVerifier.init(std.testing.allocator, &ring, 1);
    defer verifier.deinit();

    _ = try verifier.runVerification();

    // Mismatch: original was block, replay says allow
    try verifier.recordReplayResult(0, 1, 0, 5, 3);

    verifier.computeReplayHash();
    verifier.finalize();

    try std.testing.expect(!verifier.decision.pass);
    try std.testing.expectEqual(@as(u64, 1), verifier.decision.events_mismatched);
}
