// PATCH-33 - Evidence Data Model
// AEGIS NIDS v5.0+ -- Evidence record for audit trail and integrity
//
// Every evidence record identifies:
//   HEAD, TIMESTAMP, OS, TOOLCHAIN, RUNTIME_VERSION, POLICY_VERSION,
//   DRIVER_VERSION, TEST_PROFILE, COMMAND, EXPECTED, ACTUAL, ARTIFACT,
//   HASH, RESULT
//
// The hash chain (previous_hash -> current_hash) ensures tamper detection.

const std = @import("std");
const event = @import("../contract/event.zig");

pub const EVIDENCE_MAGIC: u32 = 0xED1BACC3;
pub const EVIDENCE_VERSION: u16 = 1;
pub const HASH_BYTES: usize = 32; // SHA-256
pub const MAX_COMMAND_LEN: usize = 208; // adjusted for 1024-byte alignment
pub const MAX_ARTIFACT_PATH: usize = 256;
pub const MAX_RESULT_LEN: usize = 128;

pub const EvidenceResult = enum(u8) {
    pass = 1,
    fail = 2,
    skip = 3,
    error_timeout = 4,
    error_crash = 5,
    inconclusive = 6,
    _,
};

pub const EvidenceRecord = extern struct {
    magic: u32,
    version: u16,
    result: EvidenceResult,
    reserved1: u8,

    // Provenance
    timestamp_ns: u64,
    head: [40]u8, // git commit SHA-1 (padded with zeros)

    // Environment
    os: [16]u8, // e.g. "windows-11"
    toolchain: [32]u8, // e.g. "zig-0.13.0"
    runtime_version: [16]u8, // e.g. "5.0.0"
    policy_version: [16]u8, // e.g. "1.0.0"
    driver_version: [16]u8, // e.g. "1.0.0" or empty

    // Test context
    test_profile: [32]u8, // e.g. "unit", "integration", "golden-path"

    // Provenance chain
    event_id: u64, // originating event (0 if not event-linked)
    flow_id: u64, // originating flow (0 if not flow-linked)
    audit_id: u64, // audit trail ID

    // Integrity
    previous_hash: [HASH_BYTES]u8, // hash of previous evidence record
    current_hash: [HASH_BYTES]u8, // hash of this record's content

    // Variable-length fields (stored as fixed-size, null-terminated)
    command: [MAX_COMMAND_LEN]u8,
    expected: [MAX_RESULT_LEN]u8,
    actual: [MAX_RESULT_LEN]u8,
    artifact_path: [MAX_ARTIFACT_PATH]u8,
    artifact_hash: [HASH_BYTES]u8, // SHA-256 of the artifact

    comptime {
        // EvidenceRecord must be exactly 1024 bytes for alignment
        if (@sizeOf(EvidenceRecord) != 1024) {
            @compileError("EvidenceRecord must be exactly 1024 bytes");
        }
    }

    pub fn init() EvidenceRecord {
        return .{
            .magic = EVIDENCE_MAGIC,
            .version = EVIDENCE_VERSION,
            .result = .pass,
            .reserved1 = 0,
            .timestamp_ns = 0,
            .head = [_]u8{0} ** 40,
            .os = [_]u8{0} ** 16,
            .toolchain = [_]u8{0} ** 32,
            .runtime_version = [_]u8{0} ** 16,
            .policy_version = [_]u8{0} ** 16,
            .driver_version = [_]u8{0} ** 16,
            .test_profile = [_]u8{0} ** 32,
            .event_id = 0,
            .flow_id = 0,
            .audit_id = 0,
            .previous_hash = [_]u8{0} ** HASH_BYTES,
            .current_hash = [_]u8{0} ** HASH_BYTES,
            .command = [_]u8{0} ** MAX_COMMAND_LEN,
            .expected = [_]u8{0} ** MAX_RESULT_LEN,
            .actual = [_]u8{0} ** MAX_RESULT_LEN,
            .artifact_path = [_]u8{0} ** MAX_ARTIFACT_PATH,
            .artifact_hash = [_]u8{0} ** HASH_BYTES,
        };
    }

    pub fn validate(self: *const EvidenceRecord) bool {
        return self.magic == EVIDENCE_MAGIC and self.version == EVIDENCE_VERSION;
    }

    pub fn setHead(self: *EvidenceRecord, sha: []const u8) void {
        const len = @min(sha.len, 40);
        @memcpy(self.head[0..len], sha[0..len]);
    }

    pub fn setOs(self: *EvidenceRecord, os_name: []const u8) void {
        const len = @min(os_name.len, 16);
        @memcpy(self.os[0..len], os_name[0..len]);
    }

    pub fn setToolchain(self: *EvidenceRecord, tc: []const u8) void {
        const len = @min(tc.len, 32);
        @memcpy(self.toolchain[0..len], tc[0..len]);
    }

    pub fn setRuntimeVersion(self: *EvidenceRecord, ver: []const u8) void {
        const len = @min(ver.len, 16);
        @memcpy(self.runtime_version[0..len], ver[0..len]);
    }

    pub fn setPolicyVersion(self: *EvidenceRecord, ver: []const u8) void {
        const len = @min(ver.len, 16);
        @memcpy(self.policy_version[0..len], ver[0..len]);
    }

    pub fn setDriverVersion(self: *EvidenceRecord, ver: []const u8) void {
        const len = @min(ver.len, 16);
        @memcpy(self.driver_version[0..len], ver[0..len]);
    }

    pub fn setTestProfile(self: *EvidenceRecord, profile: []const u8) void {
        const len = @min(profile.len, 32);
        @memcpy(self.test_profile[0..len], profile[0..len]);
    }

    pub fn setCommand(self: *EvidenceRecord, cmd: []const u8) void {
        const len = @min(cmd.len, MAX_COMMAND_LEN);
        @memcpy(self.command[0..len], cmd[0..len]);
    }

    pub fn setExpected(self: *EvidenceRecord, exp: []const u8) void {
        const len = @min(exp.len, MAX_RESULT_LEN);
        @memcpy(self.expected[0..len], exp[0..len]);
    }

    pub fn setActual(self: *EvidenceRecord, act: []const u8) void {
        const len = @min(act.len, MAX_RESULT_LEN);
        @memcpy(self.actual[0..len], act[0..len]);
    }

    pub fn setArtifactPath(self: *EvidenceRecord, path: []const u8) void {
        const len = @min(path.len, MAX_ARTIFACT_PATH);
        @memcpy(self.artifact_path[0..len], path[0..len]);
    }

    pub fn setArtifactHash(self: *EvidenceRecord, hash: []const u8) void {
        const len = @min(hash.len, HASH_BYTES);
        @memcpy(self.artifact_hash[0..len], hash[0..len]);
    }

    /// Compute the current hash of this record (excluding current_hash field itself).
    /// The hash covers: magic through artifact_hash, but not current_hash.
    pub fn computeHash(self: *const EvidenceRecord) [HASH_BYTES]u8 {
        const Self = @This();
        // Hash everything except current_hash: [0..current_hash) and (current_hash..end)
        const ch_off = @offsetOf(Self, "current_hash");
        const ch_size = @sizeOf([HASH_BYTES]u8);
        const data = std.mem.asBytes(self);
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        // Part 1: everything before current_hash
        if (ch_off > 0) {
            hasher.update(data[0..ch_off]);
        }
        // Part 2: everything after current_hash
        const after_start = ch_off + ch_size;
        if (after_start < data.len) {
            hasher.update(data[after_start..]);
        }
        var hash: [HASH_BYTES]u8 = undefined;
        hasher.final(&hash);
        return hash;
    }

    /// Verify the hash chain: current_hash matches computed hash.
    pub fn verifyIntegrity(self: *const EvidenceRecord) bool {
        const computed = self.computeHash();
        return std.mem.eql(u8, &self.current_hash, &computed);
    }

    /// Finalize the record: compute and set current_hash.
    pub fn finalize(self: *EvidenceRecord) void {
        self.current_hash = self.computeHash();
    }

    /// Check if this record links to a previous record.
    pub fn hasPreviousHash(self: *const EvidenceRecord) bool {
        for (self.previous_hash) |b| {
            if (b != 0) return true;
        }
        return false;
    }
};

// ============================================================================
// EvidenceChain — manages a sequence of evidence records with hash chain
// ============================================================================
pub const EvidenceChain = struct {
    records: std.ArrayList(EvidenceRecord),
    last_hash: [HASH_BYTES]u8,

    pub fn init(allocator: std.mem.Allocator) EvidenceChain {
        return .{
            .records = std.ArrayList(EvidenceRecord).init(allocator),
            .last_hash = [_]u8{0} ** HASH_BYTES,
        };
    }

    pub fn deinit(self: *EvidenceChain) void {
        self.records.deinit();
    }

    /// Append a new evidence record, linking it to the chain.
    pub fn append(self: *EvidenceChain, record: EvidenceRecord) !u64 {
        var r = record;
        r.previous_hash = self.last_hash;
        r.timestamp_ns = @intCast(std.time.nanoTimestamp());
        r.finalize();
        try self.records.append(r);
        self.last_hash = r.current_hash;
        return self.records.items.len;
    }

    /// Verify the entire chain integrity.
    pub fn verifyChain(self: *const EvidenceChain) bool {
        var prev_hash = [_]u8{0} ** HASH_BYTES;
        for (self.records.items) |*rec| {
            // Check hash chain linkage
            if (!std.mem.eql(u8, &rec.previous_hash, &prev_hash)) {
                return false;
            }
            // Check record integrity
            if (!rec.verifyIntegrity()) {
                return false;
            }
            prev_hash = rec.current_hash;
        }
        return true;
    }

    pub fn count(self: *const EvidenceChain) usize {
        return self.records.items.len;
    }

    pub fn get(self: *const EvidenceChain, index: usize) ?*const EvidenceRecord {
        if (index >= self.records.items.len) return null;
        return &self.records.items[index];
    }
};

// ============================================================================
// Tests
// ============================================================================
test "EvidenceRecord init and validate" {
    var rec = EvidenceRecord.init();
    try std.testing.expect(rec.validate());
    try std.testing.expectEqual(@as(u32, EVIDENCE_MAGIC), rec.magic);
    try std.testing.expectEqual(@as(u16, EVIDENCE_VERSION), rec.version);
}

test "EvidenceRecord size is 1024 bytes" {
    try std.testing.expectEqual(@as(usize, 1024), @sizeOf(EvidenceRecord));
}

test "EvidenceRecord finalize and verify integrity" {
    var rec = EvidenceRecord.init();
    rec.setHead("abc123");
    rec.setOs("windows-11");
    rec.setToolchain("zig-0.13.0");
    rec.setRuntimeVersion("5.0.0");
    rec.setTestProfile("unit");
    rec.setCommand("zig build test");
    rec.setExpected("all tests pass");
    rec.setActual("all tests pass");
    rec.setArtifactPath("zig-out/bin/aegis_nids.exe");

    // Before finalize, hash should be zero
    try std.testing.expect(!rec.verifyIntegrity());

    // Finalize computes the hash
    rec.finalize();
    try std.testing.expect(rec.verifyIntegrity());

    // Tamper detection
    rec.actual[0] ^= 0xFF;
    try std.testing.expect(!rec.verifyIntegrity());
}

test "EvidenceChain append and verify" {
    var chain = EvidenceChain.init(std.testing.allocator);
    defer chain.deinit();

    var rec1 = EvidenceRecord.init();
    rec1.setTestProfile("unit");
    rec1.setCommand("test 1");
    _ = try chain.append(rec1);

    var rec2 = EvidenceRecord.init();
    rec2.setTestProfile("unit");
    rec2.setCommand("test 2");
    _ = try chain.append(rec2);

    try std.testing.expectEqual(@as(usize, 2), chain.count());
    try std.testing.expect(chain.verifyChain());

    // Verify chain linkage
    const r1 = chain.get(0).?;
    const r2 = chain.get(1).?;
    try std.testing.expect(r1.hasPreviousHash() == false); // first record has zero previous
    try std.testing.expect(std.mem.eql(u8, &r2.previous_hash, &r1.current_hash));
}

test "EvidenceChain detects broken chain" {
    var chain = EvidenceChain.init(std.testing.allocator);
    defer chain.deinit();

    const rec1 = EvidenceRecord.init();
    _ = try chain.append(rec1);

    const rec2 = EvidenceRecord.init();
    _ = try chain.append(rec2);

    // Tamper with the chain by modifying a record's hash
    chain.records.items[0].current_hash[0] ^= 0xFF;
    try std.testing.expect(!chain.verifyChain());
}
