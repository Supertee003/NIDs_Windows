// I20 - Forensic Record Pipeline
// AEGIS NIDS v5.0+ -- Pre-allocated ring buffer for evidence preservation
//
// PATCH-33: Forensic Record Integrity
//   - Self-contained authenticated record format
//   - Each record contains: record_seq, prev_hash, current_hash
//   - Hash chain is embedded in each record (no separate hash_chain array)
//   - readRecord returns a snapshot copy (safe for concurrent readers)
//   - verifyHashChain correctly handles ring wrap via per-record hash verification
//
// Record layout (4KB-blocked):
//   [RecordHeader 144B] [payload up to 3948B] [padding] [u32 CRC32]
//
// Integrity model:
//   current_hash = SHA-256(record_slot[0..RECORD_BYTES-4] + prev_hash)
//   CRC32 covers record_slot[0..RECORD_BYTES-4]
//
// Concurrency model:
//   - All mutations hold mutex
//   - readRecord returns an allocated COPY (caller owns memory)
//   - verifyHashChain holds mutex for consistent snapshot
//
// Ring-wrap model:
//   - Each record is self-verifying: hash(content, stored_prev_hash) == stored_current_hash
//   - Chain linkage: record[i].prev_hash == record[i-1].current_hash
//   - Oldest retained record: prev_hash may be stale (previous record overwritten)
//     → verify per-record hash, skip linkage check for first retained record

const std = @import("std");
const event = @import("../contract/event.zig");
const manifest = @import("../contract/runtime_manifest.zig");

pub const RING_BYTES: usize = manifest.Limits.FORENSIC_RING_BYTES;
pub const RECORD_BYTES: usize = 4096;
pub const HASH_BYTES: usize = 32; // SHA-256
pub const RECORD_MAGIC: u32 = 0xF0F0FEED;

pub const RecordHeader = extern struct {
    magic: u32,
    kind: u32,
    ts_ns: i128,
    ev_id: u64,
    rule_id: u32,
    payload_len: u32,
    audit_id: u64,
    policy_id: u32,
    pep_decision: u8,
    severity: u8,
    record_seq: u64, // PATCH-33: monotonically increasing sequence
    prev_hash: [HASH_BYTES]u8, // PATCH-33: hash of previous record
    current_hash: [HASH_BYTES]u8, // PATCH-33: hash of this record
    reserved: [7]u8,
};

pub const HEADER_BYTES: usize = @sizeOf(RecordHeader);
pub const PAYLOAD_BYTES: usize = RECORD_BYTES - HEADER_BYTES - 4; // 4 for CRC

pub const ForensicRing = struct {
    storage: []u8,
    head: u64 = 0,
    tail: u64 = 0,
    written: u64 = 0,
    overwritten: u64 = 0,
    mutex: std.Thread.Mutex = .{},
    in_memory: bool = true,
    next_seq: u64 = 0, // PATCH-33: next sequence number
    last_hash: [HASH_BYTES]u8 = [_]u8{0} ** HASH_BYTES, // PATCH-33: hash of most recent record

    pub fn initMemory(allocator: std.mem.Allocator, size: usize) !ForensicRing {
        return .{
            .storage = try allocator.alloc(u8, size),
        };
    }

    pub fn deinit(self: *ForensicRing, allocator: std.mem.Allocator) void {
        allocator.free(self.storage);
    }

    pub fn capacity(self: *const ForensicRing) usize {
        return self.storage.len;
    }

    pub fn recordCount(self: *const ForensicRing) u64 {
        return self.written;
    }

    pub fn append(
        self: *ForensicRing,
        ev: *const event.IpcEvent,
        payload: []const u8,
        audit_id: u64,
        policy_id: u32,
        pep_decision: u8,
        severity: u8,
    ) !u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        const write_at = self.head % self.storage.len;
        if (write_at + RECORD_BYTES > self.storage.len) {
            return self.appendWrapped(ev, payload, audit_id, policy_id, pep_decision, severity);
        }
        const slot = self.storage[write_at .. write_at + RECORD_BYTES];
        // Step 1: Write header + payload (CRC computed AFTER hash embedding)
        self.writeSlot(slot, ev, payload, audit_id, policy_id, pep_decision, severity);
        // Step 2: Compute hash over (slot excluding current_hash + CRC) + last_hash
        const record_hash = self.computeRecordHash(slot, &self.last_hash);
        // Step 3: Embed hash into record's current_hash field
        self.embedCurrentHash(slot, record_hash);
        // Step 4: Compute CRC32 over the FINAL record (with hash embedded)
        self.writeCrc(slot);
        self.last_hash = record_hash;
        self.next_seq += 1;
        self.head += RECORD_BYTES;
        self.written += 1;
        if (self.head - self.tail > self.storage.len) {
            self.tail = self.head - self.storage.len;
            self.overwritten += 1;
        }
        return self.written;
    }

    fn appendWrapped(
        self: *ForensicRing,
        ev: *const event.IpcEvent,
        payload: []const u8,
        audit_id: u64,
        policy_id: u32,
        pep_decision: u8,
        severity: u8,
    ) !u64 {
        const at = self.head % self.storage.len;
        const first_chunk = self.storage.len - at;
        if (first_chunk > 0) {
            @memset(self.storage[at..], 0);
        }
        const slot = self.storage[0..RECORD_BYTES];
        // Step 1: Write header + payload
        self.writeSlot(slot, ev, payload, audit_id, policy_id, pep_decision, severity);
        // Step 2: Compute hash
        const record_hash = self.computeRecordHash(slot, &self.last_hash);
        // Step 3: Embed hash
        self.embedCurrentHash(slot, record_hash);
        // Step 4: Compute CRC
        self.writeCrc(slot);
        self.last_hash = record_hash;
        self.next_seq += 1;
        self.head += RECORD_BYTES;
        self.written += 1;
        if (self.head - self.tail > self.storage.len) {
            self.tail = self.head - self.storage.len;
            self.overwritten += 1;
        }
        return self.written;
    }

    fn writeSlot(
        self: *ForensicRing,
        slot: []u8,
        ev: *const event.IpcEvent,
        payload: []const u8,
        audit_id: u64,
        policy_id: u32,
        pep_decision: u8,
        severity: u8,
    ) void {
        @memset(slot, 0);
        var hdr = RecordHeader{
            .magic = RECORD_MAGIC,
            .kind = @intFromEnum(ev.kind),
            .ts_ns = @intCast(ev.timestamp_ns),
            .ev_id = ev.event_id,
            .rule_id = ev.rule_id,
            .payload_len = @intCast(@min(payload.len, PAYLOAD_BYTES)),
            .audit_id = audit_id,
            .policy_id = policy_id,
            .pep_decision = pep_decision,
            .severity = severity,
            .record_seq = self.next_seq,
            .prev_hash = self.last_hash,
            .current_hash = [_]u8{0} ** HASH_BYTES, // filled after hash computation
            .reserved = [_]u8{0} ** 7,
        };
        @memcpy(slot[0..@sizeOf(RecordHeader)], std.mem.asBytes(&hdr));
        const plen = hdr.payload_len;
        if (plen > 0) {
            @memcpy(slot[@sizeOf(RecordHeader) .. @sizeOf(RecordHeader) + plen], payload[0..plen]);
        }
        // NOTE: CRC is computed AFTER hash embedding (see append/appendWrapped)
    }

    /// PATCH-33: Compute CRC32 over slot[0..RECORD_BYTES-4] and write at the end.
    /// Must be called AFTER embedCurrentHash so CRC covers the final record content.
    fn writeCrc(self: *ForensicRing, slot: []u8) void {
        _ = self;
        var crc = std.hash.Crc32.init();
        crc.update(slot[0 .. RECORD_BYTES - 4]);
        const crc_val = crc.final();
        std.mem.writeInt(u32, slot[RECORD_BYTES - 4 ..][0..4], crc_val, .little);
    }

    /// PATCH-33: Compute SHA-256 hash of a record slot.
    /// Hash covers: everything except current_hash field and CRC, plus prev_hash.
    /// This is deterministic: same computation during write and verify.
    fn computeRecordHash(self: *ForensicRing, slot: []const u8, prev_hash: *const [HASH_BYTES]u8) [HASH_BYTES]u8 {
        _ = self;
        const ch_offset = @offsetOf(RecordHeader, "current_hash");
        const after_ch = ch_offset + HASH_BYTES;
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        // Part 1: everything before current_hash field
        if (ch_offset > 0) {
            hasher.update(slot[0..ch_offset]);
        }
        // Part 2: everything after current_hash field (up to CRC)
        if (after_ch < RECORD_BYTES - 4) {
            hasher.update(slot[after_ch .. RECORD_BYTES - 4]);
        }
        // Part 3: previous record's hash
        hasher.update(prev_hash);
        var hash: [HASH_BYTES]u8 = undefined;
        hasher.final(&hash);
        return hash;
    }

    /// PATCH-33: Write the computed hash into the record's current_hash field.
    fn embedCurrentHash(self: *ForensicRing, slot: []u8, hash: [HASH_BYTES]u8) void {
        _ = self;
        const hdr = std.mem.bytesAsValue(RecordHeader, slot[0..@sizeOf(RecordHeader)]);
        hdr.current_hash = hash;
    }

    /// PATCH-33: Read a record as a snapshot copy. Caller owns the returned memory.
    /// Returns null if index is out of range or record spans a wrap boundary.
    pub fn readRecord(self: *ForensicRing, index: u64, allocator: std.mem.Allocator) ?[]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (index >= self.written) return null;
        const off = (index * RECORD_BYTES) % self.storage.len;
        if (off + RECORD_BYTES > self.storage.len) return null;
        // Return a COPY — safe for concurrent readers
        return allocator.dupe(u8, self.storage[off .. off + RECORD_BYTES]) catch null;
    }

    /// Verify CRC32 of a record slot.
    pub fn verifyRecord(slot: []const u8) bool {
        if (slot.len < RECORD_BYTES) return false;
        var crc = std.hash.Crc32.init();
        crc.update(slot[0 .. RECORD_BYTES - 4]);
        const expected = std.mem.readInt(u32, slot[RECORD_BYTES - 4 ..][0..4], .little);
        return expected == crc.final();
    }

    /// PATCH-33: Verify per-record hash integrity.
    /// Recomputes hash using the same logic as computeRecordHash.
    pub fn verifyRecordHash(slot: []const u8) bool {
        if (slot.len < @sizeOf(RecordHeader)) return false;
        const hdr = std.mem.bytesAsValue(RecordHeader, slot[0..@sizeOf(RecordHeader)]);
        if (hdr.magic != RECORD_MAGIC) return false;
        // Recompute: hash(excluding current_hash and CRC) + prev_hash
        const ch_offset = @offsetOf(RecordHeader, "current_hash");
        const after_ch = ch_offset + HASH_BYTES;
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        if (ch_offset > 0) {
            hasher.update(slot[0..ch_offset]);
        }
        if (after_ch < RECORD_BYTES - 4) {
            hasher.update(slot[after_ch .. RECORD_BYTES - 4]);
        }
        hasher.update(&hdr.prev_hash);
        var computed: [HASH_BYTES]u8 = undefined;
        hasher.final(&computed);
        return std.mem.eql(u8, &hdr.current_hash, &computed);
    }

    /// PATCH-33: Verify the hash chain across all retained records.
    /// For each record: verifies CRC + per-record hash integrity.
    /// For consecutive records: verifies chain linkage (prev_hash == previous current_hash).
    /// The first retained record's prev_hash may be stale (previous record overwritten) —
    /// linkage check is skipped for it, but per-record hash is still verified.
    pub fn verifyHashChain(self: *ForensicRing) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.written == 0) return true;
        const num_slots = self.storage.len / RECORD_BYTES;
        const oldest: u64 = if (self.written > num_slots) self.written - num_slots else 0;
        var prev_current_hash: [HASH_BYTES]u8 = [_]u8{0} ** HASH_BYTES;
        var i = oldest;
        while (i < self.written) : (i += 1) {
            const off = (i * RECORD_BYTES) % self.storage.len;
            if (off + RECORD_BYTES > self.storage.len) return false;
            const slot = self.storage[off .. off + RECORD_BYTES];
            // 1. Verify CRC
            if (!ForensicRing.verifyRecord(slot)) return false;
            // 2. Verify per-record hash integrity
            if (!ForensicRing.verifyRecordHash(slot)) return false;
            // 3. Chain linkage (skip for first retained record)
            if (i > oldest) {
                const hdr = std.mem.bytesAsValue(RecordHeader, slot[0..@sizeOf(RecordHeader)]);
                if (!std.mem.eql(u8, &hdr.prev_hash, &prev_current_hash)) return false;
            }
            const hdr = std.mem.bytesAsValue(RecordHeader, slot[0..@sizeOf(RecordHeader)]);
            prev_current_hash = hdr.current_hash;
        }
        return true;
    }

    /// PATCH-33: Get the last hash in the chain (for linking new records).
    pub fn getLastHash(self: *const ForensicRing) [HASH_BYTES]u8 {
        return self.last_hash;
    }
};

// ============================================================================
// Tests
// ============================================================================
test "ForensicRing append and read" {
    var ring = try ForensicRing.initMemory(std.testing.allocator, 16 * 1024);
    defer ring.deinit(std.testing.allocator);
    var ev = event.IpcEvent.init(.signature_match);
    ev.now();
    ev.event_id = 1;
    const payload = "some attack payload";
    _ = try ring.append(&ev, payload, 0, 0, 0, 0);
    try std.testing.expectEqual(@as(u64, 1), ring.recordCount());
    const rec = ring.readRecord(0, std.testing.allocator) orelse return error.OutOfMemory;
    defer std.testing.allocator.free(rec);
    try std.testing.expect(ForensicRing.verifyRecord(rec));
    try std.testing.expect(ForensicRing.verifyRecordHash(rec));
}

test "ForensicRing wraps around" {
    var ring = try ForensicRing.initMemory(std.testing.allocator, 2 * RECORD_BYTES);
    defer ring.deinit(std.testing.allocator);
    var ev = event.IpcEvent.init(.signature_match);
    ev.now();
    var i: u32 = 0;
    while (i < 5) : (i += 1) {
        ev.event_id = i;
        _ = try ring.append(&ev, "x", 0, 0, 0, 0);
    }
    try std.testing.expectEqual(@as(u64, 5), ring.recordCount());
    try std.testing.expectEqual(@as(u64, 3), ring.overwritten);
}

test "ForensicRing verify detects corruption" {
    var ring = try ForensicRing.initMemory(std.testing.allocator, 8 * 1024);
    defer ring.deinit(std.testing.allocator);
    var ev = event.IpcEvent.init(.anomaly_detected);
    ev.now();
    _ = try ring.append(&ev, "data", 0, 0, 0, 0);
    const rec = ring.readRecord(0, std.testing.allocator) orelse return error.OutOfMemory;
    defer std.testing.allocator.free(rec);
    try std.testing.expect(ForensicRing.verifyRecord(rec));
    // Corrupt the record
    var mut_rec = try std.testing.allocator.dupe(u8, rec);
    defer std.testing.allocator.free(mut_rec);
    mut_rec[0] ^= 0xFF;
    try std.testing.expect(!ForensicRing.verifyRecord(mut_rec));
}

// PATCH-33: Hash chain tests
test "ForensicRing hash chain valid after append" {
    var ring = try ForensicRing.initMemory(std.testing.allocator, 8 * 1024);
    defer ring.deinit(std.testing.allocator);
    var ev = event.IpcEvent.init(.signature_match);
    ev.now();
    _ = try ring.append(&ev, "payload1", 0, 0, 0, 0);
    _ = try ring.append(&ev, "payload2", 0, 0, 0, 0);
    try std.testing.expect(ring.verifyHashChain());
}

test "ForensicRing hash chain detects tampered record" {
    var ring = try ForensicRing.initMemory(std.testing.allocator, 8 * 1024);
    defer ring.deinit(std.testing.allocator);
    var ev = event.IpcEvent.init(.signature_match);
    ev.now();
    _ = try ring.append(&ev, "data", 0, 0, 0, 0);
    // Tamper with the stored record content
    ring.storage[0] ^= 0xFF;
    // Hash chain should detect the tamper
    try std.testing.expect(!ring.verifyHashChain());
}

test "ForensicRing hash chain links records" {
    var ring = try ForensicRing.initMemory(std.testing.allocator, 8 * 1024);
    defer ring.deinit(std.testing.allocator);
    var ev = event.IpcEvent.init(.signature_match);
    ev.now();
    _ = try ring.append(&ev, "first", 0, 0, 0, 0);
    const hash1 = ring.getLastHash();
    _ = try ring.append(&ev, "second", 0, 0, 0, 0);
    const hash2 = ring.getLastHash();
    // Hashes should be different (chained)
    try std.testing.expect(!std.mem.eql(u8, &hash1, &hash2));
    // Chain should be valid
    try std.testing.expect(ring.verifyHashChain());
}

test "ForensicRing hash chain survives wrap" {
    var ring = try ForensicRing.initMemory(std.testing.allocator, 2 * RECORD_BYTES);
    defer ring.deinit(std.testing.allocator);
    var ev = event.IpcEvent.init(.signature_match);
    ev.now();
    // Append 4 records — forces wrap
    var i: u32 = 0;
    while (i < 4) : (i += 1) {
        ev.event_id = i;
        _ = try ring.append(&ev, "wrap", 0, 0, 0, 0);
    }
    try std.testing.expectEqual(@as(u64, 4), ring.recordCount());
    try std.testing.expectEqual(@as(u64, 2), ring.overwritten);
    // Chain should still be valid for retained records
    try std.testing.expect(ring.verifyHashChain());
}

test "ForensicRing readRecord returns independent copy" {
    var ring = try ForensicRing.initMemory(std.testing.allocator, 8 * 1024);
    defer ring.deinit(std.testing.allocator);
    var ev = event.IpcEvent.init(.signature_match);
    ev.now();
    _ = try ring.append(&ev, "original", 0, 0, 0, 0);
    const rec1 = ring.readRecord(0, std.testing.allocator) orelse return error.OutOfMemory;
    defer std.testing.allocator.free(rec1);
    // Append more data — should not affect the snapshot
    ev.event_id = 99;
    _ = try ring.append(&ev, "newdata", 0, 0, 0, 0);
    // rec1 should still be valid
    try std.testing.expect(ForensicRing.verifyRecord(rec1));
    try std.testing.expect(ForensicRing.verifyRecordHash(rec1));
}

test "ForensicRing record_seq increments" {
    var ring = try ForensicRing.initMemory(std.testing.allocator, 8 * RECORD_BYTES);
    defer ring.deinit(std.testing.allocator);
    var ev = event.IpcEvent.init(.signature_match);
    ev.now();
    _ = try ring.append(&ev, "a", 0, 0, 0, 0);
    _ = try ring.append(&ev, "b", 0, 0, 0, 0);
    _ = try ring.append(&ev, "c", 0, 0, 0, 0);
    // Verify sequence numbers are 0, 1, 2
    const rec0 = ring.readRecord(0, std.testing.allocator) orelse return error.OutOfMemory;
    defer std.testing.allocator.free(rec0);
    const hdr0 = std.mem.bytesAsValue(RecordHeader, rec0[0..@sizeOf(RecordHeader)]);
    try std.testing.expectEqual(@as(u64, 0), hdr0.record_seq);

    const rec1 = ring.readRecord(1, std.testing.allocator) orelse return error.OutOfMemory;
    defer std.testing.allocator.free(rec1);
    const hdr1 = std.mem.bytesAsValue(RecordHeader, rec1[0..@sizeOf(RecordHeader)]);
    try std.testing.expectEqual(@as(u64, 1), hdr1.record_seq);

    const rec2 = ring.readRecord(2, std.testing.allocator) orelse return error.OutOfMemory;
    defer std.testing.allocator.free(rec2);
    const hdr2 = std.mem.bytesAsValue(RecordHeader, rec2[0..@sizeOf(RecordHeader)]);
    try std.testing.expectEqual(@as(u64, 2), hdr2.record_seq);
}
