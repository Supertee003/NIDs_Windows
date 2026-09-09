// I20 - Forensic Record Pipeline
// AEGIS NIDS v5.0+ -- Pre-allocated ring buffer for evidence preservation
//
// The ring is a single mmap'd file (64 MiB by default). On Windows, this file
// is also marked with FILE_FLAG_DELETE_ON_CLOSE in "panic mode" so that
// tamper during incident response is detectable.
//
// Format (4KB-blocked):
//   [Header 64B] [Record 4KB][Record 4KB]...
// Each record:
//   [u32 magic] [u32 kind] [u64 ts_ns] [u32 ev_id] [u32 rule_id]
//   [u16 payload_len] [u16 reserved]
//   [u8[4032] payload]
//   [u32 crc]
//
// PATCH-33: Added hash chain (previous_hash, current_hash) for tamper detection.
// Each record's current_hash = SHA-256(content + previous_hash).

const std = @import("std");
const event = @import("../contract/event.zig");
const manifest = @import("../contract/runtime_manifest.zig");
const diag = @import("../core/diagnostics.zig");

pub const RING_BYTES: usize = manifest.Limits.FORENSIC_RING_BYTES;
pub const HEADER_BYTES: usize = 64;
pub const RECORD_BYTES: usize = 4096;
pub const HASH_BYTES: usize = 32; // SHA-256
pub const PAYLOAD_BYTES: usize = RECORD_BYTES - HEADER_BYTES - 16 - (2 * HASH_BYTES); // room for header + crc + hash chain (PATCH-33)

pub const RECORD_MAGIC: u32 = 0xF0F0FEED;

pub const RecordHeader = extern struct {
    magic: u32,
    kind: u32,
    ts_ns: i128,
    ev_id: u64,
    rule_id: u32,
    payload_len: u32,
    audit_id: u64, // PATCH-33: audit trail ID for provenance
    policy_id: u32, // PATCH-33: policy that triggered this record
    pep_decision: u8, // PATCH-33: PEP decision (allow/block/rate_limit/etc)
    severity: u8, // PATCH-33: event severity
    reserved: [7]u8,
};

pub const ForensicRing = struct {
    storage: []u8,
    head: u64 = 0, // write position
    tail: u64 = 0, // read position
    written: u64 = 0,
    overwritten: u64 = 0,
    mutex: std.Thread.Mutex = .{},
    in_memory: bool = true, // false when backed by mmap'd file

    // PATCH-33: hash chain for tamper detection
    hash_chain: [][HASH_BYTES]u8, // one hash per record slot
    last_hash: [HASH_BYTES]u8 = [_]u8{0} ** HASH_BYTES,

    pub fn initMemory(allocator: std.mem.Allocator, size: usize) !ForensicRing {
        const num_records = size / RECORD_BYTES;
        const hashes = try allocator.alloc([HASH_BYTES]u8, num_records);
        @memset(hashes, [_]u8{0} ** HASH_BYTES);
        return .{
            .storage = try allocator.alloc(u8, size),
            .hash_chain = hashes,
        };
    }

    pub fn deinit(self: *ForensicRing, allocator: std.mem.Allocator) void {
        allocator.free(self.hash_chain);
        allocator.free(self.storage);
    }

    pub fn capacity(self: *const ForensicRing) usize {
        return self.storage.len;
    }

    pub fn recordCount(self: *const ForensicRing) u64 {
        return self.written;
    }

    pub fn append(self: *ForensicRing, ev: *const event.IpcEvent, payload: []const u8, audit_id: u64, policy_id: u32, pep_decision: u8, severity: u8) !u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        const write_at = self.head % self.storage.len;
        if (write_at + RECORD_BYTES > self.storage.len) {
            // Wrap-around
            return self.appendWrapped(ev, payload, audit_id, policy_id, pep_decision, severity);
        }
        const slot = self.storage[write_at .. write_at + RECORD_BYTES];
        self.writeSlot(slot, ev, payload, audit_id, policy_id, pep_decision, severity);
        // PATCH-33: compute and store hash chain
        const slot_index = (write_at / RECORD_BYTES) % self.hash_chain.len;
        // Chain: current = SHA-256(content + previous_hash)
        var chain_input: [RECORD_BYTES + HASH_BYTES]u8 = undefined;
        @memcpy(chain_input[0..RECORD_BYTES], slot);
        @memcpy(chain_input[RECORD_BYTES..], &self.last_hash);
        var chain_hash: [HASH_BYTES]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&chain_input, &chain_hash, .{});
        self.hash_chain[slot_index] = chain_hash;
        self.last_hash = chain_hash;
        self.head += RECORD_BYTES;
        self.written += 1;
        if (self.head - self.tail > self.storage.len) {
            self.tail = self.head - self.storage.len;
            self.overwritten += 1;
        }
        return self.written;
    }

    fn appendWrapped(self: *ForensicRing, ev: *const event.IpcEvent, payload: []const u8, audit_id: u64, policy_id: u32, pep_decision: u8, severity: u8) !u64 {
        const at = self.head % self.storage.len;
        const first_chunk = self.storage.len - at;
        if (first_chunk > 0) {
            @memset(self.storage[at..], 0);
        }
        const slot = self.storage[0..RECORD_BYTES];
        self.writeSlot(slot, ev, payload, audit_id, policy_id, pep_decision, severity);
        // PATCH-33: compute and store hash chain (wrap-around)
        const slot_index = 0; // wrapped to beginning
        var chain_input: [RECORD_BYTES + HASH_BYTES]u8 = undefined;
        @memcpy(chain_input[0..RECORD_BYTES], slot);
        @memcpy(chain_input[RECORD_BYTES..], &self.last_hash);
        var chain_hash: [HASH_BYTES]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&chain_input, &chain_hash, .{});
        self.hash_chain[slot_index] = chain_hash;
        self.last_hash = chain_hash;
        self.head += RECORD_BYTES;
        self.written += 1;
        if (self.head - self.tail > self.storage.len) {
            self.tail = self.head - self.storage.len;
            self.overwritten += 1;
        }
        return self.written;
    }

    fn writeSlot(self: *ForensicRing, slot: []u8, ev: *const event.IpcEvent, payload: []const u8, audit_id: u64, policy_id: u32, pep_decision: u8, severity: u8) void {
        _ = self;
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
            .reserved = [_]u8{0} ** 7,
        };
        @memcpy(slot[0..@sizeOf(RecordHeader)], std.mem.asBytes(&hdr));
        const plen = hdr.payload_len;
        if (plen > 0) {
            @memcpy(slot[@sizeOf(RecordHeader) .. @sizeOf(RecordHeader) + plen], payload[0..plen]);
        }
        // CRC32 over the full record region
        var crc = std.hash.Crc32.init();
        crc.update(slot[0 .. RECORD_BYTES - 4]);
        const crc_val = crc.final();
        std.mem.writeInt(u32, slot[RECORD_BYTES - 4 ..][0..4], crc_val, .little);
    }

    pub fn readRecord(self: *ForensicRing, index: u64) ?[]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (index >= self.written) return null;
        // Calculate physical offset (record-aligned)
        const off = (index * RECORD_BYTES) % self.storage.len;
        if (off + RECORD_BYTES > self.storage.len) return null;
        return self.storage[off .. off + RECORD_BYTES];
    }

    pub fn verifyRecord(slot: []const u8) bool {
        if (slot.len < RECORD_BYTES) return false;
        var crc = std.hash.Crc32.init();
        crc.update(slot[0 .. RECORD_BYTES - 4]);
        const expected = std.mem.readInt(u32, slot[RECORD_BYTES - 4 ..][0..4], .little);
        return expected == crc.final();
    }

    /// PATCH-33: Verify the hash chain integrity across all written records.
    /// Returns true if the chain is unbroken.
    pub fn verifyHashChain(self: *const ForensicRing) bool {
        var prev_hash = [_]u8{0} ** HASH_BYTES;
        const num_records = @min(self.written, self.hash_chain.len);
        var i: usize = 0;
        while (i < num_records) : (i += 1) {
            // Compute expected chain hash: SHA-256(record_content + previous_hash)
            const off = (i * RECORD_BYTES) % self.storage.len;
            if (off + RECORD_BYTES > self.storage.len) return false;
            const slot = self.storage[off .. off + RECORD_BYTES];
            var chain_input: [RECORD_BYTES + HASH_BYTES]u8 = undefined;
            @memcpy(chain_input[0..RECORD_BYTES], slot);
            @memcpy(chain_input[RECORD_BYTES..], &prev_hash);
            var expected_hash: [HASH_BYTES]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(&chain_input, &expected_hash, .{});
            if (!std.mem.eql(u8, &expected_hash, &self.hash_chain[i])) {
                return false;
            }
            prev_hash = self.hash_chain[i];
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
    const rec = ring.readRecord(0).?;
    try std.testing.expect(ForensicRing.verifyRecord(rec));
}

test "ForensicRing wraps around" {
    var ring = try ForensicRing.initMemory(std.testing.allocator, 2 * RECORD_BYTES); // 2 records
    defer ring.deinit(std.testing.allocator);
    var ev = event.IpcEvent.init(.signature_match);
    ev.now();
    // Append 5 records â€” should overwrite older ones
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
    const rec = ring.readRecord(0).?;
    try std.testing.expect(ForensicRing.verifyRecord(rec));
    // Corrupt the record
    var mut_rec = std.heap.page_allocator.dupe(u8, rec) catch return error.OutOfMem;
    defer std.heap.page_allocator.free(mut_rec);
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
