// I20 - Forensic Record Pipeline
// AEGIS NIDS v5.0+ â€” Pre-allocated ring buffer for evidence preservation
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

const std = @import("std");
const event = @import("../contract/event.zig");
const manifest = @import("../contract/runtime_manifest.zig");
const diag = @import("../core/diagnostics.zig");

pub const RING_BYTES: usize = manifest.Limits.FORENSIC_RING_BYTES;
pub const HEADER_BYTES: usize = 64;
pub const RECORD_BYTES: usize = 4096;
pub const PAYLOAD_BYTES: usize = RECORD_BYTES - HEADER_BYTES - 16; // room for header + crc + extra fields (PATCH-33)

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

    pub fn initMemory(allocator: std.mem.Allocator, size: usize) !ForensicRing {
        return .{ .storage = try allocator.alloc(u8, size) };
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

    pub fn append(self: *ForensicRing, ev: *const event.IpcEvent, payload: []const u8, audit_id: u64, policy_id: u32, pep_decision: u8, severity: u8) !u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        const write_at = self.head % self.storage.len;
        if (write_at + RECORD_BYTES > self.storage.len) {
            // Wrap-around
            return self.appendWrapped(ev, payload);
        }
        const slot = self.storage[write_at .. write_at + RECORD_BYTES];
        self.writeSlot(slot, ev, payload, audit_id, policy_id, pep_decision, severity);
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
    _ = try ring.append(&ev, payload);
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
        _ = try ring.append(&ev, "x");
    }
    try std.testing.expectEqual(@as(u64, 5), ring.recordCount());
    try std.testing.expectEqual(@as(u64, 3), ring.overwritten);
}

test "ForensicRing verify detects corruption" {
    var ring = try ForensicRing.initMemory(std.testing.allocator, 8 * 1024);
    defer ring.deinit(std.testing.allocator);
    var ev = event.IpcEvent.init(.anomaly_detected);
    ev.now();
    _ = try ring.append(&ev, "data");
    const rec = ring.readRecord(0).?;
    try std.testing.expect(ForensicRing.verifyRecord(rec));
    // Corrupt the record
    var mut_rec = std.heap.page_allocator.dupe(u8, rec) catch return error.OutOfMem;
    defer std.heap.page_allocator.free(mut_rec);
    mut_rec[0] ^= 0xFF;
    try std.testing.expect(!ForensicRing.verifyRecord(mut_rec));
}
