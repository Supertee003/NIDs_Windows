//! Slicing-by-8 CRC-32/ISO-HDLC.
//!
//! `std.hash.Crc32` is a byte-at-a-time table lookup (~537 MB/s measured on the
//! reference host). A 4 KiB forensic record therefore spent more time in CRC
//! than in SHA-256: 7.60 us vs 2.53 us per record (QLOSS-CONSUMER-002).
//!
//! This module computes the SAME function - polynomial 0xEDB88320, refin=true,
//! refout=true, init 0xFFFFFFFF, xorout 0xFFFFFFFF - eight input bytes at a
//! time. It is a performance substitution only: every record it stamps is
//! byte-identical to what `std.hash.Crc32` would have produced, so the forensic
//! record format, the hash chain, the verifier and all stored vectors are
//! unchanged. `tests` below pins that equality against std as an oracle.

const std = @import("std");

const POLY: u32 = 0xEDB8_8320;

const tables: [8][256]u32 = blk: {
    @setEvalBranchQuota(200_000);
    var t: [8][256]u32 = undefined;
    for (0..256) |i| {
        var c: u32 = @intCast(i);
        for (0..8) |_| {
            c = if (c & 1 != 0) (c >> 1) ^ POLY else c >> 1;
        }
        t[0][i] = c;
    }
    for (1..8) |n| {
        for (0..256) |i| {
            const prev = t[n - 1][i];
            t[n][i] = (prev >> 8) ^ t[0][prev & 0xFF];
        }
    }
    break :blk t;
};

pub const Crc32 = struct {
    state: u32 = 0xFFFF_FFFF,

    pub fn init() Crc32 {
        return .{};
    }

    pub fn update(self: *Crc32, bytes: []const u8) void {
        var c = self.state;
        var i: usize = 0;
        while (i + 8 <= bytes.len) : (i += 8) {
            const lo = std.mem.readInt(u32, bytes[i..][0..4], .little) ^ c;
            const hi = std.mem.readInt(u32, bytes[i + 4 ..][0..4], .little);
            c = tables[7][lo & 0xFF] ^
                tables[6][(lo >> 8) & 0xFF] ^
                tables[5][(lo >> 16) & 0xFF] ^
                tables[4][(lo >> 24) & 0xFF] ^
                tables[3][hi & 0xFF] ^
                tables[2][(hi >> 8) & 0xFF] ^
                tables[1][(hi >> 16) & 0xFF] ^
                tables[0][(hi >> 24) & 0xFF];
        }
        while (i < bytes.len) : (i += 1) {
            c = (c >> 8) ^ tables[0][(c ^ bytes[i]) & 0xFF];
        }
        self.state = c;
    }

    pub fn final(self: Crc32) u32 {
        return self.state ^ 0xFFFF_FFFF;
    }

    /// One-shot helper.
    pub fn hash(bytes: []const u8) u32 {
        var c = Crc32.init();
        c.update(bytes);
        return c.final();
    }
};

const testing = std.testing;

fn expectMatchesStd(bytes: []const u8) !void {
    try testing.expectEqual(std.hash.Crc32.hash(bytes), Crc32.hash(bytes));
}

test "matches std for every length up to 64 bytes" {
    var buf: [64]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0xC0FF_EE00);
    prng.random().bytes(&buf);
    for (0..buf.len + 1) |n| {
        try expectMatchesStd(buf[0..n]);
    }
}

test "matches std for unaligned windows" {
    var buf: [512]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0x5EED_1234);
    prng.random().bytes(&buf);
    var off: usize = 0;
    while (off < 32) : (off += 1) {
        var len: usize = 0;
        while (off + len <= buf.len) : (len += 7) {
            try expectMatchesStd(buf[off .. off + len]);
        }
    }
}

test "matches std over a full 4 KiB forensic record" {
    const RECORD_BYTES = 4096;
    const buf = try testing.allocator.alloc(u8, RECORD_BYTES);
    defer testing.allocator.free(buf);
    var prng = std.Random.DefaultPrng.init(0xF0EE_5117);
    prng.random().bytes(buf);
    // CRC32 covers everything but the trailing 4-byte field.
    try expectMatchesStd(buf[0 .. RECORD_BYTES - 4]);
}

test "streamed updates match a single-shot over the same bytes" {
    var buf: [4092]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0xABCD_0123);
    prng.random().bytes(&buf);
    const want = std.hash.Crc32.hash(&buf);
    var split: usize = 0;
    while (split <= buf.len) : (split += 61) {
        var c = Crc32.init();
        c.update(buf[0..split]);
        c.update(buf[split..]);
        try testing.expectEqual(want, c.final());
    }
}

test "empty input equals std" {
    try expectMatchesStd(&[_]u8{});
}

test "known check vector stays ISO-HDLC" {
    // "123456789" -> CRC-32 (ISO-HDLC) check value.
    try testing.expectEqual(@as(u32, 0xCBF4_3926), Crc32.hash("123456789"));
}
