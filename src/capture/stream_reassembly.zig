// I10 - TCP Stream Reassembly
// AEGIS NIDS v5.0+ â€” Per-flow bidirectional TCP stream reassembly
//
// Strategy:
//   - Track sequence numbers per direction (Aâ†’B and Bâ†’A)
//   - Buffer out-of-order segments in a small ordered list (max 8 per flow)
//   - Drop segments older than the current expected seq
//   - Cap memory per flow at 1 MiB to prevent resource exhaustion

const std = @import("std");

pub const MAX_SEGMENTS_PER_FLOW: usize = 8;
pub const MAX_STREAM_BYTES: usize = 1 << 20; // 1 MiB

pub const Direction = enum(u8) {
    a_to_b = 0,
    b_to_a = 1,
};

pub const Segment = struct {
    seq: u32,
    data: []const u8, // borrowed from caller's buffer (or copied into arena)
    pushed: bool = false,
};

pub const StreamDirection = struct {
    next_seq: u32 = 0,
    isn_set: bool = false,
    segments: [MAX_SEGMENTS_PER_FLOW]Segment = [_]Segment{.{ .seq = 0, .data = "" }} ** MAX_SEGMENTS_PER_FLOW,
    seg_count: usize = 0,
    bytes_emitted: u64 = 0,
    bytes_buffered: u64 = 0,

    pub fn init(self: *StreamDirection, isn: u32) void {
        self.next_seq = isn +% 1; // SYN consumes 1 sequence number
        self.isn_set = true;
        self.seg_count = 0;
        self.bytes_emitted = 0;
        self.bytes_buffered = 0;
    }

    pub fn ingest(self: *StreamDirection, seq: u32, data: []const u8) ?[]const u8 {
        if (!self.isn_set) return null;
        if (data.len == 0) return null;

        // Drop segments entirely behind current window
        const end_seq = seq +% @as(u32, @intCast(data.len));
        _ = end_seq;
        const dist_behind = self.next_seq -% seq;
        if (dist_behind != 0 and dist_behind < 0x80000000) {
            // seq is behind next_seq; skip already-received prefix
            if (dist_behind >= data.len) {
                // entirely duplicate
                return null;
            }
            const offset: u32 = @intCast(data.len - dist_behind);
            const new_seq = seq +% @as(u32, @intCast(data.len - offset));
            return self.ingestInOrder(new_seq, data[offset..]);
        }
        return self.ingestInOrder(seq, data);
    }

    fn ingestInOrder(self: *StreamDirection, seq: u32, data: []const u8) ?[]const u8 {
        // If seq matches next_seq, emit immediately, then check queued segments
        if (seq == self.next_seq) {
            self.next_seq = seq +% @as(u32, @intCast(data.len));
            self.bytes_emitted += data.len;
            // Try to flush queued segments
            self.flushQueued();
            return data;
        }
        // Otherwise queue (if there's room and not too far ahead)
        if (self.seg_count >= MAX_SEGMENTS_PER_FLOW) return null;
        if (self.bytes_buffered + data.len > MAX_STREAM_BYTES) return null;
        // Insert sorted by seq
        var i: usize = self.seg_count;
        while (i > 0 and self.segments[i - 1].seq > seq) : (i -= 1) {
            self.segments[i] = self.segments[i - 1];
        }
        self.segments[i] = .{ .seq = seq, .data = data };
        self.seg_count += 1;
        self.bytes_buffered += data.len;
        return null;
    }

    fn flushQueued(self: *StreamDirection) void {
        while (self.seg_count > 0 and self.segments[0].seq == self.next_seq) {
            const seg = self.segments[0];
            self.next_seq = seg.seq +% @as(u32, @intCast(seg.data.len));
            self.bytes_emitted += seg.data.len;
            self.bytes_buffered -= seg.data.len;
            // Shift the rest
            var i: usize = 1;
            while (i < self.seg_count) : (i += 1) {
                self.segments[i - 1] = self.segments[i];
            }
            self.seg_count -= 1;
        }
    }
};

pub const TcpStream = struct {
    dir_a: StreamDirection = .{},
    dir_b: StreamDirection = .{},
    fin_seen: bool = false,
    rst_seen: bool = false,
    bytes_total: u64 = 0,

    pub fn onSyn(self: *TcpStream, dir: Direction, isn: u32) void {
        switch (dir) {
            .a_to_b => self.dir_a.init(isn),
            .b_to_a => self.dir_b.init(isn),
        }
    }

    pub fn onData(self: *TcpStream, dir: Direction, seq: u32, data: []const u8) ?[]const u8 {
        if (data.len == 0) return null;
        const d = switch (dir) {
            .a_to_b => &self.dir_a,
            .b_to_a => &self.dir_b,
        };
        if (d.ingest(seq, data)) |emitted| {
            self.bytes_total += emitted.len;
            return emitted;
        }
        return null;
    }

    pub fn onFin(self: *TcpStream, _: Direction) void {
        self.fin_seen = true;
    }

    pub fn onRst(self: *TcpStream, _: Direction) void {
        self.rst_seen = true;
    }

    pub fn isComplete(self: *const TcpStream) bool {
        return self.fin_seen or self.rst_seen;
    }
};

// ============================================================================
// Tests
// ============================================================================
test "StreamDirection in-order ingest" {
    var sd = StreamDirection{};
    sd.init(1000); // next_seq = 1001
    const out1 = sd.ingest(1001, "hello").?;
    try std.testing.expectEqualStrings("hello", out1);
    try std.testing.expectEqual(@as(u64, 5), sd.bytes_emitted);
    const out2 = sd.ingest(1006, " world").?;
    try std.testing.expectEqualStrings(" world", out2);
    try std.testing.expectEqual(@as(u64, 11), sd.bytes_emitted);
}

test "StreamDirection out-of-order" {
    var sd = StreamDirection{};
    sd.init(2000); // next_seq = 2001
    // First segment arrives (2001..2005)
    const out1 = sd.ingest(2001, "ABCD").?;
    try std.testing.expectEqualStrings("ABCD", out1);
    // Third segment arrives (2008..2010) â€” should be queued
    const out2 = sd.ingest(2008, "GH");
    try std.testing.expect(out2 == null);
    try std.testing.expectEqual(@as(usize, 1), sd.seg_count);
    // Second segment arrives (2005..2008) â€” should be emitted, then queued GH flushed
    const out3 = sd.ingest(2005, "EFG").?;
    try std.testing.expectEqualStrings("EFG", out3);
    try std.testing.expectEqual(@as(usize, 0), sd.seg_count);
    try std.testing.expectEqual(@as(u32, 2010), sd.next_seq);
}

test "StreamDirection duplicate prefix skipped" {
    var sd = StreamDirection{};
    sd.init(3000); // next_seq = 3001
    _ = sd.ingest(3001, "ABCDE");
    // Re-send of first 3 bytes â€” should be dropped entirely
    const out = sd.ingest(3001, "ABC");
    try std.testing.expect(out == null);
}

test "TcpStream bidirectional" {
    var s = TcpStream{};
    s.onSyn(.a_to_b, 1000); // ISN_A = 1000
    s.onSyn(.b_to_a, 2000); // ISN_B = 2000
    const r1 = s.onData(.a_to_b, 1001, "GET / HTTP/1.0\r\n").?;
    try std.testing.expectEqualStrings("GET / HTTP/1.0\r\n", r1);
    const r2 = s.onData(.b_to_a, 2001, "HTTP/1.0 200 OK\r\n").?;
    try std.testing.expectEqualStrings("HTTP/1.0 200 OK\r\n", r2);
    try std.testing.expect(!s.isComplete());
    s.onFin(.a_to_b);
    s.onFin(.b_to_a);
    try std.testing.expect(s.isComplete());
}
