//! fim_dedup.zig — ADR-0012 measurement probe for FIM ingress volume.
//!
//! Measurement only: this module never suppresses, reorders or mutates an
//! event. It answers one question per poll batch — "how many of the
//! observations in this batch repeat a `(path, kind)` already seen in the
//! same batch?" — so the duplicate ratio that gates ADR-0012 can be read
//! from `queue.stats` instead of guessed.
//!
//! Identity is `Wyhash(kind, path_bytes)` plus the path length. A hash
//! collision would count a distinct path as a duplicate (over-count); with
//! 64-bit keys and batches bounded by the 64 KiB poll buffers the chance is
//! ~n^2/2^65 and it cannot under-count, so the measured ratio is an upper
//! bound on the duplicates coalescing could remove. That direction is the
//! safe one for a gate: it can never make coalescing look better than it is.
//!
//! A full table stops adding keys (and sets `overflowed`) rather than
//! evicting: an evicted key would re-count a repeat as distinct (under-count)
//! and lose exactly the fact being measured. Callers count overflow and
//! report it, so a truncated measurement is visible, never silent.

const std = @import("std");

pub const Entry = struct {
    hash: u64,
    kind: u32,
    len: u32,
};

pub const Probe = struct {
    entries: []Entry,
    count: usize = 0,
    /// Set when the table filled and further keys were not recorded. The
    /// caller must surface this: a full table under-reports duplicates.
    overflowed: bool = false,

    pub fn init(entries: []Entry) Probe {
        return .{ .entries = entries };
    }

    /// Start a new poll batch. The previous batch's keys are dropped.
    pub fn beginBatch(self: *Probe) void {
        self.count = 0;
    }

    /// Record one observation. Returns true when the same `(path, kind)` was
    /// already observed in this batch.
    pub fn observe(self: *Probe, path: []const u8, kind: u32) bool {
        if (self.entries.len == 0) {
            self.overflowed = true;
            return false;
        }
        const key: Entry = .{
            .hash = std.hash.Wyhash.hash(kind, path),
            .kind = kind,
            .len = @intCast(@min(path.len, std.math.maxInt(u32))),
        };
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            const seen = self.entries[i];
            if (seen.hash == key.hash and seen.kind == key.kind and seen.len == key.len) {
                return true;
            }
        }
        if (self.count >= self.entries.len) {
            self.overflowed = true;
            return false;
        }
        self.entries[self.count] = key;
        self.count += 1;
        return false;
    }
};

test "observe finds exact repeats and separates kinds and paths" {
    var store: [8]Entry = undefined;
    var probe = Probe.init(&store);
    probe.beginBatch();

    try std.testing.expect(!probe.observe("C:\\a\\x.tmp", 1));
    try std.testing.expect(!probe.observe("C:\\a\\y.tmp", 1));
    try std.testing.expect(probe.observe("C:\\a\\x.tmp", 1)); // same path+kind
    try std.testing.expect(!probe.observe("C:\\a\\x.tmp", 2)); // same path, other kind
    try std.testing.expect(probe.observe("C:\\a\\x.tmp", 1));
    try std.testing.expect(!probe.overflowed);
}

test "beginBatch resets identity between poll batches" {
    var store: [4]Entry = undefined;
    var probe = Probe.init(&store);

    probe.beginBatch();
    try std.testing.expect(!probe.observe("C:\\a\\x.tmp", 1));
    try std.testing.expect(probe.observe("C:\\a\\x.tmp", 1));

    probe.beginBatch();
    try std.testing.expect(!probe.observe("C:\\a\\x.tmp", 1));
}

test "a full table reports overflow instead of evicting keys" {
    var store: [2]Entry = undefined;
    var probe = Probe.init(&store);
    probe.beginBatch();

    try std.testing.expect(!probe.observe("C:\\a", 1));
    try std.testing.expect(!probe.observe("C:\\b", 1));
    try std.testing.expect(!probe.overflowed);
    // Third distinct key cannot be stored: not a duplicate, but visible.
    try std.testing.expect(!probe.observe("C:\\c", 1));
    try std.testing.expect(probe.overflowed);
    // Stored keys are still recognised: eviction would lose this.
    try std.testing.expect(probe.observe("C:\\a", 1));
}

test "an empty table is always overflow" {
    var probe = Probe.init(&[_]Entry{});
    probe.beginBatch();
    try std.testing.expect(!probe.observe("C:\\a", 1));
    try std.testing.expect(probe.overflowed);
}
