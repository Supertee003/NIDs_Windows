//! fim_dedup.zig â€” ADR-0012 measurement probe for FIM ingress volume.
//!
//! Measurement only: this module never suppresses, reorders or mutates an
//! event. It answers one question per poll batch â€” "how many of the
//! observations in this batch repeat a `(path, kind)` already seen in the
//! same batch?" â€” so the duplicate ratio that gates ADR-0012 can be read
//! from `queue.stats` instead of guessed.
//!
//! Identity is `Wyhash(kind, path_bytes)` plus the path length. A hash
//! collision would count a distinct path as a duplicate (over-count); with
//! 64-bit keys and batches bounded by the ingress buffers (256 KiB
//! minifilter pull, 64 KiB poll) the chance is ~n^2/2^65 and it cannot
//! under-count, so the measured ratio is an upper bound on the duplicates
//! coalescing could remove. That direction is the safe one for a gate: it can
//! never make coalescing look better than it is.
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
    /// Observed process id, or 0 when the caller has no pid (the
    /// ReadDirectoryChangesW poll path). Part of the identity, so two probes
    /// can answer the two different questions ADR-0012 has to separate:
    /// "how many repeats share path+kind" (pid = 0, the raw redundancy) and
    /// "how many repeats share path+kind+process" (what a coalescer that
    /// preserves attribution could actually remove).
    pid: u32,
    /// Kernel event timestamp (100 ns FILETIME). Two records for the same
    /// callback carry the same timestamp; two distinct opens do not. Used by
    /// the third probe to tell a duplicate delivery apart from a genuine
    /// repeat open.
    ts: i64,
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

    /// Start a new poll batch. The previous batch's keys are dropped, and the
    /// overflow flag is cleared: it describes this batch, not the probe's
    /// lifetime. Leaving it set would report every later batch as truncated
    /// and make the contract that "stats measure what they name" false.
    pub fn beginBatch(self: *Probe) void {
        self.count = 0;
        self.overflowed = false;
    }

    /// Record one observation. Returns true when the same key was already
    /// observed in this batch.
    pub fn observe(self: *Probe, path: []const u8, kind: u32, pid: u32, ts: i64) bool {
        if (self.entries.len == 0) {
            self.overflowed = true;
            return false;
        }
        const key: Entry = .{
            .hash = std.hash.Wyhash.hash(kind, path),
            .kind = kind,
            .len = @intCast(@min(path.len, std.math.maxInt(u32))),
            .pid = pid,
            .ts = ts,
        };
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            const seen = self.entries[i];
            if (seen.hash == key.hash and seen.kind == key.kind and
                seen.len == key.len and seen.pid == key.pid and seen.ts == key.ts)
            {
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

    try std.testing.expect(!probe.observe("C:\\a\\x.tmp", 1, 0, 0));
    try std.testing.expect(!probe.observe("C:\\a\\y.tmp", 1, 0, 0));
    try std.testing.expect(probe.observe("C:\\a\\x.tmp", 1, 0, 0)); // same path+kind
    try std.testing.expect(!probe.observe("C:\\a\\x.tmp", 2, 0, 0)); // same path, other kind
    try std.testing.expect(probe.observe("C:\\a\\x.tmp", 1, 0, 0));
    try std.testing.expect(!probe.overflowed);
}

test "pid is part of the identity only when the caller supplies one" {
    var store: [8]Entry = undefined;

    // Raw redundancy (what the minifilter loop records for the aggregate
    // probe): pid is passed as 0, so the same path opened twice by two
    // processes is one duplicate.
    var raw = Probe.init(&store);
    raw.beginBatch();
    try std.testing.expect(!raw.observe("C:\\a\\x.tmp", 1, 0, 0));
    try std.testing.expect(raw.observe("C:\\a\\x.tmp", 1, 0, 0));

    // Attribution-preserving redundancy (the second probe): the same two
    // observations are distinct, so coalescing that keeps process identity
    // would remove nothing here.
    var per_pid = Probe.init(&store);
    per_pid.beginBatch();
    try std.testing.expect(!per_pid.observe("C:\\a\\x.tmp", 1, 100, 0));
    try std.testing.expect(!per_pid.observe("C:\\a\\x.tmp", 1, 200, 0));
    try std.testing.expect(per_pid.observe("C:\\a\\x.tmp", 1, 100, 0));
}

test "timestamp separates one callback reported twice from two opens" {
    var store: [8]Entry = undefined;
    var probe = Probe.init(&store);
    probe.beginBatch();

    // Same path, same process, different kernel timestamps: two separate
    // opens. Not a duplicate under the timestamp-bearing identity.
    try std.testing.expect(!probe.observe("C:\\a\\x.tmp", 1, 100, 1000));
    try std.testing.expect(!probe.observe("C:\\a\\x.tmp", 1, 100, 2000));
    // Same timestamp: the identical record seen twice.
    try std.testing.expect(probe.observe("C:\\a\\x.tmp", 1, 100, 1000));
}

test "beginBatch resets identity between poll batches" {
    var store: [4]Entry = undefined;
    var probe = Probe.init(&store);

    probe.beginBatch();
    try std.testing.expect(!probe.observe("C:\\a\\x.tmp", 1, 0, 0));
    try std.testing.expect(probe.observe("C:\\a\\x.tmp", 1, 0, 0));

    probe.beginBatch();
    try std.testing.expect(!probe.observe("C:\\a\\x.tmp", 1, 0, 0));
}

test "a full table reports overflow instead of evicting keys" {
    var store: [2]Entry = undefined;
    var probe = Probe.init(&store);
    probe.beginBatch();

    try std.testing.expect(!probe.observe("C:\\a", 1, 0, 0));
    try std.testing.expect(!probe.observe("C:\\b", 1, 0, 0));
    try std.testing.expect(!probe.overflowed);
    // Third distinct key cannot be stored: not a duplicate, but visible.
    try std.testing.expect(!probe.observe("C:\\c", 1, 0, 0));
    try std.testing.expect(probe.overflowed);
    // Stored keys are still recognised: eviction would lose this.
    try std.testing.expect(probe.observe("C:\\a", 1, 0, 0));
}

test "beginBatch clears the overflow flag so it describes one batch" {
    var store: [2]Entry = undefined;
    var probe = Probe.init(&store);

    probe.beginBatch();
    try std.testing.expect(!probe.observe("C:\\a", 1, 0, 0));
    try std.testing.expect(!probe.observe("C:\\b", 1, 0, 0));
    try std.testing.expect(!probe.observe("C:\\c", 1, 0, 0));
    try std.testing.expect(probe.overflowed);

    // A later, small batch is NOT truncated; reporting it as such would make
    // the overflow counter meaningless.
    probe.beginBatch();
    try std.testing.expect(!probe.overflowed);
    try std.testing.expect(!probe.observe("C:\\a", 1, 0, 0));
    try std.testing.expect(!probe.overflowed);
}

test "an empty table is always overflow" {
    var probe = Probe.init(&[_]Entry{});
    probe.beginBatch();
    try std.testing.expect(!probe.observe("C:\\a", 1, 0, 0));
    try std.testing.expect(probe.overflowed);
}
