//! Control-plane v2 freshness and replay guard.
//!
//! The active control pipe authenticates the caller with an impersonated
//! Windows token (see platform/win32_pipe.zig). That authenticates WHO calls,
//! but a captured JSON request can still be replayed verbatim. This module
//! closes that gap with two checks on every v2 envelope:
//!
//!   * freshness: |now_ms - issued_at_ms| <= max_skew_ms
//!   * single use: the 16-byte nonce must not have been accepted before
//!
//! State is a bounded ring, so it has a fixed memory ceiling and deterministic
//! eviction. It is process-local: a daemon restart resets it, which is stated
//! in the protocol contract. No key material is involved -- an HMAC would add
//! a key-distribution fiction on a pipe already gated by token identity.

const std = @import("std");

/// Maximum accepted clock skew in either direction.
pub const MAX_SKEW_MS: i64 = 60_000;
/// Upper bound on remembered nonces (fixed memory, deterministic eviction).
pub const CAPACITY: usize = 1024;

pub const Verdict = enum {
    ok,
    invalid_nonce,
    stale,
    replay,
};

const Entry = struct {
    nonce: [16]u8 = [_]u8{0} ** 16,
    issued_at_ms: i64 = 0,
    used: bool = false,
};

pub const Guard = struct {
    entries: [CAPACITY]Entry = [_]Entry{.{}} ** CAPACITY,
    next: usize = 0,

    /// Clear all replay state. Used by the server on startup and by tests.
    pub fn reset(self: *Guard) void {
        self.entries = [_]Entry{.{}} ** CAPACITY;
        self.next = 0;
    }

    /// Decode a 32-character lowercase/uppercase hex nonce into 16 bytes.
    pub fn decodeNonce(hex: []const u8) ?[16]u8 {
        if (hex.len != 32) return null;
        var out: [16]u8 = undefined;
        for (0..16) |i| {
            const hi = std.fmt.charToDigit(hex[i * 2], 16) catch return null;
            const lo = std.fmt.charToDigit(hex[i * 2 + 1], 16) catch return null;
            out[i] = (hi << 4) | lo;
        }
        return out;
    }

    /// Validate freshness and single use, then record the nonce.
    ///
    /// The caller must supply wall-clock `now_ms` (std.time.milliTimestamp).
    /// A nonce already inside the ring is rejected even if its timestamp has
    /// aged out, so a captured request cannot be replayed by rewriting only
    /// the timestamp. Ring eviction is deterministic: the oldest slot is
    /// overwritten when full.
    pub fn checkAndRecord(self: *Guard, nonce_hex: []const u8, issued_at_ms: i64, now_ms: i64) Verdict {
        const nonce = decodeNonce(nonce_hex) orelse return .invalid_nonce;
        const delta = if (now_ms >= issued_at_ms)
            now_ms - issued_at_ms
        else
            issued_at_ms - now_ms;
        if (delta > MAX_SKEW_MS) return .stale;

        for (self.entries) |entry| {
            if (entry.used and std.mem.eql(u8, &entry.nonce, &nonce)) return .replay;
        }

        const slot = &self.entries[self.next];
        slot.* = .{ .nonce = nonce, .issued_at_ms = issued_at_ms, .used = true };
        self.next = (self.next + 1) % CAPACITY;
        return .ok;
    }
};

/// Process-global guard used by the live control server. Tests reset it
/// explicitly so cases do not leak replay state into one another.
pub var g_guard: Guard = .{};

test "replay guard: fresh nonce accepted, exact replay denied" {
    var guard = Guard{};
    const nonce = "0123456789abcdef0123456789abcdef";
    try std.testing.expectEqual(Verdict.ok, guard.checkAndRecord(nonce, 1_000, 1_050));
    try std.testing.expectEqual(Verdict.replay, guard.checkAndRecord(nonce, 1_000, 1_060));
    const other = "fedcba9876543210fedcba9876543210";
    try std.testing.expectEqual(Verdict.ok, guard.checkAndRecord(other, 1_050, 1_060));
}

test "replay guard: stale and malformed nonces fail closed" {
    var guard = Guard{};
    const nonce = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    try std.testing.expectEqual(Verdict.stale, guard.checkAndRecord(nonce, 1_000, 1_000 + MAX_SKEW_MS + 1));
    try std.testing.expectEqual(Verdict.stale, guard.checkAndRecord(nonce, 1_000 + MAX_SKEW_MS + 1, 1_000));
    // A stale request must NOT consume the nonce: a later fresh request with
    // the same bytes is still subject to single-use, not silently accepted.
    try std.testing.expectEqual(Verdict.ok, guard.checkAndRecord(nonce, 1_000, 1_010));
    try std.testing.expectEqual(Verdict.replay, guard.checkAndRecord(nonce, 1_000, 1_020));
    try std.testing.expectEqual(Verdict.invalid_nonce, guard.checkAndRecord("short", 1_000, 1_010));
    try std.testing.expectEqual(Verdict.invalid_nonce, guard.checkAndRecord(
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", 1_000, 1_010,
    ));
}

test "replay guard: ring eviction is bounded and deterministic" {
    var guard = Guard{};
    // Fill the ring with distinct nonces; slot 0 holds the all-zero nonce.
    for (0..CAPACITY) |i| {
        var hex: [32]u8 = undefined;
        _ = try std.fmt.bufPrint(&hex, "{x:0>32}", .{i + 1});
        try std.testing.expectEqual(Verdict.ok, guard.checkAndRecord(&hex, 1_000, 1_000));
    }
    try std.testing.expectEqual(@as(usize, 0), guard.next);
    // One more insert overwrites slot 0 (the +1 nonce).
    try std.testing.expectEqual(Verdict.ok, guard.checkAndRecord(
        "ffffffffffffffffffffffffffffffff", 1_000, 1_000,
    ));
    try std.testing.expectEqual(Verdict.replay, guard.checkAndRecord(
        "ffffffffffffffffffffffffffffffff", 1_000, 1_000,
    ));
    // Eviction of the oldest slot is deterministic: +1 was slot 0.
    try std.testing.expectEqual(Verdict.ok, guard.checkAndRecord(
        "00000000000000000000000000000001", 1_000, 1_000,
    ));
}
