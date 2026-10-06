//! control/defcon.zig — FE-DEF-095a: the daemon is the DEFCON authority.
//!
//! Four surfaces used to compute DEFCON independently (CLI bridge/file
//! fallback, desktop file tail, web evidence feed, mouth log tail) with
//! two different label vocabularies — and every file-tailed ladder shows
//! SAFE when the evidence log is absent while the daemon holds open
//! incidents. This module is the single ladder. Inputs are daemon-owned
//! atomic counters (never file contents):
//!
//!   total     = g_pipeline_detections  (matched detections)
//!   critical  = g_critical_detections  (matched, final severity
//!               critical/emergency incl. incident escalation)
//!   confirmed = g_confirmed_blocks     (BLOCKED_CONFIRMED receipts only)
//!
//! Thresholds are the pre-existing three-surface consensus (desktop, web,
//! mouth agreed on these numbers); only the ownership changes. Labels use
//! the MAXIMUM/SEVERE/HIGH/ELEVATED/SAFE vocabulary those three share.
//! The CLI bridge fallback's COCKED PISTOL labels are diagnostic-only and
//! are NOT part of this contract.

const std = @import("std");

pub const Label = enum(u8) {
    maximum = 1,
    severe = 2,
    high = 3,
    elevated = 4,
    safe = 5,

    pub fn toString(self: Label) []const u8 {
        return switch (self) {
            .maximum => "MAXIMUM",
            .severe => "SEVERE",
            .high => "HIGH",
            .elevated => "ELEVATED",
            .safe => "SAFE",
        };
    }
};

/// Single DEFCON ladder. Pure: same inputs always give the same level.
pub fn level(total: u64, critical: u64, confirmed: u64) u8 {
    if (critical >= 10 or confirmed >= 5) return 1;
    if (critical >= 5 or confirmed >= 3) return 2;
    if (total >= 5 or critical >= 1) return 3;
    if (total >= 1) return 4;
    return 5;
}

pub fn labelFor(lvl: u8) []const u8 {
    return switch (lvl) {
        1 => Label.maximum.toString(),
        2 => Label.severe.toString(),
        3 => Label.high.toString(),
        4 => Label.elevated.toString(),
        else => Label.safe.toString(),
    };
}

test "FE-DEF-095a: ladder matches the three-surface consensus thresholds" {
    // L1: mass critical or mass confirmed blocks.
    try std.testing.expectEqual(@as(u8, 1), level(0, 10, 0));
    try std.testing.expectEqual(@as(u8, 1), level(0, 0, 5));
    // L2: severe band.
    try std.testing.expectEqual(@as(u8, 2), level(0, 5, 0));
    try std.testing.expectEqual(@as(u8, 2), level(0, 0, 3));
    // L3: volume or a single critical.
    try std.testing.expectEqual(@as(u8, 3), level(5, 0, 0));
    try std.testing.expectEqual(@as(u8, 3), level(0, 1, 0));
    // L4: any detection at all.
    try std.testing.expectEqual(@as(u8, 4), level(1, 0, 0));
    // Quiet daemon.
    try std.testing.expectEqual(@as(u8, 5), level(0, 0, 0));
}

test "FE-DEF-095a: negative controls — near-threshold inputs stay down" {
    try std.testing.expectEqual(@as(u8, 2), level(0, 9, 0));
    try std.testing.expectEqual(@as(u8, 2), level(0, 0, 4));
    try std.testing.expectEqual(@as(u8, 3), level(0, 4, 0));
    // 2 confirmed blocks with zero detections is incoherent input (blocks
    // come from detections); the ladder refuses to escalate on a
    // below-threshold confirmed count alone — matches the web/desktop
    // consensus, which also falls through to SAFE here.
    try std.testing.expectEqual(@as(u8, 5), level(0, 0, 2));
    try std.testing.expectEqual(@as(u8, 4), level(4, 0, 0));
    try std.testing.expectEqual(@as(u8, 5), level(0, 0, 0));
}

test "FE-DEF-095a: labels use the shared MAXIMUM vocabulary" {
    try std.testing.expectEqualStrings("MAXIMUM", labelFor(1));
    try std.testing.expectEqualStrings("SEVERE", labelFor(2));
    try std.testing.expectEqualStrings("HIGH", labelFor(3));
    try std.testing.expectEqualStrings("ELEVATED", labelFor(4));
    try std.testing.expectEqualStrings("SAFE", labelFor(5));
    try std.testing.expectEqualStrings("SAFE", labelFor(99));
}
