//! Phase 8 Windows adapter contract: readiness and degraded reasons.
const std = @import("std");

pub const AdapterKind = enum(u8) { npcap, etw, fim, registry, wfp, go_nose, cpp_bridge };
pub const AdapterState = enum(u8) { unavailable, starting, ready, degraded, stopped };

pub const AdapterStatus = struct {
    kind: AdapterKind,
    state: AdapterState,
    provider_version: []const u8 = "unknown",
    capability_mask: u32 = 0,
    error_code: []const u8 = "",
    started_at_ms: i64 = 0,
    last_heartbeat_ms: i64 = 0,

    pub fn isUsable(self: AdapterStatus) bool {
        return self.state == .ready or self.state == .degraded;
    }
};

pub const AdapterProfile = struct {
    name: []const u8,
    enabled_mask: u32,
    required_mask: u32,
    exclusion_mask: u32 = 0,

    pub fn satisfiesRequired(self: AdapterProfile, available_mask: u32) bool {
        return (available_mask & self.required_mask) == self.required_mask;
    }
};

test "adapter readiness distinguishes degraded from unavailable" {
    try std.testing.expect((AdapterStatus{ .kind = .etw, .state = .degraded }).isUsable());
    try std.testing.expect(!(AdapterStatus{ .kind = .etw, .state = .unavailable }).isUsable());
}

test "adapter profile checks required capabilities" {
    const profile = AdapterProfile{ .name = "default", .enabled_mask = 0x0F, .required_mask = 0x03 };
    try std.testing.expect(profile.satisfiesRequired(0x07));
    try std.testing.expect(!profile.satisfiesRequired(0x01));
}
