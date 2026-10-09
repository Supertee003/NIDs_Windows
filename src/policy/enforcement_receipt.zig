//! Phase 7 enforcement contract: decision, host effect and receipt are distinct.
const std = @import("std");

/// Receipt-local enforcement vocabulary. It is RICHER than the frozen wire
/// byte (`canonical_event.zig` enforcement_status: 0=pending, 1=enforced,
/// 2=failed, 3=rolled_back) and the two must never be reinterpreted by ordinal:
/// a raw receipt ordinal 3 means `unavailable` here but `rolled_back` on the
/// wire, and 4 is undefined there. Use `wireStatus` to cross the boundary.
pub const EnforcementStatus = enum(u8) {
    pending = 0,
    enforced = 1,
    failed = 2,
    unavailable = 3,
    rolled_back = 4,
    simulated = 5,

    /// Total mapping onto the frozen wire/forensic status byte.
    ///
    /// Only `enforced` may become 1: `unavailable` means no host effect was
    /// applied, and `simulated` is observe-only, so neither may be readable as
    /// a success. `unavailable` degrades to 2 (failed) rather than to a
    /// pending state so an operator never sees "still pending" for a provider
    /// that already answered.
    pub fn wireStatus(self: EnforcementStatus) u8 {
        return switch (self) {
            .pending => 0,
            .enforced => 1,
            .failed => 2,
            .unavailable => 2,
            .rolled_back => 3,
            .simulated => 0,
        };
    }
};

pub const EnforcementReceipt = struct {
    pub const VERSION: u16 = 1;

    request_id: u64,
    event_id: u64,
    policy_id: u32,
    decision: u8,
    status: EnforcementStatus,
    provider: []const u8,
    filter_id: u64 = 0,
    host_effect_confirmed: bool = false,
    reason: []const u8 = "",
    trace_id: u64 = 0,
    audit_id: u64 = 0,
    receipt_version: u16 = VERSION,

    /// Frozen wire/forensic status byte for this receipt's status.
    pub fn wireStatus(self: EnforcementReceipt) u8 {
        return self.status.wireStatus();
    }

    pub fn isSuccess(self: EnforcementReceipt) bool {
        return self.validate() and self.status == .enforced and self.host_effect_confirmed and
            self.provider.len > 0 and self.filter_id != 0 and
            self.trace_id != 0 and self.audit_id != 0;
    }

    pub fn isForensicallyLinkable(self: EnforcementReceipt) bool {
        return self.request_id != 0 and self.event_id != 0 and
            self.trace_id != 0 and self.audit_id != 0 and
            self.receipt_version == VERSION;
    }

    pub fn validate(self: EnforcementReceipt) bool {
        if (self.receipt_version != VERSION or self.request_id == 0 or self.event_id == 0) return false;
        // G5: enforced decisions are block (1) and quarantine (3). Any
        // other decision value on an enforced receipt is malformed —
        // never widen this without a control-plane verb that mints it.
        if (self.status == .enforced and (self.policy_id == 0 or (self.decision != 1 and self.decision != 3))) return false;
        if (self.status == .enforced and !self.host_effect_confirmed) return false;
        if (self.host_effect_confirmed and self.status != .enforced) return false;
        if (self.status == .enforced and (self.provider.len == 0 or self.filter_id == 0 or self.trace_id == 0 or self.audit_id == 0)) return false;
        return true;
    }

    pub fn isSafeFailure(self: EnforcementReceipt) bool {
        return self.status == .failed or self.status == .unavailable;
    }
};

test "enforcement receipt does not equate decision with host effect" {
    const pending = EnforcementReceipt{ .request_id = 1, .event_id = 2, .policy_id = 3, .decision = 1, .status = .pending, .provider = "wfp" };
    try std.testing.expect(!pending.isSuccess());
    const enforced = EnforcementReceipt{ .request_id = 1, .event_id = 2, .policy_id = 3, .decision = 1, .status = .enforced, .provider = "wfp", .filter_id = 9, .host_effect_confirmed = true, .reason = "filter_installed", .trace_id = 4, .audit_id = 5 };
    try std.testing.expect(enforced.isSuccess());
}

test "G5 quarantine receipt validates like block, unknown decisions do not" {
    const base = EnforcementReceipt{ .request_id = 7, .event_id = 8, .policy_id = 3, .status = .enforced, .provider = "wfp", .filter_id = 9, .host_effect_confirmed = true, .reason = "filter_installed", .trace_id = 4, .audit_id = 5, .decision = 0 };
    var q = base;
    q.decision = 3;
    try std.testing.expect(q.validate());
    try std.testing.expect(q.isSuccess());
    var bad = base;
    bad.decision = 4;
    try std.testing.expect(!bad.validate());
    try std.testing.expect(!bad.isSuccess());
}

test "forensic linkage requires trace and audit identity" {
    const receipt = EnforcementReceipt{
        .request_id = 1,
        .event_id = 2,
        .policy_id = 3,
        .decision = 1,
        .status = .simulated,
        .provider = "none",
        .trace_id = 4,
        .audit_id = 5,
    };
    try std.testing.expect(receipt.validate());
    try std.testing.expect(receipt.isForensicallyLinkable());
    const unlinked = EnforcementReceipt{
        .request_id = 1,
        .event_id = 2,
        .policy_id = 3,
        .decision = 1,
        .status = .simulated,
        .provider = "none",
    };
    try std.testing.expect(!unlinked.isForensicallyLinkable());
}

test "host effect confirmation requires enforced status" {
    const invalid = EnforcementReceipt{
        .request_id = 1,
        .event_id = 2,
        .policy_id = 3,
        .decision = 1,
        .status = .pending,
        .provider = "wfp",
        .host_effect_confirmed = true,
    };
    try std.testing.expect(!invalid.validate());
}

test "enforced receipt requires a non-zero policy and block decision" {
    const missing_policy = EnforcementReceipt{
        .request_id = 1,
        .event_id = 2,
        .policy_id = 0,
        .decision = 1,
        .status = .enforced,
        .provider = "wfp",
        .filter_id = 9,
        .host_effect_confirmed = true,
        .trace_id = 4,
        .audit_id = 5,
    };
    try std.testing.expect(!missing_policy.validate());

    const non_block = EnforcementReceipt{
        .request_id = 1,
        .event_id = 2,
        .policy_id = 3,
        .decision = 0,
        .status = .enforced,
        .provider = "wfp",
        .filter_id = 9,
        .host_effect_confirmed = true,
        .trace_id = 4,
        .audit_id = 5,
    };
    try std.testing.expect(!non_block.validate());
}
