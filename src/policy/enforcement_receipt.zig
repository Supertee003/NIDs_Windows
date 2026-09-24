//! Phase 7 enforcement contract: decision, host effect and receipt are distinct.
const std = @import("std");

pub const EnforcementStatus = enum(u8) {
    pending = 0,
    enforced = 1,
    failed = 2,
    unavailable = 3,
    rolled_back = 4,
    simulated = 5,
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
        if (self.status == .enforced and (self.policy_id == 0 or self.decision != 1)) return false;
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
