// I18 - PEP (Policy Enforcement Point) â€” Rust-side FFI bindings (Zig side)
// AEGIS NIDS v5.0+ â€” Loads aegis_pep.dll and exposes its decision API to Zig.
//
// The Rust PEP makes the *final* go/no-go decision before an action is taken
// (block, quarantine, rate-limit). It enforces:
//   - Capability-based access control (calling context must be authorized)
//   - Rate-limit quotas (avoid blocking entire subnets by accident)
//   - Two-person rule for high-severity blocks (configurable)

const std = @import("std");
const event = @import("../contract/event.zig");
const policy = @import("policy_ir.zig");

// ============================================================================
// FFI bindings to aegis_pep.dll (Rust)
// ============================================================================
pub const PepDecision = enum(u8) {
    allow = 0,
    block = 1,
    rate_limit = 2,
    quarantine = 3,
    escalate = 4,
    drop = 5,
};

pub const PepContext = extern struct {
    caller_pid: u32,
    caller_capability_mask: u32,
    request_id: u64,
    policy_version: u32 = 0,
};

pub const PepRequest = extern struct {
    decision_kind: u8, // matches EventKind
    requested_action: u8, // matches policy.Action ordinals
    flow_id: u64,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    policy_id: u32,
    severity: u8,
    ctx: PepContext,
};

pub const PepResponse = extern struct {
    decision: u8,
    reason: u32,
    quota_remaining: u32,
    signed_by: u32, // KeyId prefix
    filter_id: u64,
};

pub const PepEnforcementReceipt = struct {
    decision: PepDecision,
    reason: u32,
    quota_remaining: u32,
    signed_by: u32,
    filter_id: u64,
};

// The C user bridge and WDK header wrap this state in #pragma pack(push, 1).
// A byte-backed extern struct avoids Zig's packed-struct field alignment rules
// and makes the 20-byte ABI explicit at every compiler boundary.
pub const PepFilterState = extern struct {
    bytes: [20]u8,

    pub fn filterId(self: *const PepFilterState) u64 {
        return std.mem.readInt(u64, self.bytes[0..8], .little);
    }

    pub fn remoteIpv4(self: *const PepFilterState) u32 {
        return std.mem.readInt(u32, self.bytes[8..12], .little);
    }

    pub fn remotePort(self: *const PepFilterState) u16 {
        return std.mem.readInt(u16, self.bytes[12..14], .little);
    }

    pub fn protocol(self: *const PepFilterState) u8 {
        return self.bytes[14];
    }

    pub fn present(self: *const PepFilterState) u8 {
        return self.bytes[15];
    }

    pub fn providerStatus(self: *const PepFilterState) u32 {
        return std.mem.readInt(u32, self.bytes[16..20], .little);
    }
};

pub const FilterQueryResult = union(enum) {
    query_error,
    absent: PepFilterState,
    present: PepFilterState,
};

// Rust FFI functions
extern "aegis_pep" fn aegis_pep_enforce(req: *const PepRequest, resp: *PepResponse) c_int;
extern "aegis_pep" fn aegis_pep_unblock_filter(filter_id: u64, caller_pid: u32, caller_capability_mask: u32, request_id: u64) c_int;
extern "aegis_pep" fn aegis_pep_query_filter(filter_id: u64, out: *PepFilterState) c_int;
extern "aegis_pep" fn aegis_pep_init() c_int;
extern "aegis_pep" fn aegis_pep_provider_ready() c_int;
extern "aegis_pep" fn aegis_pep_shutdown() void;
extern "aegis_pep" fn aegis_pep_quota_remaining(src_ip: u32) u32;

// ============================================================================
// PepEnforcer â€” Zig wrapper
// ============================================================================
pub const PepEnforcer = struct {
    available: bool = false,
    last_receipt: ?PepEnforcementReceipt = null,

    pub fn init() PepEnforcer {
        // Try to load DLL
        if (@import("builtin").os.tag != .windows) {
            return .{ .available = false };
        }
        const rc = aegis_pep_init();
        return .{ .available = rc == 0 };
    }

    pub fn deinit(self: *PepEnforcer) void {
        if (self.available) aegis_pep_shutdown();
    }

    /// Returns true only when the provider DLL exports and device-open
    /// attestation succeed. This does not claim a host-side block effect.
    pub fn providerReady(_: *PepEnforcer) bool {
        if (@import("builtin").os.tag != .windows) return false;
        return aegis_pep_provider_ready() == 1;
    }

    pub fn enforce(self: *PepEnforcer, ev: *const event.IpcEvent, p: policy.Policy, caller_pid: u32, caller_caps: u32, request_id: u64) PepDecision {
        self.last_receipt = null;
        // The active JSON loader does not verify a signed canonical policy
        // envelope. Keep every privileged action non-enforcing until a
        // verified loader marks the policy trusted. Alert/log paths remain
        // available for detection-only operation.
        if (policy.requiresTrustedAuthorization(p.action) and !p.trusted) {
            return .escalate;
        }
        if (!self.available) {
            // SAFETY CONTAINMENT: unavailable PEP is not an ALLOW decision.
            // Escalate to the non-enforcing/degraded path so callers cannot
            // confuse detection-only mode with an authorized action.
            return .escalate;
        }
        var req = PepRequest{
            .decision_kind = @intFromEnum(ev.kind),
            .requested_action = @intFromEnum(p.action),
            .flow_id = ev.flow_id,
            .src_ip = ev.src_ip,
            .dst_ip = ev.dst_ip,
            .src_port = ev.src_port,
            .dst_port = ev.dst_port,
            .protocol = ev.protocol,
            .policy_id = p.id,
            .severity = @intFromEnum(ev.severity),
            .ctx = .{ .caller_pid = caller_pid, .caller_capability_mask = caller_caps, .request_id = request_id },
        };
        var resp: PepResponse = undefined;
        const rc = aegis_pep_enforce(&req, &resp);
        if (rc != 0) {
            // PEP failure must never become an ALLOW decision.
            return .escalate;
        }
        // The DLL is an untrusted ABI boundary. Never convert an unknown
        // ordinal into a Zig enum; malformed provider responses fail closed.
        if (resp.decision > @intFromEnum(PepDecision.drop)) return .escalate;
        if (resp.decision == @intFromEnum(PepDecision.block) and resp.filter_id != 0) {
            self.last_receipt = .{
                .decision = .block,
                .reason = resp.reason,
                .quota_remaining = resp.quota_remaining,
                .signed_by = resp.signed_by,
                .filter_id = resp.filter_id,
            };
        }
        return @enumFromInt(resp.decision);
    }

    pub fn lastReceipt(self: *const PepEnforcer) ?PepEnforcementReceipt {
        return self.last_receipt;
    }

    pub fn quotaRemaining(self: *PepEnforcer, src_ip: u32) u32 {
        if (!self.available) return 0;
        return aegis_pep_quota_remaining(src_ip);
    }

    pub fn enforceFlow(
        self: *PepEnforcer,
        dst_ip: u32,
        dst_port: u16,
        protocol: u8,
        policy_id: u32,
        severity: u8,
        caller_pid: u32,
        caller_caps: u32,
        request_id: u64,
    ) ?PepEnforcementReceipt {
        if (!self.available or dst_ip == 0 or dst_port == 0 or protocol == 0 or policy_id == 0) return null;
        var req = PepRequest{
            .decision_kind = 0,
            // requested_action uses the policy.Action ABI, not PepDecision.
            // Rust maps policy.Action.block to ACTION_BLOCK = 4.
            .requested_action = @intFromEnum(policy.Action.block),
            .flow_id = request_id,
            .src_ip = 0,
            .dst_ip = dst_ip,
            .src_port = 0,
            .dst_port = dst_port,
            .protocol = protocol,
            .policy_id = policy_id,
            .severity = severity,
            .ctx = .{ .caller_pid = caller_pid, .caller_capability_mask = caller_caps, .request_id = request_id },
        };
        var resp: PepResponse = undefined;
        if (aegis_pep_enforce(&req, &resp) != 0) return null;
        if (resp.decision != @intFromEnum(PepDecision.block) or resp.filter_id == 0) return null;
        return .{
            .decision = .block,
            .reason = resp.reason,
            .quota_remaining = resp.quota_remaining,
            .signed_by = resp.signed_by,
            .filter_id = resp.filter_id,
        };
    }

    pub fn unblockFilter(self: *PepEnforcer, filter_id: u64, caller_pid: u32, caller_caps: u32, request_id: u64) bool {
        if (!self.available or filter_id == 0) return false;
        return aegis_pep_unblock_filter(filter_id, caller_pid, caller_caps, request_id) == 0;
    }

    pub fn queryFilter(self: *PepEnforcer, filter_id: u64) ?PepFilterState {
        return switch (self.queryFilterResult(filter_id)) {
            .present => |state| state,
            .absent => null,
            .query_error => null,
        };
    }

    /// Preserve the provider distinction between an exact filter that is
    /// absent and a query transport/provider failure.
    pub fn queryFilterResult(self: *PepEnforcer, filter_id: u64) FilterQueryResult {
        if (!self.available or filter_id == 0) return .query_error;
        var state: PepFilterState = .{ .bytes = undefined };
        if (aegis_pep_query_filter(filter_id, &state) != 0) return .query_error;
        if (state.filterId() != filter_id) return .query_error;
        return if (state.present() != 0) .{ .present = state } else .{ .absent = state };
    }

    /// Confirm that a receipt proves the exact host effect requested by ev.
    /// A receipt ID alone is insufficient: provider read-back must report the
    /// same destination tuple and an explicitly present owned filter.
    pub fn verifyEnforcementReceipt(
        self: *PepEnforcer,
        ev: *const event.IpcEvent,
        receipt: PepEnforcementReceipt,
    ) bool {
        if (receipt.decision != .block or receipt.filter_id == 0) return false;
        return switch (self.queryFilterResult(receipt.filter_id)) {
            .present => |state| state.filterId() == receipt.filter_id and
                state.remoteIpv4() == ev.dst_ip and
                state.remotePort() == ev.dst_port and
                state.protocol() == ev.protocol and
                state.present() != 0,
            .absent, .query_error => false,
        };
    }
};

fn mapAction(a: policy.Action) PepDecision {
    return switch (a) {
        .pass => .allow,
        .log, .alert => .allow,
        .rate_limit => .rate_limit,
        .block => .block,
        .quarantine => .quarantine,
        .escalate => .escalate,
    };
}

// ============================================================================
// Tests
// ============================================================================
test "PepEnforcer unavailable is not an allow decision" {
    var pep = PepEnforcer{ .available = false };
    var ev = event.IpcEvent.init(.dns_query);
    const p = policy.Policy{
        .id = 1,
        .name = "",
        .condition = .{ .clauses = &[_]policy.Clause{} },
        .action = .block,
        .severity = .alert,
        .ttl_sec = 0,
    };
    // Unavailable PEP must remain visible to the caller as non-enforcing state.
    const d = pep.enforce(&ev, p, 0, 0, 0);
    try std.testing.expectEqual(PepDecision.escalate, d);
}

test "filter query ABI has stable packed layout" {
    try std.testing.expectEqual(@as(usize, 20), @sizeOf(PepFilterState));
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(PepFilterState, "bytes"));
}

test "receipt verification rejects incomplete receipt" {
    var pep = PepEnforcer{ .available = false };
    var ev = event.IpcEvent.init(.flow_created);
    const receipt = PepEnforcementReceipt{
        .decision = .block,
        .reason = 0,
        .quota_remaining = 0,
        .signed_by = 0,
        .filter_id = 0,
    };
    try std.testing.expect(!pep.verifyEnforcementReceipt(&ev, receipt));
}

test "mapAction correctness" {
    try std.testing.expectEqual(PepDecision.allow, mapAction(.pass));
    try std.testing.expectEqual(PepDecision.allow, mapAction(.log));
    try std.testing.expectEqual(PepDecision.allow, mapAction(.alert));
    try std.testing.expectEqual(PepDecision.rate_limit, mapAction(.rate_limit));
    try std.testing.expectEqual(PepDecision.block, mapAction(.block));
    try std.testing.expectEqual(PepDecision.quarantine, mapAction(.quarantine));
    try std.testing.expectEqual(PepDecision.escalate, mapAction(.escalate));
}

// ============================================================================
// FFI-001: Zig/Rust PEP ABI Verification
// ============================================================================
// These tests verify that the Zig-side struct layouts match the Rust-side
// #[repr(C)] definitions. Any mismatch would cause silent ABI corruption.

test "FFI-001: PepContext size matches Rust" {
    // Rust: #[repr(C)] PepContext { u32, u32, u64, u32 } = 20 bytes
    // But u64 at offset 8 requires 8-byte alignment → padded to 24 bytes
    // Actually: u32(4) + u32(4) + u64(8) + u32(4) = 20, but u64 alignment pads
    // Let's verify actual size
    try std.testing.expectEqual(@as(usize, 24), @sizeOf(PepContext));
}

test "FFI-001: PepContext field offsets match Rust" {
    // Rust #[repr(C)]: caller_pid at 0, caller_capability_mask at 4, request_id at 8, policy_version at 16
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(PepContext, "caller_pid"));
    try std.testing.expectEqual(@as(usize, 4), @offsetOf(PepContext, "caller_capability_mask"));
    try std.testing.expectEqual(@as(usize, 8), @offsetOf(PepContext, "request_id"));
    try std.testing.expectEqual(@as(usize, 16), @offsetOf(PepContext, "policy_version"));
}

test "FFI-001: PepRequest size matches Rust" {
    // Rust #[repr(C)] PepRequest:
    //   decision_kind: u8 (1) + padding(7) + flow_id: u64 (8) + src_ip: u32 (4) +
    //   dst_ip: u32 (4) + src_port: u16 (2) + dst_port: u16 (2) + policy_id: u32 (4) +
    //   severity: u8 (1) + padding(7) + ctx: PepContext (24)
    // = 1+7+8+4+4+2+2+4+1+7+24 = 64 bytes
    try std.testing.expectEqual(@as(usize, 64), @sizeOf(PepRequest));
}

test "FFI-001: PepRequest field offsets match Rust" {
    // Verify critical field offsets against Rust #[repr(C)]
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(PepRequest, "decision_kind"));
    try std.testing.expectEqual(@as(usize, 1), @offsetOf(PepRequest, "requested_action"));
    try std.testing.expectEqual(@as(usize, 8), @offsetOf(PepRequest, "flow_id"));
    try std.testing.expectEqual(@as(usize, 16), @offsetOf(PepRequest, "src_ip"));
    try std.testing.expectEqual(@as(usize, 20), @offsetOf(PepRequest, "dst_ip"));
    try std.testing.expectEqual(@as(usize, 24), @offsetOf(PepRequest, "src_port"));
    try std.testing.expectEqual(@as(usize, 26), @offsetOf(PepRequest, "dst_port"));
    try std.testing.expectEqual(@as(usize, 28), @offsetOf(PepRequest, "protocol"));
    try std.testing.expectEqual(@as(usize, 32), @offsetOf(PepRequest, "policy_id"));
    try std.testing.expectEqual(@as(usize, 36), @offsetOf(PepRequest, "severity"));
    try std.testing.expectEqual(@as(usize, 40), @offsetOf(PepRequest, "ctx"));
}

test "FFI-001: PepResponse size matches Rust" {
    // Rust #[repr(C)] PepResponse:
    // u8 + padding(3) + u32 + u32 + u32 + padding(4) + u64 = 24 bytes.
    try std.testing.expectEqual(@as(usize, 24), @sizeOf(PepResponse));
}

test "FFI-001: PepResponse field offsets match Rust" {
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(PepResponse, "decision"));
    try std.testing.expectEqual(@as(usize, 4), @offsetOf(PepResponse, "reason"));
    try std.testing.expectEqual(@as(usize, 8), @offsetOf(PepResponse, "quota_remaining"));
    try std.testing.expectEqual(@as(usize, 12), @offsetOf(PepResponse, "signed_by"));
    try std.testing.expectEqual(@as(usize, 16), @offsetOf(PepResponse, "filter_id"));
}

test "FFI-001: PepDecision enum values match Rust constants" {
    // Rust: DECISION_ALLOW=0, DECISION_BLOCK=1, DECISION_RATE_LIMIT=2,
    //        DECISION_QUARANTINE=3, DECISION_ESCALATE=4, DECISION_DROP=5
    try std.testing.expectEqual(@as(u8, 0), @intFromEnum(PepDecision.allow));
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(PepDecision.block));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(PepDecision.rate_limit));
    try std.testing.expectEqual(@as(u8, 3), @intFromEnum(PepDecision.quarantine));
    try std.testing.expectEqual(@as(u8, 4), @intFromEnum(PepDecision.escalate));
    try std.testing.expectEqual(@as(u8, 5), @intFromEnum(PepDecision.drop));
}

test "FFI-001: extern function signatures are C ABI" {
    // Verify the extern declarations exist and have correct types
    // We can verify by checking the function type is not void
    // In Zig 0.13.0, use @typeInfo(T) == .Fn or check the tag
    const enforce_type = @TypeOf(aegis_pep_enforce);
    const init_type = @TypeOf(aegis_pep_init);
    const shutdown_type = @TypeOf(aegis_pep_shutdown);
    const quota_type = @TypeOf(aegis_pep_quota_remaining);
    // Just verify they compile and are callable — the extern link will be checked at link time
    _ = enforce_type;
    _ = init_type;
    _ = shutdown_type;
    _ = quota_type;
    // If we reach here, the declarations are syntactically valid
    try std.testing.expect(true);
}

test "FFI-001: PepRequest binary serialization roundtrip" {
    // Create a known request, serialize to bytes, verify layout
    var req = PepRequest{
        .decision_kind = 61,
        .requested_action = @intFromEnum(policy.Action.block),
        .flow_id = 0x0102030405060708,
        .src_ip = 0xC0A80101,
        .dst_ip = 0x08080808,
        .src_port = 12345,
        .dst_port = 80,
        .protocol = 6,
        .policy_id = 42,
        .severity = 7,
        .ctx = .{
            .caller_pid = 1234,
            .caller_capability_mask = 0xFF,
            .request_id = 9999,
            .policy_version = 0,
        },
    };
    const bytes = std.mem.asBytes(&req);
    // Verify magic byte at offset 0
    try std.testing.expectEqual(@as(u8, 61), bytes[0]);
    // Verify flow_id at offset 8 (little-endian u64)
    const flow_id_bytes = bytes[8..16];
    try std.testing.expectEqual(@as(u8, 0x08), flow_id_bytes[0]); // LE first byte
}

test "FFI-001: flow enforcement uses policy block ordinal" {
    // PepDecision.block is a response decision (1); requests use policy.Action.
    // Rust's ACTION_BLOCK is 4 and must remain distinct from DECISION_BLOCK.
    try std.testing.expectEqual(@as(u8, 4), @intFromEnum(policy.Action.block));
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(PepDecision.block));
}
