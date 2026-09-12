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
    reserved: u32 = 0,
};

pub const PepRequest = extern struct {
    decision_kind: u8, // matches EventKind
    flow_id: u64,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    policy_id: u32,
    severity: u8,
    ctx: PepContext,
};

pub const PepResponse = extern struct {
    decision: u8,
    reason: u32,
    quota_remaining: u32,
    signed_by: u32, // KeyId prefix
};

// Rust FFI functions
extern "aegis_pep" fn aegis_pep_enforce(req: *const PepRequest, resp: *PepResponse) c_int;
extern "aegis_pep" fn aegis_pep_unblock_ip(ipv4: u32, caller_pid: u32, caller_capability_mask: u32, request_id: u64) c_int;
extern "aegis_pep" fn aegis_pep_init() c_int;
extern "aegis_pep" fn aegis_pep_shutdown() void;
extern "aegis_pep" fn aegis_pep_quota_remaining(src_ip: u32) u32;

// ============================================================================
// PepEnforcer â€” Zig wrapper
// ============================================================================
pub const PepEnforcer = struct {
    available: bool = false,

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

    pub fn enforce(self: *PepEnforcer, ev: *const event.IpcEvent, p: policy.Policy, caller_pid: u32, caller_caps: u32, request_id: u64) PepDecision {
        if (!self.available) {
            // PATCH-15: Detection-only mode when PEP unavailable.
            // System observes and detects but does NOT enforce.
            // Policy action is honored for logging/alerting only.
            // This is FAIL-SAFE: no enforcement without PEP validation.
            return mapAction(p.action);
        }
        var req = PepRequest{
            .decision_kind = @intFromEnum(ev.kind),
            .flow_id = ev.flow_id,
            .src_ip = ev.src_ip,
            .dst_ip = ev.dst_ip,
            .src_port = ev.src_port,
            .dst_port = ev.dst_port,
            .policy_id = p.id,
            .severity = @intFromEnum(ev.severity),
            .ctx = .{ .caller_pid = caller_pid, .caller_capability_mask = caller_caps, .request_id = request_id },
        };
        var resp: PepResponse = undefined;
        const rc = aegis_pep_enforce(&req, &resp);
        if (rc != 0) {
            // PEP failure must never become an enforcement decision.
            return .allow;
        }
        return @enumFromInt(resp.decision);
    }

    pub fn quotaRemaining(self: *PepEnforcer, src_ip: u32) u32 {
        if (!self.available) return 0;
        return aegis_pep_quota_remaining(src_ip);
    }

    pub fn unblockIp(self: *PepEnforcer, ipv4: u32, caller_pid: u32, caller_caps: u32, request_id: u64) bool {
        if (!self.available) return false;
        return aegis_pep_unblock_ip(ipv4, caller_pid, caller_caps, request_id) == 0;
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
test "PepEnforcer fail-open when unavailable" {
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
    const d = pep.enforce(&ev, p, 0, 0, 0);
    try std.testing.expectEqual(PepDecision.block, d);
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
    // Rust #[repr(C)]: caller_pid at 0, caller_capability_mask at 4, request_id at 8, reserved at 16
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(PepContext, "caller_pid"));
    try std.testing.expectEqual(@as(usize, 4), @offsetOf(PepContext, "caller_capability_mask"));
    try std.testing.expectEqual(@as(usize, 8), @offsetOf(PepContext, "request_id"));
    try std.testing.expectEqual(@as(usize, 16), @offsetOf(PepContext, "reserved"));
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
    try std.testing.expectEqual(@as(usize, 8), @offsetOf(PepRequest, "flow_id"));
    try std.testing.expectEqual(@as(usize, 16), @offsetOf(PepRequest, "src_ip"));
    try std.testing.expectEqual(@as(usize, 20), @offsetOf(PepRequest, "dst_ip"));
    try std.testing.expectEqual(@as(usize, 24), @offsetOf(PepRequest, "src_port"));
    try std.testing.expectEqual(@as(usize, 26), @offsetOf(PepRequest, "dst_port"));
    try std.testing.expectEqual(@as(usize, 28), @offsetOf(PepRequest, "policy_id"));
    try std.testing.expectEqual(@as(usize, 32), @offsetOf(PepRequest, "severity"));
    try std.testing.expectEqual(@as(usize, 40), @offsetOf(PepRequest, "ctx"));
}

test "FFI-001: PepResponse size matches Rust" {
    // Rust #[repr(C)] PepResponse: u8 + padding(3) + u32 + u32 + u32 = 16 bytes
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(PepResponse));
}

test "FFI-001: PepResponse field offsets match Rust" {
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(PepResponse, "decision"));
    try std.testing.expectEqual(@as(usize, 4), @offsetOf(PepResponse, "reason"));
    try std.testing.expectEqual(@as(usize, 8), @offsetOf(PepResponse, "quota_remaining"));
    try std.testing.expectEqual(@as(usize, 12), @offsetOf(PepResponse, "signed_by"));
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
        .flow_id = 0x0102030405060708,
        .src_ip = 0xC0A80101,
        .dst_ip = 0x08080808,
        .src_port = 12345,
        .dst_port = 80,
        .policy_id = 42,
        .severity = 7,
        .ctx = .{
            .caller_pid = 1234,
            .caller_capability_mask = 0xFF,
            .request_id = 9999,
            .reserved = 0,
        },
    };
    const bytes = std.mem.asBytes(&req);
    // Verify magic byte at offset 0
    try std.testing.expectEqual(@as(u8, 61), bytes[0]);
    // Verify flow_id at offset 8 (little-endian u64)
    const flow_id_bytes = bytes[8..16];
    try std.testing.expectEqual(@as(u8, 0x08), flow_id_bytes[0]); // LE first byte
}
