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

    pub fn enforce(self: *PepEnforcer, ev: *const event.IpcEvent, p: policy.Policy, caller_pid: u32, caller_caps: u32) PepDecision {
        if (!self.available) {
            // Fail-open: return the policy's action if PEP is unavailable
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
            .ctx = .{ .caller_pid = caller_pid, .caller_capability_mask = caller_caps, .request_id = ev.event_id },
        };
        var resp: PepResponse = undefined;
        const rc = aegis_pep_enforce(&req, &resp);
        if (rc != 0) {
            // PEP internal error â†’ fail-safe to block
            return .block;
        }
        return @enumFromInt(resp.decision);
    }

    pub fn quotaRemaining(self: *PepEnforcer, src_ip: u32) u32 {
        if (!self.available) return 0;
        return aegis_pep_quota_remaining(src_ip);
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
    const d = pep.enforce(&ev, p, 0, 0);
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
