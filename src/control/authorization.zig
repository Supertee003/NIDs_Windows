//! control/authorization.zig — Role-Based Access Control for Control Plane
//!
//! SECURITY (P0.4): Every command MUST be authorized before dispatch.
//! Authorization checks:
//!   1. Caller role must have sufficient privilege for the command
//!   2. Mutation commands require operate or privileged role
//!   3. Shutdown/restart require privileged role
//!
//! Default ACL: local named pipe connections get "operate" role.
//! Remote connections (TCP) get "read" role.

const std = @import("std");
const protocol = @import("protocol.zig");

pub const AuthDecision = enum {
    allow,
    deny,
};

pub const AuthResult = struct {
    decision: AuthDecision,
    reason: []const u8,
};

pub const Authorizer = struct {
    /// Default role for local pipe connections
    default_local_role: protocol.Role = .operate,
    /// Default role for remote TCP connections
    default_remote_role: protocol.Role = .read,
    /// Whether authorization is enabled (can be disabled for testing)
    enabled: bool = true,

    pub fn authorize(self: *Authorizer, cmd: protocol.Command, caller_role: protocol.Role) AuthResult {
        if (!self.enabled) {
            return .{ .decision = .allow, .reason = "authorization disabled" };
        }
        const c = protocol.contract(cmd);
        if (!caller_role.can(c.required_role)) {
            return .{
                .decision = .deny,
                .reason = "insufficient privilege",
            };
        }
        return .{ .decision = .allow, .reason = "ok" };
    }

    pub fn getLocalRole(self: *Authorizer) protocol.Role {
        return self.default_local_role;
    }

    pub fn getRemoteRole(self: *Authorizer) protocol.Role {
        return self.default_remote_role;
    }
};

// ============================================================
// Tests
// ============================================================

test "Authorizer: read role can read" {
    var auth = Authorizer{};
    const result = auth.authorize(.system_status, .read);
    try std.testing.expectEqual(AuthDecision.allow, result.decision);
}

test "Authorizer: read role cannot mutate" {
    var auth = Authorizer{};
    const result = auth.authorize(.rules_reload, .read);
    try std.testing.expectEqual(AuthDecision.deny, result.decision);
}

test "Authorizer: operate role can reload" {
    var auth = Authorizer{};
    const result = auth.authorize(.rules_reload, .operate);
    try std.testing.expectEqual(AuthDecision.allow, result.decision);
}

test "Authorizer: operate role cannot shutdown" {
    var auth = Authorizer{};
    const result = auth.authorize(.daemon_shutdown, .operate);
    try std.testing.expectEqual(AuthDecision.deny, result.decision);
}

test "Authorizer: privileged role can do everything" {
    var auth = Authorizer{};
    try std.testing.expectEqual(AuthDecision.allow, auth.authorize(.system_status, .privileged).decision);
    try std.testing.expectEqual(AuthDecision.allow, auth.authorize(.rules_reload, .privileged).decision);
    try std.testing.expectEqual(AuthDecision.allow, auth.authorize(.daemon_shutdown, .privileged).decision);
    try std.testing.expectEqual(AuthDecision.allow, auth.authorize(.runtime_stop, .privileged).decision);
}

test "Authorizer: disabled skips checks" {
    var auth = Authorizer{ .enabled = false };
    const result = auth.authorize(.daemon_shutdown, .read);
    try std.testing.expectEqual(AuthDecision.allow, result.decision);
}
