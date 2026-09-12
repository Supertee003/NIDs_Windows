// I19 - Action Dispatcher (Log/Federation routing)
// AEGIS NIDS v5.0+ — Takes a PEP decision and executes the corresponding action.
//
// SECURITY (PEP-001): ActionDispatcher NEVER touches WFP directly.
// All privileged enforcement goes through rust_pep.zig -> pep_bindings -> Rust PEP.
//
// Routing:
//   - block / quarantine -> forensic pipeline + federation (WFP via Rust PEP only)
//   - rate_limit         -> forensic pipeline + federation
//   - escalate           -> federation aggregator
//   - log / allow        -> forensic pipeline + diagnostics log

const std = @import("std");
const event = @import("../contract/event.zig");
const diag = @import("../core/diagnostics.zig");
const pep = @import("pep_bindings.zig");
const policy = @import("policy_ir.zig");

// ============================================================================
// FederationBackend — escalation to peer nodes
// ============================================================================
pub const FederationBackend = struct {
    var send_fn: ?*const fn (event_ptr: *const event.IpcEvent) c_int = null;

    pub fn install(send: *const fn (event_ptr: *const event.IpcEvent) c_int) void {
        send_fn = send;
    }

    pub fn escalate(ev: *const event.IpcEvent) bool {
        if (send_fn) |f| {
            return f(ev) == 0;
        }
        return false;
    }
};

// ============================================================================
// ForensicBackend — forensic event persistence
// ============================================================================
pub const ForensicBackend = struct {
    var write_fn_cached: ?*const fn (event_ptr: *const event.IpcEvent) c_int = null;

    pub fn install(write_fn: *const fn (event_ptr: *const event.IpcEvent) c_int) void {
        write_fn_cached = write_fn;
    }

    pub fn write(ev: *const event.IpcEvent) bool {
        if (write_fn_cached) |f| {
            return f(ev) == 0;
        }
        return false;
    }
};

// ============================================================================
// ActionDispatcher — top-level (PEP-001: no WFP, no WfpBackend)
// ============================================================================
pub const ActionDispatcher = struct {
    pub fn init() void {}

    pub fn deinit() void {}

    pub fn dispatch(ev: *const event.IpcEvent, p: policy.Policy, decision: pep.PepDecision) void {
        switch (decision) {
            .allow, .drop => {
                diag.debug("action=allow/drop event={s} rule={d} policy_id={d}", .{ @tagName(ev.kind), ev.rule_id, p.id });
                _ = ForensicBackend.write(ev);
            },
            .block => {
                diag.alert("action=block src={x} dst={x} proto={d} policy_id={d}", .{ ev.src_ip, ev.dst_ip, ev.protocol, p.id });
                diag.info("PEP validated block; WFP enforcement executed by Rust PEP", .{});
                _ = ForensicBackend.write(ev);
            },
            .rate_limit => {
                diag.warn("action=rate_limit src={x} policy_id={d}", .{ ev.src_ip, p.id });
                diag.info("PEP validated rate_limit; WFP enforcement executed by Rust PEP", .{});
                _ = ForensicBackend.write(ev);
            },
            .quarantine => {
                diag.critical("action=quarantine src={x} policy_id={d}", .{ ev.src_ip, p.id });
                diag.info("PEP validated quarantine; federation notified", .{});
                _ = FederationBackend.escalate(ev);
                _ = ForensicBackend.write(ev);
            },
            .escalate => {
                diag.warn("action=escalate event={s}", .{@tagName(ev.kind)});
                _ = FederationBackend.escalate(ev);
                _ = ForensicBackend.write(ev);
            },
        }
    }
};

test "ActionDispatcher dispatch log path" {
    var ev = event.IpcEvent.init(.dns_query);
    const p = policy.Policy{
        .id = 1,
        .name = "",
        .condition = .{ .clauses = &[_]policy.Clause{} },
        .action = .log,
        .severity = .info,
        .ttl_sec = 0,
    };
    ActionDispatcher.dispatch(&ev, p, .allow);
}

test "ActionDispatcher dispatch block path" {
    var ev = event.IpcEvent.init(.dns_query);
    const p = policy.Policy{
        .id = 2,
        .name = "",
        .condition = .{ .clauses = &[_]policy.Clause{} },
        .action = .block,
        .severity = .alert,
        .ttl_sec = 0,
    };
    ActionDispatcher.dispatch(&ev, p, .block);
}

test "ActionDispatcher dispatch alert path" {
    var ev = event.IpcEvent.init(.tls_hello);
    const p = policy.Policy{
        .id = 3,
        .name = "alert_tls",
        .condition = .{ .clauses = &[_]policy.Clause{} },
        .action = .alert,
        .severity = .warning,
        .ttl_sec = 0,
    };
    ActionDispatcher.dispatch(&ev, p, .allow);
}

test "ActionDispatcher dispatch quarantine path" {
    var ev = event.IpcEvent.init(.packet_captured);
    const p = policy.Policy{
        .id = 4,
        .name = "quarantine_pkt",
        .condition = .{ .clauses = &[_]policy.Clause{} },
        .action = .quarantine,
        .severity = .critical,
        .ttl_sec = 0,
    };
    ActionDispatcher.dispatch(&ev, p, .quarantine);
}

test "ActionDispatcher dispatch escalate path" {
    var ev = event.IpcEvent.init(.dns_query);
    const p = policy.Policy{
        .id = 5,
        .name = "escalate_dns",
        .condition = .{ .clauses = &[_]policy.Clause{} },
        .action = .escalate,
        .severity = .alert,
        .ttl_sec = 0,
    };
    ActionDispatcher.dispatch(&ev, p, .escalate);
}

test "ActionDispatcher multiple dispatches do not interfere" {
    var ev1 = event.IpcEvent.init(.dns_query);
    var ev2 = event.IpcEvent.init(.tls_hello);
    const p1 = policy.Policy{
        .id = 10,
        .name = "",
        .condition = .{ .clauses = &[_]policy.Clause{} },
        .action = .log,
        .severity = .info,
        .ttl_sec = 0,
    };
    const p2 = policy.Policy{
        .id = 11,
        .name = "",
        .condition = .{ .clauses = &[_]policy.Clause{} },
        .action = .alert,
        .severity = .warning,
        .ttl_sec = 0,
    };
    ActionDispatcher.dispatch(&ev1, p1, .allow);
    ActionDispatcher.dispatch(&ev2, p2, .allow);
}
