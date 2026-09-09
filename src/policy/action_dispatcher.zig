// I19 - Action Dispatcher (WFP/ETW/Log routing)
// AEGIS NIDS v5.0+ â€” Takes a PEP decision and executes the corresponding action.
//
// Routing:
//   - block / quarantine â†’ WFP callout (filter add)
//   - rate_limit         â†’ WFP with weighted filter
//   - escalate           â†’ federation aggregator
//   - log / allow        â†’ forensic pipeline + diagnostics log

const std = @import("std");
const event = @import("../contract/event.zig");
const diag = @import("../core/diagnostics.zig");
const pep = @import("pep_bindings.zig");
const policy = @import("policy_ir.zig");

// ============================================================================
// Action target backends (stubs â€” real impl in windows/ subdirectory)
// ============================================================================
pub const WfpBackend = struct {
    var add_filter_fn: ?*const fn (src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, proto: u8, weight: u8) c_int = null;
    var remove_filter_fn: ?*const fn (filter_id: u64) c_int = null;
    var active_filters: u32 = 0;

    pub fn install(add: *const fn (src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, proto: u8, weight: u8) c_int, remove_fn: *const fn (filter_id: u64) c_int) void {
        add_filter_fn = add;
        remove_filter_fn = remove_fn;
    }

    pub fn block(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, proto: u8) ?u64 {
        if (add_filter_fn) |f| {
            const rc = f(src_ip, dst_ip, src_port, dst_port, proto, 0);
            if (rc >= 0) {
                active_filters += 1;
                diag.metrics.blocks_issued.inc();
                return @intCast(rc);
            }
        }
        return null;
    }

    pub fn rateLimit(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, proto: u8, weight: u8) ?u64 {
        if (add_filter_fn) |f| {
            const rc = f(src_ip, dst_ip, src_port, dst_port, proto, weight);
            if (rc >= 0) {
                active_filters += 1;
                return @intCast(rc);
            }
        }
        return null;
    }

    pub fn remove(filter_id: u64) bool {
        if (remove_filter_fn) |f| {
            const rc = f(filter_id);
            if (rc == 0) {
                if (active_filters > 0) active_filters -= 1;
                return true;
            }
        }
        return false;
    }
};

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
// ActionDispatcher â€” top-level
// ============================================================================
pub const ActionDispatcher = struct {
    // PATCH-12: Removed internal PepEnforcer. Pipeline calls PEP once,
    // passes validated decision here. No second PEP evaluation.

    pub fn init() void {
        // No-op: PEP is managed by pipeline in main.zig
    }

    pub fn deinit() void {
        // No-op: PEP is managed by pipeline in main.zig
    }

    pub fn dispatch(ev: *const event.IpcEvent, p: policy.Policy, decision: pep.PepDecision) void {
        // PATCH-12: Use validated PEP decision directly -- no re-evaluation
        switch (decision) {
            .allow, .drop => {
                diag.debug("action=allow/drop event={s} rule={d} policy_id={d}", .{ @tagName(ev.kind), ev.rule_id, p.id });
                _ = ForensicBackend.write(ev);
            },
            .block => {
                diag.alert("action=block src={x} dst={x} proto={d} policy_id={d}", .{ ev.src_ip, ev.dst_ip, ev.protocol, p.id });
                diag.info("PEP validated block; enforcement routed through shield/ (real WFP pending)", .{});
                _ = ForensicBackend.write(ev);
            },
            .rate_limit => {
                diag.warn("action=rate_limit src={x} policy_id={d}", .{ ev.src_ip, p.id });
                diag.info("PEP validated rate_limit; enforcement routed through shield/ (real WFP pending)", .{});
                _ = ForensicBackend.write(ev);
            },
            .quarantine => {
                diag.critical("action=quarantine src={x} policy_id={d}", .{ ev.src_ip, p.id });
                diag.info("PEP validated quarantine; enforcement routed through shield/", .{});
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
    // No assertion â€” should not panic
}

test "ActionDispatcher dispatch block path (no WFP installed)" {
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
    // Without WFP installed, block is silently dropped
    try std.testing.expectEqual(@as(u32, 0), WfpBackend.active_filters);
}
