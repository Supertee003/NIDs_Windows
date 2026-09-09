// I16 - Policy IR (DSL Compiler)
// AEGIS NIDS v5.0+ â€” Policy intermediate representation
//
// Supports a tiny DSL with rules of the form:
//   rule NAME {
//     match { kind=dns_query AND sni~="evil.com" } OR
//           { kind=tls_hello AND sni~="bad.tld" }
//     action { block }
//     severity alert
//     ttl 3600
//   }
//
// Compiled into a Policy struct (an AST) for fast evaluation.

const std = @import("std");
const event = @import("../contract/event.zig");

pub const Action = enum(u8) {
    pass = 0,
    log = 1,
    alert = 2,
    rate_limit = 3,
    block = 4,
    quarantine = 5,
    escalate = 6,
};

pub const FieldKind = enum(u8) {
    kind,
    severity,
    source,
    src_ip,
    dst_ip,
    src_port,
    dst_port,
    protocol,
    sni,
    dns_name,
    http_uri,
    http_host,
    rule_id,
};

pub const Op = enum(u8) {
    eq, // ==
    ne, // !=
    match, // =~
    nomatch, // !~
    lt, // <
    gt, // >
    in, // in { ... }
};

pub const Predicate = struct {
    field: FieldKind,
    op: Op,
    value_int: u64 = 0,
    value_str: []const u8 = "",
};

pub const Clause = struct {
    predicates: []Predicate, // AND
};

pub const Condition = struct {
    clauses: []Clause, // OR
};

pub const Policy = struct {
    id: u32,
    name: []const u8,
    condition: Condition,
    action: Action,
    severity: event.EventSeverity,
    ttl_sec: u32,
};

pub const PolicySet = struct {
    policies: std.ArrayList(Policy),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) PolicySet {
        return .{
            .policies = std.ArrayList(Policy).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *PolicySet) void {
        for (self.policies.items) |p| {
            self.allocator.free(p.name);
            for (p.condition.clauses) |c| {
                self.allocator.free(c.predicates);
            }
            self.allocator.free(p.condition.clauses);
        }
        self.policies.deinit();
    }

    pub fn add(self: *PolicySet, p: Policy) !void {
        try self.policies.append(p);
    }

    pub fn evaluate(self: *const PolicySet, ctx: EvalContext) ?Policy {
        for (self.policies.items) |p| {
            if (evalCondition(p.condition, ctx)) return p;
        }
        return null;
    }
};

pub const EvalContext = struct {
    ev: *const event.IpcEvent,
    sni: ?[]const u8 = null,
    dns_name: ?[]const u8 = null,
    http_uri: ?[]const u8 = null,
    http_host: ?[]const u8 = null,
};

fn evalCondition(cond: Condition, ctx: EvalContext) bool {
    for (cond.clauses) |c| {
        if (evalClause(c, ctx)) return true;
    }
    return cond.clauses.len == 0;
}

fn evalClause(c: Clause, ctx: EvalContext) bool {
    for (c.predicates) |p| {
        if (!evalPred(p, ctx)) return false;
    }
    return c.predicates.len > 0;
}

fn evalPred(p: Predicate, ctx: EvalContext) bool {
    const ev = ctx.ev;
    var actual_int: u64 = 0;
    var actual_str: ?[]const u8 = null;
    switch (p.field) {
        .kind => actual_int = @intFromEnum(ev.kind),
        .severity => actual_int = @intFromEnum(ev.severity),
        .source => actual_int = @intFromEnum(ev.source),
        .src_ip => actual_int = ev.src_ip,
        .dst_ip => actual_int = ev.dst_ip,
        .src_port => actual_int = ev.src_port,
        .dst_port => actual_int = ev.dst_port,
        .protocol => actual_int = ev.protocol,
        .sni => actual_str = ctx.sni,
        .dns_name => actual_str = ctx.dns_name,
        .http_uri => actual_str = ctx.http_uri,
        .http_host => actual_str = ctx.http_host,
        .rule_id => actual_int = ev.rule_id,
    }
    return switch (p.op) {
        .eq => actual_int == p.value_int or (actual_str != null and p.value_str.len > 0 and std.mem.eql(u8, actual_str.?, p.value_str)),
        .ne => actual_int != p.value_int and (actual_str == null or p.value_str.len == 0 or !std.mem.eql(u8, actual_str.?, p.value_str)),
        .match => if (actual_str) |s| std.mem.indexOf(u8, s, p.value_str) != null else false,
        .nomatch => if (actual_str) |s| std.mem.indexOf(u8, s, p.value_str) == null else true,
        .lt => actual_int < p.value_int,
        .gt => actual_int > p.value_int,
        .in => actual_int == p.value_int, // simplified
    };
}

// ============================================================================
// Tests
// ============================================================================
test "PolicySet evaluate single rule" {
    var ps = PolicySet.init(std.testing.allocator);
    defer ps.deinit();
    var preds = try std.testing.allocator.alloc(Predicate, 1);
    preds[0] = .{ .field = .kind, .op = .eq, .value_int = @intFromEnum(event.EventKind.dns_query) };
    var clauses = try std.testing.allocator.alloc(Clause, 1);
    clauses[0] = .{ .predicates = preds };
    try ps.add(.{
        .id = 1,
        .name = try std.testing.allocator.dupe(u8, "block_dns_evil"),
        .condition = .{ .clauses = clauses },
        .action = .block,
        .severity = .alert,
        .ttl_sec = 3600,
    });
    var ev = event.IpcEvent.init(.dns_query);
    const ctx = EvalContext{ .ev = &ev };
    const p = ps.evaluate(ctx).?;
    try std.testing.expectEqual(Action.block, p.action);
}

test "PolicySet no match returns null" {
    var ps = PolicySet.init(std.testing.allocator);
    defer ps.deinit();
    var preds = try std.testing.allocator.alloc(Predicate, 1);
    preds[0] = .{ .field = .kind, .op = .eq, .value_int = @intFromEnum(event.EventKind.dns_query) };
    var clauses = try std.testing.allocator.alloc(Clause, 1);
    clauses[0] = .{ .predicates = preds };
    try ps.add(.{
        .id = 1,
        .name = try std.testing.allocator.dupe(u8, "x"),
        .condition = .{ .clauses = clauses },
        .action = .block,
        .severity = .alert,
        .ttl_sec = 3600,
    });
    var ev = event.IpcEvent.init(.packet_captured);
    const ctx = EvalContext{ .ev = &ev };
    try std.testing.expect(ps.evaluate(ctx) == null);
}

test "PolicySet string match" {
    var ps = PolicySet.init(std.testing.allocator);
    defer ps.deinit();
    var preds = try std.testing.allocator.alloc(Predicate, 1);
    preds[0] = .{ .field = .sni, .op = .match, .value_str = "evil.com" };
    var clauses = try std.testing.allocator.alloc(Clause, 1);
    clauses[0] = .{ .predicates = preds };
    try ps.add(.{
        .id = 2,
        .name = try std.testing.allocator.dupe(u8, "block_tls_sni"),
        .condition = .{ .clauses = clauses },
        .action = .block,
        .severity = .alert,
        .ttl_sec = 3600,
    });
    var ev = event.IpcEvent.init(.tls_hello);
    const ctx = EvalContext{ .ev = &ev, .sni = "totally.evil.com" };
    const p = ps.evaluate(ctx).?;
    try std.testing.expectEqual(Action.block, p.action);
}

test "PolicySet multiple rules returns first match" {
    var ps = PolicySet.init(std.testing.allocator);
    defer ps.deinit();
    // Rule 1: matches dns_query
    var preds1 = try std.testing.allocator.alloc(Predicate, 1);
    preds1[0] = .{ .field = .kind, .op = .eq, .value_int = @intFromEnum(event.EventKind.dns_query) };
    var clauses1 = try std.testing.allocator.alloc(Clause, 1);
    clauses1[0] = .{ .predicates = preds1 };
    try ps.add(.{
        .id = 1,
        .name = try std.testing.allocator.dupe(u8, "first_match"),
        .condition = .{ .clauses = clauses1 },
        .action = .log,
        .severity = .info,
        .ttl_sec = 0,
    });
    // Rule 2: also matches dns_query
    var preds2 = try std.testing.allocator.alloc(Predicate, 1);
    preds2[0] = .{ .field = .kind, .op = .eq, .value_int = @intFromEnum(event.EventKind.dns_query) };
    var clauses2 = try std.testing.allocator.alloc(Clause, 1);
    clauses2[0] = .{ .predicates = preds2 };
    try ps.add(.{
        .id = 2,
        .name = try std.testing.allocator.dupe(u8, "second_match"),
        .condition = .{ .clauses = clauses2 },
        .action = .block,
        .severity = .alert,
        .ttl_sec = 3600,
    });
    var ev = event.IpcEvent.init(.dns_query);
    const ctx = EvalContext{ .ev = &ev };
    const p = ps.evaluate(ctx).?;
    // Returns first matching rule (log), not highest priority
    try std.testing.expectEqual(Action.log, p.action);
}

test "PolicySet empty evaluation returns null" {
    var ps = PolicySet.init(std.testing.allocator);
    defer ps.deinit();
    var ev = event.IpcEvent.init(.dns_query);
    const ctx = EvalContext{ .ev = &ev };
    try std.testing.expect(ps.evaluate(ctx) == null);
}

test "PolicySet field kind match works" {
    var ps = PolicySet.init(std.testing.allocator);
    defer ps.deinit();
    var preds = try std.testing.allocator.alloc(Predicate, 1);
    preds[0] = .{ .field = .kind, .op = .eq, .value_int = @intFromEnum(event.EventKind.tls_hello) };
    var clauses = try std.testing.allocator.alloc(Clause, 1);
    clauses[0] = .{ .predicates = preds };
    try ps.add(.{
        .id = 1,
        .name = try std.testing.allocator.dupe(u8, "tls_match"),
        .condition = .{ .clauses = clauses },
        .action = .alert,
        .severity = .warning,
        .ttl_sec = 600,
    });
    var ev = event.IpcEvent.init(.tls_hello);
    const ctx = EvalContext{ .ev = &ev };
    const p = ps.evaluate(ctx).?;
    try std.testing.expectEqual(Action.alert, p.action);
}
