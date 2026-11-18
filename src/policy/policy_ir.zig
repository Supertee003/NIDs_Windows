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
    // POLICY-EVAL-FULL: appended so existing numeric values stay stable.
    gte, // >=
    lte, // <=
};

pub const Predicate = struct {
    field: FieldKind,
    op: Op,
    value_int: u64 = 0,
    value_str: []const u8 = "",
    /// For `.in` on numeric fields: the candidate set. When non-empty, this
    /// slice is owned by the PolicySet allocator and freed by `deinit`.
    /// When empty, `.in` is the single-value membership form (`== value_int`).
    value_list: []const u64 = &.{},
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
    /// Priority for evaluation order (higher first). POL-PRIO-070: the
    /// runtime JSON loader leaves this 0 unless an entry declares it, so
    /// existing files keep file order; authors gain the knob without a
    /// schema break. Mirrors the TS compiler's priority-DESC direction
    /// (TS-only specificity/rule_id tiebreaks do not apply here).
    priority: u32 = 0,
    /// The active legacy JSON loader does not verify a signed canonical
    /// policy envelope, so privileged actions remain untrusted by default.
    trusted: bool = false,
};

/// Actions that can constrain traffic or require privileged authorization.
/// Detection and unsigned policy data may describe them, but they must not
/// cross the PEP boundary as authorized requests.
pub fn requiresTrustedAuthorization(action: Action) bool {
    return switch (action) {
        .rate_limit, .block, .quarantine, .escalate => true,
        .pass, .log, .alert => false,
    };
}

/// SLICE-C-LAB: actions that can mutate host state (install a filter /
/// throttle) when handed to the Rust PEP. Exact scope of the prevention
/// gate master switch: while the gate is closed these actions never reach
/// the provider boundary. `.escalate` is authorization-gated but not
/// host-mutating; alert/log/pass keep their detection-only flow.
pub fn isHostMutating(action: Action) bool {
    return switch (action) {
        .rate_limit, .block, .quarantine => true,
        .pass, .log, .alert, .escalate => false,
    };
}

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
                for (c.predicates) |pred| {
                    // POLICY-EVAL-FULL: `.in` candidate sets are
                    // allocator-owned when non-empty (see Predicate).
                    if (pred.value_list.len > 0) self.allocator.free(pred.value_list);
                }
                self.allocator.free(c.predicates);
            }
            self.allocator.free(p.condition.clauses);
        }
        self.policies.deinit();
    }

    pub fn add(self: *PolicySet, p: Policy) !void {
        try self.policies.append(p);
    }

    /// Stable sort by priority descending (POL-PRIO-070). Equal priorities
    /// keep file order, so policy files that declare no priorities evaluate
    /// exactly as before. Insertion sort: policy sets are tiny, and
    /// std.mem.sort is not stable.
    pub fn sortByPriority(self: *PolicySet) void {
        const items = self.policies.items;
        var i: usize = 1;
        while (i < items.len) : (i += 1) {
            const key = items[i];
            var j = i;
            while (j > 0 and items[j - 1].priority < key.priority) : (j -= 1) {
                items[j] = items[j - 1];
            }
            items[j] = key;
        }
    }

    pub fn evaluate(self: *const PolicySet, ctx: EvalContext) ?Policy {
        for (self.policies.items) |p| {
            if (evalCondition(p.condition, ctx)) return p;
        }
        return null;
    }
};

// ============================================================================
// POLICY-EVAL-FULL: JSON policy-file loader
//
// Full-fidelity loader for the runtime policy file (configs/policies.json):
// every clause (OR), every predicate (AND), the full field/op vocabulary,
// string operands, and `.in` value lists are preserved. Malformed entries
// are rejected with a counted reason and are never silently reshaped (the
// previous inline loader truncated conditions to the first clause/predicate,
// mapped gte -> gt, and fell back to .kind/.eq on unknown names).
// ============================================================================

pub const PolicyLoadLimits = struct {
    /// Max OR clauses per condition.
    pub const max_clauses: usize = 8;
    /// Max AND predicates per clause.
    pub const max_predicates_per_clause: usize = 8;
    /// Max candidates in an `.in` value list.
    pub const max_in_values: usize = 64;
};

pub const JsonLoadReport = struct {
    loaded: u32 = 0,
    rejected: u32 = 0,
    /// Id of the first rejected entry (0 when unknown) plus a static reason
    /// keyword: parse | shape | id | name | action | severity | ttl |
    /// condition | clause | predicate | field | op | value | limit | add |
    /// oom.
    first_reject_id: u32 = 0,
    first_reject_reason: ?[]const u8 = null,
};

/// A loaded PolicySet plus the parsed JSON document backing its string
/// operands (`Predicate.value_str` slices point into it).
pub const LoadedPolicySet = struct {
    ps: PolicySet,
    doc: ?std.json.Parsed(std.json.Value) = null,
    report: JsonLoadReport = .{},

    pub fn deinit(self: *LoadedPolicySet) void {
        self.ps.deinit();
        if (self.doc) |*d| d.deinit();
        self.* = undefined;
    }
};

const EntryError = error{
    Shape,
    Id,
    Name,
    Action,
    Severity,
    Ttl,
    Condition,
    Clause,
    Predicate,
    Field,
    Op,
    Value,
    Limit,
    OutOfMemory,
};

/// Load a policy-file document (`{ "policies": [ ... ] }`). Always returns a
/// usable LoadedPolicySet: failures are reported via `report`, and healthy
/// entries still load (one bad entry never voids the set).
pub fn loadPolicySetFromJson(allocator: std.mem.Allocator, bytes: []const u8) LoadedPolicySet {
    var out = LoadedPolicySet{ .ps = PolicySet.init(allocator) };
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, bytes, .{}) catch {
        out.report = .{ .rejected = 1, .first_reject_reason = "parse" };
        return out;
    };
    if (parsed.value != .object) {
        parsed.deinit();
        out.report = .{ .rejected = 1, .first_reject_reason = "shape" };
        return out;
    }
    const policies_val = parsed.value.object.get("policies") orelse {
        parsed.deinit();
        out.report = .{ .rejected = 1, .first_reject_reason = "shape" };
        return out;
    };
    if (policies_val != .array) {
        parsed.deinit();
        out.report = .{ .rejected = 1, .first_reject_reason = "shape" };
        return out;
    }
    const items = policies_val.array.items;
    // Keep the parsed document alive: value_str slices point into it.
    out.doc = parsed;

    for (items) |item| {
        // Parse each entry into arena-backed structures first; a rejection
        // frees the whole attempt and never touches `out.ps`.
        var arena_state = std.heap.ArenaAllocator.init(allocator);
        defer arena_state.deinit();
        const entry = parsePolicyEntry(arena_state.allocator(), item) catch |err| {
            out.report.rejected += 1;
            if (out.report.first_reject_reason == null) {
                out.report.first_reject_reason = rejectReason(err);
                out.report.first_reject_id = rejectIdOf(item);
            }
            continue;
        };
        // Commit: deep-copy into the PolicySet allocator.
        const final = dupePolicy(allocator, entry) catch {
            out.report.rejected += 1;
            if (out.report.first_reject_reason == null) {
                out.report.first_reject_reason = "add";
                out.report.first_reject_id = entry.id;
            }
            continue;
        };
        out.ps.add(final) catch {
            freePolicy(allocator, final);
            out.report.rejected += 1;
            if (out.report.first_reject_reason == null) {
                out.report.first_reject_reason = "add";
                out.report.first_reject_id = entry.id;
            }
            continue;
        };
        out.report.loaded += 1;
    }
    return out;
}

fn rejectReason(err: EntryError) []const u8 {
    return switch (err) {
        error.Shape => "shape",
        error.Id => "id",
        error.Name => "name",
        error.Action => "action",
        error.Severity => "severity",
        error.Ttl => "ttl",
        error.Condition => "condition",
        error.Clause => "clause",
        error.Predicate => "predicate",
        error.Field => "field",
        error.Op => "op",
        error.Value => "value",
        error.Limit => "limit",
        error.OutOfMemory => "oom",
    };
}

fn rejectIdOf(item: std.json.Value) u32 {
    if (item != .object) return 0;
    const id_val = item.object.get("id") orelse return 0;
    if (id_val != .integer or id_val.integer < 0 or id_val.integer > std.math.maxInt(u32)) return 0;
    return @intCast(id_val.integer);
}

fn parseFieldName(s: []const u8) ?FieldKind {
    const Eql = std.mem.eql;
    if (Eql(u8, s, "kind")) return .kind;
    if (Eql(u8, s, "severity")) return .severity;
    if (Eql(u8, s, "source")) return .source;
    if (Eql(u8, s, "src_ip")) return .src_ip;
    if (Eql(u8, s, "dst_ip")) return .dst_ip;
    if (Eql(u8, s, "src_port")) return .src_port;
    if (Eql(u8, s, "dst_port")) return .dst_port;
    if (Eql(u8, s, "protocol")) return .protocol;
    if (Eql(u8, s, "sni")) return .sni;
    if (Eql(u8, s, "dns_name")) return .dns_name;
    if (Eql(u8, s, "http_uri")) return .http_uri;
    if (Eql(u8, s, "http_host")) return .http_host;
    if (Eql(u8, s, "rule_id")) return .rule_id;
    return null;
}

fn parseOpName(s: []const u8) ?Op {
    const Eql = std.mem.eql;
    if (Eql(u8, s, "eq")) return .eq;
    if (Eql(u8, s, "ne")) return .ne;
    if (Eql(u8, s, "match")) return .match;
    if (Eql(u8, s, "nomatch")) return .nomatch;
    if (Eql(u8, s, "lt")) return .lt;
    if (Eql(u8, s, "gt")) return .gt;
    if (Eql(u8, s, "gte")) return .gte;
    if (Eql(u8, s, "lte")) return .lte;
    if (Eql(u8, s, "in")) return .in;
    return null;
}

fn parseActionName(s: []const u8) ?Action {
    const Eql = std.mem.eql;
    if (Eql(u8, s, "block")) return .block;
    if (Eql(u8, s, "alert")) return .alert;
    if (Eql(u8, s, "rate_limit")) return .rate_limit;
    if (Eql(u8, s, "quarantine")) return .quarantine;
    if (Eql(u8, s, "log")) return .log;
    if (Eql(u8, s, "escalate")) return .escalate;
    return null;
}

/// Entry severity is metadata: recognized names map, anything else is
/// `.info` (unchanged from the previous loader).
fn parseSeverityName(s: []const u8) event.EventSeverity {
    const Eql = std.mem.eql;
    if (Eql(u8, s, "critical")) return .critical;
    if (Eql(u8, s, "alert")) return .alert;
    if (Eql(u8, s, "warning")) return .warning;
    if (Eql(u8, s, "error")) return .@"error";
    return .info;
}

fn parsePolicyEntry(a: std.mem.Allocator, item: std.json.Value) EntryError!Policy {
    if (item != .object) return error.Shape;
    const obj = item.object;

    const id_val = obj.get("id") orelse return error.Id;
    if (id_val != .integer or id_val.integer < 0 or id_val.integer > std.math.maxInt(u32)) return error.Id;
    const id: u32 = @intCast(id_val.integer);

    const name_val = obj.get("name") orelse return error.Name;
    if (name_val != .string) return error.Name;

    const action_val = obj.get("action") orelse return error.Action;
    if (action_val != .string) return error.Action;
    const action = parseActionName(action_val.string) orelse return error.Action;

    const sev_val = obj.get("severity") orelse return error.Severity;
    if (sev_val != .string) return error.Severity;

    const ttl_val = obj.get("ttl_sec") orelse return error.Ttl;
    if (ttl_val != .integer or ttl_val.integer < 0 or ttl_val.integer > std.math.maxInt(u32)) return error.Ttl;
    const ttl: u32 = @intCast(ttl_val.integer);

    // POL-PRIO-070: optional priority (default 0 = file order). Negative,
    // non-integer, or oversized values fall back per the original rules.
    var priority: u32 = 0;
    if (obj.get("priority")) |pri_val| {
        if (pri_val == .integer and pri_val.integer >= 0) {
            priority = if (pri_val.integer > std.math.maxInt(u32))
                std.math.maxInt(u32)
            else
                @intCast(pri_val.integer);
        }
    }

    const cond_val = obj.get("condition") orelse return error.Condition;
    const condition = try parseConditionJson(a, cond_val);

    return .{
        .id = id,
        .name = try a.dupe(u8, name_val.string),
        .condition = condition,
        .action = action,
        .severity = parseSeverityName(sev_val.string),
        .ttl_sec = ttl,
        .priority = priority,
    };
}

fn parseConditionJson(a: std.mem.Allocator, cond_val: std.json.Value) EntryError!Condition {
    if (cond_val != .object) return error.Condition;
    const clauses_val = cond_val.object.get("clauses") orelse return error.Condition;
    if (clauses_val != .array) return error.Condition;
    if (clauses_val.array.items.len == 0) return error.Condition;
    if (clauses_val.array.items.len > PolicyLoadLimits.max_clauses) return error.Limit;

    const clauses = try a.alloc(Clause, clauses_val.array.items.len);
    for (clauses_val.array.items, 0..) |clause_val, i| {
        if (clause_val != .object) return error.Clause;
        const preds_val = clause_val.object.get("predicates") orelse return error.Clause;
        if (preds_val != .array) return error.Clause;
        if (preds_val.array.items.len == 0) return error.Predicate;
        if (preds_val.array.items.len > PolicyLoadLimits.max_predicates_per_clause) return error.Limit;

        const preds = try a.alloc(Predicate, preds_val.array.items.len);
        for (preds_val.array.items, 0..) |pred_val, j| {
            preds[j] = try parsePredicateJson(a, pred_val);
        }
        clauses[i] = .{ .predicates = preds };
    }
    return .{ .clauses = clauses };
}

fn parsePredicateJson(a: std.mem.Allocator, pred_val: std.json.Value) EntryError!Predicate {
    if (pred_val != .object) return error.Predicate;
    const obj = pred_val.object;

    const field_val = obj.get("field") orelse return error.Field;
    if (field_val != .string) return error.Field;
    const field = parseFieldName(field_val.string) orelse return error.Field;

    const op_val = obj.get("op") orelse return error.Op;
    if (op_val != .string) return error.Op;
    const op = parseOpName(op_val.string) orelse return error.Op;

    var p = Predicate{ .field = field, .op = op };
    if (isStringField(field)) {
        // String domain: eq/ne/match/nomatch with a non-empty value_str.
        switch (op) {
            .eq, .ne, .match, .nomatch => {},
            else => return error.Op,
        }
        if (obj.get("value_int") != null or obj.get("values") != null) return error.Value;
        const vs = obj.get("value_str") orelse return error.Value;
        if (vs != .string or vs.string.len == 0) return error.Value;
        p.value_str = vs.string;
        return p;
    }

    // Numeric domain: comparison and membership operators only.
    switch (op) {
        .match, .nomatch => return error.Op,
        else => {},
    }
    if (obj.get("value_str") != null) return error.Value;
    if (op == .in) {
        if (obj.get("values")) |values_val| {
            if (values_val != .array) return error.Value;
            if (values_val.array.items.len == 0) return error.Value;
            if (values_val.array.items.len > PolicyLoadLimits.max_in_values) return error.Limit;
            const list = try a.alloc(u64, values_val.array.items.len);
            for (values_val.array.items, 0..) |cand, k| {
                if (cand != .integer or cand.integer < 0) return error.Value;
                list[k] = @intCast(cand.integer);
            }
            p.value_list = list;
            return p;
        }
        const vi = obj.get("value_int") orelse return error.Value;
        if (vi != .integer or vi.integer < 0) return error.Value;
        p.value_int = @intCast(vi.integer);
        return p;
    }
    if (obj.get("values") != null) return error.Value;
    const vi = obj.get("value_int") orelse return error.Value;
    if (vi != .integer or vi.integer < 0) return error.Value;
    p.value_int = @intCast(vi.integer);
    return p;
}

/// Deep-copy an arena-parsed entry into allocator-owned storage (the exact
/// ownership PolicySet.deinit expects). value_str keeps pointing into the
/// loaded JSON document.
fn dupePolicy(allocator: std.mem.Allocator, src: Policy) !Policy {
    const name = try allocator.dupe(u8, src.name);
    errdefer allocator.free(name);
    const clauses = try allocator.alloc(Clause, src.condition.clauses.len);
    var built_clauses: usize = 0;
    errdefer {
        for (clauses[0..built_clauses]) |clause| {
            for (clause.predicates) |pred| {
                if (pred.value_list.len > 0) allocator.free(pred.value_list);
            }
            allocator.free(clause.predicates);
        }
        allocator.free(clauses);
    }
    for (src.condition.clauses, 0..) |clause, i| {
        const preds = try allocator.alloc(Predicate, clause.predicates.len);
        var built_preds: usize = 0;
        errdefer {
            for (preds[0..built_preds]) |pred| {
                if (pred.value_list.len > 0) allocator.free(pred.value_list);
            }
            allocator.free(preds);
        }
        for (clause.predicates, 0..) |pred, j| {
            preds[j] = pred;
            preds[j].value_list = &.{}; // owned copy not materialised yet
            built_preds = j + 1;
            if (pred.value_list.len > 0) {
                const list = try allocator.alloc(u64, pred.value_list.len);
                @memcpy(list, pred.value_list);
                preds[j].value_list = list;
            }
        }
        clauses[i] = .{ .predicates = preds };
        built_clauses = i + 1;
    }
    return .{
        .id = src.id,
        .name = name,
        .condition = .{ .clauses = clauses },
        .action = src.action,
        .severity = src.severity,
        .ttl_sec = src.ttl_sec,
        .priority = src.priority,
    };
}

fn freePolicy(allocator: std.mem.Allocator, p: Policy) void {
    allocator.free(p.name);
    for (p.condition.clauses) |clause| {
        for (clause.predicates) |pred| {
            if (pred.value_list.len > 0) allocator.free(pred.value_list);
        }
        allocator.free(clause.predicates);
    }
    allocator.free(p.condition.clauses);
}

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

fn isStringField(f: FieldKind) bool {
    return switch (f) {
        .sni, .dns_name, .http_uri, .http_host => true,
        else => false,
    };
}

fn actualString(f: FieldKind, ctx: EvalContext) ?[]const u8 {
    return switch (f) {
        .sni => ctx.sni,
        .dns_name => ctx.dns_name,
        .http_uri => ctx.http_uri,
        .http_host => ctx.http_host,
        else => null,
    };
}

fn actualInt(f: FieldKind, ev: *const event.IpcEvent) u64 {
    return switch (f) {
        .kind => @intFromEnum(ev.kind),
        .severity => @intFromEnum(ev.severity),
        .source => @intFromEnum(ev.source),
        .src_ip => ev.src_ip,
        .dst_ip => ev.dst_ip,
        .src_port => ev.src_port,
        .dst_port => ev.dst_port,
        .protocol => ev.protocol,
        .rule_id => ev.rule_id,
        else => 0,
    };
}

/// POLICY-EVAL-FULL: a predicate is true only when the comparison is
/// meaningful (operator valid for the field domain, operand present) AND
/// satisfied. String fields (sni, dns_name, http_uri, http_host) compare
/// `value_str`; all other fields compare numerically. Everything else is
/// false — an accidental true must never fire a policy.
fn evalPred(p: Predicate, ctx: EvalContext) bool {
    if (isStringField(p.field)) {
        const s = actualString(p.field, ctx) orelse return false;
        if (p.value_str.len == 0) return false; // no pattern, no match
        return switch (p.op) {
            .eq => std.mem.eql(u8, s, p.value_str),
            .ne => !std.mem.eql(u8, s, p.value_str),
            .match => std.mem.indexOf(u8, s, p.value_str) != null,
            .nomatch => std.mem.indexOf(u8, s, p.value_str) == null,
            // numeric-only operators never apply to a string field
            .lt, .gt, .gte, .lte, .in => false,
        };
    }
    const actual = actualInt(p.field, ctx.ev);
    return switch (p.op) {
        .eq => actual == p.value_int,
        .ne => actual != p.value_int,
        .lt => actual < p.value_int,
        .gt => actual > p.value_int,
        .gte => actual >= p.value_int,
        .lte => actual <= p.value_int,
        // `in`: set membership when a list is supplied; otherwise the
        // single-value membership form (== value_int) used by policies.json.
        .in => if (p.value_list.len > 0) blk: {
            for (p.value_list) |cand| {
                if (actual == cand) break :blk true;
            }
            break :blk false;
        } else actual == p.value_int,
        // string-only operators never apply to a numeric field
        .match, .nomatch => false,
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

test "sortByPriority orders descending and keeps ties stable" {
    // POL-PRIO-070: files without priorities keep file order exactly;
    // declared priorities sort first-match order accordingly.
    var ps = PolicySet.init(std.testing.allocator);
    defer ps.deinit();
    for ([_]struct { id: u32, prio: u32 }{ .{ .id = 1, .prio = 0 }, .{ .id = 2, .prio = 10 }, .{ .id = 3, .prio = 0 }, .{ .id = 4, .prio = 10 } }) |spec| {
        const nm = try std.testing.allocator.dupe(u8, "p");
        const cl = try std.testing.allocator.alloc(Clause, 0);
        try ps.add(.{ .id = spec.id, .name = nm, .condition = .{ .clauses = cl }, .action = .log, .severity = .info, .ttl_sec = 0, .priority = spec.prio });
    }
    ps.sortByPriority();
    const ids = [_]u32{ ps.policies.items[0].id, ps.policies.items[1].id, ps.policies.items[2].id, ps.policies.items[3].id };
    try std.testing.expectEqualSlices(u32, &[_]u32{ 2, 4, 1, 3 }, &ids);
}

test "higher priority policy wins evaluation after sort" {
    var ps = PolicySet.init(std.testing.allocator);
    defer ps.deinit();
    var preds = try std.testing.allocator.alloc(Predicate, 1);
    preds[0] = .{ .field = .kind, .op = .eq, .value_int = @intFromEnum(event.EventKind.dns_query) };
    var clauses = try std.testing.allocator.alloc(Clause, 1);
    clauses[0] = .{ .predicates = preds };
    // Added second but higher priority: wins after sortByPriority.
    const nm_lo = try std.testing.allocator.dupe(u8, "low");
    const nm_hi = try std.testing.allocator.dupe(u8, "high");
    try ps.add(.{
        .id = 1, .name = nm_lo, .condition = .{ .clauses = clauses },
        .action = .log, .severity = .info, .ttl_sec = 0,
    });
    var preds2 = try std.testing.allocator.alloc(Predicate, 1);
    preds2[0] = .{ .field = .kind, .op = .eq, .value_int = @intFromEnum(event.EventKind.dns_query) };
    var clauses2 = try std.testing.allocator.alloc(Clause, 1);
    clauses2[0] = .{ .predicates = preds2 };
    try ps.add(.{
        .id = 2, .name = nm_hi, .condition = .{ .clauses = clauses2 },
        .action = .block, .severity = .alert, .ttl_sec = 0, .priority = 50,
    });
    ps.sortByPriority();
    var ev = event.IpcEvent.init(.dns_query);
    const p = ps.evaluate(EvalContext{ .ev = &ev }).?;
    try std.testing.expectEqual(@as(u32, 2), p.id);
    try std.testing.expectEqual(Action.block, p.action);
}

test "privileged policy actions require verified trust" {
    try std.testing.expect(requiresTrustedAuthorization(.block));
    try std.testing.expect(requiresTrustedAuthorization(.quarantine));
    try std.testing.expect(requiresTrustedAuthorization(.rate_limit));
    try std.testing.expect(!requiresTrustedAuthorization(.alert));
    try std.testing.expect(!requiresTrustedAuthorization(.log));
}

test "SLICE-C-LAB: isHostMutating covers exactly the host-mutation actions" {
    try std.testing.expect(isHostMutating(.block));
    try std.testing.expect(isHostMutating(.quarantine));
    try std.testing.expect(isHostMutating(.rate_limit));
    try std.testing.expect(!isHostMutating(.pass));
    try std.testing.expect(!isHostMutating(.log));
    try std.testing.expect(!isHostMutating(.alert));
    try std.testing.expect(!isHostMutating(.escalate));
    // Every host-mutating action is also authorization-gated (the converse
    // is not true: escalate is trust-gated but never host-mutating).
    for ([_]Action{ .rate_limit, .block, .quarantine }) |a| {
        try std.testing.expect(requiresTrustedAuthorization(a));
    }
}

test "PolicySet field kind match works" {    var ps = PolicySet.init(std.testing.allocator);
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

// ============================================================================
// POLICY-EVAL-FULL: evaluator semantics pins
//
// Rule: a predicate evaluates true only when the comparison is meaningful
// AND satisfied. String fields (sni, dns_name, http_uri, http_host) compare
// in the string domain; all other fields compare in the numeric domain.
// Ops used outside their domain, absent strings, and empty patterns are
// never a match (no accidental true).
// ============================================================================

/// Build a one-rule set whose single predicate is `p`, for evaluator pins.
fn testSetWithPredicate(pred: Predicate, action: Action) !PolicySet {
    var ps = PolicySet.init(std.testing.allocator);
    errdefer ps.deinit();
    const preds = try std.testing.allocator.alloc(Predicate, 1);
    preds[0] = pred;
    const clauses = try std.testing.allocator.alloc(Clause, 1);
    clauses[0] = .{ .predicates = preds };
    try ps.add(.{
        .id = 1,
        .name = try std.testing.allocator.dupe(u8, "pin"),
        .condition = .{ .clauses = clauses },
        .action = action,
        .severity = .alert,
        .ttl_sec = 0,
    });
    return ps;
}

test "POLICY-EVAL-FULL: eq on a string field compares the string domain only" {
    var ps = try testSetWithPredicate(.{ .field = .sni, .op = .eq, .value_str = "x.com" }, .block);
    defer ps.deinit();
    var ev = event.IpcEvent.init(.tls_hello);
    // Absent SNI: nothing to compare against, never a match.
    try std.testing.expect(ps.evaluate(.{ .ev = &ev }) == null);
    // Present but different SNI: no match.
    try std.testing.expect(ps.evaluate(.{ .ev = &ev, .sni = "other.com" }) == null);
    // Exact SNI: match.
    const m = ps.evaluate(.{ .ev = &ev, .sni = "x.com" });
    try std.testing.expect(m != null);
    if (m) |pol| try std.testing.expectEqual(Action.block, pol.action);
}

test "POLICY-EVAL-FULL: ne on a string field is real inequality" {
    var ps = try testSetWithPredicate(.{ .field = .sni, .op = .ne, .value_str = "good.com" }, .alert);
    defer ps.deinit();
    var ev = event.IpcEvent.init(.tls_hello);
    // Different SNI satisfies `ne`.
    const m = ps.evaluate(.{ .ev = &ev, .sni = "bad.com" });
    try std.testing.expect(m != null);
    if (m) |pol| try std.testing.expectEqual(Action.alert, pol.action);
    // Equal SNI must not satisfy `ne`.
    try std.testing.expect(ps.evaluate(.{ .ev = &ev, .sni = "good.com" }) == null);
    // Absent string: no meaningful inequality, no match.
    try std.testing.expect(ps.evaluate(.{ .ev = &ev }) == null);
}

test "POLICY-EVAL-FULL: match with an empty pattern never matches" {
    var ps = try testSetWithPredicate(.{ .field = .sni, .op = .match, .value_str = "" }, .block);
    defer ps.deinit();
    var ev = event.IpcEvent.init(.tls_hello);
    try std.testing.expect(ps.evaluate(.{ .ev = &ev, .sni = "anything.example" }) == null);
    try std.testing.expect(ps.evaluate(.{ .ev = &ev }) == null);
}

test "POLICY-EVAL-FULL: nomatch on a numeric field never matches" {
    var ps = try testSetWithPredicate(.{ .field = .kind, .op = .nomatch, .value_str = "x" }, .block);
    defer ps.deinit();
    var ev = event.IpcEvent.init(.dns_query);
    try std.testing.expect(ps.evaluate(.{ .ev = &ev }) == null);
}

test "POLICY-EVAL-FULL: nomatch with an absent string never matches" {
    var ps = try testSetWithPredicate(.{ .field = .sni, .op = .nomatch, .value_str = "evil.com" }, .block);
    defer ps.deinit();
    var ev = event.IpcEvent.init(.tls_hello);
    // No SNI on the event: absence is not evidence of non-containment.
    try std.testing.expect(ps.evaluate(.{ .ev = &ev }) == null);
    // Present, non-containing SNI: nomatch is meaningful and satisfied.
    const m = ps.evaluate(.{ .ev = &ev, .sni = "clean.example" });
    try std.testing.expect(m != null);
    // Present, containing SNI: nomatch fails.
    try std.testing.expect(ps.evaluate(.{ .ev = &ev, .sni = "totally.evil.com" }) == null);
}

test "POLICY-EVAL-FULL: numeric-only op on a string field never matches" {
    var ps = try testSetWithPredicate(.{ .field = .sni, .op = .lt, .value_int = 5 }, .block);
    defer ps.deinit();
    var ev = event.IpcEvent.init(.tls_hello);
    try std.testing.expect(ps.evaluate(.{ .ev = &ev, .sni = "a" }) == null);
    try std.testing.expect(ps.evaluate(.{ .ev = &ev }) == null);
}

test "POLICY-EVAL-FULL: gte is inclusive at the boundary" {
    // Regression pin for live configs/policies.json rule 1 (severity gte 6,
    // block): EventSeverity.critical == 6 must be inside the boundary.
    var ps = try testSetWithPredicate(.{ .field = .severity, .op = .gte, .value_int = 6 }, .block);
    defer ps.deinit();
    var ev = event.IpcEvent.init(.dns_query);
    ev.severity = .critical; // 6
    try std.testing.expect(ps.evaluate(.{ .ev = &ev }) != null);
    ev.severity = .@"error"; // 5
    try std.testing.expect(ps.evaluate(.{ .ev = &ev }) == null);
    ev.severity = .emergency; // 8
    try std.testing.expect(ps.evaluate(.{ .ev = &ev }) != null);
}

test "POLICY-EVAL-FULL: lte is inclusive at the boundary" {
    var ps = try testSetWithPredicate(.{ .field = .severity, .op = .lte, .value_int = 3 }, .log);
    defer ps.deinit();
    var ev = event.IpcEvent.init(.dns_query);
    ev.severity = .notice; // 3
    try std.testing.expect(ps.evaluate(.{ .ev = &ev }) != null);
    ev.severity = .warning; // 4
    try std.testing.expect(ps.evaluate(.{ .ev = &ev }) == null);
    ev.severity = .trace; // 0
    try std.testing.expect(ps.evaluate(.{ .ev = &ev }) != null);
}

test "POLICY-EVAL-FULL: in membership over a value list" {
    var ps = PolicySet.init(std.testing.allocator);
    defer ps.deinit();
    const preds = try std.testing.allocator.alloc(Predicate, 1);
    const list = try std.testing.allocator.alloc(u64, 3);
    list[0] = @intFromEnum(event.EventKind.dns_query); // 20
    list[1] = @intFromEnum(event.EventKind.dns_response); // 21
    list[2] = @intFromEnum(event.EventKind.tls_hello); // 24
    preds[0] = .{ .field = .kind, .op = .in, .value_list = list };
    const clauses = try std.testing.allocator.alloc(Clause, 1);
    clauses[0] = .{ .predicates = preds };
    try ps.add(.{
        .id = 1,
        .name = try std.testing.allocator.dupe(u8, "kind_membership"),
        .condition = .{ .clauses = clauses },
        .action = .log,
        .severity = .info,
        .ttl_sec = 0,
    });
    var ev = event.IpcEvent.init(.dns_response);
    try std.testing.expect(ps.evaluate(.{ .ev = &ev }) != null);
    ev = event.IpcEvent.init(.http_request); // 22, not in the list
    try std.testing.expect(ps.evaluate(.{ .ev = &ev }) == null);
    ev = event.IpcEvent.init(.tls_hello);
    try std.testing.expect(ps.evaluate(.{ .ev = &ev }) != null);
}

test "POLICY-EVAL-FULL: in with a single value stays membership of one" {
    // Live configs/policies.json rule 5 shape: kind `in` {70}.
    var ps = try testSetWithPredicate(.{ .field = .kind, .op = .in, .value_int = 70 }, .log);
    defer ps.deinit();
    var ev = event.IpcEvent.init(.etw_process_create); // 70
    try std.testing.expect(ps.evaluate(.{ .ev = &ev }) != null);
    ev = event.IpcEvent.init(.injection_detected); // 77
    try std.testing.expect(ps.evaluate(.{ .ev = &ev }) == null);
}

// ============================================================================
// POLICY-EVAL-FULL: JSON loader pins
//
// The loader is full-fidelity: every clause (OR), every predicate (AND),
// the full field/op vocabulary, string operands (`value_str`), `.in` value
// lists. Malformed entries are rejected with a counted reason — loudly —
// and never silently reshaped; one bad entry never voids the set.
// ============================================================================

test "POLICY-EVAL-FULL: loader preserves multi-clause OR and multi-predicate AND" {
    const json =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": 1,
        \\      "name": "multi",
        \\      "condition": { "clauses": [
        \\        { "predicates": [
        \\            { "field": "severity", "op": "gte", "value_int": 6 },
        \\            { "field": "rule_id", "op": "gt", "value_int": 0 }
        \\        ] },
        \\        { "predicates": [
        \\            { "field": "sni", "op": "match", "value_str": "evil.com" }
        \\        ] }
        \\      ] },
        \\      "action": "block",
        \\      "severity": "alert",
        \\      "ttl_sec": 300
        \\    }
        \\  ]
        \\}
    ;
    var loaded = loadPolicySetFromJson(std.testing.allocator, json);
    defer loaded.deinit();
    try std.testing.expectEqual(@as(u32, 1), loaded.report.loaded);
    try std.testing.expectEqual(@as(u32, 0), loaded.report.rejected);
    try std.testing.expectEqual(@as(usize, 1), loaded.ps.policies.items.len);
    // AND: severity 6 alone must not satisfy clause 1 (rule_id == 0).
    var ev = event.IpcEvent.init(.dns_query);
    ev.severity = .critical;
    ev.rule_id = 0;
    try std.testing.expect(loaded.ps.evaluate(.{ .ev = &ev }) == null);
    // Clause 1 fully satisfied.
    ev.rule_id = 7;
    try std.testing.expect(loaded.ps.evaluate(.{ .ev = &ev }) != null);
    // OR: the second clause alone matches.
    var ev2 = event.IpcEvent.init(.tls_hello);
    const m = loaded.ps.evaluate(.{ .ev = &ev2, .sni = "x.evil.com" });
    try std.testing.expect(m != null);
}

test "POLICY-EVAL-FULL: loader in values array is real membership" {
    const json =
        \\{
        \\  "policies": [
        \\    { "id": 2, "name": "kinds", "condition": { "clauses": [
        \\        { "predicates": [ { "field": "kind", "op": "in", "values": [20, 21, 24] } ] }
        \\    ] }, "action": "log", "severity": "info", "ttl_sec": 0 }
        \\  ]
        \\}
    ;
    var loaded = loadPolicySetFromJson(std.testing.allocator, json);
    defer loaded.deinit();
    try std.testing.expectEqual(@as(u32, 1), loaded.report.loaded);
    var ev = event.IpcEvent.init(.dns_response); // 21
    try std.testing.expect(loaded.ps.evaluate(.{ .ev = &ev }) != null);
    ev = event.IpcEvent.init(.http_request); // 22
    try std.testing.expect(loaded.ps.evaluate(.{ .ev = &ev }) == null);
}

test "POLICY-EVAL-FULL: one bad entry never voids the set" {
    const json =
        \\{
        \\  "policies": [
        \\    { "id": 10, "name": "badfield", "condition": { "clauses": [
        \\        { "predicates": [ { "field": "bogus", "op": "eq", "value_int": 1 } ] }
        \\    ] }, "action": "log", "severity": "info", "ttl_sec": 0 },
        \\    { "id": 11, "name": "badop", "condition": { "clauses": [
        \\        { "predicates": [ { "field": "kind", "op": "regex", "value_int": 1 } ] }
        \\    ] }, "action": "log", "severity": "info", "ttl_sec": 0 },
        \\    { "id": 12, "name": "good", "condition": { "clauses": [
        \\        { "predicates": [ { "field": "kind", "op": "eq", "value_int": 20 } ] }
        \\    ] }, "action": "log", "severity": "info", "ttl_sec": 0 }
        \\  ]
        \\}
    ;
    var loaded = loadPolicySetFromJson(std.testing.allocator, json);
    defer loaded.deinit();
    try std.testing.expectEqual(@as(u32, 1), loaded.report.loaded);
    try std.testing.expectEqual(@as(u32, 2), loaded.report.rejected);
    try std.testing.expectEqual(@as(u32, 10), loaded.report.first_reject_id);
    try std.testing.expectEqualStrings("field", loaded.report.first_reject_reason.?);
    var ev = event.IpcEvent.init(.dns_query);
    const m = loaded.ps.evaluate(.{ .ev = &ev });
    try std.testing.expect(m != null);
    if (m) |pol| try std.testing.expectEqual(@as(u32, 12), pol.id);
}

test "POLICY-EVAL-FULL: cross-domain and empty payloads are rejected" {
    const json =
        \\{
        \\  "policies": [
        \\    { "id": 20, "name": "match_no_pattern", "condition": { "clauses": [
        \\        { "predicates": [ { "field": "sni", "op": "match" } ] }
        \\    ] }, "action": "log", "severity": "info", "ttl_sec": 0 },
        \\    { "id": 21, "name": "string_field_numeric_payload", "condition": { "clauses": [
        \\        { "predicates": [ { "field": "sni", "op": "eq", "value_int": 5 } ] }
        \\    ] }, "action": "log", "severity": "info", "ttl_sec": 0 },
        \\    { "id": 22, "name": "numeric_field_string_payload", "condition": { "clauses": [
        \\        { "predicates": [ { "field": "kind", "op": "eq", "value_str": "x" } ] }
        \\    ] }, "action": "log", "severity": "info", "ttl_sec": 0 },
        \\    { "id": 23, "name": "empty_in_list", "condition": { "clauses": [
        \\        { "predicates": [ { "field": "kind", "op": "in", "values": [] } ] }
        \\    ] }, "action": "log", "severity": "info", "ttl_sec": 0 }
        \\  ]
        \\}
    ;
    var loaded = loadPolicySetFromJson(std.testing.allocator, json);
    defer loaded.deinit();
    try std.testing.expectEqual(@as(u32, 0), loaded.report.loaded);
    try std.testing.expectEqual(@as(u32, 4), loaded.report.rejected);
    try std.testing.expectEqual(@as(u32, 20), loaded.report.first_reject_id);
    try std.testing.expectEqualStrings("value", loaded.report.first_reject_reason.?);
}

test "POLICY-EVAL-FULL: malformed id, ttl and value are rejected, not crashed" {
    const json =
        \\{
        \\  "policies": [
        \\    { "id": -1, "name": "neg_id", "condition": { "clauses": [
        \\        { "predicates": [ { "field": "kind", "op": "eq", "value_int": 1 } ] }
        \\    ] }, "action": "log", "severity": "info", "ttl_sec": 0 },
        \\    { "id": 5000000000, "name": "big_id", "condition": { "clauses": [
        \\        { "predicates": [ { "field": "kind", "op": "eq", "value_int": 1 } ] }
        \\    ] }, "action": "log", "severity": "info", "ttl_sec": 0 },
        \\    { "id": 30, "name": "neg_ttl", "condition": { "clauses": [
        \\        { "predicates": [ { "field": "kind", "op": "eq", "value_int": 1 } ] }
        \\    ] }, "action": "log", "severity": "info", "ttl_sec": -5 },
        \\    { "id": 31, "name": "neg_value", "condition": { "clauses": [
        \\        { "predicates": [ { "field": "kind", "op": "eq", "value_int": -2 } ] }
        \\    ] }, "action": "log", "severity": "info", "ttl_sec": 0 }
        \\  ]
        \\}
    ;
    var loaded = loadPolicySetFromJson(std.testing.allocator, json);
    defer loaded.deinit();
    try std.testing.expectEqual(@as(u32, 0), loaded.report.loaded);
    try std.testing.expectEqual(@as(u32, 4), loaded.report.rejected);
    try std.testing.expectEqualStrings("id", loaded.report.first_reject_reason.?);
}

test "POLICY-EVAL-FULL: condition-less and empty conditions are rejected" {
    const json =
        \\{
        \\  "policies": [
        \\    { "id": 40, "name": "no_condition", "action": "log", "severity": "info", "ttl_sec": 0 },
        \\    { "id": 41, "name": "empty_clauses", "condition": { "clauses": [] }, "action": "log", "severity": "info", "ttl_sec": 0 },
        \\    { "id": 42, "name": "empty_predicates", "condition": { "clauses": [
        \\        { "predicates": [] }
        \\    ] }, "action": "log", "severity": "info", "ttl_sec": 0 }
        \\  ]
        \\}
    ;
    var loaded = loadPolicySetFromJson(std.testing.allocator, json);
    defer loaded.deinit();
    try std.testing.expectEqual(@as(u32, 0), loaded.report.loaded);
    try std.testing.expectEqual(@as(u32, 3), loaded.report.rejected);
    try std.testing.expectEqualStrings("condition", loaded.report.first_reject_reason.?);
    try std.testing.expectEqual(@as(usize, 0), loaded.ps.policies.items.len);
}

test "POLICY-EVAL-FULL: garbage or mis-shaped JSON loads as an empty set" {
    var l1 = loadPolicySetFromJson(std.testing.allocator, "{ not json");
    defer l1.deinit();
    try std.testing.expectEqual(@as(u32, 0), l1.report.loaded);
    try std.testing.expectEqual(@as(u32, 1), l1.report.rejected);
    try std.testing.expectEqualStrings("parse", l1.report.first_reject_reason.?);
    try std.testing.expectEqual(@as(usize, 0), l1.ps.policies.items.len);

    var l2 = loadPolicySetFromJson(std.testing.allocator, "{\"policies\": 42}");
    defer l2.deinit();
    try std.testing.expectEqualStrings("shape", l2.report.first_reject_reason.?);
    try std.testing.expectEqual(@as(usize, 0), l2.ps.policies.items.len);
}

test "POLICY-EVAL-FULL: loader caps reject oversized conditions" {
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    try buf.appendSlice("{\"policies\":[{\"id\":50,\"name\":\"big\",\"condition\":{\"clauses\":[{\"predicates\":[");
    for (0..9) |i| {
        if (i > 0) try buf.appendSlice(",");
        try buf.appendSlice("{\"field\":\"kind\",\"op\":\"eq\",\"value_int\":1}");
    }
    try buf.appendSlice("]}]},\"action\":\"log\",\"severity\":\"info\",\"ttl_sec\":0}]}");
    var loaded = loadPolicySetFromJson(std.testing.allocator, buf.items);
    defer loaded.deinit();
    try std.testing.expectEqual(@as(u32, 0), loaded.report.loaded);
    try std.testing.expectEqual(@as(u32, 1), loaded.report.rejected);
    try std.testing.expectEqualStrings("limit", loaded.report.first_reject_reason.?);
}

test "POLICY-EVAL-FULL: value_str survives the caller freeing the input bytes" {
    const json = "{\"policies\":[{\"id\":9,\"name\":\"snimatch\",\"condition\":{\"clauses\":[{\"predicates\":[{\"field\":\"sni\",\"op\":\"match\",\"value_str\":\"evil.com\"}]}]},\"action\":\"log\",\"severity\":\"info\",\"ttl_sec\":0}]}";
    const buf = try std.testing.allocator.dupe(u8, json);
    var loaded = loadPolicySetFromJson(std.testing.allocator, buf);
    defer loaded.deinit();
    // The loader keeps its own parsed copy; the caller's buffer may go away.
    std.testing.allocator.free(buf);
    var ev = event.IpcEvent.init(.tls_hello);
    try std.testing.expect(loaded.ps.evaluate(.{ .ev = &ev, .sni = "sub.evil.com" }) != null);
    try std.testing.expect(loaded.ps.evaluate(.{ .ev = &ev, .sni = "good.com" }) == null);
}

test "POLICY-EVAL-FULL: live policies.json rule 1 boundary blocks critical severity" {
    // Mirror of configs/policies.json rules 1 and 5 in file order.
    const json =
        \\{
        \\  "policies": [
        \\    { "id": 1, "name": "block_critical_threats", "condition": { "clauses": [
        \\        { "predicates": [ { "field": "severity", "op": "gte", "value_int": 6 } ] }
        \\    ] }, "action": "block", "severity": "alert", "ttl_sec": 3600 },
        \\    { "id": 5, "name": "log_etw_events", "condition": { "clauses": [
        \\        { "predicates": [ { "field": "kind", "op": "in", "value_int": 70 } ] }
        \\    ] }, "action": "log", "severity": "info", "ttl_sec": 0 }
        \\  ]
        \\}
    ;
    var loaded = loadPolicySetFromJson(std.testing.allocator, json);
    defer loaded.deinit();
    try std.testing.expectEqual(@as(u32, 2), loaded.report.loaded);
    // EventSeverity.critical == 6 is INSIDE `gte 6` (was outside while the
    // loader mapped gte -> gt).
    var ev = event.IpcEvent.init(.dns_query);
    ev.severity = .critical;
    const m = loaded.ps.evaluate(.{ .ev = &ev });
    try std.testing.expect(m != null);
    if (m) |pol| try std.testing.expectEqual(@as(u32, 1), pol.id);
    // ETW kind 70 still lands on rule 5's single-value `in`.
    var ev2 = event.IpcEvent.init(.etw_process_create);
    const m2 = loaded.ps.evaluate(.{ .ev = &ev2 });
    try std.testing.expect(m2 != null);
    if (m2) |pol| try std.testing.expectEqual(@as(u32, 5), pol.id);
}

test "POLICY-EVAL-FULL: loader keeps POL-PRIO-070 priority clamping" {
    const json =
        \\{
        \\  "policies": [
        \\    { "id": 60, "name": "neg_prio", "priority": -7, "condition": { "clauses": [
        \\        { "predicates": [ { "field": "kind", "op": "eq", "value_int": 1 } ] }
        \\    ] }, "action": "log", "severity": "info", "ttl_sec": 0 },
        \\    { "id": 61, "name": "big_prio", "priority": 5000000000, "condition": { "clauses": [
        \\        { "predicates": [ { "field": "kind", "op": "eq", "value_int": 1 } ] }
        \\    ] }, "action": "log", "severity": "info", "ttl_sec": 0 },
        \\    { "id": 62, "name": "no_prio", "condition": { "clauses": [
        \\        { "predicates": [ { "field": "kind", "op": "eq", "value_int": 1 } ] }
        \\    ] }, "action": "log", "severity": "info", "ttl_sec": 0 }
        \\  ]
        \\}
    ;
    var loaded = loadPolicySetFromJson(std.testing.allocator, json);
    defer loaded.deinit();
    try std.testing.expectEqual(@as(u32, 3), loaded.report.loaded);
    try std.testing.expectEqual(@as(u32, 0), loaded.ps.policies.items[0].priority);
    try std.testing.expectEqual(@as(u32, std.math.maxInt(u32)), loaded.ps.policies.items[1].priority);
    try std.testing.expectEqual(@as(u32, 0), loaded.ps.policies.items[2].priority);
}
