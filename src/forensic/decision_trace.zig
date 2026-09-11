//! decision_trace.zig - AEGIS Security Decision Trace (T19 / Step 56)
//!
//! Every privileged action MUST be traceable back to its triggering source.
//! The mandatory trace chain (root cause order):
//!
//!   ACTION -> PEP REQUEST -> POLICY -> VERDICT -> EVIDENCE ->
//!   CORRELATION -> EVENT -> SOURCE
//!
//! The trace is written forward (action first), each subsequent link
//! naming the causal step that produced the previous one. append() is
//! order-enforced: a link may only be recorded at its position in the
//! chain, so a trace can never skip or reorder a link. Once all 8 links
//! are present the trace is complete().
//!
//! TraceStore holds the immutable traces and answers the audit question
//! "every privileged action traceable" by verifying a set of privileged
//! action ids all have a complete trace.
//!
//! Self-contained: imports std only. Fixed capacity, fails soft.

const std = @import("std");

pub const TRACE_LINK_COUNT: usize = 8;

pub const TraceLink = enum(u8) {
    action = 0,
    pep_request = 1,
    policy = 2,
    verdict = 3,
    evidence = 4,
    correlation = 5,
    event = 6,
    source = 7,

    pub fn label(self: TraceLink) []const u8 {
        return switch (self) {
            .action => "action",
            .pep_request => "pep_request",
            .policy => "policy",
            .verdict => "verdict",
            .evidence => "evidence",
            .correlation => "correlation",
            .event => "event",
            .source => "source",
        };
    }
};

pub const TRACE_CHAIN = [TRACE_LINK_COUNT]TraceLink{
    .action,
    .pep_request,
    .policy,
    .verdict,
    .evidence,
    .correlation,
    .event,
    .source,
};

pub const ActionKind = enum(u8) {
    allow = 0,
    alert = 1,
    block = 2,
    quarantine = 3,
    rate_limit = 4,
    log_only = 5,

    pub fn isPrivileged(self: ActionKind) bool {
        return self == .block or self == .quarantine or self == .rate_limit;
    }
};

pub const Entry = struct {
    link: TraceLink,
    ref_id: u64,
    detail: []const u8,
};

pub const DecisionTrace = struct {
    trace_id: u64 = 0,
    action_ref_id: u64 = 0,
    action_kind: ActionKind = .alert,
    created_ms: u64 = 0,
    entries: [TRACE_LINK_COUNT]Entry = undefined,
    count: usize = 0,

    pub fn append(self: *DecisionTrace, link: TraceLink, ref_id: u64, detail: []const u8) bool {
        if (self.count >= TRACE_LINK_COUNT) return false;
        if (link != TRACE_CHAIN[self.count]) return false; // strict order
        self.entries[self.count] = .{ .link = link, .ref_id = ref_id, .detail = detail };
        self.count += 1;
        return true;
    }

    pub fn complete(self: *const DecisionTrace) bool {
        return self.count == TRACE_LINK_COUNT;
    }

    pub fn rootSource(self: *const DecisionTrace) ?u64 {
        if (!self.complete()) return null;
        return self.entries[TRACE_LINK_COUNT - 1].ref_id;
    }
};

pub const MAX_TRACES: usize = 256;

pub const TracedSummary = struct {
    untraced: [MAX_TRACES]u64 = undefined,
    untraced_count: usize = 0,
    traced_count: usize = 0,
    all_traced: bool = true,
};

pub const TraceStore = struct {
    traces: [MAX_TRACES]DecisionTrace = undefined,
    trace_count: usize = 0,
    traced_action_ids: [MAX_TRACES]u64 = undefined,
    traced_ids_count: usize = 0,

    pub fn record(self: *TraceStore, trace: DecisionTrace) ?u64 {
        if (self.trace_count >= MAX_TRACES) return null; // fail soft
        self.traces[self.trace_count] = trace;
        self.trace_count += 1;
        return trace.trace_id;
    }

    pub fn registerAction(self: *TraceStore, action_id: u64) bool {
        if (self.traced_ids_count >= MAX_TRACES) return false;
        for (self.traced_action_ids[0..self.traced_ids_count]) |id| {
            if (id == action_id) return true; // already known
        }
        self.traced_action_ids[self.traced_ids_count] = action_id;
        self.traced_ids_count += 1;
        return true;
    }

    pub fn auditCoverage(self: *const TraceStore, privileged_action_ids: []const u64) TracedSummary {
        var s = TracedSummary{};
        for (privileged_action_ids) |pid| {
            var found = false;
            for (self.traced_action_ids[0..self.traced_ids_count]) |tid| {
                if (tid == pid) {
                    found = true;
                    break;
                }
            }
            if (found) {
                s.traced_count += 1;
            } else {
                if (s.untraced_count < MAX_TRACES) {
                    s.untraced[s.untraced_count] = pid;
                }
                s.untraced_count += 1;
                s.all_traced = false;
            }
        }
        return s;
    }
};

// ============================================================
// Tests
// ============================================================

fn buildTrace(trace_id: u64, action_id: u64) DecisionTrace {
    var t = DecisionTrace{ .trace_id = trace_id, .action_ref_id = action_id };
    const order = [_]TraceLink{ .action, .pep_request, .policy, .verdict, .evidence, .correlation, .event, .source };
    for (order, 0..) |link, i| {
        std.debug.assert(t.append(link, 1000 + @as(u64, i), "x"));
    }
    return t;
}

test "TRACE_CHAIN is the mandated eight links in order" {
    const want = [_][]const u8{
        "action",      "pep_request", "policy",         "verdict",
        "evidence",    "correlation", "event",          "source",
    };
    for (TRACE_CHAIN, want) |link, label| {
        try std.testing.expectEqualStrings(label, link.label());
    }
}

test "append enforces strict link order" {
    var t = DecisionTrace{};
    try std.testing.expectEqual(false, t.append(.pep_request, 1, "bad")); // must start with action
    try std.testing.expectEqual(true, t.append(.action, 1, "a"));
    try std.testing.expectEqual(false, t.append(.verdict, 2, "skip")); // cannot skip
    try std.testing.expectEqual(true, t.append(.pep_request, 2, "pr"));
    try std.testing.expectEqual(false, t.complete());
}

test "a fully appended trace is complete and roots to the source" {
    var t = buildTrace(7, 42);
    try std.testing.expectEqual(true, t.complete());
    try std.testing.expectEqual(@as(u64, 1007), t.rootSource().?);
}

test "duplicate final link cannot overflow the trace" {
    var t = buildTrace(1, 1);
    try std.testing.expectEqual(false, t.append(.source, 9999, "dup"));
    try std.testing.expectEqual(@as(u8, 8), @as(u8, @intCast(t.count)));
}

test "privileged actions must all be traced" {
    var store = TraceStore{};
    _ = store.record(buildTrace(1, 100));
    _ = store.record(buildTrace(2, 200));
    _ = store.registerAction(100);
    _ = store.registerAction(200);
    const privileged = [_]u64{ 100, 200, 300 }; // 300 never recorded
    const s = store.auditCoverage(&privileged);
    try std.testing.expectEqual(false, s.all_traced);
    try std.testing.expectEqual(@as(usize, 1), s.untraced_count);
    try std.testing.expectEqual(@as(u64, 300), s.untraced[0]);
}

test "fully traced privileged action set passes the audit" {
    var store = TraceStore{};
    _ = store.record(buildTrace(1, 100));
    _ = store.registerAction(100);
    const privileged = [_]u64{100};
    const s = store.auditCoverage(&privileged);
    try std.testing.expectEqual(true, s.all_traced);
    try std.testing.expectEqual(@as(usize, 0), s.untraced_count);
}

test "only block/quarantine/rate_limit are privileged" {
    try std.testing.expectEqual(false, ActionKind.allow.isPrivileged());
    try std.testing.expectEqual(true, ActionKind.block.isPrivileged());
    try std.testing.expectEqual(true, ActionKind.quarantine.isPrivileged());
    try std.testing.expectEqual(true, ActionKind.rate_limit.isPrivileged());
    try std.testing.expectEqual(false, ActionKind.alert.isPrivileged());
}

// ============================================================
// SecurityDecisionTrace — 128-byte decision record (REBUILD-003 restore)
//
// Restores the PATCH-34 runtime API consumed by src/main.zig: a fixed-layout
// trace linking event → detection → policy → PEP → audit. Coexists with the
// graph-style DecisionTrace/TraceStore above; this one is the hot-path record.
// ============================================================

const event_mod = @import("../contract/event.zig");

pub const TRACE_MAGIC: u32 = 0x77acee01;
pub const TRACE_VERSION: u16 = 1;

/// Actor who initiated the decision
pub const TraceActor = enum(u8) {
    pipeline = 0, // automatic pipeline processing
    operator = 1, // manual operator action
    federation = 2, // cross-node federation
    recovery = 3, // system recovery
    _,
};

/// Reason the decision was made
pub const TraceReason = enum(u8) {
    none = 0,
    signature_match = 1,
    anomaly = 2,
    correlation = 3,
    policy_rule = 4,
    operator_override = 5,
    _,
};

/// Outcome of the decision
pub const TraceResult = enum(u8) {
    allow = 0,
    block = 1,
    rate_limit = 2,
    quarantine = 3,
    logged_only = 4,
    dropped = 5,
    _,
};

pub const SecurityDecisionTrace = extern struct {
    magic: u32,
    version: u16,
    _pad0: [2]u8,

    trace_id: u64,
    event_id: u64,
    timestamp_ns: u64,

    matched_rule_id: u32,
    incident_id: u64,
    incident_severity: u8,
    _pad1: [3]u8,

    policy_id: u32,
    policy_version: u16,
    _pad2: [2]u8,

    pep_request_id: u64,
    pep_decision: u8,
    _pad3: [7]u8,

    enforcement_id: u64,
    audit_id: u64,

    actor: u8,
    reason: u8,
    result: u8,
    _pad4: [13]u8,

    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    _pad5: [3]u8,

    comptime {
        if (@sizeOf(SecurityDecisionTrace) != 128) {
            @compileError("SecurityDecisionTrace must be exactly 128 bytes");
        }
    }

    pub fn init(trace_id: u64, ev: *const event_mod.IpcEvent) SecurityDecisionTrace {
        return .{
            .magic = TRACE_MAGIC,
            .version = TRACE_VERSION,
            ._pad0 = .{ 0, 0 },
            .trace_id = trace_id,
            .event_id = ev.event_id,
            .timestamp_ns = ev.timestamp_ns,
            .matched_rule_id = 0,
            .incident_id = 0,
            .incident_severity = 0,
            ._pad1 = .{ 0, 0, 0 },
            .policy_id = 0,
            .policy_version = 0,
            ._pad2 = .{ 0, 0 },
            .pep_request_id = 0,
            .pep_decision = 0,
            ._pad3 = .{ 0, 0, 0, 0, 0, 0, 0 },
            .enforcement_id = 0,
            .audit_id = 0,
            .actor = @intFromEnum(TraceActor.pipeline),
            .reason = @intFromEnum(TraceReason.none),
            .result = @intFromEnum(TraceResult.allow),
            ._pad4 = [_]u8{0} ** 13,
            .src_ip = ev.src_ip,
            .dst_ip = ev.dst_ip,
            .src_port = ev.src_port,
            .dst_port = ev.dst_port,
            .protocol = ev.protocol,
            ._pad5 = .{ 0, 0, 0 },
        };
    }

    pub fn validate(self: *const SecurityDecisionTrace) bool {
        return self.magic == TRACE_MAGIC and self.version == TRACE_VERSION;
    }

    pub fn setDetection(self: *SecurityDecisionTrace, rule_id: u32, inc_id: u64, severity: u8) void {
        self.matched_rule_id = rule_id;
        self.incident_id = inc_id;
        self.incident_severity = severity;
        if (rule_id != 0) {
            self.reason = @intFromEnum(TraceReason.signature_match);
        }
    }

    pub fn setPolicy(self: *SecurityDecisionTrace, p_id: u32, p_version: u16) void {
        self.policy_id = p_id;
        self.policy_version = p_version;
    }

    pub fn setPepDecision(self: *SecurityDecisionTrace, req_id: u64, decision: u8) void {
        self.pep_request_id = req_id;
        self.pep_decision = decision;
        self.result = switch (decision) {
            0 => @intFromEnum(TraceResult.allow),
            1 => @intFromEnum(TraceResult.block),
            2 => @intFromEnum(TraceResult.rate_limit),
            3 => @intFromEnum(TraceResult.quarantine),
            else => @intFromEnum(TraceResult.logged_only),
        };
    }

    pub fn setAuditId(self: *SecurityDecisionTrace, a_id: u64) void {
        self.audit_id = a_id;
    }

    pub fn setEnforcementId(self: *SecurityDecisionTrace, e_id: u64) void {
        self.enforcement_id = e_id;
    }

    pub fn asBytes(self: *const SecurityDecisionTrace) []const u8 {
        return std.mem.asBytes(self);
    }
};

test "SecurityDecisionTrace is 128 bytes and validates" {
    var ev = event_mod.IpcEvent.init(.dns_query);
    ev.event_id = 42;
    ev.src_ip = 0x01020304;
    ev.dst_ip = 0x0A0B0C0D;

    var trace = SecurityDecisionTrace.init(1, &ev);
    try std.testing.expect(trace.validate());
    try std.testing.expectEqual(@as(u64, 1), trace.trace_id);
    try std.testing.expectEqual(@as(u64, 42), trace.event_id);

    trace.setDetection(7, 0, 0);
    trace.setPolicy(3, 1);
    trace.setPepDecision(9, 1); // block
    trace.setAuditId(5);
    try std.testing.expectEqual(@as(u32, 7), trace.matched_rule_id);
    try std.testing.expectEqual(@as(u32, 3), trace.policy_id);
    try std.testing.expectEqual(@as(u64, 9), trace.pep_request_id);
    try std.testing.expectEqual(@as(u8, @intFromEnum(TraceResult.block)), trace.result);
    try std.testing.expectEqual(@as(u64, 5), trace.audit_id);
    try std.testing.expectEqual(@as(usize, 128), trace.asBytes().len);
}
