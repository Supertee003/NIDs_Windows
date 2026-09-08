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