// PATCH-34 — Security Decision Trace
// AEGIS NIDS v5.0+ -- Structured trace linking event → detection → policy → PEP → action → audit
//
// Every privileged/security decision produces a SecurityDecisionTrace that links:
//   trace_id → event_id → incident_id → policy_id → pep_request_id
//   → pep_decision → enforcement_id → audit_id → timestamp → result
//
// This is the authoritative record for post-incident forensics and replay.
// The trace is immutable once finalized (all fields set).

const std = @import("std");
const event = @import("../contract/event.zig");

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

/// SecurityDecisionTrace — immutable record of a complete security decision flow.
/// Fields are populated progressively as the event flows through the pipeline.
/// Once finalize() is called, the trace is read-only.
pub const SecurityDecisionTrace = extern struct {
    // Magic and version
    magic: u32,
    version: u16,
    _pad0: [2]u8,

    // Identity
    trace_id: u64, // unique per trace (monotonic counter)
    event_id: u64, // originating event ID
    timestamp_ns: u64, // when the trace was created (nanoseconds since epoch)

    // Detection phase
    matched_rule_id: u32, // 0 if no Aho-Corasick rule matched
    incident_id: u64, // 0 if no incident created
    incident_severity: u8, // severity of incident (0 if none)
    _pad1: [3]u8,

    // Policy phase
    policy_id: u32, // 0 if no policy matched
    policy_version: u16, // version of the matched policy
    _pad2: [2]u8,

    // PEP phase
    pep_request_id: u64, // 0 if PEP was not consulted
    pep_decision: u8, // PEP decision (PepDecision enum value)
    _pad3: [7]u8,

    // Enforcement phase
    enforcement_id: u64, // 0 if no enforcement action taken

    // Audit
    audit_id: u64, // monotonic audit trail ID

    // Context
    actor: u8, // TraceActor enum
    reason: u8, // TraceReason enum
    result: u8, // TraceResult enum
    _pad4: [13]u8,

    // Network context (from originating event)
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    _pad5: [3]u8,

    comptime {
        // Trace must be exactly 128 bytes for cache-line alignment
        if (@sizeOf(SecurityDecisionTrace) != 128) {
            @compileError("SecurityDecisionTrace must be exactly 128 bytes");
        }
    }

    pub fn init(trace_id: u64, ev: *const event.IpcEvent) SecurityDecisionTrace {
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

    /// Set detection result
    pub fn setDetection(self: *SecurityDecisionTrace, rule_id: u32, inc_id: u64, severity: u8) void {
        self.matched_rule_id = rule_id;
        self.incident_id = inc_id;
        self.incident_severity = severity;
        if (rule_id != 0) {
            self.reason = @intFromEnum(TraceReason.signature_match);
        }
    }

    /// Set policy match result
    pub fn setPolicy(self: *SecurityDecisionTrace, p_id: u32, p_version: u16) void {
        self.policy_id = p_id;
        self.policy_version = p_version;
    }

    /// Set PEP decision
    pub fn setPepDecision(self: *SecurityDecisionTrace, req_id: u64, decision: u8) void {
        self.pep_request_id = req_id;
        self.pep_decision = decision;
        // Map PepDecision to TraceResult
        self.result = switch (decision) {
            0 => @intFromEnum(TraceResult.allow), // allow
            1 => @intFromEnum(TraceResult.block), // block
            2 => @intFromEnum(TraceResult.rate_limit), // rate_limit
            3 => @intFromEnum(TraceResult.quarantine), // quarantine
            else => @intFromEnum(TraceResult.logged_only),
        };
    }

    /// Set audit ID
    pub fn setAuditId(self: *SecurityDecisionTrace, a_id: u64) void {
        self.audit_id = a_id;
    }

    /// Set enforcement ID
    pub fn setEnforcementId(self: *SecurityDecisionTrace, e_id: u64) void {
        self.enforcement_id = e_id;
    }

    /// Get the trace as bytes (for serialization / forensic storage)
    pub fn asBytes(self: *const SecurityDecisionTrace) []const u8 {
        return std.mem.asBytes(self);
    }
};

// ============================================================================
// Tests
// ============================================================================
test "SecurityDecisionTrace init and validate" {
    var ev = event.IpcEvent.init(.signature_match);
    ev.now();
    ev.event_id = 42;
    ev.src_ip = 0x01020304;
    ev.dst_ip = 0x0A0B0C0D;

    var trace = SecurityDecisionTrace.init(1, &ev);
    try std.testing.expect(trace.validate());
    try std.testing.expectEqual(@as(u64, 1), trace.trace_id);
    try std.testing.expectEqual(@as(u64, 42), trace.event_id);
    try std.testing.expectEqual(@intFromEnum(TraceActor.pipeline), trace.actor);
    try std.testing.expectEqual(@intFromEnum(TraceResult.allow), trace.result);
}

test "SecurityDecisionTrace detection phase" {
    var ev = event.IpcEvent.init(.signature_match);
    ev.now();
    var trace = SecurityDecisionTrace.init(100, &ev);

    trace.setDetection(42, 7, 5);
    try std.testing.expectEqual(@as(u32, 42), trace.matched_rule_id);
    try std.testing.expectEqual(@as(u64, 7), trace.incident_id);
    try std.testing.expectEqual(@as(u8, 5), trace.incident_severity);
    try std.testing.expectEqual(@intFromEnum(TraceReason.signature_match), trace.reason);
}

test "SecurityDecisionTrace policy + PEP phase" {
    var ev = event.IpcEvent.init(.signature_match);
    ev.now();
    var trace = SecurityDecisionTrace.init(200, &ev);

    trace.setPolicy(10, 1);
    try std.testing.expectEqual(@as(u32, 10), trace.policy_id);
    try std.testing.expectEqual(@as(u16, 1), trace.policy_version);

    trace.setPepDecision(55, 1); // block
    try std.testing.expectEqual(@as(u64, 55), trace.pep_request_id);
    try std.testing.expectEqual(@as(u8, 1), trace.pep_decision);
    try std.testing.expectEqual(@intFromEnum(TraceResult.block), trace.result);
}

test "SecurityDecisionTrace complete flow" {
    var ev = event.IpcEvent.init(.signature_match);
    ev.now();
    ev.src_ip = 0xC0A80101;
    ev.dst_ip = 0xC0A80102;
    ev.src_port = 12345;
    ev.dst_port = 80;
    ev.protocol = 6;

    var trace = SecurityDecisionTrace.init(999, &ev);
    trace.setDetection(5, 10, 6);
    trace.setPolicy(3, 2);
    trace.setPepDecision(100, 1);
    trace.setAuditId(500);
    trace.setEnforcementId(200);

    try std.testing.expect(trace.validate());
    try std.testing.expectEqual(@as(u64, 999), trace.trace_id);
    try std.testing.expectEqual(@as(u64, 100), trace.pep_request_id);
    try std.testing.expectEqual(@as(u64, 500), trace.audit_id);
    try std.testing.expectEqual(@as(u64, 200), trace.enforcement_id);
    try std.testing.expectEqual(@intFromEnum(TraceResult.block), trace.result);
    try std.testing.expectEqual(@as(u32, 0xC0A80101), trace.src_ip);
    try std.testing.expectEqual(@as(u16, 12345), trace.src_port);
}

test "SecurityDecisionTrace asBytes" {
    var ev = event.IpcEvent.init(.signature_match);
    ev.now();
    var trace = SecurityDecisionTrace.init(1, &ev);
    const bytes = trace.asBytes();
    try std.testing.expectEqual(@as(usize, 128), bytes.len);
    try std.testing.expect(bytes[0] == 0x01); // TRACE_MAGIC low byte
}
