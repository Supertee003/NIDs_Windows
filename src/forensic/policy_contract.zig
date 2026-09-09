// PATCH-39 - TypeScript/Policy/Rust Integration Contracts
// AEGIS NIDS v5.0+ -- Policy IR and Rust integration contracts
//
// Integration layers:
//   1. TypeScript Policy IR → Zig: JSON contract (policy_ir.json)
//   2. Zig → Rust Shield: FFI (scoring, PEP)
//   3. Policy enum contracts: must match across all languages

const std = @import("std");

// ============================================================================
// Contract 1: TypeScript Policy IR → Zig (JSON contract)
// ============================================================================

/// Policy IR (Intermediate Representation) as defined by TypeScript.
/// Zig loads and validates this from policy_ir.json.
pub const PolicyIR = extern struct {
    version: u16,
    rule_count: u16,
    ruleset_id: u32,
    created_ms: u64,
    hash: u64, // SipHash of ruleset for fast comparison
};

pub const POLICY_IR_MAGIC: u32 = 0x504F4C49; // "POLI"

/// Policy rule (single rule in the ruleset).
pub const PolicyRule = extern struct {
    id: u32,
    action: u8, // PolicyAction
    severity: u8,
    condition_type: u8, // 0=always, 1=src_ip, 2=dst_ip, 3=port, 4=protocol, 5=regex
    reserved1: u8,
    reserved2: u32,
    condition_data: [32]u8, // Packed condition data
};

/// Condition types for policy rules.
pub const ConditionType = enum(u8) {
    always = 0,
    src_ip = 1,
    dst_ip = 2,
    port = 3,
    protocol = 4,
    regex = 5,
};

// ============================================================================
// Contract 2: Zig → Rust Shield (FFI)
// ============================================================================

/// Shield scoring request (Zig → Rust).
pub const ShieldScoreRequest = extern struct {
    event_kind: u8,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    payload_length: u32,
    rule_id: u32,
    context_flags: u32,
};

/// Shield scoring response (Rust → Zig).
pub const ShieldScoreResponse = extern struct {
    score: u32, // 0-1000 threat score
    is_threat: u8, // 0=benign, 1=threat
    confidence: u8, // 0-100
    action: u8, // PolicyAction
    reserved: [5]u8,
};

/// Shield PEP request (Zig → Rust).
pub const ShieldPepRequest = extern struct {
    decision_kind: u8,
    flow_id: u64,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    policy_id: u32,
    severity: u8,
    caller_pid: u32,
    caller_capability_mask: u32,
    request_id: u64,
    reserved: u32,
};

/// Shield PEP response (Rust → Zig).
pub const ShieldPepResponse = extern struct {
    decision: u8,
    reason: u32,
    quota_remaining: u32,
    signed_by: u32,
};

/// Zig → Rust Shield FFI function signatures.
pub extern "sec_monitor" fn aegis_engine_create() callconv(.C) ?*anyopaque;
pub extern "sec_monitor" fn aegis_engine_destroy(engine: ?*anyopaque) callconv(.C) void;
pub extern "sec_monitor" fn aegis_score_event(
    engine: ?*anyopaque,
    req: *const ShieldScoreRequest,
    resp: *ShieldScoreResponse,
) callconv(.C) i32;
pub extern "sec_monitor" fn aegis_is_threat(
    engine: ?*anyopaque,
    req: *const ShieldScoreRequest,
) callconv(.C) u8;
pub extern "sec_monitor" fn aegis_pep_evaluate(
    req: *const ShieldPepRequest,
    resp: *ShieldPepResponse,
) callconv(.C) i32;

// ============================================================================
// Contract 3: Policy Enum Contracts (must match across all languages)
// ============================================================================

/// PolicyAction enum values (must match Zig/TypeScript/Rust/Go/C++/Python).
pub const PolicyAction = enum(u8) {
    allow = 0,
    alert = 1,
    block = 2,
    quarantine = 3,
    rate_limit = 4,
    log_only = 5,
};

/// Severity enum values (must match across all languages).
pub const Severity = enum(u8) {
    low = 0,
    medium = 1,
    high = 2,
    critical = 3,
};

/// Enforcement status values (must match across all languages).
pub const EnforcementStatus = enum(u8) {
    pending = 0,
    enforced = 1,
    failed = 2,
    rolled_back = 3,
};

// ============================================================================
// Tests
// ============================================================================

test "TypeScript→Zig: PolicyIR size is reasonable" {
    try std.testing.expect(@sizeOf(PolicyIR) > 0);
    try std.testing.expect(@sizeOf(PolicyIR) <= 64);
}

test "TypeScript→Zig: PolicyRule size is reasonable" {
    try std.testing.expect(@sizeOf(PolicyRule) > 0);
    try std.testing.expect(@sizeOf(PolicyRule) <= 128);
}

test "TypeScript→Zig: ConditionType enum values" {
    try std.testing.expectEqual(@as(u8, 0), @intFromEnum(ConditionType.always));
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(ConditionType.src_ip));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(ConditionType.dst_ip));
    try std.testing.expectEqual(@as(u8, 3), @intFromEnum(ConditionType.port));
    try std.testing.expectEqual(@as(u8, 4), @intFromEnum(ConditionType.protocol));
    try std.testing.expectEqual(@as(u8, 5), @intFromEnum(ConditionType.regex));
}

test "Rust→Zig: Shield scoring request/response sizes" {
    try std.testing.expect(@sizeOf(ShieldScoreRequest) > 0);
    try std.testing.expect(@sizeOf(ShieldScoreRequest) <= 128);
    try std.testing.expect(@sizeOf(ShieldScoreResponse) > 0);
    try std.testing.expect(@sizeOf(ShieldScoreResponse) <= 64);
}

test "Rust→Zig: Shield PEP request/response sizes" {
    try std.testing.expect(@sizeOf(ShieldPepRequest) > 0);
    try std.testing.expect(@sizeOf(ShieldPepRequest) <= 256);
    try std.testing.expect(@sizeOf(ShieldPepResponse) > 0);
    try std.testing.expect(@sizeOf(ShieldPepResponse) <= 64);
}

test "Policy enum: PolicyAction values match cross-language contract" {
    try std.testing.expectEqual(@as(u8, 0), @intFromEnum(PolicyAction.allow));
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(PolicyAction.alert));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(PolicyAction.block));
    try std.testing.expectEqual(@as(u8, 3), @intFromEnum(PolicyAction.quarantine));
    try std.testing.expectEqual(@as(u8, 4), @intFromEnum(PolicyAction.rate_limit));
    try std.testing.expectEqual(@as(u8, 5), @intFromEnum(PolicyAction.log_only));
}

test "Policy enum: Severity values match cross-language contract" {
    try std.testing.expectEqual(@as(u8, 0), @intFromEnum(Severity.low));
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(Severity.medium));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(Severity.high));
    try std.testing.expectEqual(@as(u8, 3), @intFromEnum(Severity.critical));
}

test "Policy enum: EnforcementStatus values match cross-language contract" {
    try std.testing.expectEqual(@as(u8, 0), @intFromEnum(EnforcementStatus.pending));
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(EnforcementStatus.enforced));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(EnforcementStatus.failed));
    try std.testing.expectEqual(@as(u8, 3), @intFromEnum(EnforcementStatus.rolled_back));
}
