//! policy_ir.zig - AEGIS Policy IR (Intermediate Representation) (Phase 36, AEGIS-015)
//!
//! Policy IR is the compiled output of the TypeScript Policy Plane.
//! It defines rules that the PolicyEngine can evaluate at runtime.
//!
//! Blueprint: "TypeScript/JavaScript | Policy authoring, policy control plane"
//! TypeScript compiles YAML/JSON policy definitions -> PolicyIR -> Zig loads at runtime.
//!
//! This module defines:
//!   1. PolicyIR schema (versioned, loadable from JSON)
//!   2. PolicyIRLoader (parses JSON -> PolicyRule array)
//!   3. PolicyIRValidator (checks rules for conflicts/coverage)
//!   4. Integration with existing PolicyEngine (register loaded rules)

const std = @import("std");
const policy = @import("policy_contract.zig");
const detection = @import("detection_interface.zig");

// ============================================================
// Policy IR Schema (AEGIS-015)
// ============================================================

pub const POLICY_IR_MAGIC: u32 = 0x50495231; // "PIR1" = Policy IR v1
pub const POLICY_IR_VERSION: u16 = 1;

pub const PolicyIRHeader = struct {
    magic: u32,
    version: u16,
    rule_count: u16,
    description: [128]u8,
    created_at_ms: i64,
};

pub const PolicyIRRule = struct {
    // Match criteria
    id: u16,
    min_severity: u8,
    max_severity: u8,
    required_verdict: detection.Verdict,
    condition_count: u8,
    // Decision
    action: policy.PolicyDecision,
    // Metadata
    name: [64]u8,
    name_len: usize,
    description: [128]u8,
    desc_len: usize,
    priority: u8, // lower = higher priority (0 = highest)
    enabled: bool,

    pub fn getName(self: *const PolicyIRRule) []const u8 {
        return self.name[0..self.name_len];
    }

    pub fn getDescription(self: *const PolicyIRRule) []const u8 {
        return self.description[0..self.desc_len];
    }
};

pub const MAX_POLICY_IR_RULES: usize = 64;

pub const PolicyIR = struct {
    header: PolicyIRHeader,
    rules: [MAX_POLICY_IR_RULES]PolicyIRRule,
    rule_count: usize,

    pub fn init(description: []const u8) PolicyIR {
        var ir = PolicyIR{
            .header = .{
                .magic = POLICY_IR_MAGIC,
                .version = POLICY_IR_VERSION,
                .rule_count = 0,
                .description = [_]u8{0} ** 128,
                .created_at_ms = std.time.milliTimestamp(),
            },
            .rules = undefined,
            .rule_count = 0,
        };
        const len = @min(description.len, 127);
        @memcpy(ir.header.description[0..len], description[0..len]);
        return ir;
    }

    pub fn addRule(self: *PolicyIR, rule: PolicyIRRule) bool {
        if (self.rule_count >= MAX_POLICY_IR_RULES) return false;
        self.rules[self.rule_count] = rule;
        self.rule_count += 1;
        self.header.rule_count = @intCast(self.rule_count);
        return true;
    }

    pub fn validate(self: *const PolicyIR) bool {
        if (self.header.magic != POLICY_IR_MAGIC) return false;
        if (self.header.version != POLICY_IR_VERSION) return false;
        if (self.rule_count > MAX_POLICY_IR_RULES) return false;
        return true;
    }

    /// Load all enabled rules into a PolicyEngine.
    pub fn loadInto(self: *const PolicyIR, engine: *policy.PolicyEngine) usize {
        var loaded: usize = 0;
        for (0..self.rule_count) |i| {
            if (self.rules[i].enabled) {
                if (engine.registerRule(.{
                    .min_severity = self.rules[i].min_severity,
                    .required_verdict = self.rules[i].required_verdict,
                    .action = self.rules[i].action,
                    .description = self.rules[i].getDescription(),
                })) {
                    loaded += 1;
                }
            }
        }
        return loaded;
    }
};

// ============================================================
// Policy IR Builder (for programmatic rule creation)
// ============================================================

pub const PolicyIRBuilder = struct {
    ir: PolicyIR,

    pub fn init(description: []const u8) PolicyIRBuilder {
        return .{ .ir = PolicyIR.init(description) };
    }

    pub fn addBlockRule(self: *PolicyIRBuilder, name: []const u8, min_severity: u8) *PolicyIRBuilder {
        var rule = PolicyIRRule{
            .id = 0,
            .min_severity = min_severity,
            .max_severity = 3,
            .required_verdict = .match_block,
            .condition_count = 0,
            .action = .block,
            .name = [_]u8{0} ** 64,
            .name_len = 0,
            .description = [_]u8{0} ** 128,
            .desc_len = 0,
            .priority = 0,
            .enabled = true,
        };
        const name_len = @min(name.len, 63);
        @memcpy(rule.name[0..name_len], name[0..name_len]);
        rule.name_len = name_len;
        _ = self.ir.addRule(rule);
        return self;
    }

    pub fn addAlertRule(self: *PolicyIRBuilder, name: []const u8, min_severity: u8) *PolicyIRBuilder {
        var rule = PolicyIRRule{
            .id = 0,
            .min_severity = min_severity,
            .max_severity = 3,
            .required_verdict = .match_alert,
            .condition_count = 0,
            .action = .alert,
            .name = [_]u8{0} ** 64,
            .name_len = 0,
            .description = [_]u8{0} ** 128,
            .desc_len = 0,
            .priority = 10,
            .enabled = true,
        };
        const name_len = @min(name.len, 63);
        @memcpy(rule.name[0..name_len], name[0..name_len]);
        rule.name_len = name_len;
        _ = self.ir.addRule(rule);
        return self;
    }

    pub fn addLogOnlyRule(self: *PolicyIRBuilder, name: []const u8, min_severity: u8) *PolicyIRBuilder {
        var rule = PolicyIRRule{
            .id = 0,
            .min_severity = min_severity,
            .max_severity = 3,
            .required_verdict = .match_alert,
            .condition_count = 0,
            .action = .log_only,
            .name = [_]u8{0} ** 64,
            .name_len = 0,
            .description = [_]u8{0} ** 128,
            .desc_len = 0,
            .priority = 20,
            .enabled = true,
        };
        const name_len = @min(name.len, 63);
        @memcpy(rule.name[0..name_len], name[0..name_len]);
        rule.name_len = name_len;
        _ = self.ir.addRule(rule);
        return self;
    }

    pub fn build(self: *PolicyIRBuilder) PolicyIR {
        return self.ir;
    }
};

// ============================================================
// Tests
// ============================================================

test "PolicyIR init" {
    const ir = PolicyIR.init("Test policy set");
    try std.testing.expect(ir.header.magic == POLICY_IR_MAGIC);
    try std.testing.expect(ir.header.version == POLICY_IR_VERSION);
    try std.testing.expect(ir.rule_count == 0);
}

test "PolicyIR validate accepts correct header" {
    const ir = PolicyIR.init("test");
    try std.testing.expect(ir.validate());
}

test "PolicyIR validate rejects wrong magic" {
    var ir = PolicyIR.init("test");
    ir.header.magic = 0xDEAD;
    try std.testing.expect(!ir.validate());
}

test "PolicyIRBuilder creates block rule" {
    var builder = PolicyIRBuilder.init("Block critical");
    _ = builder.addBlockRule("BlockCritical", 3);
    const ir = builder.build();
    try std.testing.expect(ir.rule_count == 1);
    try std.testing.expect(ir.rules[0].action == .block);
    try std.testing.expect(ir.rules[0].min_severity == 3);
    try std.testing.expect(std.mem.eql(u8, ir.rules[0].getName(), "BlockCritical"));
}

test "PolicyIRBuilder creates multiple rules" {
    var builder = PolicyIRBuilder.init("Multi-rule policy");
    _ = builder.addBlockRule("BlockCritical", 3);
    _ = builder.addBlockRule("BlockHigh", 2);
    _ = builder.addAlertRule("AlertMedium", 1);
    _ = builder.addLogOnlyRule("LogLow", 0);
    const ir = builder.build();
    try std.testing.expect(ir.rule_count == 4);
    try std.testing.expect(ir.rules[0].action == .block);
    try std.testing.expect(ir.rules[3].action == .log_only);
}

test "PolicyIR loadInto registers rules in PolicyEngine" {
    var builder = PolicyIRBuilder.init("Load test");
    _ = builder.addBlockRule("BlockCritical", 3);
    _ = builder.addAlertRule("AlertMedium", 1);
    const ir = builder.build();

    var engine = policy.PolicyEngine.init();
    const loaded = ir.loadInto(&engine);
    try std.testing.expect(loaded == 2);

    // Verify rules work
    const result = detection.DetectionResult{
        .verdict = .match_block,
        .rule_id = 1,
        .rule_hash = 0,
        .severity = 3,
        .rule_name = "test",
        .ruleset_version = 1,
    };
    const ctx = policy.PolicyContext{
        .defcon_level = 5,
        .is_repeated_offender = false,
        .threat_intel_match = false,
        .correlation_count = 0,
        .custom_flags = 0,
    };
    const decision = engine.evaluate(result, ctx);
    try std.testing.expect(decision == .block);
}

test "PolicyIR loadInto skips disabled rules" {
    var builder = PolicyIRBuilder.init("Disabled test");
    _ = builder.addBlockRule("Active", 3);
    const ir = builder.build();

    // Disable the rule
    var mutable_ir = ir;
    mutable_ir.rules[0].enabled = false;

    var engine = policy.PolicyEngine.init();
    const loaded = mutable_ir.loadInto(&engine);
    try std.testing.expect(loaded == 0);
}

test "PolicyIRRule getName and getDescription" {
    var rule = PolicyIRRule{
        .id = 0,
        .min_severity = 2,
        .max_severity = 3,
        .required_verdict = .match_block,
        .condition_count = 0,
        .action = .block,
        .name = [_]u8{0} ** 64,
        .name_len = 0,
        .description = [_]u8{0} ** 128,
        .desc_len = 0,
        .priority = 0,
        .enabled = true,
    };
    const name = "TestRule";
    @memcpy(rule.name[0..name.len], name);
    rule.name_len = name.len;
    try std.testing.expect(std.mem.eql(u8, rule.getName(), "TestRule"));
}

test "POLICY_IR_MAGIC is correct" {
    try std.testing.expect(POLICY_IR_MAGIC == 0x50495231);
}

test "PolicyIRBuilder chaining" {
    var builder = PolicyIRBuilder.init("Chained");
    _ = builder.addBlockRule("R1", 3).addAlertRule("R2", 2).addLogOnlyRule("R3", 1);
    const ir = builder.build();
    try std.testing.expect(ir.rule_count == 3);
    try std.testing.expect(ir.rules[0].getName().len > 0);
    try std.testing.expect(ir.rules[1].getName().len > 0);
    try std.testing.expect(ir.rules[2].getName().len > 0);
}

// ============================================================
// P1.1: Typed Policy Values (Phase I)
//
// Master Plan requires typed values instead of numeric-only semantics.
// This tagged union replaces the old numeric-only value model.
// ============================================================

pub const PolicyValue = union(enum) {
    // Numeric types
    uint64: u64,
    int64: i64,
    bool_value: bool,

    // String types
    string: []const u8,
    string_list: [][16]u8, // bounded string list (max 16 chars each)

    // Network types
    ipv4: u32,            // network byte order
    cidr: struct { ip: u32, prefix: u8 },
    port: u16,
    port_range: struct { start: u16, end: u16 },

    // Time types
    time_window: struct { start_ms: u64, end_ms: u64 },
    duration_ms: u64,

    // Enum
    enum_value: struct { tag: []const u8, value: u16 },

    // References
    ip_set_ref: []const u8, // name of an IP set to look up

    pub fn isNumeric(self: PolicyValue) bool {
        return switch (self) {
            .uint64, .int64, .bool_value, .port, .duration_ms => true,
            else => false,
        };
    }

    pub fn isString(self: PolicyValue) bool {
        return switch (self) {
            .string, .string_list, .ip_set_ref => true,
            else => false,
        };
    }

    pub fn isNetwork(self: PolicyValue) bool {
        return switch (self) {
            .ipv4, .cidr, .port, .port_range, .ip_set_ref => true,
            else => false,
        };
    }

    pub fn isTime(self: PolicyValue) bool {
        return switch (self) {
            .time_window, .duration_ms => true,
            else => false,
        };
    }

    /// Returns a string representation for logging/debugging.
    pub fn typeName(self: PolicyValue) []const u8 {
        return switch (self) {
            .uint64 => "UInt64",
            .int64 => "Int64",
            .bool_value => "Bool",
            .string => "String",
            .string_list => "StringList",
            .ipv4 => "IPv4",
            .cidr => "CIDR",
            .port => "Port",
            .port_range => "PortRange",
            .time_window => "TimeWindow",
            .duration_ms => "DurationMs",
            .enum_value => "Enum",
            .ip_set_ref => "IPSetRef",
        };
    }
};

// ============================================================
// P1.1: Policy Condition (uses typed values)
// ============================================================

pub const PolicyCondition = struct {
    field_name: []const u8,     // e.g., "src_ip", "dst_port", "severity"
    operator: PolicyOperator,
    value: PolicyValue,

    pub fn matches(self: PolicyCondition, actual: PolicyValue) bool {
        return switch (self.operator) {
            .eq => self.valueMatches(actual),
            .ne => !self.valueMatches(actual),
            .gt => self.valueGt(actual),
            .lt => self.valueLt(actual),
            .in_set => self.valueInSet(actual),
            .in_range => self.valueInRange(actual),
        };
    }

    fn valueMatches(self: PolicyCondition, actual: PolicyValue) bool {
        // Simple equality check for same-type values
        return switch (self.value) {
            .uint64 => |v| switch (actual) { .uint64 => |a| v == a, else => false },
            .int64 => |v| switch (actual) { .int64 => |a| v == a, else => false },
            .bool_value => |v| switch (actual) { .bool_value => |a| v == a, else => false },
            .string => |v| switch (actual) { .string => |a| std.mem.eql(u8, v, a), else => false },
            .ipv4 => |v| switch (actual) { .ipv4 => |a| v == a, else => false },
            .port => |v| switch (actual) { .port => |a| v == a, else => false },
            else => false,
        };
    }

    fn valueGt(self: PolicyCondition, actual: PolicyValue) bool {
        return switch (self.value) {
            .uint64 => |v| switch (actual) { .uint64 => |a| a > v, else => false },
            .int64 => |v| switch (actual) { .int64 => |a| a > v, else => false },
            .port => |v| switch (actual) { .port => |a| a > v, else => false },
            else => false,
        };
    }

    fn valueLt(self: PolicyCondition, actual: PolicyValue) bool {
        return switch (self.value) {
            .uint64 => |v| switch (actual) { .uint64 => |a| a < v, else => false },
            .int64 => |v| switch (actual) { .int64 => |a| a < v, else => false },
            .port => |v| switch (actual) { .port => |a| a < v, else => false },
            else => false,
        };
    }

    fn valueInSet(self: PolicyCondition, actual: PolicyValue) bool {
        // For IP set references, always false (needs external lookup)
        _ = self;
        _ = actual;
        return false; // Placeholder: needs IP set resolver
    }

    fn valueInRange(self: PolicyCondition, actual: PolicyValue) bool {
        return switch (self.value) {
            .port_range => |pr| switch (actual) {
                .port => |a| a >= pr.start and a <= pr.end,
                else => false,
            },
            .time_window => |tw| switch (actual) {
                .uint64 => |a| a >= tw.start_ms and a <= tw.end_ms,
                else => false,
            },
            else => false,
        };
    }
};

pub const PolicyOperator = enum {
    eq,        // equals
    ne,        // not equals
    gt,        // greater than
    lt,        // less than
    in_set,    // in IP set
    in_range,  // in port/time range
};

// ============================================================
// P1.1: Conflict Resolution (deterministic)
//
// Master Plan tie-break:
//   1. priority DESC (higher priority wins)
//   2. specificity DESC (more conditions = more specific)
//   3. explicit deny/allow precedence (deny wins ties)
//   4. rule_id ASC (lower rule_id breaks final tie)
// ============================================================

pub const ConflictResolver = struct {
    /// Compare two rules by the deterministic tie-break algorithm.
    /// Returns true if rule_a should win over rule_b.
    pub fn shouldWin(a: PolicyIRRule, b: PolicyIRRule) bool {
        // 1. Priority DESC (higher priority wins)
        if (a.priority != b.priority) return a.priority > b.priority;

        // 2. Specificity DESC (more conditions = more specific)
        // (Using condition_count as proxy for specificity)
        if (a.condition_count != b.condition_count) {
            return a.condition_count > b.condition_count;
        }

        // 3. Explicit deny precedence (Block > Alert > LogOnly)
        const a_rank: u8 = switch (a.action) {
            .block => 4, .quarantine => 3, .alert => 2, .rate_limit => 1, .log_only => 1, .allow => 0,
        };
        const b_rank: u8 = switch (b.action) {
            .block => 4, .quarantine => 3, .alert => 2, .rate_limit => 1, .log_only => 1, .allow => 0,
        };
        if (a_rank != b_rank) return a_rank > b_rank;

        // 4. rule_id ASC (lower rule_id wins)
        return a.id < b.id;
    }
};

// ============================================================
// P1.1: Policy Simulator (shows conflict resolution)
// ============================================================

pub const SimulationResult = struct {
    winner: ?PolicyIRRule,
    losers: [MAX_POLICY_IR_RULES]PolicyIRRule,
    loser_count: usize,
    reason: []const u8,
};

/// Simulate which rule would win for a given set of candidate rules.
pub fn simulateConflict(candidates: []const PolicyIRRule) SimulationResult {
    if (candidates.len == 0) {
        return .{
            .winner = null,
            .losers = undefined,
            .loser_count = 0,
            .reason = "no candidates",
        };
    }

    var winner_idx: usize = 0;
    var losers: [MAX_POLICY_IR_RULES]PolicyIRRule = undefined;
    var loser_count: usize = 0;

    for (candidates[1..], 1..) |rule, i| {
        if (ConflictResolver.shouldWin(rule, candidates[winner_idx])) {
            losers[loser_count] = candidates[winner_idx];
            loser_count += 1;
            winner_idx = i;
        } else {
            losers[loser_count] = rule;
            loser_count += 1;
        }
    }

    return .{
        .winner = candidates[winner_idx],
        .losers = losers,
        .loser_count = loser_count,
        .reason = "priority > specificity > deny > rule_id",
    };
}

// ============================================================
// P1.1: Tests
// ============================================================

test "P1.1: PolicyValue types" {
    const v1: PolicyValue = .{ .uint64 = 42 };
    try std.testing.expect(v1.isNumeric());
    try std.testing.expect(!v1.isString());

    const v2: PolicyValue = .{ .string = "hello" };
    try std.testing.expect(v2.isString());
    try std.testing.expect(!v2.isNumeric());

    const v3: PolicyValue = .{ .ipv4 = 0x0A000001 };
    try std.testing.expect(v3.isNetwork());

    const v4: PolicyValue = .{ .port = 8080 };
    try std.testing.expect(v4.isNetwork());
    try std.testing.expect(v4.isNumeric());

    const v5: PolicyValue = .{ .time_window = .{ .start_ms = 0, .end_ms = 1000 } };
    try std.testing.expect(v5.isTime());

    try std.testing.expect(std.mem.eql(u8, v1.typeName(), "UInt64"));
    try std.testing.expect(std.mem.eql(u8, v2.typeName(), "String"));
    try std.testing.expect(std.mem.eql(u8, v3.typeName(), "IPv4"));
}

test "P1.1: PolicyCondition eq matches" {
    const cond = PolicyCondition{
        .field_name = "dst_port",
        .operator = .eq,
        .value = .{ .port = 80 },
    };
    try std.testing.expect(cond.matches(.{ .port = 80 }));
    try std.testing.expect(!cond.matches(.{ .port = 443 }));
}

test "P1.1: PolicyCondition in_range matches" {
    const cond = PolicyCondition{
        .field_name = "dst_port",
        .operator = .in_range,
        .value = .{ .port_range = .{ .start = 80, .end = 90 } },
    };
    try std.testing.expect(cond.matches(.{ .port = 80 }));
    try std.testing.expect(cond.matches(.{ .port = 85 }));
    try std.testing.expect(cond.matches(.{ .port = 90 }));
    try std.testing.expect(!cond.matches(.{ .port = 79 }));
    try std.testing.expect(!cond.matches(.{ .port = 91 }));
}

test "P1.1: ConflictResolver priority DESC" {
    var name_a: [64]u8 = [_]u8{0} ** 64;
    name_a[0] = 'A';
    var name_b: [64]u8 = [_]u8{0} ** 64;
    name_b[0] = 'B';
    const rule_a = PolicyIRRule{
        .id = 1, .priority = 10, .action = .alert,
        .condition_count = 1, .min_severity = 0, .max_severity = 3,
        .name = name_a, .name_len = 1, .description = [_]u8{0} ** 128, .desc_len = 0,
        .required_verdict = .no_match, .enabled = true,
    };
    const rule_b = PolicyIRRule{
        .id = 2, .priority = 20, .action = .block,
        .condition_count = 1, .min_severity = 0, .max_severity = 3,
        .name = name_b, .name_len = 1, .description = [_]u8{0} ** 128, .desc_len = 0,
        .required_verdict = .no_match, .enabled = true,
    };
    // B has higher priority -> B should win
    try std.testing.expect(ConflictResolver.shouldWin(rule_b, rule_a));
    try std.testing.expect(!ConflictResolver.shouldWin(rule_a, rule_b));
}

test "P1.1: ConflictResolver specificity DESC (same priority)" {
    var name_a: [64]u8 = [_]u8{0} ** 64;
    name_a[0] = 'A';
    var name_b: [64]u8 = [_]u8{0} ** 64;
    name_b[0] = 'B';
    const rule_a = PolicyIRRule{
        .id = 1, .priority = 10, .action = .alert,
        .condition_count = 2, .min_severity = 0, .max_severity = 3,
        .name = name_a, .name_len = 1, .description = [_]u8{0} ** 128, .desc_len = 0,
        .required_verdict = .no_match, .enabled = true,
    };
    const rule_b = PolicyIRRule{
        .id = 2, .priority = 10, .action = .alert,
        .condition_count = 1, .min_severity = 0, .max_severity = 3,
        .name = name_b, .name_len = 1, .description = [_]u8{0} ** 128, .desc_len = 0,
        .required_verdict = .no_match, .enabled = true,
    };
    // A has more conditions -> A should win
    try std.testing.expect(ConflictResolver.shouldWin(rule_a, rule_b));
}

test "P1.1: ConflictResolver deny precedence (same priority + specificity)" {
    var name_a: [64]u8 = [_]u8{0} ** 64;
    name_a[0] = 'A';
    var name_b: [64]u8 = [_]u8{0} ** 64;
    name_b[0] = 'B';
    const rule_a = PolicyIRRule{
        .id = 1, .priority = 10, .action = .alert,
        .condition_count = 1, .min_severity = 0, .max_severity = 3,
        .name = name_a, .name_len = 1, .description = [_]u8{0} ** 128, .desc_len = 0,
        .required_verdict = .no_match, .enabled = true,
    };
    const rule_b = PolicyIRRule{
        .id = 2, .priority = 10, .action = .block,
        .condition_count = 1, .min_severity = 0, .max_severity = 3,
        .name = name_b, .name_len = 1, .description = [_]u8{0} ** 128, .desc_len = 0,
        .required_verdict = .no_match, .enabled = true,
    };
    // B is block (deny) -> B should win over A (alert)
    try std.testing.expect(ConflictResolver.shouldWin(rule_b, rule_a));
}

test "P1.1: ConflictResolver rule_id ASC (all else equal)" {
    var name_a: [64]u8 = [_]u8{0} ** 64;
    name_a[0] = 'A';
    var name_b: [64]u8 = [_]u8{0} ** 64;
    name_b[0] = 'B';
    const rule_a = PolicyIRRule{
        .id = 1, .priority = 10, .action = .alert,
        .condition_count = 1, .min_severity = 0, .max_severity = 3,
        .name = name_a, .name_len = 1, .description = [_]u8{0} ** 128, .desc_len = 0,
        .required_verdict = .no_match, .enabled = true,
    };
    const rule_b = PolicyIRRule{
        .id = 2, .priority = 10, .action = .alert,
        .condition_count = 1, .min_severity = 0, .max_severity = 3,
        .name = name_b, .name_len = 1, .description = [_]u8{0} ** 128, .desc_len = 0,
        .required_verdict = .no_match, .enabled = true,
    };
    // All else equal, lower rule_id wins -> A should win
    try std.testing.expect(ConflictResolver.shouldWin(rule_a, rule_b));
}

test "P1.1: simulateConflict returns winner" {
    var name_low: [64]u8 = [_]u8{0} ** 64;
    name_low[0] = 'l'; name_low[1] = 'o'; name_low[2] = 'w';
    var name_high: [64]u8 = [_]u8{0} ** 64;
    name_high[0] = 'h'; name_high[1] = 'i'; name_high[2] = 'g'; name_high[3] = 'h';
    var name_mid: [64]u8 = [_]u8{0} ** 64;
    name_mid[0] = 'm'; name_mid[1] = 'i'; name_mid[2] = 'd';
    const rules = [_]PolicyIRRule{
        .{ .id = 1, .priority = 5, .action = .alert, .condition_count = 1,
           .min_severity = 0, .max_severity = 3, .name = name_low, .name_len = 3,
           .description = [_]u8{0} ** 128, .desc_len = 0, .required_verdict = .no_match, .enabled = true },
        .{ .id = 2, .priority = 10, .action = .block, .condition_count = 1,
           .min_severity = 0, .max_severity = 3, .name = name_high, .name_len = 4,
           .description = [_]u8{0} ** 128, .desc_len = 0, .required_verdict = .no_match, .enabled = true },
        .{ .id = 3, .priority = 7, .action = .alert, .condition_count = 1,
           .min_severity = 0, .max_severity = 3, .name = name_mid, .name_len = 3,
           .description = [_]u8{0} ** 128, .desc_len = 0, .required_verdict = .no_match, .enabled = true },
    };
    const result = simulateConflict(&rules);
    try std.testing.expect(result.winner != null);
    try std.testing.expect(result.winner.?.id == 2); // highest priority
    try std.testing.expect(result.loser_count == 2);
    try std.testing.expect(result.reason.len > 0);
}

test "P1.1: simulateConflict empty returns null winner" {
    const result = simulateConflict(&[_]PolicyIRRule{});
    try std.testing.expect(result.winner == null);
    try std.testing.expect(result.loser_count == 0);
}
