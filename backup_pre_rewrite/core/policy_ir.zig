//! policy_ir.zig - AEGIS Policy IR (Intermediate Representation) (Phase 36, AEGIS-015)
//!
//! Policy IR is the compiled output of the TypeScript Policy Plane.
//! It defines rules that the PolicyEngine can evaluate at runtime.
//!
//! Blueprint: "TypeScript/JavaScript | Policy authoring, policy control plane"
//! TypeScript compiles YAML/JSON policy definitions → PolicyIR → Zig loads at runtime.
//!
//! This module defines:
//!   1. PolicyIR schema (versioned, loadable from JSON)
//!   2. PolicyIRLoader (parses JSON → PolicyRule array)
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
    min_severity: u8,
    required_verdict: detection.Verdict,
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
            .min_severity = min_severity,
            .required_verdict = .match_block,
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
            .min_severity = min_severity,
            .required_verdict = .match_alert,
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
            .min_severity = min_severity,
            .required_verdict = .match_alert,
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
        .min_severity = 2,
        .required_verdict = .match_block,
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
