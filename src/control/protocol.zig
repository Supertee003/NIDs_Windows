//! control/protocol.zig — AEGIS NIDS Control Protocol v2
//!
//! Defines the complete command contract for all control plane operations.
//! Every command flows through: Envelope → Authorization → Handler → Postcondition → Audit
//!
//! SECURITY (P0.4): Commands are role-gated. The pipe handler MUST check
//! authorization before dispatching to any handler.

const std = @import("std");

// ============================================================
// Command Enum — all 30 control commands
// ============================================================

pub const Command = enum(u16) {
    // --- system domain ---
    system_status = 100,
    system_health = 101,
    system_version = 102,
    system_diagnose = 103,

    // --- runtime domain ---
    runtime_start = 200,
    runtime_stop = 201,
    runtime_restart = 202,

    // --- rules domain ---
    rules_list = 300,
    rules_show = 301,
    rules_validate = 302,
    rules_reload = 303,

    // --- events domain ---
    events_count = 400,
    events_stats = 401,
    events_tail = 402,

    // --- incidents domain ---
    incidents_list = 500,
    incidents_show = 501,

    // --- policy domain ---
    policy_list = 600,
    policy_validate = 601,
    policy_verify = 602,
    policy_simulate = 603,

    // --- forensics domain ---
    forensics_list = 700,
    forensics_show = 701,
    forensics_verify = 702,
    forensics_export = 703,
    forensics_replay = 704,

    // --- enforcement domain ---
    enforcement_status = 800,
    enforcement_simulate = 801,
    enforcement_verify = 802,

    // --- metrics/logs domain ---
    metrics_snapshot = 900,
    logs_tail = 901,

    // --- special ---
    daemon_shutdown = 9999,

    pub fn fromString(s: []const u8) ?Command {
        const map = [_]struct { name: []const u8, cmd: Command }{
            .{ .name = "system.status", .cmd = .system_status },
            .{ .name = "system.health", .cmd = .system_health },
            .{ .name = "system.version", .cmd = .system_version },
            .{ .name = "system.diagnose", .cmd = .system_diagnose },
            .{ .name = "runtime.start", .cmd = .runtime_start },
            .{ .name = "runtime.stop", .cmd = .runtime_stop },
            .{ .name = "runtime.restart", .cmd = .runtime_restart },
            .{ .name = "rules.list", .cmd = .rules_list },
            .{ .name = "rules.show", .cmd = .rules_show },
            .{ .name = "rules.validate", .cmd = .rules_validate },
            .{ .name = "rules.reload", .cmd = .rules_reload },
            .{ .name = "events.count", .cmd = .events_count },
            .{ .name = "events.stats", .cmd = .events_stats },
            .{ .name = "events.tail", .cmd = .events_tail },
            .{ .name = "incidents.list", .cmd = .incidents_list },
            .{ .name = "incidents.show", .cmd = .incidents_show },
            .{ .name = "policy.list", .cmd = .policy_list },
            .{ .name = "policy.validate", .cmd = .policy_validate },
            .{ .name = "policy.verify", .cmd = .policy_verify },
            .{ .name = "policy.simulate", .cmd = .policy_simulate },
            .{ .name = "forensics.list", .cmd = .forensics_list },
            .{ .name = "forensics.show", .cmd = .forensics_show },
            .{ .name = "forensics.verify", .cmd = .forensics_verify },
            .{ .name = "forensics.export", .cmd = .forensics_export },
            .{ .name = "forensics.replay", .cmd = .forensics_replay },
            .{ .name = "enforcement.status", .cmd = .enforcement_status },
            .{ .name = "enforcement.simulate", .cmd = .enforcement_simulate },
            .{ .name = "enforcement.verify", .cmd = .enforcement_verify },
            .{ .name = "metrics.snapshot", .cmd = .metrics_snapshot },
            .{ .name = "logs.tail", .cmd = .logs_tail },
            .{ .name = "daemon.shutdown", .cmd = .daemon_shutdown },
            // Legacy aliases
            .{ .name = "status", .cmd = .system_status },
            .{ .name = "health", .cmd = .system_health },
            .{ .name = "health.check", .cmd = .system_health },
            .{ .name = "version", .cmd = .system_version },
        };
        for (map) |entry| {
            if (std.mem.eql(u8, s, entry.name)) return entry.cmd;
        }
        return null;
    }

    pub fn domain(self: Command) []const u8 {
        const v = @intFromEnum(self);
        if (v >= 100 and v < 200) return "system";
        if (v >= 200 and v < 300) return "runtime";
        if (v >= 300 and v < 400) return "rules";
        if (v >= 400 and v < 500) return "events";
        if (v >= 500 and v < 600) return "incidents";
        if (v >= 600 and v < 700) return "policy";
        if (v >= 700 and v < 800) return "forensics";
        if (v >= 800 and v < 900) return "enforcement";
        if (v >= 900 and v < 1000) return "metrics";
        return "special";
    }
};

// ============================================================
// Roles — hierarchical authorization
// ============================================================

pub const Role = enum(u8) {
    /// Read-only: status, health, version, list commands
    read = 0,
    /// Operational: reload, validate, simulate commands
    operate = 1,
    /// Privileged: start, stop, restart, shutdown, export, replay
    privileged = 2,

    pub fn level(self: Role) u8 {
        return @intFromEnum(self);
    }

    pub fn can(self: Role, required: Role) bool {
        return self.level() >= required.level();
    }

    pub fn fromString(s: []const u8) ?Role {
        if (std.mem.eql(u8, s, "read")) return .read;
        if (std.mem.eql(u8, s, "operate")) return .operate;
        if (std.mem.eql(u8, s, "privileged")) return .privileged;
        return null;
    }

    pub fn toString(self: Role) []const u8 {
        return switch (self) {
            .read => "read",
            .operate => "operate",
            .privileged => "privileged",
        };
    }
};

// ============================================================
// Command Contract — metadata for each command
// ============================================================

pub const CommandContract = struct {
    command: Command,
    name: []const u8,
    required_role: Role,
    description: []const u8,
    /// Whether this command triggers a mutation (state change)
    is_mutation: bool,
    /// Whether this command requires a postcondition check
    has_postcondition: bool,
};

/// Returns the contract for a given command.
pub fn contract(cmd: Command) CommandContract {
    return switch (cmd) {
        // --- system domain (read-only) ---
        .system_status => .{ .command = cmd, .name = "system.status", .required_role = .read, .description = "Show daemon status", .is_mutation = false, .has_postcondition = false },
        .system_health => .{ .command = cmd, .name = "system.health", .required_role = .read, .description = "Health check", .is_mutation = false, .has_postcondition = false },
        .system_version => .{ .command = cmd, .name = "system.version", .required_role = .read, .description = "Show version", .is_mutation = false, .has_postcondition = false },
        .system_diagnose => .{ .command = cmd, .name = "system.diagnose", .required_role = .read, .description = "Run diagnostics", .is_mutation = false, .has_postcondition = false },

        // --- runtime domain (privileged mutations) ---
        .runtime_start => .{ .command = cmd, .name = "runtime.start", .required_role = .privileged, .description = "Start runtime", .is_mutation = true, .has_postcondition = true },
        .runtime_stop => .{ .command = cmd, .name = "runtime.stop", .required_role = .privileged, .description = "Stop runtime", .is_mutation = true, .has_postcondition = true },
        .runtime_restart => .{ .command = cmd, .name = "runtime.restart", .required_role = .privileged, .description = "Restart runtime", .is_mutation = true, .has_postcondition = true },

        // --- rules domain ---
        .rules_list => .{ .command = cmd, .name = "rules.list", .required_role = .read, .description = "List rules", .is_mutation = false, .has_postcondition = false },
        .rules_show => .{ .command = cmd, .name = "rules.show", .required_role = .read, .description = "Show rule details", .is_mutation = false, .has_postcondition = false },
        .rules_validate => .{ .command = cmd, .name = "rules.validate", .required_role = .read, .description = "Validate rules", .is_mutation = false, .has_postcondition = false },
        .rules_reload => .{ .command = cmd, .name = "rules.reload", .required_role = .operate, .description = "Reload rules into engine", .is_mutation = true, .has_postcondition = true },

        // --- events domain ---
        .events_count => .{ .command = cmd, .name = "events.count", .required_role = .read, .description = "Event count", .is_mutation = false, .has_postcondition = false },
        .events_stats => .{ .command = cmd, .name = "events.stats", .required_role = .read, .description = "Event statistics", .is_mutation = false, .has_postcondition = false },
        .events_tail => .{ .command = cmd, .name = "events.tail", .required_role = .read, .description = "Recent events", .is_mutation = false, .has_postcondition = false },

        // --- incidents domain ---
        .incidents_list => .{ .command = cmd, .name = "incidents.list", .required_role = .read, .description = "List incidents", .is_mutation = false, .has_postcondition = false },
        .incidents_show => .{ .command = cmd, .name = "incidents.show", .required_role = .read, .description = "Show incident details", .is_mutation = false, .has_postcondition = false },

        // --- policy domain ---
        .policy_list => .{ .command = cmd, .name = "policy.list", .required_role = .read, .description = "List policies", .is_mutation = false, .has_postcondition = false },
        .policy_validate => .{ .command = cmd, .name = "policy.validate", .required_role = .read, .description = "Validate policies", .is_mutation = false, .has_postcondition = false },
        .policy_verify => .{ .command = cmd, .name = "policy.verify", .required_role = .operate, .description = "Verify policy signatures", .is_mutation = false, .has_postcondition = false },
        .policy_simulate => .{ .command = cmd, .name = "policy.simulate", .required_role = .operate, .description = "Simulate policy execution", .is_mutation = false, .has_postcondition = false },

        // --- forensics domain ---
        .forensics_list => .{ .command = cmd, .name = "forensics.list", .required_role = .read, .description = "List forensic records", .is_mutation = false, .has_postcondition = false },
        .forensics_show => .{ .command = cmd, .name = "forensics.show", .required_role = .read, .description = "Show forensic record", .is_mutation = false, .has_postcondition = false },
        .forensics_verify => .{ .command = cmd, .name = "forensics.verify", .required_role = .operate, .description = "Verify forensic integrity", .is_mutation = false, .has_postcondition = false },
        .forensics_export => .{ .command = cmd, .name = "forensics.export", .required_role = .privileged, .description = "Export forensic data", .is_mutation = true, .has_postcondition = true },
        .forensics_replay => .{ .command = cmd, .name = "forensics.replay", .required_role = .privileged, .description = "Replay forensic sequence", .is_mutation = true, .has_postcondition = true },

        // --- enforcement domain ---
        .enforcement_status => .{ .command = cmd, .name = "enforcement.status", .required_role = .read, .description = "Enforcement status", .is_mutation = false, .has_postcondition = false },
        .enforcement_simulate => .{ .command = cmd, .name = "enforcement.simulate", .required_role = .operate, .description = "Simulate enforcement", .is_mutation = false, .has_postcondition = false },
        .enforcement_verify => .{ .command = cmd, .name = "enforcement.verify", .required_role = .operate, .description = "Verify enforcement", .is_mutation = false, .has_postcondition = false },

        // --- metrics/logs domain ---
        .metrics_snapshot => .{ .command = cmd, .name = "metrics.snapshot", .required_role = .read, .description = "Metrics snapshot", .is_mutation = false, .has_postcondition = false },
        .logs_tail => .{ .command = cmd, .name = "logs.tail", .required_role = .read, .description = "Recent log entries", .is_mutation = false, .has_postcondition = false },

        // --- special ---
        .daemon_shutdown => .{ .command = cmd, .name = "daemon.shutdown", .required_role = .privileged, .description = "Shutdown daemon", .is_mutation = true, .has_postcondition = true },
    };
}

// ============================================================
// Command Envelope — the wire format
// ============================================================

pub const Envelope = struct {
    command: Command,
    payload: std.json.Value,
    request_id: u64,
    caller_role: Role,
};

// ============================================================
// Structured Result — the response envelope
// ============================================================

pub const Result = struct {
    ok: bool,
    code: []const u8,
    state: []const u8,
    data: ?std.json.Value = null,
    audit_id: u64 = 0,

    pub fn success(data: std.json.Value, audit_id: u64) Result {
        return .{ .ok = true, .code = "OK", .state = "OK", .data = data, .audit_id = audit_id };
    }

    pub fn errorResult(code: []const u8, state: []const u8, message: []const u8) Result {
        return .{ .ok = false, .code = code, .state = state, .data = .{ .object = .{
            .{"message", .{ .string = message }},
        } } };
    }
};

// ============================================================
// Tests
// ============================================================

test "Command.fromString parses all commands" {
    try std.testing.expectEqual(Command.system_status, Command.fromString("system.status").?);
    try std.testing.expectEqual(Command.runtime_stop, Command.fromString("runtime.stop").?);
    try std.testing.expectEqual(Command.rules_reload, Command.fromString("rules.reload").?);
    try std.testing.expectEqual(Command.events_tail, Command.fromString("events.tail").?);
    try std.testing.expectEqual(Command.incidents_list, Command.fromString("incidents.list").?);
    try std.testing.expectEqual(Command.policy_simulate, Command.fromString("policy.simulate").?);
    try std.testing.expectEqual(Command.forensics_export, Command.fromString("forensics.export").?);
    try std.testing.expectEqual(Command.enforcement_status, Command.fromString("enforcement.status").?);
    try std.testing.expectEqual(Command.metrics_snapshot, Command.fromString("metrics.snapshot").?);
    try std.testing.expectEqual(Command.logs_tail, Command.fromString("logs.tail").?);
    try std.testing.expectEqual(Command.daemon_shutdown, Command.fromString("daemon.shutdown").?);
    // Legacy aliases
    try std.testing.expectEqual(Command.system_status, Command.fromString("status").?);
    try std.testing.expectEqual(Command.system_health, Command.fromString("health.check").?);
    try std.testing.expectEqual(Command.system_version, Command.fromString("version").?);
    // Unknown
    try std.testing.expect(Command.fromString("bogus.command") == null);
}

test "Role authorization hierarchy" {
    try std.testing.expect(Role.read.can(.read));
    try std.testing.expect(!Role.read.can(.operate));
    try std.testing.expect(!Role.read.can(.privileged));
    try std.testing.expect(Role.operate.can(.read));
    try std.testing.expect(Role.operate.can(.operate));
    try std.testing.expect(!Role.operate.can(.privileged));
    try std.testing.expect(Role.privileged.can(.read));
    try std.testing.expect(Role.privileged.can(.operate));
    try std.testing.expect(Role.privileged.can(.privileged));
}

test "contracts: read-only commands have correct role" {
    const c_status = contract(.system_status);
    try std.testing.expectEqual(Role.read, c_status.required_role);
    try std.testing.expect(!c_status.is_mutation);

    const c_reload = contract(.rules_reload);
    try std.testing.expectEqual(Role.operate, c_reload.required_role);
    try std.testing.expect(c_reload.is_mutation);

    const c_stop = contract(.runtime_stop);
    try std.testing.expectEqual(Role.privileged, c_stop.required_role);
    try std.testing.expect(c_stop.is_mutation);
}
