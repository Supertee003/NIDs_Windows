//! control/state_machine.zig — AEGIS NIDS Runtime State Machine
//!
//! Single source of truth for system and subsystem states.
//! Both system.status and system.health pull from this module.
//!
//! System states: STOPPED → STARTING → READY → RUNNING → DEGRADED → RECOVERING → STOPPING → STOPPED
//! Subsystems:   ZIG, GO, C++, RUST_PEP, TIER3, CONTROL, FORENSIC
//!
//! Each subsystem tracks: state, pid, version, started_at, last_heartbeat,
//! last_event, error, capabilities.

const std = @import("std");

// ============================================================
// System State Machine
// ============================================================

pub const SystemState = enum(u8) {
    stopped = 0,
    starting = 1,
    ready = 2,
    running = 3,
    degraded = 4,
    recovering = 5,
    stopping = 6,

    pub fn toString(self: SystemState) []const u8 {
        return switch (self) {
            .stopped => "STOPPED",
            .starting => "STARTING",
            .ready => "READY",
            .running => "RUNNING",
            .degraded => "DEGRADED",
            .recovering => "RECOVERING",
            .stopping => "STOPPING",
        };
    }

    pub fn isRunning(self: SystemState) bool {
        return self == .running or self == .ready;
    }

    pub fn canServe(self: SystemState) bool {
        return self == .running or self == .ready or self == .degraded;
    }
};

// ============================================================
// Subsystem Definitions
// ============================================================

pub const SubsystemId = enum(u8) {
    zig = 0,
    go = 1,
    cpp = 2,
    rust_pep = 3,
    tier3 = 4,
    control = 5,
    forensic = 6,
};

pub const SubsystemState = enum(u8) {
    stopped = 0,
    starting = 1,
    ready = 2,
    running = 3,
    failed = 4,
    degraded = 5,

    pub fn toString(self: SubsystemState) []const u8 {
        return switch (self) {
            .stopped => "STOPPED",
            .starting => "STARTING",
            .ready => "READY",
            .running => "RUNNING",
            .failed => "FAILED",
            .degraded => "DEGRADED",
        };
    }

    pub fn isHealthy(self: SubsystemState) bool {
        return self == .running or self == .ready;
    }
};

pub const SubsystemInfo = struct {
    id: SubsystemId,
    name: []const u8,
    state: SubsystemState = .stopped,
    pid: u32 = 0,
    version: []const u8 = "unknown",
    started_at_ms: i64 = 0,
    last_heartbeat_ms: i64 = 0,
    last_event_ms: i64 = 0,
    error_msg: ?[]const u8 = null,
    capabilities: []const u8 = "",

    pub fn isHealthy(self: *const SubsystemInfo) bool {
        return self.state.isHealthy();
    }

    pub fn toJson(self: *const SubsystemInfo, a: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(a,
            \\{{"name":"{s}","state":"{s}","pid":{},"version":"{s}","started_at_ms":{},"last_heartbeat_ms":{},"last_event_ms":{},"error":{s},"capabilities":"{s}"}}
        , .{
            self.name,
            self.state.toString(),
            self.pid,
            self.version,
            self.started_at_ms,
            self.last_heartbeat_ms,
            self.last_event_ms,
            if (self.error_msg) |e| e else "null",
            self.capabilities,
        });
    }
};

// ============================================================
// Global Runtime State
// ============================================================

const MAX_SUBSYSTEMS = 8;

pub const RuntimeState = struct {
    system_state: SystemState = .stopped,
    subsystems: [MAX_SUBSYSTEMS]SubsystemInfo = undefined,
    subsystem_count: usize = 0,
    started_at_ms: i64 = 0,
    uptime_ms: i64 = 0,
    version: []const u8 = "5.0.0",
    build: []const u8 = "zig-0.13",
    mutex: std.Thread.Mutex = .{},

    /// Register a subsystem at startup.
    pub fn registerSubsystem(self: *RuntimeState, id: SubsystemId, name: []const u8, version: []const u8, capabilities: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.subsystem_count >= MAX_SUBSYSTEMS) return;
        self.subsystems[self.subsystem_count] = .{
            .id = id,
            .name = name,
            .version = version,
            .capabilities = capabilities,
        };
        self.subsystem_count += 1;
    }

    /// Mark a subsystem as started.
    pub fn subsystemStarted(self: *RuntimeState, id: SubsystemId, pid: u32) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.subsystems[0..self.subsystem_count]) |*sub| {
            if (sub.id == id) {
                sub.state = .running;
                sub.pid = pid;
                sub.started_at_ms = std.time.milliTimestamp();
                sub.last_heartbeat_ms = sub.started_at_ms;
                return;
            }
        }
    }

    /// Mark a subsystem as failed.
    pub fn subsystemFailed(self: *RuntimeState, id: SubsystemId, error_msg: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.subsystems[0..self.subsystem_count]) |*sub| {
            if (sub.id == id) {
                sub.state = .failed;
                sub.error_msg = error_msg;
                return;
            }
        }
    }

    /// Mark a subsystem as degraded.
    pub fn subsystemDegraded(self: *RuntimeState, id: SubsystemId, error_msg: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.subsystems[0..self.subsystem_count]) |*sub| {
            if (sub.id == id) {
                sub.state = .degraded;
                sub.error_msg = error_msg;
                return;
            }
        }
    }

    /// Update heartbeat for a subsystem.
    pub fn heartbeat(self: *RuntimeState, id: SubsystemId) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.subsystems[0..self.subsystem_count]) |*sub| {
            if (sub.id == id) {
                sub.last_heartbeat_ms = std.time.milliTimestamp();
                return;
            }
        }
    }

    /// Update last event time for a subsystem.
    pub fn recordEvent(self: *RuntimeState, id: SubsystemId) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.subsystems[0..self.subsystem_count]) |*sub| {
            if (sub.id == id) {
                sub.last_event_ms = std.time.milliTimestamp();
                return;
            }
        }
    }

    /// Transition system state.
    pub fn transition(self: *RuntimeState, new_state: SystemState) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const old = self.system_state;
        self.system_state = new_state;
        // Audit log
        std.log.info("[STATE] System: {s} -> {s}", .{ old.toString(), new_state.toString() });
    }

    /// Compute degraded status from subsystem health.
    pub fn recomputeHealth(self: *RuntimeState) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var any_failed = false;
        var all_healthy = true;
        for (self.subsystems[0..self.subsystem_count]) |sub| {
            if (!sub.isHealthy()) all_healthy = false;
            if (sub.state == .failed) any_failed = true;
        }
        if (any_failed and self.system_state == .running) {
            self.system_state = .degraded;
        } else if (all_healthy and self.system_state == .degraded) {
            self.system_state = .recovering;
        }
    }

    /// Get a subsystem by ID.
    pub fn getSubsystem(self: *RuntimeState, id: SubsystemId) ?*SubsystemInfo {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.subsystems[0..self.subsystem_count]) |*sub| {
            if (sub.id == id) return sub;
        }
        return null;
    }

    /// Get system state summary as JSON.
    pub fn statusJson(self: *RuntimeState, a: std.mem.Allocator) ![]u8 {
        self.mutex.lock();
        const ss = self.system_state;
        const uptime = self.uptime_ms;
        const ver = self.version;
        const bld = self.build;
        const sub_count = self.subsystem_count;
        const subs = self.subsystems[0..sub_count];
        self.mutex.unlock();

        var arr = std.ArrayList(u8).init(a);
        var writer = arr.writer();
        try writer.print(
            \\{{"state":"{s}","version":"{s}","build":"{s}","uptime_ms":{},"subsystems":[
        , .{ ss.toString(), ver, bld, uptime });

        for (subs, 0..) |sub, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.writeAll(try sub.toJson(a));
        }
        try writer.writeAll("]}");
        return arr.toOwnedSlice();
    }

    /// Get health check JSON.
    pub fn healthJson(self: *RuntimeState, a: std.mem.Allocator, pid: u32) ![]u8 {
        self.mutex.lock();
        const ss = self.system_state;
        const uptime = self.uptime_ms;
        const sub_count = self.subsystem_count;
        const subs = self.subsystems[0..sub_count];
        self.mutex.unlock();

        var all_healthy = true;
        for (subs) |sub| {
            if (!sub.isHealthy()) all_healthy = false;
        }

        var arr = std.ArrayList(u8).init(a);
        var writer = arr.writer();
        try writer.print(
            \\{{"component":"core","state":"{s}","pid":{},"uptime_ms":{},"degraded":{},"subsystems":[]
        , .{ ss.toString(), pid, uptime, !all_healthy });

        // Reset and write subsystems
        arr.clearRetainingCapacity();
        try writer.print(
            \\{{"component":"core","state":"{s}","pid":{},"uptime_ms":{},"degraded":{},"subsystems":[]
        , .{ ss.toString(), pid, uptime, !all_healthy });

        for (subs, 0..) |sub, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.writeAll(try sub.toJson(a));
        }
        try writer.writeAll("]}");
        return arr.toOwnedSlice();
    }
};

/// Global runtime state instance.
pub var g_runtime = RuntimeState{};

// ============================================================
// Tests
// ============================================================

test "SystemState: state properties" {
    try std.testing.expect(SystemState.running.isRunning());
    try std.testing.expect(SystemState.ready.isRunning());
    try std.testing.expect(!SystemState.stopped.isRunning());
    try std.testing.expect(!SystemState.degraded.isRunning());

    try std.testing.expect(SystemState.running.canServe());
    try std.testing.expect(SystemState.degraded.canServe());
    try std.testing.expect(!SystemState.stopped.canServe());
    try std.testing.expect(!SystemState.starting.canServe());
}

test "SubsystemState: health check" {
    try std.testing.expect(SubsystemState.running.isHealthy());
    try std.testing.expect(SubsystemState.ready.isHealthy());
    try std.testing.expect(!SubsystemState.failed.isHealthy());
    try std.testing.expect(!SubsystemState.degraded.isHealthy());
    try std.testing.expect(!SubsystemState.stopped.isHealthy());
}

test "RuntimeState: register and start subsystem" {
    var rs = RuntimeState{};
    rs.registerSubsystem(.zig, "zig", "5.0.0", "core");
    rs.registerSubsystem(.go, "go", "2.1.0", "capture");

    try std.testing.expectEqual(@as(usize, 2), rs.subsystem_count);
    try std.testing.expectEqual(SubsystemState.stopped, rs.subsystems[0].state);

    rs.subsystemStarted(.zig, 1234);
    try std.testing.expectEqual(SubsystemState.running, rs.subsystems[0].state);
    try std.testing.expectEqual(@as(u32, 1234), rs.subsystems[0].pid);
}

test "RuntimeState: subsystem failure degrades system" {
    var rs = RuntimeState{};
    rs.registerSubsystem(.zig, "zig", "5.0.0", "");
    rs.registerSubsystem(.go, "go", "2.1.0", "");
    rs.subsystemStarted(.zig, 100);
    rs.subsystemStarted(.go, 200);
    rs.system_state = .running;

    rs.subsystemFailed(.go, "crashed");
    rs.recomputeHealth();
    try std.testing.expectEqual(SystemState.degraded, rs.system_state);
}
