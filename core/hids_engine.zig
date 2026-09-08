//! hids_engine.zig - AEGIS HIDS Engine (Rewrite Phase 23 / Manual Phase 20)
//!
//! Host Intrusion Detection System: tracks real process events.
//! Replaces the old hids_process_monitor.zig stub with real process tracking.
//!
//! Architecture (Manual Section 28):
//!   Process events (PID, PPID, Image, CommandLine, User, Integrity, Signer, Hash)
//!   flow into Canonical Events for the pipeline.
//!
//! Features:
//!   1. ProcessEvent: rich process metadata (PID, PPID, image path, command line, etc.)
//!   2. ProcessTracker: tracks process trees (parent-child relationships)
//!   3. HidsEngine: converts process events to CanonicalEvents, tracks process lifecycle
//!   4. Suspicious process detection: unsigned processes, suspicious command lines, etc.

const std = @import("std");
const canonical = @import("canonical_event.zig");

// ============================================================
// Constants
// ============================================================

pub const MAX_PROCESSES: usize = 4096;
pub const MAX_COMMAND_LINE: usize = 512;
pub const MAX_IMAGE_PATH: usize = 260;

// ============================================================
// Process Integrity Level
// ============================================================

pub const ProcessIntegrity = enum(u8) {
    unknown = 0,
    low = 1,
    medium = 2,
    high = 3,
    system = 4,

    pub fn toString(self: ProcessIntegrity) []const u8 {
        return switch (self) {
            .unknown => "UNKNOWN",
            .low => "LOW",
            .medium => "MEDIUM",
            .high => "HIGH",
            .system => "SYSTEM",
        };
    }

    pub fn isElevated(self: ProcessIntegrity) bool {
        return self == .high or self == .system;
    }
};

// ============================================================
// Process Event Type
// ============================================================

pub const ProcessEventType = enum(u8) {
    create = 0,
    terminate = 1,
    inject = 2,
    create_remote_thread = 3,
    load_driver = 4,
    file_create = 5,
    registry_modify = 6,

    pub fn toString(self: ProcessEventType) []const u8 {
        return switch (self) {
            .create => "CREATE",
            .terminate => "TERMINATE",
            .inject => "INJECT",
            .create_remote_thread => "CREATE_REMOTE_THREAD",
            .load_driver => "LOAD_DRIVER",
            .file_create => "FILE_CREATE",
            .registry_modify => "REGISTRY_MODIFY",
        };
    }

    pub fn isSuspicious(self: ProcessEventType) bool {
        return self == .inject or self == .create_remote_thread or self == .load_driver;
    }
};

// ============================================================
// Process Info (tracked state)
// ============================================================

pub const ProcessInfo = struct {
    pid: u32,
    ppid: u32,
    image_path: [MAX_IMAGE_PATH]u8,
    image_path_len: usize,
    command_line: [MAX_COMMAND_LINE]u8,
    command_line_len: usize,
    user_sid: u32,
    integrity: ProcessIntegrity,
    is_signed: bool,
    signer: [64]u8,
    signer_len: usize,
    image_hash: u64,
    session_id: u32,
    create_time_ms: i64,
    last_seen_ms: i64,
    child_count: u32,
    is_alive: bool,

    pub fn imagePath(self: *const ProcessInfo) []const u8 {
        return self.image_path[0..self.image_path_len];
    }

    pub fn commandLine(self: *const ProcessInfo) []const u8 {
        return self.command_line[0..self.command_line_len];
    }

    pub fn signerName(self: *const ProcessInfo) []const u8 {
        return self.signer[0..self.signer_len];
    }

    pub fn isSuspicious(self: *const ProcessInfo) bool {
        // Unsigned process with elevated integrity
        if (!self.is_signed and self.integrity.isElevated()) return true;
        // System integrity but not signed
        if (self.integrity == .system and !self.is_signed) return true;
        // Empty command line (might be injected)
        if (self.command_line_len == 0) return true;
        return false;
    }
};

// ============================================================
// Process Event (for pipeline submission)
// ============================================================

pub const ProcessEvent = struct {
    event_type: ProcessEventType,
    pid: u32,
    ppid: u32,
    image_path: []const u8,
    command_line: []const u8,
    user_sid: u32,
    integrity: ProcessIntegrity,
    is_signed: bool,
    signer: []const u8,
    image_hash: u64,
    session_id: u32,
    timestamp_ms: i64,

    /// Convert to a CanonicalEvent for pipeline submission.
    pub fn toCanonicalEvent(self: ProcessEvent) canonical.CanonicalEvent {
        var event = canonical.create(.zig_core);
        event.event_type = .session_start;
        event.source_ip = 0;
        event.session_id = self.pid; // Use PID as session_id for host events
        event.is_pipe = 1; // Mark as host event
        event.protocol = 0;
        event.timestamp_ms = @intCast(self.timestamp_ms);
        // Pack PID and PPID into reserved field for forensics
        // reserved[0..4] = PID, reserved[4..8] = PPID
        var reserved: [16]u8 = [_]u8{0} ** 16;
        std.mem.writeInt(u32, reserved[0..4], self.pid, .little);
        std.mem.writeInt(u32, reserved[4..8], self.ppid, .little);
        reserved[8] = @intFromEnum(self.event_type);
        reserved[9] = @intFromEnum(self.integrity);
        reserved[10] = if (self.is_signed) 1 else 0;
        event.reserved = reserved;
        return event;
    }
};

// ============================================================
// Suspicious Activity Detection
// ============================================================

pub const SuspicionReason = enum(u8) {
    none = 0,
    unsigned_elevated = 1,
    unsigned_system = 2,
    empty_command_line = 3,
    suspicious_event_type = 4,
    process_injection = 5,
    remote_thread_creation = 6,
    driver_load = 7,

    pub fn toString(self: SuspicionReason) []const u8 {
        return switch (self) {
            .none => "NONE",
            .unsigned_elevated => "UNSIGNED_ELEVATED",
            .unsigned_system => "UNSIGNED_SYSTEM",
            .empty_command_line => "EMPTY_COMMAND_LINE",
            .suspicious_event_type => "SUSPICIOUS_EVENT_TYPE",
            .process_injection => "PROCESS_INJECTION",
            .remote_thread_creation => "REMOTE_THREAD_CREATION",
            .driver_load => "DRIVER_LOAD",
        };
    }

    pub fn isCritical(self: SuspicionReason) bool {
        return self == .process_injection or self == .remote_thread_creation or self == .driver_load;
    }
};

pub const HidsAlert = struct {
    pid: u32,
    ppid: u32,
    reason: SuspicionReason,
    image_path: []const u8,
    integrity: ProcessIntegrity,
    timestamp_ms: i64,
    is_critical: bool,

    pub fn isCriticalAlert(self: HidsAlert) bool {
        return self.is_critical;
    }
};

// ============================================================
// Process Tracker
// ============================================================

const ProcessMap = std.HashMap(u32, ProcessInfo, std.hash_map.AutoContext(u32), std.hash_map.default_max_load_percentage);

pub const ProcessTracker = struct {
    allocator: std.mem.Allocator,
    map: ProcessMap,
    /// Total processes tracked (lifetime).
    total_created: u64,
    total_terminated: u64,
    total_suspicious: u64,

    pub fn init(allocator: std.mem.Allocator) ProcessTracker {
        return .{
            .allocator = allocator,
            .map = ProcessMap.init(allocator),
            .total_created = 0,
            .total_terminated = 0,
            .total_suspicious = 0,
        };
    }

    pub fn deinit(self: *ProcessTracker) void {
        self.map.deinit();
    }

    /// Add or update a process.
    pub fn trackProcess(self: *ProcessTracker, event: ProcessEvent) ?HidsAlert {
        var alert: ?HidsAlert = null;

        if (self.map.getPtr(event.pid)) |existing| {
            // Update existing process
            existing.last_seen_ms = event.timestamp_ms;
            existing.child_count += 0; // no change

            // Check for suspicious event types on existing process
            if (event.event_type.isSuspicious()) {
                const reason: SuspicionReason = switch (event.event_type) {
                    .inject => .process_injection,
                    .create_remote_thread => .remote_thread_creation,
                    .load_driver => .driver_load,
                    else => .suspicious_event_type,
                };
                self.total_suspicious += 1;
                alert = .{
                    .pid = event.pid,
                    .ppid = existing.ppid,
                    .reason = reason,
                    .image_path = existing.imagePath(),
                    .integrity = existing.integrity,
                    .timestamp_ms = event.timestamp_ms,
                    .is_critical = reason.isCritical(),
                };
            }
        } else {
            // New process
            var info = ProcessInfo{
                .pid = event.pid,
                .ppid = event.ppid,
                .image_path = undefined,
                .image_path_len = @min(event.image_path.len, MAX_IMAGE_PATH),
                .command_line = undefined,
                .command_line_len = @min(event.command_line.len, MAX_COMMAND_LINE),
                .user_sid = event.user_sid,
                .integrity = event.integrity,
                .is_signed = event.is_signed,
                .signer = undefined,
                .signer_len = @min(event.signer.len, 64),
                .image_hash = event.image_hash,
                .session_id = event.session_id,
                .create_time_ms = event.timestamp_ms,
                .last_seen_ms = event.timestamp_ms,
                .child_count = 0,
                .is_alive = true,
            };
            @memcpy(info.image_path[0..info.image_path_len], event.image_path[0..info.image_path_len]);
            @memcpy(info.command_line[0..info.command_line_len], event.command_line[0..info.command_line_len]);
            @memcpy(info.signer[0..info.signer_len], event.signer[0..info.signer_len]);

            // Check for suspicious process
            if (info.isSuspicious()) {
                const reason: SuspicionReason = blk: {
                    if (!info.is_signed and info.integrity == .system) break :blk .unsigned_system;
                    if (!info.is_signed and info.integrity.isElevated()) break :blk .unsigned_elevated;
                    if (info.command_line_len == 0) break :blk .empty_command_line;
                    break :blk .suspicious_event_type;
                };
                self.total_suspicious += 1;
                alert = .{
                    .pid = event.pid,
                    .ppid = event.ppid,
                    .reason = reason,
                    .image_path = info.imagePath(),
                    .integrity = info.integrity,
                    .timestamp_ms = event.timestamp_ms,
                    .is_critical = false,
                };
            }

            // Update parent's child count
            if (self.map.getPtr(event.ppid)) |parent| {
                parent.child_count += 1;
            }

            self.map.put(event.pid, info) catch {};
            self.total_created += 1;
        }

        return alert;
    }

    /// Mark a process as terminated.
    pub fn terminateProcess(self: *ProcessTracker, pid: u32, timestamp_ms: i64) void {
        if (self.map.getPtr(pid)) |proc| {
            proc.is_alive = false;
            proc.last_seen_ms = timestamp_ms;
            self.total_terminated += 1;
        }
    }

    /// Get process info by PID.
    pub fn getProcess(self: *const ProcessTracker, pid: u32) ?ProcessInfo {
        return self.map.get(pid);
    }

    /// Current alive process count.
    pub fn aliveCount(self: *const ProcessTracker) usize {
        var alive: usize = 0;
        var it = self.map.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.is_alive) alive += 1;
        }
        return alive;
    }

    /// Total tracked process count.
    pub fn count(self: *const ProcessTracker) usize {
        return self.map.count();
    }
};

// ============================================================
// HIDS Engine
// ============================================================

pub const HidsEngine = struct {
    tracker: ProcessTracker,
    /// Total alerts generated.
    total_alerts: u64,
    /// Total critical alerts.
    total_critical_alerts: u64,
    /// Total canonical events generated.
    total_events_generated: u64,

    pub fn init(allocator: std.mem.Allocator) HidsEngine {
        return .{
            .tracker = ProcessTracker.init(allocator),
            .total_alerts = 0,
            .total_critical_alerts = 0,
            .total_events_generated = 0,
        };
    }

    pub fn deinit(self: *HidsEngine) void {
        self.tracker.deinit();
    }

    /// Process a HIDS event. Returns optional alert + canonical event for pipeline.
    pub fn processEvent(self: *HidsEngine, event: ProcessEvent) struct {
        alert: ?HidsAlert,
        canonical_event: canonical.CanonicalEvent,
    } {
        const alert = self.tracker.trackProcess(event);
        const canon_event = event.toCanonicalEvent();
        self.total_events_generated += 1;

        if (alert) |a| {
            self.total_alerts += 1;
            if (a.isCriticalAlert()) {
                self.total_critical_alerts += 1;
            }
        }

        return .{
            .alert = alert,
            .canonical_event = canon_event,
        };
    }

    /// Terminate a process.
    pub fn terminateProcess(self: *HidsEngine, pid: u32, timestamp_ms: i64) void {
        self.tracker.terminateProcess(pid, timestamp_ms);
    }

    /// Get process info by PID.
    pub fn getProcess(self: *const HidsEngine, pid: u32) ?ProcessInfo {
        return self.tracker.getProcess(pid);
    }

    /// Current alive process count.
    pub fn aliveProcessCount(self: *const HidsEngine) usize {
        return self.tracker.aliveCount();
    }

    /// Total tracked process count.
    pub fn trackedProcessCount(self: *const HidsEngine) usize {
        return self.tracker.count();
    }

    /// Reset stats (for tests).
    pub fn resetStats(self: *HidsEngine) void {
        self.tracker.total_created = 0;
        self.tracker.total_terminated = 0;
        self.tracker.total_suspicious = 0;
        self.total_alerts = 0;
        self.total_critical_alerts = 0;
        self.total_events_generated = 0;
    }
};

// ============================================================
// Tests
// ============================================================

test "ProcessIntegrity.toString returns readable names" {
    try std.testing.expect(std.mem.eql(u8, ProcessIntegrity.unknown.toString(), "UNKNOWN"));
    try std.testing.expect(std.mem.eql(u8, ProcessIntegrity.low.toString(), "LOW"));
    try std.testing.expect(std.mem.eql(u8, ProcessIntegrity.medium.toString(), "MEDIUM"));
    try std.testing.expect(std.mem.eql(u8, ProcessIntegrity.high.toString(), "HIGH"));
    try std.testing.expect(std.mem.eql(u8, ProcessIntegrity.system.toString(), "SYSTEM"));
}

test "ProcessIntegrity.isElevated" {
    try std.testing.expect(!ProcessIntegrity.unknown.isElevated());
    try std.testing.expect(!ProcessIntegrity.low.isElevated());
    try std.testing.expect(!ProcessIntegrity.medium.isElevated());
    try std.testing.expect(ProcessIntegrity.high.isElevated());
    try std.testing.expect(ProcessIntegrity.system.isElevated());
}

test "ProcessEventType.toString returns readable names" {
    try std.testing.expect(std.mem.eql(u8, ProcessEventType.create.toString(), "CREATE"));
    try std.testing.expect(std.mem.eql(u8, ProcessEventType.terminate.toString(), "TERMINATE"));
    try std.testing.expect(std.mem.eql(u8, ProcessEventType.inject.toString(), "INJECT"));
    try std.testing.expect(std.mem.eql(u8, ProcessEventType.create_remote_thread.toString(), "CREATE_REMOTE_THREAD"));
    try std.testing.expect(std.mem.eql(u8, ProcessEventType.load_driver.toString(), "LOAD_DRIVER"));
}

test "ProcessEventType.isSuspicious" {
    try std.testing.expect(!ProcessEventType.create.isSuspicious());
    try std.testing.expect(!ProcessEventType.terminate.isSuspicious());
    try std.testing.expect(ProcessEventType.inject.isSuspicious());
    try std.testing.expect(ProcessEventType.create_remote_thread.isSuspicious());
    try std.testing.expect(ProcessEventType.load_driver.isSuspicious());
}

test "SuspicionReason.toString returns readable names" {
    try std.testing.expect(std.mem.eql(u8, SuspicionReason.none.toString(), "NONE"));
    try std.testing.expect(std.mem.eql(u8, SuspicionReason.unsigned_elevated.toString(), "UNSIGNED_ELEVATED"));
    try std.testing.expect(std.mem.eql(u8, SuspicionReason.unsigned_system.toString(), "UNSIGNED_SYSTEM"));
    try std.testing.expect(std.mem.eql(u8, SuspicionReason.process_injection.toString(), "PROCESS_INJECTION"));
    try std.testing.expect(std.mem.eql(u8, SuspicionReason.remote_thread_creation.toString(), "REMOTE_THREAD_CREATION"));
}

test "SuspicionReason.isCritical" {
    try std.testing.expect(!SuspicionReason.none.isCritical());
    try std.testing.expect(!SuspicionReason.unsigned_elevated.isCritical());
    try std.testing.expect(SuspicionReason.process_injection.isCritical());
    try std.testing.expect(SuspicionReason.remote_thread_creation.isCritical());
    try std.testing.expect(SuspicionReason.driver_load.isCritical());
}

test "HidsAlert.isCriticalAlert" {
    const critical_alert = HidsAlert{
        .pid = 1234,
        .ppid = 100,
        .reason = .process_injection,
        .image_path = "malware.exe",
        .integrity = .high,
        .timestamp_ms = 1000,
        .is_critical = true,
    };
    try std.testing.expect(critical_alert.isCriticalAlert());

    const normal_alert = HidsAlert{
        .pid = 5678,
        .ppid = 100,
        .reason = .unsigned_elevated,
        .image_path = "tool.exe",
        .integrity = .high,
        .timestamp_ms = 2000,
        .is_critical = false,
    };
    try std.testing.expect(!normal_alert.isCriticalAlert());
}

test "ProcessEvent.toCanonicalEvent creates host event" {
    const event = ProcessEvent{
        .event_type = .create,
        .pid = 1234,
        .ppid = 100,
        .image_path = "C:\\Windows\\notepad.exe",
        .command_line = "notepad.exe",
        .user_sid = 500,
        .integrity = .medium,
        .is_signed = true,
        .signer = "Microsoft",
        .image_hash = 0xDEADBEEFCAFE,
        .session_id = 1,
        .timestamp_ms = 1700000000000,
    };

    const canon = event.toCanonicalEvent();
    try std.testing.expect(canon.source == .zig_core);
    try std.testing.expect(canon.is_pipe == 1); // host event
    try std.testing.expect(canon.session_id == 1234); // PID as session_id
    try std.testing.expect(canon.event_type == .session_start);
    // PID should be packed in reserved[0..4]
    const pid_from_reserved = std.mem.readInt(u32, canon.reserved[0..4], .little);
    try std.testing.expect(pid_from_reserved == 1234);
    // PPID in reserved[4..8]
    const ppid_from_reserved = std.mem.readInt(u32, canon.reserved[4..8], .little);
    try std.testing.expect(ppid_from_reserved == 100);
    // Event type in reserved[8]
    try std.testing.expect(canon.reserved[8] == @intFromEnum(ProcessEventType.create));
    // Integrity in reserved[9]
    try std.testing.expect(canon.reserved[9] == @intFromEnum(ProcessIntegrity.medium));
    // is_signed in reserved[10]
    try std.testing.expect(canon.reserved[10] == 1);
}

test "HidsEngine init has zero stats" {
    var engine = HidsEngine.init(std.testing.allocator);
    defer engine.deinit();

    try std.testing.expect(engine.total_alerts == 0);
    try std.testing.expect(engine.total_critical_alerts == 0);
    try std.testing.expect(engine.total_events_generated == 0);
    try std.testing.expect(engine.trackedProcessCount() == 0);
}

test "HidsEngine processEvent tracks new process" {
    var engine = HidsEngine.init(std.testing.allocator);
    defer engine.deinit();

    const event = ProcessEvent{
        .event_type = .create,
        .pid = 1234,
        .ppid = 100,
        .image_path = "C:\\Windows\\notepad.exe",
        .command_line = "notepad.exe",
        .user_sid = 500,
        .integrity = .medium,
        .is_signed = true,
        .signer = "Microsoft",
        .image_hash = 0xDEADBEEFCAFE,
        .session_id = 1,
        .timestamp_ms = 1700000000000,
    };

    const result = engine.processEvent(event);

    try std.testing.expect(result.alert == null); // not suspicious
    try std.testing.expect(engine.trackedProcessCount() == 1);
    try std.testing.expect(engine.total_events_generated == 1);

    const proc = engine.getProcess(1234);
    try std.testing.expect(proc != null);
    try std.testing.expect(proc.?.pid == 1234);
    try std.testing.expect(proc.?.ppid == 100);
    try std.testing.expect(proc.?.is_signed == true);
    try std.testing.expect(proc.?.is_alive == true);
}

test "HidsEngine processEvent detects unsigned elevated process" {
    var engine = HidsEngine.init(std.testing.allocator);
    defer engine.deinit();

    const event = ProcessEvent{
        .event_type = .create,
        .pid = 2000,
        .ppid = 100,
        .image_path = "C:\\temp\\malware.exe",
        .command_line = "malware.exe --steal",
        .user_sid = 500,
        .integrity = .high, // elevated
        .is_signed = false, // unsigned!
        .signer = "",
        .image_hash = 0x12345678,
        .session_id = 1,
        .timestamp_ms = 1700000000000,
    };

    const result = engine.processEvent(event);

    try std.testing.expect(result.alert != null);
    try std.testing.expect(result.alert.?.reason == .unsigned_elevated);
    try std.testing.expect(engine.total_alerts == 1);
    try std.testing.expect(engine.total_critical_alerts == 0); // not critical
}

test "HidsEngine processEvent detects unsigned system process" {
    var engine = HidsEngine.init(std.testing.allocator);
    defer engine.deinit();

    const event = ProcessEvent{
        .event_type = .create,
        .pid = 3000,
        .ppid = 4,
        .image_path = "C:\\temp\\rootkit.sys",
        .command_line = "",
        .user_sid = 0,
        .integrity = .system,
        .is_signed = false,
        .signer = "",
        .image_hash = 0xCAFEBABE,
        .session_id = 0,
        .timestamp_ms = 1700000000000,
    };

    const result = engine.processEvent(event);

    try std.testing.expect(result.alert != null);
    try std.testing.expect(result.alert.?.reason == .unsigned_system);
    try std.testing.expect(engine.total_alerts == 1);
}

test "HidsEngine processEvent detects process injection" {
    var engine = HidsEngine.init(std.testing.allocator);
    defer engine.deinit();

    // First create a normal process
    const create_event = ProcessEvent{
        .event_type = .create,
        .pid = 4000,
        .ppid = 100,
        .image_path = "C:\\Windows\\explorer.exe",
        .command_line = "explorer.exe",
        .user_sid = 500,
        .integrity = .medium,
        .is_signed = true,
        .signer = "Microsoft",
        .image_hash = 0xAAA,
        .session_id = 1,
        .timestamp_ms = 1000,
    };
    _ = engine.processEvent(create_event);

    // Now inject into it
    const inject_event = ProcessEvent{
        .event_type = .inject,
        .pid = 4000,
        .ppid = 100,
        .image_path = "C:\\Windows\\explorer.exe",
        .command_line = "",
        .user_sid = 500,
        .integrity = .medium,
        .is_signed = true,
        .signer = "Microsoft",
        .image_hash = 0xAAA,
        .session_id = 1,
        .timestamp_ms = 2000,
    };

    const result = engine.processEvent(inject_event);

    try std.testing.expect(result.alert != null);
    try std.testing.expect(result.alert.?.reason == .process_injection);
    try std.testing.expect(result.alert.?.is_critical == true);
    try std.testing.expect(engine.total_critical_alerts == 1);
}

test "HidsEngine processEvent detects remote thread creation" {
    var engine = HidsEngine.init(std.testing.allocator);
    defer engine.deinit();

    // Create process first
    const create_event = ProcessEvent{
        .event_type = .create,
        .pid = 5000,
        .ppid = 100,
        .image_path = "C:\\Windows\\svchost.exe",
        .command_line = "svchost.exe",
        .user_sid = 0,
        .integrity = .system,
        .is_signed = true,
        .signer = "Microsoft",
        .image_hash = 0xBBB,
        .session_id = 0,
        .timestamp_ms = 1000,
    };
    _ = engine.processEvent(create_event);

    // Remote thread creation
    const remote_event = ProcessEvent{
        .event_type = .create_remote_thread,
        .pid = 5000,
        .ppid = 100,
        .image_path = "C:\\Windows\\svchost.exe",
        .command_line = "",
        .user_sid = 0,
        .integrity = .system,
        .is_signed = true,
        .signer = "Microsoft",
        .image_hash = 0xBBB,
        .session_id = 0,
        .timestamp_ms = 2000,
    };

    const result = engine.processEvent(remote_event);

    try std.testing.expect(result.alert != null);
    try std.testing.expect(result.alert.?.reason == .remote_thread_creation);
    try std.testing.expect(result.alert.?.is_critical == true);
}

test "HidsEngine processEvent detects driver load" {
    var engine = HidsEngine.init(std.testing.allocator);
    defer engine.deinit();

    const create_event = ProcessEvent{
        .event_type = .create,
        .pid = 6000,
        .ppid = 4,
        .image_path = "C:\\Windows\\System32\\drivers\\driver.sys",
        .command_line = "",
        .user_sid = 0,
        .integrity = .system,
        .is_signed = true,
        .signer = "Microsoft",
        .image_hash = 0xCCC,
        .session_id = 0,
        .timestamp_ms = 1000,
    };
    _ = engine.processEvent(create_event);

    const load_event = ProcessEvent{
        .event_type = .load_driver,
        .pid = 6000,
        .ppid = 4,
        .image_path = "C:\\Windows\\System32\\drivers\\driver.sys",
        .command_line = "",
        .user_sid = 0,
        .integrity = .system,
        .is_signed = true,
        .signer = "Microsoft",
        .image_hash = 0xCCC,
        .session_id = 0,
        .timestamp_ms = 2000,
    };

    const result = engine.processEvent(load_event);

    try std.testing.expect(result.alert != null);
    try std.testing.expect(result.alert.?.reason == .driver_load);
    try std.testing.expect(result.alert.?.is_critical == true);
}

test "HidsEngine terminateProcess marks process as dead" {
    var engine = HidsEngine.init(std.testing.allocator);
    defer engine.deinit();

    const event = ProcessEvent{
        .event_type = .create,
        .pid = 7000,
        .ppid = 100,
        .image_path = "notepad.exe",
        .command_line = "notepad.exe",
        .user_sid = 500,
        .integrity = .medium,
        .is_signed = true,
        .signer = "Microsoft",
        .image_hash = 0xDDD,
        .session_id = 1,
        .timestamp_ms = 1000,
    };
    _ = engine.processEvent(event);
    try std.testing.expect(engine.aliveProcessCount() == 1);

    engine.terminateProcess(7000, 2000);

    const proc = engine.getProcess(7000);
    try std.testing.expect(proc != null);
    try std.testing.expect(!proc.?.is_alive);
    try std.testing.expect(engine.aliveProcessCount() == 0);
}

test "HidsEngine tracks parent-child relationships" {
    var engine = HidsEngine.init(std.testing.allocator);
    defer engine.deinit();

    // Create parent
    const parent_event = ProcessEvent{
        .event_type = .create,
        .pid = 100,
        .ppid = 4,
        .image_path = "explorer.exe",
        .command_line = "explorer.exe",
        .user_sid = 500,
        .integrity = .medium,
        .is_signed = true,
        .signer = "Microsoft",
        .image_hash = 0xEEE,
        .session_id = 1,
        .timestamp_ms = 1000,
    };
    _ = engine.processEvent(parent_event);

    // Create child
    const child_event = ProcessEvent{
        .event_type = .create,
        .pid = 200,
        .ppid = 100, // parent is PID 100
        .image_path = "cmd.exe",
        .command_line = "cmd.exe",
        .user_sid = 500,
        .integrity = .medium,
        .is_signed = true,
        .signer = "Microsoft",
        .image_hash = 0xFFF,
        .session_id = 1,
        .timestamp_ms = 2000,
    };
    _ = engine.processEvent(child_event);

    // Parent should have child_count = 1
    const parent = engine.getProcess(100);
    try std.testing.expect(parent != null);
    try std.testing.expect(parent.?.child_count == 1);
}

test "HidsEngine stats accumulate" {
    var engine = HidsEngine.init(std.testing.allocator);
    defer engine.deinit();

    // Create 3 processes
    var i: u32 = 0;
    while (i < 3) : (i += 1) {
        _ = engine.processEvent(.{
            .event_type = .create,
            .pid = 1000 + i,
            .ppid = 4,
            .image_path = "process.exe",
            .command_line = "process.exe",
            .user_sid = 500,
            .integrity = .medium,
            .is_signed = true,
            .signer = "Microsoft",
            .image_hash = 0x100 + i,
            .session_id = 1,
            .timestamp_ms = 1000 + i,
        });
    }

    try std.testing.expect(engine.trackedProcessCount() == 3);
    try std.testing.expect(engine.total_events_generated == 3);
    try std.testing.expect(engine.aliveProcessCount() == 3);
}

test "HidsEngine resetStats zeroes counters" {
    var engine = HidsEngine.init(std.testing.allocator);
    defer engine.deinit();

    _ = engine.processEvent(.{
        .event_type = .create,
        .pid = 100,
        .ppid = 4,
        .image_path = "test.exe",
        .command_line = "test.exe",
        .user_sid = 500,
        .integrity = .medium,
        .is_signed = true,
        .signer = "Microsoft",
        .image_hash = 0x123,
        .session_id = 1,
        .timestamp_ms = 1000,
    });
    try std.testing.expect(engine.total_events_generated == 1);

    engine.resetStats();
    try std.testing.expect(engine.total_events_generated == 0);
    try std.testing.expect(engine.total_alerts == 0);
}
