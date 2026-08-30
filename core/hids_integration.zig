//! hids_integration.zig - AEGIS HIDS Integration (Rewrite Phase 23)
//!
//! Thin facade over hids_engine.zig that owns a singleton HidsEngine.
//! Provides process event tracking and suspicious activity detection.

const std = @import("std");
const canonical = @import("canonical_event.zig");
const hids = @import("hids_engine.zig");

var g_engine: ?hids.HidsEngine = null;
var g_initialized: bool = false;
var g_allocator: ?std.mem.Allocator = null;

var g_total_events: u64 = 0;
var g_total_alerts: u64 = 0;
var g_total_critical: u64 = 0;

pub fn init(allocator: std.mem.Allocator) void {
    if (g_initialized) return;
    g_engine = hids.HidsEngine.init(allocator);
    g_allocator = allocator;
    g_initialized = true;
    g_total_events = 0;
    g_total_alerts = 0;
    g_total_critical = 0;
    std.log.info("[HIDS] HIDS integration initialized (process tracking)", .{});
}

pub fn isInitialized() bool {
    return g_initialized;
}

pub fn resetStats() void {
    g_total_events = 0;
    g_total_alerts = 0;
    g_total_critical = 0;
    if (g_engine) |*engine| {
        engine.resetStats();
    }
}

pub const ProcessResult = struct {
    alert: ?hids.HidsAlert,
    canonical_event: canonical.CanonicalEvent,
};

pub fn processEvent(event: hids.ProcessEvent) ProcessResult {
    if (!g_initialized) {
        return .{
            .alert = null,
            .canonical_event = event.toCanonicalEvent(),
        };
    }
    if (g_engine) |*engine| {
        const result = engine.processEvent(event);
        g_total_events += 1;
        if (result.alert) |a| {
            g_total_alerts += 1;
            if (a.isCriticalAlert()) {
                g_total_critical += 1;
            }
        }
        return .{
            .alert = result.alert,
            .canonical_event = result.canonical_event,
        };
    }
    return .{
        .alert = null,
        .canonical_event = event.toCanonicalEvent(),
    };
}

pub fn terminateProcess(pid: u32, timestamp_ms: i64) void {
    if (g_engine) |*engine| {
        engine.terminateProcess(pid, timestamp_ms);
    }
}

pub fn getProcess(pid: u32) ?hids.ProcessInfo {
    if (g_engine) |*engine| {
        return engine.getProcess(pid);
    }
    return null;
}

pub fn aliveProcessCount() usize {
    if (g_engine) |*engine| {
        return engine.aliveProcessCount();
    }
    return 0;
}

pub fn trackedProcessCount() usize {
    if (g_engine) |*engine| {
        return engine.trackedProcessCount();
    }
    return 0;
}

pub const HidsStats = struct {
    total_events: u64,
    total_alerts: u64,
    total_critical: u64,
    tracked_processes: usize,
    alive_processes: usize,
};

pub fn getStats() HidsStats {
    if (g_engine) |*engine| {
        return .{
            .total_events = g_total_events,
            .total_alerts = g_total_alerts,
            .total_critical = g_total_critical,
            .tracked_processes = engine.trackedProcessCount(),
            .alive_processes = engine.aliveProcessCount(),
        };
    }
    return .{
        .total_events = 0,
        .total_alerts = 0,
        .total_critical = 0,
        .tracked_processes = 0,
        .alive_processes = 0,
    };
}

pub fn shutdown() void {
    if (!g_initialized) return;
    if (g_engine) |*engine| {
        engine.deinit();
    }
    g_engine = null;
    g_allocator = null;
    g_initialized = false;
    std.log.info("[HIDS] HIDS integration shutdown", .{});
}

test "hids integration: full lifecycle" {
    if (g_initialized) shutdown();

    // Not initialized -> returns no alert
    const result = processEvent(.{
        .event_type = .create,
        .pid = 1234,
        .ppid = 100,
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
    try std.testing.expect(result.alert == null);

    // Init
    try std.testing.expect(!isInitialized());
    init(std.testing.allocator);
    try std.testing.expect(isInitialized());

    // Process normal event
    const normal_result = processEvent(.{
        .event_type = .create,
        .pid = 2000,
        .ppid = 100,
        .image_path = "notepad.exe",
        .command_line = "notepad.exe",
        .user_sid = 500,
        .integrity = .medium,
        .is_signed = true,
        .signer = "Microsoft",
        .image_hash = 0x456,
        .session_id = 1,
        .timestamp_ms = 1000,
    });
    try std.testing.expect(normal_result.alert == null);
    try std.testing.expect(trackedProcessCount() == 1);

    // Process suspicious event (unsigned elevated)
    const suspicious_result = processEvent(.{
        .event_type = .create,
        .pid = 3000,
        .ppid = 100,
        .image_path = "malware.exe",
        .command_line = "malware.exe",
        .user_sid = 500,
        .integrity = .high,
        .is_signed = false,
        .signer = "",
        .image_hash = 0x789,
        .session_id = 1,
        .timestamp_ms = 2000,
    });
    try std.testing.expect(suspicious_result.alert != null);
    try std.testing.expect(suspicious_result.alert.?.reason == .unsigned_elevated);

    const stats = getStats();
    try std.testing.expect(stats.total_events == 2);
    try std.testing.expect(stats.total_alerts == 1);
    try std.testing.expect(stats.tracked_processes == 2);

    // Reset
    resetStats();
    const reset_stats = getStats();
    try std.testing.expect(reset_stats.total_events == 0);

    // Double-init/double-shutdown
    init(std.testing.allocator);
    try std.testing.expect(isInitialized());
    shutdown();
    shutdown();
    try std.testing.expect(!isInitialized());
}
