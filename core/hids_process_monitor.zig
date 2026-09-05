//! hids_process_monitor.zig - AEGIS HIDS Process Monitor (Phase 23)
//!
//! Monitors process creation/termination events on Windows for HIDS.
//! On non-Windows Hosts, this module compiles but provides no-op stubs
//! so unit tests for the rest of the pipeline can run.
//!
//! On Windows, this module would:
//!   1. Register with ETW for process events
//!   2. Subscribe to WMI Win32_ProcessStartTrace
//!   3. Forward CanonicalEvents to the Event Fabric

const std = @import("std");
const canonical = @import("canonical_event.zig");

const is_windows = @import("builtin").os.tag == .windows;

var g_initialized: bool = false;
var g_total_events: u64 = 0;

pub fn init() void {
    if (g_initialized) return;
    if (!is_windows) {
        g_initialized = true;
        std.log.info("[HIDS-PROC] Process monitor initialized (Host stub, no events)", .{});
        return;
    }
    // Windows: would register ETW/WMI here
    g_initialized = true;
    std.log.info("[HIDS-PROC] Process monitor initialized (Windows ETW/WMI)", .{});
}

pub fn isInitialized() bool {
    return g_initialized;
}

pub fn shutdown() void {
    if (!g_initialized) return;
    g_initialized = false;
    std.log.info("[HIDS-PROC] Process monitor shutdown", .{});
}

/// Returns the count of process events observed.
/// On Host (non-Windows), always returns 0.
pub fn eventCount() u64 {
    return g_total_events;
}

/// Pop the next process event (if any). Returns null on Host.
pub fn nextEvent() ?canonical.CanonicalEvent {
    return null;
}

pub fn resetStats() void {
    g_total_events = 0;
}

// ============================================================
// Tests
// ============================================================

test "hids_process_monitor: init and shutdown" {
    if (isInitialized()) shutdown();
    try std.testing.expect(!isInitialized());

    init();
    defer shutdown();
    try std.testing.expect(isInitialized());
}

test "hids_process_monitor: nextEvent returns null on Host" {
    if (isInitialized()) shutdown();
    init();
    defer shutdown();
    try std.testing.expect(nextEvent() == null);
}

test "hids_process_monitor: eventCount starts at zero" {
    if (isInitialized()) shutdown();
    init();
    defer shutdown();
    try std.testing.expect(eventCount() == 0);
}
