//! pipe_monitor.zig — AEGIS NIDS Pipe Monitor Sensor (Thread 5)
//!
//! Polls \\.\pipe\* every 5 seconds and checks for suspicious named pipes.
//! Matches against PIPE_MONITOR layer rules in Rules.json.
//! Reports suspicious pipe events to nids_analyze for inspection.
//!
//! 3-Layer Architecture: This is the PIPE_MONITOR layer sensor.

const std = @import("std");

// ====== Suspicious Named Pipe Patterns (from Rules.json PIPE_MONITOR rules) ======
const SUSPICIOUS_PIPE_PATTERNS = [_][]const u8{
    "MSSE-",           // Cobalt Strike (R3001)
    "postex_",         // Cobalt Strike post-exploitation
    "status_",         // Cobalt Strike status pipe
    "psexec",          // PsExec remote execution (R3002)
    "PAExec",          // PsExec variant
    "meterpreter",     // Meterpreter (R3004)
    "atsvc",           // atexec scheduled task (R3005)
    "anonymous",       // Anonymous pipe (R3003)
};

// ====== Pipe Event — sent to nids_analyze for rule matching ======
pub const PipeEvent = struct {
    pipe_name: []const u8,
    event_type: []const u8,  // "PIPE_CREATED", "PIPE_CONNECTED", "PIPE_ALERT"
    risk_level: []const u8,  // "Critical", "High", "Medium"
    matched_rule: []const u8 = "",
    timestamp: u64 = 0,
};

// ====== Pipe Statistics ======
pub const PipeStats = struct {
    total_pipes: u32 = 0,
    suspicious_pipes: u32 = 0,
    last_scan_time: u64 = 0,
};

var stats: PipeStats = .{};
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
var allocator = gpa.allocator();

// ====== Check if pipe name matches suspicious pattern ======
fn isSuspiciousPipe(pipe_name: []const u8) ?[]const u8 {
    for (SUSPICIOUS_PIPE_PATTERNS) |pattern| {
        if (std.mem.containsAtLeast(u8, pipe_name, 1, pattern)) {
            return pattern;
        }
    }
    return null;
}

// ====== Scan named pipes — returns list of suspicious pipes found ======
pub fn scanPipes() ![]PipeEvent {
    var events = std.ArrayList(PipeEvent).init(allocator);

    // On Windows, we would enumerate \\.\pipe\* using NtQueryDirectoryFile
    // or Win32 FindFirstFile/FindNextFile on the pipe namespace.
    // For now, we log a placeholder — real implementation uses Win32 API.

    // NOTE: This is a Linux-compatible stub. On Windows, the actual pipe
    // enumeration uses kernel32.FindFirstFileW("\\\\.\\pipe\\*").
    // The Zig stdlib doesn't have a direct pipe enumeration API,
    // so we must use Win32 API bindings when building for Windows.

    // Print scan status
    std.log.info("[Pipe Monitor] Scanning named pipes... (alert-only mode)", .{});

    // In production Windows build, this function:
    // 1. Calls FindFirstFileW("\\\\.\\pipe\\*", ...) to enumerate all pipes
    // 2. For each pipe name, checks against SUSPICIOUS_PIPE_PATTERNS
    // 3. Creates PipeEvent for suspicious matches
    // 4. Sends events to nids_analyze via channel or shared queue

    // Update stats
<<<<<<< HEAD
    stats.last_scan_time = std.time.milliTimestamp();

=======
    stats.last_scan_time = @bitCast(std.time.milliTimestamp());
    
>>>>>>> fix(zig-0.13.0): comprehensive compilation fixes for Zig 0.13.0 compatibility
    return events.toOwnedSlice();
}

// ====== Print stats summary ======
pub fn printStats() void {
    std.log.info("[Pipe Monitor Stats] Total pipes: {}, Suspicious: {}, Last scan: {}ms ago", .{
        stats.total_pipes,
        stats.suspicious_pipes,
        @as(u64, @bitCast(std.time.milliTimestamp())) -% stats.last_scan_time,
    });
}

// ====== Main pipe monitor loop (Thread 5) ======
pub fn pipeMonitorLoop() !void {
    std.log.info("[Pipe Monitor] Thread 5 started — scanning every 5 seconds", .{});

    while (true) {
        const events = try scanPipes();

        // Process suspicious events
        for (events) |event| {
            if (event.risk_level.len > 0) {
                std.log.warn("[Pipe Monitor ALERT] {} pipe '{}' — Rule: {} — Risk: {}", .{
                    event.event_type,
                    event.pipe_name,
                    event.matched_rule,
                    event.risk_level,
                });
                stats.suspicious_pipes += 1;

                // TODO: Send event to nids_analyze.inspect_pipe_event()
                // via inter-thread channel or atomic queue
            }
        }

        allocator.free(events);
        printStats();

        // Scan every 5 seconds (configurable)
        std.time.sleep(5 * std.time.ns_per_s);
    }
}
