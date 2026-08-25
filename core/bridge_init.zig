//! bridge_init.zig - AEGIS NIDS Unified Bridge Initialization (M3)
//!
//! Centralized startup/shutdown for ALL bridge connections.
//! Called from nids_main.zig before spawning sensor threads.
//!
//! Bridges initialized:
//!   1. WFP IOCTL  (wfp_ioctl.zig)  -> opens AegisWfpDevice
//!   2. C++ IPC DLL (aegis_ipc.dll)  -> runtime DynLib
//!   3. Rust DLL    (sec_monitor.dll)  -> runtime DynLib
//!   4. UDP Brain   (127.0.0.1:9999)  -> event logging
//!
//! Note: Named Pipe + TCP listener remain in nids_analyze.zig
//! (they are accept-loop threads, not initialization).

const std = @import("std");

pub const AEGIS_VERSION = "1.0.0-dev";
pub const AEGIS_BUILD = "zig-0.13";
const wfp_ioctl = @import("wfp_ioctl.zig");
const win = std.os.windows;

// BP-I2: Named constants for UDP Brain logger configuration
const UDP_BRAIN_IP = "127.0.0.1";
const UDP_BRAIN_PORT: u16 = 9999;
// BP-M18: Default DEFCON level (normal = 5)
const DEFCON_DEFAULT: u8 = 5;

// ============================================================
// Bridge Status Flags
// ============================================================

pub const BridgeState = struct {
    wfp_ioctl: bool = false,
    cpp_bridge: bool = false,
    rust_shield: bool = false,
    udp_brain: bool = false,
};

var g_state = BridgeState{};

// ============================================================
// C++ IPC Bridge DLL (runtime loaded, same as nids_analyze.zig)
// ============================================================

pub const AegisIpcEvent = extern struct {
    event_type: u32,
    source_ip: u32,
    dest_ip: u32,
    source_port: u16,
    dest_port: u16,
    protocol: u8,
    direction: u8,
    layer_id: u8,
    tier_result: u8,
    payload_length: u32,
    rule_id: u32,
    severity: u32,
    reserved: u32,
    timestamp: u64,
    source_pid: u32,
    defcon_impact: u32,
};

const FnBridgeInit = *const fn () callconv(.C) i32;
const FnBridgeShutdown = *const fn () callconv(.C) i32;
const FnBridgePushEvent = *const fn (*const AegisIpcEvent) callconv(.C) i32;
const FnBridgeGetDefcon = *const fn () callconv(.C) u8;
const FnBridgeGetEventCount = *const fn () callconv(.C) u32;

var g_bridge_dll: ?std.DynLib = null;
var fn_bridge_init: ?FnBridgeInit = null;
var fn_bridge_shutdown: ?FnBridgeShutdown = null;
var fn_bridge_push_event: ?FnBridgePushEvent = null;
var fn_bridge_get_defcon: ?FnBridgeGetDefcon = null;
var fn_bridge_get_event_count: ?FnBridgeGetEventCount = null;
var g_bridge_initialized: bool = false;

// ============================================================
// Rust Safety Shield DLL
// ============================================================

const FnValidatePayloadSafety = *const fn ([*]const u8, usize) callconv(.C) bool;

var g_rust_dll: ?std.DynLib = null;
var fn_validate_payload_safety: ?FnValidatePayloadSafety = null;

// ============================================================
// UDP Brain Logger
// ============================================================

const net = std.net;
const posix = std.posix;

var g_udp_sock: posix.socket_t = 0;
var g_udp_addr: net.Address = undefined;
var g_udp_available: bool = false;

// ============================================================
// 1. WFP IOCTL Bridge (M2)
// ============================================================

fn initWfpIoctl() void {
    if (wfp_ioctl.init()) {
        g_state.wfp_ioctl = true;
    } else {
        std.log.warn("[INIT] WFP IOCTL: device not available (driver not loaded?)", .{});
        std.debug.print("[INIT] WFP IOCTL: device not available (driver not loaded?)\n", .{});
    }
}

fn shutdownWfpIoctl() void {
    wfp_ioctl.shutdown();
    g_state.wfp_ioctl = false;
}

// ============================================================
// 2. C++ IPC Bridge DLL
// ============================================================

fn initCppBridge() void {
    const dll_names = [_][]const u8{
        "aegis_ipc.dll",
        "libaegis_ipc.so",
    };
    const search_paths = [_][]const u8{
        "bridge",
        "build",
        "build\\Release",
        "build\\Debug",
        "target\\release",
        ".",
    };

    for (dll_names) |dll_name| {
        for (search_paths) |dir| {
            var path_buf: [512]u8 = undefined;
            const path = std.fmt.bufPrint(&path_buf, "{s}\\{s}", .{ dir, dll_name }) catch continue;
            if (std.DynLib.open(path)) |lib| {
                g_bridge_dll = lib;
                std.log.info("[INIT] C++ Bridge loaded: {s}", .{path});
                std.debug.print("[INIT] C++ Bridge loaded: {s}\n", .{path});
                break;
            } else |_| {}
        }
        if (g_bridge_dll == null) {
            if (std.DynLib.open(dll_name)) |lib| {
                g_bridge_dll = lib;
                std.log.info("[INIT] C++ Bridge loaded from system: {s}", .{dll_name});
                std.debug.print("[INIT] C++ Bridge loaded from system: {s}\n", .{dll_name});
            } else |_| {}
        }
        if (g_bridge_dll != null) break;
    }

    if (g_bridge_dll) |*lib| {
        fn_bridge_init = lib.lookup(FnBridgeInit, "aegis_bridge_init");
        fn_bridge_shutdown = lib.lookup(FnBridgeShutdown, "aegis_bridge_shutdown");
        fn_bridge_push_event = lib.lookup(FnBridgePushEvent, "aegis_bridge_push_event");
        fn_bridge_get_defcon = lib.lookup(FnBridgeGetDefcon, "aegis_bridge_get_defcon");
        fn_bridge_get_event_count = lib.lookup(FnBridgeGetEventCount, "aegis_bridge_get_event_count");

        if (fn_bridge_init) |f| {
            const rc = f();
            if (rc == 0) {
                g_bridge_initialized = true;
                g_state.cpp_bridge = true;
                std.log.info("[INIT] C++ IPC Bridge initialized (rc=0)", .{});
                std.debug.print("\x1b[32m[INIT] C++ IPC Bridge initialized (rc=0)\x1b[0m\n", .{});
            } else {
                std.log.warn("[INIT] C++ Bridge init failed (rc={d})", .{rc});
                std.debug.print("\x1b[33m[INIT] C++ Bridge init failed (rc={d})\x1b[0m\n", .{rc});
            }
        } else {
            std.log.warn("[INIT] C++ Bridge DLL loaded but symbols not found", .{});
            std.debug.print("\x1b[33m[INIT] C++ Bridge DLL loaded but symbols not found\x1b[0m\n", .{});
        }
    } else {
        std.log.warn("[INIT] aegis_ipc.dll not found - running without C++ Bridge", .{});
        std.debug.print("\x1b[33m[INIT] aegis_ipc.dll not found - running without C++ Bridge\x1b[0m\n", .{});
    }
}

fn shutdownCppBridge() void {
    if (fn_bridge_shutdown) |f| {
        _ = f();
    }
    g_bridge_initialized = false;
    g_state.cpp_bridge = false;
    if (g_bridge_dll) |*lib| lib.close();
    g_bridge_dll = null;
    fn_bridge_init = null;
    fn_bridge_shutdown = null;
    fn_bridge_push_event = null;
    fn_bridge_get_defcon = null;
    fn_bridge_get_event_count = null;
}

// ============================================================
// 3. Rust Safety Shield DLL
// ============================================================

fn initRustShield() void {
    const dll_names = [_][]const u8{
        "sec_monitor.dll",
        "libsec_monitor.so",
    };
    const search_paths = [_][]const u8{
        "target\\release",
        "target\\debug",
        ".",
    };

    for (dll_names) |dll_name| {
        for (search_paths) |dir| {
            var path_buf: [512]u8 = undefined;
            const path = std.fmt.bufPrint(&path_buf, "{s}\\{s}", .{ dir, dll_name }) catch continue;
            if (std.DynLib.open(path)) |lib| {
                g_rust_dll = lib;
                std.log.info("[INIT] Rust Shield loaded: {s}", .{path});
                std.debug.print("[INIT] Rust Shield loaded: {s}\n", .{path});
                break;
            } else |_| {}
        }
        if (g_rust_dll == null) {
            if (std.DynLib.open(dll_name)) |lib| {
                g_rust_dll = lib;
                std.log.info("[INIT] Rust Shield from system: {s}", .{dll_name});
                std.debug.print("[INIT] Rust Shield from system: {s}\n", .{dll_name});
            } else |_| {}
        }
        if (g_rust_dll != null) break;
    }

    if (g_rust_dll) |*lib| {
        fn_validate_payload_safety = lib.lookup(FnValidatePayloadSafety, "validate_payload_safety");
        if (fn_validate_payload_safety != null) {
            g_state.rust_shield = true;
            std.log.info("[INIT] Rust Memory Safety Shield active", .{});
            std.debug.print("\x1b[32m[INIT] Rust Memory Safety Shield active\x1b[0m\n", .{});
        }
    } else {
        std.log.warn("[INIT] sec_monitor.dll not found - running without Shield", .{});
        std.debug.print("\x1b[33m[INIT] sec_monitor.dll not found - running without Shield\x1b[0m\n", .{});
    }
}

fn shutdownRustShield() void {
    g_state.rust_shield = false;
    if (g_rust_dll) |*lib| lib.close();
    g_rust_dll = null;
    fn_validate_payload_safety = null;
}

// ============================================================
// 4. UDP Brain Logger
// ============================================================

fn initUdpBrain() void {
    if (net.Address.parseIp4(UDP_BRAIN_IP, UDP_BRAIN_PORT)) |addr| {
        g_udp_addr = addr;
        if (posix.socket(addr.any.family, posix.SOCK.DGRAM, 0)) |sock| {
            g_udp_sock = sock;
            g_udp_available = true;
            g_state.udp_brain = true;
            std.log.info("[INIT] UDP brain logger on {s}:{d}", .{ UDP_BRAIN_IP, UDP_BRAIN_PORT });
            std.debug.print("\x1b[32m[INIT] UDP brain logger on {s}:{d}\x1b[0m\n", .{ UDP_BRAIN_IP, UDP_BRAIN_PORT });
        } else |_| {
            std.log.warn("[INIT] UDP socket failed - brain logging disabled", .{});
            std.debug.print("\x1b[33m[INIT] UDP socket failed - brain logging disabled\x1b[0m\n", .{});
        }
    } else |_| {
        std.log.warn("[INIT] UDP parse failed - brain logging disabled", .{});
        std.debug.print("\x1b[33m[INIT] UDP parse failed - brain logging disabled\x1b[0m\n", .{});
    }
}

fn shutdownUdpBrain() void {
    if (g_udp_available) {
        posix.close(g_udp_sock);
        g_udp_available = false;
        g_state.udp_brain = false;
    }
}

// ============================================================
// PUBLIC API
// ============================================================

// ====== BP8: Global Shutdown Flag ======
/// Set by CTRL+C handler (see nids_analyze.ctrlHandler).
/// Thread loops should check this periodically (typically every iteration
/// or every 10-100ms in blocking calls) for graceful drain on shutdown.
///
/// Phase 5 (F3) replaced ExitProcess with graceful shutdown via this flag;
/// status reporter + sensor threads now exit cleanly when this is set.
pub var g_shutdown = std.atomic.Value(bool).init(false);

/// Signal all threads to exit. Safe to call multiple times.
pub fn requestShutdown() void {
    if (!g_shutdown.load(.seq_cst)) {
        std.log.warn("[SHUTDOWN] Signal received, draining threads", .{});
        std.debug.print("\x1b[33m[SHUTDOWN] Signal received, draining threads...\x1b[0m\n", .{});
    }
    g_shutdown.store(true, .seq_cst);
}

/// Initialize ALL bridges. Call once at startup before spawning threads.
/// Initializes WFP IOCTL, C++ IPC DLL, Rust Shield DLL, and UDP Brain logger.
/// Bridges that fail to initialize are logged but do not abort startup
/// (the NIDS runs in degraded mode without that specific bridge).
pub fn initAll() void {
    std.log.info("[INIT] AEGIS BRIDGE INITIALIZATION", .{});
    std.debug.print("\n--- AEGIS BRIDGE INITIALIZATION ---\n", .{});

    // 1. WFP kernel driver IOCTL (M2)
    initWfpIoctl();

    // 2. C++ IPC Bridge DLL
    initCppBridge();

    // 3. Rust Memory Safety Shield
    initRustShield();

    // 4. UDP Brain Logger
    initUdpBrain();

    // Summary
    const active = @as(u32, @intFromBool(g_state.wfp_ioctl)) +
        @as(u32, @intFromBool(g_state.cpp_bridge)) +
        @as(u32, @intFromBool(g_state.rust_shield)) +
        @as(u32, @intFromBool(g_state.udp_brain));
    std.log.info("[INIT] Bridge status: {d}/4 active (wfp={} cpp={} rust={} udp={})", .{
        active,
        g_state.wfp_ioctl,
        g_state.cpp_bridge,
        g_state.rust_shield,
        g_state.udp_brain,
    });
    std.debug.print("[INIT] Bridge status: {d}/4 active\n", .{active});
    // BP-L15: Bridge status summary visible in release builds via std.log
    std.log.info("[INIT]   WFP IOCTL:    {s}", .{if (g_state.wfp_ioctl) "OK" else "--"});
    std.log.info("[INIT]   C++ Bridge:  {s}", .{if (g_state.cpp_bridge) "OK" else "--"});
    std.log.info("[INIT]   Rust Shield: {s}", .{if (g_state.rust_shield) "OK" else "--"});
    std.log.info("[INIT]   UDP Brain:   {s}", .{if (g_state.udp_brain) "OK" else "--"});
    std.debug.print("[INIT]   WFP IOCTL:    {s}\n", .{if (g_state.wfp_ioctl) "OK" else "--"});
    std.debug.print("[INIT]   C++ Bridge:  {s}\n", .{if (g_state.cpp_bridge) "OK" else "--"});
    std.debug.print("[INIT]   Rust Shield: {s}\n", .{if (g_state.rust_shield) "OK" else "--"});
    std.debug.print("[INIT]   UDP Brain:   {s}\n", .{if (g_state.udp_brain) "OK" else "--"});
}

/// Shutdown ALL bridges. Call on process exit.
pub fn shutdownAll() void {
    std.log.info("[SHUTDOWN] AEGIS BRIDGE SHUTDOWN", .{});
    std.debug.print("\n--- AEGIS BRIDGE SHUTDOWN ---\n", .{});
    shutdownUdpBrain();
    shutdownCppBridge();
    shutdownRustShield();
    shutdownWfpIoctl();
}

/// Get the current bridge state (for status reporting).
pub fn getState() BridgeState {
    return g_state;
}

// ============================================================
// PUBLIC: Re-exported bridge functions for other modules
// ============================================================

/// Check if C++ bridge is initialized and ready.
pub fn isBridgeReady() bool {
    return g_bridge_initialized;
}

/// Check if WFP IOCTL device is connected.
pub fn isWfpReady() bool {
    return wfp_ioctl.isConnected();
}

/// Push event to C++ bridge (returns 0 on success, -1 if unavailable).
pub fn pushEvent(event: *const AegisIpcEvent) i32 {
    if (fn_bridge_push_event) |f| {
        return f(event);
    }
    return -1;
}

/// Get current DEFCON level from C++ bridge.
pub fn getDefcon() u8 {
    if (fn_bridge_get_defcon) |f| {
        return f();
    }
    return DEFCON_DEFAULT; // BP-M18: named default
}

/// Get event count from C++ bridge queue.
pub fn getBridgeEventCount() u32 {
    if (fn_bridge_get_event_count) |f| {
        return f();
    }
    return 0;
}

/// Validate payload safety via Rust shield (returns true if safe).
/// Fail-open: returns true if shield is not loaded.
pub fn validatePayloadSafety(data: [*]const u8, len: usize) bool {
    if (fn_validate_payload_safety) |f| {
        return f(data, len);
    }
    return true; // fail-open when Rust DLL not available
}

/// Send JSON message to Python brain via UDP.
pub fn sendToBrain(allocator: std.mem.Allocator, comptime T: type, msg: T) void {
    if (!g_udp_available) return;
    var string = std.ArrayList(u8).init(allocator);
    defer string.deinit();
    std.json.stringify(msg, .{}, string.writer()) catch return;
    _ = posix.sendto(g_udp_sock, string.items, 0, &g_udp_addr.any, g_udp_addr.getOsSockLen()) catch |err| {
        std.log.warn("[BRAIN] UDP send failed: {}", .{err});
    };
}

/// Block IP via WFP IOCTL (convenience wrapper).
pub fn blockIp(ipv4: u32) bool {
    return wfp_ioctl.block_ip(ipv4);
}

/// Read events from WFP driver ring buffer.
pub fn readWfpEvents(buf: []u8) u32 {
    return wfp_ioctl.read_events(buf);
}

/// Get WFP ring buffer stats.
pub fn getWfpStats() ?wfp_ioctl.WfpRingStats {
    return wfp_ioctl.get_stats();
}

/// Print bridge status (call periodically from a status thread).
pub fn printStatus() void {
    if (g_bridge_initialized) {
        const count = getBridgeEventCount();
        const defcon = getDefcon();
        // BP-L15: Bridge status visible in release builds via std.log
        std.log.info("[BRIDGE] C++ queue: {d} events | DEFCON: {d}", .{ count, defcon });
        std.debug.print("[BRIDGE] C++ queue: {d} events | DEFCON: {d}\n", .{ count, defcon });
    }
    if (g_state.wfp_ioctl) {
        if (getWfpStats()) |stats| {
            std.log.info("[BRIDGE] WFP ring: {d}/{} bytes", .{ stats.currentUsedBytes, stats.capacity });
            std.debug.print("[BRIDGE] WFP ring: {d}/{} bytes\n", .{ stats.currentUsedBytes, stats.capacity });
        }
    }
}
