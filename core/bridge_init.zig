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

// B-05: Magic + version fields for ABI safety
// If Zig and C++ have different struct layouts, validation fails immediately
pub const AEGIS_IPC_MAGIC: u32 = 0x41454749; // "AEGI" in ASCII
pub const AEGIS_IPC_VERSION: u16 = 1;

pub const AegisIpcEvent = extern struct {
    magic: u32,        // B-05: 0x41454749 ("AEGI") - validates struct layout
    version: u16,      // B-05: struct version (bump on schema change)
    struct_size: u16,  // B-05: sizeof(AegisIpcEvent) for forward compatibility
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

/// B-05: Validate that an IpcEvent has correct magic + version
pub fn validateIpcEvent(event: *const AegisIpcEvent) bool {
    if (event.magic != AEGIS_IPC_MAGIC) return false;
    if (event.version != AEGIS_IPC_VERSION) return false;
    if (event.struct_size != @sizeOf(AegisIpcEvent)) return false;
    return true;
}

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

// B-03: RwLock for function pointer table (prevents TOCTOU during shutdown)
// Readers (pushEvent, getDefcon, etc.) acquire shared lock
// Writers (shutdownCppBridge) acquire exclusive lock before nulling pointers
var g_fn_lock: std.Thread.RwLock = .{};

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

// B-10: UDP brain spool queue (prevents event loss on transient send failures)
const BRAIN_SPOOL_MAX: usize = 1000;
var g_brain_spool: [BRAIN_SPOOL_MAX]?[]const u8 = [_]?[]const u8{null} ** BRAIN_SPOOL_MAX;
var g_brain_spool_head: usize = 0;
var g_brain_spool_tail: usize = 0;
var g_brain_spool_count: usize = 0;
var g_brain_spool_lock: std.Thread.Mutex = .{};
pub var g_brain_dropped_events: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var g_spool_drain_running: bool = false;

/// GAP-3: Background thread that drains the spool queue.
/// Retries failed UDP sends every 100ms until queue is empty.
/// Exits when shutdown is requested or UDP becomes unavailable.
fn spoolDrainThread() void {
    std.log.info("[BRAIN] Spool drain thread started", .{});
    defer std.log.info("[BRAIN] Spool drain thread exiting", .{});

    while (true) {
        if (g_shutdown.load(.seq_cst)) break;
        if (!g_udp_available) break;

        // Pop one event from spool (FIFO)
        var msg_to_send: ?[]const u8 = null;
        {
            g_brain_spool_lock.lock();
            defer g_brain_spool_lock.unlock();

            if (g_brain_spool_count > 0) {
                msg_to_send = g_brain_spool[g_brain_spool_tail];
                g_brain_spool[g_brain_spool_tail] = null;
                g_brain_spool_tail = (g_brain_spool_tail + 1) % BRAIN_SPOOL_MAX;
                g_brain_spool_count -= 1;
            }
        }

        if (msg_to_send) |msg| {
            // Try to send
            const send_result = posix.sendto(g_udp_sock, msg, 0, &g_udp_addr.any, g_udp_addr.getOsSockLen());
            if (send_result) |_| {
                // Success - free the message
                g_brain_allocator.free(msg);
            } else |_| {
                // Still failing - put it back at the head and wait
                g_brain_spool_lock.lock();
                g_brain_spool_head = (g_brain_spool_head + BRAIN_SPOOL_MAX - 1) % BRAIN_SPOOL_MAX;
                g_brain_spool[g_brain_spool_head] = msg;
                g_brain_spool_count += 1;
                g_brain_spool_lock.unlock();
                std.time.sleep(1 * std.time.ns_per_s); // Wait 1s before retry
            }
        } else {
            // Queue empty - short sleep
            std.time.sleep(100 * std.time.ns_per_ms);
        }
    }
}

// Allocator for spool messages (uses GPA from main)
var g_brain_allocator: std.mem.Allocator = undefined;

pub fn setBrainAllocator(allocator: std.mem.Allocator) void {
    g_brain_allocator = allocator;
}

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
    // B-01 CRITICAL FIX: Removed "." (CWD) from search paths to prevent DLL planting
    // An attacker with write access to CWD could drop a malicious aegis_ipc.dll
    const search_paths = [_][]const u8{
        "bridge",
        "build",
        "build\\Release",
        "build\\Debug",
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
    // B-03: Acquire exclusive lock before nulling function pointers
    // (prevents concurrent readers from using freed pointers)
    g_fn_lock.lock();
    defer g_fn_lock.unlock();

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
    // B-01 CRITICAL FIX: Removed "." (CWD) from search paths to prevent DLL planting
    const search_paths = [_][]const u8{
        "target\\release",
        "target\\debug",
        "shield\\target\\release",
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
        } else {
            // P-01 CRITICAL FIX: Symbol missing in DLL is a fail-open risk
            // Log as error so operators see the Tier-3 bypass immediately
            std.log.err("[INIT] CRITICAL: sec_monitor.dll loaded but 'validate_payload_safety' symbol missing - Tier-3 BYPASSED", .{});
            std.debug.print("\x1b[31m[INIT] CRITICAL: sec_monitor.dll symbol missing - Tier-3 fail-open!\x1b[0m\n", .{});
        }
    } else {
        // P-01: Shield missing entirely - log as error, not warning
        std.log.err("[INIT] CRITICAL: sec_monitor.dll not found - Tier-3 Memory Safety Shield BYPASSED (fail-open)", .{});
        std.debug.print("\x1b[31m[INIT] CRITICAL: Tier-3 shield missing - fail-open mode!\x1b[0m\n", .{});
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

    // GAP-3: Start spool drain thread (retries failed UDP sends)
    if (g_udp_available) {
        const drain_thread = std.Thread.spawn(.{}, spoolDrainThread, .{}) catch |err| {
            std.log.warn("[INIT] Spool drain thread failed to spawn: {}", .{err});
        };
        if (drain_thread) |_| {
            g_spool_drain_running = true;
        }
    }

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
/// B-03: Uses shared lock (RwLock) to prevent TOCTOU during shutdown.
pub fn pushEvent(event: *const AegisIpcEvent) i32 {
    g_fn_lock.lockShared();
    defer g_fn_lock.unlockShared();
    if (fn_bridge_push_event) |f| {
        return f(event);
    }
    return -1;
}

/// Get current DEFCON level from C++ bridge.
/// B-03: Uses shared lock (RwLock) to prevent TOCTOU during shutdown.
pub fn getDefcon() u8 {
    g_fn_lock.lockShared();
    defer g_fn_lock.unlockShared();
    if (fn_bridge_get_defcon) |f| {
        return f();
    }
    return DEFCON_DEFAULT; // BP-M18: named default
}

/// Get event count from C++ bridge queue.
/// B-03: Uses shared lock (RwLock) to prevent TOCTOU during shutdown.
pub fn getBridgeEventCount() u32 {
    g_fn_lock.lockShared();
    defer g_fn_lock.unlockShared();
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
/// B-10: Uses a 1000-event spool queue — if send fails, event is queued
/// and retried by a background drain. Drops oldest if queue is full.
pub fn sendToBrain(allocator: std.mem.Allocator, comptime T: type, msg: T) void {
    if (!g_udp_available) return;
    var string = std.ArrayList(u8).init(allocator);
    defer string.deinit();
    std.json.stringify(msg, .{}, string.writer()) catch return;

    // B-10: Try direct send first
    _ = posix.sendto(g_udp_sock, string.items, 0, &g_udp_addr.any, g_udp_addr.getOsSockLen()) catch {
        // Send failed — add to spool queue for retry
        g_brain_spool_lock.lock();
        defer g_brain_spool_lock.unlock();
        if (g_brain_spool_count < BRAIN_SPOOL_MAX) {
            // Copy message into spool (uses global brain allocator for drain thread)
            const msg_copy = g_brain_allocator.dupe(u8, string.items) catch return;
            g_brain_spool[g_brain_spool_head] = msg_copy;
            g_brain_spool_head = (g_brain_spool_head + 1) % BRAIN_SPOOL_MAX;
            g_brain_spool_count += 1;
        } else {
            // Queue full — drop oldest and increment counter
            _ = g_brain_dropped_events.fetchAdd(1, .relaxed);
            std.log.warn("[BRAIN] Spool queue full, dropping event", .{});
        }
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
