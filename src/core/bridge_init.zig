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
pub const AEGIS_BUILD = "zig-0.13.0";
pub const SHIELD_VERSION = "REMOVED";  // PEP-001: shield removed, enforcement via Rust PEP only
const rust_pep = @import("rust_pep.zig");
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
    udp_brain: bool = false,
};

var g_state = BridgeState{};

/// CTRL-002: read-only snapshot of the bridge/dependency flags so the control
/// plane can report real subsystem state instead of build-time capability
/// flags. Used by src/platform/win32_pipe.zig health.check.
pub fn status() BridgeState {
    return g_state;
}

/// CTRL-002: true when every in-process bridge subsystem is actually up. When
/// false the runtime still serves the spine but reports `degraded: true`.
pub fn allActive() bool {
    return g_state.wfp_ioctl and g_state.cpp_bridge and g_state.udp_brain;
}

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
// 3. UDP Brain Logger
// ============================================================

const net = std.net;
const posix = std.posix;

// G28 fix: On Windows, posix.socket_t is a pointer type (SOCKET), so we
// cannot initialize to the integer literal 0. Use null-aware pattern:
//   - On Linux, socket_t is i32; init to -1 (invalid).
//   - On Windows, socket_t is a pointer; init to null (via optional).
// We declare as `?posix.socket_t` to make this portable.
var g_udp_sock: ?posix.socket_t = null;
var g_udp_addr: net.Address = undefined;
var g_udp_available: bool = false;

// B2-AUTH-076: shared-secret auth for the UDP brain loop. Any local
// process can send to 127.0.0.1:9999, and an unauthenticated "TIER-1
// VERIFIED" offer reaches the brain's block-request path — so offers
// carry HMAC-SHA256 when AEGIS_BRAIN_SECRET is set on both ends.
// The secret is loaded once at startup (never logged); rotation is a
// restart of daemon + brain with the new value. Absent secret keeps
// the legacy bare-JSON wire (backwards compatible, documented
// local-spoofable in UNWIRED_INVENTORY until this slice landed).
var g_brain_secret: ?[]const u8 = null;

fn loadBrainSecret() void {
    const s = std.process.getEnvVarOwned(std.heap.page_allocator, "AEGIS_BRAIN_SECRET") catch return;
    if (s.len == 0) {
        std.heap.page_allocator.free(s);
        std.log.warn("[BRAIN-AUTH] no AEGIS_BRAIN_SECRET — loopback offers are unauthenticated", .{});
        return;
    }
    if (s.len < 16) std.log.warn("[BRAIN-AUTH] secret shorter than 16 bytes; use a longer value", .{});
    g_brain_secret = s;
    std.log.info("[BRAIN-AUTH] shared-secret ON (offers carry HMAC-SHA256)", .{});
}

// B-10: UDP brain spool queue (prevents event loss on transient send failures)
const BRAIN_SPOOL_MAX: usize = 1000;
var g_brain_spool: [BRAIN_SPOOL_MAX]?[]const u8 = [_]?[]const u8{null} ** BRAIN_SPOOL_MAX;
var g_brain_spool_head: usize = 0;
var g_brain_spool_tail: usize = 0;
var g_brain_spool_count: usize = 0;
var g_brain_spool_lock: std.Thread.Mutex = .{};
pub var g_brain_dropped_events: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var g_spool_drain_running: bool = false;
// EVT-156: the drain thread handle used to be dropped at spawn
// (see initAll): shutdown closed the UDP socket while the thread could
// still be inside sendto -> TOCTOU + leaked join (.analysis/runtime.md
// "Ownership gap: bridge spool thread"). Stored now, joined in
// joinSpoolDrainThread before any socket close.
var g_spool_drain_thread: ?std.Thread = null;

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
            // G28: g_udp_sock is now optional; unwrap it. If we have a
            // valid socket, try a non-blocking send. If the socket is null
            // or the send fails, put the message back at the head.
            if (g_udp_sock) |sock| {
                const send_result = posix.sendto(sock, msg, 0, &g_udp_addr.any, g_udp_addr.getOsSockLen());
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
                // No socket available; put message back at the head and wait
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
    if (rust_pep.wfpInit()) {
        g_state.wfp_ioctl = true;
    } else {
        std.log.warn("[INIT] WFP IOCTL: device not available (driver not loaded?)", .{});
        std.debug.print("[INIT] WFP IOCTL: device not available (driver not loaded?)\n", .{});
    }
}

fn shutdownWfpIoctl() void {
    rust_pep.wfpShutdown();
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
        "dist",
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
// 4. UDP Brain Logger (init/shutdown in UDP section above)
// ============================================================

fn initUdpBrain() void {
    loadBrainSecret();
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
        // G28: g_udp_sock is now optional; unwrap before close.
        if (g_udp_sock) |sock| {
            posix.close(sock);
        }
        g_udp_sock = null;
        g_udp_available = false;
        g_state.udp_brain = false;
    }
}

/// Join the spool drain thread. Bounded: once g_shutdown is set the loop
/// sleeps at most 1s per iteration before breaking, and the flag store
/// below makes the join safe even if the caller never signaled shutdown.
/// Idempotent: a second call is a no-op (handle is nulled after join).
fn joinSpoolDrainThread() void {
    const t = g_spool_drain_thread orelse return;
    g_spool_drain_running = false;
    g_shutdown.store(true, .seq_cst);
    t.join();
    g_spool_drain_thread = null;
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
/// Initializes WFP IOCTL, C++ IPC DLL, and UDP Brain logger.
/// Bridges that fail to initialize are logged but do not abort startup
/// (the NIDS runs in degraded mode without that specific bridge).
pub fn initAll() void {
    std.log.info("[INIT] AEGIS BRIDGE INITIALIZATION", .{});
    std.debug.print("\n--- AEGIS BRIDGE INITIALIZATION ---\n", .{});

    // 1. WFP kernel driver IOCTL (M2) — read-only telemetry
    initWfpIoctl();

    // 2. C++ IPC Bridge DLL
    initCppBridge();

    // 3. UDP Brain Logger
    initUdpBrain();

    // GAP-3: Start spool drain thread (retries failed UDP sends)
    if (g_udp_available) {
        const drain_thread: ?std.Thread = blk: {
            const t = std.Thread.spawn(.{}, spoolDrainThread, .{}) catch |err| {
                std.log.warn("[INIT] Spool drain thread failed to spawn: {}", .{err});
                break :blk null;
            };
            break :blk t;
        };
        if (drain_thread) |t| {
            g_spool_drain_thread = t;
            g_spool_drain_running = true;
        }
    }

    // Summary
    const active = @as(u32, @intFromBool(g_state.wfp_ioctl)) +
        @as(u32, @intFromBool(g_state.cpp_bridge)) +
        @as(u32, @intFromBool(g_state.udp_brain));
    std.log.info("[INIT] Bridge status: {d}/3 active (wfp={} cpp={} udp={})", .{
        active,
        g_state.wfp_ioctl,
        g_state.cpp_bridge,
        g_state.udp_brain,
    });
    std.debug.print("[INIT] Bridge status: {d}/3 active\n", .{active});
    std.log.info("[INIT]   WFP IOCTL:    {s}", .{if (g_state.wfp_ioctl) "OK" else "--"});
    std.log.info("[INIT]   C++ Bridge:  {s}", .{if (g_state.cpp_bridge) "OK" else "--"});
    std.log.info("[INIT]   UDP Brain:   {s}", .{if (g_state.udp_brain) "OK" else "--"});
    std.debug.print("[INIT]   WFP IOCTL:    {s}\n", .{if (g_state.wfp_ioctl) "OK" else "--"});
    std.debug.print("[INIT]   C++ Bridge:  {s}\n", .{if (g_state.cpp_bridge) "OK" else "--"});
    std.debug.print("[INIT]   UDP Brain:   {s}\n", .{if (g_state.udp_brain) "OK" else "--"});
}

/// Shutdown ALL bridges. Call on process exit.
pub fn shutdownAll() void {
    std.log.info("[SHUTDOWN] AEGIS BRIDGE SHUTDOWN", .{});
    std.debug.print("\n--- AEGIS BRIDGE SHUTDOWN ---\n", .{});
    // EVT-156: requestShutdown is idempotent; calling it here guarantees
    // the drain loop can exit even on paths that never signaled shutdown.
    requestShutdown();
    // Join BEFORE the socket close: the thread must never be inside
    // sendto while shutdownUdpBrain closes the fd (TOCTOU, leaked join).
    joinSpoolDrainThread();
    shutdownUdpBrain();
    shutdownCppBridge();
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
    return rust_pep.wfpIsConnected();
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

/// P0.2: REMOVED — validatePayloadSafety stub deleted.
/// Payload safety is now determined by Tier-3 state (tier3_state.zig).
/// See nids_analyze.zig for the Tier-3 gating check.

/// Send JSON message to Python brain via UDP.
/// B-10: Uses a 1000-event spool queue ΓÇö if send fails, event is queued
/// and retried by a background drain. Drops oldest if queue is full.
/// Build the UDP brain wire bytes for a JSON body: bare body when no
/// secret is configured, otherwise "<64 lowercase hex HMAC-SHA256>.<body>".
/// The MAC covers the exact bytes sent, so the receiver verifies without
/// re-serializing JSON (no cross-language canonicalization). A legacy body
/// always starts with '{', so the "<hex>." prefix is an unambiguous
/// discriminator for the receiver.
pub fn formatBrainWire(allocator: std.mem.Allocator, body: []const u8, secret: ?[]const u8) ![]u8 {
    const s = secret orelse return allocator.dupe(u8, body);
    var mac: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, body, s);
    const hex = std.fmt.bytesToHex(mac, .lower);
    var out = try allocator.alloc(u8, hex.len + 1 + body.len);
    @memcpy(out[0..hex.len], &hex);
    out[hex.len] = '.';
    @memcpy(out[hex.len + 1 ..], body);
    return out;
}

pub fn sendToBrain(allocator: std.mem.Allocator, comptime T: type, msg: T) void {
    if (!g_udp_available) return;
    var string = std.ArrayList(u8).init(allocator);
    defer string.deinit();
    std.json.stringify(msg, .{}, string.writer()) catch return;

    const wire = formatBrainWire(allocator, string.items, g_brain_secret) catch return;
    defer allocator.free(wire);

    // B-10: Try direct send first (G28: unwrap optional g_udp_sock)
    if (g_udp_sock) |sock| {
        _ = posix.sendto(sock, wire, 0, &g_udp_addr.any, g_udp_addr.getOsSockLen()) catch {
            // Send failed ΓÇö add to spool queue for retry
            g_brain_spool_lock.lock();
            defer g_brain_spool_lock.unlock();
            if (g_brain_spool_count < BRAIN_SPOOL_MAX) {
                // Copy message into spool (uses global brain allocator for drain thread)
                const msg_copy = g_brain_allocator.dupe(u8, wire) catch return;
                g_brain_spool[g_brain_spool_head] = msg_copy;
                g_brain_spool_head = (g_brain_spool_head + 1) % BRAIN_SPOOL_MAX;
                g_brain_spool_count += 1;
            } else {
                // Queue full ΓÇö drop oldest and increment counter
                _ = g_brain_dropped_events.fetchAdd(1, .monotonic);
                std.log.warn("[BRAIN] Spool queue full, dropping event", .{});
            }
        };
    }
}

/// Block IP via WFP IOCTL (convenience wrapper).
pub fn blockIp(ipv4: u32) bool {
    return rust_pep.block_ip(ipv4);
}

/// Read events from WFP driver ring buffer.
pub fn readWfpEvents(buf: []u8) u32 {
    return rust_pep.read_events(buf);
}

/// Get WFP ring buffer stats.
pub fn getWfpStats() ?rust_pep.WfpRingStats {
    return rust_pep.get_stats();
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

test "brain wire HMAC matches the verified RFC 4231 test case 1" {
    // In-repo verified: Python hmac + manual ipad/opad recomputation agree.
    var mac: [32]u8 = undefined;
    const key = [_]u8{0x0b} ** 20;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, "Hi There", &key);
    try std.testing.expectEqualStrings(
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        &std.fmt.bytesToHex(mac, .lower),
    );
}

test "brain wire envelope carries the cross-language golden MAC" {
    // Shared golden, also asserted by tests/brain/test_brain_udp_auth.py:
    // secret "aegis-brain-auth-golden-v1" over the exact body bytes.
    const body = "{\"source\":\"zig_pipeline\",\"src_ip\":\"10.0.0.11\"}";
    const wire = try formatBrainWire(std.testing.allocator, body, "aegis-brain-auth-golden-v1");
    defer std.testing.allocator.free(wire);
    try std.testing.expectEqualStrings(
        "d9f85d9f559cc451d738ce842d99b37872e9e23fb309651cc869671b864fb02b." ++ body,
        wire,
    );
}

test "brain wire without secret is the bare body" {
    const wire = try formatBrainWire(std.testing.allocator, "{\"op\":\"HEALTH\"}", null);
    defer std.testing.allocator.free(wire);
    try std.testing.expectEqualStrings("{\"op\":\"HEALTH\"}", wire);
}

test "spool drain thread is stored and joined, never dropped" {
    // Ownership mechanics without UDP: store a short-lived thread through
    // the same globals shutdownAll joins, then join twice. join() stores
    // g_shutdown, so save/restore it: the test runner shares one process
    // with every other test and must not observe a shutdown.
    const prev_shutdown = g_shutdown.load(.seq_cst);
    defer g_shutdown.store(prev_shutdown, .seq_cst);
    const Quick = struct {
        fn run() void {}
    };
    g_spool_drain_thread = try std.Thread.spawn(.{}, Quick.run, .{});
    g_spool_drain_running = true;
    joinSpoolDrainThread();
    try std.testing.expect(g_spool_drain_thread == null);
    try std.testing.expect(!g_spool_drain_running);
    joinSpoolDrainThread(); // idempotent no-op, must not hang
    try std.testing.expect(g_spool_drain_thread == null);
}
