//! nids_analyze.zig - AEGIS NIDS Analysis Module (Rewrite Phase 5, Hotfix 5)
//!
//! Hotfix 5: This file was previously full of broken syntax from commented-out
//! references to removed modules (policy_int, forensics_int, det_ctx, etc.).
//! Replaced with a minimal clean stub that compiles and exports the symbols
//! that nids_capture.zig and windows_capture.zig depend on.
//!
//! In the rewrite architecture, the actual analysis pipeline lives in
//! core/runtime/dispatcher.zig (Phase 5) and will be extended in Phase 6+
//! (Flow -> Detection -> Correlation -> Threat Intel -> Brain -> Policy -> PEP).
//! This file is a transitional shim that will be removed in Phase 23
//! (Legacy Removal).

const std = @import("std");
const canonical = @import("canonical_event.zig");
const nose = @import("nose_contract.zig");
const forensic_log = @import("forensic_log.zig");
const bridge_init = @import("bridge_init.zig");

// ============================================================
// Module state
// ============================================================

var g_initialized: bool = false;
var g_shutdown_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

// ============================================================
// Public API (called by nids_capture.zig / windows_capture.zig)
// ============================================================

/// Initialize the analysis module.
/// In the rewrite, this is a thin shim - real init happens in runtime/lifecycle.zig.
pub fn init() void {
    if (g_initialized) return;
    g_initialized = true;
    std.log.info("[ANALYZE] Analysis module initialized (stub)", .{});
}

/// Request graceful shutdown of the analysis loop.
pub fn requestShutdown() void {
    g_shutdown_requested.store(true, .release);
    std.log.info("[ANALYZE] Shutdown requested", .{});
}

/// Check if shutdown has been requested.
pub fn isShutdownRequested() bool {
    return g_shutdown_requested.load(.acquire);
}

/// Check if the module is initialized.
pub fn isInitialized() bool {
    return g_initialized;
}

/// Reset state (for tests).
pub fn reset() void {
    g_initialized = false;
    g_shutdown_requested.store(false, .release);
}

// ============================================================
// Drain loop (called from main thread or runtime)
// ============================================================

/// Process events from the nose queue until shutdown is requested.
/// This is the minimal stub - the real pipeline will be built in Phase 6+.
pub fn eventFabricDrain() void {
    std.log.info("[FABRIC] Event fabric drain thread started", .{});
    defer std.log.info("[FABRIC] Event fabric drain thread exiting", .{});

    while (true) {
        if (bridge_init.g_shutdown.load(.seq_cst)) break;
        if (g_shutdown_requested.load(.acquire)) break;

        if (nose.hasEvents()) {
            if (nose.popEvent()) |event| {
                forensic_log.log(.{
                    .level = if (event.severity >= 3) .critical else if (event.severity >= 2) .warn else .info,
                    .event = "FABRIC_EVENT",
                    .src_ip = event.source_ip,
                    .src_port = event.source_port,
                    .session_id = event.session_id,
                });
            }
        } else {
            std.time.sleep(100 * std.time.ns_per_ms);
        }
    }
}

// ============================================================
// Tests
// ============================================================

test "init and reset" {
    reset();
    try std.testing.expect(!isInitialized());
    init();
    try std.testing.expect(isInitialized());
    // Double init is a no-op
    init();
    try std.testing.expect(isInitialized());
    reset();
    try std.testing.expect(!isInitialized());
}

test "shutdown request" {
    reset();
    try std.testing.expect(!isShutdownRequested());
    requestShutdown();
    try std.testing.expect(isShutdownRequested());
    reset();
    try std.testing.expect(!isShutdownRequested());
}
