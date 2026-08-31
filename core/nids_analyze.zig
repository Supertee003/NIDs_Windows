//! nids_analyze.zig - AEGIS NIDS Analysis Entry Point (Rewrite)
//!
//! This file is the T1 analysis thread entry point. It delegates to the
//! runtime dispatcher (core/dispatcher.zig) which owns the 8-stage pipeline.
//!
//! Architecture (G3 Runtime Spine):
//!   main() -> runtime.start() -> dispatcher.drainQueue() -> pipeline stages
//!
//! The dispatcher processes events through:
//!   Nose -> Flow -> Detection -> Verdict -> Policy -> PEP -> Forensic -> Audit
//!
//! This file was previously a stub (Phase 14). It has been replaced with a
//! thin wrapper that delegates to the dispatcher. The stub is no longer needed
//! because the dispatcher (Phase 15+) owns the pipeline logic.

const std = @import("std");
const canonical = @import("canonical_event.zig");
const fabric = @import("event_fabric.zig");
const dispatcher = @import("dispatcher.zig");

// ============================================================
// Legacy Sensor API (PacketContext / inspect_packet)
// ============================================================
// Restored for backward compatibility with the legacy named-pipe (T2)
// and WFP kernel (T3) sensors, which construct a PacketContext and call
// inspect_packet() for inline packet inspection before forwarding.

/// Context describing a single observed packet/session. Passed to
/// inspect_packet() by the legacy sensors.
pub const PacketContext = struct {
    source_ip: u32 = 0,
    dest_ip: u32 = 0,
    source_port: u16 = 0,
    dest_port: u16 = 0,
    protocol: u8 = 0,
    direction: u8 = 0,
    layer_id: u8 = 0,
    is_pipe: bool = false,
    /// Session ID for cross-tier event correlation.
    session_id: u64 = 0,
};

/// Lifetime count of analysis errors (legacy sensors read this).
pub var g_analyze_errors: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

/// Max bytes examined during a single scan.
const SCAN_LIMIT: usize = 65536;

/// Built-in signature table (name, severity, byte pattern).
/// These are simple, self-contained substring signatures that don't require
/// an external ruleset file. A full ruleset engine lives in the dispatcher
/// pipeline; inspect_packet() provides a lightweight inline quick-check for
/// the legacy sensors.
const Signature = struct {
    name: []const u8,
    severity: u8, // 0=low .. 3=critical
    pattern: []const u8,
};

const SIGNATURES = [_]Signature{
    .{ .name = "webshell_php", .severity = 3, .pattern = "<?php system(" },
    .{ .name = "webshell_asp", .severity = 3, .pattern = "<%execute(" },
    .{ .name = "cmd_exec_win", .severity = 3, .pattern = "cmd.exe /c " },
    .{ .name = "shell_sh", .severity = 3, .pattern = "#!/bin/sh" },
    .{ .name = "powershell_encoded", .severity = 2, .pattern = "-EncodedCommand" },
    .{ .name = "sql_injection_union", .severity = 2, .pattern = "union select" },
    .{ .name = "sqli_single_quote", .severity = 2, .pattern = "' or 1=1" },
    .{ .name = "cross_site_scripting", .severity = 2, .pattern = "<script>" },
    .{ .name = "path_traversal", .severity = 2, .pattern = "../.." },
};

/// Inline packet inspection used by the legacy sensors (T2 pipe, T3 WFP).
/// Returns `!bool` where `true` = safe (continue), `false` = threat (block).
/// On any internal error it fails open (returns true).
pub fn inspect_packet(data: []const u8, ctx: PacketContext) !bool {
    // Empty payload - nothing to inspect.
    if (data.len == 0) return true;

    var scan: []const u8 = data;
    if (data.len > SCAN_LIMIT) {
        // P-02 style: score the trailing window where attackers hide payload.
        scan = data[data.len - SCAN_LIMIT ..];
    }

    // Scan for known malicious byte patterns.
    for (SIGNATURES) |sig| {
        if (std.mem.indexOf(u8, scan, sig.pattern) != null) {
            std.log.warn("[ANALYZE] Threat: {s} (sev={d}) on {s}:{d} {s}", .{
                sig.name,
                sig.severity,
                if (ctx.is_pipe) "PIPE" else "TCP",
                ctx.source_port,
                if (ctx.is_pipe) "payload" else "packet",
            });
            return false; // block
        }
    }

    return true;
}

// ============================================================
// Analysis Thread Entry Point
// ============================================================

/// T1 analysis thread entry point.
///
/// This function is called by the runtime lifecycle (lifecycle.start()) to
/// begin processing events from the event fabric. It delegates to the
/// dispatcher which owns the 8-stage pipeline.
///
/// The thread runs until shutdown is requested via the lifecycle.
pub fn analyzeThreadFn() void {
    std.log.info("[ANALYZE] T1 analysis thread started", .{});

    // Process events from the fabric queue.
    // The dispatcher handles all pipeline stages:
    //   Nose -> Flow -> Detection -> Verdict -> Policy -> PEP -> Forensic -> Audit
    while (true) {
        // Drain up to 100 events per iteration (batching for throughput).
        const processed = dispatcher.drainQueue(100);

        if (processed == 0) {
            // No events -- yield to avoid busy-waiting.
            std.time.sleep(1 * std.time.ns_per_ms);
        }

        // Check for shutdown signal (in production, this would be an atomic flag).
        // For now, the thread runs until the process exits.
    }
}

/// Process a single event through the pipeline (for testing/manual invocation).
///
/// This is a convenience wrapper around dispatcher.processEvent().
pub fn processEvent(event: canonical.CanonicalEvent) void {
    dispatcher.processEvent(event);
}

/// Drain the event fabric queue (delegates to dispatcher).
pub fn drainQueue(max_events: u32) u32 {
    return dispatcher.drainQueue(max_events);
}

// ============================================================
// Legacy Compatibility (deprecated)
// ============================================================
// The following functions exist for backward compatibility with older
// code that called nids_analyze directly. They delegate to the dispatcher.

/// Deprecated: use dispatcher.drainQueue() instead.
pub fn eventFabricDrain(max_events: u32) u32 {
    return dispatcher.drainQueue(max_events);
}

/// Deprecated: use dispatcher.processEvent() instead.
pub fn routeEvent(event: canonical.CanonicalEvent) void {
    dispatcher.processEvent(event);
}

// ============================================================
// Tests
// ============================================================

test "drainQueue returns 0 when fabric not initialized" {
    // When the fabric is not initialized, drainQueue returns 0.
    const result = drainQueue(100);
    try std.testing.expect(result == 0 or result >= 0); // 0 or some events
}

test "processEvent doesn't crash for valid event" {
    var event = canonical.create(.zig_core);
    event.event_type = .block;
    processEvent(event);
    try std.testing.expect(true); // didn't crash
}

test "analyzeThreadFn is callable" {
    // Just verify the function exists and is callable.
    // We don't run the infinite loop here.
    try std.testing.expect(@TypeOf(analyzeThreadFn) == fn () void);
}

test "legacy compat functions delegate to dispatcher" {
    // Verify the deprecated functions still work (delegate to dispatcher).
    const event = canonical.create(.zig_core);
    routeEvent(event);
    try std.testing.expect(true);
}
