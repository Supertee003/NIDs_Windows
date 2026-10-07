//! policy/shield_screen.zig — SHIELD-WIRE-123: Tier-3 screening provider.
//!
//! Loads sec_monitor.dll (shield crate, SUPPORT) at daemon startup and
//! exposes its advisory screening verdict to the runtime. Design rules:
//!
//!   - DynLib runtime lookup ONLY. There is deliberately no link-time
//!     extern declaration for the screening library anywhere, so the
//!     NEG-001 pin (test_zig_pep_extern_lives_in_one_module) keeps
//!     passing unchanged.
//!   - Advisory ONLY. A `suspicious` verdict never enforces, never touches
//!     WFP/quotas/receipts; it is an input the canonical policy path may
//!     consider. Enforcement gating (tier3_state + Rust PEP receipt) is
//!     untouched by this module.
//!   - Fail-safe default. No DLL, no symbol, or any load error means
//!     `unknown`; prior runtime behavior is then bit-identical.
//!   - No CWD planting (B-01): candidate paths are fixed subdirectories,
//!     never bare CWD; the bare-name fallback relies on OS search order,
//!     mirroring initCppBridge.
//!
//! FFI contract (must match shield/src/lib.rs exactly):
//!   aegis_shield_screen(ptr: *const u8, len: usize) -> i32
//!   0 = clean/advisory-allow, >0 = suspicious (escalate to canonical
//!   policy path, never enforce), <0 = rejected (null/oversize input).

const std = @import("std");

/// Advisory screening verdict. `unknown` is the fail-safe default and the
/// only possible answer while the DLL is absent.
pub const ScreenVerdict = enum {
    unknown,
    clean,
    suspicious,
    rejected,
};

const FnScreen = *const fn ([*]const u8, usize) callconv(.C) i32;

var g_lib: ?std.DynLib = null;
var g_fn: ?FnScreen = null;

/// Candidate DLL locations, in order. Canonical cargo output first.
pub const CANDIDATE_PATHS = [_][]const u8{
    "shield\\target\\release\\sec_monitor.dll",
    "dist\\sec_monitor.dll",
    "sec_monitor.dll",
};

/// Attempt to load the screening provider from one explicit path.
/// Returns true only when the library opened AND the symbol resolved.
/// Never panics; any failure leaves prior state untouched.
pub fn tryLoadPath(path: []const u8) bool {
    var path_buf: [512]u8 = undefined;
    const owned = std.fmt.bufPrint(&path_buf, "{s}", .{path}) catch return false;
    var lib = std.DynLib.open(owned) catch return false;
    const sym = lib.lookup(FnScreen, "aegis_shield_screen") orelse {
        lib.close();
        return false;
    };
    // Close any previously loaded provider before replacing it, via a
    // local copy (the close call needs a mutable receiver).
    if (g_lib) |*old| {
        var prev: std.DynLib = old.*;
        prev.close();
    }
    g_lib = lib;
    g_fn = sym;
    return true;
}

/// Load from the first candidate path that works. Intended for daemon
/// startup (single-threaded init, before worker threads spawn).
pub fn tryLoadDefault() bool {
    for (CANDIDATE_PATHS) |path| {
        if (tryLoadPath(path)) return true;
    }
    return false;
}

/// True once a library + symbol pair is loaded.
pub fn isAvailable() bool {
    return g_fn != null;
}

/// Screen a payload through the provider. Returns `unknown` while the
/// provider is absent. Empty input short-circuits to `clean`, mirroring
/// the provider (which returns 0 for empty) without touching FFI.
pub fn screen(payload: []const u8) ScreenVerdict {
    const f = g_fn orelse return .unknown;
    if (payload.len == 0) return .clean;
    const rc = f(payload.ptr, payload.len);
    if (rc == 0) return .clean;
    if (rc > 0) return .suspicious;
    return .rejected;
}

// ============================================================
// Tests (hermetic: only missing-DLL paths, never a real load)
// ============================================================

test "shield_screen defaults to unavailable with unknown verdict" {
    try std.testing.expect(!isAvailable());
    try std.testing.expectEqual(ScreenVerdict.unknown, screen("anything"));
    try std.testing.expectEqual(ScreenVerdict.unknown, screen(""));
}

test "shield_screen tryLoadPath fails closed on missing file" {
    try std.testing.expect(!tryLoadPath("definitely\\not\\here\\sec_monitor.dll"));
    try std.testing.expect(!isAvailable());
    try std.testing.expectEqual(ScreenVerdict.unknown, screen("DROP!"));
}

test "shield_screen first candidate is the canonical cargo output" {
    // The historical runtime log line proves the DLL lived at
    // shield\target\release\sec_monitor.dll; the loader must look there
    // first so a cargo-built tree wires up with no configuration.
    try std.testing.expect(std.mem.eql(u8, CANDIDATE_PATHS[0], "shield\\target\\release\\sec_monitor.dll"));
}

test "shield_screen candidate paths never include bare CWD (B-01)" {
    // DLL planting via CWD is forbidden: every candidate must name a
    // subdirectory or a bare filename (OS search order), never "." / "./".
    try std.testing.expect(CANDIDATE_PATHS.len > 0);
    for (CANDIDATE_PATHS) |p| {
        try std.testing.expect(!std.mem.eql(u8, p, "."));
        try std.testing.expect(!std.mem.startsWith(u8, p, "./"));
        try std.testing.expect(!std.mem.startsWith(u8, p, ".\\"));
    }
}
