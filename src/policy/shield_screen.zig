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
///
/// EVT-191: the executable's own directory is tried FIRST, before the
/// repo-relative candidates below. The deployed service runs with
/// CWD=System32, so repo-relative paths never resolve there while the
/// exe directory (Program Files, admin-writable only) is a fixed
/// non-plantable location in the B-01 sense -- CWD planting stays
/// forbidden and CANDIDATE_PATHS is untouched (pinned order below).
/// Dev runs from the repo root keep working via the relative entries.
pub fn tryLoadDefault() bool {
    var exe_buf: [1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&exe_buf);
    if (exeDirDisplayPath(fba.allocator(), null)) |owned| {
        defer fba.allocator().free(owned);
        if (tryLoadPath(owned)) return true;
    } else |_| {}
    for (CANDIDATE_PATHS) |path| {
        if (tryLoadPath(path)) return true;
    }
    return false;
}

/// Display path for sec_monitor.dll beside the daemon executable.
/// Pass exe_path explicitly (null = query this process) so the join is
/// unit-testable without a process image. Returns allocated path.
pub fn exeDirDisplayPath(allocator: std.mem.Allocator, exe_path: ?[]const u8) ![]const u8 {
    var owned_exe: ?[]const u8 = null;
    defer if (owned_exe) |p| allocator.free(p);
    const exe = exe_path orelse blk: {
        owned_exe = try std.fs.selfExePathAlloc(allocator);
        break :blk owned_exe.?;
    };
    const dir = std.fs.path.dirname(exe) orelse return error.NoParentDir;
    return std.fs.path.join(allocator, &.{ dir, "sec_monitor.dll" });
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

test "shield_screen exe-dir candidate joins beside the daemon" {
    const alloc = std.testing.allocator;
    const win_path = try exeDirDisplayPath(alloc, "C:\\Program Files\\AEGIS NIDS\\runtime\\aegis_nids.exe");
    defer alloc.free(win_path);
    try std.testing.expect(std.mem.endsWith(u8, win_path, "\\sec_monitor.dll"));
    try std.testing.expect(std.mem.indexOf(u8, win_path, "runtime") != null);
}

test "shield_screen positive path against cargo-built DLL (host-conditional)" {
    // E5 host proof, runs only where the DLL exists (cargo-built tree);
    // elsewhere it skips instead of failing. NOTE: under `zig build test`
    // this always skips (the runner does not use the repo root as cwd, so
    // the relative candidate path never resolves there) — run
    // `zig test src/policy/shield_screen.zig` from the repo root for the
    // live positive proof (see EVT-059).
    // Must stay LAST in this file: a successful load sets process globals
    // that earlier hermetic tests require to be null.
    var probe: [512]u8 = undefined;
    const rel = std.fmt.bufPrint(&probe, "{s}", .{CANDIDATE_PATHS[0]}) catch return error.SkipTest;
    std.fs.cwd().access(rel, .{}) catch return error.SkipTest;
    try std.testing.expect(tryLoadDefault());
    try std.testing.expect(isAvailable());
    try std.testing.expectEqual(ScreenVerdict.clean, screen("benign"));
    try std.testing.expectEqual(ScreenVerdict.clean, screen(""));
    try std.testing.expectEqual(ScreenVerdict.suspicious, screen("prefix DROP! suffix"));
    var big: [5000]u8 = [_]u8{0} ** 5000;
    try std.testing.expectEqual(ScreenVerdict.rejected, screen(&big));
}
