//! Runtime bundle path resolution shared by daemon startup and control reloads.
//!
//! A NIDS service starts with cwd = C:\WINDOWS\system32, so a relative
//! `configs/Rules.json` resolves to a path that does not exist and the
//! detection engine silently runs with zero rules. Resolution must therefore
//! prefer the installed bundle (`<install>\configs\...`) derived from the
//! executable location, and must never pretend a missing bundle is usable.
const std = @import("std");

pub const Error = error{
    RuntimeRootUnavailable,
};

/// Return true only when the bundle contains both required Project 2 configs.
pub fn hasRequiredConfig(root: []const u8) bool {
    var dir = std.fs.openDirAbsolute(root, .{}) catch return false;
    defer dir.close();
    dir.access("configs/Rules.json", .{}) catch return false;
    dir.access("configs/policies.json", .{}) catch return false;
    return true;
}

/// Candidate bundle roots in priority order, derived only from absolute paths.
///
/// The installed release layout is:
///   <install>\runtime\aegis_nids.exe
///   <install>\configs\Rules.json
/// so the install root is the *parent* of the executable directory. A plain
/// developer build lives at <repo>\zig-out\bin\aegis_nids.exe with configs at
/// <repo>\configs, so the executable's ancestors are also candidates.
///
/// Returns the first candidate with a complete bundle, or null. This function
/// is pure path arithmetic over `exe_dir` so the service case is unit-testable
/// without installing anything.
pub fn selectRoot(exe_dir: []const u8, existsFn: *const fn ([]const u8) bool) ?[]const u8 {
    if (existsFn(exe_dir)) return exe_dir;
    if (std.fs.path.dirname(exe_dir)) |parent| {
        if (existsFn(parent)) return parent;
    }
    if (std.fs.path.dirname(exe_dir)) |parent| {
        if (std.fs.path.dirname(parent)) |grandparent| {
            if (existsFn(grandparent)) return grandparent;
        }
    }
    return null;
}

/// Resolve the runtime bundle root for this process.
///
/// Order:
///   1. the executable directory itself (flat layout),
///   2. its parent (installed `<install>\runtime\` layout),
///   3. its grandparent (developer `zig-out\bin\` layout),
///   4. the current working directory (developer/test convenience only).
///
/// The cwd fallback exists for `zig build test` and local console runs. It is
/// only accepted when the cwd actually holds a complete bundle, so a service
/// whose bundle is missing fails loudly instead of running with zero rules.
pub fn resolveRoot(a: std.mem.Allocator) ![]u8 {
    const exe_dir = std.fs.selfExeDirPathAlloc(a) catch return Error.RuntimeRootUnavailable;
    defer a.free(exe_dir);

    if (selectRoot(exe_dir, &hasRequiredConfig)) |root| {
        return a.dupe(u8, root);
    }

    const cwd = std.fs.cwd().realpathAlloc(a, ".") catch return Error.RuntimeRootUnavailable;
    if (hasRequiredConfig(cwd)) return cwd;
    a.free(cwd);
    return Error.RuntimeRootUnavailable;
}

pub fn configPath(a: std.mem.Allocator, root: []const u8, name: []const u8) ![]u8 {
    return std.fs.path.join(a, &.{ root, "configs", name });
}

const testing = std.testing;

fn fakeExists(targets: []const []const u8) *const fn ([]const u8) bool {
    const S = struct {
        var paths: []const []const u8 = &.{};
        fn exists(candidate: []const u8) bool {
            for (paths) |path| {
                if (std.mem.eql(u8, path, candidate)) return true;
            }
            return false;
        }
    };
    S.paths = targets;
    return &S.exists;
}

test "installed layout resolves to install root, not runtime dir" {
    // <install>\runtime\aegis_nids.exe with <install>\configs\Rules.json
    const exists = fakeExists(&.{ "C:\\Program Files\\AEGIS NIDS" });
    const root = selectRoot("C:\\Program Files\\AEGIS NIDS\\runtime", exists);
    try testing.expectEqualStrings("C:\\Program Files\\AEGIS NIDS", root.?);
}

test "developer zig-out layout resolves to repo root" {
    const exists = fakeExists(&.{ "D:\\NIDs_Windows" });
    const root = selectRoot("D:\\NIDs_Windows\\zig-out\\bin", exists);
    try testing.expectEqualStrings("D:\\NIDs_Windows", root.?);
}

test "flat layout resolves to executable directory" {
    const exists = fakeExists(&.{ "C:\\AEGIS" });
    const root = selectRoot("C:\\AEGIS", exists);
    try testing.expectEqualStrings("C:\\AEGIS", root.?);
}

test "missing bundle yields no candidate instead of a wrong path" {
    const exists = fakeExists(&.{});
    try testing.expect(selectRoot("C:\\Program Files\\AEGIS NIDS\\runtime", exists) == null);
}
