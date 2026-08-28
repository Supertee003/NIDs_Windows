//! release_info.zig - AEGIS NIDS Release Information (STEP 15)
//!
//! Compile-time version info embedded in the release binary.
//! Provides version string, build mode, and release metadata for:
//!   - CLI `--version` output
//!   - Forensic log headers (provenance tracking)
//!   - SIEM integration (asset inventory)
//!   - Crash reports (which version crashed)
//!
//! Version scheme: Semantic Versioning (MAJOR.MINOR.PATCH)
//!   - MAJOR: Breaking changes (new architecture, incompatible API)
//!   - MINOR: New features (backward-compatible)
//!   - PATCH: Bug fixes (backward-compatible)
//!
//! Build modes:
//!   - Debug:    dev builds with assertions + zero optimizations
//!   - ReleaseSafe: production with assertions (recommended for first deploy)
//!   - ReleaseFast: maximum performance (no assertions)
//!   - ReleaseSmall: minimal binary size

const std = @import("std");

// ============================================================
// STEP 15: Version constants (compile-time)
// ============================================================

pub const VERSION_MAJOR: u32 = 2;
pub const VERSION_MINOR: u32 = 0;
pub const VERSION_PATCH: u32 = 0;

/// Build mode string (set by build.zig via build options or fallback)
pub const BUILD_MODE: []const u8 = "Debug";

/// Build timestamp (set at compile time via build options or fallback)
pub const BUILD_TIMESTAMP: []const u8 = "2026-08-28";

/// Git commit hash (set via build options or "unknown")
pub const GIT_COMMIT: []const u8 = "unknown";

/// Release codename (memorable name for major releases)
pub const RELEASE_CODENAME: []const u8 = "Golden Path";

// ============================================================
// STEP 15: Version string generation
// ============================================================

/// Full version string: "AEGIS NIDS v2.0.0 (Golden Path) [Debug, 2026-08-28]"
pub const FULL_VERSION: []const u8 = "AEGIS NIDS v" ++
    std.fmt.comptimePrint("{d}.{d}.{d}", .{ VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH }) ++
    " (" ++ RELEASE_CODENAME ++ ") [" ++ BUILD_MODE ++ ", " ++ BUILD_TIMESTAMP ++ "]";

/// Short version string: "v2.0.0"
pub const SHORT_VERSION: []const u8 = std.fmt.comptimePrint("v{d}.{d}.{d}", .{ VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH });

/// Numeric version for comparison: 2.0.0 = 2000000 (major*1000000 + minor*1000 + patch)
pub const VERSION_NUMBER: u32 = VERSION_MAJOR * 1_000_000 + VERSION_MINOR * 1_000 + VERSION_PATCH;

// ============================================================
// STEP 15: Release info struct
// ============================================================

pub const ReleaseInfo = struct {
    major: u32,
    minor: u32,
    patch: u32,
    build_mode: []const u8,
    build_timestamp: []const u8,
    git_commit: []const u8,
    codename: []const u8,
    full_version: []const u8,
    short_version: []const u8,
    version_number: u32,
};

/// Get a ReleaseInfo snapshot (value type, safe to pass around).
pub fn getReleaseInfo() ReleaseInfo {
    return .{
        .major = VERSION_MAJOR,
        .minor = VERSION_MINOR,
        .patch = VERSION_PATCH,
        .build_mode = BUILD_MODE,
        .build_timestamp = BUILD_TIMESTAMP,
        .git_commit = GIT_COMMIT,
        .codename = RELEASE_CODENAME,
        .full_version = FULL_VERSION,
        .short_version = SHORT_VERSION,
        .version_number = VERSION_NUMBER,
    };
}

/// Print version banner to stdout (for `--version` CLI flag).
pub fn printVersion() void {
    std.debug.print("{s}\n", .{FULL_VERSION});
    std.debug.print("  Major:    {d}\n", .{VERSION_MAJOR});
    std.debug.print("  Minor:    {d}\n", .{VERSION_MINOR});
    std.debug.print("  Patch:    {d}\n", .{VERSION_PATCH});
    std.debug.print("  Codename: {s}\n", .{RELEASE_CODENAME});
    std.debug.print("  Mode:     {s}\n", .{BUILD_MODE});
    std.debug.print("  Built:    {s}\n", .{BUILD_TIMESTAMP});
    std.debug.print("  Commit:   {s}\n", .{GIT_COMMIT});
}

/// Check if this is a release build (not Debug).
pub fn isReleaseBuild() bool {
    return !std.mem.eql(u8, BUILD_MODE, "Debug");
}

/// Check if version is at least the specified major.minor.patch.
pub fn isAtLeast(major: u32, minor: u32, patch: u32) bool {
    const required = major * 1_000_000 + minor * 1_000 + patch;
    return VERSION_NUMBER >= required;
}

// ============================================================
// STEP 15: Tests
// ============================================================

test "VERSION constants are valid" {
    try std.testing.expect(VERSION_MAJOR >= 1);
    try std.testing.expect(VERSION_MINOR >= 0);
    try std.testing.expect(VERSION_PATCH >= 0);
}

test "SHORT_VERSION format is correct" {
    // Format: v{major}.{minor}.{patch}
    try std.testing.expect(SHORT_VERSION.len > 0);
    try std.testing.expect(SHORT_VERSION[0] == 'v');
}

test "FULL_VERSION contains all components" {
    try std.testing.expect(std.mem.indexOf(u8, FULL_VERSION, "AEGIS") != null);
    try std.testing.expect(std.mem.indexOf(u8, FULL_VERSION, "v" ++ std.fmt.comptimePrint("{d}.{d}.{d}", .{ VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH })) != null);
    try std.testing.expect(std.mem.indexOf(u8, FULL_VERSION, RELEASE_CODENAME) != null);
    try std.testing.expect(std.mem.indexOf(u8, FULL_VERSION, BUILD_MODE) != null);
}

test "VERSION_NUMBER encodes semver correctly" {
    // 2.0.0 = 2_000_000
    try std.testing.expect(VERSION_NUMBER == VERSION_MAJOR * 1_000_000 + VERSION_MINOR * 1_000 + VERSION_PATCH);
}

test "ReleaseInfo is a value type" {
    const info = getReleaseInfo();
    const copy = info;
    try std.testing.expect(copy.major == VERSION_MAJOR);
    try std.testing.expect(copy.minor == VERSION_MINOR);
    try std.testing.expect(copy.patch == VERSION_PATCH);
}

test "isReleaseBuild returns false for Debug mode" {
    // In test builds, BUILD_MODE is "Debug"
    try std.testing.expect(!isReleaseBuild());
}

test "isAtLeast returns true for lower or equal versions" {
    try std.testing.expect(isAtLeast(1, 0, 0));
    try std.testing.expect(isAtLeast(2, 0, 0));
    try std.testing.expect(isAtLeast(VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH));
}

test "isAtLeast returns false for higher versions" {
    try std.testing.expect(!isAtLeast(VERSION_MAJOR + 1, 0, 0));
    try std.testing.expect(!isAtLeast(VERSION_MAJOR, VERSION_MINOR + 1, 0));
    try std.testing.expect(!isAtLeast(VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH + 1));
}

test "printVersion does not crash" {
    // Just verify it doesn't panic
    printVersion();
}

test "STEP15: release info is embeddable in forensic log" {
    // Verify version string is suitable for forensic log header
    const info = getReleaseInfo();
    try std.testing.expect(info.full_version.len > 0);
    try std.testing.expect(info.full_version.len < 256); // reasonable max for log line
}

test "STEP15: version comparison works for upgrade detection" {
    // Simulate upgrade check: current version vs minimum required
    const min_required = isAtLeast(2, 0, 0);
    try std.testing.expect(min_required); // we're at 2.0.0

    const future_check = isAtLeast(3, 0, 0);
    try std.testing.expect(!future_check); // not yet at 3.0.0
}
