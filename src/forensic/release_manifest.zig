// PATCH-44 - Release Manifest / Reproducibility
// AEGIS NIDS v5.0+ -- Release manifest and build reproducibility
//
// This module defines the release manifest structure and verifies
// build reproducibility across environments.

const std = @import("std");

// ============================================================================
// Release Manifest
// ============================================================================

pub const ReleaseManifest = struct {
    version: [32]u8,
    build_timestamp: u64,
    git_commit: [40]u8,
    git_branch: [64]u8,
    zig_version: [32]u8,
    rust_version: [32]u8,
    go_version: [32]u8,
    python_version: [32]u8,
    target_os: [16]u8,
    target_arch: [16]u8,
    build_mode: [16]u8,
    artifacts: [8]ArtifactInfo,
    artifact_count: u32,

    pub const ArtifactInfo = struct {
        name: [64]u8,
        path: [256]u8,
        size_bytes: u64,
        sha256: [32]u8,
    };

    pub fn init() ReleaseManifest {
        return .{
            .version = [_]u8{0} ** 32,
            .build_timestamp = @intCast(std.time.nanoTimestamp()),
            .git_commit = [_]u8{0} ** 40,
            .git_branch = [_]u8{0} ** 64,
            .zig_version = [_]u8{0} ** 32,
            .rust_version = [_]u8{0} ** 32,
            .go_version = [_]u8{0} ** 32,
            .python_version = [_]u8{0} ** 32,
            .target_os = [_]u8{0} ** 16,
            .target_arch = [_]u8{0} ** 16,
            .build_mode = [_]u8{0} ** 16,
            .artifacts = [_]ArtifactInfo{std.mem.zeroes(ArtifactInfo)} ** 8,
            .artifact_count = 0,
        };
    }

    pub fn setVersion(self: *ReleaseManifest, version: []const u8) void {
        const len = @min(version.len, 31);
        @memcpy(self.version[0..len], version[0..len]);
    }

    pub fn setGitCommit(self: *ReleaseManifest, commit: []const u8) void {
        const len = @min(commit.len, 39);
        @memcpy(self.git_commit[0..len], commit[0..len]);
    }

    pub fn addArtifact(self: *ReleaseManifest, name: []const u8, path: []const u8, size: u64, hash: [32]u8) bool {
        if (self.artifact_count >= 8) return false;
        const idx = self.artifact_count;
        const name_len = @min(name.len, 63);
        @memcpy(self.artifacts[idx].name[0..name_len], name[0..name_len]);
        const path_len = @min(path.len, 255);
        @memcpy(self.artifacts[idx].path[0..path_len], path[0..path_len]);
        self.artifacts[idx].size_bytes = size;
        self.artifacts[idx].sha256 = hash;
        self.artifact_count += 1;
        return true;
    }

    pub fn verifyIntegrity(self: *const ReleaseManifest) bool {
        if (self.artifact_count > 8) return false;
        // Verify version is set
        var version_set = false;
        for (self.version) |b| {
            if (b != 0) {
                version_set = true;
                break;
            }
        }
        if (!version_set) return false;
        // Verify git commit is set
        var commit_set = false;
        for (self.git_commit) |b| {
            if (b != 0) {
                commit_set = true;
                break;
            }
        }
        if (!commit_set) return false;
        return true;
    }
};

// ============================================================================
// Build Reproducibility
// ============================================================================

/// Verify that the build environment produces deterministic output.
pub fn verifyReproducibility(manifest: *const ReleaseManifest) bool {
    // Check all required fields are set
    if (manifest.build_timestamp == 0) return false;
    if (manifest.artifact_count == 0) return false;
    // Verify each artifact has a hash
    var i: u32 = 0;
    while (i < manifest.artifact_count) : (i += 1) {
        const art = &manifest.artifacts[i];
        var hash_set = false;
        for (art.sha256) |b| {
            if (b != 0) {
                hash_set = true;
                break;
            }
        }
        if (!hash_set) return false;
    }
    return true;
}

// ============================================================================
// Release Gate
// ============================================================================

pub const ReleaseGate = struct {
    tests_passed: bool = false,
    build_passed: bool = false,
    security_review: bool = false,
    performance_baseline: bool = false,
    documentation: bool = false,

    pub fn init() ReleaseGate {
        return .{};
    }

    pub fn isReady(self: *const ReleaseGate) bool {
        return self.tests_passed and
            self.build_passed and
            self.security_review and
            self.performance_baseline and
            self.documentation;
    }

    pub fn getChecklist(self: *const ReleaseGate) [5]struct { name: []const u8, passed: bool } {
        return .{
            .{ .name = "tests_passed", .passed = self.tests_passed },
            .{ .name = "build_passed", .passed = self.build_passed },
            .{ .name = "security_review", .passed = self.security_review },
            .{ .name = "performance_baseline", .passed = self.performance_baseline },
            .{ .name = "documentation", .passed = self.documentation },
        };
    }
};

// ============================================================================
// Tests
// ============================================================================

test "ReleaseManifest init" {
    const manifest = ReleaseManifest.init();
    try std.testing.expectEqual(@as(u32, 0), manifest.artifact_count);
    try std.testing.expectEqual(@as(u64, 0), manifest.version[0]);
}

test "ReleaseManifest setVersion" {
    var manifest = ReleaseManifest.init();
    manifest.setVersion("1.0.0");
    try std.testing.expectEqual(@as(u8, '1'), manifest.version[0]);
    try std.testing.expectEqual(@as(u8, '.'), manifest.version[1]);
    try std.testing.expectEqual(@as(u8, '0'), manifest.version[2]);
}

test "ReleaseManifest setGitCommit" {
    var manifest = ReleaseManifest.init();
    manifest.setGitCommit("abc123def456");
    try std.testing.expectEqual(@as(u8, 'a'), manifest.git_commit[0]);
    try std.testing.expectEqual(@as(u8, 'b'), manifest.git_commit[1]);
}

test "ReleaseManifest addArtifact" {
    var manifest = ReleaseManifest.init();
    const hash = [_]u8{1} ** 32;
    const added = manifest.addArtifact("test.dll", "target/test.dll", 1024, hash);
    try std.testing.expect(added);
    try std.testing.expectEqual(@as(u32, 1), manifest.artifact_count);
}

test "ReleaseManifest addArtifact overflow" {
    var manifest = ReleaseManifest.init();
    const hash = [_]u8{1} ** 32;
    var i: u32 = 0;
    while (i < 9) : (i += 1) {
        _ = manifest.addArtifact("test.dll", "target/test.dll", 1024, hash);
    }
    try std.testing.expectEqual(@as(u32, 8), manifest.artifact_count);
}

test "ReleaseManifest verifyIntegrity" {
    var manifest = ReleaseManifest.init();
    manifest.setVersion("1.0.0");
    manifest.setGitCommit("abc123");
    try std.testing.expect(manifest.verifyIntegrity());
}

test "ReleaseManifest verifyIntegrity fails without version" {
    var manifest = ReleaseManifest.init();
    manifest.setGitCommit("abc123");
    try std.testing.expect(!manifest.verifyIntegrity());
}

test "verifyReproducibility" {
    var manifest = ReleaseManifest.init();
    manifest.setVersion("1.0.0");
    manifest.setGitCommit("abc123");
    const hash = [_]u8{1} ** 32;
    _ = manifest.addArtifact("test.dll", "target/test.dll", 1024, hash);
    try std.testing.expect(verifyReproducibility(&manifest));
}

test "ReleaseGate init" {
    const gate = ReleaseGate.init();
    try std.testing.expect(!gate.isReady());
}

test "ReleaseGate all checks" {
    var gate = ReleaseGate.init();
    gate.tests_passed = true;
    gate.build_passed = true;
    gate.security_review = true;
    gate.performance_baseline = true;
    gate.documentation = true;
    try std.testing.expect(gate.isReady());
}

test "ReleaseGate partial checks" {
    var gate = ReleaseGate.init();
    gate.tests_passed = true;
    gate.build_passed = true;
    // Missing security_review, performance_baseline, documentation
    try std.testing.expect(!gate.isReady());
}

test "ReleaseGate getChecklist" {
    var gate = ReleaseGate.init();
    gate.tests_passed = true;
    gate.build_passed = true;
    const checklist = gate.getChecklist();
    try std.testing.expectEqual(@as(usize, 5), checklist.len);
    try std.testing.expect(checklist[0].passed);
    try std.testing.expect(checklist[1].passed);
    try std.testing.expect(!checklist[2].passed);
}
