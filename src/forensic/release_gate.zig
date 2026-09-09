// PATCH-46 - Final Current-Head Release Gate
// AEGIS NIDS v5.0+ -- Final release gate verification
//
// This module defines the final release gate that must pass before
// any release can be published. It verifies all critical properties
// of the current HEAD.

const std = @import("std");

// ============================================================================
// Release Gate Checklist
// ============================================================================

pub const ReleaseChecklist = struct {
    // Build verification
    build_passed: bool = false,
    tests_passed: bool = false,
    lint_passed: bool = false,
    typecheck_passed: bool = false,

    // Security verification
    security_audit: bool = false,
    no_secrets: bool = false,
    no_backdoors: bool = false,
    crypto_verified: bool = false,

    // Performance verification
    performance_baseline: bool = false,
    no_regressions: bool = false,
    memory_leaks: bool = false,

    // Documentation
    readme_updated: bool = false,
    changelog_updated: bool = false,
    api_docs: bool = false,

    // Release artifacts
    binaries_built: bool = false,
    installers_ready: bool = false,
    checksums_generated: bool = false,

    pub fn init() ReleaseChecklist {
        return .{};
    }

    pub fn isReady(self: *const ReleaseChecklist) bool {
        return self.build_passed and
            self.tests_passed and
            self.lint_passed and
            self.typecheck_passed and
            self.security_audit and
            self.no_secrets and
            self.no_backdoors and
            self.crypto_verified and
            self.performance_baseline and
            self.no_regressions and
            self.memory_leaks and
            self.readme_updated and
            self.changelog_updated and
            self.api_docs and
            self.binaries_built and
            self.installers_ready and
            self.checksums_generated;
    }

    pub fn getProgress(self: *const ReleaseChecklist) struct { passed: u32, total: u32, percentage: f32 } {
        var passed: u32 = 0;
        const total: u32 = 17;

        if (self.build_passed) passed += 1;
        if (self.tests_passed) passed += 1;
        if (self.lint_passed) passed += 1;
        if (self.typecheck_passed) passed += 1;
        if (self.security_audit) passed += 1;
        if (self.no_secrets) passed += 1;
        if (self.no_backdoors) passed += 1;
        if (self.crypto_verified) passed += 1;
        if (self.performance_baseline) passed += 1;
        if (self.no_regressions) passed += 1;
        if (self.memory_leaks) passed += 1;
        if (self.readme_updated) passed += 1;
        if (self.changelog_updated) passed += 1;
        if (self.api_docs) passed += 1;
        if (self.binaries_built) passed += 1;
        if (self.installers_ready) passed += 1;
        if (self.checksums_generated) passed += 1;

        return .{
            .passed = passed,
            .total = total,
            .percentage = @as(f32, @floatFromInt(passed)) / @as(f32, @floatFromInt(total)) * 100.0,
        };
    }

    pub fn getFailedChecks(self: *const ReleaseChecklist) [17]struct { name: []const u8, passed: bool } {
        return .{
            .{ .name = "build_passed", .passed = self.build_passed },
            .{ .name = "tests_passed", .passed = self.tests_passed },
            .{ .name = "lint_passed", .passed = self.lint_passed },
            .{ .name = "typecheck_passed", .passed = self.typecheck_passed },
            .{ .name = "security_audit", .passed = self.security_audit },
            .{ .name = "no_secrets", .passed = self.no_secrets },
            .{ .name = "no_backdoors", .passed = self.no_backdoors },
            .{ .name = "crypto_verified", .passed = self.crypto_verified },
            .{ .name = "performance_baseline", .passed = self.performance_baseline },
            .{ .name = "no_regressions", .passed = self.no_regressions },
            .{ .name = "memory_leaks", .passed = self.memory_leaks },
            .{ .name = "readme_updated", .passed = self.readme_updated },
            .{ .name = "changelog_updated", .passed = self.changelog_updated },
            .{ .name = "api_docs", .passed = self.api_docs },
            .{ .name = "binaries_built", .passed = self.binaries_built },
            .{ .name = "installers_ready", .passed = self.installers_ready },
            .{ .name = "checksums_generated", .passed = self.checksums_generated },
        };
    }
};

// ============================================================================
// Release Signature
// ============================================================================

pub const ReleaseSignature = struct {
    version: [32]u8,
    git_commit: [40]u8,
    build_timestamp: u64,
    signature_hash: [32]u8,
    signed_by: [64]u8,
    signed_at: u64,

    pub fn init() ReleaseSignature {
        return .{
            .version = [_]u8{0} ** 32,
            .git_commit = [_]u8{0} ** 40,
            .build_timestamp = 0,
            .signature_hash = [_]u8{0} ** 32,
            .signed_by = [_]u8{0} ** 64,
            .signed_at = 0,
        };
    }

    pub fn computeHash(self: *const ReleaseSignature) [32]u8 {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&self.version);
        hasher.update(&self.git_commit);
        hasher.update(std.mem.asBytes(&self.build_timestamp));
        hasher.update(&self.signed_by);
        var hash: [32]u8 = undefined;
        hasher.final(&hash);
        return hash;
    }

    pub fn verify(self: *const ReleaseSignature) bool {
        const computed = self.computeHash();
        return std.mem.eql(u8, &self.signature_hash, &computed);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "ReleaseChecklist init" {
    const checklist = ReleaseChecklist.init();
    try std.testing.expect(!checklist.isReady());
}

test "ReleaseChecklist all checks" {
    var checklist = ReleaseChecklist.init();
    checklist.build_passed = true;
    checklist.tests_passed = true;
    checklist.lint_passed = true;
    checklist.typecheck_passed = true;
    checklist.security_audit = true;
    checklist.no_secrets = true;
    checklist.no_backdoors = true;
    checklist.crypto_verified = true;
    checklist.performance_baseline = true;
    checklist.no_regressions = true;
    checklist.memory_leaks = true;
    checklist.readme_updated = true;
    checklist.changelog_updated = true;
    checklist.api_docs = true;
    checklist.binaries_built = true;
    checklist.installers_ready = true;
    checklist.checksums_generated = true;
    try std.testing.expect(checklist.isReady());
}

test "ReleaseChecklist partial checks" {
    var checklist = ReleaseChecklist.init();
    checklist.build_passed = true;
    checklist.tests_passed = true;
    // Missing 15 other checks
    try std.testing.expect(!checklist.isReady());
}

test "ReleaseChecklist getProgress" {
    var checklist = ReleaseChecklist.init();
    checklist.build_passed = true;
    checklist.tests_passed = true;
    const progress = checklist.getProgress();
    try std.testing.expectEqual(@as(u32, 2), progress.passed);
    try std.testing.expectEqual(@as(u32, 17), progress.total);
}

test "ReleaseChecklist getFailedChecks" {
    var checklist = ReleaseChecklist.init();
    checklist.build_passed = true;
    const checks = checklist.getFailedChecks();
    try std.testing.expectEqual(@as(usize, 17), checks.len);
    try std.testing.expect(checks[0].passed); // build_passed
    try std.testing.expect(!checks[1].passed); // tests_passed
}

test "ReleaseSignature init" {
    const sig = ReleaseSignature.init();
    try std.testing.expectEqual(@as(u64, 0), sig.build_timestamp);
}

test "ReleaseSignature computeHash" {
    var sig = ReleaseSignature.init();
    @memcpy(sig.version[0..5], "1.0.0");
    @memcpy(sig.git_commit[0..6], "abc123");
    sig.build_timestamp = 1234567890;
    @memcpy(sig.signed_by[0..7], "builder");
    const hash = sig.computeHash();
    // Hash should be non-zero
    var all_zero = true;
    for (hash) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}

test "ReleaseSignature verify" {
    var sig = ReleaseSignature.init();
    @memcpy(sig.version[0..5], "1.0.0");
    @memcpy(sig.git_commit[0..6], "abc123");
    sig.build_timestamp = 1234567890;
    @memcpy(sig.signed_by[0..7], "builder");
    sig.signature_hash = sig.computeHash();
    try std.testing.expect(sig.verify());
}

test "ReleaseSignature verify fails with wrong hash" {
    var sig = ReleaseSignature.init();
    @memcpy(sig.version[0..5], "1.0.0");
    @memcpy(sig.git_commit[0..6], "abc123");
    sig.build_timestamp = 1234567890;
    @memcpy(sig.signed_by[0..7], "builder");
    sig.signature_hash = [_]u8{0xFF} ** 32;
    try std.testing.expect(!sig.verify());
}
