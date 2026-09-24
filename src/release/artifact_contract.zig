//! Phase 12 release contract: artifact identity, digest and install role.
const std = @import("std");

pub const ArtifactKind = enum(u8) { core_binary, pep_dll, wfp_driver, config, installer, sbom, checksum };

pub const Artifact = struct {
    name: []const u8,
    kind: ArtifactKind,
    version: []const u8,
    source_commit: []const u8,
    sha256: []const u8,
    required: bool = true,

    pub fn isIdentified(self: Artifact) bool {
        return self.name.len > 0 and self.version.len > 0 and self.source_commit.len > 0 and self.sha256.len > 0;
    }
};

pub const ReleaseBundle = struct {
    release_version: []const u8,
    source_commit: []const u8,
    artifacts: []const Artifact,
    signed: bool = false,
    install_tested: bool = false,
    rollback_tested: bool = false,

    pub fn isReady(self: ReleaseBundle) bool {
        if (!self.signed or !self.install_tested or !self.rollback_tested or self.artifacts.len == 0) return false;
        for (self.artifacts) |artifact| if (artifact.required and !artifact.isIdentified()) return false;
        return true;
    }
};

test "release artifact requires identity" {
    const artifact = Artifact{ .name = "aegis_nids.exe", .kind = .core_binary, .version = "5.0.0", .source_commit = "abc1234", .sha256 = "sha256:test" };
    try std.testing.expect(artifact.isIdentified());
}

test "release bundle is not ready before signing and install tests" {
    const artifacts = [_]Artifact{.{ .name = "aegis_nids.exe", .kind = .core_binary, .version = "5.0.0", .source_commit = "abc1234", .sha256 = "sha256:test" }};
    const bundle = ReleaseBundle{ .release_version = "5.0.0", .source_commit = "abc1234", .artifacts = &artifacts };
    try std.testing.expect(!bundle.isReady());
}
