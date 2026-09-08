//! release_provenance.zig - AEGIS Release Provenance (P3 Phase V)
//!
//! Provenance manifest for release artifacts: every artifact is
//! fingerprinted with SHA-256 and can be verified against its recorded
//! digest at any time.
//!
//! Phase V exit condition:
//!   A release package carries a provenance manifest (product, version,
//!   git sha, per-artifact SHA-256 + size), and verification detects
//!   any tampered artifact.
//!
//! Design notes:
//!   - Self-contained: imports only std, so it can be unit-tested in
//!     isolation.
//!   - SHA-256 via std.crypto (same primitive as policy_plane P0.2).
//!   - Digest comparison uses a timing-safe compare.
//!   - Artifact names reject '"' and '\\' so formatJson() output is
//!     always valid JSON without an escape pass.
//!   - Fixed capacity; overflow is counted, never panics (fail-soft).

const std = @import("std");

// ============================================================
// Constants
// ============================================================

/// Manifest magic ("AEGPRV1" marker stored as u32 fingerprint).
pub const PROV_MAGIC: u32 = 0x41455631; // "AEV1" (AEGIS ProVenance v1)
/// Maximum artifacts per manifest.
pub const MAX_ARTIFACTS: usize = 16;
/// Maximum artifact name length.
pub const MAX_NAME_LEN: usize = 96;
/// Maximum version string length.
pub const MAX_VERSION_LEN: usize = 32;
/// Maximum product name length.
pub const MAX_PRODUCT_LEN: usize = 32;
/// SHA-256 hex digest length.
pub const SHA256_HEX_LEN: usize = 64;
/// Git SHA length (full 40 chars + terminator room).
pub const GIT_SHA_LEN: usize = 41;

// ============================================================
// Digest helper
// ============================================================

/// Compute the lowercase hex SHA-256 of data into out (64 bytes).
pub fn sha256Hex(data: []const u8, out: *[SHA256_HEX_LEN]u8) void {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(data);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    const hex = std.fmt.bytesToHex(digest, .lower);
    @memcpy(out[0..SHA256_HEX_LEN], hex[0..SHA256_HEX_LEN]);
}

// ============================================================
// Artifact record
// ============================================================

pub const Artifact = struct {
    name_buf: [MAX_NAME_LEN]u8 = undefined,
    name_len: u8 = 0,
    version_buf: [MAX_VERSION_LEN]u8 = undefined,
    version_len: u8 = 0,
    sha_hex: [SHA256_HEX_LEN]u8 = [_]u8{'0'} ** SHA256_HEX_LEN,
    size_bytes: u64 = 0,

    pub fn name(self: *const Artifact) []const u8 {
        return self.name_buf[0..self.name_len];
    }

    pub fn version(self: *const Artifact) []const u8 {
        return self.version_buf[0..self.version_len];
    }

    pub fn sha(self: *const Artifact) []const u8 {
        return self.sha_hex[0..SHA256_HEX_LEN];
    }

    pub fn setName(self: *Artifact, s: []const u8) bool {
        if (s.len == 0 or s.len > MAX_NAME_LEN) return false;
        for (s) |ch| {
            if (ch == '"' or ch == '\\') return false;
        }
        @memcpy(self.name_buf[0..s.len], s);
        self.name_len = @intCast(s.len);
        return true;
    }

    pub fn setVersion(self: *Artifact, s: []const u8) bool {
        if (s.len > MAX_VERSION_LEN) return false;
        for (s) |ch| {
            if (ch == '"' or ch == '\\') return false;
        }
        @memcpy(self.version_buf[0..s.len], s);
        self.version_len = @intCast(s.len);
        return true;
    }

    /// Recompute SHA-256 of data and compare with the recorded digest
    /// (timing-safe). Returns true when the data is authentic.
    pub fn matchesData(self: *const Artifact, data: []const u8) bool {
        var actual: [SHA256_HEX_LEN]u8 = undefined;
        sha256Hex(data, &actual);
        // Timing-safe comparison: accumulate differences instead of early return.
        var diff: u8 = 0;
        for (actual, 0..) |c, i| {
            diff |= c ^ self.sha_hex[i];
        }
        const eql = diff == 0;
        // Size check first in the report, but the digest is decisive.
        return eql and data.len == self.size_bytes;
    }
};

// ============================================================
// Provenance manifest
// ============================================================

pub const ProvenanceManifest = struct {
    magic: u32,
    product_buf: [MAX_PRODUCT_LEN]u8 = undefined,
    product_len: u8 = 0,
    version_buf: [MAX_VERSION_LEN]u8 = undefined,
    version_len: u8 = 0,
    git_sha: [GIT_SHA_LEN]u8 = undefined,
    git_sha_len: u8 = 0,
    built_at_ms: i64 = 0,
    artifacts: [MAX_ARTIFACTS]Artifact = undefined,
    artifact_count: usize = 0,
    // Lifetime counters.
    total_verifications: u64 = 0,
    verified_ok: u64 = 0,
    verified_tampered: u64 = 0,

    /// Build a manifest header. product/version/git_sha are copied and
    /// validated (no quotes/backslashes, length-bounded).
    pub fn init(product_str: []const u8, version_str: []const u8, git_sha: []const u8, built_at_ms: i64) ?ProvenanceManifest {
        var m = ProvenanceManifest{
            .magic = PROV_MAGIC,
            .built_at_ms = built_at_ms,
        };
        if (product_str.len == 0 or product_str.len > MAX_PRODUCT_LEN) return null;
        if (version_str.len == 0 or version_str.len > MAX_VERSION_LEN) return null;
        if (git_sha.len == 0 or git_sha.len > GIT_SHA_LEN) return null;
        for (product_str) |ch| {
            if (ch == '"' or ch == '\\') return null;
        }
        for (version_str) |ch| {
            if (ch == '"' or ch == '\\') return null;
        }
        for (git_sha) |ch| {
            if (ch == '"' or ch == '\\') return null;
        }
        @memcpy(m.product_buf[0..product_str.len], product_str);
        m.product_len = @intCast(product_str.len);
        @memcpy(m.version_buf[0..version_str.len], version_str);
        m.version_len = @intCast(version_str.len);
        @memcpy(m.git_sha[0..git_sha.len], git_sha);
        m.git_sha_len = @intCast(git_sha.len);
        var i: usize = 0;
        while (i < MAX_ARTIFACTS) : (i += 1) {
            m.artifacts[i] = Artifact{};
        }
        return m;
    }

    pub fn product(self: *const ProvenanceManifest) []const u8 {
        return self.product_buf[0..self.product_len];
    }

    pub fn version(self: *const ProvenanceManifest) []const u8 {
        return self.version_buf[0..self.version_len];
    }

    pub fn gitSha(self: *const ProvenanceManifest) []const u8 {
        return self.git_sha[0..self.git_sha_len];
    }

    /// Add an artifact: name, raw bytes, and its own version string.
    /// The SHA-256 digest and size are computed here. Returns false on
    /// invalid input or when the table is full (fail-soft).
    pub fn addArtifact(self: *ProvenanceManifest, name: []const u8, data: []const u8, version_str: []const u8) bool {
        if (self.artifact_count >= MAX_ARTIFACTS) return false;
        const a = &self.artifacts[self.artifact_count];
        if (!a.setName(name)) return false;
        if (!a.setVersion(version_str)) return false;
        sha256Hex(data, &a.sha_hex);
        a.size_bytes = data.len;
        self.artifact_count += 1;
        return true;
    }

    /// Find an artifact by exact name.
    pub fn findArtifact(self: *const ProvenanceManifest, name: []const u8) ?*const Artifact {
        var i: usize = 0;
        while (i < self.artifact_count) : (i += 1) {
            if (std.mem.eql(u8, self.artifacts[i].name(), name)) {
                return &self.artifacts[i];
            }
        }
        return null;
    }

    /// Verify an artifact against its recorded digest. Returns null
    /// when the artifact is unknown; otherwise true = authentic,
    /// false = tampered/size mismatch. Counters always update.
    pub fn verifyArtifact(self: *ProvenanceManifest, name: []const u8, data: []const u8) ?bool {
        self.total_verifications += 1;
        const a = self.findArtifact(name) orelse {
            self.verified_tampered += 1;
            return null;
        };
        if (a.matchesData(data)) {
            self.verified_ok += 1;
            return true;
        }
        self.verified_tampered += 1;
        return false;
    }

    /// A manifest is complete when magic + version + at least one
    /// artifact are present.
    pub fn isComplete(self: *const ProvenanceManifest) bool {
        return self.magic == PROV_MAGIC and self.version_len > 0 and self.artifact_count > 0;
    }

    /// Render a compact JSON provenance manifest into buf.
    /// Returns bytes written, or 0 if buf is too small.
    pub fn formatJson(self: *const ProvenanceManifest, buf: []u8) usize {
        var off: usize = 0;
        const head = std.fmt.bufPrint(buf, "{{\"magic\":\"AEGPRV1\",\"product\":\"{s}\",\"version\":\"{s}\",\"git_sha\":\"{s}\",\"built_at_ms\":{d},\"artifacts\":[", .{
            self.product(),
            self.version(),
            self.gitSha(),
            self.built_at_ms,
        }) catch return 0;
        off += head.len;
        var i: usize = 0;
        while (i < self.artifact_count) : (i += 1) {
            const a = &self.artifacts[i];
            const sep = if (i == 0) "" else ",";
            const item = std.fmt.bufPrint(buf[off..], "{s}{{\"name\":\"{s}\",\"version\":\"{s}\",\"sha256\":\"{s}\",\"size\":{d}}}", .{
                sep,
                a.name(),
                a.version(),
                a.sha(),
                a.size_bytes,
            }) catch return 0;
            off += item.len;
        }
        const tail = std.fmt.bufPrint(buf[off..], "],\"artifact_count\":{d}}}", .{self.artifact_count}) catch return 0;
        off += tail.len;
        return off;
    }

    pub fn reset(self: *ProvenanceManifest) void {
        self.artifact_count = 0;
        self.total_verifications = 0;
        self.verified_ok = 0;
        self.verified_tampered = 0;
    }
};

// ============================================================
// Tests (P3.4 - Phase V)
// ============================================================

test "P3.4: sha256 known vector abc" {
    var hex: [SHA256_HEX_LEN]u8 = undefined;
    sha256Hex("abc", &hex);
    try std.testing.expectEqualStrings(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        hex[0..],
    );
}

test "P3.4: sha256 empty string" {
    var hex: [SHA256_HEX_LEN]u8 = undefined;
    sha256Hex("", &hex);
    try std.testing.expectEqualStrings(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        hex[0..],
    );
}

test "P3.4: addArtifact computes digest and size" {
    var m = ProvenanceManifest.init("AEGIS NIDS", "1.0.0", "dc67edd0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0", 1725260000000).?;
    try std.testing.expect(m.addArtifact("aegis-nids.exe", "hello binary", "1.0.0"));
    const a = m.findArtifact("aegis-nids.exe").?;
    try std.testing.expectEqual(@as(u64, 12), a.size_bytes);
    try std.testing.expectEqualStrings("1.0.0", a.version());
    // Digest must equal recomputation.
    var expect: [SHA256_HEX_LEN]u8 = undefined;
    sha256Hex("hello binary", &expect);
    try std.testing.expectEqualStrings(expect[0..], a.sha());
}

test "P3.4: verifyArtifact accepts original data" {
    var m = ProvenanceManifest.init("AEGIS NIDS", "1.0.0", "abc123", 0).?;
    _ = m.addArtifact("rules.json", "{\"rules\":[]}", "1.0.0");
    try std.testing.expectEqual(@as(?bool, true), m.verifyArtifact("rules.json", "{\"rules\":[]}"));
    try std.testing.expectEqual(@as(u64, 1), m.verified_ok);
}

test "P3.4: verifyArtifact detects tampering" {
    var m = ProvenanceManifest.init("AEGIS NIDS", "1.0.0", "abc123", 0).?;
    _ = m.addArtifact("rules.json", "{\"rules\":[]}", "1.0.0");
    try std.testing.expectEqual(@as(?bool, false), m.verifyArtifact("rules.json", "{\"rules\":[]}TAMPERED"));
    try std.testing.expectEqual(@as(u64, 1), m.verified_tampered);
    try std.testing.expectEqual(@as(?bool, null), m.verifyArtifact("unknown.bin", "whatever"));
}

test "P3.4: init rejects invalid header fields" {
    try std.testing.expect(ProvenanceManifest.init("", "1.0", "abc", 0) == null);
    try std.testing.expect(ProvenanceManifest.init("AEGIS", "", "abc", 0) == null);
    try std.testing.expect(ProvenanceManifest.init("AEGIS", "1.0", "", 0) == null);
    try std.testing.expect(ProvenanceManifest.init("AE\"GIS", "1.0", "abc", 0) == null);
}

test "P3.4: artifact name rejects quote and backslash" {
    var m = ProvenanceManifest.init("AEGIS NIDS", "1.0.0", "abc123", 0).?;
    try std.testing.expect(!m.addArtifact("bad\"name.bin", "x", "1.0"));
    try std.testing.expect(!m.addArtifact("bad\\name.bin", "x", "1.0"));
    try std.testing.expect(!m.addArtifact("", "x", "1.0"));
    try std.testing.expect(m.addArtifact("good-name.bin", "x", "1.0"));
}

test "P3.4: formatJson contains manifest fields" {
    var m = ProvenanceManifest.init("AEGIS NIDS", "1.0.0", "dc67edd", 1725260000000).?;
    _ = m.addArtifact("aegis-nids.exe", "binary-bytes", "1.0.0");
    _ = m.addArtifact("Rules.json", "{}", "1.0.0");
    var buf: [4096]u8 = undefined;
    const n = m.formatJson(&buf);
    try std.testing.expect(n > 0);
    const json = buf[0..n];
    try std.testing.expect(std.mem.indexOf(u8, json, "\"magic\":\"AEGPRV1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"product\":\"AEGIS NIDS\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"git_sha\":\"dc67edd\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"name\":\"aegis-nids.exe\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"artifact_count\":2") != null);
    // JSON must end with the closing brace.
    try std.testing.expect(json[n - 1] == '}');
}

test "P3.4: capacity guard at MAX_ARTIFACTS" {
    var m = ProvenanceManifest.init("AEGIS NIDS", "1.0.0", "abc123", 0).?;
    var i: usize = 0;
    while (i < MAX_ARTIFACTS) : (i += 1) {
        var name_buf: [32]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "art-{d}.bin", .{i});
        try std.testing.expect(m.addArtifact(name, "payload", "1.0"));
    }
    try std.testing.expect(!m.addArtifact("overflow.bin", "payload", "1.0"));
    try std.testing.expectEqual(@as(usize, MAX_ARTIFACTS), m.artifact_count);
}

test "P3.4: isComplete and reset" {
    var m = ProvenanceManifest.init("AEGIS NIDS", "1.0.0", "abc123", 0).?;
    try std.testing.expect(!m.isComplete());
    _ = m.addArtifact("a.bin", "x", "1.0");
    try std.testing.expect(m.isComplete());
    _ = m.verifyArtifact("a.bin", "tampered");
    try std.testing.expectEqual(@as(u64, 1), m.verified_tampered);
    m.reset();
    try std.testing.expectEqual(@as(usize, 0), m.artifact_count);
    try std.testing.expectEqual(@as(u64, 0), m.verified_tampered);
}
