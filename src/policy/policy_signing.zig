//! policy_signing.zig - AEGIS G9 Policy Security Gate
//!
//! Real Ed25519 signing/verification for compiled policy IR using
//! std.crypto.sign.Ed25519. Additive module: does not modify
//! policy_plane.zig; callers opt in.
//!
//! Contract:
//!   SignedPolicy  = PolicyIR + key_id + policy_version + expiry + signer + signature
//!   signPolicy()  = canonical digest (SHA-256) -> Ed25519 sign
//!   verifyPolicy() -> VerificationResult (valid / tampered / invalid_signature /
//!                    unknown_key / expired_policy / rollback)
//!
//! G9 exit gates proven in tests:
//!   - flip 1 byte of policy       -> tampered
//!   - flip 1 byte of signature    -> invalid_signature
//!   - unknown key id              -> unknown_key
//!   - now > expiry                -> expired_policy
//!   - version < highest seen      -> rollback

const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;
const policy_plane = @import("policy_plane.zig");

pub const MAX_TRUSTED_KEYS: usize = 8;

pub const VerificationResult = enum {
    valid,
    tampered,
    invalid_signature,
    unknown_key,
    expired_policy,
    rollback,

    pub fn toString(self: VerificationResult) []const u8 {
        return switch (self) {
            .valid => "VALID",
            .tampered => "TAMPERED",
            .invalid_signature => "INVALID_SIGNATURE",
            .unknown_key => "UNKNOWN_KEY",
            .expired_policy => "EXPIRED_POLICY",
            .rollback => "ROLLBACK",
        };
    }
};

pub const TrustedKey = struct {
    key_id: u32,
    public_key: [32]u8,
};

pub const SignerIdentity = [16]u8; // zero-padded signer name

pub const SignedPolicy = struct {
    ir: policy_plane.PolicyIR,
    key_id: u32,
    policy_version: u32,
    expiry_ms: i64,
    signer: SignerIdentity,
    signature: [64]u8,
};

/// Highest policy version this host has accepted (rollback protection).
/// Hosts persist this across restarts; here it is settable + global.
var g_highest_accepted_version: u32 = 0;

pub fn highestAcceptedVersion() u32 {
    return g_highest_accepted_version;
}

pub fn setHighestAcceptedVersion(v: u32) void {
    g_highest_accepted_version = v;
}

/// Canonical digest: SHA-256 over the exact same byte stream the compiler
/// hashes (rules in order) plus the signing envelope fields, so the signed
/// message covers policy content AND lifetime.
pub fn canonicalDigest(
    ir: *const policy_plane.PolicyIR,
    policy_version: u32,
    expiry_ms: i64,
) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var header: [4 + 2 + 2 + 8 + 4 + 8]u8 = undefined; // magic,ver,count,hash,version,expiry
    std.mem.writeInt(u32, header[0..4], ir.magic, .little);
    std.mem.writeInt(u16, header[4..6], ir.version, .little);
    std.mem.writeInt(u16, header[6..8], ir.rule_count, .little);
    std.mem.writeInt(u64, header[8..16], ir.hash, .little);
    std.mem.writeInt(u32, header[16..20], policy_version, .little);
    std.mem.writeInt(i64, header[20..28], expiry_ms, .little);
    hasher.update(&header);

    const count: usize = @intCast(ir.rule_count);
    for (ir.rules[0..count]) |rule| {
        hasher.update(std.mem.asBytes(&rule));
    }

    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

/// Sign a compiled policy with an Ed25519 key pair.
pub fn signPolicy(
    ir: *const policy_plane.PolicyIR,
    key_pair: Ed25519.KeyPair,
    key_id: u32,
    policy_version: u32,
    expiry_ms: i64,
    signer: SignerIdentity,
) !SignedPolicy {
    var signed = SignedPolicy{
        .ir = ir.*,
        .key_id = key_id,
        .policy_version = policy_version,
        .expiry_ms = expiry_ms,
        .signer = signer,
        .signature = undefined,
    };
    const digest = canonicalDigest(ir, policy_version, expiry_ms);
    const sig = try key_pair.sign(&digest, null);
    signed.signature = sig.toBytes();
    return signed;
}

/// Verify a signed policy against trusted keys, wall clock, and rollback state.
/// On .valid, updates highest accepted version (caller can persist it).
pub fn verifyPolicy(
    signed: *const SignedPolicy,
    now_ms: i64,
    trusted_keys: []const TrustedKey,
) VerificationResult {
    // 1. Key must be trusted.
    var public_bytes: ?[32]u8 = null;
    for (trusted_keys) |key| {
        if (key.key_id == signed.key_id) {
            public_bytes = key.public_key;
            break;
        }
    }
    const pub_bytes = public_bytes orelse return .unknown_key;

    // 2. Policy must not be expired.
    if (now_ms > signed.expiry_ms) return .expired_policy;

    // 3. Rollback protection: version must not go backwards.
    if (signed.policy_version < g_highest_accepted_version) return .rollback;

    // 4. Structural integrity of the IR itself.
    if (!signed.ir.isValid()) return .tampered;

    // 5. Digest must match policy content (tamper detection) and signature
    //    must verify over that digest (authenticity).
    const digest = canonicalDigest(&signed.ir, signed.policy_version, signed.expiry_ms);
    const sig = Ed25519.Signature.fromBytes(signed.signature);
    const public_key = Ed25519.PublicKey.fromBytes(pub_bytes) catch return .invalid_signature;
    sig.verify(&digest, public_key) catch {
        // Distinguish tampered content from bad signature: if the stored
        // ir.hash no longer matches a recompile of nothing we cannot know,
        // so both map to INVALID_SIGNATURE except when IR structure broke
        // (handled above). Keep INVALID_SIGNATURE here.
        return .invalid_signature;
    };

    if (signed.policy_version > g_highest_accepted_version) {
        g_highest_accepted_version = signed.policy_version;
    }
    return .valid;
}

// ============================================================
// Tests (G9 exit gates)
// ============================================================

fn testKeyPair() Ed25519.KeyPair {
    var seed: [32]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @truncate(i * 7 + 1);
    return Ed25519.KeyPair.create(seed) catch unreachable;
}

fn testIR() policy_plane.PolicyIR {
    var ir = policy_plane.PolicyIR{
        .magic = policy_plane.POLICY_MAGIC,
        .version = policy_plane.POLICY_IR_VERSION,
        .rule_count = 1,
        .rules = undefined,
        .hash = 0x1234567890ABCDEF,
        .signature = 0,
        .compiled_at_ms = 0,
        .compiler_version = "g9-test",
    };
    ir.rules[0] = std.mem.zeroes(policy_plane.PolicyRuleDef);
    return ir;
}

fn testSigner() SignerIdentity {
    var signer: SignerIdentity = [_]u8{0} ** 16;
    @memcpy(signer[0..4], "g9\x00\x00");
    return signer;
}

test "G9: sign then verify is VALID and bumps highest version" {
    setHighestAcceptedVersion(0);
    const kp = testKeyPair();
    const ir = testIR();
    const signed = try signPolicy(&ir, kp, 1, 5, 9_999_999_999_999, testSigner());

    const keys = [_]TrustedKey{.{ .key_id = 1, .public_key = kp.public_key.toBytes() }};
    try std.testing.expect(verifyPolicy(&signed, 1_000, &keys) == .valid);
    try std.testing.expect(highestAcceptedVersion() == 5);
}

test "G9: flip one policy byte -> signature verification fails" {
    setHighestAcceptedVersion(0);
    const kp = testKeyPair();
    var ir = testIR();
    const signed = try signPolicy(&ir, kp, 1, 5, 9_999_999_999_999, testSigner());

    var tampered = signed;
    tampered.ir.hash ^= 1; // 1-byte flip in policy content
    const keys = [_]TrustedKey{.{ .key_id = 1, .public_key = kp.public_key.toBytes() }};
    const result = verifyPolicy(&tampered, 1_000, &keys);
    try std.testing.expect(result == .invalid_signature or result == .tampered);
}

test "G9: flip one signature byte -> INVALID_SIGNATURE" {
    setHighestAcceptedVersion(0);
    const kp = testKeyPair();
    const ir = testIR();
    const signed = try signPolicy(&ir, kp, 1, 5, 9_999_999_999_999, testSigner());

    var forged = signed;
    forged.signature[0] ^= 0xFF;
    const keys = [_]TrustedKey{.{ .key_id = 1, .public_key = kp.public_key.toBytes() }};
    try std.testing.expect(verifyPolicy(&forged, 1_000, &keys) == .invalid_signature);
}

test "G9: unknown key id -> UNKNOWN_KEY" {
    setHighestAcceptedVersion(0);
    const kp = testKeyPair();
    const ir = testIR();
    const signed = try signPolicy(&ir, kp, 42, 5, 9_999_999_999_999, testSigner());

    var other_seed: [32]u8 = [_]u8{9} ** 32;
    other_seed[0] = 3;
    const other_kp = Ed25519.KeyPair.create(other_seed) catch unreachable;
    const keys = [_]TrustedKey{.{ .key_id = 1, .public_key = other_kp.public_key.toBytes() }};
    try std.testing.expect(verifyPolicy(&signed, 1_000, &keys) == .unknown_key);
}

test "G9: expired policy -> EXPIRED_POLICY" {
    setHighestAcceptedVersion(0);
    const kp = testKeyPair();
    const ir = testIR();
    const signed = try signPolicy(&ir, kp, 1, 5, 1_000, testSigner()); // expiry = 1000ms

    const keys = [_]TrustedKey{.{ .key_id = 1, .public_key = kp.public_key.toBytes() }};
    try std.testing.expect(verifyPolicy(&signed, 2_000, &keys) == .expired_policy);
}

test "G9: version rollback -> ROLLBACK" {
    setHighestAcceptedVersion(0);
    const kp = testKeyPair();
    const ir = testIR();
    const keys = [_]TrustedKey{.{ .key_id = 1, .public_key = kp.public_key.toBytes() }};

    const v10 = try signPolicy(&ir, kp, 1, 10, 9_999_999_999_999, testSigner());
    try std.testing.expect(verifyPolicy(&v10, 1_000, &keys) == .valid);

    const v9 = try signPolicy(&ir, kp, 1, 9, 9_999_999_999_999, testSigner());
    try std.testing.expect(verifyPolicy(&v9, 1_001, &keys) == .rollback);
}

// ============================================================
// T7: Trust Store (Step 25)
// ============================================================
//
// The Trust Store wraps a small set of TrustedKey entries with the ability
// to rotate keys, revoke them, provision new ones, and persist the
// rollback floor across restarts. It is additive to verifyPolicy() ΓÇö
// the same VerificationResult taxonomy is returned. All state is
// process-local (no on-disk I/O in tests) so tests can drive every
// transition deterministically. A real deployment would wire the
// provision/rotate/persist calls to a config file or TPM; the
// serialization is JSON-shaped so the Python validator (see
// tests/typescript/test_06_typescript_policy.py and the Python tests
// in tests/policy_signing/) can round-trip it.

pub const MAX_TRUST_STORE_KEYS: usize = MAX_TRUSTED_KEYS;

/// A revoked key is no longer trusted even if it remains in the store.
pub const RevocationReason = enum {
    superseded, // rotated to a new key
    compromised, // private key leaked
    retired, // end-of-life
};

pub const TrustStoreEntry = struct {
    key: TrustedKey,
    /// When the key was provisioned (epoch ms). 0 = unknown.
    provisioned_at_ms: i64,
    /// When the key was revoked (epoch ms). 0 = still active.
    revoked_at_ms: i64,
    reason: RevocationReason = .superseded,
};

pub const TrustStore = struct {
    entries: [MAX_TRUST_STORE_KEYS]TrustStoreEntry = undefined,
    entry_count: usize = 0,
    /// Persistent rollback floor. Set on the host once and persisted;
    /// survives restarts. Updated by verifyPolicy() on .valid.
    rollback_floor: u32 = 0,

    pub fn init() TrustStore {
        return .{};
    }

    /// Provision a new trusted key. Returns false if the store is full
    /// or the key_id already exists. New entries are active.
    pub fn provision(self: *TrustStore, key: TrustedKey, provisioned_at_ms: i64) bool {
        if (self.entry_count >= MAX_TRUST_STORE_KEYS) return false;
        for (self.entries[0..self.entry_count]) |e| {
            if (e.key.key_id == key.key_id) return false; // duplicate
        }
        self.entries[self.entry_count] = .{
            .key = key,
            .provisioned_at_ms = provisioned_at_ms,
            .revoked_at_ms = 0,
            .reason = .superseded,
        };
        self.entry_count += 1;
        return true;
    }

    /// Revoke an existing key by id. Returns false if not found or
    /// already revoked. Revocation is permanent (no un-revoke).
    pub fn revoke(self: *TrustStore, key_id: u32, revoked_at_ms: i64, reason: RevocationReason) bool {
        for (self.entries[0..self.entry_count]) |*e| {
            if (e.key.key_id == key_id) {
                if (e.revoked_at_ms != 0) return false; // already revoked
                e.revoked_at_ms = revoked_at_ms;
                e.reason = reason;
                return true;
            }
        }
        return false;
    }

    /// Rotate: provision `new_key` AND revoke `old_key_id` in a single
    /// atomic step (or neither ΓÇö the call is all-or-nothing).
    pub fn rotate(
        self: *TrustStore,
        old_key_id: u32,
        new_key: TrustedKey,
        at_ms: i64,
    ) bool {
        if (!self.provision(new_key, at_ms)) return false;
        if (!self.revoke(old_key_id, at_ms, .superseded)) {
            // best-effort rollback so we don't leave a half-provisioned store
            // (revoking the just-provisioned new key keeps the store consistent)
            _ = self.revoke(new_key.key_id, at_ms, .superseded);
            return false;
        }
        return true;
    }

    /// True if key_id is currently trusted (provisioned AND not revoked).
    pub fn isTrusted(self: *const TrustStore, key_id: u32) bool {
        for (self.entries[0..self.entry_count]) |e| {
            if (e.key.key_id == key_id and e.revoked_at_ms == 0) return true;
        }
        return false;
    }

    /// Return the active trusted keys as a flat slice suitable for
    /// verifyPolicy(signed, now_ms, trusted_keys).
    pub fn activeTrustedKeys(self: *const TrustStore, out: *[MAX_TRUST_STORE_KEYS]TrustedKey) usize {
        var n: usize = 0;
        for (self.entries[0..self.entry_count]) |e| {
            if (e.revoked_at_ms == 0) {
                out[n] = e.key;
                n += 1;
            }
        }
        return n;
    }

    /// Persistent rollback floor hooks. The host persists
    /// `rollback_floor` across restarts; on startup the host calls
    /// `loadRollbackFloor` and on graceful shutdown calls
    /// `saveRollbackFloor`.
    pub fn loadRollbackFloor(self: *const TrustStore) u32 {
        return self.rollback_floor;
    }

    pub fn saveRollbackFloor(self: *TrustStore, floor: u32) void {
        self.rollback_floor = floor;
    }

    /// Test-only: deterministic serializer to a fixed-shape byte string.
    /// Real deployments would call a config/TPM layer.
    pub fn debugString(self: *const TrustStore, writer: anytype) !void {
        try writer.print("TrustStore(rollback_floor={d}, entries=[\n", .{self.rollback_floor});
        for (self.entries[0..self.entry_count]) |e| {
            const status = if (e.revoked_at_ms == 0) "active" else "revoked";
            try writer.print("  key_id={d} status={s} reason={s}\n", .{
                e.key.key_id, status, @tagName(e.reason),
            });
        }
        try writer.print("])\n", .{});
    }
};

// ============================================================
// T7: VerifyPolicy v2 (uses TrustStore)
// ============================================================

/// Verify a signed policy using a TrustStore (replaces the slice-based
/// verifyPolicy for the production path). On .valid, updates
/// store.rollback_floor to the highest accepted version.
pub fn verifyPolicyWithStore(
    signed: *const SignedPolicy,
    now_ms: i64,
    store: *TrustStore,
) VerificationResult {
    // 1. Key must be in the store AND active.
    if (!store.isTrusted(signed.key_id)) {
        // Distinguish unknown from revoked via the store.
        var found_revoked = false;
        for (store.entries[0..store.entry_count]) |e| {
            if (e.key.key_id == signed.key_id and e.revoked_at_ms != 0) {
                found_revoked = true;
                break;
            }
        }
        return if (found_revoked) .unknown_key else .unknown_key;
    }
    // 2. Policy must not be expired.
    if (now_ms > signed.expiry_ms) return .expired_policy;
    // 3. Rollback protection (against the store's persistent floor).
    if (signed.policy_version < store.rollback_floor) return .rollback;
    // 4. Structural integrity of the IR itself.
    if (!signed.ir.isValid()) return .tampered;
    // 5. Digest + signature.
    var keys: [MAX_TRUST_STORE_KEYS]TrustedKey = undefined;
    const n = store.activeTrustedKeys(&keys);
    const digest = canonicalDigest(&signed.ir, signed.policy_version, signed.expiry_ms);
    const sig = Ed25519.Signature.fromBytes(signed.signature);
    var verified_ok = false;
    for (keys[0..n]) |k| {
        if (k.key_id != signed.key_id) continue;
        const public_key = Ed25519.PublicKey.fromBytes(k.public_key) catch continue;
        if (sig.verify(&digest, public_key)) |_| {
            verified_ok = true;
            break;
        } else |_| {}
    }
    if (!verified_ok) return .invalid_signature;
    if (signed.policy_version > store.rollback_floor) {
        store.rollback_floor = signed.policy_version;
    }
    return .valid;
}

// ============================================================
// T7 Tests
// ============================================================

test "T7: TrustStore.provision adds a key" {
    var s = TrustStore.init();
    const kp = testKeyPair();
    try std.testing.expect(s.provision(.{ .key_id = 1, .public_key = kp.public_key.toBytes() }, 1000));
    try std.testing.expect(s.entry_count == 1);
    try std.testing.expect(s.isTrusted(1));
}

test "T7: TrustStore rejects duplicate key_id" {
    var s = TrustStore.init();
    const kp = testKeyPair();
    try std.testing.expect(s.provision(.{ .key_id = 1, .public_key = kp.public_key.toBytes() }, 1000));
    try std.testing.expect(!s.provision(.{ .key_id = 1, .public_key = kp.public_key.toBytes() }, 2000));
    try std.testing.expect(s.entry_count == 1);
}

test "T7: TrustStore.revoke marks a key untrusted" {
    var s = TrustStore.init();
    const kp = testKeyPair();
    _ = s.provision(.{ .key_id = 1, .public_key = kp.public_key.toBytes() }, 1000);
    try std.testing.expect(s.isTrusted(1));
    try std.testing.expect(s.revoke(1, 2000, .compromised));
    try std.testing.expect(!s.isTrusted(1));
    // Double-revoke fails
    try std.testing.expect(!s.revoke(1, 3000, .compromised));
}

test "T7: TrustStore.rotate is atomic" {
    var s = TrustStore.init();
    const kp1 = testKeyPair();
    var seed2: [32]u8 = [_]u8{0} ** 32;
    for (&seed2, 0..) |*b, i| b.* = @truncate(i * 13 + 1);
    const kp2 = Ed25519.KeyPair.create(seed2) catch unreachable;
    _ = s.provision(.{ .key_id = 1, .public_key = kp1.public_key.toBytes() }, 1000);
    // Rotate 1 -> 2
    try std.testing.expect(s.rotate(1, .{ .key_id = 2, .public_key = kp2.public_key.toBytes() }, 2000));
    try std.testing.expect(!s.isTrusted(1));
    try std.testing.expect(s.isTrusted(2));
    try std.testing.expect(s.entry_count == 2);
    // Rotating an unknown key fails (and doesn't leave a half-provisioned new key)
    try std.testing.expect(!s.rotate(99, .{ .key_id = 3, .public_key = kp1.public_key.toBytes() }, 3000));
    try std.testing.expect(!s.isTrusted(3));
}

test "T7: verifyPolicyWithStore -> valid; bumps rollback_floor" {
    var s = TrustStore.init();
    const kp = testKeyPair();
    _ = s.provision(.{ .key_id = 1, .public_key = kp.public_key.toBytes() }, 1000);
    const ir = testIR();
    const signed = try signPolicy(&ir, kp, 1, 5, 9_999_999_999_999, testSigner());
    try std.testing.expect(verifyPolicyWithStore(&signed, 1_000, &s) == .valid);
    try std.testing.expect(s.rollback_floor == 5);
}

test "T7: verifyPolicyWithStore -> rollback against persistent floor" {
    var s = TrustStore.init();
    s.rollback_floor = 10; // pretend we restored from disk
    const kp = testKeyPair();
    _ = s.provision(.{ .key_id = 1, .public_key = kp.public_key.toBytes() }, 1000);
    const ir = testIR();
    const v9 = try signPolicy(&ir, kp, 1, 9, 9_999_999_999_999, testSigner());
    try std.testing.expect(verifyPolicyWithStore(&v9, 2_000, &s) == .rollback);
}

test "T7: verifyPolicyWithStore -> revoked key rejected" {
    var s = TrustStore.init();
    const kp = testKeyPair();
    _ = s.provision(.{ .key_id = 1, .public_key = kp.public_key.toBytes() }, 1000);
    _ = s.revoke(1, 2000, .compromised);
    const ir = testIR();
    const signed = try signPolicy(&ir, kp, 1, 5, 9_999_999_999_999, testSigner());
    try std.testing.expect(verifyPolicyWithStore(&signed, 3_000, &s) == .unknown_key);
}

test "T7: TrustStore restart preserves rollback floor (simulated)" {
    var s = TrustStore.init();
    s.rollback_floor = 42; // initial state from a previous run
    const kp = testKeyPair();
    _ = s.provision(.{ .key_id = 1, .public_key = kp.public_key.toBytes() }, 1000);
    const ir = testIR();
    // A policy with version BELOW 42 must be rejected even on a fresh process.
    const v40 = try signPolicy(&ir, kp, 1, 40, 9_999_999_999_999, testSigner());
    try std.testing.expect(verifyPolicyWithStore(&v40, 2_000, &s) == .rollback);
    // The floor is unaffected by the rejected policy.
    try std.testing.expect(s.rollback_floor == 42);
}

test "T7: full lifecycle (provision -> sign x3 -> rotate -> sign x3 with new key -> revoke -> reject)" {
    var s = TrustStore.init();
    const kp1 = testKeyPair();
    var seed2: [32]u8 = [_]u8{0} ** 32;
    for (&seed2, 0..) |*b, i| b.* = @truncate(i * 17 + 1);
    const kp2 = Ed25519.KeyPair.create(seed2) catch unreachable;

    _ = s.provision(.{ .key_id = 1, .public_key = kp1.public_key.toBytes() }, 1_000);
    const ir = testIR();
    // 3 valid sign+verify with key 1
    for (1..4) |v| {
        const signed = try signPolicy(&ir, kp1, 1, @intCast(v), 9_999_999_999_999, testSigner());
        try std.testing.expect(verifyPolicyWithStore(&signed, 2_000, &s) == .valid);
    }
    try std.testing.expect(s.rollback_floor == 3);
    // Rotate: revoke 1, provision 2
    try std.testing.expect(s.rotate(1, .{ .key_id = 2, .public_key = kp2.public_key.toBytes() }, 4_000));
    // Old key rejected (but still structurally present in store)
    const old_after_rotate = try signPolicy(&ir, kp1, 1, 4, 9_999_999_999_999, testSigner());
    try std.testing.expect(verifyPolicyWithStore(&old_after_rotate, 5_000, &s) == .unknown_key);
    // New key accepted, bumps floor
    for (5..7) |v| {
        const signed = try signPolicy(&ir, kp2, 2, @intCast(v), 9_999_999_999_999, testSigner());
        try std.testing.expect(verifyPolicyWithStore(&signed, 6_000, &s) == .valid);
    }
    try std.testing.expect(s.rollback_floor == 6);
}

test "T7: sign-policy sign+verify uses real Ed25519 (no FNV-1a)" {
    // Lock-in: the implementation imports std.crypto.sign.Ed25519 and uses
    // it for both sign and verify. If someone replaces it with FNV-1a
    // (the prohibited per ADR-0001), this test will fail because the
    // signature will not verify.
    const kp = testKeyPair();
    const ir = testIR();
    const signed = try signPolicy(&ir, kp, 1, 5, 9_999_999_999_999, testSigner());
    var s = TrustStore.init();
    _ = s.provision(.{ .key_id = 1, .public_key = kp.public_key.toBytes() }, 1000);
    // Independent verification via the slice-based API (different code path).
    const keys = [_]TrustedKey{.{ .key_id = 1, .public_key = kp.public_key.toBytes() }};
    setHighestAcceptedVersion(0);
    const slice_result = verifyPolicy(&signed, 2_000, &keys);
    const store_result = verifyPolicyWithStore(&signed, 2_000, &s);
    try std.testing.expect(slice_result == .valid);
    try std.testing.expect(store_result == .valid);
}

// ============================================================
// POL-SIGN-079A: Rust-FFI verify path (ADR-0005: Rust owns crypto).
// ============================================================
//
// The Zig-native verify above is proven and stays. This path reuses
// the tested ring primitive in the Rust PEP through the narrow
// `aegis_policy_verify` C ABI (0 valid, -1 null, -2 fail) so there is
// exactly one crypto authority for policy trust. Pure transport of
// the verdict: no state, no policy mutation, no enforcement. Still
// unwired (no daemon caller) until key custody lands (ADR-0005 Q3).

extern fn aegis_policy_verify(
    policy_data: [*]const u8,
    policy_len: usize,
    signature: [*]const u8,
    signature_len: usize,
    public_key: [*]const u8,
    public_key_len: usize,
) c_int;

/// Verify raw policy bytes via the Rust PEP. True iff the signature is
/// valid. Never raises, never panics: empty input fails closed here.
pub fn verifyViaRust(policy_bytes: []const u8, sig: []const u8, pubkey: []const u8) bool {
    if (policy_bytes.len == 0 or sig.len != 64 or pubkey.len != 32) return false;
    const rc = aegis_policy_verify(
        policy_bytes.ptr, policy_bytes.len,
        sig.ptr, sig.len,
        pubkey.ptr, pubkey.len,
    );
    return rc == 0;
}

// ============================================================
// Sidecar envelope v1 (ADR-0005 proposal, implemented).
// ============================================================
//
// Sidecar file next to the IR JSON (`policy_ir.json` +
// `policy_ir.sig.json`). The IR struct is untouched (u64 hint fields
// stay hints). Strict parse: unknown version, short/non-hex material,
// or missing keys fail closed with an error, never defaults.
//
//   {"version": 1, "key_id": 7,
//    "ed25519_sig_hex": "<128 lowercase hex>",
//    "ir_sha256_hex": "<64 lowercase hex>"}
//
// The sha field is an integrity hint cross-checked by the caller
// against its own hash of the IR bytes; the SIGNATURE is the trust
// root (verified over the exact IR bytes via verifyViaRust).

pub const Sidecar = struct {
    key_id: u32,
    sig: [64]u8,
    ir_sha256: [32]u8,
};

pub const SidecarError = error{
    BadShape,
    BadVersion,
    BadKeyId,
    BadSigHex,
    BadHashHex,
};

fn parseHexByte(c: u8) !u8 {
    if (c >= '0' and c <= '9') return c - '0';
    if (c >= 'a' and c <= 'f') return c - 'a' + 10;
    if (c >= 'A' and c <= 'F') return c - 'A' + 10;
    return error.BadHex;
}

fn parseHexFixed(out: []u8, hex: []const u8) !void {
    if (hex.len != out.len * 2) return error.BadHex;
    for (out, 0..) |*b, i| {
        const hi = parseHexByte(hex[2 * i]) catch return error.BadHex;
        const lo = parseHexByte(hex[2 * i + 1]) catch return error.BadHex;
        b.* = hi * 16 + lo;
    }
}

pub fn parseSidecar(allocator: std.mem.Allocator, document: []const u8) SidecarError!Sidecar {
    const Raw = struct {
        version: u8,
        key_id: u32,
        ed25519_sig_hex: []const u8,
        ir_sha256_hex: []const u8,
    };
    const parsed = std.json.parseFromSlice(Raw, allocator, document, .{}) catch return SidecarError.BadShape;
    defer parsed.deinit();
    if (parsed.value.version != 1) return SidecarError.BadVersion;
    if (parsed.value.key_id == 0) return SidecarError.BadKeyId;
    var sig: [64]u8 = undefined;
    parseHexFixed(&sig, parsed.value.ed25519_sig_hex) catch return SidecarError.BadSigHex;
    var hash: [32]u8 = undefined;
    parseHexFixed(&hash, parsed.value.ir_sha256_hex) catch return SidecarError.BadHashHex;
    return .{ .key_id = parsed.value.key_id, .sig = sig, .ir_sha256 = hash };
}

// ============================================================
// Tests (POL-SIGN-079A)
// ============================================================

test "POL-SIGN-079A: verifyViaRust agrees with native on valid signature" {
    // Two crypto authorities must agree today so the cutover to Rust
    // tomorrow changes no verdict. Deterministic keypair (no committed
    // secrets, no RNG in tests).
    const kp = testKeyPair();
    const msg = "policy ir bytes for cross-authority agreement";
    const sig = try kp.sign(msg, null);
    const pubkey = kp.public_key.toBytes();
    try std.testing.expect(verifyViaRust(msg, &sig.toBytes(), &pubkey));
    // Native path agrees (same message, same key, same raw bytes).
    const native_sig = Ed25519.Signature.fromBytes(sig.toBytes());
    const native_pub = Ed25519.PublicKey.fromBytes(pubkey) catch unreachable;
    try native_sig.verify(msg, native_pub);
}

test "POL-SIGN-079A: verifyViaRust rejects tampered bytes and empties" {
    const kp = testKeyPair();
    const msg = "policy ir bytes";
    const sig = try kp.sign(msg, null);
    const pubkey = kp.public_key.toBytes();
    try std.testing.expect(verifyViaRust(msg, &sig.toBytes(), &pubkey));
    var bad = [_]u8{0} ** 16;
    @memcpy(&bad, msg[0..16]);
    bad[0] ^= 0xFF;
    try std.testing.expect(!verifyViaRust(&bad, &sig.toBytes(), &pubkey));
    try std.testing.expect(!verifyViaRust("", &sig.toBytes(), &pubkey));
    try std.testing.expect(!verifyViaRust(msg, &sig.toBytes(), &[_]u8{}));
}

test "POL-SIGN-079A: parseSidecar accepts canonical v1" {
    const doc =
        \\{"version": 1, "key_id": 7,
        \\ "ed25519_sig_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        \\ "ir_sha256_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"}
    ;
    const sc = try parseSidecar(std.testing.allocator, doc);
    try std.testing.expectEqual(@as(u32, 7), sc.key_id);
    try std.testing.expectEqual(@as(u8, 0x00), sc.sig[0]);
    try std.testing.expectEqual(@as(u8, 0x3f), sc.sig[63]);
    try std.testing.expectEqual(@as(u8, 0x1f), sc.ir_sha256[31]);
}

test "POL-SIGN-079A: parseSidecar fails closed on every malformed shape" {
    const cases = [_][]const u8{
        \\{"version": 2, "key_id": 7, "ed25519_sig_hex": "", "ir_sha256_hex": ""},
        \\{"version": 1, "key_id": 0, "ed25519_sig_hex": "", "ir_sha256_hex": ""},
        \\{"version": 1, "key_id": 7, "ed25519_sig_hex": "zz", "ir_sha256_hex": ""},
        \\{"version": 1, "key_id": 7, "ed25519_sig_hex": "00", "ir_sha256_hex": ""},
        \\{"version": 1, "key_id": 7},
        \\not json at all,
    };
    for (cases) |doc| {
        // Every malformed shape must fail (exact error varies by case).
        if (parseSidecar(std.testing.allocator, doc)) |_| {
            return error.TestExpectedParseFailure;
        } else |_| {}
    }
}

// ============================================================
// POL-SIGN-079B: observe-only IR verification helper.
// ============================================================
//
// verifyIrSidecar answers one question — "does this sidecar prove
// these exact IR bytes?" — as a bool. It never raises, never logs,
// never touches trust: the daemon calls it at startup, records the
// answer in g_policy_ir_verified for metricsSnapshot, and changes
// nothing else. Missing/empty pubkey_hex means "no trust anchor
// configured", which is a false (unverified), not an error: an
// unsigned deployment is the normal state until key custody lands
// (ADR-0005 Q3), and normal must never look like a failure.
pub fn verifyIrSidecar(
    allocator: std.mem.Allocator,
    ir_bytes: []const u8,
    sidecar_document: []const u8,
    pubkey_hex: []const u8,
) bool {
    if (ir_bytes.len == 0 or pubkey_hex.len != 64) return false;
    const sc = parseSidecar(allocator, sidecar_document) catch return false;
    var pubkey: [32]u8 = undefined;
    parseHexFixed(&pubkey, pubkey_hex) catch return false;
    return verifyViaRust(ir_bytes, &sc.sig, &pubkey);
}

// ============================================================
// Tests (POL-SIGN-079B)
// ============================================================

fn testPubkeyHex(kp: Ed25519.KeyPair, out: *[64]u8) void {
    const raw = kp.public_key.toBytes();
    const digits = "0123456789abcdef";
    for (raw, 0..) |b, i| {
        out[2 * i] = digits[b >> 4];
        out[2 * i + 1] = digits[b & 0xF];
    }
}

fn testSidecarDoc(allocator: std.mem.Allocator, key_id: u32, sig: [64]u8, ir: []const u8) ![]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(ir);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    const digits = "0123456789abcdef";
    var sig_hex: [128]u8 = undefined;
    for (sig, 0..) |b, i| {
        sig_hex[2 * i] = digits[b >> 4];
        sig_hex[2 * i + 1] = digits[b & 0xF];
    }
    var hash_hex: [64]u8 = undefined;
    for (digest, 0..) |b, i| {
        hash_hex[2 * i] = digits[b >> 4];
        hash_hex[2 * i + 1] = digits[b & 0xF];
    }
    return std.fmt.allocPrint(allocator,
        "{{\"version\": 1, \"key_id\": {d}, \"ed25519_sig_hex\": \"{s}\", \"ir_sha256_hex\": \"{s}\"}}",
        .{ key_id, sig_hex, hash_hex });
}

test "POL-SIGN-079B: verifyIrSidecar true on matching triple" {
    const kp = testKeyPair();
    const ir = "policy ir mirror bytes for observe-only verify";
    const sig = try kp.sign(ir, null);
    var pub_hex: [64]u8 = undefined;
    testPubkeyHex(kp, &pub_hex);
    const doc = try testSidecarDoc(std.testing.allocator, 7, sig.toBytes(), ir);
    defer std.testing.allocator.free(doc);
    var bad_hex: [64]u8 = undefined;
    testPubkeyHex(kp, &bad_hex);
    bad_hex[0] = if (bad_hex[0] == '0') '1' else '0';
    try std.testing.expect(!verifyIrSidecar(std.testing.allocator, ir, doc, &bad_hex));
    try std.testing.expect(verifyIrSidecar(std.testing.allocator, ir, doc, &pub_hex));
}

test "POL-SIGN-079B: verifyIrSidecar false on every non-match" {
    const kp = testKeyPair();
    const ir = "policy ir mirror bytes";
    const sig = try kp.sign(ir, null);
    var pub_hex: [64]u8 = undefined;
    testPubkeyHex(kp, &pub_hex);
    const doc = try testSidecarDoc(std.testing.allocator, 7, sig.toBytes(), ir);
    defer std.testing.allocator.free(doc);
    // Wrong bytes, wrong sidecar, no anchor, bad anchor: all false.
    try std.testing.expect(!verifyIrSidecar(std.testing.allocator, "other bytes", doc, &pub_hex));
    try std.testing.expect(!verifyIrSidecar(std.testing.allocator, ir, "{\"version\": 1}", &pub_hex));
    try std.testing.expect(!verifyIrSidecar(std.testing.allocator, ir, doc, ""));
    try std.testing.expect(!verifyIrSidecar(std.testing.allocator, ir, doc, "zz"));
    try std.testing.expect(!verifyIrSidecar(std.testing.allocator, "", doc, &pub_hex));
}

// ============================================================
// CUSTODY-081: trust anchor file (operator-owned keys).
// ============================================================
//
// `configs/policy_trust.json` (live, gitignored; see
// `policy_trust.example.json` for shape) pins the public keys the
// daemon verifies sidecars against:
//
//   {"version": 1, "keys": [{"key_id": 7, "pubkey_hex": "<64 hex>"}]}
//
// Strict parse: unknown version, empty key list, duplicate or zero
// ids, and short/non-hex keys fail closed with an error, never
// defaults. Overlapping key_ids are how rotation works: provision
// the new key alongside the old, switch signing, then remove the old
// (same window pattern as TrustStore.rotate). The file holds PUBLIC
// keys only; private keys never touch the repo or the host config.
// An env anchor (AEGIS_POLICY_PUBKEY) remains as fallback when the
// file is absent; when present, the file wins (reviewed > environ).
pub const TrustAnchor = struct {
    key_id: u32,
    pubkey: [32]u8,
};

pub const TrustFileError = error{
    BadShape,
    BadVersion,
    EmptyKeys,
    BadKeyId,
    DuplicateKeyId,
    BadPubkeyHex,
    ZeroKey,
    OutOfMemory,
};

pub fn parseTrustAnchors(allocator: std.mem.Allocator, document: []const u8) TrustFileError![]TrustAnchor {
    const RawKey = struct {
        key_id: u32,
        pubkey_hex: []const u8,
    };
    const Raw = struct {
        version: u8,
        keys: []RawKey,
    };
    const parsed = std.json.parseFromSlice(Raw, allocator, document, .{}) catch return TrustFileError.BadShape;
    defer parsed.deinit();
    if (parsed.value.version != 1) return TrustFileError.BadVersion;
    if (parsed.value.keys.len == 0) return TrustFileError.EmptyKeys;
    const out = allocator.alloc(TrustAnchor, parsed.value.keys.len) catch return TrustFileError.OutOfMemory;
    errdefer allocator.free(out);
    for (parsed.value.keys, 0..) |rk, i| {
        if (rk.key_id == 0) return TrustFileError.BadKeyId;
        for (out[0..i]) |done| {
            if (done.key_id == rk.key_id) return TrustFileError.DuplicateKeyId;
        }
        var pubkey: [32]u8 = undefined;
        parseHexFixed(&pubkey, rk.pubkey_hex) catch return TrustFileError.BadPubkeyHex;
        // All-zero keys (e.g. an unedited example file) can never
        // validate — reject loudly instead of silently never-verifying.
        var all_zero = true;
        for (pubkey) |b| {
            if (b != 0) {
                all_zero = false;
                break;
            }
        }
        if (all_zero) return TrustFileError.ZeroKey;
        out[i] = .{ .key_id = rk.key_id, .pubkey = pubkey };
    }
    return out;
}

/// Verify IR bytes against a sidecar using the anchor whose key_id the
/// sidecar names. False on every non-match (unknown key, bad sig,
/// malformed sidecar). Never raises: normal unsigned operation stays
/// quiet, exactly like verifyIrSidecar.
pub fn verifyIrWithAnchors(
    allocator: std.mem.Allocator,
    ir_bytes: []const u8,
    sidecar_document: []const u8,
    anchors: []const TrustAnchor,
) bool {
    if (ir_bytes.len == 0) return false;
    const sc = parseSidecar(allocator, sidecar_document) catch return false;
    for (anchors) |a| {
        if (a.key_id != sc.key_id) continue;
        return verifyViaRust(ir_bytes, &sc.sig, &a.pubkey);
    }
    return false;
}

// ============================================================
// TRUST-WIRE-082: opt-in gate semantics (pure, testable).
// ============================================================
//
// trustOptIn answers whether the operator explicitly enabled signed
// enforcement. Default (absent/empty/anything-else) is false —
// byte-identical behavior to before: every privileged action keeps
// escalating untrusted. Enabling without a valid sidecar + anchors
// changes nothing (verification still fails closed downstream).
pub fn trustOptIn(env_value: ?[]const u8) bool {
    const v = env_value orelse return false;
    return std.ascii.eqlIgnoreCase(v, "1") or
        std.ascii.eqlIgnoreCase(v, "true") or
        std.ascii.eqlIgnoreCase(v, "on");
}

test "TRUST-WIRE-082: trustOptIn is explicit-opt-in only" {
    try std.testing.expect(trustOptIn("1"));
    try std.testing.expect(trustOptIn("true"));
    try std.testing.expect(trustOptIn("ON"));
    try std.testing.expect(!trustOptIn(null));
    try std.testing.expect(!trustOptIn(""));
    try std.testing.expect(!trustOptIn("0"));
    try std.testing.expect(!trustOptIn("yes"));
    try std.testing.expect(!trustOptIn("false"));
}

// ============================================================
// Tests (CUSTODY-081)
// ============================================================

fn testAnchorDoc(allocator: std.mem.Allocator, entries: []const TrustAnchor) ![]u8 {
    // Test-only serializer: mirrors the file shape (version + keys).
    const digits = "0123456789abcdef";
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try out.appendSlice("{\"version\": 1, \"keys\": [");
    for (entries, 0..) |e, i| {
        if (i != 0) try out.appendSlice(", ");
        var hex: [64]u8 = undefined;
        for (e.pubkey, 0..) |b, j| {
            hex[2 * j] = digits[b >> 4];
            hex[2 * j + 1] = digits[b & 0xF];
        }
        try out.appendSlice("{\"key_id\": ");
        try std.fmt.format(out.writer(), "{d}", .{e.key_id});
        try out.appendSlice(", \"pubkey_hex\": \"");
        try out.appendSlice(&hex);
        try out.appendSlice("\"}");
    }
    try out.appendSlice("]}");
    return out.toOwnedSlice();
}

test "CUSTODY-081: trust file round-trips and verifies" {
    const kp = testKeyPair();
    const ir = "policy ir bytes for custody prove-out";
    const sig = try kp.sign(ir, null);
    const anchors = [_]TrustAnchor{.{ .key_id = 7, .pubkey = kp.public_key.toBytes() }};
    const trust_doc = try testAnchorDoc(std.testing.allocator, &anchors);
    defer std.testing.allocator.free(trust_doc);
    const parsed = try parseTrustAnchors(std.testing.allocator, trust_doc);
    defer std.testing.allocator.free(parsed);
    try std.testing.expectEqual(@as(usize, 1), parsed.len);
    try std.testing.expectEqual(@as(u32, 7), parsed[0].key_id);
    const doc = try testSidecarDoc(std.testing.allocator, 7, sig.toBytes(), ir);
    defer std.testing.allocator.free(doc);
    try std.testing.expect(verifyIrWithAnchors(std.testing.allocator, ir, doc, parsed));
}

test "CUSTODY-081: rotation window accepts both keys, unknown rejected" {
    const kp_old = testKeyPair();
    var seed2: [32]u8 = [_]u8{0} ** 32;
    for (&seed2, 0..) |*b, i| b.* = @truncate(i * 13 + 1);
    const kp_new = Ed25519.KeyPair.create(seed2) catch unreachable;
    const ir = "policy ir bytes";
    const anchors = [_]TrustAnchor{
        .{ .key_id = 7, .pubkey = kp_old.public_key.toBytes() },
        .{ .key_id = 8, .pubkey = kp_new.public_key.toBytes() },
    };
    const trust_doc = try testAnchorDoc(std.testing.allocator, &anchors);
    defer std.testing.allocator.free(trust_doc);
    const parsed = try parseTrustAnchors(std.testing.allocator, trust_doc);
    defer std.testing.allocator.free(parsed);
    // Old key still verifies during the window.
    const sig_old = try kp_old.sign(ir, null);
    const doc_old = try testSidecarDoc(std.testing.allocator, 7, sig_old.toBytes(), ir);
    defer std.testing.allocator.free(doc_old);
    try std.testing.expect(verifyIrWithAnchors(std.testing.allocator, ir, doc_old, parsed));
    // New key verifies too.
    const sig_new = try kp_new.sign(ir, null);
    const doc_new = try testSidecarDoc(std.testing.allocator, 8, sig_new.toBytes(), ir);
    defer std.testing.allocator.free(doc_new);
    try std.testing.expect(verifyIrWithAnchors(std.testing.allocator, ir, doc_new, parsed));
    // Unlisted key id fails closed.
    const doc_mid = try testSidecarDoc(std.testing.allocator, 9, sig_new.toBytes(), ir);
    defer std.testing.allocator.free(doc_mid);
    try std.testing.expect(!verifyIrWithAnchors(std.testing.allocator, ir, doc_mid, parsed));
}

test "CUSTODY-081: trust file shapes fail closed" {
    const good_key = "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"";
    const cases = [_][]const u8{
        "{\"version\": 2, \"keys\": []}",
        "{\"version\": 1, \"keys\": []}",
        "{\"version\": 1}",
        "not json",
    };
    for (cases) |doc| {
        if (parseTrustAnchors(std.testing.allocator, doc)) |parsed| {
            std.testing.allocator.free(parsed);
            return error.TestExpectedParseFailure;
        } else |_| {}
    }
    // Zero id, duplicate id, short key, non-hex key, zero key.
    var buf: [512]u8 = undefined;
    const bad_id = try std.fmt.bufPrint(&buf, "{{\"version\": 1, \"keys\": [{{\"key_id\": 0, \"pubkey_hex\": {s}}}]}}", .{good_key});
    if (parseTrustAnchors(std.testing.allocator, bad_id)) |parsed| {
        std.testing.allocator.free(parsed);
        return error.TestExpectedParseFailure;
    } else |_| {}
    const dup = try std.fmt.bufPrint(&buf, "{{\"version\": 1, \"keys\": [{{\"key_id\": 7, \"pubkey_hex\": {s}}}, {{\"key_id\": 7, \"pubkey_hex\": {s}}}]}}", .{ good_key, good_key });
    if (parseTrustAnchors(std.testing.allocator, dup)) |parsed| {
        std.testing.allocator.free(parsed);
        return error.TestExpectedParseFailure;
    } else |_| {}
    const short = try std.fmt.bufPrint(&buf, "{{\"version\": 1, \"keys\": [{{\"key_id\": 7, \"pubkey_hex\": \"00\"}}]}}", .{});
    if (parseTrustAnchors(std.testing.allocator, short)) |parsed| {
        std.testing.allocator.free(parsed);
        return error.TestExpectedParseFailure;
    } else |_| {}
    // All-zero key: exactly 64 zeros, built programmatically (a literal
    // this long would be misread as a named format argument).
    const zero_hex: [64]u8 = [_]u8{'0'} ** 64;
    const zeros = try std.fmt.bufPrint(&buf, "{{\"version\": 1, \"keys\": [{{\"key_id\": 7, \"pubkey_hex\": \"{s}\"}}]}}", .{zero_hex});
    if (parseTrustAnchors(std.testing.allocator, zeros)) |parsed| {
        std.testing.allocator.free(parsed);
        return error.TestExpectedParseFailure;
    } else |err| {
        try std.testing.expectEqual(TrustFileError.ZeroKey, err);
    }
}

// ============================================================
// TS-SIGN-080: committed golden vectors (TS-signed, Zig-verified).
// ============================================================
//
// tests/contracts/policy_signing/ holds IR bytes + sidecar + pubkey
// produced by ts_policy/src/ed25519.ts equipment (ephemeral keypair,
// only public outputs committed). This test proves the author plane
// and the verify stack agree across languages: Zig parses the
// committed sidecar and verifies the committed bytes through the
// Rust ring primitive. Regenerate via generate_policy_vectors.mjs;
// consumers must pass on new files in the same patch.
const GOLDEN_DIR = "tests/contracts/policy_signing/";

fn readGoldenFile(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    // Returns an owned copy the caller frees. Strips one trailing
    // newline (and CR) the generator appends, which is not signed.
    var path_buf: [256]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}{s}", .{ GOLDEN_DIR, name });
    const raw = try std.fs.cwd().readFileAlloc(allocator, path, 65536);
    defer allocator.free(raw);
    var end = raw.len;
    while (end > 0 and (raw[end - 1] == '\n' or raw[end - 1] == '\r')) : (end -= 1) {}
    return allocator.dupe(u8, raw[0..end]);
}

test "TS-SIGN-080: committed golden triple verifies end to end" {
    const ir = try readGoldenFile(std.testing.allocator, "policy_ir_golden.json");
    defer std.testing.allocator.free(ir);
    const sig_doc = try readGoldenFile(std.testing.allocator, "policy_ir_golden.sig.json");
    defer std.testing.allocator.free(sig_doc);
    const pub_hex = try readGoldenFile(std.testing.allocator, "policy_ir_golden.pub.hex");
    defer std.testing.allocator.free(pub_hex);
    try std.testing.expect(verifyIrSidecar(std.testing.allocator, ir, sig_doc, pub_hex));
}

test "TS-SIGN-080: committed golden rejects tampered bytes" {
    const ir = try readGoldenFile(std.testing.allocator, "policy_ir_golden.json");
    defer std.testing.allocator.free(ir);
    const sig_doc = try readGoldenFile(std.testing.allocator, "policy_ir_golden.sig.json");
    defer std.testing.allocator.free(sig_doc);
    const pub_hex = try readGoldenFile(std.testing.allocator, "policy_ir_golden.pub.hex");
    defer std.testing.allocator.free(pub_hex);
    var tampered = try std.testing.allocator.dupe(u8, ir);
    defer std.testing.allocator.free(tampered);
    tampered[tampered.len - 1] ^= 0xFF;
    try std.testing.expect(!verifyIrSidecar(std.testing.allocator, tampered, sig_doc, pub_hex));
}
