// I17 - Trust Store & Key Lifecycle
// AEGIS NIDS v5.0+ â€” Cryptographic trust material management
//
// On Windows: prefers CNG (BCrypt) for key storage; falls back to in-memory.
// On Linux/test: in-memory only.
//
// Lifecycle states:
//   generated â†’ loaded â†’ active â†’ rotating â†’ retired â†’ revoked

const std = @import("std");
const diag = @import("../core/diagnostics.zig");

pub const KeyKind = enum(u8) {
    rsa_2048 = 1,
    rsa_4096 = 2,
    ecdsa_p256 = 3,
    ecdsa_p384 = 4,
    ed25519 = 5,
    aes_256_gcm = 6,
};

pub const KeyPurpose = enum(u8) {
    federation_sign = 1,
    federation_tls = 2,
    forensic_sign = 3,
    config_sign = 4,
    installer_sign = 5,
};

pub const KeyState = enum(u8) {
    generated = 0,
    loaded = 1,
    active = 2,
    rotating = 3,
    retired = 4,
    revoked = 5,
};

pub const KeyId = [16]u8;

pub const KeyRecord = struct {
    id: KeyId,
    kind: KeyKind,
    purpose: KeyPurpose,
    state: KeyState,
    not_before_ns: i128,
    not_after_ns: i128,
    rotation_after_ns: i128,
    fingerprint: [32]u8,
    // Material: kept opaque (in-memory), never written to disk in plaintext
    material: [256]u8 = [_]u8{0} ** 256,
    material_len: u16 = 0,
};

pub const TrustStore = struct {
    keys: std.ArrayList(KeyRecord),
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator) TrustStore {
        return .{
            .keys = std.ArrayList(KeyRecord).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *TrustStore) void {
        // Securely wipe material
        for (self.keys.items) |*k| {
            const buf = k.material[0..k.material_len];
            @memset(buf, 0);
            std.mem.doNotOptimizeAway(buf);
        }
        self.keys.deinit();
    }

    pub fn generate(self: *TrustStore, kind: KeyKind, purpose: KeyPurpose, ttl_ns: i128) !KeyId {
        self.mutex.lock();
        defer self.mutex.unlock();
        var id: KeyId = undefined;
        std.crypto.random.bytes(&id);
        const now: i128 = std.time.nanoTimestamp();
        var fp: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&id, &fp, .{});
        var rec = KeyRecord{
            .id = id,
            .kind = kind,
            .purpose = purpose,
            .state = .generated,
            .not_before_ns = now,
            .not_after_ns = now + ttl_ns,
            .rotation_after_ns = now + @divFloor(ttl_ns, 2),
            .fingerprint = fp,
        };
        // Generate key material (mock â€” real impl uses CNG/OpenSSL)
        switch (kind) {
            .aes_256_gcm => {
                std.crypto.random.bytes(rec.material[0..32]);
                rec.material_len = 32;
            },
            .rsa_2048, .rsa_4096, .ecdsa_p256, .ecdsa_p384, .ed25519 => {
                std.crypto.random.bytes(rec.material[0..32]);
                rec.material_len = 32; // placeholder for test
            },
        }
        rec.state = .active;
        try self.keys.append(rec);
        diag.info("TrustStore: generated key kind={} purpose={}", .{ @intFromEnum(kind), @intFromEnum(purpose) });
        return id;
    }

    pub fn lookup(self: *TrustStore, id: KeyId) ?*KeyRecord {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.keys.items) |*k| {
            if (std.mem.eql(u8, &k.id, &id)) return k;
        }
        return null;
    }

    pub fn lookupActive(self: *TrustStore, purpose: KeyPurpose) ?*KeyRecord {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.keys.items) |*k| {
            if (k.purpose == purpose and k.state == .active) {
                const now = std.time.nanoTimestamp();
                if (now < k.not_after_ns) return k;
            }
        }
        return null;
    }

    pub fn revoke(self: *TrustStore, id: KeyId) bool {
        if (self.lookup(id)) |k| {
            k.state = .revoked;
            return true;
        }
        return false;
    }

    pub fn rotateDue(self: *TrustStore, now_ns: i128) ?KeyId {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.keys.items) |*k| {
            if (k.state == .active and now_ns > k.rotation_after_ns) {
                k.state = .rotating;
                return k.id;
            }
        }
        return null;
    }
};

// ============================================================================
// Tests
// ============================================================================
test "TrustStore generate and lookup" {
    var ts = TrustStore.init(std.testing.allocator);
    defer ts.deinit();
    const id = try ts.generate(.aes_256_gcm, .federation_sign, std.time.ns_per_s * 3600);
    const k = ts.lookup(id).?;
    try std.testing.expectEqual(KeyKind.aes_256_gcm, k.kind);
    try std.testing.expectEqual(KeyState.active, k.state);
}

test "TrustStore lookupActive by purpose" {
    var ts = TrustStore.init(std.testing.allocator);
    defer ts.deinit();
    _ = try ts.generate(.aes_256_gcm, .federation_tls, std.time.ns_per_s * 3600);
    const k = ts.lookupActive(.federation_tls).?;
    try std.testing.expectEqual(KeyPurpose.federation_tls, k.purpose);
    try std.testing.expect(ts.lookupActive(.config_sign) == null);
}

test "TrustStore revoke" {
    var ts = TrustStore.init(std.testing.allocator);
    defer ts.deinit();
    const id = try ts.generate(.aes_256_gcm, .forensic_sign, std.time.ns_per_s * 3600);
    try std.testing.expect(ts.revoke(id));
    const k = ts.lookup(id).?;
    try std.testing.expectEqual(KeyState.revoked, k.state);
}

test "TrustStore rotateDue" {
    var ts = TrustStore.init(std.testing.allocator);
    defer ts.deinit();
    _ = try ts.generate(.aes_256_gcm, .config_sign, std.time.ns_per_s); // TTL 1s
    // Wait until past rotation_after (TTL/2 = 0.5s)
    std.time.sleep(600 * std.time.ns_per_ms);
    const id = ts.rotateDue(std.time.nanoTimestamp()).?;
    const k = ts.lookup(id).?;
    try std.testing.expectEqual(KeyState.rotating, k.state);
}
