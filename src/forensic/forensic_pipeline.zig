// I20 - Forensic Record Pipeline
// AEGIS NIDS v5.0+ -- Pre-allocated ring buffer for evidence preservation
//
// PATCH-33: Forensic Record Integrity
//   - Self-contained authenticated record format
//   - Each record contains: record_seq, prev_hash, current_hash
//   - Hash chain is embedded in each record (no separate hash_chain array)
//   - readRecord returns a snapshot copy (safe for concurrent readers)
//   - verifyHashChain correctly handles ring wrap via per-record hash verification
//
// Record layout (4KB-blocked):
//   [RecordHeader 144B] [payload up to 3948B] [padding] [u32 CRC32]
//
// Integrity model:
//   current_hash = SHA-256(record_slot[0..RECORD_BYTES-4] + prev_hash)
//   CRC32 covers record_slot[0..RECORD_BYTES-4]
//
// Concurrency model:
//   - All mutations hold mutex
//   - readRecord returns an allocated COPY (caller owns memory)
//   - verifyHashChain holds mutex for consistent snapshot
//
// Ring-wrap model:
//   - Each record is self-verifying: hash(content, stored_prev_hash) == stored_current_hash
//   - Chain linkage: record[i].prev_hash == record[i-1].current_hash
//   - Oldest retained record: prev_hash may be stale (previous record overwritten)
//     → verify per-record hash, skip linkage check for first retained record

const std = @import("std");
const event = @import("../contract/event.zig");
const canonical_event = @import("../contract/canonical_event.zig");
const manifest = @import("../contract/runtime_manifest.zig");
const receipt = @import("../policy/enforcement_receipt.zig");

pub const RING_BYTES: usize = manifest.Limits.FORENSIC_RING_BYTES;
pub const RECORD_BYTES: usize = 4096;
pub const HASH_BYTES: usize = 32; // SHA-256
pub const RECORD_MAGIC: u32 = 0xF0F0FEED;

pub const RecordHeader = extern struct {
    magic: u32,
    kind: u32,
    ts_ns: i128,
    ev_id: u64,
    rule_id: u32,
    payload_len: u32,
    audit_id: u64,
    policy_id: u32,
    pep_decision: u8,
    severity: u8,
    record_seq: u64, // PATCH-33: monotonically increasing sequence
    prev_hash: [HASH_BYTES]u8, // PATCH-33: hash of previous record
    current_hash: [HASH_BYTES]u8, // PATCH-33: hash of this record
    // reserved[6] stores the CANONICAL EventSource ordinal for exact sensor
    // attribution (see canonicalSourceOf); the remaining bytes stay reserved
    // for future forensic metadata.
    reserved: [7]u8,
};

pub const HEADER_BYTES: usize = @sizeOf(RecordHeader);
pub const PAYLOAD_BYTES: usize = RECORD_BYTES - HEADER_BYTES - 4; // 4 for CRC

/// Canonical source attribution for a forensic record.
///
/// The ring is appended from the legacy pipeline event space
/// (`event.EventSource`), while every operator surface and every cross-language
/// consumer speaks the canonical `canonical_event.EventSource` space. Writing
/// the legacy ordinal into `reserved[6]` made `forensics.list --source N` name
/// a different sensor than `--source N` everywhere else in the project, so the
/// translation happens once, at the writer, and is pinned by a unit test.
/// Source-space version written into `reserved[5]`:
///   0 = legacy record (written before canonical attribution)
///   1 = canonical (`reserved[6]` holds a canonical_event.EventSource ordinal)
/// Readers must honour this byte; a legacy 99 (system) is not a canonical 99.
pub const SOURCE_SPACE_CANONICAL: u8 = 1;
/// reserved[4] is the direction metadata version; reserved[3] carries the
/// direction byte. Zero version is legacy/unknown, so old records are never
/// misread as inbound merely because their reserved bytes were zero-filled.
pub const DIRECTION_METADATA_VERSION: u8 = 1;
/// Full IPv6 identity is an authenticated prefix inside the record payload.
/// The fixed 144-byte header and 4096-byte slot remain unchanged.
pub const NETWORK_METADATA_VERSION: u8 = 1;
pub const NETWORK_METADATA_IPV6: u8 = 6;
pub const IPV6_SIDECAR_BYTES: usize = 32;
pub const IPV6_SIDECAR_LENGTH: u8 = 32;

pub const NetworkAddresses = struct {
    src_ipv6: [16]u8,
    dst_ipv6: [16]u8,
};

pub const RecordPayloadView = struct {
    payload: []const u8,
    src_ipv6: ?[16]u8 = null,
    dst_ipv6: ?[16]u8 = null,
    direction: ?u8 = null,
};

/// Decode record-local metadata. Unversioned records remain payload-only;
/// malformed or unknown metadata versions fail closed instead of exposing
/// sidecar bytes as packet payload.
pub fn decodeRecordPayload(record: []const u8) ?RecordPayloadView {
    if (record.len < RECORD_BYTES) return null;
    const header = std.mem.bytesAsValue(RecordHeader, record[0..HEADER_BYTES]);
    if (header.magic != RECORD_MAGIC or @as(usize, header.payload_len) > PAYLOAD_BYTES) return null;
    const payload_start = HEADER_BYTES;
    const payload_end = payload_start + @as(usize, header.payload_len);
    if (payload_end > RECORD_BYTES - 4) return null;
    const stored = record[payload_start..payload_end];
    const direction = recordDirection(header);

    return switch (header.reserved[0]) {
        0 => if (header.reserved[1] == 0 and header.reserved[2] == 0)
            .{ .payload = stored, .direction = direction }
        else
            null,
        NETWORK_METADATA_VERSION => blk: {
            if (header.reserved[1] != NETWORK_METADATA_IPV6 or
                header.reserved[2] != IPV6_SIDECAR_LENGTH or stored.len < IPV6_SIDECAR_BYTES) return null;
            var src: [16]u8 = undefined;
            var dst: [16]u8 = undefined;
            @memcpy(&src, stored[0..16]);
            @memcpy(&dst, stored[16..32]);
            break :blk .{
                .payload = stored[IPV6_SIDECAR_BYTES..],
                .src_ipv6 = src,
                .dst_ipv6 = dst,
                .direction = direction,
            };
        },
        else => null,
    };
}

/// Render a complete lowercase IPv6 address into a caller-provided 39-byte
/// buffer. No compression means output is deterministic across all readers.
pub fn formatIpv6(address: [16]u8, output: []u8) []const u8 {
    if (output.len < 39) return output[0..0];
    const digits = "0123456789abcdef";
    var offset: usize = 0;
    for (0..8) |group_index| {
        if (group_index != 0) {
            output[offset] = ':';
            offset += 1;
        }
        const group: u16 = (@as(u16, address[group_index * 2]) << 8) | address[group_index * 2 + 1];
        output[offset] = digits[@intCast((group >> 12) & 0x0f)];
        output[offset + 1] = digits[@intCast((group >> 8) & 0x0f)];
        output[offset + 2] = digits[@intCast((group >> 4) & 0x0f)];
        output[offset + 3] = digits[@intCast(group & 0x0f)];
        offset += 4;
    }
    return output[0..offset];
}

pub fn recordDirection(header: *align(1) const RecordHeader) ?u8 {
    if (header.reserved[4] != DIRECTION_METADATA_VERSION) return null;
    if (header.reserved[3] > 1) return null;
    return header.reserved[3];
}

/// Canonical source for a raw record, honouring the source-space version byte.
/// Unknown ordinals in either space resolve to `.external` instead of being
/// attributed to a sensor that did not produce them.
pub fn canonicalSourceFromRecord(raw: u8, space_version: u8) canonical_event.EventSource {
    if (space_version == SOURCE_SPACE_CANONICAL) {
        return std.meta.intToEnum(canonical_event.EventSource, raw) catch .external;
    }
    const legacy = std.meta.intToEnum(event.EventSource, raw) catch return .external;
    return canonicalSourceOf(legacy);
}

test "canonicalSourceFromRecord canonicalizes legacy records and rejects unknown ordinals" {
    // Legacy records must still be readable, with the same attribution the
    // canonical writer would produce now.
    try std.testing.expectEqual(canonical_event.EventSource.npcap_sensor, canonicalSourceFromRecord(1, 0));
    try std.testing.expectEqual(canonical_event.EventSource.zig_core, canonicalSourceFromRecord(99, 0));
    try std.testing.expectEqual(canonical_event.EventSource.external, canonicalSourceFromRecord(200, 0));
    // Canonical records are read literally.
    try std.testing.expectEqual(canonical_event.EventSource.npcap_sensor, canonicalSourceFromRecord(9, SOURCE_SPACE_CANONICAL));
    try std.testing.expectEqual(canonical_event.EventSource.external, canonicalSourceFromRecord(99, SOURCE_SPACE_CANONICAL));
}

pub fn canonicalSourceOf(src: event.EventSource) canonical_event.EventSource {
    return switch (src) {
        .capture_npcap => .npcap_sensor,
        .capture_etw => .host_telemetry,
        .capture_fim => .file_sensor,
        .capture_registry => .registry_sensor,
        .capture_pipe_monitor => .pipe_monitor,
        .capture_wfp => .wfp_sensor,
        .detection_sig => .zig_core,
        .detection_anom => .ml_detector,
        .detection_corr => .zig_core,
        .detection_brain => .python_brain,
        .policy => .zig_core,
        .federation => .cluster_federation,
        .system => .zig_core,
        _ => .external,
    };
}

test "canonicalSourceOf maps every legacy pipeline source into the canonical space" {
    try std.testing.expectEqual(canonical_event.EventSource.npcap_sensor, canonicalSourceOf(.capture_npcap));
    try std.testing.expectEqual(canonical_event.EventSource.host_telemetry, canonicalSourceOf(.capture_etw));
    try std.testing.expectEqual(canonical_event.EventSource.file_sensor, canonicalSourceOf(.capture_fim));
    try std.testing.expectEqual(canonical_event.EventSource.registry_sensor, canonicalSourceOf(.capture_registry));
    try std.testing.expectEqual(canonical_event.EventSource.pipe_monitor, canonicalSourceOf(.capture_pipe_monitor));
    try std.testing.expectEqual(canonical_event.EventSource.cluster_federation, canonicalSourceOf(.federation));
    try std.testing.expectEqual(canonical_event.EventSource.zig_core, canonicalSourceOf(.system));
    // Unknown legacy ordinals must never masquerade as a known sensor.
    try std.testing.expectEqual(canonical_event.EventSource.external, canonicalSourceOf(@enumFromInt(200)));
}

pub const ForensicRing = struct {
    storage: []u8,
    head: u64 = 0,
    tail: u64 = 0,
    written: u64 = 0,
    overwritten: u64 = 0,
    mutex: std.Thread.Mutex = .{},
    in_memory: bool = true,
    next_seq: u64 = 0, // PATCH-33: next sequence number
    last_hash: [HASH_BYTES]u8 = [_]u8{0} ** HASH_BYTES, // PATCH-33: hash of most recent record

    pub fn initMemory(allocator: std.mem.Allocator, size: usize) !ForensicRing {
        return .{
            .storage = try allocator.alloc(u8, size),
        };
    }

    pub fn deinit(self: *ForensicRing, allocator: std.mem.Allocator) void {
        allocator.free(self.storage);
    }

    pub fn capacity(self: *const ForensicRing) usize {
        return self.storage.len;
    }

    pub fn recordCount(self: *const ForensicRing) u64 {
        return self.written;
    }

    /// Records overwritten by ring wrap (RING-STAT-103: previously
    /// tracked but exposed nowhere — operators saw ever-written totals
    /// with no notion of retention loss).
    pub fn overwrittenCount(self: *const ForensicRing) u64 {
        return self.overwritten;
    }

    /// Append one record. Infallible by construction (FOR-HARD-084):
    /// a full ring overwrites the oldest records and every write lands
    /// inside caller-checked bounds, so there is no failure to report.
    /// The old `!u64` forced a `catch 0` at every call site that could
    /// never fire. Callers that need fallibility use appendReceipt
    /// (receipt validation is the fallible step, not the write).
    pub fn append(
        self: *ForensicRing,
        ev: *const event.IpcEvent,
        payload: []const u8,
        audit_id: u64,
        policy_id: u32,
        pep_decision: u8,
        severity: u8,
    ) u64 {
        return self.appendInternal(ev, payload, audit_id, policy_id, pep_decision, severity, null, null);
    }

    /// Append a canonical network event with its direction sidecar. The
    /// record header layout stays fixed; direction uses a versioned reserved
    /// byte so records written before this field remain direction-unknown.
    pub fn appendWithDirection(
        self: *ForensicRing,
        ev: *const event.IpcEvent,
        payload: []const u8,
        audit_id: u64,
        policy_id: u32,
        pep_decision: u8,
        severity: u8,
        direction: u8,
    ) u64 {
        std.debug.assert(direction <= 1);
        return self.appendInternal(ev, payload, audit_id, policy_id, pep_decision, severity, direction, null);
    }

    /// Append a network record with full IPv6 endpoints. Sidecars are stored
    /// as authenticated metadata, not exposed as part of the logical payload.
    pub fn appendWithNetworkMetadata(
        self: *ForensicRing,
        ev: *const event.IpcEvent,
        payload: []const u8,
        audit_id: u64,
        policy_id: u32,
        pep_decision: u8,
        severity: u8,
        direction: ?u8,
        src_ipv6: [16]u8,
        dst_ipv6: [16]u8,
    ) u64 {
        std.debug.assert(direction == null or direction.? <= 1);
        return self.appendInternal(ev, payload, audit_id, policy_id, pep_decision, severity, direction, .{
            .src_ipv6 = src_ipv6,
            .dst_ipv6 = dst_ipv6,
        });
    }

    fn appendInternal(
        self: *ForensicRing,
        ev: *const event.IpcEvent,
        payload: []const u8,
        audit_id: u64,
        policy_id: u32,
        pep_decision: u8,
        severity: u8,
        direction: ?u8,
        network_addresses: ?NetworkAddresses,
    ) u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        const write_at = self.head % self.storage.len;
        if (write_at + RECORD_BYTES > self.storage.len) {
            return self.appendWrapped(ev, payload, audit_id, policy_id, pep_decision, severity, direction, network_addresses);
        }
        const slot = self.storage[write_at .. write_at + RECORD_BYTES];
        // Step 1: Write header + payload (CRC computed AFTER hash embedding)
        self.writeSlot(slot, ev, payload, audit_id, policy_id, pep_decision, severity, direction, network_addresses);
        // Step 2: Compute hash over (slot excluding current_hash + CRC) + last_hash
        const record_hash = self.computeRecordHash(slot, &self.last_hash);
        // Step 3: Embed hash into record's current_hash field
        self.embedCurrentHash(slot, record_hash);
        // Step 4: Compute CRC32 over the FINAL record (with hash embedded)
        self.writeCrc(slot);
        self.last_hash = record_hash;
        self.next_seq += 1;
        self.head += RECORD_BYTES;
        self.written += 1;
        if (self.head - self.tail > self.storage.len) {
            self.tail = self.head - self.storage.len;
            self.overwritten += 1;
        }
        return self.written;
    }

    /// Append an enforcement receipt only after proving that its identity is
    /// attached to the same event. Receipt status remains data in the
    /// forensic record; this method never upgrades a decision to host effect.
    pub fn appendReceipt(
        self: *ForensicRing,
        ev: *const event.IpcEvent,
        payload: []const u8,
        enforcement: receipt.EnforcementReceipt,
        severity: u8,
    ) !u64 {
        if (!enforcement.validate()) return error.InvalidReceipt;
        if (!enforcement.isForensicallyLinkable()) return error.UnlinkedReceipt;
        if (enforcement.event_id != ev.event_id) return error.EventIdentityMismatch;
        if (enforcement.policy_id != 0 and enforcement.policy_id != ev.rule_id) {
            return error.PolicyIdentityMismatch;
        }
        return self.append(
            ev,
            payload,
            enforcement.audit_id,
            enforcement.policy_id,
            enforcement.decision,
            severity,
        );
    }

    fn appendWrapped(
        self: *ForensicRing,
        ev: *const event.IpcEvent,
        payload: []const u8,
        audit_id: u64,
        policy_id: u32,
        pep_decision: u8,
        severity: u8,
        direction: ?u8,
        network_addresses: ?NetworkAddresses,
    ) u64 {
        const at = self.head % self.storage.len;
        const first_chunk = self.storage.len - at;
        if (first_chunk > 0) {
            @memset(self.storage[at..], 0);
        }
        const slot = self.storage[0..RECORD_BYTES];
        // Step 1: Write header + payload
        self.writeSlot(slot, ev, payload, audit_id, policy_id, pep_decision, severity, direction, network_addresses);
        // Step 2: Compute hash
        const record_hash = self.computeRecordHash(slot, &self.last_hash);
        // Step 3: Embed hash
        self.embedCurrentHash(slot, record_hash);
        // Step 4: Compute CRC
        self.writeCrc(slot);
        self.last_hash = record_hash;
        self.next_seq += 1;
        self.head += RECORD_BYTES;
        self.written += 1;
        if (self.head - self.tail > self.storage.len) {
            self.tail = self.head - self.storage.len;
            self.overwritten += 1;
        }
        return self.written;
    }

    fn writeSlot(
        self: *ForensicRing,
        slot: []u8,
        ev: *const event.IpcEvent,
        payload: []const u8,
        audit_id: u64,
        policy_id: u32,
        pep_decision: u8,
        severity: u8,
        direction: ?u8,
        network_addresses: ?NetworkAddresses,
    ) void {
        @memset(slot, 0);
        const prefix_len = if (network_addresses != null) IPV6_SIDECAR_BYTES else 0;
        const logical_len = @min(payload.len, PAYLOAD_BYTES - prefix_len);
        var hdr = RecordHeader{
            .magic = RECORD_MAGIC,
            .kind = @intFromEnum(ev.kind),
            .ts_ns = @intCast(ev.timestamp_ns),
            .ev_id = ev.event_id,
            .rule_id = ev.rule_id,
            .payload_len = @intCast(prefix_len + logical_len),
            .audit_id = audit_id,
            .policy_id = policy_id,
            .pep_decision = pep_decision,
            .severity = severity,
            .record_seq = self.next_seq,
            .prev_hash = self.last_hash,
            .current_hash = [_]u8{0} ** HASH_BYTES, // filled after hash computation
            .reserved = [_]u8{
                if (network_addresses != null) NETWORK_METADATA_VERSION else 0,
                if (network_addresses != null) NETWORK_METADATA_IPV6 else 0,
                if (network_addresses != null) IPV6_SIDECAR_LENGTH else 0,
                direction orelse 0, if (direction != null) DIRECTION_METADATA_VERSION else 0,
                SOURCE_SPACE_CANONICAL, @intFromEnum(canonicalSourceOf(ev.source)),
            },
        };
        @memcpy(slot[0..@sizeOf(RecordHeader)], std.mem.asBytes(&hdr));
        if (network_addresses) |addresses| {
            const prefix = slot[@sizeOf(RecordHeader) ..][0..IPV6_SIDECAR_BYTES];
            @memcpy(prefix[0..16], &addresses.src_ipv6);
            @memcpy(prefix[16..32], &addresses.dst_ipv6);
        }
        if (logical_len > 0) {
            const start = @sizeOf(RecordHeader) + prefix_len;
            @memcpy(slot[start .. start + logical_len], payload[0..logical_len]);
        }
        // NOTE: CRC is computed AFTER hash embedding (see append/appendWrapped)
    }

    /// PATCH-33: Compute CRC32 over slot[0..RECORD_BYTES-4] and write at the end.
    /// Must be called AFTER embedCurrentHash so CRC covers the final record content.
    fn writeCrc(self: *ForensicRing, slot: []u8) void {
        _ = self;
        var crc = std.hash.Crc32.init();
        crc.update(slot[0 .. RECORD_BYTES - 4]);
        const crc_val = crc.final();
        std.mem.writeInt(u32, slot[RECORD_BYTES - 4 ..][0..4], crc_val, .little);
    }

    /// PATCH-33: Compute SHA-256 hash of a record slot.
    /// Hash covers: everything except current_hash field and CRC, plus prev_hash.
    /// This is deterministic: same computation during write and verify.
    fn computeRecordHash(self: *ForensicRing, slot: []const u8, prev_hash: *const [HASH_BYTES]u8) [HASH_BYTES]u8 {
        _ = self;
        const ch_offset = @offsetOf(RecordHeader, "current_hash");
        const after_ch = ch_offset + HASH_BYTES;
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        // Part 1: everything before current_hash field
        if (ch_offset > 0) {
            hasher.update(slot[0..ch_offset]);
        }
        // Part 2: everything after current_hash field (up to CRC)
        if (after_ch < RECORD_BYTES - 4) {
            hasher.update(slot[after_ch .. RECORD_BYTES - 4]);
        }
        // Part 3: previous record's hash
        hasher.update(prev_hash);
        var hash: [HASH_BYTES]u8 = undefined;
        hasher.final(&hash);
        return hash;
    }

    /// PATCH-33: Write the computed hash into the record's current_hash field.
    fn embedCurrentHash(self: *ForensicRing, slot: []u8, hash: [HASH_BYTES]u8) void {
        _ = self;
        const hdr = std.mem.bytesAsValue(RecordHeader, slot[0..@sizeOf(RecordHeader)]);
        hdr.current_hash = hash;
    }

    /// PATCH-33: Read a record as a snapshot copy. Caller owns the returned memory.
    /// Returns null if index is out of range or record spans a wrap boundary.
    pub fn readRecord(self: *ForensicRing, index: u64, allocator: std.mem.Allocator) ?[]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (index >= self.written) return null;
        const off = (index * RECORD_BYTES) % self.storage.len;
        if (off + RECORD_BYTES > self.storage.len) return null;
        // Return a COPY — safe for concurrent readers
        return allocator.dupe(u8, self.storage[off .. off + RECORD_BYTES]) catch null;
    }

    /// Read back the authenticated hash for a record accepted by append.
    /// The caller supplies the one-based append ordinal returned by append;
    /// an overwritten or unavailable record fails closed.
    pub fn recordHash(self: *ForensicRing, append_ordinal: u64) ?[HASH_BYTES]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (append_ordinal == 0 or append_ordinal > self.written) return null;
        const index = append_ordinal - 1;
        const num_slots = self.storage.len / RECORD_BYTES;
        const oldest: u64 = if (self.written > num_slots) self.written - num_slots else 0;
        if (index < oldest) return null;
        const off = (index * RECORD_BYTES) % self.storage.len;
        if (off + RECORD_BYTES > self.storage.len) return null;
        const slot = self.storage[off .. off + RECORD_BYTES];
        const header = std.mem.bytesAsValue(RecordHeader, slot[0..HEADER_BYTES]);
        if (header.record_seq != index) return null;
        return header.current_hash;
    }

    /// Verify CRC32 of a record slot.
    pub fn verifyRecord(slot: []const u8) bool {
        if (slot.len < RECORD_BYTES) return false;
        var crc = std.hash.Crc32.init();
        crc.update(slot[0 .. RECORD_BYTES - 4]);
        const expected = std.mem.readInt(u32, slot[RECORD_BYTES - 4 ..][0..4], .little);
        return expected == crc.final();
    }

    /// PATCH-33: Verify per-record hash integrity.
    /// Recomputes hash using the same logic as computeRecordHash.
    pub fn verifyRecordHash(slot: []const u8) bool {
        if (slot.len < @sizeOf(RecordHeader)) return false;
        const hdr = std.mem.bytesAsValue(RecordHeader, slot[0..@sizeOf(RecordHeader)]);
        if (hdr.magic != RECORD_MAGIC) return false;
        // Recompute: hash(excluding current_hash and CRC) + prev_hash
        const ch_offset = @offsetOf(RecordHeader, "current_hash");
        const after_ch = ch_offset + HASH_BYTES;
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        if (ch_offset > 0) {
            hasher.update(slot[0..ch_offset]);
        }
        if (after_ch < RECORD_BYTES - 4) {
            hasher.update(slot[after_ch .. RECORD_BYTES - 4]);
        }
        hasher.update(&hdr.prev_hash);
        var computed: [HASH_BYTES]u8 = undefined;
        hasher.final(&computed);
        return std.mem.eql(u8, &hdr.current_hash, &computed);
    }

    /// PATCH-33: Verify the hash chain across all retained records.
    /// For each record: verifies CRC + per-record hash integrity.
    /// For consecutive records: verifies chain linkage (prev_hash == previous current_hash).
    /// The first retained record's prev_hash may be stale (previous record overwritten) —
    /// linkage check is skipped for it, but per-record hash is still verified.
    pub fn verifyHashChain(self: *ForensicRing) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.written == 0) return true;
        const num_slots = self.storage.len / RECORD_BYTES;
        const oldest: u64 = if (self.written > num_slots) self.written - num_slots else 0;
        var prev_current_hash: [HASH_BYTES]u8 = [_]u8{0} ** HASH_BYTES;
        var i = oldest;
        while (i < self.written) : (i += 1) {
            const off = (i * RECORD_BYTES) % self.storage.len;
            if (off + RECORD_BYTES > self.storage.len) return false;
            const slot = self.storage[off .. off + RECORD_BYTES];
            // 1. Verify CRC
            if (!ForensicRing.verifyRecord(slot)) return false;
            // 2. Verify per-record hash integrity
            if (!ForensicRing.verifyRecordHash(slot)) return false;
            // 3. Chain linkage (skip for first retained record)
            if (i > oldest) {
                const hdr = std.mem.bytesAsValue(RecordHeader, slot[0..@sizeOf(RecordHeader)]);
                if (!std.mem.eql(u8, &hdr.prev_hash, &prev_current_hash)) return false;
            }
            const hdr = std.mem.bytesAsValue(RecordHeader, slot[0..@sizeOf(RecordHeader)]);
            prev_current_hash = hdr.current_hash;
        }
        return true;
    }

    /// PATCH-33: Get the last hash in the chain (for linking new records).
    pub fn getLastHash(self: *const ForensicRing) [HASH_BYTES]u8 {
        return self.last_hash;
    }
};

// ============================================================================
// Tests
// ============================================================================
test "ForensicRing append and read" {
    var ring = try ForensicRing.initMemory(std.testing.allocator, 16 * 1024);
    defer ring.deinit(std.testing.allocator);
    var ev = event.IpcEvent.init(.signature_match);
    ev.now();
    ev.event_id = 1;
    const payload = "some attack payload";
    _ = ring.append(&ev, payload, 0, 0, 0, 0);
    try std.testing.expectEqual(@as(u64, 1), ring.recordCount());
    const rec = ring.readRecord(0, std.testing.allocator) orelse return error.OutOfMemory;
    defer std.testing.allocator.free(rec);
    try std.testing.expect(ForensicRing.verifyRecord(rec));
    try std.testing.expect(ForensicRing.verifyRecordHash(rec));
}

test "ForensicRing recordHash reads the authenticated hash for an accepted append" {
    var ring = try ForensicRing.initMemory(std.testing.allocator, 2 * RECORD_BYTES);
    defer ring.deinit(std.testing.allocator);
    var ev = event.IpcEvent.init(.signature_match);
    ev.event_id = 77;
    ev.rule_id = 9001;
    ev.timestamp_ns = 1;
    const ordinal = ring.append(&ev, "evidence", 0, 0, 0, 4);
    const hash = ring.recordHash(ordinal).?;
    try std.testing.expect(!std.mem.eql(u8, &hash, &([_]u8{0} ** HASH_BYTES)));
    try std.testing.expect(ring.recordHash(0) == null);
    try std.testing.expect(ring.recordHash(ordinal + 1) == null);
}

test "forensic direction is versioned and old records remain unknown" {
    var ring = try ForensicRing.initMemory(std.testing.allocator, 4 * RECORD_BYTES);
    defer ring.deinit(std.testing.allocator);
    var ev = event.IpcEvent.init(.packet_captured);
    ev.now();

    _ = ring.appendWithDirection(&ev, "outbound", 0, 0, 0, 0, 1);
    _ = ring.append(&ev, "legacy", 0, 0, 0, 0);

    const outbound = ring.readRecord(0, std.testing.allocator) orelse return error.OutOfMemory;
    defer std.testing.allocator.free(outbound);
    const outbound_header = std.mem.bytesAsValue(RecordHeader, outbound[0..HEADER_BYTES]);
    try std.testing.expectEqual(@as(?u8, 1), recordDirection(outbound_header));
    try std.testing.expect(ForensicRing.verifyRecord(outbound));
    try std.testing.expect(ForensicRing.verifyRecordHash(outbound));

    const legacy = ring.readRecord(1, std.testing.allocator) orelse return error.OutOfMemory;
    defer std.testing.allocator.free(legacy);
    const legacy_header = std.mem.bytesAsValue(RecordHeader, legacy[0..HEADER_BYTES]);
    try std.testing.expect(recordDirection(legacy_header) == null);
    try std.testing.expect(ring.verifyHashChain());
}

test "forensic ring preserves IPv6 sidecars in authenticated payload metadata" {
    var ring = try ForensicRing.initMemory(std.testing.allocator, 4 * RECORD_BYTES);
    defer ring.deinit(std.testing.allocator);
    var ev = event.IpcEvent.init(.signature_match);
    ev.event_id = 0x1234;
    ev.src_ip = 0x20010DB8;
    ev.dst_ip = 0x26064700;
    const src6 = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const dst6 = [16]u8{ 0x26, 0x06, 0x47, 0, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11 };
    const payload = "GET /kernel-sensor?v=6 HTTP/1.1";

    _ = ring.appendWithNetworkMetadata(&ev, payload, 7, 0, 0, 3, 1, src6, dst6);
    const record = ring.readRecord(0, std.testing.allocator) orelse return error.OutOfMemory;
    defer std.testing.allocator.free(record);

    const view = decodeRecordPayload(record) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, payload, view.payload);
    try std.testing.expectEqual(src6, view.src_ipv6.?);
    try std.testing.expectEqual(dst6, view.dst_ipv6.?);
    try std.testing.expectEqual(@as(?u8, 1), view.direction);
    try std.testing.expectEqual(@as(u32, @intCast(payload.len + 32)), std.mem.bytesAsValue(RecordHeader, record[0..HEADER_BYTES]).payload_len);
    try std.testing.expect(ForensicRing.verifyRecord(record));
    try std.testing.expect(ForensicRing.verifyRecordHash(record));
    try std.testing.expect(ring.verifyHashChain());
}

test "forensic record decoder preserves legacy payload-only records" {
    var ring = try ForensicRing.initMemory(std.testing.allocator, 2 * RECORD_BYTES);
    defer ring.deinit(std.testing.allocator);
    var ev = event.IpcEvent.init(.packet_captured);
    _ = ring.append(&ev, "legacy-payload", 0, 0, 0, 0);
    const raw = ring.readRecord(0, std.testing.allocator) orelse return error.OutOfMemory;
    defer std.testing.allocator.free(raw);

    const view = decodeRecordPayload(raw) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("legacy-payload", view.payload);
    try std.testing.expect(view.src_ipv6 == null and view.dst_ipv6 == null);

    const header = @constCast(std.mem.bytesAsValue(RecordHeader, raw[0..HEADER_BYTES]));
    header.reserved[0] = 99;
    try std.testing.expect(decodeRecordPayload(raw) == null);
}

test "formatIpv6 renders full lowercase hextets deterministically" {
    var output: [39]u8 = undefined;
    const loopback = [_]u8{0} ** 15 ++ [_]u8{1};
    try std.testing.expectEqualStrings("0000:0000:0000:0000:0000:0000:0000:0001", formatIpv6(loopback, &output));
}

test "ForensicRing wraps around" {
    var ring = try ForensicRing.initMemory(std.testing.allocator, 2 * RECORD_BYTES);
    defer ring.deinit(std.testing.allocator);
    var ev = event.IpcEvent.init(.signature_match);
    ev.now();
    var i: u32 = 0;
    while (i < 5) : (i += 1) {
        ev.event_id = i;
        _ = ring.append(&ev, "x", 0, 0, 0, 0);
    }
    try std.testing.expectEqual(@as(u64, 5), ring.recordCount());
    try std.testing.expectEqual(@as(u64, 3), ring.overwritten);
}

test "ForensicRing verify detects corruption" {
    var ring = try ForensicRing.initMemory(std.testing.allocator, 8 * 1024);
    defer ring.deinit(std.testing.allocator);
    var ev = event.IpcEvent.init(.anomaly_detected);
    ev.now();
    _ = ring.append(&ev, "data", 0, 0, 0, 0);
    const rec = ring.readRecord(0, std.testing.allocator) orelse return error.OutOfMemory;
    defer std.testing.allocator.free(rec);
    try std.testing.expect(ForensicRing.verifyRecord(rec));
    // Corrupt the record
    var mut_rec = try std.testing.allocator.dupe(u8, rec);
    defer std.testing.allocator.free(mut_rec);
    mut_rec[0] ^= 0xFF;
    try std.testing.expect(!ForensicRing.verifyRecord(mut_rec));
}

// PATCH-33: Hash chain tests
test "ForensicRing hash chain valid after append" {
    var ring = try ForensicRing.initMemory(std.testing.allocator, 8 * 1024);
    defer ring.deinit(std.testing.allocator);
    var ev = event.IpcEvent.init(.signature_match);
    ev.now();
    _ = ring.append(&ev, "payload1", 0, 0, 0, 0);
    _ = ring.append(&ev, "payload2", 0, 0, 0, 0);
    try std.testing.expect(ring.verifyHashChain());
}

test "ForensicRing hash chain detects tampered record" {
    var ring = try ForensicRing.initMemory(std.testing.allocator, 8 * 1024);
    defer ring.deinit(std.testing.allocator);
    var ev = event.IpcEvent.init(.signature_match);
    ev.now();
    _ = ring.append(&ev, "data", 0, 0, 0, 0);
    // Tamper with the stored record content
    ring.storage[0] ^= 0xFF;
    // Hash chain should detect the tamper
    try std.testing.expect(!ring.verifyHashChain());
}

test "ForensicRing hash chain links records" {
    var ring = try ForensicRing.initMemory(std.testing.allocator, 8 * 1024);
    defer ring.deinit(std.testing.allocator);
    var ev = event.IpcEvent.init(.signature_match);
    ev.now();
    _ = ring.append(&ev, "first", 0, 0, 0, 0);
    const hash1 = ring.getLastHash();
    _ = ring.append(&ev, "second", 0, 0, 0, 0);
    const hash2 = ring.getLastHash();
    // Hashes should be different (chained)
    try std.testing.expect(!std.mem.eql(u8, &hash1, &hash2));
    // Chain should be valid
    try std.testing.expect(ring.verifyHashChain());
}

test "ForensicRing hash chain survives wrap" {
    var ring = try ForensicRing.initMemory(std.testing.allocator, 2 * RECORD_BYTES);
    defer ring.deinit(std.testing.allocator);
    var ev = event.IpcEvent.init(.signature_match);
    ev.now();
    // Append 4 records — forces wrap
    var i: u32 = 0;
    while (i < 4) : (i += 1) {
        ev.event_id = i;
        _ = ring.append(&ev, "wrap", 0, 0, 0, 0);
    }
    try std.testing.expectEqual(@as(u64, 4), ring.recordCount());
    try std.testing.expectEqual(@as(u64, 2), ring.overwritten);
    // Chain should still be valid for retained records
    try std.testing.expect(ring.verifyHashChain());
}

test "ForensicRing readRecord returns independent copy" {
    var ring = try ForensicRing.initMemory(std.testing.allocator, 8 * 1024);
    defer ring.deinit(std.testing.allocator);
    var ev = event.IpcEvent.init(.signature_match);
    ev.now();
    _ = ring.append(&ev, "original", 0, 0, 0, 0);
    const rec1 = ring.readRecord(0, std.testing.allocator) orelse return error.OutOfMemory;
    defer std.testing.allocator.free(rec1);
    // Append more data — should not affect the snapshot
    ev.event_id = 99;
    _ = ring.append(&ev, "newdata", 0, 0, 0, 0);
    // rec1 should still be valid
    try std.testing.expect(ForensicRing.verifyRecord(rec1));
    try std.testing.expect(ForensicRing.verifyRecordHash(rec1));
}

test "ForensicRing record_seq increments" {
    var ring = try ForensicRing.initMemory(std.testing.allocator, 8 * RECORD_BYTES);
    defer ring.deinit(std.testing.allocator);
    var ev = event.IpcEvent.init(.signature_match);
    ev.now();
    _ = ring.append(&ev, "a", 0, 0, 0, 0);
    _ = ring.append(&ev, "b", 0, 0, 0, 0);
    _ = ring.append(&ev, "c", 0, 0, 0, 0);
    // Verify sequence numbers are 0, 1, 2
    const rec0 = ring.readRecord(0, std.testing.allocator) orelse return error.OutOfMemory;
    defer std.testing.allocator.free(rec0);
    const hdr0 = std.mem.bytesAsValue(RecordHeader, rec0[0..@sizeOf(RecordHeader)]);
    try std.testing.expectEqual(@as(u64, 0), hdr0.record_seq);

    const rec1 = ring.readRecord(1, std.testing.allocator) orelse return error.OutOfMemory;
    defer std.testing.allocator.free(rec1);
    const hdr1 = std.mem.bytesAsValue(RecordHeader, rec1[0..@sizeOf(RecordHeader)]);
    try std.testing.expectEqual(@as(u64, 1), hdr1.record_seq);

    const rec2 = ring.readRecord(2, std.testing.allocator) orelse return error.OutOfMemory;
    defer std.testing.allocator.free(rec2);
    const hdr2 = std.mem.bytesAsValue(RecordHeader, rec2[0..@sizeOf(RecordHeader)]);
    try std.testing.expectEqual(@as(u64, 2), hdr2.record_seq);
}

test "ForensicRing appendReceipt requires matching forensic identity" {
    var ring = try ForensicRing.initMemory(std.testing.allocator, 4 * RECORD_BYTES);
    defer ring.deinit(std.testing.allocator);

    var ev = event.IpcEvent.init(.signature_match);
    ev.now();
    ev.event_id = 77;
    ev.rule_id = 12;
    const valid = receipt.EnforcementReceipt{
        .request_id = 100,
        .event_id = 77,
        .policy_id = 12,
        .decision = 1,
        .status = .simulated,
        .provider = "none",
        .trace_id = 77,
        .audit_id = 100,
    };
    try std.testing.expectEqual(@as(u64, 1), try ring.appendReceipt(&ev, "alert", valid, 3));

    const wrong_event = receipt.EnforcementReceipt{
        .request_id = 101,
        .event_id = 999,
        .policy_id = 12,
        .decision = 1,
        .status = .simulated,
        .provider = "none",
        .trace_id = 999,
        .audit_id = 101,
    };
    try std.testing.expectError(error.EventIdentityMismatch, ring.appendReceipt(&ev, "bad", wrong_event, 3));
}

test "ForensicRing rejects receipt host effect without enforced status" {
    var ring = try ForensicRing.initMemory(std.testing.allocator, 2 * RECORD_BYTES);
    defer ring.deinit(std.testing.allocator);
    var ev = event.IpcEvent.init(.signature_match);
    ev.now();
    ev.event_id = 78;
    const invalid = receipt.EnforcementReceipt{
        .request_id = 102,
        .event_id = 78,
        .policy_id = 0,
        .decision = 1,
        .status = .pending,
        .provider = "wfp",
        .host_effect_confirmed = true,
        .trace_id = 78,
        .audit_id = 102,
    };
    try std.testing.expectError(error.InvalidReceipt, ring.appendReceipt(&ev, "bad", invalid, 3));
}

// ============================================================================
// FOR-CNC-001: Concurrent Integrity Tests
// ============================================================================

const CncWriterCtx = struct {
    ring: *ForensicRing,
    thread_id: u32,
    count: u32,
};

fn cncWriterFn(ctx: *CncWriterCtx) void {
    var i: u32 = 0;
    while (i < ctx.count) : (i += 1) {
        var ev = event.IpcEvent.init(.signature_match);
        ev.now();
        ev.event_id = @as(u64, ctx.thread_id) * 1000 + i;
        _ = ctx.ring.append(&ev, "concurrent", 0, 0, 0, 0);
    }
}

test "ForensicRing concurrent append from multiple threads" {
    var ring = try ForensicRing.initMemory(std.testing.allocator, 16 * RECORD_BYTES);
    defer ring.deinit(std.testing.allocator);

    const num_threads = 4;
    const per_thread = 5;
    var threads: [num_threads]std.Thread = undefined;
    var contexts: [num_threads]CncWriterCtx = undefined;

    var t: u32 = 0;
    while (t < num_threads) : (t += 1) {
        contexts[t] = .{ .ring = &ring, .thread_id = t, .count = per_thread };
        threads[t] = try std.Thread.spawn(.{}, cncWriterFn, .{&contexts[t]});
    }

    for (threads) |th| {
        th.join();
    }

    // All threads wrote per_thread records
    try std.testing.expectEqual(@as(u64, num_threads * per_thread), ring.recordCount());
    // Hash chain should still be valid
    try std.testing.expect(ring.verifyHashChain());
}

const CncReaderCtx = struct {
    ring: *ForensicRing,
    read_count: *std.atomic.Value(u32),
    total: u32,
};

fn cncReaderFn(ctx: *CncReaderCtx) void {
    var i: u32 = 0;
    while (i < ctx.total) : (i += 1) {
        const idx = @as(u64, i) % ctx.ring.recordCount();
        if (ctx.ring.readRecord(idx, std.testing.allocator)) |rec| {
            std.testing.allocator.free(rec);
            _ = ctx.read_count.fetchAdd(1, .monotonic);
        }
    }
}

const CncLiveWriterCtx = struct {
    ring: *ForensicRing,
    count: u32,
};

fn cncLiveWriterFn(ctx: *CncLiveWriterCtx) void {
    var i: u32 = 0;
    while (i < ctx.count) : (i += 1) {
        var ev = event.IpcEvent.init(.anomaly_detected);
        ev.now();
        ev.event_id = 100 + i;
        _ = ctx.ring.append(&ev, "live", 0, 0, 0, 0);
    }
}

test "ForensicRing concurrent read while appending" {
    var ring = try ForensicRing.initMemory(std.testing.allocator, 8 * RECORD_BYTES);
    defer ring.deinit(std.testing.allocator);

    // Pre-populate with some records
    var ev = event.IpcEvent.init(.signature_match);
    ev.now();
    var i: u32 = 0;
    while (i < 4) : (i += 1) {
        ev.event_id = i;
        _ = ring.append(&ev, "seed", 0, 0, 0, 0);
    }

    var read_count = std.atomic.Value(u32).init(0);
    const read_total: u32 = 20;
    const write_total: u32 = 8;

    var r_ctx = CncReaderCtx{ .ring = &ring, .read_count = &read_count, .total = read_total };
    var w_ctx = CncLiveWriterCtx{ .ring = &ring, .count = write_total };

    var reader = try std.Thread.spawn(.{}, cncReaderFn, .{&r_ctx});
    var writer = try std.Thread.spawn(.{}, cncLiveWriterFn, .{&w_ctx});

    reader.join();
    writer.join();

    // Reader should have completed all reads
    try std.testing.expect(read_count.load(.monotonic) >= read_total);
    // Hash chain should still be valid
    try std.testing.expect(ring.verifyHashChain());
}

const CncDualCtx = struct {
    ring: *ForensicRing,
    id: u32,
    count: u32,
};

fn cncDualFn1(ctx: *CncDualCtx) void {
    var i: u32 = 0;
    while (i < ctx.count) : (i += 1) {
        var ev = event.IpcEvent.init(.signature_match);
        ev.now();
        ev.event_id = @as(u64, ctx.id) * 100 + i;
        _ = ctx.ring.append(&ev, "t1", 0, 0, 0, 0);
    }
}

fn cncDualFn2(ctx: *CncDualCtx) void {
    var i: u32 = 0;
    while (i < ctx.count) : (i += 1) {
        var ev = event.IpcEvent.init(.anomaly_detected);
        ev.now();
        ev.event_id = @as(u64, ctx.id) * 100 + i;
        _ = ctx.ring.append(&ev, "t2", 0, 0, 0, 0);
    }
}

test "ForensicRing concurrent append preserves record integrity" {
    var ring = try ForensicRing.initMemory(std.testing.allocator, 4 * RECORD_BYTES);
    defer ring.deinit(std.testing.allocator);

    const N: u32 = 12; // More than capacity to force wrap

    var c1 = CncDualCtx{ .ring = &ring, .id = 1, .count = N };
    var c2 = CncDualCtx{ .ring = &ring, .id = 2, .count = N };

    var t1 = try std.Thread.spawn(.{}, cncDualFn1, .{&c1});
    var t2 = try std.Thread.spawn(.{}, cncDualFn2, .{&c2});

    t1.join();
    t2.join();

    // Total records should be 2*N
    try std.testing.expectEqual(@as(u64, 2 * N), ring.recordCount());

    // Every retained record should pass CRC + hash verification
    const num_slots = ring.capacity() / RECORD_BYTES;
    const oldest: u64 = if (ring.recordCount() > num_slots) ring.recordCount() - num_slots else 0;
    var idx = oldest;
    while (idx < ring.recordCount()) : (idx += 1) {
        const rec = ring.readRecord(idx, std.testing.allocator) orelse return error.OutOfMemory;
        defer std.testing.allocator.free(rec);
        try std.testing.expect(ForensicRing.verifyRecord(rec));
        try std.testing.expect(ForensicRing.verifyRecordHash(rec));
    }

    // Full chain verification
    try std.testing.expect(ring.verifyHashChain());
}
