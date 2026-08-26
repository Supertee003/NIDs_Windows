//! wire_event.zig - AEGIS Wire Event Format v1 (Phase 24, AEGIS-003)
//!
//! Defines the wire-level serialization format for CanonicalEvent transport
//! across IPC channels (named pipes, UDP, shared memory, TCP).
//!
//! Wire Format:
//!   [4 bytes]  Magic: 0x57455631 ("WEV1" = Wire Event v1)
//!   [2 bytes]  Version: 1
//!   [2 bytes]  Payload type: 0=CanonicalEvent, 1=Command, 2=Ack
//!   [4 bytes]  Payload length (u32, little-endian)
//!   [N bytes]  Payload data (serialized CanonicalEvent or command)
//!   [4 bytes]  CRC32 of payload (for integrity check)
//!
//! Total header: 16 bytes. Max payload: 65536 bytes.

const std = @import("std");
const canonical = @import("canonical_event.zig");

// ============================================================
// Wire Protocol Constants (AEGIS-003)
// ============================================================

pub const WIRE_MAGIC: u32 = 0x57455631; // "WEV1" = Wire Event v1
pub const WIRE_VERSION: u16 = 1;
pub const WIRE_HEADER_SIZE: usize = 16;
pub const WIRE_MAX_PAYLOAD: usize = 65536;

// Payload types
pub const PayloadType = enum(u16) {
    canonical_event = 0,  // Standard CanonicalEvent
    command = 1,         // Control command (reload, shutdown, etc.)
    ack = 2,             // Acknowledgement
    heartbeat = 3,        // Keepalive
};

// ============================================================
// Wire Header Structure
// ============================================================

pub const WireHeader = extern struct {
    magic: u32,           // WIRE_MAGIC (0x57455631)
    version: u16,         // WIRE_VERSION (1)
    payload_type: u16,    // PayloadType enum value
    payload_length: u32,  // Length of payload data following header
    crc32: u32,           // CRC32 of payload for integrity
};

// ============================================================
// Serialization
// ============================================================

/// Serialize a CanonicalEvent into a wire-format frame.
/// Writes header + payload into the provided buffer.
/// Returns the total bytes written, or error if buffer too small.
pub fn serializeEvent(buf: []u8, event: *const canonical.CanonicalEvent) !usize {
    if (buf.len < WIRE_HEADER_SIZE + @sizeOf(canonical.CanonicalEvent)) {
        return error.BufferTooSmall;
    }

    // Compute CRC32 of the event payload
    const event_bytes = canonical.serialize(event);
    var crc = std.hash.Crc32.init();
    crc.update(event_bytes);
    const crc_val = crc.final();

    // Build header
    const header = WireHeader{
        .magic = WIRE_MAGIC,
        .version = WIRE_VERSION,
        .payload_type = @intFromEnum(PayloadType.canonical_event),
        .payload_length = @intCast(event_bytes.len),
        .crc32 = crc_val,
    };

    // Copy header
    const header_bytes: [*]const u8 = @ptrCast(&header);
    @memcpy(buf[0..WIRE_HEADER_SIZE], header_bytes[0..WIRE_HEADER_SIZE]);

    // Copy payload
    @memcpy(buf[WIRE_HEADER_SIZE..WIRE_HEADER_SIZE + event_bytes.len], event_bytes);

    return WIRE_HEADER_SIZE + event_bytes.len;
}

/// Deserialize a wire-format frame into a CanonicalEvent.
/// Validates magic, version, and CRC32.
/// Returns the event pointer, or null if validation fails.
pub fn deserializeEvent(buf: []const u8) ?*const canonical.CanonicalEvent {
    if (buf.len < WIRE_HEADER_SIZE) return null;

    // Parse header
    const header: *const WireHeader = @ptrCast(@alignCast(buf.ptr));

    // Validate magic
    if (header.magic != WIRE_MAGIC) return null;

    // Validate version
    if (header.version != WIRE_VERSION) return null;

    // Validate payload type
    if (header.payload_type != @intFromEnum(PayloadType.canonical_event)) return null;

    // Validate payload length
    const payload_len = header.payload_length;
    if (payload_len != @sizeOf(canonical.CanonicalEvent)) return null;
    if (buf.len < WIRE_HEADER_SIZE + payload_len) return null;

    // Extract payload
    const payload = buf[WIRE_HEADER_SIZE..WIRE_HEADER_SIZE + payload_len];

    // Verify CRC32
    var crc = std.hash.Crc32.init();
    crc.update(payload);
    if (crc.final() != header.crc32) return null;

    // Deserialize CanonicalEvent
    return canonical.deserialize(payload);
}

/// Serialize a command (non-event control message).
pub fn serializeCommand(buf: []u8, cmd_id: u32, data: []const u8) !usize {
    const total = WIRE_HEADER_SIZE + 4 + data.len; // header + cmd_id + data
    if (buf.len < total) return error.BufferTooSmall;

    // CRC32 of cmd_id + data
    var crc = std.hash.Crc32.init();
    var cmd_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &cmd_bytes, cmd_id, .little);
    crc.update(&cmd_bytes);
    crc.update(data);

    const header = WireHeader{
        .magic = WIRE_MAGIC,
        .version = WIRE_VERSION,
        .payload_type = @intFromEnum(PayloadType.command),
        .payload_length = @intCast(4 + data.len),
        .crc32 = crc.final(),
    };

    const header_bytes: [*]const u8 = @ptrCast(&header);
    @memcpy(buf[0..WIRE_HEADER_SIZE], header_bytes[0..WIRE_HEADER_SIZE]);
    @memcpy(buf[WIRE_HEADER_SIZE..][0..4], &cmd_bytes);
    @memcpy(buf[WIRE_HEADER_SIZE + 4..][0..data.len], data);

    return total;
}

/// Check if a buffer contains a valid wire frame header.
pub fn isValidFrame(buf: []const u8) bool {
    if (buf.len < WIRE_HEADER_SIZE) return false;
    const header: *const WireHeader = @ptrCast(@alignCast(buf.ptr));
    return header.magic == WIRE_MAGIC and header.version == WIRE_VERSION;
}

/// Get the total frame size (header + payload) from a buffer.
pub fn getFrameSize(buf: []const u8) ?usize {
    if (!isValidFrame(buf)) return null;
    const header: *const WireHeader = @ptrCast(@alignCast(buf.ptr));
    return WIRE_HEADER_SIZE + header.payload_length;
}

// ============================================================
// Tests
// ============================================================

test "WireHeader size is 16 bytes" {
    try std.testing.expect(@sizeOf(WireHeader) == 16);
}

test "WIRE_MAGIC is correct" {
    try std.testing.expect(WIRE_MAGIC == 0x57455631);
}

test "serializeEvent/deserializeEvent round-trip" {
    var event = canonical.create(.zig_core);
    event.event_type = .block;
    event.severity = 3;
    event.rule_id = 0x12345678;
    event.source_ip = 0xC0A80164;

    var buf: [256]u8 = undefined;
    const written = try serializeEvent(&buf, &event);
    try std.testing.expect(written == WIRE_HEADER_SIZE + @sizeOf(canonical.CanonicalEvent));

    const restored = deserializeEvent(&buf);
    try std.testing.expect(restored != null);
    try std.testing.expect(restored.?.event_type == .block);
    try std.testing.expect(restored.?.severity == 3);
    try std.testing.expect(restored.?.rule_id == 0x12345678);
    try std.testing.expect(restored.?.source_ip == 0xC0A80164);
}

test "deserializeEvent rejects wrong magic" {
    var event = canonical.create(.zig_core);
    var buf: [256]u8 = undefined;
    _ = try serializeEvent(&buf, &event);

    // Corrupt magic
    buf[0] = 0x00;
    try std.testing.expect(deserializeEvent(&buf) == null);
}

test "deserializeEvent rejects corrupted CRC" {
    var event = canonical.create(.zig_core);
    var buf: [256]u8 = undefined;
    _ = try serializeEvent(&buf, &event);

    // Corrupt payload (after header)
    buf[WIRE_HEADER_SIZE + 4] ^= 0xFF;
    try std.testing.expect(deserializeEvent(&buf) == null);
}

test "deserializeEvent rejects short buffer" {
    const short = [_]u8{0} ** 10;
    try std.testing.expect(deserializeEvent(&short) == null);
}

test "serializeCommand round-trip" {
    var buf: [256]u8 = undefined;
    const cmd_data = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const written = try serializeCommand(&buf, 42, &cmd_data);
    try std.testing.expect(written == WIRE_HEADER_SIZE + 4 + 4);

    // Verify header
    try std.testing.expect(isValidFrame(&buf));
    const frame_size = getFrameSize(&buf);
    try std.testing.expect(frame_size != null);
    try std.testing.expect(frame_size.? == written);
}

test "isValidFrame rejects garbage" {
    const garbage = [_]u8{ 0x00, 0x01, 0x02, 0x03 } ++ [_]u8{0} ** 12;
    try std.testing.expect(!isValidFrame(&garbage));
}

test "PayloadType enum values" {
    try std.testing.expect(@intFromEnum(PayloadType.canonical_event) == 0);
    try std.testing.expect(@intFromEnum(PayloadType.command) == 1);
    try std.testing.expect(@intFromEnum(PayloadType.ack) == 2);
    try std.testing.expect(@intFromEnum(PayloadType.heartbeat) == 3);
}
