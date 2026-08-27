//! wire_event.zig - AEGIS Wire Event Format v1 (Phase 24, AEGIS-003)
//!
//! STEP 2 COMPLETE: Explicit field-by-field encoding for BOTH header AND payload.
//! No @ptrCast, no @alignCast, no struct memcpy anywhere in the wire path.
//!
//! Wire frame layout (little-endian, fixed offsets):
//!   [0..4]    magic           u32  0x57455631 ("WEV1")
//!   [4..6]    version         u16  1
//!   [6..8]    payload_type    u16  0=event, 1=cmd, 2=ack, 3=heartbeat
//!   [8..12]   payload_length  u32  bytes following header
//!   [12..16]  crc32           u32  CRC32 of payload
//!   [16..N]   payload         variable (109 bytes for canonical event)
//!
//! Total canonical event frame = 16 + 109 = 125 bytes.

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
    canonical_event = 0, // Standard CanonicalEvent
    command = 1, // Control command (reload, shutdown, etc.)
    ack = 2, // Acknowledgement
    heartbeat = 3, // Keepalive
};

// ============================================================
// Wire Header (logical struct — NOT used for serialization)
// ============================================================
// This is a plain Zig struct used only as a logical container.
// All actual wire encoding/decoding goes through serializeHeader() /
// deserializeHeader() below, which use explicit field-by-field
// std.mem.writeInt() / std.mem.readInt() — no @ptrCast, no @memcpy of struct.

pub const WireHeader = struct {
    magic: u32,
    version: u16,
    payload_type: u16,
    payload_length: u32,
    crc32: u32,
};

// ============================================================
// STEP 2: Explicit header encoding (no @ptrCast, no struct memcpy)
// ============================================================

/// Encode WireHeader field-by-field into buf[0..16].
/// All fields little-endian, matches wire_v1.md offset table.
pub fn serializeHeader(buf: []u8, header: WireHeader) !void {
    if (buf.len < WIRE_HEADER_SIZE) return error.BufferTooSmall;
    std.mem.writeInt(u32, buf[0..4], header.magic, .little);
    std.mem.writeInt(u16, buf[4..6], header.version, .little);
    std.mem.writeInt(u16, buf[6..8], header.payload_type, .little);
    std.mem.writeInt(u32, buf[8..12], header.payload_length, .little);
    std.mem.writeInt(u32, buf[12..16], header.crc32, .little);
}

/// Decode WireHeader field-by-field from bytes[0..16].
/// Returns null if buffer too short. No @ptrCast, no @alignCast.
pub fn deserializeHeader(bytes: []const u8) ?WireHeader {
    if (bytes.len < WIRE_HEADER_SIZE) return null;
    return WireHeader{
        .magic = std.mem.readInt(u32, bytes[0..4], .little),
        .version = std.mem.readInt(u16, bytes[4..6], .little),
        .payload_type = std.mem.readInt(u16, bytes[6..8], .little),
        .payload_length = std.mem.readInt(u32, bytes[8..12], .little),
        .crc32 = std.mem.readInt(u32, bytes[12..16], .little),
    };
}

// ============================================================
// Event Serialization (STEP 2: explicit throughout)
// ============================================================

/// Serialize a CanonicalEvent into a wire-format frame.
/// STEP 2: Both header AND payload use explicit field-by-field encoding.
/// Total frame size = WIRE_HEADER_SIZE + canonical.WIRE_PAYLOAD_SIZE = 16 + 109 = 125 bytes.
pub fn serializeEvent(buf: []u8, event: *const canonical.CanonicalEvent) !usize {
    const total = WIRE_HEADER_SIZE + canonical.WIRE_PAYLOAD_SIZE;
    if (buf.len < total) return error.BufferTooSmall;

    // Encode payload using canonical's explicit encoder (109 bytes, field-by-field).
    const payload_buf = buf[WIRE_HEADER_SIZE..];
    const payload_bytes_written = try canonical.serializeToBytes(event, payload_buf);
    std.debug.assert(payload_bytes_written == canonical.WIRE_PAYLOAD_SIZE);

    // Compute CRC32 over the encoded payload.
    var crc = std.hash.Crc32.init();
    crc.update(buf[WIRE_HEADER_SIZE .. WIRE_HEADER_SIZE + payload_bytes_written]);

    // Encode header field-by-field (no @ptrCast, no struct memcpy).
    const header = WireHeader{
        .magic = WIRE_MAGIC,
        .version = WIRE_VERSION,
        .payload_type = @intFromEnum(PayloadType.canonical_event),
        .payload_length = @intCast(payload_bytes_written),
        .crc32 = crc.final(),
    };
    try serializeHeader(buf[0..WIRE_HEADER_SIZE], header);

    return total;
}

/// Deserialize a wire-format frame into a CanonicalEvent (value, not pointer).
/// STEP 2: Both header AND payload use explicit field-by-field decoding.
/// Validates magic, version, payload_type, length, and CRC32.
/// Returns the decoded event value, or null if validation fails.
pub fn deserializeEvent(buf: []const u8) ?canonical.CanonicalEvent {
    if (buf.len < WIRE_HEADER_SIZE) return null;

    // Decode header field-by-field (no @ptrCast).
    const header = deserializeHeader(buf) orelse return null;

    // Validate magic.
    if (header.magic != WIRE_MAGIC) return null;
    // Validate version.
    if (header.version != WIRE_VERSION) return null;
    // Validate payload type.
    if (header.payload_type != @intFromEnum(PayloadType.canonical_event)) return null;
    // Validate payload length matches expected canonical event payload size.
    if (header.payload_length != canonical.WIRE_PAYLOAD_SIZE) return null;
    if (buf.len < WIRE_HEADER_SIZE + header.payload_length) return null;

    // Extract payload slice.
    const payload = buf[WIRE_HEADER_SIZE .. WIRE_HEADER_SIZE + header.payload_length];

    // Verify CRC32 integrity.
    var crc = std.hash.Crc32.init();
    crc.update(payload);
    if (crc.final() != header.crc32) return null;

    // Deserialize CanonicalEvent using explicit field-by-field decoding.
    return canonical.deserializeFromBytes(payload);
}

/// Serialize a command (non-event control message).
/// STEP 2: Explicit header encoding (no @ptrCast).
pub fn serializeCommand(buf: []u8, cmd_id: u32, data: []const u8) !usize {
    const total = WIRE_HEADER_SIZE + 4 + data.len;
    if (buf.len < total) return error.BufferTooSmall;

    // Encode cmd_id field-by-field.
    var cmd_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &cmd_bytes, cmd_id, .little);

    // CRC32 of cmd_id + data.
    var crc = std.hash.Crc32.init();
    crc.update(&cmd_bytes);
    crc.update(data);

    // Encode header field-by-field.
    const header = WireHeader{
        .magic = WIRE_MAGIC,
        .version = WIRE_VERSION,
        .payload_type = @intFromEnum(PayloadType.command),
        .payload_length = @intCast(4 + data.len),
        .crc32 = crc.final(),
    };
    try serializeHeader(buf[0..WIRE_HEADER_SIZE], header);

    @memcpy(buf[WIRE_HEADER_SIZE..][0..4], &cmd_bytes);
    @memcpy(buf[WIRE_HEADER_SIZE + 4 ..][0..data.len], data);

    return total;
}

/// Check if a buffer contains a valid wire frame header.
/// STEP 2: Uses explicit decoding (no @ptrCast).
pub fn isValidFrame(buf: []const u8) bool {
    const header = deserializeHeader(buf) orelse return false;
    return header.magic == WIRE_MAGIC and header.version == WIRE_VERSION;
}

/// Get the total frame size (header + payload) from a buffer.
/// STEP 2: Uses explicit header decoding.
pub fn getFrameSize(buf: []const u8) ?usize {
    if (!isValidFrame(buf)) return null;
    const header = deserializeHeader(buf) orelse return null;
    return WIRE_HEADER_SIZE + header.payload_length;
}

// ============================================================
// Tests
// ============================================================

test "WIRE_HEADER_SIZE is 16 bytes" {
    try std.testing.expect(WIRE_HEADER_SIZE == 16);
}

test "WIRE_MAGIC is correct" {
    try std.testing.expect(WIRE_MAGIC == 0x57455631);
}

test "PayloadType enum values" {
    try std.testing.expect(@intFromEnum(PayloadType.canonical_event) == 0);
    try std.testing.expect(@intFromEnum(PayloadType.command) == 1);
    try std.testing.expect(@intFromEnum(PayloadType.ack) == 2);
    try std.testing.expect(@intFromEnum(PayloadType.heartbeat) == 3);
}

// ============================================================
// STEP 2: Explicit header encoding tests
// ============================================================

test "STEP2: serializeHeader produces 16 bytes little-endian" {
    var buf: [16]u8 = undefined;
    const header = WireHeader{
        .magic = 0x57455631,
        .version = 1,
        .payload_type = 0,
        .payload_length = 109,
        .crc32 = 0xDEADBEEF,
    };
    try serializeHeader(&buf, header);

    // magic at offset 0 (LE: 31 56 45 57)
    try std.testing.expect(buf[0] == 0x31);
    try std.testing.expect(buf[1] == 0x56);
    try std.testing.expect(buf[2] == 0x45);
    try std.testing.expect(buf[3] == 0x57);

    // version at offset 4 (LE: 01 00)
    try std.testing.expect(buf[4] == 1);
    try std.testing.expect(buf[5] == 0);

    // payload_type at offset 6 (LE: 00 00)
    try std.testing.expect(buf[6] == 0);
    try std.testing.expect(buf[7] == 0);

    // payload_length at offset 8 (LE: 6D 00 00 00 = 109)
    try std.testing.expect(buf[8] == 109);
    try std.testing.expect(buf[9] == 0);
    try std.testing.expect(buf[10] == 0);
    try std.testing.expect(buf[11] == 0);

    // crc32 at offset 12 (LE: EF BE AD DE)
    try std.testing.expect(buf[12] == 0xEF);
    try std.testing.expect(buf[13] == 0xBE);
    try std.testing.expect(buf[14] == 0xAD);
    try std.testing.expect(buf[15] == 0xDE);
}

test "STEP2: deserializeHeader round-trip" {
    var buf: [16]u8 = undefined;
    const original = WireHeader{
        .magic = WIRE_MAGIC,
        .version = WIRE_VERSION,
        .payload_type = @intFromEnum(PayloadType.command),
        .payload_length = 42,
        .crc32 = 0x12345678,
    };
    try serializeHeader(&buf, original);

    const restored = deserializeHeader(&buf);
    try std.testing.expect(restored != null);
    try std.testing.expect(restored.?.magic == WIRE_MAGIC);
    try std.testing.expect(restored.?.version == WIRE_VERSION);
    try std.testing.expect(restored.?.payload_type == @intFromEnum(PayloadType.command));
    try std.testing.expect(restored.?.payload_length == 42);
    try std.testing.expect(restored.?.crc32 == 0x12345678);
}

test "STEP2: deserializeHeader rejects short buffer" {
    const short = [_]u8{0} ** 10;
    try std.testing.expect(deserializeHeader(&short) == null);
}

// ============================================================
// STEP 2: Event serialization tests
// ============================================================

test "STEP2: serializeEvent produces 125 bytes (16 header + 109 payload)" {
    var event = canonical.create(.zig_core);
    event.event_type = .block;
    event.severity = 3;
    event.rule_id = 0x12345678;
    event.source_ip = 0xC0A80164;

    var buf: [256]u8 = undefined;
    const written = try serializeEvent(&buf, &event);

    try std.testing.expect(written == WIRE_HEADER_SIZE + canonical.WIRE_PAYLOAD_SIZE);
    try std.testing.expect(written == 125);

    // Verify wire magic at offset 0 (LE: 31 56 45 57)
    try std.testing.expect(buf[0] == 0x31);
    try std.testing.expect(buf[1] == 0x56);
    try std.testing.expect(buf[2] == 0x45);
    try std.testing.expect(buf[3] == 0x57);

    // Verify version at offset 4 (LE: 01 00)
    try std.testing.expect(buf[4] == 1);
    try std.testing.expect(buf[5] == 0);

    // Verify payload_type at offset 6 (canonical_event = 0)
    try std.testing.expect(buf[6] == 0);
    try std.testing.expect(buf[7] == 0);

    // Verify payload_length at offset 8 (LE: 6D = 109)
    try std.testing.expect(buf[8] == 109);
    try std.testing.expect(buf[9] == 0);

    // Verify canonical magic at offset 16 (payload start, LE: 31 47 45 41)
    try std.testing.expect(buf[16] == 0x31);
    try std.testing.expect(buf[17] == 0x47);
    try std.testing.expect(buf[18] == 0x45);
    try std.testing.expect(buf[19] == 0x41);
}

test "STEP2: serializeEvent/deserializeEvent round-trip" {
    var event = canonical.create(.zig_core);
    event.event_type = .block;
    event.severity = 3;
    event.rule_id = 0x12345678;
    event.source_ip = 0xC0A80164;
    event.source_port = 8080;
    event.session_id = 42;
    event.payload_length = 256;

    var buf: [256]u8 = undefined;
    const written = try serializeEvent(&buf, &event);

    const restored = deserializeEvent(buf[0..written]);
    try std.testing.expect(restored != null);
    try std.testing.expect(restored.?.event_type == .block);
    try std.testing.expect(restored.?.severity == 3);
    try std.testing.expect(restored.?.rule_id == 0x12345678);
    try std.testing.expect(restored.?.source_ip == 0xC0A80164);
    try std.testing.expect(restored.?.source_port == 8080);
    try std.testing.expect(restored.?.session_id == 42);
    try std.testing.expect(restored.?.payload_length == 256);
}

test "STEP2: deserializeEvent rejects wrong magic" {
    var event = canonical.create(.zig_core);
    var buf: [256]u8 = undefined;
    _ = try serializeEvent(&buf, &event);

    buf[0] = 0x00; // Corrupt magic
    try std.testing.expect(deserializeEvent(&buf) == null);
}

test "STEP2: deserializeEvent rejects wrong version" {
    var event = canonical.create(.zig_core);
    var buf: [256]u8 = undefined;
    _ = try serializeEvent(&buf, &event);

    buf[4] = 99; // Corrupt version
    try std.testing.expect(deserializeEvent(&buf) == null);
}

test "STEP2: deserializeEvent rejects wrong payload_type" {
    var event = canonical.create(.zig_core);
    var buf: [256]u8 = undefined;
    _ = try serializeEvent(&buf, &event);

    buf[6] = 1; // payload_type = command (not event)
    try std.testing.expect(deserializeEvent(&buf) == null);
}

test "STEP2: deserializeEvent rejects corrupted CRC" {
    var event = canonical.create(.zig_core);
    var buf: [256]u8 = undefined;
    _ = try serializeEvent(&buf, &event);

    // Corrupt a payload byte (within canonical event, after header)
    buf[WIRE_HEADER_SIZE + 4] ^= 0xFF;
    try std.testing.expect(deserializeEvent(&buf) == null);
}

test "STEP2: deserializeEvent rejects short buffer" {
    const short = [_]u8{0} ** 10;
    try std.testing.expect(deserializeEvent(&short) == null);
}

test "STEP2: deserializeEvent rejects wrong payload_length" {
    var event = canonical.create(.zig_core);
    var buf: [256]u8 = undefined;
    _ = try serializeEvent(&buf, &event);

    // Corrupt payload_length to wrong value (e.g., 200 instead of 109)
    std.mem.writeInt(u32, buf[8..12], 200, .little);
    try std.testing.expect(deserializeEvent(&buf) == null);
}

// ============================================================
// STEP 2: Command serialization tests
// ============================================================

test "STEP2: serializeCommand uses explicit header encoding" {
    var buf: [256]u8 = undefined;
    const cmd_data = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const written = try serializeCommand(&buf, 42, &cmd_data);
    try std.testing.expect(written == WIRE_HEADER_SIZE + 4 + 4);

    // Verify wire magic at offset 0 (LE: 31 56 45 57)
    try std.testing.expect(buf[0] == 0x31);
    try std.testing.expect(buf[1] == 0x56);
    try std.testing.expect(buf[2] == 0x45);
    try std.testing.expect(buf[3] == 0x57);

    // Verify version at offset 4
    try std.testing.expect(buf[4] == 1);

    // Verify payload_type at offset 6 (command = 1, LE: 01 00)
    try std.testing.expect(buf[6] == 1);
    try std.testing.expect(buf[7] == 0);

    // Verify payload_length at offset 8 (4 cmd_id + 4 data = 8, LE: 08 00 00 00)
    try std.testing.expect(buf[8] == 8);

    // Verify cmd_id at offset 16 (42 = 0x2A, LE: 2A 00 00 00)
    try std.testing.expect(buf[16] == 42);
    try std.testing.expect(buf[17] == 0);

    // Verify data at offset 20
    try std.testing.expect(buf[20] == 0xDE);
    try std.testing.expect(buf[21] == 0xAD);
    try std.testing.expect(buf[22] == 0xBE);
    try std.testing.expect(buf[23] == 0xEF);
}

// ============================================================
// STEP 2: Frame inspection tests
// ============================================================

test "STEP2: isValidFrame works with explicit encoding" {
    var event = canonical.create(.zig_core);
    var buf: [256]u8 = undefined;
    _ = try serializeEvent(&buf, &event);

    try std.testing.expect(isValidFrame(&buf));

    // Corrupt magic
    buf[0] = 0x00;
    try std.testing.expect(!isValidFrame(&buf));
}

test "STEP2: getFrameSize returns 125 for canonical event frame" {
    var event = canonical.create(.zig_core);
    var buf: [256]u8 = undefined;
    _ = try serializeEvent(&buf, &event);

    const frame_size = getFrameSize(&buf);
    try std.testing.expect(frame_size != null);
    try std.testing.expect(frame_size.? == WIRE_HEADER_SIZE + canonical.WIRE_PAYLOAD_SIZE);
    try std.testing.expect(frame_size.? == 125);
}

test "STEP2: isValidFrame rejects garbage" {
    const garbage = [_]u8{ 0x00, 0x01, 0x02, 0x03 } ++ [_]u8{0} ** 12;
    try std.testing.expect(!isValidFrame(&garbage));
}
