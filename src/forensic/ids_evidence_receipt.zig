//! IDS Evidence Receipt — non-enforcement proof that a detection was recorded.
//!
//! This is deliberately separate from policy/enforcement_receipt.zig. An IDS
//! receipt proves that the Zig forensic writer accepted a detection record and
//! identifies the exact event, detector, rule, and hash-chain position. It
//! never proves a host effect and contains no provider/filter/action fields.

const std = @import("std");
const event = @import("../contract/event.zig");
const canonical = @import("../contract/canonical_event.zig");

pub const VERSION: u16 = 1;
pub const HASH_BYTES: usize = 32;
pub const RUNTIME_DETECTOR_ID: u16 = 1;
pub const RUNTIME_DETECTOR_VERSION: u16 = 1;

pub const Receipt = struct {
    pub const version: u16 = VERSION;

    event_id: u64,
    flow_id: u64,
    incident_id: u64,
    source: canonical.EventSource,
    detector_id: u16,
    detector_version: u16,
    rule_id: u32,
    severity: event.EventSeverity,
    confidence: u8,
    payload_hash: u32,
    forensic_sequence: u64,
    forensic_hash: [HASH_BYTES]u8,
    timestamp_ns: u64,

    /// A valid IDS receipt proves recording only. It cannot represent an
    /// action, provider, filter, or host-effect state by construction.
    pub fn validate(self: *const Receipt) bool {
        if (self.event_id == 0 or self.detector_id == 0 or self.detector_version == 0 or
            self.rule_id == 0 or self.forensic_sequence == 0 or self.timestamp_ns == 0)
        {
            return false;
        }
        var nonzero = false;
        for (self.forensic_hash) |byte| nonzero = nonzero or byte != 0;
        return nonzero;
    }

    pub fn isNonEnforcement(self: *const Receipt) bool {
        return self.validate();
    }

    pub fn sourceName(self: *const Receipt) []const u8 {
        return @tagName(self.source);
    }
};

/// Issue an IDS receipt after the forensic writer has accepted a record.
/// `forensic_hash` must be the hash read back from that exact record slot.
pub fn issue(
    ev: *const event.IpcEvent,
    forensic_sequence: u64,
    forensic_hash: [HASH_BYTES]u8,
    detector_id: u16,
    detector_version: u16,
    confidence: u8,
) ?Receipt {
    if (ev.event_id == 0 or ev.rule_id == 0 or forensic_sequence == 0) return null;
    const receipt = Receipt{
        .event_id = ev.event_id,
        .flow_id = ev.flow_id,
        .incident_id = ev.incident_id,
        .source = sourceOf(ev.source),
        .detector_id = detector_id,
        .detector_version = detector_version,
        .rule_id = ev.rule_id,
        .severity = ev.severity,
        .confidence = confidence,
        .payload_hash = ev.payload_hash,
        .forensic_sequence = forensic_sequence,
        .forensic_hash = forensic_hash,
        .timestamp_ns = ev.timestamp_ns,
    };
    return if (receipt.validate()) receipt else null;
}

fn sourceOf(source: event.EventSource) canonical.EventSource {
    return switch (source) {
        .capture_npcap => .npcap_sensor,
        .capture_etw => .host_telemetry,
        .capture_fim => .file_sensor,
        .capture_registry => .registry_sensor,
        .capture_pipe_monitor => .pipe_monitor,
        .capture_wfp => .wfp_sensor,
        .detection_brain => .python_brain,
        .federation => .cluster_federation,
        .detection_sig, .detection_anom, .detection_corr, .policy, .system => .zig_core,
        _ => .external,
    };
}

test "IDS receipt validates exact recording identity without enforcement fields" {
    var ev = event.IpcEvent.init(.signature_match);
    ev.event_id = 42;
    ev.timestamp_ns = 1000;
    ev.source = .capture_npcap;
    ev.rule_id = 9001;
    ev.payload_hash = 0x12345678;
    const hash = [_]u8{0xA5} ** HASH_BYTES;
    const r = issue(&ev, 7, hash, RUNTIME_DETECTOR_ID, RUNTIME_DETECTOR_VERSION, 80).?;
    try std.testing.expect(r.validate());
    try std.testing.expect(r.isNonEnforcement());
    try std.testing.expectEqual(canonical.EventSource.npcap_sensor, r.source);
    try std.testing.expectEqual(@as(u64, 42), r.event_id);
    try std.testing.expectEqual(@as(u64, 7), r.forensic_sequence);
    try std.testing.expectEqual(@as(u32, 0x12345678), r.payload_hash);
}

test "IDS receipt rejects missing detection or forensic identity" {
    var ev = event.IpcEvent.init(.signature_match);
    ev.timestamp_ns = 1000;
    ev.rule_id = 9001;
    const hash = [_]u8{0xA5} ** HASH_BYTES;
    try std.testing.expect(issue(&ev, 1, hash, RUNTIME_DETECTOR_ID, RUNTIME_DETECTOR_VERSION, 80) == null);
    ev.event_id = 1;
    try std.testing.expect(issue(&ev, 0, hash, RUNTIME_DETECTOR_ID, RUNTIME_DETECTOR_VERSION, 80) == null);
    try std.testing.expect(issue(&ev, 1, [_]u8{0} ** HASH_BYTES, RUNTIME_DETECTOR_ID, RUNTIME_DETECTOR_VERSION, 80) == null);
}
