//! Phase 5 detection contract: deterministic, explainable detector output.
const std = @import("std");

pub const DetectorKind = enum(u8) {
    signature = 1,
    anomaly = 2,
    correlation = 3,
    threat_tracker = 4,
};

pub const DetectionResult = struct {
    event_id: u64,
    detector: DetectorKind,
    detector_version: u16 = 1,
    matched: bool = false,
    rule_id: u32 = 0,
    incident_id: u64 = 0,
    severity: u8 = 0,
    reason: []const u8 = "",

    pub fn isExplainable(self: DetectionResult) bool {
        return self.event_id != 0 and self.reason.len > 0;
    }
};

test "detection result requires identity and reason" {
    const result = DetectionResult{ .event_id = 7, .detector = .signature, .matched = true, .rule_id = 12, .reason = "signature_match" };
    try std.testing.expect(result.isExplainable());
    try std.testing.expect(!(DetectionResult{ .event_id = 7, .detector = .signature }).isExplainable());
}
