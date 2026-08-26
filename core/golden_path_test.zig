//! golden_path_test.zig - E2E Integration Test (Phase 30)
//!
//! Tests the complete Golden Path: Sensor → Nose Contract → Priority Queue
//! → Detection Manager → Policy Engine → PEP → Forensic Log
//!
//! Run with: zig test core/golden_path_test.zig

const std = @import("std");
const canonical = @import("canonical_event.zig");
const nose = @import("nose_contract.zig");
const detection = @import("detection_interface.zig");
const policy = @import("policy_contract.zig");

// ============================================================
// E2E Test Helpers
// ============================================================

fn e2eDummyScan(payload: []const u8, ctx: *const canonical.CanonicalEvent) detection.DetectionResult {
    _ = ctx;
    // Simulate: block if payload contains "malware"
    if (std.mem.indexOf(u8, payload, "malware") != null) {
        return .{
            .verdict = .match_block,
            .rule_id = 100,
            .rule_hash = 0xABCDEF,
            .severity = 3,
            .rule_name = "E2E_TEST_MALWARE",
            .ruleset_version = 1,
        };
    }
    // Simulate: alert if payload contains "suspicious"
    if (std.mem.indexOf(u8, payload, "suspicious") != null) {
        return .{
            .verdict = .match_alert,
            .rule_id = 200,
            .rule_hash = 0x123456,
            .severity = 2,
            .rule_name = "E2E_TEST_SUSPICIOUS",
            .ruleset_version = 1,
        };
    }
    return detection.DetectionResult.noMatch();
}

// ============================================================
// E2E Tests
// ============================================================

test "E2E: Complete Golden Path - Block event" {
    // 1. Initialize Event Fabric (Sensor → Queue)
    try nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 });
    defer nose.shutdownFabric(std.testing.allocator);

    // 2. Initialize Detection Manager with test detector
    var dm = detection.DetectionManager.init();
    _ = dm.register(.{
        .name = "E2E Detector",
        .detector_type = .tier1_aho_corasick,
        .is_active = true,
        .scan_fn = &e2eDummyScan,
    });

    // 3. Initialize Policy Engine
    var pe = policy.PolicyEngine.init();
    _ = pe.registerRule(.{
        .min_severity = 2,
        .required_verdict = .match_block,
        .action = .block,
        .description = "E2E Block Rule",
    });

    // 4. Initialize PEP
    var pep = policy.PEP.init();

    // === SIMULATE SENSOR ===
    var sensor_event = nose.createEvent(.wfp_sensor);
    sensor_event.event_type = .forward;
    sensor_event.source_ip = 0xC0A80164; // 192.168.1.100
    sensor_event.source_port = 12345;
    sensor_event.payload_length = 20;
    const submit_result = nose.submitEvent(sensor_event);
    try std.testing.expect(submit_result == .accepted);

    // Verify event is in queue
    try std.testing.expect(nose.hasEvents());
    try std.testing.expect(nose.pendingCount() == 1);

    // === SIMULATE DETECTION LAYER ===
    // Pop event from queue (what eventFabricDrain does)
    const queued_event = nose.popEvent();
    try std.testing.expect(queued_event != null);
    try std.testing.expect(queued_event.?.source_ip == 0xC0A80164);

    // Run detection on "malware" payload
    const ctx = canonical.create(.wfp_sensor);
    const det_result = dm.detect("malware payload test", &ctx);
    try std.testing.expect(det_result.verdict == .match_block);
    try std.testing.expect(det_result.rule_id == 100);
    try std.testing.expect(det_result.severity == 3);

    // === SIMULATE POLICY ENGINE ===
    const pol_ctx = policy.PolicyContext{
        .defcon_level = 5,
        .is_repeated_offender = false,
        .threat_intel_match = false,
        .correlation_count = 0,
        .custom_flags = 0,
    };
    const decision = pe.evaluate(det_result, pol_ctx);
    try std.testing.expect(decision == .block);

    // === SIMULATE PEP ===
    var enforce_event = canonical.create(.wfp_sensor);
    enforce_event.source_ip = 0xC0A80164;
    enforce_event.event_type = .block;
    const enf_result = pep.enforce(decision, &enforce_event);
    try std.testing.expect(enf_result == .success);
    try std.testing.expect(enforce_event.policy_action == .block);
    try std.testing.expect(enforce_event.enforcement_status == 1);
}

test "E2E: Golden Path - Alert event (no block)" {
    try nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 });
    defer nose.shutdownFabric(std.testing.allocator);

    var dm = detection.DetectionManager.init();
    _ = dm.register(.{ .name = "E2E", .detector_type = .tier1_aho_corasick, .is_active = true, .scan_fn = &e2eDummyScan });

    var pe = policy.PolicyEngine.init();
    var pep = policy.PEP.init();

    // Sensor submits suspicious event
    var sensor_event = nose.createEvent(.pipe_sensor);
    sensor_event.event_type = .forward;
    const submit_result = nose.submitEvent(sensor_event);
    try std.testing.expect(submit_result == .accepted);

    // Detection finds "suspicious" (alert, not block)
    const ctx = canonical.create(.pipe_sensor);
    const det_result = dm.detect("suspicious payload", &ctx);
    try std.testing.expect(det_result.verdict == .match_alert);
    try std.testing.expect(det_result.rule_id == 200);

    // Policy: no block rule for alerts in this engine, default is allow
    const pol_ctx = policy.PolicyContext{ .defcon_level = 5, .is_repeated_offender = false, .threat_intel_match = false, .correlation_count = 0, .custom_flags = 0 };
    const decision = pe.evaluate(det_result, pol_ctx);
    try std.testing.expect(decision == .allow);

    // PEP: allow is skipped (no enforcement needed)
    var enforce_event = canonical.create(.pipe_sensor);
    const enf_result = pep.enforce(decision, &enforce_event);
    try std.testing.expect(enf_result == .skipped);
}

test "E2E: Golden Path - No match (forward)" {
    try nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 });
    defer nose.shutdownFabric(std.testing.allocator);

    var dm = detection.DetectionManager.init();
    _ = dm.register(.{ .name = "E2E", .detector_type = .tier1_aho_corasick, .is_active = true, .scan_fn = &e2eDummyScan });

    var pe = policy.PolicyEngine.init();
    var pep = policy.PEP.init();

    var sensor_event = nose.createEvent(.wfp_sensor);
    sensor_event.event_type = .forward;
    _ = nose.submitEvent(sensor_event);

    // Detection: clean payload
    const ctx = canonical.create(.wfp_sensor);
    const det_result = dm.detect("clean traffic data", &ctx);
    try std.testing.expect(det_result.verdict == .no_match);

    // Policy: default allow
    const pol_ctx = policy.PolicyContext{ .defcon_level = 5, .is_repeated_offender = false, .threat_intel_match = false, .correlation_count = 0, .custom_flags = 0 };
    const decision = pe.evaluate(det_result, pol_ctx);
    try std.testing.expect(decision == .allow);

    // PEP: skipped
    var enforce_event = canonical.create(.wfp_sensor);
    const enf_result = pep.enforce(decision, &enforce_event);
    try std.testing.expect(enf_result == .skipped);
}

test "E2E: DEFCON 1 escalates alert to block" {
    var dm = detection.DetectionManager.init();
    _ = dm.register(.{ .name = "E2E", .detector_type = .tier1_aho_corasick, .is_active = true, .scan_fn = &e2eDummyScan });

    var pe = policy.PolicyEngine.init();
    var pep = policy.PEP.init();

    // Detection finds "suspicious" (normally just an alert)
    const ctx = canonical.create(.wfp_sensor);
    const det_result = dm.detect("suspicious payload", &ctx);
    try std.testing.expect(det_result.verdict == .match_alert);

    // BUT DEFCON is 1 (critical) — policy should escalate to BLOCK
    const pol_ctx = policy.PolicyContext{ .defcon_level = 1, .is_repeated_offender = true, .threat_intel_match = true, .correlation_count = 5, .custom_flags = 0 };
    const decision = pe.evaluate(det_result, pol_ctx);
    try std.testing.expect(decision == .block);

    // PEP enforces block
    var enforce_event = canonical.create(.wfp_sensor);
    const enf_result = pep.enforce(decision, &enforce_event);
    try std.testing.expect(enf_result == .success);
    try std.testing.expect(enforce_event.policy_action == .block);
}

test "E2E: Priority ordering - high before low" {
    try nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 });
    defer nose.shutdownFabric(std.testing.allocator);

    // Submit low-priority event first
    var low_event = nose.createEvent(.wfp_sensor);
    low_event.event_type = .forward;
    _ = nose.submitEvent(low_event);

    // Submit high-priority event second
    var high_event = nose.createEvent(.wfp_sensor);
    high_event.event_type = .block;
    high_event.source_ip = 0x0A000001;
    _ = nose.submitEvent(high_event);

    // Pop should return high-priority first
    const first = nose.popEvent();
    try std.testing.expect(first != null);
    try std.testing.expect(first.?.event_type == .block);

    // Then low-priority
    const second = nose.popEvent();
    try std.testing.expect(second != null);
    try std.testing.expect(second.?.event_type == .forward);
}

test "E2E: Wire format round-trip through Event Fabric" {
    const wire = @import("wire_event.zig");

    try nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 });
    defer nose.shutdownFabric(std.testing.allocator);

    // Create event
    var event = canonical.create(.minifilter);
    event.event_type = .block;
    event.source_ip = 0xC0A80164;
    event.severity = 3;
    event.rule_id = 42;

    // Serialize to wire format
    var buf: [256]u8 = undefined;
    const written = try wire.serializeEvent(&buf, &event);
    try std.testing.expect(written > 0);

    // Submit through wire format
    const submit_result = nose.submitWireEvent(&buf);
    try std.testing.expect(submit_result == .accepted);

    // Verify event is in queue with correct fields
    try std.testing.expect(nose.pendingCount() == 1);
    const popped = nose.popEvent();
    try std.testing.expect(popped != null);
    try std.testing.expect(popped.?.source_ip == 0xC0A80164);
    try std.testing.expect(popped.?.rule_id == 42);
}
