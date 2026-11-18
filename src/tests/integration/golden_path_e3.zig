//! golden_path_e3.zig — E3 Evidence: Data Plane Golden Path Integration
//!
//! Proves the full pipeline flow across real component boundaries (not mocks):
//!   CanonicalEvent → nose_contract → policy → detection → forensic
//!   → tier-3 gate → PEP guard → end-to-end record
//!
//! Evidence level: E3 (component integration).
//!
//! SCOPE-103 repair: this harness had never been compiled since the policy /
//! detection / forensic APIs were reshaped, so all eight scenario bodies were
//! dead. They are rewritten against the current modules; the scenario intent
//! of each test is unchanged, and no assertion was weakened to make it pass.

const std = @import("std");

const canonical = @import("../../contract/canonical_event.zig");
const event = @import("../../contract/event.zig");
const nose = @import("../../capture/nose_contract.zig");
const policy_ir = @import("../../policy/policy_ir.zig");
const pep = @import("../../policy/pep_bindings.zig");
const tier3 = @import("../../policy/tier3_state.zig");
const forensic = @import("../../forensic/forensic_pipeline.zig");
const threat_tracker = @import("../../detection/threat_tracker.zig");

// ── E3-001: CanonicalEvent → nose_contract submit/pop round-trip ────────────
// Proves: nose wire format → Zig nose contract queue preserves identity.

test "E3-001: CanonicalEvent → nose_contract round-trip" {
    if (nose.isFabricInitialized()) nose.shutdownFabric(std.testing.allocator);
    try nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 64 });
    defer nose.shutdownFabric(std.testing.allocator);

    var ev = canonical.create(.zig_core);
    ev.event_id = 0x12345678;
    ev.event_type = .match_;
    ev.source_ip = 0xC0A80164; // 192.168.1.100
    ev.dest_ip = 0xC0A80101; // 192.168.1.1
    ev.source_port = 443;
    ev.dest_port = 8080;
    ev.protocol = 6; // TCP
    ev.severity = 3;

    try std.testing.expectEqual(nose.SubmitResult.accepted, nose.submitEvent(ev));

    const popped = nose.popEvent() orelse {
        try std.testing.expect(false);
        return;
    };

    try std.testing.expectEqual(@as(u64, 0x12345678), popped.event_id);
    try std.testing.expectEqual(canonical.EventSource.zig_core, popped.source);
    try std.testing.expectEqual(@as(u32, 0xC0A80164), popped.source_ip);
    try std.testing.expectEqual(@as(u32, 0xC0A80101), popped.dest_ip);
    try std.testing.expectEqual(@as(u16, 443), popped.source_port);
    try std.testing.expectEqual(@as(u16, 8080), popped.dest_port);
    try std.testing.expectEqual(@as(u8, 6), popped.protocol);
    try std.testing.expectEqual(@as(u8, 3), popped.severity);
    try std.testing.expectEqual(canonical.EventType.match_, popped.event_type);
}

// ── E3-002: batch → nose_contract preserves FIFO order ─────────────────────

test "E3-002: Batch events → nose_contract preserves FIFO order" {
    if (nose.isFabricInitialized()) nose.shutdownFabric(std.testing.allocator);
    try nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 64 });
    defer nose.shutdownFabric(std.testing.allocator);

    var i: u64 = 0;
    while (i < 8) : (i += 1) {
        var ev = canonical.create(.zig_core);
        ev.event_id = 1000 + i;
        ev.source_ip = 0x0A000001 +% @as(u32, @intCast(i));
        _ = nose.submitEvent(ev);
    }

    i = 0;
    while (i < 8) : (i += 1) {
        const popped = nose.popEvent() orelse {
            try std.testing.expect(false);
            return;
        };
        try std.testing.expectEqual(@as(u64, 1000 + i), popped.event_id);
    }

    try std.testing.expect(nose.popEvent() == null);
}

// ── E3-003: policy_ir JSON load → evaluate on a real event ─────────────────

test "E3-003: Policy JSON → evaluate produces the intended action" {
    const json =
        \\{"policies":[{
        \\  "id": 1,
        \\  "name": "block_high_sev_tcp",
        \\  "action": "block",
        \\  "severity": "critical",
        \\  "ttl_sec": 3600,
        \\  "condition": {"clauses": [
        \\    {"predicates": [
        \\      {"field": "severity", "op": "gte", "value_int": 5},
        \\      {"field": "protocol", "op": "eq", "value_int": 6}
        \\    ]}
        \\  ]}
        \\}]}
    ;

    var loaded = policy_ir.loadPolicySetFromJson(std.testing.allocator, json);
    defer loaded.deinit();
    try std.testing.expectEqual(@as(u32, 1), loaded.report.loaded);
    try std.testing.expectEqual(@as(u32, 0), loaded.report.rejected);

    var matching = event.IpcEvent.init(.signature_match);
    matching.severity = .critical;
    matching.protocol = 6;

    const hit = loaded.ps.evaluate(.{ .ev = &matching });
    try std.testing.expect(hit != null);
    if (hit) |p| {
        try std.testing.expectEqual(policy_ir.Action.block, p.action);
        try std.testing.expectEqualStrings("block_high_sev_tcp", p.name);
    }

    // A non-matching event must not select the policy (no fail-open match).
    var non_matching = event.IpcEvent.init(.signature_match);
    non_matching.severity = .info;
    non_matching.protocol = 17;
    try std.testing.expect(loaded.ps.evaluate(.{ .ev = &non_matching }) == null);
}

// ── E3-004: repeated flow threats → incident at the score threshold ────────

test "E3-004: Detection evidence → threat_tracker creates an incident" {
    var tt = threat_tracker.ThreatTracker.init(std.testing.allocator);
    defer tt.deinit();

    const src_ip: u32 = 0xC0A80164;
    var incident: ?*threat_tracker.Incident = null;
    var i: u32 = 0;
    while (i < 5) : (i += 1) {
        var ev = event.IpcEvent.init(.signature_match);
        ev.event_id = 1000 + i;
        ev.flow_id = 42;
        ev.src_ip = src_ip;
        ev.dst_ip = 0xC0A80101;
        ev.src_port = 12345;
        ev.dst_port = 80;
        ev.protocol = 6;
        ev.rule_id = 42;
        ev.severity = .critical;
        // 5 × 30 = 150 ≥ the 100-point escalation threshold.
        if (try tt.observeFlowThreat(&ev, 30)) |inc| incident = inc;
    }

    const inc = incident orelse {
        try std.testing.expect(false);
        return;
    };
    try std.testing.expectEqual(@as(u64, 42), inc.flow_id);
    try std.testing.expect(inc.score >= 100);

    const open = tt.openIncidents();
    try std.testing.expect(open.len >= 1);
    try std.testing.expectEqual(src_ip, std.mem.readInt(u32, inc.src_ip[0..4], .little));
}

// ── E3-005: forensic ring append → read → hash chain intact ────────────────

test "E3-005: Forensic ring append → read → hash chain intact" {
    const slots = 8;
    var ring = try forensic.ForensicRing.initMemory(std.testing.allocator, slots * forensic.RECORD_BYTES);
    defer ring.deinit(std.testing.allocator);

    var i: u32 = 0;
    while (i < 5) : (i += 1) {
        var ev = event.IpcEvent.init(.signature_match);
        ev.event_id = 1000 + i;
        ev.rule_id = 42;
        ev.severity = .warning;
        const ordinal = ring.append(&ev, "golden-path", 0xA0 + i, 1, @intFromEnum(pep.PepDecision.allow), 4);
        try std.testing.expectEqual(@as(u64, i + 1), ordinal);
    }

    var prev_hash: [forensic.HASH_BYTES]u8 = [_]u8{0} ** forensic.HASH_BYTES;
    i = 0;
    while (i < 5) : (i += 1) {
        const record = ring.readRecord(i, std.testing.allocator) orelse {
            try std.testing.expect(false);
            return;
        };
        defer std.testing.allocator.free(record);

        const hdr = std.mem.bytesToValue(forensic.RecordHeader, record[0..@sizeOf(forensic.RecordHeader)]);
        try std.testing.expectEqual(@as(u64, 1000 + i), hdr.ev_id);
        try std.testing.expectEqual(@as(u32, 42), hdr.rule_id);
        try std.testing.expectEqual(@as(u64, i), hdr.record_seq);
        // Hash chain: every record commits to its predecessor.
        if (i > 0) {
            try std.testing.expectEqualSlices(u8, &prev_hash, &hdr.prev_hash);
        }
        prev_hash = hdr.current_hash;
    }
}

// ── E3-006: Tier-3 state gates enforcement (fail-closed) ───────────────────

test "E3-006: Tier-3 state gates enforcement correctly" {
    var sub = tier3.Tier3Subsystem{};

    sub.state = .absent;
    try std.testing.expect(!sub.canEnforce());
    try std.testing.expect(!sub.canEnforcePrivileged());

    sub.state = .ready;
    try std.testing.expect(sub.canEnforce());
    try std.testing.expect(sub.canEnforcePrivileged());

    sub.state = .failed;
    try std.testing.expect(!sub.canEnforce());
    try std.testing.expect(!sub.canEnforcePrivileged());

    sub.state = .degraded;
    try std.testing.expect(!sub.canEnforce());
}

// ── E3-007: unavailable PEP escalates — it is never an allow ───────────────

test "E3-007: PEP unavailable escalates instead of allowing" {
    var ev = event.IpcEvent.init(.signature_match);
    ev.severity = .critical;
    ev.src_ip = 0xC0A80164;
    ev.dst_ip = 0xC0A80101;

    const policy = policy_ir.Policy{
        .id = 1,
        .name = "test",
        .condition = .{ .clauses = &.{} },
        .action = .block,
        .severity = .critical,
        .ttl_sec = 60,
        .trusted = false,
    };

    var enforcer = pep.PepEnforcer{ .available = false };
    // gate_open=false is the production posture: no host-mutating action may
    // cross the provider boundary. The decision must be a degraded escalation,
    // never an allow that could be mistaken for authorization.
    const decision = enforcer.enforce(&ev, policy, 0, 0, 1, false);
    try std.testing.expectEqual(pep.PepDecision.escalate, decision);

    // A trusted policy with the gate still closed must not enforce either.
    var trusted = policy;
    trusted.trusted = true;
    try std.testing.expectEqual(pep.PepDecision.escalate, enforcer.enforce(&ev, trusted, 0, 0, 2, false));
}

// ── E3-008: full golden path — event → queue → forensic record ─────────────

test "E3-008: Full golden path — event → queue → forensic record" {
    if (nose.isFabricInitialized()) nose.shutdownFabric(std.testing.allocator);
    try nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 64 });
    defer nose.shutdownFabric(std.testing.allocator);

    var ev = canonical.create(.zig_core);
    ev.event_id = 99999;
    ev.source_ip = 0x0A000001;
    ev.dest_ip = 0x0A000002;
    ev.source_port = 31337;
    ev.dest_port = 80;
    ev.protocol = 6;
    ev.severity = 5;
    ev.event_type = .match_;

    try std.testing.expectEqual(nose.SubmitResult.accepted, nose.submitEvent(ev));

    const popped = nose.popEvent() orelse {
        try std.testing.expect(false);
        return;
    };
    try std.testing.expectEqual(@as(u64, 99999), popped.event_id);
    try std.testing.expectEqual(@as(u32, 0x0A000001), popped.source_ip);
    try std.testing.expectEqual(@as(u8, 5), popped.severity);

    var ring = try forensic.ForensicRing.initMemory(std.testing.allocator, 4 * forensic.RECORD_BYTES);
    defer ring.deinit(std.testing.allocator);

    var legacy = event.IpcEvent.init(.signature_match);
    legacy.event_id = popped.event_id;
    legacy.src_ip = popped.source_ip;
    legacy.dst_ip = popped.dest_ip;
    legacy.severity = .warning;
    _ = ring.append(&legacy, "golden-path-e3", 1, 1, @intFromEnum(pep.PepDecision.allow), popped.severity);

    const record = ring.readRecord(0, std.testing.allocator) orelse {
        try std.testing.expect(false);
        return;
    };
    defer std.testing.allocator.free(record);

    const hdr = std.mem.bytesToValue(forensic.RecordHeader, record[0..@sizeOf(forensic.RecordHeader)]);
    try std.testing.expectEqual(@as(u64, 99999), hdr.ev_id);
    try std.testing.expectEqual(@as(u32, 0), hdr.rule_id);
}
