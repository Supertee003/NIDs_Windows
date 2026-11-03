//! Recording-only advisory XDR evidence bridge.
//!
//! This module serializes a frozen multi-source XDR assessment to the
//! hash-chained forensic ring, issues a non-enforcement IDS Evidence Receipt
//! after hash read-back, and reproduces the assessment from the persisted
//! record. XDR-RECEIPT-002 wires it into the production detection pipeline
//! only through `pipeline/event_processor.recordXdrAdvisoryReceipt`; it does
//! not call policy, PEP, DEFCON, or any host-effect path.

const std = @import("std");
const event = @import("../contract/event.zig");
const forensic = @import("../forensic/forensic_pipeline.zig");
const ids_receipt = @import("../forensic/ids_evidence_receipt.zig");
const xdr = @import("xdr_incident_fabric.zig");

pub const XDR_DETECTOR_ID: u16 = 2;
pub const XDR_DETECTOR_VERSION: u16 = 1;
/// Built-in correlation rule: evidence from at least two source categories
/// was folded into one XDR incident. This is an evidence label, never an
/// enforcement instruction.
pub const MULTI_SOURCE_RULE_ID: u32 = 0x5844_5201;

const SNAPSHOT_MAGIC: u32 = 0x3152_4458; // "XDR1" in little endian
const SNAPSHOT_VERSION: u16 = 1;
const SNAPSHOT_HEADER_BYTES: usize = 35;
const SNAPSHOT_EVIDENCE_BYTES: usize = 18;
const MAX_SNAPSHOT_BYTES: usize = SNAPSHOT_HEADER_BYTES + xdr.MAX_KEY_LEN + xdr.MAX_EVIDENCE * SNAPSHOT_EVIDENCE_BYTES;

pub const RecordedAssessment = struct {
    incident_id: u64,
    source_event_id: u64,
    forensic_sequence: u64,
    correlation_event_id: u64,
    decision: xdr.Decision,
    receipt: ids_receipt.Receipt,
};

pub const ReplayOutcome = struct {
    incident_id: u64,
    source_event_id: u64,
    forensic_sequence: u64,
    decision: xdr.Decision,
};

const Snapshot = struct {
    incident_id: u64,
    source_event_id: u64,
    entity: [xdr.MAX_KEY_LEN]u8 = undefined,
    entity_len: usize,
    evidence: [xdr.MAX_EVIDENCE]xdr.Evidence = undefined,
    evidence_count: usize,
    decision: xdr.Decision,
};

/// Correlate a single-entity evidence batch, persist its advisory assessment,
/// and issue the IDS receipt only after reading the accepted record hash back.
pub fn recordAssessment(
    ring: *forensic.ForensicRing,
    source_event: *const event.IpcEvent,
    evidence: []const xdr.Evidence,
    assessed_at_ms: i64,
) !RecordedAssessment {
    if (source_event.event_id == 0 or source_event.timestamp_ns == 0) return error.InvalidSourceEvent;
    if (evidence.len == 0 or evidence.len > xdr.MAX_EVIDENCE) return error.InvalidEvidenceCount;

    var fabric = xdr.Fabric{};
    for (evidence) |observation| {
        if (observation.event_id == 0) return error.InvalidEvidenceEvent;
        if (observation.entity_len == 0 or observation.entity_len > xdr.MAX_KEY_LEN) return error.InvalidEntity;
        if (fabric.ingest(observation) == 0) return error.FabricCapacity;
    }
    if (fabric.incidentCount() != 1) return error.MultipleIncidentEntities;

    var source_event_found = false;
    for (evidence) |observation| {
        if (observation.event_id == source_event.event_id) source_event_found = true;
    }
    if (!source_event_found) return error.SourceEventNotInEvidence;

    const incident = &fabric.incidents[0];
    if (incident.evidence_count != evidence.len) return error.DuplicateEvidenceEvent;
    const decision = fabric.decide(0, assessed_at_ms) orelse return error.AssessmentUnavailable;
    if (decision.source_categories_used < 2) return error.NotMultiSource;

    var snapshot_buf: [MAX_SNAPSHOT_BYTES]u8 = undefined;
    const snapshot = try encodeSnapshot(evidence, incident.*, source_event.event_id, decision, &snapshot_buf);

    var correlation_event = event.IpcEvent.init(.correlation_match);
    correlation_event.timestamp_ns = source_event.timestamp_ns;
    correlation_event.event_id = event.nextEventId();
    while (correlation_event.event_id == source_event.event_id) {
        correlation_event.event_id = event.nextEventId();
    }
    correlation_event.trace_id = source_event.trace_id;
    correlation_event.flow_id = source_event.flow_id;
    correlation_event.incident_id = incident.incident_id;
    correlation_event.detection_id = source_event.event_id;
    correlation_event.source = .detection_corr;
    correlation_event.rule_id = MULTI_SOURCE_RULE_ID;
    correlation_event.severity = @enumFromInt(@min(decision.severity, @intFromEnum(event.EventSeverity.emergency)));
    correlation_event.setPayload(snapshot);

    const sequence = ring.append(
        &correlation_event,
        snapshot,
        source_event.trace_id,
        0,
        0,
        @intFromEnum(correlation_event.severity),
    );
    if (sequence == 0) return error.ForensicWriteRejected;
    const persisted_hash = ring.recordHash(sequence) orelse return error.ForensicReadbackFailed;
    const receipt = ids_receipt.issue(
        &correlation_event,
        sequence,
        persisted_hash,
        XDR_DETECTOR_ID,
        XDR_DETECTOR_VERSION,
        decision.confidence,
    ) orelse return error.ReceiptIssueFailed;

    return .{
        .incident_id = incident.incident_id,
        .source_event_id = source_event.event_id,
        .forensic_sequence = sequence,
        .correlation_event_id = correlation_event.event_id,
        .decision = decision,
        .receipt = receipt,
    };
}

/// Rebuild the selected XDR fabric from the serialized source observations in
/// the forensic record addressed by an IDS receipt. All receipt, CRC, chain
/// hash, and payload links are checked before replay.
pub fn replayFromReceipt(
    allocator: std.mem.Allocator,
    ring: *forensic.ForensicRing,
    receipt: ids_receipt.Receipt,
) !ReplayOutcome {
    if (!receipt.isNonEnforcement()) return error.InvalidReceipt;
    if (receipt.detector_id != XDR_DETECTOR_ID or receipt.detector_version != XDR_DETECTOR_VERSION) return error.WrongDetector;
    if (receipt.forensic_sequence == 0) return error.InvalidSequence;

    const slot = ring.readRecord(receipt.forensic_sequence - 1, allocator) orelse return error.ForensicRecordUnavailable;
    defer allocator.free(slot);
    if (!forensic.ForensicRing.verifyRecord(slot)) return error.ForensicCrcMismatch;
    if (!forensic.ForensicRing.verifyRecordHash(slot)) return error.ForensicHashMismatch;

    const header = std.mem.bytesAsValue(forensic.RecordHeader, slot[0..forensic.HEADER_BYTES]);
    if (header.record_seq != receipt.forensic_sequence - 1 or header.ev_id != receipt.event_id or
        header.kind != @intFromEnum(event.EventKind.correlation_match) or header.rule_id != MULTI_SOURCE_RULE_ID or
        header.policy_id != 0 or header.pep_decision != 0 or receipt.source != .zig_core)
    {
        return error.ReceiptRecordMismatch;
    }
    const hash = ring.recordHash(receipt.forensic_sequence) orelse return error.ForensicRecordUnavailable;
    if (!std.mem.eql(u8, &hash, &receipt.forensic_hash)) return error.ReceiptHashMismatch;

    const view = forensic.decodeRecordPayload(slot) orelse return error.InvalidForensicPayload;
    if (event.fnv1a32(view.payload) != receipt.payload_hash) return error.PayloadHashMismatch;
    const snapshot = try decodeSnapshot(view.payload);
    if (snapshot.incident_id != receipt.incident_id) return error.ReceiptIncidentMismatch;

    var fabric = xdr.Fabric{};
    for (snapshot.evidence[0..snapshot.evidence_count]) |observation| {
        if (fabric.ingest(observation) == 0) return error.FabricCapacity;
    }
    if (fabric.incidentCount() != 1) return error.MultipleIncidentEntities;
    if (fabric.incidents[0].evidence_count != snapshot.evidence_count) return error.DuplicateEvidenceEvent;
    var source_event_found = false;
    for (snapshot.evidence[0..snapshot.evidence_count]) |observation| {
        if (observation.event_id == snapshot.source_event_id) source_event_found = true;
    }
    if (!source_event_found) return error.SourceEventNotInEvidence;

    const replayed = fabric.decide(0, snapshot.decision.made_ms) orelse return error.AssessmentUnavailable;
    if (replayed.source_categories_used < 2 or fabric.incidents[0].incident_id != snapshot.incident_id or !sameDecision(replayed, snapshot.decision)) {
        return error.ReplayMismatch;
    }
    return .{
        .incident_id = snapshot.incident_id,
        .source_event_id = snapshot.source_event_id,
        .forensic_sequence = receipt.forensic_sequence,
        .decision = replayed,
    };
}

fn encodeSnapshot(
    evidence: []const xdr.Evidence,
    incident: xdr.Incident,
    source_event_id: u64,
    decision: xdr.Decision,
    output: []u8,
) ![]const u8 {
    const entity = incident.entitySlice();
    if (entity.len == 0 or entity.len > xdr.MAX_KEY_LEN or evidence.len > xdr.MAX_EVIDENCE) return error.InvalidSnapshot;
    const needed = SNAPSHOT_HEADER_BYTES + entity.len + evidence.len * SNAPSHOT_EVIDENCE_BYTES;
    if (needed > output.len) return error.SnapshotTooLarge;

    var offset: usize = 0;
    std.mem.writeInt(u32, output[offset..][0..4], SNAPSHOT_MAGIC, .little);
    offset += 4;
    std.mem.writeInt(u16, output[offset..][0..2], SNAPSHOT_VERSION, .little);
    offset += 2;
    output[offset] = @intCast(entity.len);
    offset += 1;
    output[offset] = @intCast(evidence.len);
    offset += 1;
    std.mem.writeInt(u64, output[offset..][0..8], incident.incident_id, .little);
    offset += 8;
    std.mem.writeInt(u64, output[offset..][0..8], source_event_id, .little);
    offset += 8;
    std.mem.writeInt(i64, output[offset..][0..8], decision.made_ms, .little);
    offset += 8;
    output[offset] = decision.severity;
    output[offset + 1] = decision.confidence;
    output[offset + 2] = decision.source_categories_used;
    offset += 3;
    @memcpy(output[offset..][0..entity.len], entity);
    offset += entity.len;

    for (evidence) |observation| {
        if (observation.entity_len != entity.len or !std.mem.eql(u8, observation.entitySlice(), entity)) return error.MultipleIncidentEntities;
        output[offset] = @intFromEnum(observation.source);
        offset += 1;
        std.mem.writeInt(u64, output[offset..][0..8], observation.event_id, .little);
        offset += 8;
        std.mem.writeInt(i64, output[offset..][0..8], observation.ts_ms, .little);
        offset += 8;
        output[offset] = observation.severity;
        offset += 1;
    }
    return output[0..offset];
}

fn decodeSnapshot(bytes: []const u8) !Snapshot {
    if (bytes.len < SNAPSHOT_HEADER_BYTES) return error.InvalidSnapshot;
    var offset: usize = 0;
    if (try readInt(u32, bytes, &offset) != SNAPSHOT_MAGIC) return error.InvalidSnapshot;
    if (try readInt(u16, bytes, &offset) != SNAPSHOT_VERSION) return error.UnsupportedSnapshotVersion;
    const entity_len: usize = try readByte(bytes, &offset);
    const evidence_count: usize = try readByte(bytes, &offset);
    if (entity_len == 0 or entity_len > xdr.MAX_KEY_LEN or evidence_count == 0 or evidence_count > xdr.MAX_EVIDENCE) return error.InvalidSnapshot;
    const incident_id = try readInt(u64, bytes, &offset);
    const source_event_id = try readInt(u64, bytes, &offset);
    const made_ms = try readInt(i64, bytes, &offset);
    const severity = try readByte(bytes, &offset);
    const confidence = try readByte(bytes, &offset);
    const source_count = try readByte(bytes, &offset);
    if (offset + entity_len > bytes.len) return error.InvalidSnapshot;

    var snapshot = Snapshot{
        .incident_id = incident_id,
        .source_event_id = source_event_id,
        .entity_len = entity_len,
        .evidence_count = evidence_count,
        .decision = .{
            .made_ms = made_ms,
            .severity = severity,
            .confidence = confidence,
            .source_categories_used = source_count,
        },
    };
    @memcpy(snapshot.entity[0..entity_len], bytes[offset..][0..entity_len]);
    offset += entity_len;

    for (snapshot.evidence[0..evidence_count]) |*observation| {
        const category = std.meta.intToEnum(xdr.SourceCategory, try readByte(bytes, &offset)) catch return error.InvalidSnapshot;
        observation.* = .{ .source = category };
        observation.event_id = try readInt(u64, bytes, &offset);
        observation.ts_ms = try readInt(i64, bytes, &offset);
        observation.severity = try readByte(bytes, &offset);
        @memcpy(observation.entity[0..entity_len], snapshot.entity[0..entity_len]);
        observation.entity_len = entity_len;
    }
    if (offset != bytes.len) return error.InvalidSnapshot;
    return snapshot;
}

fn readByte(bytes: []const u8, offset: *usize) !u8 {
    if (offset.* >= bytes.len) return error.InvalidSnapshot;
    const value = bytes[offset.*];
    offset.* += 1;
    return value;
}

fn readInt(comptime Int: type, bytes: []const u8, offset: *usize) !Int {
    const width = @sizeOf(Int);
    if (offset.* + width > bytes.len) return error.InvalidSnapshot;
    const value = std.mem.readInt(Int, bytes[offset.*..][0..width], .little);
    offset.* += width;
    return value;
}

fn sameDecision(a: xdr.Decision, b: xdr.Decision) bool {
    return a.made_ms == b.made_ms and a.severity == b.severity and
        a.confidence == b.confidence and a.source_categories_used == b.source_categories_used;
}

test "XDR assessment persists, issues an IDS receipt, and replays from the record" {
    var ring = try forensic.ForensicRing.initMemory(std.testing.allocator, 16 * 1024);
    defer ring.deinit(std.testing.allocator);

    var source_event = event.IpcEvent.init(.signature_match);
    source_event.timestamp_ns = 1_700_000_000_000_000_000;
    source_event.event_id = 41;
    source_event.flow_id = 7;
    source_event.trace_id = 9;
    source_event.rule_id = 9001;
    source_event.source = .capture_npcap;
    source_event.setPayload("GET /suspicious");

    var network = xdr.Evidence{ .source = .network, .event_id = source_event.event_id, .ts_ms = 1700000000000, .severity = 4 };
    @memcpy(network.entity[0..11], "203.0.113.7");
    network.entity_len = 11;
    var host = xdr.Evidence{ .source = .host, .event_id = 42, .ts_ms = 1700000000100, .severity = 3 };
    @memcpy(host.entity[0..11], "203.0.113.7");
    host.entity_len = 11;
    const evidence = [_]xdr.Evidence{ network, host };

    const recorded = try recordAssessment(&ring, &source_event, &evidence, 1700000000200);
    try std.testing.expect(recorded.receipt.isNonEnforcement());
    try std.testing.expectEqual(recorded.forensic_sequence, recorded.receipt.forensic_sequence);
    try std.testing.expectEqual(recorded.correlation_event_id, recorded.receipt.event_id);
    try std.testing.expectEqual(recorded.incident_id, recorded.receipt.incident_id);
    try std.testing.expectEqual(MULTI_SOURCE_RULE_ID, recorded.receipt.rule_id);
    try std.testing.expectEqual(@as(u8, 2), recorded.decision.source_categories_used);

    var tampered_receipt = recorded.receipt;
    tampered_receipt.forensic_hash[0] ^= 1;
    try std.testing.expectError(error.ReceiptHashMismatch, replayFromReceipt(std.testing.allocator, &ring, tampered_receipt));

    const replayed = try replayFromReceipt(std.testing.allocator, &ring, recorded.receipt);
    try std.testing.expectEqual(recorded.incident_id, replayed.incident_id);
    try std.testing.expectEqual(recorded.source_event_id, replayed.source_event_id);
    try std.testing.expect(sameDecision(recorded.decision, replayed.decision));

    var verifier = @import("../forensic/replay_verifier.zig").ReplayVerifier.init(std.testing.allocator, &ring, 77);
    defer verifier.deinit();
    try std.testing.expect(try verifier.runVerification());
    try verifier.recordReplayResult(
        recorded.source_event_id,
        recorded.decision.severity,
        replayed.decision.severity,
        MULTI_SOURCE_RULE_ID,
        0,
    );
    verifier.computeReplayHash();
    verifier.finalize();
    try std.testing.expect(verifier.decision.pass);
    try std.testing.expectEqual(@as(u64, 1), verifier.decision.events_matched);
}

test "XDR runtime freeze batch records and replays through the evidence flow" {
    const xdr_runtime = @import("xdr_runtime.zig");
    xdr_runtime.startLive();

    var net = event.IpcEvent.init(.signature_match);
    net.event_id = 501;
    net.timestamp_ns = 1_700_000_100_000_000_000;
    net.source = .capture_npcap;
    net.rule_id = 9001;
    var host = event.IpcEvent.init(.signature_match);
    host.event_id = 502;
    host.timestamp_ns = net.timestamp_ns + 100 * std.time.ns_per_ms;
    host.source = .capture_etw;
    host.rule_id = 9002;

    var out = xdr_runtime.ObserveOutcome{};
    _ = xdr_runtime.observeEvent(&out, .network, "203.0.113.88", 4, &net);
    _ = xdr_runtime.observeEvent(&out, .host, "203.0.113.88", 3, &host);
    try std.testing.expect(out.frozen);
    try std.testing.expectEqual(@as(usize, 2), out.row_count);

    var ring = try forensic.ForensicRing.initMemory(std.testing.allocator, 16 * 1024);
    defer ring.deinit(std.testing.allocator);
    const assessed_at_ms = std.math.cast(i64, host.timestamp_ns / std.time.ns_per_ms).?;
    const recorded = try recordAssessment(&ring, &host, out.rows[0..out.row_count], assessed_at_ms);
    try std.testing.expect(recorded.receipt.isNonEnforcement());
    try std.testing.expectEqual(@as(u8, 2), recorded.decision.source_categories_used);

    const replayed = try replayFromReceipt(std.testing.allocator, &ring, recorded.receipt);
    try std.testing.expectEqual(recorded.incident_id, replayed.incident_id);
    try std.testing.expectEqual(recorded.source_event_id, replayed.source_event_id);
    try std.testing.expect(sameDecision(recorded.decision, replayed.decision));
}

test "XDR evidence flow rejects unrelated entities and source events" {
    var ring = try forensic.ForensicRing.initMemory(std.testing.allocator, 16 * 1024);
    defer ring.deinit(std.testing.allocator);
    var source_event = event.IpcEvent.init(.signature_match);
    source_event.timestamp_ns = 1000;
    source_event.event_id = 10;

    var a = xdr.Evidence{ .source = .network, .event_id = 10, .ts_ms = 1, .severity = 2 };
    @memcpy(a.entity[0..5], "hostA");
    a.entity_len = 5;
    var b = xdr.Evidence{ .source = .host, .event_id = 11, .ts_ms = 2, .severity = 3 };
    @memcpy(b.entity[0..5], "hostB");
    b.entity_len = 5;
    const evidence = [_]xdr.Evidence{ a, b };
    try std.testing.expectError(error.MultipleIncidentEntities, recordAssessment(&ring, &source_event, &evidence, 3));

    a.event_id = 11;
    b = a;
    b.event_id = 12;
    const missing_source = [_]xdr.Evidence{ a, b };
    try std.testing.expectError(error.SourceEventNotInEvidence, recordAssessment(&ring, &source_event, &missing_source, 3));

    a.event_id = source_event.event_id;
    const one_source = [_]xdr.Evidence{a};
    try std.testing.expectError(error.NotMultiSource, recordAssessment(&ring, &source_event, &one_source, 3));

    a.event_id = 0;
    const zero_id = [_]xdr.Evidence{a};
    try std.testing.expectError(error.InvalidEvidenceEvent, recordAssessment(&ring, &source_event, &zero_id, 3));
}
