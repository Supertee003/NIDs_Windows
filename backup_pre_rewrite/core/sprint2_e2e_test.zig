//! sprint2_e2e_test.zig - Sprint 2 E2E Integration Tests (Phase 39)
//!
//! Tests the complete Sprint 2 pipeline:
//! HIDS → Event Fabric → XDR Correlation → RAG Enrichment → Flow Engine → Policy IR → Policy Engine → PEP
//!
//! Run with: zig test core/sprint2_e2e_test.zig

const std = @import("std");
const canonical = @import("canonical_event.zig");
const nose = @import("nose_contract.zig");
const detection = @import("detection_interface.zig");
const policy = @import("policy_contract.zig");
const flow = @import("flow_engine.zig");
const xdr = @import("xdr_correlator.zig");
const rag = @import("rag_intelligence.zig");
const policy_ir = @import("policy_ir.zig");

// ============================================================
// E2E: HIDS + Event Fabric + XDR Correlation
// ============================================================

test "S2-E2E: HIDS event → Fabric → XDR correlation" {
    // Init Event Fabric
    try nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 32 });
    defer nose.shutdownFabric(std.testing.allocator);

    // Init XDR Correlator
    var corr = xdr.XDRCorrelator.init();

    // Simulate HIDS process event (suspicious process detected)
    var proc_event = nose.createEvent(.minifilter);
    proc_event.event_type = .session_start;
    proc_event.session_id = 5001;
    proc_event.payload_length = 100;
    proc_event.severity = 2;
    proc_event.context_flags = 0x01; // suspicious_name_match

    // Submit to Fabric
    try std.testing.expect(nose.submitEvent(proc_event) == .accepted);

    // Also submit to XDR Correlator
    const idx = corr.submitEvent(proc_event);
    try std.testing.expect(idx != null);

    // Verify XDR incident created
    const inc = corr.getIncident(idx.?);
    try std.testing.expect(inc != null);
    try std.testing.expect(inc.?.event_count == 1);
    try std.testing.expect(inc.?.severity == 2);
}

test "S2-E2E: Network + Host events correlated by session_id" {
    try nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 32 });
    defer nose.shutdownFabric(std.testing.allocator);

    var corr = xdr.XDRCorrelator.init();

    // Network event (WFP sensor)
    var net_event = canonical.create(.wfp_sensor);
    net_event.session_id = 7000;
    net_event.source_ip = 0xC0A80164;
    net_event.event_type = .forward;
    net_event.severity = 0;

    // Host event (same session — suspicious process)
    var host_event = canonical.create(.minifilter);
    host_event.session_id = 7000;
    host_event.source_ip = 0x0A000001;
    host_event.event_type = .block;
    host_event.severity = 3;

    // Submit both to XDR
    const idx1 = corr.submitEvent(net_event);
    const idx2 = corr.submitEvent(host_event);

    // Should be same incident (linked by session_id)
    try std.testing.expect(idx1.? == idx2.?);

    const inc = corr.getIncident(idx1.?);
    try std.testing.expect(inc.?.event_count == 2);
    try std.testing.expect(inc.?.ip_count == 2);
    try std.testing.expect(inc.?.severity == 3); // escalated
}

// ============================================================
// E2E: RAG Enrichment + Policy Decision
// ============================================================

test "S2-E2E: RAG enriches event → Policy blocks APT IP" {
    // Init RAG with known APT IP
    var rag_engine = rag.RAGEngine.init();
    _ = rag_engine.addThreat(.{
        .ip = 0xC0A80164,
        .severity = 3,
        .confidence = 90,
        .source = "threat_intel",
        .category = .apt,
        .first_seen_ms = 0,
        .last_seen_ms = 0,
    });

    // Init Policy Engine with Policy IR
    var builder = policy_ir.PolicyIRBuilder.init("APT Block Policy");
    _ = builder.addBlockRule("BlockAPT", 2);
    const ir = builder.build();

    var pe = policy.PolicyEngine.init();
    const loaded = ir.loadInto(&pe);
    try std.testing.expect(loaded == 1);

    // Enrich the IP
    const enrichment = rag_engine.enrich(0xC0A80164);
    try std.testing.expect(enrichment.threat_intel_match);
    try std.testing.expect(enrichment.threat_category == .apt);

    // Create detection result (high severity block)
    const det_result = detection.DetectionResult{
        .verdict = .match_block,
        .rule_id = 1,
        .rule_hash = 0,
        .severity = 2,
        .rule_name = "suspicious_activity",
        .ruleset_version = 1,
    };

    // Policy context with RAG enrichment
    const pol_ctx = policy.PolicyContext{
        .defcon_level = 5,
        .is_repeated_offender = false,
        .threat_intel_match = enrichment.threat_intel_match,
        .correlation_count = 0,
        .custom_flags = enrichment.context_flags,
    };

    // Policy should BLOCK (severity 2 + match_alert + rule min_severity=2)
    const decision = pe.evaluate(det_result, pol_ctx);
    try std.testing.expect(decision == .block);
}

test "S2-E2E: RAG no match → Policy allows benign traffic" {
    var rag_engine = rag.RAGEngine.init();
    var pe = policy.PolicyEngine.init();
    // No rules registered — default is allow

    const enrichment = rag_engine.enrich(0x0A000001);
    try std.testing.expect(!enrichment.threat_intel_match);

    const det_result = detection.DetectionResult.noMatch();
    const pol_ctx = policy.PolicyContext{
        .defcon_level = 5,
        .is_repeated_offender = false,
        .threat_intel_match = false,
        .correlation_count = 0,
        .custom_flags = 0,
    };

    try std.testing.expect(pe.evaluate(det_result, pol_ctx) == .allow);
}

// ============================================================
// E2E: Flow Engine + IPS
// ============================================================

test "S2-E2E: Flow Engine tracks connection → PEP blocks on policy" {
    var flow_table = flow.FlowTable.init();

    // Track a network flow
    const key = flow.FlowKey{
        .src_ip = 0xC0A80164,
        .dst_ip = 0x0A000001,
        .src_port = 12345,
        .dst_port = 80,
        .protocol = 6,
    };

    // Simulate multiple packets on same flow
    const f1 = flow_table.upsert(key, 1024, 42);
    try std.testing.expect(f1.packet_count == 1);

    const f2 = flow_table.upsert(key, 2048, 42);
    try std.testing.expect(f2.packet_count == 2);
    try std.testing.expect(f2.byte_count == 3072);

    // Flow has risk_score — PEP can use it for IPS decisions
    f2.risk_score = 200; // High risk

    // Init PEP and enforce block
    var pep = policy.PEP.init();
    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0xC0A80164;
    event.event_type = .block;

    const enf_result = pep.enforce(.block, &event);
    // In test mode, WFP device not open → .failed is acceptable
    try std.testing.expect(enf_result == .failed or enf_result == .success);
    try std.testing.expect(event.policy_action == .block);
}

test "S2-E2E: Flow Engine purges expired flows" {
    var flow_table = flow.FlowTable.init();

    const key = flow.FlowKey{
        .src_ip = 0x0A000001,
        .dst_ip = 0x0A000002,
        .src_port = 80,
        .dst_port = 443,
        .protocol = 6,
    };
    _ = flow_table.upsert(key, 512, 1);
    try std.testing.expect(flow_table.len() == 1);

    // Purge (flows with last_seen > 60s ago)
    const purged = flow_table.purgeExpired();
    // Flow was just created — shouldn't be purged
    try std.testing.expect(purged == 0);
    try std.testing.expect(flow_table.len() == 1);
}

// ============================================================
// E2E: Full Golden Path with all Sprint 2 modules
// ============================================================

test "S2-E2E: Complete Golden Path — all Sprint 2 modules" {
    // 1. Init all modules
    try nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 });
    defer nose.shutdownFabric(std.testing.allocator);

    var corr = xdr.XDRCorrelator.init();
    var rag_engine = rag.RAGEngine.init();
    var flow_table = flow.FlowTable.init();
    var pep = policy.PEP.init();

    // Policy IR with block rules
    var builder = policy_ir.PolicyIRBuilder.init("Full E2E Policy");
    _ = builder.addBlockRule("BlockCritical", 3);
    const ir = builder.build();
    var pe = policy.PolicyEngine.init();
    _ = ir.loadInto(&pe);

    // RAG: seed with known bad IP
    _ = rag_engine.addThreat(.{
        .ip = 0xC0A80164,
        .severity = 3,
        .confidence = 95,
        .source = "e2e_test",
        .category = .apt,
        .first_seen_ms = 0,
        .last_seen_ms = 0,
    });

    // 2. Simulate sensor event → Fabric
    var sensor_event = nose.createEvent(.wfp_sensor);
    sensor_event.event_type = .forward;
    sensor_event.source_ip = 0xC0A80164;
    sensor_event.session_id = 9999;
    try std.testing.expect(nose.submitEvent(sensor_event) == .accepted);

    // 3. XDR Correlator: track incident
    const inc_idx = corr.submitEvent(sensor_event);
    try std.testing.expect(inc_idx != null);

    // 4. Flow Engine: track connection
    const flow_key = flow.FlowKey{
        .src_ip = 0xC0A80164,
        .dst_ip = 0x0A000001,
        .src_port = 54321,
        .dst_port = 443,
        .protocol = 6,
    };
    _ = flow_table.upsert(flow_key, 4096, 9999);

    // 5. RAG: enrich with threat intel
    const enrichment = rag_engine.enrich(0xC0A80164);
    try std.testing.expect(enrichment.threat_intel_match);
    try std.testing.expect(enrichment.threat_category == .apt);

    // 6. Detection: simulate match
    const det_result = detection.DetectionResult{
        .verdict = .match_block,
        .rule_id = 42,
        .rule_hash = 0xABCDEF,
        .severity = 3,
        .rule_name = "E2E_ATTACK",
        .ruleset_version = 1,
    };

    // 7. Policy: evaluate with RAG context
    const pol_ctx = policy.PolicyContext{
        .defcon_level = 5,
        .is_repeated_offender = false,
        .threat_intel_match = enrichment.threat_intel_match,
        .correlation_count = 1,
        .custom_flags = enrichment.context_flags,
    };
    const decision = pe.evaluate(det_result, pol_ctx);
    try std.testing.expect(decision == .block);

    // 8. PEP: enforce block
    var enforce_event = canonical.create(.wfp_sensor);
    enforce_event.source_ip = 0xC0A80164;
    enforce_event.session_id = 9999;
    const enf_result = pep.enforce(decision, &enforce_event);
    try std.testing.expect(enf_result == .failed or enf_result == .success);
    try std.testing.expect(enforce_event.policy_action == .block);

    // 9. Verify XDR incident was updated
    const inc = corr.getIncident(inc_idx.?);
    try std.testing.expect(inc != null);
    try std.testing.expect(inc.?.event_count >= 1);

    // 10. Verify Flow was tracked
    try std.testing.expect(flow_table.len() == 1);

    // Full Golden Path verified!
}

test "S2-E2E: Policy IR builder creates complete rule set" {
    var builder = policy_ir.PolicyIRBuilder.init("Complete Policy");
    _ = builder.addBlockRule("BlockCritical", 3);
    _ = builder.addBlockRule("BlockHigh", 2);
    _ = builder.addAlertRule("AlertMedium", 1);
    _ = builder.addLogOnlyRule("LogLow", 0);
    const ir = builder.build();

    try std.testing.expect(ir.validate());
    try std.testing.expect(ir.rule_count == 4);

    // Load into PolicyEngine
    var pe = policy.PolicyEngine.init();
    const loaded = ir.loadInto(&pe);
    try std.testing.expect(loaded == 4);
}

test "S2-E2E: XDR escalation tracking across multiple events" {
    var corr = xdr.XDRCorrelator.init();

    // Event 1: Low severity
    var e1 = canonical.create(.wfp_sensor);
    e1.session_id = 1;
    e1.severity = 1;
    _ = corr.submitEvent(e1);

    // Event 2: Medium (same session)
    var e2 = canonical.create(.minifilter);
    e2.session_id = 1;
    e2.severity = 2;
    _ = corr.submitEvent(e2);

    // Event 3: Critical (same session)
    var e3 = canonical.create(.pipe_sensor);
    e3.session_id = 1;
    e3.severity = 3;
    _ = corr.submitEvent(e3);

    const stats = corr.getStats();
    try std.testing.expect(stats.total_correlations == 2); // e2 + e3 correlated to existing
    try std.testing.expect(stats.total_escalations == 2); // severity escalated twice

    // Verify final severity is 3 (highest)
    const inc = corr.getIncident(0);
    try std.testing.expect(inc.?.severity == 3);
}
