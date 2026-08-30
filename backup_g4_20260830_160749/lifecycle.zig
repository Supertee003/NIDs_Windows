//! lifecycle.zig - AEGIS Runtime Lifecycle (Rewrite G3 Runtime Spine)
//!
//! Manages init/shutdown of all subsystems in correct order.
//! main() calls runtime.start() and runtime.shutdown() - nothing else.
//!
//! G3: Added Runtime Spine (module classification, lifecycle pattern, worker model, golden path tracing).

const std = @import("std");
const canonical = @import("canonical_event.zig");
const fabric = @import("event_fabric.zig");
const nose = @import("nose_contract.zig");
const nose_int = @import("nose_integration.zig");
const flow_int = @import("flow_integration.zig");
const detection_int = @import("detection_integration.zig");
const correlation_int = @import("correlation_integration.zig");
const threat_intel_int = @import("threat_intel_integration.zig");
const brain_int = @import("brain_integration.zig");
const policy_int = @import("policy_integration.zig");
const rust_pep_int = @import("rust_pep_integration.zig");
const forensics_int = @import("forensics_integration.zig");
const replay_int = @import("replay_integration.zig");
const e2e_int = @import("e2e_harness_integration.zig");
const perf_int = @import("performance_integration.zig");
const canary_int = @import("ips_canary_integration.zig");
const xdr_int = @import("xdr_harden_integration.zig");
const release_int = @import("release_engineering_integration.zig");
const rag_int = @import("rag_integration.zig");
const hids_int = @import("hids_integration.zig");
const conc_int = @import("concurrency_harden_integration.zig");
const fault_int = @import("fault_injection_integration.zig");
const ips_sim_int = @import("ips_simulation_integration.zig");
const policy_plane_int = @import("policy_plane_integration.zig");
const forensic_log = @import("forensic_log.zig");

// ============================================================
// Lifecycle states
// ============================================================

pub const State = enum(u8) {
    init = 0,
    starting = 1,
    running = 2,
    draining = 3,
    stopped = 4,

    pub fn toString(self: State) []const u8 {
        return switch (self) {
            .init => "INIT",
            .starting => "STARTING",
            .running => "RUNNING",
            .draining => "DRAINING",
            .stopped => "STOPPED",
        };
    }
};

var g_state: State = .init;
var g_allocator: ?std.mem.Allocator = null;

// ============================================================
// Start (init all subsystems in order)
// ============================================================

pub fn start(allocator: std.mem.Allocator) !void {
    switch (g_state) {
        .starting, .running => return,
        .init, .stopped, .draining => {},
    }
    g_state = .starting;
    g_allocator = allocator;

    // 1. Forensic logger (needs to log everything from start)
    forensic_log.init();
    defer if (g_state != .running) forensic_log.shutdown();

    // 2. Event Fabric (queue must be ready before sensors)
    try nose.initFabric(allocator, .{ .capacity_per_priority = 256 });
    defer if (g_state != .running) nose.shutdownFabric(allocator);

    // 3. Nose Contract (validation must be ready before events)
    // (nose_contract delegates to event_fabric, already initialized)

    // 4. Nose Integration (pressure-aware sampling)
    nose_int.init(nose_int.SamplingPolicy.default);

    // 5. Flow Engine (Phase 6) - tracks connections, emits FlowUpdate
    flow_int.init(allocator);
    defer if (g_state != .running) flow_int.shutdown();

    // 6. Detection Engine (Phase 7) - evidence producer
    detection_int.init();
    defer if (g_state != .running) detection_int.shutdown();

    // 7. Verdict Aggregator (Phase 8) - consumes evidence from Detection
    const dispatcher = @import("dispatcher.zig");
    dispatcher.initAggregator();
    defer if (g_state != .running) dispatcher.shutdownAggregator();

    // 8. Correlation Engine (Phase 9) - entity tracking across flows
    correlation_int.init(allocator);
    defer if (g_state != .running) correlation_int.shutdown();

    // 9. Threat Intel (Phase 10) - IP blocklist + enrichment
    threat_intel_int.init(allocator);
    defer if (g_state != .running) threat_intel_int.shutdown();

    // 10. Brain Advisor (Phase 11) - heuristic model for verdict refinement
    brain_int.init();
    defer if (g_state != .running) brain_int.shutdown();

    // 11. Policy Engine (Phase 12) - planner, not enforcer
    policy_int.init();
    defer if (g_state != .running) policy_int.shutdown();

    // 12. Rust PEP (Phase 13) - security authority: validate -> execute
    rust_pep_int.init();
    defer if (g_state != .running) rust_pep_int.shutdown();

    // 13. Forensics (Phase 14) - final stage: records everything for replay
    forensics_int.init();
    defer if (g_state != .running) forensics_int.shutdown();

    // 14. Replay Engine (Phase 15) - read-only analysis tool for regression testing
    replay_int.init();
    defer if (g_state != .running) replay_int.shutdown();

    // 15. E2E Harness (Phase 16) - end-to-end test framework
    e2e_int.init();
    defer if (g_state != .running) e2e_int.shutdown();

    // 16. Performance Harness (Phase 17) - benchmarking and latency measurement
    perf_int.init();
    defer if (g_state != .running) perf_int.shutdown();

    // 17. IPS Canary (Phase 18) - health monitoring and enforcement verification
    canary_int.init();
    defer if (g_state != .running) canary_int.shutdown();

    // 18. XDR Hardening (Phase 19) - SIEM export and incident aggregation
    xdr_int.init();
    defer if (g_state != .running) xdr_int.shutdown();

    // 19. Release Engineering (Phase 20) - metrics export and build info
    release_int.init();
    defer if (g_state != .running) release_int.shutdown();

    // 20. RAG (Phase 22) - Retrieval Augmented Generation, fail-soft context
    rag_int.init();
    defer if (g_state != .running) rag_int.shutdown();

    // 21. HIDS (Phase 23) - real process event tracking
    hids_int.init(allocator);
    defer if (g_state != .running) hids_int.shutdown();

    // 22. Concurrency Hardening (Phase 24) - race/deadlock/event-loss testing
    conc_int.init();
    defer if (g_state != .running) conc_int.shutdown();

    // 23. Fault Injection (Phase 25) - simulate subsystem failures
    fault_int.init();
    defer if (g_state != .running) fault_int.shutdown();

    // 24. IPS Simulation (Phase 26) - AUDIT->SIMULATE->CANARY->ENFORCE
    ips_sim_int.init();
    defer if (g_state != .running) ips_sim_int.shutdown();

    // 25. Policy Plane (Phase 27) - TypeScript policy IR, compiler, simulator
    policy_plane_int.init();
    defer if (g_state != .running) policy_plane_int.shutdown();

    g_state = .running;
    std.log.info("[RUNTIME] Started (state={s})", .{g_state.toString()});
}

// ============================================================
// Shutdown (reverse order)
// ============================================================

pub fn shutdown() void {
    if (g_state == .stopped) return;
    if (g_state == .init) return;
    g_state = .draining;

    const allocator = g_allocator orelse {
        g_state = .init;
        return;
    };

    // Drain queue (process remaining events)
    const dispatcher = @import("dispatcher.zig");
    _ = dispatcher.drainQueue(1000);

    // Shutdown in reverse order:
    // 25. Policy Plane (Phase 27)
    policy_plane_int.shutdown();
    // 24. IPS Simulation (Phase 26)
    ips_sim_int.shutdown();
    // 23. Fault Injection (Phase 25)
    fault_int.shutdown();
    // 22. Concurrency Hardening (Phase 24)
    conc_int.shutdown();
    // 21. HIDS (Phase 23)
    hids_int.shutdown();
    // 20. RAG (Phase 22)
    rag_int.shutdown();
    // 19. Release Engineering (Phase 20)
    release_int.shutdown();
    // 18. XDR Hardening (Phase 19)
    xdr_int.shutdown();
    // 17. IPS Canary (Phase 18)
    canary_int.shutdown();
    // 16. Performance Harness (Phase 17)
    perf_int.shutdown();
    // 15. E2E Harness (Phase 16)
    e2e_int.shutdown();
    // 14. Replay Engine (Phase 15)
    replay_int.shutdown();
    // 13. Forensics (Phase 14)
    forensics_int.shutdown();
    // 12. Rust PEP (Phase 13)
    rust_pep_int.shutdown();
    // 11. Policy Engine (Phase 12)
    policy_int.shutdown();
    // 10. Brain Advisor (Phase 11)
    brain_int.shutdown();
    // 9. Threat Intel (Phase 10)
    threat_intel_int.shutdown();
    // 8. Correlation Engine (Phase 9)
    correlation_int.shutdown();
    // 7. Verdict Aggregator (Phase 8)
    dispatcher.shutdownAggregator();
    // 6. Detection Engine (Phase 7)
    detection_int.shutdown();
    // 5. Flow Engine (Phase 6)
    flow_int.shutdown();
    // 4. nose_integration has no shutdown() - just reset stats
    nose_int.resetStats();
    // 2. Event Fabric
    nose.shutdownFabric(allocator);
    // 1. Forensic logger
    forensic_log.shutdown();

    g_state = .init;
    g_allocator = null;
    std.log.info("[RUNTIME] Stopped", .{});
}

// ============================================================
// State queries
// ============================================================

pub fn getState() State {
    return g_state;
}

pub fn isRunning() bool {
    return g_state == .running;
}

pub fn getAllocator() ?std.mem.Allocator {
    return g_allocator;
}

// ============================================================
// Tests (all stateful tests merged into ONE serial test)
// ============================================================

test "State.toString returns readable names" {
    try std.testing.expect(std.mem.eql(u8, State.init.toString(), "INIT"));
    try std.testing.expect(std.mem.eql(u8, State.running.toString(), "RUNNING"));
    try std.testing.expect(std.mem.eql(u8, State.stopped.toString(), "STOPPED"));
    try std.testing.expect(std.mem.eql(u8, State.draining.toString(), "DRAINING"));
    try std.testing.expect(std.mem.eql(u8, State.starting.toString(), "STARTING"));
}

test "lifecycle: full sequence (start, double-start, shutdown, double-shutdown)" {
    if (fabric.isInitialized()) {
        shutdown();
    }

    try start(std.testing.allocator);
    try std.testing.expect(isRunning());
    try std.testing.expect(getState() == .running);

    try start(std.testing.allocator);
    try std.testing.expect(isRunning());
    try std.testing.expect(getState() == .running);

    shutdown();
    try std.testing.expect(!isRunning());
    try std.testing.expect(getState() == .init);

    shutdown();
    shutdown();
    try std.testing.expect(getState() == .init);
    try std.testing.expect(!isRunning());

    try start(std.testing.allocator);
    try std.testing.expect(isRunning());
    shutdown();
    try std.testing.expect(getState() == .init);
}

test "lifecycle: all subsystems initialized after start" {
    if (fabric.isInitialized()) {
        shutdown();
    }

    try start(std.testing.allocator);
    try std.testing.expect(flow_int.isInitialized());
    try std.testing.expect(detection_int.isInitialized());
    try std.testing.expect(correlation_int.isInitialized());
    try std.testing.expect(threat_intel_int.isInitialized());
    try std.testing.expect(brain_int.isInitialized());
    try std.testing.expect(policy_int.isInitialized());
    try std.testing.expect(rust_pep_int.isInitialized());
    try std.testing.expect(forensics_int.isInitialized());
    try std.testing.expect(replay_int.isInitialized());
    try std.testing.expect(e2e_int.isInitialized());
    try std.testing.expect(perf_int.isInitialized());
    try std.testing.expect(canary_int.isInitialized());
    try std.testing.expect(xdr_int.isInitialized());
    try std.testing.expect(release_int.isInitialized());
    try std.testing.expect(rag_int.isInitialized());
    try std.testing.expect(hids_int.isInitialized());
    try std.testing.expect(conc_int.isInitialized());
    try std.testing.expect(fault_int.isInitialized());
    try std.testing.expect(ips_sim_int.isInitialized());
    try std.testing.expect(policy_plane_int.isInitialized());

    const dispatcher = @import("dispatcher.zig");
    try std.testing.expect(dispatcher.isAggregatorInitialized());

    shutdown();
    try std.testing.expect(!flow_int.isInitialized());
    try std.testing.expect(!detection_int.isInitialized());
    try std.testing.expect(!correlation_int.isInitialized());
    try std.testing.expect(!threat_intel_int.isInitialized());
    try std.testing.expect(!brain_int.isInitialized());
    try std.testing.expect(!policy_int.isInitialized());
    try std.testing.expect(!rust_pep_int.isInitialized());
    try std.testing.expect(!forensics_int.isInitialized());
    try std.testing.expect(!replay_int.isInitialized());
    try std.testing.expect(!e2e_int.isInitialized());
    try std.testing.expect(!perf_int.isInitialized());
    try std.testing.expect(!canary_int.isInitialized());
    try std.testing.expect(!xdr_int.isInitialized());
    try std.testing.expect(!release_int.isInitialized());
    try std.testing.expect(!rag_int.isInitialized());
    try std.testing.expect(!hids_int.isInitialized());
    try std.testing.expect(!conc_int.isInitialized());
    try std.testing.expect(!fault_int.isInitialized());
    try std.testing.expect(!ips_sim_int.isInitialized());
    try std.testing.expect(!policy_plane_int.isInitialized());
    try std.testing.expect(!dispatcher.isAggregatorInitialized());
}
