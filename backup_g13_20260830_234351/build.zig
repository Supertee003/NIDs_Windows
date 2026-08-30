const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "aegis-nids",
        .root_source_file = b.path("core/nids_main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const rules_src = b.path("config/Rules.json");
    const rules_install = b.addInstallFileWithDir(rules_src, .bin, "Rules.json");
    exe.step.dependOn(&rules_install.step);
    b.installFile("config/Rules.json", "Rules.json");

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const test_step = b.step("test", "Run unit tests");

    // G13: Added health_monitoring_proof.zig (liveness, readiness, metrics, DEFCON rollup).
    //
    // Import chain verification (updated for Phase 18):
    //   core/dispatcher.zig           -> no change (Canary is health monitoring tool)
    //   core/lifecycle.zig           -> + ips_canary_integration
    //   core/health_monitoring_proof.zig -> self-contained (no runtime module imports)
    //
    // NOTE: All runtime modules now live in core/ (not core/runtime/) because
    // `zig test core/runtime/file.zig` cannot resolve @import() relative paths.
    const test_files = [_][]const u8{
        // Base modules
        "core/canonical_event.zig",
        "core/wire_event.zig",
        "core/event_queue.zig",
        "core/priority_queue.zig",
        "core/event_fabric.zig",
        "core/nose_contract.zig",
        "core/nose_integration.zig",
        "core/detection_interface.zig",
        "core/policy_contract.zig",
        "core/forensic_log.zig",
        "core/wfp_ioctl.zig",
        // Runtime modules (Phase 5..27)
        "core/dispatcher.zig",
        "core/lifecycle.zig",
        // Flow Engine modules (Phase 6)
        "core/flow_engine.zig",
        "core/flow_integration.zig",
        // Detection Engine modules (Phase 7)
        "core/detection_engine.zig",
        "core/detection_integration.zig",
        // Verdict Aggregator (Phase 8)
        "core/verdict_aggregator.zig",
        // Correlation Engine modules (Phase 9)
        "core/correlation_engine.zig",
        "core/correlation_integration.zig",
        // Threat Intel modules (Phase 10)
        "core/threat_intel.zig",
        "core/threat_intel_integration.zig",
        // Brain Advisor modules (Phase 11)
        "core/brain_engine.zig",
        "core/brain_integration.zig",
        // Policy Engine modules (Phase 12)
        "core/policy_engine.zig",
        "core/policy_integration.zig",
        // Rust PEP modules (Phase 13)
        "core/rust_pep.zig",
        "core/rust_pep_integration.zig",
        // Forensics modules (Phase 14)
        "core/forensics_engine.zig",
        "core/forensics_integration.zig",
        // Replay modules (Phase 15)
        "core/replay_engine.zig",
        "core/replay_integration.zig",
        // E2E Harness modules (Phase 16)
        "core/e2e_harness.zig",
        "core/e2e_harness_integration.zig",
        // Performance modules (Phase 17)
        "core/performance_harness.zig",
        "core/performance_integration.zig",
        // IPS Canary modules (Phase 18 NEW)
        "core/ips_canary.zig",
        "core/ips_canary_integration.zig",
        // XDR Hardening modules (Phase 19 NEW)
        "core/xdr_harden.zig",
        "core/xdr_harden_integration.zig",
        // Release Engineering modules (Phase 20 NEW)
        "core/release_engineering.zig",
        "core/release_engineering_integration.zig",
        // Legacy Removal (Phase 21 NEW)
        "core/legacy_removal.zig",
        // RAG modules (Phase 22 NEW)
        "core/rag_engine.zig",
        "core/rag_integration.zig",
        // HIDS modules (Phase 23 NEW)
        "core/hids_engine.zig",
        "core/hids_integration.zig",
        // Concurrency Hardening modules (Phase 24 NEW)
        "core/concurrency_harden.zig",
        "core/concurrency_harden_integration.zig",
        // Fault Injection modules (Phase 25 NEW)
        "core/fault_injection.zig",
        "core/fault_injection_integration.zig",
        // IPS Simulation modules (Phase 26 NEW)
        "core/ips_simulation.zig",
        "core/ips_simulation_integration.zig",
        // Policy Plane modules (Phase 27 NEW)
        "core/policy_plane.zig",
        "core/policy_plane_integration.zig",
        // Contract Freeze (G1 NEW)
        "core/contract_freeze.zig",
        // Fabric Accounting (G2 NEW)
        "core/fabric_accounting.zig",
        // Runtime Spine (G3 NEW)
        "core/runtime_spine.zig",
        // Flow State Proof (G4 NEW)
        "core/flow_state_proof.zig",
        // Detection Fabric Proof (G5 NEW)
        "core/detection_fabric_proof.zig",
        // Correlation Proof (G6 NEW)
        "core/correlation_proof.zig",
        // Intelligence Proof (G7 NEW)
        "core/intelligence_proof.zig",
        // Brain Proof (G8 NEW)
        "core/brain_proof.zig",
        // Policy Plane Proof (G9 NEW)
        "core/policy_plane_proof.zig",
        // PEP Enforcement Proof (G10 NEW)
        "core/pep_enforcement_proof.zig",
        // Forensic Replay Proof (G11 NEW)
        "core/forensic_replay_proof.zig",
        // Config Reload Proof (G12 NEW)
        "core/config_reload_proof.zig",
        // Health Monitoring Proof (G13 NEW)
        "core/health_monitoring_proof.zig",
        // Sensor/platform modules
        "core/bridge_init.zig",
        "core/win32_io.zig",
        "core/pipe_monitor.zig",
        "core/minifilter_reader.zig",
        "core/hids_process_monitor.zig",
        "core/nids_analyze.zig",
        "core/nids_capture.zig",
        "core/windows_capture.zig",
    };

    for (test_files) |test_file| {
        const tests = b.addTest(.{
            .root_source_file = b.path(test_file),
            .target = target,
            .optimize = optimize,
        });
        const run_tests = b.addRunArtifact(tests);
        test_step.dependOn(&run_tests.step);
    }
}
