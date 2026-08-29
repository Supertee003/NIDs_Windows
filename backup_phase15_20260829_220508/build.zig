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

    // Rewrite Phase 15: Added replay_engine.zig + replay_integration.zig.
    //
    // Import chain verification (updated for Phase 15):
    //   core/dispatcher.zig           -> canonical_event + event_fabric + flow_integration
    //                                    + detection_integration + verdict_aggregator
    //                                    + correlation_integration + threat_intel_integration
    //                                    + brain_integration + policy_integration
    //                                    + rust_pep_integration + forensics_integration
    //   core/lifecycle.zig           -> + replay_integration
    //   core/replay_engine.zig       -> canonical_event + detection_engine + verdict_aggregator
    //                                    + forensics_engine + policy_engine + rust_pep (all exist)
    //   core/replay_integration.zig  -> forensics_engine + replay_engine (both exist)
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
        // Runtime modules (Phase 5 + 6 + 7 + 8 + 9 + 10 + 11 + 12 + 13 + 14 + 15)
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
        // Replay modules (Phase 15 NEW)
        "core/replay_engine.zig",
        "core/replay_integration.zig",
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
