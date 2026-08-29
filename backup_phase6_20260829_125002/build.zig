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

    // Rewrite Phase 6: Added flow_engine.zig + flow_integration.zig.
    //
    // Import chain verification (updated for Phase 6):
    //   core/dispatcher.zig        -> canonical_event + event_fabric + flow_integration
    //   core/lifecycle.zig         -> canonical_event + event_fabric + nose_contract
    //                                 + nose_integration + flow_integration + forensic_log + dispatcher (local)
    //   core/flow_engine.zig        -> canonical_event (no deps on integration modules)
    //   core/flow_integration.zig   -> canonical_event + flow_engine (both exist)
    //
    // NOTE: All runtime modules now live in core/ (not core/runtime/) because
    // `zig test core/runtime/dispatcher.zig` cannot resolve @import("canonical_event.zig")
    // (Zig looks relative to the file's directory). See hotfix2 history.
    //
    // User's versions of sensor modules may have additional imports from STEP 3-15.
    // If any fail to compile, they will show specific import errors - we can fix individually.
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
        // Runtime modules (Phase 5 + 6)
        "core/dispatcher.zig",
        "core/lifecycle.zig",
        // Flow Engine modules (Phase 6 NEW)
        "core/flow_engine.zig",
        "core/flow_integration.zig",
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
