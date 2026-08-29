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

    // Rewrite Phase 5: Added runtime/ modules + sensor modules
    //
    // Import chain verification:
    //   runtime/dispatcher.zig -> canonical_event + event_fabric + nose_contract (local)
    //   runtime/lifecycle.zig -> canonical_event + event_fabric + nose_contract
    //                            + nose_integration + forensic_log + dispatcher (local)
    //   bridge_init.zig -> wfp_ioctl (exists)
    //   win32_io.zig -> (none)
    //   hids_process_monitor.zig -> (aegis_latest: none, user version may import nose_integration)
    //   pipe_monitor.zig -> bridge_init (exists)
    //   minifilter_reader.zig -> bridge_init + win32_io (both exist)
    //   nids_analyze.zig -> bridge_init + forensic_log + win32_io + nose_contract (all exist)
    //   nids_capture.zig -> bridge_init + nids_analyze + win32_io + nose_contract (all exist)
    //   windows_capture.zig -> bridge_init + nids_analyze + wfp_ioctl + nose_contract (all exist)
    //
    // NOTE: User's versions of these files may have additional imports from STEP 3-15.
    // If any fail to compile, they will show specific import errors — we can fix individually.
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
        // Runtime modules (NEW)
        "core/dispatcher.zig",
        "core/lifecycle.zig",
        // Sensor/platform modules (may need fixes if user's version imports removed modules)
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
