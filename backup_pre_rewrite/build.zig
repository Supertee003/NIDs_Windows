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

    const test_files = [_][]const u8{
        "core/nids_analyze.zig", "core/wfp_ioctl.zig", "core/pipe_monitor.zig",
        "core/minifilter_reader.zig", "core/win32_io.zig", "core/forensic_log.zig",
        "core/canonical_event.zig", "core/wire_event.zig", "core/event_queue.zig",
        "core/priority_queue.zig", "core/event_fabric.zig", "core/nose_integration.zig",
        "core/flow_integration.zig", "core/detection_integration.zig",
        "core/correlation_integration.zig", "core/rag_integration.zig",
        "core/policy_integration.zig", "core/forensics_integration.zig",
        "core/runtime_golden_path_test.zig", "core/perf_benchmark.zig",
        "core/ips_canary_test.zig", "core/xdr_hardening.zig", "core/release_info.zig",
        "core/cpp_bridge_integration.zig", "core/rust_shield_integration.zig",
        "core/go_aggregator_integration.zig", "core/python_brain_integration.zig",
        "core/cython_acceleration.zig", "core/metrics_export.zig",
        "core/wfp_driver_test.zig", "core/stress_test.zig",
        "core/memory_leak_test.zig", "core/crash_recovery_test.zig",
        "core/nose_contract.zig", "core/detection_interface.zig",
        "core/policy_contract.zig", "core/golden_path_test.zig",
        "core/hids_process_monitor.zig", "core/flow_engine.zig",
        "core/xdr_correlator.zig", "core/rag_intelligence.zig",
        "core/policy_ir.zig", "core/sprint2_e2e_test.zig",
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
