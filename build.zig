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



    // Install Rules.json alongside exe so analyze_packets can find it
    const rules_src = b.path("config/Rules.json");
    const rules_install = b.addInstallFileWithDir(rules_src, .bin, "Rules.json");
    exe.step.dependOn(&rules_install.step);

    // Also install to project root for `zig build run` (which runs from project dir)
    b.installFile("config/Rules.json", "Rules.json");


    // NOTE: linkLibC() removed — it was causing 0xC000007B (STATUS_INVALID_IMAGE_FORMAT)
    // on Windows when the matching VC++ Redistributable was absent.
    // Our code only uses extern "kernel32" (Windows API) which Zig links natively.
    // No libc functions (printf, malloc, etc.) are called from C code.
    //
    // If you add C interop that truly needs libc, uncomment the line below:
    // exe.linkLibC();

    // NOTE: No linkSystemLibrary needed!
    // aegis_ipc.dll and sec_monitor.dll are loaded at runtime
    // via std.DynLib (like Python ctypes) — no link-time dependency.
    // This allows Zig to build completely standalone.

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // ============================================================
    // Test step: runs all unit tests across core/*.zig modules
    // Usage: zig build test
    // ============================================================
    const test_step = b.step("test", "Run unit tests");

    // List all Zig source files that contain tests
    const test_files = [_][]const u8{
        "core/nids_analyze.zig",
        "core/wfp_ioctl.zig",
        "core/pipe_monitor.zig",
        "core/minifilter_reader.zig",
        "core/win32_io.zig",
        "core/forensic_log.zig",
        "core/canonical_event.zig",
        "core/wire_event.zig",
        "core/event_queue.zig",
        "core/priority_queue.zig",
        "core/nose_contract.zig",
        "core/detection_interface.zig",
        "core/policy_contract.zig",
        "core/golden_path_test.zig",
        "core/hids_process_monitor.zig",
        "core/flow_engine.zig",
        "core/xdr_correlator.zig",
        "core/rag_intelligence.zig",
        "core/policy_ir.zig",
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
