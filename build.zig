const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "aegis-nids",
        .root_source_file = b.path("core/src/nids_main.zig"),
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
}
