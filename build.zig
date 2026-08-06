const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "aegis-nids",
        .root_source_file = b.path("nids_main.zig"),
        .target = target,
        .optimize = optimize,
    });

    b.installArtifact(exe);
    exe.linkLibC();

    // NOTE: No linkSystemLibrary needed!
    // aegis_ipc.dll and sec_monitor.dll are loaded at runtime
    // via std.DynLib (like Python ctypes) — no link-time dependency.
    // This allows Zig to build completely standalone.

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
