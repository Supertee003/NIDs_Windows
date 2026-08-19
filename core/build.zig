const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Main NIDS executable
    const nids = b.addExecutable(.{
        .name = "aegis_nids",
        .root_source_file = b.path("src/nids_main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Capture module
    const capture = b.addExecutable(.{
        .name = "aegis_capture",
        .root_source_file = b.path("src/nids_capture.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Analyze module
    const analyze = b.addExecutable(.{
        .name = "aegis_analyze",
        .root_source_file = b.path("src/nids_analyze.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Pipe monitor
    const pipe_mon = b.addExecutable(.{
        .name = "aegis_pipe_monitor",
        .root_source_file = b.path("src/pipe_monitor.zig"),
        .target = target,
        .optimize = optimize,
    });

    const install_nids = b.addInstallArtifact(nids);
    const install_capture = b.addInstallArtifact(capture);
    const install_analyze = b.addInstallArtifact(analyze);
    const install_pipe = b.addInstallArtifact(pipe_mon);

    const build_all = b.step("all", "Build all NIDS components");
    build_all.dependOn(&install_nids.step);
    build_all.dependOn(&install_capture.step);
    build_all.dependOn(&install_analyze.step);
    build_all.dependOn(&install_pipe.step);
}