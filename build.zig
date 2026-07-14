const std = @import("std");

// =====================================================================
// build.zig — AEGIS NIDS Core build script
// ---------------------------------------------------------------------
//   Build target: aegis-nids.exe
//   Dependencies:
//     - sec_monitor.dll (Rust FFI — build ด้วย `cargo build --release` ก่อน)
//     - fltlib.lib (Windows FilterManager user-mode API — สำหรับ minifilter_reader)
// =====================================================================

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

    // Rust FFI: sec_monitor.dll (จาก target/release/)
    exe.addLibraryPath(.{ .cwd_relative = "target/release" });
    exe.linkSystemLibrary("sec_monitor");

    // Windows libs สำหรับ minifilter_reader.zig (FilterManager user-mode API)
    // NOTE: ต้องติดตั้ง Windows SDK / WDK
    exe.linkSystemLibrary("fltlib");

    // Run step
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    const run_step = b.step("run", "Run the AEGIS NIDS");
    run_step.dependOn(&run_cmd.step);

    // Test step (unit tests ถ้ามี)
    const tests = b.addTest(.{
        .root_source_file = b.path("nids_analyze.zig"),
        .target = target,
        .optimize = optimize,
    });
    tests.linkLibC();
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&b.addRunArtifact(tests).step);
}
