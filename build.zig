const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Optional: link C++ IPC Bridge and Rust FFI
    // Use: zig build -Dlink-bridge -Dlink-rust
    // Without flags: builds standalone (no DLL dependencies at link time)
    // DLLs are loaded at runtime via std.DynLib (graceful degradation)
    const link_bridge = b.option(bool, "link-bridge", "Link C++ IPC Bridge (aegis_ipc)") orelse false;
    const link_rust = b.option(bool, "link-rust", "Link Rust FFI (sec_monitor)") orelse false;
    const exe = b.addExecutable(.{
        .name = "aegis-nids",
        .root_source_file = b.path("nids_main.zig"),
        .target = target,
        .optimize = optimize,
    });

    b.installArtifact(exe);
    // exe.linkLibC(); // removed: causing 0xC000007B

    // Link ws2_32 for Winsock2 (system DLL, always available)
    exe.linkSystemLibrary("ws2_32");

    // Only link optional DLLs when flags are set
    // Without flags: exe starts standalone, loads DLLs at runtime via std.DynLib
    if (link_bridge) {
        exe.addLibraryPath(.{ .cwd_relative = "build" });
        exe.addLibraryPath(.{ .cwd_relative = "build/Release" });
        exe.addLibraryPath(.{ .cwd_relative = "build/Debug" });
        exe.linkSystemLibrary("aegis_ipc");
        exe.linkSystemLibrary("aegis_packet_parser");
    }

    if (link_rust) {
        exe.addLibraryPath(.{ .cwd_relative = "build" });
        exe.addLibraryPath(.{ .cwd_relative = "target/release" });
        exe.linkSystemLibrary("aegis_shield");
    }

    // kernel32 is always available on Windows (extern "kernel32" works natively)
    // No need to explicitly linkSystemLibrary for it

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
