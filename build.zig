const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Optional: link C++ IPC Bridge and Rust FFI
    // Use: zig build -Dlink-bridge -Dlink-rust
    // Without flags: builds standalone (no DLL dependencies)
    const link_bridge = b.option(bool, "link-bridge", "Link C++ IPC Bridge (aegis_ipc)") orelse false;
    const link_rust = b.option(bool, "link-rust", "Link Rust FFI (sec_monitor)") orelse false;

    const exe = b.addExecutable(.{
        .name = "aegis-nids",
        .root_source_file = b.path("nids_main.zig"),
        .target = target,
        .optimize = optimize,
    });

    b.installArtifact(exe);
    exe.linkLibC();

    // Rust FFI (sec_monitor.dll) — Tier-0 Memory Safety Shield
    // Only link if -Dlink-rust is set AND the library exists
    if (link_rust) {
        exe.addLibraryPath(.{ .cwd_relative = "target/release" });
        exe.linkSystemLibrary("sec_monitor");
    }

    // C++ IPC Bridge (aegis_ipc.dll) — Zig Core ↔ Bridge ↔ Dashboard
    // Only link if -Dlink-bridge is set AND the library exists
    if (link_bridge) {
        // MSVC multi-config: build/Release or build/Debug
        exe.addLibraryPath(.{ .cwd_relative = "build/Release" });
        exe.addLibraryPath(.{ .cwd_relative = "build/Debug" });
        exe.addLibraryPath(.{ .cwd_relative = "build" });
        exe.linkSystemLibrary("aegis_ipc");
    }

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
