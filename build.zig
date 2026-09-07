// I01 - Repository Bootstrap: build.zig
// AEGIS NIDS v5.0+ â€” Master Build File
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{
        .default_target = .{ .os_tag = .windows, .cpu_arch = .x86_64 },
    });
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe });

    // ----- Core NIDS Executable -----
    const exe = b.addExecutable(.{
        .name = "aegis_nids",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe.linkLibC();

    // Link Windows system libraries
    exe.linkSystemLibrary("ws2_32");
    exe.linkSystemLibrary("advapi32");
    exe.linkSystemLibrary("kernel32");
    exe.linkSystemLibrary("user32");
    exe.linkSystemLibrary("ole32");
    exe.linkSystemLibrary("secur32");
    exe.linkSystemLibrary("ntdll");
    exe.linkSystemLibrary("tdh"); // ETW TDH helpers

    // Npcap (located via NPCAP_DIR env, %LOCALAPPDATA%\NpcapSDK, or C:\Npcap)
    var npcap_inc: ?[]const u8 = null;
    var npcap_lib: ?[]const u8 = null;
    if (std.process.getEnvVarOwned(b.allocator, "NPCAP_DIR")) |npcap_dir| {
        npcap_inc = b.pathJoin(&.{ npcap_dir, "Include" });
        npcap_lib = b.pathJoin(&.{ npcap_dir, "Lib", "x64" });
    } else |_| {
        if (std.process.getEnvVarOwned(b.allocator, "LOCALAPPDATA")) |local| {
            const sdk_lib = b.pathJoin(&.{ local, "NpcapSDK", "Lib", "x64" });
            if (std.fs.cwd().access(sdk_lib, .{})) |_| {
                npcap_inc = b.pathJoin(&.{ local, "NpcapSDK", "Include" });
                npcap_lib = sdk_lib;
            } else |_| {}
        } else |_| {}
        if (npcap_lib == null) {
            npcap_inc = "C:/Npcap/Include";
            npcap_lib = "C:/Npcap/Lib/x64";
        }
    }
    exe.addIncludePath(.{ .cwd_relative = npcap_inc.? });
    exe.addLibraryPath(.{ .cwd_relative = npcap_lib.? });
    exe.linkSystemLibrary("wpcap");
    exe.linkSystemLibrary("Packet");

    b.installArtifact(exe);

    // ----- Rust PEP import library (aegis_pep.dll built via `cargo build --release`) -----
    if (std.fs.cwd().access("target/release/aegis_pep.dll.lib", .{})) |_| {
        std.fs.cwd().copyFile(
            "target/release/aegis_pep.dll.lib",
            std.fs.cwd(),
            "target/release/aegis_pep.lib",
            .{},
        ) catch {};
        exe.addLibraryPath(.{ .cwd_relative = "target/release" });
        exe.linkSystemLibrary("aegis_pep");
    } else |_| {
        std.debug.print("WARNING: target/release/aegis_pep.dll.lib not found; run `cargo build --release` first\n", .{});
    }

    // ----- Run Step -----
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run AEGIS NIDS");
    run_step.dependOn(&run_cmd.step);

    // ----- Tests -----
    const tests = b.addTest(.{
        .root_source_file = b.path("src/all_tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    tests.linkLibC();

    // Windows system libs used by test modules (ETW via tdh)
    tests.linkSystemLibrary("tdh");
    tests.linkSystemLibrary("advapi32");
    tests.linkSystemLibrary("ntdll");

    // Native helper DLLs (aegis_etw_helper / aegis_fim_helper).
    // Real builds come from CMake; for unit tests we link the zig cc stubs.
    if (std.fs.cwd().access("target/helpers/aegis_etw_helper.lib", .{})) |_| {
        tests.addLibraryPath(.{ .cwd_relative = "target/helpers" });
        tests.linkSystemLibrary("aegis_etw_helper");
        tests.linkSystemLibrary("aegis_fim_helper");
    } else |_| {
        std.debug.print("WARNING: target/helpers/aegis_*_helper.lib not found; build test stubs via zig cc\n", .{});
    }

    // Rust PEP import library (pep_bindings.zig is reached by unit tests
    // through the policy stub, so the tests artifact must resolve -laegis_pep).
    if (std.fs.cwd().access("target/release/aegis_pep.dll.lib", .{})) |_| {
        std.fs.cwd().copyFile(
            "target/release/aegis_pep.dll.lib",
            std.fs.cwd(),
            "target/release/aegis_pep.lib",
            .{},
        ) catch {};
        tests.addLibraryPath(.{ .cwd_relative = "target/release" });
        tests.linkSystemLibrary("aegis_pep");
    } else |_| {
        std.debug.print("WARNING: target/release/aegis_pep.dll.lib not found for tests; run `cargo build --release` first\n", .{});
    }

    const run_tests = b.addRunArtifact(tests);
    run_tests.addPathDir(b.pathFromRoot("target/helpers"));
    run_tests.addPathDir(b.pathFromRoot("target/release"));
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);

    // ----- Fuzz target -----
    const fuzz = b.addExecutable(.{
        .name = "aegis_fuzz",
        .root_source_file = b.path("src/fuzz_entry.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(fuzz);
    const fuzz_step = b.step("fuzz", "Build fuzz targets");
    fuzz_step.dependOn(b.getInstallStep());
}
