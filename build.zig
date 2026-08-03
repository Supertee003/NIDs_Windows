const std = @import("std"); // นำเข้าไลบรารีมาตรฐานของ Zig

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{}); // กำหนด Target OS (เช่น Windows x86_64)
    const optimize = b.standardOptimizeOption(.{}); // กำหนดการ Optimize โค้ด

    const exe = b.addExecutable(.{
        .name = "aegis-nids", // ชื่อไฟล์ .exe ที่จะได้
        .root_source_file = b.path("nids_main.zig"), // ไฟล์เริ่มต้น (เปลี่ยนจาก .root_module กลับมาเป็นแบบ 0.13.0)
        .target = target, // ใส่ target ลงใน executable options โดยตรง
        .optimize = optimize, // ใส่ optimize ลงใน executable options โดยตรง
    });

    b.installArtifact(exe); // สั่งติดตั้งไฟล์ที่ build เสร็จแล้วลงในโฟลเดอร์ zig-out/bin
    exe.linkLibC();

    // Rust FFI (sec_monitor.dll) — Tier-0 Memory Safety Shield
    exe.addLibraryPath(.{ .cwd_relative = "target/release" });
    exe.linkSystemLibrary("sec_monitor");

    // C++ IPC Bridge (aegis_ipc.dll) — เชื่อม Zig Core ↔ Bridge ↔ Dashboard
    exe.addLibraryPath(.{ .cwd_relative = "build/Release" });
    exe.linkSystemLibrary("aegis_ipc");

    const run_cmd = b.addRunArtifact(exe); // สร้างคำสั่งสำหรับรันโปรแกรม
    run_cmd.step.dependOn(b.getInstallStep()); // กำหนดว่าต้อง build เสร็จก่อนถึงจะรันได้

    const run_step = b.step("run", "Run the app"); // สร้าง step ชื่อ "run" สำหรับใช้คำสั่ง zig build run
    run_step.dependOn(&run_cmd.step); // เชื่อมโยง step run กับคำสั่งรัน
}
