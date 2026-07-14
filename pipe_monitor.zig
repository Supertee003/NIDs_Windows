const std = @import("std");
const nids_analyze = @import("nids_analyze.zig");

// =====================================================================
// pipe_monitor.zig
// ---------------------------------------------------------------------
// Monitor named pipe creation/connection ของโปรเซสอื่นในระบบ
//
// วิธีการ (เลือกใช้วิธีง่าย = polling, no hook ต้องการ):
//   1. Poll directory `\\.\pipe\` ทุก 2 วินาที (FindFirstFile/FindNextFile)
//   2. เก็บรายชื่อ pipe ที่เคยเห็นใน `known_pipes` set
//   3. เมื่อเจอ pipe ใหม่ → สร้าง EventHeader (PIPE_MONITOR type) + payload
//      ใส่ pipe name → เรียก inspect_event()
//
// Use cases:
//   - ตรวจจับ Cobalt Strike default pipes (\\MSSE-*, \\status_*, \\postex_*)
//   - ตรวจจับ PsExec service pipes (\\PSEXESVC)
//   - ตรวจจับ lateral movement tools ที่ใช้ named pipe
//
// TODO (ขั้นสูง):
//   - ใช้ ETW (Event Tracing for Windows) เพื่อดัก pipe creation real-time
//   - หรือใช้ kernel minifilter ที่ดัก IRP_MJ_CREATE บน \\Device\\NamedPipe
// =====================================================================

const win = std.os.windows;

// --- Windows API externs ---
extern "kernel32" fn FindFirstFileA(
    lpFileName: [*:0]const u8,
    lpFindFileData: *WIN32_FIND_DATAA,
) win.HANDLE;

extern "kernel32" fn FindNextFileA(
    hFindFile: win.HANDLE,
    lpFindFileData: *WIN32_FIND_DATAA,
) win.BOOL;

extern "kernel32" fn FindClose(hFindFile: win.HANDLE) win.BOOL;

extern "kernel32" fn GetLastError() win.Win32Error;

const WIN32_FIND_DATAA = extern struct {
    dwFileAttributes: u32,
    ftCreationTime: [2]u32, // FILETIME = 2x u32
    ftLastAccessTime: [2]u32,
    ftLastWriteTime: [2]u32,
    nFileSizeHigh: u32,
    nFileSizeLow: u32,
    dwReserved0: u32,
    dwReserved1: u32,
    cFileName: [260]u8, // MAX_PATH
    cAlternateFileName: [14]u8,
};

const INVALID_HANDLE_VALUE = win.INVALID_HANDLE_VALUE;
const POLL_INTERVAL_NS: u64 = 2 * std.time.ns_per_s;
const PIPE_DIR_QUERY = "\\\\.\\pipe\\*";

/// สร้าง pipe full-path จาก name: "\\.\pipe\<name>"
fn build_pipe_path(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "\\\\.{s}\\{s}", .{ "\\pipe", name });
}

/// ส่ง PIPE_MONITOR event ไปยัง inspect_event
fn emit_pipe_event(allocator: std.mem.Allocator, pipe_path: []const u8) void {
    var header = std.mem.zeroes(nids_analyze.EventHeader);
    header.event_type = @intFromEnum(nids_analyze.EventSource.PIPE_MONITOR);
    header.event_size = @intCast(nids_analyze.EVENT_HEADER_SIZE + pipe_path.len);
    header.timestamp = @intCast(std.time.nanoTimestamp());
    header.path_offset = 0; // path เริ่มที่ต้น payload
    header.path_length = @intCast(@min(pipe_path.len, 65535));
    header.operation = 0; // CREATE

    _ = nids_analyze.inspect_event(&header, pipe_path) catch |err| {
        std.debug.print("[PIPE-MON] inspect_event error: {}\n", .{err});
    };
    _ = allocator; // future use: when we want to dupe pipe_path
}

pub fn run(allocator: std.mem.Allocator) void {
    std.debug.print("[PIPE-MON] Thread started. Polling \\\\.{s}\\ every 2s...\n", .{"\\pipe"});

    var known_pipes = std.StringHashMap(void).init(allocator);
    defer {
        var it = known_pipes.keyIterator();
        while (it.next()) |k| allocator.free(k.*);
        known_pipes.deinit();
    }

    while (true) {
        var find_data: WIN32_FIND_DATAA = undefined;

        const hFind = FindFirstFileA(PIPE_DIR_QUERY, &find_data);
        if (hFind == INVALID_HANDLE_VALUE) {
            std.debug.print("[PIPE-MON] FindFirstFile failed. Retrying in 5s...\n", .{});
            std.time.sleep(5 * std.time.ns_per_s);
            continue;
        }
        defer _ = FindClose(hFind);

        // วนลูปไฟล์ทั้งหมดใน \\.\pipe\
        while (true) {
            // ดึงชื่อ pipe (null-terminated string)
            const name_slice = std.mem.sliceTo(&find_data.cFileName, 0);
            if (name_slice.len == 0) break;

            // ข้าม "." และ ".."
            if (std.mem.eql(u8, name_slice, ".") or std.mem.eql(u8, name_slice, "..")) {
                if (FindNextFileA(hFind, &find_data) == 0) break;
                continue;
            }

            // สร้าง full path: \\.\pipe\<name>
            const pipe_path = build_pipe_path(allocator, name_slice) catch {
                if (FindNextFileA(hFind, &find_data) == 0) break;
                continue;
            };

            // ถ้าเป็น pipe ใหม่ → emit event
            if (!known_pipes.contains(pipe_path)) {
                const owned_path = allocator.dupe(u8, pipe_path) catch {
                    allocator.free(pipe_path);
                    if (FindNextFileA(hFind, &find_data) == 0) break;
                    continue;
                };
                known_pipes.put(owned_path, {}) catch {};

                std.debug.print("[PIPE-MON] New pipe detected: {s}\n", .{pipe_path});
                emit_pipe_event(allocator, pipe_path);
            }

            allocator.free(pipe_path);

            // ไป pipe ถัดไป
            if (FindNextFileA(hFind, &find_data) == 0) break;
        }

        std.time.sleep(POLL_INTERVAL_NS);
    }
}
