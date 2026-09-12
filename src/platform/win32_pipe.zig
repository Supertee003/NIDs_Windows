//! Win32 named-pipe control plane for the AEGIS daemon.
//!
//! Extracted from main.zig. Contains the named-pipe FFI declarations,
//! the Everyone-read/write ACL construction, the JSON control request
//! handler (aegisctl protocol), and the blocking pipe server loop.

const std = @import("std");
const manifest = @import("../contract/runtime_manifest.zig");
const diag = @import("../core/diagnostics.zig");
const bridge_init = @import("../core/bridge_init.zig");
const state = @import("../pipeline/runtime_state.zig");
const rules = @import("../pipeline/rule_loader.zig");
const control = @import("../control.zig");

pub const control_pipe_name = "\\\\.\\pipe\\aegis_control";

pub fn runtimeHealthState(pep_ready: bool, bridge_ready: bool, wfp_ready: bool) []const u8 {
    return if (pep_ready and bridge_ready and wfp_ready) "RUNNING" else "DEGRADED";
}

const PIPE_ACCESS_DUPLEX: std.os.windows.DWORD = 0x00000003;
const PIPE_TYPE_BYTE_V: std.os.windows.DWORD = 0x00000000;
const PIPE_READMODE_BYTE_V: std.os.windows.DWORD = 0x00000000;
const PIPE_WAIT_V: std.os.windows.DWORD = 0x00000000;
const PIPE_UNLIMITED_INSTANCES: std.os.windows.DWORD = 255;
const CONTROL_PIPE_BUFFER_SIZE: std.os.windows.DWORD = 65536;

extern "kernel32" fn CreateNamedPipeW(
    lpName: [*:0]const u16,
    dwOpenMode: std.os.windows.DWORD,
    dwPipeMode: std.os.windows.DWORD,
    nMaxInstances: std.os.windows.DWORD,
    nOutBufferSize: std.os.windows.DWORD,
    nInBufferSize: std.os.windows.DWORD,
    nDefaultTimeOut: std.os.windows.DWORD,
    lpSecurityAttributes: ?*std.os.windows.SECURITY_ATTRIBUTES,
) std.os.windows.HANDLE;

extern "kernel32" fn ConnectNamedPipe(
    hNamedPipe: std.os.windows.HANDLE,
    lpOverlapped: ?*std.os.windows.OVERLAPPED,
) std.os.windows.BOOL;

extern "kernel32" fn DisconnectNamedPipe(hNamedPipe: std.os.windows.HANDLE) std.os.windows.BOOL;

// CTRL-002: process identity for the RUNTIME_CONTRACT.md §4.1 health payload.
extern "kernel32" fn GetCurrentProcessId() std.os.windows.DWORD;

extern "kernel32" fn CreateFileW(
    lpFileName: [*:0]const u16,
    dwDesiredAccess: std.os.windows.DWORD,
    dwShareMode: std.os.windows.DWORD,
    lpSecurityAttributes: ?*std.os.windows.SECURITY_ATTRIBUTES,
    dwCreationDisposition: std.os.windows.DWORD,
    dwFlagsAndAttributes: std.os.windows.DWORD,
    hTemplateFile: ?std.os.windows.HANDLE,
) std.os.windows.HANDLE;

const GENERIC_READ_V: std.os.windows.DWORD = 0x80000000;
const GENERIC_WRITE_V: std.os.windows.DWORD = 0x40000000;
const OPEN_EXISTING_V: std.os.windows.DWORD = 3;
const FILE_ATTRIBUTE_NORMAL_V: std.os.windows.DWORD = 0x80;

// --- Windows ACL construction (advapi32) ---
const SET_ACCESS_V: std.os.windows.DWORD = 0x00000001;
const NO_INHERITANCE_V: std.os.windows.DWORD = 0x00000000;
const TRUSTEE_IS_SID_V: std.os.windows.DWORD = 0x00000003;
const TRUSTEE_IS_UNKNOWN_V: std.os.windows.DWORD = 0x00000000;
const SECURITY_DESCRIPTOR_REVISION_V: std.os.windows.DWORD = 1;

const TRUSTEE = extern struct {
    pMultipleTrustee: ?*TRUSTEE,
    MultipleTrusteeOperation: std.os.windows.DWORD,
    TrusteeForm: std.os.windows.DWORD,
    TrusteeType: std.os.windows.DWORD,
    ptstrName: ?*anyopaque,
};

const EXPLICIT_ACCESS = extern struct {
    grfAccessPermissions: std.os.windows.DWORD,
    grfAccessMode: std.os.windows.DWORD,
    grfInheritance: std.os.windows.DWORD,
    Trustee: TRUSTEE,
};

const SECURITY_DESCRIPTOR = extern struct {
    Revision: u8,
    Sbz1: u8,
    Control: u16,
    Owner: ?*anyopaque,
    Group: ?*anyopaque,
    Sacl: ?*anyopaque,
    Dacl: ?*anyopaque,
};

extern "advapi32" fn ConvertStringSidToSidW(lpStringSid: [*:0]const u16, sid: *?*anyopaque) std.os.windows.BOOL;
extern "advapi32" fn SetEntriesInAclW(
    cCountOfExplicitEntries: std.os.windows.DWORD,
    pListOfExplicitEntries: ?*const EXPLICIT_ACCESS,
    oldAcl: ?*anyopaque,
    newAcl: *?*anyopaque,
) std.os.windows.BOOL;
extern "advapi32" fn InitializeSecurityDescriptor(sd: *SECURITY_DESCRIPTOR, dwRevision: std.os.windows.DWORD) std.os.windows.BOOL;
extern "advapi32" fn SetSecurityDescriptorDacl(
    sd: *SECURITY_DESCRIPTOR,
    bDaclPresent: std.os.windows.BOOL,
    dacl: ?*anyopaque,
    bDaclDefaulted: std.os.windows.BOOL,
) std.os.windows.BOOL;

fn utf16zFromSlice(a: std.mem.Allocator, s: []const u8) ![*:0]const u16 {
    const buf = try a.alloc(u16, s.len + 1);
    const n = std.unicode.utf8ToUtf16Le(buf[0..s.len], s) catch return error.InvalidUtf8;
    std.debug.assert(n == s.len);
    buf[s.len] = 0;
    return @ptrCast(buf);
}

fn sendResponse(a: std.mem.Allocator, pipe: std.os.windows.HANDLE, ok: bool, data_body: ?[]const u8) void {
    const full = if (data_body) |body|
        std.fmt.allocPrint(a, "{{\"ok\":{},\"data\":{s}}}", .{ ok, body }) catch return
    else
        std.fmt.allocPrint(a, "{{\"ok\":{}}}", .{ok}) catch return;
    _ = std.os.windows.WriteFile(pipe, full, null) catch {};
}

fn handleControlRequest(a: std.mem.Allocator, pipe: std.os.windows.HANDLE, payload: []const u8, caps: *const manifest.Capability, start_ns: i128) bool {
    // P0.4: Use the new control protocol dispatch
    var auth = control.authorization.Authorizer{};
    var ctx = control.handler_registry.HandlerContext{
        .start_ns = start_ns,
        .request_id = @as(u64, @intCast(state.g_pipeline_audit_id)),
        .caller_role = auth.getLocalRole(),
        .caller_pid = @as(u32, @intCast(GetCurrentProcessId())),
        .caps = caps,
    };
    state.g_pipeline_audit_id +|= 1;
    const result = control.handler_registry.dispatch(a, pipe, payload, &ctx, &auth, &control.audit.g_audit);
    return result.shutdown;
}

pub fn serveWindowsPipe(caps: *const manifest.Capability, start_ns: i128) !void {
    // P0.4: Initialize the command handler registry
    control.handler_registry.initHandlers();
    diag.info("control plane: {d} command handlers registered", .{control.handler_registry.g_handler_count});
    const w = std.os.windows;
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const pipe_name_z = try utf16zFromSlice(arena.allocator(), control_pipe_name);

    // Grant Everyone read/write on the pipe: service runs as SYSTEM and
    // operator clients (aegisctl) run as ordinary users.
    var sa = w.SECURITY_ATTRIBUTES{
        .nLength = @sizeOf(w.SECURITY_ATTRIBUTES),
        .lpSecurityDescriptor = null,
        .bInheritHandle = 0,
    };
    var sid: ?*anyopaque = null;
    var acl: ?*anyopaque = null;
    var sd: SECURITY_DESCRIPTOR = undefined;
    defer if (sid != null) w.LocalFree(sid.?);
    defer if (acl != null) w.LocalFree(acl.?);
    const world_sid_z = "S-1-1-0";
    const world_buf = try arena.allocator().alloc(u16, world_sid_z.len + 1);
    _ = std.unicode.utf8ToUtf16Le(world_buf[0..world_sid_z.len], world_sid_z) catch unreachable;
    world_buf[world_sid_z.len] = 0;
    if (ConvertStringSidToSidW(@ptrCast(world_buf), &sid) != 0) {
        if (sid) |s| {
            var ea: EXPLICIT_ACCESS = .{
                .grfAccessPermissions = GENERIC_READ_V | GENERIC_WRITE_V,
                .grfAccessMode = SET_ACCESS_V,
                .grfInheritance = NO_INHERITANCE_V,
                .Trustee = .{
                    .pMultipleTrustee = null,
                    .MultipleTrusteeOperation = 0,
                    .TrusteeForm = TRUSTEE_IS_SID_V,
                    .TrusteeType = TRUSTEE_IS_UNKNOWN_V,
                    .ptstrName = s,
                },
            };
            if (SetEntriesInAclW(1, &ea, null, &acl) != 0) {
                if (InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION_V) != 0) {
                    if (SetSecurityDescriptorDacl(&sd, 1, acl, 0) != 0) {
                        sa.lpSecurityDescriptor = &sd;
                    }
                }
            }
        }
    }

    const pipe = CreateNamedPipeW(
        pipe_name_z,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE_V | PIPE_READMODE_BYTE_V | PIPE_WAIT_V,
        PIPE_UNLIMITED_INSTANCES,
        CONTROL_PIPE_BUFFER_SIZE,
        CONTROL_PIPE_BUFFER_SIZE,
        0,
        if (sa.lpSecurityDescriptor != null) &sa else null,
    );
    if (pipe == w.INVALID_HANDLE_VALUE) {
        diag.err("control pipe CreateNamedPipeW failed", .{});
        return;
    }
    defer _ = w.CloseHandle(pipe);
    diag.info("control pipe ready at {s}", .{control_pipe_name});

    while (!state.g_stop_requested.load(.acquire)) {
        const ok = ConnectNamedPipe(pipe, null);
        if (ok == 0) {
            if (w.kernel32.GetLastError() != .PIPE_CONNECTED) {
                std.time.sleep(100 * std.time.ns_per_ms);
                continue;
            }
        }

        var conn_arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer conn_arena.deinit();
        const a = conn_arena.allocator();

        var buf: [CONTROL_PIPE_BUFFER_SIZE]u8 = undefined;
        const n = w.ReadFile(pipe, buf[0..], null) catch 0;

        var shutdown = false;
        if (n > 0) {
            shutdown = handleControlRequest(a, pipe, buf[0..n], caps, start_ns);
        }

        _ = DisconnectNamedPipe(pipe);
        if (shutdown or state.g_stop_requested.load(.acquire)) break;
        std.time.sleep(20 * std.time.ns_per_ms);
    }
}

/// Wake the control pipe server so a blocking ConnectNamedPipe returns
/// promptly on shutdown (used by the SCM stop handler).
pub fn wakeControlPipe() void {
    var scratch: [128]u16 = undefined;
    const n = std.unicode.utf8ToUtf16Le(scratch[0..100], control_pipe_name) catch return;
    scratch[n] = 0;
    const name_z: [*:0]const u16 = @ptrCast(&scratch);
    const h = CreateFileW(name_z, GENERIC_READ_V | GENERIC_WRITE_V, 0, null, OPEN_EXISTING_V, FILE_ATTRIBUTE_NORMAL_V, null);
    if (h != std.os.windows.INVALID_HANDLE_VALUE) {
        _ = std.os.windows.CloseHandle(h);
    }
}

test "runtimeHealthState requires enforcement dependencies" {
    try std.testing.expectEqualStrings("RUNNING", runtimeHealthState(true, true, true));
    try std.testing.expectEqualStrings("DEGRADED", runtimeHealthState(false, true, true));
    try std.testing.expectEqualStrings("DEGRADED", runtimeHealthState(true, false, true));
    try std.testing.expectEqualStrings("DEGRADED", runtimeHealthState(true, true, false));
}
