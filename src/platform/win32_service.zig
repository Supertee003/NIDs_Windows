//! Windows Service (SCM) integration for the AEGIS daemon.
//!
//! Extracted from main.zig. Owns the service control handler, status
//! reporting, and the SCM dispatch decision made at process start.
//! The actual daemon body lives in daemon.zig; this module only wires
//! the service lifecycle around it.

const std = @import("std");
const builtin = @import("builtin");
const state = @import("../pipeline/runtime_state.zig");
const daemon = @import("../daemon.zig");
const diag = @import("../core/diagnostics.zig");
const bridge_init = @import("../core/bridge_init.zig");
const control = @import("win32_pipe.zig");

const SERVICE_WIN32_OWN_PROCESS: std.os.windows.DWORD = 0x00000010;
const SERVICE_STOPPED: std.os.windows.DWORD = 0x00000001;
const SERVICE_START_PENDING: std.os.windows.DWORD = 0x00000002;
const SERVICE_STOP_PENDING: std.os.windows.DWORD = 0x00000003;
const SERVICE_RUNNING: std.os.windows.DWORD = 0x00000004;
const SERVICE_ACCEPT_STOP: std.os.windows.DWORD = 0x00000001;
const SERVICE_CONTROL_STOP: std.os.windows.DWORD = 0x00000001;
const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: u32 = 1063;
const NO_ERROR: u32 = 0;

const SERVICE_STATUS = extern struct {
    dwServiceType: std.os.windows.DWORD,
    dwCurrentState: std.os.windows.DWORD,
    dwControlsAccepted: std.os.windows.DWORD,
    dwWin32ExitCode: std.os.windows.DWORD,
    dwServiceSpecificExitCode: std.os.windows.DWORD,
    dwCheckPoint: std.os.windows.DWORD,
    dwWaitHint: std.os.windows.DWORD,
};

const SERVICE_TABLE_ENTRYW = extern struct {
    lpServiceName: ?[*:0]const u16,
    lpServiceProc: ?*const fn (std.os.windows.DWORD, [*][*:0]u16) callconv(.C) void,
};

extern "advapi32" fn StartServiceCtrlDispatcherW(lpServiceTable: [*]const SERVICE_TABLE_ENTRYW) std.os.windows.BOOL;
extern "advapi32" fn RegisterServiceCtrlHandlerW(lpServiceName: [*:0]const u16, lpHandlerProc: ?*const fn (std.os.windows.DWORD) callconv(.C) std.os.windows.DWORD) ?*anyopaque;
extern "advapi32" fn SetServiceStatus(hServiceStatus: ?*anyopaque, lpServiceStatus: *SERVICE_STATUS) std.os.windows.BOOL;

var g_svc_handle: ?*anyopaque = null;
var g_svc_status = SERVICE_STATUS{
    .dwServiceType = SERVICE_WIN32_OWN_PROCESS,
    .dwCurrentState = SERVICE_STOPPED,
    .dwControlsAccepted = SERVICE_ACCEPT_STOP,
    .dwWin32ExitCode = NO_ERROR,
    .dwServiceSpecificExitCode = 0,
    .dwCheckPoint = 0,
    .dwWaitHint = 0,
};

pub fn setServiceStatus(state_val: std.os.windows.DWORD, checkpoint: std.os.windows.DWORD) void {
    g_svc_status.dwCurrentState = state_val;
    g_svc_status.dwCheckPoint = checkpoint;
    if (g_svc_handle != null) {
        _ = SetServiceStatus(g_svc_handle, &g_svc_status);
    }
}

fn serviceControlHandler(dwControl: std.os.windows.DWORD) callconv(.C) std.os.windows.DWORD {
    switch (dwControl) {
        SERVICE_CONTROL_STOP => {
            state.g_stop_requested.store(true, .release);
            bridge_init.requestShutdown(); // drain bridge/sensor threads
            setServiceStatus(SERVICE_STOP_PENDING, 1);
            control.wakeControlPipe();
            return NO_ERROR;
        },
        else => return NO_ERROR,
    }
}

fn serviceMain(dwArgc: std.os.windows.DWORD, lpArgv: [*][*:0]u16) callconv(.C) void {
    _ = dwArgc;
    _ = lpArgv;
    var name_buf: [32]u16 = undefined;
    const name = "AegisNids";
    const n = std.unicode.utf8ToUtf16Le(name_buf[0..name.len], name) catch return;
    name_buf[n] = 0;
    const handle = RegisterServiceCtrlHandlerW(@ptrCast(&name_buf), serviceControlHandler);
    if (handle == null) return;
    g_svc_handle = handle;
    setServiceStatus(SERVICE_START_PENDING, 0);
    defer setServiceStatus(SERVICE_STOPPED, 0);
    daemon.runDaemon() catch |err| {
        diag.err("service main error: {}", .{err});
    };
}

/// Process entry decision: dispatch to SCM when launched as a service,
/// otherwise fall back to console/foreground daemon mode.
pub fn mainEntry() !void {
    if (builtin.os.tag == .windows) {
        const w = std.os.windows;
        const empty_name: [1]u16 = .{0};
        var table: [2]SERVICE_TABLE_ENTRYW = .{
            .{ .lpServiceName = @ptrCast(&empty_name), .lpServiceProc = serviceMain },
            .{ .lpServiceName = null, .lpServiceProc = null },
        };
        const rc = StartServiceCtrlDispatcherW(&table);
        if (rc != 0) {
            // SCM ran us as a service; dispatcher only returns after stop.
            return;
        }
        const err = w.kernel32.GetLastError();
        if (err != @as(w.Win32Error, @enumFromInt(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT))) {
            diag.err("StartServiceCtrlDispatcherW failed: {}", .{@intFromEnum(err)});
            return;
        }
    }
    // Not launched by the service controller -> console/foreground mode.
    try daemon.runDaemon();
}
