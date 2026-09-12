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
    const parsed = std.json.parseFromSlice(std.json.Value, a, payload, .{}) catch {
        sendResponse(a, pipe, false, null);
        return false;
    };
    const root = parsed.value;
    if (root != .object) {
        sendResponse(a, pipe, false, null);
        return false;
    }
    const cmd_val = root.object.get("command") orelse root.object.get("op") orelse {
        sendResponse(a, pipe, false, null);
        return false;
    };
    if (cmd_val != .string) {
        sendResponse(a, pipe, false, null);
        return false;
    }
    const cmd_raw = cmd_val.string;
    // Map op-style commands to internal command names
    const cmd = if (std.mem.eql(u8, cmd_raw, "HEALTH")) "health.check" else cmd_raw;
    const uptime_sec: i64 = @intCast(@divTrunc(std.time.nanoTimestamp() - start_ns, std.time.ns_per_s));

    // Control command audit — log every operator command
    diag.info("CONTROL_AUDIT cmd={s} payload_len={d}", .{ cmd, payload.len });

    if (std.mem.eql(u8, cmd, "status")) {
        // Status response bound to real runtime metrics.
        // CTRL-001: `state` uses the closed set from RUNTIME_CONTRACT.md §2.
        // `degraded` and `wfp_available` report real subsystem state, not
        // build-time capability flags.
        const body = std.fmt.allocPrint(a,
            \\{{"version":"5.0.0","state":"RUNNING","uptime_sec":{},"packets_captured":{},"flows_active":{},"incidents_open":{},"watchdog_alerts":{},"degraded":{},"etw_enabled":{},"fim_enabled":{},"wfp_available":{},"nids_version":"5.0.0","rules_loaded":{},"pipeline_processed":{},"pipeline_detections":{},\"audit_id\":{}}}
        , .{
            uptime_sec,
            @as(u32, @intCast(diag.metrics.packets_captured.get())),
            @as(u32, @intCast(diag.metrics.flows_active.get())),
            state.g_incidents_open,
            @as(u32, @intCast(diag.metrics.errors.get())),
            !bridge_init.allActive(),
            caps.has_etw_realtime,
            caps.has_fim,
            bridge_init.status().wfp_ioctl,
            state.g_rules_loaded,
            state.g_pipeline_events_processed,
            state.g_pipeline_detections,
            state.g_pipeline_audit_id,
        }) catch return false;
        sendResponse(a, pipe, true, body);
        return false;
    }

    if (std.mem.eql(u8, cmd, "metrics.snapshot")) {
        // Metrics bound to real diagnostics state
        const body = std.fmt.allocPrint(a,
            \\{{"uptime_sec":{},"rules_loaded":{},"packets_captured":{},"flows_active":{},"incidents_open":{},"etw_enabled":{},"fim_enabled":{},"signatures_matched":{},"anomalies_detected":{},"blocks_issued":{},"federation_messages":{},"errors":{}}}
        , .{
            uptime_sec,
            state.g_rules_loaded,
            @as(u32, @intCast(diag.metrics.packets_captured.get())),
            @as(u32, @intCast(diag.metrics.flows_active.get())),
            state.g_incidents_open,
            caps.has_etw_realtime,
            caps.has_fim,
            state.g_pipeline_detections,
            @as(u32, @intCast(diag.metrics.anomalies_detected.get())),
            @as(u32, @intCast(diag.metrics.blocks_issued.get())),
            @as(u32, @intCast(diag.metrics.federation_messages.get())),
            @as(u32, @intCast(diag.metrics.errors.get())),
        }) catch return false;
        sendResponse(a, pipe, true, body);
        return false;
    }

    if (std.mem.eql(u8, cmd, "rules.list")) {
        const body = std.fmt.allocPrint(a, "{{\"rules_loaded\":{},\"engine\":\"aho_corasick\"}}", .{state.g_rules_loaded}) catch return false;
        sendResponse(a, pipe, true, body);
        return false;
    }

    if (std.mem.eql(u8, cmd, "rules.reload")) {
        // Actually reload Rules.json into a fresh AC automaton
        const new_count = rules.reloadRules();
        const body = std.fmt.allocPrint(a, "{{\"rules_loaded\":{},\"status\":\"reloaded\"}}", .{new_count}) catch return false;
        sendResponse(a, pipe, true, body);
        return false;
    }

    if (std.mem.eql(u8, cmd, "incidents.list")) {
        // Real incident data from ThreatTracker via pipeline globals
        const body = std.fmt.allocPrint(a, "{{\"incidents_total\":{},\"incidents_open\":{},\"detections\":{},\"policies_matched\":{},\"correlations\":{}}}", .{
            state.g_incidents_total,
            state.g_incidents_open,
            state.g_pipeline_detections,
            state.g_pipeline_policies_matched,
            state.g_pipeline_correlations,
        }) catch return false;
        sendResponse(a, pipe, true, body);
        return false;
    }

    if (std.mem.eql(u8, cmd, "federation.status")) {
        // Federation status: standalone mode (multi-node not yet implemented)
        sendResponse(a, pipe, true, "{\"enabled\":false,\"self_id\":1,\"role\":\"standalone\",\"leader_id\":1,\"node_count\":1,\"heartbeat_ms\":1000}");
        return false;
    }

    if (std.mem.eql(u8, cmd, "version")) {
        // CTRL-001: version command returns component versions from runtime
        sendResponse(a, pipe, true, "{\"core\":\"5.0.0\",\"nose\":\"2.1.0\",\"shield\":\"0.1.0\",\"pep\":\"1.0.0\"}");
        return false;
    }

    if (std.mem.eql(u8, cmd, "health.check")) {
        // CTRL-002: RUNTIME_CONTRACT.md §4.1 payload. Contract fields (`state`,
        // `pid`, `uptime_ms`, `last_event_ms`, `counters`, `deps`) carry real
        // runtime data. `checks[].ok` reflects the live in-process subsystem
        // flags for every bridge-managed subsystem; npcap/etw/fim are marked
        // `capability-only` because their live state is not yet instrumented
        // (tracked as P0-8).
        const elapsed_ms: u64 = @intCast(@divTrunc(std.time.nanoTimestamp() - start_ns, std.time.ns_per_ms));
        const bs = bridge_init.status();
        const pid: u32 = GetCurrentProcessId();
        const now_ms: i64 = std.time.milliTimestamp();
        const last_event_ms: i64 = if (state.g_last_event_ms == 0) 0 else now_ms - state.g_last_event_ms;
        const health_state = runtimeHealthState(state.g_pep_available, bs.cpp_bridge, bs.wfp_ioctl);
        const body = std.fmt.allocPrint(a,
            \\{{"component":"core","state":"{s}","pid":{},"uptime_ms":{},"last_event_ms":{},"degraded":{},"deps":[{{"name":"bridge","state":"{s}","required":true}},{{"name":"pep","state":"{s}","required":true}}],"counters":{{"in_events":{},"out_events":{},"errors":{},"dropped":{}}},"checks":[{{"name":"core","ok":true,"detail":"initialized"}},{{"name":"wfp","ok":{},"detail":"{s}"}},{{"name":"shield","ok":{},"detail":"{s}"}},{{"name":"cpp_bridge","ok":{},"detail":"{s}"}},{{"name":"brain","ok":{},"detail":"{s}"}},{{"name":"npcap","ok":{},"detail":"capability-only"}},{{"name":"etw","ok":{},"detail":"capability-only"}},{{"name":"fim","ok":{},"detail":"capability-only"}}]}}
        , .{
            health_state,
            pid,
            elapsed_ms,
            last_event_ms,
            !bridge_init.allActive(),
            if (bs.cpp_bridge) "RUNNING" else "STOPPED",
            if (state.g_pep_available) "RUNNING" else "STOPPED",
            state.g_pipeline_events_processed,
            diag.metrics.events_emitted.get(),
            diag.metrics.errors.get(),
            state.g_queue_drops,
            bs.wfp_ioctl,    if (bs.wfp_ioctl) "ioctl-connected" else "driver-unavailable",
            bs.rust_shield,  if (bs.rust_shield) "loaded" else "missing-fail-closed",
            bs.cpp_bridge,   if (bs.cpp_bridge) "dll-loaded" else "dll-missing",
            bs.udp_brain,    if (bs.udp_brain) "udp-9999" else "unavailable",
            caps.has_npcap,
            caps.has_etw_realtime,
            caps.has_fim,
        }) catch return false;
        sendResponse(a, pipe, true, body);
        return false;
    }

    if (std.mem.eql(u8, cmd, "daemon.shutdown")) {
        state.g_stop_requested.store(true, .release);
        bridge_init.requestShutdown(); // drain bridge/sensor threads
        sendResponse(a, pipe, true, null);
        return true;
    }

    sendResponse(a, pipe, false, null);
    return false;
}

pub fn serveWindowsPipe(caps: *const manifest.Capability, start_ns: i128) !void {
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
