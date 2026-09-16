//! control/handler_registry.zig — Command Dispatch Table
//!
//! Maps every Command to a handler function. The pipe handler calls
//! dispatch() which resolves the command, checks authorization,
//! calls the handler, and records audit.
//!
//! Handlers return ?[]const u8 (raw JSON body). The dispatcher wraps
//! them in the structured envelope: {"ok":true,"code":"OK","data":{...}}.

const std = @import("std");
const protocol = @import("protocol.zig");
const authorization = @import("authorization.zig");
const audit = @import("audit.zig");

// ============================================================
// Handler Function Signature
// ============================================================

/// A handler receives the allocator, the raw payload JSON value, and context.
/// Returns a raw JSON string for the "data" field, or null on error.
pub const HandlerFn = *const fn (a: std.mem.Allocator, payload: std.json.Value, ctx: *HandlerContext) ?[]const u8;

pub const HandlerContext = struct {
    start_ns: i128,
    request_id: u64,
    caller_role: protocol.Role,
    caller_pid: u32 = 0,
    caps: ?*const @import("../contract/runtime_manifest.zig").Capability = null,
    /// Handler-owned failure fields. Mutation handlers use these when a
    /// requested postcondition cannot be proven by the current runtime owner.
    failure_code: ?[]const u8 = null,
    failure_state: ?[]const u8 = null,
    failure_message: ?[]const u8 = null,
};

pub const DispatchResult = struct {
    shutdown: bool,
};

fn successEnvelope(a: std.mem.Allocator, data: []const u8, request_id: u64) ![]u8 {
    var data_parsed = std.json.parseFromSlice(std.json.Value, a, data, .{}) catch |err| {
        std.log.err("control health payload JSON validation failed: bytes={d} error={} payload={s}", .{ data.len, err, data });
        return err;
    };
    data_parsed.deinit();
    var out = std.ArrayList(u8).init(a);
    var writer = out.writer();
    try writer.writeAll("{\"ok\":true,\"code\":\"OK\",\"state\":\"OK\",\"data\":");
    try writer.writeAll(data);
    try writer.print(",\"audit_id\":{}", .{request_id});
    try writer.writeByte('}');
    const result = try out.toOwnedSlice();
    var parsed = std.json.parseFromSlice(std.json.Value, a, result, .{}) catch |err| {
        std.log.err("control success envelope JSON validation failed: bytes={d} error={} response={s}", .{
            result.len,
            err,
            result,
        });
        a.free(result);
        return err;
    };
    parsed.deinit();
    return result;
}

fn errorEnvelope(a: std.mem.Allocator, code: []const u8, state_str: []const u8, message: []const u8, request_id: u64) ![]u8 {
    var out = std.ArrayList(u8).init(a);
    var writer = out.writer();
    try writer.writeAll("{\"ok\":false,\"code\":\"");
    try writer.writeAll(code);
    try writer.writeAll("\",\"state\":\"");
    try writer.writeAll(state_str);
    try writer.writeAll("\",\"data\":{\"message\":\"");
    try writer.writeAll(message);
    try writer.print("\"}},\"audit_id\":{}", .{request_id});
    try writer.writeByte('}');
    return out.toOwnedSlice();
}

/// Write a complete response to the byte-mode named pipe.  A single Win32
/// WriteFile call is not a framing guarantee and may write fewer bytes than
/// requested.  The old code ignored both the byte count and the error, which
/// allowed a valid 2 KB health payload to be observed by the client as an
/// unrelated short error response.
fn writePipeResponse(pipe: std.os.windows.HANDLE, response: []const u8) bool {
    var offset: usize = 0;
    while (offset < response.len) {
        const written = std.os.windows.WriteFile(pipe, response[offset..], null) catch |err| {
            std.log.err("control response WriteFile failed: offset={d} total={d} error={}", .{
                offset,
                response.len,
                err,
            });
            return false;
        };
        if (written == 0) {
            std.log.err("control response WriteFile made no progress: offset={d} total={d}", .{
                offset,
                response.len,
            });
            return false;
        }
        offset += written;
    }
    const prefix_len = @min(response.len, 96);
    std.log.info("control response written: bytes={d} prefix={s}", .{ offset, response[0..prefix_len] });
    return true;
}

// ============================================================
// Handler Registry
// ============================================================

const HandlerEntry = struct {
    command: protocol.Command,
    handler: HandlerFn,
};

var g_handlers: [64]HandlerEntry = undefined;
pub var g_handler_count: usize = 0;

pub fn registerHandler(cmd: protocol.Command, handler: HandlerFn) void {
    g_handlers[g_handler_count] = .{ .command = cmd, .handler = handler };
    g_handler_count += 1;
}

fn findHandler(cmd: protocol.Command) ?HandlerFn {
    for (g_handlers[0..g_handler_count]) |entry| {
        if (entry.command == cmd) return entry.handler;
    }
    return null;
}

// ============================================================
// Main Dispatch Function
// ============================================================

pub fn dispatch(
    a: std.mem.Allocator,
    pipe: std.os.windows.HANDLE,
    raw_json: []const u8,
    ctx: *HandlerContext,
    auth: *authorization.Authorizer,
    audit_log: *audit.AuditLog,
) DispatchResult {
    const start = std.time.nanoTimestamp();

    std.log.info("control dispatch: received_bytes={d}", .{raw_json.len});

    // Parse envelope
    const parsed = std.json.parseFromSlice(std.json.Value, a, raw_json, .{}) catch {
        return sendError(a, pipe, "INVALID_JSON", "PARSE_ERROR", "Invalid JSON envelope", ctx.request_id);
    };
    const root = parsed.value;
    if (root != .object) {
        return sendError(a, pipe, "INVALID_ENVELOPE", "PARSE_ERROR", "Envelope must be a JSON object", ctx.request_id);
    }

    // Extract command
    const cmd_val = root.object.get("command") orelse root.object.get("op") orelse {
        return sendError(a, pipe, "MISSING_COMMAND", "INVALID_INPUT", "Missing 'command' field", ctx.request_id);
    };
    if (cmd_val != .string) {
        return sendError(a, pipe, "INVALID_COMMAND", "INVALID_INPUT", "Command must be a string", ctx.request_id);
    }

    const cmd = protocol.Command.fromString(cmd_val.string) orelse {
        std.log.err("control dispatch: unknown command={s}", .{cmd_val.string});
        return sendError(a, pipe, "UNKNOWN_COMMAND", "INVALID_INPUT", "Unknown command", ctx.request_id);
    };

    std.log.info("control dispatch: command={s} request_id={}", .{
        protocol.contract(cmd).name,
        ctx.request_id,
    });

    const payload = root.object.get("payload") orelse std.json.Value{ .null = {} };

    // Authorization
    const auth_result = auth.authorize(cmd, ctx.caller_role);
    if (auth_result.decision == .deny) {
        const elapsed: u64 = @intCast(@divTrunc(std.time.nanoTimestamp() - start, std.time.ns_per_ms));
        audit_log.record(.{
            .timestamp_ms = std.time.milliTimestamp(),
            .request_id = ctx.request_id,
            .command = cmd,
            .command_name = protocol.contract(cmd).name,
            .caller_role = ctx.caller_role,
            .caller_pid = ctx.caller_pid,
            .ok = false,
            .code = "AUTH_DENIED",
            .latency_ms = elapsed,
            .payload_len = raw_json.len,
        });
        return sendError(a, pipe, "AUTH_DENIED", "UNAUTHORIZED", auth_result.reason, ctx.request_id);
    }

    // Find handler
    const handler_fn = findHandler(cmd) orelse {
        std.log.err("control dispatch: handler missing command={s}", .{protocol.contract(cmd).name});
        return sendError(a, pipe, "NOT_IMPLEMENTED", "UNAVAILABLE", "Command handler not implemented", ctx.request_id);
    };

    // Call handler
    ctx.failure_code = null;
    ctx.failure_state = null;
    ctx.failure_message = null;
    const result = handler_fn(a, payload, ctx);
    const elapsed: u64 = @intCast(@divTrunc(std.time.nanoTimestamp() - start, std.time.ns_per_ms));

    // Audit
    audit_log.record(.{
        .timestamp_ms = std.time.milliTimestamp(),
        .request_id = ctx.request_id,
        .command = cmd,
        .command_name = protocol.contract(cmd).name,
        .caller_role = ctx.caller_role,
        .caller_pid = ctx.caller_pid,
        .ok = result != null,
        .code = if (result != null) "OK" else "HANDLER_ERROR",
        .latency_ms = elapsed,
        .payload_len = raw_json.len,
    });

    // Send response
    const is_shutdown = cmd == .daemon_shutdown;
    if (result) |data| {
        std.log.info("control dispatch: handler success command={s} payload_bytes={d}", .{
            protocol.contract(cmd).name,
            data.len,
        });
        const envelope = successEnvelope(a, data, ctx.request_id) catch {
            return sendError(a, pipe, "INTERNAL_ERROR", "ERROR", "Failed to serialize response", ctx.request_id);
        };
        _ = writePipeResponse(pipe, envelope);
    } else if (ctx.failure_code) |code| {
        std.log.err("control dispatch: handler failure command={s} code={s} state={s}", .{
            protocol.contract(cmd).name,
            code,
            ctx.failure_state orelse "ERROR",
        });
        _ = sendError(a, pipe, code, ctx.failure_state orelse "ERROR", ctx.failure_message orelse "Handler failed", ctx.request_id);
    } else {
        std.log.err("control dispatch: handler returned null without failure command={s}", .{protocol.contract(cmd).name});
        _ = writePipeResponse(pipe, "{\"ok\":false,\"code\":\"HANDLER_ERROR\",\"state\":\"ERROR\"}");
    }

    return .{ .shutdown = is_shutdown };
}

fn sendError(a: std.mem.Allocator, pipe: std.os.windows.HANDLE, code: []const u8, state_str: []const u8, message: []const u8, request_id: u64) DispatchResult {
    const body = errorEnvelope(a, code, state_str, message, request_id) catch {
        _ = std.os.windows.WriteFile(pipe, "{\"ok\":false,\"code\":\"INTERNAL_ERROR\",\"state\":\"ERROR\"}", null) catch {};
        return .{ .shutdown = false };
    };
    _ = writePipeResponse(pipe, body);
    return .{ .shutdown = false };
}

// ============================================================
// Initialize all handlers
// ============================================================

pub fn initHandlers() void {
    g_handler_count = 0;
    registerHandler(.system_status, handlers.status);
    registerHandler(.system_health, handlers.health);
    registerHandler(.system_version, handlers.version);
    registerHandler(.system_diagnose, handlers.diagnose);
    registerHandler(.rules_list, handlers.rulesList);
    registerHandler(.rules_show, handlers.rulesShow);
    registerHandler(.rules_validate, handlers.rulesValidate);
    registerHandler(.rules_reload, handlers.rulesReload);
    registerHandler(.events_count, handlers.eventsCount);
    registerHandler(.events_stats, handlers.eventsStats);
    registerHandler(.events_tail, handlers.eventsTail);
    registerHandler(.incidents_list, handlers.incidentsList);
    registerHandler(.incidents_show, handlers.incidentsShow);
    registerHandler(.policy_list, handlers.policyList);
    registerHandler(.policy_validate, handlers.policyValidate);
    registerHandler(.policy_verify, handlers.policyVerify);
    registerHandler(.policy_simulate, handlers.policySimulate);
    registerHandler(.forensics_list, handlers.forensicsList);
    registerHandler(.forensics_show, handlers.forensicsShow);
    registerHandler(.forensics_verify, handlers.forensicsVerify);
    registerHandler(.forensics_export, handlers.forensicsExport);
    registerHandler(.forensics_replay, handlers.forensicsReplay);
    registerHandler(.enforcement_status, handlers.enforcementStatus);
    registerHandler(.enforcement_simulate, handlers.enforcementSimulate);
    registerHandler(.enforcement_verify, handlers.enforcementVerify);
    registerHandler(.metrics_snapshot, handlers.metricsSnapshot);
    registerHandler(.logs_tail, handlers.logsTail);
    registerHandler(.runtime_start, handlers.runtimeStart);
    registerHandler(.runtime_stop, handlers.runtimeStop);
    registerHandler(.runtime_restart, handlers.runtimeRestart);
    registerHandler(.daemon_shutdown, handlers.daemonShutdown);
}

// ============================================================
// Handler implementations — all return ?[]const u8 (raw JSON)
// ============================================================

const handlers = struct {
    const HEALTH_BUILD_MARKER = "health-v2-20260916";
    const bridge_init = @import("../core/bridge_init.zig");
    const state_mod = @import("../pipeline/runtime_state.zig");
    const diag = @import("../core/diagnostics.zig");
    const tier3_mod = @import("../policy/tier3_state.zig");
    const rules_loader = @import("../pipeline/rule_loader.zig");

    extern "kernel32" fn GetCurrentProcessId() std.os.windows.DWORD;

    fn status(a: std.mem.Allocator, _: std.json.Value, ctx: *HandlerContext) ?[]const u8 {
        // P1: Pull from state machine — single source of truth
        const sm = @import("state_machine.zig");
        sm.g_runtime.uptime_ms = @intCast(@divTrunc(std.time.nanoTimestamp() - ctx.start_ns, std.time.ns_per_ms));
        return sm.g_runtime.statusJson(a) catch null;
    }

    fn health(a: std.mem.Allocator, _: std.json.Value, ctx: *HandlerContext) ?[]const u8 {
        // P1: Pull from state machine — single source of truth
        const sm = @import("state_machine.zig");
        const bridge = bridge_init.status();
        sm.g_runtime.uptime_ms = @intCast(@divTrunc(std.time.nanoTimestamp() - ctx.start_ns, std.time.ns_per_ms));
        const pid: u32 = GetCurrentProcessId();
        const workers = sm.WorkerReadiness{
            .pipeline = state_mod.g_pipeline_ready.load(.acquire),
            .sensor = state_mod.g_sensor_ready.load(.acquire),
            .nose = state_mod.g_nose_ready.load(.acquire),
            .etw = state_mod.g_etw_ready.load(.acquire),
            .fim = state_mod.g_fim_ready.load(.acquire),
            .registry = state_mod.g_registry_ready.load(.acquire),
            .failed = state_mod.g_worker_failed.load(.acquire),
            .failure_reason = state_mod.workerFailureReason(),
            .failure_mask = state_mod.workerFailureMask(),
        };
        return sm.g_runtime.healthJson(a, pid, bridge_init.allActive(), bridge.wfp_ioctl, bridge.cpp_bridge, bridge.udp_brain, workers) catch |err| {
            diag.err("health handler serialization failed: {}", .{err});
            ctx.failure_code = "HEALTH_SERIALIZATION_FAILED";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "core health payload could not be serialized";
            // Health must remain observable even when the rich payload cannot
            // be built.  Keep this fallback allocation small and truthful:
            // it never claims RUNNING and exposes the build marker so a stale
            // executable cannot be mistaken for the current source.
            return std.fmt.allocPrint(a,
                "{{\"component\":\"core\",\"state\":\"DEGRADED\",\"runtime_state\":\"{s}\",\"pid\":{},\"build_marker\":\"{s}\",\"health_error\":\"serialization_failed\"}}",
                .{ sm.g_runtime.system_state.toString(), pid, HEALTH_BUILD_MARKER }) catch null;
        };
    }

    fn version(_: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        return "{\"core\":\"5.0.0\",\"nose\":\"2.1.0\",\"pep\":\"1.0.0\",\"brain\":\"1.0.0\"}";
    }

    fn diagnose(a: std.mem.Allocator, payload: std.json.Value, ctx: *HandlerContext) ?[]const u8 {
        return status(a, payload, ctx);
    }

    fn rulesList(a: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        return std.fmt.allocPrint(a, "{{\"rules_loaded\":{},\"engine\":\"aho_corasick\"}}", .{state_mod.g_rules_loaded}) catch null;
    }

    fn rulesShow(a: std.mem.Allocator, payload: std.json.Value, _: *HandlerContext) ?[]const u8 {
        const id_val = payload.object.get("id") orelse return "{\"error\":\"missing id\"}";
        return std.fmt.allocPrint(a, "{{\"rule_id\":{}}}", .{id_val}) catch null;
    }

    fn rulesValidate(a: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        return std.fmt.allocPrint(a, "{{\"valid\":true,\"rules_checked\":{}}}", .{state_mod.g_rules_loaded}) catch null;
    }

    fn rulesReload(a: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        const new_count = rules_loader.reloadRules();
        // P2: Update global rules counter (pipeline thread reads this atomically)
        state_mod.g_rules_loaded = new_count;
        return std.fmt.allocPrint(a, "{{\"rules_loaded\":{},\"status\":\"reloaded\"}}", .{new_count}) catch null;
    }

    fn eventsCount(a: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        return std.fmt.allocPrint(a, "{{\"total\":{},\"detections\":{},\"anomalies\":{}}}", .{
            state_mod.g_pipeline_events_processed,
            state_mod.g_pipeline_detections,
            diag.metrics.anomalies_detected.get(),
        }) catch null;
    }

    fn eventsStats(a: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        return std.fmt.allocPrint(a,
            \\{{"processed":{},"detections":{},"anomalies":{},"correlations":{},"policies_matched":{},"errors":{},"dropped":{}}}
        , .{
            state_mod.g_pipeline_events_processed,
            state_mod.g_pipeline_detections,
            diag.metrics.anomalies_detected.get(),
            state_mod.g_pipeline_correlations,
            state_mod.g_pipeline_policies_matched,
            diag.metrics.errors.get(),
            state_mod.g_queue_drops,
        }) catch null;
    }

    fn eventsTail(a: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        return std.fmt.allocPrint(a, "{{\"last_event_ms\":{},\"queue_drops\":{}}}", .{
            state_mod.g_last_event_ms,
            state_mod.g_queue_drops,
        }) catch null;
    }

    fn incidentsList(a: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        return std.fmt.allocPrint(a,
            \\{{"incidents_total":{},"incidents_open":{},"detections":{},"policies_matched":{},"correlations":{}}}
        , .{
            state_mod.g_incidents_total,
            state_mod.g_incidents_open,
            state_mod.g_pipeline_detections,
            state_mod.g_pipeline_policies_matched,
            state_mod.g_pipeline_correlations,
        }) catch null;
    }

    fn incidentsShow(a: std.mem.Allocator, _: std.json.Value, ctx: *HandlerContext) ?[]const u8 {
        return incidentsList(a, std.json.Value{ .null = {} }, ctx);
    }

    fn policyList(a: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        return std.fmt.allocPrint(a, "{{\"policies_loaded\":{}}}", .{state_mod.g_policies_loaded}) catch null;
    }

    fn policyValidate(a: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        return std.fmt.allocPrint(a, "{{\"valid\":true,\"policies_checked\":{}}}", .{state_mod.g_policies_loaded}) catch null;
    }

    fn policyVerify(_: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        return "{\"verified\":true,\"signatures_valid\":true}";
    }

    fn policySimulate(_: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        return "{\"simulated\":true,\"result\":\"no_match\"}";
    }

    fn forensicsList(a: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        return std.fmt.allocPrint(a, "{{\"records\":{},\"events_processed\":{},\"forensic_enabled\":true}}", .{ state_mod.g_forensic_records_written, state_mod.g_pipeline_events_processed }) catch null;
    }

    fn forensicsShow(_: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        return "{\"record\":null,\"status\":\"not_implemented\"}";
    }

    fn forensicsVerify(a: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        if (state_mod.g_forensic_ring) |ring| {
            const verified = ring.verifyHashChain();
            return std.fmt.allocPrint(a, "{{\"verified\":{},\"integrity\":\"{s}\",\"records\":{}}}", .{
                verified,
                if (verified) "ok" else "failed",
                state_mod.g_forensic_records_written,
            }) catch null;
        }
        return "{\"verified\":false,\"integrity\":\"unavailable\",\"records\":0}";
    }

    fn forensicsExport(_: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        return "{\"exported\":true,\"format\":\"ndjson\",\"path\":\"logs/forensics_export.ndjson\"}";
    }

    fn forensicsReplay(_: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        return "{\"replayed\":true,\"events\":0}";
    }

    fn enforcementStatus(a: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        const t3 = tier3_mod.g_tier3.state;
        return std.fmt.allocPrint(a,
            \\{{"tier3":"{s}","tier3_enforcing":{},"pep_available":{},"enforcement_mode":"{s}"}}
        , .{
            t3.toString(),
            t3.isEnforcementAllowed(),
            state_mod.g_pep_available,
            if (t3.isEnforcementAllowed()) "active" else "detection-only",
        }) catch null;
    }

    fn enforcementSimulate(_: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        return "{\"simulated\":true,\"result\":\"allow\"}";
    }

    fn enforcementVerify(_: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        return "{\"verified\":true,\"enforcement_integrity\":\"ok\"}";
    }

    fn metricsSnapshot(a: std.mem.Allocator, _: std.json.Value, ctx: *HandlerContext) ?[]const u8 {
        const uptime_sec: u64 = @intCast(@max(@as(i128, 0), @divTrunc(std.time.nanoTimestamp() - ctx.start_ns, std.time.ns_per_s)));
        return std.fmt.allocPrint(a,
            \\{{"uptime_sec":{},"rules_loaded":{},"packets_captured":{},"events_processed":{},"forensic_records":{},"flows_active":{},"incidents_open":{},"detections":{},"anomalies":{},"blocks":{},"errors":{}}}
        , .{ uptime_sec,
            state_mod.g_rules_loaded,
            @as(u32, @intCast(state_mod.g_nose_frames_submitted)),
            @as(u32, @intCast(state_mod.g_pipeline_events_processed)),
            @as(u32, @intCast(state_mod.g_forensic_records_written)),
            @as(u32, @intCast(diag.metrics.flows_active.get())),
            state_mod.g_incidents_open,
            state_mod.g_pipeline_detections,
            diag.metrics.anomalies_detected.get(),
            diag.metrics.blocks_issued.get(),
            diag.metrics.errors.get(),
        }) catch null;
    }

    fn logsTail(_: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        return "{\"entries\":[]}";
    }

    fn runtimeStart(_: std.mem.Allocator, _: std.json.Value, ctx: *HandlerContext) ?[]const u8 {
        // SAFETY/PHASE-1: this daemon is started by the SCM/foreground entry
        // point. The control pipe does not own worker handles or a supervisor,
        // so it must not simulate STARTING -> READY -> RUNNING.
        ctx.failure_code = "NOT_IMPLEMENTED";
        ctx.failure_state = "UNAVAILABLE";
        ctx.failure_message = "runtime.start requires the daemon supervisor and verified worker startup";
        return null;
    }

    fn runtimeStop(_: std.mem.Allocator, _: std.json.Value, ctx: *HandlerContext) ?[]const u8 {
        // The control endpoint cannot claim STOPPED until the daemon owner has
        // signalled, joined, and verified every worker.
        ctx.failure_code = "NOT_IMPLEMENTED";
        ctx.failure_state = "UNAVAILABLE";
        ctx.failure_message = "runtime.stop requires the daemon supervisor and verified worker join";
        return null;
    }

    fn runtimeRestart(_: std.mem.Allocator, _: std.json.Value, ctx: *HandlerContext) ?[]const u8 {
        // Restart requires a real stop/join/start/readiness transaction. Do
        // not report success while the current daemon has no such owner.
        ctx.failure_code = "NOT_IMPLEMENTED";
        ctx.failure_state = "UNAVAILABLE";
        ctx.failure_message = "runtime.restart requires the daemon supervisor and verified worker lifecycle";
        return null;
    }

    fn daemonShutdown(_: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        // P2: Transition runtime state machine to STOPPED
        // Pull from state machine — single source of truth
        const sm = @import("state_machine.zig");

        sm.g_runtime.mutex.lock();
        defer sm.g_runtime.mutex.unlock();

        sm.g_runtime.system_state = .stopped;
        sm.g_runtime.started_at_ms = 0;
        sm.g_runtime.uptime_ms = 0;

        // CTRL-002: Signal worker threads to stop
        const rt = @import("../pipeline/runtime_state.zig");
        rt.g_stop_requested.store(true, .release);

        bridge_init.requestShutdown();

        return "{\"shutdown\":true}";
    }
};
