//! control/handler_registry.zig â€” Command Dispatch Table
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
const pep_bindings = @import("../policy/pep_bindings.zig");
const enforcement_receipt = @import("../policy/enforcement_receipt.zig");
const forensic_pipeline = @import("../forensic/forensic_pipeline.zig");
const siem_mod = @import("../forensic/siem_forwarder.zig");
const event_queue = @import("../pipeline/event_queue.zig");
const event_contract = @import("../contract/event.zig");
const telemetry = @import("../pipeline/telemetry_threads.zig");
const host_net = @import("../windows/host_net.zig");
const source_arbiter = @import("../capture/source_arbiter.zig");
const etw_rt = @import("../windows/etw_realtime.zig");
const fault = @import("../reliability/fault_injection.zig");
const tracker_mod = @import("../detection/threat_tracker.zig");
const xdr_runtime = @import("../xdr/xdr_runtime.zig");
const xdr_evidence_flow = @import("../xdr/xdr_evidence_flow.zig");

// ============================================================
// Handler Function Signature
// ============================================================

/// A handler receives the allocator, the raw payload JSON value, and context.
/// Returns a raw JSON string for the "data" field, or null on error.
/// OWNERSHIP CONTRACT (LIT-FREE-096): the return is ALWAYS allocator-owned
/// (dupe literals); the caller frees unconditionally. A static string here
/// segfaults every freeing caller (test.exe abort observed).
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

fn eventKindName(ordinal: u8, buf: []u8) []const u8 {
    inline for (std.meta.fields(event_contract.EventKind)) |field| {
        if (field.value == ordinal and !std.mem.eql(u8, field.name, "_")) return field.name;
    }
    return std.fmt.bufPrint(buf, "unknown_{d}", .{ordinal}) catch "unknown";
}

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
    registerHandler(.queue_stats, handlers.queueStats);
    registerHandler(.incidents_list, handlers.incidentsList);
    registerHandler(.incidents_show, handlers.incidentsShow);
    registerHandler(.xdr_list, handlers.xdrList);
    registerHandler(.xdr_verify, handlers.xdrVerify);
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
    registerHandler(.enforcement_block, handlers.enforcementBlock);
    registerHandler(.enforcement_quarantine, handlers.enforcementQuarantine);
    registerHandler(.enforcement_unblock, handlers.enforcementUnblock);
    registerHandler(.enforcement_two_person, handlers.enforcementTwoPerson);
    registerHandler(.enforcement_approve, handlers.enforcementApprove);
    registerHandler(.metrics_snapshot, handlers.metricsSnapshot);
    registerHandler(.logs_tail, handlers.logsTail);
    registerHandler(.federation_status, handlers.federationStatus);
    registerHandler(.runtime_start, handlers.runtimeStart);
    registerHandler(.runtime_stop, handlers.runtimeStop);
    registerHandler(.runtime_restart, handlers.runtimeRestart);
    registerHandler(.daemon_shutdown, handlers.daemonShutdown);
}

// ============================================================
// Handler implementations â€” all return ?[]const u8 (raw JSON)
// ============================================================

const handlers = struct {
    const HEALTH_BUILD_MARKER = "health-v2-20260916";
    const bridge_init = @import("../core/bridge_init.zig");
    const state_mod = @import("../pipeline/runtime_state.zig");
    const diag = @import("../core/diagnostics.zig");
    const tier3_mod = @import("../policy/tier3_state.zig");
    const rules_loader = @import("../pipeline/rule_loader.zig");
    const canonical_event = @import("../contract/canonical_event.zig");

    const RecordOrigin = struct {
        ordinal: u8,
        name: []const u8,
        space: []const u8,
    };

    /// Single canonical attribution for a forensic record. `reserved[5]` is the
    /// source-space version byte, so records written before the canonical
    /// writer are canonicalized on read: `--source N` then names the same
    /// sensor for the whole ring instead of crossing two ordinal spaces.
    fn forensicRecordOrigin(source_raw: u8, space_version: u8) RecordOrigin {
        const canonical = forensic_pipeline.canonicalSourceFromRecord(source_raw, space_version);
        return .{
            .ordinal = @intFromEnum(canonical),
            .name = canonical_event.sourceName(canonical),
            .space = if (space_version == forensic_pipeline.SOURCE_SPACE_CANONICAL)
                "canonical"
            else
                "legacy_mapped",
        };
    }

    extern "kernel32" fn GetCurrentProcessId() std.os.windows.DWORD;

    fn status(a: std.mem.Allocator, _: std.json.Value, ctx: *HandlerContext) ?[]const u8 {
        // P1: Pull from state machine â€” single source of truth
        const sm = @import("state_machine.zig");
        sm.g_runtime.uptime_ms = @intCast(@divTrunc(std.time.nanoTimestamp() - ctx.start_ns, std.time.ns_per_ms));
        return sm.g_runtime.statusJson(a) catch null;
    }

    fn health(a: std.mem.Allocator, _: std.json.Value, ctx: *HandlerContext) ?[]const u8 {
        // P1: Pull from state machine â€” single source of truth
        const sm = @import("state_machine.zig");
        const bridge = bridge_init.status();
        const bridge_ready = bridge_init.isAllActive(bridge);
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
        return sm.g_runtime.healthJson(a, pid, bridge_ready, bridge.wfp_ioctl, bridge.cpp_bridge, bridge.udp_brain, workers) catch |err| {
            diag.err("health handler serialization failed: {}", .{err});
            ctx.failure_code = "HEALTH_SERIALIZATION_FAILED";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "core health payload could not be serialized";
            // Health must remain observable even when the rich payload cannot
            // be built.  Keep this fallback allocation small and truthful:
            // it never claims RUNNING and exposes the build marker so a stale
            // executable cannot be mistaken for the current source.
            return std.fmt.allocPrint(a, "{{\"component\":\"core\",\"state\":\"DEGRADED\",\"runtime_state\":\"{s}\",\"pid\":{},\"build_marker\":\"{s}\",\"health_error\":\"serialization_failed\"}}", .{ sm.g_runtime.system_state.toString(), pid, HEALTH_BUILD_MARKER }) catch null;
        };
    }

    fn version(a: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        // VER-TRUTH-032: every value mirrors its component's own source of
        // truth — core/nose 5.0.0 (product line), pep 5.0.0 (Cargo package
        // aegis_pep), brain 2.0.0 (windows_brain --version/banner).
        return a.dupe(u8, "{\"core\":\"5.0.0\",\"nose\":\"5.0.0\",\"pep\":\"5.0.0\",\"brain\":\"2.0.0\"}") catch null;
    }

    fn diagnose(a: std.mem.Allocator, payload: std.json.Value, ctx: *HandlerContext) ?[]const u8 {
        return status(a, payload, ctx);
    }

    fn rulesList(a: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        return std.fmt.allocPrint(a, "{{\"rules_loaded\":{},\"engine\":\"aho_corasick\"}}", .{state_mod.g_rules_loaded.load(.acquire)}) catch null;
    }

    fn rulesShow(a: std.mem.Allocator, payload: std.json.Value, ctx: *HandlerContext) ?[]const u8 {
        // Honest lookup: find the rule by its string rule_id in Rules.json
        // (the same file the detection engine loads). Never invents fields.
        if (payload != .object) {
            ctx.failure_code = "INVALID_INPUT";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "payload must be an object with an id field";
            return null;
        }
        const id_val = payload.object.get("id") orelse {
            ctx.failure_code = "INVALID_INPUT";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "id is required (string rule_id, e.g. R0056)";
            return null;
        };
        if (id_val != .string) {
            ctx.failure_code = "INVALID_INPUT";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "id must be a string rule_id";
            return null;
        }
        const runtime_paths = @import("../core/runtime_paths.zig");
        const root = runtime_paths.resolveRoot(a) catch {
            ctx.failure_code = "CONFIG_UNAVAILABLE";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "cannot resolve runtime root";
            return null;
        };
        defer a.free(root);
        const rules_path = runtime_paths.configPath(a, root, "Rules.json") catch {
            ctx.failure_code = "CONFIG_UNAVAILABLE";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "cannot build Rules.json path";
            return null;
        };
        defer a.free(rules_path);
        const file = std.fs.openFileAbsolute(rules_path, .{}) catch {
            ctx.failure_code = "CONFIG_UNAVAILABLE";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "cannot open Rules.json";
            return null;
        };
        defer file.close();
        const bytes = file.readToEndAlloc(a, 4 * 1024 * 1024) catch {
            ctx.failure_code = "CONFIG_UNAVAILABLE";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "cannot read Rules.json";
            return null;
        };
        defer a.free(bytes);
        var parsed = std.json.parseFromSlice(std.json.Value, a, bytes, .{}) catch {
            ctx.failure_code = "CONFIG_INVALID";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "Rules.json is not valid JSON";
            return null;
        };
        defer parsed.deinit();
        if (parsed.value != .object) {
            ctx.failure_code = "CONFIG_INVALID";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "Rules.json root must be an object";
            return null;
        }
        const rules_val = parsed.value.object.get("nids_rules") orelse {
            ctx.failure_code = "CONFIG_INVALID";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "Rules.json has no nids_rules array";
            return null;
        };
        if (rules_val != .array) {
            ctx.failure_code = "CONFIG_INVALID";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "nids_rules is not an array";
            return null;
        }
        for (rules_val.array.items) |r| {
            if (r != .object) continue;
            const rid = r.object.get("rule_id") orelse continue;
            if (rid != .string) continue;
            if (!std.mem.eql(u8, rid.string, id_val.string)) continue;
            const get = struct {
                fn s(obj: std.json.ObjectMap, key: []const u8) []const u8 {
                    const v = obj.get(key) orelse return "";
                    if (v != .string) return "";
                    return v.string;
                }
            }.s;
            return std.fmt.allocPrint(a, "{{\"rule_id\":\"{s}\",\"name\":\"{s}\",\"category\":\"{s}\",\"severity\":\"{s}\",\"action\":\"{s}\",\"found\":true}}", .{
                rid.string, get(r.object, "name"), get(r.object, "category"), get(r.object, "severity"), get(r.object, "action"),
            }) catch null;
        }
        return std.fmt.allocPrint(a, "{{\"rule_id\":\"{s}\",\"found\":false}}", .{id_val.string}) catch null;
    }

    fn rulesValidate(a: std.mem.Allocator, _: std.json.Value, ctx: *HandlerContext) ?[]const u8 {
        // Dry-run validation: parse Rules.json and check every rule carries
        // the fields the loader requires. Reads only; never touches the
        // live automaton (rules.reload owns mutation).
        const runtime_paths = @import("../core/runtime_paths.zig");
        const root = runtime_paths.resolveRoot(a) catch {
            ctx.failure_code = "CONFIG_UNAVAILABLE";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "cannot resolve runtime root";
            return null;
        };
        defer a.free(root);
        const rules_path = runtime_paths.configPath(a, root, "Rules.json") catch {
            ctx.failure_code = "CONFIG_UNAVAILABLE";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "cannot build Rules.json path";
            return null;
        };
        defer a.free(rules_path);
        const file = std.fs.openFileAbsolute(rules_path, .{}) catch {
            ctx.failure_code = "CONFIG_UNAVAILABLE";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "cannot open Rules.json";
            return null;
        };
        defer file.close();
        const bytes = file.readToEndAlloc(a, 4 * 1024 * 1024) catch {
            ctx.failure_code = "CONFIG_UNAVAILABLE";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "cannot read Rules.json";
            return null;
        };
        defer a.free(bytes);
        var parsed = std.json.parseFromSlice(std.json.Value, a, bytes, .{}) catch {
            ctx.failure_code = "CONFIG_INVALID";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "Rules.json is not valid JSON";
            return null;
        };
        defer parsed.deinit();
        if (parsed.value != .object) {
            ctx.failure_code = "CONFIG_INVALID";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "Rules.json root must be an object";
            return null;
        }
        const rules_val = parsed.value.object.get("nids_rules") orelse {
            ctx.failure_code = "CONFIG_INVALID";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "Rules.json has no nids_rules array";
            return null;
        };
        if (rules_val != .array) {
            ctx.failure_code = "CONFIG_INVALID";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "nids_rules is not an array";
            return null;
        }
        var checked: u32 = 0;
        for (rules_val.array.items) |r| {
            if (r != .object) {
                ctx.failure_code = "CONFIG_INVALID";
                ctx.failure_state = "REJECTED";
                ctx.failure_message = "rule entry is not an object";
                return null;
            }
            for ([_][]const u8{ "rule_id", "name", "severity", "action" }) |key| {
                const v = r.object.get(key) orelse {
                    ctx.failure_code = "CONFIG_INVALID";
                    ctx.failure_state = "REJECTED";
                    ctx.failure_message = "rule is missing a required field";
                    return null;
                };
                if (v != .string or v.string.len == 0) {
                    ctx.failure_code = "CONFIG_INVALID";
                    ctx.failure_state = "REJECTED";
                    ctx.failure_message = "rule has an empty required field";
                    return null;
                }
            }
            checked += 1;
        }
        if (checked == 0) {
            ctx.failure_code = "CONFIG_INVALID";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "Rules.json contains zero rules";
            return null;
        }
        return std.fmt.allocPrint(a, "{{\"valid\":true,\"rules_checked\":{}}}", .{checked}) catch null;
    }

    fn rulesReload(a: std.mem.Allocator, _: std.json.Value, ctx: *HandlerContext) ?[]const u8 {
        const previous_count = state_mod.g_rules_loaded.load(.acquire);
        const rep = rules_loader.reloadRules();
        if (rep.loaded == 0) {
            ctx.failure_code = "RULES_RELOAD_EMPTY";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "reload produced zero active rules; previous ruleset was retained";
            return null;
        }
        // Update global rules counter (pipeline thread reads this atomically).
        state_mod.g_rules_loaded.store(rep.loaded, .monotonic);
        // BE-DRIFT-098: name every skipped rule with its reason (IDs are
        // operator-controlled strings, JSON-escaped). Additive keys only:
        // older CLIs ignore unknown fields.
        var out = std.ArrayList(u8).init(a);
        errdefer out.deinit();
        var writer = out.writer();
        writer.print("{{\"rules_loaded\":{},\"previous_rules_loaded\":{},\"status\":\"reloaded\",\"postcondition\":\"ACTIVE\",\"skipped\":{{\"no_pattern\":{},\"disabled\":{},\"malformed\":{},\"add_failed\":{}}},\"skipped_ids\":[", .{
            rep.loaded,             previous_count,
            rep.skipped_no_pattern, rep.skipped_disabled,
            rep.skipped_malformed,  rep.skipped_add_failed,
        }) catch return null;
        var si: usize = 0;
        while (si < rep.skipped_id_count) : (si += 1) {
            if (si > 0) writer.writeByte(',') catch return null;
            rules_loader.writeJsonString(writer, rep.skippedId(si));
        }
        writer.print("],\"skipped_truncated\":{}}}", .{rep.skipped_truncated}) catch return null;
        return out.toOwnedSlice() catch null;
    }

    fn eventsCount(a: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        return std.fmt.allocPrint(a, "{{\"total\":{},\"detections\":{},\"anomalies\":{}}}", .{
            state_mod.g_pipeline_events_processed.load(.acquire),
            state_mod.g_pipeline_detections.load(.acquire),
            diag.metrics.anomalies_detected.get(),
        }) catch null;
    }

    fn eventsStats(a: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        const queue_drops = state_mod.g_queue_drops.load(.acquire);
        // GAP-015: fault-injection drops were invisible in metrics (only
        // g_queue_drops surfaced). Exact when FI is off (production: always
        // off, zeros); best-effort while a test enables it mid-run.
        const fi = &state_mod.g_fi;
        return std.fmt.allocPrint(a,
            \\{{"processed":{},"detections":{},"anomalies":{},"correlations":{},"policies_matched":{},"errors":{},"dropped":{},"fi_enabled":{},"fi_dropped":{},"fi_corrupted":{}}}
        , .{
            state_mod.g_pipeline_events_processed.load(.acquire),
            state_mod.g_pipeline_detections.load(.acquire),
            diag.metrics.anomalies_detected.get(),
            state_mod.g_pipeline_correlations.load(.acquire),
            state_mod.g_pipeline_policies_matched.load(.acquire),
            diag.metrics.errors.get(),
            queue_drops,
            fi.cfg.enabled,
            fi.injected[@intFromEnum(fault.FaultKind.drop_packet)],
            fi.injected[@intFromEnum(fault.FaultKind.corrupt_event)],
        }) catch null;
    }

    fn eventsTail(a: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        const queue_drops = state_mod.g_queue_drops.load(.acquire);
        return std.fmt.allocPrint(a, "{{\"last_event_ms\":{},\"queue_drops\":{}}}", .{
            state_mod.lastEventAgeMs(state_mod.g_last_event_ms.load(.acquire), std.time.milliTimestamp()),
            queue_drops,
        }) catch null;
    }

    /// GAP-015: per-source ingress accounting plus the pipeline latency
    /// snapshot. Read-only: counters are monotonic, the perf snapshot is
    /// taken under g_perf_mutex, and only nonzero source buckets are
    /// emitted. This is the instrument that turns "dropped=N" into
    /// "sensor X starves while sensor Y floods".
    fn queueStats(a: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        var pushed_total: u64 = 0;
        var dropped_total: u64 = 0;
        var buckets: [256]struct { pushed: u64, dropped: u64, active: u64 } = undefined;
        var i: usize = 0;
        while (i < 256) : (i += 1) {
            const p = event_queue.g_ingress_pushed[i].load(.acquire);
            const d = event_queue.g_ingress_dropped[i].load(.acquire);
            const act = event_queue.g_ingress_active[i].load(.acquire);
            buckets[i] = .{ .pushed = p, .dropped = d, .active = act };
            pushed_total += p;
            dropped_total += d;
        }
        state_mod.g_perf_mutex.lock();
        const snap = state_mod.g_perf.snapshot();
        state_mod.g_perf_mutex.unlock();

        var out = std.ArrayList(u8).init(a);
        errdefer out.deinit();
        var writer = out.writer();
        writer.print("{{\"queue_size\":{},\"depth\":{},\"depth_peak\":{},\"reserved_network_slots\":{},\"source_occupancy_cap\":{},\"critical_slots\":{},\"critical_pushed_total\":{},\"reserved_tail_shed\":{},\"source_quota_shed\":{},\"pushed_total\":{},\"dropped_total\":{},\"minifilter_pipeline_dropped\":{},\"shed_overload\":{},\"fim_probe\":{{\"batch_records\":{},\"batch_duplicates\":{},\"batch_duplicates_per_pid\":{},\"batch_overflow\":{},\"minifilter\":{{\"records\":{},\"duplicates\":{},\"duplicates_per_pid\":{},\"duplicates_same_ts\":{}}},\"native_poll\":{{\"records\":{},\"duplicates\":{}}}}},\"by_source\":[", .{
            event_queue.PIPELINE_QUEUE_SIZE,
            event_queue.queueDepth(),
            event_queue.queuePeakDepth(),
            event_queue.RESERVED_NETWORK_SLOTS,
            event_queue.SOURCE_OCCUPANCY_CAP,
            event_queue.CRITICAL_SLOTS,
            state_mod.g_critical_pushed.load(.acquire),
            state_mod.g_reserved_tail_shed.load(.acquire),
            state_mod.g_source_quota_shed.load(.acquire),
            pushed_total,
            dropped_total,
            state_mod.g_minifilter_pipeline_dropped.load(.acquire),
            telemetry.g_shed_overload.load(.acquire),
            state_mod.g_fim_batch_records.load(.acquire),
            state_mod.g_fim_batch_duplicates.load(.acquire),
            state_mod.g_fim_batch_duplicates_per_pid.load(.acquire),
            state_mod.g_fim_batch_overflow.load(.acquire),
            state_mod.g_fim_minifilter_batch_records.load(.acquire),
            state_mod.g_fim_minifilter_batch_duplicates.load(.acquire),
            state_mod.g_fim_minifilter_batch_duplicates_per_pid.load(.acquire),
            state_mod.g_fim_minifilter_batch_duplicates_same_ts.load(.acquire),
            state_mod.g_fim_poll_batch_records.load(.acquire),
            state_mod.g_fim_poll_batch_duplicates.load(.acquire),
        }) catch return null;
        var first = true;
        var ord: usize = 0;
        while (ord < 256) : (ord += 1) {
            if (buckets[ord].pushed == 0 and buckets[ord].dropped == 0) continue;
            var name_buf: [32]u8 = undefined;
            const name = event_contract.legacySourceName(@intCast(ord), &name_buf);
            if (!first) writer.writeByte(',') catch return null;
            first = false;
            writer.print("{{\"ordinal\":{},\"name\":\"{s}\",\"pushed\":{},\"dropped\":{},\"active\":{}}}", .{
                ord, name, buckets[ord].pushed, buckets[ord].dropped, buckets[ord].active,
            }) catch return null;
        }
        writer.writeAll("],\"by_source_kind\":[") catch return null;
        first = true;
        // Bounded source × canonical kind attribution. Only nonzero lanes are
        // emitted; counters are observational and never influence admission.
        var source_ord: usize = 0;
        while (source_ord < 256) : (source_ord += 1) {
            var kind_ord: usize = 0;
            while (kind_ord < 256) : (kind_ord += 1) {
                const idx = source_ord * 256 + kind_ord;
                const kind_pushed = event_queue.g_ingress_kind_pushed[idx].load(.acquire);
                const kind_dropped = event_queue.g_ingress_kind_dropped[idx].load(.acquire);
                if (kind_pushed == 0 and kind_dropped == 0) continue;
                if (!first) writer.writeByte(',') catch return null;
                first = false;
                var source_name_buf: [32]u8 = undefined;
                var kind_name_buf: [32]u8 = undefined;
                const source_name = event_contract.legacySourceName(@intCast(source_ord), &source_name_buf);
                const kind_name = eventKindName(@intCast(kind_ord), &kind_name_buf);
                writer.print("{{\"source_ordinal\":{},\"source\":\"{s}\",\"kind_ordinal\":{},\"kind\":\"{s}\",\"pushed\":{},\"dropped\":{}}}", .{
                    source_ord, source_name, kind_ord, kind_name, kind_pushed, kind_dropped,
                }) catch return null;
            }
        }
        writer.writeAll("],\"pipeline\":[") catch return null;
        first = true;
        // PerfSnapshot carries 16 slots but only the declared Stage enum values
        // are ever observed; the rest are undefined memory, never read.
        const named_stage_count = @typeInfo(@import("../reliability/latency_histogram.zig").Stage).Enum.fields.len;
        for (snap.stages[0..named_stage_count]) |stage| {
            if (!first) writer.writeByte(',') catch return null;
            first = false;
            writer.print("{{\"stage\":\"{s}\",\"count\":{},\"p50_ns\":{},\"p95_ns\":{},\"p99_ns\":{},\"mean_ns\":{d},\"max_ns\":{}}}", .{
                stage.name, stage.count, stage.p50_ns, stage.p95_ns, stage.p99_ns, stage.mean_ns, stage.max_ns,
            }) catch return null;
        }
        writer.writeAll("],\"etw\":{") catch return null;
        writer.print("\"process_start\":{},\"file_name_create\":{},\"name_create_deduped\":{},\"file_name_delete\":{},\"file_write\":{},\"reg_create\":{},\"reg_set\":{},\"dropped_unmapped\":{},\"predecode_dropped\":{},\"shed_exempted\":{}}}", .{
            telemetry.g_etw_classes.process_start.load(.acquire),
            telemetry.g_etw_classes.file_name_create.load(.acquire),
            telemetry.g_etw_classes.name_create_deduped.load(.acquire),
            telemetry.g_etw_classes.file_name_delete.load(.acquire),
            telemetry.g_etw_classes.file_write.load(.acquire),
            telemetry.g_etw_classes.reg_create.load(.acquire),
            telemetry.g_etw_classes.reg_set.load(.acquire),
            telemetry.g_etw_classes.dropped_unmapped.load(.acquire),
            etw_rt.g_etw_predecode_dropped.load(.acquire),
            telemetry.g_shed_exempted.load(.acquire),
        }) catch return null;
        // EVT-211: kernel WFP telemetry health, stamped by the capture
        // loop. "unavailable" is a LABELED absence (no silent zero);
        // rows>0 is the only "kernel flows are flowing" claim.
        writer.writeAll(",\"wfp\":{") catch return null;
        // PHASE-6: acquisition arbitration. `mode` names which source owns
        // network ingress; `shadow_rows` counts kernel rows drained while
        // the packet path owns it (visible, never a silent drop).
        const cap_mode = state_mod.g_capture_mode.load(.acquire);
        writer.print("\"state\":\"{s}\",\"reads\":{},\"rows\":{},\"last_bytes\":{},\"mode\":\"{s}\",\"reason\":\"{s}\",\"shadow_rows\":{},\"kernel_owned\":{}}}", .{
            providerStateName(state_mod.g_wfp_provider_state.load(.acquire)),
            state_mod.g_wfp_reads.load(.acquire),
            state_mod.g_wfp_rows.load(.acquire),
            state_mod.g_wfp_last_bytes.load(.acquire),
            source_arbiter.modeName(cap_mode),
            source_arbiter.reasonName(state_mod.g_capture_reason.load(.acquire)),
            state_mod.g_wfp_shadow_rows.load(.acquire),
            cap_mode == @intFromEnum(source_arbiter.Mode.kernel_fallback),
        }) catch return null;
        // EVT-230: kernel minifilter host telemetry health (file/process
        // events via \AegisMinifilterPort), stamped by the reader loop.
        // Same labeled-absence rule as wfp; `dropped` is the KERNEL ring's
        // own loss counter, so ring overflow is never silent. `pipeline_dropped`
        // separately counts rows rejected after leaving the kernel ring.
        writer.writeAll(",\"minifilter\":{") catch return null;
        writer.print("\"state\":\"{s}\",\"reads\":{},\"rows\":{},\"last_bytes\":{},\"dropped\":{},\"ring_written\":{},\"pipeline_dropped\":{}}}", .{
            providerStateName(state_mod.g_minifilter_state.load(.acquire)),
            state_mod.g_minifilter_reads.load(.acquire),
            state_mod.g_minifilter_rows.load(.acquire),
            state_mod.g_minifilter_last_bytes.load(.acquire),
            state_mod.g_minifilter_dropped.load(.acquire),
            state_mod.g_minifilter_ring_written.load(.acquire),
            state_mod.g_minifilter_pipeline_dropped.load(.acquire),
        }) catch return null;
        // XDR-005-A: observe-only Windows TCP endpoint telemetry health.
        // `seeded` is the poll that establishes the baseline and emits
        // nothing; `poll_errors` is nonfatal by contract (the loop beats
        // the watchdog even on failure). No action/enforcement fields.
        const hn = host_net.snapshot();
        writer.writeAll(",\"host_net\":{") catch return null;
        writer.print("\"enabled\":{},\"ready\":{},\"seeded\":{},\"polls\":{},\"poll_errors\":{},\"rows_seen\":{},\"tracked\":{},\"emitted\":{},\"emit_deferred\":{},\"overflow\":{},\"last_poll_ms\":{}}}", .{
            hn.enabled,
            hn.ready,
            hn.seeded,
            hn.polls,
            hn.poll_errors,
            hn.rows_seen,
            hn.tracked,
            hn.emitted,
            hn.emit_deferred,
            hn.overflow,
            hn.last_poll_ms,
        }) catch return null;
        writer.writeByte('}') catch return null;
        return out.toOwnedSlice() catch null;
    }

    /// EVT-211/EVT-230: stable names for the three-state kernel provider
    /// health ordinals (WfpProviderState / MinifilterState; identical
    /// ordinal space). Switch, not @tagName: an unrecognized host value
    /// degrades to a printed "unknown", never a trap on the control thread.
    fn providerStateName(v: u8) []const u8 {
        return switch (v) {
            1 => "ok",
            2 => "unavailable",
            else => "unknown",
        };
    }

    /// EVT-210: numeric → stable string for incident severity/state. Switch,
    /// not @tagName: a row from a future/hostile ordinal must degrade to a
    /// printed "unknown", never trap the control thread.
    fn severityName(v: u8) []const u8 {
        return switch (v) {
            0 => "trace",
            1 => "debug",
            2 => "info",
            3 => "notice",
            4 => "warning",
            5 => "error",
            6 => "critical",
            7 => "alert",
            8 => "emergency",
            else => "unknown",
        };
    }

    fn incidentStateName(v: u8) []const u8 {
        return switch (v) {
            0 => "open",
            1 => "escalated",
            2 => "blocked",
            3 => "resolved",
            4 => "false_positive",
            else => "unknown",
        };
    }

    fn incidentsList(a: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        // EVT-210: counters + a bounded, mutex-copied snapshot of the open
        // incidents themselves (highest score first). The counters stay the
        // authority for totals; the array is the detail view, capped at
        // SNAPSHOT_CAP with the true open count already in "incidents_open".
        var rows: [tracker_mod.SNAPSHOT_CAP]tracker_mod.SnapshotRow = undefined;
        var total: u64 = 0;
        const n = tracker_mod.snapshotOpenIncidents(&rows, &total);
        var out = std.ArrayList(u8).init(a);
        errdefer out.deinit();
        const writer = out.writer();
        writer.print("{{\"incidents_total\":{},\"incidents_open\":{},\"detections\":{},\"policies_matched\":{},\"correlations\":{},\"incidents\":[", .{
            state_mod.g_incidents_total.load(.acquire),
            state_mod.g_incidents_open.load(.acquire),
            state_mod.g_pipeline_detections.load(.acquire),
            state_mod.g_pipeline_policies_matched.load(.acquire),
            state_mod.g_pipeline_correlations.load(.acquire),
        }) catch return null;
        for (rows[0..n], 0..) |r, i| {
            if (i != 0) writer.writeByte(',') catch return null;
            writer.print("{{\"id\":{},\"flow_id\":{},\"src_ip\":\"{}.{}.{}.{}\",\"severity\":\"{s}\",\"state\":\"{s}\",\"score\":{},\"evidence\":{}}}", .{
                r.id,
                r.flow_id,
                (r.src_ip >> 24) & 0xFF,
                (r.src_ip >> 16) & 0xFF,
                (r.src_ip >> 8) & 0xFF,
                r.src_ip & 0xFF,
                severityName(r.severity),
                incidentStateName(r.state),
                r.score,
                r.evidence_count,
            }) catch return null;
        }
        writer.print("],\"incidents_returned\":{},\"incident_view_cap\":{}}}", .{
            n, tracker_mod.SNAPSHOT_CAP,
        }) catch return null;
        return out.toOwnedSlice() catch null;
    }

    fn incidentsShow(a: std.mem.Allocator, payload: std.json.Value, ctx: *HandlerContext) ?[]const u8 {
        // DEADCODE-QUARANTINE: a real show-by-id. The old handler was an
        // alias for incidents.list that silently dropped the payload — a
        // client asking for one incident received every incident. Contract
        // follows forensics.show: {"id": <u64>} is required, and the
        // lookup scans the FULL tracker table (never the SNAPSHOT_CAP
        // view) so a valid id outside the top-64 list is found, not
        // misreported as missing.
        const requested_id = payloadU64(payload, "id") orelse {
            ctx.failure_code = "INVALID_INPUT";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "id is required";
            return null;
        };
        var row: tracker_mod.SnapshotRow = undefined;
        if (!tracker_mod.snapshotIncidentById(requested_id, &row)) {
            ctx.failure_code = "INCIDENT_NOT_FOUND";
            ctx.failure_state = "NOT_FOUND";
            ctx.failure_message = "no incident with the requested id";
            return null;
        }
        return std.fmt.allocPrint(a, "{{\"id\":{},\"flow_id\":{},\"src_ip\":\"{}.{}.{}.{}\",\"severity\":\"{s}\",\"state\":\"{s}\",\"score\":{},\"evidence\":{}}}", .{
            row.id,
            row.flow_id,
            (row.src_ip >> 24) & 0xFF,
            (row.src_ip >> 16) & 0xFF,
            (row.src_ip >> 8) & 0xFF,
            row.src_ip & 0xFF,
            severityName(row.severity),
            incidentStateName(row.state),
            row.score,
            row.evidence_count,
        }) catch null;
    }

    fn xdrList(a: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        // XDR-WIRE-001: advisory read-only evidence view. The fabric owns
        // its own counters; nothing here may mutate state or feed DEFCON,
        // policy, PEP, or ActionDispatcher. Honest-empty before startLive().
        return xdr_runtime.listJson(a);
    }

    fn xdrVerify(a: std.mem.Allocator, payload: std.json.Value, ctx: *HandlerContext) ?[]const u8 {
        // XDR-005-B: read-only snapshot replay. Scan the forensic ring from
        // newest to oldest, prefilter on the correlation header, and replay
        // each persisted multi-source snapshot through
        // xdr_evidence_flow.replayRecord (CRC + per-record hash + ring
        // linkage + snapshot re-assessment). Nothing here detects, decides,
        // enforces, or writes: it only proves a persisted record still
        // replays to the decision it recorded.
        //
        // Limitation stated in the response `note`: receipt tokens are not
        // persisted by design, so post-hoc replay cannot prove that a token
        // was issued. Token issuance stays live evidence in xdr.list.
        var limit: u64 = 8;
        if (payload == .object) {
            if (payload.object.get("limit")) |lv| {
                if (lv != .integer or lv.integer <= 0) {
                    ctx.failure_code = "INVALID_ARGUMENT";
                    ctx.failure_state = "REJECTED";
                    ctx.failure_message = "limit must be a positive integer";
                    return null;
                }
                limit = @min(@as(u64, @intCast(lv.integer)), 64);
            }
        }
        const note = "persisted-snapshot replay; receipt tokens are not persisted, so this proves replay integrity, not token issuance";

        const ring = state_mod.g_forensic_ring orelse {
            return std.fmt.allocPrint(a, "{{\"available\":false,\"ring_records\":0,\"retained\":0,\"scanned\":0,\"xdr_records\":0,\"verified\":0,\"failed\":0,\"vanished\":0,\"limit\":{d},\"note\":\"{s}\",\"records\":[]}}", .{ limit, note }) catch null;
        };

        const total = ring.recordCount();
        const slots: u64 = @intCast(ring.capacity() / forensic_pipeline.RECORD_BYTES);
        const retained: u64 = @min(total, slots);
        const oldest_seq: u64 = if (retained > 0) total - retained + 1 else 1;

        var rows = std.ArrayList(u8).init(a);
        defer rows.deinit();
        const rw = rows.writer();

        var scanned: u64 = 0;
        var xdr_records: u64 = 0;
        var verified: u64 = 0;
        var failed: u64 = 0;
        var vanished: u64 = 0;

        var seq = total;
        while (retained > 0 and seq >= oldest_seq and xdr_records < limit) : (seq -= 1) {
            scanned += 1;
            const slot = ring.readRecord(seq - 1, a) orelse {
                vanished += 1;
                continue;
            };
            defer a.free(slot);
            if (slot.len != forensic_pipeline.RECORD_BYTES) {
                vanished += 1;
                continue;
            }
            const header = std.mem.bytesAsValue(forensic_pipeline.RecordHeader, slot[0..forensic_pipeline.HEADER_BYTES]);
            // A wrapped offset can hold a newer record: sequence identity is
            // checked before the header is trusted for attribution.
            if (header.record_seq != seq - 1) {
                vanished += 1;
                continue;
            }
            if (header.magic != forensic_pipeline.RECORD_MAGIC or
                header.kind != @intFromEnum(event_contract.EventKind.correlation_match) or
                header.rule_id != xdr_evidence_flow.MULTI_SOURCE_RULE_ID)
            {
                continue;
            }
            xdr_records += 1;

            if (xdr_evidence_flow.replayRecord(a, ring, seq)) |outcome| {
                verified += 1;
                if (rows.items.len != 0) rw.writeByte(',') catch return null;
                rw.print("{{\"sequence\":{d},\"incident_id\":{d},\"source_event_id\":{d},\"evidence\":{d},\"severity\":{d},\"confidence\":{d},\"source_categories\":[", .{
                    seq,
                    outcome.incident_id,
                    outcome.source_event_id,
                    outcome.evidence_count,
                    outcome.decision.severity,
                    outcome.decision.confidence,
                }) catch return null;
                var i: usize = 0;
                const cat_count: usize = outcome.decision.source_categories_used;
                while (i < cat_count) : (i += 1) {
                    if (i != 0) rw.writeByte(',') catch return null;
                    rw.print("\"{s}\"", .{outcome.categories[i].label()}) catch return null;
                }
                rw.writeAll("],\"verified\":true,\"error\":null}") catch return null;
            } else |err| {
                failed += 1;
                if (rows.items.len != 0) rw.writeByte(',') catch return null;
                rw.print("{{\"sequence\":{d},\"incident_id\":null,\"source_event_id\":null,\"evidence\":0,\"severity\":0,\"confidence\":0,\"source_categories\":[],\"verified\":false,\"error\":\"{s}\"}}", .{ seq, @errorName(err) }) catch return null;
            }
        }

        return std.fmt.allocPrint(a, "{{\"available\":true,\"ring_records\":{d},\"retained\":{d},\"scanned\":{d},\"xdr_records\":{d},\"verified\":{d},\"failed\":{d},\"vanished\":{d},\"limit\":{d},\"note\":\"{s}\",\"records\":[{s}]}}", .{
            total,
            retained,
            scanned,
            xdr_records,
            verified,
            failed,
            vanished,
            limit,
            note,
            rows.items,
        }) catch null;
    }

    fn policyList(a: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        return std.fmt.allocPrint(a, "{{\"policies_loaded\":{}}}", .{state_mod.g_policies_loaded.load(.acquire)}) catch null;
    }

    fn policyValidate(a: std.mem.Allocator, _: std.json.Value, ctx: *HandlerContext) ?[]const u8 {
        // Dry-run structural validation of configs/policies.json: every
        // entry carries the fields the loader requires (id/integer, name,
        // known action, severity, ttl_sec/integer). Reads only; never
        // touches the live PolicySet (policy reload owns mutation).
        // Mirrors rulesValidate field-for-field in strictness.
        const runtime_paths = @import("../core/runtime_paths.zig");
        const root = runtime_paths.resolveRoot(a) catch {
            ctx.failure_code = "CONFIG_UNAVAILABLE";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "cannot resolve runtime root";
            return null;
        };
        defer a.free(root);
        const policies_path = runtime_paths.configPath(a, root, "policies.json") catch {
            ctx.failure_code = "CONFIG_UNAVAILABLE";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "cannot build policies.json path";
            return null;
        };
        defer a.free(policies_path);
        const file = std.fs.openFileAbsolute(policies_path, .{}) catch {
            ctx.failure_code = "CONFIG_UNAVAILABLE";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "cannot open policies.json";
            return null;
        };
        defer file.close();
        const bytes = file.readToEndAlloc(a, 4 * 1024 * 1024) catch {
            ctx.failure_code = "CONFIG_UNAVAILABLE";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "cannot read policies.json";
            return null;
        };
        defer a.free(bytes);
        var parsed = std.json.parseFromSlice(std.json.Value, a, bytes, .{}) catch {
            ctx.failure_code = "CONFIG_INVALID";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "policies.json is not valid JSON";
            return null;
        };
        defer parsed.deinit();
        if (parsed.value != .object) {
            ctx.failure_code = "CONFIG_INVALID";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "policies.json root must be an object";
            return null;
        }
        const arr = parsed.value.object.get("policies") orelse {
            ctx.failure_code = "CONFIG_INVALID";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "policies.json has no policies array";
            return null;
        };
        if (arr != .array) {
            ctx.failure_code = "CONFIG_INVALID";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "policies is not an array";
            return null;
        }
        var checked: u32 = 0;
        var skipped: u32 = 0;
        for (arr.array.items) |pol| {
            if (pol != .object) {
                skipped += 1;
                continue;
            }
            const id_ok = if (pol.object.get("id")) |v| v == .integer else false;
            const name_ok = if (pol.object.get("name")) |v| v == .string and v.string.len > 0 else false;
            const action_ok = if (pol.object.get("action")) |v| blk: {
                if (v != .string) break :blk false;
                break :blk std.mem.eql(u8, v.string, "block") or
                    std.mem.eql(u8, v.string, "alert") or
                    std.mem.eql(u8, v.string, "rate_limit") or
                    std.mem.eql(u8, v.string, "quarantine") or
                    std.mem.eql(u8, v.string, "log") or
                    std.mem.eql(u8, v.string, "escalate");
            } else false;
            const severity_ok = if (pol.object.get("severity")) |v| v == .string and v.string.len > 0 else false;
            const ttl_ok = if (pol.object.get("ttl_sec")) |v| v == .integer else false;
            if (id_ok and name_ok and action_ok and severity_ok and ttl_ok) {
                checked += 1;
            } else {
                skipped += 1;
            }
        }
        if (checked == 0) {
            ctx.failure_code = "CONFIG_INVALID";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "policies.json contains zero loadable policies";
            return null;
        }
        return std.fmt.allocPrint(a, "{{\"valid\":true,\"policies_checked\":{},\"policies_skipped\":{}}}", .{ checked, skipped }) catch null;
    }

    fn policyVerify(a: std.mem.Allocator, _: std.json.Value, ctx: *HandlerContext) ?[]const u8 {
        // BE-RCPT-091: report the canonical envelope verification for both
        // the enforcement policies and the advisory IR mirror, using the
        // same verifyEnvelope routine daemon startup uses. Read-only:
        // resolves anchors + verifies bytes, marks nothing trusted,
        // touches no enforcement authority. Top-level "verified" tracks
        // the enforcement envelope (policies.json); the mirror reports
        // separately because its absence is normal without a TS compile.
        const policy_signing = @import("../policy/policy_signing.zig");
        const runtime_paths = @import("../core/runtime_paths.zig");
        const root = runtime_paths.resolveRoot(a) catch {
            ctx.failure_code = "CONFIG_UNAVAILABLE";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "cannot resolve runtime root";
            return null;
        };
        defer a.free(root);
        const pol = policy_signing.verifyEnvelope(a, root, "policies.json", "policies.sig.json");
        const mir = policy_signing.verifyEnvelope(a, root, "policy_ir.json", "policy_ir.sig.json");
        return std.fmt.allocPrint(a, "{{\"verified\":{},\"policies\":{{\"present\":{},\"sidecar\":{},\"anchors\":\"{s}\",\"anchors_broken\":{},\"valid\":{},\"reason\":\"{s}\"}},\"policy_ir\":{{\"present\":{},\"sidecar\":{},\"anchors\":\"{s}\",\"anchors_broken\":{},\"valid\":{},\"reason\":\"{s}\"}}}}", .{
            pol.valid,
            pol.doc_present,
            pol.sidecar_present,
            pol.anchor_source.toString(),
            pol.anchors_broken,
            pol.valid,
            pol.reason.toString(),
            mir.doc_present,
            mir.sidecar_present,
            mir.anchor_source.toString(),
            mir.anchors_broken,
            mir.valid,
            mir.reason.toString(),
        }) catch null;
    }

    fn policySimulate(a: std.mem.Allocator, payload: std.json.Value, ctx: *HandlerContext) ?[]const u8 {
        // What-if evaluation against the TS-authored IR mirror: pure
        // compute, no state change, no PEP contact. Absent IR is an honest
        // failure, never a canned "no_match". Input validated before state
        // so malformed calls fail identically with or without loaded rules.
        const plane = @import("../policy/policy_plane.zig");
        if (payload != .object) {
            ctx.failure_code = "INVALID_INPUT";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "payload must be an object with a values array";
            return null;
        }
        const values_val = payload.object.get("values") orelse {
            ctx.failure_code = "INVALID_INPUT";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "values array is required";
            return null;
        };
        if (values_val != .array or values_val.array.items.len == 0 or values_val.array.items.len > 32) {
            ctx.failure_code = "INVALID_INPUT";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "values must be a non-empty array of at most 32 integers";
            return null;
        }
        var values: [32]u64 = undefined;
        for (values_val.array.items, 0..) |v, i| {
            if (v != .integer or v.integer < 0) {
                ctx.failure_code = "INVALID_INPUT";
                ctx.failure_state = "REJECTED";
                ctx.failure_message = "values must contain only non-negative integers";
                return null;
            }
            values[i] = @intCast(v.integer);
        }
        const pir = state_mod.g_policy_ir orelse {
            ctx.failure_code = "POLICY_IR_ABSENT";
            ctx.failure_state = "UNAVAILABLE";
            ctx.failure_message = "no TS policy IR loaded; place policy_ir.json in configs/";
            return null;
        };
        const result = plane.PolicySimulator.simulate(pir.ir, values[0..values_val.array.items.len]);
        if (result.rule_matched) |rule_id| {
            return std.fmt.allocPrint(a, "{{\"simulated\":true,\"matched\":true,\"rule_id\":{},\"action\":\"{s}\",\"evaluated\":{}}}", .{ rule_id, @tagName(result.action), result.evaluated_count }) catch null;
        }
        return std.fmt.allocPrint(a, "{{\"simulated\":true,\"matched\":false,\"evaluated\":{}}}", .{result.evaluated_count}) catch null;
    }

    /// One control response must fit inside a single pipe read on every
    /// canonical client (64 KiB per ReadFile). A limit=1000 forensic page
    /// serialized to >100 KB and failed with ERROR_MORE_DATA, which callers
    /// observed as a hard control failure. Pages are byte-budgeted instead and
    /// carry an explicit continuation cursor; a page never silently drops
    /// records it claims to have covered.
    const FORENSIC_PAGE_DEFAULT_BYTES: u64 = 32 * 1024;
    const FORENSIC_PAGE_MIN_BYTES: u64 = 2 * 1024;
    const FORENSIC_PAGE_MAX_BYTES: u64 = 256 * 1024;
    /// Upper bound for one serialized record entry plus its separator comma.
    /// Fixed-width integers and bounded source names keep every entry below
    /// this, so the writer can stop before the response crosses the budget.
    const FORENSIC_ENTRY_MAX_BYTES: usize = 240;
    /// Reserve for the closing fields (counts, integrity, continuation).
    const FORENSIC_FOOTER_BYTES: usize = 256;

    fn forensicsList(a: std.mem.Allocator, payload: std.json.Value, _: *HandlerContext) ?[]const u8 {
        const requested_source = payloadU64(payload, "source");
        const requested_prefix: []const u8 = if (payload == .object) blk: {
            if (payload.object.get("payload_prefix")) |value| {
                break :blk switch (value) {
                    .string => |s| s,
                    else => "",
                };
            }
            break :blk "";
        } else "";

        const requested_limit: u64 = @min(
            @max(payloadU64(payload, "limit") orelse 100, 1),
            1000,
        );
        const requested_after = payloadU64(payload, "after");
        const requested_budget: usize = @intCast(@min(
            @max(
                payloadU64(payload, "max_bytes") orelse FORENSIC_PAGE_DEFAULT_BYTES,
                FORENSIC_PAGE_MIN_BYTES,
            ),
            FORENSIC_PAGE_MAX_BYTES,
        ));

        const ring = state_mod.g_forensic_ring orelse
            return a.dupe(u8, "{\"available\":false,\"records\":[],\"records_returned\":0,\"records_matched\":0,\"truncated\":false,\"next_after\":null,\"integrity\":\"unavailable\",\"verified\":false}") catch null;

        const count = ring.recordCount();
        const slots = ring.capacity() / forensic_pipeline.RECORD_BYTES;
        const oldest: u64 = if (count > slots) count - slots else 0;
        const chain_verified = ring.verifyHashChain();

        var out = std.ArrayList(u8).init(a);
        errdefer out.deinit();
        var writer = out.writer();

        writer.writeAll("{\"available\":true,\"records\":[") catch return null;
        var returned: u64 = 0;
        var matched: u64 = 0;
        var index = oldest;
        var first = true;
        var truncated = false;
        var last_returned: ?u64 = null;

        // GAP-015: cursor exactness under ring wrap. Sequence space is
        // append-ordered and slot S%capacity holds the newest record with
        // that residue, so starting at max(oldest, after+1) reads each
        // retained seq exactly once. The old per-record seq<=after skip
        // compared STORED seqs (newest aliasing) against the cursor and
        // returned the tip for any mid-ring cursor — windowing that never
        // windowed. A stored seq disagreeing with its index was
        // overwritten mid-scan; skip it (retention loss, not a lie).
        if (requested_after) |after| {
            const floor = if (after >= count) count else after + 1;
            if (floor > index) index = floor;
        }

        while (index < count) : (index += 1) {
            const record = ring.readRecord(index, a) orelse continue;
            defer a.free(record);

            if (record.len < forensic_pipeline.HEADER_BYTES) continue;
            if (!forensic_pipeline.ForensicRing.verifyRecord(record)) continue;

            const header = std.mem.bytesAsValue(
                forensic_pipeline.RecordHeader,
                record[0..forensic_pipeline.HEADER_BYTES],
            );

            if (header.record_seq != index) continue;

            const origin = forensicRecordOrigin(header.reserved[6], header.reserved[5]);

            if (requested_source) |source| {
                if (source > std.math.maxInt(u8) or
                    origin.ordinal != @as(u8, @intCast(source))) continue;
            }

            // EVT-176 / GAP-019: rule-id filter. Ring responses carry no
            // payload text, so content search cannot find one marked event
            // on a busy host; the u32 rule hash (FNV-1a of the rule string,
            // cross-pinned Zig/Go/Python) gives exact attribution instead.
            const requested_rule = payloadU64(payload, "rule");
            if (requested_rule) |rule| {
                if (rule > std.math.maxInt(u32) or
                    header.rule_id != @as(u32, @intCast(rule))) continue;
            }

            const payload_start = forensic_pipeline.HEADER_BYTES;
            const payload_end = payload_start + @as(usize, header.payload_len);
            if (payload_end > record.len) continue;

            if (requested_prefix.len > 0 and
                (requested_prefix.len > @as(usize, header.payload_len) or
                !std.mem.eql(u8, record[payload_start .. payload_start + requested_prefix.len], requested_prefix))) continue;

            matched += 1;

            // Budget gate: the first matching record is always written so a
            // page can never stall, then the writer stops before the response
            // crosses the budget. The record it did not write is covered by
            // the continuation cursor, so it is returned by the next page.
            if (returned > 0 and
                out.items.len + FORENSIC_ENTRY_MAX_BYTES + FORENSIC_FOOTER_BYTES > requested_budget)
            {
                truncated = true;
                break;
            }

            if (!first) writer.writeByte(',') catch return null;
            first = false;
            writer.print(
                "{{\"record_seq\":{},\"event_id\":{},\"rule_id\":{},\"source\":{},\"source_name\":\"{s}\",\"source_space\":\"{s}\",\"payload_len\":{},\"direction\":{s},\"verified\":true}}",
                .{
                    header.record_seq,
                    header.ev_id,
                    header.rule_id,
                    origin.ordinal,
                    origin.name,
                    origin.space,
                    header.payload_len,
                    directionJson(header),
                },
            ) catch return null;
            returned += 1;
            last_returned = header.record_seq;

            if (returned >= requested_limit) {
                truncated = index + 1 < count;
                break;
            }
        }

        // A continuation cursor is emitted only when the page stopped before
        // the end of the ring; null means this page covered every remaining
        // record, so callers can prove completeness instead of assuming it.
        const cursor: ?u64 = if (truncated) last_returned else null;
        writer.print(
            "],\"records_returned\":{},\"records_matched\":{},\"truncated\":{},\"next_after\":",
            .{ returned, matched, truncated },
        ) catch return null;
        if (cursor) |seq| {
            writer.print("{},", .{seq}) catch return null;
        } else {
            writer.writeAll("null,") catch return null;
        }
        writer.print(
            "\"ring_records\":{},\"oldest_record_seq\":{},\"max_bytes\":{},\"integrity\":\"{s}\",\"verified\":{}}}",
            .{
                count,
                oldest,
                requested_budget,
                if (chain_verified) "ok" else "failed",
                chain_verified,
            },
        ) catch return null;

        return out.toOwnedSlice() catch null;
    }

    fn forensicsShow(
        a: std.mem.Allocator,
        payload: std.json.Value,
        ctx: *HandlerContext,
    ) ?[]const u8 {
        const requested_seq =
            payloadU64(payload, "record_seq") orelse
            payloadU64(payload, "id") orelse {
            ctx.failure_code = "INVALID_INPUT";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "record_seq is required";
            return null;
        };

        const ring = state_mod.g_forensic_ring orelse {
            ctx.failure_code = "UNAVAILABLE";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "forensic ring is unavailable";
            return null;
        };

        const slots = ring.capacity() / forensic_pipeline.RECORD_BYTES;
        const count = ring.recordCount();
        const oldest: u64 = if (count > slots) count - slots else 0;

        if (requested_seq < oldest or requested_seq >= count) {
            ctx.failure_code = "RECORD_NOT_FOUND";
            ctx.failure_state = "NOT_FOUND";
            ctx.failure_message = "record_seq is outside the active forensic ring";
            return null;
        }

        const record = ring.readRecord(requested_seq, a) orelse {
            ctx.failure_code = "RECORD_NOT_FOUND";
            ctx.failure_state = "NOT_FOUND";
            ctx.failure_message = "forensic record could not be read";
            return null;
        };
        defer a.free(record);

        if (record.len < forensic_pipeline.HEADER_BYTES or
            !forensic_pipeline.ForensicRing.verifyRecord(record))
        {
            ctx.failure_code = "RECORD_INTEGRITY_FAILED";
            ctx.failure_state = "INTEGRITY_ERROR";
            ctx.failure_message = "forensic record verification failed";
            return null;
        }

        const header = std.mem.bytesAsValue(
            forensic_pipeline.RecordHeader,
            record[0..forensic_pipeline.HEADER_BYTES],
        );

        const payload_start = forensic_pipeline.HEADER_BYTES;
        const payload_end = payload_start + @as(usize, header.payload_len);

        if (payload_end > record.len) {
            ctx.failure_code = "RECORD_INTEGRITY_FAILED";
            ctx.failure_state = "INTEGRITY_ERROR";
            ctx.failure_message = "forensic payload length exceeds record boundary";
            return null;
        }

        const origin = forensicRecordOrigin(header.reserved[6], header.reserved[5]);
        return std.fmt.allocPrint(
            a,
            "{{\"record_seq\":{},\"event_id\":{},\"rule_id\":{},\"source\":{},\"source_name\":\"{s}\",\"source_space\":\"{s}\",\"payload_len\":{},\"direction\":{s},\"verified\":true}}",
            .{
                header.record_seq,
                header.ev_id,
                header.rule_id,
                origin.ordinal,
                origin.name,
                origin.space,
                header.payload_len,
                directionJson(header),
            },
        ) catch null;
    }

    fn directionJson(header: *align(1) const forensic_pipeline.RecordHeader) []const u8 {
        return if (forensic_pipeline.recordDirection(header)) |direction|
            (if (direction == 0) "0" else "1")
        else
            "null";
    }

    fn forensicsVerify(a: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        if (state_mod.g_forensic_ring) |ring| {
            const verified = ring.verifyHashChain();
            // RING-STAT-103: report retention, not just the ever-written
            // total — a fixed ring overwrites, and operators must see loss.
            // Additive keys; old readers ignore them.
            const count = ring.recordCount();
            const slots = ring.capacity() / forensic_pipeline.RECORD_BYTES;
            const retained: u64 = if (count > slots) slots else count;
            const oldest: u64 = if (count > slots) count - slots else 0;
            return std.fmt.allocPrint(a, "{{\"verified\":{},\"integrity\":\"{s}\",\"records\":{},\"retained\":{},\"overwritten\":{},\"capacity_slots\":{},\"oldest_record_seq\":{}}}", .{
                verified,
                if (verified) "ok" else "failed",
                state_mod.g_forensic_records_written.load(.acquire),
                retained,
                ring.overwrittenCount(),
                slots,
                oldest,
            }) catch null;
        }
        return a.dupe(u8, "{\"verified\":false,\"integrity\":\"unavailable\",\"records\":0}") catch null;
    }

    fn forensicsExport(a: std.mem.Allocator, payload: std.json.Value, ctx: *HandlerContext) ?[]const u8 {
        // BE-EXP-099: server-side attested export. Chain-verified records
        // serialize to one JSON line each under logs/ (fixed directory,
        // request_id filename — no operator path input, no traversal).
        // Bounded (limit 1..1000 default 100, 256 KiB budget, truncation
        // flagged); the written file is re-read, counted, and hashed so
        // the response postcondition proves durability, not just intent.
        // Partial files are deleted, never left to masquerade as exports.
        const ring = state_mod.g_forensic_ring orelse {
            ctx.failure_code = "FORENSIC_UNAVAILABLE";
            ctx.failure_state = "UNAVAILABLE";
            ctx.failure_message = "forensic ring is not initialized";
            return null;
        };
        var limit: u64 = 100;
        if (payload == .object) {
            if (payload.object.get("limit")) |lv| {
                if (lv != .integer or lv.integer <= 0 or lv.integer > 1000) {
                    ctx.failure_code = "INVALID_INPUT";
                    ctx.failure_state = "REJECTED";
                    ctx.failure_message = "limit must be an integer in 1..1000";
                    return null;
                }
                limit = @intCast(lv.integer);
            }
        }
        const runtime_paths = @import("../core/runtime_paths.zig");
        const root = runtime_paths.resolveRoot(a) catch {
            ctx.failure_code = "CONFIG_UNAVAILABLE";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "cannot resolve runtime root";
            return null;
        };
        defer a.free(root);
        const logs_dir = std.fs.path.join(a, &.{ root, "logs" }) catch return null;
        defer a.free(logs_dir);
        std.fs.cwd().makePath(logs_dir) catch {
            ctx.failure_code = "EXPORT_FAILED";
            ctx.failure_state = "ERROR";
            ctx.failure_message = "cannot create export directory";
            return null;
        };
        const filename = std.fmt.allocPrint(a, "forensic_export_{d}.json", .{ctx.request_id}) catch return null;
        defer a.free(filename);
        const abs_path = std.fs.path.join(a, &.{ logs_dir, filename }) catch return null;
        defer a.free(abs_path);
        const res = exportRingToFile(a, ring, abs_path, limit) catch |err| {
            ctx.failure_code = if (err == error.ChainBroken) "INTEGRITY_ERROR" else "EXPORT_FAILED";
            ctx.failure_state = if (err == error.ChainBroken) "INTEGRITY_ERROR" else "ERROR";
            ctx.failure_message = if (err == error.ChainBroken)
                "hash chain verification failed; suspect records are not exported"
            else
                "export write or postcondition verification failed";
            return null;
        };
        var hex: [64]u8 = undefined;
        const digits = "0123456789abcdef";
        for (res.sha, 0..) |b, i| {
            hex[2 * i] = digits[b >> 4];
            hex[2 * i + 1] = digits[b & 0xF];
        }
        return std.fmt.allocPrint(
            a,
            "{{\"exported\":true,\"path\":\"{s}\",\"records\":{},\"truncated\":{},\"integrity\":\"ok\",\"sha256\":\"{s}\",\"oldest_record_seq\":{},\"postcondition\":\"WRITTEN_VERIFIED\"}}",
            .{ abs_path, res.records, res.truncated, hex, res.oldest },
        ) catch null;
    }

    const ExportError = error{ ChainBroken, RecordInvalid, WriteFailed, PostconditionFailed, OutOfMemory };

    const ExportResult = struct {
        records: u64,
        truncated: bool,
        oldest: u64,
        sha: [32]u8,
    };

    /// Serialize chain-verified ring records to NDJSON at abs_path, then
    /// prove the file by re-reading it (count + SHA-256). Same entry
    /// shape as forensics.list; payload bytes are NOT exported (metadata
    /// evidence only — full bytes stay behind forensics.show per record).
    fn exportRingToFile(
        a: std.mem.Allocator,
        ring: *forensic_pipeline.ForensicRing,
        abs_path: []const u8,
        limit: u64,
    ) ExportError!ExportResult {
        if (!ring.verifyHashChain()) return ExportError.ChainBroken;
        const count = ring.recordCount();
        const slots = ring.capacity() / forensic_pipeline.RECORD_BYTES;
        const oldest: u64 = if (count > slots) count - slots else 0;

        const file = std.fs.createFileAbsolute(abs_path, .{ .truncate = true }) catch {
            return ExportError.WriteFailed;
        };
        var file_open = true;
        errdefer {
            if (file_open) file.close();
            std.fs.deleteFileAbsolute(abs_path) catch {};
        }
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        var written: u64 = 0;
        var byte_budget: usize = 256 * 1024;
        var index = oldest;
        // Truncated only when the ring holds more than we wrote.
        var truncated = false;
        while (index < count and written < limit) : (index += 1) {
            const record = ring.readRecord(index, a) orelse return ExportError.RecordInvalid;
            defer a.free(record);
            if (record.len < forensic_pipeline.HEADER_BYTES) return ExportError.RecordInvalid;
            if (!forensic_pipeline.ForensicRing.verifyRecord(record)) return ExportError.RecordInvalid;
            const header = std.mem.bytesAsValue(
                forensic_pipeline.RecordHeader,
                record[0..forensic_pipeline.HEADER_BYTES],
            );
            const origin = forensicRecordOrigin(header.reserved[6], header.reserved[5]);
            var line_buf: [512]u8 = undefined;
            var fbs = std.io.fixedBufferStream(&line_buf);
            fbs.writer().print(
                "{{\"record_seq\":{},\"event_id\":{},\"rule_id\":{},\"source\":{},\"source_name\":\"{s}\",\"source_space\":\"{s}\",\"payload_len\":{},\"direction\":{s},\"verified\":true}}\n",
                .{
                    header.record_seq,
                    header.ev_id,
                    header.rule_id,
                    origin.ordinal,
                    origin.name,
                    origin.space,
                    header.payload_len,
                    directionJson(header),
                },
            ) catch return ExportError.WriteFailed;
            const line = fbs.getWritten();
            if (line.len > byte_budget) {
                truncated = true;
                break;
            }
            byte_budget -= line.len;
            file.writer().writeAll(line) catch return ExportError.WriteFailed;
            hasher.update(line);
            written += 1;
        }
        if (index < count) truncated = true;
        file.close();
        file_open = false;
        // Postcondition: re-read, recount, rehash. A short write, a
        // concurrent mutation, or a disk lie fails here — never OK.
        const back = std.fs.cwd().readFileAlloc(a, abs_path, 2 * 1024 * 1024) catch {
            std.fs.deleteFileAbsolute(abs_path) catch {};
            return ExportError.PostconditionFailed;
        };
        defer a.free(back);
        var rehash = std.crypto.hash.sha2.Sha256.init(.{});
        rehash.update(back);
        var digest: [32]u8 = undefined;
        rehash.final(&digest);
        var lines: u64 = 0;
        var it = std.mem.splitScalar(u8, back, '\n');
        while (it.next()) |ln| {
            if (ln.len > 0) lines += 1;
        }
        if (lines != written) {
            std.fs.deleteFileAbsolute(abs_path) catch {};
            return ExportError.PostconditionFailed;
        }
        // The re-read digest IS the attested hash: it proves the exact
        // bytes resting on disk, not bytes we intended to write.
        return .{ .records = written, .truncated = truncated, .oldest = oldest, .sha = digest };
    }

    fn forensicsReplay(a: std.mem.Allocator, _: std.json.Value, ctx: *HandlerContext) ?[]const u8 {
        // Integrity-only observe replay (T1-REPLAY-021). Exports the retained
        // forensic ring, re-verifies CRC + hash chain, and reports the source
        // range with both hashes. Pipeline re-execution is deliberately NOT
        // performed here: replaying events through live detection/policy/PEP
        // would be a second enforcement path, so events_replayed stays 0 and
        // pass stays false until a deterministic re-execution harness exists.
        // Callers must treat pass=false + reason below as "not re-executed",
        // not as integrity failure (see integrity_verified/integrity_errors).
        const replay_mod = @import("../forensic/replay_verifier.zig");
        const ring = state_mod.g_forensic_ring orelse {
            ctx.failure_code = "FORENSIC_UNAVAILABLE";
            ctx.failure_state = "UNAVAILABLE";
            ctx.failure_message = "forensic ring is not initialized";
            return null;
        };
        var verifier = replay_mod.ReplayVerifier.init(a, ring, ctx.request_id);
        defer verifier.deinit();
        _ = verifier.runVerification() catch {
            ctx.failure_code = "REPLAY_EXPORT_FAILED";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "forensic export for replay failed";
            return null;
        };
        verifier.finalize();
        const d = verifier.decision;
        var orig_hex: [64]u8 = undefined;
        var replay_hex: [64]u8 = undefined;
        _ = std.fmt.bufPrint(&orig_hex, "{s}", .{std.fmt.bytesToHex(d.original_hash, .lower)}) catch {
            ctx.failure_code = "INTERNAL_ERROR";
            ctx.failure_state = "ERROR";
            ctx.failure_message = "failed to encode replay hashes";
            return null;
        };
        _ = std.fmt.bufPrint(&replay_hex, "{s}", .{std.fmt.bytesToHex(d.replay_hash, .lower)}) catch {
            ctx.failure_code = "INTERNAL_ERROR";
            ctx.failure_state = "ERROR";
            ctx.failure_message = "failed to encode replay hashes";
            return null;
        };
        return std.fmt.allocPrint(a,
            \\{{"replay_id":{},"mode":"observe_only","source_start":{},"source_end":{},"source_count":{},"integrity_verified":{},"integrity_errors":{},"events_replayed":{},"events_matched":{},"events_mismatched":{},"original_hash":"{s}","replay_hash":"{s}","pass":{},"reason":"pipeline re-execution not performed; integrity-only replay"}}
        , .{
            d.replay_id,
            d.source_start,
            d.source_end,
            d.source_count,
            d.integrity_verified,
            d.integrity_errors,
            d.events_replayed,
            d.events_matched,
            d.events_mismatched,
            orig_hex,
            replay_hex,
            d.pass,
        }) catch null;
    }

    fn enforcementStatus(a: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        const t3 = tier3_mod.g_tier3.state;
        var provider_probe = pep_bindings.PepEnforcer{ .available = state_mod.g_pep_available.load(.acquire) };
        const provider_ready = provider_probe.providerReady();
        const gate_open = state_mod.g_prevention_gate_open;
        // SLICE-C-LAB: additive provenance of the gate position. "closed"
        // is the boot default everywhere; "lab-build-optin" can only be set
        // in memory by a build compiled with -Dlab-prevention-gate=true.
        const gate_source = switch (state_mod.g_gate_source) {
            .closed => "closed",
            .lab_build_optin => "lab-build-optin",
        };
        return std.fmt.allocPrint(a,
            \\{{"tier3":"{s}","tier3_ready":{},"shield_loaded":{},"payload_screening":{},"tier3_enforcing":{},"pep_available":{},"provider_ready":{},"host_effect_capable":{},"prevention_gate":"{s}","gate_source":"{s}","receipt_required":true,"enforcement_mode":"{s}"}}
        , .{
            t3.toString(),
            t3.isEnforcementAllowed(),
            tier3_mod.g_tier3.shield_loaded,
            tier3_mod.g_tier3.payload_screening,
            gate_open,
            state_mod.g_pep_available.load(.acquire),
            provider_ready,
            provider_ready and gate_open,
            if (gate_open) "open" else "closed",
            gate_source,
            // Project 2 observe-only contract: a closed prevention gate must
            // always project detection-only, even when the PEP provider is
            // ready. Provider readiness alone is never active enforcement.
            if (gate_open and provider_ready) "provider-attested-enforcement-enabled" else "detection-only",
        }) catch null;
    }

    fn enforcementSimulate(a: std.mem.Allocator, payload: std.json.Value, ctx: *HandlerContext) ?[]const u8 {
        // Posture projection, not a decision: reports what the current
        // gate/provider posture would do with a requested action, without
        // invoking the PEP, touching quotas, or contacting WFP. enforced is
        // always false here; only enforcement.status + a real receipt can
        // prove a host effect. Input validated before state so malformed
        // calls fail identically with any gate position.
        if (payload != .object) {
            ctx.failure_code = "INVALID_INPUT";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "payload must be an object with action and severity";
            return null;
        }
        const action_val = payload.object.get("action") orelse {
            ctx.failure_code = "INVALID_INPUT";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "action is required (allow/block/rate_limit/quarantine)";
            return null;
        };
        if (action_val != .string) {
            ctx.failure_code = "INVALID_INPUT";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "action must be a string";
            return null;
        }
        const action = action_val.string;
        const known = std.mem.eql(u8, action, "allow") or std.mem.eql(u8, action, "block") or
            std.mem.eql(u8, action, "rate_limit") or std.mem.eql(u8, action, "quarantine");
        if (!known) {
            ctx.failure_code = "INVALID_INPUT";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "action must be allow/block/rate_limit/quarantine";
            return null;
        }
        const sev_val = payload.object.get("severity") orelse {
            ctx.failure_code = "INVALID_INPUT";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "severity is required (integer 0..10)";
            return null;
        };
        if (sev_val != .integer or sev_val.integer < 0 or sev_val.integer > 10) {
            ctx.failure_code = "INVALID_INPUT";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "severity must be an integer in 0..10";
            return null;
        }
        const gate_open = state_mod.g_prevention_gate_open;
        var probe = pep_bindings.PepEnforcer{ .available = state_mod.g_pep_available.load(.acquire) };
        const provider_ready = probe.providerReady();
        if (!gate_open) {
            return std.fmt.allocPrint(a, "{{\"simulated\":true,\"enforced\":false,\"host_effect_confirmed\":false,\"action\":\"{s}\",\"severity\":{},\"prevention_gate\":\"closed\",\"provider_ready\":{},\"outcome\":\"allow\",\"reason\":\"prevention_gate_closed;detection-only;pep_not_invoked\"}}", .{ action, sev_val.integer, provider_ready }) catch null;
        }
        if (!provider_ready) {
            return std.fmt.allocPrint(a, "{{\"simulated\":true,\"enforced\":false,\"host_effect_confirmed\":false,\"action\":\"{s}\",\"severity\":{},\"prevention_gate\":\"open\",\"provider_ready\":false,\"outcome\":\"escalate\",\"reason\":\"provider_unavailable;pep_not_invoked\"}}", .{ action, sev_val.integer }) catch null;
        }
        return std.fmt.allocPrint(a, "{{\"simulated\":true,\"enforced\":false,\"host_effect_confirmed\":false,\"action\":\"{s}\",\"severity\":{},\"prevention_gate\":\"open\",\"provider_ready\":true,\"outcome\":\"would_request\",\"reason\":\"simulation_only;pep_not_invoked;approval_state_pep_held\"}}", .{ action, sev_val.integer }) catch null;
    }

    const VerifyTarget = struct {
        filter_id: u64,
        direction: u8,
        remote_ipv4: u32,
        service_port: u16,
        protocol: u8,
    };

    /// Parse the exact postcondition tuple. Direction 0 keeps the historical
    /// outbound dst_ip/dst_port contract. Direction 1 names the inbound peer
    /// (src_ip) and the local service port (dst_port). The explicit direction
    /// removes the ambiguity that made an inbound verify look like a mismatch
    /// when the caller supplied the original destination instead of the peer.
    fn parseVerifyTarget(payload: std.json.Value, ctx: *HandlerContext) ?VerifyTarget {
        const filter_id = payloadU64(payload, "filter_id") orelse {
            ctx.failure_code = "INVALID_INPUT";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "filter_id from an EnforcementReceipt is required";
            return null;
        };
        const direction_present = payload == .object and payload.object.get("direction") != null;
        const direction_u64 = if (direction_present)
            payloadU64(payload, "direction") orelse {
                ctx.failure_code = "INVALID_INPUT";
                ctx.failure_state = "REJECTED";
                ctx.failure_message = "direction must be 0 (outbound) or 1 (inbound)";
                return null;
            }
        else
            0;
        if (direction_u64 > 1) {
            ctx.failure_code = "INVALID_INPUT";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "direction must be 0 (outbound) or 1 (inbound)";
            return null;
        }
        const direction: u8 = @intCast(direction_u64);
        const remote_ipv4 = if (direction == 1)
            payloadU64(payload, "src_ip") orelse {
                ctx.failure_code = "INVALID_INPUT";
                ctx.failure_state = "REJECTED";
                ctx.failure_message = "src_ip is required for inbound postcondition verification";
                return null;
            }
        else
            payloadU64(payload, "dst_ip") orelse {
                ctx.failure_code = "INVALID_INPUT";
                ctx.failure_state = "REJECTED";
                ctx.failure_message = "dst_ip is required for outbound postcondition verification";
                return null;
            };
        if (direction == 1 and remote_ipv4 == 0) {
            ctx.failure_code = "INVALID_INPUT";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "src_ip must be nonzero for inbound postcondition verification";
            return null;
        }
        const service_port = payloadU64(payload, "dst_port") orelse {
            ctx.failure_code = "INVALID_INPUT";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "dst_port is required for exact postcondition verification";
            return null;
        };
        const proto = payloadU64(payload, "protocol") orelse {
            ctx.failure_code = "INVALID_INPUT";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "protocol is required for exact postcondition verification";
            return null;
        };
        if (filter_id == 0 or remote_ipv4 > std.math.maxInt(u32) or
            service_port > std.math.maxInt(u16) or proto > std.math.maxInt(u8))
        {
            ctx.failure_code = "INVALID_INPUT";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "postcondition fields exceed ABI bounds";
            return null;
        }
        return .{
            .filter_id = filter_id,
            .direction = direction,
            .remote_ipv4 = @intCast(remote_ipv4),
            .service_port = @intCast(service_port),
            .protocol = @intCast(proto),
        };
    }

    /// The provider query is already scoped to target.direction, so a
    /// wrong-layer filter cannot produce `present` here. Keep the tuple
    /// comparison exact; direction is not a field of the 20-byte read-back.
    fn verifyStateMatches(target: VerifyTarget, state: pep_bindings.PepFilterState) bool {
        return state.filterId() == target.filter_id and
            state.remoteIpv4() == target.remote_ipv4 and
            state.remotePort() == target.service_port and
            state.protocol() == target.protocol and
            state.present() != 0;
    }

    fn enforcementVerify(a: std.mem.Allocator, payload: std.json.Value, ctx: *HandlerContext) ?[]const u8 {
        const target = parseVerifyTarget(payload, ctx) orelse return null;
        var pep = pep_bindings.PepEnforcer{ .available = state_mod.g_pep_available.load(.acquire) };
        const state = pep.queryFilter(target.filter_id, target.direction) orelse {
            ctx.failure_code = "POSTCONDITION_FAILED";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "receipt filter is not present or provider query failed";
            return null;
        };
        if (!verifyStateMatches(target, state)) {
            ctx.failure_code = "POSTCONDITION_FAILED";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "receipt filter does not match the requested exact flow";
            return null;
        }
        if (target.direction == 1) {
            return std.fmt.allocPrint(a, "{{\"verified\":true,\"filter_id\":{},\"present\":true,\"direction\":1,\"remote_ipv4\":{},\"src_ip\":{},\"dst_port\":{},\"protocol\":{},\"postcondition\":\"MATCH\"}}", .{ target.filter_id, target.remote_ipv4, target.remote_ipv4, target.service_port, target.protocol }) catch null;
        }
        return std.fmt.allocPrint(a, "{{\"verified\":true,\"filter_id\":{},\"present\":true,\"direction\":0,\"remote_ipv4\":{},\"dst_ip\":{},\"dst_port\":{},\"protocol\":{},\"postcondition\":\"MATCH\"}}", .{ target.filter_id, target.remote_ipv4, target.remote_ipv4, target.service_port, target.protocol }) catch null;
    }

    fn payloadU64(payload: std.json.Value, key: []const u8) ?u64 {
        if (payload != .object) return null;
        const value = payload.object.get(key) orelse return null;
        if (value != .integer or value.integer < 0) return null;
        return @intCast(value.integer);
    }

    fn payloadBool(payload: std.json.Value, key: []const u8) ?bool {
        if (payload != .object) return null;
        const value = payload.object.get(key) orelse return null;
        return switch (value) {
            .bool => |b| b,
            .integer => |i| if (i == 0) false else if (i == 1) true else null,
            else => null,
        };
    }

    /// G5: workable two-person ceremony identity. The daemon's control
    /// request_id is a GLOBAL counter shared with pipeline audit entries
    /// (1100+/s), so approving-then-hitting it is a race no operator can
    /// win. An explicit nonzero payload request_id is the ceremony
    /// identity instead: approve(X), then block/quarantine carrying
    /// request_id=X, in either pace — the approval sits pending, matched
    /// exactly by the Rust gate. Absent/zero keeps the legacy ctx id.
    fn ceremonyRequestId(payload: std.json.Value, ctx_id: u64) u64 {
        const v = payloadU64(payload, "request_id") orelse return ctx_id;
        return if (v == 0) ctx_id else v;
    }

    /// DETECTION-ONLY (issue #25): the confirmed product decision is that this
    /// IDS never mutates the host. The verb stays registered so a legacy caller
    /// gets an explicit refusal instead of an unknown-method error, but no
    /// authorization, ceremony or payload can reach a host effect. Cleanup of
    /// pre-existing filters stays available through enforcement.unblock.
    fn enforcementBlock(a: std.mem.Allocator, payload: std.json.Value, ctx: *HandlerContext) ?[]const u8 {
        _ = a;
        _ = payload;
        ctx.failure_code = "DETECTION_ONLY";
        ctx.failure_state = "REFUSED";
        ctx.failure_message = "enforcement.block is refused: AEGIS is detection-only and never applies a host effect";
        return null;
    }

    /// DETECTION-ONLY (issue #25): same refusal as enforcement.block. A
    /// quarantine is a host effect; this build classifies and escalates, it
    /// never applies one.
    fn enforcementQuarantine(a: std.mem.Allocator, payload: std.json.Value, ctx: *HandlerContext) ?[]const u8 {
        _ = a;
        _ = payload;
        ctx.failure_code = "DETECTION_ONLY";
        ctx.failure_state = "REFUSED";
        ctx.failure_message = "enforcement.quarantine is refused: AEGIS is detection-only and never applies a host effect";
        return null;
    }

    fn enforcementUnblock(a: std.mem.Allocator, payload: std.json.Value, ctx: *HandlerContext) ?[]const u8 {
        if (ctx.caller_role != .privileged) {
            ctx.failure_code = "AUTH_DENIED";
            ctx.failure_state = "UNAUTHORIZED";
            ctx.failure_message = "enforcement.unblock requires privileged control-plane authorization";
            return null;
        }
        const filter_id = payloadU64(payload, "filter_id") orelse {
            ctx.failure_code = "INVALID_INPUT";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "filter_id from an EnforcementReceipt is required";
            return null;
        };
        if (filter_id == 0) {
            ctx.failure_code = "INVALID_INPUT";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "filter_id from an EnforcementReceipt must be non-zero";
            return null;
        }
        var pep = pep_bindings.PepEnforcer{ .available = state_mod.g_pep_available.load(.acquire) };
        if (!pep.unblockFilter(filter_id, ctx.caller_pid, 1, ctx.request_id)) {
            ctx.failure_code = "CLEANUP_FAILED";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "Rust PEP could not remove the exact receipt filter";
            return null;
        }
        // The unblock payload may name either an outbound or an inbound
        // receipt filter. Prove absence on both layers; a single-direction
        // query would call an inbound filter "absent" while it still exists.
        const outbound_absent = switch (pep.queryFilterResult(filter_id, 0)) {
            .absent => true,
            .present => false,
            .query_error => {
                ctx.failure_code = "CLEANUP_POSTCONDITION_FAILED";
                ctx.failure_state = "ROLLBACK_PENDING";
                ctx.failure_message = "filter removal returned but outbound absence could not be proven";
                return null;
            },
        };
        const inbound_absent = switch (pep.queryFilterResult(filter_id, 1)) {
            .absent => true,
            .present => false,
            .query_error => {
                ctx.failure_code = "CLEANUP_POSTCONDITION_FAILED";
                ctx.failure_state = "ROLLBACK_PENDING";
                ctx.failure_message = "filter removal returned but inbound absence could not be proven";
                return null;
            },
        };
        if (outbound_absent and inbound_absent) {
            return std.fmt.allocPrint(a, "{{\"status\":\"ROLLED_BACK\",\"filter_id\":{},\"present\":false,\"postcondition\":\"ABSENT\"}}", .{filter_id}) catch null;
        }
        ctx.failure_code = "CLEANUP_POSTCONDITION_FAILED";
        ctx.failure_state = "ROLLBACK_PENDING";
        ctx.failure_message = "filter removal returned but the exact filter is still present";
        return null;
    }

    /// T3-TWOP-023: privileged control-plane edge for the two-person rule.
    /// Flips Rust PEP authorization policy for high-severity BLOCKs; the FFI
    /// requires capability bit 0x01 (passed as 1, like every other PEP call
    /// from this file). Disabling drops pending approvals inside the DLL.
    fn enforcementTwoPerson(a: std.mem.Allocator, payload: std.json.Value, ctx: *HandlerContext) ?[]const u8 {
        if (ctx.caller_role != .privileged) {
            ctx.failure_code = "AUTH_DENIED";
            ctx.failure_state = "UNAUTHORIZED";
            ctx.failure_message = "enforcement.two_person requires privileged control-plane authorization";
            return null;
        }
        const enabled = payloadBool(payload, "enabled") orelse {
            ctx.failure_code = "INVALID_INPUT";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "enabled must be a boolean (or 0/1)";
            return null;
        };
        var pep = pep_bindings.PepEnforcer{ .available = state_mod.g_pep_available.load(.acquire) };
        if (!pep.setTwoPersonRule(enabled, 1)) {
            ctx.failure_code = "PEP_UNAVAILABLE";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "Rust PEP did not accept the two-person rule change";
            return null;
        }
        return std.fmt.allocPrint(a, "{{\"two_person_rule\":{},\"postcondition\":\"SET\"}}", .{enabled}) catch null;
    }

    /// T3-TWOP-023: records a one-shot second-human approval for a single
    /// enforcement request_id. Approval identity is the calling operator's
    /// pid; the DLL consumes the approval on the next matching BLOCK.
    fn enforcementApprove(a: std.mem.Allocator, payload: std.json.Value, ctx: *HandlerContext) ?[]const u8 {
        if (ctx.caller_role != .privileged) {
            ctx.failure_code = "AUTH_DENIED";
            ctx.failure_state = "UNAUTHORIZED";
            ctx.failure_message = "enforcement.approve requires privileged control-plane authorization";
            return null;
        }
        const request_id = payloadU64(payload, "request_id") orelse {
            ctx.failure_code = "INVALID_INPUT";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "request_id must be a non-zero integer";
            return null;
        };
        if (request_id == 0) {
            ctx.failure_code = "INVALID_INPUT";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "request_id must be a non-zero integer";
            return null;
        }
        var pep = pep_bindings.PepEnforcer{ .available = state_mod.g_pep_available.load(.acquire) };
        if (!pep.approveRequest(request_id, ctx.caller_pid, 1)) {
            ctx.failure_code = "PEP_UNAVAILABLE";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "Rust PEP did not record the approval";
            return null;
        }
        return std.fmt.allocPrint(a, "{{\"approved\":true,\"request_id\":{},\"approver_pid\":{},\"postcondition\":\"RECORDED\"}}", .{ request_id, ctx.caller_pid }) catch null;
    }

    fn metricsSnapshot(a: std.mem.Allocator, _: std.json.Value, ctx: *HandlerContext) ?[]const u8 {
        const uptime_sec: u64 = @intCast(@max(@as(i128, 0), @divTrunc(std.time.nanoTimestamp() - ctx.start_ns, std.time.ns_per_s)));
        // T1-SIEM-021b: SIEM durability is operator-visible here. Zeros when
        // the forwarder was never initialized (enabled=false tells why).
        const siem = siem_mod.getStats();
        const siem_enabled = siem_mod.isEnabled();
        // T3-TSIR-025: TS-authored IR mirror (verify-only). Absent by
        // default; loaded=false tells why instead of claiming rules.
        // Pointer captures: the stored IR is large (256-rule array), never
        // copied for a metrics read.
        const pir_loaded = state_mod.g_policy_ir != null;
        const pir_rules: u16 = if (state_mod.g_policy_ir) |*p| p.ir.rule_count else 0;
        const pir_hash: []const u8 = if (state_mod.g_policy_ir) |*p| &p.hash_hex else "";
        // POL-SIGN-079B: observe-only Ed25519 verdict over the exact
        // mirrored bytes (sidecar + AEGIS_POLICY_PUBKEY at startup).
        // False covers absent sidecar, absent anchor, and INVALID alike:
        // unverified is the normal state until key custody lands, and it
        // changes no enforcement decision anywhere.
        const pir_verified = state_mod.g_policy_ir_verified.load(.acquire);
        // METR-U64-061: lifetime counters print full u64. Narrowing casts
        // (@as(u32, @intCast(...))) panicked debug builds past 4B events
        // and wrapped release builds silently (~71 min at 1M eps). JSON
        // consumers (Python int, Rust as_u64) take full width; JS Number
        // stays precise to 2^53, unreachable in practice.
        return std.fmt.allocPrint(a,
            \\{{"uptime_sec":{},"rules_loaded":{},"packets_captured":{},"events_processed":{},"forensic_records":{},"flows_active":{},"incidents_open":{},"detections":{},"anomalies":{},"blocks":{},"confirmed_blocks":{},"confirmed_quarantines":{},"errors":{},"siem":{{"enabled":{},"forwarded":{},"failed":{},"spooled":{},"batches":{},"retries":{}}},"policy_ir":{{"loaded":{},"rules":{},"hash":"{s}","verified":{}}}}}
        , .{
            uptime_sec,
            state_mod.g_rules_loaded.load(.acquire),
            state_mod.g_nose_frames_submitted.load(.acquire),
            state_mod.g_pipeline_events_processed.load(.acquire),
            state_mod.g_forensic_records_written.load(.acquire),
            diag.metrics.flows_active.get(),
            state_mod.g_incidents_open.load(.acquire),
            state_mod.g_pipeline_detections.load(.acquire),
            diag.metrics.anomalies_detected.get(),
            diag.metrics.blocks_issued.get(),
            state_mod.g_confirmed_blocks.load(.acquire),
            state_mod.g_confirmed_quarantines.load(.acquire),
            diag.metrics.errors.get(),
            siem_enabled,
            siem.total_events_forwarded,
            siem.total_events_failed,
            siem.total_events_spooled,
            siem.total_batches_sent,
            siem.total_retries,
            pir_loaded,
            pir_rules,
            pir_hash,
            pir_verified,
        }) catch null;
    }

    fn logsTail(a: std.mem.Allocator, payload: std.json.Value, ctx: *HandlerContext) ?[]const u8 {
        // Tail the forensic NDJSON log (read-only). Bounded: at most 100
        // entries and 32 KiB total so the response always fits one pipe
        // read. Lines are JSON-escaped, never spliced raw.
        var limit: usize = 20;
        if (payload == .object) {
            if (payload.object.get("limit")) |lv| {
                if (lv != .integer or lv.integer <= 0 or lv.integer > 100) {
                    ctx.failure_code = "INVALID_INPUT";
                    ctx.failure_state = "REJECTED";
                    ctx.failure_message = "limit must be an integer in 1..100";
                    return null;
                }
                limit = @intCast(lv.integer);
            }
        }
        const file = std.fs.cwd().openFile("logs\\aegis_core.ndjson", .{}) catch {
            ctx.failure_code = "LOG_UNAVAILABLE";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "forensic log is not readable here";
            return null;
        };
        defer file.close();
        const stat = file.stat() catch {
            ctx.failure_code = "LOG_UNAVAILABLE";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "forensic log stat failed";
            return null;
        };
        const max_bytes: u64 = 64 * 1024;
        const tail_len: usize = @intCast(@min(stat.size, max_bytes));
        if (tail_len == 0) return a.dupe(u8, "{\"entries\":[]}") catch null;
        const start: u64 = stat.size - tail_len;
        file.seekTo(start) catch {
            ctx.failure_code = "LOG_UNAVAILABLE";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "forensic log seek failed";
            return null;
        };
        const buf = a.alloc(u8, tail_len) catch return null;
        defer a.free(buf);
        var total: usize = 0;
        while (total < tail_len) {
            const n = file.read(buf[total..]) catch {
                ctx.failure_code = "LOG_UNAVAILABLE";
                ctx.failure_state = "DEGRADED";
                ctx.failure_message = "forensic log read failed";
                return null;
            };
            if (n == 0) break;
            total += n;
        }
        // Collect the last `limit` non-empty lines (skip a leading partial
        // line when the window starts mid-record).
        var lines: [100][]const u8 = undefined;
        var count: usize = 0;
        var it = std.mem.splitScalar(u8, buf[0..total], '\n');
        var first = true;
        while (it.next()) |line| {
            if (first and start != 0) {
                first = false;
                continue;
            }
            first = false;
            if (line.len == 0) continue;
            if (count < lines.len) {
                lines[count] = line;
                count += 1;
            } else {
                std.mem.copyForwards([]const u8, lines[0 .. lines.len - 1], lines[1..]);
                lines[lines.len - 1] = line;
            }
        }
        const keep_from = if (count > limit) count - limit else 0;
        var out = std.ArrayList(u8).init(a);
        defer out.deinit();
        const writer = out.writer();
        writer.writeAll("{\"entries\":[") catch return null;
        var emitted: usize = 0;
        for (lines[keep_from..count]) |line| {
            if (emitted > 0) writer.writeByte(',') catch return null;
            std.json.stringify(line, .{}, writer) catch return null;
            emitted += 1;
        }
        writer.writeAll("]}") catch return null;
        return out.toOwnedSlice() catch null;
    }

    fn federationStatus(a: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        // Live status from the uplink (FED-P4). When the uplink is not
        // installed (standalone), report the truthful standalone state.
        const uplink = @import("../federation/cluster_uplink.zig");
        if (uplink.g_uplink) |u| {
            return u.statusJson(a) catch null;
        }
        return a.dupe(u8, "{\"mode\":\"standalone\",\"cluster_enabled\":false,\"nodes\":0,\"role\":\"standalone\"}") catch null;
    }

    fn runtimeStart(a: std.mem.Allocator, _: std.json.Value, ctx: *HandlerContext) ?[]const u8 {
        // The process that owns this control pipe is already the runtime
        // owner.  A control request must never create a second worker set.
        // Treat start as an idempotent assertion only when the state machine
        // proves that this owner is serving; a stopped/degraded owner cannot
        // claim that it started successfully.
        const sm = @import("state_machine.zig");
        sm.g_runtime.mutex.lock();
        const current = sm.g_runtime.system_state;
        sm.g_runtime.mutex.unlock();

        if (current == .running or current == .ready) {
            return std.fmt.allocPrint(a, "{{\"requested\":\"start\",\"accepted\":true,\"idempotent\":true,\"state\":\"{s}\",\"owner\":\"daemon\"}}", .{current.toString()}) catch null;
        }

        ctx.failure_code = "RUNTIME_NOT_READY";
        ctx.failure_state = current.toString();
        ctx.failure_message = "runtime.start cannot create workers through the control pipe; daemon owner is not ready";
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

    fn daemonShutdown(a: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        // The daemon supervisor owns the STOPPED postcondition. This handler
        // only requests cancellation; workers and pipe handles may still be
        // live while the control response is being returned.
        const sm = @import("state_machine.zig");

        sm.g_runtime.transition(.stopping);

        // CTRL-002: Signal worker threads to stop
        const rt = @import("../pipeline/runtime_state.zig");
        rt.g_stop_requested.store(true, .release);

        bridge_init.requestShutdown();

        return a.dupe(u8, "{\"shutdown_requested\":true,\"state\":\"STOPPING\"}") catch null;
    }
};

// ============================================================
// Tests (T3-TWOP-023)
// ============================================================

test "enforcementTwoPerson denies non-privileged callers before touching PEP" {
    var ctx = HandlerContext{ .start_ns = 0, .request_id = 7, .caller_role = .read, .caller_pid = 1234 };
    const out = handlers.enforcementTwoPerson(std.testing.allocator, .{ .null = {} }, &ctx);
    try std.testing.expect(out == null);
    try std.testing.expectEqualStrings("AUTH_DENIED", ctx.failure_code.?);
    try std.testing.expectEqualStrings("UNAUTHORIZED", ctx.failure_state.?);
}

test "enforcementApprove denies non-privileged callers before touching PEP" {
    var ctx = HandlerContext{ .start_ns = 0, .request_id = 7, .caller_role = .operate, .caller_pid = 1234 };
    const out = handlers.enforcementApprove(std.testing.allocator, .{ .null = {} }, &ctx);
    try std.testing.expect(out == null);
    try std.testing.expectEqualStrings("AUTH_DENIED", ctx.failure_code.?);
    try std.testing.expectEqualStrings("UNAUTHORIZED", ctx.failure_state.?);
}

test "payloadBool accepts booleans and 0/1 integers only" {
    const bare = std.json.Value{ .bool = true };
    try std.testing.expect(handlers.payloadBool(bare, "enabled") == null); // not an object
    var obj = std.json.Value{ .object = std.json.ObjectMap.init(std.testing.allocator) };
    defer obj.object.deinit();
    try obj.object.put("b", .{ .bool = true });
    try obj.object.put("i1", .{ .integer = 1 });
    try obj.object.put("i0", .{ .integer = 0 });
    try obj.object.put("i2", .{ .integer = 2 });
    try obj.object.put("s", .{ .string = "on" });
    try std.testing.expectEqual(true, handlers.payloadBool(obj, "b").?);
    try std.testing.expectEqual(true, handlers.payloadBool(obj, "i1").?);
    try std.testing.expectEqual(false, handlers.payloadBool(obj, "i0").?);
    try std.testing.expect(handlers.payloadBool(obj, "i2") == null);
    try std.testing.expect(handlers.payloadBool(obj, "s") == null);
    try std.testing.expect(handlers.payloadBool(obj, "missing") == null);
}

test "metricsSnapshot exposes SIEM durability counters" {
    // T1-SIEM-021b: operators must see forwarded/failed/spooled without a
    // live forwarder (zeros + enabled=false is the honest uninitialized
    // answer, never a claim).
    var ctx = HandlerContext{ .start_ns = 0, .request_id = 9, .caller_role = .read, .caller_pid = 0 };
    const out = handlers.metricsSnapshot(std.testing.allocator, .{ .null = {} }, &ctx).?;
    defer std.testing.allocator.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"siem\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"spooled\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"forwarded\"") != null);
    // T3-TSIR-025: TS-IR mirror reports absent-but-honest with no file.
    try std.testing.expect(std.mem.indexOf(u8, out, "\"policy_ir\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"loaded\":false") != null);
    // POL-SIGN-079B: observe-only verdict rides along, false by default.
    try std.testing.expect(std.mem.indexOf(u8, out, "\"verified\":false") != null);
    // G2-METRICS-001: the receipt-verified host-effect counters are
    // operator-visible without relying on a stderr diagnostic stream.
    try std.testing.expect(std.mem.indexOf(u8, out, "\"confirmed_blocks\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"confirmed_quarantines\"") != null);
}

test "queueStats emits parseable JSON with shed and etw keys (GAP-015)" {
    // The G3 etw tail once closed only the etw object, leaving the root
    // unbalanced: successEnvelope re-parse failed (UnexpectedEndOfInput)
    // and every queue.stats query answered INTERNAL_ERROR live. This test
    // parses the real handler output, so no response shape can regress
    // to unparseable again.
    var ctx = HandlerContext{ .start_ns = 0, .request_id = 29, .caller_role = .read, .caller_pid = 0 };
    const out = handlers.queueStats(std.testing.allocator, .{ .null = {} }, &ctx).?;
    defer std.testing.allocator.free(out);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, out, .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try std.testing.expect(root.contains("queue_size"));
    // IDS-QUEUE-001: the network admission reserve and its refusal cause are
    // stated, so a drop below queue_size is explainable rather than a bug.
    try std.testing.expect(root.contains("reserved_network_slots"));
    try std.testing.expect(root.contains("reserved_tail_shed"));
    try std.testing.expectEqual(@as(i64, @intCast(event_queue.RESERVED_NETWORK_SLOTS)), root.get("reserved_network_slots").?.integer);
    try std.testing.expect(root.get("reserved_tail_shed").?.integer >= 0);
    try std.testing.expect(root.contains("shed_overload"));
    // ADR-0012 measurement gate: the duplicate probe is always reported, so
    // the gate's ratio is read from the daemon, not inferred from a log.
    try std.testing.expect(root.contains("fim_probe"));
    const fim_probe = root.get("fim_probe").?.object;
    try std.testing.expect(fim_probe.contains("batch_records"));
    try std.testing.expect(fim_probe.contains("batch_duplicates"));
    try std.testing.expect(fim_probe.contains("batch_duplicates_per_pid"));
    try std.testing.expect(fim_probe.contains("batch_overflow"));
    try std.testing.expect(fim_probe.get("minifilter").?.object.contains("duplicates_per_pid"));
    try std.testing.expect(fim_probe.get("minifilter").?.object.contains("duplicates_same_ts"));
    try std.testing.expect(fim_probe.get("minifilter").?.object.contains("duplicates"));
    try std.testing.expect(fim_probe.get("native_poll").?.object.contains("duplicates"));
    try std.testing.expect(root.contains("minifilter_pipeline_dropped"));
    try std.testing.expect(root.contains("by_source"));
    try std.testing.expect(root.contains("by_source_kind"));
    try std.testing.expect(root.contains("pipeline"));
    try std.testing.expect(root.contains("etw"));
    try std.testing.expect(root.get("etw").?.object.contains("file_write"));
    // #29 ETW-FILE-DEDUPE-001: suppressed duplicates are a counted class, so
    // operators can see observed NameCreate = pushed + deduped.
    try std.testing.expect(root.get("etw").?.object.contains("name_create_deduped"));
    try std.testing.expect(root.get("etw").?.object.contains("predecode_dropped"));
    try std.testing.expect(root.get("etw").?.object.contains("shed_exempted"));
    // EVT-211: the wfp health block must be present and parseable; state
    // is a string so operators can tell labeled absence from flowing.
    try std.testing.expect(root.contains("wfp"));
    const wfp = root.get("wfp").?.object;
    try std.testing.expect(wfp.contains("state"));
    try std.testing.expect(wfp.contains("reads"));
    try std.testing.expect(wfp.contains("rows"));
    try std.testing.expect(wfp.contains("last_bytes"));
    // PHASE-6: acquisition arbitration is stated, not inferred: which
    // source owns ingress, why, and how many kernel rows it shadowed.
    try std.testing.expect(wfp.contains("mode"));
    try std.testing.expect(wfp.contains("reason"));
    try std.testing.expect(wfp.contains("shadow_rows"));
    try std.testing.expect(wfp.contains("kernel_owned"));
    // Until the telemetry loop publishes a decision the fields report the
    // honest pre-decision state, not an invented primary mode.
    try std.testing.expectEqualStrings("undecided", wfp.get("mode").?.string);
    try std.testing.expectEqualStrings("none", wfp.get("reason").?.string);
    try std.testing.expectEqual(@as(i64, 0), wfp.get("shadow_rows").?.integer);
    try std.testing.expect(!wfp.get("kernel_owned").?.bool);
    // EVT-230: the minifilter health block (same labeled-absence rule as
    // wfp) plus the KERNEL ring's own dropped counter - loss visibility.
    try std.testing.expect(root.contains("minifilter"));
    const mf = root.get("minifilter").?.object;
    try std.testing.expect(mf.contains("state"));
    try std.testing.expect(mf.contains("reads"));
    try std.testing.expect(mf.contains("rows"));
    try std.testing.expect(mf.contains("last_bytes"));
    try std.testing.expect(mf.contains("dropped"));
    try std.testing.expect(mf.contains("pipeline_dropped"));
}

test "ceremonyRequestId prefers explicit identity, falls back to ctx (G5)" {
    // The two-person match keys on this id; a missing/zero payload keeps
    // the legacy control-message id so old callers behave identically.
    const made = std.json.parseFromSlice(std.json.Value, std.testing.allocator, "{\"request_id\":9001}", .{}) catch unreachable;
    defer made.deinit();
    try std.testing.expectEqual(@as(u64, 9001), handlers.ceremonyRequestId(made.value, 41));
    const zero = std.json.parseFromSlice(std.json.Value, std.testing.allocator, "{\"request_id\":0}", .{}) catch unreachable;
    defer zero.deinit();
    try std.testing.expectEqual(@as(u64, 41), handlers.ceremonyRequestId(zero.value, 41));
    const bare = std.json.parseFromSlice(std.json.Value, std.testing.allocator, "{\"dst_ip\":1}", .{}) catch unreachable;
    defer bare.deinit();
    try std.testing.expectEqual(@as(u64, 41), handlers.ceremonyRequestId(bare.value, 41));
}

test "B1: enforcement.quarantine is refused before any gate (issue #25)" {
    // Nothing can reach a quarantine: not a malformed payload, not an
    // anonymous caller, not a privileged caller with a complete ceremony.
    // The refusal comes first, so the reason is the product decision rather
    // than whichever validation would have failed next.
    var ctx = HandlerContext{ .start_ns = 0, .request_id = 39, .caller_role = .privileged, .caller_pid = 0 };
    const bad = std.json.parseFromSlice(std.json.Value, std.testing.allocator, "{\"dst_ip\":1}", .{}) catch unreachable;
    defer bad.deinit();
    try std.testing.expect(handlers.enforcementQuarantine(std.testing.allocator, bad.value, &ctx) == null);
    try std.testing.expectEqualStrings("DETECTION_ONLY", ctx.failure_code.?);

    var anon = HandlerContext{ .start_ns = 0, .request_id = 39, .caller_role = .read, .caller_pid = 0 };
    const full = std.json.parseFromSlice(std.json.Value, std.testing.allocator, "{\"dst_ip\":1,\"dst_port\":80,\"protocol\":6,\"policy_id\":1,\"event_id\":1,\"trace_id\":1}", .{}) catch unreachable;
    defer full.deinit();
    try std.testing.expect(handlers.enforcementQuarantine(std.testing.allocator, full.value, &anon) == null);
    try std.testing.expectEqualStrings("DETECTION_ONLY", anon.failure_code.?);

    var privileged = HandlerContext{ .start_ns = 0, .request_id = 39, .caller_role = .privileged, .caller_pid = 0 };
    try std.testing.expect(handlers.enforcementQuarantine(std.testing.allocator, full.value, &privileged) == null);
    try std.testing.expectEqualStrings("DETECTION_ONLY", privileged.failure_code.?);
}

test "B1: enforcement.block is refused before any gate (issue #25)" {
    var payload_ctx = HandlerContext{ .start_ns = 0, .request_id = 40, .caller_role = .privileged, .caller_pid = 0 };
    const payload = std.json.parseFromSlice(std.json.Value, std.testing.allocator, "{\"dst_ip\":1,\"dst_port\":443,\"protocol\":6,\"policy_id\":2,\"event_id\":3,\"trace_id\":4}", .{}) catch unreachable;
    defer payload.deinit();
    try std.testing.expect(handlers.enforcementBlock(std.testing.allocator, payload.value, &payload_ctx) == null);
    try std.testing.expectEqualStrings("DETECTION_ONLY", payload_ctx.failure_code.?);
    try std.testing.expectEqualStrings("REFUSED", payload_ctx.failure_state.?);
}

test "metricsSnapshot prints lifetime counters at full u64 width" {
    // METR-U64-061: narrowing casts panicked debug builds past 4B events
    // (and wrapped release builds silently). A >u32max counter must
    // round-trip through the formatter with every digit intact.
    const state = @import("../pipeline/runtime_state.zig");
    const prev = state.g_nose_frames_submitted.load(.acquire);
    const prev_blocks = state.g_confirmed_blocks.load(.acquire);
    const prev_quarantines = state.g_confirmed_quarantines.load(.acquire);
    defer {
        state.g_nose_frames_submitted.store(prev, .monotonic);
        state.g_confirmed_blocks.store(prev_blocks, .monotonic);
        state.g_confirmed_quarantines.store(prev_quarantines, .monotonic);
    }
    state.g_nose_frames_submitted.store(0x1_0000_0042, .monotonic);
    state.g_confirmed_blocks.store(0x1_0000_0042, .monotonic);
    state.g_confirmed_quarantines.store(0x1_0000_0043, .monotonic);
    var ctx = HandlerContext{ .start_ns = 0, .request_id = 19, .caller_role = .read, .caller_pid = 0 };
    const out = handlers.metricsSnapshot(std.testing.allocator, .{ .null = {} }, &ctx).?;
    defer std.testing.allocator.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"packets_captured\":4294967362") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"confirmed_blocks\":4294967362") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"confirmed_quarantines\":4294967363") != null);
}

test "enforcement.verify parses legacy outbound target" {
    // No direction keeps the historical dst_ip/dst_port contract.
    const parsed = std.json.parseFromSlice(std.json.Value, std.testing.allocator, "{\"filter_id\":78093,\"dst_ip\":3405803786,\"dst_port\":443,\"protocol\":6}", .{}) catch unreachable;
    defer parsed.deinit();
    var ctx = HandlerContext{ .start_ns = 0, .request_id = 31, .caller_role = .read, .caller_pid = 0 };
    const target = handlers.parseVerifyTarget(parsed.value, &ctx).?;
    try std.testing.expectEqual(@as(u64, 78093), target.filter_id);
    try std.testing.expectEqual(@as(u8, 0), target.direction);
    try std.testing.expectEqual(@as(u32, 3405803786), target.remote_ipv4);
    try std.testing.expectEqual(@as(u16, 443), target.service_port);
    try std.testing.expectEqual(@as(u8, 6), target.protocol);
    try std.testing.expectEqual(@as(?[]const u8, null), ctx.failure_code);
}

test "enforcement.verify parses inbound peer/local-port target" {
    // Direction 1 names the inbound peer (src_ip) and the local service port
    // (dst_port); the original destination is not the WFP remote address.
    const parsed = std.json.parseFromSlice(std.json.Value, std.testing.allocator, "{\"filter_id\":73000,\"direction\":1,\"src_ip\":3232239105,\"dst_port\":443,\"protocol\":6}", .{}) catch unreachable;
    defer parsed.deinit();
    var ctx = HandlerContext{ .start_ns = 0, .request_id = 32, .caller_role = .read, .caller_pid = 0 };
    const target = handlers.parseVerifyTarget(parsed.value, &ctx).?;
    try std.testing.expectEqual(@as(u8, 1), target.direction);
    try std.testing.expectEqual(@as(u32, 3232239105), target.remote_ipv4);
    try std.testing.expectEqual(@as(u16, 443), target.service_port);
    try std.testing.expectEqual(@as(?[]const u8, null), ctx.failure_code);
}

test "enforcement.verify matches inbound peer and rejects the original destination" {
    // Pins the 2026-10-21 control-path null: the filter's remote address for
    // an inbound filter is the peer (192.168.126.1), not the original
    // destination (203.0.113.10). The read-back tuple must match exactly.
    var bytes = [_]u8{0} ** 20;
    std.mem.writeInt(u64, bytes[0..8], 73000, .little);
    std.mem.writeInt(u32, bytes[8..12], 0xC0A87E01, .little);
    std.mem.writeInt(u16, bytes[12..14], 443, .little);
    bytes[14] = 6;
    bytes[15] = 1;
    const state = pep_bindings.PepFilterState{ .bytes = bytes };

    const inbound = handlers.VerifyTarget{
        .filter_id = 73000,
        .direction = 1,
        .remote_ipv4 = 0xC0A87E01,
        .service_port = 443,
        .protocol = 6,
    };
    try std.testing.expect(handlers.verifyStateMatches(inbound, state));

    const wrong_remote = handlers.VerifyTarget{
        .filter_id = 73000,
        .direction = 1,
        .remote_ipv4 = 0xCB00710A,
        .service_port = 443,
        .protocol = 6,
    };
    try std.testing.expect(!handlers.verifyStateMatches(wrong_remote, state));

    const wrong_port = handlers.VerifyTarget{
        .filter_id = 73000,
        .direction = 1,
        .remote_ipv4 = 0xC0A87E01,
        .service_port = 444,
        .protocol = 6,
    };
    try std.testing.expect(!handlers.verifyStateMatches(wrong_port, state));
}

test "enforcement.verify rejects unknown direction and missing inbound peer" {
    const bad_direction = std.json.parseFromSlice(std.json.Value, std.testing.allocator, "{\"filter_id\":73000,\"direction\":2,\"src_ip\":3232239105,\"dst_port\":443,\"protocol\":6}", .{}) catch unreachable;
    defer bad_direction.deinit();
    var ctx1 = HandlerContext{ .start_ns = 0, .request_id = 33, .caller_role = .read, .caller_pid = 0 };
    try std.testing.expect(handlers.parseVerifyTarget(bad_direction.value, &ctx1) == null);
    try std.testing.expectEqualStrings("INVALID_INPUT", ctx1.failure_code.?);

    const missing_peer = std.json.parseFromSlice(std.json.Value, std.testing.allocator, "{\"filter_id\":73000,\"direction\":1,\"dst_ip\":3232239136,\"dst_port\":443,\"protocol\":6}", .{}) catch unreachable;
    defer missing_peer.deinit();
    var ctx2 = HandlerContext{ .start_ns = 0, .request_id = 34, .caller_role = .read, .caller_pid = 0 };
    try std.testing.expect(handlers.parseVerifyTarget(missing_peer.value, &ctx2) == null);
    try std.testing.expectEqualStrings("INVALID_INPUT", ctx2.failure_code.?);
}

test "enforcementStatus exposes shield screening flags" {
    // SHIELD-WIRE-123: advisory screening state rides the enforcement
    // posture payload without affecting any gate.
    const tier3 = @import("../policy/tier3_state.zig");
    const prev_shield = tier3.g_tier3.shield_loaded;
    const prev_screen = tier3.g_tier3.payload_screening;
    defer {
        tier3.g_tier3.shield_loaded = prev_shield;
        tier3.g_tier3.payload_screening = prev_screen;
    }
    tier3.g_tier3.shield_loaded = true;
    tier3.g_tier3.payload_screening = true;
    var ctx = HandlerContext{ .start_ns = 0, .request_id = 29, .caller_role = .read, .caller_pid = 0 };
    const out = handlers.enforcementStatus(std.testing.allocator, .{ .null = {} }, &ctx).?;
    defer std.testing.allocator.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"shield_loaded\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"payload_screening\":true") != null);
}

test "rulesShow rejects malformed payloads before touching disk" {
    var ctx = HandlerContext{ .start_ns = 0, .request_id = 10, .caller_role = .read, .caller_pid = 0 };
    try std.testing.expect(handlers.rulesShow(std.testing.allocator, .{ .null = {} }, &ctx) == null);
    try std.testing.expectEqualStrings("INVALID_INPUT", ctx.failure_code.?);
    var obj = std.json.Value{ .object = std.json.ObjectMap.init(std.testing.allocator) };
    defer obj.object.deinit();
    try obj.object.put("id", .{ .integer = 7 });
    var ctx2 = HandlerContext{ .start_ns = 0, .request_id = 11, .caller_role = .read, .caller_pid = 0 };
    try std.testing.expect(handlers.rulesShow(std.testing.allocator, obj, &ctx2) == null);
    try std.testing.expectEqualStrings("INVALID_INPUT", ctx2.failure_code.?);
}

test "rulesShow finds a real rule in Rules.json" {
    var obj = std.json.Value{ .object = std.json.ObjectMap.init(std.testing.allocator) };
    defer obj.object.deinit();
    try obj.object.put("id", .{ .string = "R0056" });
    var ctx = HandlerContext{ .start_ns = 0, .request_id = 12, .caller_role = .read, .caller_pid = 0 };
    const out = handlers.rulesShow(std.testing.allocator, obj, &ctx) orelse {
        try std.testing.expectEqualStrings("CONFIG_UNAVAILABLE", ctx.failure_code orelse "?");
        return;
    };
    defer std.testing.allocator.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"found\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "SQL Injection") != null);
}

test "rulesValidate dry-runs Rules.json without touching the engine" {
    var ctx = HandlerContext{ .start_ns = 0, .request_id = 13, .caller_role = .read, .caller_pid = 0 };
    const out = handlers.rulesValidate(std.testing.allocator, .{ .null = {} }, &ctx) orelse {
        try std.testing.expectEqualStrings("CONFIG_UNAVAILABLE", ctx.failure_code orelse "?");
        return;
    };
    defer std.testing.allocator.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"valid\":true") != null);
}

test "logsTail rejects bad limits before touching disk" {
    var obj = std.json.Value{ .object = std.json.ObjectMap.init(std.testing.allocator) };
    defer obj.object.deinit();
    try obj.object.put("limit", .{ .integer = 0 });
    var ctx = HandlerContext{ .start_ns = 0, .request_id = 14, .caller_role = .read, .caller_pid = 0 };
    try std.testing.expect(handlers.logsTail(std.testing.allocator, obj, &ctx) == null);
    try std.testing.expectEqualStrings("INVALID_INPUT", ctx.failure_code.?);
}

test "logsTail returns entries when the forensic log exists" {
    std.fs.cwd().access("logs\\aegis_core.ndjson", .{}) catch return;
    var ctx = HandlerContext{ .start_ns = 0, .request_id = 15, .caller_role = .read, .caller_pid = 0 };
    const out = handlers.logsTail(std.testing.allocator, .{ .null = {} }, &ctx).?;
    defer std.testing.allocator.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"entries\"") != null);
}

test "policySimulate needs values and a loaded IR" {
    var ctx = HandlerContext{ .start_ns = 0, .request_id = 16, .caller_role = .operate, .caller_pid = 0 };
    try std.testing.expect(handlers.policySimulate(std.testing.allocator, .{ .null = {} }, &ctx) == null);
    try std.testing.expectEqualStrings("INVALID_INPUT", ctx.failure_code.?);
    var obj = std.json.Value{ .object = std.json.ObjectMap.init(std.testing.allocator) };
    defer obj.object.deinit();
    try obj.object.put("values", .{ .integer = 1 });
    var ctx2 = HandlerContext{ .start_ns = 0, .request_id = 17, .caller_role = .operate, .caller_pid = 0 };
    try std.testing.expect(handlers.policySimulate(std.testing.allocator, obj, &ctx2) == null);
    try std.testing.expectEqualStrings("INVALID_INPUT", ctx2.failure_code.?);
    // No IR in unit tests: honest absence, never a canned match.
    var obj2 = std.json.Value{ .object = std.json.ObjectMap.init(std.testing.allocator) };
    defer obj2.object.deinit();
    var arr = std.json.Array.init(std.testing.allocator);
    defer arr.deinit();
    try arr.append(.{ .integer = 1 });
    try obj2.object.put("values", .{ .array = arr });
    var ctx3 = HandlerContext{ .start_ns = 0, .request_id = 18, .caller_role = .operate, .caller_pid = 0 };
    // No IR in unit tests (daemon never runs here): honest absence with a
    // named code, never a canned match.
    try std.testing.expect(handlers.policySimulate(std.testing.allocator, obj2, &ctx3) == null);
    try std.testing.expectEqualStrings("POLICY_IR_ABSENT", ctx3.failure_code.?);
}

test "enforcementSimulate rejects malformed payloads before reading posture" {
    var ctx = HandlerContext{ .start_ns = 0, .request_id = 20, .caller_role = .operate, .caller_pid = 0 };
    try std.testing.expect(handlers.enforcementSimulate(std.testing.allocator, .{ .null = {} }, &ctx) == null);
    try std.testing.expectEqualStrings("INVALID_INPUT", ctx.failure_code.?);
    var obj = std.json.Value{ .object = std.json.ObjectMap.init(std.testing.allocator) };
    defer obj.object.deinit();
    try obj.object.put("action", .{ .string = "nuke" });
    try obj.object.put("severity", .{ .integer = 9 });
    var ctx2 = HandlerContext{ .start_ns = 0, .request_id = 21, .caller_role = .operate, .caller_pid = 0 };
    try std.testing.expect(handlers.enforcementSimulate(std.testing.allocator, obj, &ctx2) == null);
    try std.testing.expectEqualStrings("INVALID_INPUT", ctx2.failure_code.?);
    var obj3 = std.json.Value{ .object = std.json.ObjectMap.init(std.testing.allocator) };
    defer obj3.object.deinit();
    try obj3.object.put("action", .{ .string = "block" });
    try obj3.object.put("severity", .{ .integer = 99 });
    var ctx3 = HandlerContext{ .start_ns = 0, .request_id = 22, .caller_role = .operate, .caller_pid = 0 };
    try std.testing.expect(handlers.enforcementSimulate(std.testing.allocator, obj3, &ctx3) == null);
    try std.testing.expectEqualStrings("INVALID_INPUT", ctx3.failure_code.?);
}

test "enforcementSimulate never claims a host effect" {
    // Unit tests run with the prevention gate closed and no PEP: the only
    // honest projection is detection-only allow, enforced=false always.
    var obj = std.json.Value{ .object = std.json.ObjectMap.init(std.testing.allocator) };
    defer obj.object.deinit();
    try obj.object.put("action", .{ .string = "block" });
    try obj.object.put("severity", .{ .integer = 9 });
    var ctx = HandlerContext{ .start_ns = 0, .request_id = 23, .caller_role = .operate, .caller_pid = 0 };
    const out = handlers.enforcementSimulate(std.testing.allocator, obj, &ctx).?;
    defer std.testing.allocator.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"simulated\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"enforced\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"host_effect_confirmed\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "pep_not_invoked") != null);
}

test "version handler mirrors each component's own source of truth" {
    // VER-TRUTH-032: core/nose 5.0.0 (product line), pep 5.0.0 (Cargo
    // package aegis_pep), brain 2.0.0 (windows_brain --version). A stale
    // hardcoded version here misleads operators into debugging the wrong
    // binary, so the exact values are pinned.
    var ctx = HandlerContext{ .start_ns = 0, .request_id = 24, .caller_role = .read, .caller_pid = 0 };
    // LIT-FREE-096: version() output is allocator-owned like every handler
    // (uniform caller-frees contract), so it is freed here.
    const out = handlers.version(std.testing.allocator, .{ .null = {} }, &ctx).?;
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings("{\"core\":\"5.0.0\",\"nose\":\"5.0.0\",\"pep\":\"5.0.0\",\"brain\":\"2.0.0\"}", out);
}

test "BE-EXP-099: export writes chain-verified records and proves the file" {
    // Hermetic: in-memory ring (4 slots) + tmp path. The re-read
    // postcondition, not the write call, is what the test trusts.
    const event_mod = @import("../contract/event.zig");
    var ring = try forensic_pipeline.ForensicRing.initMemory(std.testing.allocator, 4 * forensic_pipeline.RECORD_BYTES);
    defer ring.deinit(std.testing.allocator);
    var i: u64 = 0;
    while (i < 3) : (i += 1) {
        var ev = event_mod.IpcEvent.init(.signature_match);
        ev.event_id = 100 + i;
        ev.timestamp_ns = 1000 + i;
        ev.rule_id = 4242;
        _ = ring.append(&ev, "pay", 500 + i, 7, 1, 6);
    }
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    const path = try std.fs.path.join(std.testing.allocator, &.{ root, "exp.json" });
    defer std.testing.allocator.free(path);

    const res = try handlers.exportRingToFile(std.testing.allocator, &ring, path, 100);
    try std.testing.expectEqual(@as(u64, 3), res.records);
    try std.testing.expect(!res.truncated);
    try std.testing.expectEqual(@as(u64, 0), res.oldest);
    // Independent re-read: 3 lines, each naming rule 4242 and event ids.
    const back = try std.fs.cwd().readFileAlloc(std.testing.allocator, path, 65536);
    defer std.testing.allocator.free(back);
    try std.testing.expectEqual(@as(usize, 3), std.mem.count(u8, back, "\n"));
    try std.testing.expect(std.mem.indexOf(u8, back, "4242") != null);
    try std.testing.expect(std.mem.indexOf(u8, back, "\"event_id\":100") != null);
    try std.testing.expect(std.mem.indexOf(u8, back, "\"event_id\":102") != null);
    // Attested hash matches the bytes on disk.
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(back);
    var digest: [32]u8 = undefined;
    h.final(&digest);
    try std.testing.expectEqualSlices(u8, &digest, &res.sha);
}

test "BE-EXP-099: export honors limit with truncation flagged" {
    const event_mod = @import("../contract/event.zig");
    var ring = try forensic_pipeline.ForensicRing.initMemory(std.testing.allocator, 4 * forensic_pipeline.RECORD_BYTES);
    defer ring.deinit(std.testing.allocator);
    var i: u64 = 0;
    while (i < 3) : (i += 1) {
        var ev = event_mod.IpcEvent.init(.signature_match);
        ev.event_id = 200 + i;
        ev.timestamp_ns = 2000 + i;
        _ = ring.append(&ev, "", 600 + i, 0, 0, 2);
    }
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    const path = try std.fs.path.join(std.testing.allocator, &.{ root, "exp2.json" });
    defer std.testing.allocator.free(path);

    const res = try handlers.exportRingToFile(std.testing.allocator, &ring, path, 2);
    try std.testing.expectEqual(@as(u64, 2), res.records);
    try std.testing.expect(res.truncated);
}

test "BE-EXP-099: export on empty ring writes zero records, still verified" {
    var ring = try forensic_pipeline.ForensicRing.initMemory(std.testing.allocator, 4 * forensic_pipeline.RECORD_BYTES);
    defer ring.deinit(std.testing.allocator);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    const path = try std.fs.path.join(std.testing.allocator, &.{ root, "exp3.json" });
    defer std.testing.allocator.free(path);

    const res = try handlers.exportRingToFile(std.testing.allocator, &ring, path, 100);
    try std.testing.expectEqual(@as(u64, 0), res.records);
    try std.testing.expect(!res.truncated);
    // Empty file hashes to the well-known SHA-256 of nothing.
    const back = try std.fs.cwd().readFileAlloc(std.testing.allocator, path, 65536);
    defer std.testing.allocator.free(back);
    try std.testing.expectEqual(@as(usize, 0), back.len);
}

test "RING-STAT-103: overwrite accounting exposes retention loss" {
    // 2-slot ring, 5 appends → 3 overwritten, 2 retained. The old
    // verify response (ever-written total only) could not show this.
    const event_mod = @import("../contract/event.zig");
    var ring = try forensic_pipeline.ForensicRing.initMemory(std.testing.allocator, 2 * forensic_pipeline.RECORD_BYTES);
    defer ring.deinit(std.testing.allocator);
    var i: u64 = 0;
    while (i < 5) : (i += 1) {
        var ev = event_mod.IpcEvent.init(.signature_match);
        ev.event_id = 300 + i;
        ev.timestamp_ns = 3000 + i;
        _ = ring.append(&ev, "", 700 + i, 0, 0, 2);
    }
    try std.testing.expectEqual(@as(u64, 5), ring.recordCount());
    try std.testing.expectEqual(@as(u64, 3), ring.overwrittenCount());
}

test "RING-STAT-103: forensics.verify reports retention additively" {
    const event_mod = @import("../contract/event.zig");
    const state_mod = @import("../pipeline/runtime_state.zig");
    var ring = try forensic_pipeline.ForensicRing.initMemory(std.testing.allocator, 2 * forensic_pipeline.RECORD_BYTES);
    defer ring.deinit(std.testing.allocator);
    var i: u64 = 0;
    while (i < 3) : (i += 1) {
        var ev = event_mod.IpcEvent.init(.signature_match);
        ev.event_id = 400 + i;
        ev.timestamp_ns = 4000 + i;
        _ = ring.append(&ev, "", 800 + i, 0, 0, 2);
    }
    const prev = state_mod.g_forensic_ring;
    state_mod.g_forensic_ring = &ring;
    defer state_mod.g_forensic_ring = prev;
    var ctx = HandlerContext{ .start_ns = 0, .request_id = 25, .caller_role = .operate, .caller_pid = 0 };
    const out = handlers.forensicsVerify(std.testing.allocator, .{ .null = {} }, &ctx).?;
    defer std.testing.allocator.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"integrity\":\"ok\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"retained\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"overwritten\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"capacity_slots\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"oldest_record_seq\":1") != null);
}

test "GAP-015 forensics.list after-cursor windows under ring wrap" {
    // CHARACTERIZATION, not regression reproduction: static analysis
    // proves old and new code agree on quiescent rings (residue math),
    // so this pins the cursor contract (after=3->[4], after=99->empty,
    // none->[3,4]) against future drift. The live incident it addresses
    // was mid-scan churn (appends during multi-page scans alias stored
    // seqs past fixed cursors at 1100/s) — unreproducible single-threaded
    // by construction; the floor-start plus seq-identity code above is
    // what makes that case honest.
    const event_mod = @import("../contract/event.zig");
    const state_mod = @import("../pipeline/runtime_state.zig");
    var ring = try forensic_pipeline.ForensicRing.initMemory(std.testing.allocator, 2 * forensic_pipeline.RECORD_BYTES);
    defer ring.deinit(std.testing.allocator);
    var i: u64 = 0;
    while (i < 5) : (i += 1) {
        var ev = event_mod.IpcEvent.init(.signature_match);
        ev.event_id = 500 + i;
        ev.timestamp_ns = 5000 + i;
        _ = ring.append(&ev, "", 900 + i, 0, 0, 2);
    }
    const prev = state_mod.g_forensic_ring;
    state_mod.g_forensic_ring = &ring;
    defer state_mod.g_forensic_ring = prev;
    var ctx = HandlerContext{ .start_ns = 0, .request_id = 35, .caller_role = .read, .caller_pid = 0 };
    const q_after3 = std.json.parseFromSlice(std.json.Value, std.testing.allocator, "{\"after\":3,\"limit\":100}", .{}) catch unreachable;
    defer q_after3.deinit();
    const out3 = handlers.forensicsList(std.testing.allocator, q_after3.value, &ctx).?;
    defer std.testing.allocator.free(out3);
    try std.testing.expect(std.mem.indexOf(u8, out3, "\"record_seq\":4") != null);
    try std.testing.expect(std.mem.indexOf(u8, out3, "\"record_seq\":3") == null);
    const q_after99 = std.json.parseFromSlice(std.json.Value, std.testing.allocator, "{\"after\":99,\"limit\":100}", .{}) catch unreachable;
    defer q_after99.deinit();
    const out99 = handlers.forensicsList(std.testing.allocator, q_after99.value, &ctx).?;
    defer std.testing.allocator.free(out99);
    try std.testing.expect(std.mem.indexOf(u8, out99, "\"records_returned\":0") != null);
    const q_all = std.json.parseFromSlice(std.json.Value, std.testing.allocator, "{\"limit\":100}", .{}) catch unreachable;
    defer q_all.deinit();
    const out_all = handlers.forensicsList(std.testing.allocator, q_all.value, &ctx).?;
    defer std.testing.allocator.free(out_all);
    try std.testing.expect(std.mem.indexOf(u8, out_all, "\"record_seq\":3") != null);
    try std.testing.expect(std.mem.indexOf(u8, out_all, "\"record_seq\":4") != null);
}

test "forensics.list exposes canonical direction and preserves legacy unknown" {
    const event_mod = @import("../contract/event.zig");
    const state_mod = @import("../pipeline/runtime_state.zig");
    var ring = try forensic_pipeline.ForensicRing.initMemory(std.testing.allocator, 4 * forensic_pipeline.RECORD_BYTES);
    defer ring.deinit(std.testing.allocator);

    var outbound = event_mod.IpcEvent.init(.packet_captured);
    outbound.event_id = 601;
    _ = ring.appendWithDirection(&outbound, "direction-proof", 0, 0, 0, 2, 1);
    var legacy = event_mod.IpcEvent.init(.packet_captured);
    legacy.event_id = 602;
    _ = ring.append(&legacy, "legacy-record", 0, 0, 0, 2);

    const prev = state_mod.g_forensic_ring;
    state_mod.g_forensic_ring = &ring;
    defer state_mod.g_forensic_ring = prev;
    var ctx = HandlerContext{ .start_ns = 0, .request_id = 36, .caller_role = .read, .caller_pid = 0 };
    const query = std.json.parseFromSlice(std.json.Value, std.testing.allocator, "{\"limit\":10}", .{}) catch unreachable;
    defer query.deinit();
    const out = handlers.forensicsList(std.testing.allocator, query.value, &ctx).?;
    defer std.testing.allocator.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"event_id\":601") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"event_id\":601,\"rule_id\":0,\"source\":0,\"source_name\":\"zig_core\",\"source_space\":\"canonical\",\"payload_len\":15,\"direction\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"event_id\":602,\"rule_id\":0,\"source\":0,\"source_name\":\"zig_core\",\"source_space\":\"canonical\",\"payload_len\":13,\"direction\":null") != null);
}

test "EVT-176 forensics.list rule filter attributes exact rule ids" {
    // GAP-019: ring responses carry no payload text, so a marked event
    // cannot be found by content on a busy host. The u32 rule hash gives
    // exact attribution: three records with rule ids [111, 222, 111], a
    // {"rule":111} query must return seqs 0 and 2 but never 1.
    const event_mod = @import("../contract/event.zig");
    const state_mod = @import("../pipeline/runtime_state.zig");
    var ring = try forensic_pipeline.ForensicRing.initMemory(std.testing.allocator, 4 * forensic_pipeline.RECORD_BYTES);
    defer ring.deinit(std.testing.allocator);
    const rule_ids = [_]u32{ 111, 222, 111 };
    for (rule_ids, 0..) |rid, i| {
        var ev = event_mod.IpcEvent.init(.signature_match);
        ev.event_id = 600 + i;
        ev.timestamp_ns = 6000 + i;
        ev.rule_id = rid;
        _ = ring.append(&ev, "", 900 + i, 0, 0, 2);
    }
    const prev = state_mod.g_forensic_ring;
    state_mod.g_forensic_ring = &ring;
    defer state_mod.g_forensic_ring = prev;
    var ctx = HandlerContext{ .start_ns = 0, .request_id = 36, .caller_role = .read, .caller_pid = 0 };
    const q = std.json.parseFromSlice(std.json.Value, std.testing.allocator, "{\"rule\":111,\"limit\":100}", .{}) catch unreachable;
    defer q.deinit();
    const out = handlers.forensicsList(std.testing.allocator, q.value, &ctx).?;
    defer std.testing.allocator.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"record_seq\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"record_seq\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"record_seq\":1") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"records_returned\":2") != null);
}

test "DEADCODE-QUARANTINE: incidentsShow requires an id and answers NOT_FOUND honestly" {
    // The old handler was an alias for incidents.list: the payload was
    // silently dropped, so a client asking for one incident received
    // every incident. Missing id must be rejected; a valid id with no
    // incident state in this process must be a named miss, never a list.
    var ctx = HandlerContext{ .start_ns = 0, .request_id = 41, .caller_role = .read, .caller_pid = 0 };
    const none = handlers.incidentsShow(std.testing.allocator, std.json.Value{ .null = {} }, &ctx);
    try std.testing.expect(none == null);
    try std.testing.expectEqualStrings("INVALID_INPUT", ctx.failure_code.?);
    try std.testing.expectEqualStrings("REJECTED", ctx.failure_state.?);

    tracker_mod.g_live = null;
    var obj = std.json.Value{ .object = std.json.ObjectMap.init(std.testing.allocator) };
    defer obj.object.deinit();
    try obj.object.put("id", .{ .integer = 7 });
    const miss = handlers.incidentsShow(std.testing.allocator, obj, &ctx);
    try std.testing.expect(miss == null);
    try std.testing.expectEqualStrings("INCIDENT_NOT_FOUND", ctx.failure_code.?);
    try std.testing.expectEqualStrings("NOT_FOUND", ctx.failure_state.?);
}

test "XDR-005-B: xdr.verify replays persisted snapshots and reports honest-empty" {
    const event_mod = @import("../contract/event.zig");
    const fabric = @import("../xdr/xdr_incident_fabric.zig");
    const state_mod = @import("../pipeline/runtime_state.zig");

    var ctx = HandlerContext{ .start_ns = 0, .request_id = 51, .caller_role = .read, .caller_pid = 0 };

    // No ring: honest-unavailable body, never an error/throw.
    const prev = state_mod.g_forensic_ring;
    state_mod.g_forensic_ring = null;
    const unavailable = handlers.xdrVerify(std.testing.allocator, .{ .null = {} }, &ctx) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(unavailable);
    try std.testing.expect(std.mem.indexOf(u8, unavailable, "\"available\":false") != null);

    var ring = try forensic_pipeline.ForensicRing.initMemory(std.testing.allocator, 8 * forensic_pipeline.RECORD_BYTES);
    defer ring.deinit(std.testing.allocator);
    defer state_mod.g_forensic_ring = prev;

    var source_event = event_mod.IpcEvent.init(.signature_match);
    source_event.timestamp_ns = 1_700_000_000_000_000_000;
    source_event.event_id = 801;
    source_event.source = .capture_npcap;
    source_event.rule_id = 9001;

    var network = fabric.Evidence{ .source = .network, .event_id = 801, .ts_ms = 1700000000000, .severity = 4 };
    @memcpy(network.entity[0..12], "203.0.113.77");
    network.entity_len = 12;
    var host = fabric.Evidence{ .source = .host, .event_id = 802, .ts_ms = 1700000000100, .severity = 3 };
    @memcpy(host.entity[0..12], "203.0.113.77");
    host.entity_len = 12;
    const evidence = [_]fabric.Evidence{ network, host };
    const recorded = try xdr_evidence_flow.recordAssessment(&ring, &source_event, &evidence, 1700000000200);

    // A newer non-XDR record proves the prefilter skips noise instead of
    // counting it as a failed snapshot.
    var plain = event_mod.IpcEvent.init(.packet_captured);
    plain.event_id = 803;
    plain.timestamp_ns = 1_700_000_000_500_000_000;
    _ = ring.append(&plain, "noise", 0, 0, 0, 1);

    state_mod.g_forensic_ring = &ring;
    const out = handlers.xdrVerify(std.testing.allocator, .{ .null = {} }, &ctx) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"available\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"xdr_records\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"verified\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"failed\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"source_categories\":[\"network\",\"host\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "token issuance") != null);
    var seq_buf: [32]u8 = undefined;
    const seq = try std.fmt.bufPrint(&seq_buf, "\"sequence\":{d}", .{recorded.forensic_sequence});
    try std.testing.expect(std.mem.indexOf(u8, out, seq) != null);
}

test "DEADCODE-QUARANTINE: incidentsShow returns exactly the requested incident" {
    var tt = tracker_mod.ThreatTracker.init(std.testing.allocator);
    defer tt.deinit();
    tracker_mod.g_live = &tt;
    defer tracker_mod.g_live = null;

    var ev_a = event_contract.IpcEvent.init(.signature_match);
    ev_a.flow_id = 11;
    ev_a.timestamp_ns = 1000;
    ev_a.event_id = 11;
    ev_a.src_ip = 0x0A000001;
    const inc_a = (try tt.observeFlowThreat(&ev_a, 100)).?;

    var ev_b = event_contract.IpcEvent.init(.signature_match);
    ev_b.flow_id = 12;
    ev_b.timestamp_ns = 2000;
    ev_b.event_id = 12;
    ev_b.src_ip = 0xC0A87E14;
    _ = try tt.observeFlowThreat(&ev_b, 300);

    var obj = std.json.Value{ .object = std.json.ObjectMap.init(std.testing.allocator) };
    defer obj.object.deinit();
    try obj.object.put("id", .{ .integer = @intCast(inc_a.id) });

    var ctx = HandlerContext{ .start_ns = 0, .request_id = 42, .caller_role = .read, .caller_pid = 0 };
    const body = handlers.incidentsShow(std.testing.allocator, obj, &ctx) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(body);

    // One incident — not the list shape, not the sibling's data.
    try std.testing.expect(std.mem.indexOf(u8, body, "\"incidents\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, body, "192.168.126.20") == null);
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, body, .{});
    defer parsed.deinit();
    const doc = parsed.value.object;
    try std.testing.expectEqual(@as(i64, @intCast(inc_a.id)), doc.get("id").?.integer);
    try std.testing.expectEqual(@as(i64, 11), doc.get("flow_id").?.integer);
    try std.testing.expectEqualStrings("10.0.0.1", doc.get("src_ip").?.string);
    try std.testing.expectEqual(@as(i64, 100), doc.get("score").?.integer);
    try std.testing.expectEqualStrings("open", doc.get("state").?.string);
}

test "DEADCODE-QUARANTINE: runtime.stop refuses until a supervisor exists" {
    // Decision pin (do not weaken): the control endpoint cannot claim
    // STOPPED until a daemon supervisor has signalled, joined, and
    // verified every worker. Until that owner exists, the only honest
    // answer is NOT_IMPLEMENTED — never a fabricated success.
    var ctx = HandlerContext{ .start_ns = 0, .request_id = 43, .caller_role = .privileged, .caller_pid = 0 };
    const out = handlers.runtimeStop(std.testing.allocator, std.json.Value{ .null = {} }, &ctx);
    try std.testing.expect(out == null);
    try std.testing.expectEqualStrings("NOT_IMPLEMENTED", ctx.failure_code.?);
    try std.testing.expectEqualStrings("UNAVAILABLE", ctx.failure_state.?);
    try std.testing.expect(ctx.failure_message.?.len > 0);
}

test "DEADCODE-QUARANTINE: runtime.restart refuses until a supervisor exists" {
    var ctx = HandlerContext{ .start_ns = 0, .request_id = 44, .caller_role = .privileged, .caller_pid = 0 };
    const out = handlers.runtimeRestart(std.testing.allocator, std.json.Value{ .null = {} }, &ctx);
    try std.testing.expect(out == null);
    try std.testing.expectEqualStrings("NOT_IMPLEMENTED", ctx.failure_code.?);
    try std.testing.expectEqualStrings("UNAVAILABLE", ctx.failure_state.?);
    try std.testing.expect(ctx.failure_message.?.len > 0);
}
