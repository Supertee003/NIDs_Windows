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
    registerHandler(.enforcement_block, handlers.enforcementBlock);
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
            return std.fmt.allocPrint(a, "{{\"component\":\"core\",\"state\":\"DEGRADED\",\"runtime_state\":\"{s}\",\"pid\":{},\"build_marker\":\"{s}\",\"health_error\":\"serialization_failed\"}}", .{ sm.g_runtime.system_state.toString(), pid, HEALTH_BUILD_MARKER }) catch null;
        };
    }

    fn version(_: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        // VER-TRUTH-032: every value mirrors its component's own source of
        // truth — core/nose 5.0.0 (product line), pep 5.0.0 (Cargo package
        // aegis_pep), brain 2.0.0 (windows_brain --version/banner).
        return "{\"core\":\"5.0.0\",\"nose\":\"5.0.0\",\"pep\":\"5.0.0\",\"brain\":\"2.0.0\"}";
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
            rep.loaded, previous_count,
            rep.skipped_no_pattern, rep.skipped_disabled,
            rep.skipped_malformed, rep.skipped_add_failed,
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
        return std.fmt.allocPrint(a,
            \\{{"processed":{},"detections":{},"anomalies":{},"correlations":{},"policies_matched":{},"errors":{},"dropped":{}}}
        , .{
            state_mod.g_pipeline_events_processed.load(.acquire),
            state_mod.g_pipeline_detections.load(.acquire),
            diag.metrics.anomalies_detected.get(),
            state_mod.g_pipeline_correlations.load(.acquire),
            state_mod.g_pipeline_policies_matched.load(.acquire),
            diag.metrics.errors.get(),
            queue_drops,
        }) catch null;
    }

    fn eventsTail(a: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        const queue_drops = state_mod.g_queue_drops.load(.acquire);
        return std.fmt.allocPrint(a, "{{\"last_event_ms\":{},\"queue_drops\":{}}}", .{
            state_mod.g_last_event_ms.load(.acquire),
            queue_drops,
        }) catch null;
    }

    fn incidentsList(a: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        return std.fmt.allocPrint(a,
            \\{{"incidents_total":{},"incidents_open":{},"detections":{},"policies_matched":{},"correlations":{}}}
        , .{
            state_mod.g_incidents_total.load(.acquire),
            state_mod.g_incidents_open.load(.acquire),
            state_mod.g_pipeline_detections.load(.acquire),
            state_mod.g_pipeline_policies_matched.load(.acquire),
            state_mod.g_pipeline_correlations.load(.acquire),
        }) catch null;
    }

    fn incidentsShow(a: std.mem.Allocator, _: std.json.Value, ctx: *HandlerContext) ?[]const u8 {
        return incidentsList(a, std.json.Value{ .null = {} }, ctx);
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
        return std.fmt.allocPrint(a,
            "{{\"verified\":{},\"policies\":{{\"present\":{},\"sidecar\":{},\"anchors\":\"{s}\",\"anchors_broken\":{},\"valid\":{},\"reason\":\"{s}\"}},\"policy_ir\":{{\"present\":{},\"sidecar\":{},\"anchors\":\"{s}\",\"anchors_broken\":{},\"valid\":{},\"reason\":\"{s}\"}}}}",
            .{
                pol.valid,
                pol.doc_present, pol.sidecar_present,
                pol.anchor_source.toString(), pol.anchors_broken,
                pol.valid, pol.reason.toString(),
                mir.doc_present, mir.sidecar_present,
                mir.anchor_source.toString(), mir.anchors_broken,
                mir.valid, mir.reason.toString(),
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
    const FORENSIC_ENTRY_MAX_BYTES: usize = 224;
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
            return "{\"available\":false,\"records\":[],\"records_returned\":0,\"records_matched\":0,\"truncated\":false,\"next_after\":null,\"integrity\":\"unavailable\",\"verified\":false}";

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

        while (index < count) : (index += 1) {
            const record = ring.readRecord(index, a) orelse continue;
            defer a.free(record);

            if (record.len < forensic_pipeline.HEADER_BYTES) continue;
            if (!forensic_pipeline.ForensicRing.verifyRecord(record)) continue;

            const header = std.mem.bytesAsValue(
                forensic_pipeline.RecordHeader,
                record[0..forensic_pipeline.HEADER_BYTES],
            );

            if (requested_after) |after| {
                if (header.record_seq <= after) continue;
            }

            const origin = forensicRecordOrigin(header.reserved[6], header.reserved[5]);

            if (requested_source) |source| {
                if (source > std.math.maxInt(u8) or
                    origin.ordinal != @as(u8, @intCast(source))) continue;
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
                "{{\"record_seq\":{},\"event_id\":{},\"rule_id\":{},\"source\":{},\"source_name\":\"{s}\",\"source_space\":\"{s}\",\"payload_len\":{},\"verified\":true}}",
                .{
                    header.record_seq,
                    header.ev_id,
                    header.rule_id,
                    origin.ordinal,
                    origin.name,
                    origin.space,
                    header.payload_len,
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
            !forensic_pipeline.ForensicRing.verifyRecord(record)) {
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
            "{{\"record_seq\":{},\"event_id\":{},\"rule_id\":{},\"source\":{},\"source_name\":\"{s}\",\"source_space\":\"{s}\",\"payload_len\":{},\"verified\":true}}",
            .{
                header.record_seq,
                header.ev_id,
                header.rule_id,
                origin.ordinal,
                origin.name,
                origin.space,
                header.payload_len,
            },
        ) catch null;
    }

    fn forensicsVerify(a: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        if (state_mod.g_forensic_ring) |ring| {
            const verified = ring.verifyHashChain();
            return std.fmt.allocPrint(a, "{{\"verified\":{},\"integrity\":\"{s}\",\"records\":{}}}", .{
                verified,
                if (verified) "ok" else "failed",
                state_mod.g_forensic_records_written.load(.acquire),
            }) catch null;
        }
        return "{\"verified\":false,\"integrity\":\"unavailable\",\"records\":0}";
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
        return std.fmt.allocPrint(a,
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
                "{{\"record_seq\":{},\"event_id\":{},\"rule_id\":{},\"source\":{},\"source_name\":\"{s}\",\"source_space\":\"{s}\",\"payload_len\":{},\"verified\":true}}\n",
                .{
                    header.record_seq,
                    header.ev_id,
                    header.rule_id,
                    origin.ordinal,
                    origin.name,
                    origin.space,
                    header.payload_len,
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
        return std.fmt.allocPrint(a,
            \\{{"tier3":"{s}","tier3_ready":{},"tier3_enforcing":{},"pep_available":{},"provider_ready":{},"host_effect_capable":{},"prevention_gate":"{s}","receipt_required":true,"enforcement_mode":"{s}"}}
        , .{
            t3.toString(),
            t3.isEnforcementAllowed(),
            gate_open,
            state_mod.g_pep_available.load(.acquire),
            provider_ready,
            provider_ready and gate_open,
            if (gate_open) "open" else "closed",
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
            return std.fmt.allocPrint(a,
                "{{\"simulated\":true,\"enforced\":false,\"host_effect_confirmed\":false,\"action\":\"{s}\",\"severity\":{},\"prevention_gate\":\"closed\",\"provider_ready\":{},\"outcome\":\"allow\",\"reason\":\"prevention_gate_closed;detection-only;pep_not_invoked\"}}",
                .{ action, sev_val.integer, provider_ready }) catch null;
        }
        if (!provider_ready) {
            return std.fmt.allocPrint(a,
                "{{\"simulated\":true,\"enforced\":false,\"host_effect_confirmed\":false,\"action\":\"{s}\",\"severity\":{},\"prevention_gate\":\"open\",\"provider_ready\":false,\"outcome\":\"escalate\",\"reason\":\"provider_unavailable;pep_not_invoked\"}}",
                .{ action, sev_val.integer }) catch null;
        }
        return std.fmt.allocPrint(a,
            "{{\"simulated\":true,\"enforced\":false,\"host_effect_confirmed\":false,\"action\":\"{s}\",\"severity\":{},\"prevention_gate\":\"open\",\"provider_ready\":true,\"outcome\":\"would_request\",\"reason\":\"simulation_only;pep_not_invoked;approval_state_pep_held\"}}",
            .{ action, sev_val.integer }) catch null;
    }

    fn enforcementVerify(a: std.mem.Allocator, payload: std.json.Value, ctx: *HandlerContext) ?[]const u8 {
        const filter_id = payloadU64(payload, "filter_id") orelse {
            ctx.failure_code = "INVALID_INPUT";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "filter_id from an EnforcementReceipt is required";
            return null;
        };
        const expected_ip = payloadU64(payload, "dst_ip") orelse {
            ctx.failure_code = "INVALID_INPUT";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "dst_ip is required for exact postcondition verification";
            return null;
        };
        const expected_port = payloadU64(payload, "dst_port") orelse {
            ctx.failure_code = "INVALID_INPUT";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "dst_port is required for exact postcondition verification";
            return null;
        };
        const expected_protocol = payloadU64(payload, "protocol") orelse {
            ctx.failure_code = "INVALID_INPUT";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "protocol is required for exact postcondition verification";
            return null;
        };
        if (filter_id == 0 or expected_ip > std.math.maxInt(u32) or
            expected_port > std.math.maxInt(u16) or expected_protocol > std.math.maxInt(u8))
        {
            ctx.failure_code = "INVALID_INPUT";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "postcondition fields exceed ABI bounds";
            return null;
        }
        var pep = pep_bindings.PepEnforcer{ .available = state_mod.g_pep_available.load(.acquire) };
        const state = pep.queryFilter(filter_id) orelse {
            ctx.failure_code = "POSTCONDITION_FAILED";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "receipt filter is not present or provider query failed";
            return null;
        };
        if (state.remoteIpv4() != @as(u32, @intCast(expected_ip)) or
            state.remotePort() != @as(u16, @intCast(expected_port)) or
            state.protocol() != @as(u8, @intCast(expected_protocol)))
        {
            ctx.failure_code = "POSTCONDITION_FAILED";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "receipt filter does not match the requested exact flow";
            return null;
        }
        return std.fmt.allocPrint(a, "{{\"verified\":true,\"filter_id\":{},\"present\":true,\"dst_ip\":{},\"dst_port\":{},\"protocol\":{},\"postcondition\":\"MATCH\"}}", .{ filter_id, expected_ip, expected_port, expected_protocol }) catch null;
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

    fn enforcementBlock(a: std.mem.Allocator, payload: std.json.Value, ctx: *HandlerContext) ?[]const u8 {
        if (ctx.caller_role != .privileged) {
            ctx.failure_code = "AUTH_DENIED";
            ctx.failure_state = "UNAUTHORIZED";
            ctx.failure_message = "enforcement.block requires privileged control-plane authorization";
            return null;
        }
        const dst_ip = payloadU64(payload, "dst_ip") orelse {
            ctx.failure_code = "INVALID_INPUT";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "dst_ip must be an IPv4 integer";
            return null;
        };
        const dst_port = payloadU64(payload, "dst_port") orelse {
            ctx.failure_code = "INVALID_INPUT";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "dst_port is required and must be non-zero";
            return null;
        };
        const protocol_number = payloadU64(payload, "protocol") orelse {
            ctx.failure_code = "INVALID_INPUT";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "protocol is required";
            return null;
        };
        const policy_id = payloadU64(payload, "policy_id") orelse {
            ctx.failure_code = "INVALID_INPUT";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "policy_id is required for an authorized action";
            return null;
        };
        const event_id = payloadU64(payload, "event_id") orelse {
            ctx.failure_code = "INVALID_INPUT";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "event_id is required to link an enforcement receipt to a source event";
            return null;
        };
        const trace_id = payloadU64(payload, "trace_id") orelse {
            ctx.failure_code = "INVALID_INPUT";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "trace_id is required to link an enforcement receipt to a decision trace";
            return null;
        };
        const severity = payloadU64(payload, "severity") orelse 9;
        if (dst_ip > std.math.maxInt(u32) or dst_port > std.math.maxInt(u16) or protocol_number > std.math.maxInt(u8) or policy_id > std.math.maxInt(u32) or event_id == 0 or trace_id == 0 or severity > std.math.maxInt(u8)) {
            ctx.failure_code = "INVALID_INPUT";
            ctx.failure_state = "REJECTED";
            ctx.failure_message = "flow fields exceed ABI bounds";
            return null;
        }
        // P0/P1 safety invariant: provider readiness is not host-effect proof.
        // Keep mutation closed until the isolated WFP proof can attest the
        // postcondition and emit a complete EnforcementReceipt v1.
        if (!state_mod.g_prevention_gate_open) {
            ctx.failure_code = "PREVENTION_GATE_CLOSED";
            ctx.failure_state = "UNAVAILABLE";
            ctx.failure_message = "blocking is disabled until controlled host-effect proof and receipt validation complete";
            return null;
        }
        var pep = pep_bindings.PepEnforcer{ .available = state_mod.g_pep_available.load(.acquire) };
        const receipt = pep.enforceFlow(@intCast(dst_ip), @intCast(dst_port), @intCast(protocol_number), @intCast(policy_id), @intCast(severity), ctx.caller_pid, 1, ctx.request_id) orelse {
            ctx.failure_code = "ENFORCEMENT_FAILED";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "Rust PEP did not return a validated host-effect receipt";
            return null;
        };
        const queried = switch (pep.queryFilterResult(receipt.filter_id)) {
            .present => |state| state,
            .absent => {
                _ = pep.unblockFilter(receipt.filter_id, ctx.caller_pid, 1, ctx.request_id);
                ctx.failure_code = "POSTCONDITION_FAILED";
                ctx.failure_state = "DEGRADED";
                ctx.failure_message = "provider-backed exact filter read-back reported absent after block; cleanup was attempted";
                return null;
            },
            .query_error => {
                _ = pep.unblockFilter(receipt.filter_id, ctx.caller_pid, 1, ctx.request_id);
                ctx.failure_code = "POSTCONDITION_FAILED";
                ctx.failure_state = "DEGRADED";
                ctx.failure_message = "provider-backed exact filter read-back failed after block; cleanup was attempted";
                return null;
            },
        };
        if (queried.providerStatus() != 0 or queried.remoteIpv4() != @as(u32, @intCast(dst_ip)) or
            queried.remotePort() != @as(u16, @intCast(dst_port)) or queried.protocol() != @as(u8, @intCast(protocol_number)))
        {
            _ = pep.unblockFilter(receipt.filter_id, ctx.caller_pid, 1, ctx.request_id);
            ctx.failure_code = "POSTCONDITION_FAILED";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "provider filter did not match the requested exact flow; cleanup was attempted";
            return null;
        }
        const confirmed = enforcement_receipt.EnforcementReceipt{
            .request_id = ctx.request_id,
            .event_id = event_id,
            .policy_id = @intCast(policy_id),
            .decision = 1,
            .status = .enforced,
            .provider = "wfp",
            .filter_id = receipt.filter_id,
            .host_effect_confirmed = true,
            .reason = "provider_exact_tuple_match",
            .trace_id = trace_id,
            .audit_id = ctx.request_id,
        };
        if (!confirmed.isSuccess()) {
            _ = pep.unblockFilter(receipt.filter_id, ctx.caller_pid, 1, ctx.request_id);
            ctx.failure_code = "RECEIPT_INVALID";
            ctx.failure_state = "DEGRADED";
            ctx.failure_message = "complete EnforcementReceipt v1 validation failed; cleanup was attempted";
            return null;
        }
        return std.fmt.allocPrint(a, "{{\"status\":\"ENFORCED\",\"receipt_version\":{},\"request_id\":{},\"event_id\":{},\"policy_id\":{},\"decision\":\"block\",\"provider\":\"wfp\",\"filter_id\":{},\"host_effect_confirmed\":true,\"trace_id\":{},\"audit_id\":{},\"dst_ip\":{},\"dst_port\":{},\"protocol\":{}}}", .{ enforcement_receipt.EnforcementReceipt.VERSION, confirmed.request_id, confirmed.event_id, confirmed.policy_id, confirmed.filter_id, confirmed.trace_id, confirmed.audit_id, dst_ip, dst_port, protocol_number }) catch null;
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
        switch (pep.queryFilterResult(filter_id)) {
            .absent => return std.fmt.allocPrint(a, "{{\"status\":\"ROLLED_BACK\",\"filter_id\":{},\"present\":false,\"postcondition\":\"ABSENT\"}}", .{filter_id}) catch null,
            .present => {
                ctx.failure_code = "CLEANUP_POSTCONDITION_FAILED";
                ctx.failure_state = "ROLLBACK_PENDING";
                ctx.failure_message = "filter removal returned but the exact filter is still present";
                return null;
            },
            .query_error => {
                ctx.failure_code = "CLEANUP_POSTCONDITION_FAILED";
                ctx.failure_state = "ROLLBACK_PENDING";
                ctx.failure_message = "filter removal returned but exact filter absence could not be proven";
                return null;
            },
        }
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
            \\{{"uptime_sec":{},"rules_loaded":{},"packets_captured":{},"events_processed":{},"forensic_records":{},"flows_active":{},"incidents_open":{},"detections":{},"anomalies":{},"blocks":{},"errors":{},"siem":{{"enabled":{},"forwarded":{},"failed":{},"spooled":{},"batches":{},"retries":{}}},"policy_ir":{{"loaded":{},"rules":{},"hash":"{s}","verified":{}}}}}
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
        if (tail_len == 0) return "{\"entries\":[]}";
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
        return "{\"mode\":\"standalone\",\"cluster_enabled\":false,\"nodes\":0,\"role\":\"standalone\"}";
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

    fn daemonShutdown(_: std.mem.Allocator, _: std.json.Value, _: *HandlerContext) ?[]const u8 {
        // The daemon supervisor owns the STOPPED postcondition. This handler
        // only requests cancellation; workers and pipe handles may still be
        // live while the control response is being returned.
        const sm = @import("state_machine.zig");

        sm.g_runtime.transition(.stopping);

        // CTRL-002: Signal worker threads to stop
        const rt = @import("../pipeline/runtime_state.zig");
        rt.g_stop_requested.store(true, .release);

        bridge_init.requestShutdown();

        return "{\"shutdown_requested\":true,\"state\":\"STOPPING\"}";
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
}

test "metricsSnapshot prints lifetime counters at full u64 width" {
    // METR-U64-061: narrowing casts panicked debug builds past 4B events
    // (and wrapped release builds silently). A >u32max counter must
    // round-trip through the formatter with every digit intact.
    const state = @import("../pipeline/runtime_state.zig");
    const prev = state.g_nose_frames_submitted.load(.acquire);
    defer state.g_nose_frames_submitted.store(prev, .monotonic);
    state.g_nose_frames_submitted.store(0x1_0000_0042, .monotonic);
    var ctx = HandlerContext{ .start_ns = 0, .request_id = 19, .caller_role = .read, .caller_pid = 0 };
    const out = handlers.metricsSnapshot(std.testing.allocator, .{ .null = {} }, &ctx).?;
    defer std.testing.allocator.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"packets_captured\":4294967362") != null);
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
    // version() returns a string literal (no allocation), so no free.
    const out = handlers.version(std.testing.allocator, .{ .null = {} }, &ctx).?;
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
