//! Daemon orchestration for the AEGIS NIDS runtime.
//!
//! Extracted from main.zig during the god-file refactor (REBUILD-006).
//! runDaemon() owns the full startup sequence:
//!   1. Diagnostics + security self-check + capability probe
//!   2. Core subsystems (arena, forensic ring, watchdog, perf, fault inject)
//!   3. Detection engine (Aho-Corasick rules + policies.json)
//!   4. PEP + action dispatcher
//!   5. Bridges (WFP IOCTL / C++ IPC / Rust Shield / UDP Brain) + pipe sensor
//!   6. Worker threads (pipeline, Npcap, ETW, FIM, registry)
//!   7. Control pipe server until shutdown

const std = @import("std");
const builtin = @import("builtin");
const event = @import("contract/event.zig");
const manifest = @import("contract/runtime_manifest.zig");
const diag = @import("core/diagnostics.zig");
const mem = @import("core/memory_pool.zig");
const flow = @import("capture/flow_table.zig");
const sig = @import("detection/signature_engine.zig");
const anom = @import("detection/anomaly_detector.zig");
const tracker = @import("detection/threat_tracker.zig");
const policy = @import("policy/policy_ir.zig");
const pep = @import("policy/pep_bindings.zig");
const forensic = @import("forensic/forensic_pipeline.zig");
const dispatcher = @import("policy/action_dispatcher.zig");
const watchdog = @import("reliability/watchdog.zig");
const sec_check = @import("reliability/security_check.zig");
const fault = @import("reliability/fault_injection.zig");

// REBUILD-003: Legacy core bridge layer (WFP IOCTL / C++ IPC / Rust Shield / UDP Brain)
const bridge_init = @import("core/bridge_init.zig");
const legacy_capture = @import("core/nids_capture.zig");

// PATCH-20: Windows Data Plane adapters (Phase 3)
const inj_det = @import("windows/injection_detector.zig");

// Refactored modules (this extraction)
const state = @import("pipeline/runtime_state.zig");
const rule_loader = @import("pipeline/rule_loader.zig");
const processor = @import("pipeline/event_processor.zig");
const telemetry = @import("pipeline/telemetry_threads.zig");
const nose_reader = @import("capture/nose_pipe_reader.zig");
const pipe_monitor = @import("capture/pipe_monitor.zig");
const event_queue = @import("pipeline/event_queue.zig");
const service = @import("platform/win32_service.zig");
const control = @import("platform/win32_pipe.zig");

const SERVICE_RUNNING: u32 = 0x00000004;
const runtime_sm = @import("control.zig").state_machine;
extern "kernel32" fn GetCurrentProcessId() std.os.windows.DWORD;

/// PHASE-1: the daemon owns every worker handle it creates. Control handlers
/// may request a transition, but only this supervisor can signal, join, and
/// complete the transition after all workers have terminated.
const RuntimeSupervisor = struct {
    pipeline: ?std.Thread = null,
    sensor: ?std.Thread = null,
    nose_reader: ?std.Thread = null,
    etw: ?std.Thread = null,
    fim: ?std.Thread = null,
    registry: ?std.Thread = null,
    pipe_monitor: ?std.Thread = null,

    pub fn requestStop(_: *RuntimeSupervisor) void {
        state.g_stop_requested.store(true, .release);
        bridge_init.requestShutdown();
    }

    pub fn shutdown(self: *RuntimeSupervisor) void {
        self.requestStop();
        // Join in reverse startup order. Every handle is joined exactly once.
        if (self.registry) |thread| thread.join();
        self.registry = null;
        if (self.pipe_monitor) |thread| thread.join();
        self.pipe_monitor = null;
        if (self.fim) |thread| thread.join();
        self.fim = null;
        if (self.etw) |thread| thread.join();
        self.etw = null;
        if (self.nose_reader) |thread| thread.join();
        self.nose_reader = null;
        if (self.sensor) |thread| thread.join();
        self.sensor = null;
        if (self.pipeline) |thread| thread.join();
        self.pipeline = null;
        // STOPPED is a postcondition of the owner completing every join. The
        // control handler publishes STOPPING while this work is pending.
        runtime_sm.g_runtime.transition(.stopped);
    }
};

fn publishPipeObservation(observation: pipe_monitor.PipeObservation, payload: []const u8) bool {
    var ev = event.IpcEvent.init(.signature_match);
    ev.source = .capture_pipe_monitor;
    ev.event_id = event.nextEventId();
    ev.trace_id = ev.event_id;
    ev.severity = .warning;
    ev.timestamp_ns = observation.timestamp_ns;
    ev.payload_len = observation.payload_len;
    ev.payload_hash = observation.payload_hash;
    return event_queue.pushEvent(ev, payload);
}

pub fn runDaemon() !void {
    // Install the sink before any startup work so failures before the control
    // pipe exists are still visible to the console/service harness.
    diag.Logger.setSink(diag.StderrSink.init());
    diag.Logger.setLevel(.info);
    diag.info("AEGIS NIDS v5.0+ starting up", .{});

    // Startup diagnostics are intentionally limited to resolved paths and
    // component state; never print secrets or policy contents.  These values
    // are essential when a Windows service and a console launch have
    // different working directories.
    if (std.fs.cwd().realpathAlloc(std.heap.page_allocator, ".")) |cwd| {
        defer std.heap.page_allocator.free(cwd);
        diag.info("startup context: cwd={s}", .{cwd});
    } else |err| {
        diag.warn("startup context: unable to resolve cwd: {}", .{err});
    }

    // P1: Initialize runtime state machine
    runtime_sm.g_runtime.transition(.starting);
    runtime_sm.g_runtime.registerSubsystem(.zig, "zig", "5.0.0", "core,detection,correlation");
    runtime_sm.g_runtime.registerSubsystem(.go, "go", "2.1.0", "capture,nose");
    runtime_sm.g_runtime.registerSubsystem(.cpp, "cpp", "1.0.0", "etw,fim,registry,wfp");
    runtime_sm.g_runtime.registerSubsystem(.rust_pep, "rust_pep", "1.0.0", "enforcement,crypto");
    runtime_sm.g_runtime.registerSubsystem(.tier3, "tier3", "1.0.0", "authorization,pep");
    runtime_sm.g_runtime.registerSubsystem(.control, "control", "1.0.0", "pipe,audit");
    runtime_sm.g_runtime.registerSubsystem(.forensic, "forensic", "1.0.0", "ring,hash,replay");
    runtime_sm.g_runtime.subsystemStarted(.zig, @as(u32, @intCast(GetCurrentProcessId())));

    // 1. Run security self-check
    const sc = sec_check.SecurityCheck.run();
    sc.report();
    if (!sc.passed) {
        diag.err("security self-check failed; refusing to start in production mode", .{});
        return error.SecurityCheckFailed;
    }
    // The daemon is the authenticated runtime caller for pipeline-originated
    // enforcement requests. Keep a real PID and grant only the explicit
    // block capability; never fabricate 0xFFFFFFFF caller capabilities.
    state.g_runtime_pid = @as(u32, @intCast(GetCurrentProcessId()));
    state.g_runtime_capability_mask = 0x01;

    // 3. Probe capabilities
    const caps = manifest.probeCapabilities();
    manifest.RuntimeManifest.publish(caps);
    diag.info("Capabilities: npcap={} etw={} fim={} wfp={}", .{
        caps.has_npcap, caps.has_etw_realtime, caps.has_fim, caps.has_wfp_block,
    });

    // 4. Initialize core subsystems
    var arena = try mem.ByteArena.init(std.heap.page_allocator, 16 * 1024 * 1024);
    defer arena.deinit(std.heap.page_allocator);
    var forensic_ring = try forensic.ForensicRing.initMemory(std.heap.page_allocator, 64 * 1024 * 1024);
    defer forensic_ring.deinit(std.heap.page_allocator);
    state.g_forensic_ring = &forensic_ring;
    defer state.g_forensic_ring = null;
    state.g_wd = watchdog.ReliabilityWatchdog.init(std.heap.page_allocator); // PATCH-29: global watchdog
    defer state.g_wd.deinit();
    state.g_perf = .{}; // PATCH-31: global performance tracker

    // 5. Start fault injector (disabled by default)
    state.g_fi = fault.FaultInjector.fromEnv(); // PATCH-30: global fault injector

    // 6. Initialize detection engine
    var ac = sig.AhoCorasick.init(std.heap.page_allocator, 100_000) catch |err| {
        diag.err("failed to init Aho-Corasick: {}", .{err});
        return err;
    };
    defer ac.deinit();

    // 6a. Load Rules.json into Aho-Corasick
    var rules_loaded: u32 = 0;
    blk: {
        const rules_path = "configs/Rules.json";
        const rules_file = std.fs.cwd().openFile(rules_path, .{}) catch |err| {
            diag.warn("config resolution: cannot open {s}: {} — detection engine has 0 rules", .{ rules_path, err });
            break :blk;
        };
        defer rules_file.close();
        const rules_bytes = rules_file.readToEndAlloc(std.heap.page_allocator, 4 * 1024 * 1024) catch |err| {
            diag.warn("cannot read {s}: {}", .{ rules_path, err });
            break :blk;
        };
        defer std.heap.page_allocator.free(rules_bytes);

        rules_loaded = rule_loader.loadRulesInto(&ac, rules_bytes, rules_path);
        state.g_rules_loaded = rules_loaded;
        state.g_active_ac = &ac; // PATCH-14: expose AC for reload mechanism
        diag.info("loaded {} rules from {s}", .{ rules_loaded, rules_path });
    }
    if (rules_loaded == 0) {
        diag.warn("detection engine has 0 rules — signature matching disabled", .{});
    }

    // 6b. Load policy rules from configs/policies.json
    var ps = policy.PolicySet.init(std.heap.page_allocator);
    defer ps.deinit();
    var policies_loaded: u32 = 0;
    policy_load_blk: {
        const pol_path = "configs/policies.json";
        const pol_file = std.fs.cwd().openFile(pol_path, .{}) catch |err| {
            diag.warn("config resolution: cannot open {s}: {} — policy set empty", .{ pol_path, err });
            break :policy_load_blk;
        };
        defer pol_file.close();
        const pol_bytes = pol_file.readToEndAlloc(std.heap.page_allocator, 1 * 1024 * 1024) catch |err| {
            diag.warn("cannot read {s}: {}", .{ pol_path, err });
            break :policy_load_blk;
        };
        defer std.heap.page_allocator.free(pol_bytes);

        var pol_parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, pol_bytes, .{}) catch |err| {
            diag.warn("cannot parse {s}: {}", .{ pol_path, err });
            break :policy_load_blk;
        };
        defer pol_parsed.deinit();

        const root = pol_parsed.value;
        if (root != .object) {
            diag.warn("{s}: expected object at root", .{pol_path});
            break :policy_load_blk;
        }
        const policies_arr = root.object.get("policies") orelse {
            diag.warn("{s}: missing policies key", .{pol_path});
            break :policy_load_blk;
        };
        if (policies_arr != .array) {
            diag.warn("{s}: policies is not an array", .{pol_path});
            break :policy_load_blk;
        }

        for (policies_arr.array.items) |pol_val| {
            if (pol_val != .object) continue;
            const pol_obj = pol_val.object;

            const id_val = pol_obj.get("id") orelse continue;
            if (id_val != .integer) continue;
            const pol_id: u32 = @intCast(id_val.integer);

            const name_val = pol_obj.get("name") orelse continue;
            if (name_val != .string) continue;
            const pol_name = std.heap.page_allocator.dupe(u8, name_val.string) catch continue;

            const action_val = pol_obj.get("action") orelse continue;
            if (action_val != .string) continue;
            const pol_action: policy.Action = blk: {
                if (std.mem.eql(u8, action_val.string, "block")) break :blk .block;
                if (std.mem.eql(u8, action_val.string, "alert")) break :blk .alert;
                if (std.mem.eql(u8, action_val.string, "rate_limit")) break :blk .rate_limit;
                if (std.mem.eql(u8, action_val.string, "quarantine")) break :blk .quarantine;
                if (std.mem.eql(u8, action_val.string, "log")) break :blk .log;
                if (std.mem.eql(u8, action_val.string, "escalate")) break :blk .escalate;
                // Unknown actions are malformed policy, never implicit allow.
                diag.err("{s}: policy {} has unknown action '{s}'; rejecting policy", .{ pol_path, pol_id, action_val.string });
                std.heap.page_allocator.free(pol_name);
                continue;
            };

            const severity_val = pol_obj.get("severity") orelse continue;
            if (severity_val != .string) continue;
            const pol_severity: event.EventSeverity = if (std.mem.eql(u8, severity_val.string, "critical")) .critical else if (std.mem.eql(u8, severity_val.string, "alert")) .alert else if (std.mem.eql(u8, severity_val.string, "warning")) .warning else if (std.mem.eql(u8, severity_val.string, "error")) .@"error" else .info;

            const ttl_val = pol_obj.get("ttl_sec") orelse continue;
            if (ttl_val != .integer) continue;
            const pol_ttl: u32 = @intCast(ttl_val.integer);

            // Build condition from JSON (simplified: single clause with single predicate)
            var preds = std.heap.page_allocator.alloc(policy.Predicate, 1) catch continue;
            preds[0] = .{ .field = .kind, .op = .eq, .value_int = 0 }; // default

            // Parse condition if present
            if (pol_obj.get("condition")) |cond_val| {
                if (cond_val == .object) {
                    if (cond_val.object.get("clauses")) |clauses_val| {
                        if (clauses_val == .array and clauses_val.array.items.len > 0) {
                            const first_clause = clauses_val.array.items[0];
                            if (first_clause == .object) {
                                if (first_clause.object.get("predicates")) |preds_val| {
                                    if (preds_val == .array and preds_val.array.items.len > 0) {
                                        const first_pred = preds_val.array.items[0];
                                        if (first_pred == .object) {
                                            const field_str = first_pred.object.get("field") orelse std.json.Value{ .string = "kind" };
                                            const op_str = first_pred.object.get("op") orelse std.json.Value{ .string = "eq" };
                                            const val_int = first_pred.object.get("value_int") orelse std.json.Value{ .integer = 0 };

                                            if (field_str == .string) {
                                                preds[0].field = if (std.mem.eql(u8, field_str.string, "kind")) .kind else if (std.mem.eql(u8, field_str.string, "severity")) .severity else if (std.mem.eql(u8, field_str.string, "src_ip")) .src_ip else if (std.mem.eql(u8, field_str.string, "dst_ip")) .dst_ip else if (std.mem.eql(u8, field_str.string, "src_port")) .src_port else if (std.mem.eql(u8, field_str.string, "dst_port")) .dst_port else if (std.mem.eql(u8, field_str.string, "protocol")) .protocol else if (std.mem.eql(u8, field_str.string, "rule_id")) .rule_id else .kind;
                                            }
                                            if (op_str == .string) {
                                                preds[0].op = if (std.mem.eql(u8, op_str.string, "eq")) .eq else if (std.mem.eql(u8, op_str.string, "ne")) .ne else if (std.mem.eql(u8, op_str.string, "gt")) .gt else if (std.mem.eql(u8, op_str.string, "lt")) .lt else if (std.mem.eql(u8, op_str.string, "gte")) .gt // simplified: gte -> gt
                                                else if (std.mem.eql(u8, op_str.string, "match")) .match else .eq;
                                            }
                                            if (val_int == .integer) {
                                                preds[0].value_int = @intCast(val_int.integer);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            var clauses = std.heap.page_allocator.alloc(policy.Clause, 1) catch continue;
            clauses[0] = .{ .predicates = preds };

            ps.add(.{
                .id = pol_id,
                .name = pol_name,
                .condition = .{ .clauses = clauses },
                .action = pol_action,
                .severity = pol_severity,
                .ttl_sec = pol_ttl,
            }) catch |err| {
                diag.warn("failed to add policy {}: {}", .{ pol_id, err });
                std.heap.page_allocator.free(pol_name);
                continue;
            };
            policies_loaded += 1;
        }

        state.g_policies_loaded = policies_loaded;
        diag.info("loaded {} policies from {s}", .{ policies_loaded, pol_path });
    }

    var ad = anom.AnomalyDetector.init(std.heap.page_allocator);
    defer ad.deinit();

    var ft = flow.FlowTable{};

    var tt = tracker.ThreatTracker.init(std.heap.page_allocator);
    defer tt.deinit();

    // 7. Initialize PEP (PolicySet already loaded with policies from JSON)
    var pep_enf = pep.PepEnforcer.init();
    defer pep_enf.deinit();
    // P0.2: Tier-3 state machine initialization
    const tier3 = @import("policy/tier3_state.zig");
    tier3.g_tier3.beginInit();
    if (pep_enf.available) {
        tier3.g_tier3.markReady();
        diag.info("Tier-3 state: READY (PEP available)", .{});
    } else {
        tier3.g_tier3.markAbsent("aegis_pep.dll not loaded");
        diag.critical("Tier-3 state: ABSENT — PEP unavailable, DETECTION-ONLY MODE: no enforcement", .{});
    }
    // PATCH-15: PEP availability check — detection-only mode if unavailable
    state.g_pep_available = pep_enf.available;
    if (!pep_enf.available) {
        diag.critical("PEP unavailable (aegis_pep.dll not loaded) — DETECTION-ONLY MODE: no enforcement", .{});
    } else {
        diag.info("PEP available — enforcement mode active", .{});
    }
    dispatcher.ActionDispatcher.init();
    defer dispatcher.ActionDispatcher.deinit();

    // PATCH-29: Register all threads in watchdog
    _ = state.g_wd.registerThread(watchdog.ThreadKind.pipeline, "pipeline");
    _ = state.g_wd.registerThread(watchdog.ThreadKind.capture, "capture");
    _ = state.g_wd.registerThread(watchdog.ThreadKind.host_telemetry, "etw");
    _ = state.g_wd.registerThread(watchdog.ThreadKind.host_telemetry, "fim");
    _ = state.g_wd.registerThread(watchdog.ThreadKind.host_telemetry, "registry");
    // 8. Federation/XDR (disabled in standalone mode)

    // PATCH-20: Initialize Windows Data Plane adapters (Phase 3)
    // These adapters feed real Windows telemetry into the pipeline.
    var etw_source = @import("windows/etw_realtime.zig").EtwSource.init();
    var fim_watcher = @import("windows/fim.zig").FimWatcher.init(std.heap.page_allocator);
    defer fim_watcher.deinit();
    var reg_monitor = @import("windows/registry_monitor.zig").RegistryMonitor.init(std.heap.page_allocator);
    defer reg_monitor.deinit();
    var inj_detector = inj_det.InjectionDetector.init(std.heap.page_allocator, &inj_det.DEFAULT_RULES);
    defer inj_detector.deinit();

    diag.info("AEGIS NIDS initialization complete — entering main loop", .{}); // 9. Main loop: pipeline processing + control pipe
    // PHASE-1: do not mark every subsystem RUNNING before its worker and
    // dependency have actually started. The supervisor below owns readiness.
    const start_ns = std.time.nanoTimestamp();
    if (builtin.os.tag == .windows) {
        // REBUILD-003: Initialize all bridges (WFP IOCTL, C++ IPC DLL, Rust Shield
        // DLL, UDP Brain). Bridges that fail to load degrade gracefully — same
        // contract as the legacy nids_main.zig startup path.
        bridge_init.initAll();
        defer bridge_init.shutdownAll();

        var supervisor = RuntimeSupervisor{};
        defer supervisor.shutdown();

        // Reset handshake state before creating workers. A readiness flag is
        // meaningful only for the current daemon generation.
        state.g_pipeline_ready.store(false, .release);
        state.g_sensor_ready.store(false, .release);
        state.g_nose_ready.store(false, .release);
        state.g_etw_ready.store(false, .release);
        state.g_fim_ready.store(false, .release);
        state.g_registry_ready.store(false, .release);
        state.g_worker_failed.store(false, .release);
        state.g_worker_failure_kind.store(@intFromEnum(state.WorkerFailureKind.none), .release);
        state.g_worker_failure_mask.store(0, .release);

        // REBUILD-003: Named-pipe sensor thread (\\.\pipe\aegis_sensor_pipe).
        // Exits when bridge_init.requestShutdown() is signalled.
        supervisor.sensor = std.Thread.spawn(.{}, legacy_capture.capture_packets, .{ std.heap.page_allocator, "" }) catch |err| blk: {
            diag.warn("failed to spawn pipe sensor thread: {} — sensor disabled", .{err});
            state.markWorkerFailure(.sensor);
            break :blk null;
        };

        // Start pipeline loop in a separate thread
        supervisor.pipeline = std.Thread.spawn(.{}, processor.pipelineLoop, .{
            &ac, &ad, &ft, &tt, &ps, &pep_enf, &forensic_ring, rules_loaded, 0,
        }) catch |err| {
            diag.err("failed to spawn pipeline thread: {} — RECOVERY: system runs in degraded mode", .{err});
            state.markWorkerFailure(.pipeline);
            return err;
        };

        // Canonical network ingress is Go Nose -> aegis_nose -> Zig reader.
        // Do not start the legacy direct Zig Npcap path in production: running
        // both paths creates duplicate events and independent event-id streams,
        // making exactly-once forensic identity impossible. The direct adapter
        // remains available to focused diagnostics/tests, but is not a runtime
        // acquisition authority.
        diag.info("direct Zig Npcap capture disabled; Go Nose is canonical network ingress", .{});

        // Canonical Go Nose -> named pipe -> detector pipeline queue path.
        supervisor.nose_reader = std.Thread.spawn(.{}, nose_reader.runPipeReaderLoop, .{&state.g_stop_requested}) catch |err| blk: {
            diag.warn("failed to spawn Go Nose pipe reader: {} — external capture disabled", .{err});
            state.markWorkerFailure(.nose);
            break :blk null;
        };

        // Native named-pipe enumeration is part of the active daemon path.
        // It remains observe-only and publishes into the same pipeline queue.
        pipe_monitor.setEventPublisher(publishPipeObservation);
        supervisor.pipe_monitor = std.Thread.spawn(.{}, pipe_monitor.pipeMonitorLoop, .{}) catch |err| blk: {
            diag.warn("failed to spawn named-pipe monitor: {} — pipe telemetry disabled", .{err});
            break :blk null;
        };
        if (supervisor.pipe_monitor != null) diag.info("named-pipe monitor started", .{});

        // PATCH-20: Start Windows Data Plane adapter threads (Phase 3)
        // ETW thread: receives Windows kernel events (process, file, registry, image)
        supervisor.etw = std.Thread.spawn(.{}, telemetry.etwThread, .{&etw_source}) catch |err| blk: {
            diag.warn("failed to spawn ETW thread: {} — ETW disabled", .{err});
            state.markWorkerFailure(.etw);
            break :blk null;
        };
        // FIM thread: polls file integrity changes
        supervisor.fim = std.Thread.spawn(.{}, telemetry.fimThread, .{&fim_watcher}) catch |err| blk: {
            diag.warn("failed to spawn FIM thread: {} — FIM disabled", .{err});
            state.markWorkerFailure(.fim);
            break :blk null;
        };
        // Registry thread: polls registry changes
        supervisor.registry = std.Thread.spawn(.{}, telemetry.registryThread, .{&reg_monitor}) catch |err| blk: {
            diag.warn("failed to spawn registry thread: {} — registry monitoring disabled", .{err});
            state.markWorkerFailure(.registry);
            break :blk null;
        };

        // Bounded readiness barrier: thread creation alone is not readiness.
        // The C++/Windows telemetry subsystem is represented by ETW, FIM, and
        // Registry readiness. Waiting only for pipeline_ready published the
        // subsystem as degraded before those adapters finished initializing,
        // and there was no later promotion to RUNNING. Wait for the complete
        // sensor set, but retain a hard timeout so a broken adapter cannot
        // block daemon startup indefinitely.
        var readiness_wait_ms: u32 = 0;
        while ((!state.g_pipeline_ready.load(.acquire) or
            !state.g_etw_ready.load(.acquire) or
            !state.g_fim_ready.load(.acquire) or
            !state.g_registry_ready.load(.acquire)) and
            !state.g_worker_failed.load(.acquire) and
            readiness_wait_ms < 5000)
        {
            std.time.sleep(10 * std.time.ns_per_ms);
            readiness_wait_ms += 10;
        }

        // Publish subsystem state from the same readiness facts used by the
        // supervisor. Do not leave registered subsystems at their default
        // STOPPED state after their workers have actually initialized.
        const runtime_pid = @as(u32, @intCast(GetCurrentProcessId()));
        if (state.g_nose_ready.load(.acquire)) {
            runtime_sm.g_runtime.subsystemStarted(.go, runtime_pid);
        } else {
            runtime_sm.g_runtime.subsystemDegraded(.go, "go_nose_not_ready");
        }
        if (state.g_etw_ready.load(.acquire) and state.g_fim_ready.load(.acquire) and state.g_registry_ready.load(.acquire)) {
            runtime_sm.g_runtime.subsystemStarted(.cpp, runtime_pid);
        } else {
            runtime_sm.g_runtime.subsystemDegraded(.cpp, "windows_telemetry_not_ready");
        }
        if (pep_enf.available) {
            runtime_sm.g_runtime.subsystemStarted(.rust_pep, runtime_pid);
        } else {
            runtime_sm.g_runtime.subsystemDegraded(.rust_pep, "pep_unavailable");
        }
        // Tier-3 authority is the PEP/payload-screening layer. WFP is the
        // separate host-effect provider and must not make Tier-3 appear
        // STOPPED when policy authority is ready but host enforcement is
        // unavailable. The health contract reports provider_ready and
        // host_effect_capable independently and keeps the overall gate
        // fail-closed until WFP is actually attested.
        if (pep_enf.available) {
            runtime_sm.g_runtime.subsystemStarted(.tier3, runtime_pid);
        } else {
            runtime_sm.g_runtime.subsystemDegraded(.tier3, "tier3_dependencies_not_ready");
        }
        runtime_sm.g_runtime.subsystemStarted(.control, runtime_pid);
        runtime_sm.g_runtime.subsystemStarted(.forensic, runtime_pid);

        // Hybrid readiness: the control/pipeline spine owns core liveness.
        // ETW/FIM/registry/WFP adapters remain visible as degraded capability
        // fields and must not make the daemon's primary control state appear
        // stopped when the spine is serving safely.
        const pipeline_failed = (state.workerFailureMask() & 0x01) != 0;
        if (state.g_pipeline_ready.load(.acquire) and !pipeline_failed) {
            runtime_sm.g_runtime.transition(.running);
        } else {
            runtime_sm.g_runtime.transition(.degraded);
        }
        service.setServiceStatus(SERVICE_RUNNING, 0);

        // Serve control pipe on main thread
        control.serveWindowsPipe(&caps, start_ns) catch |err| {
            diag.err("control server error: {}", .{err});
        };
        supervisor.requestStop();
    } else {
        // Non-Windows: run pipeline + control loop on main thread
        diag.info("running pipeline loop (non-Windows test mode)", .{});
        processor.pipelineLoop(&ac, &ad, &ft, &tt, &ps, &pep_enf, &forensic_ring, rules_loaded, 0);
    }

    diag.info("AEGIS NIDS shutting down", .{});
}
