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
// SLICE-C-LAB: build-option module wired in build.zig (exe graph only).
const build_options = @import("build_options");
const event = @import("contract/event.zig");
const manifest = @import("contract/runtime_manifest.zig");
const diag = @import("core/diagnostics.zig");
const mem = @import("core/memory_pool.zig");
const flow = @import("capture/flow_table.zig");
const sig = @import("detection/signature_engine.zig");
const anom = @import("detection/anomaly_detector.zig");
const tracker = @import("detection/threat_tracker.zig");
const policy = @import("policy/policy_ir.zig");
const policy_plane = @import("policy/policy_plane.zig");
const policy_signing = @import("policy/policy_signing.zig");
const pep = @import("policy/pep_bindings.zig");
const forensic = @import("forensic/forensic_pipeline.zig");
const siem_mod = @import("forensic/siem_forwarder.zig");
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
const runtime_paths = @import("core/runtime_paths.zig");
const processor = @import("pipeline/event_processor.zig");
const corr_mod = @import("detection/correlator.zig");
const telemetry = @import("pipeline/telemetry_threads.zig");
const nose_reader = @import("capture/nose_pipe_reader.zig");
const wfp_telemetry = @import("capture/wfp_telemetry.zig");
const minifilter_reader = @import("capture/minifilter_reader.zig");
const pipe_monitor = @import("capture/pipe_monitor.zig");
const packet_callback = @import("pipeline/packet_callback.zig");
const event_queue = @import("pipeline/event_queue.zig");
const service = @import("platform/win32_service.zig");
const control = @import("platform/win32_pipe.zig");
const federation_uplink = @import("federation/cluster_uplink.zig");

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
    wfp_telemetry: ?std.Thread = null,
    minifilter: ?std.Thread = null,
    direct_capture: ?std.Thread = null,
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
        if (self.wfp_telemetry) |thread| thread.join();
        self.wfp_telemetry = null;
        if (self.minifilter) |thread| thread.join();
        self.minifilter = null;
        if (self.direct_capture) |thread| thread.join();
        self.direct_capture = null;
        if (self.sensor) |thread| thread.join();
        self.sensor = null;
        if (self.pipeline) |thread| thread.join();
        self.pipeline = null;
        // SIEM drain runs on the pipeline thread (same-thread discipline),
        // so flushing here — after the pipeline joined — races nothing and
        // persists the tail the interval flush may not have reached yet.
        siem_mod.flush();
        siem_mod.shutdown();
        // STOPPED is a postcondition of the owner completing every join. The
        // control handler publishes STOPPING while this work is pending.
        runtime_sm.g_runtime.transition(.stopped);
    }
};

/// Read AEGIS_SIEM_* environment into a forwarder config. Returns null
/// (forwarder stays uninitialized) unless AEGIS_SIEM=1/on/true.
fn initSiemFromEnv() void {
    const enabled_raw = std.process.getEnvVarOwned(std.heap.page_allocator, "AEGIS_SIEM") catch return;
    defer std.heap.page_allocator.free(enabled_raw);
    const enabled = std.ascii.eqlIgnoreCase(enabled_raw, "1") or
        std.ascii.eqlIgnoreCase(enabled_raw, "true") or
        std.ascii.eqlIgnoreCase(enabled_raw, "on");
    if (!enabled) return;

    var config = siem_mod.SiemConfig{ .enabled = true };
    if (std.process.getEnvVarOwned(std.heap.page_allocator, "AEGIS_SIEM_TRANSPORT") catch null) |t| {
        defer std.heap.page_allocator.free(t);
        if (siem_mod.Transport.fromString(t)) |tr| config.transport = tr;
    }
    if (std.process.getEnvVarOwned(std.heap.page_allocator, "AEGIS_SIEM_FORMAT") catch null) |f| {
        defer std.heap.page_allocator.free(f);
        if (siem_mod.OutputFormat.fromString(f)) |fmt| config.format = fmt;
    }
    if (std.process.getEnvVarOwned(std.heap.page_allocator, "AEGIS_SIEM_ENDPOINT") catch null) |e| {
        defer std.heap.page_allocator.free(e);
        // Daemon-lifetime intentional retain: the singleton outlives this
        // scope, so the endpoint string is duplicated, never borrowed.
        if (e.len > 0) config.endpoint = std.heap.page_allocator.dupe(u8, e) catch config.endpoint;
    }
    if (std.process.getEnvVarOwned(std.heap.page_allocator, "AEGIS_SIEM_DEST") catch null) |d| {
        defer std.heap.page_allocator.free(d);
        if (d.len > 0) config.destination = std.heap.page_allocator.dupe(u8, d) catch config.destination;
    }
    siem_mod.init(std.heap.page_allocator, config);
    diag.info("[SIEM] forwarder enabled transport={s} format={s} dest={s}", .{
        config.transport.toString(), config.format.toString(), config.destination,
    });
}

fn publishPipeObservation(observation: pipe_monitor.PipeObservation, payload: []const u8) bool {    var ev = event.IpcEvent.init(.signature_match);
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
    runtime_sm.g_runtime.registerSubsystem(.go, "go", "5.0.0", "capture,nose");
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

    // 4a. SIEM forwarder (opt-in, default off). Enabled only with
    // AEGIS_SIEM=1; transport/format/endpoint/destination come from env
    // with fail-safe file defaults. The pipeline thread owns all
    // forward/flush calls; shutdown drains after the pipeline joins.
    initSiemFromEnv();

    // 4a2. Evidence-log projection (default ON, BE-EVI-097). Appends one
    // NDJSON line per detection to logs/aegis_core.ndjson — the file the
    // whole frontend fleet (CLI/desktop/web/mouth/aggregator/logs.tail)
    // tails. AEGIS_EVIDENCE_LOG=0 opts out. Init failure degrades to
    // no-op (drop-on-error); the forensic ring stays the record.
    {
        const forensic_log = @import("forensic/forensic_log.zig");
        var enabled = true;
        if (std.process.getEnvVarOwned(std.heap.page_allocator, "AEGIS_EVIDENCE_LOG") catch null) |v| {
            defer std.heap.page_allocator.free(v);
            if (std.ascii.eqlIgnoreCase(v, "0") or std.ascii.eqlIgnoreCase(v, "false") or std.ascii.eqlIgnoreCase(v, "off")) {
                enabled = false;
            }
        }
        state.g_evidence_log_enabled = enabled;
        if (enabled) {
            forensic_log.init();
            diag.info("[EVIDENCE] NDJSON projection enabled (logs/aegis_core.ndjson)", .{});
        } else {
            diag.info("[EVIDENCE] NDJSON projection disabled by env", .{});
        }
    }
    defer @import("forensic/forensic_log.zig").shutdown();

    // 4b. Tier-2 brain inspection loop (opt-in, default off). AEGIS_BRAIN=1
    // lets the pipeline offer detections to the brain over UDP for deep
    // inspection; findings return via the opt-in sensor pipe (T2-BRAIN-023).
    // Advisory only: the brain path never blocks, enforces, or gates detection.
    if (std.process.getEnvVarOwned(std.heap.page_allocator, "AEGIS_BRAIN") catch null) |b| {
        defer std.heap.page_allocator.free(b);
        if (std.ascii.eqlIgnoreCase(b, "1") or std.ascii.eqlIgnoreCase(b, "true") or std.ascii.eqlIgnoreCase(b, "on")) {
            state.g_brain_enabled.store(true, .release);
            diag.info("[BRAIN] Tier-2 inspection enabled (daemon -> UDP 127.0.0.1:9999)", .{});
        }
    }

    // 5. Start fault injector (disabled by default)
    state.g_fi = fault.FaultInjector.fromEnv(); // PATCH-30: global fault injector

    // 6. Initialize detection engine
    var ac = sig.AhoCorasick.init(std.heap.page_allocator, 100_000) catch |err| {
        diag.err("failed to init Aho-Corasick: {}", .{err});
        return err;
    };
    defer ac.deinit();

    const runtime_root = runtime_paths.resolveRoot(std.heap.page_allocator) catch |err| {
        diag.err("cannot resolve AEGIS runtime root: {}", .{err});
        return err;
    };
    defer std.heap.page_allocator.free(runtime_root);
    diag.info("runtime bundle root: {s}", .{runtime_root});

    // 6a. Load Rules.json into Aho-Corasick
    var rules_loaded: u32 = 0;
    blk: {
        const rules_path = runtime_paths.configPath(std.heap.page_allocator, runtime_root, "Rules.json") catch |err| {
            diag.warn("config resolution: cannot build Rules.json path: {}", .{err});
            break :blk;
        };
        defer std.heap.page_allocator.free(rules_path);
        const rules_file = std.fs.openFileAbsolute(rules_path, .{}) catch |err| {
            diag.warn("config resolution: cannot open {s}: {} — detection engine has 0 rules", .{ rules_path, err });
            break :blk;
        };
        defer rules_file.close();
        const rules_bytes = rules_file.readToEndAlloc(std.heap.page_allocator, 4 * 1024 * 1024) catch |err| {
            diag.warn("cannot read {s}: {}", .{ rules_path, err });
            break :blk;
        };
        defer std.heap.page_allocator.free(rules_bytes);

        const rep = rule_loader.loadRulesInto(&ac, rules_bytes, rules_path);
        rules_loaded = rep.loaded;
        state.g_rules_loaded.store(rules_loaded, .monotonic);
        state.g_active_ac = &ac; // PATCH-14: expose AC for reload mechanism
        diag.info("loaded {} rules from {s}", .{ rules_loaded, rules_path });
        // BE-DRIFT-098: name skipped rules at startup (not just counts)
        // so a patternless/disabled rule is visible before attack tests.
        var si: usize = 0;
        while (si < rep.skipped_id_count) : (si += 1) {
            diag.warn("startup: rule {s} not loaded (see reload report reasons)", .{rep.skippedId(si)});
        }
        if (rep.skipped_truncated) {
            diag.warn("startup: skipped-ID list truncated at {} entries", .{rule_loader.MAX_SKIPPED_IDS});
        }
    }
    if (rules_loaded == 0) {
        // A zero-rule runtime is not a valid NIDS configuration. Continuing
        // would make health appear usable while silently disabling the primary
        // detection path. Fail closed so a bad working directory, missing
        // config, or malformed Rules.json is immediately observable.
        diag.err("detection engine has 0 rules — refusing to start", .{});
        return error.RulesUnavailable;
    }

    // 6b. Load policy rules from configs/policies.json
    var ps = policy.PolicySet.init(std.heap.page_allocator);
    defer ps.deinit();
    // POLICY-EVAL-FULL: the parsed policy document must outlive the
    // PolicySet because predicate value_str slices point into it.
    var policy_doc: ?std.json.Parsed(std.json.Value) = null;
    defer if (policy_doc) |d| d.deinit();
    var policies_loaded: u32 = 0;
    policy_load_blk: {
        const pol_path = runtime_paths.configPath(std.heap.page_allocator, runtime_root, "policies.json") catch |err| {
            diag.warn("config resolution: cannot build policies.json path: {}", .{err});
            break :policy_load_blk;
        };
        defer std.heap.page_allocator.free(pol_path);
        const pol_file = std.fs.openFileAbsolute(pol_path, .{}) catch |err| {
            diag.warn("config resolution: cannot open {s}: {} — policy set empty", .{ pol_path, err });
            break :policy_load_blk;
        };
        defer pol_file.close();
        const pol_bytes = pol_file.readToEndAlloc(std.heap.page_allocator, 1 * 1024 * 1024) catch |err| {
            diag.warn("cannot read {s}: {}", .{ pol_path, err });
            break :policy_load_blk;
        };
        defer std.heap.page_allocator.free(pol_bytes);

        const pol_load = policy.loadPolicySetFromJson(std.heap.page_allocator, pol_bytes);
        if (pol_load.doc) |doc| policy_doc = doc;
        ps = pol_load.ps;
        policies_loaded = pol_load.report.loaded;
        if (pol_load.report.first_reject_reason) |reason| {
            diag.warn("{s}: policy load: {d} loaded, {d} rejected (first: id={d} reason={s})", .{ pol_path, pol_load.report.loaded, pol_load.report.rejected, pol_load.report.first_reject_id, reason });
        }

        // POL-PRIO-070: order by priority (stable — files without
        // priorities keep file order exactly).
        ps.sortByPriority();
        // TRUST-WIRE-082: opt-in signed-policy trust (ADR-0005
        // implementation). AEGIS_POLICY_ENFORCE_TRUSTED=1 plus a valid
        // sidecar (configs/policies.sig.json) over the exact bytes above
        // plus trust anchors (policy_trust.json file wins, else
        // AEGIS_POLICY_PUBKEY env) marks every loaded policy trusted.
        // Default (flag absent/off, or anything unverifiable): zero
        // behavior change — privileged actions keep escalating exactly
        // as before. Unsigned deployments are unaffected by construction.
        // BE-RCPT-091: anchor resolution + verification is the canonical
        // policy_signing.verifyEnvelope routine (shared with the
        // policy.verify control handler) — same verdicts, one code path.
        trust_blk: {
            const flag = std.process.getEnvVarOwned(std.heap.page_allocator, "AEGIS_POLICY_ENFORCE_TRUSTED") catch break :trust_blk;
            defer std.heap.page_allocator.free(flag);
            if (!policy_signing.trustOptIn(flag)) break :trust_blk;
            const rep = policy_signing.verifyEnvelope(std.heap.page_allocator, runtime_root, "policies.json", "policies.sig.json");
            if (!rep.doc_present) break :trust_blk;
            if (!rep.sidecar_present) {
                diag.warn("signed enforcement requested but policies.sig.json is absent; policies stay untrusted", .{});
                break :trust_blk;
            }
            if (rep.valid) {
                for (ps.policies.items) |*p| p.trusted = true;
                diag.info("signed enforcement: {} policies marked trusted (envelope VALID)", .{ps.policies.items.len});
            } else {
                diag.warn("signed enforcement requested but envelope {s} (anchors={s}); policies stay untrusted", .{ rep.reason.toString(), rep.anchor_source.toString() });
            }
        }
        state.g_policies_loaded.store(policies_loaded, .monotonic);
        diag.info("loaded {} policies from {s}", .{ policies_loaded, pol_path });
    }

    // 6c. Load TS-authored policy IR (verify-only mirror, T3-TSIR-025).
    // Absence is normal (advisory plane may not be compiled yet); an
    // invalid document warns and continues. This NEVER replaces the
    // runtime PolicySet above and NEVER touches enforcement authority.
    policy_ir_blk: {
        const ir_path = runtime_paths.configPath(std.heap.page_allocator, runtime_root, "policy_ir.json") catch |err| {
            diag.warn("config resolution: cannot build policy_ir.json path: {}", .{err});
            break :policy_ir_blk;
        };
        defer std.heap.page_allocator.free(ir_path);
        const ir_file = std.fs.openFileAbsolute(ir_path, .{}) catch {
            diag.info("no TS policy IR at {s}; continuing with runtime PolicySet only", .{ir_path});
            break :policy_ir_blk;
        };
        defer ir_file.close();
        const ir_bytes = ir_file.readToEndAlloc(std.heap.page_allocator, 1 * 1024 * 1024) catch |err| {
            diag.warn("cannot read {s}: {}", .{ ir_path, err });
            break :policy_ir_blk;
        };
        defer std.heap.page_allocator.free(ir_bytes);
        var loaded = policy_plane.loadIrFromJson(std.heap.page_allocator, ir_bytes) catch |err| {
            diag.warn("TS policy IR at {s} failed verification: {}; continuing with runtime PolicySet only", .{ ir_path, err });
            break :policy_ir_blk;
        };
        state.g_policy_ir = loaded;
        diag.info("TS policy IR verified: {} rules hash={s} compiler={s}", .{
            loaded.ir.rule_count,
            loaded.hash_hex[0..16],
            loaded.ir.compiler_version,
        });
        // POL-SIGN-079B: observe-only Ed25519 check. If the operator
        // placed a sidecar (policy_ir.sig.json) AND pinned a trust
        // anchor (AEGIS_POLICY_PUBKEY, 64 hex chars), verify the exact
        // bytes just loaded and expose the answer in metricsSnapshot.
        // Every other case stays unverified:false. This NEVER marks
        // anything trusted and NEVER touches enforcement authority.
        // CUSTODY-081: a reviewed trust file (configs/policy_trust.json,
        // gitignored live file, example tracks the shape) wins over the
        // env anchor when present; rotation works by listing old+new
        // key_ids side by side.
        // BE-RCPT-091: same canonical verifyEnvelope routine as the
        // policies envelope above and the policy.verify handler.
        state.g_policy_ir_verified.store(false, .monotonic);
        sig_blk: {
            const rep = policy_signing.verifyEnvelope(std.heap.page_allocator, runtime_root, "policy_ir.json", "policy_ir.sig.json");
            if (!rep.doc_present) break :sig_blk;
            // Present-but-broken file fails the check loudly (warn +
            // unverified) instead of silently falling back to env: a
            // reviewed file that no longer parses is operator error,
            // not an absent file.
            if (rep.anchors_broken) {
                diag.warn("policy_trust.json present but unusable; mirror stays unverified", .{});
            }
            state.g_policy_ir_verified.store(rep.valid, .monotonic);
            diag.info("TS policy IR signature: {s}", .{if (rep.valid) "VALID (observe-only, enforcement unchanged)" else "INVALID or untrusted anchor (mirror stays unverified)"});
        }
    }

    var ad = anom.AnomalyDetector.init(std.heap.page_allocator);
    defer ad.deinit();

    var ft = flow.FlowTable{};

    var tt = tracker.ThreatTracker.init(std.heap.page_allocator);
    defer tt.deinit();
    // EVT-210: publish the live tracker for the control plane before any
    // worker spawns. The incidents handler reads a bounded, mutex-copied
    // snapshot through this pointer; nothing else dereferences it.
    tracker.g_live = &tt;

    // Tier-1 correlation stage (FLOW_MAP DATA-001 step 6). Static rule set:
    // IDs live in the 9000 block, outside the FNV-1a signature space, so a
    // correlation hit can never be mistaken for a signature rule match.
    // Observe-only: hits count as detections and escalate severity; the PEP
    // gate still owns every host effect.
    const corr_repeat_specs = [_]corr_mod.EventSpec{
        .{ .kind = .signature_match, .count = 5 },
    };
    const corr_brute_specs = [_]corr_mod.EventSpec{
        .{ .kind = .http_request, .count = 3 },
    };
    var corr_rules = [_]corr_mod.CorrelationRule{
        .{ .id = 9001, .events = &corr_repeat_specs, .window_sec = 60, .severity = .alert },
        .{ .id = 9002, .events = &corr_brute_specs, .window_sec = 30, .severity = .alert },
        corr_mod.Correlator.dnsExfilRule(),
    };
    var corr = corr_mod.Correlator.init(std.heap.page_allocator, &corr_rules);
    defer corr.deinit();

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
    // SHIELD-WIRE-123: payload-screening provider (advisory only, DynLib).
    // Never affects the enforcement gating above: when the DLL is absent
    // both flags keep their initialized values (prior behavior identical).
    const shield_screen = @import("policy/shield_screen.zig");
    if (shield_screen.tryLoadDefault()) {
        tier3.g_tier3.shield_loaded = true;
        tier3.g_tier3.payload_screening = true;
        diag.info("Tier-3 screening provider loaded (advisory only, no enforcement authority)", .{});
    }
    // PATCH-15: PEP availability check — detection-only mode if unavailable
    state.g_pep_available.store(pep_enf.available, .monotonic);
    if (!pep_enf.available) {
        diag.critical("PEP unavailable (aegis_pep.dll not loaded) — DETECTION-ONLY MODE: no enforcement", .{});
    } else {
        diag.info("PEP available — prevention gate closed, DETECTION-ONLY MODE: provider ready, no host effect without receipt", .{});
    }
    // SLICE-C-LAB: lab-only prevention gate (G1). Compiled in only with
    // -Dlab-prevention-gate=true; default/production builds contain no
    // reachable caller, so the gate cannot open. In-memory only: a restart
    // re-closes it. Preconditions fail closed (docs/SLICE_C_LAB_GATE_DESIGN.md).
    if (build_options.lab_prevention_gate) {
        const gate_outcome = state.openPreventionGateLab(
            pep_enf.available,
            pep_enf.providerReady(),
            tier3.g_tier3.state == .ready,
            state.g_forensic_ring != null,
        );
        if (gate_outcome.opened) {
            diag.critical("LAB: prevention gate OPEN ({s}) — host mutation enabled for lab qualification ONLY", .{gate_outcome.reason});
            if (state.g_evidence_log_enabled) {
                @import("forensic/forensic_log.zig").log(.{
                    .level = .critical,
                    .event = "lab_prevention_gate_open",
                    .extra = "SLICE-C-LAB; in-memory only; restart re-closes; lab qualification builds only",
                });
            }
        } else {
            diag.warn("LAB: prevention gate stays closed ({s})", .{gate_outcome.reason});
        }
    }
    dispatcher.ActionDispatcher.init();
    defer dispatcher.ActionDispatcher.deinit();

    // PATCH-29: Register all threads in watchdog
    _ = state.g_wd.registerThread(watchdog.ThreadKind.pipeline, "pipeline");
    _ = state.g_wd.registerThread(watchdog.ThreadKind.capture, "capture");
    _ = state.g_wd.registerThread(watchdog.ThreadKind.host_telemetry, "etw");
    _ = state.g_wd.registerThread(watchdog.ThreadKind.host_telemetry, "fim");
    _ = state.g_wd.registerThread(watchdog.ThreadKind.host_telemetry, "registry");
    // 8. Federation/XDR (opt-in, default off). AEGIS_CLUSTER=1 enables
    // the cluster uplink: static peers from configs/cluster.json, TLS
    // material from env PEM paths (fail-closed), outbound-only publish
    // of detection reports. No listener, no policy authority — reports
    // only, enforcement stays local (ADR-0007 P4).
    federation_uplink.initFromEnv(std.heap.page_allocator) catch |err| {
        diag.warn("[CLUSTER] uplink init failed: {s}", .{@errorName(err)});
    };
    defer federation_uplink.shutdown();

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
        // GAP-020: single-owner preflight FIRST -- before any worker (the
        // sensor pipe is unlimited-instance, so a stray second daemon would
        // split nose flow). Exit 3 = owned by another runtime, fail fast.
        if (control.controlPipeOwnedByAnother()) {
            diag.critical("control pipe already owned by another runtime -- refusing second instance (exit 3)", .{});
            std.process.exit(3);
        }
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

        // REBUILD-003: Named-pipe sensor thread (\\.\pipe\aegis_sensor_pipe_t1).
        // Exits when bridge_init.requestShutdown() is signalled.
        supervisor.sensor = std.Thread.spawn(.{}, legacy_capture.capture_packets, .{ std.heap.page_allocator, "" }) catch |err| blk: {
            diag.warn("failed to spawn pipe sensor thread: {} — sensor disabled", .{err});
            state.markWorkerFailure(.sensor);
            break :blk null;
        };

        // Start pipeline loop in a separate thread
        supervisor.pipeline = std.Thread.spawn(.{}, processor.pipelineLoop, .{
            &ac, &ad, &ft, &corr, &tt, &ps, &pep_enf, &forensic_ring, rules_loaded, 0,
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
        //
        // EVT-200: single exception -- AEGIS_DAEMON_IFACE set. A pinned lab
        // interface (e.g. host-only VMnet) carries DISJOINT traffic from the
        // nose path, so no duplicates arise, and nose-pipe frames are
        // metadata-only (lengths+hashes, no payload bytes) while direct
        // capture pushes full packets -- L7 Tier-1 can only match here.
        // Unset keeps the historical disabled behavior byte-identically.
        // A set-but-unmatched value fails closed inside NpcapAdapter.open.
        const lab_iface = std.process.getEnvVarOwned(std.heap.page_allocator, "AEGIS_DAEMON_IFACE") catch null;
        if (lab_iface) |filter| {
            defer std.heap.page_allocator.free(filter);
            if (filter.len > 0) {
                supervisor.direct_capture = std.Thread.spawn(.{}, packet_callback.captureThread, .{}) catch |err| blk: {
                    diag.warn("failed to spawn direct capture thread: {} -- lab capture disabled", .{err});
                    state.markWorkerFailure(.sensor);
                    break :blk null;
                };
                if (supervisor.direct_capture != null) diag.info("direct Zig Npcap capture STARTED (lab interface pin: {s})", .{filter});
            } else {
                diag.info("direct Zig Npcap capture disabled; Go Nose is canonical network ingress", .{});
            }
        } else {
            diag.info("direct Zig Npcap capture disabled; Go Nose is canonical network ingress", .{});
        }

        // Canonical Go Nose -> named pipe -> detector pipeline queue path.
        supervisor.nose_reader = std.Thread.spawn(.{}, nose_reader.runPipeReaderLoop, .{&state.g_stop_requested}) catch |err| blk: {
            diag.warn("failed to spawn Go Nose pipe reader: {} — external capture disabled", .{err});
            state.markWorkerFailure(.nose);
            break :blk null;
        };

        // EVT-202: kernel WFP flow telemetry (submit-only). Always spawned:
        // driver-absent hosts idle in a quiet retry loop, and the Rust
        // adapter is the sole device owner (no handle taken here), so this
        // cannot race or blind anything. See wfp_telemetry.zig for the
        // never-inspect-never-block contract.
        supervisor.wfp_telemetry = std.Thread.spawn(.{}, wfp_telemetry.telemetryLoop, .{&state.g_stop_requested}) catch |err| blk: {
            diag.warn("failed to spawn WFP telemetry thread: {} — kernel flow telemetry disabled", .{err});
            break :blk null;
        };

        // EVT-230: kernel minifilter host telemetry (file-create + process
        // create/exit rows) via \AegisMinifilterPort. Always spawned:
        // driver-absent hosts stay in a labeled retry loop (queue.stats
        // `minifilter` block reports unavailable), never silent.
        // Observe-only: drained rows are detection input, never enforcement.
        supervisor.minifilter = std.Thread.spawn(.{}, minifilter_reader.minifilterReaderLoop, .{}) catch |err| blk: {
            diag.warn("failed to spawn minifilter reader: {} — kernel host telemetry disabled", .{err});
            break :blk null;
        };
        if (supervisor.minifilter != null) diag.info("minifilter kernel host telemetry reader started", .{});

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

        // A runtime with a live pipeline but missing enforcement/bridge
        // dependencies must not be advertised as fully RUNNING. The control
        // pipe may remain available for diagnostics, but the state machine is
        // degraded until every required bridge is active.
        const pipeline_failed = (state.workerFailureMask() & 0x01) != 0;
        const bridges_ready = bridge_init.allActive();
        if (!bridges_ready) {
            diag.warn("runtime degraded: required bridge dependency is unavailable", .{});
        }
        if (state.g_pipeline_ready.load(.acquire) and !pipeline_failed and bridges_ready) {
            runtime_sm.g_runtime.transition(.running);
        } else {
            runtime_sm.g_runtime.transition(.degraded);
        }
        service.setServiceStatus(SERVICE_RUNNING, 0);

        // Serve control pipe on main thread. GAP-020: a create failure means
        // no control plane (duplicate owner or broken endpoint) -- exit
        // non-zero fast instead of running blind; the preflight above
        // catches the common case, this covers the race.
        control.serveWindowsPipe(&caps, start_ns) catch |err| {
            diag.err("control server error: {}", .{err});
            if (err == error.ControlPipeCreateFailed) std.process.exit(1);
        };
        supervisor.requestStop();
    } else {
        // Non-Windows: run pipeline + control loop on main thread
        diag.info("running pipeline loop (non-Windows test mode)", .{});
        processor.pipelineLoop(&ac, &ad, &ft, &corr, &tt, &ps, &pep_enf, &forensic_ring, rules_loaded, 0);
    }

    diag.info("AEGIS NIDS shutting down", .{});
}
