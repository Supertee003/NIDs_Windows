//! control/state_machine.zig — AEGIS NIDS Runtime State Machine
//!
//! Single source of truth for system and subsystem states.
//! Both system.status and system.health pull from this module.
//!
//! System states: STOPPED → STARTING → READY → RUNNING → DEGRADED → RECOVERING → STOPPING → STOPPED
//! Subsystems:   ZIG, GO, C++, RUST_PEP, TIER3, CONTROL, FORENSIC
//!
//! Each subsystem tracks: state, pid, version, started_at, last_heartbeat,
//! last_event, error, capabilities.

const std = @import("std");
const runtime_state = @import("../pipeline/runtime_state.zig");
const telemetry = @import("../pipeline/telemetry_threads.zig");
// RESOURCE-TELEMETRY-001: sampled CPU/memory gauges. Pulled only from
// healthJson (a control query) — never from the event pipeline (ADR-0013).
const resource_telemetry = @import("../windows/resource_telemetry.zig");
const defcon = @import("defcon.zig");
const diag = @import("../core/diagnostics.zig");

// ============================================================
// System State Machine
// ============================================================

pub const SystemState = enum(u8) {
    stopped = 0,
    starting = 1,
    ready = 2,
    running = 3,
    degraded = 4,
    recovering = 5,
    stopping = 6,
    failed = 7,

    pub fn toString(self: SystemState) []const u8 {
        return switch (self) {
            .stopped => "STOPPED",
            .starting => "STARTING",
            .ready => "READY",
            .running => "RUNNING",
            .degraded => "DEGRADED",
            .recovering => "RECOVERING",
            .stopping => "STOPPING",
            .failed => "FAILED",
        };
    }

    pub fn isRunning(self: SystemState) bool {
        return self == .running or self == .ready;
    }

    pub fn canServe(self: SystemState) bool {
        return self == .running or self == .ready or self == .degraded;
    }

    /// Structural lifecycle contract. The legacy `transition` method remains
    /// available for existing call sites; new owners should use
    /// `transitionChecked` so illegal state jumps cannot be silently published.
    pub fn canTransition(self: SystemState, next: SystemState) bool {
        return switch (self) {
            .stopped => next == .starting,
            .starting => next == .ready or next == .running or next == .degraded or next == .stopped,
            .ready => next == .running or next == .degraded or next == .stopping,
            .running => next == .degraded or next == .recovering or next == .stopping,
            .degraded => next == .recovering or next == .stopping or next == .failed,
            .recovering => next == .running or next == .degraded or next == .failed or next == .stopping,
            .stopping => next == .stopped,
            .failed => next == .starting or next == .stopped,
        };
    }
};

// ============================================================
// Subsystem Definitions
// ============================================================

pub const SubsystemId = enum(u8) {
    zig = 0,
    go = 1,
    cpp = 2,
    rust_pep = 3,
    tier3 = 4,
    control = 5,
    forensic = 6,
};

pub const SubsystemState = enum(u8) {
    stopped = 0,
    starting = 1,
    ready = 2,
    running = 3,
    failed = 4,
    degraded = 5,

    pub fn toString(self: SubsystemState) []const u8 {
        return switch (self) {
            .stopped => "STOPPED",
            .starting => "STARTING",
            .ready => "READY",
            .running => "RUNNING",
            .failed => "FAILED",
            .degraded => "DEGRADED",
        };
    }

    pub fn isHealthy(self: SubsystemState) bool {
        return self == .running or self == .ready;
    }
};

pub const SubsystemInfo = struct {
    id: SubsystemId,
    name: []const u8,
    state: SubsystemState = .stopped,
    pid: u32 = 0,
    version: []const u8 = "unknown",
    started_at_ms: i64 = 0,
    last_heartbeat_ms: i64 = 0,
    last_event_ms: i64 = 0,
    error_msg: ?[]const u8 = null,
    capabilities: []const u8 = "",

    pub fn isHealthy(self: *const SubsystemInfo) bool {
        return self.state.isHealthy();
    }

    pub fn toJson(self: *const SubsystemInfo, a: std.mem.Allocator) ![]u8 {
        var out = std.ArrayList(u8).init(a);
        var writer = out.writer();
        try writer.print(
            "{{\"name\":\"{s}\",\"state\":\"{s}\",\"pid\":{},\"version\":\"{s}\",\"started_at_ms\":{},\"last_heartbeat_ms\":{},\"last_event_ms\":{},\"error\":",
            .{
                self.name,
                self.state.toString(),
                self.pid,
                self.version,
                self.started_at_ms,
                self.last_heartbeat_ms,
                self.last_event_ms,
            },
        );
        if (self.error_msg) |e| {
            // Internal failure reasons are controlled tokens, but still emit
            // them as a JSON string. The previous unquoted value produced an
            // invalid health document exactly when a subsystem failed.
            try writer.print("\"{s}\"", .{e});
        } else {
            try writer.writeAll("null");
        }
        try writer.print(",\"capabilities\":\"{s}\"}}", .{self.capabilities});
        return out.toOwnedSlice();
    }
};

// ============================================================
// Global Runtime State
// ============================================================

const MAX_SUBSYSTEMS = 8;

pub const RuntimeState = struct {
    system_state: SystemState = .stopped,
    subsystems: [MAX_SUBSYSTEMS]SubsystemInfo = undefined,
    subsystem_count: usize = 0,
    started_at_ms: i64 = 0,
    uptime_ms: i64 = 0,
    version: []const u8 = "5.0.0",
    build: []const u8 = "zig-0.13.0",
    mutex: std.Thread.Mutex = .{},

    /// READY-PROMOTION-001: consecutive healthy samples behind a promotion.
    /// Kept in the state, not in a caller, so no second authority exists.
    promote_streak: u8 = 0,
    last_sample_ms: i64 = 0,

    /// Register a subsystem at startup.
    pub fn registerSubsystem(self: *RuntimeState, id: SubsystemId, name: []const u8, version: []const u8, capabilities: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.subsystem_count >= MAX_SUBSYSTEMS) return;
        self.subsystems[self.subsystem_count] = .{
            .id = id,
            .name = name,
            .version = version,
            .capabilities = capabilities,
        };
        self.subsystem_count += 1;
    }

    /// Mark a subsystem as started.
    pub fn subsystemStarted(self: *RuntimeState, id: SubsystemId, pid: u32) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.subsystems[0..self.subsystem_count]) |*sub| {
            if (sub.id == id) {
                sub.state = .running;
                sub.pid = pid;
                sub.started_at_ms = std.time.milliTimestamp();
                sub.last_heartbeat_ms = sub.started_at_ms;
                return;
            }
        }
    }

    /// Mark a subsystem as failed.
    pub fn subsystemFailed(self: *RuntimeState, id: SubsystemId, error_msg: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.subsystems[0..self.subsystem_count]) |*sub| {
            if (sub.id == id) {
                sub.state = .failed;
                sub.error_msg = error_msg;
                return;
            }
        }
    }

    /// Mark a subsystem as degraded.
    pub fn subsystemDegraded(self: *RuntimeState, id: SubsystemId, error_msg: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.subsystems[0..self.subsystem_count]) |*sub| {
            if (sub.id == id) {
                sub.state = .degraded;
                sub.error_msg = error_msg;
                return;
            }
        }
    }

    /// Update heartbeat for a subsystem.
    pub fn heartbeat(self: *RuntimeState, id: SubsystemId) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.subsystems[0..self.subsystem_count]) |*sub| {
            if (sub.id == id) {
                sub.last_heartbeat_ms = std.time.milliTimestamp();
                return;
            }
        }
    }

    /// Update last event time for a subsystem.
    pub fn recordEvent(self: *RuntimeState, id: SubsystemId) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.subsystems[0..self.subsystem_count]) |*sub| {
            if (sub.id == id) {
                sub.last_event_ms = std.time.milliTimestamp();
                return;
            }
        }
    }

    /// Transition system state.
    pub fn transition(self: *RuntimeState, new_state: SystemState) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const old = self.system_state;
        self.system_state = new_state;
        // Audit log
        std.log.info("[STATE] System: {s} -> {s}", .{ old.toString(), new_state.toString() });
    }

    /// Compute degraded status from subsystem health.
    pub fn recomputeHealth(self: *RuntimeState) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var any_failed = false;
        var all_healthy = true;
        for (self.subsystems[0..self.subsystem_count]) |sub| {
            if (!sub.isHealthy()) all_healthy = false;
            if (sub.state == .failed) any_failed = true;
        }
        if (any_failed and self.system_state == .running) {
            self.system_state = .degraded;
        } else if (all_healthy and self.system_state == .degraded) {
            self.system_state = .recovering;
        }
    }

    /// READY-PROMOTION-001. Healthy samples needed before each promotion step
    /// and the minimum spacing between counted samples.
    pub const PROMOTION_SAMPLES: u8 = 3;
    pub const PROMOTION_MIN_INTERVAL_MS: i64 = 5_000;

    /// The facts a promotion may depend on. `fresh_loss_observed` is
    /// deliberately NOT the health contract's cumulative `data_loss_observed`:
    /// the daemon samples fresh loss since the previous 5 s poll, so lifecycle
    /// can recover while health stays DEGRADED under the cumulative budget.
    /// P4-F7 names the difference instead of claiming identical booleans.
    pub const LifecycleFacts = struct {
        pipeline_ready: bool = false,
        pipeline_failed: bool = false,
        bridge_ready: bool = false,
        fresh_loss_observed: bool = false,

        pub fn allClear(self: LifecycleFacts) bool {
            return self.pipeline_ready and !self.pipeline_failed and self.bridge_ready and !self.fresh_loss_observed;
        }
    };

    /// Apply one lifecycle sample. Returns the new state when it changed.
    ///
    /// DEFECT-READY-001 was that the daemon sampled this once at startup and
    /// never again, so a bridge that came up a second later left the process
    /// DEGRADED until the next restart. DEMOTE is immediate (a failed subsystem
    /// or fresh loss must not be averaged away); PROMOTE needs
    /// PROMOTION_SAMPLES consecutive clear samples at least
    /// PROMOTION_MIN_INTERVAL_MS apart, so a flapping bridge cannot hide.
    pub fn reconcileLifecycle(self: *RuntimeState, now_ms: i64, facts: LifecycleFacts) ?SystemState {
        self.mutex.lock();
        defer self.mutex.unlock();

        var subsystems_healthy = true;
        for (self.subsystems[0..self.subsystem_count]) |sub| {
            if (!sub.isHealthy()) subsystems_healthy = false;
        }
        const clear = facts.allClear() and subsystems_healthy;

        if (!clear) {
            self.promote_streak = 0;
            if (self.system_state == .running or self.system_state == .recovering) {
                const old = self.system_state;
                self.system_state = .degraded;
                std.log.info("[STATE] System: {s} -> {s} (live facts disagree)", .{ old.toString(), self.system_state.toString() });
                return self.system_state;
            }
            return null;
        }

        if (self.last_sample_ms != 0 and now_ms - self.last_sample_ms < PROMOTION_MIN_INTERVAL_MS) {
            return null; // Too soon to count another sample; a fast poll must not promote.
        }
        self.last_sample_ms = now_ms;
        if (self.promote_streak < PROMOTION_SAMPLES) self.promote_streak += 1;
        if (self.promote_streak < PROMOTION_SAMPLES) return null;

        const next: ?SystemState = switch (self.system_state) {
            .degraded => .recovering,
            .recovering => .running,
            .starting, .ready => .running,
            else => null,
        };
        if (next) |n| {
            if (!self.system_state.canTransition(n)) return null;
            const old = self.system_state;
            self.system_state = n;
            std.log.info("[STATE] System: {s} -> {s} ({} clear samples)", .{ old.toString(), n.toString(), self.promote_streak });
            // Each step is paid for on its own: RECOVERING -> RUNNING must also
            // wait PROMOTION_SAMPLES, so the streak restarts after every step.
            self.promote_streak = 0;
        }
        return next;
    }

    /// Get a subsystem by ID.
    pub fn getSubsystem(self: *RuntimeState, id: SubsystemId) ?*SubsystemInfo {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.subsystems[0..self.subsystem_count]) |*sub| {
            if (sub.id == id) return sub;
        }
        return null;
    }

    /// Get system state summary as JSON.
    pub fn statusJson(self: *RuntimeState, a: std.mem.Allocator) ![]u8 {
        self.mutex.lock();
        const ss = self.system_state;
        const uptime = self.uptime_ms;
        const ver = self.version;
        const bld = self.build;
        const sub_count = self.subsystem_count;
        const subs = self.subsystems[0..sub_count];
        self.mutex.unlock();

        var arr = std.ArrayList(u8).init(a);
        var writer = arr.writer();
        try writer.print(
            \\{{"state":"{s}","version":"{s}","build":"{s}","uptime_ms":{},"packets_captured":{},"flows_active":{},"subsystems":[
        , .{ ss.toString(), ver, bld, uptime, runtime_state.g_nose_frames_submitted.load(.acquire), diag.metrics.flows_active.get() });

        for (subs, 0..) |sub, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.writeAll(try sub.toJson(a));
        }
        try writer.writeAll("]}");
        return arr.toOwnedSlice();
    }

    /// Get health check JSON.
    pub fn healthJson(self: *RuntimeState, a: std.mem.Allocator, pid: u32, bridge_ready: bool, wfp_ready: bool, cpp_ready: bool, udp_ready: bool, workers: WorkerReadiness) ![]u8 {
        self.mutex.lock();
        const ss = self.system_state;
        const uptime = self.uptime_ms;
        const ver = self.version;
        const sub_count = self.subsystem_count;
        const subs = self.subsystems[0..sub_count];
        self.mutex.unlock();

        var all_healthy = true;
        for (subs) |sub| {
            if (!sub.isHealthy()) all_healthy = false;
        }

        var arr = std.ArrayList(u8).init(a);
        var writer = arr.writer();
        // Health state must agree with the degraded flag. A live control or
        // pipeline spine is useful for diagnostics, but it is not a fully
        // operational NIDS when a required bridge/WFP dependency is absent.
        // Keep the process serving, while reporting DEGRADED consistently in
        // both `state` and `degraded`.
        const core_pipeline_failed = (workers.failure_mask & 0x01) != 0;
        const queue_drops = runtime_state.g_queue_drops.load(.acquire);
        const nose_rejected = runtime_state.g_nose_frames_rejected.load(.acquire);
        const nose_dropped = runtime_state.g_nose_frames_dropped.load(.acquire);
        const nose_pipe_errors = runtime_state.g_nose_pipe_errors.load(.acquire);
        const pipeline_processing_errors = runtime_state.g_pipeline_processing_errors.load(.acquire);
        const minifilter_ring_dropped = runtime_state.g_minifilter_dropped.load(.acquire);
        const minifilter_pipeline_dropped = runtime_state.g_minifilter_pipeline_dropped.load(.acquire);
        // OBSERVABILITY-001: the soak tool reads this health payload, but
        // `shed_overload` used to exist only on queue.stats (recorded honesty
        // gap). Report the same counter here. It is deliberately NOT part of
        // `data_loss_observed`: a shed-only storm (dropped=0) is a budgeted
        // policy outcome, scored separately by `--shed-budget`, not DEGRADED.
        const shed_overload = telemetry.g_shed_overload.load(.acquire);
        // RC-CLOSEOUT: the owner-approved envelope. A counter at or below the
        // budget is inside the declared loss envelope and must not flip the
        // runtime to DEGRADED; above it, the strict behaviour returns.
        const loss_budget = runtime_state.g_loss_budget.load(.acquire);
        const data_loss_observed = queue_drops > loss_budget or nose_rejected > loss_budget or
            nose_dropped > loss_budget or nose_pipe_errors > loss_budget or
            pipeline_processing_errors > loss_budget or
            minifilter_ring_dropped > loss_budget or minifilter_pipeline_dropped > loss_budget;
        const operationally_ready = workers.pipeline and !core_pipeline_failed and bridge_ready and !data_loss_observed;
        const operational_state = if (operationally_ready) "RUNNING" else "DEGRADED";
        const health_degraded = !all_healthy or !workers.pipeline or core_pipeline_failed or !bridge_ready or data_loss_observed;
        // FE-DEF-095a: daemon-owned DEFCON rides the health payload so every
        // UI reads one authority instead of computing its own ladder from
        // files. Additive fields; older readers ignore unknown keys.
        const defcon_total = runtime_state.g_pipeline_detections.load(.acquire);
        const defcon_critical = runtime_state.g_critical_detections.load(.acquire);
        // QUAR-RCPT-112: confirmed counts every receipt-verified host effect
        // (blocks plus quarantines, saturating). Thresholds in defcon.level
        // are unchanged; only the input widens from blocks-only.
        const defcon_confirmed = runtime_state.g_confirmed_blocks.load(.acquire) +|
            runtime_state.g_confirmed_quarantines.load(.acquire);
        const defcon_level = defcon.level(defcon_total, defcon_critical, defcon_confirmed);
        // STEP-43 + P0-8 remainder, additive keys (older readers ignore
        // unknown fields): packets_captured is canonical data-plane ingress
        // (nose submissions, same source as metrics.snapshot and the Python
        // counters synthesis — NOT the dormant direct-Npcap counter), and
        // counters mirrors the control_api mapping so the daemon itself
        // satisfies RUNTIME_CONTRACT §4.1.
        try writer.print(
            \\{{"component":"core","version":"{s}","state":"{s}","runtime_state":"{s}","pid":{} ,"uptime_ms":{},"last_event_ms":{},"degraded":{},"rules_loaded":{},"policies_loaded":{},"defcon_level":{},"defcon_label":"{s}","capabilities":{{"wfp":{},"cpp_bridge":{},"udp_brain":{} }},
        , .{ ver, operational_state, ss.toString(), pid, uptime, runtime_state.lastEventAgeMs(runtime_state.g_last_event_ms.load(.acquire), std.time.milliTimestamp()), health_degraded, runtime_state.g_rules_loaded.load(.acquire), runtime_state.g_policies_loaded.load(.acquire), defcon_level, defcon.labelFor(defcon_level), wfp_ready, cpp_ready, udp_ready });
        try writer.print(
            \\"data_plane":{{"nose_connected":{},"nose_frames_read":{},"nose_frames_rejected":{},"nose_frames_submitted":{},"nose_frames_dropped":{},"nose_pipe_errors":{},"nose_last_event_id":{},"nose_duplicate_event_ids":{},"nose_non_monotonic_event_ids":{},"nose_producer_invalid":{},"nose_producer_duplicate":{},"nose_producer_regression":{},"nose_producer_gap":{},"nose_producer_evictions":{},"nose_last_capture_sequence":{},"nose_last_producer_epoch":{},"nose_last_producer_generation":{},"nose_last_interface_id":{}}},"packets_captured":{},"flows_active":{},"counters":{{"in_events":{},"out_events":{},"errors":{},"dropped":{}}},
        , .{
            runtime_state.g_nose_connected.load(.acquire),
            runtime_state.g_nose_frames_read.load(.acquire),
            runtime_state.g_nose_frames_rejected.load(.acquire),
            runtime_state.g_nose_frames_submitted.load(.acquire),
            runtime_state.g_nose_frames_dropped.load(.acquire),
            runtime_state.g_nose_pipe_errors.load(.acquire),
            runtime_state.g_nose_last_event_id.load(.acquire),
            runtime_state.g_nose_duplicate_event_ids.load(.acquire),
            runtime_state.g_nose_non_monotonic_event_ids.load(.acquire),
            runtime_state.g_nose_producer_invalid.load(.acquire),
            runtime_state.g_nose_producer_duplicate.load(.acquire),
            runtime_state.g_nose_producer_regression.load(.acquire),
            runtime_state.g_nose_producer_gap.load(.acquire),
            runtime_state.g_nose_producer_evictions.load(.acquire),
            runtime_state.g_nose_last_capture_sequence.load(.acquire),
            runtime_state.g_nose_last_producer_epoch.load(.acquire),
            runtime_state.g_nose_last_producer_generation.load(.acquire),
            runtime_state.g_nose_last_interface_id.load(.acquire),
            runtime_state.g_nose_frames_submitted.load(.acquire),
            diag.metrics.flows_active.get(),
            runtime_state.g_nose_frames_read.load(.acquire),
            runtime_state.g_nose_frames_submitted.load(.acquire),
            runtime_state.g_nose_pipe_errors.load(.acquire),
            runtime_state.g_nose_frames_dropped.load(.acquire),
        });
        // OBSERVABILITY-001 / issue #44: additive keys inside data_integrity.
        // The five `nose_frames_dropped_*` keys are DIAGNOSTIC SUBSETS of the
        // total, not extra loss: they are never summed by the soak gate.
        // `shed_overload` was recorded only on queue.stats before (soak reads
        // health, hence the honesty gap). `process_generation_ms` is captured
        // once at daemon start: monotonic counters reset at process start, so a
        // generation change between soak baseline and delta makes the delta
        // meaningless. It is a PROCESS generation token (not an OS reboot id).
        // Older readers ignore all additive keys.
        try writer.print("\"data_integrity\":{{\"queue_dropped_total\":{},\"nose_frames_rejected\":{},\"nose_frames_dropped\":{},\"nose_frames_dropped_framing\":{},\"nose_frames_dropped_midframe\":{},\"nose_frames_dropped_shape\":{},\"nose_frames_dropped_identity\":{},\"nose_frames_dropped_capacity\":{},\"nose_pipe_errors\":{},\"pipeline_processing_errors\":{},\"minifilter_ring_dropped\":{},\"minifilter_pipeline_dropped\":{},\"loss_budget\":{},\"shed_overload\":{},\"process_generation_ms\":{}}},", .{
            queue_drops,
            nose_rejected,
            nose_dropped,
            runtime_state.g_nose_frames_dropped_framing.load(.acquire),
            runtime_state.g_nose_frames_dropped_midframe.load(.acquire),
            runtime_state.g_nose_frames_dropped_shape.load(.acquire),
            runtime_state.g_nose_frames_dropped_identity.load(.acquire),
            runtime_state.g_nose_frames_dropped_capacity.load(.acquire),
            nose_pipe_errors,
            pipeline_processing_errors,
            minifilter_ring_dropped,
            minifilter_pipeline_dropped,
            loss_budget,
            shed_overload,
            runtime_state.g_process_generation_ms.load(.acquire),
        });
        // P4-F6: detection degradation is visible but is NOT event loss. A
        // separate object keeps it out of `data_loss_observed` and out of the
        // soak tool's LOSS_COUNTERS. The event keeps flowing on every failure.
        try writer.print("\"detector_degradation\":{{\"correlator_errors\":{},\"anomaly_detector_errors\":{},\"threat_tracker_errors\":{}}},", .{
            runtime_state.g_correlator_observe_errors.load(.acquire),
            runtime_state.g_anomaly_observe_errors.load(.acquire),
            runtime_state.g_threat_tracker_observe_errors.load(.acquire),
        });
        // RESOURCE-TELEMETRY-001: additive, sampled off the hot path. Written
        // through the pure json() helper so escaped-brace errors cannot truncate
        // the health payload (successEnvelope re-parses it).
        try writer.writeAll("\"resources\":");
        const resources_json = try resource_telemetry.json(a, resource_telemetry.current());
        defer a.free(resources_json);
        try writer.writeAll(resources_json);
        try writer.writeAll(",\"deps\":[");

        try writer.print("{{\"name\":\"bridge\",\"state\":\"{s}\"}},{{\"name\":\"pipeline\",\"state\":\"{s}\"}}],\"subsystems\":[", .{
            if (bridge_ready) "RUNNING" else "DEGRADED",
            if (workers.pipeline) "RUNNING" else "DEGRADED",
        });

        for (subs, 0..) |sub, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.writeAll(try sub.toJson(a));
        }
        try writer.print("],\"workers\":{{\"pipeline_ready\":{},\"sensor_ready\":{},\"nose_ready\":{},\"etw_ready\":{},\"fim_ready\":{},\"registry_ready\":{},\"failed\":{},\"failure_reason\":\"{s}\",\"failure_mask\":{}", .{
            workers.pipeline,
            workers.sensor,
            workers.nose,
            workers.etw,
            workers.fim,
            workers.registry,
            workers.failed,
            workers.failure_reason,
            workers.failure_mask,
        });
        // Close the workers object and the health payload root explicitly.
        // Keeping delimiters out of the format string avoids escaped-brace
        // counting errors that can truncate the JSON response.
        try writer.writeAll("}}");
        return arr.toOwnedSlice();
    }
};

/// Readiness reported by daemon-owned workers. Thread creation alone is not
/// represented as readiness.
pub const WorkerReadiness = struct {
    pipeline: bool,
    sensor: bool,
    nose: bool,
    etw: bool,
    fim: bool,
    registry: bool,
    failed: bool,
    failure_reason: []const u8,
    failure_mask: u8,
};

/// Global runtime state instance.
pub var g_runtime = RuntimeState{};

// ============================================================
// Tests
// ============================================================

test "SystemState: state properties" {
    try std.testing.expect(SystemState.running.isRunning());
    try std.testing.expect(SystemState.ready.isRunning());
    try std.testing.expect(!SystemState.stopped.isRunning());
    try std.testing.expect(!SystemState.degraded.isRunning());

    try std.testing.expect(SystemState.running.canServe());
    try std.testing.expect(SystemState.degraded.canServe());
    try std.testing.expect(!SystemState.stopped.canServe());
    try std.testing.expect(!SystemState.starting.canServe());
}

test "SystemState: lifecycle transition graph" {
    try std.testing.expect(SystemState.stopped.canTransition(.starting));
    try std.testing.expect(SystemState.starting.canTransition(.ready));
    try std.testing.expect(SystemState.ready.canTransition(.running));
    try std.testing.expect(SystemState.running.canTransition(.stopping));
    try std.testing.expect(SystemState.stopping.canTransition(.stopped));
    try std.testing.expect(!SystemState.stopped.canTransition(.running));
    try std.testing.expect(!SystemState.running.canTransition(.starting));
}

test "SubsystemState: health check" {
    try std.testing.expect(SubsystemState.running.isHealthy());
    try std.testing.expect(SubsystemState.ready.isHealthy());
    try std.testing.expect(!SubsystemState.failed.isHealthy());
    try std.testing.expect(!SubsystemState.degraded.isHealthy());
    try std.testing.expect(!SubsystemState.stopped.isHealthy());
}

test "RuntimeState: register and start subsystem" {
    var rs = RuntimeState{};
    rs.registerSubsystem(.zig, "zig", "5.0.0", "core");
    rs.registerSubsystem(.go, "go", "5.0.0", "capture");

    try std.testing.expectEqual(@as(usize, 2), rs.subsystem_count);
    try std.testing.expectEqual(SubsystemState.stopped, rs.subsystems[0].state);

    rs.subsystemStarted(.zig, 1234);
    try std.testing.expectEqual(SubsystemState.running, rs.subsystems[0].state);
    try std.testing.expectEqual(@as(u32, 1234), rs.subsystems[0].pid);
}

test "RuntimeState: subsystem failure degrades system" {
    var rs = RuntimeState{};
    rs.registerSubsystem(.zig, "zig", "5.0.0", "");
    rs.registerSubsystem(.go, "go", "5.0.0", "");
    rs.subsystemStarted(.zig, 100);
    rs.subsystemStarted(.go, 200);
    rs.system_state = .running;

    rs.subsystemFailed(.go, "crashed");
    rs.recomputeHealth();
    try std.testing.expectEqual(SystemState.degraded, rs.system_state);
}

test "statusJson exposes packets_captured and flows_active from live counters" {
    // STEP-43: system.status readers did dict.get(key, 0) on absent keys.
    const prev_sub = runtime_state.g_nose_frames_submitted.load(.acquire);
    defer runtime_state.g_nose_frames_submitted.store(prev_sub, .monotonic);
    const prev_flow: i64 = diag.metrics.flows_active.get();
    defer diag.metrics.flows_active.set(prev_flow);
    runtime_state.g_nose_frames_submitted.store(424242, .monotonic);
    diag.metrics.flows_active.set(7);
    var rs = RuntimeState{};
    const out = try rs.statusJson(std.testing.allocator);
    defer std.testing.allocator.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"packets_captured\":424242") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"flows_active\":7") != null);
}

test "healthJson exposes packets_captured, flows_active and counters from live counters" {
    // STEP-43 + P0-8 remainder: RUNTIME_CONTRACT §4.1 counters must come
    // from the daemon, with the same mapping the Python shim synthesizes
    // (in=read, out=submitted, errors=pipe_errors, dropped=dropped).
    const prev_read = runtime_state.g_nose_frames_read.load(.acquire);
    const prev_sub = runtime_state.g_nose_frames_submitted.load(.acquire);
    const prev_err = runtime_state.g_nose_pipe_errors.load(.acquire);
    const prev_drop = runtime_state.g_nose_frames_dropped.load(.acquire);
    defer {
        runtime_state.g_nose_frames_read.store(prev_read, .monotonic);
        runtime_state.g_nose_frames_submitted.store(prev_sub, .monotonic);
        runtime_state.g_nose_pipe_errors.store(prev_err, .monotonic);
        runtime_state.g_nose_frames_dropped.store(prev_drop, .monotonic);
    }
    const prev_flow: i64 = diag.metrics.flows_active.get();
    defer diag.metrics.flows_active.set(prev_flow);
    runtime_state.g_nose_frames_read.store(1000, .monotonic);
    runtime_state.g_nose_frames_submitted.store(900, .monotonic);
    runtime_state.g_nose_pipe_errors.store(3, .monotonic);
    runtime_state.g_nose_frames_dropped.store(12, .monotonic);
    diag.metrics.flows_active.set(5);
    var rs = RuntimeState{};
    const workers = WorkerReadiness{ .pipeline = true, .sensor = true, .nose = true, .etw = true, .fim = true, .registry = true, .failed = false, .failure_reason = "", .failure_mask = 0 };
    const out = try rs.healthJson(std.testing.allocator, 1234, true, true, true, true, workers);
    defer std.testing.allocator.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"packets_captured\":900") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"flows_active\":5") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"counters\":{\"in_events\":1000,\"out_events\":900,\"errors\":3,\"dropped\":12}") != null);
}

test "healthJson reports DEGRADED when ingress loss counters are nonzero" {
    const saved = .{
        runtime_state.g_queue_drops.load(.acquire),
        runtime_state.g_nose_frames_rejected.load(.acquire),
        runtime_state.g_nose_frames_dropped.load(.acquire),
        runtime_state.g_nose_pipe_errors.load(.acquire),
        runtime_state.g_minifilter_dropped.load(.acquire),
        runtime_state.g_minifilter_pipeline_dropped.load(.acquire),
    };
    defer {
        runtime_state.g_queue_drops.store(saved[0], .monotonic);
        runtime_state.g_nose_frames_rejected.store(saved[1], .monotonic);
        runtime_state.g_nose_frames_dropped.store(saved[2], .monotonic);
        runtime_state.g_nose_pipe_errors.store(saved[3], .monotonic);
        runtime_state.g_minifilter_dropped.store(saved[4], .monotonic);
        runtime_state.g_minifilter_pipeline_dropped.store(saved[5], .monotonic);
    }
    runtime_state.g_queue_drops.store(1, .monotonic);
    runtime_state.g_nose_frames_rejected.store(0, .monotonic);
    runtime_state.g_nose_frames_dropped.store(0, .monotonic);
    runtime_state.g_nose_pipe_errors.store(0, .monotonic);
    runtime_state.g_minifilter_dropped.store(0, .monotonic);
    runtime_state.g_minifilter_pipeline_dropped.store(0, .monotonic);
    var rs = RuntimeState{};
    const workers = WorkerReadiness{ .pipeline = true, .sensor = true, .nose = true, .etw = true, .fim = true, .registry = true, .failed = false, .failure_reason = "", .failure_mask = 0 };
    const out = try rs.healthJson(std.testing.allocator, 1234, true, true, true, true, workers);
    defer std.testing.allocator.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"state\":\"DEGRADED\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"degraded\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"queue_dropped_total\":1") != null);
}

test "healthJson exposes pipeline processing errors and degrades on them (issue #44)" {
    const saved = .{
        runtime_state.g_queue_drops.load(.acquire),
        runtime_state.g_nose_frames_rejected.load(.acquire),
        runtime_state.g_nose_frames_dropped.load(.acquire),
        runtime_state.g_nose_pipe_errors.load(.acquire),
        runtime_state.g_pipeline_processing_errors.load(.acquire),
        runtime_state.g_minifilter_dropped.load(.acquire),
        runtime_state.g_minifilter_pipeline_dropped.load(.acquire),
        runtime_state.g_loss_budget.load(.acquire),
    };
    defer {
        runtime_state.g_queue_drops.store(saved[0], .monotonic);
        runtime_state.g_nose_frames_rejected.store(saved[1], .monotonic);
        runtime_state.g_nose_frames_dropped.store(saved[2], .monotonic);
        runtime_state.g_nose_pipe_errors.store(saved[3], .monotonic);
        runtime_state.g_pipeline_processing_errors.store(saved[4], .monotonic);
        runtime_state.g_minifilter_dropped.store(saved[5], .monotonic);
        runtime_state.g_minifilter_pipeline_dropped.store(saved[6], .monotonic);
        runtime_state.g_loss_budget.store(saved[7], .monotonic);
    }
    runtime_state.g_queue_drops.store(0, .monotonic);
    runtime_state.g_nose_frames_rejected.store(0, .monotonic);
    runtime_state.g_nose_frames_dropped.store(0, .monotonic);
    runtime_state.g_nose_pipe_errors.store(0, .monotonic);
    runtime_state.g_pipeline_processing_errors.store(1, .monotonic);
    runtime_state.g_minifilter_dropped.store(0, .monotonic);
    runtime_state.g_minifilter_pipeline_dropped.store(0, .monotonic);
    runtime_state.g_loss_budget.store(0, .monotonic);
    var rs = RuntimeState{};
    const workers = WorkerReadiness{ .pipeline = true, .sensor = true, .nose = true, .etw = true, .fim = true, .registry = true, .failed = false, .failure_reason = "", .failure_mask = 0 };
    const out = try rs.healthJson(std.testing.allocator, 1234, true, true, true, true, workers);
    defer std.testing.allocator.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"pipeline_processing_errors\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"state\":\"DEGRADED\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"degraded\":true") != null);
}

test "healthJson exposes cause splits and detector degradation without double-counting (issue #44)" {
    const saved = .{
        runtime_state.g_queue_drops.load(.acquire),
        runtime_state.g_nose_frames_rejected.load(.acquire),
        runtime_state.g_nose_frames_dropped.load(.acquire),
        runtime_state.g_nose_frames_dropped_framing.load(.acquire),
        runtime_state.g_nose_frames_dropped_midframe.load(.acquire),
        runtime_state.g_nose_frames_dropped_shape.load(.acquire),
        runtime_state.g_nose_frames_dropped_capacity.load(.acquire),
        runtime_state.g_nose_pipe_errors.load(.acquire),
        runtime_state.g_correlator_observe_errors.load(.acquire),
        runtime_state.g_anomaly_observe_errors.load(.acquire),
        runtime_state.g_threat_tracker_observe_errors.load(.acquire),
        runtime_state.g_minifilter_dropped.load(.acquire),
        runtime_state.g_minifilter_pipeline_dropped.load(.acquire),
        runtime_state.g_loss_budget.load(.acquire),
    };
    defer {
        runtime_state.g_queue_drops.store(saved[0], .monotonic);
        runtime_state.g_nose_frames_rejected.store(saved[1], .monotonic);
        runtime_state.g_nose_frames_dropped.store(saved[2], .monotonic);
        runtime_state.g_nose_frames_dropped_framing.store(saved[3], .monotonic);
        runtime_state.g_nose_frames_dropped_midframe.store(saved[4], .monotonic);
        runtime_state.g_nose_frames_dropped_shape.store(saved[5], .monotonic);
        runtime_state.g_nose_frames_dropped_capacity.store(saved[6], .monotonic);
        runtime_state.g_nose_pipe_errors.store(saved[7], .monotonic);
        runtime_state.g_correlator_observe_errors.store(saved[8], .monotonic);
        runtime_state.g_anomaly_observe_errors.store(saved[9], .monotonic);
        runtime_state.g_threat_tracker_observe_errors.store(saved[10], .monotonic);
        runtime_state.g_minifilter_dropped.store(saved[11], .monotonic);
        runtime_state.g_minifilter_pipeline_dropped.store(saved[12], .monotonic);
        runtime_state.g_loss_budget.store(saved[13], .monotonic);
    }
    runtime_state.g_queue_drops.store(0, .monotonic);
    runtime_state.g_nose_frames_rejected.store(0, .monotonic);
    runtime_state.g_nose_frames_dropped.store(4, .monotonic);
    runtime_state.g_nose_frames_dropped_framing.store(1, .monotonic);
    runtime_state.g_nose_frames_dropped_midframe.store(1, .monotonic);
    runtime_state.g_nose_frames_dropped_shape.store(1, .monotonic);
    runtime_state.g_nose_frames_dropped_capacity.store(1, .monotonic);
    runtime_state.g_nose_pipe_errors.store(0, .monotonic);
    runtime_state.g_correlator_observe_errors.store(1, .monotonic);
    runtime_state.g_anomaly_observe_errors.store(1, .monotonic);
    runtime_state.g_threat_tracker_observe_errors.store(1, .monotonic);
    runtime_state.g_minifilter_dropped.store(0, .monotonic);
    runtime_state.g_minifilter_pipeline_dropped.store(0, .monotonic);
    runtime_state.g_loss_budget.store(4, .monotonic);
    var rs = RuntimeState{};
    const workers = WorkerReadiness{ .pipeline = true, .sensor = true, .nose = true, .etw = true, .fim = true, .registry = true, .failed = false, .failure_reason = "", .failure_mask = 0 };
    const out = try rs.healthJson(std.testing.allocator, 1234, true, true, true, true, workers);
    defer std.testing.allocator.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"nose_frames_dropped_framing\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"nose_frames_dropped_midframe\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"nose_frames_dropped_shape\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"nose_frames_dropped_capacity\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"detector_degradation\":{\"correlator_errors\":1,\"anomaly_detector_errors\":1,\"threat_tracker_errors\":1}") != null);
    // Total is inside the budget and causes/detector counters are subsets or
    // non-loss, so this must stay RUNNING. No cause is counted twice.
    try std.testing.expect(std.mem.indexOf(u8, out, "\"state\":\"RUNNING\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"degraded\":false") != null);
}

test "healthJson exposes v3 producer identity counters additively" {
    const saved = .{
        runtime_state.g_nose_producer_invalid.load(.acquire),
        runtime_state.g_nose_producer_duplicate.load(.acquire),
        runtime_state.g_nose_producer_regression.load(.acquire),
        runtime_state.g_nose_producer_gap.load(.acquire),
        runtime_state.g_nose_producer_evictions.load(.acquire),
        runtime_state.g_nose_last_capture_sequence.load(.acquire),
        runtime_state.g_nose_last_producer_epoch.load(.acquire),
        runtime_state.g_nose_last_producer_generation.load(.acquire),
        runtime_state.g_nose_last_interface_id.load(.acquire),
    };
    defer {
        runtime_state.g_nose_producer_invalid.store(saved[0], .monotonic);
        runtime_state.g_nose_producer_duplicate.store(saved[1], .monotonic);
        runtime_state.g_nose_producer_regression.store(saved[2], .monotonic);
        runtime_state.g_nose_producer_gap.store(saved[3], .monotonic);
        runtime_state.g_nose_producer_evictions.store(saved[4], .monotonic);
        runtime_state.g_nose_last_capture_sequence.store(saved[5], .monotonic);
        runtime_state.g_nose_last_producer_epoch.store(saved[6], .monotonic);
        runtime_state.g_nose_last_producer_generation.store(saved[7], .monotonic);
        runtime_state.g_nose_last_interface_id.store(saved[8], .monotonic);
    }
    runtime_state.g_nose_producer_invalid.store(1, .monotonic);
    runtime_state.g_nose_producer_duplicate.store(2, .monotonic);
    runtime_state.g_nose_producer_regression.store(3, .monotonic);
    runtime_state.g_nose_producer_gap.store(4, .monotonic);
    runtime_state.g_nose_producer_evictions.store(5, .monotonic);
    runtime_state.g_nose_last_capture_sequence.store(42, .monotonic);
    runtime_state.g_nose_last_producer_epoch.store(1_700_000_000, .monotonic);
    runtime_state.g_nose_last_producer_generation.store(2, .monotonic);
    runtime_state.g_nose_last_interface_id.store(0xCAFE, .monotonic);
    var rs = RuntimeState{};
    const workers = WorkerReadiness{ .pipeline = true, .sensor = true, .nose = true, .etw = true, .fim = true, .registry = true, .failed = false, .failure_reason = "", .failure_mask = 0 };
    const out = try rs.healthJson(std.testing.allocator, 1234, true, true, true, true, workers);
    defer std.testing.allocator.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"nose_producer_invalid\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"nose_producer_duplicate\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"nose_producer_regression\":3") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"nose_producer_gap\":4") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"nose_producer_evictions\":5") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"nose_last_capture_sequence\":42") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"nose_last_producer_epoch\":1700000000") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"nose_last_producer_generation\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"nose_last_interface_id\":51966") != null);
}

test "healthJson accepts loss at or below the owner-approved budget" {
    const saved = .{
        runtime_state.g_queue_drops.load(.acquire),
        runtime_state.g_nose_frames_rejected.load(.acquire),
        runtime_state.g_nose_frames_dropped.load(.acquire),
        runtime_state.g_nose_pipe_errors.load(.acquire),
        runtime_state.g_minifilter_dropped.load(.acquire),
        runtime_state.g_minifilter_pipeline_dropped.load(.acquire),
        runtime_state.g_loss_budget.load(.acquire),
    };
    defer {
        runtime_state.g_queue_drops.store(saved[0], .monotonic);
        runtime_state.g_nose_frames_rejected.store(saved[1], .monotonic);
        runtime_state.g_nose_frames_dropped.store(saved[2], .monotonic);
        runtime_state.g_nose_pipe_errors.store(saved[3], .monotonic);
        runtime_state.g_minifilter_dropped.store(saved[4], .monotonic);
        runtime_state.g_minifilter_pipeline_dropped.store(saved[5], .monotonic);
        runtime_state.g_loss_budget.store(saved[6], .monotonic);
    }
    runtime_state.g_queue_drops.store(1, .monotonic);
    runtime_state.g_nose_frames_rejected.store(0, .monotonic);
    runtime_state.g_nose_frames_dropped.store(0, .monotonic);
    runtime_state.g_nose_pipe_errors.store(0, .monotonic);
    runtime_state.g_minifilter_dropped.store(0, .monotonic);
    runtime_state.g_minifilter_pipeline_dropped.store(0, .monotonic);
    runtime_state.g_loss_budget.store(2, .monotonic);
    var rs = RuntimeState{};
    const workers = WorkerReadiness{ .pipeline = true, .sensor = true, .nose = true, .etw = true, .fim = true, .registry = true, .failed = false, .failure_reason = "", .failure_mask = 0 };
    const out = try rs.healthJson(std.testing.allocator, 1234, true, true, true, true, workers);
    defer std.testing.allocator.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"state\":\"RUNNING\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"degraded\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"loss_budget\":2") != null);
}

test "READY-PROMOTION: three clear samples promote DEGRADED -> RECOVERING -> RUNNING" {
    var rs = RuntimeState{};
    rs.registerSubsystem(.zig, "zig", "5.0.0", "");
    rs.subsystemStarted(.zig, 1);
    rs.system_state = .degraded;
    const clear = RuntimeState.LifecycleFacts{
        .pipeline_ready = true,
        .pipeline_failed = false,
        .bridge_ready = true,
        .fresh_loss_observed = false,
    };
    var t: i64 = 1_000;
    const step = RuntimeState.PROMOTION_MIN_INTERVAL_MS;
    // Two samples are not enough; the third promotes.
    try std.testing.expectEqual(@as(?SystemState, null), rs.reconcileLifecycle(t, clear));
    t += step;
    try std.testing.expectEqual(@as(?SystemState, null), rs.reconcileLifecycle(t, clear));
    t += step;
    try std.testing.expectEqual(@as(?SystemState, SystemState.recovering), rs.reconcileLifecycle(t, clear));
    try std.testing.expectEqual(SystemState.recovering, rs.system_state);
    t += step;
    try std.testing.expectEqual(@as(?SystemState, null), rs.reconcileLifecycle(t, clear));
    t += step;
    try std.testing.expectEqual(@as(?SystemState, null), rs.reconcileLifecycle(t, clear));
    t += step;
    try std.testing.expectEqual(@as(?SystemState, SystemState.running), rs.reconcileLifecycle(t, clear));
    try std.testing.expectEqual(SystemState.running, rs.system_state);
}

test "READY-PROMOTION: a failure inside the hysteresis window resets the streak" {
    var rs = RuntimeState{};
    rs.registerSubsystem(.zig, "zig", "5.0.0", "");
    rs.subsystemStarted(.zig, 1);
    rs.system_state = .degraded;
    const clear = RuntimeState.LifecycleFacts{ .pipeline_ready = true, .bridge_ready = true };
    var t: i64 = 1_000;
    _ = rs.reconcileLifecycle(t, clear);
    t += RuntimeState.PROMOTION_MIN_INTERVAL_MS;
    _ = rs.reconcileLifecycle(t, clear);
    // One bad sample between them, then the streak must start again from zero.
    t += RuntimeState.PROMOTION_MIN_INTERVAL_MS;
    const bad = RuntimeState.LifecycleFacts{ .pipeline_ready = false, .bridge_ready = true };
    try std.testing.expectEqual(@as(?SystemState, null), rs.reconcileLifecycle(t, bad));
    try std.testing.expectEqual(SystemState.degraded, rs.system_state);
    t += RuntimeState.PROMOTION_MIN_INTERVAL_MS;
    try std.testing.expectEqual(@as(?SystemState, null), rs.reconcileLifecycle(t, clear));
    try std.testing.expectEqual(SystemState.degraded, rs.system_state);
}

test "READY-PROMOTION: data loss above budget blocks promotion even with every worker ready" {
    var rs = RuntimeState{};
    rs.registerSubsystem(.zig, "zig", "5.0.0", "");
    rs.subsystemStarted(.zig, 1);
    rs.system_state = .degraded;
    const lossy = RuntimeState.LifecycleFacts{
        .pipeline_ready = true,
        .pipeline_failed = false,
        .bridge_ready = true,
        .fresh_loss_observed = true,
    };
    var t: i64 = 1_000;
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        try std.testing.expectEqual(@as(?SystemState, null), rs.reconcileLifecycle(t, lossy));
        t += RuntimeState.PROMOTION_MIN_INTERVAL_MS;
    }
    try std.testing.expectEqual(SystemState.degraded, rs.system_state);
}

test "READY-PROMOTION: a fast poll cannot accumulate samples" {
    var rs = RuntimeState{};
    rs.registerSubsystem(.zig, "zig", "5.0.0", "");
    rs.subsystemStarted(.zig, 1);
    rs.system_state = .degraded;
    const clear = RuntimeState.LifecycleFacts{ .pipeline_ready = true, .bridge_ready = true };
    var t: i64 = 1_000;
    var i: usize = 0;
    // 20 samples 100 ms apart are 2 s of evidence, not 3 x 5 s.
    while (i < 20) : (i += 1) {
        _ = rs.reconcileLifecycle(t, clear);
        t += 100;
    }
    try std.testing.expectEqual(SystemState.degraded, rs.system_state);
}

test "READY-PROMOTION: losing a required fact demotes RUNNING immediately" {
    var rs = RuntimeState{};
    rs.registerSubsystem(.zig, "zig", "5.0.0", "");
    rs.subsystemStarted(.zig, 1);
    rs.system_state = .running;
    const bad = RuntimeState.LifecycleFacts{ .pipeline_ready = true, .bridge_ready = false };
    try std.testing.expectEqual(@as(?SystemState, SystemState.degraded), rs.reconcileLifecycle(1_000, bad));
    try std.testing.expectEqual(SystemState.degraded, rs.system_state);
}
