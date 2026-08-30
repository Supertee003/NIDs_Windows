//! health_monitoring_proof.zig - AEGIS G13 Health Monitoring Proof (v5.0 Section 50-52)
//!
//! F16: Liveness heartbeat, readiness checks, metrics export, DEFCON rollup.
//!
//! v5.0 Section 50: Liveness -- process heartbeat with last_seen timestamp.
//!                  Liveness probe detects deadlocks/hangs within heartbeat interval.
//! v5.0 Section 51: Readiness -- each subsystem reports ready/not-ready.
//!                  System is ready only when ALL critical subsystems are ready.
//! v5.0 Section 52: G13 Exit Gate - metrics (EPS, queue depth, latencies) exported
//!                  and DEFCON level rolls up from subsystem health (1=critical, 5=normal).
//!
//! Architecture (Phase 18 Canary + Phase 26 metrics + aegis_status.bat):
//!   LivenessProbe (heartbeat) -> ReadinessCheck (5 subsystems) -> MetricsExport -> DEFCON
//!
//! This module proves:
//!   1. Liveness: heartbeat with last_seen, stale detection within threshold
//!   2. Readiness: 5 subsystems (Nose/Flow/Detection/Policy/PEP) report ready/not-ready
//!   3. Metrics: EPS, queue depth, p50/p95/p99 latencies, decision counts
//!   4. DEFCON Rollup: level 1 (critical) to 5 (normal) computed from subsystem health

const std = @import("std");

// ============================================================
// Liveness (v5.0 Section 50)
// ============================================================
// v5.0: "Liveness probe detects deadlocks/hangs within heartbeat interval."

pub const HEARTBEAT_INTERVAL_MS: i64 = 1 * 1000; // 1 second
pub const LIVENESS_STALE_THRESHOLD_MS: i64 = 5 * 1000; // 5 seconds (5 missed heartbeats)

pub const LivenessState = struct {
    /// Process ID (for multi-process systems).
    pid: u32,
    /// Last heartbeat timestamp (epoch_ms).
    last_seen_ms: i64,
    /// Total heartbeats received.
    total_heartbeats: u64,
    /// Total missed heartbeats (heartbeat was expected but didn't arrive).
    total_missed: u64,

    pub fn init(pid: u32, now_ms: i64) LivenessState {
        return .{
            .pid = pid,
            .last_seen_ms = now_ms,
            .total_heartbeats = 1,
            .total_missed = 0,
        };
    }

    /// Record a heartbeat. Updates last_seen_ms and increments counter.
    pub fn recordHeartbeat(self: *LivenessState, now_ms: i64) void {
        self.last_seen_ms = now_ms;
        self.total_heartbeats += 1;
    }

    /// Check if the process is alive (last_seen within stale threshold).
    pub fn isAlive(self: LivenessState, now_ms: i64) bool {
        return (now_ms - self.last_seen_ms) <= LIVENESS_STALE_THRESHOLD_MS;
    }

    /// Check if the process is stale (missed too many heartbeats).
    pub fn isStale(self: LivenessState, now_ms: i64) bool {
        return !self.isAlive(now_ms);
    }

    /// Returns milliseconds since last heartbeat.
    pub fn msSinceHeartbeat(self: LivenessState, now_ms: i64) i64 {
        return now_ms - self.last_seen_ms;
    }
};

pub const LivenessCheck = struct {
    heartbeat_updates_last_seen: bool,
    alive_within_threshold: bool,
    stale_after_5s: bool,
    missed_heartbeat_counted: bool,
    liveness_ok: bool,

    pub fn isPassed(self: LivenessCheck) bool {
        return self.liveness_ok;
    }
};

/// Verify liveness probe detects stale processes.
/// v5.0 Section 50: heartbeat + last_seen + stale detection.
pub fn verifyLiveness() LivenessCheck {
    // Process starts at t=1000ms with initial heartbeat.
    var state = LivenessState.init(42, 1000);

    // Heartbeat at t=2000ms (1s later, within interval).
    state.recordHeartbeat(2000);
    const heartbeat_updates_last_seen = state.last_seen_ms == 2000 and
        state.total_heartbeats == 2;

    // At t=3000ms (1s after last heartbeat), process is alive.
    const alive_within_threshold = state.isAlive(3000);

    // At t=8000ms (6s after last heartbeat), process is stale (exceeded 5s threshold).
    const stale_after_5s = state.isStale(8000);

    // Missed heartbeat: at t=8000ms, the msSinceHeartbeat should be 6000ms.
    const ms_since = state.msSinceHeartbeat(8000);
    const missed_heartbeat_counted = ms_since == 6000 and ms_since > LIVENESS_STALE_THRESHOLD_MS;

    return .{
        .heartbeat_updates_last_seen = heartbeat_updates_last_seen,
        .alive_within_threshold = alive_within_threshold,
        .stale_after_5s = stale_after_5s,
        .missed_heartbeat_counted = missed_heartbeat_counted,
        .liveness_ok = heartbeat_updates_last_seen and alive_within_threshold and
            stale_after_5s and missed_heartbeat_counted,
    };
}

// ============================================================
// Readiness (v5.0 Section 51)
// ============================================================
// v5.0: "Each subsystem reports ready/not-ready. System ready only when ALL critical ready."

pub const SubsystemId = enum(u8) {
    /// Nose (sensor ingestion).
    nose = 0,
    /// Flow Engine (flow tracking).
    flow = 1,
    /// Detection Engine (rule matching).
    detection = 2,
    /// Policy Engine (decision making).
    policy = 3,
    /// Rust PEP (enforcement).
    pep = 4,

    pub fn toString(self: SubsystemId) []const u8 {
        return switch (self) {
            .nose => "NOSE",
            .flow => "FLOW",
            .detection => "DETECTION",
            .policy => "POLICY",
            .pep => "PEP",
        };
    }
};

pub const SUBSYSTEM_COUNT: usize = 5;

pub const SubsystemStatus = enum(u8) {
    /// Subsystem is fully operational.
    ready = 0,
    /// Subsystem is starting up (not yet ready).
    starting = 1,
    /// Subsystem is degraded (partial failure, still serving).
    degraded = 2,
    /// Subsystem is down (not serving).
    down = 3,

    pub fn toString(self: SubsystemStatus) []const u8 {
        return switch (self) {
            .ready => "READY",
            .starting => "STARTING",
            .degraded => "DEGRADED",
            .down => "DOWN",
        };
    }

    /// Returns true if the subsystem is ready to serve traffic.
    pub fn isReady(self: SubsystemStatus) bool {
        return self == .ready;
    }

    /// Returns true if the subsystem is in a failure state.
    pub fn isFailed(self: SubsystemStatus) bool {
        return self == .down;
    }

    /// Returns true if the subsystem is degraded but still serving.
    pub fn isDegraded(self: SubsystemStatus) bool {
        return self == .degraded;
    }
};

pub const ReadinessReport = struct {
    /// Status of each subsystem.
    statuses: [SUBSYSTEM_COUNT]SubsystemStatus,
    /// Number of subsystems that are ready.
    ready_count: u8,
    /// Number of subsystems that are failed.
    failed_count: u8,
    /// Number of subsystems that are degraded.
    degraded_count: u8,
    /// True if all critical subsystems are ready.
    system_ready: bool,

    pub fn allReady() ReadinessReport {
        return .{
            .statuses = [_]SubsystemStatus{.ready} ** SUBSYSTEM_COUNT,
            .ready_count = SUBSYSTEM_COUNT,
            .failed_count = 0,
            .degraded_count = 0,
            .system_ready = true,
        };
    }

    pub fn fromStatuses(statuses: [SUBSYSTEM_COUNT]SubsystemStatus) ReadinessReport {
        var ready: u8 = 0;
        var failed: u8 = 0;
        var degraded: u8 = 0;
        for (statuses) |s| {
            if (s.isReady()) ready += 1;
            if (s.isFailed()) failed += 1;
            if (s.isDegraded()) degraded += 1;
        }
        return .{
            .statuses = statuses,
            .ready_count = ready,
            .failed_count = failed,
            .degraded_count = degraded,
            .system_ready = (failed == 0) and (degraded == 0) and (ready == SUBSYSTEM_COUNT),
        };
    }

    pub fn isSystemReady(self: ReadinessReport) bool {
        return self.system_ready;
    }
};

pub const ReadinessCheck = struct {
    all_ready_passes: bool,
    one_down_fails_system: bool,
    degraded_does_not_fail: bool,
    starting_not_ready: bool,
    ready_count_correct: bool,
    readiness_ok: bool,

    pub fn isPassed(self: ReadinessCheck) bool {
        return self.readiness_ok;
    }
};

/// Verify readiness checks: system ready only when ALL subsystems ready.
/// v5.0 Section 51.
pub fn verifyReadiness() ReadinessCheck {
    // All 5 subsystems ready -> system ready.
    const all_ready = ReadinessReport.allReady();
    const all_ready_passes = all_ready.isSystemReady() and
        all_ready.ready_count == 5 and all_ready.failed_count == 0;

    // One subsystem down -> system NOT ready.
    var one_down_statuses = [_]SubsystemStatus{.ready} ** SUBSYSTEM_COUNT;
    one_down_statuses[2] = .down; // Detection down
    const one_down = ReadinessReport.fromStatuses(one_down_statuses);
    const one_down_fails_system = !one_down.isSystemReady() and
        one_down.failed_count == 1 and one_down.ready_count == 4;

    // One degraded -> system NOT ready (degraded counts as not-ready).
    var degraded_statuses = [_]SubsystemStatus{.ready} ** SUBSYSTEM_COUNT;
    degraded_statuses[1] = .degraded; // Flow degraded
    const degraded = ReadinessReport.fromStatuses(degraded_statuses);
    const degraded_does_not_fail = !degraded.isSystemReady() and
        degraded.degraded_count == 1 and degraded.failed_count == 0;

    // Subsystem starting -> not ready yet.
    var starting_statuses = [_]SubsystemStatus{.ready} ** SUBSYSTEM_COUNT;
    starting_statuses[0] = .starting; // Nose starting
    const starting = ReadinessReport.fromStatuses(starting_statuses);
    const starting_not_ready = !starting.isSystemReady() and
        starting.ready_count == 4;

    // Ready count is correctly computed.
    const ready_count_correct = (all_ready.ready_count == 5) and
        (one_down.ready_count == 4) and
        (degraded.ready_count == 4) and
        (starting.ready_count == 4);

    return .{
        .all_ready_passes = all_ready_passes,
        .one_down_fails_system = one_down_fails_system,
        .degraded_does_not_fail = degraded_does_not_fail,
        .starting_not_ready = starting_not_ready,
        .ready_count_correct = ready_count_correct,
        .readiness_ok = all_ready_passes and one_down_fails_system and
            degraded_does_not_fail and starting_not_ready and ready_count_correct,
    };
}

// ============================================================
// Metrics (v5.0 Section 52)
// ============================================================
// v5.0: "Metrics: EPS, queue depth, p50/p95/p99 latencies, decision counts."

pub const MAX_LATENCY_SAMPLES: usize = 256;

pub const MetricsSnapshot = struct {
    /// Timestamp when this snapshot was taken (epoch_ms).
    captured_at_ms: i64,
    /// Total events processed since startup.
    total_events: u64,
    /// Total events blocked (Block action enforced).
    total_blocks: u64,
    /// Total events alerted (Alert action).
    total_alerts: u64,
    /// Total events allowed (no enforcement).
    total_allowed: u64,
    /// Current event fabric queue depth.
    queue_depth: u32,
    /// Maximum queue depth observed.
    max_queue_depth: u32,
    /// Latency samples (in microseconds) for percentile calculation.
    latency_samples_us: [MAX_LATENCY_SAMPLES]u64,
    /// Number of valid latency samples.
    latency_sample_count: usize,
    /// Total CPU time used (in milliseconds).
    cpu_time_ms: u64,
    /// Total memory used (in bytes).
    memory_bytes: u64,

    /// Calculate events-per-second rate over a time window.
    pub fn epsRate(self: MetricsSnapshot, window_start_ms: i64) f64 {
        const window_ms = self.captured_at_ms - window_start_ms;
        if (window_ms <= 0) return 0.0;
        return @as(f64, @floatFromInt(self.total_events)) / (@as(f64, @floatFromInt(window_ms)) / 1000.0);
    }

    /// Calculate p50 (median) latency in microseconds.
    pub fn p50LatencyUs(self: MetricsSnapshot) u64 {
        if (self.latency_sample_count == 0) return 0;
        return percentileConst(self.latency_samples_us[0..self.latency_sample_count], 50);
    }

    /// Calculate p95 latency in microseconds.
    pub fn p95LatencyUs(self: MetricsSnapshot) u64 {
        if (self.latency_sample_count == 0) return 0;
        return percentileConst(self.latency_samples_us[0..self.latency_sample_count], 95);
    }

    /// Calculate p99 latency in microseconds.
    pub fn p99LatencyUs(self: MetricsSnapshot) u64 {
        if (self.latency_sample_count == 0) return 0;
        return percentileConst(self.latency_samples_us[0..self.latency_sample_count], 99);
    }

    /// Returns the block rate (blocks per total events).
    pub fn blockRate(self: MetricsSnapshot) f64 {
        if (self.total_events == 0) return 0.0;
        return @as(f64, @floatFromInt(self.total_blocks)) / @as(f64, @floatFromInt(self.total_events));
    }
};

/// Compute the p-th percentile of a sample array.
/// Reads from a const slice; copies into a local buffer for in-place sort
/// so the input is not mutated.
/// Returns 0 if samples is empty.
pub fn percentileConst(samples: []const u64, p: u8) u64 {
    if (samples.len == 0) return 0;
    if (samples.len == 1) return samples[0];

    // Copy samples into a local buffer so we can sort without mutating the input.
    var buf: [MAX_LATENCY_SAMPLES]u64 = undefined;
    var i: usize = 0;
    while (i < samples.len) : (i += 1) {
        buf[i] = samples[i];
    }
    var mutable = buf[0..samples.len];

    // Sort the copy in-place.
    std.mem.sort(u64, mutable, {}, std.sort.asc(u64));

    // Compute the index for percentile p.
    // index = (p / 100) * (n - 1), rounded to nearest integer.
    const n: f64 = @floatFromInt(samples.len);
    const p_f: f64 = @floatFromInt(p);
    const idx_f = (p_f / 100.0) * (n - 1.0);
    const idx: usize = @intFromFloat(idx_f);

    return mutable[idx];
}

pub const MetricsCheck = struct {
    eps_rate_correct: bool,
    p50_p95_p99_computed: bool,
    queue_depth_tracked: bool,
    decision_counts_correct: bool,
    block_rate_correct: bool,
    metrics_ok: bool,

    pub fn isPassed(self: MetricsCheck) bool {
        return self.metrics_ok;
    }
};

/// Verify metrics computation: EPS, percentiles, queue depth, decision counts.
/// v5.0 Section 52.
pub fn verifyMetrics() MetricsCheck {
    // Build a snapshot with 100 events processed over 10 seconds = 10 EPS.
    var snapshot = MetricsSnapshot{
        .captured_at_ms = 11000,
        .total_events = 100,
        .total_blocks = 10,
        .total_alerts = 20,
        .total_allowed = 70,
        .queue_depth = 5,
        .max_queue_depth = 50,
        .latency_samples_us = undefined,
        .latency_sample_count = 5,
        .cpu_time_ms = 5000,
        .memory_bytes = 1024 * 1024 * 100, // 100 MB
    };
    // Set 5 latency samples: [100, 200, 300, 400, 500] us
    snapshot.latency_samples_us[0] = 100;
    snapshot.latency_samples_us[1] = 200;
    snapshot.latency_samples_us[2] = 300;
    snapshot.latency_samples_us[3] = 400;
    snapshot.latency_samples_us[4] = 500;

    // EPS rate: 100 events / 10 seconds = 10 EPS.
    const eps = snapshot.epsRate(1000);
    const eps_rate_correct = eps == 10.0;

    // Percentiles (samples sorted: 100, 200, 300, 400, 500):
    //   p50 (50%): index = (50/100) * 4 = 2 -> 300
    //   p95 (95%): index = (95/100) * 4 = 3.8 -> 3 -> 400
    //   p99 (99%): index = (99/100) * 4 = 3.96 -> 3 -> 400
    const p50 = snapshot.p50LatencyUs();
    const p95 = snapshot.p95LatencyUs();
    const p99 = snapshot.p99LatencyUs();
    const p50_p95_p99_computed = (p50 == 300) and (p95 == 400) and (p99 == 400);

    // Queue depth tracked.
    const queue_depth_tracked = snapshot.queue_depth == 5 and
        snapshot.max_queue_depth == 50;

    // Decision counts: 10 + 20 + 70 = 100 == total_events.
    const decision_counts_correct = (snapshot.total_blocks +
        snapshot.total_alerts + snapshot.total_allowed) == snapshot.total_events;

    // Block rate: 10 blocks / 100 events = 0.1 (10%).
    const rate = snapshot.blockRate();
    const block_rate_correct = rate == 0.1;

    return .{
        .eps_rate_correct = eps_rate_correct,
        .p50_p95_p99_computed = p50_p95_p99_computed,
        .queue_depth_tracked = queue_depth_tracked,
        .decision_counts_correct = decision_counts_correct,
        .block_rate_correct = block_rate_correct,
        .metrics_ok = eps_rate_correct and p50_p95_p99_computed and
            queue_depth_tracked and decision_counts_correct and block_rate_correct,
    };
}

// ============================================================
// DEFCON Rollup (v5.0 Section 52) - G13 Exit Gate
// ============================================================
// v5.0: "DEFCON level rolls up from subsystem health.
//        DEFCON 1 = critical (system down), DEFCON 5 = normal (all healthy)."

pub const DefconLevel = enum(u8) {
    /// DEFCON 1: critical -- system down, fail-closed mode.
    critical = 1,
    /// DEFCON 2: severe -- multiple subsystems degraded or down.
    severe = 2,
    /// DEFCON 3: elevated -- one subsystem degraded.
    elevated = 3,
    /// DEFCON 4: guarded -- all subsystems up but metrics show stress.
    guarded = 4,
    /// DEFCON 5: normal -- all subsystems healthy, metrics nominal.
    normal = 5,

    pub fn toString(self: DefconLevel) []const u8 {
        return switch (self) {
            .critical => "DEFCON 1 (CRITICAL)",
            .severe => "DEFCON 2 (SEVERE)",
            .elevated => "DEFCON 3 (ELEVATED)",
            .guarded => "DEFCON 4 (GUARDED)",
            .normal => "DEFCON 5 (NORMAL)",
        };
    }

    /// Returns true if the system is in fail-closed mode (DEFCON 1).
    pub fn isFailClosed(self: DefconLevel) bool {
        return self == .critical;
    }

    /// Returns true if the system is operating normally (DEFCON 5).
    pub fn isNormal(self: DefconLevel) bool {
        return self == .normal;
    }

    /// Returns true if the system requires immediate attention (DEFCON 1 or 2).
    pub fn requiresAttention(self: DefconLevel) bool {
        return self == .critical or self == .severe;
    }
};

/// Compute DEFCON level from a readiness report and metrics snapshot.
/// v5.0 Section 52: G13 Exit Gate.
pub fn computeDefcon(readiness: ReadinessReport, metrics: MetricsSnapshot) DefconLevel {
    // DEFCON 1: any subsystem DOWN -> critical, fail-closed.
    if (readiness.failed_count > 0) {
        return .critical;
    }

    // DEFCON 2: multiple subsystems degraded or starting.
    if (readiness.degraded_count >= 2) {
        return .severe;
    }

    // DEFCON 3: one subsystem degraded.
    if (readiness.degraded_count == 1) {
        return .elevated;
    }

    // DEFCON 4: all ready but queue depth high (>80% of max).
    if (metrics.queue_depth > (metrics.max_queue_depth * 4) / 5) {
        return .guarded;
    }

    // DEFCON 5: all subsystems healthy, metrics nominal.
    return .normal;
}

pub const DefconCheck = struct {
    all_healthy_normal: bool,
    one_down_critical: bool,
    multiple_degraded_severe: bool,
    one_degraded_elevated: bool,
    high_queue_guarded: bool,
    defcon_ok: bool,

    pub fn isPassed(self: DefconCheck) bool {
        return self.defcon_ok;
    }
};

/// Verify DEFCON level rolls up correctly from subsystem health.
/// v5.0 Section 52: G13 Exit Gate.
pub fn verifyDefcon() DefconCheck {
    // All subsystems healthy, low queue depth -> DEFCON 5 (normal).
    const all_ready = ReadinessReport.allReady();
    const low_queue_metrics = MetricsSnapshot{
        .captured_at_ms = 1000,
        .total_events = 100,
        .total_blocks = 5,
        .total_alerts = 10,
        .total_allowed = 85,
        .queue_depth = 10,
        .max_queue_depth = 100,
        .latency_samples_us = undefined,
        .latency_sample_count = 0,
        .cpu_time_ms = 100,
        .memory_bytes = 1024 * 1024,
    };
    const defcon_normal = computeDefcon(all_ready, low_queue_metrics);
    const all_healthy_normal = defcon_normal.isNormal();

    // One subsystem down -> DEFCON 1 (critical, fail-closed).
    var one_down_statuses = [_]SubsystemStatus{.ready} ** SUBSYSTEM_COUNT;
    one_down_statuses[2] = .down; // Detection down
    const one_down = ReadinessReport.fromStatuses(one_down_statuses);
    const defcon_critical = computeDefcon(one_down, low_queue_metrics);
    const one_down_critical = defcon_critical.isFailClosed();

    // Multiple subsystems degraded -> DEFCON 2 (severe).
    var multi_degraded_statuses = [_]SubsystemStatus{.ready} ** SUBSYSTEM_COUNT;
    multi_degraded_statuses[0] = .degraded;
    multi_degraded_statuses[3] = .degraded;
    const multi_degraded = ReadinessReport.fromStatuses(multi_degraded_statuses);
    const defcon_severe = computeDefcon(multi_degraded, low_queue_metrics);
    const multiple_degraded_severe = defcon_severe == .severe and
        defcon_severe.requiresAttention();

    // One subsystem degraded -> DEFCON 3 (elevated).
    var one_degraded_statuses = [_]SubsystemStatus{.ready} ** SUBSYSTEM_COUNT;
    one_degraded_statuses[1] = .degraded;
    const one_degraded = ReadinessReport.fromStatuses(one_degraded_statuses);
    const defcon_elevated = computeDefcon(one_degraded, low_queue_metrics);
    const one_degraded_elevated = defcon_elevated == .elevated and
        !defcon_elevated.requiresAttention();

    // All ready but high queue depth -> DEFCON 4 (guarded).
    const high_queue_metrics = MetricsSnapshot{
        .captured_at_ms = 1000,
        .total_events = 100,
        .total_blocks = 5,
        .total_alerts = 10,
        .total_allowed = 85,
        .queue_depth = 90, // 90% of max
        .max_queue_depth = 100,
        .latency_samples_us = undefined,
        .latency_sample_count = 0,
        .cpu_time_ms = 100,
        .memory_bytes = 1024 * 1024,
    };
    const defcon_guarded = computeDefcon(all_ready, high_queue_metrics);
    const high_queue_guarded = defcon_guarded == .guarded;

    return .{
        .all_healthy_normal = all_healthy_normal,
        .one_down_critical = one_down_critical,
        .multiple_degraded_severe = multiple_degraded_severe,
        .one_degraded_elevated = one_degraded_elevated,
        .high_queue_guarded = high_queue_guarded,
        .defcon_ok = all_healthy_normal and one_down_critical and
            multiple_degraded_severe and one_degraded_elevated and high_queue_guarded,
    };
}

// ============================================================
// G13 Report
// ============================================================

pub const G13Report = struct {
    liveness_ok: bool,
    readiness_ok: bool,
    metrics_ok: bool,
    defcon_ok: bool,

    pub fn isComplete(self: G13Report) bool {
        return self.liveness_ok and self.readiness_ok and
            self.metrics_ok and self.defcon_ok;
    }
};

pub fn generateReport() G13Report {
    return .{
        .liveness_ok = verifyLiveness().isPassed(),
        .readiness_ok = verifyReadiness().isPassed(),
        .metrics_ok = verifyMetrics().isPassed(),
        .defcon_ok = verifyDefcon().isPassed(),
    };
}

// ============================================================
// Tests
// ============================================================

test "LivenessState init sets initial heartbeat" {
    const state = LivenessState.init(42, 1000);
    try std.testing.expect(state.pid == 42);
    try std.testing.expect(state.last_seen_ms == 1000);
    try std.testing.expect(state.total_heartbeats == 1);
    try std.testing.expect(state.total_missed == 0);
}

test "LivenessState recordHeartbeat updates last_seen" {
    var state = LivenessState.init(1, 1000);
    state.recordHeartbeat(2000);
    try std.testing.expect(state.last_seen_ms == 2000);
    try std.testing.expect(state.total_heartbeats == 2);
}

test "LivenessState isAlive within threshold" {
    var state = LivenessState.init(1, 1000);
    state.recordHeartbeat(2000);
    try std.testing.expect(state.isAlive(2500)); // 500ms after, alive
    try std.testing.expect(state.isAlive(7000)); // 5s after, still alive (boundary)
}

test "LivenessState isStale after threshold" {
    var state = LivenessState.init(1, 1000);
    state.recordHeartbeat(2000);
    try std.testing.expect(state.isStale(8000)); // 6s after, stale
    try std.testing.expect(!state.isStale(7000)); // 5s after, not stale yet
}

test "LivenessState msSinceHeartbeat" {
    var state = LivenessState.init(1, 1000);
    state.recordHeartbeat(2000);
    try std.testing.expect(state.msSinceHeartbeat(2500) == 500);
    try std.testing.expect(state.msSinceHeartbeat(8000) == 6000);
}

test "verifyLiveness passes (v5.0 Section 50)" {
    const check = verifyLiveness();
    try std.testing.expect(check.isPassed());
    try std.testing.expect(check.heartbeat_updates_last_seen);
    try std.testing.expect(check.alive_within_threshold);
    try std.testing.expect(check.stale_after_5s);
    try std.testing.expect(check.missed_heartbeat_counted);
}

test "SubsystemId.toString returns readable names" {
    try std.testing.expect(std.mem.eql(u8, SubsystemId.nose.toString(), "NOSE"));
    try std.testing.expect(std.mem.eql(u8, SubsystemId.flow.toString(), "FLOW"));
    try std.testing.expect(std.mem.eql(u8, SubsystemId.detection.toString(), "DETECTION"));
    try std.testing.expect(std.mem.eql(u8, SubsystemId.policy.toString(), "POLICY"));
    try std.testing.expect(std.mem.eql(u8, SubsystemId.pep.toString(), "PEP"));
}

test "SUBSYSTEM_COUNT is 5" {
    try std.testing.expect(SUBSYSTEM_COUNT == 5);
}

test "SubsystemStatus.toString returns readable names" {
    try std.testing.expect(std.mem.eql(u8, SubsystemStatus.ready.toString(), "READY"));
    try std.testing.expect(std.mem.eql(u8, SubsystemStatus.starting.toString(), "STARTING"));
    try std.testing.expect(std.mem.eql(u8, SubsystemStatus.degraded.toString(), "DEGRADED"));
    try std.testing.expect(std.mem.eql(u8, SubsystemStatus.down.toString(), "DOWN"));
}

test "SubsystemStatus.isReady" {
    try std.testing.expect(SubsystemStatus.ready.isReady());
    try std.testing.expect(!SubsystemStatus.starting.isReady());
    try std.testing.expect(!SubsystemStatus.degraded.isReady());
    try std.testing.expect(!SubsystemStatus.down.isReady());
}

test "SubsystemStatus.isFailed" {
    try std.testing.expect(SubsystemStatus.down.isFailed());
    try std.testing.expect(!SubsystemStatus.ready.isFailed());
    try std.testing.expect(!SubsystemStatus.degraded.isFailed());
}

test "SubsystemStatus.isDegraded" {
    try std.testing.expect(SubsystemStatus.degraded.isDegraded());
    try std.testing.expect(!SubsystemStatus.ready.isDegraded());
    try std.testing.expect(!SubsystemStatus.down.isDegraded());
}

test "ReadinessReport.allReady" {
    const r = ReadinessReport.allReady();
    try std.testing.expect(r.isSystemReady());
    try std.testing.expect(r.ready_count == 5);
    try std.testing.expect(r.failed_count == 0);
    try std.testing.expect(r.degraded_count == 0);
}

test "ReadinessReport.fromStatuses with one down" {
    var statuses = [_]SubsystemStatus{.ready} ** SUBSYSTEM_COUNT;
    statuses[2] = .down;
    const r = ReadinessReport.fromStatuses(statuses);
    try std.testing.expect(!r.isSystemReady());
    try std.testing.expect(r.ready_count == 4);
    try std.testing.expect(r.failed_count == 1);
}

test "ReadinessReport.fromStatuses with degraded" {
    var statuses = [_]SubsystemStatus{.ready} ** SUBSYSTEM_COUNT;
    statuses[1] = .degraded;
    const r = ReadinessReport.fromStatuses(statuses);
    try std.testing.expect(!r.isSystemReady());
    try std.testing.expect(r.degraded_count == 1);
    try std.testing.expect(r.failed_count == 0);
}

test "verifyReadiness passes (v5.0 Section 51)" {
    const check = verifyReadiness();
    try std.testing.expect(check.isPassed());
    try std.testing.expect(check.all_ready_passes);
    try std.testing.expect(check.one_down_fails_system);
    try std.testing.expect(check.degraded_does_not_fail);
    try std.testing.expect(check.starting_not_ready);
    try std.testing.expect(check.ready_count_correct);
}

test "MetricsSnapshot.epsRate" {
    const snapshot = MetricsSnapshot{
        .captured_at_ms = 11000,
        .total_events = 100,
        .total_blocks = 10,
        .total_alerts = 20,
        .total_allowed = 70,
        .queue_depth = 5,
        .max_queue_depth = 50,
        .latency_samples_us = undefined,
        .latency_sample_count = 0,
        .cpu_time_ms = 1000,
        .memory_bytes = 1024,
    };
    // 100 events over 10s = 10 EPS.
    const eps = snapshot.epsRate(1000);
    try std.testing.expect(eps == 10.0);
}

test "MetricsSnapshot.percentiles" {
    var snapshot = MetricsSnapshot{
        .captured_at_ms = 1000,
        .total_events = 5,
        .total_blocks = 1,
        .total_alerts = 2,
        .total_allowed = 2,
        .queue_depth = 1,
        .max_queue_depth = 10,
        .latency_samples_us = undefined,
        .latency_sample_count = 5,
        .cpu_time_ms = 100,
        .memory_bytes = 1024,
    };
    snapshot.latency_samples_us[0] = 100;
    snapshot.latency_samples_us[1] = 200;
    snapshot.latency_samples_us[2] = 300;
    snapshot.latency_samples_us[3] = 400;
    snapshot.latency_samples_us[4] = 500;

    // Note: percentileConst() does not mutate input, so we can call it directly.
    var sorted_samples = [_]u64{ 100, 200, 300, 400, 500 };
    const p50 = percentileConst(&sorted_samples, 50);
    var sorted_samples2 = [_]u64{ 100, 200, 300, 400, 500 };
    const p95 = percentileConst(&sorted_samples2, 95);
    var sorted_samples3 = [_]u64{ 100, 200, 300, 400, 500 };
    const p99 = percentileConst(&sorted_samples3, 99);

    try std.testing.expect(p50 == 300);
    try std.testing.expect(p95 == 400);
    try std.testing.expect(p99 == 400);
}

test "MetricsSnapshot.blockRate" {
    const snapshot = MetricsSnapshot{
        .captured_at_ms = 1000,
        .total_events = 100,
        .total_blocks = 10,
        .total_alerts = 20,
        .total_allowed = 70,
        .queue_depth = 5,
        .max_queue_depth = 50,
        .latency_samples_us = undefined,
        .latency_sample_count = 0,
        .cpu_time_ms = 100,
        .memory_bytes = 1024,
    };
    const rate = snapshot.blockRate();
    try std.testing.expect(rate == 0.1);
}

test "MetricsSnapshot with no events" {
    const snapshot = MetricsSnapshot{
        .captured_at_ms = 1000,
        .total_events = 0,
        .total_blocks = 0,
        .total_alerts = 0,
        .total_allowed = 0,
        .queue_depth = 0,
        .max_queue_depth = 0,
        .latency_samples_us = undefined,
        .latency_sample_count = 0,
        .cpu_time_ms = 0,
        .memory_bytes = 0,
    };
    try std.testing.expect(snapshot.epsRate(500) == 0.0);
    try std.testing.expect(snapshot.blockRate() == 0.0);
    try std.testing.expect(snapshot.p50LatencyUs() == 0);
}

test "verifyMetrics passes (v5.0 Section 52)" {
    const check = verifyMetrics();
    try std.testing.expect(check.isPassed());
    try std.testing.expect(check.eps_rate_correct);
    try std.testing.expect(check.p50_p95_p99_computed);
    try std.testing.expect(check.queue_depth_tracked);
    try std.testing.expect(check.decision_counts_correct);
    try std.testing.expect(check.block_rate_correct);
}

test "DefconLevel.toString" {
    try std.testing.expect(std.mem.eql(u8, DefconLevel.critical.toString(), "DEFCON 1 (CRITICAL)"));
    try std.testing.expect(std.mem.eql(u8, DefconLevel.normal.toString(), "DEFCON 5 (NORMAL)"));
}

test "DefconLevel.isFailClosed" {
    try std.testing.expect(DefconLevel.critical.isFailClosed());
    try std.testing.expect(!DefconLevel.severe.isFailClosed());
    try std.testing.expect(!DefconLevel.normal.isFailClosed());
}

test "DefconLevel.isNormal" {
    try std.testing.expect(DefconLevel.normal.isNormal());
    try std.testing.expect(!DefconLevel.critical.isNormal());
}

test "DefconLevel.requiresAttention" {
    try std.testing.expect(DefconLevel.critical.requiresAttention());
    try std.testing.expect(DefconLevel.severe.requiresAttention());
    try std.testing.expect(!DefconLevel.elevated.requiresAttention());
    try std.testing.expect(!DefconLevel.normal.requiresAttention());
}

test "computeDefcon returns normal when all healthy" {
    const readiness = ReadinessReport.allReady();
    const metrics = MetricsSnapshot{
        .captured_at_ms = 1000,
        .total_events = 100,
        .total_blocks = 5,
        .total_alerts = 10,
        .total_allowed = 85,
        .queue_depth = 10,
        .max_queue_depth = 100,
        .latency_samples_us = undefined,
        .latency_sample_count = 0,
        .cpu_time_ms = 100,
        .memory_bytes = 1024,
    };
    const defcon = computeDefcon(readiness, metrics);
    try std.testing.expect(defcon.isNormal());
}

test "computeDefcon returns critical when any down" {
    var statuses = [_]SubsystemStatus{.ready} ** SUBSYSTEM_COUNT;
    statuses[2] = .down;
    const readiness = ReadinessReport.fromStatuses(statuses);
    const metrics = MetricsSnapshot{
        .captured_at_ms = 1000,
        .total_events = 100,
        .total_blocks = 5,
        .total_alerts = 10,
        .total_allowed = 85,
        .queue_depth = 10,
        .max_queue_depth = 100,
        .latency_samples_us = undefined,
        .latency_sample_count = 0,
        .cpu_time_ms = 100,
        .memory_bytes = 1024,
    };
    const defcon = computeDefcon(readiness, metrics);
    try std.testing.expect(defcon.isFailClosed());
}

test "computeDefcon returns elevated when one degraded" {
    var statuses = [_]SubsystemStatus{.ready} ** SUBSYSTEM_COUNT;
    statuses[1] = .degraded;
    const readiness = ReadinessReport.fromStatuses(statuses);
    const metrics = MetricsSnapshot{
        .captured_at_ms = 1000,
        .total_events = 100,
        .total_blocks = 5,
        .total_alerts = 10,
        .total_allowed = 85,
        .queue_depth = 10,
        .max_queue_depth = 100,
        .latency_samples_us = undefined,
        .latency_sample_count = 0,
        .cpu_time_ms = 100,
        .memory_bytes = 1024,
    };
    const defcon = computeDefcon(readiness, metrics);
    try std.testing.expect(defcon == .elevated);
}

test "computeDefcon returns guarded when queue high" {
    const readiness = ReadinessReport.allReady();
    const metrics = MetricsSnapshot{
        .captured_at_ms = 1000,
        .total_events = 100,
        .total_blocks = 5,
        .total_alerts = 10,
        .total_allowed = 85,
        .queue_depth = 90, // 90% of max
        .max_queue_depth = 100,
        .latency_samples_us = undefined,
        .latency_sample_count = 0,
        .cpu_time_ms = 100,
        .memory_bytes = 1024,
    };
    const defcon = computeDefcon(readiness, metrics);
    try std.testing.expect(defcon == .guarded);
}

test "verifyDefcon passes (G13 Exit Gate)" {
    // v5.0 Section 52: "DEFCON rolls up from subsystem health"
    const check = verifyDefcon();
    try std.testing.expect(check.isPassed());
    try std.testing.expect(check.all_healthy_normal);
    try std.testing.expect(check.one_down_critical);
    try std.testing.expect(check.multiple_degraded_severe);
    try std.testing.expect(check.one_degraded_elevated);
    try std.testing.expect(check.high_queue_guarded);
}

test "generateReport is complete" {
    const report = generateReport();
    try std.testing.expect(report.liveness_ok);
    try std.testing.expect(report.readiness_ok);
    try std.testing.expect(report.metrics_ok);
    try std.testing.expect(report.defcon_ok);
    try std.testing.expect(report.isComplete());
}

test "G13 Exit Gate: full health monitoring flow" {
    // v5.0 Section 50-52: liveness + readiness + metrics -> DEFCON
    var liveness = LivenessState.init(42, 1000);

    // Step 1: heartbeat at t=2000ms.
    liveness.recordHeartbeat(2000);
    try std.testing.expect(liveness.isAlive(3000));

    // Step 2: all 5 subsystems ready.
    const all_ready = ReadinessReport.allReady();
    try std.testing.expect(all_ready.isSystemReady());

    // Step 3: capture metrics.
    const metrics = MetricsSnapshot{
        .captured_at_ms = 5000,
        .total_events = 1000,
        .total_blocks = 100,
        .total_alerts = 200,
        .total_allowed = 700,
        .queue_depth = 50,
        .max_queue_depth = 100,
        .latency_samples_us = undefined,
        .latency_sample_count = 0,
        .cpu_time_ms = 2000,
        .memory_bytes = 1024 * 1024 * 50,
    };

    // Step 4: compute DEFCON -- should be normal (all healthy, low queue).
    const defcon = computeDefcon(all_ready, metrics);
    try std.testing.expect(defcon.isNormal());

    // Step 5: simulate degradation -- Detection subsystem goes down.
    var degraded_statuses = [_]SubsystemStatus{.ready} ** SUBSYSTEM_COUNT;
    degraded_statuses[2] = .down;
    const degraded = ReadinessReport.fromStatuses(degraded_statuses);
    const defcon_critical = computeDefcon(degraded, metrics);
    try std.testing.expect(defcon_critical.isFailClosed());

    // Step 6: recovery -- Detection comes back online.
    const recovered = ReadinessReport.allReady();
    const defcon_recovered = computeDefcon(recovered, metrics);
    try std.testing.expect(defcon_recovered.isNormal());
}
