/// RuntimeHealth - Centralized runtime health object (G13 Section 50-53)
///
/// This object is the single source of truth for the AEGIS NIDS runtime health state.
/// All frontend interfaces (CLI, TUI, WEB) MUST delegate to this object for health state.
/// It replaces scattered health checks and log-based truth with structured, queryable state.
///
/// State transitions: STOPPED -> STARTING -> READY -> RUNNING -> DEGRADED -> RECOVERING -> STOPPED
/// Health determination: sec_monitor.dll absence -> DEGRADED/FAILED, not healthy/OK
///
/// v5.0 Sections 50-53: Liveness (50), Readiness (51), Metrics (52), DEFCON (52-53)
pub const RuntimeHealth = struct {
    /// Overall system state progression.
    state: State,

    /// Process identifier for multi-process coordination.
    pid: u32,

    /// Version string of the running runtime.
    version: [4]u8,

    /// Uptime in milliseconds since process start.
    uptime_ms: u64,

    /// Timestamp of last event processed (epoch_ms).
    last_event_ms: u64,

    /// Overall degraded flag.
    /// True if one or more subsystems are degraded or down.
    degraded: bool,

    /// Tier-3 (sec_monitor) enforcement authority state.
    /// True if Tier-3 is loaded and operational; False if absent -> system is degraded.
    tier3: bool,

    /// Per-subsystem health status.
    /// Order: capture, etw, fim, wfp, pep, control
    subsystems: [6]SubsystemStatus,

    /// Operational counters since process start.
    counters: Counters,
};

pub const State = enum(u8) {
    /// System is stopped / not running.
    stopped = 0,
    /// System is starting up, subsystems initializing.
    starting = 1,
    /// System is ready to accept traffic/events.
    ready = 2,
    /// System is running normally.
    running = 3,
    /// System is degraded -- some functionality impaired but still serving.
    degraded = 4,
    /// System is failed -- critical components down, fail-closed mode.
    failed = 5,
    /// System is recovering after a transient subsystem failure.
    recovering = 6,
};

pub const SubsystemStatus = enum(u8) {
    /// Subsystem is fully operational.
    ready = 0,
    /// Subsystem is starting up (not yet ready).
    starting = 1,
    /// Subsystem is degraded (partial failure, still serving).
    degraded = 2,
    /// Subsystem is down (not serving).
    down = 3,
};

pub const SubsystemId = enum(u8) {
    capture = 0,
    etw = 1,
    fim = 2,
    wfp = 3,
    pep = 4,
    control = 5,
};

/// Per-subsystem health status with liveness tracking.

pub const Counters = struct {
    /// Total packets captured/processed.
    packets: u64,
    /// Total events generated from captured data.
    events: u64,
    /// Total detections triggered by signature/anomaly matching.
    detections: u64,
    /// Total incidents created from detected threats.
    incidents: u64,
    /// Total enforcement actions (block/allow/rate_limit) executed.
    actions: u64,
};

// ============================================================
// RuntimeHealth initialization and defaults
// ============================================================

/// Creates a RuntimeHealth with default (stopped) state.
pub fn initHealth(version: [4]u8, pid: u32) RuntimeHealth {
    return .{
        .state = State.stopped,
        .pid = pid,
        .version = version,
        .uptime_ms = 0,
        .last_event_ms = 0,
        .degraded = true,  // Start degraded until subsystems prove ready
        .tier3 = false,    // Tier-3 absent at startup
        .subsystems = [_]SubsystemStatus{
            .starting, .starting, .starting, .starting, .starting, .starting,
        },  // No subsystem is ready until its liveness is observed.
        .counters = .{0, 0, 0, 0, 0},
    };
}

/// Updates the runtime health state based on subsystem status changes.
/// This is the single point where health state transitions are computed.
pub fn updateHealth(
    current_ms: u64,
    tier3_loaded: bool,
    subsystem_statuses: [6]SubsystemStatus,
) RuntimeHealth {
    var has_failed: bool = false;
    var has_degraded: bool = false;
    var ready_count: u8 = 0;

    for (subsystem_statuses) |ss| {
        switch (ss) {
            case .ready => ready_count += 1;
            case .degraded => has_degraded = true;
            case .down, .starting => has_failed = true;
            // default: keep current state
        }
    }

    var overall_degraded: bool = has_failed or (ready_count < 6);
    var tier3_ok: bool = tier3_loaded;  // True only if Tier-3 is explicitly loaded

    // If Tier-3 is absent, system cannot be "healthy"
    var effective_degraded: bool = overall_degraded or not tier3_ok;

    // Determine overall state
    var overall_state: State = State.stopped;
    if (ready_count == 6 and not has_failed and tier3_ok) {
        overall_state = State.running;
    } else if (ready_count > 0 and not has_failed and tier3_ok) {
        overall_state = State.ready;
    } else if (has_failed) {
        overall_state = State.failed;
    } else if (has_degraded or not tier3_ok) {
        overall_state = State.degraded;
    } else {
        overall_state = State.stopped;
    }

    return .{
        .state = overall_state,
        .degraded = effective_degraded,
        .tier3 = tier3_ok,
        .subsystems = subsystem_statuses,
    };
}

// ============================================================
// Health payload for aegisctl / frontend consumption
// ============================================================

/// Returns the health payload that aegisctl and the frontend expect.
/// This conforms to the contract: component, state, pid, uptime_ms, degraded, checks
pub fn healthPayload(
    runtime_health: RuntimeHealth,
    uptime_ms: u64,
    component: []const u8,
) []const u8 {
    // Build a JSON-like payload string directly for maximum compatibility
    // Format: {"component":"...","state":"...","pid":...,"uptime_ms":...,"degraded":...,"checks":{"tier3":...}}
    var result: [256]u8 = undefined;
    var idx: usize = 0;

    // Start JSON object
    idx += appendString(&result, idx, "\"component\":");
    idx += appendEscapedString(&result, idx, component);
    idx += appendString(&result, idx, ",");

    // state
    idx += appendString(&result, idx, "\"state\":");
    idx += appendStateString(&result, idx, runtime_health.state);
    idx += appendString(&result, idx, ",");

    // pid
    idx += appendString(&result, idx, "\"pid\":");
    idx += appendU32(&result, idx, runtime_health.pid);
    idx += appendString(&result, idx, ",");

    // uptime_ms
    idx += appendString(&result, idx, "\"uptime_ms\":");
    idx += appendU64(&result, idx, uptime_ms);
    idx += appendString(&result, idx, ",");

    // degraded
    idx += appendString(&result, idx, "\"degraded\":");
    idx += appendBool(&result, idx, runtime_health.degraded);
    idx += appendString(&result, idx, ",");

    // checks (tier3 + subsystem summaries)
    idx += appendString(&result, idx, "\"checks\":{");
    // tier3 check
    idx += appendString(&result, idx, "\"tier3\":");
    idx += appendBool(&result, idx, runtime_health.tier3);
    idx += appendString(&result, idx, "}");

    // Null-terminate and return as slice
    return result[0..idx];
}

pub fn healthPayloadBool(b: bool) []const u8 {
    if b {
        return "true"_" "[1..];
    }
    return "false"_" "[1..];
}

pub fn appendString(buf: []u8, idx: i32, s: []const u8) i32 {
    var n: i32 = idx;
    for (s) |c| {
        if (n + 1 >= buf.len) return idx;
        buf[n] = c;
        n += 1;
    }
    return n;
}

pub fn appendEscapedString(buf: []u8, idx: i32, s: []const u8) i32 {
    var n: i32 = idx;
    idx += appendString(&buf, idx, "\"");
    for (s) |c| {
        if (n + 4 >= buf.len) return idx;
        if (c == '"') {
            buf[n] = '\\';
            buf[n + 1] = '"';
        } else if (c == '\\') {
            buf[n] = '\\';
            buf[n + 1] = '\\';
        } else if (c == '\n') {
            buf[n] = '\\';
            buf[n + 1] = 'n';
        } else if (c == '\r') {
            buf[n] = '\\';
            buf[n + 1] = 'r';
        } else if (c == '\t') {
            buf[n] = '\\';
            buf[n + 1] = 't';
        } else if c < 0x20 {
            buf[n] = '\\';
            buf[n + 1] = 'u';
            buf[n + 2] = '0';
            buf[n + 3] = hexChar(c >> 4);
            buf[n + 4] = hexChar(c & 0xF);
        } else {
            buf[n] = c;
        }
        n += 1;
    }
    idx += appendString(&buf, idx, "\"");
    return n;
}

pub fn appendStateString(buf: []u8, idx: i32, state: State) i32 {
    return appendEscapedString(buf, idx, switch (state) {
        .stopped => "stopped",
        .starting => "starting",
        .ready => "ready",
        .running => "running",
        .degraded => "degraded",
        .failed => "failed",
        .recovering => "recovering",
    });
}

pub fn appendU32(buf: []u8, idx: i32, v: u32) i32 {
    // Simple u32 to decimal string
    var n: i32 = idx;
    if (n + 11 >= buf.len) return idx;
    // Handle 0 case
    var temp: [11]u8 = undefined;
    var i: i32 = 10;
    temp[10] = 'u8';
    // Actually let's just use a simpler approach
    var s = intToString(v);
    for (s) |c| {
        if (n + 1 >= buf.len) return idx;
        buf[n] = c;
        n += 1;
    }
    return n;
}

pub fn intToString(v: u32) []const u8 {
    // Simple conversion
    var buf: [12]u8 = undefined;
    var i: i32 = 11;
    if (v == 0) {
        buf[0] = '0';
        return buf[0..1];
    }
    while (v > 0) {
        i -= 1;
        var d: u8 = u8('0' + (v % 10));
        buf[i] = d;
        v /= 10;
    }
    return buf[i..];
}

pub fn appendU64(buf: []u8, idx: i32, v: u64) i32 {
    var n: i32 = idx;
    if (v == 0) {
        if (n + 1 >= buf.len) return idx;
        buf[n] = '0';
        return n + 1;
    }
    var temp: [20]u8 = undefined;
    var i: i32 = 19;
    var vv: u64 = v;
    while (vv > 0) {
        i -= 1;
        var d: u8 = u8('0' + (vv % 10));
        buf[i] = d;
        vv /= 10;
    }
    var end: i32 = i + 1;
    if (n + (19 - i) >= buf.len) return idx;
    buf[n + (19 - i - 1)] = 0; // null terminator not needed for slice
    return n + (19 - i);
}

pub fn hexChar(n: u8) u8 {
    return if n < 10 { u8('0' + n) } else { u8('A' + n - 10) };
}

// ============================================================
// Global runtime health state (accessible from aegisctl)
// ============================================================

// Global runtime health instance - updated by the runtime spine
var g_runtime_health: RuntimeHealth = RuntimeHealth.initHealth(
    /* version */ "v5.0"_u8,
    /* pid */ cast(u32, @intCast(@os PID)),
);

/// Returns the current runtime health state.
pub fn getRuntimeHealth() RuntimeHealth {
    return g_runtime_health;
}

/// Updates the global runtime health state.
/// Called by the runtime spine during startup, subsystem status changes, and heartbeat.
pub fn setRuntimeHealth(new_health: RuntimeHealth) void {
    g_runtime_health = new_health;
}

/// Increments the liveness heartbeat and updates last_seen_ms.
/// The heartbeat interval and staleness threshold are defined in
/// health_monitoring_proof.zig section 50.
pub fn recordHealthbeat(now_ms: u64) void {
    g_runtime_health.last_event_ms = now_ms;
    g_runtime_health.counters.events += 1;
}

/// Increments the packet counter.
pub fn recordPacket() void {
    g_runtime_health.counters.packets += 1;
}

/// Increments the detection counter.
pub fn recordDetection() void {
    g_runtime_health.counters.detections += 1;
}

/// Increments the incident counter.
pub fn recordIncident() void {
    g_runtime_health.counters.incidents += 1;
}

/// Increments the action counter.
pub fn recordAction() void {
    g_runtime_health.counters.actions += 1;
}
