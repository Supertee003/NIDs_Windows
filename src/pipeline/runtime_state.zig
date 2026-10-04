//! Shared runtime state for the AEGIS daemon.
//!
//! Extracted from main.zig during the god-file refactor.
//! These globals are deliberately centralized so that the control pipe,
//! event queue, rule loader, and event processor can coordinate without
//! circular imports. Access is guarded per the comment on each variable.

const std = @import("std");
const sig = @import("../detection/signature_engine.zig");
const watchdog = @import("../reliability/watchdog.zig");
const fault = @import("../reliability/fault_injection.zig");
const hist = @import("../reliability/latency_histogram.zig");
const forensic = @import("../forensic/forensic_pipeline.zig");

/// Set by SCM stop / `daemon.shutdown`. Polled by every worker thread.
pub var g_stop_requested = std.atomic.Value(bool).init(false);

/// Host mutation remains disabled until the isolated WFP proof opens this
/// gate. Provider readiness alone must never change it.
pub var g_prevention_gate_open: bool = false;

/// Tier-2 brain inspection (daemon -> brain UDP, detections only). Opt-in
/// via AEGIS_BRAIN=1 (default off): without a running brain the datagrams
/// go nowhere, so the pipeline skips formatting entirely when closed.
pub var g_brain_enabled = std.atomic.Value(bool).init(false);

/// TS-authored policy IR (verify-only mirror of configs/policy_ir.json).
/// Loaded at startup when the file exists; the runtime PolicySet
/// (policies.json) stays the sole evaluation authority. Null when absent
/// or invalid — metrics report loaded=false instead of claiming rules.
pub var g_policy_ir: ?@import("../policy/policy_plane.zig").LoadedIr = null;

// PHASE-1 readiness handshake. Thread creation is not readiness: each worker
// sets its ready flag only after its required initialization succeeds and
// clears it before returning. A failed flag preserves the reason at runtime
// level even when the worker exits quickly.
pub var g_pipeline_ready = std.atomic.Value(bool).init(false);
pub var g_sensor_ready = std.atomic.Value(bool).init(false);
pub var g_nose_ready = std.atomic.Value(bool).init(false);
pub var g_etw_ready = std.atomic.Value(bool).init(false);
pub var g_fim_ready = std.atomic.Value(bool).init(false);
pub var g_registry_ready = std.atomic.Value(bool).init(false);
pub var g_worker_failed = std.atomic.Value(bool).init(false);

pub const WorkerFailureKind = enum(u8) {
    none = 0,
    pipeline = 1,
    sensor = 2,
    nose = 3,
    etw = 4,
    fim = 5,
    registry = 6,
};

pub var g_worker_failure_kind = std.atomic.Value(u8).init(@intFromEnum(WorkerFailureKind.none));
pub var g_worker_failure_mask = std.atomic.Value(u8).init(0);

pub fn markWorkerFailure(kind: WorkerFailureKind) void {
    g_worker_failure_kind.store(@intFromEnum(kind), .release);
    if (kind != .none) {
        const shift: u3 = @intCast(@intFromEnum(kind) - 1);
        const bit: u8 = @as(u8, 1) << shift;
        _ = g_worker_failure_mask.fetchOr(bit, .acq_rel);
    }
    g_worker_failed.store(true, .release);
}

pub fn workerFailureReason() []const u8 {
    return switch (@as(WorkerFailureKind, @enumFromInt(g_worker_failure_kind.load(.acquire)))) {
        .none => "none",
        .pipeline => "pipeline_init_failed",
        .sensor => "sensor_init_failed",
        .nose => "nose_init_failed",
        .etw => "etw_init_failed",
        .fim => "fim_init_failed",
        .registry => "registry_init_failed",
    };
}

pub fn workerFailureMask() u8 {
    return g_worker_failure_mask.load(.acquire);
}

// --- Pipeline counters (written by the pipeline/nose threads, read by the
// control-pipe thread for health/metrics). All atomics: plain u64/bool here
// used to be cross-thread data races (control handlers read while workers
// write). Ordering: writers use .monotonic (counters need no ordering
// beyond atomicity), readers use .acquire.
pub var g_pipeline_events_processed = std.atomic.Value(u64).init(0);
pub var g_pipeline_detections = std.atomic.Value(u64).init(0);
// ANOM-COUNT-035: g_pipeline_anomalies removed (write-only, zero readers).
// Anomaly counts live in AnomalyDetector.anomalies_emitted (detector-owned)
// and diag.metrics.anomalies_detected (metrics-snapshot feed).
pub var g_pipeline_correlations = std.atomic.Value(u64).init(0);
pub var g_rules_loaded = std.atomic.Value(u32).init(0);
pub var g_policies_loaded = std.atomic.Value(u32).init(0);
pub var g_pipeline_policies_matched = std.atomic.Value(u64).init(0);
pub var g_forensic_records_written = std.atomic.Value(u64).init(0);
pub var g_forensic_ring: ?*forensic.ForensicRing = null;
pub var g_pipeline_audit_id = std.atomic.Value(u64).init(0); // monotonic audit trail counter
pub var g_pep_request_id = std.atomic.Value(u64).init(0); // unique PEP request ID counter
pub var g_trace_id = std.atomic.Value(u64).init(0); // monotonic trace counter
pub var g_pep_available = std.atomic.Value(bool).init(false); // PEP availability for health check
/// Identity used for events originating from the verified daemon process.
/// Set during daemon startup; never use a fabricated all-capability mask.
pub var g_runtime_pid: u32 = 0;
/// Capability bitmask granted to the verified runtime service.
pub var g_runtime_capability_mask: u32 = 0;
pub var g_incidents_total = std.atomic.Value(u64).init(0); // real incident count from ThreatTracker
pub var g_incidents_open = std.atomic.Value(u64).init(0); // currently open incidents
pub var g_queue_drops = std.atomic.Value(u64).init(0); // events dropped due to queue full
// Canonical Go Nose -> Zig reader counters. These are deliberately separate
// from process liveness: RUNNING does not imply that the data plane is active.
pub var g_nose_connected = std.atomic.Value(bool).init(false);
pub var g_nose_frames_read = std.atomic.Value(u64).init(0);
pub var g_nose_frames_rejected = std.atomic.Value(u64).init(0);
pub var g_nose_frames_submitted = std.atomic.Value(u64).init(0);
pub var g_nose_frames_dropped = std.atomic.Value(u64).init(0);
pub var g_nose_pipe_errors = std.atomic.Value(u64).init(0);
pub var g_nose_last_event_id = std.atomic.Value(u64).init(0);
pub var g_nose_duplicate_event_ids = std.atomic.Value(u64).init(0);
pub var g_nose_non_monotonic_event_ids = std.atomic.Value(u64).init(0);
/// CTRL-002: monotonic epoch-ms of the last processed event. 0 means no event
/// has been processed yet. Exposed through the control plane so
/// `last_event_ms` in RUNTIME_CONTRACT.md §4.1 is real data, never a placeholder.
pub var g_last_event_ms = std.atomic.Value(i64).init(0);

// PATCH-14: Rules reload mechanism.
// The pipeline thread reads the active AC automaton pointer; the control
// pipe thread rebuilds a new AC and swaps the pointer atomically.
pub var g_active_ac: ?*sig.AhoCorasick = null;
pub var g_ac_mutex: std.Thread.Mutex = .{};

// PATCH-29/30/31: Reliability globals (initialized by daemon.zig)
pub var g_wd: watchdog.ReliabilityWatchdog = undefined;
pub var g_fi: fault.FaultInjector = undefined;
pub var g_perf: hist.PerfTracker = undefined;
