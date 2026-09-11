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

/// Set by SCM stop / `daemon.shutdown`. Polled by every worker thread.
pub var g_stop_requested = std.atomic.Value(bool).init(false);

// --- Pipeline counters (owned by event_processor.zig / event_queue.zig) ---
pub var g_pipeline_events_processed: u64 = 0;
pub var g_pipeline_detections: u64 = 0;
pub var g_pipeline_anomalies: u64 = 0;
pub var g_pipeline_correlations: u64 = 0;
pub var g_rules_loaded: u32 = 0;
pub var g_policies_loaded: u32 = 0;
pub var g_pipeline_policies_matched: u64 = 0;
pub var g_pipeline_audit_id: u64 = 0; // monotonic audit trail counter
pub var g_pep_request_id: u64 = 0; // unique PEP request ID counter
pub var g_trace_id: u64 = 0; // monotonic trace counter
pub var g_pep_available: bool = false; // PEP availability for health check
pub var g_incidents_total: u64 = 0; // real incident count from ThreatTracker
pub var g_incidents_open: u64 = 0; // currently open incidents
pub var g_queue_drops: u64 = 0; // events dropped due to queue full

// PATCH-14: Rules reload mechanism.
// The pipeline thread reads the active AC automaton pointer; the control
// pipe thread rebuilds a new AC and swaps the pointer atomically.
pub var g_active_ac: ?*sig.AhoCorasick = null;
pub var g_ac_mutex: std.Thread.Mutex = .{};

// PATCH-29/30/31: Reliability globals (initialized by daemon.zig)
pub var g_wd: watchdog.ReliabilityWatchdog = undefined;
pub var g_fi: fault.FaultInjector = undefined;
pub var g_perf: hist.PerfTracker = undefined;
