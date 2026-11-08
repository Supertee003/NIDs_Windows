//! Shared runtime state for the AEGIS daemon.
//!
//! Extracted from main.zig during the god-file refactor.
//! These globals are deliberately centralized so that the control pipe,
//! event queue, rule loader, and event processor can coordinate without
//! circular imports. Access is guarded per the comment on each variable.

const std = @import("std");
const sig = @import("../detection/signature_engine.zig");
const l4 = @import("l4_matcher.zig");
const watchdog = @import("../reliability/watchdog.zig");
const fault = @import("../reliability/fault_injection.zig");
const hist = @import("../reliability/latency_histogram.zig");
const forensic = @import("../forensic/forensic_pipeline.zig");

/// Set by SCM stop / `daemon.shutdown`. Polled by every worker thread.
pub var g_stop_requested = std.atomic.Value(bool).init(false);

/// Host mutation remains disabled until the isolated WFP proof opens this
/// gate. Provider readiness alone must never change it. SLICE-C-LAB: the
/// only writer is openPreventionGateLab() below (daemon, lab builds only).
pub var g_prevention_gate_open: bool = false;

/// SLICE-C-LAB: provenance of the gate position. Only the dedicated lab
/// opener may move this off `.closed`; it is never persisted, so a restart
/// re-closes the gate.
pub const GateSource = enum { closed, lab_build_optin };
pub var g_gate_source: GateSource = .closed;

pub const GateOpenOutcome = struct { opened: bool, reason: []const u8 };

/// SLICE-C-LAB: THE single writer of g_prevention_gate_open. Called by the
/// daemon only when compiled with -Dlab-prevention-gate=true (see
/// docs/SLICE_C_LAB_GATE_DESIGN.md). Fails closed on any missing
/// precondition and stays in-memory only.
pub fn openPreventionGateLab(pep_available: bool, provider_ready: bool, tier3_ready: bool, ring_present: bool) GateOpenOutcome {
    if (g_prevention_gate_open) return .{ .opened = true, .reason = "already-open" };
    if (!pep_available) return .{ .opened = false, .reason = "pep-unavailable" };
    if (!provider_ready) return .{ .opened = false, .reason = "provider-not-ready" };
    if (!tier3_ready) return .{ .opened = false, .reason = "tier3-not-ready" };
    if (!ring_present) return .{ .opened = false, .reason = "forensic-ring-absent" };
    g_prevention_gate_open = true;
    g_gate_source = .lab_build_optin;
    return .{ .opened = true, .reason = "opened" };
}
// BE-EVI-097: evidence-log projection (logs/aegis_core.ndjson) on by
// default so file-tail surfaces see live detections. AEGIS_EVIDENCE_LOG=0
// opts out. A failed write never fails detection (drop-on-error in
// forensic_log.log); the forensic ring stays the detection record.
pub var g_evidence_log_enabled: bool = true;

/// Tier-2 brain inspection (daemon -> brain UDP, detections only). Opt-in
/// via AEGIS_BRAIN=1 (default off): without a running brain the datagrams
/// go nowhere, so the pipeline skips formatting entirely when closed.
pub var g_brain_enabled = std.atomic.Value(bool).init(false);
pub var g_cluster_enabled = std.atomic.Value(bool).init(false);

/// TS-authored policy IR (verify-only mirror of configs/policy_ir.json).
/// Loaded at startup when the file exists; the runtime PolicySet
/// (policies.json) stays the sole evaluation authority. Null when absent
/// or invalid — metrics report loaded=false instead of claiming rules.
pub var g_policy_ir: ?@import("../policy/policy_plane.zig").LoadedIr = null;
pub var g_policy_ir_verified = std.atomic.Value(bool).init(false);

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

test "runtime fail-closed defaults hold (BYTE-ORDER-096 audit)" {
    // Pinned boot posture: prevention closed (the only writer is
    // openPreventionGateLab, called solely by the daemon behind the lab
    // build option; default builds have no reachable caller), gate
    // provenance closed, evidence log on, no policy mirror loaded, all
    // readiness flags clear, no recorded worker failure. Only daemon paths
    // and live worker threads mutate these; unit tests restore any state
    // they touch, so any drift here is a real regression.
    try std.testing.expect(!g_prevention_gate_open);
    try std.testing.expect(g_gate_source == .closed);
    try std.testing.expect(g_evidence_log_enabled);
    try std.testing.expect(g_policy_ir == null);
    try std.testing.expect(!g_policy_ir_verified.load(.acquire));
    try std.testing.expect(!g_pipeline_ready.load(.acquire));
    try std.testing.expect(!g_sensor_ready.load(.acquire));
    try std.testing.expect(!g_nose_ready.load(.acquire));
    try std.testing.expect(!g_etw_ready.load(.acquire));
    try std.testing.expect(!g_fim_ready.load(.acquire));
    try std.testing.expect(!g_registry_ready.load(.acquire));
    try std.testing.expect(!g_worker_failed.load(.acquire));
    try std.testing.expectEqual(WorkerFailureKind.none, @as(WorkerFailureKind, @enumFromInt(g_worker_failure_kind.load(.acquire))));
    try std.testing.expectEqual(@as(u8, 0), g_worker_failure_mask.load(.acquire));
}

fn resetGateForTest() void {
    g_prevention_gate_open = false;
    g_gate_source = .closed;
}

test "SLICE-C-LAB: prevention gate stays closed unless every lab precondition holds" {
    defer resetGateForTest();
    try std.testing.expect(!openPreventionGateLab(false, true, true, true).opened);
    try std.testing.expect(!g_prevention_gate_open);
    try std.testing.expect(!openPreventionGateLab(true, false, true, true).opened);
    try std.testing.expect(!g_prevention_gate_open);
    try std.testing.expect(!openPreventionGateLab(true, true, false, true).opened);
    try std.testing.expect(!g_prevention_gate_open);
    try std.testing.expect(!openPreventionGateLab(true, true, true, false).opened);
    try std.testing.expect(!g_prevention_gate_open);
    try std.testing.expect(g_gate_source == .closed);
}

test "SLICE-C-LAB: gate opens only via the dedicated writer and records its source" {
    defer resetGateForTest();
    const r = openPreventionGateLab(true, true, true, true);
    try std.testing.expect(r.opened);
    try std.testing.expect(std.mem.eql(u8, r.reason, "opened"));
    try std.testing.expect(g_prevention_gate_open);
    try std.testing.expect(g_gate_source == .lab_build_optin);
    const again = openPreventionGateLab(true, true, true, true);
    try std.testing.expect(again.opened);
    try std.testing.expect(std.mem.eql(u8, again.reason, "already-open"));
}

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
// FE-DEF-095a: daemon-owned DEFCON inputs. Critical = matched detections
// whose final (possibly incident-escalated) severity is critical or
// emergency. Confirmed = BLOCKED_CONFIRMED receipts only (verified
// EnforcementReceipt + host effect). Both counted at emission, read by
// control/defcon.zig via healthJson. Never file-derived.
pub var g_critical_detections = std.atomic.Value(u64).init(0);
pub var g_confirmed_blocks = std.atomic.Value(u64).init(0);
// QUAR-RCPT-094: confirmed-quarantine counter, incremented ONLY on the
// receipt-verified quarantine path in dispatchWithReceipt (same
// daemon-owned discipline as confirmed blocks). DEFCON's `confirmed`
// input still reads blocks only — quarantines are reported via health,
// not folded into the DEFCON ladder without a threshold review.
pub var g_confirmed_quarantines = std.atomic.Value(u64).init(0);
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
// EVT-211: kernel WFP flow-telemetry health. The capture loop owns these;
// control/queue renders them so a missing provider read surface is a
// LABELED state, never a silent zero. Ordinals: see WfpProviderState.
pub const WfpProviderState = enum(u8) { unknown = 0, ok = 1, unavailable = 2 };
pub var g_wfp_provider_state = std.atomic.Value(u8).init(@intFromEnum(WfpProviderState.unknown));
pub var g_wfp_reads = std.atomic.Value(u64).init(0); // provider poll calls answered
pub var g_wfp_rows = std.atomic.Value(u64).init(0); // ring records submitted to the pipeline
pub var g_wfp_last_bytes = std.atomic.Value(u64).init(0); // bytes in the last answered read
// PHASE-6: network acquisition arbitration (capture/source_arbiter.zig).
// The WFP telemetry loop is the single writer of mode/reason; the control
// plane renders them in queue.stats. `shadow_rows` counts kernel records
// that were DRAINED but not submitted because the packet path owns
// ingress — evidence the kernel saw traffic Npcap did not deliver, never a
// silent drop. Ordinals: source_arbiter.Mode / source_arbiter.Reason.
pub var g_capture_mode = std.atomic.Value(u8).init(0); // 0 = undecided
pub var g_capture_reason = std.atomic.Value(u8).init(0);
pub var g_wfp_shadow_rows = std.atomic.Value(u64).init(0);
// EVT-230: kernel minifilter host-telemetry health (file/process events via
// \AegisMinifilterPort). The reader loop owns these; control/queue renders
// them so a driver-absent host shows a LABELED `unavailable` state, never a
// silent zero. rows>0 is the only "kernel file/process rows are flowing"
// claim; dropped is the KERNEL ring's own loss counter (never silent).
// Ordinals: same three-state shape as WfpProviderState.
pub const MinifilterState = enum(u8) { unknown = 0, ok = 1, unavailable = 2 };
pub var g_minifilter_state = std.atomic.Value(u8).init(@intFromEnum(MinifilterState.unknown));
pub var g_minifilter_reads = std.atomic.Value(u64).init(0); // READ_EVENTS pulls answered
pub var g_minifilter_rows = std.atomic.Value(u64).init(0); // kernel records submitted to the pipeline
pub var g_minifilter_last_bytes = std.atomic.Value(u64).init(0); // bytes in the last answered pull
pub var g_minifilter_dropped = std.atomic.Value(u64).init(0); // kernel ring DroppedEvents (polled)
pub var g_minifilter_pipeline_dropped = std.atomic.Value(u64).init(0); // rows rejected by shared EventQueue
/// Identity used for events originating from the verified daemon process.
/// Set during daemon startup; never use a fabricated all-capability mask.
pub var g_runtime_pid: u32 = 0;
/// Capability bitmask granted to the verified runtime service.
pub var g_runtime_capability_mask: u32 = 0;
pub var g_incidents_total = std.atomic.Value(u64).init(0); // real incident count from ThreatTracker
pub var g_incidents_open = std.atomic.Value(u64).init(0); // currently open incidents
pub var g_queue_drops = std.atomic.Value(u64).init(0); // events refused by queue admission (full or reserved-tail shed)
/// IDS-QUEUE-001: subset of g_queue_drops refused specifically because host
/// telemetry reached the reserved network tail. Exposed separately so an
/// operator can distinguish "queue actually full" from "network reserve
/// protected"; it never changes admission or health behavior by itself.
pub var g_reserved_tail_shed = std.atomic.Value(u64).init(0);
/// QLOSS-FAIRSHARE-001: host-source refusals caused by the per-source
/// occupancy cap rather than by a full queue. Counted in g_queue_drops too, so
/// health still degrades; this counter only names the cause.
pub var g_source_quota_shed = std.atomic.Value(u64).init(0);
/// QLOSS-CRITICAL-001: FIM events admitted because they target a protected
/// system tree. Exposed so an operator can see that the reserved slice is
/// actually carrying protection rather than sitting unused.
pub var g_critical_pushed = std.atomic.Value(u64).init(0);
/// ADR-0012 measurement gate: FIM observations probed for an exact duplicate
/// `(path, kind)` inside the same poll batch, how many of those repeated an
/// observation already seen in that batch, and how often the bounded probe
/// table filled (a full table under-reports duplicates, so it is counted).
/// Measurement only: no event is suppressed by these counters.
pub var g_fim_batch_records = std.atomic.Value(u64).init(0);
pub var g_fim_batch_duplicates = std.atomic.Value(u64).init(0);
pub var g_fim_batch_overflow = std.atomic.Value(u64).init(0);
/// The same probe split by ingress path, because the fix (coalesce where the
/// duplicates actually are) needs to know which sensor produced them: the
/// minifilter pull (`\AegisMinifilterPort`, file-create records) or the
/// ReadDirectoryChangesW poll batch.
pub var g_fim_minifilter_batch_records = std.atomic.Value(u64).init(0);
pub var g_fim_minifilter_batch_duplicates = std.atomic.Value(u64).init(0);
pub var g_fim_poll_batch_records = std.atomic.Value(u64).init(0);
pub var g_fim_poll_batch_duplicates = std.atomic.Value(u64).init(0);
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

/// §4.1 wire conformance (EVT-222): on the wire `last_event_ms` is the AGE
/// (ms since the last processed event), never an absolute timestamp. The
/// stored value above is epoch-ms, so every emitter converts at emit time
/// through this helper (the Python brain and the nids_main probe already
/// emit ages; the two control-plane emitters leaked epoch-ms).
pub fn lastEventAgeMs(last_ms: i64, now_ms: i64) i64 {
    if (last_ms <= 0 or now_ms <= last_ms) return 0;
    return now_ms - last_ms;
}

test "lastEventAgeMs: §4.1 age semantics, clamped (EVT-222)" {
    try std.testing.expectEqual(@as(i64, 0), lastEventAgeMs(0, 1_000)); // nothing yet
    try std.testing.expectEqual(@as(i64, 0), lastEventAgeMs(1_000, 1_000)); // just now
    try std.testing.expectEqual(@as(i64, 250), lastEventAgeMs(1_000, 1_250)); // 250ms ago
    try std.testing.expectEqual(@as(i64, 0), lastEventAgeMs(2_000, 1_500)); // skew -> 0
    try std.testing.expectEqual(@as(i64, 0), lastEventAgeMs(-7, 1_000)); // defensive
}

// PATCH-14: Rules reload mechanism.
// The pipeline thread reads the active AC automaton pointer; the control
// pipe thread rebuilds a new AC and swaps the pointer atomically.
pub var g_active_ac: ?*sig.AhoCorasick = null;
pub var g_ac_mutex: std.Thread.Mutex = .{};

// L4 predicate rules (layer=="L4") loaded from the same Rules.json as the
// AC. The reload path swaps this table and g_active_ac under g_ac_mutex so
// the pipeline never observes a half-updated rule set. Fixed size: the
// catalog has three L4 rules today; a larger set is a deliberate limit, not
// silent truncation (rule_loader records a named skip past MAX_RULES).
pub var g_l4_rules: [l4.MAX_RULES]l4.Rule = l4.empty_rules;
pub var g_l4_rule_count: usize = 0;

// L4 rate/window state. One consumer observes; g_l4_rate_mutex serializes
// that observer with rules.reload, which resets the table when the catalog
// changes (a threshold from an old rule must never suppress a new rule).
pub var g_l4_rate: l4.RateTracker = .{};
pub var g_l4_rate_mutex: std.Thread.Mutex = .{};

// PATCH-29/30/31: Reliability globals (initialized by daemon.zig)
pub var g_wd: watchdog.ReliabilityWatchdog = undefined;
pub var g_fi: fault.FaultInjector = undefined;
pub var g_perf: hist.PerfTracker = .{};
pub var g_perf_mutex: std.Thread.Mutex = .{};
/// GAP-015: guards PerfTracker.observe (pipeline consumer) against
/// PerfTracker.snapshot (control-plane readers). The consumer previously
/// raced any reader over plain u64 bins; one uncontended mutex per event
/// is ~ns against a ~ms service budget. daemon.zig re-inits g_perf at
/// startup as before; the zero value keeps unit-test contexts valid.

// WD-BEAT-049: one cached watchdog slot per self-beating worker. pop
// via state.g_wd.beatLazy(&slot, kind, name) from the worker loop only —
// never from unit tests (g_wd is undefined until the daemon inits it).
// nose (blocked reads) and pipe_monitor (10s sweeps) are intentionally
// absent: their cadence exceeds the 5s watchdog timeout, so beating there
// would false-positive. They need per-thread timeouts (follow-up slice).
pub var g_wd_sensor_slot: ?usize = null;
pub var g_wd_etw_slot: ?usize = null;
pub var g_wd_fim_slot: ?usize = null;
pub var g_wd_registry_slot: ?usize = null;
/// XDR-005-A: host_net is an advisory telemetry source; it beats the generic
/// host-telemetry watchdog from its own loop and is not part of the startup
/// readiness barrier.
pub var g_wd_hostnet_slot: ?usize = null;
