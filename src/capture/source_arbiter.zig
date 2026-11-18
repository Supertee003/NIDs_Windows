//! capture/source_arbiter.zig — PHASE-6 network acquisition arbitration.
//!
//! AEGIS has two network acquisition sources:
//!   1. Npcap through Go Nose -> named pipe -> Zig reader (full packets,
//!      stream reassembly, L7 payload authority);
//!   2. the WFP kernel ring (5-tuple + bounded transport payload copy,
//!      real direction byte, sees every interface incl. tunnels).
//!
//! Running both as detection ingress duplicates every row (two event
//! identities, doubled flow packet/byte accounting, doubled rate-rule
//! observations) — the duplicate-authority defect DP-10 records. Running
//! only Npcap leaves the host blind whenever Nose is absent, and running
//! only the kernel gives up payload/reassembly. This module makes the
//! ownership explicit and stated, never implicit:
//!
//!   | mode            | condition                                  | packet | kernel |
//!   |-----------------|--------------------------------------------|--------|--------|
//!   | npcap_primary   | Nose connected+ready and producing         | submit | shadow |
//!   | kernel_fallback | Nose absent OR Nose stalled (kernel sees   | submit | submit |
//!   |                 | rows while Nose submitted count stands still)   |        |        |
//!   | split_lab       | AEGIS_CAPTURE_SPLIT=1 opt-in (disjoint     | submit | submit |
//!   |                 | lab interfaces only)                       |        |        |
//!   | none            | neither source available                   | -      | -      |
//!
//! "shadow" means the kernel ring is still DRAINED (never let a 2 MB ring
//! overflow) but its rows are counted in `g_wfp_shadow_rows` and NOT
//! submitted to the pipeline. A shadow row is evidence the kernel saw
//! traffic the packet path did not deliver; the counters make that
//! visible instead of silently dropping it.
//!
//! The kernel-side takeover is evidence-driven: it needs both (a) at
//! least one kernel row while the Nose submitted-frame counter has not advanced and
//! (b) STALL_MS of no Nose progress. An idle network produces no kernel
//! rows either, so idleness alone never triggers a takeover. When Nose
//! resumes, the next evaluate() stands the kernel back down before that
//! record is submitted, so the overlap window is at most the records
//! already in flight.
//!
//! This module NEVER decides enforcement, never inspects payloads, and
//! never touches a device handle. It is a pure routing decision + the
//! publish of that decision for the control plane.

const std = @import("std");
const runtime_state = @import("../pipeline/runtime_state.zig");

/// Public acquisition mode. Ordinals are the control-plane wire values;
/// append only (queue.stats prints a stable name per ordinal).
pub const Mode = enum(u8) {
    undecided = 0,
    npcap_primary = 1,
    kernel_fallback = 2,
    split_lab = 3,
    none = 4,
};

/// Why the mode is what it is. Kept separate from Mode so an operator can
/// tell "Nose is simply not running" from "Nose is connected but stopped
/// producing while the kernel still sees traffic" (the dangerous case).
pub const Reason = enum(u8) {
    none = 0,
    nose_absent = 1,
    nose_stalled = 2,
    split_lab = 3,
    no_source = 4,
};

/// Nose progress must stand still this long before the kernel takes over.
/// A 10 s window is long enough that normal idle gaps do not flap the
/// mode, and short enough that a dead Nose is noticed inside one
/// operator poll interval.
pub const STALL_MS: i64 = 10_000;

pub const Decision = struct {
    mode: Mode,
    reason: Reason,
    packet_may_submit: bool,
    kernel_may_submit: bool,
};

pub const Input = struct {
    nose_ready: bool,
    nose_connected: bool,
    nose_frames_submitted: u64,
    kernel_available: bool,
    /// True when this evaluation accompanies an actual kernel record
    /// (not just an idle availability probe).
    kernel_row: bool,
    split_lab: bool,
    now_ms: i64,
};

/// Stateful arbiter. One instance lives in the WFP telemetry loop (its
/// single writer); tests construct their own.
pub const Arbiter = struct {
    started: bool = false,
    last_nose_frames: u64 = 0,
    last_nose_progress_ms: i64 = 0,
    /// Kernel records seen since the Nose submitted-frame counter last advanced.
    kernel_rows_while_nose_idle: u64 = 0,

    pub fn evaluate(self: *Arbiter, in: Input) Decision {
        if (!self.started) {
            self.started = true;
            self.last_nose_frames = in.nose_frames_submitted;
            self.last_nose_progress_ms = in.now_ms;
        } else if (in.nose_frames_submitted != self.last_nose_frames) {
            self.last_nose_frames = in.nose_frames_submitted;
            self.last_nose_progress_ms = in.now_ms;
            self.kernel_rows_while_nose_idle = 0;
        }

        const nose_healthy = in.nose_ready and in.nose_connected;

        if (!nose_healthy) {
            if (!in.kernel_available) {
                return .{ .mode = .none, .reason = .no_source, .packet_may_submit = false, .kernel_may_submit = false };
            }
            return .{ .mode = .kernel_fallback, .reason = .nose_absent, .packet_may_submit = false, .kernel_may_submit = true };
        }

        // Split mode needs an actual second source; without it the label
        // would claim a two-source posture the host does not have.
        if (in.split_lab and in.kernel_available) {
            return .{ .mode = .split_lab, .reason = .split_lab, .packet_may_submit = true, .kernel_may_submit = true };
        }

        // Nose is healthy but the kernel is seeing rows Nose is not
        // delivering: only an observably stalled Nose is displaced.
        if (in.kernel_row and in.kernel_available) self.kernel_rows_while_nose_idle += 1;
        const stalled = in.kernel_available and
            self.kernel_rows_while_nose_idle > 0 and
            (in.now_ms - self.last_nose_progress_ms) >= STALL_MS;
        if (stalled) {
            return .{ .mode = .kernel_fallback, .reason = .nose_stalled, .packet_may_submit = true, .kernel_may_submit = true };
        }

        return .{ .mode = .npcap_primary, .reason = .none, .packet_may_submit = true, .kernel_may_submit = false };
    }
};

/// Publish the current decision for the control plane (queue.stats). Only
/// the WFP telemetry loop calls this.
pub fn publish(decision: Decision) void {
    runtime_state.g_capture_mode.store(@intFromEnum(decision.mode), .release);
    runtime_state.g_capture_reason.store(@intFromEnum(decision.reason), .release);
}

pub fn modeName(v: u8) []const u8 {
    return switch (v) {
        1 => "npcap_primary",
        2 => "kernel_fallback",
        3 => "split_lab",
        4 => "none",
        else => "undecided",
    };
}

pub fn reasonName(v: u8) []const u8 {
    return switch (v) {
        1 => "nose_absent",
        2 => "nose_stalled",
        3 => "split_lab",
        4 => "no_source",
        else => "none",
    };
}

// ============================================================
// Tests (pure: no device, no threads)
// ============================================================

const t = std.testing;

fn baseInput() Input {
    return .{
        .nose_ready = true,
        .nose_connected = true,
        .nose_frames_submitted = 100,
        .kernel_available = true,
        .kernel_row = true,
        .split_lab = false,
        .now_ms = 1_000,
    };
}

test "healthy Nose owns network rows; kernel is drained as shadow" {
    var a = Arbiter{};
    const d = a.evaluate(baseInput());
    try t.expectEqual(Mode.npcap_primary, d.mode);
    try t.expectEqual(Reason.none, d.reason);
    try t.expect(d.packet_may_submit);
    try t.expect(!d.kernel_may_submit);
}

test "absent Nose hands both directions to the kernel, never silently blind" {
    var a = Arbiter{};
    var in = baseInput();
    in.nose_connected = false;
    const d = a.evaluate(in);
    try t.expectEqual(Mode.kernel_fallback, d.mode);
    try t.expectEqual(Reason.nose_absent, d.reason);
    try t.expect(!d.packet_may_submit);
    try t.expect(d.kernel_may_submit);
}

test "neither source available reports none, not a fake primary" {
    var a = Arbiter{};
    var in = baseInput();
    in.nose_ready = false;
    in.kernel_available = false;
    const d = a.evaluate(in);
    try t.expectEqual(Mode.none, d.mode);
    try t.expectEqual(Reason.no_source, d.reason);
    try t.expect(!d.packet_may_submit);
    try t.expect(!d.kernel_may_submit);
}

test "kernel takeover needs BOTH kernel evidence and STALL_MS of Nose silence" {
    var a = Arbiter{};
    var in = baseInput();
    _ = a.evaluate(in); // anchors last_nose_progress_ms

    // Kernel rows arrive, but the stall window has not elapsed yet.
    in.now_ms = 1_000 + STALL_MS - 1;
    const early = a.evaluate(in);
    try t.expectEqual(Mode.npcap_primary, early.mode);
    try t.expect(!early.kernel_may_submit);

    // Same Nose submitted-frame count after the full window: stall proven.
    in.now_ms = 1_000 + STALL_MS;
    const late = a.evaluate(in);
    try t.expectEqual(Mode.kernel_fallback, late.mode);
    try t.expectEqual(Reason.nose_stalled, late.reason);
    try t.expect(late.kernel_may_submit);
    // Nose stays allowed: its rows are still real, and a resumed Nose
    // must stand the kernel down on the next evaluate.
    try t.expect(late.packet_may_submit);
}

test "idle network never triggers takeover (no kernel rows, no evidence)" {
    var a = Arbiter{};
    var in = baseInput();
    in.kernel_row = false;
    _ = a.evaluate(in);
    in.now_ms = 1_000 + (STALL_MS * 6);
    const d = a.evaluate(in);
    try t.expectEqual(Mode.npcap_primary, d.mode);
    try t.expect(!d.kernel_may_submit);
}

test "resumed Nose stands the kernel back down before the next submit" {
    var a = Arbiter{};
    var in = baseInput();
    _ = a.evaluate(in);
    in.now_ms = 1_000 + STALL_MS;
    try t.expect(a.evaluate(in).kernel_may_submit);

    in.now_ms += 100;
    in.nose_frames_submitted += 1; // one delivered frame proves progress
    const d = a.evaluate(in);
    try t.expectEqual(Mode.npcap_primary, d.mode);
    try t.expect(!d.kernel_may_submit);
}

test "split_lab opts both sources in and says so" {
    var a = Arbiter{};
    var in = baseInput();
    in.split_lab = true;
    const d = a.evaluate(in);
    try t.expectEqual(Mode.split_lab, d.mode);
    try t.expectEqual(Reason.split_lab, d.reason);
    try t.expect(d.packet_may_submit);
    try t.expect(d.kernel_may_submit);
}

test "split_lab without a kernel source stays npcap_primary, never a fake split" {
    var a = Arbiter{};
    var in = baseInput();
    in.split_lab = true;
    in.kernel_available = false;
    const d = a.evaluate(in);
    try t.expectEqual(Mode.npcap_primary, d.mode);
    try t.expect(!d.kernel_may_submit);
}

test "mode and reason names are stable for the control plane" {
    try t.expectEqualStrings("npcap_primary", modeName(@intFromEnum(Mode.npcap_primary)));
    try t.expectEqualStrings("kernel_fallback", modeName(@intFromEnum(Mode.kernel_fallback)));
    try t.expectEqualStrings("undecided", modeName(200));
    try t.expectEqualStrings("nose_stalled", reasonName(@intFromEnum(Reason.nose_stalled)));
    try t.expectEqualStrings("none", reasonName(0));
}
