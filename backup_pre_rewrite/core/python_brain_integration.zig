//! python_brain_integration.zig - AEGIS Python Brain Integration (STEP 20)
//!
//! Wires the Python Tier-2 deep inspection brain with the Zig pipeline.
//! The Python brain is a standalone UDP service (127.0.0.1:9999) that:
//!   - Receives suspicious payloads from Zig Core
//!   - Runs regex-based deep inspection against compiled rule patterns
//!   - Enforces IPS policy via Windows Firewall + C++ Bridge
//!   - Computes DEFCON level from event counts
//!
//! Before STEP 20, Zig pipeline had no structured way to:
//!   - Submit events to Python brain for Tier-2 inspection
//!   - Receive scoring results back
//!   - Query DEFCON level
//!
//! After STEP 20:
//!   - BrainResult: scoring result from Python brain
//!   - submitToBrain(): send payload to Python brain via UDP
//!   - getDefconLevel(): query current DEFCON level (1=critical..5=normal)
//!   - brainDetector(): Detector adapter for DetectionManager (tier2_regex)
//!   - registerBrainDetector(): register as tier2_regex detector
//!   - Stub implementations (test mode — no Python service running)
//!
//! Architecture:
//!   Zig pipeline (STEP 6) -> DetectionManager
//!     -> Detector.scan_fn (brainDetector) -> UDP to Python brain (:9999)
//!       -> regex deep inspection -> BrainResult
//!         -> verdict based on score + DEFCON level

const std = @import("std");
const canonical = @import("canonical_event.zig");
const detection = @import("detection_interface.zig");

// ============================================================
// STEP 20: Brain result types
// ============================================================

pub const DefconLevel = enum(u8) {
    defcon1 = 1, // Critical — imminent attack
    defcon2 = 2, // High — multiple blocks
    defcon3 = 3, // Medium — multiple matches
    defcon4 = 4, // Low — single match
    defcon5 = 5, // Normal — no threats

    pub fn toString(self: DefconLevel) []const u8 {
        return switch (self) {
            .defcon1 => "DEFCON 1 (Critical)",
            .defcon2 => "DEFCON 2 (High)",
            .defcon3 => "DEFCON 3 (Medium)",
            .defcon4 => "DEFCON 4 (Low)",
            .defcon5 => "DEFCON 5 (Normal)",
        };
    }

    pub fn isCritical(self: DefconLevel) bool {
        return self == .defcon1;
    }

    pub fn fromCounts(critical: u32, blocked: u32, matched: u32, forwarded: u32) DefconLevel {
        if (critical >= 1) return .defcon1;
        if (blocked >= 3) return .defcon2;
        if (matched >= 10) return .defcon3;
        if (matched >= 1) return .defcon4;
        _ = forwarded;
        return .defcon5;
    }
};

pub const BrainResult = struct {
    matched: bool,
    rule_id: u32,
    rule_name: []const u8,
    severity: u8, // 0-3
    score: i32, // 0-100, -1 = error
    defcon: DefconLevel,
    pattern_index: i32, // -1 if no match
};

// ============================================================
// STEP 20: Integration state
// ============================================================

const DEFAULT_BRAIN_HOST = "127.0.0.1";
const DEFAULT_BRAIN_PORT: u16 = 9999;

var g_initialized: bool = false;
var g_brain_host: []const u8 = DEFAULT_BRAIN_HOST;
var g_brain_port: u16 = DEFAULT_BRAIN_PORT;
var g_defcon: DefconLevel = .defcon5;
var g_total_submissions: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var g_total_matches: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var g_total_blocks: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var g_total_errors: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

// Stub counters (for DEFCON computation)
var g_stub_critical: u32 = 0;
var g_stub_blocked: u32 = 0;
var g_stub_matched: u32 = 0;

// ============================================================
// Initialization
// ============================================================

pub fn init(host: []const u8, port: u16) void {
    if (g_initialized) return;
    g_brain_host = if (host.len > 0) host else DEFAULT_BRAIN_HOST;
    g_brain_port = if (port > 0) port else DEFAULT_BRAIN_PORT;
    g_initialized = true;
    g_defcon = .defcon5;
    g_total_submissions.store(0, .monotonic);
    g_total_matches.store(0, .monotonic);
    g_total_blocks.store(0, .monotonic);
    g_total_errors.store(0, .monotonic);
    g_stub_critical = 0;
    g_stub_blocked = 0;
    g_stub_matched = 0;
    std.log.info("[PY-BRAIN] Python brain integration initialized (host={s}:{d})", .{ g_brain_host, g_brain_port });
}

pub fn shutdown() void {
    if (!g_initialized) return;
    g_initialized = false;
    std.log.info("[PY-BRAIN] Python brain integration shutdown (submissions={d} matches={d} blocks={d})", .{
        g_total_submissions.load(.monotonic),
        g_total_matches.load(.monotonic),
        g_total_blocks.load(.monotonic),
    });
}

pub fn isInitialized() bool {
    return g_initialized;
}

pub fn resetStats() void {
    g_total_submissions.store(0, .monotonic);
    g_total_matches.store(0, .monotonic);
    g_total_blocks.store(0, .monotonic);
    g_total_errors.store(0, .monotonic);
    g_stub_critical = 0;
    g_stub_blocked = 0;
    g_stub_matched = 0;
    g_defcon = .defcon5;
}

// ============================================================
// STEP 20: Stub brain inspection (test mode)
// ============================================================

/// Stub brain inspection — simulates Python brain regex matching.
/// In production: sends payload via UDP to Python brain, receives BrainResult.
/// In test mode: checks payload for known patterns.
fn stubBrainInspect(payload: []const u8, ctx: *const canonical.CanonicalEvent) BrainResult {
    // Simulate pattern matching (Python brain does regex)
    if (std.mem.indexOf(u8, payload, "malware") != null) {
        g_stub_critical += 1;
        g_defcon = DefconLevel.fromCounts(g_stub_critical, g_stub_blocked, g_stub_matched, 0);
        return .{
            .matched = true,
            .rule_id = 100,
            .rule_name = "PYTHON_MALWARE",
            .severity = 3,
            .score = 100,
            .defcon = g_defcon,
            .pattern_index = 0,
        };
    }
    if (std.mem.indexOf(u8, payload, "suspicious") != null) {
        g_stub_matched += 1;
        g_defcon = DefconLevel.fromCounts(g_stub_critical, g_stub_blocked, g_stub_matched, 0);
        return .{
            .matched = true,
            .rule_id = 200,
            .rule_name = "PYTHON_SUSPICIOUS",
            .severity = 2,
            .score = 75,
            .defcon = g_defcon,
            .pattern_index = 1,
        };
    }
    if (std.mem.indexOf(u8, payload, "scan") != null) {
        g_stub_matched += 1;
        g_defcon = DefconLevel.fromCounts(g_stub_critical, g_stub_blocked, g_stub_matched, 0);
        return .{
            .matched = true,
            .rule_id = 300,
            .rule_name = "PYTHON_SCAN",
            .severity = 1,
            .score = 50,
            .defcon = g_defcon,
            .pattern_index = 2,
        };
    }

    // Check context for threat intel (simulate brain using RAG enrichment)
    if (ctx.context_flags & 0x01 != 0) {
        // threat_intel_match — brain escalates
        g_stub_matched += 1;
        g_defcon = DefconLevel.fromCounts(g_stub_critical, g_stub_blocked, g_stub_matched, 0);
        return .{
            .matched = true,
            .rule_id = 400,
            .rule_name = "PYTHON_THREAT_INTEL",
            .severity = 2,
            .score = 60,
            .defcon = g_defcon,
            .pattern_index = 3,
        };
    }

    return .{
        .matched = false,
        .rule_id = 0,
        .rule_name = "",
        .severity = 0,
        .score = 0,
        .defcon = g_defcon,
        .pattern_index = -1,
    };
}

// ============================================================
// STEP 20: Public API — submit to brain + query DEFCON
// ============================================================

/// Submit payload to Python brain for Tier-2 deep inspection.
/// In production: sends UDP packet to 127.0.0.1:9999.
/// In test mode: uses stub pattern matcher.
pub fn submitToBrain(payload: []const u8, ctx: *const canonical.CanonicalEvent) BrainResult {
    if (!g_initialized) {
        return .{
            .matched = false,
            .rule_id = 0,
            .rule_name = "",
            .severity = 0,
            .score = -1,
            .defcon = .defcon5,
            .pattern_index = -1,
        };
    }

    g_total_submissions.store(g_total_submissions.load(.monotonic) + 1, .monotonic);

    const result = stubBrainInspect(payload, ctx);

    if (result.matched) {
        g_total_matches.store(g_total_matches.load(.monotonic) + 1, .monotonic);
        if (result.severity >= 3) {
            g_total_blocks.store(g_total_blocks.load(.monotonic) + 1, .monotonic);
            g_stub_blocked += 1;
        }
    }

    // Recompute DEFCON
    g_defcon = DefconLevel.fromCounts(g_stub_critical, g_stub_blocked, g_stub_matched, 0);

    return result;
}

/// Get current DEFCON level from Python brain.
pub fn getDefconLevel() DefconLevel {
    if (!g_initialized) return .defcon5;
    return g_defcon;
}

/// Get DEFCON level as numeric (1-5).
pub fn getDefconNumeric() u8 {
    return @intFromEnum(getDefconLevel());
}

/// Force DEFCON level (for testing or manual override).
pub fn setDefconLevel(level: DefconLevel) void {
    if (!g_initialized) return;
    g_defcon = level;
}

// ============================================================
// STEP 20: Brain detector — adapter for DetectionManager (STEP 6)
// ============================================================

/// Brain detector scan function.
/// Implements the Detector.scan_fn signature from detection_interface.zig.
/// Calls Python brain (stub) for Tier-2 regex inspection.
///
/// Verdict logic:
///   - score >= 100 (malware) -> match_block
///   - score >= 50 (suspicious/scan/threat_intel) -> match_alert
///   - score < 50 -> no_match
///   - DEFCON 1 -> always match_block (override)
pub fn brainDetector(payload: []const u8, ctx: *const canonical.CanonicalEvent) detection.DetectionResult {
    if (!g_initialized) return detection.DetectionResult.noMatch();

    const result = submitToBrain(payload, ctx);

    if (!result.matched) {
        // Check DEFCON override — if DEFCON 1, escalate even no-match
        if (g_defcon.isCritical()) {
            return .{
                .verdict = .match_block,
                .rule_id = 5000,
                .rule_hash = 0xDEFC0DE1,
                .severity = 3,
                .rule_name = "PYTHON_DEFCON1_OVERRIDE",
                .ruleset_version = 1,
            };
        }
        return detection.DetectionResult.noMatch();
    }

    // DEFCON 1 override — always block
    if (g_defcon.isCritical()) {
        return .{
            .verdict = .match_block,
            .rule_id = result.rule_id,
            .rule_hash = 0xDEFC0DE2,
            .severity = @max(result.severity, 3),
            .rule_name = result.rule_name,
            .ruleset_version = 1,
        };
    }

    // Score-based verdict
    if (result.score >= 100) {
        return .{
            .verdict = .match_block,
            .rule_id = result.rule_id,
            .rule_hash = 0xABCD1001,
            .severity = 3,
            .rule_name = result.rule_name,
            .ruleset_version = 1,
        };
    }

    if (result.score >= 50) {
        return .{
            .verdict = .match_alert,
            .rule_id = result.rule_id,
            .rule_hash = 0xABCD1002,
            .severity = @max(result.severity, 2),
            .rule_name = result.rule_name,
            .ruleset_version = 1,
        };
    }

    return detection.DetectionResult.noMatch();
}

/// Register the brain detector with a DetectionManager.
pub fn registerBrainDetector(dm: *detection.DetectionManager) bool {
    if (!g_initialized) return false;
    return dm.register(.{
        .name = "Python Brain (Tier-2)",
        .detector_type = .tier2_regex,
        .is_active = true,
        .scan_fn = &brainDetector,
    });
}

// ============================================================
// STEP 20: Stats
// ============================================================

pub const BrainStats = struct {
    initialized: bool,
    defcon: DefconLevel,
    defcon_numeric: u8,
    total_submissions: u64,
    total_matches: u64,
    total_blocks: u64,
    total_errors: u64,
    stub_critical: u32,
    stub_blocked: u32,
    stub_matched: u32,
};

pub fn getStats() BrainStats {
    if (!g_initialized) {
        return .{
            .initialized = false,
            .defcon = .defcon5,
            .defcon_numeric = 5,
            .total_submissions = 0,
            .total_matches = 0,
            .total_blocks = 0,
            .total_errors = 0,
            .stub_critical = 0,
            .stub_blocked = 0,
            .stub_matched = 0,
        };
    }
    return .{
        .initialized = true,
        .defcon = g_defcon,
        .defcon_numeric = @intFromEnum(g_defcon),
        .total_submissions = g_total_submissions.load(.monotonic),
        .total_matches = g_total_matches.load(.monotonic),
        .total_blocks = g_total_blocks.load(.monotonic),
        .total_errors = g_total_errors.load(.monotonic),
        .stub_critical = g_stub_critical,
        .stub_blocked = g_stub_blocked,
        .stub_matched = g_stub_matched,
    };
}

// ============================================================
// Tests
// ============================================================

test "DefconLevel.toString returns readable names" {
    try std.testing.expect(std.mem.eql(u8, DefconLevel.defcon1.toString(), "DEFCON 1 (Critical)"));
    try std.testing.expect(std.mem.eql(u8, DefconLevel.defcon5.toString(), "DEFCON 5 (Normal)"));
}

test "DefconLevel.isCritical returns true only for defcon1" {
    try std.testing.expect(DefconLevel.defcon1.isCritical());
    try std.testing.expect(!DefconLevel.defcon2.isCritical());
    try std.testing.expect(!DefconLevel.defcon5.isCritical());
}

test "DefconLevel.fromCounts computes correctly" {
    try std.testing.expect(DefconLevel.fromCounts(1, 0, 0, 0) == .defcon1);
    try std.testing.expect(DefconLevel.fromCounts(0, 3, 0, 0) == .defcon2);
    try std.testing.expect(DefconLevel.fromCounts(0, 0, 10, 0) == .defcon3);
    try std.testing.expect(DefconLevel.fromCounts(0, 0, 1, 0) == .defcon4);
    try std.testing.expect(DefconLevel.fromCounts(0, 0, 0, 0) == .defcon5);
}

test "BrainResult is a value type" {
    const r = BrainResult{
        .matched = true,
        .rule_id = 100,
        .rule_name = "test",
        .severity = 3,
        .score = 100,
        .defcon = .defcon1,
        .pattern_index = 0,
    };
    const copy = r;
    try std.testing.expect(copy.matched);
    try std.testing.expect(copy.score == 100);
}

test "init and shutdown lifecycle" {
    init("127.0.0.1", 9999);
    defer shutdown();
    try std.testing.expect(isInitialized());

    const stats = getStats();
    try std.testing.expect(stats.initialized);
    try std.testing.expect(stats.defcon == .defcon5);
}

test "submitToBrain detects malware payload" {
    init("127.0.0.1", 9999);
    defer shutdown();
    resetStats();

    var event = canonical.create(.zig_core);
    const result = submitToBrain("this contains malware signature", &event);

    try std.testing.expect(result.matched);
    try std.testing.expect(result.severity == 3);
    try std.testing.expect(result.score == 100);
    try std.testing.expect(result.defcon == .defcon1); // critical count = 1

    const stats = getStats();
    try std.testing.expect(stats.total_submissions == 1);
    try std.testing.expect(stats.total_matches == 1);
    try std.testing.expect(stats.total_blocks == 1);
}

test "submitToBrain detects suspicious payload" {
    init("127.0.0.1", 9999);
    defer shutdown();
    resetStats();

    var event = canonical.create(.zig_core);
    const result = submitToBrain("suspicious activity detected", &event);

    try std.testing.expect(result.matched);
    try std.testing.expect(result.severity == 2);
    try std.testing.expect(result.score == 75);
    try std.testing.expect(result.defcon == .defcon4); // matched count = 1
}

test "submitToBrain detects scan payload" {
    init("127.0.0.1", 9999);
    defer shutdown();
    resetStats();

    var event = canonical.create(.zig_core);
    const result = submitToBrain("port scan in progress", &event);

    try std.testing.expect(result.matched);
    try std.testing.expect(result.severity == 1);
    try std.testing.expect(result.score == 50);
}

test "submitToBrain returns no match for benign payload" {
    init("127.0.0.1", 9999);
    defer shutdown();
    resetStats();

    var event = canonical.create(.zig_core);
    const result = submitToBrain("normal traffic data", &event);

    try std.testing.expect(!result.matched);
    try std.testing.expect(result.score == 0);

    const stats = getStats();
    try std.testing.expect(stats.total_matches == 0);
}

test "submitToBrain uses threat intel from context_flags" {
    init("127.0.0.1", 9999);
    defer shutdown();
    resetStats();

    var event = canonical.create(.wfp_sensor);
    event.context_flags = 0x01; // threat_intel_match

    const result = submitToBrain("unknown payload", &event);
    try std.testing.expect(result.matched);
    try std.testing.expect(result.rule_name.len > 0);
    try std.testing.expect(result.severity == 2);
}

test "DEFCON escalates with multiple matches" {
    init("127.0.0.1", 9999);
    defer shutdown();
    resetStats();

    var event = canonical.create(.zig_core);

    // 1 match -> DEFCON 4
    _ = submitToBrain("scan", &event);
    try std.testing.expect(getDefconLevel() == .defcon4);

    // 10 matches -> DEFCON 3
    var i: u32 = 1;
    while (i < 10) : (i += 1) {
        _ = submitToBrain("scan", &event);
    }
    try std.testing.expect(getDefconLevel() == .defcon3);

    // 1 critical -> DEFCON 1
    _ = submitToBrain("malware", &event);
    try std.testing.expect(getDefconLevel() == .defcon1);
}

test "brainDetector returns block for malware" {
    init("127.0.0.1", 9999);
    defer shutdown();
    resetStats();

    var event = canonical.create(.zig_core);
    const result = brainDetector("contains malware", &event);

    try std.testing.expect(result.verdict == .match_block);
    try std.testing.expect(result.severity == 3);
}

test "brainDetector returns alert for suspicious" {
    init("127.0.0.1", 9999);
    defer shutdown();
    resetStats();

    var event = canonical.create(.zig_core);
    const result = brainDetector("suspicious data", &event);

    try std.testing.expect(result.verdict == .match_alert);
    try std.testing.expect(result.severity >= 2);
}

test "brainDetector returns no_match for benign" {
    init("127.0.0.1", 9999);
    defer shutdown();
    resetStats();

    var event = canonical.create(.zig_core);
    const result = brainDetector("normal traffic", &event);

    try std.testing.expect(result.verdict == .no_match);
}

test "brainDetector DEFCON 1 override blocks even benign" {
    init("127.0.0.1", 9999);
    defer shutdown();
    resetStats();

    // Trigger DEFCON 1
    var event = canonical.create(.zig_core);
    _ = submitToBrain("malware", &event);
    try std.testing.expect(getDefconLevel() == .defcon1);

    // Even benign payload should block under DEFCON 1
    const result = brainDetector("normal traffic", &event);
    try std.testing.expect(result.verdict == .match_block);
}

test "registerBrainDetector adds to DetectionManager" {
    init("127.0.0.1", 9999);
    defer shutdown();

    var dm = detection.DetectionManager.init();
    try std.testing.expect(registerBrainDetector(&dm));
    try std.testing.expect(dm.count == 1);
}

test "STEP20: full detection flow with brain detector" {
    init("127.0.0.1", 9999);
    defer shutdown();
    resetStats();

    var dm = detection.DetectionManager.init();
    _ = registerBrainDetector(&dm);

    var event = canonical.create(.wfp_sensor);
    event.event_type = .block;
    event.severity = 0;

    const result = dm.detect("contains malware signature", &event);
    try std.testing.expect(result.verdict == .match_block);

    const stats = getStats();
    try std.testing.expect(stats.total_submissions == 1);
    try std.testing.expect(stats.total_matches == 1);
    try std.testing.expect(stats.defcon == .defcon1);
}

test "getStats returns full brain state" {
    init("127.0.0.1", 9999);
    defer shutdown();
    resetStats();

    var event = canonical.create(.zig_core);
    _ = submitToBrain("malware", &event);
    _ = submitToBrain("scan", &event);

    const stats = getStats();
    try std.testing.expect(stats.initialized);
    try std.testing.expect(stats.total_submissions == 2);
    try std.testing.expect(stats.total_matches == 2);
    try std.testing.expect(stats.defcon == .defcon1); // critical = 1
}

test "setDefconLevel allows manual override" {
    init("127.0.0.1", 9999);
    defer shutdown();

    setDefconLevel(.defcon2);
    try std.testing.expect(getDefconLevel() == .defcon2);
    try std.testing.expect(getDefconNumeric() == 2);
}
