//! ============================================================
//! AEGIS NIDS - Phase 36: ML Detector Demo / Verification CLI
//! ============================================================
//! Runs the flow-anomaly detector end-to-end WITHOUT Npcap:
//! builds synthetic CanonicalEvent windows (the frozen Phase 32
//! contract), feeds them through MlDetector + your trained
//! ml_model.json, and checks 5 scenario verdicts.
//!
//! Usage:
//!   ml_test_cli.exe help
//!   ml_test_cli.exe model  models\ml_model.json   (print model summary)
//!   ml_test_cli.exe demo   models\ml_model.json   (run 5 scenarios + PASS/FAIL)
//!
//! Build:
//!   zig build-exe ml_test_cli.zig -lc
//!   (ml_detector.zig must sit next to this file)
//!
//! Exit code: demo returns 0 iff ALL scenarios match expectations.
//! ============================================================

const std = @import("std");
const ml = @import("ml_detector.zig");

const SRC = [4]u8{ 192, 168, 1, 41 }; // sensor host (Killer Wi-Fi in field tests)
const GW = [4]u8{ 192, 168, 1, 1 };
const EVIL = [4]u8{ 45, 33, 20, 161 };
const T0: i64 = 1_757_000_000_000_000_000; // fixed epoch for determinism

const USAGE =
    \\AEGIS NIDS Phase 36 - ML flow anomaly detector CLI
    \\
    \\Usage:
    \\  ml_test_cli.exe help
    \\  ml_test_cli.exe model  <model.json>   Print model summary
    \\  ml_test_cli.exe demo   <model.json>   Run 5 verification scenarios
    \\
    \\Examples:
    \\  ml_test_cli.exe model  models\ml_model.json
    \\  ml_test_cli.exe demo   models\ml_model.json
    \\
;

fn loadModelFile(alloc: std.mem.Allocator, path: []const u8) ![]u8 {
    return std.fs.cwd().readFileAlloc(alloc, path, 1 << 20);
}

fn printModel(alloc: std.mem.Allocator, path: []const u8) !void {
    const bytes = try loadModelFile(alloc, path);
    defer alloc.free(bytes);

    var det = ml.MlDetector.init(alloc, .{ .enabled = true });
    defer det.deinit();
    try det.loadModelJson(bytes);
    const m = det.modelInfo().?;

    const w = std.io.getStdOut().writer();
    try w.print("model file     : {s}\n", .{path});
    try w.print("name           : {s} (version {d})\n", .{ m.name, m.version });
    try w.print("trained_at     : {s}\n", .{m.trained_at});
    try w.print("threshold      : {d:.2}\n", .{m.confidence_threshold});
    try w.print("test metrics   : acc={d:.3} precision={d:.3} recall={d:.3} f1={d:.3} (n={d})\n", .{
        m.metrics.accuracy, m.metrics.precision, m.metrics.recall, m.metrics.f1, m.metrics.samples,
    });
    try w.print("bias           : {d:.4}\n", .{m.bias});
    try w.print("features       :\n", .{});
    for (ml.FEATURE_NAMES, 0..) |fname, i| {
        try w.print("  {d}. {s:<18} w={s}{d:7.3}  mean={d:>12.3}  std={d:>10.3}\n", .{
            i + 1,
            fname,
            if (m.weights[i] >= 0) "+" else "-",
            @abs(m.weights[i]),
            m.mean[i],
            m.std[i],
        });
    }
}

// ------------------------------------------------------------
// Scenario event builders (10 s classification windows)
// ------------------------------------------------------------

fn scenarioBrowsing(det: *ml.MlDetector) void {
    // 60 data packets over 10 s, 2 dst ports, 6 handshakes, 400 B payload.
    var i: u16 = 0;
    while (i < 60) : (i += 1) {
        const flags: u8 = if (i % 10 == 0) ml.TCP_SYN | ml.TCP_ACK else ml.TCP_ACK | ml.TCP_PSH;
        const dir: ml.CanonicalEvent.Direction = if (i % 2 == 0) .outbound else .inbound;
        det.observe(.{
            .timestamp_ns = T0 + @as(i64, i) * 166_666_666,
            .src_ip = if (i % 2 == 0) SRC else GW,
            .dst_ip = if (i % 2 == 0) GW else SRC,
            .src_port = 63000 + i,
            .dst_port = if (i % 3 == 0) 443 else 80,
            .protocol = 6,
            .tcp_flags = flags,
            .payload_len = 400,
            .direction = dir,
        });
    }
}

fn scenarioPortScan(det: *ml.MlDetector) void {
    // 50 SYN probes to 50 distinct ports, no payload, single attacker.
    var port: u16 = 20;
    var i: u16 = 0;
    while (port < 70) : ({
        port += 1;
        i += 1;
    }) {
        det.observe(.{
            .timestamp_ns = T0 + @as(i64, i) * 100_000_000,
            .src_ip = EVIL,
            .dst_ip = SRC,
            .src_port = 40000 + i,
            .dst_port = port,
            .protocol = 6,
            .tcp_flags = ml.TCP_SYN,
            .payload_len = 0,
            .direction = .inbound,
        });
    }
}

fn scenarioSynFlood(det: *ml.MlDetector) void {
    // 300 bare SYNs at port 80 within 3 s (~100 pps).
    var i: u16 = 0;
    while (i < 300) : (i += 1) {
        det.observe(.{
            .timestamp_ns = T0 + @as(i64, i) * 10_000_000,
            .src_ip = EVIL,
            .dst_ip = SRC,
            .src_port = 20000 + i,
            .dst_port = 80,
            .protocol = 6,
            .tcp_flags = ml.TCP_SYN,
            .payload_len = 0,
            .direction = .inbound,
        });
    }
}

fn scenarioRstSweep(det: *ml.MlDetector) void {
    // 20 RST|ACK responses across 20 ports (closed-port sweep echo).
    var i: u16 = 0;
    while (i < 20) : (i += 1) {
        det.observe(.{
            .timestamp_ns = T0 + @as(i64, i) * 400_000_000,
            .src_ip = EVIL,
            .dst_ip = SRC,
            .src_port = 8080,
            .dst_port = 1000 + i,
            .protocol = 6,
            .tcp_flags = ml.TCP_RST | ml.TCP_ACK,
            .payload_len = 0,
            .direction = .inbound,
        });
    }
}

const Expected = enum { benign, malicious, not_benign, disabled };

const ScenarioResult = struct {
    name: []const u8,
    expected: Expected,
    verdict: ml.Verdict,
    pkts: u64,
    pps: f64,
    ports: usize,
};

fn runScenario(
    alloc: std.mem.Allocator,
    model_bytes: []const u8,
    observeFn: *const fn (*ml.MlDetector) void,
    name: []const u8,
    expected: Expected,
) ScenarioResult {
    var det = ml.MlDetector.init(alloc, .{
        .enabled = true,
        .window_secs = 10.0,
        .confidence_threshold = 0.70,
        .min_baseline_samples = 5,
    });
    defer det.deinit();
    det.loadModelJson(model_bytes) catch {};
    observeFn(&det);
    const pkts = det.window.pkts;
    const feats = det.window.finalize();
    const v = det.flushWindow() orelse ml.Verdict{ .label = .disabled };
    return .{
        .name = name,
        .expected = expected,
        .verdict = v,
        .pkts = pkts,
        .pps = feats.pkts_per_sec,
        .ports = @intFromFloat(feats.unique_dst_ports),
    };
}

fn printResult(res: ScenarioResult) !bool {
    const w = std.io.getStdOut().writer();
    const ok = switch (res.expected) {
        .benign => res.verdict.label == .benign,
        .malicious => res.verdict.label == .malicious,
        .not_benign => res.verdict.label != .benign,
        .disabled => res.verdict.label == .disabled,
    };
    try w.print("{s:<18} pkts={d:<4} pps={d:>6.1} ports={d:<3} score={d:.3} z={s}{d:.1} -> {s}\n", .{
        res.name,
        res.pkts,
        res.pps,
        res.ports,
        res.verdict.score,
        if (res.verdict.baseline_z >= 0) "+" else "-",
        @abs(res.verdict.baseline_z),
        res.verdict.label.name(),
    });
    var i: usize = 0;
    while (i < res.verdict.reason_count) : (i += 1) {
        try w.print("    - {s}\n", .{res.verdict.reason(i)});
    }
    try w.print("    expected {s}: {s}\n", .{
        @tagName(res.expected),
        if (ok) "PASS" else "FAIL",
    });
    return ok;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();
    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    const w = std.io.getStdOut().writer();

    if (args.len < 2) {
        try w.print("{s}", .{USAGE});
        return;
    }

    const mode = args[1];
    if (std.mem.eql(u8, mode, "help") or std.mem.eql(u8, mode, "--help") or std.mem.eql(u8, mode, "-h")) {
        try w.print("{s}", .{USAGE});
        return;
    }

    const model_path: ?[]const u8 = if (args.len >= 3) args[2] else null;

    if (std.mem.eql(u8, mode, "model")) {
        const p = model_path orelse {
            try w.print("[ERR] model mode requires a path\n{s}", .{USAGE});
            std.process.exit(2);
        };
        try printModel(alloc, p);
        return;
    }

    if (!std.mem.eql(u8, mode, "demo")) {
        try w.print("[ERR] unknown mode '{s}'\n{s}", .{ mode, USAGE });
        std.process.exit(2);
    }

    const p = model_path orelse {
        try w.print("[ERR] demo mode requires a model path\n{s}", .{USAGE});
        std.process.exit(2);
    };
    const model_bytes = loadModelFile(alloc, p) catch |e| {
        try w.print("[ERR] cannot read model '{s}': {s}\n", .{ p, @errorName(e) });
        std.process.exit(2);
    };
    defer alloc.free(model_bytes);

    try w.print("AEGIS NIDS Phase 36 - ML demo (model: {s})\n", .{p});
    try w.print("------------------------------------------------------------\n", .{});

    var pass: usize = 0;

    // Kill-switch scenario: even a flood must be IGNORED when disabled.
    {
        var det = ml.MlDetector.init(alloc, .{ .enabled = false });
        defer det.deinit();
        det.loadModelJson(model_bytes) catch {};
        scenarioSynFlood(&det);
        const v = det.flushWindow() orelse ml.Verdict{ .label = .disabled };
        const r = ScenarioResult{
            .name = "kill-switch-off",
            .expected = .disabled,
            .verdict = v,
            .pkts = 0,
            .pps = 0,
            .ports = 0,
        };
        if (try printResult(r)) pass += 1;
    }

    const scenarios = [_]struct {
        observe: *const fn (*ml.MlDetector) void,
        name: []const u8,
        expected: Expected,
    }{
        .{ .observe = scenarioBrowsing, .name = "normal-browsing", .expected = .benign },
        .{ .observe = scenarioPortScan, .name = "port-scan-50", .expected = .malicious },
        .{ .observe = scenarioSynFlood, .name = "syn-flood-300", .expected = .malicious },
        .{ .observe = scenarioRstSweep, .name = "rst-sweep-20", .expected = .not_benign },
    };
    for (scenarios) |sc| {
        const r = runScenario(alloc, model_bytes, sc.observe, sc.name, sc.expected);
        if (try printResult(r)) pass += 1;
    }

    try w.print("------------------------------------------------------------\n", .{});
    try w.print("RESULT: {d}/5 scenarios matched expectations\n", .{pass});
    if (pass == 5) {
        try w.print("[OK] ML detector verdict chain verified (kill switch, model, signatures)\n", .{});
    } else {
        try w.print("[FAIL] unexpected verdicts above - inspect scores/reasons\n", .{});
        std.process.exit(1);
    }
}
