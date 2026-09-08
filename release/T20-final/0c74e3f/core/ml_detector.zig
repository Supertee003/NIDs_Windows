//! ============================================================
//! AEGIS NIDS - Phase 36: ML/AI Flow Anomaly Detection
//! ============================================================
//! Pure-Zig ML inference engine for flow-based anomaly detection.
//!
//! Design (DevSecOps Tier 4, risk HIGH -> mitigations):
//!   * KILL SWITCH: MlConfig.enabled = false by default. Detector
//!     is fully additive; enforcement stays in the WFP driver.
//!   * Deterministic inference: logistic regression over 8
//!     standardized flow features (no hidden state, no RNG).
//!   * Behavioral baseline: EWMA mean/variance of packet rate per
//!     source IP with configurable sigma gate (min sample count).
//!   * Explainable verdicts: every decision carries human-readable
//!     reasons (model score, port-scan pattern, SYN flood pattern,
//!     baseline deviation).
//!   * Model is OFFLINE-trained by scripts/ml_train.py and loaded
//!     from JSON at runtime (weights + bias + mean/std + metrics).
//!   * Integrates with the frozen Phase 32 CanonicalEvent contract
//!     (npcap_capture.zig). No Npcap dependency here: all logic is
//!     testable on any host.
//!
//! Verdict policy (label selection):
//!   malicious  : model score >= confidence_threshold
//!                OR unique dst ports >= 40 (hard scan signature)
//!                OR SYN-flood signature (syn_ratio >= 0.8 at
//!                   >= 50 pps)
//!                OR baseline z >= 2x sigma_mult AND score >= 0.5
//!   suspicious : score >= 0.5 x confidence_threshold
//!                OR unique dst ports >= 20
//!                OR RST ratio >= 0.5
//!                OR baseline z >= sigma_mult
//!   benign     : otherwise
//!   disabled   : kill switch OFF (no scoring at all)
//!
//! Usage sketch:
//!   var det = ml_detector.MlDetector.init(alloc, .{ .enabled = true });
//!   try det.loadModelJson(model_json_bytes);
//!   for (events) |ev| det.observe(ev);        // accumulates window
//!   if (det.flushWindow()) |v| handle(v);     // score + baseline update
//!
//! Zig 0.13.0 - zig test ml_detector.zig (26 unit tests, no deps).
//! ============================================================

const std = @import("std");

// ============================================================
// Configuration (kill switch lives here)
// ============================================================

pub const MlConfig = struct {
    /// KILL SWITCH. Default OFF: detector returns .disabled verdicts
    /// and updates no baselines until explicitly enabled.
    enabled: bool = false,
    /// Model probability at/above which a window is malicious.
    confidence_threshold: f64 = 0.70,
    /// Baseline sigma multiplier for rate-deviation suspiciousness.
    baseline_sigma_mult: f64 = 3.0,
    /// EWMA smoothing factor for per-source rate baseline.
    ewma_alpha: f64 = 0.15,
    /// Baseline needs this many samples before z-scores are trusted.
    min_baseline_samples: u32 = 20,
    /// Scoring window length in seconds (rollover policy).
    window_secs: f64 = 10.0,
    /// Maximum distinct source IPs tracked in the baseline store.
    /// When full, new sources are ignored until resetBaselines().
    max_keys: usize = 4096,
};

// ============================================================
// TCP flag bits (subset used for features)
// ============================================================

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

// ============================================================
// Feature vector - 8 standardized flow features
// ============================================================

pub const FEATURE_NAMES = [FEATURE_COUNT][]const u8{
    "pkts_per_sec",
    "bytes_per_sec",
    "syn_ratio",
    "rst_ratio",
    "unique_dst_ports",
    "unique_dst_ips",
    "inbound_ratio",
    "mean_payload_len",
};
pub const FEATURE_COUNT: usize = 8;

pub const Features = struct {
    pkts_per_sec: f64 = 0,
    bytes_per_sec: f64 = 0,
    syn_ratio: f64 = 0,
    rst_ratio: f64 = 0,
    unique_dst_ports: f64 = 0,
    unique_dst_ips: f64 = 0,
    inbound_ratio: f64 = 0,
    mean_payload_len: f64 = 0,

    pub fn toArray(self: Features) [FEATURE_COUNT]f64 {
        return .{
            self.pkts_per_sec,
            self.bytes_per_sec,
            self.syn_ratio,
            self.rst_ratio,
            self.unique_dst_ports,
            self.unique_dst_ips,
            self.inbound_ratio,
            self.mean_payload_len,
        };
    }
};

/// Logistic function with input clamping for f64 safety.
pub fn sigmoid(x: f64) f64 {
    const clamped = @max(-30.0, @min(30.0, x));
    return 1.0 / (1.0 + std.math.exp(-clamped));
}

/// Standardize x with model mean/std (std guarded against zero).
pub fn standardize(x: f64, mean: f64, stdv: f64) f64 {
    const safe_std = if (stdv < 1e-9) 1.0 else stdv;
    return (x - mean) / safe_std;
}

// ============================================================
// Fixed-capacity dedup sets (deterministic, no allocator)
// ============================================================

pub const PortSet = struct {
    const CAP: usize = 64;
    items: [CAP]u16 = [_]u16{0} ** CAP,
    len: usize = 0,
    saturated: bool = false,

    pub fn add(self: *PortSet, v: u16) void {
        if (v == 0) return;
        var i: usize = 0;
        while (i < self.len) : (i += 1) {
            if (self.items[i] == v) return;
        }
        if (self.len >= CAP) {
            self.saturated = true;
            return;
        }
        self.items[self.len] = v;
        self.len += 1;
    }

    /// Reported count saturates at CAP (a documented lower bound).
    pub fn count(self: *const PortSet) usize {
        return self.len;
    }

    pub fn contains(self: *const PortSet, v: u16) bool {
        var i: usize = 0;
        while (i < self.len) : (i += 1) {
            if (self.items[i] == v) return true;
        }
        return false;
    }
};

pub const IpSet = struct {
    const CAP: usize = 64;
    items: [CAP][4]u8 = [_][4]u8{[_]u8{0} ** 4} ** CAP,
    len: usize = 0,
    saturated: bool = false,

    pub fn add(self: *IpSet, ip: [4]u8) void {
        if (isZeroIp(ip)) return;
        var i: usize = 0;
        while (i < self.len) : (i += 1) {
            if (std.mem.eql(u8, &self.items[i], &ip)) return;
        }
        if (self.len >= CAP) {
            self.saturated = true;
            return;
        }
        self.items[self.len] = ip;
        self.len += 1;
    }

    pub fn count(self: *const IpSet) usize {
        return self.len;
    }
};

// ============================================================
// Flow window - accumulates CanonicalEvents into Features
// ============================================================

/// Minimal event shape matching the frozen Phase 32 CanonicalEvent
/// contract (npcap_capture.zig). Kept as a local mirror so this
/// module has zero imports beyond std.
pub const CanonicalEvent = struct {
    timestamp_ns: i64 = 0,
    src_ip: [4]u8 = [_]u8{0} ** 4,
    dst_ip: [4]u8 = [_]u8{0} ** 4,
    src_port: u16 = 0,
    dst_port: u16 = 0,
    protocol: u8 = 0, // 6=TCP, 17=UDP, 1=ICMP, 0=non-IP
    tcp_flags: u8 = 0,
    payload_len: u16 = 0,
    direction: Direction = .unknown,

    pub const Direction = enum(u8) {
        unknown = 0,
        inbound = 1,
        outbound = 2,
    };
};

pub const FlowWindow = struct {
    start_ns: i64 = 0,
    end_ns: i64 = 0,
    pkts: u64 = 0,
    bytes: u64 = 0,
    syn_count: u64 = 0,
    ack_count: u64 = 0,
    fin_count: u64 = 0,
    rst_count: u64 = 0,
    tcp_count: u64 = 0,
    inbound_count: u64 = 0,
    payload_sum: u64 = 0,
    ports: PortSet = .{},
    ips: IpSet = .{},
    // Up to 4 candidate primary source keys with hit counts.
    src_keys: [4]u32 = [_]u32{0} ** 4,
    src_key_hits: [4]u64 = [_]u64{0} ** 4,
    src_key_count: usize = 0,

    pub fn reset(self: *FlowWindow) void {
        self.* = .{};
    }

    pub fn isEmpty(self: *const FlowWindow) bool {
        return self.pkts == 0;
    }

    pub fn observe(self: *FlowWindow, ev: CanonicalEvent) void {
        if (self.start_ns == 0) self.start_ns = ev.timestamp_ns;
        if (ev.timestamp_ns > self.end_ns) self.end_ns = ev.timestamp_ns;
        self.pkts += 1;
        self.bytes += ev.payload_len;
        self.payload_sum += ev.payload_len;

        if (ev.protocol == 6) {
            self.tcp_count += 1;
            if (ev.tcp_flags & TCP_SYN != 0) self.syn_count += 1;
            if (ev.tcp_flags & TCP_ACK != 0) self.ack_count += 1;
            if (ev.tcp_flags & TCP_FIN != 0) self.fin_count += 1;
            if (ev.tcp_flags & TCP_RST != 0) self.rst_count += 1;
        }
        if (ev.direction == .inbound) self.inbound_count += 1;

        self.ports.add(ev.dst_port);
        self.ips.add(ev.dst_ip);

        if (!isZeroIp(ev.src_ip)) {
            self.noteSrc(keyFromIp(ev.src_ip));
        }
    }

    fn noteSrc(self: *FlowWindow, key: u32) void {
        var i: usize = 0;
        while (i < self.src_key_count) : (i += 1) {
            if (self.src_keys[i] == key) {
                self.src_key_hits[i] += 1;
                return;
            }
        }
        if (self.src_key_count >= 4) return;
        self.src_keys[self.src_key_count] = key;
        self.src_key_hits[self.src_key_count] = 1;
        self.src_key_count += 1;
    }

    /// Dominant source key of this window (majority by hit count).
    pub fn primarySrcKey(self: *const FlowWindow) u32 {
        var best: usize = 0;
        var i: usize = 1;
        while (i < self.src_key_count) : (i += 1) {
            if (self.src_key_hits[i] > self.src_key_hits[best]) best = i;
        }
        return self.src_keys[best];
    }

    /// Duration seconds, clamped to >= 1.0 to keep rates sane for
    /// sub-second bursts (documented conservative choice).
    pub fn durationSecs(self: *const FlowWindow) f64 {
        if (self.end_ns <= self.start_ns) return 1.0;
        const secs = @as(f64, @floatFromInt(self.end_ns - self.start_ns)) / 1e9;
        return @max(1.0, secs);
    }

    pub fn finalize(self: *const FlowWindow) Features {
        const dur = self.durationSecs();
        const pkts_f: f64 = @floatFromInt(self.pkts);
        const bytes_f: f64 = @floatFromInt(self.bytes);
        const tcp_f: f64 = @floatFromInt(self.tcp_count);
        const syn_f: f64 = @floatFromInt(self.syn_count);
        const rst_f: f64 = @floatFromInt(self.rst_count);
        const in_f: f64 = @floatFromInt(self.inbound_count);
        const pay_f: f64 = @floatFromInt(self.payload_sum);

        return .{
            .pkts_per_sec = pkts_f / dur,
            .bytes_per_sec = bytes_f / dur,
            .syn_ratio = if (tcp_f > 0) syn_f / tcp_f else 0,
            .rst_ratio = if (tcp_f > 0) rst_f / tcp_f else 0,
            .unique_dst_ports = @floatFromInt(self.ports.count()),
            .unique_dst_ips = @floatFromInt(self.ips.count()),
            .inbound_ratio = if (pkts_f > 0) in_f / pkts_f else 0,
            .mean_payload_len = if (pkts_f > 0) pay_f / pkts_f else 0,
        };
    }
};

pub fn keyFromIp(ip: [4]u8) u32 {
    return (@as(u32, ip[0]) << 24) | (@as(u32, ip[1]) << 16) |
        (@as(u32, ip[2]) << 8) | @as(u32, ip[3]);
}

pub fn ipFromKey(key: u32) [4]u8 {
    return .{
        @intCast((key >> 24) & 0xFF),
        @intCast((key >> 16) & 0xFF),
        @intCast((key >> 8) & 0xFF),
        @intCast(key & 0xFF),
    };
}

pub fn formatIp4(buf: []u8, ip: [4]u8) []const u8 {
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }) catch buf[0..0];
}

pub fn isZeroIp(ip: [4]u8) bool {
    return ip[0] == 0 and ip[1] == 0 and ip[2] == 0 and ip[3] == 0;
}

// ============================================================
// EWMA behavioral baseline (per source IP)
// ============================================================

pub const Baseline = struct {
    mean_rate: f64 = 0,
    var_rate: f64 = 0,
    samples: u32 = 0,

    pub fn update(self: *Baseline, x: f64, alpha: f64) void {
        if (self.samples == 0) {
            self.mean_rate = x;
            self.var_rate = 0;
            self.samples = 1;
            return;
        }
        const d = x - self.mean_rate;
        self.mean_rate += alpha * d;
        self.var_rate = (1.0 - alpha) * (self.var_rate + alpha * d * d);
        self.samples += 1;
    }

    pub fn zScore(self: *const Baseline, x: f64) f64 {
        const sd = @sqrt(self.var_rate + 1e-9);
        return (x - self.mean_rate) / sd;
    }
};

// ============================================================
// Model (JSON-trained logistic regression)
// ============================================================

pub const ModelMetrics = struct {
    accuracy: f64 = 0,
    precision: f64 = 0,
    recall: f64 = 0,
    f1: f64 = 0,
    samples: u64 = 0,
};

pub const Model = struct {
    version: u32 = 1,
    name: []const u8 = "",
    trained_at: []const u8 = "",
    features: [FEATURE_COUNT][]const u8 = undefined,
    mean: [FEATURE_COUNT]f64 = [_]f64{0} ** FEATURE_COUNT,
    std: [FEATURE_COUNT]f64 = [_]f64{1} ** FEATURE_COUNT,
    weights: [FEATURE_COUNT]f64 = [_]f64{0} ** FEATURE_COUNT,
    bias: f64 = 0,
    confidence_threshold: f64 = 0.70,
    metrics: ModelMetrics = .{},
};

pub const ModelError = error{
    InvalidJson,
    UnsupportedVersion,
    FeatureCountMismatch,
    BadStd,
    BadThreshold,
    NotLoaded,
};

// ============================================================
// Verdict
// ============================================================

pub const Label = enum(u8) {
    disabled = 0,
    benign = 1,
    suspicious = 2,
    malicious = 3,

    pub fn name(self: Label) []const u8 {
        return switch (self) {
            .disabled => "DISABLED",
            .benign => "BENIGN",
            .suspicious => "SUSPICIOUS",
            .malicious => "MALICIOUS",
        };
    }
};

pub const MAX_REASONS: usize = 4;
pub const REASON_CAP: usize = 96;

pub const Verdict = struct {
    label: Label = .benign,
    score: f64 = 0,
    baseline_z: f64 = 0,
    reason_bufs: [MAX_REASONS][REASON_CAP]u8 = undefined,
    reason_lens: [MAX_REASONS]usize = [_]usize{0} ** MAX_REASONS,
    reason_count: usize = 0,

    pub fn pushFmt(self: *Verdict, comptime fmt: []const u8, args: anytype) void {
        if (self.reason_count >= MAX_REASONS) return;
        const i = self.reason_count;
        const s = std.fmt.bufPrint(&self.reason_bufs[i], fmt, args) catch return;
        self.reason_lens[i] = s.len;
        self.reason_count += 1;
    }

    pub fn reason(self: *const Verdict, i: usize) []const u8 {
        if (i >= self.reason_count) return "";
        return self.reason_bufs[i][0..self.reason_lens[i]];
    }
};

// ============================================================
// MlDetector - main engine
// ============================================================

/// Pattern thresholds for signature-style reasons layered on the
/// statistical model (explainability first).
pub const SCAN_PORTS_SUSPICIOUS: usize = 20;
pub const SCAN_PORTS_MALICIOUS: usize = 40;
pub const SYN_FLOOD_RATIO: f64 = 0.8;
pub const SYN_FLOOD_MIN_PPS: f64 = 50.0;
pub const RST_SUSPICIOUS_RATIO: f64 = 0.5;

pub const MlDetector = struct {
    allocator: std.mem.Allocator,
    config: MlConfig,
    model: ?std.json.Parsed(Model) = null,
    window: FlowWindow = .{},
    baselines: std.AutoHashMap(u32, Baseline),
    last: Verdict = .{},
    // stats
    events_observed: u64 = 0,
    windows_scored: u64 = 0,
    benign_count: u64 = 0,
    suspicious_count: u64 = 0,
    malicious_count: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, config: MlConfig) MlDetector {
        return .{
            .allocator = allocator,
            .config = config,
            .baselines = std.AutoHashMap(u32, Baseline).init(allocator),
        };
    }

    pub fn deinit(self: *MlDetector) void {
        if (self.model) |*p| p.deinit();
        self.model = null;
        self.baselines.deinit();
        self.baselines = undefined;
    }

    /// Parse + validate a model JSON payload (replaces any previous).
    /// The parsed memory stays owned by the detector until replaced
    /// or deinit.
    pub fn loadModelJson(self: *MlDetector, json_bytes: []const u8) ModelError!void {
        const parsed = std.json.parseFromSlice(
            Model,
            self.allocator,
            json_bytes,
            .{ .ignore_unknown_fields = true },
        ) catch return ModelError.InvalidJson;

        const m = &parsed.value;
        if (m.version != 1) {
            parsed.deinit();
            return ModelError.UnsupportedVersion;
        }
        for (m.std) |s| {
            if (!(s > 0.0) or std.math.isNan(s)) {
                parsed.deinit();
                return ModelError.BadStd;
            }
        }
        if (!(m.confidence_threshold > 0.0 and m.confidence_threshold < 1.0)) {
            parsed.deinit();
            return ModelError.BadThreshold;
        }

        if (self.model) |*old| old.deinit();
        self.model = parsed;
    }

    pub fn modelLoaded(self: *const MlDetector) bool {
        return self.model != null;
    }

    pub fn modelInfo(self: *const MlDetector) ?*const Model {
        if (self.model) |*p| return &p.value; // pointer into self, not a copy
        return null;
    }

    /// Feed one canonical event into the current window.
    /// Scoring happens on flushWindow() / observeAndMaybeScore().
    pub fn observe(self: *MlDetector, ev: CanonicalEvent) void {
        if (!self.config.enabled) return; // kill switch: no accumulation
        self.events_observed += 1;
        self.window.observe(ev);
    }

    /// Window-rollover helper: feed event, and when the window is
    /// older than window_secs, flush (score + baseline update) and
    /// start a fresh one. Returns the flushed verdict, if any.
    pub fn observeAndMaybeScore(self: *MlDetector, ev: CanonicalEvent) ?Verdict {
        if (!self.config.enabled) return null;

        const should_flush = blk: {
            if (self.window.isEmpty()) break :blk false;
            const elapsed_ns = ev.timestamp_ns - self.window.start_ns;
            const elapsed = @as(f64, @floatFromInt(elapsed_ns)) / 1e9;
            break :blk elapsed >= self.config.window_secs;
        };
        if (!should_flush) {
            self.observe(ev);
            return null;
        }
        const flushed = self.flushWindow();
        self.observe(ev);
        return flushed;
    }

    /// Finalize + score the current window, update the per-source
    /// EWMA baseline, reset the window, store verdict in self.last.
    /// Returns null if the window is empty or kill switch is off.
    pub fn flushWindow(self: *MlDetector) ?Verdict {
        if (!self.config.enabled) return null;
        if (self.window.isEmpty()) return null;

        const feats = self.window.finalize();
        const key = self.window.primarySrcKey();
        const z = self.baselineZFor(key, feats.pkts_per_sec);
        const verdict = self.classify(feats, z);

        // Baseline update with the observed rate.
        self.updateBaseline(key, feats.pkts_per_sec);

        self.last = verdict;
        self.windows_scored += 1;
        switch (verdict.label) {
            .malicious => self.malicious_count += 1,
            .suspicious => self.suspicious_count += 1,
            else => self.benign_count += 1,
        }
        self.window.reset();
        return verdict;
    }

    /// Score the current window WITHOUT consuming it (dry run).
    pub fn scoreCurrent(self: *const MlDetector) Verdict {
        if (!self.config.enabled) return .{ .label = .disabled };
        if (self.window.isEmpty()) return .{ .label = .benign };
        const feats = self.window.finalize();
        const key = self.window.primarySrcKey();
        const z = self.baselineZFor(key, feats.pkts_per_sec);
        return self.classify(feats, z);
    }

    pub fn resetWindow(self: *MlDetector) void {
        self.window.reset();
    }

    pub fn resetBaselines(self: *MlDetector) void {
        self.baselines.clearRetainingCapacity();
    }

    pub fn resetStats(self: *MlDetector) void {
        self.events_observed = 0;
        self.windows_scored = 0;
        self.benign_count = 0;
        self.suspicious_count = 0;
        self.malicious_count = 0;
    }

    pub fn baselineCount(self: *const MlDetector) usize {
        return self.baselines.count();
    }

    fn baselineZFor(self: *const MlDetector, key: u32, rate: f64) f64 {
        const b = self.baselines.get(key) orelse return 0;
        if (b.samples < self.config.min_baseline_samples) return 0;
        return b.zScore(rate);
    }

    fn updateBaseline(self: *MlDetector, key: u32, rate: f64) void {
        if (key == 0) return;
        if (self.baselines.getPtr(key)) |b| {
            b.update(rate, self.config.ewma_alpha);
            return;
        }
        if (self.baselines.count() >= self.config.max_keys) return; // bounded
        var b = Baseline{};
        b.update(rate, self.config.ewma_alpha);
        self.baselines.put(key, b) catch return;
    }

    /// Core classifier: features + baseline z-score -> verdict.
    pub fn classify(self: *const MlDetector, feats: Features, z: f64) Verdict {
        var v = Verdict{ .baseline_z = z };
        if (!self.config.enabled) {
            v.label = .disabled;
            return v;
        }

        // Model probability (0 when no model loaded).
        var p: f64 = 0;
        if (self.model) |parsed| {
            const m = &parsed.value;
            const x = feats.toArray();
            var logits: f64 = m.bias;
            var i: usize = 0;
            while (i < FEATURE_COUNT) : (i += 1) {
                logits += m.weights[i] * standardize(x[i], m.mean[i], m.std[i]);
            }
            p = sigmoid(logits);
        } else {
            v.pushFmt("model not loaded - statistical rules only", .{});
        }
        v.score = p;

        const thr = self.config.confidence_threshold;
        var malicious = false;
        var suspicious = false;

        // 1) Model score gate.
        if (self.model != null) {
            if (p >= thr) {
                malicious = true;
                v.pushFmt("model score {d:.2} >= threshold {d:.2}", .{ p, thr });
            } else if (p >= 0.5 * thr) {
                suspicious = true;
                v.pushFmt("model score {d:.2} (elevated)", .{p});
            }
        }

        // 2) Port-scan signature.
        const n_ports: usize = @intFromFloat(@min(feats.unique_dst_ports, 1e9));
        if (n_ports >= SCAN_PORTS_MALICIOUS) {
            malicious = true;
            v.pushFmt("port scan pattern: {d} unique dst ports", .{n_ports});
        } else if (n_ports >= SCAN_PORTS_SUSPICIOUS) {
            suspicious = true;
            v.pushFmt("port scan pattern: {d} unique dst ports", .{n_ports});
        }

        // 3) SYN-flood signature.
        if (feats.syn_ratio >= SYN_FLOOD_RATIO and feats.pkts_per_sec >= SYN_FLOOD_MIN_PPS) {
            malicious = true;
            v.pushFmt("syn flood pattern: ratio {d:.2} at {d:.0} pps", .{ feats.syn_ratio, feats.pkts_per_sec });
        }

        // 4) RST-heavy window.
        if (feats.rst_ratio >= RST_SUSPICIOUS_RATIO) {
            suspicious = true;
            v.pushFmt("high RST ratio {d:.2}", .{feats.rst_ratio});
        }

        // 5) Baseline deviation gate.
        const sigma = self.config.baseline_sigma_mult;
        if (z >= 2.0 * sigma and p >= 0.5) {
            malicious = true;
            v.pushFmt("rate {d:.1} sigma above baseline (z={d:.1})", .{ z, z });
        } else if (z >= sigma) {
            suspicious = true;
            v.pushFmt("rate {d:.1} sigma above baseline (z={d:.1})", .{ z, z });
        }

        v.label = if (malicious) .malicious else if (suspicious) .suspicious else .benign;
        return v;
    }
};

// ============================================================
// Singleton facade (project style: init/shutdown/instance)
// ============================================================

var g_instance: ?MlDetector = null;

pub fn init(allocator: std.mem.Allocator, config: MlConfig) !void {
    if (g_instance != null) return error.AlreadyInitialized;
    g_instance = MlDetector.init(allocator, config);
}

pub fn shutdown() void {
    if (g_instance) |*d| d.deinit();
    g_instance = null;
}

pub fn instance() ?*MlDetector {
    if (g_instance) |*d| return d;
    return null;
}

pub fn isAvailable() bool {
    return g_instance != null;
}

// ============================================================
// Tests (24) - pure std, host-friendly, no Npcap required
// ============================================================

const testing = std.testing;
const talloc = testing.allocator;

fn mkEvent(ts_ns: i64, src: [4]u8, dst: [4]u8, dport: u16, proto: u8, flags: u8, plen: u16) CanonicalEvent {
    return .{
        .timestamp_ns = ts_ns,
        .src_ip = src,
        .dst_ip = dst,
        .dst_port = dport,
        .protocol = proto,
        .tcp_flags = flags,
        .payload_len = plen,
        .direction = .inbound,
    };
}

const SRC1 = [4]u8{ 192, 168, 1, 41 };
const DST1 = [4]u8{ 93, 184, 216, 34 };

test "sigmoid basics" {
    try testing.expectApproxEqAbs(@as(f64, 0.5), sigmoid(0.0), 1e-9);
    try testing.expect(sigmoid(5.0) > 0.99);
    try testing.expect(sigmoid(-5.0) < 0.01);
    try testing.expect(sigmoid(30.0) <= 1.0);
    try testing.expect(sigmoid(-30.0) >= 0.0);
}

test "sigmoid monotonic" {
    var x: f64 = -10;
    var prev = sigmoid(x);
    while (x <= 10) : (x += 1) {
        const cur = sigmoid(x);
        try testing.expect(cur >= prev);
        prev = cur;
    }
}

test "standardize guards zero std" {
    const z = standardize(5.0, 1.0, 0.0);
    try testing.expectApproxEqAbs(@as(f64, 4.0), z, 1e-9);
    const z2 = standardize(3.0, 3.0, 2.0);
    try testing.expectApproxEqAbs(@as(f64, 0.0), z2, 1e-12);
}

test "port set dedup and cap" {
    var ps = PortSet{};
    ps.add(80);
    ps.add(443);
    ps.add(80); // dup
    try testing.expectEqual(@as(usize, 2), ps.count());
    var p: u16 = 1;
    while (p < 200) : (p += 1) ps.add(p);
    try testing.expectEqual(@as(usize, PortSet.CAP), ps.count());
    try testing.expect(ps.saturated);
    try testing.expect(ps.contains(443));
    try testing.expect(ps.contains(62)); // made it in before saturation
    try testing.expect(!ps.contains(199)); // rejected after saturation
    try testing.expect(!ps.contains(0)); // never added (port 0 skipped)
}

test "ip set dedup and zero-ip skipped" {
    var is = IpSet{};
    is.add(DST1);
    is.add(DST1);
    is.add([_]u8{ 0, 0, 0, 0 }); // zero skipped
    try testing.expectEqual(@as(usize, 1), is.count());
    is.add([_]u8{ 8, 8, 8, 8 });
    try testing.expectEqual(@as(usize, 2), is.count());
}

test "keyFromIp roundtrip" {
    const key = keyFromIp(SRC1);
    try testing.expectEqual(keyFromIp(SRC1), key);
    const back = ipFromKey(key);
    try testing.expectEqualSlices(u8, &SRC1, &back);
}

test "flow window counts and ratios" {
    var w = FlowWindow{};
    const t0: i64 = 1_000_000_000; // 1s
    var i: u16 = 0;
    while (i < 40) : (i += 1) {
        const flags: u8 = if (i < 36) TCP_SYN | TCP_ACK else TCP_RST;
        w.observe(mkEvent(t0 + @as(i64, i) * 100_000_000, SRC1, DST1, 1000 + i, 6, flags, 100));
    }
    // 40 TCP over 3.9s (clamped rates use duration ~3.9s)
    try testing.expectEqual(@as(u64, 40), w.pkts);
    try testing.expectEqual(@as(u64, 36), w.syn_count);
    try testing.expectEqual(@as(u64, 4), w.rst_count);
    try testing.expectEqual(@as(u64, 4000), w.payload_sum);
    try testing.expectEqual(@as(usize, 40), w.ports.count());

    const f = w.finalize();
    try testing.expect(f.pkts_per_sec > 0);
    try testing.expectApproxEqAbs(@as(f64, 0.9), f.syn_ratio, 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 0.1), f.rst_ratio, 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 100.0), f.mean_payload_len, 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 1.0), f.inbound_ratio, 1e-9);
}

test "flow window duration clamp" {
    var w = FlowWindow{};
    w.observe(mkEvent(1_000_000_000, SRC1, DST1, 80, 6, TCP_SYN, 0));
    w.observe(mkEvent(1_050_000_000, SRC1, DST1, 80, 6, TCP_SYN, 0)); // 50ms apart
    try testing.expectApproxEqAbs(@as(f64, 1.0), w.durationSecs(), 1e-9);
    const f = w.finalize();
    try testing.expectApproxEqAbs(@as(f64, 2.0), f.pkts_per_sec, 1e-9); // clamped to 1s
}

test "flow window primary src selection" {
    var w = FlowWindow{};
    var i: usize = 0;
    while (i < 5) : (i += 1) w.observe(mkEvent(1_000_000_000 + @as(i64, @intCast(i)), SRC1, DST1, 80, 6, TCP_ACK, 0));
    i = 0;
    while (i < 2) : (i += 1) w.observe(mkEvent(1_000_000_100 + @as(i64, @intCast(i)), DST1, SRC1, 80, 6, TCP_ACK, 0));
    try testing.expectEqual(keyFromIp(SRC1), w.primarySrcKey());
}

test "baseline ewma converges and z-scores spikes" {
    var b = Baseline{};
    var i: usize = 0;
    while (i < 50) : (i += 1) b.update(10.0, 0.15);
    try testing.expect(b.samples == 50);
    try testing.expectApproxEqAbs(@as(f64, 10.0), b.mean_rate, 0.5);
    const z_low = b.zScore(10.0);
    try testing.expectApproxEqAbs(@as(f64, 0.0), z_low, 0.1);
    const z_spike = b.zScore(100.0);
    try testing.expect(z_spike > 5.0);
}

test "model json parse and validation" {
    const json =
        \\{
        \\  "version": 1,
        \\  "name": "aegis-flow-anomaly-v1",
        \\  "trained_at": "2026-09-05T00:00:00Z",
        \\  "features": ["pkts_per_sec","bytes_per_sec","syn_ratio","rst_ratio","unique_dst_ports","unique_dst_ips","inbound_ratio","mean_payload_len"],
        \\  "mean": [10, 500, 0.2, 0.05, 3, 2, 0.5, 300],
        \\  "std": [5, 200, 0.1, 0.05, 4, 2, 0.2, 100],
        \\  "weights": [1.5, 0.5, 2.0, 1.0, 3.0, 2.0, -0.3, -1.0],
        \\  "bias": -2.0,
        \\  "confidence_threshold": 0.7,
        \\  "metrics": {"accuracy": 0.97, "precision": 0.96, "recall": 0.95, "f1": 0.955, "samples": 4800}
        \\}
    ;
    var det = MlDetector.init(talloc, .{ .enabled = true });
    defer det.deinit();
    try det.loadModelJson(json);
    try testing.expect(det.modelLoaded());
    const m = det.modelInfo().?;
    try testing.expectEqualStrings("aegis-flow-anomaly-v1", m.name);
    try testing.expectApproxEqAbs(@as(f64, -2.0), m.bias, 1e-12);
    try testing.expectEqual(@as(u64, 4800), m.metrics.samples);
    try testing.expectApproxEqAbs(@as(f64, 3.0), m.weights[4], 1e-12);

    // bad version
    try testing.expectError(ModelError.UnsupportedVersion, det.loadModelJson("{\"version\":2,\"std\":[1,1,1,1,1,1,1,1],\"confidence_threshold\":0.7}"));
    // bad std (zero)
    try testing.expectError(ModelError.BadStd, det.loadModelJson("{\"version\":1,\"std\":[0,1,1,1,1,1,1,1],\"confidence_threshold\":0.7}"));
    // bad threshold
    try testing.expectError(ModelError.BadThreshold, det.loadModelJson("{\"version\":1,\"std\":[1,1,1,1,1,1,1,1],\"confidence_threshold\":1.5}"));
    // invalid json
    try testing.expectError(ModelError.InvalidJson, det.loadModelJson("{not json"));
}

test "kill switch disabled: no observe, no scoring" {
    var det = MlDetector.init(talloc, .{ .enabled = false });
    defer det.deinit();
    det.observe(mkEvent(1_000_000_000, SRC1, DST1, 80, 6, TCP_SYN, 0));
    try testing.expectEqual(@as(u64, 0), det.events_observed);
    try testing.expect(det.flushWindow() == null);
    try testing.expectEqual(Label.disabled, det.scoreCurrent().label);
    const v = det.classify(Features{ .pkts_per_sec = 500 }, 9.0);
    try testing.expectEqual(Label.disabled, v.label);
}

test "benign window stays benign" {
    var det = MlDetector.init(talloc, .{ .enabled = true, .window_secs = 10 });
    defer det.deinit();
    // No model: statistical rules only, calm traffic.
    const t0: i64 = 1_000_000_000;
    var i: u16 = 0;
    while (i < 30) : (i += 1) {
        det.observe(mkEvent(t0 + @as(i64, i) * 200_000_000, SRC1, DST1, if (i % 3 == 0) 443 else 80, 6, TCP_ACK | TCP_PSH, 400));
    }
    const v = det.flushWindow().?;
    try testing.expectEqual(Label.benign, v.label);
    try testing.expectEqual(@as(u64, 1), det.windows_scored);
    try testing.expectEqual(@as(u64, 1), det.benign_count);
}

test "port scan window flagged malicious" {
    var det = MlDetector.init(talloc, .{ .enabled = true });
    defer det.deinit();
    const t0: i64 = 2_000_000_000;
    var port: u16 = 1;
    while (port <= 50) : (port += 1) {
        det.observe(mkEvent(t0 + @as(i64, port) * 100_000_000, SRC1, DST1, port, 6, TCP_SYN, 0));
    }
    const v = det.flushWindow().?;
    try testing.expectEqual(Label.malicious, v.label);
    var found_scan_reason = false;
    var ri: usize = 0;
    while (ri < v.reason_count) : (ri += 1) {
        if (std.mem.startsWith(u8, v.reason(ri), "port scan pattern")) found_scan_reason = true;
    }
    try testing.expect(found_scan_reason);
}

test "syn flood window flagged malicious" {
    var det = MlDetector.init(talloc, .{ .enabled = true });
    defer det.deinit();
    const t0: i64 = 3_000_000_000;
    var i: u16 = 0;
    while (i < 300) : (i += 1) {
        det.observe(mkEvent(t0 + @as(i64, i) * 20_000_000, SRC1, DST1, 80, 6, TCP_SYN, 0));
    }
    const v = det.flushWindow().?;
    try testing.expectEqual(Label.malicious, v.label);
    var found_syn_reason = false;
    var ri: usize = 0;
    while (ri < v.reason_count) : (ri += 1) {
        if (std.mem.startsWith(u8, v.reason(ri), "syn flood pattern")) found_syn_reason = true;
    }
    try testing.expect(found_syn_reason);
}

test "rst-heavy window suspicious" {
    var det = MlDetector.init(talloc, .{ .enabled = true });
    defer det.deinit();
    const t0: i64 = 4_000_000_000;
    var i: u16 = 0;
    while (i < 20) : (i += 1) {
        det.observe(mkEvent(t0 + @as(i64, i) * 200_000_000, SRC1, DST1, 8080 + i, 6, TCP_RST | TCP_ACK, 0));
    }
    const v = det.flushWindow().?;
    try testing.expect(v.label == .suspicious or v.label == .malicious);
}

test "empty window returns null verdict" {
    var det = MlDetector.init(talloc, .{ .enabled = true });
    defer det.deinit();
    try testing.expect(det.flushWindow() == null);
}

test "window rollover via observeAndMaybeScore" {
    var det = MlDetector.init(talloc, .{ .enabled = true, .window_secs = 10 });
    defer det.deinit();
    const t0: i64 = 5_000_000_000;
    var i: u16 = 0;
    while (i < 15) : (i += 1) {
        const v = det.observeAndMaybeScore(mkEvent(t0 + @as(i64, i) * 1_000_000_000, SRC1, DST1, 443, 6, TCP_ACK, 200));
        // 15 events at 1s spacing across a 10s window -> exactly one rollover.
        if (i == 10) {
            try testing.expect(v != null);
            try testing.expectEqual(@as(u64, 1), det.windows_scored);
        } else {
            try testing.expect(v == null);
        }
    }
}

test "baseline update happens on flush and gates spikes" {
    var det = MlDetector.init(talloc, .{
        .enabled = true,
        .min_baseline_samples = 5,
        .ewma_alpha = 0.3,
        .baseline_sigma_mult = 3.0,
    });
    defer det.deinit();
    const t0: i64 = 6_000_000_000;
    // Train baseline: 8 calm windows (~30 pps each, from one source).
    var w: u16 = 0;
    while (w < 8) : (w += 1) {
        var i: u16 = 0;
        while (i < 30) : (i += 1) {
            det.observe(mkEvent(
                t0 + @as(i64, w) * 10_000_000_000 + @as(i64, i) * 300_000_000,
                SRC1,
                DST1,
                443,
                6,
                TCP_ACK,
                300,
            ));
        }
        _ = det.flushWindow();
    }
    try testing.expectEqual(@as(usize, 1), det.baselineCount());
    // Spike window: same source, 400 pps, single dst (not scan/syn signatures).
    var k: u16 = 0;
    while (k < 400) : (k += 1) {
        det.observe(mkEvent(7_000_000_000 + @as(i64, k) * 2_500_000, SRC1, DST1, 443, 6, TCP_ACK, 64));
    }
    const spike = det.flushWindow().?;
    try testing.expect(spike.baseline_z > 3.0);
    // Baseline deviation alone (no model) is suspicious, not malicious.
    try testing.expectEqual(Label.suspicious, spike.label);
}

test "model score gate drives verdict with trained weights" {
    var det = MlDetector.init(talloc, .{ .enabled = true, .confidence_threshold = 0.7 });
    defer det.deinit();
    const json =
        \\{"version":1,"name":"t","features":["pkts_per_sec","bytes_per_sec","syn_ratio","rst_ratio","unique_dst_ports","unique_dst_ips","inbound_ratio","mean_payload_len"],
        \\ "mean":[10,500,0.2,0.05,3,2,0.5,300],"std":[5,200,0.1,0.05,4,2,0.2,100],
        \\ "weights":[0,0,0,0,3.0,0,0,0],"bias":-6.0,"confidence_threshold":0.7}
    ;
    try det.loadModelJson(json);
    // unique_dst_ports = 50 -> z = (50-3)/4 = 11.75 -> w*11.75 - 6 > 0 -> p ~ 1
    var w = FlowWindow{};
    const t0: i64 = 8_000_000_000;
    var port: u16 = 1;
    while (port <= 50) : (port += 1) {
        w.observe(mkEvent(t0 + @as(i64, port) * 100_000_000, SRC1, DST1, port, 6, TCP_SYN, 0));
    }
    const v = det.classify(w.finalize(), 0.0);
    try testing.expectEqual(Label.malicious, v.label);
    try testing.expect(v.score > 0.7);
}

test "custom threshold respected" {
    var det = MlDetector.init(talloc, .{ .enabled = true, .confidence_threshold = 0.9 });
    defer det.deinit();
    // Weight tuned so a single feature hits p ~ 0.88 (below 0.9).
    const json =
        \\{"version":1,"name":"t","features":["pkts_per_sec","bytes_per_sec","syn_ratio","rst_ratio","unique_dst_ports","unique_dst_ips","inbound_ratio","mean_payload_len"],
        \\ "mean":[10,500,0.2,0.05,3,2,0.5,300],"std":[5,200,0.1,0.05,4,2,0.2,100],
        \\ "weights":[2.0,0,0,0,0,0,0,0],"bias":0.0,"confidence_threshold":0.7}
    ;
    try det.loadModelJson(json);
    // pkts_per_sec 25 -> z = (25-10)/5 = 3 -> logits 6 -> p ~ 0.9975 (malicious at any thr)
    // pkts_per_sec 15 -> z = 1 -> logits 2 -> p ~ 0.88 (suspicious at thr 0.9)
    const calm = Features{ .pkts_per_sec = 15 };
    const v = det.classify(calm, 0.0);
    try testing.expectEqual(Label.suspicious, v.label);
    const hot = Features{ .pkts_per_sec = 25 };
    const v2 = det.classify(hot, 0.0);
    try testing.expectEqual(Label.malicious, v2.label);
}

test "verdict reasons capped and formatted" {
    var det = MlDetector.init(talloc, .{ .enabled = true });
    defer det.deinit();
    const f = Features{
        .pkts_per_sec = 500,
        .syn_ratio = 0.95,
        .unique_dst_ports = 60,
        .rst_ratio = 0.7,
    };
    const v = det.classify(f, 9.0);
    try testing.expectEqual(Label.malicious, v.label);
    try testing.expect(v.reason_count <= MAX_REASONS);
    try testing.expect(v.reason_count >= 2);
}

test "reset baselines and stats" {
    var det = MlDetector.init(talloc, .{ .enabled = true });
    defer det.deinit();
    const t0: i64 = 9_000_000_000;
    var i: u16 = 0;
    while (i < 10) : (i += 1) {
        det.observe(mkEvent(t0 + @as(i64, i) * 100_000_000, SRC1, DST1, 443, 6, TCP_ACK, 100));
    }
    _ = det.flushWindow().?;
    try testing.expect(det.baselineCount() == 1);
    try testing.expect(det.windows_scored == 1);
    det.resetBaselines();
    det.resetStats();
    try testing.expect(det.baselineCount() == 0);
    try testing.expect(det.windows_scored == 0);
    try testing.expectEqual(@as(u64, 0), det.events_observed);
}

test "max_keys bound on baseline store" {
    var det = MlDetector.init(talloc, .{ .enabled = true, .max_keys = 4 });
    defer det.deinit();
    const t0: i64 = 10_000_000_000;
    var oct: u8 = 1;
    while (oct <= 8) : (oct += 1) {
        var src = SRC1;
        src[3] = oct;
        det.observe(mkEvent(t0 + @as(i64, oct) * 100_000_000, src, DST1, 443, 6, TCP_ACK, 100));
        _ = det.flushWindow().?;
    }
    try testing.expectEqual(@as(usize, 4), det.baselineCount()); // capped
}

test "singleton facade lifecycle" {
    try testing.expect(!isAvailable());
    try init(talloc, .{ .enabled = false });
    try testing.expect(isAvailable());
    try testing.expectError(error.AlreadyInitialized, init(talloc, .{ .enabled = false }));
    instance().?.resetStats();
    shutdown();
    try testing.expect(!isAvailable());
}

test "model replacement frees old parse" {
    var det = MlDetector.init(talloc, .{ .enabled = true });
    defer det.deinit();
    const j1 =
        \\{"version":1,"name":"m1","features":["pkts_per_sec","bytes_per_sec","syn_ratio","rst_ratio","unique_dst_ports","unique_dst_ips","inbound_ratio","mean_payload_len"],
        \\ "mean":[0,0,0,0,0,0,0,0],"std":[1,1,1,1,1,1,1,1],"weights":[0,0,0,0,0,0,0,0],"bias":0,"confidence_threshold":0.7}
    ;
    try det.loadModelJson(j1);
    try testing.expectEqualStrings("m1", det.modelInfo().?.name);
    try det.loadModelJson(j1); // same payload, replaced cleanly
    try testing.expectEqualStrings("m1", det.modelInfo().?.name);
}
