//! performance_harness.zig - AEGIS Performance Harness (Rewrite Phase 17)
//!
//! Benchmarks pipeline throughput and per-stage latency.
//! Read-only measurement tool (does NOT modify the pipeline).
//!
//! Architecture:
//!   Performance Harness measures: Event Fabric -> ... -> Forensics
//!   Tracks timing for each pipeline stage + overall throughput.
//!
//! Metrics captured:
//!   - Throughput: events per second (EPS)
//!   - Latency: per-event total + per-stage breakdown
//!   - Percentiles: p50 (median), p95, p99
//!   - Memory: approximate allocation tracking
//!
//! Design:
//!   - Fixed-size sample buffer (no allocation in hot path)
//!   - Uses monotonic timestamps (user's field is u64, not i128)
//!   - Computes statistics after sampling phase completes

const std = @import("std");

// ============================================================
// Constants
// ============================================================

/// Maximum latency samples to keep (ring buffer).
pub const MAX_SAMPLES: usize = 4096;

/// Pipeline stages (for per-stage timing).
pub const Stage = enum(u8) {
    total = 0, // Total pipeline time
    flow = 1, // Phase 6
    detection = 2, // Phase 7
    aggregation = 3, // Phase 8
    correlation = 4, // Phase 9
    threat_intel = 5, // Phase 10
    brain = 6, // Phase 11
    policy = 7, // Phase 12
    pep = 8, // Phase 13
    forensics = 9, // Phase 14

    pub fn toString(self: Stage) []const u8 {
        return switch (self) {
            .total => "TOTAL",
            .flow => "FLOW",
            .detection => "DETECTION",
            .aggregation => "AGGREGATION",
            .correlation => "CORRELATION",
            .threat_intel => "THREAT_INTEL",
            .brain => "BRAIN",
            .policy => "POLICY",
            .pep => "PEP",
            .forensics => "FORENSICS",
        };
    }
};

pub const STAGE_COUNT: usize = 10;

// ============================================================
// Latency Sample
// ============================================================

/// A single latency measurement for one event through the pipeline.
/// Each field is nanoseconds spent in that stage.
pub const LatencySample = struct {
    /// Total pipeline time (flow -> forensics).
    total_ns: u64,
    /// Per-stage times.
    flow_ns: u64,
    detection_ns: u64,
    aggregation_ns: u64,
    correlation_ns: u64,
    threat_intel_ns: u64,
    brain_ns: u64,
    policy_ns: u64,
    pep_ns: u64,
    forensics_ns: u64,
    /// Event ID that was measured.
    event_id: u64,
};

// ============================================================
// Latency Statistics
// ============================================================

pub const LatencyStats = struct {
    /// Minimum latency (ns).
    min_ns: u64,
    /// Maximum latency (ns).
    max_ns: u64,
    /// Average latency (ns).
    avg_ns: u64,
    /// p50 (median) latency (ns).
    p50_ns: u64,
    /// p95 latency (ns).
    p95_ns: u64,
    /// p99 latency (ns).
    p99_ns: u64,
    /// Number of samples.
    count: usize,

    /// Returns true if stats are valid (count > 0).
    pub fn isValid(self: LatencyStats) bool {
        return self.count > 0;
    }

    /// Returns average latency in microseconds.
    pub fn avgUs(self: LatencyStats) u64 {
        return self.avg_ns / 1000;
    }

    /// Returns average latency in milliseconds.
    pub fn avgMs(self: LatencyStats) u64 {
        return self.avg_ns / std.time.ns_per_ms;
    }
};

// ============================================================
// Sample Buffer (ring buffer for latency samples)
// ============================================================

pub const SampleBuffer = struct {
    samples: [MAX_SAMPLES]LatencySample,
    head: usize,
    count: usize,

    pub fn init() SampleBuffer {
        return .{
            .samples = undefined,
            .head = 0,
            .count = 0,
        };
    }

    /// Add a sample. Overwrites oldest if full.
    pub fn append(self: *SampleBuffer, sample: LatencySample) void {
        self.samples[self.head] = sample;
        self.head = (self.head + 1) % MAX_SAMPLES;
        if (self.count < MAX_SAMPLES) {
            self.count += 1;
        }
    }

    /// Get a slice of all valid samples.
    pub fn slice(self: *const SampleBuffer) []const LatencySample {
        if (self.count == 0) return &[_]LatencySample{};
        if (self.count < MAX_SAMPLES) {
            return self.samples[0..self.count];
        }
        // Ring buffer is full - return all
        return self.samples[0..MAX_SAMPLES];
    }

    /// Current sample count.
    pub fn len(self: *const SampleBuffer) usize {
        return self.count;
    }

    /// Clear all samples.
    pub fn clear(self: *SampleBuffer) void {
        self.head = 0;
        self.count = 0;
    }
};

// ============================================================
// Performance Harness
// ============================================================

pub const PerformanceHarness = struct {
    buffer: SampleBuffer,
    /// Total events processed (lifetime, includes overwritten).
    total_events: u64,
    /// Total time spent processing (ns, lifetime).
    total_time_ns: u64,
    /// Count of events that exceeded latency threshold.
    slow_event_count: u64,
    /// Latency threshold for "slow" events (ns). Default: 10ms.
    slow_threshold_ns: u64,

    pub fn init() PerformanceHarness {
        return .{
            .buffer = SampleBuffer.init(),
            .total_events = 0,
            .total_time_ns = 0,
            .slow_event_count = 0,
            .slow_threshold_ns = 10 * std.time.ns_per_ms, // 10ms
        };
    }

    /// Record a latency sample for one event.
    pub fn recordSample(self: *PerformanceHarness, sample: LatencySample) void {
        self.buffer.append(sample);
        self.total_events += 1;
        self.total_time_ns += sample.total_ns;
        if (sample.total_ns > self.slow_threshold_ns) {
            self.slow_event_count += 1;
        }
    }

    /// Set the slow event threshold (ns).
    pub fn setSlowThreshold(self: *PerformanceHarness, threshold_ns: u64) void {
        self.slow_threshold_ns = threshold_ns;
    }

    /// Compute statistics for a specific stage across all samples.
    pub fn computeStats(self: *const PerformanceHarness, stage: Stage) LatencyStats {
        const samples = self.buffer.slice();
        if (samples.len == 0) {
            return .{
                .min_ns = 0,
                .max_ns = 0,
                .avg_ns = 0,
                .p50_ns = 0,
                .p95_ns = 0,
                .p99_ns = 0,
                .count = 0,
            };
        }

        // Extract values for the requested stage
        var values: [MAX_SAMPLES]u64 = undefined;
        const count = samples.len;
        for (samples, 0..) |s, i| {
            values[i] = getStageValue(s, stage);
        }

        // Sort values for percentile computation
        std.mem.sort(u64, values[0..count], {}, std.sort.asc(u64));

        const min = values[0];
        const max = values[count - 1];

        // Average
        var sum: u64 = 0;
        for (values[0..count]) |v| {
            sum += v;
        }
        const avg = sum / count;

        // Percentiles (using nearest-rank method)
        const p50_idx = (count * 50) / 100;
        const p95_idx = (count * 95) / 100;
        const p99_idx = (count * 99) / 100;

        const p50 = if (p50_idx < count) values[p50_idx] else max;
        const p95 = if (p95_idx < count) values[p95_idx] else max;
        const p99 = if (p99_idx < count) values[p99_idx] else max;

        return .{
            .min_ns = min,
            .max_ns = max,
            .avg_ns = avg,
            .p50_ns = p50,
            .p95_ns = p95,
            .p99_ns = p99,
            .count = count,
        };
    }

    /// Compute throughput (events per second).
    pub fn throughputEPS(self: *const PerformanceHarness) f64 {
        if (self.total_time_ns == 0) return 0;
        const total_seconds = @as(f64, @floatFromInt(self.total_time_ns)) / @as(f64, std.time.ns_per_s);
        return @as(f64, @floatFromInt(self.total_events)) / total_seconds;
    }

    /// Returns slow event percentage (0-100).
    pub fn slowEventPercent(self: *const PerformanceHarness) u8 {
        if (self.total_events == 0) return 0;
        return @intCast((self.slow_event_count * 100) / self.total_events);
    }

    /// Get a summary of all stage stats.
    pub fn getSummary(self: *const PerformanceHarness) PerformanceSummary {
        return .{
            .total_events = self.total_events,
            .throughput_eps = self.throughputEPS(),
            .total_stats = self.computeStats(.total),
            .flow_stats = self.computeStats(.flow),
            .detection_stats = self.computeStats(.detection),
            .aggregation_stats = self.computeStats(.aggregation),
            .correlation_stats = self.computeStats(.correlation),
            .threat_intel_stats = self.computeStats(.threat_intel),
            .brain_stats = self.computeStats(.brain),
            .policy_stats = self.computeStats(.policy),
            .pep_stats = self.computeStats(.pep),
            .forensics_stats = self.computeStats(.forensics),
            .slow_event_count = self.slow_event_count,
            .slow_event_percent = self.slowEventPercent(),
            .sample_count = self.buffer.len(),
        };
    }

    /// Reset all stats and samples.
    pub fn reset(self: *PerformanceHarness) void {
        self.buffer.clear();
        self.total_events = 0;
        self.total_time_ns = 0;
        self.slow_event_count = 0;
    }
};

// ============================================================
// Performance Summary
// ============================================================

pub const PerformanceSummary = struct {
    total_events: u64,
    throughput_eps: f64,
    total_stats: LatencyStats,
    flow_stats: LatencyStats,
    detection_stats: LatencyStats,
    aggregation_stats: LatencyStats,
    correlation_stats: LatencyStats,
    threat_intel_stats: LatencyStats,
    brain_stats: LatencyStats,
    policy_stats: LatencyStats,
    pep_stats: LatencyStats,
    forensics_stats: LatencyStats,
    slow_event_count: u64,
    slow_event_percent: u8,
    sample_count: usize,
};

// ============================================================
// Helpers
// ============================================================

/// Extract the latency value for a specific stage from a sample.
fn getStageValue(sample: LatencySample, stage: Stage) u64 {
    return switch (stage) {
        .total => sample.total_ns,
        .flow => sample.flow_ns,
        .detection => sample.detection_ns,
        .aggregation => sample.aggregation_ns,
        .correlation => sample.correlation_ns,
        .threat_intel => sample.threat_intel_ns,
        .brain => sample.brain_ns,
        .policy => sample.policy_ns,
        .pep => sample.pep_ns,
        .forensics => sample.forensics_ns,
    };
}

// ============================================================
// Tests (all use local harness instances - parallelism-safe)
// ============================================================

test "Stage.toString returns readable names" {
    try std.testing.expect(std.mem.eql(u8, Stage.total.toString(), "TOTAL"));
    try std.testing.expect(std.mem.eql(u8, Stage.flow.toString(), "FLOW"));
    try std.testing.expect(std.mem.eql(u8, Stage.detection.toString(), "DETECTION"));
    try std.testing.expect(std.mem.eql(u8, Stage.aggregation.toString(), "AGGREGATION"));
    try std.testing.expect(std.mem.eql(u8, Stage.correlation.toString(), "CORRELATION"));
    try std.testing.expect(std.mem.eql(u8, Stage.threat_intel.toString(), "THREAT_INTEL"));
    try std.testing.expect(std.mem.eql(u8, Stage.brain.toString(), "BRAIN"));
    try std.testing.expect(std.mem.eql(u8, Stage.policy.toString(), "POLICY"));
    try std.testing.expect(std.mem.eql(u8, Stage.pep.toString(), "PEP"));
    try std.testing.expect(std.mem.eql(u8, Stage.forensics.toString(), "FORENSICS"));
}

test "LatencyStats.isValid" {
    const valid = LatencyStats{
        .min_ns = 100,
        .max_ns = 500,
        .avg_ns = 300,
        .p50_ns = 250,
        .p95_ns = 450,
        .p99_ns = 490,
        .count = 10,
    };
    try std.testing.expect(valid.isValid());

    const invalid = LatencyStats{
        .min_ns = 0,
        .max_ns = 0,
        .avg_ns = 0,
        .p50_ns = 0,
        .p95_ns = 0,
        .p99_ns = 0,
        .count = 0,
    };
    try std.testing.expect(!invalid.isValid());
}

test "LatencyStats.avgUs and avgMs" {
    const stats = LatencyStats{
        .min_ns = 1000,
        .max_ns = 5000,
        .avg_ns = 3000, // 3us = 0.003ms
        .p50_ns = 2500,
        .p95_ns = 4500,
        .p99_ns = 4900,
        .count = 10,
    };
    try std.testing.expect(stats.avgUs() == 3);
    try std.testing.expect(stats.avgMs() == 0); // 3000ns < 1ms
}

test "SampleBuffer init, append, len" {
    var buf = SampleBuffer.init();
    try std.testing.expect(buf.len() == 0);

    const sample = LatencySample{
        .total_ns = 1000,
        .flow_ns = 100,
        .detection_ns = 200,
        .aggregation_ns = 150,
        .correlation_ns = 100,
        .threat_intel_ns = 50,
        .brain_ns = 100,
        .policy_ns = 100,
        .pep_ns = 100,
        .forensics_ns = 100,
        .event_id = 1,
    };
    buf.append(sample);
    try std.testing.expect(buf.len() == 1);

    const samples = buf.slice();
    try std.testing.expect(samples.len == 1);
    try std.testing.expect(samples[0].event_id == 1);
}

test "SampleBuffer slice returns valid samples only" {
    var buf = SampleBuffer.init();

    // Add 3 samples
    var i: u64 = 0;
    while (i < 3) : (i += 1) {
        buf.append(.{
            .total_ns = i * 1000,
            .flow_ns = 100,
            .detection_ns = 200,
            .aggregation_ns = 150,
            .correlation_ns = 100,
            .threat_intel_ns = 50,
            .brain_ns = 100,
            .policy_ns = 100,
            .pep_ns = 100,
            .forensics_ns = 100,
            .event_id = i,
        });
    }

    const samples = buf.slice();
    try std.testing.expect(samples.len == 3);
    try std.testing.expect(samples[0].event_id == 0);
    try std.testing.expect(samples[2].event_id == 2);
}

test "SampleBuffer clear" {
    var buf = SampleBuffer.init();
    buf.append(.{
        .total_ns = 1000,
        .flow_ns = 100,
        .detection_ns = 200,
        .aggregation_ns = 150,
        .correlation_ns = 100,
        .threat_intel_ns = 50,
        .brain_ns = 100,
        .policy_ns = 100,
        .pep_ns = 100,
        .forensics_ns = 100,
        .event_id = 1,
    });
    try std.testing.expect(buf.len() == 1);

    buf.clear();
    try std.testing.expect(buf.len() == 0);
}

test "PerformanceHarness init has zero stats" {
    const harness = PerformanceHarness.init();
    try std.testing.expect(harness.total_events == 0);
    try std.testing.expect(harness.total_time_ns == 0);
    try std.testing.expect(harness.slow_event_count == 0);
    try std.testing.expect(harness.slow_threshold_ns == 10 * std.time.ns_per_ms);
}

test "PerformanceHarness recordSample accumulates stats" {
    var harness = PerformanceHarness.init();

    harness.recordSample(.{
        .total_ns = 5000,
        .flow_ns = 500,
        .detection_ns = 1000,
        .aggregation_ns = 500,
        .correlation_ns = 500,
        .threat_intel_ns = 500,
        .brain_ns = 500,
        .policy_ns = 500,
        .pep_ns = 500,
        .forensics_ns = 500,
        .event_id = 1,
    });

    try std.testing.expect(harness.total_events == 1);
    try std.testing.expect(harness.total_time_ns == 5000);
    try std.testing.expect(harness.slow_event_count == 0); // 5000ns < 10ms threshold
}

test "PerformanceHarness recordSample tracks slow events" {
    var harness = PerformanceHarness.init();

    // Fast event: 1ms
    harness.recordSample(.{
        .total_ns = 1 * std.time.ns_per_ms,
        .flow_ns = 100,
        .detection_ns = 200,
        .aggregation_ns = 150,
        .correlation_ns = 100,
        .threat_intel_ns = 50,
        .brain_ns = 100,
        .policy_ns = 100,
        .pep_ns = 100,
        .forensics_ns = 200,
        .event_id = 1,
    });

    // Slow event: 15ms (> 10ms threshold)
    harness.recordSample(.{
        .total_ns = 15 * std.time.ns_per_ms,
        .flow_ns = 1000,
        .detection_ns = 2000,
        .aggregation_ns = 1500,
        .correlation_ns = 1000,
        .threat_intel_ns = 500,
        .brain_ns = 1000,
        .policy_ns = 1000,
        .pep_ns = 1000,
        .forensics_ns = 7000,
        .event_id = 2,
    });

    try std.testing.expect(harness.total_events == 2);
    try std.testing.expect(harness.slow_event_count == 1);
    try std.testing.expect(harness.slowEventPercent() == 50); // 1 of 2 = 50%
}

test "PerformanceHarness setSlowThreshold" {
    var harness = PerformanceHarness.init();
    try std.testing.expect(harness.slow_threshold_ns == 10 * std.time.ns_per_ms);

    harness.setSlowThreshold(5 * std.time.ns_per_ms);
    try std.testing.expect(harness.slow_threshold_ns == 5 * std.time.ns_per_ms);
}

test "PerformanceHarness computeStats with no samples returns zeros" {
    const harness = PerformanceHarness.init();
    const stats = harness.computeStats(.total);

    try std.testing.expect(!stats.isValid());
    try std.testing.expect(stats.count == 0);
}

test "PerformanceHarness computeStats computes min/max/avg" {
    var harness = PerformanceHarness.init();

    // 3 samples with total_ns: 1000, 2000, 3000
    harness.recordSample(.{
        .total_ns = 1000,
        .flow_ns = 100,
        .detection_ns = 200,
        .aggregation_ns = 150,
        .correlation_ns = 100,
        .threat_intel_ns = 50,
        .brain_ns = 100,
        .policy_ns = 100,
        .pep_ns = 100,
        .forensics_ns = 100,
        .event_id = 1,
    });
    harness.recordSample(.{
        .total_ns = 2000,
        .flow_ns = 200,
        .detection_ns = 400,
        .aggregation_ns = 300,
        .correlation_ns = 200,
        .threat_intel_ns = 100,
        .brain_ns = 200,
        .policy_ns = 200,
        .pep_ns = 200,
        .forensics_ns = 200,
        .event_id = 2,
    });
    harness.recordSample(.{
        .total_ns = 3000,
        .flow_ns = 300,
        .detection_ns = 600,
        .aggregation_ns = 450,
        .correlation_ns = 300,
        .threat_intel_ns = 150,
        .brain_ns = 300,
        .policy_ns = 300,
        .pep_ns = 300,
        .forensics_ns = 300,
        .event_id = 3,
    });

    const stats = harness.computeStats(.total);
    try std.testing.expect(stats.isValid());
    try std.testing.expect(stats.count == 3);
    try std.testing.expect(stats.min_ns == 1000);
    try std.testing.expect(stats.max_ns == 3000);
    try std.testing.expect(stats.avg_ns == 2000); // (1000+2000+3000)/3
}

test "PerformanceHarness computeStats computes percentiles" {
    var harness = PerformanceHarness.init();

    // Add 100 samples with increasing latency
    var i: u64 = 0;
    while (i < 100) : (i += 1) {
        harness.recordSample(.{
            .total_ns = (i + 1) * 100, // 100, 200, ..., 10000
            .flow_ns = 10,
            .detection_ns = 20,
            .aggregation_ns = 15,
            .correlation_ns = 10,
            .threat_intel_ns = 5,
            .brain_ns = 10,
            .policy_ns = 10,
            .pep_ns = 10,
            .forensics_ns = 10,
            .event_id = i,
        });
    }

    const stats = harness.computeStats(.total);
    try std.testing.expect(stats.count == 100);
    try std.testing.expect(stats.min_ns == 100);
    try std.testing.expect(stats.max_ns == 10000);

    // p50: sorted[50] = (50+1)*100 = 5100
    try std.testing.expect(stats.p50_ns == 5100);
    // p95: sorted[95] = (95+1)*100 = 9600
    try std.testing.expect(stats.p95_ns == 9600);
    // p99: sorted[99] = (99+1)*100 = 10000
    try std.testing.expect(stats.p99_ns == 10000);
}

test "PerformanceHarness computeStats for specific stage" {
    var harness = PerformanceHarness.init();

    harness.recordSample(.{
        .total_ns = 1000,
        .flow_ns = 100,
        .detection_ns = 500,
        .aggregation_ns = 50,
        .correlation_ns = 50,
        .threat_intel_ns = 50,
        .brain_ns = 50,
        .policy_ns = 50,
        .pep_ns = 50,
        .forensics_ns = 100,
        .event_id = 1,
    });

    const flow_stats = harness.computeStats(.flow);
    try std.testing.expect(flow_stats.min_ns == 100);
    try std.testing.expect(flow_stats.max_ns == 100);
    try std.testing.expect(flow_stats.avg_ns == 100);

    const detection_stats = harness.computeStats(.detection);
    try std.testing.expect(detection_stats.min_ns == 500);
    try std.testing.expect(detection_stats.max_ns == 500);
    try std.testing.expect(detection_stats.avg_ns == 500);
}

test "PerformanceHarness throughputEPS" {
    var harness = PerformanceHarness.init();

    // 100 events, total time 1 second (1e9 ns)
    var i: u64 = 0;
    while (i < 100) : (i += 1) {
        harness.recordSample(.{
            .total_ns = 10_000_000, // 10ms each
            .flow_ns = 1000,
            .detection_ns = 2000,
            .aggregation_ns = 1500,
            .correlation_ns = 1000,
            .threat_intel_ns = 500,
            .brain_ns = 1000,
            .policy_ns = 1000,
            .pep_ns = 1000,
            .forensics_ns = 1000,
            .event_id = i,
        });
    }

    // Total time = 100 * 10ms = 1000ms = 1s
    // Throughput = 100 events / 1s = 100 EPS
    const eps = harness.throughputEPS();
    try std.testing.expect(eps > 99.0 and eps < 101.0); // approximately 100
}

test "PerformanceHarness slowEventPercent" {
    var harness = PerformanceHarness.init();

    // 4 fast + 1 slow = 20% slow
    var i: u64 = 0;
    while (i < 4) : (i += 1) {
        harness.recordSample(.{
            .total_ns = 1 * std.time.ns_per_ms, // 1ms (fast)
            .flow_ns = 100,
            .detection_ns = 200,
            .aggregation_ns = 150,
            .correlation_ns = 100,
            .threat_intel_ns = 50,
            .brain_ns = 100,
            .policy_ns = 100,
            .pep_ns = 100,
            .forensics_ns = 200,
            .event_id = i,
        });
    }
    harness.recordSample(.{
        .total_ns = 15 * std.time.ns_per_ms, // 15ms (slow)
        .flow_ns = 1000,
        .detection_ns = 2000,
        .aggregation_ns = 1500,
        .correlation_ns = 1000,
        .threat_intel_ns = 500,
        .brain_ns = 1000,
        .policy_ns = 1000,
        .pep_ns = 1000,
        .forensics_ns = 7000,
        .event_id = 4,
    });

    try std.testing.expect(harness.slowEventPercent() == 20); // 1/5 = 20%
}

test "PerformanceHarness getSummary returns all stage stats" {
    var harness = PerformanceHarness.init();

    harness.recordSample(.{
        .total_ns = 1000,
        .flow_ns = 100,
        .detection_ns = 200,
        .aggregation_ns = 150,
        .correlation_ns = 100,
        .threat_intel_ns = 50,
        .brain_ns = 100,
        .policy_ns = 100,
        .pep_ns = 100,
        .forensics_ns = 100,
        .event_id = 1,
    });

    const summary = harness.getSummary();
    try std.testing.expect(summary.total_events == 1);
    try std.testing.expect(summary.sample_count == 1);
    try std.testing.expect(summary.total_stats.isValid());
    try std.testing.expect(summary.flow_stats.isValid());
    try std.testing.expect(summary.detection_stats.isValid());
    try std.testing.expect(summary.aggregation_stats.isValid());
    try std.testing.expect(summary.correlation_stats.isValid());
    try std.testing.expect(summary.threat_intel_stats.isValid());
    try std.testing.expect(summary.brain_stats.isValid());
    try std.testing.expect(summary.policy_stats.isValid());
    try std.testing.expect(summary.pep_stats.isValid());
    try std.testing.expect(summary.forensics_stats.isValid());
}

test "PerformanceHarness reset zeroes everything" {
    var harness = PerformanceHarness.init();

    harness.recordSample(.{
        .total_ns = 1000,
        .flow_ns = 100,
        .detection_ns = 200,
        .aggregation_ns = 150,
        .correlation_ns = 100,
        .threat_intel_ns = 50,
        .brain_ns = 100,
        .policy_ns = 100,
        .pep_ns = 100,
        .forensics_ns = 100,
        .event_id = 1,
    });
    try std.testing.expect(harness.total_events == 1);

    harness.reset();
    try std.testing.expect(harness.total_events == 0);
    try std.testing.expect(harness.total_time_ns == 0);
    try std.testing.expect(harness.slow_event_count == 0);
    try std.testing.expect(harness.buffer.len() == 0);
}

test "getStageValue extracts correct field" {
    const sample = LatencySample{
        .total_ns = 1000,
        .flow_ns = 100,
        .detection_ns = 200,
        .aggregation_ns = 150,
        .correlation_ns = 100,
        .threat_intel_ns = 50,
        .brain_ns = 100,
        .policy_ns = 100,
        .pep_ns = 100,
        .forensics_ns = 100,
        .event_id = 1,
    };

    try std.testing.expect(getStageValue(sample, .total) == 1000);
    try std.testing.expect(getStageValue(sample, .flow) == 100);
    try std.testing.expect(getStageValue(sample, .detection) == 200);
    try std.testing.expect(getStageValue(sample, .aggregation) == 150);
    try std.testing.expect(getStageValue(sample, .correlation) == 100);
    try std.testing.expect(getStageValue(sample, .threat_intel) == 50);
    try std.testing.expect(getStageValue(sample, .brain) == 100);
    try std.testing.expect(getStageValue(sample, .policy) == 100);
    try std.testing.expect(getStageValue(sample, .pep) == 100);
    try std.testing.expect(getStageValue(sample, .forensics) == 100);
}
