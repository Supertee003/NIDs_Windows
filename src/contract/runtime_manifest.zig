// I03 - Runtime Manifest & Capability Declaration
// AEGIS NIDS v5.0+ â€” Self-describing runtime for fail-soft feature negotiation
//
// The runtime manifest is published once at startup. All subsystems query it
// to determine: "is feature X available?", "what is the configured cap?",
// "should I degrade or hard-fail?".

const std = @import("std");
const event = @import("event.zig");

// ----------------------------------------------------------------------------
// Capability flags (bitmask)
// ----------------------------------------------------------------------------
pub const Capability = packed struct {
    has_npcap: bool = false,
    has_etw_realtime: bool = false,
    has_fim: bool = false,
    has_registry_monitor: bool = false,
    has_wfp_block: bool = false,
    has_injection_detector: bool = false,
    has_federation: bool = false,
    has_tls: bool = false,
    has_pep_rust: bool = false,
    has_xdr: bool = false,
    has_replay: bool = false,
    has_forensic_pipeline: bool = false,
    has_fault_injection: bool = false,
    _reserved: u18 = 0,
};

// ----------------------------------------------------------------------------
// Limits â€” caps for memory, queues, tables
// ----------------------------------------------------------------------------
pub const Limits = struct {
    pub const FLOW_TABLE_ENTRIES: u32 = 4096;
    pub const FLOW_EVICTION_TIMEOUT_SEC: u32 = 60;
    pub const EVENT_QUEUE_DEPTH: u32 = 65536;
    pub const PAYLOAD_BUFFER_BYTES: u32 = 1 << 24; // 16 MiB
    pub const FORENSIC_RING_BYTES: u32 = 1 << 26;  // 64 MiB
    pub const SIGNATURE_RULE_MAX: u32 = 100_000;
    pub const ANOMALY_BASELINE_SAMPLES: u32 = 1000;
    pub const CORRELATOR_WINDOW_SEC: u32 = 300;
    pub const FEDERATION_NODES_MAX: u8 = 64;
    pub const FEDERATION_HEARTBEAT_MS: u32 = 1000;
    pub const WATCHDOG_TIMEOUT_MS: u32 = 5000;
    pub const LATENCY_HISTOGRAM_BUCKETS: u8 = 32;
};

// ----------------------------------------------------------------------------
// RuntimeManifest â€” global, read-only after init
// ----------------------------------------------------------------------------
pub const RuntimeManifest = struct {
    version: u16 = event.EVENT_VERSION,
    build_commit: [40]u8 = [_]u8{0} ** 40,
    build_timestamp: u64 = 0,
    start_timestamp_ns: i128 = 0,
    process_id: u32 = 0,
    hostname: [64]u8 = [_]u8{0} ** 64,
    capabilities: Capability = .{},
    degraded_mode: bool = false,
    degrade_reason: [128]u8 = [_]u8{0} ** 128,

    var instance: ?RuntimeManifest = null;

    pub fn init() RuntimeManifest {
        return .{
            .start_timestamp_ns = std.time.nanoTimestamp(),
            .process_id = @intCast(std.os.linux.getpid()),
        };
    }

    pub fn global() *RuntimeManifest {
        return &instance.?;
    }

    pub fn publish(capabilities: Capability) void {
        instance = .{
            .start_timestamp_ns = std.time.nanoTimestamp(),
            .capabilities = capabilities,
            .process_id = if (@import("builtin").os.tag == .windows) 0 else @intCast(std.os.linux.getpid()),
        };
    }

    pub fn degrade(reason: []const u8) void {
        if (instance) |*m| {
            m.degraded_mode = true;
            const n = @min(reason.len, m.degrade_reason.len);
            @memcpy(m.degrade_reason[0..n], reason[0..n]);
        }
    }

    pub fn has(self: *const RuntimeManifest, comptime field: []const u8) bool {
        return @field(self.capabilities, field);
    }
};

// ----------------------------------------------------------------------------
// CapabilityProbe â€” runtime feature detection (Windows-only APIs are stubbed
// on Linux so unit tests can run)
// ----------------------------------------------------------------------------
pub fn probeCapabilities() Capability {
    var c: Capability = .{};
    c.has_npcap = probeNpcap();
    c.has_etw_realtime = probeEtw();
    c.has_fim = probeFim();
    c.has_registry_monitor = probeRegistry();
    c.has_wfp_block = probeWfp();
    c.has_injection_detector = true;
    c.has_federation = true;
    c.has_tls = true;
    c.has_pep_rust = true;
    c.has_xdr = true;
    c.has_replay = true;
    c.has_forensic_pipeline = true;
    c.has_fault_injection = true;
    return c;
}

fn probeNpcap() bool {
    if (@import("builtin").os.tag != .windows) return false;
    // On Windows, attempt to load wpcap.dll dynamically
    var lib = std.DynLib.open("wpcap.dll") catch return false;
    lib.close();
    return true;
}

fn probeEtw() bool {
    // ETW is always available on Vista+
    return @import("builtin").os.tag == .windows;
}

fn probeFim() bool {
    return @import("builtin").os.tag == .windows;
}

fn probeRegistry() bool {
    return @import("builtin").os.tag == .windows;
}

fn probeWfp() bool {
    if (@import("builtin").os.tag != .windows) return false;
    var lib = std.DynLib.open("fwpuclnt.dll") catch return false;
    lib.close();
    return true;
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------
test "Capability is packed u32" {
    try std.testing.expectEqual(@as(usize, 4), @sizeOf(Capability));
}

test "Limits are sane" {
    try std.testing.expect(Limits.FLOW_TABLE_ENTRIES >= 1024);
    try std.testing.expect(Limits.EVENT_QUEUE_DEPTH >= 1024);
}

test "probeCapabilities runs without panic" {
    const c = probeCapabilities();
    if (@import("builtin").os.tag == .windows) {
        // ETW and FIM are always available on Windows (Vista+)
        try std.testing.expect(c.has_etw_realtime);
        try std.testing.expect(c.has_fim);
    } else {
        // On Linux, all Windows-only features should be false
        try std.testing.expect(!c.has_npcap);
        try std.testing.expect(!c.has_etw_realtime);
        try std.testing.expect(!c.has_fim);
    }
}

test "RuntimeManifest degrade flag" {
    RuntimeManifest.publish(.{});
    try std.testing.expect(!RuntimeManifest.instance.?.degraded_mode);
    RuntimeManifest.degrade("test reason");
    try std.testing.expect(RuntimeManifest.instance.?.degraded_mode);
}
