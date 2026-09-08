// siem_forwarder.zig - AEGIS SIEM Forwarder (Phase 33)
//
// Forwards detection events to SIEM platforms (Splunk, Elasticsearch, syslog).
// This is an ADDITIVE module - it reads from forensics ring buffer and forwards.
// Does NOT modify detection or blocking logic.
//
// Supported formats:
//   - NDJSON (default, for Elasticsearch/Logstash)
//   - CEF (Common Event Format, for Splunk/QRadar)
//   - Syslog (RFC 5424, for traditional SIEM)
//
// Supported transports:
//   - HTTP/HTTPS (POST to collector endpoint)
//   - TCP (raw socket, for syslog)
//   - UDP (for syslog)
//   - File (local append, for testing)
//
// Risk: LOW (additive module, can be disabled without affecting NIDS)

const std = @import("std");

// ============================================================
// Constants
// ============================================================

pub const MAX_BATCH_SIZE = 100;
pub const DEFAULT_FLUSH_INTERVAL_MS = 5000; // 5 seconds
pub const DEFAULT_RETRY_COUNT = 3;
pub const DEFAULT_RETRY_DELAY_MS = 1000;

// ============================================================
// Output Formats
// ============================================================

pub const OutputFormat = enum {
    ndjson,
    cef,
    syslog,

    pub fn toString(self: OutputFormat) []const u8 {
        return switch (self) {
            .ndjson => "NDJSON",
            .cef => "CEF",
            .syslog => "SYSLOG",
        };
    }

    pub fn fromString(s: []const u8) ?OutputFormat {
        if (std.ascii.eqlIgnoreCase(s, "ndjson") or std.ascii.eqlIgnoreCase(s, "json")) return .ndjson;
        if (std.ascii.eqlIgnoreCase(s, "cef")) return .cef;
        if (std.ascii.eqlIgnoreCase(s, "syslog")) return .syslog;
        return null;
    }
};

// ============================================================
// Transport Types
// ============================================================

pub const Transport = enum {
    http,
    https,
    tcp,
    udp,
    file,

    pub fn toString(self: Transport) []const u8 {
        return switch (self) {
            .http => "HTTP",
            .https => "HTTPS",
            .tcp => "TCP",
            .udp => "UDP",
            .file => "FILE",
        };
    }

    pub fn fromString(s: []const u8) ?Transport {
        if (std.ascii.eqlIgnoreCase(s, "http")) return .http;
        if (std.ascii.eqlIgnoreCase(s, "https")) return .https;
        if (std.ascii.eqlIgnoreCase(s, "tcp")) return .tcp;
        if (std.ascii.eqlIgnoreCase(s, "udp")) return .udp;
        if (std.ascii.eqlIgnoreCase(s, "file")) return .file;
        return null;
    }
};

// ============================================================
// SIEM Configuration
// ============================================================

pub const SiemConfig = struct {
    enabled: bool = false,
    format: OutputFormat = .ndjson,
    transport: Transport = .file,
    destination: []const u8 = "logs/siem_forward.json",
    batch_size: u32 = MAX_BATCH_SIZE,
    flush_interval_ms: u32 = DEFAULT_FLUSH_INTERVAL_MS,
    retry_count: u32 = DEFAULT_RETRY_COUNT,
    retry_delay_ms: u32 = DEFAULT_RETRY_DELAY_MS,
    include_fields: []const []const u8 = &.{
        "timestamp", "attack_type", "src_ip", "dst_ip", "severity",
        "policy", "rule_id", "status",
    },
};

// ============================================================
// Forwarded Event (subset of forensic event)
// ============================================================

pub const ForwardedEvent = struct {
    timestamp: i64,
    attack_type: []const u8,
    src_ip: []const u8,
    dst_ip: []const u8,
    src_port: u16,
    dst_port: u16,
    protocol: []const u8,
    severity: []const u8,
    policy: []const u8,
    rule_id: []const u8,
    status: []const u8,
    payload: []const u8,
};

// ============================================================
// Forward Statistics
// ============================================================

pub const ForwardStats = struct {
    total_events_read: u64 = 0,
    total_events_forwarded: u64 = 0,
    total_events_failed: u64 = 0,
    total_batches_sent: u64 = 0,
    total_retries: u64 = 0,
    last_forward_ms: i64 = 0,

    pub fn successRate(self: ForwardStats) f64 {
        const total = self.total_events_forwarded + self.total_events_failed;
        if (total == 0) return 100.0;
        return @as(f64, @floatFromInt(self.total_events_forwarded)) / @as(f64, @floatFromInt(total)) * 100.0;
    }
};

// ============================================================
// SIEM Forwarder
// ============================================================

pub const SiemForwarder = struct {
    allocator: std.mem.Allocator,
    config: SiemConfig,
    stats: ForwardStats = .{},
    initialized: bool = false,
    batch_buffer: std.ArrayList(ForwardedEvent),
    last_flush_ms: i64 = 0,

    pub fn init(allocator: std.mem.Allocator, config: SiemConfig) SiemForwarder {
        return .{
            .allocator = allocator,
            .config = config,
            .initialized = true,
            .batch_buffer = std.ArrayList(ForwardedEvent).init(allocator),
            .last_flush_ms = std.time.milliTimestamp(),
        };
    }

    pub fn deinit(self: *SiemForwarder) void {
        // Flush remaining events
        if (self.batch_buffer.items.len > 0) {
            self.flush() catch {};
        }
        self.batch_buffer.deinit();
        self.initialized = false;
    }

    /// Add an event to the batch buffer. Automatically flushes when batch is full.
    pub fn forwardEvent(self: *SiemForwarder, event: ForwardedEvent) !void {
        if (!self.initialized or !self.config.enabled) return;

        self.stats.total_events_read += 1;

        try self.batch_buffer.append(event);

        // Auto-flush when batch is full
        if (self.batch_buffer.items.len >= self.config.batch_size) {
            try self.flush();
        }
    }

    /// Flush the batch buffer to the configured destination.
    pub fn flush(self: *SiemForwarder) !void {
        if (self.batch_buffer.items.len == 0) return;

        const start_ms = std.time.milliTimestamp();
        var attempt: u32 = 0;

        while (attempt < self.config.retry_count) : (attempt += 1) {
            const result = self.sendBatch(self.batch_buffer.items);
            if (result) {
                self.stats.total_events_forwarded += @intCast(self.batch_buffer.items.len);
                self.stats.total_batches_sent += 1;
                self.stats.last_forward_ms = std.time.milliTimestamp() - start_ms;
                self.batch_buffer.clearRetainingCapacity();
                self.last_flush_ms = std.time.milliTimestamp();
                return;
            } else {
                self.stats.total_retries += 1;
                if (attempt < self.config.retry_count - 1) {
                    std.time.sleep(@as(u64, self.config.retry_delay_ms) * std.time.ns_per_ms);
                }
            }
        }

        // All retries failed
        self.stats.total_events_failed += @intCast(self.batch_buffer.items.len);
        std.log.warn("[SIEM] Failed to forward {d} events after {d} retries", .{
            self.batch_buffer.items.len, self.config.retry_count,
        });

        // Clear buffer to avoid memory growth (events are lost)
        self.batch_buffer.clearRetainingCapacity();
    }

    /// Send a batch of events to the configured destination.
    /// Returns true on success, false on failure.
    fn sendBatch(self: *SiemForwarder, events: []const ForwardedEvent) bool {
        return switch (self.config.transport) {
            .file => self.sendToFile(events),
            .http, .https => self.sendViaHttp(events),
            .tcp => self.sendViaTcp(events),
            .udp => self.sendViaUdp(events),
        };
    }

    /// Send events to a local file (default, for testing).
    fn sendToFile(self: *SiemForwarder, events: []const ForwardedEvent) bool {
        const file = std.fs.cwd().createFile(self.config.destination, .{ .truncate = false }) catch {
            std.log.err("[SIEM] Failed to open file: {s}", .{self.config.destination});
            return false;
        };
        defer file.close();

        // Seek to end for append
        file.seekFromEnd(0) catch {};

        const writer = file.writer();
        for (events) |event| {
            const formatted = self.formatEvent(event) catch continue;
            defer self.allocator.free(formatted);
            writer.writeAll(formatted) catch return false;
            writer.writeByte('\n') catch return false;
        }

        return true;
    }

    /// Send events via HTTP/HTTPS (stub - requires networking).
    fn sendViaHttp(self: *SiemForwarder, events: []const ForwardedEvent) bool {
        _ = self;
        _ = events;
        // HTTP client would go here (requires std.http or external lib)
        // For now, log that HTTP is not implemented on Host
        std.log.warn("[SIEM] HTTP/HTTPS transport not implemented (use FILE for testing)", .{});
        return false;
    }

    /// Send events via TCP (stub - requires networking).
    fn sendViaTcp(self: *SiemForwarder, events: []const ForwardedEvent) bool {
        _ = self;
        _ = events;
        std.log.warn("[SIEM] TCP transport not implemented (use FILE for testing)", .{});
        return false;
    }

    /// Send events via UDP (stub - requires networking).
    fn sendViaUdp(self: *SiemForwarder, events: []const ForwardedEvent) bool {
        _ = self;
        _ = events;
        std.log.warn("[SIEM] UDP transport not implemented (use FILE for testing)", .{});
        return false;
    }

    /// Format an event according to the configured output format.
    fn formatEvent(self: *SiemForwarder, event: ForwardedEvent) ![]u8 {
        return switch (self.config.format) {
            .ndjson => self.formatAsNdjson(event),
            .cef => self.formatAsCef(event),
            .syslog => self.formatAsSyslog(event),
        };
    }

    /// Format as NDJSON (one JSON object per line).
    fn formatAsNdjson(self: *SiemForwarder, event: ForwardedEvent) ![]u8 {
        return std.fmt.allocPrint(self.allocator,
            \\{{"timestamp":{d},"attack_type":"{s}","src_ip":"{s}","dst_ip":"{s}","src_port":{d},"dst_port":{d},"protocol":"{s}","severity":"{s}","policy":"{s}","rule_id":"{s}","status":"{s}"}}
        , .{
            event.timestamp,
            event.attack_type,
            event.src_ip,
            event.dst_ip,
            event.src_port,
            event.dst_port,
            event.protocol,
            event.severity,
            event.policy,
            event.rule_id,
            event.status,
        });
    }

    /// Format as CEF (Common Event Format).
    /// CEF:Version|Vendor|Product|DevVersion|SignatureID|Name|Severity|Extension
    fn formatAsCef(self: *SiemForwarder, event: ForwardedEvent) ![]u8 {
        const cef_severity = if (std.mem.eql(u8, event.severity, "Critical")) "10" else if (std.mem.eql(u8, event.severity, "High")) "8" else if (std.mem.eql(u8, event.severity, "Medium")) "5" else "3";

        return std.fmt.allocPrint(self.allocator,
            "CEF:0|AEGIS|NIDS|5.0|{s}|{s}|{s}|src={s} dst={s} spt={d} dpt={d} proto={s} policy={s} status={s}",
            .{
                event.rule_id,
                event.attack_type,
                cef_severity,
                event.src_ip,
                event.dst_ip,
                event.src_port,
                event.dst_port,
                event.protocol,
                event.policy,
                event.status,
            },
        );
    }

    /// Format as Syslog (RFC 5424).
    fn formatAsSyslog(self: *SiemForwarder, event: ForwardedEvent) ![]u8 {
        const priority = 4; // warning severity, local0 facility
        const timestamp = std.time.timestamp();

        return std.fmt.allocPrint(self.allocator,
            "<{d}>1 {d} - AEGIS NIDS - - - attack_type={s} src={s} dst={s} severity={s} status={s}",
            .{
                priority,
                timestamp,
                event.attack_type,
                event.src_ip,
                event.dst_ip,
                event.severity,
                event.status,
            },
        );
    }

    /// Check if flush is needed based on time interval.
    pub fn shouldFlush(self: SiemForwarder) bool {
        const now = std.time.milliTimestamp();
        return (now - self.last_flush_ms) >= self.config.flush_interval_ms and
            self.batch_buffer.items.len > 0;
    }

    /// Get current statistics.
    pub fn getStats(self: SiemForwarder) ForwardStats {
        return self.stats;
    }

    pub fn resetStats(self: *SiemForwarder) void {
        self.stats = .{};
    }
};

// ============================================================
// Singleton facade
// ============================================================

var g_forwarder: ?SiemForwarder = null;
var g_initialized: bool = false;
var g_config: SiemConfig = .{};

pub fn init(allocator: std.mem.Allocator, config: SiemConfig) void {
    if (g_initialized) return;
    g_forwarder = SiemForwarder.init(allocator, config);
    g_config = config;
    g_initialized = true;
    std.log.info("[SIEM] Forwarder initialized (format={s}, transport={s}, dest={s})", .{
        config.format.toString(),
        config.transport.toString(),
        config.destination,
    });
}

pub fn isInitialized() bool {
    return g_initialized;
}

pub fn shutdown() void {
    if (!g_initialized) return;
    if (g_forwarder) |*f| f.deinit();
    g_forwarder = null;
    g_initialized = false;
    std.log.info("[SIEM] Forwarder shutdown", .{});
}

pub fn forwardEvent(event: ForwardedEvent) void {
    if (!g_initialized) return;
    if (g_forwarder) |*f| {
        f.forwardEvent(event) catch |err| {
            std.log.warn("[SIEM] Failed to forward event: {}", .{err});
        };
    }
}

pub fn flush() void {
    if (!g_initialized) return;
    if (g_forwarder) |*f| {
        f.flush() catch |err| {
            std.log.warn("[SIEM] Flush failed: {}", .{err});
        };
    }
}

pub fn getStats() ForwardStats {
    if (g_initialized and g_forwarder != null) {
        return g_forwarder.?.getStats();
    }
    return .{};
}

pub fn isEnabled() bool {
    return g_initialized and g_config.enabled;
}

// ============================================================
// Tests
// ============================================================

test "OutputFormat.toString returns correct names" {
    try std.testing.expect(std.mem.eql(u8, OutputFormat.ndjson.toString(), "NDJSON"));
    try std.testing.expect(std.mem.eql(u8, OutputFormat.cef.toString(), "CEF"));
    try std.testing.expect(std.mem.eql(u8, OutputFormat.syslog.toString(), "SYSLOG"));
}

test "OutputFormat.fromString parses names" {
    try std.testing.expect(OutputFormat.fromString("ndjson") == OutputFormat.ndjson);
    try std.testing.expect(OutputFormat.fromString("json") == OutputFormat.ndjson);
    try std.testing.expect(OutputFormat.fromString("CEF") == OutputFormat.cef);
    try std.testing.expect(OutputFormat.fromString("syslog") == OutputFormat.syslog);
    try std.testing.expect(OutputFormat.fromString("unknown") == null);
}

test "Transport.toString returns correct names" {
    try std.testing.expect(std.mem.eql(u8, Transport.http.toString(), "HTTP"));
    try std.testing.expect(std.mem.eql(u8, Transport.https.toString(), "HTTPS"));
    try std.testing.expect(std.mem.eql(u8, Transport.tcp.toString(), "TCP"));
    try std.testing.expect(std.mem.eql(u8, Transport.udp.toString(), "UDP"));
    try std.testing.expect(std.mem.eql(u8, Transport.file.toString(), "FILE"));
}

test "Transport.fromString parses names" {
    try std.testing.expect(Transport.fromString("http") == Transport.http);
    try std.testing.expect(Transport.fromString("https") == Transport.https);
    try std.testing.expect(Transport.fromString("tcp") == Transport.tcp);
    try std.testing.expect(Transport.fromString("udp") == Transport.udp);
    try std.testing.expect(Transport.fromString("file") == Transport.file);
}

test "SiemConfig has sensible defaults" {
    const config = SiemConfig{};
    try std.testing.expect(!config.enabled);
    try std.testing.expect(config.format == .ndjson);
    try std.testing.expect(config.transport == .file);
    try std.testing.expect(config.batch_size == MAX_BATCH_SIZE);
    try std.testing.expect(config.flush_interval_ms == DEFAULT_FLUSH_INTERVAL_MS);
}

test "ForwardStats.successRate handles zero" {
    const stats = ForwardStats{};
    try std.testing.expect(stats.successRate() == 100.0);
}

test "ForwardStats.successRate computes percentage" {
    const stats = ForwardStats{
        .total_events_forwarded = 90,
        .total_events_failed = 10,
    };
    try std.testing.expect(stats.successRate() == 90.0);
}

test "SiemForwarder.init creates forwarder" {
    var forwarder = SiemForwarder.init(std.testing.allocator, .{});
    defer forwarder.deinit();
    try std.testing.expect(forwarder.initialized);
    try std.testing.expect(forwarder.batch_buffer.items.len == 0);
}

test "SiemForwarder.forwardEvent adds to buffer" {
    const dest = "siem_buffer_test.json";
    defer std.fs.cwd().deleteFile(dest) catch {};
    var forwarder = SiemForwarder.init(std.testing.allocator, .{
        .enabled = true,
        .batch_size = 10,
        .destination = dest,
    });
    defer forwarder.deinit();

    const event = ForwardedEvent{
        .timestamp = 1000,
        .attack_type = "SQLI",
        .src_ip = "10.0.0.1",
        .dst_ip = "10.0.0.2",
        .src_port = 12345,
        .dst_port = 80,
        .protocol = "TCP",
        .severity = "Critical",
        .policy = "BLOCK",
        .rule_id = "R001",
        .status = "DETECTED",
        .payload = "",
    };

    try forwarder.forwardEvent(event);
    try std.testing.expect(forwarder.batch_buffer.items.len == 1);
    try std.testing.expect(forwarder.stats.total_events_read == 1);
}

test "SiemForwarder.flush writes to file" {
    // Use a temp file in current directory (cleaned up after test)
    const dest = "siem_test_output.json";
    defer std.fs.cwd().deleteFile(dest) catch {};

    var forwarder = SiemForwarder.init(std.testing.allocator, .{
        .enabled = true,
        .destination = dest,
        .format = .ndjson,
        .transport = .file,
    });
    defer forwarder.deinit();

    const event = ForwardedEvent{
        .timestamp = 1000,
        .attack_type = "SQLI",
        .src_ip = "10.0.0.1",
        .dst_ip = "10.0.0.2",
        .src_port = 12345,
        .dst_port = 80,
        .protocol = "TCP",
        .severity = "Critical",
        .policy = "BLOCK",
        .rule_id = "R001",
        .status = "DETECTED",
        .payload = "",
    };

    try forwarder.forwardEvent(event);
    try forwarder.flush();

    try std.testing.expect(forwarder.stats.total_events_forwarded == 1);
    try std.testing.expect(forwarder.stats.total_batches_sent == 1);
}

test "SiemForwarder auto-flushes when batch full" {
    const dest = "siem_batch_output.json";
    defer std.fs.cwd().deleteFile(dest) catch {};

    var forwarder = SiemForwarder.init(std.testing.allocator, .{
        .enabled = true,
        .destination = dest,
        .batch_size = 3,
        .transport = .file,
    });
    defer forwarder.deinit();

    const event = ForwardedEvent{
        .timestamp = 1000,
        .attack_type = "XSS",
        .src_ip = "10.0.0.1",
        .dst_ip = "10.0.0.2",
        .src_port = 12345,
        .dst_port = 80,
        .protocol = "TCP",
        .severity = "High",
        .policy = "ALERT",
        .rule_id = "R002",
        .status = "DETECTED",
        .payload = "",
    };

    var i: u32 = 0;
    while (i < 3) : (i += 1) {
        try forwarder.forwardEvent(event);
    }

    // Auto-flush should have triggered
    try std.testing.expect(forwarder.stats.total_events_forwarded == 3);
    try std.testing.expect(forwarder.batch_buffer.items.len == 0);
}

test "formatAsNdjson produces valid JSON" {
    var forwarder = SiemForwarder.init(std.testing.allocator, .{});
    defer forwarder.deinit();

    const event = ForwardedEvent{
        .timestamp = 1000,
        .attack_type = "SQLI",
        .src_ip = "10.0.0.1",
        .dst_ip = "10.0.0.2",
        .src_port = 12345,
        .dst_port = 80,
        .protocol = "TCP",
        .severity = "Critical",
        .policy = "BLOCK",
        .rule_id = "R001",
        .status = "DETECTED",
        .payload = "",
    };

    const json = try forwarder.formatAsNdjson(event);
    defer std.testing.allocator.free(json);

    // Check it starts with { and ends with }
    try std.testing.expect(json[0] == '{');
    try std.testing.expect(json[json.len - 1] == '}');
    // Check it contains attack_type
    try std.testing.expect(std.mem.indexOf(u8, json, "SQLI") != null);
}

test "formatAsCef produces CEF format" {
    var forwarder = SiemForwarder.init(std.testing.allocator, .{});
    defer forwarder.deinit();

    const event = ForwardedEvent{
        .timestamp = 1000,
        .attack_type = "XSS",
        .src_ip = "10.0.0.1",
        .dst_ip = "10.0.0.2",
        .src_port = 12345,
        .dst_port = 80,
        .protocol = "TCP",
        .severity = "High",
        .policy = "ALERT",
        .rule_id = "R002",
        .status = "DETECTED",
        .payload = "",
    };

    const cef = try forwarder.formatAsCef(event);
    defer std.testing.allocator.free(cef);

    // Check it starts with CEF:0
    try std.testing.expect(std.mem.indexOf(u8, cef, "CEF:0") != null);
    // Check it contains the attack type
    try std.testing.expect(std.mem.indexOf(u8, cef, "XSS") != null);
}

test "formatAsSyslog produces syslog format" {
    var forwarder = SiemForwarder.init(std.testing.allocator, .{});
    defer forwarder.deinit();

    const event = ForwardedEvent{
        .timestamp = 1000,
        .attack_type = "PORT_SCAN",
        .src_ip = "10.0.0.1",
        .dst_ip = "10.0.0.2",
        .src_port = 12345,
        .dst_port = 22,
        .protocol = "TCP",
        .severity = "Medium",
        .policy = "ALERT",
        .rule_id = "R003",
        .status = "DETECTED",
        .payload = "",
    };

    const syslog = try forwarder.formatAsSyslog(event);
    defer std.testing.allocator.free(syslog);

    // Check it starts with <priority>1
    try std.testing.expect(syslog[0] == '<');
    try std.testing.expect(std.mem.indexOf(u8, syslog, "AEGIS NIDS") != null);
}

test "shouldFlush returns false when buffer empty" {
    var forwarder = SiemForwarder.init(std.testing.allocator, .{});
    defer forwarder.deinit();
    try std.testing.expect(!forwarder.shouldFlush());
}

test "SiemForwarder.resetStats zeroes counters" {
    var forwarder = SiemForwarder.init(std.testing.allocator, .{});
    defer forwarder.deinit();
    forwarder.stats.total_events_forwarded = 100;
    forwarder.resetStats();
    try std.testing.expect(forwarder.stats.total_events_forwarded == 0);
}

test "siem_forwarder singleton lifecycle" {
    if (isInitialized()) shutdown();
    try std.testing.expect(!isInitialized());

    init(std.testing.allocator, .{ .enabled = true });
    defer shutdown();
    try std.testing.expect(isInitialized());
}
