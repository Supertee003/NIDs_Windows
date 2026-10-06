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
// Spool replay bounds (T1-SIEM-021): one flush replays at most this many
// spooled lines and reads at most this many bytes, so a huge spool file
// can never stall the live path. The remainder waits for later flushes.
pub const MAX_SPOOL_REPLAY_LINES = MAX_BATCH_SIZE;
pub const MAX_SPOOL_REPLAY_BYTES = 1024 * 1024;

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
    /// Collector endpoint for http/https/tcp/udp transports
    /// (e.g. "https://collector:8088", "tcp://syslog:514").
    endpoint: []const u8 = "",
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
    /// Events neither delivered nor lost: spilled to <destination>.spool
    /// for later replay after all retries were exhausted.
    total_events_spooled: u64 = 0,
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
    /// Ownership: string fields are duplicated into the forwarder allocator,
    /// so callers may pass stack/short-lived slices (e.g. the pipeline hot
    /// path formats into stack buffers). Freed on buffer clear.
    pub fn forwardEvent(self: *SiemForwarder, event: ForwardedEvent) !void {
        if (!self.initialized or !self.config.enabled) return;

        self.stats.total_events_read += 1;

        try self.batch_buffer.append(try self.dupEvent(event));

        // Auto-flush when batch is full
        if (self.batch_buffer.items.len >= self.config.batch_size) {
            try self.flush();
        }
    }

    fn dupEvent(self: *SiemForwarder, event: ForwardedEvent) !ForwardedEvent {
        var owned = event;
        owned.attack_type = try self.allocator.dupe(u8, event.attack_type);
        errdefer self.allocator.free(owned.attack_type);
        owned.src_ip = try self.allocator.dupe(u8, event.src_ip);
        errdefer self.allocator.free(owned.src_ip);
        owned.dst_ip = try self.allocator.dupe(u8, event.dst_ip);
        errdefer self.allocator.free(owned.dst_ip);
        owned.protocol = try self.allocator.dupe(u8, event.protocol);
        errdefer self.allocator.free(owned.protocol);
        owned.severity = try self.allocator.dupe(u8, event.severity);
        errdefer self.allocator.free(owned.severity);
        owned.policy = try self.allocator.dupe(u8, event.policy);
        errdefer self.allocator.free(owned.policy);
        owned.rule_id = try self.allocator.dupe(u8, event.rule_id);
        errdefer self.allocator.free(owned.rule_id);
        owned.status = try self.allocator.dupe(u8, event.status);
        errdefer self.allocator.free(owned.status);
        owned.payload = try self.allocator.dupe(u8, event.payload);
        return owned;
    }

    fn freeEventStrings(self: *SiemForwarder, event: *const ForwardedEvent) void {
        self.allocator.free(event.attack_type);
        self.allocator.free(event.src_ip);
        self.allocator.free(event.dst_ip);
        self.allocator.free(event.protocol);
        self.allocator.free(event.severity);
        self.allocator.free(event.policy);
        self.allocator.free(event.rule_id);
        self.allocator.free(event.status);
        self.allocator.free(event.payload);
    }

    fn clearBuffer(self: *SiemForwarder) void {
        for (self.batch_buffer.items) |*ev| self.freeEventStrings(ev);
        self.batch_buffer.clearRetainingCapacity();
    }

    /// Flush the batch buffer to the configured destination.
    pub fn flush(self: *SiemForwarder) !void {
        // T1-SIEM-021: drain yesterday's evidence first (bounded), so a
        // spilled batch is retried automatically instead of waiting for an
        // operator. Replay is best-effort single-pass: anything still
        // undeliverable stays spooled for a later flush.
        _ = self.replaySpool();
        if (self.batch_buffer.items.len == 0) return;

        const start_ms = std.time.milliTimestamp();
        var attempt: u32 = 0;

        while (attempt < self.config.retry_count) : (attempt += 1) {
            const result = self.sendBatch(self.batch_buffer.items);
            if (result) {
                self.stats.total_events_forwarded += @intCast(self.batch_buffer.items.len);
                self.stats.total_batches_sent += 1;
                self.stats.last_forward_ms = std.time.milliTimestamp() - start_ms;
                self.clearBuffer();
                self.last_flush_ms = std.time.milliTimestamp();
                return;
            } else {
                self.stats.total_retries += 1;
                if (attempt < self.config.retry_count - 1) {
                    std.time.sleep(@as(u64, self.config.retry_delay_ms) * std.time.ns_per_ms);
                }
            }
        }

        // All retries failed: spill to <destination>.spool instead of
        // dropping. A spooled batch is pending evidence, not lost data; an
        // operator (or a future auto-retry pass) replays the spool file.
        // Only a failed spill itself counts as lost.
        if (self.spillBatch(self.batch_buffer.items)) {
            self.stats.total_events_spooled += @intCast(self.batch_buffer.items.len);
            std.log.warn("[SIEM] Forward failed after {d} retries; {d} events spooled for replay", .{
                self.config.retry_count, self.batch_buffer.items.len,
            });
        } else {
            self.stats.total_events_failed += @intCast(self.batch_buffer.items.len);
            std.log.err("[SIEM] Forward failed after {d} retries AND spool write failed; {d} events lost", .{
                self.config.retry_count, self.batch_buffer.items.len,
            });
        }
        self.clearBuffer();
    }

    /// Result of one bounded spool-replay pass.
    pub const SpoolReplayResult = struct {
        replayed: u64 = 0,
        remaining: u64 = 0,
    };

    /// Replay spooled lines (bounded single pass, oldest first).
    /// Fully delivered lines are acked by removing them from the spool;
    /// the first undeliverable line stops the pass and the tail (including
    /// that line) is rewritten back.Delivery is at-least-once: a crash
    /// between send and ack may duplicate a line at the collector, which
    /// carries event_ids/timestamps for dedupe.
    pub fn replaySpool(self: *SiemForwarder) SpoolReplayResult {
        var result = SpoolReplayResult{};
        if (!self.initialized or !self.config.enabled) return result;
        const spool_path = std.fmt.allocPrint(self.allocator, "{s}.spool", .{self.config.destination}) catch return result;
        defer self.allocator.free(spool_path);
        const raw = std.fs.cwd().readFileAlloc(self.allocator, spool_path, MAX_SPOOL_REPLAY_BYTES) catch return result;
        defer self.allocator.free(raw);

        var sent_count: usize = 0;
        var line_count: usize = 0;
        var lines = std.mem.splitScalar(u8, raw, '\n');
        var stopped = false;
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            line_count += 1;
            if (line_count > MAX_SPOOL_REPLAY_LINES or stopped) {
                result.remaining += 1;
                continue;
            }
            if (self.sendRawLine(line)) {
                sent_count += 1;
                self.stats.total_events_forwarded += 1;
            } else {
                stopped = true;
                result.remaining += 1;
            }
        }
        result.replayed = sent_count;
        if (result.remaining == 0) {
            std.fs.cwd().deleteFile(spool_path) catch {};
        } else {
            rewriteSpoolTail(spool_path, raw, sent_count);
        }
        if (sent_count > 0) {
            self.stats.total_batches_sent += 1;
            self.last_flush_ms = std.time.milliTimestamp();
            std.log.info("[SIEM] Spool replay: {d} replayed, {d} remaining", .{ sent_count, result.remaining });
        }
        return result;
    }

    /// Rewrite the spool file keeping only lines after the first
    /// `acked_lines` non-empty lines. Best effort: a rewrite failure keeps
    /// the old file (at-least-once may duplicate, never loses).
    fn rewriteSpoolTail(spool_path: []const u8, raw: []const u8, acked_lines: usize) void {
        const file = std.fs.cwd().createFile(spool_path, .{ .truncate = true }) catch {
            std.log.err("[SIEM] Failed to rewrite spool tail: {s}", .{spool_path});
            return;
        };
        defer file.close();
        var seen: usize = 0;
        var lines = std.mem.splitScalar(u8, raw, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            seen += 1;
            if (seen <= acked_lines) continue;
            file.writer().writeAll(line) catch return;
            file.writer().writeByte('\n') catch return;
        }
    }

    /// Send one already-formatted spool line over the configured transport.
    /// Returns true only when the collector accepted the bytes.
    fn sendRawLine(self: *SiemForwarder, line: []const u8) bool {
        return switch (self.config.transport) {
            .file => self.sendRawToFile(line),
            .http, .https => self.sendRawViaHttp(line),
            .tcp => self.sendRawViaTcp(line),
            .udp => self.sendRawViaUdp(line),
        };
    }

    fn sendRawToFile(self: *SiemForwarder, line: []const u8) bool {
        const file = std.fs.cwd().createFile(self.config.destination, .{ .truncate = false }) catch return false;
        defer file.close();
        file.seekFromEnd(0) catch {};
        file.writer().writeAll(line) catch return false;
        file.writer().writeByte('\n') catch return false;
        return true;
    }

    fn sendRawViaHttp(self: *SiemForwarder, line: []const u8) bool {
        const uri = std.Uri.parse(self.config.endpoint) catch return false;
        if (uriHost(uri) == null) return false;
        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();
        const extra_headers = [_]std.http.Header{
            .{ .name = "Content-Type", .value = "application/json" },
        };
        var req_buf: [16 * 1024]u8 = undefined;
        var req = client.open(.POST, uri, .{ .server_header_buffer = &req_buf, .extra_headers = &extra_headers }) catch |err| {
            std.log.warn("[SIEM] Spool replay HTTP open failed: {}", .{err});
            return false;
        };
        defer req.deinit();
        req.writeAll(line) catch |err| {
            std.log.warn("[SIEM] Spool replay HTTP write failed: {}", .{err});
            return false;
        };
        req.finish() catch |err| {
            std.log.warn("[SIEM] Spool replay HTTP finish failed: {}", .{err});
            return false;
        };
        req.wait() catch |err| {
            std.log.warn("[SIEM] Spool replay HTTP wait failed: {}", .{err});
            return false;
        };
        if (req.response.status != .ok) {
            std.log.warn("[SIEM] Spool replay HTTP status: {}", .{req.response.status});
            return false;
        }
        return true;
    }

    fn sendRawViaTcp(self: *SiemForwarder, line: []const u8) bool {
        const uri = std.Uri.parse(self.config.endpoint) catch return false;
        const host = uriHost(uri) orelse return false;
        const port: u16 = uri.port orelse 514;
        var stream = std.net.tcpConnectToHost(self.allocator, host, port) catch |err| {
            std.log.warn("[SIEM] Spool replay TCP connect failed: {}", .{err});
            return false;
        };
        defer stream.close();
        stream.writeAll(line) catch |err| {
            std.log.warn("[SIEM] Spool replay TCP write failed: {}", .{err});
            return false;
        };
        return true;
    }

    fn sendRawViaUdp(self: *SiemForwarder, line: []const u8) bool {
        const uri = std.Uri.parse(self.config.endpoint) catch return false;
        const host = uriHost(uri) orelse return false;
        const port: u16 = uri.port orelse 514;
        const addr_list = std.net.getAddressList(self.allocator, host, port) catch |err| {
            std.log.warn("[SIEM] Spool replay UDP resolve failed: {}", .{err});
            return false;
        };
        defer addr_list.deinit();
        if (addr_list.addrs.len == 0) return false;
        const addr = addr_list.addrs[0];
        const sock = std.posix.socket(addr.any.family, std.posix.SOCK.DGRAM, 0) catch return false;
        defer std.posix.close(sock);
        std.posix.connect(sock, &addr.any, addr.getOsSockLen()) catch return false;
        _ = std.posix.send(sock, line, 0) catch |err| {
            std.log.warn("[SIEM] Spool replay UDP write failed: {}", .{err});
            return false;
        };
        return true;
    }

    /// Append a batch to the durable spool file next to the destination.
    /// Returns true when every event was persisted.
    fn spillBatch(self: *SiemForwarder, events: []const ForwardedEvent) bool {
        const spool_path = std.fmt.allocPrint(self.allocator, "{s}.spool", .{self.config.destination}) catch return false;
        defer self.allocator.free(spool_path);
        const file = std.fs.cwd().createFile(spool_path, .{ .truncate = false }) catch {
            std.log.err("[SIEM] Failed to open spool file: {s}", .{spool_path});
            return false;
        };
        defer file.close();
        file.seekFromEnd(0) catch {};
        const writer = file.writer();
        for (events) |event| {
            const formatted = self.formatEvent(event) catch return false;
            defer self.allocator.free(formatted);
            writer.writeAll(formatted) catch return false;
            writer.writeByte('\n') catch return false;
        }
        return true;
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

    /// Unwrap a URI host component (raw or percent-encoded) to bytes.
    fn uriHost(uri: std.Uri) ?[]const u8 {
        const comp = uri.host orelse return null;
        return switch (comp) {
            .raw => |raw| raw,
            .percent_encoded => |enc| enc,
        };
    }

    /// Send events via HTTP/HTTPS (POST to collector endpoint).
    fn sendViaHttp(self: *SiemForwarder, events: []const ForwardedEvent) bool {
        const uri = std.Uri.parse(self.config.endpoint) catch {
            std.log.err("[SIEM] Invalid HTTP endpoint: {s}", .{self.config.endpoint});
            return false;
        };

        if (uriHost(uri) == null) {
            std.log.err("[SIEM] HTTP endpoint missing host", .{});
            return false;
        }

        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();

        const extra_headers = [_]std.http.Header{
            .{ .name = "Content-Type", .value = "application/json" },
        };
        // At-least-once honesty: ANY undelivered event fails the batch so
        // the retry loop (then the spool file) engages. Returning true here
        // with silent skips would count lost events as forwarded.
        var failed = false;
        for (events) |event| {
            const body = self.formatEvent(event) catch {
                failed = true;
                continue;
            };
            defer self.allocator.free(body);

            var req_buf: [16 * 1024]u8 = undefined;
            var req = client.open(.POST, uri, .{ .server_header_buffer = &req_buf, .extra_headers = &extra_headers }) catch |err| {
                // Network failure, not a code bug: warn (never err — the
                // test runner fails any test that logs at err level, and a
                // dead collector is an operator condition, not an assertion).
                std.log.warn("[SIEM] HTTP open failed: {}", .{err});
                failed = true;
                continue;
            };
            defer req.deinit();

            req.writeAll(body) catch |err| {
                std.log.warn("[SIEM] HTTP write failed: {}", .{err});
                failed = true;
                continue;
            };

            req.finish() catch |err| {
                std.log.warn("[SIEM] HTTP finish failed: {}", .{err});
                failed = true;
                continue;
            };

            req.wait() catch |err| {
                std.log.warn("[SIEM] HTTP wait failed: {}", .{err});
                failed = true;
                continue;
            };

            if (req.response.status != .ok) {
                std.log.warn("[SIEM] HTTP status: {}", .{req.response.status});
                failed = true;
            }
        }
        return !failed;
    }

    /// Send events via TCP (raw socket, for syslog).
    fn sendViaTcp(self: *SiemForwarder, events: []const ForwardedEvent) bool {
        const uri = std.Uri.parse(self.config.endpoint) catch {
            std.log.err("[SIEM] Invalid TCP endpoint: {s}", .{self.config.endpoint});
            return false;
        };

        const host = uriHost(uri) orelse {
            std.log.err("[SIEM] TCP endpoint missing host", .{});
            return false;
        };

        const port: u16 = uri.port orelse 514; // Default syslog port

        var stream = std.net.tcpConnectToHost(self.allocator, host, port) catch |err| {
            std.log.warn("[SIEM] TCP connect failed: {}", .{err});
            return false;
        };
        defer stream.close();

        var failed = false;
        for (events) |event| {
            const body = self.formatEvent(event) catch {
                failed = true;
                continue;
            };
            defer self.allocator.free(body);

            stream.writeAll(body) catch |err| {
                std.log.warn("[SIEM] TCP write failed: {}", .{err});
                failed = true;
                continue;
            };
        }
        return !failed;
    }

    /// Send events via UDP (for syslog).
    fn sendViaUdp(self: *SiemForwarder, events: []const ForwardedEvent) bool {
        const uri = std.Uri.parse(self.config.endpoint) catch {
            std.log.err("[SIEM] Invalid UDP endpoint: {s}", .{self.config.endpoint});
            return false;
        };

        const host = uriHost(uri) orelse {
            std.log.err("[SIEM] UDP endpoint missing host", .{});
            return false;
        };

        const port: u16 = uri.port orelse 514; // Default syslog port

        const addr_list = std.net.getAddressList(self.allocator, host, port) catch |err| {
            std.log.warn("[SIEM] UDP resolve failed: {}", .{err});
            return false;
        };
        defer addr_list.deinit();
        if (addr_list.addrs.len == 0) {
            std.log.err("[SIEM] UDP resolve returned no addresses", .{});
            return false;
        }
        const addr = addr_list.addrs[0];
        const sock = std.posix.socket(addr.any.family, std.posix.SOCK.DGRAM, 0) catch |err| {
            std.log.err("[SIEM] UDP socket failed: {}", .{err});
            return false;
        };
        defer std.posix.close(sock);
        std.posix.connect(sock, &addr.any, addr.getOsSockLen()) catch |err| {
            std.log.warn("[SIEM] UDP connect failed: {}", .{err});
            return false;
        };

        var failed = false;
        for (events) |event| {
            const body = self.formatEvent(event) catch {
                failed = true;
                continue;
            };
            defer self.allocator.free(body);

            _ = std.posix.send(sock, body, 0) catch |err| {
                std.log.warn("[SIEM] UDP write failed: {}", .{err});
                failed = true;
                continue;
            };
        }
        return !failed;
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

/// Cheap time-based flush gate for hot paths (e.g. the pipeline thread):
/// true only when initialized, enabled, and the flush interval has passed
/// with a non-empty buffer. Avoids a file/network syscall per event.
pub fn shouldFlush() bool {
    if (!g_initialized or !g_config.enabled) return false;
    if (g_forwarder) |*f| return f.shouldFlush();
    return false;
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

test "BE-SPOOL-092: refused collector spills, next flush replays to file" {
    // Live proof, no mocks: a real refused TCP collector (nothing
    // listens on 127.0.0.1:9) forces the spill path; switching the SAME
    // forwarder to file transport proves the auto-replay in flush().
    // Every file lives under a tmp dir (no tracked-tree writes).
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    const dest = try std.fmt.allocPrint(std.testing.allocator, "{s}/out.json", .{root});
    defer std.testing.allocator.free(dest);
    const spool = try std.fmt.allocPrint(std.testing.allocator, "{s}.spool", .{dest});
    defer std.testing.allocator.free(spool);

    var fwd = SiemForwarder.init(std.testing.allocator, .{
        .enabled = true,
        .transport = .tcp,
        .endpoint = "tcp://127.0.0.1:9",
        .destination = dest,
        .retry_count = 1,
        .retry_delay_ms = 0,
        .batch_size = 100,
    });
    defer fwd.deinit();

    const ev1 = ForwardedEvent{
        .timestamp = 1700000000000, .attack_type = "sig", .src_ip = "10.0.0.1",
        .dst_ip = "10.0.0.2", .src_port = 1000, .dst_port = 80, .protocol = "TCP",
        .severity = "alert", .policy = "alert", .rule_id = "4242",
        .status = "DETECTED", .payload = "",
    };
    const ev2 = ForwardedEvent{
        .timestamp = 1700000000001, .attack_type = "sig", .src_ip = "10.0.0.3",
        .dst_ip = "10.0.0.4", .src_port = 1001, .dst_port = 443, .protocol = "TCP",
        .severity = "critical", .policy = "block", .rule_id = "7777",
        .status = "DETECTED", .payload = "",
    };
    try fwd.forwardEvent(ev1);
    try fwd.forwardEvent(ev2);
    try fwd.flush();

    // Phase 1: refused → spilled, nothing forwarded, nothing lost.
    var stats = fwd.getStats();
    try std.testing.expectEqual(@as(u64, 2), stats.total_events_read);
    try std.testing.expectEqual(@as(u64, 2), stats.total_events_spooled);
    try std.testing.expectEqual(@as(u64, 0), stats.total_events_forwarded);
    try std.testing.expectEqual(@as(u64, 0), stats.total_events_failed);
    const spooled = try std.fs.cwd().readFileAlloc(std.testing.allocator, spool, 65536);
    defer std.testing.allocator.free(spooled);
    try std.testing.expect(std.mem.count(u8, spooled, "\n") == 2);
    try std.testing.expect(std.mem.indexOf(u8, spooled, "4242") != null);
    try std.testing.expect(std.mem.indexOf(u8, spooled, "7777") != null);

    // Phase 2: same forwarder, working transport → auto-replay delivers.
    fwd.config.transport = .file;
    try fwd.flush();
    stats = fwd.getStats();
    try std.testing.expectEqual(@as(u64, 2), stats.total_events_forwarded);
    try std.testing.expectEqual(@as(u64, 0), stats.total_events_failed);
    // Fully drained spool is deleted (ack = removal).
    try std.testing.expectError(error.FileNotFound, std.fs.cwd().readFileAlloc(std.testing.allocator, spool, 65536));
    const delivered = try std.fs.cwd().readFileAlloc(std.testing.allocator, dest, 65536);
    defer std.testing.allocator.free(delivered);
    try std.testing.expect(std.mem.count(u8, delivered, "\n") == 2);
    try std.testing.expect(std.mem.indexOf(u8, delivered, "4242") != null);
    try std.testing.expect(std.mem.indexOf(u8, delivered, "7777") != null);
}

test "BE-SPOOL-092: replay with no spool is a no-op" {
    // Negative control: flush against an absent spool file changes no
    // counters and creates no files.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    const dest = try std.fmt.allocPrint(std.testing.allocator, "{s}/out.json", .{root});
    defer std.testing.allocator.free(dest);

    var fwd = SiemForwarder.init(std.testing.allocator, .{
        .enabled = true,
        .transport = .file,
        .destination = dest,
        .retry_count = 1,
        .retry_delay_ms = 0,
    });
    defer fwd.deinit();
    const res = fwd.replaySpool();
    try std.testing.expectEqual(@as(u64, 0), res.replayed);
    try std.testing.expectEqual(@as(u64, 0), res.remaining);
    const stats = fwd.getStats();
    try std.testing.expectEqual(@as(u64, 0), stats.total_events_forwarded);
    try std.testing.expectError(error.FileNotFound, std.fs.cwd().readFileAlloc(std.testing.allocator, dest, 65536));
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

test "SiemForwarder spills (never drops) when all retries are exhausted" {
    // TCP to a refused loopback port fails fast; with retry_count=1 the
    // batch must land in <destination>.spool with counters to prove it.
    const dest = "siem_spill_probe.json";
    const spool = "siem_spill_probe.json.spool";
    defer std.fs.cwd().deleteFile(dest) catch {};
    defer std.fs.cwd().deleteFile(spool) catch {};
    var forwarder = SiemForwarder.init(std.testing.allocator, .{
        .enabled = true,
        .destination = dest,
        .transport = .tcp,
        .retry_count = 1,
        .retry_delay_ms = 0,
    });
    // Point the endpoint at a refused port. Field name follows Transport
    // config (endpoint); a refused connect must fail the batch.
    forwarder.config.endpoint = "tcp://127.0.0.1:1";
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

    try std.testing.expect(forwarder.stats.total_events_forwarded == 0);
    try std.testing.expect(forwarder.stats.total_events_failed == 0);
    try std.testing.expect(forwarder.stats.total_events_spooled == 1);
    try std.testing.expect(forwarder.batch_buffer.items.len == 0);
    const spooled = try std.fs.cwd().readFileAlloc(std.testing.allocator, spool, 65536);
    defer std.testing.allocator.free(spooled);
    try std.testing.expect(spooled.len > 0);
}

test "SiemForwarder HTTP total failure spills instead of counting forwarded" {
    // Before the at-least-once fix, sendViaHttp returned true with every
    // per-event failure swallowed by `continue`, so a dead collector was
    // counted as delivered. Refused loopback port + retry_count=1 must
    // spill with zero forwarded.
    const dest = "siem_http_spill_probe.json";
    const spool = "siem_http_spill_probe.json.spool";
    defer std.fs.cwd().deleteFile(dest) catch {};
    defer std.fs.cwd().deleteFile(spool) catch {};
    var forwarder = SiemForwarder.init(std.testing.allocator, .{
        .enabled = true,
        .destination = dest,
        .transport = .http,
        .retry_count = 1,
        .retry_delay_ms = 0,
    });
    forwarder.config.endpoint = "http://127.0.0.1:1/ingest";
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

    try std.testing.expect(forwarder.stats.total_events_forwarded == 0);
    try std.testing.expect(forwarder.stats.total_events_failed == 0);
    try std.testing.expect(forwarder.stats.total_events_spooled == 1);
    try std.testing.expect(forwarder.batch_buffer.items.len == 0);
    const spooled = try std.fs.cwd().readFileAlloc(std.testing.allocator, spool, 65536);
    defer std.testing.allocator.free(spooled);
    try std.testing.expect(spooled.len > 0);
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

fn replayProbeEvent() ForwardedEvent {
    return .{
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
}

fn writeTestSpool(allocator: std.mem.Allocator, spool_path: []const u8, lines: []const []const u8) !void {
    const file = try std.fs.cwd().createFile(spool_path, .{ .truncate = true });
    defer file.close();
    for (lines) |line| {
        try file.writer().writeAll(line);
        try file.writer().writeByte('\n');
    }
    _ = allocator;
}

test "replaySpool delivers spooled lines and acks by deleting the spool" {
    const dest = "siem_replay_ok.json";
    const spool = "siem_replay_ok.json.spool";
    defer std.fs.cwd().deleteFile(dest) catch {};
    defer std.fs.cwd().deleteFile(spool) catch {};
    try writeTestSpool(std.testing.allocator, spool, &.{ "{\"a\":1}", "{\"b\":2}" });

    var forwarder = SiemForwarder.init(std.testing.allocator, .{
        .enabled = true,
        .destination = dest,
        .transport = .file,
    });
    defer forwarder.deinit();

    const result = forwarder.replaySpool();
    try std.testing.expectEqual(@as(u64, 2), result.replayed);
    try std.testing.expectEqual(@as(u64, 0), result.remaining);
    try std.testing.expectEqual(@as(u64, 2), forwarder.stats.total_events_forwarded);
    // Acked: spool file is gone, destination holds both lines.
    try std.testing.expectEqual(false, blk: {
        std.fs.cwd().access(spool, .{}) catch break :blk false;
        break :blk true;
    });
    const body = try std.fs.cwd().readFileAlloc(std.testing.allocator, dest, 65536);
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "{\"a\":1}") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "{\"b\":2}") != null);
}

test "replaySpool stops at first failure and keeps the tail spooled" {
    const dest = "siem_replay_fail.json";
    const spool = "siem_replay_fail.json.spool";
    defer std.fs.cwd().deleteFile(dest) catch {};
    defer std.fs.cwd().deleteFile(spool) catch {};
    try writeTestSpool(std.testing.allocator, spool, &.{ "{\"a\":1}", "{\"b\":2}" });

    var forwarder = SiemForwarder.init(std.testing.allocator, .{
        .enabled = true,
        .destination = dest,
        .transport = .tcp,
        .retry_count = 1,
        .retry_delay_ms = 0,
    });
    forwarder.config.endpoint = "tcp://127.0.0.1:1";
    defer forwarder.deinit();

    const result = forwarder.replaySpool();
    try std.testing.expectEqual(@as(u64, 0), result.replayed);
    try std.testing.expectEqual(@as(u64, 2), result.remaining);
    try std.testing.expectEqual(@as(u64, 0), forwarder.stats.total_events_forwarded);
    const tail = try std.fs.cwd().readFileAlloc(std.testing.allocator, spool, 65536);
    defer std.testing.allocator.free(tail);
    try std.testing.expect(std.mem.indexOf(u8, tail, "{\"a\":1}") != null);
    try std.testing.expect(std.mem.indexOf(u8, tail, "{\"b\":2}") != null);
}

test "flush auto-replays a pre-existing spool before the live batch" {
    const dest = "siem_replay_flush.json";
    const spool = "siem_replay_flush.json.spool";
    defer std.fs.cwd().deleteFile(dest) catch {};
    defer std.fs.cwd().deleteFile(spool) catch {};
    try writeTestSpool(std.testing.allocator, spool, &.{"{\"old\":true}"});

    var forwarder = SiemForwarder.init(std.testing.allocator, .{
        .enabled = true,
        .destination = dest,
        .transport = .file,
    });
    defer forwarder.deinit();

    try forwarder.forwardEvent(replayProbeEvent());
    try forwarder.flush();

    // 1 replayed + 1 live, nothing newly spooled.
    try std.testing.expectEqual(@as(u64, 2), forwarder.stats.total_events_forwarded);
    try std.testing.expectEqual(@as(u64, 0), forwarder.stats.total_events_spooled);
    const body = try std.fs.cwd().readFileAlloc(std.testing.allocator, dest, 65536);
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "{\"old\":true}") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "SQLI") != null);
}
