//! host_telemetry_mock.zig - AEGIS NIDS Phase 37 Ext 1: Mock Telemetry Source
//!
//! Defines the HostTelemetrySource interface + provides a MockTelemetrySource
//! that replays scripted HostEvent sequences. Closes the gap between Phase
//! 37's logical model (HostTelemetry facade) and the absence of real Windows
//! adapters (ETW/FIM/RegNotify) on the Linux host test environment.
//!
//! Three layers:
//!   1. HostTelemetrySource: vtable interface that real adapters (ETW,
//!      ReadDirectoryChangesW, RegNotifyChangeKeyValue, ETW Winsock-APM)
//!      and MockTelemetrySource both implement.
//!   2. MockTelemetrySource: holds a list of (HostEvent, delay_ns) tuples,
//!      replays them in order, supports reset/replay for repeatable tests.
//!   3. ScriptedScenario: predefined attack scenarios (macro-dropper,
//!      persistence-install, lateral-movement, fim-tamper) as ready-to-use
//!      MockTelemetrySource factories.
//!   4. EventPump: pulls events from a source at the configured rate and
//!      feeds them to HostTelemetry.ingestEvent().
//!
//! Design principles (mirrors Phase 32/36/37/39):
//!   - Pure Zig, host-testable on Linux (no Win32 API; that's the point)
//!   - Additive only - enforcement stays in WFP kernel driver
//!   - Kill switch OFF by default; MockConfig{.enabled=true} opts in
//!   - Singleton facade not needed - MockTelemetrySource is per-test
//!   - Bounded memory: fixed scenario buffer, capped event queue
//!
//! Build:
//!   zig test host_telemetry_mock.zig -lc
//!   zig build-exe host_telemetry_mock_cli.zig -lc

const std = @import("std");
const ht = @import("host_telemetry.zig");

// ============================================================
// Constants & limits
// ============================================================

pub const MAX_SCENARIO_EVENTS: usize = 256;
pub const MAX_SOURCE_NAME: usize = 64;
pub const DEFAULT_TICK_NS: i64 = 1_000_000; // 1ms per event by default

// ============================================================
// MockConfig (kill switch + replay params)
// ============================================================

pub const MockConfig = struct {
    /// Master kill switch. OFF by default - mock source is a no-op until
    /// explicitly enabled. Per-node enforcement stays in WFP driver.
    enabled: bool = false,
    /// Tick interval in nanoseconds (controls replay speed)
    tick_ns: i64 = DEFAULT_TICK_NS,
    /// Loop the scenario when exhausted (useful for stress tests)
    loop_on_exhausted: bool = false,
    /// Random delay jitter (0 = deterministic, useful for tests)
    jitter_ns: i64 = 0,
};

// ============================================================
// HostTelemetrySource interface (vtable pattern)
// ============================================================

pub const SourceError = error{
    SourceExhausted,
    SourceDisabled,
    InvalidState,
};

/// Vtable interface that all telemetry sources implement.
/// Real adapters (ETW, FIM, RegNotify, Winsock-APM) and MockTelemetrySource
/// both conform to this. The facade calls nextEvent() in a poll loop.
pub const HostTelemetrySource = struct {
    ctx: *anyopaque,
    nextEventFn: *const fn (ctx: *anyopaque, now_ns: i64) SourceError!?ht.HostEvent,
    nameFn: *const fn (ctx: *anyopaque) []const u8,
    isExhaustedFn: *const fn (ctx: *anyopaque) bool,
    resetFn: *const fn (ctx: *anyopaque) void,

    pub fn nextEvent(self: HostTelemetrySource, now_ns: i64) SourceError!?ht.HostEvent {
        return self.nextEventFn(self.ctx, now_ns);
    }
    pub fn name(self: HostTelemetrySource) []const u8 {
        return self.nameFn(self.ctx);
    }
    pub fn isExhausted(self: HostTelemetrySource) bool {
        return self.isExhaustedFn(self.ctx);
    }
    pub fn reset(self: HostTelemetrySource) void {
        self.resetFn(self.ctx);
    }
};

// ============================================================
// MockTelemetrySource: replays scripted events in order
// ============================================================

pub const ScriptedEvent = struct {
    event: ht.HostEvent,
    /// Delay (ns) to wait before emitting this event (relative to previous)
    delay_ns: i64 = 0,
};

pub const MockTelemetrySource = struct {
    name_buf: [MAX_SOURCE_NAME]u8 = [_]u8{0} ** MAX_SOURCE_NAME,
    name_len: u8 = 0,
    events: [MAX_SCENARIO_EVENTS]ScriptedEvent = undefined,
    event_count: usize = 0,
    cursor: usize = 0,
    config: MockConfig,
    last_emit_ns: i64 = 0,
    total_emitted: u64 = 0,
    total_loops: u64 = 0,

    pub fn init(name: []const u8, config: MockConfig) MockTelemetrySource {
        var s = MockTelemetrySource{ .config = config };
        const n = @min(name.len, MAX_SOURCE_NAME);
        @memcpy(s.name_buf[0..n], name[0..n]);
        s.name_len = @intCast(n);
        return s;
    }

    pub fn nameStr(self: *const MockTelemetrySource) []const u8 {
        return self.name_buf[0..self.name_len];
    }

    /// Append a scripted event to the scenario. Returns false if the
    /// scenario buffer is full.
    pub fn appendEvent(self: *MockTelemetrySource, ev: ht.HostEvent, delay_ns: i64) bool {
        if (self.event_count >= MAX_SCENARIO_EVENTS) return false;
        self.events[self.event_count] = .{ .event = ev, .delay_ns = delay_ns };
        self.event_count += 1;
        return true;
    }

    /// Get the next event to emit. Returns null if exhausted (and not looping).
    /// Honors delay_ns: if the elapsed time since last_emit is less than
    /// the current event's delay, returns null (not yet time).
    pub fn nextEventImpl(self: *MockTelemetrySource, now_ns: i64) SourceError!?ht.HostEvent {
        if (!self.config.enabled) return error.SourceDisabled;
        if (self.event_count == 0) return error.SourceExhausted;

        if (self.cursor >= self.event_count) {
            if (self.config.loop_on_exhausted) {
                self.cursor = 0;
                self.total_loops += 1;
                self.last_emit_ns = now_ns;
            } else {
                return error.SourceExhausted;
            }
        }

        const entry = self.events[self.cursor];
        const elapsed_ns = now_ns - self.last_emit_ns;

        // Apply jitter (could be 0 for deterministic tests)
        const effective_delay = if (self.config.jitter_ns > 0)
            entry.delay_ns + @mod(@as(i64, @intCast(std.time.nanoTimestamp())), self.config.jitter_ns)
        else
            entry.delay_ns;

        if (self.cursor > 0 and elapsed_ns < effective_delay) {
            return null; // not yet time to emit
        }

        self.last_emit_ns = now_ns;
        self.cursor += 1;
        self.total_emitted += 1;
        return entry.event;
    }

    pub fn isExhaustedImpl(self: *const MockTelemetrySource) bool {
        if (self.config.loop_on_exhausted) return false;
        return self.cursor >= self.event_count;
    }

    pub fn resetImpl(self: *MockTelemetrySource) void {
        self.cursor = 0;
        self.last_emit_ns = 0;
    }

    pub fn eventCount(self: *const MockTelemetrySource) usize {
        return self.event_count;
    }

    pub fn asSource(self: *MockTelemetrySource) HostTelemetrySource {
        return .{
            .ctx = self,
            .nextEventFn = &nextEventAdapter,
            .nameFn = &nameAdapter,
            .isExhaustedFn = &isExhaustedAdapter,
            .resetFn = &resetAdapter,
        };
    }

    fn nextEventAdapter(ctx: *anyopaque, now_ns: i64) SourceError!?ht.HostEvent {
        const self: *MockTelemetrySource = @ptrCast(@alignCast(ctx));
        return self.nextEventImpl(now_ns);
    }
    fn nameAdapter(ctx: *anyopaque) []const u8 {
        const self: *MockTelemetrySource = @ptrCast(@alignCast(ctx));
        return self.nameStr();
    }
    fn isExhaustedAdapter(ctx: *anyopaque) bool {
        const self: *MockTelemetrySource = @ptrCast(@alignCast(ctx));
        return self.isExhaustedImpl();
    }
    fn resetAdapter(ctx: *anyopaque) void {
        const self: *MockTelemetrySource = @ptrCast(@alignCast(ctx));
        self.resetImpl();
    }
};

// ============================================================
// Scripted scenarios (predefined attack patterns)
// ============================================================

/// Scenario: Macro dropper executes from Office app
/// (T1566.001 - Spearphishing Attachment)
///
/// Timeline:
///   t=0ms   : WINWORD.EXE creates cmd.exe (parent-child anomaly)
///   t=10ms  : cmd.exe creates dropper.exe in Public folder (unsigned)
///   t=20ms  : dropper.exe opens TCP socket to C2 198.51.100.7:4444
///   t=30ms  : ML detector emits malicious verdict for that 4-tuple
pub fn buildMacroDropperScenario(out: *MockTelemetrySource) !void {
    // 1. WINWORD creates cmd.exe (suspicious parent-child)
    var word_create_cmd = ht.HostEvent{
        .event_type = .process_create,
        .pid = 100,
        .ppid = 50,
        .integrity = .medium,
        .is_signed = true,
        .timestamp_ns = 0,
    };
    const word_img = "C:\\Program Files\\Microsoft Office\\WINWORD.EXE";
    @memcpy(word_create_cmd.image_path[0..word_img.len], word_img);
    word_create_cmd.image_path_len = @intCast(word_img.len);
    _ = out.appendEvent(word_create_cmd, 0);

    // 2. cmd.exe (PID 200) spawned by WINWORD (PID 100) - the anomaly
    var cmd_create = ht.HostEvent{
        .event_type = .process_create,
        .pid = 200,
        .ppid = 100,
        .integrity = .medium,
        .is_signed = true,
        .timestamp_ns = 5_000_000, // 5ms
    };
    const cmd_img = "C:\\Windows\\System32\\cmd.exe";
    @memcpy(cmd_create.image_path[0..cmd_img.len], cmd_img);
    cmd_create.image_path_len = @intCast(cmd_img.len);
    _ = out.appendEvent(cmd_create, 5_000_000); // 5ms delay

    // 3. cmd.exe spawns dropper.exe (unsigned, in user-writable path)
    var dropper_create = ht.HostEvent{
        .event_type = .process_create,
        .pid = 300,
        .ppid = 200,
        .integrity = .high,
        .is_signed = false,
        .timestamp_ns = 10_000_000,
    };
    const dropper_img = "C:\\Users\\Public\\dropper.exe";
    @memcpy(dropper_create.image_path[0..dropper_img.len], dropper_img);
    dropper_create.image_path_len = @intCast(dropper_img.len);
    _ = out.appendEvent(dropper_create, 5_000_000);

    // 4. dropper.exe opens TCP socket to C2
    const socket_open = ht.HostEvent{
        .event_type = .socket_open,
        .pid = 300,
        .proto = .tcp,
        .local_ip = .{ 192, 168, 1, 41 },
        .local_port = 51000,
        .remote_ip = .{ 198, 51, 100, 7 },
        .remote_port = 4444,
        .timestamp_ns = 15_000_000,
    };
    _ = out.appendEvent(socket_open, 5_000_000);
}

/// Scenario: Persistence via HKLM Run key
/// (T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys)
///
/// Timeline:
///   t=0ms  : svchost.exe tampered (hash mismatch on system binary)
///   t=5ms  : attacker sets HKLM\...\Run\Backdoor = "C:\evil.exe"
pub fn buildPersistenceScenario(out: *MockTelemetrySource) !void {
    // 1. File integrity tamper on svchost.exe
    var fim_ev = ht.HostEvent{
        .event_type = .file_modify,
        .pid = 1234,
        .timestamp_ns = 0,
        .file_size = 50_000,
        .file_attrs = 0x20,
    };
    const path = "C:\\Windows\\System32\\svchost.exe";
    @memcpy(fim_ev.file_path[0..path.len], path);
    fim_ev.file_path_len = @intCast(path.len);
    const tampered_hash = ht.sha256("tampered-svchost-binary-content");
    @memcpy(fim_ev.file_hash[0..ht.SHA256_LEN], &tampered_hash);
    _ = out.appendEvent(fim_ev, 0);

    // 2. Persistence via HKLM Run key
    var reg_ev = ht.HostEvent{
        .event_type = .registry_set_value,
        .pid = 1234,
        .timestamp_ns = 5_000_000,
    };
    const key = "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor";
    @memcpy(reg_ev.reg_key[0..key.len], key);
    reg_ev.reg_key_len = @intCast(key.len);
    const val = "Updater";
    @memcpy(reg_ev.reg_value_name[0..val.len], val);
    reg_ev.reg_value_name_len = val.len;
    _ = out.appendEvent(reg_ev, 5_000_000);
}

/// Scenario: Unsigned system binary (T1027 - Obfuscated Files)
///
/// Timeline:
///   t=0ms  : suspicious unsigned binary in System32 spawns
pub fn buildUnsignedSystemScenario(out: *MockTelemetrySource) !void {
    var ev = ht.HostEvent{
        .event_type = .process_create,
        .pid = 999,
        .ppid = 4,
        .integrity = .system,
        .is_signed = false,
        .timestamp_ns = 0,
    };
    const img = "C:\\Windows\\System32\\malware.dll";
    @memcpy(ev.image_path[0..img.len], img);
    ev.image_path_len = @intCast(img.len);
    _ = out.appendEvent(ev, 0);
}

/// Scenario: Lateral movement attempt (T1021 - Remote Services)
///
/// Timeline:
///   t=0ms   : process opens TCP socket to internal host on port 445 (SMB)
///   t=10ms  : process opens TCP socket to internal host on port 3389 (RDP)
///   t=20ms  : process opens TCP socket to internal host on port 22 (SSH)
///   t=30ms  : ML detector emits suspicious verdict for port-scan pattern
pub fn buildLateralMovementScenario(out: *MockTelemetrySource) !void {
    var i: u16 = 0;
    const ports = [_]u16{ 445, 3389, 22, 135, 139 };
    while (i < ports.len) : (i += 1) {
        const ev = ht.HostEvent{
            .event_type = .socket_open,
            .pid = 4321,
            .proto = .tcp,
            .local_ip = .{ 192, 168, 1, 41 },
            .local_port = 50000 + i,
            .remote_ip = .{ 10, 0, 0, @intCast(5 + i) },
            .remote_port = ports[i],
            .timestamp_ns = @as(i64, @intCast(i)) * 10_000_000,
        };
        _ = out.appendEvent(ev, if (i == 0) 0 else 10_000_000);
    }
}

// ============================================================
// EventPump: pulls events from a source and feeds HostTelemetry
// ============================================================

pub const EventPump = struct {
    source: HostTelemetrySource,
    host: *ht.HostTelemetry,
    total_pumped: u64 = 0,
    total_skipped: u64 = 0,
    total_suspicion_emitted: u64 = 0,
    last_event_ns: i64 = 0,

    pub fn init(source: HostTelemetrySource, host: *ht.HostTelemetry) EventPump {
        return .{ .source = source, .host = host };
    }

    /// Pump one event from the source (if available). Returns:
    ///   - .emitted(SuspicionReason) if an event was ingested
    ///   - .skipped if the source had no event ready (delay not yet elapsed)
    ///   - .exhausted if the source has no more events
    ///   - .disabled if the host's kill switch is off
    pub const PumpResult = union(enum) {
        emitted: ht.SuspicionReason,
        skipped: void,
        exhausted: void,
        disabled: void,
    };

    pub fn pumpOnce(self: *EventPump, now_ns: i64) PumpResult {
        if (!self.host.isAvailable()) return .{ .disabled = {} };

        const ev_opt = self.source.nextEvent(now_ns) catch |err| switch (err) {
            error.SourceExhausted => return .{ .exhausted = {} },
            error.SourceDisabled => return .{ .disabled = {} },
            error.InvalidState => return .{ .skipped = {} },
        };
        const ev = ev_opt orelse return .{ .skipped = {} };

        const reason = self.host.ingestEvent(ev);
        self.total_pumped += 1;
        self.last_event_ns = now_ns;
        if (reason != .none) self.total_suspicion_emitted += 1;
        return .{ .emitted = reason };
    }

    /// Pump all events until exhausted or max_iterations reached.
    /// Returns the number of events actually pumped.
    pub fn pumpAll(self: *EventPump, now_ns: i64, max_iterations: u32) u32 {
        var count: u32 = 0;
        var t = now_ns;
        var i: u32 = 0;
        while (i < max_iterations) : (i += 1) {
            switch (self.pumpOnce(t)) {
                .emitted => {
                    count += 1;
                    t += self.host.config.correlation_window_ms * 1_000_000; // advance time
                },
                .skipped => {
                    t += 1_000_000; // advance 1ms
                },
                .exhausted, .disabled => break,
            }
        }
        return count;
    }

    pub fn resetStats(self: *EventPump) void {
        self.total_pumped = 0;
        self.total_skipped = 0;
        self.total_suspicion_emitted = 0;
    }
};

// ============================================================
// Multi-source pump: pulls from multiple sources in round-robin
// ============================================================

pub const MultiSourcePump = struct {
    sources: []HostTelemetrySource,
    host: *ht.HostTelemetry,
    cursor: usize = 0,
    total_pumped: u64 = 0,

    pub fn init(sources: []HostTelemetrySource, host: *ht.HostTelemetry) MultiSourcePump {
        return .{ .sources = sources, .host = host };
    }

    /// Try each source in round-robin; emit one event if any source has one.
    pub const PumpResult = union(enum) {
        emitted: ht.SuspicionReason,
        skipped: void,
        all_exhausted: void,
        disabled: void,
    };

    pub fn pumpOnce(self: *MultiSourcePump, now_ns: i64) PumpResult {
        if (!self.host.isAvailable()) return .{ .disabled = {} };

        var i: usize = 0;
        while (i < self.sources.len) : (i += 1) {
            const idx = (self.cursor + i) % self.sources.len;
            const src = self.sources[idx];
            if (src.isExhausted()) continue;

            const ev_opt = src.nextEvent(now_ns) catch continue;
            if (ev_opt) |ev| {
                self.cursor = (idx + 1) % self.sources.len;
                const reason = self.host.ingestEvent(ev);
                self.total_pumped += 1;
                return .{ .emitted = reason };
            }
        }
        // All sources either exhausted, disabled, or had no event ready
        const all_exhausted = blk: {
            for (self.sources) |s| {
                if (!s.isExhausted()) break :blk false;
            }
            break :blk true;
        };
        if (all_exhausted) return .{ .all_exhausted = {} };
        return .{ .skipped = {} };
    }
};

// ============================================================
// Tests
// ============================================================

test "MockConfig defaults - kill switch OFF" {
    const c = MockConfig{};
    try std.testing.expect(!c.enabled);
    try std.testing.expectEqual(@as(i64, 1_000_000), c.tick_ns);
    try std.testing.expect(!c.loop_on_exhausted);
}

test "MockTelemetrySource init" {
    const s = MockTelemetrySource.init("test-source", .{ .enabled = true });
    try std.testing.expectEqualStrings("test-source", s.nameStr());
    try std.testing.expectEqual(@as(usize, 0), s.eventCount());
    try std.testing.expect(s.isExhaustedImpl()); // empty = exhausted
}

test "MockTelemetrySource appendEvent and eventCount" {
    var s = MockTelemetrySource.init("test", .{ .enabled = true });
    _ = s.appendEvent(.{ .event_type = .process_create, .pid = 1 }, 0);
    _ = s.appendEvent(.{ .event_type = .process_exit, .pid = 1 }, 5_000_000);
    try std.testing.expectEqual(@as(usize, 2), s.eventCount());
    try std.testing.expect(!s.isExhaustedImpl());
}

test "MockTelemetrySource nextEvent emits in order" {
    var s = MockTelemetrySource.init("test", .{ .enabled = true });
    _ = s.appendEvent(.{ .event_type = .process_create, .pid = 1, .timestamp_ns = 100 }, 0);
    _ = s.appendEvent(.{ .event_type = .process_exit, .pid = 1, .timestamp_ns = 200 }, 5_000_000);

    // First event: no delay (cursor=0, no previous)
    const ev1 = try s.nextEventImpl(0);
    try std.testing.expect(ev1 != null);
    try std.testing.expectEqual(ht.HostEventType.process_create, ev1.?.event_type);
    try std.testing.expectEqual(@as(u32, 1), ev1.?.pid);

    // Second event: delay 5ms; at t=1ms -> skipped (null)
    const ev_early = try s.nextEventImpl(1_000_000);
    try std.testing.expect(ev_early == null);

    // At t=6ms -> emits
    const ev2 = try s.nextEventImpl(6_000_000);
    try std.testing.expect(ev2 != null);
    try std.testing.expectEqual(ht.HostEventType.process_exit, ev2.?.event_type);
}

test "MockTelemetrySource exhausted" {
    var s = MockTelemetrySource.init("test", .{ .enabled = true });
    _ = s.appendEvent(.{ .event_type = .process_create, .pid = 1 }, 0);

    _ = try s.nextEventImpl(0);
    try std.testing.expect(s.isExhaustedImpl());
    try std.testing.expectError(error.SourceExhausted, s.nextEventImpl(0));
}

test "MockTelemetrySource loop_on_exhausted" {
    var s = MockTelemetrySource.init("test", .{ .enabled = true, .loop_on_exhausted = true });
    _ = s.appendEvent(.{ .event_type = .process_create, .pid = 1 }, 0);

    _ = try s.nextEventImpl(0);
    // First call consumed event 0; cursor is now 1 = event_count but we
    // haven't looped yet (loop only triggers when nextEvent is called and
    // cursor >= event_count).
    try std.testing.expect(!s.isExhaustedImpl());
    try std.testing.expectEqual(@as(u64, 0), s.total_loops);

    // Second call: cursor >= event_count -> loop triggers (total_loops becomes 1)
    const ev = try s.nextEventImpl(1_000_000);
    try std.testing.expect(ev != null);
    try std.testing.expectEqual(@as(u32, 1), ev.?.pid);
    try std.testing.expectEqual(@as(u64, 1), s.total_loops);
}

test "MockTelemetrySource respects kill switch" {
    var s = MockTelemetrySource.init("test", .{ .enabled = false });
    _ = s.appendEvent(.{ .event_type = .process_create, .pid = 1 }, 0);
    try std.testing.expectError(error.SourceDisabled, s.nextEventImpl(0));
}

test "MockTelemetrySource reset" {
    var s = MockTelemetrySource.init("test", .{ .enabled = true });
    _ = s.appendEvent(.{ .event_type = .process_create, .pid = 1 }, 0);
    _ = try s.nextEventImpl(0);
    try std.testing.expect(s.isExhaustedImpl());

    s.resetImpl();
    try std.testing.expect(!s.isExhaustedImpl());
    try std.testing.expectEqual(@as(usize, 0), s.cursor);
}

test "MockTelemetrySource asSource vtable works" {
    var s = MockTelemetrySource.init("vtable-test", .{ .enabled = true });
    _ = s.appendEvent(.{ .event_type = .process_create, .pid = 42 }, 0);

    const src = s.asSource();
    try std.testing.expectEqualStrings("vtable-test", src.name());
    try std.testing.expect(!src.isExhausted());

    const ev = try src.nextEvent(0);
    try std.testing.expect(ev != null);
    try std.testing.expectEqual(@as(u32, 42), ev.?.pid);
}

test "MockTelemetrySource appendEvent returns false when full" {
    var s = MockTelemetrySource.init("test", .{ .enabled = true });
    var i: usize = 0;
    while (i < MAX_SCENARIO_EVENTS) : (i += 1) {
        _ = s.appendEvent(.{ .event_type = .process_create, .pid = @intCast(i) }, 0);
    }
    // Buffer full
    const ok = s.appendEvent(.{ .event_type = .process_create, .pid = 999 }, 0);
    try std.testing.expect(!ok);
}

test "buildMacroDropperScenario creates 4 events" {
    var s = MockTelemetrySource.init("macro", .{ .enabled = true });
    try buildMacroDropperScenario(&s);
    try std.testing.expectEqual(@as(usize, 4), s.eventCount());
}

test "buildPersistenceScenario creates 2 events" {
    var s = MockTelemetrySource.init("persistence", .{ .enabled = true });
    try buildPersistenceScenario(&s);
    try std.testing.expectEqual(@as(usize, 2), s.eventCount());
}

test "buildUnsignedSystemScenario creates 1 event" {
    var s = MockTelemetrySource.init("unsigned", .{ .enabled = true });
    try buildUnsignedSystemScenario(&s);
    try std.testing.expectEqual(@as(usize, 1), s.eventCount());
}

test "buildLateralMovementScenario creates 5 events" {
    var s = MockTelemetrySource.init("lateral", .{ .enabled = true });
    try buildLateralMovementScenario(&s);
    try std.testing.expectEqual(@as(usize, 5), s.eventCount());
}

test "EventPump pumpOnce emits event and returns reason" {
    const alloc = std.testing.allocator;
    var host = try ht.HostTelemetry.init(alloc, .{ .enabled = true });
    defer host.shutdown();

    var s = MockTelemetrySource.init("test", .{ .enabled = true });
    var ev = ht.HostEvent{
        .event_type = .process_create,
        .pid = 1234,
        .ppid = 100,
        .integrity = .high,
        .is_signed = false,
    };
    const img = "C:\\Windows\\System32\\evil.exe";
    @memcpy(ev.image_path[0..img.len], img);
    ev.image_path_len = @intCast(img.len);
    _ = s.appendEvent(ev, 0);

    var pump = EventPump.init(s.asSource(), host);
    const r = pump.pumpOnce(0);
    switch (r) {
        .emitted => |reason| try std.testing.expectEqual(ht.SuspicionReason.unsigned_system_path, reason),
        else => return error.TestExpectedEmitted,
    }
    try std.testing.expectEqual(@as(u64, 1), pump.total_pumped);
    try std.testing.expectEqual(@as(u64, 1), pump.total_suspicion_emitted);
}

test "EventPump returns disabled when host kill switch off" {
    const alloc = std.testing.allocator;
    var host = try ht.HostTelemetry.init(alloc, .{ .enabled = false });
    defer host.shutdown();

    var s = MockTelemetrySource.init("test", .{ .enabled = true });
    _ = s.appendEvent(.{ .event_type = .process_create, .pid = 1 }, 0);

    var pump = EventPump.init(s.asSource(), host);
    const r = pump.pumpOnce(0);
    switch (r) {
        .disabled => {},
        else => return error.TestExpectedDisabled,
    }
}

test "EventPump returns exhausted when source is empty" {
    const alloc = std.testing.allocator;
    var host = try ht.HostTelemetry.init(alloc, .{ .enabled = true });
    defer host.shutdown();

    var s = MockTelemetrySource.init("empty", .{ .enabled = true });
    var pump = EventPump.init(s.asSource(), host);
    const r = pump.pumpOnce(0);
    switch (r) {
        .exhausted => {},
        else => return error.TestExpectedExhausted,
    }
}

test "EventPump pumpAll drains source" {
    const alloc = std.testing.allocator;
    var host = try ht.HostTelemetry.init(alloc, .{ .enabled = true });
    defer host.shutdown();

    var s = MockTelemetrySource.init("test", .{ .enabled = true });
    var i: u32 = 0;
    while (i < 5) : (i += 1) {
        _ = s.appendEvent(.{
            .event_type = .process_create,
            .pid = i + 1,
            .ppid = 0,
            .integrity = .medium,
            .is_signed = true,
            .timestamp_ns = @as(i64, @intCast(i)),
        }, 0);
    }

    var pump = EventPump.init(s.asSource(), host);
    const count = pump.pumpAll(0, 100);
    try std.testing.expectEqual(@as(u32, 5), count);
    try std.testing.expectEqual(@as(u64, 5), pump.total_pumped);
}

test "EventPump handles skipped events (delay not elapsed)" {
    const alloc = std.testing.allocator;
    var host = try ht.HostTelemetry.init(alloc, .{ .enabled = true });
    defer host.shutdown();

    var s = MockTelemetrySource.init("test", .{ .enabled = true });
    _ = s.appendEvent(.{ .event_type = .process_create, .pid = 1 }, 0);
    _ = s.appendEvent(.{ .event_type = .process_exit, .pid = 1 }, 10_000_000); // 10ms delay

    var pump = EventPump.init(s.asSource(), host);
    // First event emits at t=0
    var r = pump.pumpOnce(0);
    switch (r) {
        .emitted => {},
        else => return error.TestExpectedEmitted,
    }

    // Second event not yet time at t=1ms (delay 10ms)
    r = pump.pumpOnce(1_000_000);
    switch (r) {
        .skipped => {},
        else => return error.TestExpectedSkipped,
    }

    // At t=11ms -> emits
    r = pump.pumpOnce(11_000_000);
    switch (r) {
        .emitted => {},
        else => return error.TestExpectedEmitted,
    }
}

test "End-to-end: macro-dropper scenario produces 2 incidents" {
    const alloc = std.testing.allocator;
    var host = try ht.HostTelemetry.init(alloc, .{ .enabled = true });
    defer host.shutdown();

    var s = MockTelemetrySource.init("macro", .{ .enabled = true });
    try buildMacroDropperScenario(&s);

    var pump = EventPump.init(s.asSource(), host);
    const count = pump.pumpAll(0, 100);
    try std.testing.expectEqual(@as(u32, 4), count);

    // WINWORD->cmd.exe should produce parent_child_anomaly
    // dropper.exe unsigned HIGH should produce unsigned_elevated
    try std.testing.expect(pump.total_suspicion_emitted >= 2);
    try std.testing.expectEqual(@as(u64, 1), host.tracker.suspicious_parent_pairs);
}

test "End-to-end: persistence scenario produces 2 incidents" {
    const alloc = std.testing.allocator;
    var host = try ht.HostTelemetry.init(alloc, .{ .enabled = true });
    defer host.shutdown();

    // Pre-establish baseline so FIM detects tamper
    const path = "C:\\Windows\\System32\\svchost.exe";
    const clean_hash = ht.sha256("clean-svchost-binary-content");
    try host.fim.setBaseline(path, clean_hash, 50_000, 1_000_000, 0x20, 1_500_000);

    var s = MockTelemetrySource.init("persistence", .{ .enabled = true });
    try buildPersistenceScenario(&s);

    var pump = EventPump.init(s.asSource(), host);
    const count = pump.pumpAll(0, 100);
    try std.testing.expectEqual(@as(u32, 2), count);

    // FIM mismatch + registry persistence
    try std.testing.expectEqual(@as(u64, 1), host.fim.total_mismatch);
    try std.testing.expectEqual(@as(u64, 1), host.reg.total_persistence_hits);
    try std.testing.expectEqual(@as(u64, 2), pump.total_suspicion_emitted);
}

test "End-to-end: unsigned-system scenario produces 1 incident" {
    const alloc = std.testing.allocator;
    var host = try ht.HostTelemetry.init(alloc, .{ .enabled = true });
    defer host.shutdown();

    var s = MockTelemetrySource.init("unsigned", .{ .enabled = true });
    try buildUnsignedSystemScenario(&s);

    var pump = EventPump.init(s.asSource(), host);
    const count = pump.pumpAll(0, 100);
    try std.testing.expectEqual(@as(u32, 1), count);
    try std.testing.expectEqual(@as(u64, 1), pump.total_suspicion_emitted);
    try std.testing.expectEqual(@as(u64, 1), host.tracker.total_suspicious);
}

test "End-to-end: lateral-movement scenario opens 5 sockets" {
    const alloc = std.testing.allocator;
    var host = try ht.HostTelemetry.init(alloc, .{ .enabled = true });
    defer host.shutdown();

    var s = MockTelemetrySource.init("lateral", .{ .enabled = true });
    try buildLateralMovementScenario(&s);

    var pump = EventPump.init(s.asSource(), host);
    const count = pump.pumpAll(0, 100);
    try std.testing.expectEqual(@as(u32, 5), count);
    // All 5 socket_open events -> 5 entries in socket table for PID 4321
    const sockets = host.sockets.socketsForPid(4321);
    try std.testing.expectEqual(@as(usize, 5), sockets.len);
}

test "End-to-end: full attack chain triggers correlated incident" {
    // Combine macro-dropper + malicious-flow-verdict -> correlated incident
    const alloc = std.testing.allocator;
    var host = try ht.HostTelemetry.init(alloc, .{ .enabled = true });
    defer host.shutdown();

    var s = MockTelemetrySource.init("full-chain", .{ .enabled = true });
    try buildMacroDropperScenario(&s);

    var pump = EventPump.init(s.asSource(), host);
    _ = pump.pumpAll(0, 100);

    // Now emit a malicious flow verdict for the dropper's C2 socket
    const idx = host.pushFlowVerdict(.{
        .timestamp_ns = 30_000_000,
        .proto = .tcp,
        .local_ip = .{ 192, 168, 1, 41 },
        .local_port = 51000,
        .remote_ip = .{ 198, 51, 100, 7 },
        .remote_port = 4444,
        .score = 0.95,
    }) orelse return error.TestExpectedIncident;

    const inc = host.correlator.getIncident(idx).?;
    try std.testing.expectEqual(@as(u32, 300), inc.attributed_pid); // dropper.exe
    try std.testing.expectEqual(ht.IncidentSeverity.critical, inc.severity);
    try std.testing.expect(inc.reason_count >= 2); // network_correlation + unsigned_elevated
}

test "MultiSourcePump round-robins between sources" {
    const alloc = std.testing.allocator;
    var host = try ht.HostTelemetry.init(alloc, .{ .enabled = true });
    defer host.shutdown();

    var s1 = MockTelemetrySource.init("src1", .{ .enabled = true });
    var s2 = MockTelemetrySource.init("src2", .{ .enabled = true });
    _ = s1.appendEvent(.{ .event_type = .process_create, .pid = 1 }, 0);
    _ = s2.appendEvent(.{ .event_type = .process_create, .pid = 2 }, 0);

    var sources = [_]HostTelemetrySource{ s1.asSource(), s2.asSource() };
    var pump = MultiSourcePump.init(&sources, host);

    // First pump: emits from s1 (cursor starts at 0)
    var r = pump.pumpOnce(0);
    switch (r) {
        .emitted => {},
        else => return error.TestExpectedEmitted,
    }

    // Second pump: should round-robin to s2
    r = pump.pumpOnce(0);
    switch (r) {
        .emitted => {},
        else => return error.TestExpectedEmitted,
    }

    // Third pump: both exhausted
    r = pump.pumpOnce(0);
    switch (r) {
        .all_exhausted => {},
        else => return error.TestExpectedAllExhausted,
    }

    try std.testing.expectEqual(@as(u64, 2), pump.total_pumped);
}

test "MultiSourcePump respects host kill switch" {
    const alloc = std.testing.allocator;
    var host = try ht.HostTelemetry.init(alloc, .{ .enabled = false });
    defer host.shutdown();

    var s = MockTelemetrySource.init("test", .{ .enabled = true });
    _ = s.appendEvent(.{ .event_type = .process_create, .pid = 1 }, 0);

    var sources = [_]HostTelemetrySource{s.asSource()};
    var pump = MultiSourcePump.init(&sources, host);
    const r = pump.pumpOnce(0);
    switch (r) {
        .disabled => {},
        else => return error.TestExpectedDisabled,
    }
}

test "SourceError types" {
    // Verify error type exists and is one of the expected values
    const err: SourceError = error.SourceExhausted;
    try std.testing.expect(err == error.SourceExhausted);
    try std.testing.expect(err != error.SourceDisabled);
}

test "HostTelemetrySource interface dispatch" {
    var s = MockTelemetrySource.init("iface", .{ .enabled = true });
    _ = s.appendEvent(.{ .event_type = .process_create, .pid = 1 }, 0);

    const src = s.asSource();
    // Use the interface methods
    try std.testing.expectEqualStrings("iface", src.name());
    try std.testing.expect(!src.isExhausted());
    const ev = try src.nextEvent(0);
    try std.testing.expect(ev != null);
    try std.testing.expect(src.isExhausted());

    // Reset
    src.reset();
    try std.testing.expect(!src.isExhausted());
}

test "MockTelemetrySource handles empty scenario gracefully" {
    var s = MockTelemetrySource.init("empty", .{ .enabled = true });
    // No events appended
    try std.testing.expect(s.isExhaustedImpl());
    try std.testing.expectError(error.SourceExhausted, s.nextEventImpl(0));
}

test "ScriptedEvent struct" {
    const se = ScriptedEvent{
        .event = .{ .event_type = .process_create, .pid = 1, .timestamp_ns = 0 },
        .delay_ns = 5_000_000,
    };
    try std.testing.expectEqual(@as(i64, 5_000_000), se.delay_ns);
    try std.testing.expectEqual(ht.HostEventType.process_create, se.event.event_type);
}

test "EventPump resetStats" {
    const alloc = std.testing.allocator;
    var host = try ht.HostTelemetry.init(alloc, .{ .enabled = true });
    defer host.shutdown();

    var s = MockTelemetrySource.init("test", .{ .enabled = true });
    _ = s.appendEvent(.{ .event_type = .process_create, .pid = 1 }, 0);

    var pump = EventPump.init(s.asSource(), host);
    _ = pump.pumpOnce(0);
    try std.testing.expectEqual(@as(u64, 1), pump.total_pumped);

    pump.resetStats();
    try std.testing.expectEqual(@as(u64, 0), pump.total_pumped);
}
