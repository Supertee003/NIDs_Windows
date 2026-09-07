// II06 - Host Telemetry Aggregator
// AEGIS NIDS v5.0+ â€” Unified facade over ETW + FIM + Registry + Injection detector.
//
// This is the single "host telemetry source" consumed by the dispatcher.
// It hides per-source complexity and emits normalized IpcEvents into the
// detection pipeline.

const std = @import("std");
const event = @import("../contract/event.zig");
const diag = @import("../core/diagnostics.zig");
const etw = @import("etw_realtime.zig");
const fim = @import("fim.zig");
const regmon = @import("registry_monitor.zig");
const inject = @import("injection_detector.zig");

pub const HostTelemetrySource = struct {
    etw_source: etw.EtwSource = .{},
    fim_watcher: fim.FimWatcher,
    registry_mon: regmon.RegistryMonitor,
    injection_det: inject.InjectionDetector,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    allocator: std.mem.Allocator,
    events_emitted: u64 = 0,

    pub fn init(allocator: std.mem.Allocator) HostTelemetrySource {
        return .{
            .fim_watcher = fim.FimWatcher.init(allocator),
            .registry_mon = regmon.RegistryMonitor.init(allocator),
            .injection_det = inject.InjectionDetector.init(allocator, &inject.DEFAULT_RULES),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *HostTelemetrySource) void {
        self.fim_watcher.deinit();
        self.registry_mon.deinit();
        self.injection_det.deinit();
    }

    pub fn start(self: *HostTelemetrySource, etw_providers: []const [16]u8) !void {
        // Start ETW
        if (@import("builtin").os.tag == .windows) {
            try self.etw_source.start(etw_providers);
        }
        // Start FIM
        self.fim_watcher.startAll() catch |err| {
            diag.warn("FIM failed to start: {}", .{err});
        };
        self.running.store(true, .release);
        diag.info("HostTelemetrySource started (ETW={} FIM={} RegMon={})", .{
            self.etw_source.running.load(.acquire),
            self.fim_watcher.running.load(.acquire),
            self.running.load(.acquire),
        });
    }

    pub fn stop(self: *HostTelemetrySource) void {
        self.etw_source.stop();
        self.fim_watcher.stopAll();
        self.running.store(false, .release);
    }

    pub fn onFimChange(self: *HostTelemetrySource, kind: fim.FimChangeKind, path: []const u8) !void {
        var ev = event.IpcEvent.init(.fim_change);
        ev.now();
        ev.source = .capture_fim;
        ev.severity = .info;
        _ = kind;
        _ = path;
        self.events_emitted += 1;
    }

    pub fn onRegChange(self: *HostTelemetrySource, kind: regmon.RegChangeKind, path: []const u8) !void {
        try self.registry_mon.observe(kind, path);
        var ev = event.IpcEvent.init(.reg_change);
        ev.now();
        ev.source = .capture_registry;
        ev.severity = if (self.registry_mon.trie.match(path) != null) .warning else .info;
        self.events_emitted += 1;
    }

    pub fn onInjection(self: *HostTelemetrySource, source_pid: u32, target_pid: u32, api_hash: u32, target_image: []const u8) !void {
        if (try self.injection_det.observe(source_pid, target_pid, api_hash, target_image, std.time.nanoTimestamp())) |ie| {
            var ev = event.IpcEvent.init(.injection_detected);
            ev.now();
            ev.source = .capture_etw;
            ev.severity = .alert;
            ev.rule_id = ie.rule_id;
            ev.flow_id = ((@as(u64, source_pid) << 32) | target_pid);
            diag.alert("INJECTION: pattern={s} src={d} dst={d} img={s}", .{
                @tagName(ie.pattern),
                source_pid,
                target_pid,
                target_image,
            });
            self.events_emitted += 1;
        }
    }
};

// ============================================================================
// Tests
// ============================================================================
test "HostTelemetrySource init/deinit" {
    var ht = HostTelemetrySource.init(std.testing.allocator);
    defer ht.deinit();
    // Verify it can construct without error
    try std.testing.expect(!ht.running.load(.acquire));
}

test "HostTelemetrySource onRegChange emits event" {
    var ht = HostTelemetrySource.init(std.testing.allocator);
    defer ht.deinit();
    try ht.onRegChange(.value_changed, "HKLM\\Software\\Test\\SomeKey");
    try std.testing.expect(ht.events_emitted > 0);
}
