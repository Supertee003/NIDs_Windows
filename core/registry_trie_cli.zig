// registry_trie_cli.zig - AEGIS Phase 42: Registry Trie Optimization CLI.
// Builds with `zig build-exe registry_trie_cli.zig -lc`.
//
// Modes:
//   help                              - this screen
//   demo                              - 6 scenarios + PASS/FAIL summary (exit 0)
//   bench                              - benchmark trie vs linear scan
//   scenario <name>                   - run a single named scenario

const std = @import("std");
const ht = @import("host_telemetry.zig");
const trie = @import("registry_trie.zig");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    std.debug.print("AEGIS NIDS - Phase 42: Registry Trie Optimization CLI\n", .{});
    std.debug.print("=====================================================\n\n", .{});

    const mode: []const u8 = if (args.len >= 2) args[1] else "help";

    if (std.mem.eql(u8, mode, "help")) {
        printHelp();
        return;
    }

    if (std.mem.eql(u8, mode, "demo")) {
        const results = [_]struct { name: []const u8, ok: bool }{
            .{ .name = "kill-switch-off", .ok = scenarioKillSwitchOff() },
            .{ .name = "insert-and-match", .ok = scenarioInsertAndMatch() },
            .{ .name = "case-insensitive", .ok = scenarioCaseInsensitive() },
            .{ .name = "persistence-detection", .ok = scenarioPersistenceDetection() },
            .{ .name = "critical-detection", .ok = scenarioCriticalDetection() },
            .{ .name = "drop-in-compat", .ok = scenarioDropInCompat() },
            .{ .name = "benchmark-comparison", .ok = scenarioBenchmarkComparison() },
        };
        var passed: usize = 0;
        for (results) |r| {
            const tag = if (r.ok) "PASS" else "FAIL";
            std.debug.print("  [{s}] {s}\n", .{ tag, r.name });
            if (r.ok) passed += 1;
        }
        std.debug.print("\n{d}/{d} scenarios passed\n", .{ passed, results.len });
        if (passed != results.len) std.process.exit(1);
        return;
    }

    if (std.mem.eql(u8, mode, "bench")) {
        _ = runBenchmarkComparison();
        return;
    }

    if (std.mem.eql(u8, mode, "scenario")) {
        if (args.len < 3) {
            std.debug.print("Usage: registry_trie_cli scenario <name>\n", .{});
            printHelp();
            return;
        }
        const name = args[2];
        const ok = runScenarioByName(name);
        const tag = if (ok) "PASS" else "FAIL";
        std.debug.print("\n  [{s}] {s}\n", .{ tag, name });
        if (!ok) std.process.exit(1);
        return;
    }

    std.debug.print("Unknown mode: {s}\n", .{mode});
    printHelp();
}

fn printHelp() void {
    std.debug.print("Usage:\n", .{});
    std.debug.print("  registry_trie_cli help                          - this screen\n", .{});
    std.debug.print("  registry_trie_cli demo                          - all 7 scenarios + summary\n", .{});
    std.debug.print("  registry_trie_cli bench                          - benchmark trie vs linear\n", .{});
    std.debug.print("  registry_trie_cli scenario <name>               - one scenario\n", .{});
    std.debug.print("\nScenario names:\n", .{});
    std.debug.print("  kill-switch-off          - trie respects kill switch\n", .{});
    std.debug.print("  insert-and-match         - insert key + matchPrefix\n", .{});
    std.debug.print("  case-insensitive          - case variations all match\n", .{});
    std.debug.print("  persistence-detection     - HKLM Run key detected\n", .{});
    std.debug.print("  critical-detection        - SAM key detected\n", .{});
    std.debug.print("  drop-in-compat           - same defaults as RegistryWatchQueue\n", .{});
    std.debug.print("  benchmark-comparison      - trie vs linear scan speedup\n", .{});
}

fn runScenarioByName(name: []const u8) bool {
    if (std.mem.eql(u8, name, "kill-switch-off")) return scenarioKillSwitchOff();
    if (std.mem.eql(u8, name, "insert-and-match")) return scenarioInsertAndMatch();
    if (std.mem.eql(u8, name, "case-insensitive")) return scenarioCaseInsensitive();
    if (std.mem.eql(u8, name, "persistence-detection")) return scenarioPersistenceDetection();
    if (std.mem.eql(u8, name, "critical-detection")) return scenarioCriticalDetection();
    if (std.mem.eql(u8, name, "drop-in-compat")) return scenarioDropInCompat();
    if (std.mem.eql(u8, name, "benchmark-comparison")) return scenarioBenchmarkComparison();
    std.debug.print("[ERR] unknown scenario: {s}\n", .{name});
    return false;
}

// --------------------------------------------------------------
// Scenario implementations
// --------------------------------------------------------------

fn scenarioKillSwitchOff() bool {
    var t = trie.PrefixTrie.init(.{ .enabled = false });
    const ok = t.insert("hello", .persistence);
    const match = t.matchPrefix("hello");
    const result = !ok and match == .none;
    std.debug.print("  -> kill switch off; insert={s}, match={s}\n", .{
        if (ok) "true" else "false (expected)",
        @tagName(match),
    });
    return result;
}

fn scenarioInsertAndMatch() bool {
    var t = trie.PrefixTrie.init(.{ .enabled = true });
    _ = t.insert("hello", .persistence);

    const exact = t.matchPrefix("hello");
    const prefix = t.matchPrefix("hello\\world");
    const nomatch = t.matchPrefix("world");

    const ok = exact == .persistence and prefix == .persistence and nomatch == .none;
    std.debug.print("  -> exact={s}, prefix={s}, nomatch={s}\n", .{
        @tagName(exact), @tagName(prefix), @tagName(nomatch),
    });
    return ok;
}

fn scenarioCaseInsensitive() bool {
    var t = trie.PrefixTrie.init(.{ .enabled = true });
    _ = t.insert("Hello", .persistence);

    const lower = t.matchPrefix("hello");
    const upper = t.matchPrefix("HELLO");
    const mixed = t.matchPrefix("HeLLo\\World");

    const ok = lower == .persistence and upper == .persistence and mixed == .persistence;
    std.debug.print("  -> lower={s}, upper={s}, mixed={s}\n", .{
        @tagName(lower), @tagName(upper), @tagName(mixed),
    });
    return ok;
}

fn scenarioPersistenceDetection() bool {
    var w = trie.TrieRegistryWatch.init(.{ .enabled = true });

    var ev = ht.HostEvent{
        .event_type = .registry_set_value,
        .pid = 1234,
        .timestamp_ns = 1000,
    };
    const k = "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor";
    @memcpy(ev.reg_key[0..k.len], k);
    ev.reg_key_len = @intCast(k.len);

    const r = w.enqueue(ev) orelse return false;
    const ok = r == .registry_persistence_key;
    std.debug.print("  -> HKLM Run\\Backdoor; reason={s}, persistence_hits={d}\n", .{
        @tagName(r), w.total_persistence_hits,
    });
    return ok;
}

fn scenarioCriticalDetection() bool {
    var w = trie.TrieRegistryWatch.init(.{ .enabled = true });

    var ev = ht.HostEvent{
        .event_type = .registry_set_value,
        .pid = 1234,
        .timestamp_ns = 1000,
    };
    const k = "\\REGISTRY\\MACHINE\\SAM\\SAM\\Domains\\Account";
    @memcpy(ev.reg_key[0..k.len], k);
    ev.reg_key_len = @intCast(k.len);

    const r = w.enqueue(ev) orelse return false;
    const ok = r == .registry_critical_key;
    std.debug.print("  -> HKLM SAM\\Domains; reason={s}, critical_hits={d}\n", .{
        @tagName(r), w.total_critical_hits,
    });
    return ok;
}

fn scenarioDropInCompat() bool {
    var w = trie.TrieRegistryWatch.init(.{ .enabled = true });
    // Should install 6 persistence + 5 critical = 11 default keys
    // (same as ht.RegistryWatchQueue)
    const count = w.registeredKeyCount();
    const ok = count == 11;
    std.debug.print("  -> registered_keys={d} (expected 11 for drop-in compat)\n", .{count});
    return ok;
}

fn scenarioBenchmarkComparison() bool {
    return runBenchmarkComparison();
}

fn runBenchmarkComparison() bool {
    var t = trie.PrefixTrie.init(.{ .enabled = true });
    const keys = [_][]const u8{
        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "\\REGISTRY\\USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "\\REGISTRY\\MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services",
        "\\REGISTRY\\MACHINE\\SAM\\SAM",
        "\\REGISTRY\\MACHINE\\SECURITY",
        "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager",
        "\\REGISTRY\\USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    };
    for (keys) |k| _ = t.insert(k, .persistence);

    // Build linear scan arrays
    var linear_keys: [11][64]u8 = undefined;
    var linear_lens: [11]usize = undefined;
    for (keys, 0..) |k, i| {
        const n = @min(k.len, 64);
        @memcpy(linear_keys[i][0..n], k[0..n]);
        linear_lens[i] = n;
    }

    const query = "\\REGISTRY\\USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\Backdoor";
    const iterations: u32 = 50_000;

    // Trie benchmark
    const trie_start = std.time.nanoTimestamp();
    var i: u32 = 0;
    while (i < iterations) : (i += 1) {
        _ = t.matchPrefix(query);
    }
    const trie_ns: i64 = @intCast(std.time.nanoTimestamp() - trie_start);

    // Linear scan benchmark
    const linear_start = std.time.nanoTimestamp();
    i = 0;
    while (i < iterations) : (i += 1) {
        var buf: [256]u8 = undefined;
        const ql = @min(query.len, 256);
        @memcpy(buf[0..ql], query[0..ql]);
        for (buf[0..ql]) |*c| c.* = std.ascii.toLower(c.*);
        const query_lower = buf[0..ql];

        for (linear_keys, linear_lens) |lk, len| {
            var eb: [64]u8 = undefined;
            const el = @min(len, 64);
            @memcpy(eb[0..el], lk[0..el]);
            for (eb[0..el]) |*c| c.* = std.ascii.toLower(c.*);
            const entry_lower = eb[0..el];
            if (std.mem.startsWith(u8, query_lower, entry_lower)) break;
        }
    }
    const linear_ns: i64 = @intCast(std.time.nanoTimestamp() - linear_start);

    const trie_ops: f64 = @as(f64, @floatFromInt(iterations)) * 1_000_000_000.0 / @as(f64, @floatFromInt(trie_ns));
    const linear_ops: f64 = @as(f64, @floatFromInt(iterations)) * 1_000_000_000.0 / @as(f64, @floatFromInt(linear_ns));
    const ratio: f64 = @as(f64, @floatFromInt(linear_ns)) / @as(f64, @floatFromInt(trie_ns));

    std.debug.print("  -> Trie:      {d:>10.0} ops/sec  ({d:>8.2} us/op)\n", .{ trie_ops, @as(f64, @floatFromInt(trie_ns)) / @as(f64, @floatFromInt(iterations)) / 1000.0 });
    std.debug.print("  -> Linear:    {d:>10.0} ops/sec  ({d:>8.2} us/op)\n", .{ linear_ops, @as(f64, @floatFromInt(linear_ns)) / @as(f64, @floatFromInt(iterations)) / 1000.0 });
    std.debug.print("  -> Speedup:   {d:>10.2}x\n", .{ratio});

    return ratio > 1.0;
}
