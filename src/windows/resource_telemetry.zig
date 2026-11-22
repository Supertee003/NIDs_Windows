//! windows/resource_telemetry.zig — honest, off-hot-path process resource sample.
//!
//! RESOURCE-TELEMETRY-001. Produces CPU% and memory gauges for the control-plane
//! health payload ONLY. It is never called from the event pipeline (ADR-0013:
//! no per-event sampling). The Win32 calls are gated to Windows builds; the
//! non-Windows stub is honest (`available = false`).
//!
//! CPU% is percent of ONE logical core (100 = one fully busy core; a multi-core
//! host can legitimately exceed 100). It is a SAMPLED delta, not an instant
//! reading, and the first sample is `null` + `seeded = false` because there is
//! no previous tick to difference — a fabricated 0.0 would be a production mock.
//!
//! GetProcessMemoryInfo is resolved at runtime (kernel32 K32GetProcessMemoryInfo
//! first, psapi fallback) because Zig 0.13's bundled mingw definitions have no
//! x86_64 import lib for psapi. This keeps build.zig / CMakeLists.txt untouched,
//! matching the iphlpapi discipline in windows/host_net.zig.

const std = @import("std");
const builtin = @import("builtin");

pub const Sample = struct {
    available: bool = false,
    seeded: bool = false,
    /// null = unknown (cold start or failed Win32 read). Never coerce to 0.0.
    cpu_percent: ?f64 = null,
    working_set_bytes: u64 = 0,
    private_bytes: u64 = 0,
    /// 0 = no successful sample yet; rendered as unknown by the CLI.
    sampled_at_ms: i64 = 0,
    /// Internal monotonic CPU tick total (100 ns units); never emitted as JSON.
    ticks: u64 = 0,
};

/// Pure CPU percentage from two cumulative 100 ns FILETIME tick totals.
/// Returns null (unknown) for zero/negative elapsed or non-monotonic ticks —
/// never a negative or fabricated zero reading.
pub fn cpuPercent(prev_ticks: u64, cur_ticks: u64, elapsed_ns: u64) ?f64 {
    if (elapsed_ns == 0) return null;
    if (cur_ticks < prev_ticks) return null;
    const seconds = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000_000.0;
    if (seconds <= 0.0) return null;
    const cpu_seconds = @as(f64, @floatFromInt(cur_ticks - prev_ticks)) / 10_000_000.0;
    const pct = (cpu_seconds / seconds) * 100.0;
    if (!std.math.isFinite(pct) or pct < 0.0) return null;
    return pct;
}

/// Additive control-plane JSON object. Older readers ignore the whole block.
pub fn json(a: std.mem.Allocator, s: Sample) ![]u8 {
    var arr = std.ArrayList(u8).init(a);
    errdefer arr.deinit();
    const w = arr.writer();
    try w.print("{{\"available\":{},\"seeded\":{},\"cpu_percent\":", .{ s.available, s.seeded });
    if (s.cpu_percent) |p| {
        if (std.math.isFinite(p) and p >= 0.0) {
            try w.print("{d}", .{p});
        } else {
            try w.writeAll("null");
        }
    } else {
        try w.writeAll("null");
    }
    try w.print(",\"working_set_bytes\":{},\"private_bytes\":{},\"sampled_at_ms\":", .{
        s.working_set_bytes, s.private_bytes,
    });
    if (s.sampled_at_ms > 0) {
        try w.print("{}", .{s.sampled_at_ms});
    } else {
        try w.writeAll("null");
    }
    try w.writeAll("}");
    return arr.toOwnedSlice();
}

// ── Windows implementation (only referenced on Windows builds) ─────────────
const StubImpl = struct {
    fn sample() Sample {
        return .{}; // available=false, honest absence
    }
};

const WinImpl = struct {
    const HANDLE = ?*anyopaque;
    const FILETIME = extern struct {
        dwLowDateTime: u32,
        dwHighDateTime: u32,
    };
    const PROCESS_MEMORY_COUNTERS_EX = extern struct {
        cb: u32,
        PageFaultCount: u32,
        PeakWorkingSetSize: usize,
        WorkingSetSize: usize,
        QuotaPeakPagedPoolUsage: usize,
        QuotaPagedPoolUsage: usize,
        QuotaPeakNonPagedPoolUsage: usize,
        QuotaNonPagedPoolUsage: usize,
        PagefileUsage: usize,
        PeakPagefileUsage: usize,
        PrivateUsage: usize,
    };

    comptime {
        if (@sizeOf(PROCESS_MEMORY_COUNTERS_EX) != 2 * @sizeOf(u32) + 9 * @sizeOf(usize)) {
            @compileError("PROCESS_MEMORY_COUNTERS_EX ABI size drift");
        }
        if (@sizeOf(FILETIME) != 8) @compileError("FILETIME ABI size drift");
    }

    extern "kernel32" fn GetCurrentProcess() HANDLE;
    extern "kernel32" fn GetProcessTimes(
        hProcess: HANDLE,
        lpCreationTime: *FILETIME,
        lpExitTime: *FILETIME,
        lpKernelTime: *FILETIME,
        lpUserTime: *FILETIME,
    ) i32;

    const MemInfoFn = *const fn (hProcess: HANDLE, counters: *PROCESS_MEMORY_COUNTERS_EX, cb: u32) callconv(.C) i32;

    var api_lock: std.Thread.Mutex = .{};
    var g_kernel32: ?std.DynLib = null;
    var g_psapi: ?std.DynLib = null;
    var g_mem_info: ?MemInfoFn = null;

    fn memInfoFn() ?MemInfoFn {
        api_lock.lock();
        defer api_lock.unlock();
        if (g_mem_info) |f| return f;

        if (std.DynLib.open("kernel32.dll")) |loaded| {
            var k32 = loaded; // lookup takes *DynLib
            if (k32.lookup(MemInfoFn, "K32GetProcessMemoryInfo")) |f| {
                g_kernel32 = k32; // process-lifetime singleton; never closed
                g_mem_info = f;
                return f;
            }
            k32.close();
        } else |_| {}

        if (std.DynLib.open("psapi.dll")) |loaded| {
            var ps = loaded;
            if (ps.lookup(MemInfoFn, "GetProcessMemoryInfo")) |f| {
                g_psapi = ps;
                g_mem_info = f;
                return f;
            }
            ps.close();
        } else |_| {}
        return null;
    }

    fn filetimeTicks(ft: FILETIME) u64 {
        return (@as(u64, ft.dwHighDateTime) << 32) | @as(u64, ft.dwLowDateTime);
    }

    fn sample() Sample {
        var s = Sample{};
        const proc = GetCurrentProcess();
        if (proc == null) return s;

        var creation: FILETIME = .{ .dwLowDateTime = 0, .dwHighDateTime = 0 };
        var exit: FILETIME = .{ .dwLowDateTime = 0, .dwHighDateTime = 0 };
        var kernel: FILETIME = .{ .dwLowDateTime = 0, .dwHighDateTime = 0 };
        var user: FILETIME = .{ .dwLowDateTime = 0, .dwHighDateTime = 0 };
        if (GetProcessTimes(proc, &creation, &exit, &kernel, &user) == 0) return s;
        s.ticks = filetimeTicks(kernel) +| filetimeTicks(user);

        if (memInfoFn()) |get_mem| {
            var pmc: PROCESS_MEMORY_COUNTERS_EX = undefined;
            @memset(std.mem.asBytes(&pmc), 0);
            pmc.cb = @sizeOf(PROCESS_MEMORY_COUNTERS_EX);
            if (get_mem(proc, &pmc, pmc.cb) != 0) {
                s.working_set_bytes = pmc.WorkingSetSize;
                s.private_bytes = pmc.PrivateUsage;
                s.available = true;
            }
        }
        // CPU ticks were read even if memory failed: still a usable sample.
        if (!s.available and s.ticks != 0) s.available = true;
        return s;
    }
};

const Impl = if (builtin.os.tag == .windows) WinImpl else StubImpl;

/// Minimum interval between actual Win32 reads, so N dashboard clients cannot
/// turn a control query into a polling flood. Cached value is returned in between.
const MIN_INTERVAL_NS: i128 = 500 * std.time.ns_per_ms;

var sample_lock: std.Thread.Mutex = .{};
var g_prev_ticks: u64 = 0;
var g_prev_ns: i128 = 0;
var g_last_ns: i128 = 0;
var g_cached: Sample = .{};

/// Pull-on-query entry point. Structurally incapable of touching the hot path:
/// only src/control/state_machine.zig healthJson calls this.
pub fn current() Sample {
    const now = std.time.nanoTimestamp();
    sample_lock.lock();
    defer sample_lock.unlock();

    if (g_last_ns != 0 and now - g_last_ns < MIN_INTERVAL_NS) return g_cached;

    var s = Impl.sample();
    if (s.available) {
        if (g_prev_ns != 0 and now > g_prev_ns) {
            const elapsed: u64 = @intCast(now - g_prev_ns);
            s.cpu_percent = cpuPercent(g_prev_ticks, s.ticks, elapsed);
            s.seeded = true;
        } else {
            s.cpu_percent = null;
            s.seeded = false;
        }
        g_prev_ticks = s.ticks;
        g_prev_ns = now;
        s.sampled_at_ms = std.time.milliTimestamp();
    } else {
        s.cpu_percent = null;
        s.seeded = false;
        s.sampled_at_ms = 0;
    }
    g_last_ns = now;
    g_cached = s;
    return s;
}

// ── E2 tests: pure functions only; no Win32 call, no DLL open ──────────────
test "cpuPercent: zero elapsed is unknown, never zero" {
    try std.testing.expect(cpuPercent(100, 200, 0) == null);
}

test "cpuPercent: equal ticks is a real zero delta" {
    const p = cpuPercent(1_000, 1_000, std.time.ns_per_s);
    try std.testing.expect(p != null);
    try std.testing.expectEqual(@as(f64, 0.0), p.?);
}

test "cpuPercent: non-monotonic ticks are unknown, never negative" {
    try std.testing.expect(cpuPercent(500, 400, std.time.ns_per_s) == null);
}

test "cpuPercent: 100ms of CPU over 1s is 10 percent of one core" {
    const delta_ticks: u64 = 1_000_000; // 100 ms in 100 ns units
    const p = cpuPercent(0, delta_ticks, std.time.ns_per_s);
    try std.testing.expect(p != null);
    try std.testing.expectApproxEqAbs(@as(f64, 10.0), p.?, 0.0001);
}

test "cpuPercent: one busy core for one second is 100 percent" {
    const p = cpuPercent(0, 10_000_000, std.time.ns_per_s);
    try std.testing.expect(p != null);
    try std.testing.expectApproxEqAbs(@as(f64, 100.0), p.?, 0.0001);
}

test "resource json: cold start emits null cpu and null sampled_at" {
    const a = std.testing.allocator;
    const out = try json(a, .{});
    defer a.free(out);
    try std.testing.expectEqualStrings(
        "{\"available\":false,\"seeded\":false,\"cpu_percent\":null,\"working_set_bytes\":0,\"private_bytes\":0,\"sampled_at_ms\":null}",
        out,
    );
}

test "resource json: finite sample emits numbers; NaN cpu is sanitized to null" {
    const a = std.testing.allocator;
    const good = try json(a, .{
        .available = true,
        .seeded = true,
        .cpu_percent = 12.5,
        .working_set_bytes = 268_435_456,
        .private_bytes = 201_326_592,
        .sampled_at_ms = 1_763_550_000_123,
    });
    defer a.free(good);
    try std.testing.expect(std.mem.indexOf(u8, good, "\"cpu_percent\":12.5") != null);
    try std.testing.expect(std.mem.indexOf(u8, good, "\"sampled_at_ms\":1763550000123") != null);

    const bad = try json(a, .{ .available = true, .cpu_percent = std.math.nan(f64) });
    defer a.free(bad);
    try std.testing.expect(std.mem.indexOf(u8, bad, "\"cpu_percent\":null") != null);
}
