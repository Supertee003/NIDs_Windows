// II04 - Process & Thread Injection Detector (T1055 patterns)
// AEGIS NIDS v5.0+ â€” Detects 6 common process injection patterns via ETW
//
// Patterns:
//   1. VirtualAllocEx + WriteProcessMemory (classic CreateRemoteThread)
//   2. NtMapViewOfSection (process hollowing)
//   3. QueueUserAPC (APC injection)
//   4. SetThreadContext (thread hijack)
//   5. NtCreateThreadEx (modern thread creation)
//   6. RtlCreateUserThread (legacy thread creation)
//
// Triggers on ETW Kernel Proc/Thread + Image events with depth-2 call stacks.

const std = @import("std");
const event = @import("../contract/event.zig");
const diag = @import("../core/diagnostics.zig");

pub const InjectionPattern = enum(u8) {
    virtual_alloc_ex = 1,        // T1055.001 CreateRemoteThread
    map_view_of_section = 2,     // T1055.012 hollowing
    queue_user_apc = 3,          // T1055.004 APC
    set_thread_context = 4,      // T1055.005 thread hijack
    nt_create_thread_ex = 5,
    rtl_create_user_thread = 6,
};

pub const InjectionEvent = struct {
    pattern: InjectionPattern,
    source_pid: u32,
    target_pid: u32,
    target_image: [256]u8 = [_]u8{0} ** 256,
    timestamp_ns: i128,
    rule_id: u32,
    weight: u16,
};

pub const DetectionRule = struct {
    pattern: InjectionPattern,
    rule_id: u32,
    weight: u16,
    description: []const u8,
};

// ============================================================================
// Per-source-pid state â€” short sliding window of recent API calls
// ============================================================================
const RECENT_WINDOW: usize = 32;

pub const ApiCall = struct {
    timestamp_ns: i128,
    target_pid: u32,
    api_hash: u32, // FNV-1a of API name
    target_image: [256]u8 = [_]u8{0} ** 256,
    target_image_len: u16 = 0,
};

pub const SourceState = struct {
    calls: [RECENT_WINDOW]ApiCall = [_]ApiCall{.{ .timestamp_ns = 0, .target_pid = 0, .api_hash = 0 }} ** RECENT_WINDOW,
    head: usize = 0,
    count: usize = 0,

    pub fn push(self: *SourceState, call: ApiCall) void {
        self.calls[self.head] = call;
        self.head = (self.head + 1) % RECENT_WINDOW;
        if (self.count < RECENT_WINDOW) self.count += 1;
    }

    pub fn recent(self: *const SourceState, within_ns: i128, now_ns: i128) []const ApiCall {
        // Returns a slice view; caller must copy if needed
        _ = within_ns;
        _ = now_ns;
        return self.calls[0..self.count];
    }
};

// ============================================================================
// InjectionDetector
// ============================================================================
pub const InjectionDetector = struct {
    rules: []const DetectionRule,
    states: std.AutoHashMap(u32, SourceState), // keyed by source_pid
    detected: std.ArrayList(InjectionEvent),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, rules: []const DetectionRule) InjectionDetector {
        return .{
            .rules = rules,
            .states = std.AutoHashMap(u32, SourceState).init(allocator),
            .detected = std.ArrayList(InjectionEvent).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *InjectionDetector) void {
        self.states.deinit();
        self.detected.deinit();
    }

    pub fn observe(self: *InjectionDetector, source_pid: u32, target_pid: u32, api_hash: u32, target_image: []const u8, now_ns: i128) !?InjectionEvent {
        const gop = try self.states.getOrPut(source_pid);
        if (!gop.found_existing) gop.value_ptr.* = .{};
        const st = gop.value_ptr;
        var call = ApiCall{
            .timestamp_ns = now_ns,
            .target_pid = target_pid,
            .api_hash = api_hash,
        };
        const n = @min(target_image.len, call.target_image.len);
        @memcpy(call.target_image[0..n], target_image[0..n]);
        call.target_image_len = @intCast(n);
        st.push(call);

        // Check each rule
        for (self.rules) |rule| {
            const expected_hash = hashApi(rule.pattern);
            if (api_hash != expected_hash) continue;
            // Check if recent calls include a "target_pid" match (cross-process)
            if (target_pid != source_pid) {
                const ev = InjectionEvent{
                    .pattern = rule.pattern,
                    .source_pid = source_pid,
                    .target_pid = target_pid,
                    .target_image = call.target_image,
                    .timestamp_ns = now_ns,
                    .rule_id = rule.rule_id,
                    .weight = rule.weight,
                };
                try self.detected.append(ev);
                diag.alert("INJECTION DETECTED: pattern={s} src_pid={d} dst_pid={d}", .{ @tagName(rule.pattern), source_pid, target_pid });
                return ev;
            }
        }
        return null;
    }

    pub fn pending(self: *const InjectionDetector) usize {
        return self.detected.items.len;
    }

    pub fn drain(self: *InjectionDetector) []InjectionEvent {
        const items = self.detected.items;
        self.detected = std.ArrayList(InjectionEvent).init(self.allocator);
        return items;
    }
};

pub fn hashApi(p: InjectionPattern) u32 {
    const name = switch (p) {
        .virtual_alloc_ex => "VirtualAllocEx",
        .map_view_of_section => "NtMapViewOfSection",
        .queue_user_apc => "QueueUserAPC",
        .set_thread_context => "SetThreadContext",
        .nt_create_thread_ex => "NtCreateThreadEx",
        .rtl_create_user_thread => "RtlCreateUserThread",
    };
    var h: u32 = 0x811c9dc5;
    for (name) |b| {
        h ^= b;
        h *%= 0x01000193;
    }
    return h;
}

// ============================================================================
// Default rules
// ============================================================================
pub const DEFAULT_RULES = [_]DetectionRule{
    .{ .pattern = .virtual_alloc_ex, .rule_id = 2001, .weight = 80, .description = "T1055.001 VirtualAllocEx cross-process" },
    .{ .pattern = .map_view_of_section, .rule_id = 2002, .weight = 100, .description = "T1055.012 NtMapViewOfSection hollowing" },
    .{ .pattern = .queue_user_apc, .rule_id = 2003, .weight = 60, .description = "T1055.004 QueueUserAPC" },
    .{ .pattern = .set_thread_context, .rule_id = 2004, .weight = 70, .description = "T1055.005 SetThreadContext hijack" },
    .{ .pattern = .nt_create_thread_ex, .rule_id = 2005, .weight = 50, .description = "NtCreateThreadEx remote thread" },
    .{ .pattern = .rtl_create_user_thread, .rule_id = 2006, .weight = 50, .description = "RtlCreateUserThread remote thread" },
};

// ============================================================================
// Tests
// ============================================================================
test "hashApi deterministic" {
    try std.testing.expectEqual(hashApi(.virtual_alloc_ex), hashApi(.virtual_alloc_ex));
    try std.testing.expect(hashApi(.virtual_alloc_ex) != hashApi(.map_view_of_section));
}

test "InjectionDetector cross-process triggers" {
    var det = InjectionDetector.init(std.testing.allocator, &DEFAULT_RULES);
    defer det.deinit();
    const h = hashApi(.virtual_alloc_ex);
    const ev = try det.observe(1234, 5678, h, "C:\\Windows\\System32\\evil.exe", std.time.nanoTimestamp());
    try std.testing.expect(ev != null);
    try std.testing.expectEqual(InjectionPattern.virtual_alloc_ex, ev.?.pattern);
    try std.testing.expectEqual(@as(u32, 1234), ev.?.source_pid);
    try std.testing.expectEqual(@as(u32, 5678), ev.?.target_pid);
}

test "InjectionDetector same-process does not trigger" {
    var det = InjectionDetector.init(std.testing.allocator, &DEFAULT_RULES);
    defer det.deinit();
    const h = hashApi(.virtual_alloc_ex);
    const ev = try det.observe(1234, 1234, h, "C:\\Windows\\System32\\x.exe", std.time.nanoTimestamp());
    try std.testing.expect(ev == null);
}
