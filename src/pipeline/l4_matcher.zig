//! L4 predicate rules for Rules.json entries whose layer is "L4".
//!
//! The Aho-Corasick engine only sees payload bytes. L4 rules are not
//! payload signatures: their match is (protocol, TCP flags, ports). Keeping
//! them out of the AC table prevents a literal token such as "FLAGS:S"
//! from firing on an HTTP body, and lets the pipeline evaluate the packet
//! metadata the sensor actually observed.
//!
//! The current Rules.json L4 vocabulary is deliberately small:
//!   PROTO:ICMP  -> protocol 1, any TCP flags
//!   FLAGS:S     -> TCP, flags exactly SYN
//!   FLAGS:FPU   -> TCP, flags exactly FIN|PSH|URG
//! An unsupported token is a malformed rule, never a payload fallback.
//!
//! Rate/window semantics are opt-in per rule through the optional
//! `rate_mode` / `rate_threshold` / `rate_window_ms` fields. The canonical
//! R9002 (ICMP) and R9006 (SYN) entries opt in; R9007 remains a per-packet
//! exact-flag predicate. A rate rule emits at most one detection per source
//! and window, when the threshold is first reached.

const std = @import("std");

pub const MAX_RULES: usize = 16;
pub const MAX_PORTS: usize = 8;

pub const MAX_RATE_ENTRIES: usize = 256;
pub const MAX_DISTINCT_PORTS: usize = 64;
pub const MAX_RATE_THRESHOLD: u32 = 1_000_000;
pub const MAX_RATE_WINDOW_MS: u32 = 3_600_000;

pub const RateMode = enum {
    none,
    count,
    distinct_dst_ports,
};

pub const Rule = struct {
    rule_id: u32 = 0,
    protocol: u8 = 0, // 0 = any; otherwise IP protocol number
    flags_value: u8 = 0, // 0 = no flag constraint; otherwise exact TCP flags
    ports: [MAX_PORTS]u16 = [_]u16{0} ** MAX_PORTS,
    port_count: u8 = 0,
    rate_mode: RateMode = .none,
    rate_threshold: u32 = 0,
    rate_window_ms: u32 = 0,
};

pub const empty_rules = [_]Rule{.{}} ** MAX_RULES;

pub fn isL4(rule_val: std.json.Value) bool {
    if (rule_val != .object) return false;
    const layer = rule_val.object.get("layer") orelse return false;
    if (layer != .string) return false;
    return std.mem.eql(u8, layer.string, "L4");
}

fn protocolFromName(name: []const u8) ?u8 {
    if (std.mem.eql(u8, name, "TCP")) return 6;
    if (std.mem.eql(u8, name, "UDP")) return 17;
    if (std.mem.eql(u8, name, "ICMP")) return 1;
    if (std.mem.eql(u8, name, "ICMPV6")) return 58;
    return null;
}

fn flagsFromToken(token: []const u8) ?u8 {
    if (token.len == 0) return null;
    var flags: u8 = 0;
    for (token) |c| {
        const bit: u8 = switch (c) {
            'F' => 0x01,
            'S' => 0x02,
            'R' => 0x04,
            'P' => 0x08,
            'A' => 0x10,
            'U' => 0x20,
            'E' => 0x40,
            'C' => 0x80,
            else => return null,
        };
        flags |= bit;
    }
    return flags;
}

/// Parse the optional rate block. All three fields must be present together;
/// an empty block means a per-packet predicate. Invalid values are malformed,
/// not silently ignored.
fn parseRate(rule_val: std.json.Value, rule: *Rule) bool {
    const mode_val = rule_val.object.get("rate_mode");
    const threshold_val = rule_val.object.get("rate_threshold");
    const window_val = rule_val.object.get("rate_window_ms");

    if (mode_val == null and threshold_val == null and window_val == null) return true;
    if (mode_val == null or threshold_val == null or window_val == null) return false;
    if (mode_val.? != .string or threshold_val.? != .integer or window_val.? != .integer) return false;

    const mode: RateMode = if (std.mem.eql(u8, mode_val.?.string, "count"))
        .count
    else if (std.mem.eql(u8, mode_val.?.string, "distinct_dst_ports"))
        .distinct_dst_ports
    else
        return false;

    const threshold = threshold_val.?.integer;
    const window_ms = window_val.?.integer;
    if (threshold <= 0 or threshold > @as(i64, MAX_RATE_THRESHOLD)) return false;
    if (window_ms <= 0 or window_ms > @as(i64, MAX_RATE_WINDOW_MS)) return false;
    if (mode == .distinct_dst_ports and threshold > @as(i64, MAX_DISTINCT_PORTS)) return false;

    rule.rate_mode = mode;
    rule.rate_threshold = @intCast(threshold);
    rule.rate_window_ms = @intCast(window_ms);
    return true;
}

/// Parse one layer=="L4" rule. `pattern` is the already-classified
/// match_pattern string; `id_hash` is the cross-language FNV-1a rule id.
/// Returns null for any unsupported predicate or malformed metadata so the
/// caller records a named skip instead of silently loading a payload token.
pub fn parse(rule_val: std.json.Value, pattern: []const u8, id_hash: u32) ?Rule {
    if (!isL4(rule_val)) return null;
    if (pattern.len == 0) return null;

    var target_protocol: ?u8 = null;
    if (rule_val.object.get("target_protocols")) |protocols| {
        if (protocols != .array) return null;
        for (protocols.array.items, 0..) |value, i| {
            if (value != .string) return null;
            const protocol = protocolFromName(value.string) orelse return null;
            if (i == 0) {
                target_protocol = protocol;
            } else if (target_protocol.? != protocol) {
                return null;
            }
        }
    }

    var rule = Rule{ .rule_id = id_hash };

    if (std.mem.startsWith(u8, pattern, "PROTO:")) {
        const protocol = protocolFromName(pattern["PROTO:".len..]) orelse return null;
        if (target_protocol) |declared| {
            if (declared != protocol) return null;
        }
        rule.protocol = protocol;
    } else if (std.mem.startsWith(u8, pattern, "FLAGS:")) {
        const flags = flagsFromToken(pattern["FLAGS:".len..]) orelse return null;
        rule.protocol = 6;
        if (target_protocol) |declared| {
            if (declared != 6) return null;
            rule.protocol = declared;
        }
        rule.flags_value = flags;
    } else {
        return null;
    }

    if (rule_val.object.get("target_ports")) |ports| {
        if (ports != .array) return null;
        if (ports.array.items.len > MAX_PORTS) return null;
        for (ports.array.items, 0..) |value, i| {
            if (value != .integer) return null;
            if (value.integer < 0 or value.integer > 65535) return null;
            rule.ports[i] = @intCast(value.integer);
        }
        rule.port_count = @intCast(ports.array.items.len);
    }

    if (!parseRate(rule_val, &rule)) return null;

    return rule;
}

pub fn matches(rule: *const Rule, src_port: u16, dst_port: u16, protocol: u8, tcp_flags: u8) bool {
    if (rule.protocol != 0 and protocol != rule.protocol) return false;
    if (rule.flags_value != 0) {
        // The tokens in Rules.json name an exact flag set (SYN, not SYN+ACK;
        // FIN|PSH|URG, not a subset). Matching a subset would turn a normal
        // handshake into a scan hit.
        if (protocol != 6 or tcp_flags != rule.flags_value) return false;
    }
    if (rule.port_count > 0) {
        var port_match = false;
        for (rule.ports[0..rule.port_count]) |port| {
            if (src_port == port or dst_port == port) {
                port_match = true;
                break;
            }
        }
        if (!port_match) return false;
    }
    return true;
}

const RateEntry = struct {
    used: bool = false,
    rule_id: u32 = 0,
    src_ip: [16]u8 = [_]u8{0} ** 16,
    src_is_ipv6: bool = false,
    window_start_ms: i64 = 0,
    count: u32 = 0,
    port_count: u8 = 0,
    ports: [MAX_DISTINCT_PORTS]u16 = [_]u16{0} ** MAX_DISTINCT_PORTS,
    alerted: bool = false,
};

/// Fixed-size per-source rate/window state. The pipeline has one consumer;
/// the mutex around the runtime global protects the control-plane reload.
/// Eviction is round-robin, so a table full of unrelated sources cannot
/// allocate or grow without bound.
pub const RateTracker = struct {
    entries: [MAX_RATE_ENTRIES]RateEntry = [_]RateEntry{.{}} ** MAX_RATE_ENTRIES,
    next: usize = 0,

    pub fn reset(self: *RateTracker) void {
        self.* = .{};
    }

    fn hasPort(entry: *const RateEntry, port: u16) bool {
        for (entry.ports[0..entry.port_count]) |candidate| {
            if (candidate == port) return true;
        }
        return false;
    }

    fn findOrCreate(self: *RateTracker, rule_id: u32, src_ip: [16]u8, src_is_ipv6: bool) *RateEntry {
        for (&self.entries) |*entry| {
            if (!entry.used) continue;
            if (entry.rule_id != rule_id) continue;
            if (entry.src_is_ipv6 != src_is_ipv6) continue;
            if (!std.mem.eql(u8, entry.src_ip[0..], src_ip[0..])) continue;
            return entry;
        }

        const entry = &self.entries[self.next];
        self.next = (self.next + 1) % MAX_RATE_ENTRIES;
        entry.* = .{
            .used = true,
            .rule_id = rule_id,
            .src_ip = src_ip,
            .src_is_ipv6 = src_is_ipv6,
        };
        return entry;
    }

    /// Return true when this packet is the first one in its window to reach
    /// the rule threshold. Per-packet rules (rate_mode == .none) always true.
    pub fn observe(
        self: *RateTracker,
        rule: *const Rule,
        src_ip: [16]u8,
        src_is_ipv6: bool,
        dst_port: u16,
        now_ms: i64,
    ) bool {
        if (rule.rate_mode == .none) return true;
        if (rule.rate_threshold == 0 or rule.rate_window_ms == 0) return true;

        const entry = self.findOrCreate(rule.rule_id, src_ip, src_is_ipv6);
        const window_ms: i64 = @intCast(rule.rate_window_ms);
        const expired = entry.count == 0 or
            now_ms < entry.window_start_ms or
            now_ms - entry.window_start_ms >= window_ms;
        if (expired) {
            entry.window_start_ms = now_ms;
            entry.count = 0;
            entry.port_count = 0;
            entry.ports = [_]u16{0} ** MAX_DISTINCT_PORTS;
            entry.alerted = false;
        }

        switch (rule.rate_mode) {
            .none => return true,
            .count => entry.count +|= 1,
            .distinct_dst_ports => {
                if (!hasPort(entry, dst_port)) {
                    if (entry.port_count < MAX_DISTINCT_PORTS) {
                        entry.ports[entry.port_count] = dst_port;
                        entry.port_count += 1;
                    }
                    entry.count = @intCast(entry.port_count);
                }
            },
        }

        if (!entry.alerted and entry.count >= rule.rate_threshold) {
            entry.alerted = true;
            return true;
        }
        return false;
    }
};

test "L4 parser accepts the three real Rules.json predicates" {
    const doc =
        \\[
        \\ {"rule_id":"R9002","layer":"L4","match_pattern":"PROTO:ICMP","target_protocols":["ICMP"],"target_ports":[],"rate_mode":"count","rate_threshold":50,"rate_window_ms":1000},
        \\ {"rule_id":"R9006","layer":"L4","match_pattern":"FLAGS:S","target_protocols":["TCP"],"target_ports":[],"rate_mode":"distinct_dst_ports","rate_threshold":20,"rate_window_ms":10000},
        \\ {"rule_id":"R9007","layer":"L4","match_pattern":"FLAGS:FPU","target_protocols":["TCP"],"target_ports":[]},
        \\ {"rule_id":"R9100","layer":"L4","match_pattern":"FLAGS:S","target_protocols":["TCP"],"target_ports":[80,443]}
        \\]
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, doc, .{});
    defer parsed.deinit();
    const items = parsed.value.array.items;

    const icmp = parse(items[0], "PROTO:ICMP", 0x1111).?;
    try std.testing.expectEqual(@as(u32, 0x1111), icmp.rule_id);
    try std.testing.expectEqual(@as(u8, 1), icmp.protocol);
    try std.testing.expectEqual(@as(u8, 0), icmp.flags_value);
    try std.testing.expectEqual(RateMode.count, icmp.rate_mode);
    try std.testing.expectEqual(@as(u32, 50), icmp.rate_threshold);
    try std.testing.expectEqual(@as(u32, 1000), icmp.rate_window_ms);
    try std.testing.expect(matches(&icmp, 0, 0, 1, 0));
    try std.testing.expect(!matches(&icmp, 0, 0, 6, 0x02));

    const syn = parse(items[1], "FLAGS:S", 0x2222).?;
    try std.testing.expectEqual(@as(u8, 6), syn.protocol);
    try std.testing.expectEqual(@as(u8, 0x02), syn.flags_value);
    try std.testing.expectEqual(RateMode.distinct_dst_ports, syn.rate_mode);
    try std.testing.expectEqual(@as(u32, 20), syn.rate_threshold);
    try std.testing.expectEqual(@as(u32, 10000), syn.rate_window_ms);
    try std.testing.expect(matches(&syn, 12345, 80, 6, 0x02));
    try std.testing.expect(!matches(&syn, 12345, 80, 6, 0x12)); // SYN+ACK is not a stealth SYN
    try std.testing.expect(!matches(&syn, 12345, 80, 6, 0x10)); // ACK is not SYN
    try std.testing.expect(!matches(&syn, 12345, 80, 17, 0x02));

    const xmas = parse(items[2], "FLAGS:FPU", 0x3333).?;
    try std.testing.expectEqual(@as(u8, 0x29), xmas.flags_value);
    try std.testing.expectEqual(RateMode.none, xmas.rate_mode);
    try std.testing.expect(matches(&xmas, 0, 0, 6, 0x29));
    try std.testing.expect(!matches(&xmas, 0, 0, 6, 0x01));
    try std.testing.expect(!matches(&xmas, 0, 0, 6, 0x28));

    const ported = parse(items[3], "FLAGS:S", 0x4444).?;
    try std.testing.expectEqual(@as(u8, 2), ported.port_count);
    try std.testing.expectEqual(RateMode.none, ported.rate_mode);
    try std.testing.expect(matches(&ported, 5555, 443, 6, 0x02));
    try std.testing.expect(matches(&ported, 80, 5555, 6, 0x02));
    try std.testing.expect(!matches(&ported, 5555, 8080, 6, 0x02));

    try std.testing.expect(isL4(items[0]));
    try std.testing.expect(!isL4(items[0].object.get("rule_id").?));
}

test "L4 parser rejects unsupported or malformed predicates" {
    const doc =
        \\[
        \\ {"rule_id":"B1","layer":"L4","match_pattern":"FLAGS:X"},
        \\ {"rule_id":"B2","layer":"L4","match_pattern":"PROTO:BOGUS"},
        \\ {"rule_id":"B3","layer":"L4","match_pattern":"FLAGS:S","target_protocols":["UDP"]},
        \\ {"rule_id":"B4","layer":"L4","match_pattern":"PROTO:ICMP","target_protocols":["TCP"]},
        \\ {"rule_id":"B5","layer":"L4","match_pattern":"FLAGS:S","target_ports":[80,443,8080,8443,1,2,3,4,5]},
        \\ {"rule_id":"B6","layer":"L4","match_pattern":"FLAGS:S","target_ports":["80"]},
        \\ {"rule_id":"B7","layer":"L4","match_pattern":"FLAGS:S","target_ports":[-1]},
        \\ {"rule_id":"B8","layer":"L4","match_pattern":"FLAGS:S","target_ports":[70000]},
        \\ {"rule_id":"B9","layer":"L7","match_pattern":"FLAGS:S"},
        \\ {"rule_id":"B10","layer":"L4","match_pattern":"literal"},
        \\ {"rule_id":"B11","layer":"L4","match_pattern":""},
        \\ {"rule_id":"B12","layer":"L4"},
        \\ {"rule_id":"B13","layer":"L4","match_pattern":"PROTO:ICMP","rate_mode":"count","rate_threshold":0,"rate_window_ms":1000},
        \\ {"rule_id":"B14","layer":"L4","match_pattern":"PROTO:ICMP","rate_mode":"count","rate_threshold":50,"rate_window_ms":0},
        \\ {"rule_id":"B15","layer":"L4","match_pattern":"PROTO:ICMP","rate_mode":"bogus","rate_threshold":50,"rate_window_ms":1000},
        \\ {"rule_id":"B16","layer":"L4","match_pattern":"PROTO:ICMP","rate_mode":"count","rate_window_ms":1000},
        \\ {"rule_id":"B17","layer":"L4","match_pattern":"FLAGS:S","rate_mode":"distinct_dst_ports","rate_threshold":65,"rate_window_ms":10000},
        \\ {"rule_id":"B18","layer":"L4","match_pattern":"PROTO:ICMP","rate_mode":"count","rate_threshold":"50","rate_window_ms":1000},
        \\ {"rule_id":"B19","layer":"L4","match_pattern":"PROTO:ICMP","rate_threshold":50}
        \\]
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, doc, .{});
    defer parsed.deinit();
    for (parsed.value.array.items) |item| {
        const pat = if (item.object.get("match_pattern")) |p| p.string else "";
        try std.testing.expect(parse(item, pat, 1) == null);
    }
}

test "L4 rate negative control: normal handshakes and pings stay below threshold" {
    const syn_doc =
        \\{"rule_id":"R9006","layer":"L4","match_pattern":"FLAGS:S","target_protocols":["TCP"],"target_ports":[],"rate_mode":"distinct_dst_ports","rate_threshold":20,"rate_window_ms":10000}
    ;
    var syn_parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, syn_doc, .{});
    defer syn_parsed.deinit();
    const syn = parse(syn_parsed.value, "FLAGS:S", 0x2222).?;

    var src_a = [_]u8{0} ** 16;
    src_a[15] = 10;
    var syn_tracker = RateTracker{};

    // A single normal handshake is a valid SYN predicate, but not yet a scan.
    try std.testing.expect(matches(&syn, 40000, 80, 6, 0x02));
    try std.testing.expect(!syn_tracker.observe(&syn, src_a, false, 80, 0));

    // One normal handshake plus eighteen more distinct destinations is
    // still below the scan threshold; the twentieth is the first alert
    // (tested separately).
    var i: u16 = 0;
    while (i < 18) : (i += 1) {
        try std.testing.expect(!syn_tracker.observe(&syn, src_a, false, 1000 + i, @intCast(i)));
    }

    const icmp_doc =
        \\{"rule_id":"R9002","layer":"L4","match_pattern":"PROTO:ICMP","target_protocols":["ICMP"],"target_ports":[],"rate_mode":"count","rate_threshold":50,"rate_window_ms":1000}
    ;
    var icmp_parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, icmp_doc, .{});
    defer icmp_parsed.deinit();
    const icmp = parse(icmp_parsed.value, "PROTO:ICMP", 0x1111).?;
    var ping_tracker = RateTracker{};

    // Normal pings below the flood threshold never fire.
    i = 0;
    while (i < 49) : (i += 1) {
        try std.testing.expect(!ping_tracker.observe(&icmp, src_a, false, 0, @intCast(i)));
    }
}

test "L4 rate positive: threshold fires once per window and re-arms" {
    const icmp_doc =
        \\{"rule_id":"R9002","layer":"L4","match_pattern":"PROTO:ICMP","target_protocols":["ICMP"],"target_ports":[],"rate_mode":"count","rate_threshold":50,"rate_window_ms":1000}
    ;
    var icmp_parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, icmp_doc, .{});
    defer icmp_parsed.deinit();
    const icmp = parse(icmp_parsed.value, "PROTO:ICMP", 0x1111).?;
    var src_a = [_]u8{0} ** 16;
    src_a[15] = 10;
    var tracker = RateTracker{};

    var i: u32 = 0;
    while (i < 49) : (i += 1) {
        try std.testing.expect(!tracker.observe(&icmp, src_a, false, 0, @intCast(i)));
    }
    try std.testing.expect(tracker.observe(&icmp, src_a, false, 0, 49));
    try std.testing.expect(!tracker.observe(&icmp, src_a, false, 0, 50));

    // The next window re-arms at the same source. The first packet of the
    // window starts a new count; the fiftieth is the next alert.
    i = 0;
    while (i < 49) : (i += 1) {
        try std.testing.expect(!tracker.observe(&icmp, src_a, false, 0, 1000 + @as(i64, @intCast(i))));
    }
    try std.testing.expect(tracker.observe(&icmp, src_a, false, 0, 1049));

    const syn_doc =
        \\{"rule_id":"R9006","layer":"L4","match_pattern":"FLAGS:S","target_protocols":["TCP"],"target_ports":[],"rate_mode":"distinct_dst_ports","rate_threshold":20,"rate_window_ms":10000}
    ;
    var syn_parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, syn_doc, .{});
    defer syn_parsed.deinit();
    const syn = parse(syn_parsed.value, "FLAGS:S", 0x2222).?;
    var scan_tracker = RateTracker{};

    i = 0;
    while (i < 20) : (i += 1) {
        try std.testing.expectEqual(i == 19, scan_tracker.observe(&syn, src_a, false, 1000 + @as(u16, @intCast(i)), @intCast(i)));
    }
    // A duplicate destination port does not advance a distinct-port count.
    try std.testing.expect(!scan_tracker.observe(&syn, src_a, false, 1000, 20));
}

test "L4 rate state is per source and resets with the rule table" {
    const syn_doc =
        \\{"rule_id":"R9006","layer":"L4","match_pattern":"FLAGS:S","target_protocols":["TCP"],"target_ports":[],"rate_mode":"distinct_dst_ports","rate_threshold":20,"rate_window_ms":10000}
    ;
    var syn_parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, syn_doc, .{});
    defer syn_parsed.deinit();
    const syn = parse(syn_parsed.value, "FLAGS:S", 0x2222).?;
    var tracker = RateTracker{};

    var src_a = [_]u8{0} ** 16;
    src_a[15] = 10;
    var src_b = [_]u8{0} ** 16;
    src_b[15] = 11;

    var i: u16 = 0;
    while (i < 19) : (i += 1) {
        try std.testing.expect(!tracker.observe(&syn, src_a, false, 2000 + i, @intCast(i)));
    }
    try std.testing.expect(tracker.observe(&syn, src_a, false, 2019, 20));
    try std.testing.expect(!tracker.observe(&syn, src_a, false, 2020, 21));

    // Source B is independent: its twentieth distinct port fires even though
    // source A is already suppressed in the same window.
    i = 0;
    while (i < 19) : (i += 1) {
        try std.testing.expect(!tracker.observe(&syn, src_b, false, 3000 + i, @intCast(i)));
    }
    try std.testing.expect(tracker.observe(&syn, src_b, false, 3019, 19));

    // Same bytes with an IPv6 identity are a different source.
    const src_a_v6 = src_a;
    try std.testing.expect(!tracker.observe(&syn, src_a_v6, true, 2000, 0));

    // Reset is what the rule-loader calls after a rules swap.
    tracker.reset();
    i = 0;
    while (i < 19) : (i += 1) {
        try std.testing.expect(!tracker.observe(&syn, src_a, false, 2000 + i, @intCast(i)));
    }
    try std.testing.expect(tracker.observe(&syn, src_a, false, 2019, 20));
}

test "L4 per-packet rules remain stateless" {
    const xmas_doc =
        \\{"rule_id":"R9007","layer":"L4","match_pattern":"FLAGS:FPU","target_protocols":["TCP"],"target_ports":[]}
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, xmas_doc, .{});
    defer parsed.deinit();
    const xmas = parse(parsed.value, "FLAGS:FPU", 0x3333).?;
    try std.testing.expectEqual(RateMode.none, xmas.rate_mode);

    var tracker = RateTracker{};
    const src = [_]u8{0} ** 16;
    var i: u8 = 0;
    while (i < 5) : (i += 1) {
        try std.testing.expect(tracker.observe(&xmas, src, false, 0, @intCast(i)));
    }
}
