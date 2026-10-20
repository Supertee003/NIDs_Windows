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

const std = @import("std");

pub const MAX_RULES: usize = 16;
pub const MAX_PORTS: usize = 8;

pub const Rule = struct {
    rule_id: u32 = 0,
    protocol: u8 = 0, // 0 = any; otherwise IP protocol number
    flags_value: u8 = 0, // 0 = no flag constraint; otherwise exact TCP flags
    ports: [MAX_PORTS]u16 = [_]u16{0} ** MAX_PORTS,
    port_count: u8 = 0,
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

test "L4 parser accepts the three real Rules.json predicates" {
    const doc =
        \\[
        \\ {"rule_id":"R9002","layer":"L4","match_pattern":"PROTO:ICMP","target_protocols":["ICMP"],"target_ports":[]},
        \\ {"rule_id":"R9006","layer":"L4","match_pattern":"FLAGS:S","target_protocols":["TCP"],"target_ports":[]},
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
    try std.testing.expect(matches(&icmp, 0, 0, 1, 0));
    try std.testing.expect(!matches(&icmp, 0, 0, 6, 0x02));

    const syn = parse(items[1], "FLAGS:S", 0x2222).?;
    try std.testing.expectEqual(@as(u8, 6), syn.protocol);
    try std.testing.expectEqual(@as(u8, 0x02), syn.flags_value);
    try std.testing.expect(matches(&syn, 12345, 80, 6, 0x02));
    try std.testing.expect(!matches(&syn, 12345, 80, 6, 0x12)); // SYN+ACK is not a stealth SYN
    try std.testing.expect(!matches(&syn, 12345, 80, 6, 0x10)); // ACK is not SYN
    try std.testing.expect(!matches(&syn, 12345, 80, 17, 0x02));

    const xmas = parse(items[2], "FLAGS:FPU", 0x3333).?;
    try std.testing.expectEqual(@as(u8, 0x29), xmas.flags_value);
    try std.testing.expect(matches(&xmas, 0, 0, 6, 0x29));
    try std.testing.expect(!matches(&xmas, 0, 0, 6, 0x01));
    try std.testing.expect(!matches(&xmas, 0, 0, 6, 0x28));

    const ported = parse(items[3], "FLAGS:S", 0x4444).?;
    try std.testing.expectEqual(@as(u8, 2), ported.port_count);
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
        \\ {"rule_id":"B12","layer":"L4"}
        \\]
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, doc, .{});
    defer parsed.deinit();
    for (parsed.value.array.items) |item| {
        const pat = if (item.object.get("match_pattern")) |p| p.string else "";
        try std.testing.expect(parse(item, pat, 1) == null);
    }
}
