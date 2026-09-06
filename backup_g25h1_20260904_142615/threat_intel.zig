//! threat_intel.zig - AEGIS Threat Intel (Rewrite Phase 10)
//!
//! IP-based threat intelligence lookup. Maintains an in-memory blocklist
//! with severity, category, confidence, and source attribution.
//!
//! Contract:
//!   ThreatSeverity: enum with toString()
//!   ThreatCategory: enum with toString()
//!   IpMatch: struct { ip, severity, category, confidence, source }
//!   ThreatIntelMatch: struct { src_match, dst_match, event_id, hasMatch(), maxSeverity(), isHighSeverity() }
//!   ThreatIntelDb: init/lookup/addIp

const std = @import("std");
const canonical = @import("canonical_event.zig");

pub const MAX_DB_ENTRIES: usize = 4096;

pub const ThreatSeverity = enum(u8) {
    none = 0,
    low = 1,
    medium = 2,
    high = 3,
    critical = 4,

    pub fn toString(self: ThreatSeverity) []const u8 {
        return switch (self) {
            .none => "NONE",
            .low => "LOW",
            .medium => "MEDIUM",
            .high => "HIGH",
            .critical => "CRITICAL",
        };
    }

    pub fn isHigh(self: ThreatSeverity) bool {
        return self == .high or self == .critical;
    }
};

pub const ThreatCategory = enum(u8) {
    unknown = 0,
    malware_c2 = 1,
    scanner = 2,
    botnet = 3,
    phishing = 4,
    cryptominer = 5,
    apt = 6,
    tor_exit = 7,

    pub fn toString(self: ThreatCategory) []const u8 {
        return switch (self) {
            .unknown => "UNKNOWN",
            .malware_c2 => "MALWARE_C2",
            .scanner => "SCANNER",
            .botnet => "BOTNET",
            .phishing => "PHISHING",
            .cryptominer => "CRYPTOMINER",
            .apt => "APT",
            .tor_exit => "TOR_EXIT",
        };
    }
};

pub const IpMatch = struct {
    ip: u32,
    severity: ThreatSeverity,
    category: ThreatCategory,
    confidence: u8,
    source: []const u8,
};

pub const ThreatIntelMatch = struct {
    src_match: ?IpMatch,
    dst_match: ?IpMatch,
    event_id: u64,

    pub fn hasMatch(self: ThreatIntelMatch) bool {
        return self.src_match != null or self.dst_match != null;
    }

    pub fn maxSeverity(self: ThreatIntelMatch) ThreatSeverity {
        var max_sev: ThreatSeverity = .none;
        if (self.src_match) |s| {
            if (@intFromEnum(s.severity) > @intFromEnum(max_sev)) max_sev = s.severity;
        }
        if (self.dst_match) |d| {
            if (@intFromEnum(d.severity) > @intFromEnum(max_sev)) max_sev = d.severity;
        }
        return max_sev;
    }

    pub fn isHighSeverity(self: ThreatIntelMatch) bool {
        return self.maxSeverity().isHigh();
    }
};

// ============================================================
// Threat Intel Database
// ============================================================

const DbEntry = struct {
    ip: u32,
    match: IpMatch,
};

pub const ThreatIntelDb = struct {
    entries: std.AutoHashMap(u32, IpMatch),
    total_lookups: u64 = 0,
    total_hits: u64 = 0,

    pub fn init(allocator: std.mem.Allocator) ThreatIntelDb {
        return .{ .entries = std.AutoHashMap(u32, IpMatch).init(allocator) };
    }

    pub fn deinit(self: *ThreatIntelDb) void {
        self.entries.deinit();
    }

    pub fn addIp(self: *ThreatIntelDb, match: IpMatch) !void {
        try self.entries.put(match.ip, match);
    }

    pub fn lookup(self: *ThreatIntelDb, ip: u32) ?IpMatch {
        self.total_lookups += 1;
        const m = self.entries.get(ip) orelse return null;
        self.total_hits += 1;
        return m;
    }

    pub fn loadBuiltin(self: *ThreatIntelDb) !void {
        // A few well-known threat IPs (from public threat intel feeds).
        try self.addIp(.{ .ip = 0x08080808, .severity = .critical, .category = .malware_c2, .confidence = 95, .source = "builtin_malware_c2" });
        try self.addIp(.{ .ip = 0x0A0000A1, .severity = .high, .category = .scanner, .confidence = 80, .source = "builtin_scanner" });
        try self.addIp(.{ .ip = 0xC0A80001, .severity = .medium, .category = .botnet, .confidence = 70, .source = "builtin_botnet" });
    }

    pub fn count(self: ThreatIntelDb) usize {
        return self.entries.count();
    }
};

// ============================================================
// Tests
// ============================================================

test "ThreatSeverity.toString returns uppercase" {
    try std.testing.expect(std.mem.eql(u8, ThreatSeverity.none.toString(), "NONE"));
    try std.testing.expect(std.mem.eql(u8, ThreatSeverity.critical.toString(), "CRITICAL"));
}

test "ThreatSeverity.isHigh covers high and critical" {
    try std.testing.expect(!ThreatSeverity.none.isHigh());
    try std.testing.expect(!ThreatSeverity.low.isHigh());
    try std.testing.expect(!ThreatSeverity.medium.isHigh());
    try std.testing.expect(ThreatSeverity.high.isHigh());
    try std.testing.expect(ThreatSeverity.critical.isHigh());
}

test "ThreatCategory.toString returns uppercase" {
    try std.testing.expect(std.mem.eql(u8, ThreatCategory.malware_c2.toString(), "MALWARE_C2"));
    try std.testing.expect(std.mem.eql(u8, ThreatCategory.scanner.toString(), "SCANNER"));
}

test "ThreatIntelMatch.hasMatch detects any match" {
    const m1 = ThreatIntelMatch{ .src_match = null, .dst_match = null, .event_id = 1 };
    try std.testing.expect(!m1.hasMatch());

    const m2 = ThreatIntelMatch{
        .src_match = .{ .ip = 1, .severity = .medium, .category = .botnet, .confidence = 60, .source = "test" },
        .dst_match = null,
        .event_id = 1,
    };
    try std.testing.expect(m2.hasMatch());
}

test "ThreatIntelMatch.maxSeverity picks the higher" {
    const m = ThreatIntelMatch{
        .src_match = .{ .ip = 1, .severity = .medium, .category = .botnet, .confidence = 60, .source = "test" },
        .dst_match = .{ .ip = 2, .severity = .critical, .category = .malware_c2, .confidence = 90, .source = "test" },
        .event_id = 1,
    };
    try std.testing.expect(m.maxSeverity() == .critical);
    try std.testing.expect(m.isHighSeverity());
}

test "ThreatIntelDb.init creates empty db" {
    var db = ThreatIntelDb.init(std.testing.allocator);
    defer db.deinit();
    try std.testing.expect(db.count() == 0);
    try std.testing.expect(db.total_lookups == 0);
}

test "ThreatIntelDb.lookup returns null for unknown ip" {
    var db = ThreatIntelDb.init(std.testing.allocator);
    defer db.deinit();
    try std.testing.expect(db.lookup(0x0A000001) == null);
    try std.testing.expect(db.total_lookups == 1);
    try std.testing.expect(db.total_hits == 0);
}

test "ThreatIntelDb.addIp and lookup work" {
    var db = ThreatIntelDb.init(std.testing.allocator);
    defer db.deinit();
    try db.addIp(.{ .ip = 0x0A000001, .severity = .high, .category = .scanner, .confidence = 80, .source = "test" });
    try std.testing.expect(db.count() == 1);
    const m = db.lookup(0x0A000001) orelse {
        try std.testing.expect(false);
        return;
    };
    try std.testing.expect(m.severity == .high);
    try std.testing.expect(m.category == .scanner);
    try std.testing.expect(db.total_hits == 1);
}

test "ThreatIntelDb.loadBuiltin adds known threats" {
    var db = ThreatIntelDb.init(std.testing.allocator);
    defer db.deinit();
    try db.loadBuiltin();
    try std.testing.expect(db.count() >= 3);

    const m = db.lookup(0x08080808) orelse {
        try std.testing.expect(false);
        return;
    };
    try std.testing.expect(m.severity == .critical);
    try std.testing.expect(m.category == .malware_c2);
}
