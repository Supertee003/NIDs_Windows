//! threat_intel.zig - AEGIS Threat Intelligence (Rewrite Phase 10)
//!
//! IP-based threat intelligence lookup. Provides CONTEXT ENRICHMENT
//! (not verdicts) that correlation and policy can use to escalate.
//!
//! Architecture:
//!   Detection (Phase 7) -> Aggregation (Phase 8) -> Correlation (Phase 9)
//!   -> Threat Intel Enrichment (Phase 10) -> [future Policy Phase 12]
//!
//! Threat Intel is an ADVISOR, not an enforcer:
//!   - lookupIp(ip) -> ?ThreatIntelEntry (returns metadata if known bad IP)
//!   - enrichEvent(event) -> ThreatIntelMatch (attach threat intel context)
//!   - Does NOT block, alert, or modify the event directly.
//!
//! Database format (simple, no external dependencies):
//!   HashMap<u32 ip, ThreatIntelEntry> with built-in entries loaded at init.
//!   Future: load from JSON/CSV file, sync with external feeds.

const std = @import("std");
const canonical = @import("canonical_event.zig");

// ============================================================
// Constants
// ============================================================

/// Maximum entries in the threat intel database.
pub const MAX_ENTRIES: usize = 65536;

// ============================================================
// Threat Intel Entry
// ============================================================

/// Threat severity classification from intelligence feed.
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

    /// Numeric rank for comparison (higher = more severe).
    pub fn rank(self: ThreatSeverity) u8 {
        return @intFromEnum(self);
    }
};

/// Threat category (what kind of malicious activity).
pub const ThreatCategory = enum(u8) {
    unknown = 0,
    malware_c2 = 1,
    botnet = 2,
    scanner = 3,
    brute_force = 4,
    spam = 5,
    phishing = 6,
    miner = 7,
    apt = 8,
    suspicious_proxy = 9,

    pub fn toString(self: ThreatCategory) []const u8 {
        return switch (self) {
            .unknown => "UNKNOWN",
            .malware_c2 => "MALWARE_C2",
            .botnet => "BOTNET",
            .scanner => "SCANNER",
            .brute_force => "BRUTE_FORCE",
            .spam => "SPAM",
            .phishing => "PHISHING",
            .miner => "MINER",
            .apt => "APT",
            .suspicious_proxy => "SUSPICIOUS_PROXY",
        };
    }
};

/// A single threat intelligence entry for an IP address.
pub const ThreatIntelEntry = struct {
    ip: u32,
    severity: ThreatSeverity,
    category: ThreatCategory,
    /// Confidence in the intelligence (0-100).
    confidence: u8,
    /// Source feed name (static string).
    source: []const u8,
    /// First seen timestamp (epoch ms).
    first_seen_ms: i64,
    /// Last seen timestamp (epoch ms).
    last_seen_ms: i64,
    /// Number of times this IP has been reported across feeds.
    report_count: u32,
};

// ============================================================
// Threat Intel Match (result of enriching an event)
// ============================================================

/// Result of looking up threat intel for an event.
/// Contains matches for both source and destination IPs.
pub const ThreatIntelMatch = struct {
    /// Match on source IP (null if no match).
    src_match: ?ThreatIntelEntry,
    /// Match on destination IP (null if no match).
    dst_match: ?ThreatIntelEntry,
    /// The event_id that was enriched.
    event_id: u64,

    /// Returns true if either source or destination matched.
    pub fn hasMatch(self: ThreatIntelMatch) bool {
        return self.src_match != null or self.dst_match != null;
    }

    /// Returns the highest severity match (src or dst).
    /// Returns .none if no match.
    pub fn maxSeverity(self: ThreatIntelMatch) ThreatSeverity {
        const src_sev = if (self.src_match) |e| e.severity else .none;
        const dst_sev = if (self.dst_match) |e| e.severity else .none;
        return if (src_sev.rank() >= dst_sev.rank()) src_sev else dst_sev;
    }

    /// Returns true if any match is high or critical severity.
    pub fn isHighSeverity(self: ThreatIntelMatch) bool {
        return self.maxSeverity().rank() >= ThreatSeverity.high.rank();
    }
};

// ============================================================
// Threat Intel Database
// ============================================================

const ThreatMap = std.HashMap(u32, ThreatIntelEntry, std.hash_map.AutoContext(u32), std.hash_map.default_max_load_percentage);

pub const ThreatIntelDB = struct {
    allocator: std.mem.Allocator,
    map: ThreatMap,
    /// Total lookups performed (lifetime).
    total_lookups: u64,
    /// Total hits (IP found in database).
    total_hits: u64,
    /// Total misses (IP not found).
    total_misses: u64,

    pub fn init(allocator: std.mem.Allocator) ThreatIntelDB {
        return .{
            .allocator = allocator,
            .map = ThreatMap.init(allocator),
            .total_lookups = 0,
            .total_hits = 0,
            .total_misses = 0,
        };
    }

    pub fn deinit(self: *ThreatIntelDB) void {
        self.map.deinit();
    }

    /// Add a threat intel entry to the database.
    /// If the IP already exists, updates with the higher-severity entry.
    pub fn addEntry(self: *ThreatIntelDB, entry: ThreatIntelEntry) void {
        if (self.map.get(entry.ip)) |existing| {
            // Keep the higher-severity entry
            if (entry.severity.rank() > existing.severity.rank()) {
                self.map.put(entry.ip, entry) catch {};
            } else if (entry.severity.rank() == existing.severity.rank()) {
                // Same severity, merge report counts
                var merged = entry;
                merged.report_count = existing.report_count + entry.report_count;
                self.map.put(entry.ip, merged) catch {};
            }
            // Else: keep existing (lower severity entry discarded)
        } else {
            self.map.put(entry.ip, entry) catch {};
        }
    }

    /// Look up an IP in the threat intel database.
    /// Returns null if not found.
    pub fn lookupIp(self: *ThreatIntelDB, ip: u32) ?ThreatIntelEntry {
        self.total_lookups += 1;
        if (self.map.get(ip)) |entry| {
            self.total_hits += 1;
            return entry;
        }
        self.total_misses += 1;
        return null;
    }

    /// Enrich an event with threat intel context.
    /// Looks up both source_ip and dest_ip.
    pub fn enrichEvent(self: *ThreatIntelDB, event: canonical.CanonicalEvent) ThreatIntelMatch {
        const src_match = if (event.source_ip != 0) self.lookupIp(event.source_ip) else null;
        const dst_match = if (event.dest_ip != 0) self.lookupIp(event.dest_ip) else null;

        return .{
            .src_match = src_match,
            .dst_match = dst_match,
            .event_id = event.event_id,
        };
    }

    /// Current number of entries in the database.
    pub fn count(self: *const ThreatIntelDB) usize {
        return self.map.count();
    }

    /// Load built-in threat intel entries (Phase 10 minimal set).
    /// These are well-known bad IPs for testing. Production: load from file.
    pub fn loadBuiltinEntries(self: *ThreatIntelDB) void {
        // Test entries - use documentation ranges to avoid real IPs
        // 10.0.0.0/8 = private (test only)
        // 192.0.2.0/24 = TEST-NET-1 (documentation)
        // 198.51.100.0/24 = TEST-NET-2 (documentation)
        // 203.0.113.0/24 = TEST-NET-3 (documentation)

        const entries = [_]ThreatIntelEntry{
            .{
                .ip = 0x0A0000A1, // 10.0.0.161 (test: malware C2)
                .severity = .critical,
                .category = .malware_c2,
                .confidence = 95,
                .source = "builtin-test",
                .first_seen_ms = 1700000000000,
                .last_seen_ms = 1700000000000,
                .report_count = 5,
            },
            .{
                .ip = 0x0A0000B2, // 10.0.0.178 (test: botnet)
                .severity = .high,
                .category = .botnet,
                .confidence = 85,
                .source = "builtin-test",
                .first_seen_ms = 1700000000000,
                .last_seen_ms = 1700000000000,
                .report_count = 3,
            },
            .{
                .ip = 0x0A0000C3, // 10.0.0.195 (test: scanner)
                .severity = .medium,
                .category = .scanner,
                .confidence = 70,
                .source = "builtin-test",
                .first_seen_ms = 1700000000000,
                .last_seen_ms = 1700000000000,
                .report_count = 2,
            },
            .{
                .ip = 0x0A0000D4, // 10.0.0.212 (test: brute force)
                .severity = .high,
                .category = .brute_force,
                .confidence = 80,
                .source = "builtin-test",
                .first_seen_ms = 1700000000000,
                .last_seen_ms = 1700000000000,
                .report_count = 4,
            },
            .{
                .ip = 0x0A0000E5, // 10.0.0.229 (test: phishing)
                .severity = .medium,
                .category = .phishing,
                .confidence = 65,
                .source = "builtin-test",
                .first_seen_ms = 1700000000000,
                .last_seen_ms = 1700000000000,
                .report_count = 1,
            },
        };

        for (entries) |entry| {
            self.addEntry(entry);
        }
    }
};

// ============================================================
// Tests (all use local DB instances - parallelism-safe)
// ============================================================

test "ThreatSeverity.toString returns readable names" {
    try std.testing.expect(std.mem.eql(u8, ThreatSeverity.none.toString(), "NONE"));
    try std.testing.expect(std.mem.eql(u8, ThreatSeverity.low.toString(), "LOW"));
    try std.testing.expect(std.mem.eql(u8, ThreatSeverity.medium.toString(), "MEDIUM"));
    try std.testing.expect(std.mem.eql(u8, ThreatSeverity.high.toString(), "HIGH"));
    try std.testing.expect(std.mem.eql(u8, ThreatSeverity.critical.toString(), "CRITICAL"));
}

test "ThreatSeverity.rank ordering" {
    try std.testing.expect(ThreatSeverity.none.rank() < ThreatSeverity.low.rank());
    try std.testing.expect(ThreatSeverity.low.rank() < ThreatSeverity.medium.rank());
    try std.testing.expect(ThreatSeverity.medium.rank() < ThreatSeverity.high.rank());
    try std.testing.expect(ThreatSeverity.high.rank() < ThreatSeverity.critical.rank());
}

test "ThreatCategory.toString returns readable names" {
    try std.testing.expect(std.mem.eql(u8, ThreatCategory.unknown.toString(), "UNKNOWN"));
    try std.testing.expect(std.mem.eql(u8, ThreatCategory.malware_c2.toString(), "MALWARE_C2"));
    try std.testing.expect(std.mem.eql(u8, ThreatCategory.botnet.toString(), "BOTNET"));
    try std.testing.expect(std.mem.eql(u8, ThreatCategory.scanner.toString(), "SCANNER"));
    try std.testing.expect(std.mem.eql(u8, ThreatCategory.brute_force.toString(), "BRUTE_FORCE"));
    try std.testing.expect(std.mem.eql(u8, ThreatCategory.phishing.toString(), "PHISHING"));
    try std.testing.expect(std.mem.eql(u8, ThreatCategory.apt.toString(), "APT"));
}

test "ThreatIntelDB init has zero entries and stats" {
    var db = ThreatIntelDB.init(std.testing.allocator);
    defer db.deinit();

    try std.testing.expect(db.count() == 0);
    try std.testing.expect(db.total_lookups == 0);
    try std.testing.expect(db.total_hits == 0);
    try std.testing.expect(db.total_misses == 0);
}

test "ThreatIntelDB addEntry and lookupIp" {
    var db = ThreatIntelDB.init(std.testing.allocator);
    defer db.deinit();

    const entry = ThreatIntelEntry{
        .ip = 0xC0A80001,
        .severity = .high,
        .category = .malware_c2,
        .confidence = 90,
        .source = "test-feed",
        .first_seen_ms = 1700000000000,
        .last_seen_ms = 1700000000000,
        .report_count = 1,
    };
    db.addEntry(entry);

    try std.testing.expect(db.count() == 1);

    const found = db.lookupIp(0xC0A80001);
    try std.testing.expect(found != null);
    try std.testing.expect(found.?.severity == .high);
    try std.testing.expect(found.?.category == .malware_c2);
    try std.testing.expect(found.?.confidence == 90);
    try std.testing.expect(db.total_hits == 1);
}

test "ThreatIntelDB lookupIp returns null for unknown IP" {
    var db = ThreatIntelDB.init(std.testing.allocator);
    defer db.deinit();

    const result = db.lookupIp(0x0A000001);
    try std.testing.expect(result == null);
    try std.testing.expect(db.total_misses == 1);
    try std.testing.expect(db.total_lookups == 1);
}

test "ThreatIntelDB addEntry keeps higher severity on conflict" {
    var db = ThreatIntelDB.init(std.testing.allocator);
    defer db.deinit();

    const low_entry = ThreatIntelEntry{
        .ip = 0x0A000001,
        .severity = .low,
        .category = .scanner,
        .confidence = 50,
        .source = "feed1",
        .first_seen_ms = 1000,
        .last_seen_ms = 2000,
        .report_count = 1,
    };
    db.addEntry(low_entry);

    const high_entry = ThreatIntelEntry{
        .ip = 0x0A000001, // same IP
        .severity = .critical,
        .category = .malware_c2,
        .confidence = 95,
        .source = "feed2",
        .first_seen_ms = 3000,
        .last_seen_ms = 4000,
        .report_count = 2,
    };
    db.addEntry(high_entry);

    // Should keep the higher severity (critical) entry
    try std.testing.expect(db.count() == 1);
    const found = db.lookupIp(0x0A000001);
    try std.testing.expect(found != null);
    try std.testing.expect(found.?.severity == .critical);
    try std.testing.expect(found.?.category == .malware_c2);
    try std.testing.expect(found.?.confidence == 95);
}

test "ThreatIntelDB addEntry merges report_count on same severity" {
    var db = ThreatIntelDB.init(std.testing.allocator);
    defer db.deinit();

    const entry1 = ThreatIntelEntry{
        .ip = 0x0A000001,
        .severity = .high,
        .category = .botnet,
        .confidence = 80,
        .source = "feed1",
        .first_seen_ms = 1000,
        .last_seen_ms = 2000,
        .report_count = 3,
    };
    db.addEntry(entry1);

    const entry2 = ThreatIntelEntry{
        .ip = 0x0A000001, // same IP, same severity
        .severity = .high,
        .category = .botnet,
        .confidence = 85,
        .source = "feed2",
        .first_seen_ms = 3000,
        .last_seen_ms = 4000,
        .report_count = 5,
    };
    db.addEntry(entry2);

    // Should merge report counts (3 + 5 = 8)
    const found = db.lookupIp(0x0A000001);
    try std.testing.expect(found != null);
    try std.testing.expect(found.?.report_count == 8);
    try std.testing.expect(found.?.severity == .high);
}

test "ThreatIntelDB loadBuiltinEntries adds 5 test entries" {
    var db = ThreatIntelDB.init(std.testing.allocator);
    defer db.deinit();

    db.loadBuiltinEntries();

    try std.testing.expect(db.count() == 5);

    // Verify known entries are present
    const c2 = db.lookupIp(0x0A0000A1); // 10.0.0.161
    try std.testing.expect(c2 != null);
    try std.testing.expect(c2.?.severity == .critical);
    try std.testing.expect(c2.?.category == .malware_c2);

    const scanner = db.lookupIp(0x0A0000C3); // 10.0.0.195
    try std.testing.expect(scanner != null);
    try std.testing.expect(scanner.?.category == .scanner);
}

test "ThreatIntelDB enrichEvent with no matches" {
    var db = ThreatIntelDB.init(std.testing.allocator);
    defer db.deinit();
    db.loadBuiltinEntries();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001; // not in database
    event.dest_ip = 0x0A000002; // not in database

    const match = db.enrichEvent(event);
    try std.testing.expect(!match.hasMatch());
    try std.testing.expect(match.src_match == null);
    try std.testing.expect(match.dst_match == null);
    try std.testing.expect(match.maxSeverity() == .none);
    try std.testing.expect(!match.isHighSeverity());
}

test "ThreatIntelDB enrichEvent matches source IP" {
    var db = ThreatIntelDB.init(std.testing.allocator);
    defer db.deinit();
    db.loadBuiltinEntries();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A0000A1; // 10.0.0.161 - known malware C2
    event.dest_ip = 0x0A000002; // not in database

    const match = db.enrichEvent(event);
    try std.testing.expect(match.hasMatch());
    try std.testing.expect(match.src_match != null);
    try std.testing.expect(match.dst_match == null);
    try std.testing.expect(match.src_match.?.severity == .critical);
    try std.testing.expect(match.src_match.?.category == .malware_c2);
    try std.testing.expect(match.maxSeverity() == .critical);
    try std.testing.expect(match.isHighSeverity());
}

test "ThreatIntelDB enrichEvent matches destination IP" {
    var db = ThreatIntelDB.init(std.testing.allocator);
    defer db.deinit();
    db.loadBuiltinEntries();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001; // not in database
    event.dest_ip = 0x0A0000B2; // 10.0.0.178 - known botnet

    const match = db.enrichEvent(event);
    try std.testing.expect(match.hasMatch());
    try std.testing.expect(match.src_match == null);
    try std.testing.expect(match.dst_match != null);
    try std.testing.expect(match.dst_match.?.severity == .high);
    try std.testing.expect(match.dst_match.?.category == .botnet);
    try std.testing.expect(match.maxSeverity() == .high);
    try std.testing.expect(match.isHighSeverity());
}

test "ThreatIntelDB enrichEvent matches both src and dst" {
    var db = ThreatIntelDB.init(std.testing.allocator);
    defer db.deinit();
    db.loadBuiltinEntries();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A0000C3; // scanner (medium)
    event.dest_ip = 0x0A0000A1; // malware_c2 (critical)

    const match = db.enrichEvent(event);
    try std.testing.expect(match.hasMatch());
    try std.testing.expect(match.src_match != null);
    try std.testing.expect(match.dst_match != null);
    // Max severity should be critical (from dst)
    try std.testing.expect(match.maxSeverity() == .critical);
    try std.testing.expect(match.isHighSeverity());
}

test "ThreatIntelDB enrichEvent with zero IPs returns no match" {
    var db = ThreatIntelDB.init(std.testing.allocator);
    defer db.deinit();
    db.loadBuiltinEntries();

    var event = canonical.create(.pipe_sensor);
    event.source_ip = 0;
    event.dest_ip = 0;
    event.is_pipe = 1;

    const match = db.enrichEvent(event);
    try std.testing.expect(!match.hasMatch());
}

test "ThreatIntelDB stats accumulate correctly" {
    var db = ThreatIntelDB.init(std.testing.allocator);
    defer db.deinit();
    db.loadBuiltinEntries();

    // 3 lookups: 2 hits, 1 miss
    _ = db.lookupIp(0x0A0000A1); // hit
    _ = db.lookupIp(0x0A0000B2); // hit
    _ = db.lookupIp(0x0A000099); // miss

    try std.testing.expect(db.total_lookups == 3);
    try std.testing.expect(db.total_hits == 2);
    try std.testing.expect(db.total_misses == 1);
}

test "ThreatIntelMatch.hasMatch and maxSeverity" {
    const match_both = ThreatIntelMatch{
        .src_match = .{
            .ip = 0x0A000001,
            .severity = .medium,
            .category = .scanner,
            .confidence = 70,
            .source = "test",
            .first_seen_ms = 1000,
            .last_seen_ms = 2000,
            .report_count = 1,
        },
        .dst_match = .{
            .ip = 0x0A000002,
            .severity = .critical,
            .category = .malware_c2,
            .confidence = 95,
            .source = "test",
            .first_seen_ms = 1000,
            .last_seen_ms = 2000,
            .report_count = 1,
        },
        .event_id = 42,
    };
    try std.testing.expect(match_both.hasMatch());
    try std.testing.expect(match_both.maxSeverity() == .critical);
    try std.testing.expect(match_both.isHighSeverity());

    const match_none = ThreatIntelMatch{
        .src_match = null,
        .dst_match = null,
        .event_id = 42,
    };
    try std.testing.expect(!match_none.hasMatch());
    try std.testing.expect(match_none.maxSeverity() == .none);
    try std.testing.expect(!match_none.isHighSeverity());
}
