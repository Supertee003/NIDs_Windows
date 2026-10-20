//! Rule loading and hot-reload for the AEGIS detection engine.
//!
//! Extracted from main.zig. Owns the deterministic rule-id hashing and
//! the thread-safe Rules.json reload (rebuild + atomic AC pointer swap).

const std = @import("std");
const diag = @import("../core/diagnostics.zig");
const runtime_paths = @import("../core/runtime_paths.zig");
const sig = @import("../detection/signature_engine.zig");
const l4 = @import("l4_matcher.zig");
const state = @import("runtime_state.zig");

/// Hash a rule_id string (e.g. "R0056") to a deterministic u32.
/// Used to map JSON rule_id strings to the AhoCorasick numeric rule_id space.
pub fn hashRuleId(rule_id: []const u8) u32 {
    var h: u32 = 0x811c9dc5; // FNV-1a offset basis
    for (rule_id) |b| {
        h ^= b;
        h *%= 0x01000193; // FNV-1a prime
    }
    return h;
}

test "hashRuleId matches the cross-language golden table" {
    // Shared golden values, also asserted by nose/signature_classifier_test.go (Go
    // network classifier) and tests/security/test_detection_contract_pin.py.
    // The Go classifier and this detector must map one rule_id to the same
    // numeric rule id, or a detection attributed by one tier would name a
    // different rule in the other.
    const golden = [_]struct { id: []const u8, hash: u32 }{
        .{ .id = "R0056", .hash = 2107512682 },
        .{ .id = "R0088", .hash = 4254503461 },
        .{ .id = "R0089", .hash = 4237725842 },
        .{ .id = "R1001", .hash = 3813986375 },
        .{ .id = "R1002", .hash = 3830763994 },
        .{ .id = "R1003", .hash = 3847541613 },
        .{ .id = "R1004", .hash = 3730098280 },
        .{ .id = "R1005", .hash = 3746875899 },
        .{ .id = "R2001", .hash = 2452150132 },
        .{ .id = "R2002", .hash = 2502482989 },
        .{ .id = "R2003", .hash = 2485705370 },
        .{ .id = "R2004", .hash = 2401817275 },
        .{ .id = "R2005", .hash = 2385039656 },
        .{ .id = "R3001", .hash = 1836645033 },
        .{ .id = "R3002", .hash = 1786312176 },
        .{ .id = "R3003", .hash = 1803089795 },
        .{ .id = "R3004", .hash = 1886977890 },
        .{ .id = "R3005", .hash = 1903755509 },
        .{ .id = "R9002", .hash = 1812566754 },
        .{ .id = "R9006", .hash = 1745456278 },
        .{ .id = "R9007", .hash = 1762233897 },
        .{ .id = "R9059", .hash = 4009890390 },
        .{ .id = "R9064", .hash = 4194591294 },
    };
    for (golden) |entry| {
        try std.testing.expectEqual(entry.hash, hashRuleId(entry.id));
    }
}

/// BE-DIS-089: honor config/disabled_rules.json in the daemon engine.
///
/// The CLI (`tools/aegisctl.py policy list`) has always shown DISABLED
/// from that file, but the engine never read it — a rule shown DISABLED
/// still fired. Both load paths (startup + rules.reload) now skip
/// disabled IDs. Fail direction is deliberate: a missing/unreadable/
/// malformed disabled file means NONE disabled (engine keeps firing),
/// never a silent zero-rule engine. Malformed warns loudly.
fn loadDisabledMap() std.StringHashMap(void) {
    var map = std.StringHashMap(void).init(std.heap.page_allocator);
    const runtime_root = runtime_paths.resolveRoot(std.heap.page_allocator) catch |err| {
        diag.warn("disabled_rules: cannot resolve runtime root: {} — none disabled", .{err});
        return map;
    };
    defer std.heap.page_allocator.free(runtime_root);
    const disabled_path = runtime_paths.configPath(std.heap.page_allocator, runtime_root, "disabled_rules.json") catch |err| {
        diag.warn("disabled_rules: cannot build path: {} — none disabled", .{err});
        return map;
    };
    defer std.heap.page_allocator.free(disabled_path);
    const file = std.fs.openFileAbsolute(disabled_path, .{}) catch {
        return map; // absent file = none disabled (normal case)
    };
    defer file.close();
    const bytes = file.readToEndAlloc(std.heap.page_allocator, 64 * 1024) catch |err| {
        diag.warn("disabled_rules: cannot read {s}: {} — none disabled", .{ disabled_path, err });
        return map;
    };
    defer std.heap.page_allocator.free(bytes);
    var parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, bytes, .{}) catch |err| {
        diag.warn("disabled_rules: {s} is not valid JSON: {} — none disabled", .{ disabled_path, err });
        return map;
    };
    defer parsed.deinit();
    if (parsed.value != .object) {
        diag.warn("disabled_rules: {s}: root must be an object — none disabled", .{disabled_path});
        return map;
    }
    const list = parsed.value.object.get("disabled_rules") orelse return map;
    if (list != .array) {
        diag.warn("disabled_rules: {s}: disabled_rules is not an array — none disabled", .{disabled_path});
        return map;
    }
    for (list.array.items) |v| {
        if (v != .string or v.string.len == 0) continue;
        map.put(v.string, {}) catch continue;
    }
    return map;
}

/// Pure membership check over parsed JSON bytes (no filesystem).
/// Shared by the daemon filter and the unit test below.
pub fn disabledListContains(disabled_bytes: []const u8, rule_id: []const u8) bool {
    var parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, disabled_bytes, .{}) catch return false;
    defer parsed.deinit();
    if (parsed.value != .object) return false;
    const list = parsed.value.object.get("disabled_rules") orelse return false;
    if (list != .array) return false;
    for (list.array.items) |v| {
        if (v != .string) continue;
        if (std.mem.eql(u8, v.string, rule_id)) return true;
    }
    return false;
}

// ============================================================
// BE-DRIFT-098: named skip accounting (no more silent drops).
// ============================================================
//
// Every catalog entry ends in exactly one bucket: loaded, or skipped
// with a reason AND (when it names one) its rule_id. Both load paths
// share classifyRule so startup and reload can never disagree about
// WHY a rule is absent. The report carries a bounded ID list (first
// 16, truncation flagged) so the control response stays small while
// proving completeness: loaded + all skipped == catalog entries.
pub const MAX_SKIPPED_IDS: usize = 16;
pub const MAX_SKIPPED_ID_LEN: usize = 31;

pub const ReloadReport = struct {
    loaded: u32 = 0,
    skipped_no_pattern: u32 = 0,
    skipped_disabled: u32 = 0,
    skipped_malformed: u32 = 0,
    skipped_add_failed: u32 = 0,
    skipped_ids: [MAX_SKIPPED_IDS][MAX_SKIPPED_ID_LEN + 1]u8 = [_][MAX_SKIPPED_ID_LEN + 1]u8{[_]u8{0} ** (MAX_SKIPPED_ID_LEN + 1)} ** MAX_SKIPPED_IDS,
    skipped_id_lens: [MAX_SKIPPED_IDS]u8 = [_]u8{0} ** MAX_SKIPPED_IDS,
    skipped_id_count: u8 = 0,
    skipped_truncated: bool = false,

    pub fn totalSkipped(self: *const ReloadReport) u32 {
        return self.skipped_no_pattern + self.skipped_disabled + self.skipped_malformed + self.skipped_add_failed;
    }

    pub fn recordSkip(self: *ReloadReport, reason: SkipReason, id: ?[]const u8) void {
        switch (reason) {
            .no_pattern => self.skipped_no_pattern += 1,
            .disabled => self.skipped_disabled += 1,
            .malformed => self.skipped_malformed += 1,
            .add_failed => self.skipped_add_failed += 1,
        }
        const name = id orelse return;
        if (name.len == 0) return;
        if (self.skipped_id_count >= MAX_SKIPPED_IDS) {
            self.skipped_truncated = true;
            return;
        }
        const n: usize = @min(name.len, MAX_SKIPPED_ID_LEN);
        @memcpy(self.skipped_ids[self.skipped_id_count][0..n], name[0..n]);
        self.skipped_id_lens[self.skipped_id_count] = @intCast(n);
        self.skipped_id_count += 1;
        if (name.len > MAX_SKIPPED_ID_LEN) self.skipped_truncated = true;
    }

    pub fn skippedId(self: *const ReloadReport, i: usize) []const u8 {
        return self.skipped_ids[i][0..self.skipped_id_lens[i]];
    }
};

pub const SkipReason = enum { no_pattern, disabled, malformed, add_failed };

pub const ClassifiedRule = struct {
    verdict: enum { load, skip },
    reason: SkipReason,
    id: ?[]const u8,
    pattern: ?[]const u8,
};

/// One classifier for both load paths. A rule loads ONLY with a
/// non-empty string rule_id, no disabled hit, and a non-empty string
/// match_pattern. Everything else names its reason.
pub fn classifyRule(
    rule_val: std.json.Value,
    disabled: *const std.StringHashMap(void),
) ClassifiedRule {
    if (rule_val != .object) return .{ .verdict = .skip, .reason = .malformed, .id = null, .pattern = null };
    const id_val = rule_val.object.get("rule_id") orelse return .{ .verdict = .skip, .reason = .malformed, .id = null, .pattern = null };
    if (id_val != .string or id_val.string.len == 0) return .{ .verdict = .skip, .reason = .malformed, .id = null, .pattern = null };
    const id = id_val.string;
    if (disabled.contains(id)) return .{ .verdict = .skip, .reason = .disabled, .id = id, .pattern = null };
    const pat_val = rule_val.object.get("match_pattern") orelse return .{ .verdict = .skip, .reason = .no_pattern, .id = id, .pattern = null };
    if (pat_val != .string or pat_val.string.len == 0) return .{ .verdict = .skip, .reason = .no_pattern, .id = id, .pattern = null };
    return .{ .verdict = .load, .reason = .malformed, .id = id, .pattern = pat_val.string };
}

/// JSON-escape one string into a writer (rule IDs are operator-controlled;
/// a quote in an ID must not break the control response).
pub fn writeJsonString(writer: anytype, s: []const u8) void {
    writer.writeByte('"') catch return;
    for (s) |c| {
        switch (c) {
            '"' => writer.writeAll("\\\"") catch return,
            '\\' => writer.writeAll("\\\\") catch return,
            '\n' => writer.writeAll("\\n") catch return,
            '\r' => writer.writeAll("\\r") catch return,
            '\t' => writer.writeAll("\\t") catch return,
            0...8, 11, 12, 14...31 => writer.print("\\u{x:0>4}", .{c}) catch return,
            else => writer.writeByte(c) catch return,
        }
    }
    writer.writeByte('"') catch return;
}

/// Reload Rules.json into a fresh Aho-Corasick automaton.
/// Called from the control pipe thread on `rules.reload`.
/// Thread-safe: rebuilds a new AC and swaps the global pointer atomically.
/// Returns the full report (loaded + named skips) for the control response.
pub fn reloadRules() ReloadReport {
    // Heap-allocate the new AC so the pointer survives after this function returns
    const heap_ac = std.heap.page_allocator.create(sig.AhoCorasick) catch |err| {
        diag.err("reload: failed to allocate AhoCorasick: {}", .{err});
        return .{};
    };
    heap_ac.* = sig.AhoCorasick.init(std.heap.page_allocator, 100_000) catch |err| {
        diag.err("reload: failed to init AhoCorasick: {}", .{err});
        std.heap.page_allocator.destroy(heap_ac);
        return .{};
    };

    var report = ReloadReport{};
    var l4_rules: [l4.MAX_RULES]l4.Rule = l4.empty_rules;
    var l4_count: usize = 0;
    var disabled_map = loadDisabledMap();
    defer disabled_map.deinit();
    blk: {
        const runtime_root = runtime_paths.resolveRoot(std.heap.page_allocator) catch |err| {
            diag.warn("reload: cannot resolve runtime root: {}", .{err});
            heap_ac.deinit();
            std.heap.page_allocator.destroy(heap_ac);
            break :blk;
        };
        defer std.heap.page_allocator.free(runtime_root);
        const rules_path = runtime_paths.configPath(std.heap.page_allocator, runtime_root, "Rules.json") catch |err| {
            diag.warn("reload: cannot build Rules.json path: {}", .{err});
            heap_ac.deinit();
            std.heap.page_allocator.destroy(heap_ac);
            break :blk;
        };
        defer std.heap.page_allocator.free(rules_path);
        const rules_file = std.fs.openFileAbsolute(rules_path, .{}) catch |err| {
            diag.warn("reload: cannot open {s}: {}", .{ rules_path, err });
            heap_ac.deinit();
            std.heap.page_allocator.destroy(heap_ac);
            break :blk;
        };
        defer rules_file.close();
        const rules_bytes = rules_file.readToEndAlloc(std.heap.page_allocator, 4 * 1024 * 1024) catch |err| {
            diag.warn("reload: cannot read {s}: {}", .{ rules_path, err });
            heap_ac.deinit();
            std.heap.page_allocator.destroy(heap_ac);
            break :blk;
        };
        defer std.heap.page_allocator.free(rules_bytes);

        var rules_parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, rules_bytes, .{}) catch |err| {
            diag.warn("reload: cannot parse {s}: {}", .{ rules_path, err });
            heap_ac.deinit();
            std.heap.page_allocator.destroy(heap_ac);
            break :blk;
        };
        defer rules_parsed.deinit();

        const root = rules_parsed.value;
        if (root != .object) {
            diag.warn("reload: {s}: expected object at root", .{rules_path});
            heap_ac.deinit();
            std.heap.page_allocator.destroy(heap_ac);
            break :blk;
        }
        const nids_rules = root.object.get("nids_rules") orelse {
            diag.warn("reload: {s}: missing nids_rules key", .{rules_path});
            heap_ac.deinit();
            std.heap.page_allocator.destroy(heap_ac);
            break :blk;
        };
        if (nids_rules != .array) {
            diag.warn("reload: {s}: nids_rules is not an array", .{rules_path});
            heap_ac.deinit();
            std.heap.page_allocator.destroy(heap_ac);
            break :blk;
        }

        for (nids_rules.array.items) |rule_val| {
            const c = classifyRule(rule_val, &disabled_map);
            if (c.verdict != .load) {
                report.recordSkip(c.reason, c.id);
                continue;
            }
            if (l4.isL4(rule_val)) {
                if (l4.parse(rule_val, c.pattern.?, hashRuleId(c.id.?))) |l4_rule| {
                    if (l4_count < l4.MAX_RULES) {
                        l4_rules[l4_count] = l4_rule;
                        l4_count += 1;
                        report.loaded += 1;
                    } else {
                        report.recordSkip(.malformed, c.id);
                    }
                } else {
                    report.recordSkip(.malformed, c.id);
                }
                continue;
            }
            const rule_id = hashRuleId(c.id.?);
            heap_ac.addPattern(rule_id, c.pattern.?) catch |err| {
                diag.warn("reload: failed to add pattern for {s}: {}", .{ c.id.?, err });
                report.recordSkip(.add_failed, c.id);
                continue;
            };
            report.loaded += 1;
        }

        heap_ac.build() catch |err| {
            diag.err("reload: failed to build Aho-Corasick: {}", .{err});
            heap_ac.deinit();
            std.heap.page_allocator.destroy(heap_ac);
            break :blk;
        };
    }

    if (report.loaded > 0) {
        // Swap: take old AC, install new heap-allocated one
        state.g_ac_mutex.lock();
        const old_ac_ptr = state.g_active_ac;
        state.g_active_ac = heap_ac;
        state.g_l4_rules = l4_rules;
        state.g_l4_rule_count = l4_count;
        state.g_l4_rate_mutex.lock();
        state.g_l4_rate.reset();
        state.g_l4_rate_mutex.unlock();
        state.g_rules_loaded.store(report.loaded, .monotonic);
        state.g_ac_mutex.unlock();

        // Do not destroy the old automaton here. The pipeline may have taken
        // a reference immediately before the swap and can still be reading it
        // after the mutex is released. Immediate reclamation made
        // rules.reload intermittently close the control pipe with an empty
        // response. Retain retired automata for the daemon lifetime; reloads
        // are infrequent and this fail-safe policy prevents use-after-free.
        _ = old_ac_ptr;
        if (report.totalSkipped() > 0) {
            diag.info("reload: loaded {} rules (swap complete), skipped {} (no_pattern={} disabled={} malformed={} add_failed={})", .{
                report.loaded,             report.totalSkipped(),
                report.skipped_no_pattern, report.skipped_disabled,
                report.skipped_malformed,  report.skipped_add_failed,
            });
        } else {
            diag.info("reload: loaded {} rules (swap complete)", .{report.loaded});
        }
    } else {
        heap_ac.deinit();
        std.heap.page_allocator.destroy(heap_ac);
        diag.warn("reload: 0 rules loaded, keeping old ruleset", .{});
    }

    return report;
}

/// Parse the nids_rules array from Rules.json bytes into an existing AC.
/// Shared by initial startup load and reload; returns the loaded count.
///
/// NOTE (Project 2 observe-only contract): only rule_id + match_pattern are
/// loaded. A rule's `action` (Drop/Block/Alert) is an advisory display label;
/// no detection tier branches on it. Enforcement orders come exclusively from
/// configs/policies.json through the Rust PEP receipt path. See AC5 in
/// tests/security/test_detection_contract_pin.py, which fails loudly if any
/// tier starts reading rule actions.
pub fn loadRulesInto(ac: *sig.AhoCorasick, bytes: []const u8, rules_path: []const u8) ReloadReport {
    var report = ReloadReport{};
    var l4_rules: [l4.MAX_RULES]l4.Rule = l4.empty_rules;
    var l4_count: usize = 0;
    var ac_ready = false;
    var disabled_map = loadDisabledMap();
    defer disabled_map.deinit();
    blk: {
        var rules_parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, bytes, .{}) catch |err| {
            diag.warn("cannot parse {s}: {}", .{ rules_path, err });
            break :blk;
        };
        defer rules_parsed.deinit();

        const root = rules_parsed.value;
        if (root != .object) {
            diag.warn("{s}: expected object at root", .{rules_path});
            break :blk;
        }
        const nids_rules = root.object.get("nids_rules") orelse {
            diag.warn("{s}: missing nids_rules key", .{rules_path});
            break :blk;
        };
        if (nids_rules != .array) {
            diag.warn("{s}: nids_rules is not an array", .{rules_path});
            break :blk;
        }

        for (nids_rules.array.items) |rule_val| {
            const c = classifyRule(rule_val, &disabled_map);
            if (c.verdict != .load) {
                report.recordSkip(c.reason, c.id);
                continue;
            }
            if (l4.isL4(rule_val)) {
                if (l4.parse(rule_val, c.pattern.?, hashRuleId(c.id.?))) |l4_rule| {
                    if (l4_count < l4.MAX_RULES) {
                        l4_rules[l4_count] = l4_rule;
                        l4_count += 1;
                        report.loaded += 1;
                    } else {
                        report.recordSkip(.malformed, c.id);
                    }
                } else {
                    report.recordSkip(.malformed, c.id);
                }
                continue;
            }
            const rule_id = hashRuleId(c.id.?);
            ac.addPattern(rule_id, c.pattern.?) catch |err| {
                diag.warn("failed to add pattern for {s}: {}", .{ c.id.?, err });
                report.recordSkip(.add_failed, c.id);
                continue;
            };
            report.loaded += 1;
        }

        ac.build() catch |err| {
            diag.err("failed to build Aho-Corasick automaton: {}", .{err});
            break :blk;
        };
        ac_ready = true;
    }
    if (ac_ready) {
        // Publish the L4 half of the same parsed catalog only after the AC
        // build succeeded. Startup is single-threaded, but taking the same
        // mutex keeps the invariant identical to the reload swap.
        state.g_ac_mutex.lock();
        state.g_l4_rules = l4_rules;
        state.g_l4_rule_count = l4_count;
        state.g_l4_rate_mutex.lock();
        state.g_l4_rate.reset();
        state.g_l4_rate_mutex.unlock();
        state.g_ac_mutex.unlock();
    }
    if (report.totalSkipped() > 0) {
        diag.info("startup: loaded {} rules, skipped {} (no_pattern={} disabled={} malformed={} add_failed={})", .{
            report.loaded,             report.totalSkipped(),
            report.skipped_no_pattern, report.skipped_disabled,
            report.skipped_malformed,  report.skipped_add_failed,
        });
    }
    return report;
}

test "BE-DIS-089: disabledListContains honors the disabled_rules shape" {
    // Positive: listed IDs match exactly, others do not.
    try std.testing.expect(disabledListContains("{\"disabled_rules\":[\"R0001\",\"R0002\"]}", "R0001"));
    try std.testing.expect(!disabledListContains("{\"disabled_rules\":[\"R0001\",\"R0002\"]}", "R0003"));
    // Negative controls: malformed shapes never disable (fail-closed =
    // engine keeps firing, never a silent zero-rule engine).
    try std.testing.expect(!disabledListContains("not json", "R0001"));
    try std.testing.expect(!disabledListContains("{\"disabled_rules\":\"R0001\"}", "R0001"));
    try std.testing.expect(!disabledListContains("{\"other\":[]}", "R0001"));
    try std.testing.expect(!disabledListContains("{\"disabled_rules\":[]}", "R0001"));
}

test "BE-DIS-089: engine skip uses exact-ID map membership (mirrors the load loop)" {
    // The load/reload loops call disabled_map.contains(rule_id_str) and
    // `continue` before addPattern. This pins that semantic: an exact
    // listed ID is skipped, a prefix/suffix lookalike is not.
    var map = std.StringHashMap(void).init(std.testing.allocator);
    defer map.deinit();
    try map.put("R0001", {});
    try std.testing.expect(map.contains("R0001"));
    try std.testing.expect(!map.contains("R00010"));
    try std.testing.expect(!map.contains("R000"));
    try std.testing.expect(!map.contains("r0001"));
}

test "BE-DRIFT-098: classifyRule names every skip reason" {
    var empty = std.StringHashMap(void).init(std.testing.allocator);
    defer empty.deinit();
    var disabled = std.StringHashMap(void).init(std.testing.allocator);
    defer disabled.deinit();
    try disabled.put("R0009", {});

    const doc =
        \\{"nids_rules": [
        \\ {"rule_id": "R0001", "match_pattern": "abc"},
        \\ {"rule_id": "R0002"},
        \\ {"rule_id": "R0003", "match_pattern": ""},
        \\ {"rule_id": "R0009", "match_pattern": "xyz"},
        \\ {"rule_id": 42, "match_pattern": "xyz"},
        \\ {"match_pattern": "xyz"},
        \\ 42
        \\]}
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, doc, .{});
    defer parsed.deinit();
    const items = parsed.value.object.get("nids_rules").?.array.items;

    const c0 = classifyRule(items[0], &empty);
    try std.testing.expect(c0.verdict == .load);
    try std.testing.expectEqualStrings("R0001", c0.id.?);
    try std.testing.expectEqualStrings("abc", c0.pattern.?);

    const c1 = classifyRule(items[1], &empty);
    try std.testing.expect(c1.verdict == .skip and c1.reason == .no_pattern);
    try std.testing.expectEqualStrings("R0002", c1.id.?);

    const c2 = classifyRule(items[2], &empty);
    try std.testing.expect(c2.verdict == .skip and c2.reason == .no_pattern);

    const c3 = classifyRule(items[3], &disabled);
    try std.testing.expect(c3.verdict == .skip and c3.reason == .disabled);
    try std.testing.expectEqualStrings("R0009", c3.id.?);

    // Same rule without the disabled entry is a pattern issue, not disabled.
    const c3b = classifyRule(items[3], &empty);
    try std.testing.expect(c3b.verdict == .load);

    // Malformed entries carry no ID.
    for ([_]usize{ 4, 5, 6 }) |i| {
        const c = classifyRule(items[i], &empty);
        try std.testing.expect(c.verdict == .skip and c.reason == .malformed);
        try std.testing.expect(c.id == null);
    }
}

test "BE-DRIFT-098: loadRulesInto reports named skips end to end" {
    // NOTE: loadDisabledMap reads the live configs/disabled_rules.json
    // (absent in a clean tree = none disabled). IDs here avoid any
    // plausible operator-disabled value.
    const doc =
        \\{"nids_rules": [
        \\ {"rule_id": "R0101", "match_pattern": "alpha"},
        \\ {"rule_id": "R0102"},
        \\ {"rule_id": "R0103", "match_pattern": ""},
        \\ {"nope": true},
        \\ {"rule_id": "R0104", "match_pattern": "beta"}
        \\]}
    ;
    var ac = sig.AhoCorasick.init(std.testing.allocator, 100) catch unreachable;
    defer ac.deinit();
    const rep = loadRulesInto(&ac, doc, "test-rules.json");
    try std.testing.expectEqual(@as(u32, 2), rep.loaded);
    try std.testing.expectEqual(@as(u32, 2), rep.skipped_no_pattern);
    try std.testing.expectEqual(@as(u32, 0), rep.skipped_disabled);
    try std.testing.expectEqual(@as(u32, 1), rep.skipped_malformed);
    try std.testing.expectEqual(@as(u32, 3), rep.totalSkipped());
    // Only skips that name an ID are listed (the malformed entry
    // without rule_id contributes its count, not a name).
    try std.testing.expectEqual(@as(u8, 2), rep.skipped_id_count);
    try std.testing.expect(!rep.skipped_truncated);
    try std.testing.expectEqualStrings("R0102", rep.skippedId(0));
    try std.testing.expectEqualStrings("R0103", rep.skippedId(1));
    // Completeness: every catalog entry is accounted for.
    try std.testing.expectEqual(@as(usize, 5), rep.loaded + rep.totalSkipped());
}

test "L4 rules load into the predicate table, never the payload AC" {
    const doc =
        \\{"nids_rules": [
        \\ {"rule_id": "R0056", "layer": "L7", "match_pattern": "' OR 1=1"},
        \\ {"rule_id": "R9002", "layer": "L4", "match_pattern": "PROTO:ICMP", "target_protocols": ["ICMP"], "target_ports": []},
        \\ {"rule_id": "R9006", "layer": "L4", "match_pattern": "FLAGS:S", "target_protocols": ["TCP"], "target_ports": []},
        \\ {"rule_id": "R9007", "layer": "L4", "match_pattern": "FLAGS:FPU", "target_protocols": ["TCP"], "target_ports": []}
        \\]}
    ;
    var ac = sig.AhoCorasick.init(std.testing.allocator, 100) catch unreachable;
    defer ac.deinit();
    defer {
        state.g_ac_mutex.lock();
        state.g_l4_rules = l4.empty_rules;
        state.g_l4_rule_count = 0;
        state.g_ac_mutex.unlock();
    }

    const rep = loadRulesInto(&ac, doc, "test-l4-rules.json");
    try std.testing.expectEqual(@as(u32, 4), rep.loaded);
    try std.testing.expectEqual(@as(u32, 0), rep.totalSkipped());
    try std.testing.expectEqual(@as(usize, 3), state.g_l4_rule_count);

    // A synthetic payload token must not hit the AC after the layer split.
    try std.testing.expect(ac.matchFirst("FLAGS:S") == null);
    try std.testing.expect(ac.matchFirst("FLAGS:FPU") == null);
    const payload_hit = ac.matchFirst("' OR 1=1").?;
    try std.testing.expectEqual(hashRuleId("R0056"), payload_hit.rule_id);

    const syn = state.g_l4_rules[1];
    try std.testing.expectEqual(hashRuleId("R9006"), syn.rule_id);
    try std.testing.expect(l4.matches(&syn, 40000, 445, 6, 0x02));
    try std.testing.expect(!l4.matches(&syn, 40000, 445, 6, 0x12));
}

test "BE-DRIFT-098: writeJsonString escapes operator-controlled IDs" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    writeJsonString(fbs.writer(), "R01\"02\\");
    try std.testing.expectEqualStrings("\"R01\\\"02\\\\\"", fbs.getWritten());
}
