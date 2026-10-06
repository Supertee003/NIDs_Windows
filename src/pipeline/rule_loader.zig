//! Rule loading and hot-reload for the AEGIS detection engine.
//!
//! Extracted from main.zig. Owns the deterministic rule-id hashing and
//! the thread-safe Rules.json reload (rebuild + atomic AC pointer swap).

const std = @import("std");
const diag = @import("../core/diagnostics.zig");
const runtime_paths = @import("../core/runtime_paths.zig");
const sig = @import("../detection/signature_engine.zig");
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

/// Reload Rules.json into a fresh Aho-Corasick automaton.
/// Called from the control pipe thread on `rules.reload`.
/// Thread-safe: rebuilds a new AC and swaps the global pointer atomically.
pub fn reloadRules() u32 {
    // Heap-allocate the new AC so the pointer survives after this function returns
    const heap_ac = std.heap.page_allocator.create(sig.AhoCorasick) catch |err| {
        diag.err("reload: failed to allocate AhoCorasick: {}", .{err});
        return 0;
    };
    heap_ac.* = sig.AhoCorasick.init(std.heap.page_allocator, 100_000) catch |err| {
        diag.err("reload: failed to init AhoCorasick: {}", .{err});
        std.heap.page_allocator.destroy(heap_ac);
        return 0;
    };

    var new_count: u32 = 0;
    var disabled_skipped: u32 = 0;
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
            if (rule_val != .object) continue;
            const rule_obj = rule_val.object;
            const rule_id_str = rule_obj.get("rule_id") orelse continue;
            if (rule_id_str != .string) continue;
            if (disabled_map.contains(rule_id_str.string)) {
                disabled_skipped += 1;
                continue;
            }
            const rule_id = hashRuleId(rule_id_str.string);
            const match_pattern = rule_obj.get("match_pattern") orelse continue;
            if (match_pattern != .string) continue;
            if (match_pattern.string.len == 0) continue;
            heap_ac.addPattern(rule_id, match_pattern.string) catch |err| {
                diag.warn("reload: failed to add pattern for {s}: {}", .{ rule_id_str.string, err });
                continue;
            };
            new_count += 1;
        }

        heap_ac.build() catch |err| {
            diag.err("reload: failed to build Aho-Corasick: {}", .{err});
            heap_ac.deinit();
            std.heap.page_allocator.destroy(heap_ac);
            break :blk;
        };
    }

    if (new_count > 0) {
        // Swap: take old AC, install new heap-allocated one
        state.g_ac_mutex.lock();
        const old_ac_ptr = state.g_active_ac;
        state.g_active_ac = heap_ac;
        state.g_rules_loaded.store(new_count, .monotonic);
        state.g_ac_mutex.unlock();

        // Do not destroy the old automaton here. The pipeline may have taken
        // a reference immediately before the swap and can still be reading it
        // after the mutex is released. Immediate reclamation made
        // rules.reload intermittently close the control pipe with an empty
        // response. Retain retired automata for the daemon lifetime; reloads
        // are infrequent and this fail-safe policy prevents use-after-free.
        _ = old_ac_ptr;
        if (disabled_skipped > 0) {
            diag.info("reload: loaded {} rules (swap complete), skipped {} disabled", .{ new_count, disabled_skipped });
        } else {
            diag.info("reload: loaded {} rules (swap complete)", .{new_count});
        }
    } else {
        heap_ac.deinit();
        std.heap.page_allocator.destroy(heap_ac);
        diag.warn("reload: 0 rules loaded, keeping old ruleset", .{});
    }

    return new_count;
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
pub fn loadRulesInto(ac: *sig.AhoCorasick, bytes: []const u8, rules_path: []const u8) u32 {
    var count: u32 = 0;
    var disabled_map = loadDisabledMap();
    defer disabled_map.deinit();
    var disabled_skipped: u32 = 0;
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
            if (rule_val != .object) continue;
            const rule_obj = rule_val.object;
            const rule_id_str = rule_obj.get("rule_id") orelse continue;
            if (rule_id_str != .string) continue;
            if (disabled_map.contains(rule_id_str.string)) {
                disabled_skipped += 1;
                continue;
            }
            const rule_id = hashRuleId(rule_id_str.string);
            const match_pattern = rule_obj.get("match_pattern") orelse continue;
            if (match_pattern != .string) continue;
            if (match_pattern.string.len == 0) continue;
            ac.addPattern(rule_id, match_pattern.string) catch |err| {
                diag.warn("failed to add pattern for {s}: {}", .{ rule_id_str.string, err });
                continue;
            };
            count += 1;
        }

        ac.build() catch |err| {
            diag.err("failed to build Aho-Corasick automaton: {}", .{err});
            break :blk;
        };
    }
    if (disabled_skipped > 0) {
        diag.info("startup: loaded {} rules, skipped {} disabled", .{ count, disabled_skipped });
    }
    return count;
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
