//! Rule loading and hot-reload for the AEGIS detection engine.
//!
//! Extracted from main.zig. Owns the deterministic rule-id hashing and
//! the thread-safe Rules.json reload (rebuild + atomic AC pointer swap).

const std = @import("std");
const diag = @import("../core/diagnostics.zig");
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

/// Reload Rules.json into a fresh Aho-Corasick automaton.
/// Called from the control pipe thread on `rules.reload`.
/// Thread-safe: rebuilds a new AC and swaps the global pointer atomically.
pub fn reloadRules() u32 {
    // Heap-allocate the new AC so the pointer survives after this function returns
    const heap_ac = std.heap.page_allocator.create(sig.AhoCorasick) catch |err| {
        diag.err("reload: failed to allocate AhoCorasick: {}", .{err});
        return state.g_rules_loaded;
    };
    heap_ac.* = sig.AhoCorasick.init(std.heap.page_allocator, 100_000) catch |err| {
        diag.err("reload: failed to init AhoCorasick: {}", .{err});
        std.heap.page_allocator.destroy(heap_ac);
        return state.g_rules_loaded;
    };

    var new_count: u32 = 0;
    blk: {
        const rules_path = "configs/Rules.json";
        const rules_file = std.fs.cwd().openFile(rules_path, .{}) catch |err| {
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
        state.g_rules_loaded = new_count;
        state.g_ac_mutex.unlock();

        // Free old AC if it existed
        if (old_ac_ptr) |old| {
            old.deinit();
            std.heap.page_allocator.destroy(old);
        }
        diag.info("reload: loaded {} rules (swap complete)", .{new_count});
    } else {
        heap_ac.deinit();
        std.heap.page_allocator.destroy(heap_ac);
        diag.warn("reload: 0 rules loaded, keeping old ruleset", .{});
    }

    return new_count;
}

/// Parse the nids_rules array from Rules.json bytes into an existing AC.
/// Shared by initial startup load and reload; returns the loaded count.
pub fn loadRulesInto(ac: *sig.AhoCorasick, bytes: []const u8, rules_path: []const u8) u32 {
    var count: u32 = 0;
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
    return count;
}
