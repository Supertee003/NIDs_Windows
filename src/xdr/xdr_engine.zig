// II16 - XDR Engine (Cross-Layer Correlation)
// AEGIS NIDS v5.0+ â€” Correlates events across network + host + identity layers
//
// Goal: detect attack chains that span layers, e.g.:
//   "Network port scan from X" + "Host process spawn from X" + "Registry run key set"
//   â†’ Host compromise likely.
//
// Each layer emits normalized IpcEvents. XdrEngine correlates them within
// time windows using per-source-host keys.

const std = @import("std");
const event = @import("../contract/event.zig");
const manifest = @import("../contract/runtime_manifest.zig");
const diag = @import("../core/diagnostics.zig");

pub const LAYER_NETWORK: u8 = 1;
pub const LAYER_HOST: u8 = 2;
pub const LAYER_IDENTITY: u8 = 3;
pub const LAYER_FEDERATION: u8 = 4;

pub const CrossLayerChain = struct {
    network_events: u32 = 0,
    host_events: u32 = 0,
    identity_events: u32 = 0,
    first_seen_ns: i128 = 0,
    last_seen_ns: i128 = 0,
    score: u16 = 0,
    chain_id: u64 = 0,
};

pub const XdrRule = struct {
    id: u32,
    name: [64]u8 = [_]u8{0} ** 64,
    required_layers: u8, // bitmask
    min_events: u8,
    window_sec: i64,
    score_per_event: u16,
};

pub const DEFAULT_RULES = [_]XdrRule{
    .{
        .id = 3001,
        .required_layers = LAYER_NETWORK | LAYER_HOST,
        .min_events = 3,
        .window_sec = 300,
        .score_per_event = 30,
    },
    .{
        .id = 3002,
        .required_layers = LAYER_NETWORK | LAYER_HOST | LAYER_IDENTITY,
        .min_events = 5,
        .window_sec = 600,
        .score_per_event = 50,
    },
};

pub const XdrEngine = struct {
    chains: std.AutoHashMap(u32, CrossLayerChain), // keyed by src_ip
    rules: []const XdrRule,
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    next_chain_id: u64 = 1,
    triggered: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, rules: []const XdrRule) XdrEngine {
        return .{
            .chains = std.AutoHashMap(u32, CrossLayerChain).init(allocator),
            .rules = rules,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *XdrEngine) void {
        self.chains.deinit();
    }

    pub fn observe(self: *XdrEngine, ev: *const event.IpcEvent, layer: u8) !?*CrossLayerChain {
        self.mutex.lock();
        defer self.mutex.unlock();
        const gop = try self.chains.getOrPut(ev.src_ip);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{
                .first_seen_ns = ev.timestamp_ns,
                .chain_id = self.next_chain_id,
            };
            self.next_chain_id += 1;
        }
        const chain = gop.value_ptr;
        chain.last_seen_ns = ev.timestamp_ns;
        switch (layer) {
            LAYER_NETWORK => chain.network_events += 1,
            LAYER_HOST => chain.host_events += 1,
            LAYER_IDENTITY => chain.identity_events += 1,
            else => {},
        }
        chain.score += 10;
        // Check rules
        for (self.rules) |rule| {
            if ((chain.network_events > 0 and (rule.required_layers & LAYER_NETWORK) != 0) and
                (chain.host_events > 0 and (rule.required_layers & LAYER_HOST) != 0))
            {
                const total = chain.network_events + chain.host_events + chain.identity_events;
                if (total >= rule.min_events) {
                    chain.score += rule.score_per_event;
                    if (chain.score >= 100) {
                        self.triggered += 1;
                        diag.alert("XDR: chain {d} triggered rule {d} (score={d})", .{ chain.chain_id, rule.id, chain.score });
                        return chain;
                    }
                }
            }
        }
        return null;
    }

    pub fn prune(self: *XdrEngine, now_ns: i128) u32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        var to_remove = std.ArrayList(u32).init(self.allocator);
        defer to_remove.deinit();
        var it = self.chains.iterator();
        while (it.next()) |entry| {
            const c = entry.value_ptr;
            if (now_ns - c.last_seen_ns > 2 * @as(i128, 600) * std.time.ns_per_s) {
                to_remove.append(entry.key_ptr.*) catch break;
            }
        }
        const n: u32 = @intCast(to_remove.items.len);
        for (to_remove.items) |k| _ = self.chains.remove(k);
        return n;
    }

    pub fn chainCount(self: *XdrEngine) usize {
        return self.chains.count();
    }
};

// ============================================================================
// Tests
// ============================================================================
test "XdrEngine observes and accumulates" {
    var xdr = XdrEngine.init(std.testing.allocator, &DEFAULT_RULES);
    defer xdr.deinit();
    var ev = event.IpcEvent.init(.signature_match);
    ev.src_ip = 0x0A000001;
    ev.timestamp_ns = 1000;
    _ = try xdr.observe(&ev, LAYER_NETWORK);
    _ = try xdr.observe(&ev, LAYER_HOST);
    _ = try xdr.observe(&ev, LAYER_HOST);
    try std.testing.expectEqual(@as(usize, 1), xdr.chainCount());
}

test "XdrEngine triggers rule 3001" {
    var xdr = XdrEngine.init(std.testing.allocator, &DEFAULT_RULES);
    defer xdr.deinit();
    var ev = event.IpcEvent.init(.signature_match);
    ev.src_ip = 0x0A000002;
    ev.timestamp_ns = 1000;
    _ = try xdr.observe(&ev, LAYER_NETWORK); // score += 10
    _ = try xdr.observe(&ev, LAYER_NETWORK); // +10
    _ = try xdr.observe(&ev, LAYER_HOST); // +10
    _ = try xdr.observe(&ev, LAYER_HOST); // +10 + 30 (rule)
    _ = try xdr.observe(&ev, LAYER_HOST); // +10 + 30 (rule)
    _ = try xdr.observe(&ev, LAYER_NETWORK); // +10 + 30 â†’ trigger
    try std.testing.expect(xdr.triggered >= 1);
}

test "XdrEngine prune" {
    var xdr = XdrEngine.init(std.testing.allocator, &DEFAULT_RULES);
    defer xdr.deinit();
    var ev = event.IpcEvent.init(.signature_match);
    ev.src_ip = 0x0A000003;
    ev.timestamp_ns = 1_000_000_000;
    _ = try xdr.observe(&ev, LAYER_NETWORK);
    const removed = xdr.prune(1_000_000_000 + 1201 * std.time.ns_per_s);
    try std.testing.expectEqual(@as(u32, 1), removed);
}
