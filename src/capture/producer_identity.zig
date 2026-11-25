//! V3-PRODUCER-IDENTITY-001: bounded producer-identity admission guard.
//!
//! Go Nose owns issuance of the provenance tuple; this module owns Zig-side
//! admission/dedup. It never authorizes enforcement: it only decides whether a
//! frame is usable as a distinct acquisition observation. Legacy v1/v2 and
//! metadata-only v3 frames are explicitly accepted without identity claims.
//! Provenance-bearing v3 frames must carry a complete tuple and a monotonic
//! capture sequence per (epoch, generation, interface) key.
//!
//! The table is bounded and deterministic. Eviction is counted, never silent.

const std = @import("std");
const canonical = @import("../contract/canonical_event.zig");

pub const MAX_TRACKED_PRODUCERS: usize = 64;

pub const ProducerIdentity = struct {
    capture_sequence: u64 = 0,
    producer_epoch: u32 = 0,
    producer_generation: u32 = 0,
    interface_id: u32 = 0,

    pub fn fromEnvelope(env_opt: ?canonical.V3Envelope) ?ProducerIdentity {
        const env = env_opt orelse return null;
        if (!env.provenanceValid()) return null;
        return .{
            .capture_sequence = env.capture_sequence,
            .producer_epoch = env.producer_epoch,
            .producer_generation = env.producer_generation,
            .interface_id = env.interface_id,
        };
    }

    pub fn isValid(self: ProducerIdentity) bool {
        return self.capture_sequence != 0 and self.producer_epoch != 0 and
            self.producer_generation != 0 and self.interface_id != 0;
    }

    pub fn sameKey(self: ProducerIdentity, other: ProducerIdentity) bool {
        return self.producer_epoch == other.producer_epoch and
            self.producer_generation == other.producer_generation and
            self.interface_id == other.interface_id;
    }
};

pub const Decision = enum {
    /// v1/v2 or metadata-only v3: no identity claim, unchanged compatibility.
    legacy,
    /// First observation or exact next sequence for a known producer.
    accepted,
    /// Sequence advanced by more than one. Visible, still admitted.
    gap,
    /// Exact sequence replay for a known producer key. Reject before queue.
    duplicate,
    /// Sequence moved backwards for a known producer key. Reject before queue.
    regression,
    /// Provenance flag set but tuple incomplete. Reject before queue.
    invalid,
    /// Bound reached; an old key was evicted. Visible, still admitted.
    evicted,
};

pub const Evaluation = struct {
    decision: Decision,
    identity: ?ProducerIdentity,
};

const Tracked = struct {
    used: bool = false,
    identity: ProducerIdentity = .{},
    last_sequence: u64 = 0,
};

pub const Guard = struct {
    entries: [MAX_TRACKED_PRODUCERS]Tracked = [_]Tracked{.{}} ** MAX_TRACKED_PRODUCERS,
    count: usize = 0,
    cursor: usize = 0,
    evictions: u64 = 0,

    pub fn reset(self: *Guard) void {
        self.* = .{};
    }

    pub fn evaluate(self: *Guard, env_opt: ?canonical.V3Envelope) Evaluation {
        const identity = ProducerIdentity.fromEnvelope(env_opt) orelse
            return .{ .decision = .legacy, .identity = null };
        if (!identity.isValid()) return .{ .decision = .invalid, .identity = identity };

        for (&self.entries) |*entry| {
            if (!entry.used or !entry.identity.sameKey(identity)) continue;
            if (identity.capture_sequence == entry.last_sequence) {
                return .{ .decision = .duplicate, .identity = identity };
            }
            if (identity.capture_sequence < entry.last_sequence) {
                return .{ .decision = .regression, .identity = identity };
            }
            const decision: Decision = if (identity.capture_sequence == entry.last_sequence + 1)
                .accepted
            else
                .gap;
            entry.last_sequence = identity.capture_sequence;
            return .{ .decision = decision, .identity = identity };
        }

        if (self.count == self.entries.len) {
            const slot = &self.entries[self.cursor];
            slot.* = .{
                .used = true,
                .identity = identity,
                .last_sequence = identity.capture_sequence,
            };
            self.cursor = (self.cursor + 1) % self.entries.len;
            self.evictions += 1;
            return .{ .decision = .evicted, .identity = identity };
        }

        self.entries[self.count] = .{
            .used = true,
            .identity = identity,
            .last_sequence = identity.capture_sequence,
        };
        self.count += 1;
        // The first observation defines the baseline for a new key; it is
        // not a gap merely because the producer was already mid-stream when
        // this daemon started.
        return .{ .decision = .accepted, .identity = identity };
    }
};

fn envelope(seq: u64, epoch: u32, generation: u32, interface_id: u32) canonical.V3Envelope {
    return .{
        .flags = canonical.V3PayloadFlags.PROVENANCE_VALID,
        .capture_sequence = seq,
        .producer_epoch = epoch,
        .producer_generation = generation,
        .interface_id = interface_id,
    };
}

test "V3-PRODUCER-IDENTITY-001: legacy frames carry no identity claim" {
    var guard = Guard{};
    const legacy = guard.evaluate(null);
    try std.testing.expectEqual(Decision.legacy, legacy.decision);
    try std.testing.expect(legacy.identity == null);

    var metadata_only = envelope(0, 0, 0, 0);
    metadata_only.flags = 0;
    try std.testing.expectEqual(Decision.legacy, guard.evaluate(metadata_only).decision);
    // Explicit provenance with a partial tuple must fail closed.
    var partial = envelope(9, 0, 2, 0xCAFE);
    partial.flags |= canonical.V3PayloadFlags.PROVENANCE_VALID;
    try std.testing.expectEqual(Decision.invalid, guard.evaluate(partial).decision);
}

test "V3-PRODUCER-IDENTITY-001: duplicate and regression are rejected, gap is visible" {
    var guard = Guard{};
    try std.testing.expectEqual(Decision.accepted, guard.evaluate(envelope(3, 100, 1, 0xCAFE)).decision);
    try std.testing.expectEqual(Decision.duplicate, guard.evaluate(envelope(3, 100, 1, 0xCAFE)).decision);
    try std.testing.expectEqual(Decision.regression, guard.evaluate(envelope(2, 100, 1, 0xCAFE)).decision);
    try std.testing.expectEqual(Decision.gap, guard.evaluate(envelope(5, 100, 1, 0xCAFE)).decision);
    try std.testing.expectEqual(Decision.accepted, guard.evaluate(envelope(6, 100, 1, 0xCAFE)).decision);
}

test "V3-PRODUCER-IDENTITY-001: restart generation makes reused sequence distinct" {
    var guard = Guard{};
    try std.testing.expectEqual(Decision.accepted, guard.evaluate(envelope(1, 100, 1, 0xCAFE)).decision);
    try std.testing.expectEqual(Decision.accepted, guard.evaluate(envelope(1, 100, 2, 0xCAFE)).decision);
    try std.testing.expectEqual(Decision.accepted, guard.evaluate(envelope(1, 100, 2, 0xBEEF)).decision);
}

test "V3-PRODUCER-IDENTITY-001: tracking is bounded and eviction is counted" {
    var guard = Guard{};
    var i: u32 = 0;
    while (i < MAX_TRACKED_PRODUCERS) : (i += 1) {
        try std.testing.expectEqual(Decision.accepted, guard.evaluate(envelope(1, 100, i + 1, 0xCAFE)).decision);
    }
    try std.testing.expectEqual(@as(usize, MAX_TRACKED_PRODUCERS), guard.count);
    try std.testing.expectEqual(@as(u64, 0), guard.evictions);

    try std.testing.expectEqual(Decision.evicted, guard.evaluate(envelope(1, 100, MAX_TRACKED_PRODUCERS + 1, 0xCAFE)).decision);
    try std.testing.expectEqual(@as(usize, MAX_TRACKED_PRODUCERS), guard.count);
    try std.testing.expectEqual(@as(u64, 1), guard.evictions);
}
