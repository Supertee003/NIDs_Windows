//! Phase 4 data-plane contract: ingress conservation and event identity.
const std = @import("std");

pub const Source = enum(u8) {
    go_nose = 1,
    etw = 2,
    fim = 3,
    registry = 4,
    legacy_sensor = 5,
    replay = 6,
};

pub const EventIdentity = struct {
    source: Source,
    epoch: u64,
    sequence: u64,

    pub fn isValid(self: EventIdentity) bool {
        return self.epoch != 0 and self.sequence != 0;
    }
};

/// Cross-restart producer identity. The CanonicalEvent v1 wire layout stays
/// unchanged; adapters may carry this identity through a versioned side
/// channel or a later wire revision.
pub const ProducerIdentity = struct {
    source: Source,
    runtime_generation: u64,
    producer_epoch: u64,
    producer_sequence: u64,

    pub fn isValid(self: ProducerIdentity) bool {
        return self.runtime_generation != 0 and
            self.producer_epoch != 0 and
            self.producer_sequence != 0;
    }

    pub fn isSameProducer(self: ProducerIdentity, other: ProducerIdentity) bool {
        return self.source == other.source and
            self.runtime_generation == other.runtime_generation and
            self.producer_epoch == other.producer_epoch;
    }
};

pub const IngressCounters = struct {
    frames_read: u64 = 0,
    frames_rejected: u64 = 0,
    frames_submitted: u64 = 0,
    events_processed: u64 = 0,
    events_dropped: u64 = 0,
    capacity_dropped: u64 = 0,
    lifecycle_dropped: u64 = 0,
    duplicate_ids: u64 = 0,
    non_monotonic_ids: u64 = 0,

    pub fn conservationGap(self: IngressCounters) i128 {
        return @as(i128, self.frames_submitted) - @as(i128, self.events_processed) -
            @as(i128, self.events_dropped) - @as(i128, self.capacity_dropped) -
            @as(i128, self.lifecycle_dropped);
    }
};

test "data plane counters expose conservation fields" {
    const counters = IngressCounters{ .frames_submitted = 10, .events_processed = 8, .events_dropped = 2 };
    try std.testing.expectEqual(@as(i128, 0), counters.conservationGap());
}

test "event identity requires epoch and sequence" {
    try std.testing.expect((EventIdentity{ .source = .go_nose, .epoch = 1, .sequence = 1 }).isValid());
    try std.testing.expect(!(EventIdentity{ .source = .go_nose, .epoch = 0, .sequence = 1 }).isValid());
}

test "producer identity requires generation, epoch and sequence" {
    const identity = ProducerIdentity{
        .source = .go_nose,
        .runtime_generation = 7,
        .producer_epoch = 3,
        .producer_sequence = 1,
    };
    try std.testing.expect(identity.isValid());
    try std.testing.expect(identity.isSameProducer(.{
        .source = .go_nose,
        .runtime_generation = 7,
        .producer_epoch = 3,
        .producer_sequence = 2,
    }));
    try std.testing.expect(!identity.isSameProducer(.{
        .source = .go_nose,
        .runtime_generation = 8,
        .producer_epoch = 3,
        .producer_sequence = 2,
    }));
}

test "ingress conservation includes capacity and lifecycle drops" {
    const counters = IngressCounters{
        .frames_submitted = 10,
        .events_processed = 6,
        .events_dropped = 1,
        .capacity_dropped = 2,
        .lifecycle_dropped = 1,
    };
    try std.testing.expectEqual(@as(i128, 0), counters.conservationGap());
}
