//! Lock-free-ish event queue feeding the detection pipeline.
//!
//! Extracted from main.zig. Sensors (Npcap, ETW, FIM, registry, pipe)
//! push QueuedEvents; the pipeline loop pops and processes them.

const std = @import("std");
const event = @import("../contract/event.zig");
const state = @import("runtime_state.zig");

pub const PIPELINE_QUEUE_SIZE: usize = 4096;
pub const MAX_PAYLOAD_BYTES: usize = 1500; // MTU-sized payload buffer

/// Queued event: wraps IpcEvent + actual packet payload bytes.
/// The payload is needed for Aho-Corasick signature matching.
pub const QueuedEvent = struct {
    ev: event.IpcEvent,
    payload: [MAX_PAYLOAD_BYTES]u8 = [_]u8{0} ** MAX_PAYLOAD_BYTES,
    payload_len: u16 = 0,
};

var g_event_queue: [PIPELINE_QUEUE_SIZE]QueuedEvent = undefined;
var g_queue_head: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var g_queue_tail: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var g_queue_mutex: std.Thread.Mutex = .{};

/// Push an event + optional payload into the pipeline queue.
/// Returns true if accepted, false if queue is full (event dropped).
pub fn pushEvent(ev: event.IpcEvent, payload: []const u8) bool {
    const head = g_queue_head.load(.monotonic);
    const tail = g_queue_tail.load(.acquire);
    if (head -% tail >= PIPELINE_QUEUE_SIZE) {
        // Queue full — drop event
        state.g_queue_drops += 1; // track queue drops
        return false;
    }
    var qe = QueuedEvent{ .ev = ev };
    const copy_len = @min(payload.len, MAX_PAYLOAD_BYTES);
    @memcpy(qe.payload[0..copy_len], payload[0..copy_len]);
    qe.payload_len = @intCast(copy_len);
    g_event_queue[head % PIPELINE_QUEUE_SIZE] = qe;
    g_queue_head.store(head + 1, .release);
    return true;
}

/// Pop the next queued event from the pipeline queue.
/// Returns null if queue is empty.
pub fn popEvent() ?QueuedEvent {
    g_queue_mutex.lock();
    defer g_queue_mutex.unlock();
    const tail = g_queue_tail.load(.monotonic);
    const head = g_queue_head.load(.acquire);
    if (tail == head) return null;
    const qe = g_event_queue[tail % PIPELINE_QUEUE_SIZE];
    g_queue_tail.store(tail + 1, .release);
    return qe;
}
