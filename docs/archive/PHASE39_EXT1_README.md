# AEGIS NIDS - Phase 39 Ext 1: Federation Codec & Loopback Transport

**Risk**: MEDIUM | **Phase 39 Extension** | **Status: HOST-VERIFIED + 33 tests**

Bridges the gap between Phase 39's logical cluster model and actual
cross-node messaging. Defines the binary wire format for `ClusterMessage`
and provides transport abstractions so the same code path that drives
real TCP/gRPC also drives tests.

## Why This Extension

Phase 39 defines `ClusterCoord.ingest(msg)` to receive peer messages,
but never specifies how bytes get from peer to peer. Three pieces were
missing:

1. **Wire format** — how is a `ClusterMessage` serialized on the wire?
2. **Connection management** — what happens when a peer goes down? How
   do we recover? When do we retry?
3. **Transport abstraction** — how do we test cross-node logic without
   real network peers on the host?

Phase 39 Ext 1 closes all three gaps with a custom binary codec, a
connection state machine, and a loopback transport — all host-testable
on Linux with no external dependencies (no protobuf, no gRPC).

## Design Principles

Mirrors Phase 32 (Npcap) + Phase 36 (ML) + Phase 37 (HIDS) + Phase 39:

- **Pure Zig, host-testable on Linux** — no sockets, no DNS, no TLS in
  this module. Real transport adapters implement the `Transport` vtable.
- **Additive only** — enforcement stays in WFP kernel driver per node.
- **Kill switch OFF by default** — `FederationConfig{ .enabled = true }`
  must be set explicitly.
- **Singleton facade** — `FederationFacade.instance()` (project style).
- **Bounded memory** — 4096-byte max frame, 256-entry outbound queue,
  fixed-size ring buffers everywhere.

## Files

| File | Purpose |
|---|---|
| `core/federation_codec.zig` | Wire codec + ConnectionManager + OutboundQueue + LoopbackTransport + FederationFacade, **33 tests** |
| `core/federation_cli.zig` | CLI demo (7 scenarios + PASS/FAIL summary, exit 0 iff all match) |
| `core/federation_config.json` | Reference config (wire format spec, state machine, backoff policy) |
| `PHASE39_EXT1_README.md` | This document |

## Architecture

```
                 Application Layer (Phase 39 ClusterCoord)
                              |
                              v
              +-------------------------------+
              |   FederationFacade (singleton) |
              |   ----------------------------- |
              |   OutboundQueue (256-entry)    |
              |   ConnectionManager (state m/c) |
              +---------------+---------------+
                              |
                              v
              +-------------------------------+
              |   Codec: encode/decode        |
              |   12-byte header + CRC32       |
              |   payload (msg-type specific) |
              +---------------+---------------+
                              |
                              v
              +-------------------------------+
              |   Transport vtable             |
              |   { send, recv, isConnected } |
              +---------------+---------------+
                              |
              +---------------+---------------+
              |               |               |
              v               v               v
       +-----------+   +-----------+   +-----------+
       | Loopback  |   | TCP/Unix  |   | gRPC /    |
       | Transport |   | socket    |   | ZeroMQ    |
       | (tests)   |   | (future)  |   | (future)  |
       +-----------+   +-----------+   +-----------+
```

## Wire Format

Little-endian, 12-byte header + variable payload:

```
Offset  Size  Field          Description
------  ----  -----          -----------
0       4     magic          0x41_45_47_49 ("AEGI")
4       1     version        1 (current)
5       1     msg_type       MessageType enum value (0-6)
6       2     payload_len    u16 LE, max 4084
8       4     crc32          u32 LE, CRC32 of payload bytes
12      var   payload        msg_type-specific fields
```

### Payload Layout (all messages share the common prefix)

```
Common prefix (always present):
  +0   4   from_node_id     u32 LE
  +4   4   to_node_id       u32 LE (0 = broadcast)
  +8   8   timestamp_ns     i64 LE

Optional node payload (NODE_JOIN / HEARTBEAT w/ announcement):
  +16  1   has_node         u8 (0 or 1)
  +17  var  node fields     (node_id, name, endpoint, role, health,
                            capacity, joined_ns, last_seen_ns)

Incident fields (INCIDENT_REPORT):
  +N   4   source_ip        [4]u8
  +N+4 2   remote_port      u16 LE
  +N+6 1   proto            u8 (6=TCP, 17=UDP)
  +N+7 1   severity         u8 (IncidentSeverity enum)
  +N+8 4   score            f32 LE
  +N+12 var label           [u8 len][bytes]

Threat intel (THREAT_INTEL_SHARE):
  +N   1   has_threat_intel u8 (0 or 1)
  +N+1 var threat_intel     (kind, ip, hash[16], domain, source,
                            first_seen_ns, confidence)

Leader (LEADER_ANNOUNCE):
  +N   4   leader_node_id   u32 LE
```

All string fields are length-prefixed (1-byte length, max 255 chars).

## CRC32 Implementation

IEEE 802.3 polynomial (0xEDB88320), table-based, ~10ns per call.
Matches Ethernet FCS, PNG, zip CRC32. **NOT cryptographic** — designed
to catch bit-flips on the wire, not resist intentional tampering.
For tamper resistance, wrap the transport in TLS (future work).

Known CRC32 values:
- `crc32("") = 0x00000000`
- `crc32("hello") = 0x3610a686` (verified in test suite)

## Connection State Machine

```
   beginConnect()         markConnected()
DISCONNECTED -------> CONNECTING -------> CONNECTED
     ^                                        |
     | disconnect()                            | markSendFailure()
     |                                        v
     +--------                            DEGRADED
                                            |
                                            | markSendSuccess()
                                            |  (recover when failures=0)
                                            v
                                         CONNECTED

                                            DEGRADED
                                            | beginReconnect() after backoff
                                            v
                                         RECONNECTING
                                            | markConnected() on success
                                            v
                                         CONNECTED
```

Active states (will send/receive): `CONNECTED`, `DEGRADED`.
Inactive states: `DISCONNECTED`, `CONNECTING`, `RECONNECTING`.

## Backoff Policy

Exponential with cap:

| Consecutive failures | Backoff (default config) |
|---|---|
| 0 | 1 ms |
| 1 | 2 ms |
| 2 | 4 ms |
| 3 | 8 ms |
| 4 | 16 ms |
| 5 | 32 ms |
| ... | ... |
| >=15 | 30,000 ms (capped) |

Tunable via `FederationConfig{ .initial_backoff_ms, .max_backoff_ms, .backoff_multiplier }`.

## Transport Interface

```zig
pub const Transport = struct {
    ctx: *anyopaque,
    sendFn: *const fn (ctx: *anyopaque, data: []const u8) TransportError!void,
    recvFn: *const fn (ctx: *anyopaque, out: []u8) TransportError!usize,
    isConnectedFn: *const fn (ctx: *anyopaque) bool,
};
```

`LoopbackTransport` is the reference implementation — uses in-process
ArrayLists for inbox/outbox, with `deliverTo(other)` simulating network
delivery. Real adapters (TCP/Unix socket, gRPC, ZeroMQ) implement the
same vtable.

## Quick Start

```bash
# 1. Run unit tests (host: Linux or Windows, no network needed)
zig test core/federation_codec.zig -lc

# 2. Build CLI demo
zig build-exe core/federation_cli.zig -lc

# 3. Run all 7 scenarios + summary (exit 0 iff all pass)
./federation_cli demo

# 4. Run a single scenario
./federation_cli scenario two-node-loopback
```

Expected demo output (excerpt):
```
AEGIS NIDS - Phase 39 Ext 1: Federation Codec CLI

  -> send returned false, queue_count=0
  -> encoded 47 bytes; decoded msg_type=HEARTBEAT, from=5, ts=1000000000
  -> encoded 56 bytes; severity=HIGH, score=0.85, src=198.51.100.5:4444
  -> bit-flip in payload; decode returned CrcMismatch (expected)
  -> after 3 failures: state=DEGRADED, backoffs=2ms/4ms/8ms
  -> node 1 sent heartbeat; node 2 received msg_type=HEARTBEAT, from=1
  -> queued 261 items; queue_count=256, dropped=5
  [PASS] kill-switch-off
  [PASS] roundtrip-heartbeat
  [PASS] roundtrip-incident
  [PASS] crc-detects-bitflip
  [PASS] retry-backoff
  [PASS] two-node-loopback
  [PASS] queue-overflow-drops

7/7 scenarios passed
```

## Integration Sketch

```zig
const fc = @import("federation_codec.zig");
const cc = @import("cluster_coord.zig");

// On startup:
var fed = try fc.FederationFacade.init(allocator, .{
    .enabled = true,
    .node_id = my_node_id,
});
defer fed.shutdown();

// Wire up transport (LoopbackTransport for tests; real socket in production)
var transport = fc.LoopbackTransport.init(allocator);
defer transport.deinit();
transport.connect();

// On outgoing message (from ClusterCoord broadcast):
fed.send(.{
    .msg_type = .incident_report,
    .from_node_id = my_node_id,
    .timestamp_ns = now_ns,
    .incident_source_ip = inc.flow_local_ip,
    .incident_remote_port = inc.flow_remote_port,
    .incident_proto = @intFromEnum(inc.flow_proto),
    .incident_severity = .high,
    .incident_score = inc.flow_score,
}, now_ns);

// Periodic flush: encode + deliver via transport
fed.flushTo(transport.asTransport(), now_ns) catch |err| {
    std.log.warn("flush failed: {s}", .{@errorName(err)});
};

// On incoming bytes from transport:
const msg = try fed.receive(transport.asTransport());
cc.ClusterCoord.instance().?.ingest(msg); // forward to cluster logic
```

## Verification Checklist

Run on host (Linux or Windows) before promoting to production:

```
[ ] zig test core/federation_codec.zig -lc           -> "All 33 tests passed"
                                                       (37 cluster_coord tests also run
                                                        transitively = 70 total)
[ ] zig build-exe core/federation_cli.zig -lc        -> clean compile
[ ] ./federation_cli demo                            -> "7/7 scenarios passed" (exit 0)
[ ] ./federation_cli scenario two-node-loopback      -> [PASS]
[ ] ./federation_cli scenario crc-detects-bitflip    -> [PASS]
[ ] Inspect core/federation_config.json             -> valid JSON, kill_switch.enabled=false
```

## Risk & Rollback

- **Risk**: MEDIUM — additive transport layer; no per-node enforcement
  changes
- **Rollback**: set `FederationConfig.enabled = false` (kill switch) —
  module becomes a no-op without code removal. To fully remove: stop
  calling `FederationFacade.init()` and unlink the import in `build.zig`.
- **Failure mode**: real transport adapters (TCP/Unix socket, gRPC,
  ZeroMQ) NOT yet wired in. Module compiles + tests pass with
  `LoopbackTransport`, but produces no actual cross-node traffic at
  runtime until a real adapter is implemented.
- **Wire format**: versioned (current=1). Future versions can add
  fields without breaking older nodes by appending optional payloads
  (the decoder skips unknown trailing bytes via length-prefixing).
- **CRC32 limitation**: catches bit-flips, NOT intentional tampering.
  For tamper resistance, wrap transport in TLS (mTLS recommended for
  sensor clusters).
