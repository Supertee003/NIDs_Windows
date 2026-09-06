# AEGIS NIDS - Phase 39 Ext 2: Federation TCP Adapter

**Risk**: MEDIUM | **Phase 39 Extension** | **Status: HOST-VERIFIED + 25 tests**

Real TCP/Unix socket transport implementing the `Transport` vtable from
Phase 39 Ext 1. Closes the gap between the `LoopbackTransport` (in-process
only) and actual cross-node messaging over a network.

## Why This Extension

Phase 39 Ext 1 defined the wire codec and `Transport` interface, but only
shipped a `LoopbackTransport` for in-process tests. To actually federate
two AEGIS nodes running on different machines (or different processes on
the same machine), we need a real socket transport. Phase 39 Ext 2 ships:

1. **TcpTransport** — a single TCP connection implementing `send/recv/
   isConnected` via the `Transport` vtable. Blocking sockets with
   `SO_RCVTIMEO`/`SO_SNDTIMEO` so `recv()` never hangs forever.
2. **TcpServer** — bind + listen + accept. Returns a `TcpTransport` for
   each accepted connection. SO_REUSEADDR for quick restarts.
3. **TcpClient** — connect + reconnect logic. Exponential backoff on
   failure; bounded retries.
4. **FramedReader** — reassembles length-prefixed frames from arbitrary
   `recv()` byte chunks. TCP is a byte stream, not a message stream.

## Design Principles

Mirrors Phase 32 (Npcap) + Phase 36 (ML) + Phase 37 (HIDS) + Phase 39 +
Phase 39 Ext 1:

- **Pure Zig, host-testable on Linux** — uses `std.posix`; same code
  works on Windows via WinSock2 (no `#ifdef` needed in this module).
- **Additive only** — enforcement stays in WFP kernel driver per node.
- **Kill switch OFF by default** — `TcpConfig{ .enabled = true }` opts in.
- **Bounded memory** — 4096-byte frame reassembly buffer.
- **Graceful degradation** — connection drop → `TransportError.NotConnected`;
  caller (`FederationFacade`) handles reconnect via `ConnectionManager`.

## Files

| File | Purpose |
|---|---|
| `core/federation_tcp.zig` | TcpTransport + TcpServer + TcpClient + FramedReader, **25 tests** |
| `core/federation_tcp_cli.zig` | CLI demo (6 scenarios + PASS/FAIL summary, exit 0 iff all match) |
| `core/federation_tcp_config.json` | Reference config (bind/connect addresses, timeouts, reconnect policy) |
| `PHASE39_EXT2_README.md` | This document |

## Architecture

```
                 Application Layer (ClusterCoord / FederationFacade)
                              |
                              v
              +-------------------------------+
              |   Transport vtable             |   <- from federation_codec.zig
              |   { send, recv, isConnected } |
              +---------------+---------------+
                              |
              +---------------+---------------+
              |               |               |
              v               v               v
       +-----------+   +-----------+   +-----------+
       | Loopback  |   | Tcp       |   | Future    |
       | Transport |   | Transport |   | adapters  |
       | (Ext 1)   |   | (Ext 2)   |   | (gRPC)    |
       +-----------+   +-----+-----+   +-----------+
                            |
                            v
                   +-----------------+
                   | FramedReader    |    reassembles 12-byte header
                   | (Ext 2)         |    + payload from arbitrary
                   +-----------------+    recv() byte chunks
                            |
                            v
                   +-----------------+
                   | TCP socket      |    blocking with SO_RCVTIMEO
                   | (POSIX/WinSock) |    SO_SNDTIMEO + TCP_NODELAY
                   +-----------------+
```

## Socket Lifecycle

### Server side (passive listener)

```zig
// 1. Bind + listen
var srv = ft.TcpServer.init();
defer srv.deinit();
const addr = std.net.Address.parseIp4("127.0.0.1", 7931) catch unreachable;
try srv.bindAndListen(addr, 32);

// 2. Accept incoming connections (loop in production)
while (running) {
    var conn = srv.accept(1000, 5000) catch continue;
    // conn is a TcpTransport - hand off to a worker thread
    // OR use FramedReader to receive messages:
    var reader = ft.FramedReader.init();
    switch (reader.readFrameFromTransport(conn.asTransport())) {
        .frame => |f| { /* decoded ClusterMessage */ },
        .need_more => continue,
        .err => break,
    }
}
```

### Client side (active connector)

```zig
var client = ft.TcpClient.init(.{
    .connect_addr = "127.0.0.1:7931",
    .recv_timeout_ms = 1000,
});
defer client.deinit();
try client.connect();

// Send a framed message
var wire: [fc.MAX_FRAME_SIZE]u8 = undefined;
const n = try fc.encode(.{
    .msg_type = .heartbeat,
    .from_node_id = my_node_id,
    .timestamp_ns = std.time.nanoTimestamp(),
}, &wire);
try client.transport.sendBytes(wire[0..n]);

// On disconnect, reconnect with backoff:
if (!client.transport.connected) {
    if (client.shouldRetry()) {
        _ = client.reconnectIfNeeded(std.time.nanoTimestamp()) catch {
            // give up; mark node as dead in registry
        };
    }
}
```

## Framed Protocol

TCP delivers bytes, not messages. A single `recv()` may return:

- A complete frame (lucky case)
- A partial frame (need more bytes)
- Multiple frames concatenated
- The tail of one frame + the head of the next

`FramedReader` handles all four cases by:

1. Maintaining an internal 4096-byte buffer
2. Appending incoming bytes via `append()`
3. Trying to decode a complete frame via `tryReadFrame()`
4. Returning:
   - `.frame` if a complete frame is available (caller-owned until next call)
   - `.need_more` if buffer doesn't have a complete frame yet
   - `.err` on decode failure (magic mismatch, CRC mismatch, etc.)
5. After processing a frame, calling `consumeFrame(frame_len)` shifts
   remaining bytes to the front of the buffer

The high-level helper `readFrameFromTransport(transport)` does the recv +
append + tryReadFrame sequence in one call.

## Socket Options

| Option | Value | Purpose |
|---|---|---|
| `SO_RCVTIMEO` | 1000 ms (default) | `recv()` blocks but doesn't hang forever |
| `SO_SNDTIMEO` | 5000 ms (default) | `send()` blocks but doesn't hang forever |
| `TCP_NODELAY` | 1 (enabled) | Disable Nagle's algorithm for low-latency federation messages |
| `SO_REUSEADDR` | 1 (server only) | Quick rebind after restart without TIME_WAIT delay |

## Error Handling

| Error | Cause | Recovery |
|---|---|---|
| `NotConnected` | send/recv before connect, or after disconnect | Caller calls `reconnectIfNeeded()` |
| `ConnectionReset` | Peer closed gracefully or abruptly | Caller calls `reconnectIfNeeded()` |
| `Timeout` | SO_RCVTIMEO elapsed without data | Non-fatal; retry recv |
| `SendFailed` | `send()` syscall error (EPIPE, etc.) | Caller calls `reconnectIfNeeded()` |
| `ReceiveEmpty` | `recv()` returned 0 bytes | Non-fatal; no data available |
| `ConnectFailed` | `connect()` syscall error (ECONNREFUSED, etc.) | Backoff and retry |
| `BindFailed` | `bind()` syscall error (EADDRINUSE) | Use different port |
| `AcceptFailed` | `accept()` syscall error | Log and continue |

All errors propagate as `TransportError` (from Phase 39 Ext 1) so the
`FederationFacade` handles them uniformly via `ConnectionManager`.

## Quick Start

```bash
# 1. Run unit tests (host: Linux or Windows, no external services needed)
zig test core/federation_tcp.zig -lc

# 2. Build CLI demo
zig build-exe core/federation_tcp_cli.zig -lc

# 3. Run all 6 scenarios + summary (exit 0 iff all pass)
./federation_tcp_cli demo

# 4. Run a single scenario
./federation_tcp_cli scenario framed-roundtrip
```

Expected demo output (excerpt):
```
AEGIS NIDS - Phase 39 Ext 2: Federation TCP Adapter CLI

  -> TcpConfig.enabled=false; transport is no-op at TcpClient level
  -> bound to 127.0.0.1:44401; listening=true
  -> sent 14 bytes; server received 14 bytes; match=true
  -> frame received; msg_type=HEARTBEAT, from=7
  -> sent 5 incident frames; reassembled 5 on server side
  -> client closed; server recv returned ConnectionReset (expected); server.connected=false
  [PASS] kill-switch-off
  [PASS] bind-and-listen
  [PASS] connect-and-echo
  [PASS] framed-roundtrip
  [PASS] multi-message-stream
  [PASS] peer-disconnect-detected

6/6 scenarios passed
```

## Integration Sketch

```zig
const ft = @import("federation_tcp.zig");
const fc = @import("federation_codec.zig");
const cc = @import("cluster_coord.zig");

// On startup - server side:
var srv = ft.TcpServer.init();
defer srv.deinit();
const bind_addr = std.net.Address.parseIp4("0.0.0.0", 7931) catch unreachable;
try srv.bindAndListen(bind_addr, 32);

// Background accept loop (simplified):
while (running) {
    var conn = srv.accept(1000, 5000) catch |err| {
        if (err == error.Timeout) continue;
        std.log.warn("accept failed: {s}", .{@errorName(err)});
        continue;
    };
    // Hand off to worker thread OR process inline:
    var reader = ft.FramedReader.init();
    while (conn.connected) {
        switch (reader.readFrameFromTransport(conn.asTransport())) {
            .frame => |f| {
                const msg = try fc.decode(f);
                cc.ClusterCoord.instance().?.ingest(msg); // forward to cluster
                reader.consumeFrame(f.len);
            },
            .need_more => continue,
            .err => break,
        }
    }
}

// On startup - client side:
var client = ft.TcpClient.init(.{
    .connect_addr = "remote-sensor.example.com:7931",
});
defer client.deinit();
try client.connect();

// Outgoing: encode + send via TCP
var wire: [fc.MAX_FRAME_SIZE]u8 = undefined;
const n = try fc.encode(.{
    .msg_type = .incident_report,
    .from_node_id = my_node_id,
    .timestamp_ns = std.time.nanoTimestamp(),
    .incident_source_ip = inc.flow_local_ip,
    .incident_remote_port = inc.flow_remote_port,
}, &wire);
client.transport.sendBytes(wire[0..n]) catch {
    // Mark transport as disconnected; FederationFacade will reconnect
};
```

## Verification Checklist

Run on host (Linux or Windows) before promoting to production:

```
[ ] zig test core/federation_tcp.zig -lc              -> "All 101 tests passed"
                                                       (25 federation_tcp + 33 federation_codec
                                                        + 37 cluster_coord transitively)
[ ] zig build-exe core/federation_tcp_cli.zig -lc     -> clean compile
[ ] ./federation_tcp_cli demo                         -> "6/6 scenarios passed" (exit 0)
[ ] ./federation_tcp_cli scenario framed-roundtrip    -> [PASS]
[ ] ./federation_tcp_cli scenario multi-message-stream -> [PASS]
[ ] Inspect core/federation_tcp_config.json           -> valid JSON, kill_switch.enabled=false
```

## Risk & Rollback

- **Risk**: MEDIUM — additive transport layer; no per-node enforcement
  changes
- **Rollback**: set `TcpConfig.enabled = false` (kill switch) — module
  becomes a no-op without code removal. To fully remove: stop calling
  `TcpServer.bindAndListen()` / `TcpClient.connect()` and unlink the
  import in `build.zig`.
- **Failure mode**: this module ships a real working TCP transport; no
  further adapters are needed for basic cross-node messaging. For
  production hardening, add TLS/mTLS wrap (future Ext 3 candidate).
- **Portability**: uses `std.posix`; works on Linux + Windows (via
  WinSock2). No `#ifdef` needed in this module. IPv4 + IPv6 supported
  via `parseAddrPort()`.
- **Concurrency**: this module is single-threaded per connection. For
  production, run an accept-loop thread that hands off each connection
  to a worker thread (or use `epoll`/`IOCP` for high-fanout scenarios).
- **Security**: plaintext TCP. For tamper resistance, wrap in TLS
  (mTLS recommended for trusted internal sensor clusters). The CRC32
  in the wire format catches bit-flips but NOT intentional tampering.

## Phase 39 Extension Progress

| Extension | Status | Notes |
|---|---|---|
| Ext 1 — Federation Codec | COMPLETE | Wire format + ConnectionManager + LoopbackTransport (33 tests) |
| **Ext 2 — Federation TCP Adapter** | **COMPLETE (this extension)** | TcpTransport + TcpServer + TcpClient + FramedReader (25 tests) |
| Ext 3 — TLS/mTLS Wrap | PENDING | For tamper-resistant federation traffic |
| Ext 4 — gRPC Adapter | PENDING | For typed messages + richer schema (optional) |

After Ext 2, AEGIS can actually federate two nodes over TCP — the
logical cluster model from Phase 39 now has a real transport. Ext 3
(hardening) is the next sensible step for production deployment.
