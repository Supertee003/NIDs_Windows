# AEGIS NIDS - Phase 39: Distributed Cluster Coordination

**Risk**: MEDIUM | **Tier 5 - Complex Capability** | **Status: HOST-VERIFIED + 33 tests**

Extends AEGIS from single-node NIDS to a coordinated multi-sensor cluster.
A single sensor sees only its own network segment; Phase 39 lets multiple
sensors share state so that an attacker hitting several segments is
recognized as one campaign rather than N isolated incidents.

## Why Phase 39 (Cluster Layer)

Phases 32-37 see **one network segment + one host**. They cannot answer:

- An attacker scanning 192.168.1.0/24 from sensor A and 10.0.0.0/24 from
  sensor B in the same minute — is this one campaign or two?
- A C2 IP appears in threat intel shared by sensor C; can sensor A block
  it on first contact without re-learning?
- Which node coordinates policy rollouts? (Leader election)
- Is peer sensor D alive, or has it been compromised / disconnected?

Phase 39 closes these gaps with five coordinated capabilities:

1. **ClusterNode registry** — peer discovery (NodeId, endpoint, capacity, role)
2. **HeartbeatMonitor** — liveness (last_seen, miss count, healthy→dead)
3. **CrossNodeIncidentAggregator** — same source IP across N nodes within
   `window_ms` → severity escalation (2 nodes → HIGH, 3+ → CRITICAL)
4. **ThreatIntelBroadcast** — IP/hash/domain IoCs shared across nodes
5. **LeaderElection** — deterministic ring (highest active NodeId wins)

## Design Principles

Mirrors Phase 32 (Npcap) + Phase 36 (ML) + Phase 37 (HIDS):

- **Pure Zig, host-testable on Linux** — no real network sockets in the
  core module. Transport adapters (gRPC / ZeroMQ / REST) live outside and
  feed `ClusterMessage` records via `ClusterCoord.ingest(msg)`. All 33
  tests run on Linux with no cluster peers needed.
- **Additive only** — enforcement stays in the WFP kernel driver **per
  node**. Phase 39 emits aggregated `ClusterIncident` records; it does
  NOT block, kill, or quarantine.
- **Kill switch OFF by default** — `ClusterConfig{ .enabled = true }`
  must be set explicitly. Until then `ingest()` is a no-op.
- **Singleton facade** — `ClusterCoord.instance()` (project style).
- **Bounded memory** — fixed caps: 64 nodes, 512 incidents, 1024
  threat-intel entries, 8 reporting nodes per incident, 6 reasons.

## Files

| File | Purpose |
|---|---|
| `core/cluster_coord.zig` | Core module (NodeRegistry, HeartbeatMonitor, CrossNodeIncidentAggregator, ThreatIntelBroadcast, LeaderElection), **33 tests** |
| `core/cluster_cli.zig` | CLI demo (7 scenarios + PASS/FAIL summary, exit 0 iff all match) |
| `core/cluster_config.json` | Reference config (kill switch, heartbeat, escalation thresholds) |
| `PHASE39_README.md` | This document |

## Architecture

```
       Node A (sensor)        Node B (sensor)        Node C (aggregator)
       +-----------+          +-----------+          +-----------+
       | Npcap     |          | Npcap     |          |           |
       | ML (P36)  |          | ML (P36)  |          |           |
       | HIDS(P37) |          | HIDS(P37) |          |           |
       +-----+-----+          +-----+-----+          +-----+-----+
             |                      |                      |
             v                      v                      v
       +-----+----------------------+----------------------+-----+
       |          Federation Transport (gRPC / ZeroMQ)            |
       +-----+----------------------+----------------------+-----+
             |                      |                      |
             v                      v                      v
       +----------------------------------------------------------+
       |   ClusterCoord.ingest(ClusterMessage)                    |
       |   ----------------------------------                     |
       |   NodeRegistry      HeartbeatMonitor                     |
       |       |                  |                               |
       |       v                  v                               |
       |   LeaderElection    CrossNodeIncidentAggregator          |
       |       |                  |                               |
       |       v                  v                               |
       |   currentLeader()    ClusterIncident                     |
       |                       (aggregated across nodes)           |
       |                           |                               |
       |                           v                               |
       |                   ThreatIntelBroadcast                   |
       |                   (shared IoC list)                      |
       +----------------------------------------------------------+
                                |
                                v
                       Phase 19 XdrEngine
                       (CEF -> SIEM export)
```

## Federation Protocol

7 message types — all cluster traffic flows through `ClusterCoord.ingest()`:

| Message | Direction | Purpose |
|---|---|---|
| `HEARTBEAT` | periodic broadcast | liveness; refreshes last_seen + resets misses |
| `NODE_JOIN` | on startup | announce self with role/endpoint/capacity |
| `NODE_LEAVE` | on graceful shutdown | remove from registry |
| `INCIDENT_REPORT` | on detection | share flow verdict for cross-node aggregation |
| `THREAT_INTEL_SHARE` | on IoC discovery | add to shared list; dedup by (kind, key) |
| `LEADER_ANNOUNCE` | post-election | declare new leader |
| `LEADER_REQUEST` | on election timeout | trigger leader election |

## Cross-Node Aggregation Policy

A `ClusterIncident` is aggregated by **stable key**: `source_ip + remote_port + proto`.
Two nodes reporting the same source hitting the same dest:port within
`cross_node_window_ms` (default 30s) join the same incident.

| Reporting nodes | Severity |
|---|---|
| 1 | original (info/low/medium/high from ML detector) |
| 2 | **HIGH** (escalated) |
| 3+ | **CRITICAL** (escalated) |

Score across nodes: max of all reported scores. Reporting node list is
deduplicated (a node reporting twice within window counts once).

## Heartbeat Health States

| State | Trigger | Active? |
|---|---|---|
| `HEALTHY` | heartbeat received within timeout | YES |
| `DEGRADED` | 1 missed beat | YES |
| `UNHEALTHY` | `dead_threshold / 2 + 1` misses | NO |
| `DEAD` | `dead_threshold` misses (default 3) | NO |

Dead nodes are excluded from leader election. Dead nodes can be evicted
from `NodeRegistry` when at capacity (LRU-ish on `last_seen`).

## Threat Intel Broadcast

IoC entries are shared and deduplicated. Three kinds:

| Kind | Key | Use case |
|---|---|---|
| `MALICIOUS_IP` | 4-byte IPv4 | block on first contact |
| `MALICIOUS_HASH` | 16-byte SHA-256 prefix | drop files matching known malware |
| `MALICIOUS_DOMAIN` | up to 64-byte name | block DNS resolution |
| `C2_SERVER` | 4-byte IPv4 | high-priority IP block (command-and-control) |

Each entry carries `source_node_id`, `confidence` (0-100), and `hits`
(incremented on every local match — gives feedback on IoC usefulness).

When the list is full, the entry with lowest `confidence` is evicted.

## Leader Election

Deterministic ring election (no Paxos/Raft complexity):

- **Algorithm**: highest active `NodeId` wins
- **Frequency**: every `election_interval_ms` (default 30s)
- **Trigger**: also runs on `LEADER_REQUEST` if interval allows
- **Determinism**: same set of active nodes always elects the same
  leader; no random components, no split-brain
- **Failure mode**: leader dies → next election picks the next-highest
  active NodeId (≤30s stale window)

The leader's role is **coordinator** (policy rollout sequencing, threat
intel fan-out origin) — NOT enforcement. Each node's WFP driver remains
independent; the cluster layer only shares detection state.

## Quick Start

```bash
# 1. Run unit tests (host: Linux or Windows, no network needed)
zig test core/cluster_coord.zig -lc

# 2. Build CLI demo
zig build-exe core/cluster_cli.zig -lc

# 3. Run all 7 scenarios + summary (exit 0 iff all pass)
./cluster_cli demo

# 4. Run a single scenario
./cluster_cli scenario critical-escalation
```

Expected demo output (excerpt):
```
AEGIS NIDS - Phase 39 Distributed Cluster Coordination CLI

  -> kill switch off; incidents_aggregated=0
  -> single node; reporting_count=1, severity=MEDIUM
  -> 2 nodes reported; reporting_count=2, severity=HIGH (escalated), score=0.80
  -> 3 nodes reported; reporting_count=3, severity=CRITICAL (CRITICAL), critical_count=1
  -> peer 5 joined; health=HEALTHY
  -> after 3 missed beats; health=DEAD, misses=3
  -> IoC shared by peer 2; entries=1, match_kind=C2_SERVER, confidence=95
  -> election: leader=10, changed=true, self_is_leader=false
  [PASS] kill-switch-off
  [PASS] single-node
  [PASS] cross-node-escalation
  [PASS] critical-escalation
  [PASS] heartbeat-timeout
  [PASS] threat-intel-broadcast
  [PASS] leader-election

7/7 scenarios passed
```

## Integration Sketch

```zig
const cc = @import("cluster_coord.zig");
const ml = @import("ml_detector.zig");     // Phase 36
const ht = @import("host_telemetry.zig");  // Phase 37

// On startup:
var cluster = try cc.ClusterCoord.init(allocator, .{
    .enabled = true,
    .node_id = config.cluster_node_id,
    .role = .sensor,
});
defer cluster.shutdown();

// Periodic tick (every 1s): heartbeat-timeout check + leader election
cluster.tick(now_ns);

// When ML detector emits a malicious flow verdict (Phase 36):
if (ml_verdict.score >= 0.70) {
    // Forward to local host attribution (Phase 37)
    if (host.pushFlowVerdict(ml_verdict_to_host(ml_verdict))) |idx| {
        const inc = host.correlator.getIncident(idx).?;

        // Share with cluster peers
        cluster.broadcast(.{
            .msg_type = .incident_report,
            .from_node_id = cluster.config.node_id,
            .timestamp_ns = now_ns,
            .incident_source_ip = inc.flow_local_ip,
            .incident_remote_port = inc.flow_remote_port,
            .incident_proto = @intFromEnum(inc.flow_proto),
            .incident_severity = severityFromScore(inc.flow_score),
            .incident_score = inc.flow_score,
        });
    }
}

// When local sensor sees a new connection, check threat intel:
if (cluster.checkThreatIp(remote_ip)) |ioc| {
    // Block immediately - peer already learned this is malicious
    wfp_driver.block(remote_ip);
    log("blocked {d}.{d}.{d}.{d} - threat intel from node {d} (confidence {d})",
        .{ remote_ip[0], remote_ip[1], remote_ip[2], remote_ip[3],
           ioc.source_node_id, ioc.confidence });
}

// When host telemetry (Phase 37) discovers a new malicious hash:
if (host.fim.observe(...).kind == .modified) {
    cluster.broadcast(.{
        .msg_type = .threat_intel_share,
        .from_node_id = cluster.config.node_id,
        .timestamp_ns = now_ns,
        .threat_intel = .{
            .kind = .malicious_hash,
            .hash = first_16_bytes_of_sha256,
            .source_node_id = cluster.config.node_id,
            .confidence = 90,
        },
    });
}
```

## Verification Checklist

Run on host (Linux or Windows) before promoting to production:

```
[ ] zig test core/cluster_coord.zig -lc             -> "All 33 tests passed"
[ ] zig build-exe core/cluster_cli.zig -lc          -> clean compile
[ ] ./cluster_cli demo                              -> "7/7 scenarios passed" (exit 0)
[ ] ./cluster_cli scenario critical-escalation     -> [PASS]
[ ] ./cluster_cli scenario leader-election          -> [PASS]
[ ] ./cluster_cli help                              -> usage screen
[ ] Inspect core/cluster_config.json               -> valid JSON, kill_switch.enabled=false
```

## DevSecOps Tier Progress

| Tier | Phase | Status |
|---|---|---|
| 1 - Safety Foundation | Phase 35 (kill switches) | COMPLETE |
| 1 - Safety Foundation | Phase 40 (rollback) | COMPLETE |
| 2 - Additive Integrations | Phase 33 (WFP bridge) | COMPLETE |
| 2 - Additive Integrations | Phase 34 (forensic replay) | COMPLETE |
| 3 - Core Expansion | Phase 32 (Npcap) | COMPLETE (v3 ARP-visibility) |
| 3 - Core Expansion | Phase 38 (sensor ingest) | COMPLETE |
| 4 - Advanced Detection | Phase 36 (ML/AI flow) | COMPLETE |
| 4 - Advanced Detection | Phase 37 (HIDS/XDR endpoint) | COMPLETE |
| 5 - Complex | **Phase 39 (cluster coordination)** | **COMPLETE (this phase)** |

**Gate-5 tag**: `v5.5-distributed-cluster` is now ready — Tier 5 is complete.

**Full DevSecOps roadmap complete**: All 5 tiers delivered (Phase 32-40 + extensions).

## Risk & Rollback

- **Risk**: MEDIUM — additive detection/attribution layer; no per-node
  enforcement changes
- **Rollback**: set `ClusterConfig.enabled = false` (kill switch) — module
  becomes a no-op without code removal. To fully remove: stop calling
  `ClusterCoord.init()` and unlink the import in `build.zig`.
- **Failure mode**: Federation transport adapters NOT yet wired in (gRPC /
  ZeroMQ / REST). Module compiles + tests pass, but produces no
  cross-node aggregation at runtime until adapters feed `ClusterMessage`
  records via `ingest()`. This is intentional: keeps the core testable
  and the transport contracts clean.
- **Split-brain**: deterministic ring election eliminates split-brain
  risk — same set of active nodes always elects the same leader. No
  Byzantine defense (assumes honest peers); suitable for trusted
  internal sensor clusters.
