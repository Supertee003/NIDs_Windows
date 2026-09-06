# G14 — Federation

**Gate:** G14
**Status:** DOCUMENTED (framework designed in Phase 39 Ext 1-3)
**Date:** 2026-09-07

## Requirement
```
node identity, real TLS/mTLS, certificate validation, message authentication,
replay protection, sequence number, trust state, key rotation, split-brain handling
```

## Current State
- No federation code in repository (single-node only)
- Phase 39 Ext 1-3 (in `/home/z/my-project/download/`) provides:
  - FederationCodec: binary wire format with CRC32
  - TcpTransport + FramedReader: real TCP transport
  - TlsTransport: TLS/mTLS wrapper (mock on Linux)
  - ClusterCoord: node registry, heartbeat, cross-node aggregation, leader election

## Integration Plan
1. Copy federation modules from `download/` to `core/federation/`
2. Wire ClusterCoord.ingest() into inspect_packet (after detection)
3. Wire pushFlowVerdict() into AtomicThreatTracker (G7)
4. Enable TLS transport for cross-machine deployment

## Exit Gate
```
[x] Federation framework designed (Phase 39 Ext 1-3)
[x] Wire format: CRC32-checked binary frames
[x] Transport: real TCP + TLS/mTLS (mock on Linux for testing)
[x] Cluster: node registry, heartbeat, cross-node escalation, leader election
[ ] Integration into repository (copy from download/)
[ ] Node identity (certificate-based)
[ ] Key rotation
[ ] Split-brain handling (documented in Phase 39 leader election)
```
